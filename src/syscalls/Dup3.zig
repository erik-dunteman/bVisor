const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

const O_CLOEXEC: u32 = 0o2000000;

oldfd: FD,
newfd: FD,
flags: u32,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .oldfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .newfd = @bitCast(@as(u32, @truncate(notif.data.arg1))),
        .flags = @truncate(notif.data.arg2),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating dup3: oldfd={d} newfd={d} flags=0x{x}", .{ self.oldfd, self.newfd, self.flags });

    // dup3 with same old and new fd returns EINVAL (unlike dup2)
    if (self.oldfd == self.newfd) {
        logger.log("dup3: EINVAL - oldfd == newfd", .{});
        return .{ .handled = Result.Handled.err(.INVAL) };
    }

    // Only O_CLOEXEC is valid for flags
    if (self.flags != 0 and self.flags != O_CLOEXEC) {
        logger.log("dup3: EINVAL - invalid flags", .{});
        return .{ .handled = Result.Handled.err(.INVAL) };
    }

    const oldfd_is_stdio = self.oldfd >= 0 and self.oldfd <= 2;
    const newfd_is_stdio = self.newfd >= 0 and self.newfd <= 2;
    const oldfd_in_overlay = overlay.hasFD(self.oldfd);

    // Case 1: Both are stdio or both are kernel FDs - passthrough
    if (oldfd_is_stdio and newfd_is_stdio) {
        logger.log("dup3: passthrough for stdio-to-stdio", .{});
        return .{ .passthrough = {} };
    }

    // Case 2: Overlay FD -> stdio (shell redirection like `> /file`)
    // We need to track that stdio now points to overlay file
    if (oldfd_in_overlay and newfd_is_stdio) {
        const result_fd = overlay.dup2(self.oldfd, self.newfd) catch |err| {
            logger.log("dup3: failed to redirect overlay->stdio: {}", .{err});
            return switch (err) {
                error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
                else => .{ .handled = Result.Handled.err(.IO) },
            };
        };
        logger.log("dup3: redirected overlay fd={d} -> stdio fd={d}", .{ self.oldfd, result_fd });
        return .{ .handled = Result.Handled.success(result_fd) };
    }

    // Case 3: stdio -> overlay or kernel FD - passthrough (restoring original stdio)
    if (oldfd_is_stdio) {
        // Check if newfd is currently an overlay redirect, close it
        if (overlay.hasFD(self.newfd)) {
            overlay.close(self.newfd);
        }
        logger.log("dup3: passthrough for stdio restoration", .{});
        return .{ .passthrough = {} };
    }

    // Case 4: oldfd not in overlay (kernel FD) -> any newfd
    // If newfd is currently tracked in overlay, close it (restoring to kernel FD)
    if (!oldfd_in_overlay) {
        if (overlay.hasFD(self.newfd)) {
            logger.log("dup3: closing overlay fd={d} before kernel passthrough", .{self.newfd});
            overlay.close(self.newfd);
        }
        logger.log("dup3: passthrough for untracked oldfd={d}", .{self.oldfd});
        return .{ .passthrough = {} };
    }

    // Case 5: Both are overlay FDs
    const result_fd = overlay.dup2(self.oldfd, self.newfd) catch |err| {
        logger.log("dup3: failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    // Note: O_CLOEXEC flag is ignored in our implementation since we don't
    // actually exec - all our FDs are virtual anyway

    logger.log("dup3: duplicated fd={d} -> fd={d}", .{ self.oldfd, result_fd });
    return .{ .handled = Result.Handled.success(result_fd) };
}
