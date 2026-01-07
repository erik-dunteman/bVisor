const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

oldfd: FD,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .oldfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating dup: oldfd={d}", .{self.oldfd});

    // stdio passthrough
    if (self.oldfd >= 0 and self.oldfd <= 2) {
        logger.log("dup: passthrough for stdio fd={d}", .{self.oldfd});
        return .{ .passthrough = {} };
    }

    // Check if FD is tracked by overlay
    if (!overlay.hasFD(self.oldfd)) {
        logger.log("dup: passthrough for untracked fd={d}", .{self.oldfd});
        return .{ .passthrough = {} };
    }

    const newfd = overlay.dup(self.oldfd) catch |err| {
        logger.log("dup: failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("dup: duplicated fd={d} -> fd={d}", .{ self.oldfd, newfd });
    return .{ .handled = Result.Handled.success(newfd) };
}
