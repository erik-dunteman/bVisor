const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

// fcntl commands
const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_DUPFD_CLOEXEC: u32 = 1030;

fd: FD,
cmd: u32,
arg: u64,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .cmd = @truncate(notif.data.arg1),
        .arg = notif.data.arg2,
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating fcntl: fd={d} cmd={d} arg={d}", .{ self.fd, self.cmd, self.arg });

    // stdio passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("fcntl: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Check if FD is tracked by overlay
    const entry = overlay.getFDBackend(self.fd);
    if (entry == null) {
        logger.log("fcntl: passthrough for untracked fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    switch (self.cmd) {
        F_DUPFD, F_DUPFD_CLOEXEC => {
            // Duplicate FD to lowest available >= arg
            // For simplicity, we ignore the minimum FD constraint and just dup
            const newfd = overlay.dup(self.fd) catch |err| {
                logger.log("fcntl F_DUPFD: failed: {}", .{err});
                return switch (err) {
                    error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
                    else => .{ .handled = Result.Handled.err(.IO) },
                };
            };
            logger.log("fcntl F_DUPFD: duplicated fd={d} -> fd={d}", .{ self.fd, newfd });
            return .{ .handled = Result.Handled.success(newfd) };
        },
        F_GETFD => {
            // Get FD flags (FD_CLOEXEC) - we don't track this, return 0
            logger.log("fcntl F_GETFD: returning 0", .{});
            return .{ .handled = Result.Handled.success(0) };
        },
        F_SETFD => {
            // Set FD flags (FD_CLOEXEC) - we ignore this since we don't exec
            logger.log("fcntl F_SETFD: ignored (no exec)", .{});
            return .{ .handled = Result.Handled.success(0) };
        },
        F_GETFL => {
            // Get file status flags
            const flags = entry.?.flags;
            logger.log("fcntl F_GETFL: returning flags=0x{x}", .{flags});
            return .{ .handled = Result.Handled.success(@intCast(flags)) };
        },
        F_SETFL => {
            // Set file status flags - we could update entry.flags but for now ignore
            // Only O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, O_NONBLOCK can be changed
            logger.log("fcntl F_SETFL: ignored", .{});
            return .{ .handled = Result.Handled.success(0) };
        },
        else => {
            // Unknown command - passthrough to kernel
            logger.log("fcntl: passthrough for unknown cmd={d}", .{self.cmd});
            return .{ .passthrough = {} };
        },
    }
}
