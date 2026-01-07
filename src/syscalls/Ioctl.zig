const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,
request: u64,
arg: u64,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .request = notif.data.arg1,
        .arg = notif.data.arg2,
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating ioctl: fd={d} request=0x{x}", .{ self.fd, self.request });

    // stdio passthrough - terminal ioctls need to go to real terminal
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("ioctl: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Check if FD is tracked by overlay
    if (!overlay.hasFD(self.fd)) {
        logger.log("ioctl: passthrough for untracked fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // For overlay FDs, most ioctls don't make sense
    // Return ENOTTY (inappropriate ioctl for device)
    logger.log("ioctl: ENOTTY for overlay fd={d}", .{self.fd});
    return .{ .handled = Result.Handled.err(.NOTTY) };
}
