const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Overlay = @import("../Overlay.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,
offset: i64,
whence: u32,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .offset = @bitCast(notif.data.arg1),
        .whence = @truncate(notif.data.arg2),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating lseek: fd={d} offset={d} whence={d}", .{
        self.fd,
        self.offset,
        self.whence,
    });

    // stdio passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("lseek: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    const whence: Overlay.SeekWhence = switch (self.whence) {
        0 => .SET,
        1 => .CUR,
        2 => .END,
        else => {
            logger.log("lseek: invalid whence={d}", .{self.whence});
            return .{ .handled = Result.Handled.err(.INVAL) };
        },
    };

    const new_offset = overlay.lseek(self.fd, self.offset, whence) catch |err| {
        logger.log("lseek: failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.InvalidSeek => .{ .handled = Result.Handled.err(.INVAL) },
        };
    };

    logger.log("lseek: new offset={d}", .{new_offset});
    return .{ .handled = Result.Handled.success(new_offset) };
}
