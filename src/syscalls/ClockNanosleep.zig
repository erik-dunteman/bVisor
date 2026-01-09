const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = types.MemoryBridge;
const Logger = types.Logger;
const Result = @import("../syscall.zig").Syscall.Result;

clock_id: linux.clockid_t,
flags: linux.TIMER,
request_ptr: u64,
request: linux.timespec,
remain_ptr: u64, // may be 0 (null)

const Self = @This();

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .clock_id = @enumFromInt(notif.data.arg0),
        .flags = @bitCast(@as(u32, @truncate(notif.data.arg1))),
        .request_ptr = notif.data.arg2,
        .request = try mem_bridge.read(linux.timespec, notif.data.arg2),
        .remain_ptr = notif.data.arg3,
    };
}

pub fn handle(self: Self, mem_bridge: MemoryBridge, logger: Logger) !Result {
    logger.log("Emulating clock_nanosleep: clock={s} sec={d}.{d}", .{
        @tagName(self.clock_id),
        self.request.sec,
        self.request.nsec,
    });

    var remain: linux.timespec = undefined;
    const result = linux.clock_nanosleep(self.clock_id, self.flags, &self.request, &remain);
    const err_code = linux.errno(result);

    if (err_code == .SUCCESS) {
        logger.log("clock_nanosleep completed successfully", .{});
        return .{ .handled = Result.Handled.success(0) };
    }

    if (err_code == .INTR and self.remain_ptr != 0) {
        logger.log("clock_nanosleep interrupted, remain={d}.{d}", .{ remain.sec, remain.nsec });
        mem_bridge.write(linux.timespec, remain, self.remain_ptr) catch |write_err| {
            logger.log("Failed to write remain: {}", .{write_err});
        };
    }

    return .{ .handled = Result.Handled.err(err_code) };
}
