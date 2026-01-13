const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Logger = types.Logger;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../Supervisor.zig");

// comptime dependency injection
const deps = @import("../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pid: linux.pid_t,
clock_id: linux.clockid_t,
flags: linux.TIMER,
request_ptr: u64,
request: linux.timespec,
remain_ptr: u64, // may be 0 (null)

const Self = @This();

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    return .{
        .pid = @intCast(notif.pid),
        .clock_id = @enumFromInt(notif.data.arg0),
        .flags = @bitCast(@as(u32, @truncate(notif.data.arg1))),
        .request_ptr = notif.data.arg2,
        .request = try memory_bridge.read(linux.timespec, @intCast(notif.pid), notif.data.arg2),
        .remain_ptr = notif.data.arg3,
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

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
        memory_bridge.write(linux.timespec, self.pid, remain, self.remain_ptr) catch |write_err| {
            logger.log("Failed to write remain: {}", .{write_err});
        };
    }

    return .{ .handled = Result.Handled.err(err_code) };
}
