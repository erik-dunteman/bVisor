const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const NsPid = Proc.NsPid;
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: AbsPid = @intCast(notif.pid);
    const target_pid: NsPid = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    // Non-positive PIDs (process groups) not supported
    // TODO: support all integer target PIDS
    if (target_pid <= 0) {
        return replyErr(notif.id, .INVAL);
    }

    // Critical section just to normalize target PID to absolute
    var target_abs_pid: AbsPid = undefined;
    {
        supervisor.mutex.lock();
        defer supervisor.mutex.unlock();

        const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
            std.log.err("kill: process not found for pid={d}: {}", .{ caller_pid, err });
            return replyErr(notif.id, .SRCH);
        };

        const target = supervisor.guest_procs.getNamespaced(caller, target_pid) catch |err| {
            std.log.err("kill: target process not found for pid={d}: {}", .{ target_pid, err });
            return replyErr(notif.id, .SRCH);
        };

        target_abs_pid = target.pid;
    }

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(signal);
    posix.kill(@intCast(target_abs_pid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return replyErr(notif.id, errno);
    };

    // Do not remove from internal procs tracking.
    // Killing a process is just a signal invocation.
    // exit_group is what actually removes it from procs.

    return replySuccess(notif.id, 0);
}

test "kill with negative pid returns EINVAL" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = @as(u64, @bitCast(@as(i64, -1))), // -1 = all processes
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}

test "kill with zero pid returns EINVAL" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 0, // process group
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}
