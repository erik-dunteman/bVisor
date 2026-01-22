const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const isError = @import("../../../seccomp/notif.zig").isError;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.KernelPID = @intCast(notif.pid);
    const target_pid: Proc.KernelPID = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    // Negative PIDs (process groups) not supported
    if (target_pid <= 0) {
        return replyErr(notif.id, .INVAL);
    }

    const caller = supervisor.virtual_procs.get(caller_pid) catch
        return replyErr(notif.id, .SRCH);

    // TODO ERIK get target via namespace reference frame, not from virtual_procs
    // also rename virtual_procs to "kernel_procs" and make the type of target_pid and args to namespace procs be virtualPID
    // caller.namespace.procs.get(self.target_pid) catch
    // const target: *Proc = caller.namespace.procs.get(self.target_pid)

    const target = supervisor.virtual_procs.get(target_pid) catch
        return replyErr(notif.id, .SRCH);

    // Caller must be able to see target
    if (!caller.canSee(target)) {
        return replyErr(notif.id, .SRCH);
    }

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(signal);
    posix.kill(@intCast(target.pid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return replyErr(notif.id, errno);
    };

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
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
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
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}
