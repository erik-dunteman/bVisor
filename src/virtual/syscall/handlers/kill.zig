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
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
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

    // Sync supervisor's procs with the kernel
    supervisor.guest_procs.syncNewProcs() catch {};

    // Get references to the caller and target processes
    const caller_proc = supervisor.guest_procs.get(caller_pid) catch
        return replyErr(notif.id, .SRCH);
    const target_proc = caller_proc.namespace.procs.get(target_pid) orelse
        return replyErr(notif.id, .SRCH);

    // Caller must be able to see target
    // TODO: rethink, this lookup is all messed up and ignores NsPids being an option
    if (!caller_proc.canSee(target_proc)) {
        return replyErr(notif.id, .SRCH);
    }

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(signal);
    posix.kill(@intCast(target_proc.pid), sig) catch |err| {
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
