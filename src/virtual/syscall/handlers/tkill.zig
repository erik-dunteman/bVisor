const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

/// tkill(tid, sig) sends a signal to a specific thread.
/// Unlike kill, tid is always a positive thread ID — no process group semantics.
/// Since bVisor doesn't support multi-threading yet, tid == pid.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: AbsPid = @intCast(notif.pid);
    const target_tid: AbsPid = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    if (target_tid <= 0) {
        return replyErr(notif.id, .INVAL);
    }

    // Resolve target tid to absolute pid
    var target_abs_pid: AbsPid = undefined;
    {
        supervisor.mutex.lock();
        defer supervisor.mutex.unlock();

        const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
            std.log.err("tkill: process not found for pid={d}: {}", .{ caller_pid, err });
            return replyErr(notif.id, .SRCH);
        };

        // Since tid == pid (no threading), use namespace lookup same as kill
        const target = supervisor.guest_procs.getNamespaced(caller, target_tid) catch |err| {
            std.log.err("tkill: target thread not found for tid={d}: {}", .{ target_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        target_abs_pid = target.pid;
    }

    const sig: posix.SIG = @enumFromInt(signal);
    posix.kill(@intCast(target_abs_pid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return replyErr(notif.id, errno);
    };

    return replySuccess(notif.id, 0);
}
