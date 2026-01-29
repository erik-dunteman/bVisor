const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

/// gettid returns the thread ID. For the main thread (which bVisor supports),
/// this equals the process ID.
// TODO: differentiate from main pid
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: AbsPid = @intCast(notif.pid);

    const proc = supervisor.guest_procs.get(caller_pid) catch |err| {
        std.debug.panic("gettid: supervisor invariant violated - kernel pid {d} not in guest_procs: {}", .{ caller_pid, err });
    };

    // For main thread, tid == pid
    return replySuccess(notif.id, @intCast(proc.pid));
}
