const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

/// gettid returns the thread ID. For the main thread (which bVisor supports),
/// this equals the process ID.
// TODO: differentiate from main pid
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: AbsPid = @intCast(notif.pid);

    const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
        std.log.err("gettid: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    const ns_tid = caller.namespace.getNsPid(caller) orelse std.debug.panic("gettid: supervisor invariant violated - proc's namespace doesn't contain itself", .{});

    // For main thread, tid == pid
    return replySuccess(notif.id, @intCast(ns_tid));
}
