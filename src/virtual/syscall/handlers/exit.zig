const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

/// exit exits just the calling thread. In a multi-threaded process, other threads continue.
/// exit_group exits all threads in the thread group.
/// Since bVisor doesn't support multi-threading yet, both behave the same.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Clean up virtual proc entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.guest_procs.handleProcessExit(caller_pid) catch {};

    return replyContinue(notif.id);
}
