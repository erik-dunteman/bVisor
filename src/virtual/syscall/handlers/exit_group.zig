const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);

    // Clean up virtual proc entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.guest_procs.handleProcessExit(caller_pid) catch {};

    // Let kernel execute the actual exit_group syscall
    return replyContinue(notif.id);
}
