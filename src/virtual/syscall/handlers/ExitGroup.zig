const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");

const Self = @This();

kernel_pid: Proc.KernelPID,

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{ .kernel_pid = @intCast(notif.pid) };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    // Clean up virtual proc entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.virtual_procs.handle_process_exit(self.kernel_pid) catch {};

    // Let kernel execute the actual exit_group syscall
    return .use_kernel;
}
