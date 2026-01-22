const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: Proc.KernelPID = @intCast(notif.pid);

    const proc = supervisor.virtual_procs.get(caller_pid) catch |err| {
        // getpid() never fails in the kernel - if we can't find the process,
        // it's a supervisor invariant violation
        std.debug.panic("getpid: supervisor invariant violated - kernel pid {d} not in virtual_procs: {}", .{ caller_pid, err });
    };

    return replySuccess(notif.id, @intCast(proc.pid));
}

test "getpid returns kernel pid" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = kernel_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(kernel_pid, resp.val);
}

test "getpid for child process returns child kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.registerChild(parent, child_pid, Procs.CloneFlags.from(0));

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = child_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(child_pid, resp.val);
}
