const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const NsPid = Proc.NsPid;
const Procs = @import("../../proc/Procs.zig");
const proc_info = @import("../../../deps/deps.zig").proc_info;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_pid: AbsPid = @intCast(notif.pid);

    const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
        std.log.err("getppid: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Return parent's kernel PID, or 0 if:
    // - No parent (sandbox root)
    // - Parent not visible (e.g., in CLONE_NEWPID case where parent is in different namespace)
    if (caller.parent == null) return replySuccess(notif.id, 0);
    const parent = caller.parent.?;
    if (!caller.canSee(parent)) return replySuccess(notif.id, 0);

    // Caller can see parent, but we need to remap to nspid
    const ns_ppid = caller.namespace.getNsPid(parent) orelse std.debug.panic("getppid: supervisor invariant violated - proc's namespace doesn't contain itself", .{});

    return replySuccess(notif.id, @intCast(ns_ppid));
}

test "getppid for init process returns 0" {
    const allocator = testing.allocator;
    const init_pid: AbsPid = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = init_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "getppid for child returns parent's NsPid" {
    const allocator = testing.allocator;
    const init_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: AbsPid = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, child_pid, Procs.CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = child_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent's NsPid
    try testing.expectEqual(@as(i64, init_pid), resp.val);
}

test "getppid for grandchild returns parent's NsPid" {
    const allocator = testing.allocator;
    const init_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const child_pid: AbsPid = 200;
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, child_pid, Procs.CloneFlags.from(0));

    const grandchild_pid: AbsPid = 300;
    const child = supervisor.guest_procs.lookup.get(child_pid).?;
    _ = try supervisor.guest_procs.registerChild(child, grandchild_pid, Procs.CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandchild_pid });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    // Parent's NsPid
    try testing.expectEqual(@as(i64, child_pid), resp.val);
}

test "getppid for CLONE_NEWPID immediate child returns 0" {
    const allocator = testing.allocator;
    const init_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();
    defer proc_info.testing.reset(allocator);

    // Child in new namespace (depth 2, PID 1 in its own namespace)
    const child_pid: AbsPid = 200;
    const nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, child_pid, &nspids);

    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, child_pid, Procs.CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getppid - parent is not visible from within child's namespace
    const notif = makeNotif(.getppid, .{ .pid = child_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent not visible, returns 0
    try testing.expectEqual(@as(i64, 0), resp.val);
}
