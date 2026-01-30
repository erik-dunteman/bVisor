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
        std.log.err("getpid: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    const ns_pid = caller.namespace.getNsPid(caller) orelse std.debug.panic("getpid: supervisor invariant violated - proc's namespace doesn't contain itself", .{});

    return replySuccess(notif.id, @intCast(ns_pid));
}

test "getpid returns supervisor pid" {
    const allocator = testing.allocator;
    const supervisor_pid: AbsPid = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, supervisor_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = supervisor_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(supervisor_pid, resp.val);
}

test "getpid for guest process returns guest pid" {
    const allocator = testing.allocator;
    // Add an initial guest
    const init_guest_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_guest_pid);
    defer supervisor.deinit();

    // Add a child to the initial guest
    const child_pid: AbsPid = 200;
    const init_proc = supervisor.guest_procs.lookup.get(init_guest_pid).?;
    _ = try supervisor.guest_procs.registerChild(init_proc, child_pid, Procs.CloneFlags.from(0));

    // Child calls getpid
    //   ... supposing converted child's requested pid to be :AbsPid
    const notif = makeNotif(.getpid, .{ .pid = child_pid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(child_pid, resp.val);
}

test "getpid from immediate child in new namespace returns namespace-local PID" {
    const allocator = testing.allocator;
    const init_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();
    defer proc_info.testing.reset(allocator);

    // Child in new namespace (depth 2, PID 1 in its own namespace)
    const guest_pid: AbsPid = 9999;
    const nspids = [_]NsPid{ 9999, 1 };
    try proc_info.testing.setupNsPids(allocator, guest_pid, &nspids);

    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, guest_pid, Procs.CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = guest_pid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(1, resp.val);
    // Child's NsPid should (almost certainly) not match the AbsPid for that guest process (e.g., 1)
    try testing.expect(guest_pid != resp.val);
}
