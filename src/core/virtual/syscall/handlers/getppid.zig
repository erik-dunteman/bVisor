const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const AbsTgid = Thread.AbsTgid;
const NsTgid = Thread.NsTgid;
const Threads = @import("../../proc/Threads.zig");
const CloneFlags = Threads.CloneFlags;
const proc_info = @import("../../../deps/deps.zig").proc_info;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

/// getppid return the namespaced TGID of the parent thread
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("getppid: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Return 0 if:
    // - No parent (sandbox root)
    // - Parent not visible (e.g., in CLONE_NEWPID case where parent is in different namespace)
    // Get parent Thread to caller
    const parent_process = caller.thread_group.parent orelse return replySuccess(notif.id, 0);
    const parent = parent_process.getLeader() catch |err| {
        std.log.err("getppid: Thread not found with tid={d}: {}", .{ parent_process.tgid, err });
        return replyErr(notif.id, .SRCH);
    };
    if (!caller.canSee(parent)) return replySuccess(notif.id, 0);

    // Get namespaced TGID of parent's ThreadGroup, which matches the namespaced TID of the parent
    const ns_ptgid: NsTgid = caller.namespace.getNsTid(parent) orelse std.debug.panic("getppid: Supervisor invariant violated - caller's Namespace doesn't contain the parent Thread", .{});

    return replySuccess(notif.id, @intCast(ns_ptgid));
}

test "getppid for init Thread returns 0" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = init_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "getppid for child returns parent's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    // Add a child Thread
    const child_tid: AbsTid = 200;
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = child_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent's AbsTgid
    try testing.expectEqual(@as(i64, init_tid), resp.val);
}

test "getppid for grandchild returns parent's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const child_tid: AbsTid = 200;
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(0));

    const grandchild_tid: AbsTid = 300;
    const child = supervisor.guest_threads.lookup.get(child_tid).?;
    _ = try supervisor.guest_threads.registerChild(child, grandchild_tid, CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandchild_tid });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    // Parent's AbsTgid
    try testing.expectEqual(@as(i64, child_tid), resp.val);
}
