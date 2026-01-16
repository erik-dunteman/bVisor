const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const Proc = @import("Proc.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const KernelPID = Proc.KernelPID;
pub const VirtualPID = Namespace.VirtualPID;

const ProcLookup = std.AutoHashMapUnmanaged(KernelPID, *Proc);

const Self = @This();

pub const CloneFlags = struct {
    raw: u64,

    /// Returns error if unsupported namespace flags are set
    pub fn check_supported(self: CloneFlags) !void {
        if (self.raw & linux.CLONE.NEWUSER != 0) return error.UnsupportedUserNamespace;
        if (self.raw & linux.CLONE.NEWNET != 0) return error.UnsupportedNetNamespace;
        if (self.raw & linux.CLONE.NEWNS != 0) return error.UnsupportedMountNamespace;
    }

    pub fn from(raw: u64) CloneFlags {
        return .{ .raw = raw };
    }

    pub fn create_pid_namespace(self: CloneFlags) bool {
        return self.raw & linux.CLONE.NEWPID != 0;
    }

    pub fn is_thread(self: CloneFlags) bool {
        return self.raw & linux.CLONE.THREAD != 0;
    }

    pub fn share_parent(self: CloneFlags) bool {
        return self.raw & linux.CLONE.PARENT != 0;
    }

    pub fn share_files(self: CloneFlags) bool {
        return self.raw & linux.CLONE.FILES != 0;
    }
};

/// Tracks kernel to virtual mappings, handling parent/child relationships.
/// Note: we don't currently reparent orphaned children to init; killing a
/// process kills its entire subtree including any nested namespaces.
allocator: Allocator,

// flat list of mappings from kernel to virtual PID
// owns underlying procs
procs: ProcLookup = .empty,

pub fn init(allocator: Allocator) Self {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    var iter = self.procs.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.parent == null) {
            const subtree = entry.value_ptr.*.collect_subtree_owned(self.allocator) catch break;
            defer self.allocator.free(subtree);
            for (subtree) |proc| {
                proc.deinit(self.allocator);
            }
            break;
        }
    }
    self.procs.deinit(self.allocator);
}

pub fn handle_initial_process(self: *Self, pid: KernelPID) !VirtualPID {
    if (self.procs.size != 0) return error.InitialProcessExists;

    // passing null namespace/fd_table creates new ones
    const root_proc = try Proc.init(self.allocator, pid, null, null, null);
    errdefer root_proc.deinit(self.allocator);

    try self.procs.put(self.allocator, pid, root_proc);

    return root_proc.vpid;
}

pub fn handle_clone(self: *Self, parent_pid: KernelPID, child_pid: KernelPID, clone_flags: CloneFlags) !VirtualPID {
    try clone_flags.check_supported();

    const parent: *Proc = self.procs.get(parent_pid) orelse return error.KernelPIDNotFound;

    // CLONE_NEWPID creates a new PID namespace; otherwise inherit parent's
    const namespace: ?*Namespace = if (clone_flags.create_pid_namespace())
        null // triggers new namespace creation in init_child
    else
        parent.namespace;

    // CLONE_FILES shares the fd_table; otherwise clone it
    const fd_table: *FdTable = if (clone_flags.share_files())
        parent.fd_table.ref()
    else
        try parent.fd_table.clone();
    errdefer fd_table.unref();

    const child = try parent.init_child(self.allocator, child_pid, namespace, fd_table);
    errdefer parent.deinit_child(child, self.allocator);

    try self.procs.put(self.allocator, child_pid, child);

    return child.vpid;
}

pub fn handle_process_exit(self: *Self, pid: KernelPID) !void {
    const target_proc = self.procs.get(pid) orelse return;

    // remove target from parent's children
    if (target_proc.parent) |parent| {
        parent.remove_child_link(target_proc);
    }

    // collect all descendant procs (crosses namespace boundaries)
    const descendant_procs = try target_proc.collect_subtree_owned(self.allocator);
    defer self.allocator.free(descendant_procs);

    // remove from lookup table and deinit each proc
    for (descendant_procs) |proc| {
        _ = self.procs.remove(proc.pid);
        proc.deinit(self.allocator);
    }
}

test "state is correct after initial proc" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();
    try std.testing.expect(v_procs.procs.size == 0);

    // supervisor spawns child proc of say PID=22, need to register that virtually
    const init_pid = 22;
    const init_vpid = try v_procs.handle_initial_process(init_pid);
    try std.testing.expectEqual(1, init_vpid);
    try std.testing.expectEqual(1, v_procs.procs.size);
    const proc = v_procs.procs.get(init_pid).?;
    try std.testing.expectEqual(init_vpid, proc.vpid);
    try std.testing.expectEqual(null, proc.parent);
    try std.testing.expectEqual(0, proc.children.size);
    try std.testing.expect(proc.is_namespace_root());
    try std.testing.expectEqual(@as(VirtualPID, 1), proc.get_namespace_root().vpid);
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    try std.testing.expectEqual(0, v_procs.procs.size);

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    const a_vpid = try v_procs.handle_initial_process(a_pid);
    try std.testing.expectEqual(1, v_procs.procs.size);
    try std.testing.expectEqual(1, a_vpid);

    const b_pid = 44;
    const b_vpid = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    try std.testing.expectEqual(2, b_vpid);
    try std.testing.expectEqual(2, v_procs.procs.size);
    try std.testing.expectEqual(1, v_procs.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(b_pid).?.children.size);

    const c_pid = 55;
    const c_vpid = try v_procs.handle_clone(a_pid, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(3, c_vpid);
    try std.testing.expectEqual(3, v_procs.procs.size);
    try std.testing.expectEqual(2, v_procs.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(b_pid).?.children.size);

    const d_pid = 66;
    const d_vpid = try v_procs.handle_clone(c_pid, d_pid, CloneFlags.from(0));
    try std.testing.expectEqual(4, d_vpid);
    try std.testing.expectEqual(4, v_procs.procs.size);
    try std.testing.expectEqual(2, v_procs.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, v_procs.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(b_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(d_pid).?.children.size);

    // shrink to
    // a
    // - c
    //   - d
    try v_procs.handle_process_exit(b_pid);
    try std.testing.expectEqual(3, v_procs.procs.size);
    try std.testing.expectEqual(1, v_procs.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, v_procs.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, v_procs.procs.get(d_pid).?.children.size);
    try std.testing.expectEqual(null, v_procs.procs.get(b_pid));

    // get vpids
    var a_vpids = try v_procs.procs.get(a_pid).?.get_vpids_owned(allocator);
    try std.testing.expectEqual(3, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[3]VirtualPID{ 1, 3, 4 }, a_vpids);
    allocator.free(a_vpids); // free immediately, since we reuse a_vpids var later

    // re-add b, should issue a new vpid 5
    const b_pid_2 = 45;
    const b_vpid_2 = try v_procs.handle_clone(a_pid, b_pid_2, CloneFlags.from(0));
    try std.testing.expectEqual(5, b_vpid_2);

    a_vpids = try v_procs.procs.get(a_pid).?.get_vpids_owned(allocator);
    defer allocator.free(a_vpids);
    try std.testing.expectEqual(4, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[4]VirtualPID{ 1, 3, 4, 5 }, a_vpids);

    // clear whole tree
    try v_procs.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, v_procs.procs.size);
    try std.testing.expectEqual(null, v_procs.procs.get(a_pid));
    try std.testing.expectEqual(null, v_procs.procs.get(b_pid));
    try std.testing.expectEqual(null, v_procs.procs.get(b_pid_2));
    try std.testing.expectEqual(null, v_procs.procs.get(c_pid));
    try std.testing.expectEqual(null, v_procs.procs.get(d_pid));
}

test "handle_initial_process fails if already registered" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    _ = try v_procs.handle_initial_process(100);
    try std.testing.expectError(error.InitialProcessExists, v_procs.handle_initial_process(200));
}

test "handle_clone fails with unknown parent" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    _ = try v_procs.handle_initial_process(100);
    try std.testing.expectError(error.KernelPIDNotFound, v_procs.handle_clone(999, 200, CloneFlags.from(0)));
}

test "handle_process_exit on non-existent pid is no-op" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    _ = try v_procs.handle_initial_process(100);
    try v_procs.handle_process_exit(999);
    try std.testing.expectEqual(1, v_procs.procs.size);
}

test "kill intermediate node removes subtree but preserves siblings" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    _ = try v_procs.handle_initial_process(a_pid);
    const b_pid = 20;
    _ = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    const c_pid = 30;
    _ = try v_procs.handle_clone(a_pid, c_pid, CloneFlags.from(0));
    const d_pid = 40;
    _ = try v_procs.handle_clone(c_pid, d_pid, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_procs.procs.size);

    // kill c (intermediate) - should also remove d but preserve a and b
    try v_procs.handle_process_exit(c_pid);

    try std.testing.expectEqual(2, v_procs.procs.size);
    try std.testing.expect(v_procs.procs.get(a_pid) != null);
    try std.testing.expect(v_procs.procs.get(b_pid) != null);
    try std.testing.expectEqual(null, v_procs.procs.get(c_pid));
    try std.testing.expectEqual(null, v_procs.procs.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    _ = try v_procs.handle_initial_process(100);
    const proc = v_procs.procs.get(100).?;

    const vpids = try proc.get_vpids_owned(allocator);
    defer allocator.free(vpids);

    try std.testing.expectEqual(1, vpids.len);
    try std.testing.expectEqual(1, vpids[0]);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // chain: a -> b -> c -> d -> e
    var pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    _ = try v_procs.handle_initial_process(pids[0]);
    for (1..5) |i| {
        _ = try v_procs.handle_clone(pids[i - 1], pids[i], CloneFlags.from(0));
    }

    try std.testing.expectEqual(5, v_procs.procs.size);

    // kill middle (c) - should remove c, d, e
    try v_procs.handle_process_exit(pids[2]);
    try std.testing.expectEqual(2, v_procs.procs.size);
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const parent_pid = 100;
    _ = try v_procs.handle_initial_process(parent_pid);

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        const vpid = try v_procs.handle_clone(parent_pid, child_pid, CloneFlags.from(0));
        try std.testing.expectEqual(@as(VirtualPID, @intCast(i + 1)), vpid);
    }

    try std.testing.expectEqual(11, v_procs.procs.size);
    try std.testing.expectEqual(10, v_procs.procs.get(parent_pid).?.children.size);
}

test "nested namespace - get_vpids_owned respects boundaries" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // Create structure:
    // ns1: A(vpid=1) -> B(vpid=2)
    //                   B is also ns2 root (vpid=1 in ns2)
    //                   ns2: B(vpid=1) -> C(vpid=2)

    const a_pid = 100;
    _ = try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.procs.get(a_pid).?;

    // B: child of A but root of new namespace (CLONE_NEWPID)
    const b_pid = 200;
    _ = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.procs.get(b_pid).?;

    try std.testing.expect(b_proc.is_namespace_root());
    try std.testing.expectEqual(@as(VirtualPID, 1), b_proc.vpid); // vpid 1 in ns2
    try std.testing.expect(a_proc.namespace != b_proc.namespace);

    // C: child of B in ns2
    const c_pid = 300;
    const c_vpid = try v_procs.handle_clone(b_pid, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(@as(VirtualPID, 2), c_vpid); // vpid 2 in ns2

    const c_proc = v_procs.procs.get(c_pid).?;
    try std.testing.expect(b_proc.namespace == c_proc.namespace);

    // get_vpids_owned from A should only see A and B's vpid in ns1
    // (B appears as vpid 2 in ns1's counter, but wait - B created new ns so it doesn't increment ns1)
    // Actually B is a child of A in the tree, but B has a different namespace.
    // So ns1 only contains A.
    const ns1_vpids = try a_proc.get_vpids_owned(allocator);
    defer allocator.free(ns1_vpids);
    try std.testing.expectEqual(1, ns1_vpids.len);
    try std.testing.expectEqual(@as(VirtualPID, 1), ns1_vpids[0]);

    // get_vpids_owned from B should see B and C (ns2)
    const ns2_vpids = try b_proc.get_vpids_owned(allocator);
    defer allocator.free(ns2_vpids);
    try std.testing.expectEqual(2, ns2_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[2]VirtualPID{ 1, 2 }, ns2_vpids);

    // get_vpids_owned from C should also see B and C (same namespace)
    const ns2_vpids_from_c = try c_proc.get_vpids_owned(allocator);
    defer allocator.free(ns2_vpids_from_c);
    try std.testing.expectEqual(2, ns2_vpids_from_c.len);
}

test "nested namespace - killing parent kills nested namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // ns1: A(1) -> B(ns2 root, vpid=1) -> C(vpid=2 in ns2)
    const a_pid = 100;
    _ = try v_procs.handle_initial_process(a_pid);

    const b_pid = 200;
    _ = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const c_pid = 300;
    _ = try v_procs.handle_clone(b_pid, c_pid, CloneFlags.from(0));

    try std.testing.expectEqual(3, v_procs.procs.size);

    // Kill B - should also kill C (entire subtree, crossing namespace boundary)
    try v_procs.handle_process_exit(b_pid);

    try std.testing.expectEqual(1, v_procs.procs.size);
    try std.testing.expect(v_procs.procs.get(a_pid) != null);
    try std.testing.expectEqual(null, v_procs.procs.get(b_pid));
    try std.testing.expectEqual(null, v_procs.procs.get(c_pid));
}

test "nested namespace - killing grandparent kills all" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // ns1: A -> B (ns2 root) -> C -> D (ns3 root) -> E
    const a_pid = 100;
    _ = try v_procs.handle_initial_process(a_pid);

    const b_pid = 200;
    _ = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const c_pid = 300;
    _ = try v_procs.handle_clone(b_pid, c_pid, CloneFlags.from(0));

    const d_pid = 400;
    _ = try v_procs.handle_clone(c_pid, d_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const e_pid = 500;
    _ = try v_procs.handle_clone(d_pid, e_pid, CloneFlags.from(0));

    try std.testing.expectEqual(5, v_procs.procs.size);

    // Kill A - should kill everything
    try v_procs.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, v_procs.procs.size);
}

test "pid is stored correctly" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const a_pid = 12345;
    _ = try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.procs.get(a_pid).?;
    try std.testing.expectEqual(a_pid, a_proc.pid);

    const b_pid = 67890;
    _ = try v_procs.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    const b_proc = v_procs.procs.get(b_pid).?;
    try std.testing.expectEqual(b_pid, b_proc.pid);
}
