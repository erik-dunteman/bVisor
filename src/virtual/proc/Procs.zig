const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const deps = @import("../../deps/deps.zig");
const proc_info = deps.proc_info;

pub const Proc = @import("Proc.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const KernelPID = Proc.KernelPID;

const ProcLookup = std.AutoHashMapUnmanaged(KernelPID, *Proc);

const Self = @This();

pub const CloneFlags = struct {
    raw: u64 = 0,

    /// Returns error if unsupported namespace flags are set
    pub fn check_supported(self: CloneFlags) !void {
        if (self.raw & linux.CLONE.NEWUSER != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNET != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNS != 0) return error.UnsupportedCloneFlag;
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

// flat list of mappings from kernel PID to Proc
// owns underlying procs
lookup: ProcLookup = .empty,

pub fn init(allocator: Allocator) Self {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    var iter = self.lookup.iterator();
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
    self.lookup.deinit(self.allocator);
}

/// Get a proc by kernel PID. Performs a kernel lookup for unknown children.
pub fn get(self: *Self, pid: KernelPID) !*Proc {
    // proc already in our tree
    if (self.lookup.get(pid)) |proc| return proc;

    // proc not in our tree. It and (maybe) its ancestors need to get registered.

    // walk the kernel API until we hit a known process
    // note: must protect against escapes where init_pid is not in the lineage
    var lineage: std.ArrayList(KernelPID) = try .initCapacity(self.allocator, 10);
    defer lineage.deinit(self.allocator);

    var child_pid = pid;
    var nearest_registered_proc: ?*Proc = null;
    while (true) {
        try lineage.append(self.allocator, child_pid);

        // ask kernel for parent pid
        const ppid = try proc_info.read_ppid(child_pid);

        // check if parent in our tree
        if (self.lookup.get(ppid)) |parent_proc| {
            // no need to walk higher
            nearest_registered_proc = parent_proc;
            break;
        }

        if (ppid <= 1) return error.ProcNotInSandbox; // escaped past init_pid

        child_pid = ppid;
    }

    if (nearest_registered_proc == null) unreachable;

    // if no error, lineage is fully in sandbox
    // register any unknown procs in reverse order
    var current_parent = nearest_registered_proc.?;
    var i = lineage.items.len;
    while (i > 0) : (i -= 1) {
        child_pid = lineage.items[i - 1];
        const flags = proc_info.detect_clone_flags(current_parent.pid, child_pid);
        current_parent = try self.register_child(current_parent, child_pid, flags);
    }

    return current_parent;
}

/// Register the initial sandbox root process
pub fn handle_initial_process(self: *Self, pid: KernelPID) !void {
    if (self.lookup.count() != 0) return error.InitialProcessExists;

    // passing null namespace/fd_table creates new ones
    const root_proc = try Proc.init(self.allocator, pid, null, null, null);
    errdefer root_proc.deinit(self.allocator);

    try self.lookup.put(self.allocator, pid, root_proc);
}

/// Register a child process with given parent and flags
pub fn register_child(self: *Self, parent: *Proc, child_pid: KernelPID, clone_flags: CloneFlags) !*Proc {
    try clone_flags.check_supported();

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

    try self.lookup.put(self.allocator, child_pid, child);

    return child;
}

pub fn handle_process_exit(self: *Self, pid: KernelPID) !void {
    const target_proc = self.lookup.get(pid) orelse return;

    // remove target from parent's children
    if (target_proc.parent) |parent| {
        parent.remove_child_link(target_proc);
    }

    // collect all descendant procs (crosses namespace boundaries)
    const descendant_procs = try target_proc.collect_subtree_owned(self.allocator);
    defer self.allocator.free(descendant_procs);

    // remove from lookup table and deinit each proc
    for (descendant_procs) |proc| {
        _ = self.lookup.remove(proc.pid);
        proc.deinit(self.allocator);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "state is correct after initial proc" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();
    try std.testing.expect(v_procs.lookup.count() == 0);

    const init_pid = 22;
    try v_procs.handle_initial_process(init_pid);
    try std.testing.expectEqual(1, v_procs.lookup.count());
    const proc = v_procs.lookup.get(init_pid).?;
    try std.testing.expectEqual(init_pid, proc.pid);
    try std.testing.expectEqual(null, proc.parent);
    try std.testing.expectEqual(0, proc.children.count());
    try std.testing.expect(proc.is_namespace_root());
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    try std.testing.expectEqual(0, v_procs.lookup.count());

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    try v_procs.handle_initial_process(a_pid);
    try std.testing.expectEqual(1, v_procs.lookup.count());

    const b_pid = 44;
    const a_proc = v_procs.lookup.get(a_pid).?;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(0));
    try std.testing.expectEqual(2, v_procs.lookup.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());

    const c_pid = 55;
    _ = try v_procs.register_child(a_proc, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expectEqual(2, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());

    const d_pid = 66;
    const c_proc = v_procs.lookup.get(c_pid).?;
    _ = try v_procs.register_child(c_proc, d_pid, CloneFlags.from(0));
    try std.testing.expectEqual(4, v_procs.lookup.count());
    try std.testing.expectEqual(2, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(d_pid).?.children.count());

    // shrink to
    // a
    // - c
    //   - d
    try v_procs.handle_process_exit(b_pid);
    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(d_pid).?.children.count());
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid));

    // get pids
    var a_pids = try v_procs.lookup.get(a_pid).?.get_pids_owned(allocator);
    try std.testing.expectEqual(3, a_pids.len);
    try std.testing.expectEqualSlices(KernelPID, &[3]KernelPID{ 33, 55, 66 }, a_pids);
    allocator.free(a_pids);

    // re-add b, should work
    const b_pid_2 = 45;
    _ = try v_procs.register_child(v_procs.lookup.get(a_pid).?, b_pid_2, CloneFlags.from(0));

    a_pids = try v_procs.lookup.get(a_pid).?.get_pids_owned(allocator);
    defer allocator.free(a_pids);
    try std.testing.expectEqual(4, a_pids.len);
    try std.testing.expectEqualSlices(KernelPID, &[4]KernelPID{ 33, 45, 55, 66 }, a_pids);

    // clear whole tree
    try v_procs.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, v_procs.lookup.count());
    try std.testing.expectEqual(null, v_procs.lookup.get(a_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid_2));
    try std.testing.expectEqual(null, v_procs.lookup.get(c_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(d_pid));
}

test "handle_initial_process fails if already registered" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    try v_procs.handle_initial_process(100);
    try std.testing.expectError(error.InitialProcessExists, v_procs.handle_initial_process(200));
}

test "handle_process_exit on non-existent pid is no-op" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    try v_procs.handle_initial_process(100);
    try v_procs.handle_process_exit(999);
    try std.testing.expectEqual(1, v_procs.lookup.count());
}

test "kill intermediate node removes subtree but preserves siblings" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    const b_pid = 20;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(0));
    const c_pid = 30;
    _ = try v_procs.register_child(a_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;
    const d_pid = 40;
    _ = try v_procs.register_child(c_proc, d_pid, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_procs.lookup.count());

    // kill c (intermediate) - should also remove d but preserve a and b
    try v_procs.handle_process_exit(c_pid);

    try std.testing.expectEqual(2, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(a_pid) != null);
    try std.testing.expect(v_procs.lookup.get(b_pid) != null);
    try std.testing.expectEqual(null, v_procs.lookup.get(c_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    try v_procs.handle_initial_process(100);
    const proc = v_procs.lookup.get(100).?;

    const pids = try proc.get_pids_owned(allocator);
    defer allocator.free(pids);

    try std.testing.expectEqual(1, pids.len);
    try std.testing.expectEqual(100, pids[0]);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // chain: a -> b -> c -> d -> e
    var pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    try v_procs.handle_initial_process(pids[0]);
    for (1..5) |i| {
        const parent = v_procs.lookup.get(pids[i - 1]).?;
        _ = try v_procs.register_child(parent, pids[i], CloneFlags.from(0));
    }

    try std.testing.expectEqual(5, v_procs.lookup.count());

    // kill middle (c) - should remove c, d, e
    try v_procs.handle_process_exit(pids[2]);
    try std.testing.expectEqual(2, v_procs.lookup.count());
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const parent_pid = 100;
    try v_procs.handle_initial_process(parent_pid);
    const parent = v_procs.lookup.get(parent_pid).?;

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        _ = try v_procs.register_child(parent, child_pid, CloneFlags.from(0));
    }

    try std.testing.expectEqual(11, v_procs.lookup.count());
    try std.testing.expectEqual(10, v_procs.lookup.get(parent_pid).?.children.count());
}

test "nested namespace - get_pids_owned respects boundaries" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // Create structure:
    // ns1: A -> B (B is ns2 root with CLONE_NEWPID)
    //           ns2: B -> C

    const a_pid = 100;
    try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    // B: child of A but root of new namespace (CLONE_NEWPID)
    const b_pid = 200;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    try std.testing.expect(b_proc.is_namespace_root());
    try std.testing.expect(a_proc.namespace != b_proc.namespace);

    // C: child of B in ns2
    const c_pid = 300;
    _ = try v_procs.register_child(b_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;
    try std.testing.expect(b_proc.namespace == c_proc.namespace);

    // get_pids_owned from A should only see A (B created new ns)
    const ns1_pids = try a_proc.get_pids_owned(allocator);
    defer allocator.free(ns1_pids);
    try std.testing.expectEqual(1, ns1_pids.len);
    try std.testing.expectEqual(a_pid, ns1_pids[0]);

    // get_pids_owned from B should see B and C (ns2)
    const ns2_pids = try b_proc.get_pids_owned(allocator);
    defer allocator.free(ns2_pids);
    try std.testing.expectEqual(2, ns2_pids.len);
    try std.testing.expectEqualSlices(KernelPID, &[2]KernelPID{ 200, 300 }, ns2_pids);

    // get_pids_owned from C should also see B and C (same namespace)
    const ns2_pids_from_c = try c_proc.get_pids_owned(allocator);
    defer allocator.free(ns2_pids_from_c);
    try std.testing.expectEqual(2, ns2_pids_from_c.len);
}

test "nested namespace - killing parent kills nested namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // ns1: A -> B(ns2 root) -> C
    const a_pid = 100;
    try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    const b_pid = 200;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    const c_pid = 300;
    _ = try v_procs.register_child(b_proc, c_pid, CloneFlags.from(0));

    try std.testing.expectEqual(3, v_procs.lookup.count());

    // Kill B - should also kill C (entire subtree, crossing namespace boundary)
    try v_procs.handle_process_exit(b_pid);

    try std.testing.expectEqual(1, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(a_pid) != null);
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(c_pid));
}

test "nested namespace - killing grandparent kills all" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // ns1: A -> B (ns2 root) -> C -> D (ns3 root) -> E
    const a_pid = 100;
    try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    const b_pid = 200;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    const c_pid = 300;
    _ = try v_procs.register_child(b_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;

    const d_pid = 400;
    _ = try v_procs.register_child(c_proc, d_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const d_proc = v_procs.lookup.get(d_pid).?;

    const e_pid = 500;
    _ = try v_procs.register_child(d_proc, e_pid, CloneFlags.from(0));

    try std.testing.expectEqual(5, v_procs.lookup.count());

    // Kill A - should kill everything
    try v_procs.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, v_procs.lookup.count());
}

test "pid is stored correctly" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const a_pid = 12345;
    try v_procs.handle_initial_process(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;
    try std.testing.expectEqual(a_pid, a_proc.pid);

    const b_pid = 67890;
    _ = try v_procs.register_child(a_proc, b_pid, CloneFlags.from(0));
    const b_proc = v_procs.lookup.get(b_pid).?;
    try std.testing.expectEqual(b_pid, b_proc.pid);
}

test "can_see - same namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    try v_procs.handle_initial_process(100);
    const a = v_procs.lookup.get(100).?;
    _ = try v_procs.register_child(a, 200, CloneFlags.from(0));
    const b = v_procs.lookup.get(200).?;

    try std.testing.expect(a.can_see(b));
    try std.testing.expect(b.can_see(a));
}

test "can_see - child namespace cannot see parent-only procs" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    try v_procs.handle_initial_process(100);
    const a = v_procs.lookup.get(100).?;

    // B is in new namespace
    _ = try v_procs.register_child(a, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const b = v_procs.lookup.get(200).?;

    // A can see B (B is registered in parent namespace too)
    try std.testing.expect(a.can_see(b));
    // B cannot see A (A is only in parent namespace)
    try std.testing.expect(!b.can_see(a));
}

// ============================================================================
// Out-of-Order Discovery Tests (using mocked proc_info)
// ============================================================================

test "grandchild syscalls before child - recursive registration" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);
    try std.testing.expectEqual(1, v_procs.lookup.count());

    // Setup mock: grandchild 300 has parent 200, child 200 has parent 100
    try proc_info.testing.setup_parent(allocator, 300, 200);
    try proc_info.testing.setup_parent(allocator, 200, 100);

    // Grandchild 300 makes a syscall - triggers recursive registration
    const proc_300 = try v_procs.get(300);

    // Both 200 and 300 should now be registered
    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(100) != null);
    try std.testing.expect(v_procs.lookup.get(200) != null);
    try std.testing.expect(v_procs.lookup.get(300) != null);

    // Verify parent-child relationships
    const proc_200 = v_procs.lookup.get(200).?;
    const proc_100 = v_procs.lookup.get(100).?;
    try std.testing.expectEqual(proc_100, proc_200.parent.?);
    try std.testing.expectEqual(proc_200, proc_300.parent.?);
}

test "multiple children - grandchild first, then siblings" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);

    // Setup mock relationships:
    // 100 -> 200 -> 300
    // 100 -> 201
    try proc_info.testing.setup_parent(allocator, 300, 200);
    try proc_info.testing.setup_parent(allocator, 200, 100);
    try proc_info.testing.setup_parent(allocator, 201, 100);

    // Grandchild 300 syscalls first (discovers 200 recursively)
    _ = try v_procs.get(300);
    try std.testing.expectEqual(3, v_procs.lookup.count());

    // Child 200 syscalls - already registered
    _ = try v_procs.get(200);
    try std.testing.expectEqual(3, v_procs.lookup.count());

    // Sibling 201 syscalls - new registration
    _ = try v_procs.get(201);
    try std.testing.expectEqual(4, v_procs.lookup.count());

    // Verify tree structure
    const proc_100 = v_procs.lookup.get(100).?;
    try std.testing.expectEqual(2, proc_100.children.count()); // 200 and 201
}

test "deep chain discovery - great-grandchild first" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);

    // Setup mock: chain 400 -> 300 -> 200 -> 100
    try proc_info.testing.setup_parent(allocator, 400, 300);
    try proc_info.testing.setup_parent(allocator, 300, 200);
    try proc_info.testing.setup_parent(allocator, 200, 100);

    // Great-grandchild 400 syscalls - triggers recursive registration of entire chain
    _ = try v_procs.get(400);

    // All four should be registered
    try std.testing.expectEqual(4, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(100) != null);
    try std.testing.expect(v_procs.lookup.get(200) != null);
    try std.testing.expect(v_procs.lookup.get(300) != null);
    try std.testing.expect(v_procs.lookup.get(400) != null);

    // Verify chain structure
    const proc_400 = v_procs.lookup.get(400).?;
    const proc_300 = v_procs.lookup.get(300).?;
    const proc_200 = v_procs.lookup.get(200).?;
    const proc_100 = v_procs.lookup.get(100).?;

    try std.testing.expectEqual(proc_300, proc_400.parent.?);
    try std.testing.expectEqual(proc_200, proc_300.parent.?);
    try std.testing.expectEqual(proc_100, proc_200.parent.?);
    try std.testing.expectEqual(null, proc_100.parent);
}

test "out-of-order with clone flags" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);

    // Setup mock: 200 is child of 100 with CLONE_NEWPID
    try proc_info.testing.setup_parent(allocator, 200, 100);
    try proc_info.testing.setup_clone_flags(allocator, 200, CloneFlags.from(linux.CLONE.NEWPID));

    // Child 200 syscalls - should be in new namespace
    const proc_200 = try v_procs.get(200);
    const proc_100 = v_procs.lookup.get(100).?;

    try std.testing.expect(proc_200.is_namespace_root());
    try std.testing.expect(proc_100.namespace != proc_200.namespace);
}

test "out-of-order fails for process outside sandbox escaping to 1" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);

    // Setup mock: 300 has parent 200, but 200's parent (999) is not in sandbox
    try proc_info.testing.setup_parent(allocator, 300, 200);
    try proc_info.testing.setup_parent(allocator, 200, 999);
    // Note: 999 is not in our sandbox, its lineage escapes up to pid 1 or 0
    try proc_info.testing.setup_parent(allocator, 999, 1);
    try proc_info.testing.setup_parent(allocator, 1, 0);

    // 300 syscalls - should fail because chain leads outside sandbox
    try std.testing.expectError(error.ProcNotInSandbox, v_procs.get(300));
}

test "out-of-order fails for process outside sandbox escaping to nonexistant kernel pid" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handle_initial_process(100);

    // Setup mock: 300 has parent 200, but 200's parent (999) is not in sandbox
    try proc_info.testing.setup_parent(allocator, 300, 200);
    try proc_info.testing.setup_parent(allocator, 200, 999);
    // say 999 has no parent in the kernel

    // 300 syscalls - should fail because chain fails due to proc not in kernel
    try std.testing.expectError(error.ProcNotInKernel, v_procs.get(300));
}
