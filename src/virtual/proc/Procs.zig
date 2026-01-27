const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const deps = @import("../../deps/deps.zig");
const proc_info = deps.proc_info;

pub const Proc = @import("Proc.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const SupervisorPID = Proc.SupervisorPID;

const ProcLookup = std.AutoHashMapUnmanaged(SupervisorPID, *Proc);

const Self = @This();

pub const CloneFlags = struct {
    raw: u64 = 0,

    /// Returns error if unsupported namespace flags are set
    pub fn checkSupported(self: CloneFlags) !void {
        if (self.raw & linux.CLONE.NEWUSER != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNET != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNS != 0) return error.UnsupportedCloneFlag;
    }

    pub fn from(raw: u64) CloneFlags {
        return .{ .raw = raw };
    }

    pub fn createPidNamespace(self: CloneFlags) bool {
        return self.raw & linux.CLONE.NEWPID != 0;
    }

    pub fn isThread(self: CloneFlags) bool {
        return self.raw & linux.CLONE.THREAD != 0;
    }

    pub fn shareParent(self: CloneFlags) bool {
        return self.raw & linux.CLONE.PARENT != 0;
    }

    pub fn shareFiles(self: CloneFlags) bool {
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
            const subtree = entry.value_ptr.*.collectSubtreeOwned(self.allocator) catch break;
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
pub fn get(self: *Self, pid: SupervisorPID) !*Proc {
    // proc already in our tree
    if (self.lookup.get(pid)) |proc| return proc;

    // proc not in our tree. It and (maybe) its ancestors need to get registered.

    // walk the kernel API until we hit a known process
    // note: must protect against escapes where init_pid is not in the lineage
    var lineage: std.ArrayList(SupervisorPID) = try .initCapacity(self.allocator, 10);
    defer lineage.deinit(self.allocator);

    var child_pid = pid;
    var nearest_registered_proc: ?*Proc = null;
    while (true) {
        try lineage.append(self.allocator, child_pid);

        // ask kernel for parent pid
        const ppid = try proc_info.readPpid(child_pid);

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
        const flags = proc_info.detectCloneFlags(current_parent.pid, child_pid);
        current_parent = try self.registerChild(current_parent, child_pid, flags);
    }

    return current_parent;
}

/// Register the initial sandbox root process
pub fn handleInitialProcess(self: *Self, pid: SupervisorPID) !void {
    if (self.lookup.count() != 0) return error.InitialProcessExists;

    // passing null namespace/fd_table creates new ones
    const root_proc = try Proc.init(self.allocator, pid, null, null, null);
    errdefer root_proc.deinit(self.allocator);

    try self.lookup.put(self.allocator, pid, root_proc);
}

/// Register a child process with given parent and flags
pub fn registerChild(self: *Self, parent: *Proc, child_pid: SupervisorPID, clone_flags: CloneFlags) !*Proc {
    try clone_flags.checkSupported();

    // CLONE_NEWPID creates a new PID namespace; otherwise inherit parent's
    const namespace: ?*Namespace = if (clone_flags.createPidNamespace())
        null // triggers new namespace creation in initChild
    else
        parent.namespace;

    // CLONE_FILES shares the fd_table; otherwise clone it
    const fd_table: *FdTable = if (clone_flags.shareFiles())
        parent.fd_table.ref()
    else
        try parent.fd_table.clone(self.allocator);
    errdefer fd_table.unref();

    const child = try parent.initChild(self.allocator, child_pid, namespace, fd_table);
    errdefer parent.deinitChild(child, self.allocator);

    try self.lookup.put(self.allocator, child_pid, child);

    return child;
}

pub fn handleProcessExit(self: *Self, pid: SupervisorPID) !void {
    const target_proc = self.lookup.get(pid) orelse return;

    // remove target from parent's children
    if (target_proc.parent) |parent| {
        parent.removeChildLink(target_proc);
    }

    // collect all descendant procs (crosses namespace boundaries)
    const descendant_procs = try target_proc.collectSubtreeOwned(self.allocator);
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
    try v_procs.handleInitialProcess(init_pid);
    try std.testing.expectEqual(1, v_procs.lookup.count());
    const proc = v_procs.lookup.get(init_pid).?;
    try std.testing.expectEqual(init_pid, proc.pid);
    try std.testing.expectEqual(null, proc.parent);
    try std.testing.expectEqual(0, proc.children.count());
    try std.testing.expect(proc.isNamespaceRoot());
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
    try v_procs.handleInitialProcess(a_pid);
    try std.testing.expectEqual(1, v_procs.lookup.count());

    const b_pid = 44;
    const a_proc = v_procs.lookup.get(a_pid).?;
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(0));
    try std.testing.expectEqual(2, v_procs.lookup.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());

    const c_pid = 55;
    _ = try v_procs.registerChild(a_proc, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expectEqual(2, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());

    const d_pid = 66;
    const c_proc = v_procs.lookup.get(c_pid).?;
    _ = try v_procs.registerChild(c_proc, d_pid, CloneFlags.from(0));
    try std.testing.expectEqual(4, v_procs.lookup.count());
    try std.testing.expectEqual(2, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(b_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(d_pid).?.children.count());

    // shrink to
    // a
    // - c
    //   - d
    try v_procs.handleProcessExit(b_pid);
    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(a_pid).?.children.count());
    try std.testing.expectEqual(1, v_procs.lookup.get(c_pid).?.children.count());
    try std.testing.expectEqual(0, v_procs.lookup.get(d_pid).?.children.count());
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid));

    // verify namespace visibility via namespace.procs
    try std.testing.expectEqual(3, v_procs.lookup.get(a_pid).?.namespace.procs.count());

    // re-add b, should work
    const b_pid_2 = 45;
    _ = try v_procs.registerChild(v_procs.lookup.get(a_pid).?, b_pid_2, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_procs.lookup.get(a_pid).?.namespace.procs.count());

    // clear whole tree
    try v_procs.handleProcessExit(a_pid);
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

    try v_procs.handleInitialProcess(100);
    try std.testing.expectError(error.InitialProcessExists, v_procs.handleInitialProcess(200));
}

test "handle_process_exit on non-existent pid is no-op" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    try v_procs.handleProcessExit(999);
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
    try v_procs.handleInitialProcess(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    const b_pid = 20;
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(0));
    const c_pid = 30;
    _ = try v_procs.registerChild(a_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;
    const d_pid = 40;
    _ = try v_procs.registerChild(c_proc, d_pid, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_procs.lookup.count());

    // kill c (intermediate) - should also remove d but preserve a and b
    try v_procs.handleProcessExit(c_pid);

    try std.testing.expectEqual(2, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(a_pid) != null);
    try std.testing.expect(v_procs.lookup.get(b_pid) != null);
    try std.testing.expectEqual(null, v_procs.lookup.get(c_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(d_pid));
}

test "namespace visibility on single node" {
    var v_procs = Self.init(std.testing.allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const proc = v_procs.lookup.get(100).?;

    try std.testing.expectEqual(1, proc.namespace.procs.count());
    try std.testing.expect(proc.namespace.contains(proc));
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    // chain: a -> b -> c -> d -> e
    var pids = [_]SupervisorPID{ 10, 20, 30, 40, 50 };

    try v_procs.handleInitialProcess(pids[0]);
    for (1..5) |i| {
        const parent = v_procs.lookup.get(pids[i - 1]).?;
        _ = try v_procs.registerChild(parent, pids[i], CloneFlags.from(0));
    }

    try std.testing.expectEqual(5, v_procs.lookup.count());

    // kill middle (c) - should remove c, d, e
    try v_procs.handleProcessExit(pids[2]);
    try std.testing.expectEqual(2, v_procs.lookup.count());
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const parent_pid = 100;
    try v_procs.handleInitialProcess(parent_pid);
    const parent = v_procs.lookup.get(parent_pid).?;

    // add 10 children
    for (1..11) |i| {
        const child_pid: SupervisorPID = @intCast(100 + i);
        _ = try v_procs.registerChild(parent, child_pid, CloneFlags.from(0));
    }

    try std.testing.expectEqual(11, v_procs.lookup.count());
    try std.testing.expectEqual(10, v_procs.lookup.get(parent_pid).?.children.count());
}

test "nested namespace - visibility rules" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Create structure:
    // ns1: A -> B (B is ns2 root with CLONE_NEWPID)
    //           ns2: B -> C

    const a_pid = 100;
    try v_procs.handleInitialProcess(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    // B: child of A but root of new namespace (CLONE_NEWPID)
    // B is PID 1 in its own namespace, 200 from root namespace view
    const b_pid = 200;
    const b_nspids = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    try std.testing.expect(b_proc.isNamespaceRoot());
    try std.testing.expect(a_proc.namespace != b_proc.namespace);

    // C: child of B in ns2
    // C is PID 2 in B's namespace, 300 from root namespace view
    const c_pid = 300;
    const c_nspids = [_]Proc.GuestPID{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, c_pid, &c_nspids);
    _ = try v_procs.registerChild(b_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;
    try std.testing.expect(b_proc.namespace == c_proc.namespace);

    // Parent namespace (ns1) can see all procs including those in child namespaces
    // This is the correct Linux behavior: parent namespaces have visibility into children
    try std.testing.expectEqual(3, a_proc.namespace.procs.count());
    try std.testing.expect(a_proc.canSee(a_proc));
    try std.testing.expect(a_proc.canSee(b_proc));
    try std.testing.expect(a_proc.canSee(c_proc));

    // Child namespace (ns2) can only see procs in its own namespace
    try std.testing.expectEqual(2, b_proc.namespace.procs.count());
    try std.testing.expect(b_proc.canSee(b_proc));
    try std.testing.expect(b_proc.canSee(c_proc));
    try std.testing.expect(!b_proc.canSee(a_proc)); // cannot see parent namespace

    // C has same visibility as B (same namespace)
    try std.testing.expectEqual(2, c_proc.namespace.procs.count());
    try std.testing.expect(c_proc.canSee(b_proc));
    try std.testing.expect(!c_proc.canSee(a_proc));
}

test "nested namespace - killing parent kills nested namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // ns1: A -> B(ns2 root) -> C
    const a_pid = 100;
    try v_procs.handleInitialProcess(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    // B: namespace root, PID 1 in its namespace
    const b_pid = 200;
    const b_nspids = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    // C: PID 2 in B's namespace
    const c_pid = 300;
    const c_nspids = [_]Proc.GuestPID{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, c_pid, &c_nspids);
    _ = try v_procs.registerChild(b_proc, c_pid, CloneFlags.from(0));

    try std.testing.expectEqual(3, v_procs.lookup.count());

    // Kill B - should also kill C (entire subtree, crossing namespace boundary)
    try v_procs.handleProcessExit(b_pid);

    try std.testing.expectEqual(1, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(a_pid) != null);
    try std.testing.expectEqual(null, v_procs.lookup.get(b_pid));
    try std.testing.expectEqual(null, v_procs.lookup.get(c_pid));
}

test "nested namespace - killing grandparent kills all" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // ns1: A -> B (ns2 root) -> C -> D (ns3 root) -> E
    const a_pid = 100;
    try v_procs.handleInitialProcess(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;

    // B: ns2 root, depth 2
    const b_pid = 200;
    const b_nspids = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    // C: in ns2, depth 2
    const c_pid = 300;
    const c_nspids = [_]Proc.GuestPID{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, c_pid, &c_nspids);
    _ = try v_procs.registerChild(b_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;

    // D: ns3 root, depth 3
    const d_pid = 400;
    const d_nspids = [_]Proc.GuestPID{ 400, 3, 1 };
    try proc_info.testing.setupNsPids(allocator, d_pid, &d_nspids);
    _ = try v_procs.registerChild(c_proc, d_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const d_proc = v_procs.lookup.get(d_pid).?;

    // E: in ns3, depth 3
    const e_pid = 500;
    const e_nspids = [_]Proc.GuestPID{ 500, 4, 2 };
    try proc_info.testing.setupNsPids(allocator, e_pid, &e_nspids);
    _ = try v_procs.registerChild(d_proc, e_pid, CloneFlags.from(0));

    try std.testing.expectEqual(5, v_procs.lookup.count());

    // Kill A - should kill everything
    try v_procs.handleProcessExit(a_pid);
    try std.testing.expectEqual(0, v_procs.lookup.count());
}

test "pid is stored correctly" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    const a_pid = 12345;
    try v_procs.handleInitialProcess(a_pid);
    const a_proc = v_procs.lookup.get(a_pid).?;
    try std.testing.expectEqual(a_pid, a_proc.pid);

    const b_pid = 67890;
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(0));
    const b_proc = v_procs.lookup.get(b_pid).?;
    try std.testing.expectEqual(b_pid, b_proc.pid);
}

test "can_see - same namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const a = v_procs.lookup.get(100).?;
    _ = try v_procs.registerChild(a, 200, CloneFlags.from(0));
    const b = v_procs.lookup.get(200).?;

    try std.testing.expect(a.canSee(b));
    try std.testing.expect(b.canSee(a));
}

test "can_see - child namespace cannot see parent-only procs" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    try v_procs.handleInitialProcess(100);
    const a = v_procs.lookup.get(100).?;

    // B is in new namespace (depth 2)
    const b_nspids = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &b_nspids);
    _ = try v_procs.registerChild(a, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const b = v_procs.lookup.get(200).?;

    // A can see B (B is registered in parent namespace too)
    try std.testing.expect(a.canSee(b));
    // B cannot see A (A is only in parent namespace)
    try std.testing.expect(!b.canSee(a));
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
    try v_procs.handleInitialProcess(100);
    try std.testing.expectEqual(1, v_procs.lookup.count());

    // Setup mock: grandchild 300 has parent 200, child 200 has parent 100
    try proc_info.testing.setupParent(allocator, 300, 200);
    try proc_info.testing.setupParent(allocator, 200, 100);

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
    try v_procs.handleInitialProcess(100);

    // Setup mock relationships:
    // 100 -> 200 -> 300
    // 100 -> 201
    try proc_info.testing.setupParent(allocator, 300, 200);
    try proc_info.testing.setupParent(allocator, 200, 100);
    try proc_info.testing.setupParent(allocator, 201, 100);

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
    try v_procs.handleInitialProcess(100);

    // Setup mock: chain 400 -> 300 -> 200 -> 100
    try proc_info.testing.setupParent(allocator, 400, 300);
    try proc_info.testing.setupParent(allocator, 300, 200);
    try proc_info.testing.setupParent(allocator, 200, 100);

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
    try v_procs.handleInitialProcess(100);

    // Setup mock: 200 is child of 100 with CLONE_NEWPID
    try proc_info.testing.setupParent(allocator, 200, 100);
    try proc_info.testing.setupCloneFlags(allocator, 200, CloneFlags.from(linux.CLONE.NEWPID));
    // 200 is in a new namespace (depth 2), PID 1 in its own namespace
    const nspids_200 = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &nspids_200);

    // Child 200 syscalls - should be in new namespace
    const proc_200 = try v_procs.get(200);
    const proc_100 = v_procs.lookup.get(100).?;

    try std.testing.expect(proc_200.isNamespaceRoot());
    try std.testing.expect(proc_100.namespace != proc_200.namespace);
}

test "out-of-order fails for process outside sandbox escaping to 1" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handleInitialProcess(100);

    // Setup mock: 300 has parent 200, but 200's parent (999) is not in sandbox
    try proc_info.testing.setupParent(allocator, 300, 200);
    try proc_info.testing.setupParent(allocator, 200, 999);
    // Note: 999 is not in our sandbox, its lineage escapes up to pid 1 or 0
    try proc_info.testing.setupParent(allocator, 999, 1);
    try proc_info.testing.setupParent(allocator, 1, 0);

    // 300 syscalls - should fail because chain leads outside sandbox
    try std.testing.expectError(error.ProcNotInSandbox, v_procs.get(300));
}

test "out-of-order fails for process outside sandbox escaping to nonexistant kernel pid" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register root process 100
    try v_procs.handleInitialProcess(100);

    // Setup mock: 300 has parent 200, but 200's parent (999) is not in sandbox
    try proc_info.testing.setupParent(allocator, 300, 200);
    try proc_info.testing.setupParent(allocator, 200, 999);
    // say 999 has no parent in the kernel

    // 300 syscalls - should fail because chain fails due to proc not in kernel
    try std.testing.expectError(error.ProcNotInKernel, v_procs.get(300));
}

test "deep namespace hierarchy (10 levels)" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    const DEPTH = 10;

    // Create a chain: ns0 -> ns1 -> ns2 -> ... -> ns9
    // Each level has one process that is the root of a new namespace
    var pids: [DEPTH]Proc.SupervisorPID = undefined;
    var procs: [DEPTH]*Proc = undefined;

    // Root process (depth 1)
    pids[0] = 1000;
    try v_procs.handleInitialProcess(pids[0]);
    procs[0] = v_procs.lookup.get(pids[0]).?;

    // Create nested namespaces
    for (1..DEPTH) |i| {
        pids[i] = @intCast(1000 + i);

        // Build NSpid array: [pid_as_seen_from_ns0, ..., pid_as_seen_from_own_ns]
        // For depth i+1, we need i+1 entries
        var nspid_buf: [DEPTH]Proc.GuestPID = undefined;
        for (0..i + 1) |j| {
            // From ancestor namespace j's view, this proc has a certain PID
            // For simplicity: from ns_j, the PID is (1000 + i) - j
            // This simulates different PIDs in different namespaces
            nspid_buf[j] = @intCast(pids[i] - @as(Proc.SupervisorPID, @intCast(j)));
        }
        try proc_info.testing.setupNsPids(allocator, pids[i], nspid_buf[0 .. i + 1]);

        _ = try v_procs.registerChild(procs[i - 1], pids[i], CloneFlags.from(linux.CLONE.NEWPID));
        procs[i] = v_procs.lookup.get(pids[i]).?;

        // Verify namespace is different from parent
        try std.testing.expect(procs[i].namespace != procs[i - 1].namespace);
        try std.testing.expect(procs[i].isNamespaceRoot());
    }

    // Verify visibility rules:
    // Root namespace (ns0) should see ALL processes
    try std.testing.expectEqual(DEPTH, procs[0].namespace.procs.count());

    // Each namespace should see fewer processes as we go deeper
    for (1..DEPTH) |i| {
        const expected_visible = DEPTH - i;
        try std.testing.expectEqual(expected_visible, procs[i].namespace.procs.count());

        // Can see self and descendants
        for (i..DEPTH) |j| {
            try std.testing.expect(procs[i].canSee(procs[j]));
        }
        // Cannot see ancestors
        for (0..i) |j| {
            try std.testing.expect(!procs[i].canSee(procs[j]));
        }
    }

    // Kill middle of chain (ns4) - should kill ns4 through ns9
    try v_procs.handleProcessExit(pids[4]);

    // Only ns0-ns3 remain
    try std.testing.expectEqual(4, v_procs.lookup.count());
    for (0..4) |i| {
        try std.testing.expect(v_procs.lookup.get(pids[i]) != null);
    }
    for (4..DEPTH) |i| {
        try std.testing.expect(v_procs.lookup.get(pids[i]) == null);
    }
}

test "wide tree with many processes per namespace" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    const CHILDREN_PER_LEVEL = 20;

    // Root process
    const root_pid: Proc.SupervisorPID = 1;
    try v_procs.handleInitialProcess(root_pid);
    const root = v_procs.lookup.get(root_pid).?;

    var total_procs: usize = 1; // root

    // Level 1: 20 children of root (same namespace)
    var level1_procs: [CHILDREN_PER_LEVEL]*Proc = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        const pid: Proc.SupervisorPID = @intCast(100 + i);
        _ = try v_procs.registerChild(root, pid, CloneFlags.from(0));
        level1_procs[i] = v_procs.lookup.get(pid).?;
        total_procs += 1;
    }

    // Level 2: Each level1 proc has 20 children (same namespace)
    var level2_procs: [CHILDREN_PER_LEVEL][CHILDREN_PER_LEVEL]*Proc = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        for (0..CHILDREN_PER_LEVEL) |j| {
            const pid: Proc.SupervisorPID = @intCast(1000 + i * 100 + j);
            _ = try v_procs.registerChild(level1_procs[i], pid, CloneFlags.from(0));
            level2_procs[i][j] = v_procs.lookup.get(pid).?;
            total_procs += 1;
        }
    }

    // Verify total count: 1 + 20 + 20*20 = 421
    const expected_total = 1 + CHILDREN_PER_LEVEL + CHILDREN_PER_LEVEL * CHILDREN_PER_LEVEL;
    try std.testing.expectEqual(expected_total, total_procs);
    try std.testing.expectEqual(expected_total, v_procs.lookup.count());

    // All in same namespace, so everyone should see everyone
    try std.testing.expectEqual(expected_total, root.namespace.procs.count());

    // Kill one level1 proc, which should kill it and its 20 children
    try v_procs.handleProcessExit(level1_procs[5].pid);
    try std.testing.expectEqual(expected_total - 1 - CHILDREN_PER_LEVEL, v_procs.lookup.count());
}

test "mixed namespaces: some shared, some isolated" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Structure:
    // ns0: root(1) -> A(10), B(20), C(30)
    //                  |       |
    //                  v       v
    //          ns1: A1(11) -> A2(12)    ns2: B1(21) -> B2(22)
    //                                          |
    //                                          v
    //                                  ns3: B1a(211)

    // Root namespace
    try v_procs.handleInitialProcess(1);
    const root = v_procs.lookup.get(1).?;

    // A, B, C in root namespace
    _ = try v_procs.registerChild(root, 10, CloneFlags.from(0));
    const proc_a = v_procs.lookup.get(10).?;
    _ = try v_procs.registerChild(root, 20, CloneFlags.from(0));
    const proc_b = v_procs.lookup.get(20).?;
    _ = try v_procs.registerChild(root, 30, CloneFlags.from(0));
    const proc_c = v_procs.lookup.get(30).?;

    // ns1: A's children in new namespace
    const a1_nspids = [_]Proc.GuestPID{ 11, 1 };
    try proc_info.testing.setupNsPids(allocator, 11, &a1_nspids);
    _ = try v_procs.registerChild(proc_a, 11, CloneFlags.from(linux.CLONE.NEWPID));
    const proc_a1 = v_procs.lookup.get(11).?;

    const a2_nspids = [_]Proc.GuestPID{ 12, 2 };
    try proc_info.testing.setupNsPids(allocator, 12, &a2_nspids);
    _ = try v_procs.registerChild(proc_a1, 12, CloneFlags.from(0));
    const proc_a2 = v_procs.lookup.get(12).?;

    // ns2: B's children in new namespace
    const b1_nspids = [_]Proc.GuestPID{ 21, 1 };
    try proc_info.testing.setupNsPids(allocator, 21, &b1_nspids);
    _ = try v_procs.registerChild(proc_b, 21, CloneFlags.from(linux.CLONE.NEWPID));
    const proc_b1 = v_procs.lookup.get(21).?;

    const b2_nspids = [_]Proc.GuestPID{ 22, 2 };
    try proc_info.testing.setupNsPids(allocator, 22, &b2_nspids);
    _ = try v_procs.registerChild(proc_b1, 22, CloneFlags.from(0));

    // ns3: nested inside ns2
    const b1a_nspids = [_]Proc.GuestPID{ 211, 3, 1 }; // seen as 211 from ns0, 3 from ns2, 1 from ns3
    try proc_info.testing.setupNsPids(allocator, 211, &b1a_nspids);
    _ = try v_procs.registerChild(proc_b1, 211, CloneFlags.from(linux.CLONE.NEWPID));
    const proc_b1a = v_procs.lookup.get(211).?;

    // Total: 9 processes (root, A, B, C, A1, A2, B1, B2, B1a)
    try std.testing.expectEqual(9, v_procs.lookup.count());

    // Verify namespace counts:
    // ns0 (root): sees all 9
    try std.testing.expectEqual(9, root.namespace.procs.count());

    // ns1 (A's namespace): sees A1, A2 = 2
    try std.testing.expectEqual(2, proc_a1.namespace.procs.count());
    try std.testing.expect(proc_a1.namespace == proc_a2.namespace);

    // ns2 (B's namespace): sees B1, B2, B1a = 3
    try std.testing.expectEqual(3, proc_b1.namespace.procs.count());

    // ns3 (B1a's namespace): sees only B1a = 1
    try std.testing.expectEqual(1, proc_b1a.namespace.procs.count());

    // Cross-namespace visibility
    // Root can see everything
    try std.testing.expect(root.canSee(proc_a));
    try std.testing.expect(root.canSee(proc_a1));
    try std.testing.expect(root.canSee(proc_b1a));

    // A1 cannot see root or B's subtree
    try std.testing.expect(!proc_a1.canSee(root));
    try std.testing.expect(!proc_a1.canSee(proc_b));
    try std.testing.expect(!proc_a1.canSee(proc_b1));

    // B1 can see B1a (descendant namespace) but not A1 (sibling namespace)
    try std.testing.expect(proc_b1.canSee(proc_b1a));
    try std.testing.expect(!proc_b1.canSee(proc_a1));

    // C is isolated, so shares root namespace but has no children
    try std.testing.expect(proc_c.canSee(root));
    try std.testing.expect(proc_c.canSee(proc_a));
    try std.testing.expect(proc_c.canSee(proc_a1));

    // Kill A, which should kill A, A1, A2 (entire subtree), showing 9 - 3 = 6
    try v_procs.handleProcessExit(10);
    try std.testing.expectEqual(6, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(10) == null);
    try std.testing.expect(v_procs.lookup.get(11) == null);
    try std.testing.expect(v_procs.lookup.get(12) == null);

    // Kill B1, which should kill B1, B2, B1a, giving 6 - 3 = 3
    try v_procs.handleProcessExit(21);
    try std.testing.expectEqual(3, v_procs.lookup.count());

    // Only root, B, C should remain
    try std.testing.expect(v_procs.lookup.get(1) != null);
    try std.testing.expect(v_procs.lookup.get(20) != null);
    try std.testing.expect(v_procs.lookup.get(30) != null);
}

test "stress: verify GuestPID mapping correctness across namespaces" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Create: root(100) -> child(200) in new namespace
    // NSpid for child: [200, 1] meaning:
    //   - From root namespace: GuestPID = 200
    //   - From child's own namespace: GuestPID = 1

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;

    const child_nspids = [_]Proc.GuestPID{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &child_nspids);
    _ = try v_procs.registerChild(root, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const child = v_procs.lookup.get(200).?;

    // Verify GuestPID from each namespace's perspective
    // From root namespace, child's GuestPID should be 200
    const child_gpid_from_root = root.namespace.getGuestPID(child);
    try std.testing.expectEqual(@as(?Proc.GuestPID, 200), child_gpid_from_root);

    // From child's namespace, child's GuestPID should be 1
    const child_gpid_from_self = child.namespace.getGuestPID(child);
    try std.testing.expectEqual(@as(?Proc.GuestPID, 1), child_gpid_from_self);

    // Root should not be visible from child's namespace
    const root_gpid_from_child = child.namespace.getGuestPID(root);
    try std.testing.expectEqual(@as(?Proc.GuestPID, null), root_gpid_from_child);

    // Root's GuestPID from root namespace should be 100
    const root_gpid_from_self = root.namespace.getGuestPID(root);
    try std.testing.expectEqual(@as(?Proc.GuestPID, 100), root_gpid_from_self);

    // Add grandchild: child(200) -> grandchild(300) in same namespace as child
    // NSpid for grandchild: [300, 2] meaning:
    //   - From root namespace: GuestPID = 300
    //   - From child's namespace: GuestPID = 2
    const grandchild_nspids = [_]Proc.GuestPID{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, 300, &grandchild_nspids);
    _ = try v_procs.registerChild(child, 300, CloneFlags.from(0));
    const grandchild = v_procs.lookup.get(300).?;

    // Grandchild should be in same namespace as child
    try std.testing.expect(grandchild.namespace == child.namespace);

    // Verify GuestPID of grandchild
    //  from root's perspective
    const gc_gpid_from_root = root.namespace.getGuestPID(grandchild);
    try std.testing.expectEqual(@as(?Proc.GuestPID, 300), gc_gpid_from_root);

    //  from child's perspective
    const gc_gpid_from_child_ns = child.namespace.getGuestPID(grandchild);
    try std.testing.expectEqual(@as(?Proc.GuestPID, 2), gc_gpid_from_child_ns);

    // Lookup by GuestPID from child's namespace
    const found_child = child.namespace.procs.get(1);
    try std.testing.expectEqual(child, found_child);

    const found_grandchild = child.namespace.procs.get(2);
    try std.testing.expectEqual(grandchild, found_grandchild);
}
