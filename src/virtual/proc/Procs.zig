const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const deps = @import("../../deps/deps.zig");
const proc_info = deps.proc_info;

pub const Proc = @import("Proc.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const AbsPid = Proc.AbsPid;
pub const NsPid = Proc.NsPid;
pub const ProcStatus = @import("ProcStatus.zig");
pub const detectCloneFlags = proc_info.detectCloneFlags;
pub const getStatus = proc_info.getStatus;
pub const listPids = proc_info.listPids;

const ProcLookup = std.AutoHashMapUnmanaged(AbsPid, *Proc);

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

/// Get the process of this pid from self.lookup
///
/// This is a hotpath for most syscalls, so we try to avoid syncing with the kernel unless necessary.
/// Syncs happen only if the initial lookup fails.
pub fn get(self: *Self, pid: AbsPid) !*Proc {
    // Initial lookup
    if (self.lookup.get(pid)) |proc| return proc;

    // Initial lookup failed, try lazy register
    try self.syncNewProcs();
    if (self.lookup.get(pid)) |proc| return proc;

    // Still not found, give up
    return error.ProcNotRegistered;
}

/// Get the process from an NsPid via a reference proc's namespace
///
/// This is a hotpath for any NsPid-targeting syscalls like kill and waitpid,
/// So syncs with kernel only happen if initial lookup fails.
pub fn getNamespaced(self: *Self, ref_proc: *Proc, nspid: NsPid) !*Proc {
    // Initial lookup
    if (ref_proc.namespace.procs.get(nspid)) |proc| return proc;

    // Initial lookup failed, try lazy register
    try self.syncNewProcs();
    if (ref_proc.namespace.procs.get(nspid)) |proc| return proc;

    // Still not found, give up
    return error.ProcNotRegistered;
}

/// Recursive lazy registration of processes if necessary
fn ensureRegistered(
    self: *Self,
    status_map: *std.AutoHashMap(AbsPid, ProcStatus),
    pid: AbsPid,
) !void {
    // If already registered, done
    if (self.lookup.contains(pid)) return;

    // Get cached status (ppid and namespace info)
    const status = status_map.get(pid) orelse return error.ProcNotInKernel;
    const ppid = status.ppid;

    // Ensure parent is registered first (recursive call)
    if (!self.lookup.contains(ppid)) {
        // Stop recursion if we've reached init or outside sandbox
        if (ppid <= 1) return error.ProcNotInSandbox;
        try self.ensureRegistered(status_map, ppid);
    }

    // Get the parent proc (must be registered now)
    const parent = self.lookup.get(ppid) orelse return error.ParentNotRegistered;

    // Detect clone flags and register this process
    const flags = detectCloneFlags(ppid, pid);
    _ = try self.registerChild(parent, pid, flags);
}

/// Confer with the kernel to check for any guest processes
/// which might need to be lazily added.
///
/// This scans /proc once to collect status for all PIDs, then recursively
/// registers any missing processes using the cached status data.
pub fn syncNewProcs(
    self: *Self,
) !void {
    var status_map = std.AutoHashMap(AbsPid, ProcStatus).init(self.allocator);
    defer status_map.deinit();

    // Scan /proc and collect status for all PIDs
    const pids = try listPids(self.allocator);
    defer self.allocator.free(pids);

    for (pids) |pid| {
        const status = getStatus(pid) catch continue;
        try status_map.put(pid, status);
    }

    // Try to register all PIDs (ancestors before descendants)
    var iter = status_map.keyIterator();
    while (iter.next()) |pid_ptr| {
        self.ensureRegistered(&status_map, pid_ptr.*) catch continue;
    }

    // TODO?: processes that no longer exist in the kernel should be deleted
    // Would involve calling handleProcessExit() on whichever PIDs have disappeared
}

/// Register the initial sandbox root process
pub fn handleInitialProcess(self: *Self, pid: AbsPid) !void {
    if (self.lookup.count() != 0) return error.InitialProcessExists;

    // passing null namespace/fd_table creates new ones
    const root_proc = try Proc.init(self.allocator, pid, null, null, null);
    errdefer root_proc.deinit(self.allocator);

    try self.lookup.put(self.allocator, pid, root_proc);
}

/// Register a child process with given parent and flags
pub fn registerChild(
    self: *Self,
    parent: *Proc,
    child_pid: AbsPid,
    clone_flags: CloneFlags,
) !*Proc {
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

pub fn handleProcessExit(self: *Self, pid: AbsPid) !void {
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
    var pids = [_]AbsPid{ 10, 20, 30, 40, 50 };

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
        const child_pid: AbsPid = @intCast(100 + i);
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
    const b_nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    try std.testing.expect(b_proc.isNamespaceRoot());
    try std.testing.expect(a_proc.namespace != b_proc.namespace);

    // C: child of B in ns2
    // C is PID 2 in B's namespace, 300 from root namespace view
    const c_pid = 300;
    const c_nspids = [_]NsPid{ 300, 2 };
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
    const b_nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    // C: PID 2 in B's namespace
    const c_pid = 300;
    const c_nspids = [_]NsPid{ 300, 2 };
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
    const b_nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, b_pid, &b_nspids);
    _ = try v_procs.registerChild(a_proc, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = v_procs.lookup.get(b_pid).?;

    // C: in ns2, depth 2
    const c_pid = 300;
    const c_nspids = [_]NsPid{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, c_pid, &c_nspids);
    _ = try v_procs.registerChild(b_proc, c_pid, CloneFlags.from(0));
    const c_proc = v_procs.lookup.get(c_pid).?;

    // D: ns3 root, depth 3
    const d_pid = 400;
    const d_nspids = [_]NsPid{ 400, 3, 1 };
    try proc_info.testing.setupNsPids(allocator, d_pid, &d_nspids);
    _ = try v_procs.registerChild(c_proc, d_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const d_proc = v_procs.lookup.get(d_pid).?;

    // E: in ns3, depth 3
    const e_pid = 500;
    const e_nspids = [_]NsPid{ 500, 4, 2 };
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
    const b_nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &b_nspids);
    _ = try v_procs.registerChild(a, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const b = v_procs.lookup.get(200).?;

    // A can see B (B is registered in parent namespace too)
    try std.testing.expect(a.canSee(b));
    // B cannot see A (A is only in parent namespace)
    try std.testing.expect(!b.canSee(a));
}

test "deep namespace hierarchy (10 levels)" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    const DEPTH = 10;

    // Create a chain: ns0 -> ns1 -> ns2 -> ... -> ns9
    // Each level has one process that is the root of a new namespace
    var pids: [DEPTH]AbsPid = undefined;
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
        var nspid_buf: [DEPTH]NsPid = undefined;
        for (0..i + 1) |j| {
            // From ancestor namespace j's view, this proc has a certain PID
            // For simplicity: from ns_j, the PID is (1000 + i) - j
            // This simulates different PIDs in different namespaces
            nspid_buf[j] = @intCast(pids[i] - @as(AbsPid, @intCast(j)));
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
    const root_pid: AbsPid = 1;
    try v_procs.handleInitialProcess(root_pid);
    const root = v_procs.lookup.get(root_pid).?;

    var total_procs: usize = 1; // root

    // Level 1: 20 children of root (same namespace)
    var level1_procs: [CHILDREN_PER_LEVEL]*Proc = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        const pid: AbsPid = @intCast(100 + i);
        _ = try v_procs.registerChild(root, pid, CloneFlags.from(0));
        level1_procs[i] = v_procs.lookup.get(pid).?;
        total_procs += 1;
    }

    // Level 2: Each level1 proc has 20 children (same namespace)
    var level2_procs: [CHILDREN_PER_LEVEL][CHILDREN_PER_LEVEL]*Proc = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        for (0..CHILDREN_PER_LEVEL) |j| {
            const pid: AbsPid = @intCast(1000 + i * 100 + j);
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
    const a1_nspids = [_]NsPid{ 11, 1 };
    try proc_info.testing.setupNsPids(allocator, 11, &a1_nspids);
    _ = try v_procs.registerChild(proc_a, 11, CloneFlags.from(linux.CLONE.NEWPID));
    const proc_a1 = v_procs.lookup.get(11).?;

    const a2_nspids = [_]NsPid{ 12, 2 };
    try proc_info.testing.setupNsPids(allocator, 12, &a2_nspids);
    _ = try v_procs.registerChild(proc_a1, 12, CloneFlags.from(0));
    const proc_a2 = v_procs.lookup.get(12).?;

    // ns2: B's children in new namespace
    const b1_nspids = [_]NsPid{ 21, 1 };
    try proc_info.testing.setupNsPids(allocator, 21, &b1_nspids);
    _ = try v_procs.registerChild(proc_b, 21, CloneFlags.from(linux.CLONE.NEWPID));
    const proc_b1 = v_procs.lookup.get(21).?;

    const b2_nspids = [_]NsPid{ 22, 2 };
    try proc_info.testing.setupNsPids(allocator, 22, &b2_nspids);
    _ = try v_procs.registerChild(proc_b1, 22, CloneFlags.from(0));

    // ns3: nested inside ns2
    const b1a_nspids = [_]NsPid{ 211, 3, 1 }; // seen as 211 from ns0, 3 from ns2, 1 from ns3
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

test "stress: verify NsPid mapping correctness across namespaces" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Create: root(100) -> child(200) in new namespace
    // NSpid for child: [200, 1] meaning:
    //   - From root namespace: NsPid = 200
    //   - From child's own namespace: NsPid = 1

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;

    const child_nspids = [_]NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &child_nspids);
    _ = try v_procs.registerChild(root, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const child = v_procs.lookup.get(200).?;

    // Verify NsPid from each namespace's perspective
    // From root namespace, child's NsPid should be 200
    const child_gpid_from_root = root.namespace.getNsPid(child);
    try std.testing.expectEqual(@as(?NsPid, 200), child_gpid_from_root);

    // From child's namespace, child's NsPid should be 1
    const child_gpid_from_self = child.namespace.getNsPid(child);
    try std.testing.expectEqual(@as(?NsPid, 1), child_gpid_from_self);

    // Root should not be visible from child's namespace
    const root_gpid_from_child = child.namespace.getNsPid(root);
    try std.testing.expectEqual(@as(?NsPid, null), root_gpid_from_child);

    // Root's NsPid from root namespace should be 100
    const root_gpid_from_self = root.namespace.getNsPid(root);
    try std.testing.expectEqual(@as(?NsPid, 100), root_gpid_from_self);

    // Add grandchild: child(200) -> grandchild(300) in same namespace as child
    // NSpid for grandchild: [300, 2] meaning:
    //   - From root namespace: NsPid = 300
    //   - From child's namespace: NsPid = 2
    const grandchild_nspids = [_]NsPid{ 300, 2 };
    try proc_info.testing.setupNsPids(allocator, 300, &grandchild_nspids);
    _ = try v_procs.registerChild(child, 300, CloneFlags.from(0));
    const grandchild = v_procs.lookup.get(300).?;

    // Grandchild should be in same namespace as child
    try std.testing.expect(grandchild.namespace == child.namespace);

    // Verify NsPid of grandchild
    //  from root's perspective
    const gc_gpid_from_root = root.namespace.getNsPid(grandchild);
    try std.testing.expectEqual(@as(?NsPid, 300), gc_gpid_from_root);

    //  from child's perspective
    const gc_gpid_from_child_ns = child.namespace.getNsPid(grandchild);
    try std.testing.expectEqual(@as(?NsPid, 2), gc_gpid_from_child_ns);

    // Lookup by NsPid from child's namespace
    const found_child = child.namespace.procs.get(1);
    try std.testing.expectEqual(child, found_child);

    const found_grandchild = child.namespace.procs.get(2);
    try std.testing.expectEqual(grandchild, found_grandchild);
}

test "ensureRegistered registers process and ancestors" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register initial process 100
    try v_procs.handleInitialProcess(100);
    try std.testing.expectEqual(1, v_procs.lookup.count());

    // Build a status_map with chain: 300 -> 200 -> 100
    var status_map = std.AutoHashMap(AbsPid, ProcStatus).init(allocator);
    defer status_map.deinit();

    try proc_info.testing.setupParent(allocator, 200, 100);
    try proc_info.testing.setupParent(allocator, 300, 200);

    const status_200 = try getStatus(200);
    const status_300 = try getStatus(300);
    try status_map.put(200, status_200);
    try status_map.put(300, status_300);

    // Register 300 should also register 200
    try v_procs.ensureRegistered(&status_map, 300);

    try std.testing.expectEqual(3, v_procs.lookup.count());
    try std.testing.expect(v_procs.lookup.get(100) != null);
    try std.testing.expect(v_procs.lookup.get(200) != null);
    try std.testing.expect(v_procs.lookup.get(300) != null);

    // Verify parental relationships
    const proc_100 = v_procs.lookup.get(100).?;
    const proc_200 = v_procs.lookup.get(200).?;
    const proc_300 = v_procs.lookup.get(300).?;

    try std.testing.expectEqual(proc_100, proc_200.parent.?);
    try std.testing.expectEqual(proc_200, proc_300.parent.?);
}

test "ensureRegistered is idempotent for already registered process" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    // Register initial process 100
    try v_procs.handleInitialProcess(100);

    var status_map = std.AutoHashMap(AbsPid, ProcStatus).init(allocator);
    defer status_map.deinit();

    // Calling ensureRegistered on already registered process is a no-op
    try v_procs.ensureRegistered(&status_map, 100);
    try std.testing.expectEqual(1, v_procs.lookup.count());
}

test "ensureRegistered fails for process not in status_map" {
    const allocator = std.testing.allocator;
    var v_procs = Self.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);

    var status_map = std.AutoHashMap(AbsPid, ProcStatus).init(allocator);
    defer status_map.deinit();
    // status_map is empty, 200 not in it

    try std.testing.expectError(error.ProcNotInKernel, v_procs.ensureRegistered(&status_map, 200));
}
