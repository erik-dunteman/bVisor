const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const VirtualPID = linux.pid_t;
const KernelPID = linux.pid_t;

const CloneFlags = struct {
    raw: u64,

    const Self = @This();

    pub fn from(raw: u64) Self {
        return .{ .raw = raw };
    }

    /// Returns error if unsupported namespace flags are set
    pub fn check_supported(self: Self) !void {
        if (self.raw & linux.CLONE.NEWUSER != 0) return error.UnsupportedUserNamespace;
        if (self.raw & linux.CLONE.NEWNET != 0) return error.UnsupportedNetNamespace;
        if (self.raw & linux.CLONE.NEWNS != 0) return error.UnsupportedMountNamespace;
    }

    pub fn create_pid_namespace(self: Self) bool {
        return self.raw & linux.CLONE.NEWPID != 0;
    }

    pub fn is_thread(self: Self) bool {
        return self.raw & linux.CLONE.THREAD != 0;
    }

    pub fn share_parent(self: Self) bool {
        return self.raw & linux.CLONE.PARENT != 0;
    }
};

const ProcLookup = std.AutoHashMapUnmanaged(KernelPID, *Proc);
const VpidLookup = std.AutoHashMapUnmanaged(VirtualPID, *Proc);
const ProcSet = std.AutoHashMapUnmanaged(*Proc, void);
const ProcList = std.ArrayList(*Proc);

/// Namespaces are owned by their root proc.
/// Each namespace tracks all procs visible to it (own procs + procs in child namespaces).
const Namespace = struct {
    vpid_counter: VirtualPID = 0,
    parent: ?*Namespace,
    procs: VpidLookup = .empty, // vpid → Proc for all visible procs

    const Self = @This();

    pub fn init(allocator: Allocator, parent: ?*Namespace) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .parent = parent };
        return self;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.procs.deinit(allocator);
        allocator.destroy(self);
    }

    pub fn next_vpid(self: *Self) VirtualPID {
        self.vpid_counter += 1;
        return self.vpid_counter;
    }

    /// Get a proc by its vpid as visible from this namespace
    pub fn get_proc(self: *Self, vpid: VirtualPID) ?*Proc {
        return self.procs.get(vpid);
    }

    /// Register a proc in this namespace and all ancestor namespaces.
    /// Each namespace assigns its own vpid to the proc.
    fn register_proc(self: *Self, allocator: Allocator, proc: *Proc) !void {
        // Register in this namespace (proc already has vpid assigned from this ns)
        try self.procs.put(allocator, proc.vpid, proc);

        // Register in all ancestor namespaces with their own vpids
        var ancestor = self.parent;
        while (ancestor) |ns| {
            const ancestor_vpid = ns.next_vpid();
            try ns.procs.put(allocator, ancestor_vpid, proc);
            ancestor = ns.parent;
        }
    }

    /// Unregister a proc from this namespace and all ancestor namespaces.
    /// Searches by proc pointer since we don't store vpid-per-namespace in Proc.
    fn unregister_proc(self: *Self, proc: *Proc) void {
        // Remove from this namespace
        _ = self.procs.remove(proc.vpid);

        // Remove from all ancestor namespaces (search by pointer)
        var ancestor = self.parent;
        while (ancestor) |ns| {
            var iter = ns.procs.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* == proc) {
                    _ = ns.procs.remove(entry.key_ptr.*);
                    break;
                }
            }
            ancestor = ns.parent;
        }
    }
};

const Proc = struct {
    pid: KernelPID,
    namespace: *Namespace,
    vpid: VirtualPID,
    parent: ?*Proc,
    children: ProcSet = .empty,

    const Self = @This();

    fn init(allocator: Allocator, pid: KernelPID, namespace: ?*Namespace, parent: ?*Proc) !*Self {
        if (namespace) |ns| {
            // proc inherits parent namespace
            const vpid = ns.next_vpid();
            const self = try allocator.create(Self);
            self.* = .{
                .pid = pid,
                .namespace = ns,
                .vpid = vpid,
                .parent = parent,
            };
            errdefer allocator.destroy(self);

            // register in own namespace and all ancestors
            try ns.register_proc(allocator, self);

            return self;
        }

        // create this proc as root in a new namespace
        const parent_ns = if (parent) |p| p.namespace else null;
        var ns = try Namespace.init(allocator, parent_ns);
        errdefer ns.deinit(allocator);

        const vpid = ns.next_vpid();
        const self = try allocator.create(Self);
        self.* = .{
            .pid = pid,
            .namespace = ns,
            .vpid = vpid,
            .parent = parent,
        };
        errdefer allocator.destroy(self);

        // register in own namespace and all ancestors
        try ns.register_proc(allocator, self);

        return self;
    }

    pub fn is_namespace_root(self: *Self) bool {
        if (self.parent) |p| {
            return self.namespace != p.namespace; // crossed boundary
        }
        return true; // no parent = top-level root
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        // unregister from own namespace and all ancestors
        self.namespace.unregister_proc(self);

        if (self.is_namespace_root()) {
            // the root Proc in a namespace is responsible for deallocating it
            self.namespace.deinit(allocator);
        }
        self.children.deinit(allocator);
        allocator.destroy(self);
    }

    fn get_namespace_root(self: *Self) *Proc {
        var current = self;
        while (current.parent) |p| {
            if (current.namespace != p.namespace) break;
            current = p;
        }
        return current;
    }

    fn init_child(self: *Self, allocator: Allocator, pid: KernelPID, namespace: ?*Namespace) !*Self {
        const child = try Proc.init(allocator, pid, namespace, self);
        errdefer child.deinit(allocator);

        try self.children.put(allocator, child, {});

        return child;
    }

    fn deinit_child(self: *Self, child: *Self, allocator: Allocator) void {
        self.remove_child_link(child);
        child.deinit(allocator);
    }

    fn remove_child_link(self: *Self, child: *Self) void {
        _ = self.children.remove(child);
    }

    /// Get a sorted list of all virtual PIDs visible in this process's namespace.
    /// Does not include processes in nested child namespaces.
    fn get_vpids_owned(self: *Self, allocator: Allocator) ![]VirtualPID {
        const root = self.get_namespace_root();
        const procs = try root.collect_namespace_procs_owned(allocator);
        defer allocator.free(procs);

        var vpids = try std.ArrayList(VirtualPID).initCapacity(allocator, procs.len);
        for (procs) |proc| {
            try vpids.append(allocator, proc.vpid);
        }
        std.mem.sort(VirtualPID, vpids.items, {}, std.sort.asc(VirtualPID));
        return vpids.toOwnedSlice(allocator);
    }

    /// Collect all procs in the same namespace as self (stops at namespace boundaries).
    /// Returned slice must be freed by caller.
    fn collect_namespace_procs_owned(self: *Self, allocator: Allocator) ![]*Proc {
        var accumulator = try ProcList.initCapacity(allocator, 16);
        try self._collect_namespace_recursive(&accumulator, allocator, self.namespace);
        return accumulator.toOwnedSlice(allocator);
    }

    fn _collect_namespace_recursive(self: *Self, accumulator: *ProcList, allocator: Allocator, ns: *Namespace) !void {
        try accumulator.append(allocator, self);
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *Proc = child_entry.key_ptr.*;
            // stop at namespace boundary
            if (child.namespace != ns) continue;
            try child._collect_namespace_recursive(accumulator, allocator, ns);
        }
    }

    /// Collect all descendant procs (crosses namespace boundaries).
    /// Used for process exit to kill entire subtree.
    /// Returned slice must be freed by caller.
    fn collect_subtree_owned(self: *Self, allocator: Allocator) ![]*Proc {
        var accumulator = try ProcList.initCapacity(allocator, 16);
        try self._collect_subtree_recursive(&accumulator, allocator);
        return accumulator.toOwnedSlice(allocator);
    }

    fn _collect_subtree_recursive(self: *Self, accumulator: *ProcList, allocator: Allocator) !void {
        // Children first, then self - ensures namespace roots are deinitialized after their children
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *Proc = child_entry.key_ptr.*;
            try child._collect_subtree_recursive(accumulator, allocator);
        }
        try accumulator.append(allocator, self);
    }
};

/// Tracks kernel to virtual mappings, handling parent/child relationships.
/// Note: we don't currently reparent orphaned children to init; killing a
/// process kills its entire subtree including any nested namespaces.
const Virtualizer = struct {
    allocator: Allocator,

    // flat list of mappings from kernel to virtual PID
    // owns underlying procs
    procs: ProcLookup = .empty,

    const Self = @This();

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

        // passing null namespace creates a new one
        const root_proc = try Proc.init(self.allocator, pid, null, null);
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

        const child = try parent.init_child(self.allocator, child_pid, namespace);
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
};

test "state is correct after initial proc" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();
    try std.testing.expect(virtualizer.procs.size == 0);

    // supervisor spawns child proc of say PID=22, need to register that virtually
    const init_pid = 22;
    const init_vpid = try virtualizer.handle_initial_process(init_pid);
    try std.testing.expectEqual(1, init_vpid);
    try std.testing.expectEqual(1, virtualizer.procs.size);
    const proc = virtualizer.procs.get(init_pid).?;
    try std.testing.expectEqual(init_vpid, proc.vpid);
    try std.testing.expectEqual(null, proc.parent);
    try std.testing.expectEqual(0, proc.children.size);
    try std.testing.expect(proc.is_namespace_root());
    try std.testing.expectEqual(@as(VirtualPID, 1), proc.get_namespace_root().vpid);
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();
    try std.testing.expectEqual(0, virtualizer.procs.size);

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    const a_vpid = try virtualizer.handle_initial_process(a_pid);
    try std.testing.expectEqual(1, virtualizer.procs.size);
    try std.testing.expectEqual(1, a_vpid);

    const b_pid = 44;
    const b_vpid = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    try std.testing.expectEqual(2, b_vpid);
    try std.testing.expectEqual(2, virtualizer.procs.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);

    const c_pid = 55;
    const c_vpid = try virtualizer.handle_clone(a_pid, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(3, c_vpid);
    try std.testing.expectEqual(3, virtualizer.procs.size);
    try std.testing.expectEqual(2, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);

    const d_pid = 66;
    const d_vpid = try virtualizer.handle_clone(c_pid, d_pid, CloneFlags.from(0));
    try std.testing.expectEqual(4, d_vpid);
    try std.testing.expectEqual(4, virtualizer.procs.size);
    try std.testing.expectEqual(2, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(d_pid).?.children.size);

    // shrink to
    // a
    // - c
    //   - d
    try virtualizer.handle_process_exit(b_pid);
    try std.testing.expectEqual(3, virtualizer.procs.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(d_pid).?.children.size);
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid));

    // get vpids
    var a_vpids = try virtualizer.procs.get(a_pid).?.get_vpids_owned(allocator);
    try std.testing.expectEqual(3, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[3]VirtualPID{ 1, 3, 4 }, a_vpids);
    allocator.free(a_vpids); // free immediately, since we reuse a_vpids var later

    // re-add b, should issue a new vpid 5
    const b_pid_2 = 45;
    const b_vpid_2 = try virtualizer.handle_clone(a_pid, b_pid_2, CloneFlags.from(0));
    try std.testing.expectEqual(5, b_vpid_2);

    a_vpids = try virtualizer.procs.get(a_pid).?.get_vpids_owned(allocator);
    defer allocator.free(a_vpids);
    try std.testing.expectEqual(4, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[4]VirtualPID{ 1, 3, 4, 5 }, a_vpids);

    // clear whole tree
    try virtualizer.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, virtualizer.procs.size);
    try std.testing.expectEqual(null, virtualizer.procs.get(a_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid_2));
    try std.testing.expectEqual(null, virtualizer.procs.get(c_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(d_pid));
}

test "handle_initial_process fails if already registered" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try std.testing.expectError(error.InitialProcessExists, virtualizer.handle_initial_process(200));
}

test "handle_clone fails with unknown parent" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try std.testing.expectError(error.KernelPIDNotFound, virtualizer.handle_clone(999, 200, CloneFlags.from(0)));
}

test "handle_process_exit on non-existent pid is no-op" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try virtualizer.handle_process_exit(999);
    try std.testing.expectEqual(1, virtualizer.procs.size);
}

test "kill intermediate node removes subtree but preserves siblings" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    _ = try virtualizer.handle_initial_process(a_pid);
    const b_pid = 20;
    _ = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    const c_pid = 30;
    _ = try virtualizer.handle_clone(a_pid, c_pid, CloneFlags.from(0));
    const d_pid = 40;
    _ = try virtualizer.handle_clone(c_pid, d_pid, CloneFlags.from(0));

    try std.testing.expectEqual(4, virtualizer.procs.size);

    // kill c (intermediate) - should also remove d but preserve a and b
    try virtualizer.handle_process_exit(c_pid);

    try std.testing.expectEqual(2, virtualizer.procs.size);
    try std.testing.expect(virtualizer.procs.get(a_pid) != null);
    try std.testing.expect(virtualizer.procs.get(b_pid) != null);
    try std.testing.expectEqual(null, virtualizer.procs.get(c_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    const proc = virtualizer.procs.get(100).?;

    const vpids = try proc.get_vpids_owned(allocator);
    defer allocator.free(vpids);

    try std.testing.expectEqual(1, vpids.len);
    try std.testing.expectEqual(1, vpids[0]);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    // chain: a -> b -> c -> d -> e
    var pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    _ = try virtualizer.handle_initial_process(pids[0]);
    for (1..5) |i| {
        _ = try virtualizer.handle_clone(pids[i - 1], pids[i], CloneFlags.from(0));
    }

    try std.testing.expectEqual(5, virtualizer.procs.size);

    // kill middle (c) - should remove c, d, e
    try virtualizer.handle_process_exit(pids[2]);
    try std.testing.expectEqual(2, virtualizer.procs.size);
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    const parent_pid = 100;
    _ = try virtualizer.handle_initial_process(parent_pid);

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        const vpid = try virtualizer.handle_clone(parent_pid, child_pid, CloneFlags.from(0));
        try std.testing.expectEqual(@as(VirtualPID, @intCast(i + 1)), vpid);
    }

    try std.testing.expectEqual(11, virtualizer.procs.size);
    try std.testing.expectEqual(10, virtualizer.procs.get(parent_pid).?.children.size);
}

test "nested namespace - get_vpids_owned respects boundaries" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    // Create structure:
    // ns1: A(vpid=1) -> B(vpid=2)
    //                   B is also ns2 root (vpid=1 in ns2)
    //                   ns2: B(vpid=1) -> C(vpid=2)

    const a_pid = 100;
    _ = try virtualizer.handle_initial_process(a_pid);
    const a_proc = virtualizer.procs.get(a_pid).?;

    // B: child of A but root of new namespace (CLONE_NEWPID)
    const b_pid = 200;
    _ = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_proc = virtualizer.procs.get(b_pid).?;

    try std.testing.expect(b_proc.is_namespace_root());
    try std.testing.expectEqual(@as(VirtualPID, 1), b_proc.vpid); // vpid 1 in ns2
    try std.testing.expect(a_proc.namespace != b_proc.namespace);

    // C: child of B in ns2
    const c_pid = 300;
    const c_vpid = try virtualizer.handle_clone(b_pid, c_pid, CloneFlags.from(0));
    try std.testing.expectEqual(@as(VirtualPID, 2), c_vpid); // vpid 2 in ns2

    const c_proc = virtualizer.procs.get(c_pid).?;
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
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    // ns1: A(1) -> B(ns2 root, vpid=1) -> C(vpid=2 in ns2)
    const a_pid = 100;
    _ = try virtualizer.handle_initial_process(a_pid);

    const b_pid = 200;
    _ = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const c_pid = 300;
    _ = try virtualizer.handle_clone(b_pid, c_pid, CloneFlags.from(0));

    try std.testing.expectEqual(3, virtualizer.procs.size);

    // Kill B - should also kill C (entire subtree, crossing namespace boundary)
    try virtualizer.handle_process_exit(b_pid);

    try std.testing.expectEqual(1, virtualizer.procs.size);
    try std.testing.expect(virtualizer.procs.get(a_pid) != null);
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(c_pid));
}

test "nested namespace - killing grandparent kills all" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    // ns1: A -> B (ns2 root) -> C -> D (ns3 root) -> E
    const a_pid = 100;
    _ = try virtualizer.handle_initial_process(a_pid);

    const b_pid = 200;
    _ = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const c_pid = 300;
    _ = try virtualizer.handle_clone(b_pid, c_pid, CloneFlags.from(0));

    const d_pid = 400;
    _ = try virtualizer.handle_clone(c_pid, d_pid, CloneFlags.from(linux.CLONE.NEWPID));

    const e_pid = 500;
    _ = try virtualizer.handle_clone(d_pid, e_pid, CloneFlags.from(0));

    try std.testing.expectEqual(5, virtualizer.procs.size);

    // Kill A - should kill everything
    try virtualizer.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, virtualizer.procs.size);
}

test "pid is stored correctly" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    const a_pid = 12345;
    _ = try virtualizer.handle_initial_process(a_pid);
    const a_proc = virtualizer.procs.get(a_pid).?;
    try std.testing.expectEqual(a_pid, a_proc.pid);

    const b_pid = 67890;
    _ = try virtualizer.handle_clone(a_pid, b_pid, CloneFlags.from(0));
    const b_proc = virtualizer.procs.get(b_pid).?;
    try std.testing.expectEqual(b_pid, b_proc.pid);
}
