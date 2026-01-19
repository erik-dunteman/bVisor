const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const Proc = @import("Proc.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const KernelPID = Proc.KernelPID;

const ProcLookup = std.AutoHashMapUnmanaged(KernelPID, *Proc);

// kcmp types from linux/kcmp.h
const KCMP_FILES: u5 = 2;

const Self = @This();

pub const CloneFlags = struct {
    raw: u64 = 0,

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

/// Get a proc by kernel PID. If unknown, attempts lazy registration
/// by walking the parent chain via /proc.
pub fn get(self: *Self, pid: KernelPID) !*Proc {
    if (self.lookup.get(pid)) |proc| return proc;
    return self.register_from_kernel(pid);
}

/// Lazy registration: read parent from /proc, walk chain to find sandbox ancestor
fn register_from_kernel(self: *Self, child_pid: KernelPID) !*Proc {
    const ppid = try read_ppid(child_pid);

    // Try to get parent - this may recursively register ancestors
    const parent = self.lookup.get(ppid) orelse return error.NotInSandbox;

    // Query kernel for actual clone flags used
    const flags = detect_clone_flags(ppid, child_pid);

    return self.register_child(parent, child_pid, flags);
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

/// Read parent PID from /proc/[pid]/status
fn read_ppid(pid: KernelPID) !KernelPID {
    var path_buf: [32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{pid}) catch unreachable;

    const fd = linux.open(@ptrCast(path.ptr), .{ .ACCMODE = .RDONLY }, 0);
    if (fd > std.math.maxInt(i32)) {
        return error.CannotReadProc;
    }
    defer _ = linux.close(@intCast(fd));

    var buf: [1024]u8 = undefined;
    const n = linux.read(@intCast(fd), &buf, buf.len);
    if (n > buf.len) {
        return error.CannotReadProc;
    }

    // Parse "PPid:\t<pid>" line
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PPid:")) {
            const ppid_str = std.mem.trim(u8, line[5..], " \t");
            return std.fmt.parseInt(KernelPID, ppid_str, 10) catch return error.CannotReadProc;
        }
    }

    return error.CannotReadProc;
}

/// Detect clone flags by querying kernel state
fn detect_clone_flags(parent_pid: KernelPID, child_pid: KernelPID) CloneFlags {
    var flags: u64 = 0;

    // Check CLONE_NEWPID via namespace inode comparison
    if (!same_pid_namespace(parent_pid, child_pid)) {
        flags |= linux.CLONE.NEWPID;
    }

    // Check CLONE_FILES via kcmp syscall
    if (shares_fd_table(parent_pid, child_pid)) {
        flags |= linux.CLONE.FILES;
    }

    return CloneFlags.from(flags);
}

/// Check if two processes share the same PID namespace
fn same_pid_namespace(pid1: KernelPID, pid2: KernelPID) bool {
    const ino1 = get_ns_inode(pid1, "pid") orelse return true;
    const ino2 = get_ns_inode(pid2, "pid") orelse return true;
    return ino1 == ino2;
}

/// Get namespace inode for a process
fn get_ns_inode(pid: KernelPID, ns_type: []const u8) ?u64 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{ pid, ns_type }) catch return null;

    var stat_buf: linux.Statx = undefined;
    const result = linux.statx(
        linux.AT.FDCWD,
        @ptrCast(path.ptr),
        0,
        @bitCast(linux.STATX{ .INO = true }),
        &stat_buf,
    );
    if (result != 0) return null;

    return stat_buf.ino;
}

/// Check if two processes share the same fd table using kcmp
fn shares_fd_table(pid1: KernelPID, pid2: KernelPID) bool {
    const result = linux.syscall5(
        .kcmp,
        @intCast(pid1),
        @intCast(pid2),
        KCMP_FILES,
        0,
        0,
    );
    // kcmp returns 0 if resources are equal
    return result == 0;
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

