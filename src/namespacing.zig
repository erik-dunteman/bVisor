const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const FD = union { kernel: KernelFD, virtual: VirtualFD };
const VirtualFD = linux.fd_t;
const KernelFD = linux.fd_t;

const PID = union { kernel: KernelPID, virtual: VirtualPID };
const VirtualPID = linux.pid_t;
const KernelPID = linux.pid_t;

const KernelToVirtualProcMap = std.AutoHashMapUnmanaged(KernelPID, *VirtualProc);
const VirtualProcSet = std.AutoHashMapUnmanaged(*VirtualProc, void);
const VirtualProcList = std.ArrayList(*VirtualProc);

const VirtualProc = struct {
    const Self = @This();

    pid: VirtualPID,
    parent: ?*VirtualProc,
    children: VirtualProcSet = .empty,

    fn init(allocator: Allocator, pid: VirtualPID, parent: ?*VirtualProc) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .pid = pid,
            .parent = parent,
        };
        return self;
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }

    fn init_child(self: *Self, allocator: Allocator) !*Self {
        // TODO: support different clone flags to determine what gets copied over from parent

        const child = try VirtualProc.init(
            allocator,
            try self.next_pid(allocator),
            self,
        );
        errdefer child.deinit(allocator);

        try self.children.put(allocator, child, {});

        return child;
    }

    pub fn deinit_child(self: *Self, child: *Self, allocator: Allocator) void {
        self.remove_child_link(child);
        child.deinit(allocator);
    }

    pub fn remove_child_link(self: *Self, child: *Self) void {
        _ = self.children.remove(child);
    }

    /// Collect a flat list of this process and all descendents
    /// Returned ArrayList must be freed by caller
    fn collect_tree_owned(self: *Self, allocator: Allocator) ![]*VirtualProc {
        var accumulator = try VirtualProcList.initCapacity(allocator, 16);
        try self._collect_tree_recursive(&accumulator, allocator);
        return accumulator.toOwnedSlice(allocator);
    }

    fn collect_tree_pids_sorted_owned(self: *Self, allocator: Allocator) ![]VirtualPID {
        const procs = try self.collect_tree_owned(allocator);
        defer allocator.free(procs);
        var pids = try std.ArrayList(VirtualPID).initCapacity(allocator, procs.len);
        for (procs) |proc| {
            try pids.append(allocator, proc.pid);
        }

        std.mem.sort(VirtualPID, pids.items, {}, std.sort.asc(VirtualPID));
        return pids.toOwnedSlice(allocator);
    }

    fn _collect_tree_recursive(self: *Self, accumulator: *VirtualProcList, allocator: Allocator) !void {
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *VirtualProc = child_entry.key_ptr.*;
            try child._collect_tree_recursive(accumulator, allocator);
        }
        try accumulator.append(allocator, self);
    }

    pub fn next_pid(self: *Self, allocator: Allocator) !VirtualPID {
        std.debug.print("collecting tree pids\n", .{});
        std.debug.print("self.pid: {}\n", .{self.pid});
        const pids = try self.collect_tree_pids_sorted_owned(allocator);
        std.debug.print("pids: {any}\n", .{pids});
        defer allocator.free(pids);
        if (pids.len == 0) return 1;
        // find first gap using windows
        var iter = std.mem.window(VirtualPID, pids, 2, 1);
        while (iter.next()) |window| {
            // window can return a partial window
            // requiring checks for index-out-of-bounds
            switch (window.len) {
                0 => unreachable, // window returns null in this case
                1 => {
                    // partial window at end of pids slice
                    return window[0] + 1;
                },
                2 => {
                    // full window in middle of pids slice
                    // check for gaps
                    const a = window[0];
                    const b = window[1];
                    if (b - a > 1) {
                        return a + 1;
                    }
                },
                else => unreachable,
            }
        }

        return pids[pids.len - 1] + 1; // no gap found, return next after last
    }
};

const FlatMap = struct {
    arena: ArenaAllocator,

    // flat list of mappings from kernel to virtual PID
    // the VirtualProc pointed to may be arbitrarily nested
    procs: KernelToVirtualProcMap = .empty,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .arena = .init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit(); // frees every VirtualProc in procs, as they're all descendent from this arena
    }

    /// Called once on sandbox startup, to track the initial process virtually
    pub fn register_initial_proc(self: *Self, pid: KernelPID) !VirtualPID {
        // should only ever happen once on sandbox boot. We don't allow new top-level processes, only cloned children.
        if (self.procs.size != 0) return error.InitialProcessExists;

        const allocator = self.arena.allocator();

        const vpid = 1; // initial virtual PID always starts at 1
        const initial = try VirtualProc.init(
            allocator,
            vpid,
            null,
        );
        errdefer initial.deinit(allocator);

        try self.procs.put(allocator, pid, initial);

        return vpid;
    }

    pub fn register_child_proc(self: *Self, parent_pid: KernelPID, child_pid: KernelPID) !VirtualPID {
        const allocator = self.arena.allocator();
        const parent: *VirtualProc = self.procs.get(parent_pid) orelse return error.KernelPIDNotFound;
        const child = try parent.init_child(allocator);
        errdefer parent.deinit_child(child, allocator);

        try self.procs.put(allocator, child_pid, child);

        return child.pid;
    }

    pub fn kill_proc(self: *Self, pid: KernelPID) !void {
        const allocator = self.arena.allocator();

        var target_proc = self.procs.get(pid) orelse return;
        const parent = target_proc.parent;

        // collect all descendents
        var procs_to_delete = try target_proc.collect_tree_owned(allocator);
        defer allocator.free(procs_to_delete);

        // remove target from parent's children
        if (parent) |parent_proc| {
            parent_proc.remove_child_link(target_proc);
        }

        // remove mappings from procs
        var kernel_pids_to_remove = try std.ArrayList(KernelPID).initCapacity(allocator, procs_to_delete.len);
        defer kernel_pids_to_remove.deinit(allocator);
        for (procs_to_delete) |child| {
            var iter = self.procs.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* == child) {
                    try kernel_pids_to_remove.append(allocator, entry.key_ptr.*);
                }
            }
        }
        for (kernel_pids_to_remove.items) |kernel_pid| {
            _ = self.procs.remove(kernel_pid);
        }

        // mass-deinit items
        for (procs_to_delete) |proc| {
            proc.deinit(allocator);
        }
    }
};

test "child proc initial state correct" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();
    try std.testing.expect(flat_map.procs.count() == 0);

    // supervisor spawns child proc of say PID=22, need to register that virtually
    const init_pid = 22;
    const init_vpid = try flat_map.register_initial_proc(init_pid);
    try std.testing.expectEqual(1, init_vpid);
    try std.testing.expectEqual(1, flat_map.procs.count());
    const maybe_proc = flat_map.procs.get(init_pid);
    try std.testing.expect(maybe_proc != null);
    const proc = maybe_proc.?;
    try std.testing.expectEqual(1, proc.pid); // correct virtual PID assignment
    try std.testing.expectEqual(0, proc.children.size);
}

test "tree operations" {
    const allocator = std.testing.allocator;
    var flat_map = FlatMap.init(allocator);
    defer flat_map.deinit();
    try std.testing.expectEqual(0, flat_map.procs.count());

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    const a_vpid = try flat_map.register_initial_proc(a_pid);
    try std.testing.expectEqual(1, flat_map.procs.count());
    try std.testing.expectEqual(1, a_vpid);

    const b_pid = 44;
    const b_vpid = try flat_map.register_child_proc(a_pid, b_pid);
    try std.testing.expectEqual(2, b_vpid);
    try std.testing.expectEqual(2, flat_map.procs.count());
    try std.testing.expectEqual(1, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);

    const c_pid = 55;
    const c_vpid = try flat_map.register_child_proc(a_pid, c_pid);
    try std.testing.expectEqual(3, c_vpid);
    try std.testing.expectEqual(3, flat_map.procs.count());
    try std.testing.expectEqual(2, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);

    const d_pid = 66;
    const d_vpid = try flat_map.register_child_proc(c_pid, d_pid);
    try std.testing.expectEqual(4, d_vpid);
    try std.testing.expectEqual(4, flat_map.procs.count());
    try std.testing.expectEqual(2, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(d_pid).?.children.size);

    // shrink to
    // a
    // - c
    //   - d
    try flat_map.kill_proc(b_pid);
    try std.testing.expectEqual(3, flat_map.procs.count());
    try std.testing.expectEqual(1, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(d_pid).?.children.size);
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid));

    // get pids
    var a_pids = try flat_map.procs.get(a_pid).?.collect_tree_pids_sorted_owned(allocator);
    try std.testing.expectEqual(3, a_pids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[3]VirtualPID{ 1, 3, 4 }, a_pids);
    allocator.free(a_pids); // free immediately, since we reuse a_pids var later

    // re-add b, should get original pid for b since was freed
    const b_pid_2 = 45;
    const b_vpid_2 = try flat_map.register_child_proc(a_pid, b_pid_2);
    try std.testing.expectEqual(b_vpid, b_vpid_2);

    a_pids = try flat_map.procs.get(a_pid).?.collect_tree_pids_sorted_owned(allocator);
    defer allocator.free(a_pids);
    try std.testing.expectEqual(4, a_pids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[4]VirtualPID{ 1, 2, 3, 4 }, a_pids);

    // clear whole tree
    try flat_map.kill_proc(a_pid);
    try std.testing.expectEqual(0, flat_map.procs.count());
    try std.testing.expectEqual(null, flat_map.procs.get(a_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid_2));
    try std.testing.expectEqual(null, flat_map.procs.get(c_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(d_pid));
}

test "register_initial_proc fails if already registered" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_initial_proc(100);
    try std.testing.expectError(error.InitialProcessExists, flat_map.register_initial_proc(200));
}

test "register_child_proc fails with unknown parent" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_initial_proc(100);
    try std.testing.expectError(error.KernelPIDNotFound, flat_map.register_child_proc(999, 200));
}

test "kill_proc on non-existent pid is no-op" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_initial_proc(100);
    try flat_map.kill_proc(999);
    try std.testing.expectEqual(1, flat_map.procs.count());
}

test "kill intermediate node removes subtree but preserves siblings" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    _ = try flat_map.register_initial_proc(a_pid);
    const b_pid = 20;
    _ = try flat_map.register_child_proc(a_pid, b_pid);
    const c_pid = 30;
    _ = try flat_map.register_child_proc(a_pid, c_pid);
    const d_pid = 40;
    _ = try flat_map.register_child_proc(c_pid, d_pid);

    try std.testing.expectEqual(4, flat_map.procs.count());

    // kill c (intermediate) - should also remove d but preserve a and b
    try flat_map.kill_proc(c_pid);

    try std.testing.expectEqual(2, flat_map.procs.count());
    try std.testing.expect(flat_map.procs.get(a_pid) != null);
    try std.testing.expect(flat_map.procs.get(b_pid) != null);
    try std.testing.expectEqual(null, flat_map.procs.get(c_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var flat_map = FlatMap.init(allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_initial_proc(100);
    const proc = flat_map.procs.get(100).?;

    const pids = try proc.collect_tree_pids_sorted_owned(allocator);
    defer allocator.free(pids);

    try std.testing.expectEqual(1, pids.len);
    try std.testing.expectEqual(1, pids[0]);
}

test "next_pid returns sequential when no gaps" {
    const allocator = std.testing.allocator;
    var flat_map = FlatMap.init(allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_initial_proc(100);
    const proc = flat_map.procs.get(100).?;

    const next = try proc.next_pid(allocator);
    try std.testing.expectEqual(2, next);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var flat_map = FlatMap.init(allocator);
    defer flat_map.deinit();

    // chain: a -> b -> c -> d -> e
    var kernel_pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    _ = try flat_map.register_initial_proc(kernel_pids[0]);
    for (1..5) |i| {
        _ = try flat_map.register_child_proc(kernel_pids[i - 1], kernel_pids[i]);
    }

    try std.testing.expectEqual(5, flat_map.procs.count());

    // kill middle (c) - should remove c, d, e
    try flat_map.kill_proc(kernel_pids[2]);
    try std.testing.expectEqual(2, flat_map.procs.count());
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var flat_map = FlatMap.init(allocator);
    defer flat_map.deinit();

    const parent_pid = 100;
    _ = try flat_map.register_initial_proc(parent_pid);

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        const vpid = try flat_map.register_child_proc(parent_pid, child_pid);
        try std.testing.expectEqual(@as(VirtualPID, @intCast(i + 1)), vpid);
    }

    try std.testing.expectEqual(11, flat_map.procs.count());
    try std.testing.expectEqual(10, flat_map.procs.get(parent_pid).?.children.size);
}
