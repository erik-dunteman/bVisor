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

    fn traverse_descendants(self: *Self, accumulator: *std.ArrayList(*VirtualProc), allocator: Allocator) !void {
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *VirtualProc = child_entry.key_ptr.*;
            try child.traverse_descendants(accumulator, allocator);
            try accumulator.append(allocator, child);
        }
    }

    pub fn next_pid(self: *Self, allocator: Allocator) !VirtualPID {
        var desc = try std.ArrayList(*VirtualProc).initCapacity(allocator, 16);
        defer desc.deinit(allocator);
        try self.traverse_descendants(&desc, allocator);

        var pid = self.pid + 1;
        // increment until no collision with existing
        // TODO: can be optimized significantly
        while (true) : (pid += 1) {
            for (desc.items) |proc| {
                if (proc.pid == pid) {
                    continue;
                }
            }
            return pid;
        }
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
        var to_delete = try std.ArrayList(*VirtualProc).initCapacity(allocator, 16);
        defer to_delete.deinit(allocator);
        try target_proc.traverse_descendants(&to_delete, allocator);

        // include target
        try to_delete.append(allocator, target_proc);

        // remove mappings from procs
        for (to_delete.items) |child| {
            var iter = self.procs.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* == child) {
                    _ = self.procs.remove(entry.key_ptr.*);
                }
            }
        }

        // remove target from parent's children
        if (parent) |parent_proc| {
            parent_proc.remove_child_link(target_proc);
        }

        // mass-deinit
        for (to_delete.items) |proc| {
            proc.deinit(allocator);
        }
    }

    // pub fn register_clone(self: *Self, parent: KernelPID, child: KernelPID) VirtualPID {}
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

test "child proc deinit" {
    var flat_map = FlatMap.init(std.testing.allocator);
    defer flat_map.deinit();
    try std.testing.expectEqual(0, flat_map.procs.count());

    const init_pid = 33;
    const init_vpid = try flat_map.register_initial_proc(init_pid);
    try std.testing.expectEqual(1, flat_map.procs.count());
    try std.testing.expectEqual(1, init_vpid);

    const child_pid = 44;
    const child_vpid = try flat_map.register_child_proc(init_pid, child_pid);
    try std.testing.expectEqual(2, flat_map.procs.count());
    try std.testing.expectEqual(1, flat_map.procs.get(init_pid).?.children.size);
    try std.testing.expectEqual(2, child_vpid);

    try flat_map.kill_proc(init_pid);
    try std.testing.expectEqual(0, flat_map.procs.count());
}
