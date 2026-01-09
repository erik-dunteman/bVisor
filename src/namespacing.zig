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

const VirtualProcMap = std.AutoHashMapUnmanaged(KernelPID, *VirtualProc);
const VirtualProcSet = std.AutoHashMapUnmanaged(*VirtualProc, void);

const VirtualProc = struct {
    const Self = @This();

    pid: VirtualPID,
    arena: ArenaAllocator,
    parent: ?*VirtualProc,
    children: VirtualProcSet = .empty,

    /// Allocate a new VirtualProc, owned by caller's allocator
    /// Any children will be owned by internal arena
    fn init_owned(parent_allocator: Allocator, pid: VirtualPID, parent: ?*VirtualProc) !*Self {
        // parent owns Self
        // self owns children
        const self = try parent_allocator.create(Self);
        self.* = .{
            .arena = ArenaAllocator.init(parent_allocator),
            .pid = pid,
            .parent = parent,
        };
        return self;
    }

    fn deinit(self: *Self, parent_allocator: Allocator) void {
        // Deinit internal arena, which deinits all descendants
        self.arena.deinit();

        // Now deallocate self
        parent_allocator.destroy(self);
    }

    /// Allocates a new child owned by self, and returns a pointer to its VirtualProc
    /// Deinit on child is not mandatory, as arena deinit on self will free all children
    fn init_child(self: *Self) !*Self {
        // TODO: support different clone flags to determine what gets copied over from parent
        const allocator = self.arena.allocator();

        const child = try VirtualProc.init_owned(
            allocator,
            try self.next_pid(),
            self,
        );
        errdefer allocator.destroy(child);

        try self.children.put(allocator, child, {});

        return child;
    }

    /// Not mandatory under the happy path, as self.arena deinit will free all children
    fn deinit_child(self: *Self, child: *Self) void {
        self.remove_child(child);
        self.arena.allocator().destroy(child);
    }

    pub fn remove_child(self: *Self, child: *Self) void {
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

    pub fn next_pid(self: *Self) !VirtualPID {
        const allocator = self.arena.allocator();
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
    procs: VirtualProcMap = .empty,

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
        const initial = try VirtualProc.init_owned(
            allocator,
            vpid,
            null,
        );
        errdefer allocator.destroy(initial);

        try self.procs.put(allocator, pid, initial);

        return vpid;
    }

    pub fn register_child_proc(self: *Self, parent_pid: KernelPID, child_pid: KernelPID) !VirtualPID {
        const parent: *VirtualProc = self.procs.get(parent_pid) orelse return error.KernelPIDNotFound;
        const child = try parent.init_child();
        errdefer parent.deinit_child(child);

        try self.procs.put(self.arena.allocator(), child_pid, child);

        return child.pid;
    }

    pub fn kill_proc(self: *Self, pid: KernelPID) !void {
        var target_proc = self.procs.get(pid) orelse return;
        const parent = target_proc.parent;

        // recursively remove descendents, deepest first
        var desc = try std.ArrayList(*VirtualProc).initCapacity(self.arena.allocator(), 16);
        defer desc.deinit(self.arena.allocator());
        try target_proc.traverse_descendants(&desc, self.arena.allocator());
        for (desc.items) |child| {
            // look up by value in procs map
            var match_iter = self.procs.iterator();
            while (match_iter.next()) |entry| {
                if (entry.value_ptr.* == child) {
                    _ = self.procs.remove(entry.key_ptr.*);
                    break;
                }
            }
        }
        // remove target_proc
        var match_iter = self.procs.iterator();
        while (match_iter.next()) |entry| {
            if (entry.value_ptr.* == target_proc) {
                _ = self.procs.remove(entry.key_ptr.*);
                break;
            }
        }

        if (parent) |parent_proc| {
            // remove target_proc from parent's children
            parent_proc.remove_child(target_proc);
        }

        // now deinit target_proc, this deallocates itself and all descendents
        target_proc.deinit(self.arena.allocator());
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
