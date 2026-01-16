const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Namespace = @import("Namespace.zig");
const FdTable = @import("../fs/FdTable.zig");
const VirtualPID = Namespace.VirtualPID;

pub const KernelPID = linux.pid_t;

const ProcSet = std.AutoHashMapUnmanaged(*Self, void);
const ProcList = std.ArrayList(*Self);

const Self = @This();

pid: KernelPID,
namespace: *Namespace,
fd_table: *FdTable,
vpid: VirtualPID,
parent: ?*Self,
children: ProcSet = .empty,

pub fn init(allocator: Allocator, pid: KernelPID, namespace: ?*Namespace, fd_table: ?*FdTable, parent: ?*Self) !*Self {
    // Create or use provided fd_table
    const fdt = fd_table orelse try FdTable.init(allocator);
    errdefer if (fd_table == null) fdt.unref();

    if (namespace) |ns| {
        // proc inherits parent namespace - acquire it
        const ns_acquired = ns.ref();
        errdefer ns_acquired.unref();

        const vpid = ns_acquired.next_vpid();
        const self = try allocator.create(Self);
        self.* = .{
            .pid = pid,
            .namespace = ns_acquired,
            .fd_table = fdt,
            .vpid = vpid,
            .parent = parent,
        };
        errdefer allocator.destroy(self);

        // register in own namespace and all ancestors
        try ns_acquired.register_proc(allocator, self);

        return self;
    }

    // create this proc as root in a new namespace
    const parent_ns = if (parent) |p| p.namespace else null;
    const ns = try Namespace.init(allocator, parent_ns);
    errdefer ns.unref();

    const vpid = ns.next_vpid();
    const self = try allocator.create(Self);
    self.* = .{
        .pid = pid,
        .namespace = ns,
        .fd_table = fdt,
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

pub fn deinit(self: *Self, allocator: Allocator) void {
    // unregister from own namespace and all ancestors
    self.namespace.unregister_proc(self);

    // release namespace reference (will free if refcount hits 0)
    self.namespace.unref();

    // release fd_table reference (will free if refcount hits 0)
    self.fd_table.unref();

    self.children.deinit(allocator);
    allocator.destroy(self);
}

pub fn get_namespace_root(self: *Self) *Self {
    var current = self;
    while (current.parent) |p| {
        if (current.namespace != p.namespace) break;
        current = p;
    }
    return current;
}

pub fn init_child(self: *Self, allocator: Allocator, pid: KernelPID, namespace: ?*Namespace, fd_table: ?*FdTable) !*Self {
    const child = try Self.init(allocator, pid, namespace, fd_table, self);
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

/// Get a sorted list of all virtual PIDs visible in this process's namespace.
/// Does not include processes in nested child namespaces.
pub fn get_vpids_owned(self: *Self, allocator: Allocator) ![]VirtualPID {
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
pub fn collect_namespace_procs_owned(self: *Self, allocator: Allocator) ![]*Self {
    var accumulator = try ProcList.initCapacity(allocator, 16);
    try self._collect_namespace_recursive(&accumulator, allocator, self.namespace);
    return accumulator.toOwnedSlice(allocator);
}

fn _collect_namespace_recursive(self: *Self, accumulator: *ProcList, allocator: Allocator, ns: *Namespace) !void {
    try accumulator.append(allocator, self);
    var iter = self.children.iterator();
    while (iter.next()) |child_entry| {
        const child: *Self = child_entry.key_ptr.*;
        // stop at namespace boundary
        if (child.namespace != ns) continue;
        try child._collect_namespace_recursive(accumulator, allocator, ns);
    }
}

/// Collect all descendant procs (crosses namespace boundaries).
/// Used for process exit to kill entire subtree.
/// Returned slice must be freed by caller.
pub fn collect_subtree_owned(self: *Self, allocator: Allocator) ![]*Self {
    var accumulator = try ProcList.initCapacity(allocator, 16);
    try self._collect_subtree_recursive(&accumulator, allocator);
    return accumulator.toOwnedSlice(allocator);
}

fn _collect_subtree_recursive(self: *Self, accumulator: *ProcList, allocator: Allocator) !void {
    // Children first, then self - ensures namespace roots are deinitialized after their children
    var iter = self.children.iterator();
    while (iter.next()) |child_entry| {
        const child: *Self = child_entry.key_ptr.*;
        try child._collect_subtree_recursive(accumulator, allocator);
    }
    try accumulator.append(allocator, self);
}
