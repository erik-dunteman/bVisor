const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Namespace = @import("Namespace.zig");
const FdTable = @import("../fs/FdTable.zig");

pub const AbsPid = linux.pid_t;
pub const NsPid = linux.pid_t; // a pid as visible within a namespace, requiring lookup via namespace

const ProcSet = std.AutoHashMapUnmanaged(*Self, void);
const ProcList = std.ArrayList(*Self);

const Self = @This();

pid: AbsPid,
namespace: *Namespace,
fd_table: *FdTable,
parent: ?*Self,
children: ProcSet = .empty,

pub fn init(allocator: Allocator, pid: AbsPid, namespace: ?*Namespace, fd_table: ?*FdTable, parent: ?*Self) !*Self {
    // Create or use provided fd_table
    const fdt = fd_table orelse try FdTable.init(allocator);
    errdefer if (fd_table == null) fdt.unref();

    if (namespace) |ns| {
        // proc inherits parent namespace - acquire it
        const ns_acquired = ns.ref();
        errdefer ns_acquired.unref();

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Initialize struct first
        self.* = .{
            .pid = pid,
            .namespace = ns_acquired,
            .fd_table = fdt,
            .parent = parent,
        };

        // Register in own namespace and all ancestors
        try ns_acquired.registerProc(allocator, self, pid);
        errdefer ns_acquired.unregisterProc(self);

        return self;
    }

    // Create this proc as root in a new namespace
    const parent_ns = if (parent) |p| p.namespace else null;
    const ns = try Namespace.init(allocator, parent_ns);
    errdefer ns.unref();

    const self = try allocator.create(Self);
    errdefer allocator.destroy(self);

    // Initialize struct first
    self.* = .{
        .pid = pid,
        .namespace = ns,
        .fd_table = fdt,
        .parent = parent,
    };

    // Register in own namespace and all ancestors
    try ns.registerProc(allocator, self, pid);
    errdefer ns.unregisterProc(self);

    return self;
}

pub fn isNamespaceRoot(self: *Self) bool {
    if (self.parent) |p| {
        return self.namespace != p.namespace; // crossed boundary
    }
    return true; // no parent = top-level root
}

pub fn deinit(self: *Self, allocator: Allocator) void {
    // unregister from own namespace and all ancestors
    self.namespace.unregisterProc(self);

    // release namespace reference (will free if refcount hits 0)
    self.namespace.unref();

    // release fd_table reference (will free if refcount hits 0)
    self.fd_table.unref();

    self.children.deinit(allocator);
    allocator.destroy(self);
}

pub fn getNamespaceRoot(self: *Self) *Self {
    var current = self;
    while (current.parent) |p| {
        if (current.namespace != p.namespace) break;
        current = p;
    }
    return current;
}

pub fn initChild(self: *Self, allocator: Allocator, pid: AbsPid, namespace: ?*Namespace, fd_table: ?*FdTable) !*Self {
    const child = try Self.init(allocator, pid, namespace, fd_table, self);
    errdefer child.deinit(allocator);

    try self.children.put(allocator, child, {});

    return child;
}

pub fn deinitChild(self: *Self, child: *Self, allocator: Allocator) void {
    self.removeChildLink(child);
    child.deinit(allocator);
}

pub fn removeChildLink(self: *Self, child: *Self) void {
    _ = self.children.remove(child);
}

/// Check if this process can see the target process.
pub fn canSee(self: *Self, target: *Self) bool {
    return self.namespace.contains(target);
}

/// Collect all descendant procs (crosses namespace boundaries).
/// Used for process exit to kill entire subtree.
/// Returned slice must be freed by caller.
pub fn collectSubtreeOwned(self: *Self, allocator: Allocator) ![]*Self {
    var accumulator = try ProcList.initCapacity(allocator, 16);
    try self._collectSubtreeRecursive(&accumulator, allocator);
    return accumulator.toOwnedSlice(allocator);
}

fn _collectSubtreeRecursive(self: *Self, accumulator: *ProcList, allocator: Allocator) !void {
    // Children first, then self - ensures namespace roots are deinitialized after their children
    var iter = self.children.iterator();
    while (iter.next()) |child_entry| {
        const child: *Self = child_entry.key_ptr.*;
        try child._collectSubtreeRecursive(accumulator, allocator);
    }
    try accumulator.append(allocator, self);
}
