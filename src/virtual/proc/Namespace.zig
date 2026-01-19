const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");

const ProcSet = std.AutoHashMapUnmanaged(*Proc, void);

const Self = @This();

/// Namespaces are refcounted and shared between procs.
/// Used for visibility filtering - processes can only see other processes
/// in the same namespace or descendent namespaces.
ref_count: usize,
allocator: Allocator,
parent: ?*Self,
procs: ProcSet = .empty,

pub fn init(allocator: Allocator, parent: ?*Self) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = 1,
        .allocator = allocator,
        .parent = if (parent) |p| p.ref() else null,
    };
    return self;
}

pub fn ref(self: *Self) *Self {
    self.ref_count += 1;
    return self;
}

pub fn unref(self: *Self) void {
    self.ref_count -= 1;
    if (self.ref_count == 0) {
        if (self.parent) |p| p.unref();
        self.procs.deinit(self.allocator);
        self.allocator.destroy(self);
    }
}

/// Register a proc in this namespace and all ancestor namespaces.
pub fn register_proc(self: *Self, allocator: Allocator, proc: *Proc) !void {
    try self.procs.put(allocator, proc, {});

    // Register in all ancestor namespaces for visibility
    var ancestor = self.parent;
    while (ancestor) |ns| {
        try ns.procs.put(allocator, proc, {});
        ancestor = ns.parent;
    }
}

/// Unregister a proc from this namespace and all ancestor namespaces.
pub fn unregister_proc(self: *Self, proc: *Proc) void {
    _ = self.procs.remove(proc);

    // Remove from all ancestor namespaces
    var ancestor = self.parent;
    while (ancestor) |ns| {
        _ = ns.procs.remove(proc);
        ancestor = ns.parent;
    }
}

/// Check if a proc is visible in this namespace.
pub fn contains(self: *Self, proc: *Proc) bool {
    return self.procs.contains(proc);
}

const testing = std.testing;

test "Namespace refcount - ref increases count" {
    const allocator = testing.allocator;
    const ns1 = try Self.init(allocator, null);
    defer ns1.unref();

    try testing.expectEqual(1, ns1.ref_count);

    const ns2 = ns1.ref();
    try testing.expectEqual(2, ns1.ref_count);
    try testing.expect(ns1 == ns2);

    ns2.unref();
    try testing.expectEqual(1, ns1.ref_count);
}

test "Namespace refcount - unref at zero frees" {
    const allocator = testing.allocator;
    const ns = try Self.init(allocator, null);
    ns.unref();
    // No leak detected by testing.allocator
}

test "Namespace refcount - child holds parent" {
    const allocator = testing.allocator;
    const parent = try Self.init(allocator, null);

    const child = try Self.init(allocator, parent);
    try testing.expectEqual(2, parent.ref_count); // original + child reference

    parent.unref(); // refcount -> 1
    try testing.expectEqual(1, parent.ref_count);

    child.unref(); // child frees, then parent refcount -> 0, parent frees
    // No leaks detected by testing.allocator
}
