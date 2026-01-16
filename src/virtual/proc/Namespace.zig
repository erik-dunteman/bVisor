const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");

pub const VirtualPID = linux.pid_t;

const VpidLookup = std.AutoHashMapUnmanaged(VirtualPID, *Proc);

const Self = @This();

/// Namespaces are refcounted and shared between procs.
/// Each namespace tracks all procs visible to it (own procs + procs in child namespaces).

ref_count: usize,
allocator: Allocator,
vpid_counter: VirtualPID = 0,
parent: ?*Self,
procs: VpidLookup = .empty,

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
pub fn register_proc(self: *Self, allocator: Allocator, proc: *Proc) !void {
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
pub fn unregister_proc(self: *Self, proc: *Proc) void {
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
