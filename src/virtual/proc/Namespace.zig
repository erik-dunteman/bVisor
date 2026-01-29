const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");
const NsPid = Proc.NsPid;
const AbsPid = Proc.AbsPid;
const proc_info = @import("../../deps/proc_info/proc_info.zig");

const ProcMap = std.AutoHashMapUnmanaged(NsPid, *Proc);

const Self = @This();

/// Namespaces are refcounted and shared between procs.
/// Used for visibility filtering - processes can only see other processes
/// in the same namespace or descendent namespaces.
ref_count: usize,
allocator: Allocator,
parent: ?*Self,
procs: ProcMap = .empty,

pub fn init(allocator: Allocator, parent: ?*Self) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = 1,
        .allocator = allocator,
        // TODO: check consistency of calling p.ref() here versus elsewhere
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
/// Reads NSpid from /proc/[pid]/status to get the guest PID for each namespace level.
/// NSpid format: "NSpid: 15234  892  7  1" (outermost to innermost)
pub fn registerProc(self: *Self, allocator: Allocator, proc: *Proc, supervisor_pid: AbsPid) !void {
    // Read NSpid chain from kernel. Gives us PIDs from outermost to innermost namespace
    var nspid_buf: [128]NsPid = undefined;
    const nspids = try proc_info.readNsPids(supervisor_pid, &nspid_buf);

    // Count namespace depth (self + ancestors)
    var ns_depth: usize = 1;
    var ns = self.parent;
    while (ns) |p| : (ns = p.parent) {
        ns_depth += 1;
    }

    // NSpid length should match namespace depth
    if (nspids.len != ns_depth) {
        return error.NamespaceDepthMismatch;
    }

    // Register in own namespace
    try self.procs.put(allocator, nspids[nspids.len - 1], proc);

    // Register in all ancestor namespaces (walking backwards through nspids)
    // Only enter loop if there are ancestors (nspids.len > 1)
    if (nspids.len > 1) {
        var ancestor = self.parent;
        var idx: usize = nspids.len - 2; // Start from second-to-last
        while (ancestor) |anc_ns| {
            try anc_ns.procs.put(allocator, nspids[idx], proc);
            ancestor = anc_ns.parent;
            if (idx == 0) break;
            idx -= 1;
        }
    }
}

/// Unregister a proc from this namespace and all ancestor namespaces.
pub fn unregisterProc(self: *Self, proc: *Proc) void {
    // Find and remove from own namespace
    if (self.getNsPid(proc)) |guest_pid| {
        _ = self.procs.remove(guest_pid);
    }

    // Remove from all ancestor namespaces
    var ancestor = self.parent;
    while (ancestor) |ns| {
        if (ns.getNsPid(proc)) |guest_pid| {
            _ = ns.procs.remove(guest_pid);
        }
        ancestor = ns.parent;
    }
}

/// Check if a proc is visible in this namespace.
pub fn contains(self: *Self, proc: *Proc) bool {
    return self.getNsPid(proc) != null;
}

/// Reverse lookup in ProcMap for guest PID of a Proc
pub fn getNsPid(self: *Self, proc: *Proc) ?NsPid {
    var iterator = self.procs.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr;
        const val = entry.value_ptr;
        if (val.* == proc) return key.*;
    }
    return null;
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
