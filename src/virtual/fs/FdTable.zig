const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const File = @import("file.zig").File;
const posix = std.posix;

const SupervisorFD = types.SupervisorFD;

/// Virtual file descriptor - the fd number visible to the sandboxed process.
/// We manage all fd allocation, so these start at 3 (after stdin/stdout/stderr).
pub const VirtualFD = i32;

const Self = @This();

/// FdTable is a refcounted file descriptor table.
/// When CLONE_FILES is set, parent and child share the same table (refd).
/// When CLONE_FILES is not set, child gets a clone (copy with fresh refcount).
ref_count: usize,
allocator: Allocator,
open_files: std.AutoHashMapUnmanaged(VirtualFD, File),
next_vfd: VirtualFD = 3, // start after stdin/stdout/stderr

pub fn init(allocator: Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = 1,
        .allocator = allocator,
        .open_files = .empty,
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
        self.open_files.deinit(self.allocator);
        self.allocator.destroy(self);
    }
}

/// Create an independent copy with refcount=1.
/// Used when CLONE_FILES is not set.
pub fn clone(self: *Self, allocator: Allocator) !*Self {
    const new = try allocator.create(Self);
    errdefer self.allocator.destroy(new);

    // AutoHashMapUnmanaged has no clone(), so we iterate manually
    var new_open_files: std.AutoHashMapUnmanaged(VirtualFD, File) = .empty;
    errdefer new_open_files.deinit(self.allocator);

    var iter = self.open_files.iterator();
    while (iter.next()) |entry| {
        // performs value copy
        try new_open_files.put(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
    }

    new.* = .{
        .ref_count = 1,
        .allocator = allocator,
        .open_files = new_open_files,
        .next_vfd = self.next_vfd,
    };
    return new;
}

pub fn insert(self: *Self, file: File) !VirtualFD {
    const vfd = self.next_vfd;
    self.next_vfd += 1;
    try self.open_files.put(self.allocator, vfd, file);
    return vfd;
}

pub fn get(self: *Self, vfd: VirtualFD) ?*File {
    return self.open_files.getPtr(vfd);
}

pub fn remove(self: *Self, vfd: VirtualFD) bool {
    return self.open_files.remove(vfd);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const ProcFile = @import("backend/procfile.zig").ProcFile;

test "insert returns incrementing vfds starting at 3" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    for (0..10) |i| {
        const actual_fd: posix.fd_t = @intCast(100 + i);
        const expected_virtual_fd: VirtualFD = @intCast(3 + i);
        const file = File{ .passthrough = .{ .fd = actual_fd } };
        const vfd = try table.insert(file);
        try testing.expectEqual(expected_virtual_fd, vfd);
    }
}

test "get returns pointer to file" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = File{ .passthrough = .{ .fd = 42 } };
    const vfd = try table.insert(file);

    const retrieved = table.get(vfd);
    try testing.expect(retrieved != null);
    try testing.expectEqual(@as(i32, 42), retrieved.?.passthrough.fd);
}

test "get on missing vfd returns null" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const retrieved = table.get(99);
    try testing.expect(retrieved == null);
}

test "remove returns true for existing vfd" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = File{ .passthrough = .{ .fd = 100 } };
    const vfd = try table.insert(file);

    const removed = table.remove(vfd);
    try testing.expect(removed);
    try testing.expect(table.get(vfd) == null);
}

test "remove returns false for missing vfd" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const removed = table.remove(99);
    try testing.expect(!removed);
}

test "CLONE_FILES scenario: shared table, changes visible to both" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    // Simulate CLONE_FILES by ref'ing the same table
    const shared = table.ref();
    defer shared.unref();

    // Insert via original
    const file = File{ .passthrough = .{ .fd = 100 } };
    const vfd = try table.insert(file);

    // Should be visible via shared reference
    try testing.expect(shared.get(vfd) != null);

    // Remove via shared reference
    _ = shared.remove(vfd);

    // Should be gone from both
    try testing.expect(table.get(vfd) == null);
    try testing.expect(shared.get(vfd) == null);
}

test "CLONE_FILES not set: cloned table, changes independent" {
    const original = try Self.init(testing.allocator);
    defer original.unref();

    // Insert a file into original
    const file = File{ .passthrough = .{ .fd = 100 } };
    const vfd = try original.insert(file);

    // Clone the table (simulates fork without CLONE_FILES)
    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Both should have the file initially
    try testing.expect(original.get(vfd) != null);
    try testing.expect(cloned.get(vfd) != null);

    // Remove from cloned - should not affect original
    _ = cloned.remove(vfd);
    try testing.expect(original.get(vfd) != null);
    try testing.expect(cloned.get(vfd) == null);

    // Insert into original - should not affect cloned
    const file2 = File{ .passthrough = .{ .fd = 101 } };
    const vfd2 = try original.insert(file2);
    try testing.expect(original.get(vfd2) != null);
    try testing.expect(cloned.get(vfd2) == null);
}
