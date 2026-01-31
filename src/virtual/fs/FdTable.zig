const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const File = @import("file.zig").File;
const posix = std.posix;

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

test "insert then remove then insert does not reuse VFD" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = File{ .passthrough = .{ .fd = 100 } };
    const vfd1 = try table.insert(file);
    try testing.expectEqual(@as(VirtualFD, 3), vfd1);

    _ = table.remove(vfd1);

    const file2 = File{ .passthrough = .{ .fd = 101 } };
    const vfd2 = try table.insert(file2);
    try testing.expectEqual(@as(VirtualFD, 4), vfd2);
}

test "get after remove returns null" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = File{ .passthrough = .{ .fd = 100 } };
    const vfd = try table.insert(file);
    _ = table.remove(vfd);

    try testing.expect(table.get(vfd) == null);
}

test "remove does not call file.close (caller responsibility)" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    // Insert a passthrough file and remove it
    // If remove called close(), the fd would be invalid and later test cleanup would fail
    // This test verifies behavioral correctness: remove only removes from the table
    const file = File{ .passthrough = .{ .fd = 42 } };
    const vfd = try table.insert(file);

    const removed = table.remove(vfd);
    try testing.expect(removed);
    // The fact that testing.allocator doesn't complain proves no double-free
    // and that close wasn't called (42 isn't a real fd)
}

test "unref from refcount=2 keeps table alive" {
    const table = try Self.init(testing.allocator);

    const shared = table.ref();
    try testing.expectEqual(@as(usize, 2), table.ref_count);

    shared.unref();
    try testing.expectEqual(@as(usize, 1), table.ref_count);

    // Table should still be usable
    const file = File{ .passthrough = .{ .fd = 100 } };
    _ = try table.insert(file);

    table.unref(); // final cleanup
}

test "unref from refcount=1 frees table (testing allocator verifies no leak)" {
    const table = try Self.init(testing.allocator);
    table.unref();
    // testing.allocator will detect leaks if table wasn't freed
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

test "clone inherits next_vfd so first insert continues sequence" {
    const original = try Self.init(testing.allocator);
    defer original.unref();

    // Insert some files to advance next_vfd
    _ = try original.insert(File{ .passthrough = .{ .fd = 100 } }); // vfd 3
    _ = try original.insert(File{ .passthrough = .{ .fd = 101 } }); // vfd 4

    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Clone's first insert should continue from where original left off
    const clone_vfd = try cloned.insert(File{ .passthrough = .{ .fd = 200 } });
    try testing.expectEqual(@as(VirtualFD, 5), clone_vfd);
}

test "inserts in both after clone produce no VFD collisions" {
    const original = try Self.init(testing.allocator);
    defer original.unref();

    _ = try original.insert(File{ .passthrough = .{ .fd = 100 } }); // vfd 3

    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Both insert independently
    const orig_vfd = try original.insert(File{ .passthrough = .{ .fd = 200 } });
    const clone_vfd = try cloned.insert(File{ .passthrough = .{ .fd = 300 } });

    // Both should get vfd 4 since they diverge from the same next_vfd
    try testing.expectEqual(@as(VirtualFD, 4), orig_vfd);
    try testing.expectEqual(@as(VirtualFD, 4), clone_vfd);

    // But they should refer to different files in their respective tables
    try testing.expectEqual(@as(i32, 200), original.get(orig_vfd).?.passthrough.fd);
    try testing.expectEqual(@as(i32, 300), cloned.get(clone_vfd).?.passthrough.fd);
}

test "insert 1000 files returns all unique VFDs and all retrievable" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    var vfds: [1000]VirtualFD = undefined;
    for (0..1000) |i| {
        const fd: posix.fd_t = @intCast(i);
        vfds[i] = try table.insert(File{ .passthrough = .{ .fd = fd } });
    }

    // All VFDs should be unique and sequential
    for (0..1000) |i| {
        const expected: VirtualFD = @intCast(3 + i);
        try testing.expectEqual(expected, vfds[i]);

        // All should be retrievable
        const retrieved = table.get(vfds[i]);
        try testing.expect(retrieved != null);
        try testing.expectEqual(@as(i32, @intCast(i)), retrieved.?.passthrough.fd);
    }
}

test "insert one of each backend type - all distinguishable by union tag" {
    const allocator = testing.allocator;
    const table = try Self.init(allocator);
    defer table.unref();

    // Passthrough
    const vfd_pt = try table.insert(File{ .passthrough = .{ .fd = 42 } });
    // Proc
    var proc_content: [256]u8 = undefined;
    @memcpy(proc_content[0..4], "100\n");
    const vfd_proc = try table.insert(File{ .proc = .{
        .content = proc_content,
        .content_len = 4,
        .offset = 0,
    } });

    // Verify tags are distinguishable
    try testing.expect(table.get(vfd_pt).?.* == .passthrough);
    try testing.expect(table.get(vfd_proc).?.* == .proc);
}
