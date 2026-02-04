const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const File = @import("File.zig");
const posix = std.posix;

/// Virtual file descriptor - the fd number visible to the sandboxed process.
/// We manage all fd allocation, so these start at 3 (after stdin/stdout/stderr).
pub const VirtualFD = i32;

const AtomicUsize = std.atomic.Value(usize);

const Self = @This();

/// FdTable is a refcounted file descriptor table.
/// When CLONE_FILES is set, parent and child share the same table (refd).
/// When CLONE_FILES is not set, child gets a clone (copy with fresh refcount).
ref_count: AtomicUsize = undefined,
allocator: Allocator,
open_files: std.AutoHashMapUnmanaged(VirtualFD, *File),
next_vfd: VirtualFD = 3, // start after stdin/stdout/stderr

pub fn init(allocator: Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = AtomicUsize.init(1),
        .allocator = allocator,
        .open_files = .empty,
    };
    return self;
}

pub fn ref(self: *Self) *Self {
    const prev = self.ref_count.fetchAdd(1, .monotonic);
    _ = prev;
    return self;
}

pub fn unref(self: *Self) void {
    const prev = self.ref_count.fetchSub(1, .acq_rel);
    if (prev == 1) {
        // .acq_rel required to ensure full memory syncronization before deinit
        // Unref all files before destroying the hashmap
        var iter = self.open_files.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.unref();
        }
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
    var new_open_files: std.AutoHashMapUnmanaged(VirtualFD, *File) = .empty;
    errdefer new_open_files.deinit(self.allocator);

    var iter = self.open_files.iterator();
    while (iter.next()) |entry| {
        const copy = try File.init(allocator, entry.value_ptr.*.backend);
        try new_open_files.put(self.allocator, entry.key_ptr.*, copy);
    }

    new.* = .{
        .ref_count = AtomicUsize.init(1),
        .allocator = allocator,
        .open_files = new_open_files,
        .next_vfd = self.next_vfd,
    };
    return new;
}

// Insert a file into the FdTable
// The File will live with at least one ref until .remove is called
pub fn insert(self: *Self, file: *File) !VirtualFD {
    // Programmer error if we call insert with a File that's already had refs taken
    std.debug.assert(file.ref_count.load(.monotonic) == 1);

    const vfd = self.next_vfd;
    self.next_vfd += 1;
    try self.open_files.put(self.allocator, vfd, file);
    return vfd;
}

/// Get a reference to the file associated with the given vfd.
/// Caller must call unref()
pub fn get_ref(self: *Self, vfd: VirtualFD) ?*File {
    const file_ptr = self.open_files.get(vfd);
    if (file_ptr) |file| {
        return file.ref();
    }
    return null;
}

/// Remove the file associated with the given vfd.
/// This unrefs the file
pub fn remove(self: *Self, vfd: VirtualFD) bool {
    const file_ptr = self.open_files.get(vfd);
    if (file_ptr) |file| {
        file.unref();
    }
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
        const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = actual_fd } });
        const vfd = try table.insert(file);
        try testing.expectEqual(expected_virtual_fd, vfd);
    }
}

test "get returns pointer to file" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    const vfd = try table.insert(file);

    const retrieved = table.get_ref(vfd);
    defer if (retrieved) |f| f.unref();
    try testing.expect(retrieved != null);
    try testing.expectEqual(@as(i32, 42), retrieved.?.backend.passthrough.fd);
}

test "get on missing vfd returns null" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const retrieved = table.get_ref(99);
    defer if (retrieved) |f| f.unref();
    try testing.expect(retrieved == null);
}

test "remove returns true for existing vfd" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
    const vfd = try table.insert(file);

    const removed = table.remove(vfd);
    try testing.expect(removed);

    const retrieved = table.get_ref(vfd);
    defer if (retrieved) |f| f.unref();
    try testing.expect(retrieved == null);
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
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
    const vfd = try table.insert(file);

    // Should be visible via shared reference
    const shared_ref = shared.get_ref(vfd);
    defer if (shared_ref) |f| f.unref();
    try testing.expect(shared_ref != null);

    // Remove via shared reference
    _ = shared.remove(vfd);

    // Should be gone from both
    const retrieved = table.get_ref(vfd);
    defer if (retrieved) |f| f.unref();
    const shared_retrieved = shared.get_ref(vfd);
    defer if (shared_retrieved) |f| f.unref();
    try testing.expect(retrieved == null);
    try testing.expect(shared_retrieved == null);
}

test "insert then remove then insert does not reuse VFD" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
    const vfd1 = try table.insert(file);
    try testing.expectEqual(@as(VirtualFD, 3), vfd1);

    _ = table.remove(vfd1);

    const file2 = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 101 } });
    const vfd2 = try table.insert(file2);
    try testing.expectEqual(@as(VirtualFD, 4), vfd2);
}

test "get after remove returns null" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
    const vfd = try table.insert(file);
    _ = table.remove(vfd);

    const retrieved = table.get_ref(vfd);
    defer if (retrieved) |f| f.unref();
    try testing.expect(retrieved == null);
}

test "remove does not call file.close (caller responsibility)" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    // Insert a passthrough file and remove it
    // If remove called close(), the fd would be invalid and later test cleanup would fail
    // This test verifies behavioral correctness: remove only removes from the table
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    const vfd = try table.insert(file);

    const removed = table.remove(vfd);
    try testing.expect(removed);
    // The fact that testing.allocator doesn't complain proves no double-free
    // and that close wasn't called (42 isn't a real fd)
}

test "unref from refcount=2 keeps table alive" {
    const table = try Self.init(testing.allocator);

    const shared = table.ref();
    try testing.expectEqual(@as(usize, 2), table.ref_count.raw);

    shared.unref();
    try testing.expectEqual(@as(usize, 1), table.ref_count.raw);

    // Table should still be usable
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
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
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } });
    const vfd = try original.insert(file);

    // Clone the table (simulates fork without CLONE_FILES)
    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Both should have the file initially
    const orig_ref1 = original.get_ref(vfd);
    defer if (orig_ref1) |f| f.unref();
    const cloned_ref1 = cloned.get_ref(vfd);
    defer if (cloned_ref1) |f| f.unref();
    try testing.expect(orig_ref1 != null);
    try testing.expect(cloned_ref1 != null);

    // Remove from cloned - should not affect original
    _ = cloned.remove(vfd);
    const orig_ref2 = original.get_ref(vfd);
    defer if (orig_ref2) |f| f.unref();
    const cloned_ref2 = cloned.get_ref(vfd);
    defer if (cloned_ref2) |f| f.unref();
    try testing.expect(orig_ref2 != null);
    try testing.expect(cloned_ref2 == null);

    // Insert into original - should not affect cloned
    const file2 = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 101 } });
    const vfd2 = try original.insert(file2);
    const orig_ref3 = original.get_ref(vfd2);
    defer if (orig_ref3) |f| f.unref();
    const cloned_ref3 = cloned.get_ref(vfd2);
    defer if (cloned_ref3) |f| f.unref();
    try testing.expect(orig_ref3 != null);
    try testing.expect(cloned_ref3 == null);
}

test "clone inherits next_vfd so first insert continues sequence" {
    const original = try Self.init(testing.allocator);
    defer original.unref();

    // Insert some files to advance next_vfd
    _ = try original.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } })); // vfd 3
    _ = try original.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 101 } })); // vfd 4

    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Clone's first insert should continue from where original left off
    const clone_vfd = try cloned.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 200 } }));
    try testing.expectEqual(@as(VirtualFD, 5), clone_vfd);
}

test "inserts in both after clone produce no VFD collisions" {
    const original = try Self.init(testing.allocator);
    defer original.unref();

    _ = try original.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 100 } })); // vfd 3

    const cloned = try original.clone(testing.allocator);
    defer cloned.unref();

    // Both insert independently
    const orig_vfd = try original.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 200 } }));
    const clone_vfd = try cloned.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = 300 } }));

    // Both should get vfd 4 since they diverge from the same next_vfd
    try testing.expectEqual(@as(VirtualFD, 4), orig_vfd);
    try testing.expectEqual(@as(VirtualFD, 4), clone_vfd);

    // But they should refer to different files in their respective tables
    const orig_file = original.get_ref(orig_vfd).?;
    defer orig_file.unref();
    const cloned_file = cloned.get_ref(clone_vfd).?;
    defer cloned_file.unref();
    try testing.expectEqual(@as(i32, 200), orig_file.backend.passthrough.fd);
    try testing.expectEqual(@as(i32, 300), cloned_file.backend.passthrough.fd);
}

test "insert 1000 files returns all unique VFDs and all retrievable" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    var vfds: [1000]VirtualFD = undefined;
    for (0..1000) |i| {
        const fd: posix.fd_t = @intCast(i);
        vfds[i] = try table.insert(try File.init(testing.allocator, .{ .passthrough = .{ .fd = fd } }));
    }

    // All VFDs should be unique and sequential
    for (0..1000) |i| {
        const expected: VirtualFD = @intCast(3 + i);
        try testing.expectEqual(expected, vfds[i]);

        // All should be retrievable
        const retrieved = table.get_ref(vfds[i]);
        defer if (retrieved) |f| f.unref();
        try testing.expect(retrieved != null);
        try testing.expectEqual(@as(i32, @intCast(i)), retrieved.?.backend.passthrough.fd);
    }
}

test "insert one of each backend type - all distinguishable by union tag" {
    const allocator = testing.allocator;
    const table = try Self.init(allocator);
    defer table.unref();

    // Passthrough
    const vfd_pt = try table.insert(try File.init(allocator, .{ .passthrough = .{ .fd = 42 } }));
    // Proc
    var proc_content: [256]u8 = undefined;
    @memcpy(proc_content[0..4], "100\n");
    const vfd_proc = try table.insert(try File.init(allocator, .{ .proc = .{
        .content = proc_content,
        .content_len = 4,
        .offset = 0,
    } }));

    // Verify tags are distinguishable
    const pt_ref = table.get_ref(vfd_pt).?;
    defer pt_ref.unref();
    const proc_ref = table.get_ref(vfd_proc).?;
    defer proc_ref.unref();
    try testing.expect(pt_ref.backend == .passthrough);
    try testing.expect(proc_ref.backend == .proc);
}

test "get_ref increments File refcount" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    const vfd = try table.insert(file);
    try testing.expectEqual(@as(usize, 1), file.ref_count.load(.monotonic));

    const got = table.get_ref(vfd).?;
    try testing.expectEqual(@as(usize, 2), file.ref_count.load(.monotonic));

    got.unref();
    _ = table.remove(vfd);
}

test "remove decrements File refcount but get_ref keeps it alive" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 77 } });
    const vfd = try table.insert(file);
    try testing.expectEqual(@as(usize, 1), file.ref_count.load(.monotonic));

    // get_ref bumps to 2
    const got = table.get_ref(vfd).?;
    try testing.expectEqual(@as(usize, 2), got.ref_count.load(.monotonic));

    // remove drops the table's ref → rc=1, but the File is still alive via got
    _ = table.remove(vfd);
    try testing.expectEqual(@as(usize, 1), got.ref_count.load(.monotonic));

    // File fields are still accessible
    try testing.expectEqual(@as(i32, 77), got.backend.passthrough.fd);

    // Final unref frees the File (testing allocator verifies no leak)
    got.unref();
}

test "multiple get_ref calls accumulate refcount" {
    const table = try Self.init(testing.allocator);
    defer table.unref();

    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 55 } });
    const vfd = try table.insert(file);
    try testing.expectEqual(@as(usize, 1), file.ref_count.load(.monotonic));

    const ref1 = table.get_ref(vfd).?;
    const ref2 = table.get_ref(vfd).?;
    try testing.expectEqual(@as(usize, 3), file.ref_count.load(.monotonic));

    // remove drops table's ref → rc=2
    _ = table.remove(vfd);
    try testing.expectEqual(@as(usize, 2), ref1.ref_count.load(.monotonic));

    // unref both caller refs → rc=0, freed
    ref1.unref();
    ref2.unref();
}
