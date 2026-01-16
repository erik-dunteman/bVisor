const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const FD = @import("FD.zig").FD;

const KernelFD = types.KernelFD;

/// Virtual file descriptor - the fd number visible to the sandboxed process.
/// We manage all fd allocation, so these start at 3 (after stdin/stdout/stderr).
pub const VirtualFD = i32;

const Self = @This();

/// FdTable is a refcounted file descriptor table.
/// When CLONE_FILES is set, parent and child share the same table (refd).
/// When CLONE_FILES is not set, child gets a clone (copy with fresh refcount).
ref_count: usize,
allocator: Allocator,
fds: std.AutoHashMapUnmanaged(VirtualFD, FD),
next_vfd: VirtualFD = 3, // start after stdin/stdout/stderr

pub fn init(allocator: Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = 1,
        .allocator = allocator,
        .fds = .empty,
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
        self.fds.deinit(self.allocator);
        self.allocator.destroy(self);
    }
}

/// Create an independent copy with refcount=1.
/// Used when CLONE_FILES is not set.
pub fn clone(self: *Self) !*Self {
    const new = try self.allocator.create(Self);
    errdefer self.allocator.destroy(new);

    // AutoHashMapUnmanaged has no clone(), so we iterate manually
    var new_fds: std.AutoHashMapUnmanaged(VirtualFD, FD) = .empty;
    errdefer new_fds.deinit(self.allocator);

    var iter = self.fds.iterator();
    while (iter.next()) |entry| {
        try new_fds.put(self.allocator, entry.key_ptr.*, entry.value_ptr.*);
    }

    new.* = .{
        .ref_count = 1,
        .allocator = self.allocator,
        .fds = new_fds,
        .next_vfd = self.next_vfd,
    };
    return new;
}

pub fn insert(self: *Self, vfd: VirtualFD, file: FD) !void {
    try self.fds.put(self.allocator, vfd, file);
}

/// Allocate a new virtual fd number, insert the file, and return the vfd
pub fn open(self: *Self, file: FD) !VirtualFD {
    const vfd = self.next_vfd;
    self.next_vfd += 1;
    try self.fds.put(self.allocator, vfd, file);
    return vfd;
}

pub fn get(self: *Self, vfd: VirtualFD) ?*FD {
    return self.fds.getPtr(vfd);
}

pub fn remove(self: *Self, vfd: VirtualFD) bool {
    return self.fds.remove(vfd);
}

const testing = std.testing;

test "FdTable refcount - ref increases count" {
    const allocator = testing.allocator;
    const table1 = try Self.init(allocator);
    defer table1.unref();

    try testing.expectEqual(1, table1.ref_count);

    const table2 = table1.ref();
    try testing.expectEqual(2, table1.ref_count);
    try testing.expect(table1 == table2);

    table2.unref();
    try testing.expectEqual(1, table1.ref_count);
}

test "FdTable refcount - unref at zero frees" {
    const allocator = testing.allocator;
    const table = try Self.init(allocator);
    table.unref();
    // No leak detected by testing.allocator
}

test "FdTable clone creates independent copy" {
    const allocator = testing.allocator;
    const table1 = try Self.init(allocator);
    defer table1.unref();

    // Insert an FD
    try table1.insert(5, .{ .proc = .{ .self = .{ .vpid = 42 } } });

    const table2 = try table1.clone();
    defer table2.unref();

    try testing.expect(table1 != table2);
    try testing.expectEqual(1, table1.ref_count);
    try testing.expectEqual(1, table2.ref_count);

    // Both should have the FD
    try testing.expect(table1.get(5) != null);
    try testing.expect(table2.get(5) != null);

    // Removing from one doesn't affect the other
    _ = table2.remove(5);
    try testing.expect(table1.get(5) != null);
    try testing.expect(table2.get(5) == null);
}

test "FdTable insert and get" {
    const allocator = testing.allocator;
    const table = try Self.init(allocator);
    defer table.unref();

    try table.insert(3, .{ .proc = .{ .self = .{ .vpid = 7 } } });

    const fd_ptr = table.get(3);
    try testing.expect(fd_ptr != null);

    // Verify it's the right FD by reading from it
    var buf: [16]u8 = undefined;
    const n = try fd_ptr.?.read(&buf);
    try testing.expectEqualStrings("7\n", buf[0..n]);
}

test "FdTable remove" {
    const allocator = testing.allocator;
    const table = try Self.init(allocator);
    defer table.unref();

    try table.insert(10, .{ .proc = .{ .self = .{ .vpid = 99 } } });
    try testing.expect(table.get(10) != null);

    const removed = table.remove(10);
    try testing.expect(removed);
    try testing.expect(table.get(10) == null);

    const removed_again = table.remove(10);
    try testing.expect(!removed_again);
}

test "CLONE_FILES set - shared table, changes visible to both" {
    const allocator = testing.allocator;

    // Parent creates table
    const parent_table = try Self.init(allocator);
    defer parent_table.unref();

    // Child with CLONE_FILES shares the table (ref, not clone)
    const child_table = parent_table.ref();
    defer child_table.unref();

    // Same pointer
    try testing.expect(parent_table == child_table);
    try testing.expectEqual(@as(usize, 2), parent_table.ref_count);

    // Parent opens a file
    const vfd1 = try parent_table.open(.{ .proc = .{ .self = .{ .vpid = 1 } } });
    try testing.expectEqual(@as(VirtualFD, 3), vfd1);

    // Child can see it
    try testing.expect(child_table.get(vfd1) != null);

    // Child opens a file
    const vfd2 = try child_table.open(.{ .proc = .{ .self = .{ .vpid = 2 } } });
    try testing.expectEqual(@as(VirtualFD, 4), vfd2);

    // Parent can see it
    try testing.expect(parent_table.get(vfd2) != null);

    // Child closes a file - parent also loses it
    _ = child_table.remove(vfd1);
    try testing.expect(parent_table.get(vfd1) == null);
}

test "CLONE_FILES not set - cloned table, changes independent" {
    const allocator = testing.allocator;

    // Parent creates table and opens a file
    const parent_table = try Self.init(allocator);
    defer parent_table.unref();

    const vfd1 = try parent_table.open(.{ .proc = .{ .self = .{ .vpid = 1 } } });
    try testing.expectEqual(@as(VirtualFD, 3), vfd1);

    // Child without CLONE_FILES gets a clone
    const child_table = try parent_table.clone();
    defer child_table.unref();

    // Different pointers
    try testing.expect(parent_table != child_table);
    try testing.expectEqual(@as(usize, 1), parent_table.ref_count);
    try testing.expectEqual(@as(usize, 1), child_table.ref_count);

    // Child inherited the file
    try testing.expect(child_table.get(vfd1) != null);

    // Child inherited next_vfd counter
    const vfd2 = try child_table.open(.{ .proc = .{ .self = .{ .vpid = 2 } } });
    try testing.expectEqual(@as(VirtualFD, 4), vfd2);

    // Parent opens another - gets same vfd since counters are independent now
    const vfd3 = try parent_table.open(.{ .proc = .{ .self = .{ .vpid = 3 } } });
    try testing.expectEqual(@as(VirtualFD, 4), vfd3);

    // Child closes inherited file - parent still has it
    _ = child_table.remove(vfd1);
    try testing.expect(parent_table.get(vfd1) != null);
    try testing.expect(child_table.get(vfd1) == null);

    // Parent's vfd3 is not visible to child (different tables)
    try testing.expect(child_table.get(vfd3) != null); // child has its own vfd4
    // But they're different FDs with different vpids
    var parent_buf: [16]u8 = undefined;
    var child_buf: [16]u8 = undefined;
    const parent_fd = parent_table.get(vfd3).?;
    const child_fd = child_table.get(vfd2).?;
    const pn = try parent_fd.read(&parent_buf);
    const cn = try child_fd.read(&child_buf);
    try testing.expectEqualStrings("3\n", parent_buf[0..pn]);
    try testing.expectEqualStrings("2\n", child_buf[0..cn]);
}
