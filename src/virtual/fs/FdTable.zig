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

//todo: reintroduce tests when File backends are implemented
