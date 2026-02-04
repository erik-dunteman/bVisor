const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const Thread = @import("Thread.zig");
// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const ThreadMap = std.AutoHashMapUnmanaged(AbsTid, *Thread);

const Self = @This();

/// ThreadGroups are refcounted and shared between Thread-s.
ref_count: usize,
allocator: Allocator,
tgid: AbsTgid,
parent: ?*Self,
threads: ThreadMap = .empty,

pub fn init(allocator: Allocator, tgid: AbsTgid, parent: ?*Self) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = 1,
        .allocator = allocator,
        .tgid = tgid,
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
        self.threads.deinit(self.allocator);
        self.allocator.destroy(self);
    }
}

pub inline fn getLeader(self: *Self) !*Thread {
    return self.threads.get(self.tgid) orelse error.LeaderNotFound;
}

/// Register a Thread in this ThreadGroup
pub fn registerThread(self: *Self, allocator: Allocator, thread: *Thread) !void {
    try self.threads.put(allocator, thread.tid, thread);
}

/// Unregister a Thread from this ThreadGroup
pub fn unregisterThread(self: *Self, thread: *Thread) void {
    // Reverse lookup to remove
    var iterator = self.threads.iterator();
    while (iterator.next()) |entry| {
        if (entry.value_ptr.* == thread) {
            _ = self.threads.remove(entry.key_ptr.*);
            return;
        }
    }
}
