const std = @import("std");
const posix = std.posix;

const Cow = @import("backend/cow.zig").Cow;
const Tmp = @import("backend/tmp.zig").Tmp;
const ProcFile = @import("backend/procfile.zig").ProcFile;
const Passthrough = @import("backend/passthrough.zig").Passthrough;

const AtomicUsize = std.atomic.Value(usize);

pub const BackendType = enum { passthrough, cow, tmp, proc };
pub const Backend = union(BackendType) {
    passthrough: Passthrough,
    cow: Cow,
    tmp: Tmp,
    proc: ProcFile,
};

const Self = @This();

backend: Backend,
allocator: std.mem.Allocator,
ref_count: AtomicUsize = undefined,

pub fn init(allocator: std.mem.Allocator, backend: Backend) !*Self {
    const self = try allocator.create(Self);
    errdefer allocator.destroy(self);
    self.* = .{ .backend = backend, .allocator = allocator, .ref_count = AtomicUsize.init(1) };
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
        self.deinit();
    }
}

fn deinit(self: *Self) void {
    self.allocator.destroy(self);
}

pub fn read(self: *Self, buf: []u8) !usize {
    switch (self.backend) {
        .passthrough => |*f| return f.read(buf),
        .cow => |*f| return f.read(buf),
        .tmp => |*f| return f.read(buf),
        .proc => |*f| return f.read(buf),
    }
}

pub fn write(self: *Self, data: []const u8) !usize {
    switch (self.backend) {
        .passthrough => |*f| return f.write(data),
        .cow => |*f| return f.write(data),
        .tmp => |*f| return f.write(data),
        .proc => |*f| return f.write(data),
    }
}

pub fn close(self: *Self) void {
    switch (self.backend) {
        .passthrough => |*f| f.close(),
        .cow => |*f| f.close(),
        .tmp => |*f| f.close(),
        .proc => |*f| f.close(),
    }
}
