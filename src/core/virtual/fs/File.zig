const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Thread = @import("../proc/Thread.zig");
const OverlayRoot = @import("../OverlayRoot.zig");

const Cow = @import("backend/cow.zig").Cow;
const Tmp = @import("backend/tmp.zig").Tmp;
const ProcFile = @import("backend/procfile.zig").ProcFile;
const Passthrough = @import("backend/passthrough.zig").Passthrough;

const types = @import("../../types.zig");
const Stat = types.Stat;

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
    self.* = .{
        .backend = backend,
        .allocator = allocator,
        .ref_count = AtomicUsize.init(1),
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
        self.deinit();
    }
}

fn deinit(self: *Self) void {
    self.close();
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

fn close(self: *Self) void {
    switch (self.backend) {
        .passthrough => |*f| f.close(),
        .cow => |*f| f.close(),
        .tmp => |*f| f.close(),
        .proc => |*f| f.close(),
    }
}

pub fn statx(self: *Self) !linux.Statx {
    switch (self.backend) {
        .passthrough => |*f| return f.statx(),
        .cow => |*f| return f.statx(),
        .tmp => |*f| return f.statx(),
        .proc => |*f| return f.statx(),
    }
}

pub fn statxByPath(backend_type: BackendType, overlay: *OverlayRoot, path: []const u8, caller: ?*Thread) !linux.Statx {
    return switch (backend_type) {
        .passthrough => Passthrough.statxByPath(path),
        .cow => Cow.statxByPath(overlay, path),
        .tmp => Tmp.statxByPath(overlay, path),
        .proc => ProcFile.statxByPath(caller.?, path),
    };
}

/// Convert a `linux.Statx` (internal representation used by all File backends)
/// into the aarch64 `struct stat` ABI expected by fstat(2) callers.
///
/// Only fields whose corresponding `statx.mask` bits are set are considered
/// populated; unset fields are left as zero in the output.
pub fn statxToStat(sx: linux.Statx) Stat {
    var st: Stat = std.mem.zeroes(Stat);

    if (sx.mask.MODE) st.st_mode = sx.mode;
    if (sx.mask.NLINK) st.st_nlink = sx.nlink;
    if (sx.mask.SIZE) st.st_size = @bitCast(sx.size);
    if (sx.mask.INO) st.st_ino = sx.ino;

    // UID/GID share a single mask bit in statx
    if (sx.mask.UID) st.st_uid = sx.uid;
    if (sx.mask.GID) st.st_gid = sx.gid;

    if (sx.mask.ATIME) {
        st.st_atime = sx.atime.sec;
        st.st_atime_nsec = @intCast(sx.atime.nsec);
    }
    if (sx.mask.MTIME) {
        st.st_mtime = sx.mtime.sec;
        st.st_mtime_nsec = @intCast(sx.mtime.nsec);
    }
    if (sx.mask.CTIME) {
        st.st_ctime = sx.ctime.sec;
        st.st_ctime_nsec = @intCast(sx.ctime.nsec);
    }
    if (sx.mask.BLOCKS) st.st_blocks = @bitCast(sx.blocks);

    // Kernel always populates blksize regardless of the mask
    st.st_blksize = @intCast(sx.blksize);

    // dev/rdev: statx splits these into major/minor pairs.
    // Recombine with the standard makedev formula: (major << 8) | minor.
    // This matches the glibc/musl makedev() for basic device numbers.
    st.st_dev = (sx.dev_minor & 0xff) | (@as(u64, sx.dev_major) << 8) | (@as(u64, sx.dev_minor & ~@as(u32, 0xff)) << 12);
    st.st_rdev = (@as(u64, sx.rdev_major) << 8) | sx.rdev_minor;

    return st;
}
