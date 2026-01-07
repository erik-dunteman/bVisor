const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Overlay = @import("../Overlay.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

// Flags for fstatat
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

// Linux stat structure for aarch64 (glibc/musl compatible)
pub const LinuxStat = extern struct {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    __pad1: u64,
    size: i64,
    blksize: i32,
    __pad2: i32,
    blocks: i64,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    __unused: [2]i32,
};

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
statbuf_ptr: u64,
flags: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .statbuf_ptr = notif.data.arg2,
        .flags = @truncate(notif.data.arg3),
    };

    // Read pathname from child memory (may be empty for AT_EMPTY_PATH)
    if (notif.data.arg1 != 0) {
        self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);
        self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;
    const mem_bridge = supervisor.mem_bridge;

    const path = self.pathname[0..self.pathname_len];
    const is_fstat = (self.flags & AT_EMPTY_PATH) != 0 and self.pathname_len == 0;
    const follow_symlinks = (self.flags & AT_SYMLINK_NOFOLLOW) == 0;

    logger.log("Emulating fstatat: dirfd={d} path=\"{s}\" flags=0x{x} is_fstat={} follow={}", .{
        self.dirfd,
        path,
        self.flags,
        is_fstat,
        follow_symlinks,
    });

    // fstat mode: stat an open FD
    if (is_fstat) {
        if (overlay.fstat(self.dirfd)) |stat_result| {
            try writeStatBuf(mem_bridge, self.statbuf_ptr, stat_result);
            logger.log("fstatat: returned overlay stat for fd={d}", .{self.dirfd});
            return .{ .handled = Result.Handled.success(0) };
        }
        // FD not in overlay - passthrough to kernel
        logger.log("fstatat: passthrough for kernel fd={d}", .{self.dirfd});
        return .{ .passthrough = {} };
    }

    // stat/lstat mode: stat by path
    // For lstat (AT_SYMLINK_NOFOLLOW), we don't follow symlinks
    var effective_path = path;

    // If following symlinks, resolve the symlink first
    if (follow_symlinks) {
        if (overlay.readlink(path)) |target| {
            effective_path = target;
        }
    }

    if (overlay.stat(effective_path)) |stat_result| {
        // If lstat on a symlink, return symlink info directly
        if (!follow_symlinks and overlay.isSymlink(path)) {
            if (overlay.stat(path)) |symlink_stat| {
                try writeStatBuf(mem_bridge, self.statbuf_ptr, symlink_stat);
                logger.log("fstatat: returned overlay lstat for symlink path=\"{s}\"", .{path});
                return .{ .handled = Result.Handled.success(0) };
            }
        }

        try writeStatBuf(mem_bridge, self.statbuf_ptr, stat_result);
        logger.log("fstatat: returned overlay stat for path=\"{s}\"", .{effective_path});
        return .{ .handled = Result.Handled.success(0) };
    }

    // Path not in overlay - passthrough to kernel
    logger.log("fstatat: passthrough for path=\"{s}\"", .{path});
    return .{ .passthrough = {} };
}

fn writeStatBuf(mem_bridge: MemoryBridge, statbuf_ptr: u64, stat_result: Overlay.StatResult) !void {
    // Build a stat structure
    var statbuf: LinuxStat = std.mem.zeroes(LinuxStat);

    // Set mode with file type bits
    statbuf.mode = stat_result.mode;
    switch (stat_result.file_type) {
        .regular => statbuf.mode |= linux.S.IFREG,
        .directory => statbuf.mode |= linux.S.IFDIR,
        .symlink => statbuf.mode |= linux.S.IFLNK,
    }

    statbuf.size = @intCast(stat_result.size);
    statbuf.blksize = 4096;
    statbuf.blocks = @intCast((stat_result.size + 511) / 512);
    statbuf.nlink = 1;

    // Write to child memory
    try mem_bridge.write(LinuxStat, statbuf, statbuf_ptr);
}
