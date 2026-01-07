const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

target_ptr: u64,
target: [256]u8,
target_len: usize,
newdirfd: i32,
linkpath_ptr: u64,
linkpath: [256]u8,
linkpath_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .target_ptr = notif.data.arg0,
        .target = undefined,
        .target_len = 0,
        .newdirfd = @bitCast(@as(u32, @truncate(notif.data.arg1))),
        .linkpath_ptr = notif.data.arg2,
        .linkpath = undefined,
        .linkpath_len = 0,
    };

    // Read target path from child memory
    self.target = try mem_bridge.read([256]u8, notif.data.arg0);
    self.target_len = std.mem.indexOfScalar(u8, &self.target, 0) orelse 256;

    // Read linkpath from child memory
    self.linkpath = try mem_bridge.read([256]u8, notif.data.arg2);
    self.linkpath_len = std.mem.indexOfScalar(u8, &self.linkpath, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    const target = self.target[0..self.target_len];
    const linkpath = self.linkpath[0..self.linkpath_len];

    logger.log("Emulating symlinkat: target=\"{s}\" newdirfd={d} linkpath=\"{s}\"", .{
        target,
        self.newdirfd,
        linkpath,
    });

    // All symlinks are virtualized - stored in overlay to prevent escape
    overlay.symlink(target, linkpath) catch |err| {
        logger.log("symlinkat: failed: {}", .{err});
        return switch (err) {
            error.FileExists => .{ .handled = Result.Handled.err(.EXIST) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("symlinkat: created overlay symlink", .{});
    return .{ .handled = Result.Handled.success(0) };
}
