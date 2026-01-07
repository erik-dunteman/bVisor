const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

const AT_REMOVEDIR: u32 = 0x200;

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
flags: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .flags = @truncate(notif.data.arg2),
    };

    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    const path = self.pathname[0..self.pathname_len];
    const is_rmdir = (self.flags & AT_REMOVEDIR) != 0;

    logger.log("Emulating unlinkat: dirfd={d} path=\"{s}\" flags=0x{x} rmdir={}", .{
        self.dirfd,
        path,
        self.flags,
        is_rmdir,
    });

    if (is_rmdir) {
        overlay.rmdir(path) catch |err| {
            logger.log("unlinkat: rmdir failed: {}", .{err});
            return switch (err) {
                error.FileNotFound => .{ .passthrough = {} }, // Let kernel handle real dirs
                else => .{ .handled = Result.Handled.err(.IO) },
            };
        };
        logger.log("unlinkat: removed overlay directory", .{});
    } else {
        overlay.unlink(path) catch |err| {
            logger.log("unlinkat: unlink failed: {}", .{err});
            return switch (err) {
                error.FileNotFound => .{ .passthrough = {} }, // Let kernel handle real files
                error.IsDirectory => .{ .handled = Result.Handled.err(.ISDIR) },
                else => .{ .handled = Result.Handled.err(.IO) },
            };
        };
        logger.log("unlinkat: removed overlay file/symlink", .{});
    }

    return .{ .handled = Result.Handled.success(0) };
}
