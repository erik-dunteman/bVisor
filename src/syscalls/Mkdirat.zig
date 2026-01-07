const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
mode: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .mode = @truncate(notif.data.arg2),
    };

    // Read pathname from child memory
    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    const path = self.pathname[0..self.pathname_len];

    logger.log("Emulating mkdirat: dirfd={d} path=\"{s}\" mode=0o{o}", .{
        self.dirfd,
        path,
        self.mode,
    });

    // All directories are created in overlay only
    overlay.mkdir(path, self.mode) catch |err| {
        logger.log("mkdirat: failed: {}", .{err});
        return switch (err) {
            error.FileExists => .{ .handled = Result.Handled.err(.EXIST) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("mkdirat: created overlay directory", .{});
    return .{ .handled = Result.Handled.success(0) };
}
