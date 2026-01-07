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
buf_ptr: u64,
bufsiz: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .buf_ptr = notif.data.arg2,
        .bufsiz = @truncate(notif.data.arg3),
    };

    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;
    const mem_bridge = supervisor.mem_bridge;

    const path = self.pathname[0..self.pathname_len];

    logger.log("Emulating readlinkat: dirfd={d} path=\"{s}\" bufsiz={d}", .{
        self.dirfd,
        path,
        self.bufsiz,
    });

    // Virtualize /proc/self/exe - return a safe path instead of real binary location
    if (std.mem.eql(u8, path, "/proc/self/exe")) {
        const virtual_exe = "/sandbox";
        const to_copy = @min(virtual_exe.len, self.bufsiz);
        try mem_bridge.writeSlice(virtual_exe[0..to_copy], self.buf_ptr);
        logger.log("readlinkat: virtualized /proc/self/exe -> \"{s}\"", .{virtual_exe});
        return .{ .handled = Result.Handled.success(@intCast(to_copy)) };
    }

    // Check if symlink exists in overlay
    if (overlay.readlink(path)) |target| {
        const to_copy = @min(target.len, self.bufsiz);
        try mem_bridge.writeSlice(target[0..to_copy], self.buf_ptr);
        logger.log("readlinkat: returned overlay symlink target=\"{s}\"", .{target});
        return .{ .handled = Result.Handled.success(@intCast(to_copy)) };
    }

    // Not in overlay - passthrough to kernel
    logger.log("readlinkat: passthrough for path=\"{s}\"", .{path});
    return .{ .passthrough = {} };
}
