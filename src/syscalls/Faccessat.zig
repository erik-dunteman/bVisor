const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

// Access mode flags
const F_OK: u32 = 0; // Test for existence
const R_OK: u32 = 4; // Test for read permission
const W_OK: u32 = 2; // Test for write permission
const X_OK: u32 = 1; // Test for execute permission

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
mode: u32,
flags: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .mode = @truncate(notif.data.arg2),
        .flags = @truncate(notif.data.arg3),
    };

    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    const path = self.pathname[0..self.pathname_len];

    logger.log("Emulating faccessat: dirfd={d} path=\"{s}\" mode=0x{x} flags=0x{x}", .{
        self.dirfd,
        path,
        self.mode,
        self.flags,
    });

    // Check if path exists in overlay
    if (overlay.pathExists(path)) {
        // File exists in overlay or on host
        // For F_OK, we're done
        if (self.mode == F_OK) {
            logger.log("faccessat: path exists", .{});
            return .{ .handled = Result.Handled.success(0) };
        }

        // For R_OK/W_OK/X_OK, we'd need to check actual permissions
        // For simplicity, if the file exists, assume it's accessible
        // (This is a simplification - proper impl would check overlay metadata)
        logger.log("faccessat: assuming accessible (mode=0x{x})", .{self.mode});
        return .{ .handled = Result.Handled.success(0) };
    }

    // Path doesn't exist in overlay - passthrough to kernel for host filesystem
    logger.log("faccessat: passthrough for path=\"{s}\"", .{path});
    return .{ .passthrough = {} };
}
