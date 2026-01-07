const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

buf_ptr: u64,
size: usize,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .buf_ptr = notif.data.arg0,
        .size = @truncate(notif.data.arg1),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    _ = supervisor.overlay; // Could track cwd in overlay in future

    logger.log("Emulating getcwd: buf_ptr=0x{x} size={d}", .{ self.buf_ptr, self.size });

    // For now, passthrough to kernel since we don't virtualize the working directory
    // A full implementation would track chdir calls and return the virtual cwd
    logger.log("getcwd: passthrough to kernel", .{});
    return .{ .passthrough = {} };
}
