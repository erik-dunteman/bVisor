const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

pipefd_ptr: u64,
flags: u32,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .pipefd_ptr = notif.data.arg0,
        .flags = @truncate(notif.data.arg1),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating pipe2: flags=0x{x}", .{self.flags});

    // Pipes are used for inter-process communication
    // For sandboxed processes, we should passthrough to kernel since
    // the pipe FDs need to work with real kernel operations
    // A full implementation would virtualize pipes within the sandbox
    logger.log("pipe2: passthrough to kernel", .{});
    return .{ .passthrough = {} };
}
