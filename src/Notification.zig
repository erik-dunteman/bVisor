const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const MemoryBridge = types.MemoryBridge;
const Logger = types.Logger;
const Syscall = @import("syscall.zig").Syscall;

/// Notification is a wrapper around linux.SECCOMP.notif
const Self = @This();

id: u64,
action: union(enum) {
    passthrough: linux.SYS,
    emulate: Syscall,
},

/// Parse a linux.SECCOMP.notif into a Notification
pub fn from_notif(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    const supported = try Syscall.parse(mem_bridge, notif);

    if (supported) |syscall| {
        return .{
            .id = notif.id,
            .action = .{
                .emulate = syscall,
            },
        };
    }

    // Else not supported, passthrough
    return .{
        .id = notif.id,
        .action = .{
            .passthrough = @enumFromInt(notif.data.nr),
        },
    };
}

/// Invoke the handler, or perform passthrough
pub fn handle(self: Self, mem_bridge: MemoryBridge, logger: Logger) !Response {
    switch (self.action) {
        .passthrough => |sys_code| {
            logger.log("Syscall: passthrough: {s}", .{@tagName(sys_code)});
            return Response.Passthrough(self.id);
        },
        .emulate => |syscall| {
            const result = try syscall.handle(mem_bridge, logger);
            return Response.Emulated(self.id, result);
        },
    }
}

/// Wrapper around linux.SECCOMP.notif_resp
pub const Response = struct {
    id: u64,
    result: union(enum) {
        passthrough: void,
        emulated: Syscall.Result,
    },

    pub fn Passthrough(id: u64) @This() {
        return .{
            .id = id,
            .result = .{ .passthrough = {} },
        };
    }

    pub fn Emulated(id: u64, result: Syscall.Result) @This() {
        return .{
            .id = id,
            .result = .{ .emulated = result },
        };
    }

    pub fn to_notif_resp(self: @This()) linux.SECCOMP.notif_resp {
        return switch (self.result) {
            .passthrough => .{
                .id = self.id,
                .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                .val = 0,
                .@"error" = 0,
            },
            .emulated => |emulated| switch (emulated) {
                .passthrough => .{
                    .id = self.id,
                    .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                    .val = 0,
                    .@"error" = 0,
                },
                .handled => |handled| .{
                    .id = self.id,
                    .flags = 0,
                    .val = handled.val,
                    .@"error" = handled.errno,
                },
            },
        };
    }
};
