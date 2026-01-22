const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const Logger = types.Logger;
const Syscall = @import("../virtual/syscall/syscall.zig").Syscall;
const Supervisor = @import("../Supervisor.zig");

/// Notification is a wrapper around linux.SECCOMP.notif
const Self = @This();

id: u64,
backend: union(enum) {
    kernel: void, // The native kernel will handle the syscall
    virtual: Syscall, // ERIK TODO: naming. standardize on names in ("kernel", "host", "virtual", "emulated", "conditionalVirtual", "supervisor", "guest", "parent", "child"
},

/// Parse a linux.SECCOMP.notif into a Notification
pub fn fromNotif(notif: linux.SECCOMP.notif) !Self {
    // ERIK TODO: remove NOTIFICATION entirely
    const supported = try Syscall.parse(notif);

    if (supported) |syscall| {
        return .{
            .id = notif.id,
            .backend = .{
                .virtual = syscall,
            },
        };
    }

    // Else not supported, passthrough
    return .{
        .id = notif.id,
        .backend = .{ .kernel = {} },
    };
}

/// Invoke the handler, or perform passthrough
pub fn handleSyscall(self: Self, supervisor: *Supervisor) !Response {
    switch (self.backend) {
        .kernel => {
            return Response.useKernel(self.id); // ERIK TODO: dumb, remove.
        },
        .virtual => |syscall| {
            const syscall_res = try syscall.handle(supervisor);
            return Response.virtualRes(self.id, syscall_res);
        },
    }
}

/// Wrapper around linux.SECCOMP.notif_resp
pub const Response = struct {
    id: u64,
    backend: union(enum) {
        kernel: void,
        virtual: Syscall.Result,
    },

    pub fn useKernel(id: u64) @This() {
        return .{
            .id = id,
            .backend = .{ .kernel = {} },
        };
    }

    pub fn virtualRes(id: u64, result: Syscall.Result) @This() {
        return .{
            .id = id,
            .backend = .{ .virtual = result },
        };
    }

    pub fn toNotifResp(self: @This()) linux.SECCOMP.notif_resp {
        return switch (self.backend) {
            .kernel => .{
                .id = self.id,
                .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                .val = 0,
                .@"error" = 0,
            },
            .virtual => |syscall_res| switch (syscall_res) {
                .use_kernel => .{
                    .id = self.id,
                    .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                    .val = 0,
                    .@"error" = 0,
                },
                .reply => |reply| .{
                    .id = self.id,
                    .flags = 0,
                    .val = reply.val,
                    // error field must be negative for failures (see seccomp_unotify(2))
                    .@"error" = if (reply.errno != 0) -reply.errno else 0,
                },
            },
        };
    }
};
