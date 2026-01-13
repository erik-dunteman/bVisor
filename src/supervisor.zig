const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const Notification = @import("seccomp/Notification.zig");
const FD = types.FD;
const Result = types.LinuxResult;
const Logger = types.Logger;

const Self = @This();

init_child_pid: linux.pid_t,
notify_fd: FD,
logger: Logger,

pub fn init(notify_fd: FD, child_pid: linux.pid_t) Self {
    const logger = Logger.init(.supervisor);
    return .{ .init_child_pid = child_pid, .notify_fd = notify_fd, .logger = logger };
}

pub fn deinit(self: Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        const notification = try Notification.from_notif(notif);

        // Handle (or prepare passthrough resp)
        const response = try notification.handle(self);

        // Reply to kernel
        try self.send(response.to_notif_resp());
    }
}

fn recv(self: Self) !?linux.SECCOMP.notif {
    var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    const recv_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
    switch (Result(usize).from(recv_result)) {
        .Ok => return notif,
        .Error => |err| switch (err) {
            .NOENT => {
                self.logger.log("Child exited, stopping notification handler", .{});
                return null;
            },
            else => |_| return posix.unexpectedErrno(err),
        },
    }
}

fn send(self: Self, resp: linux.SECCOMP.notif_resp) !void {
    _ = try Result(usize).from(
        linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
    ).unwrap();
}

// E2E tests

const testing = std.testing;
