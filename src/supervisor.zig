const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const Notification = @import("seccomp/Notification.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;
const Logger = types.Logger;
const Procs = @import("virtual/proc/Procs.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
init_child_pid: linux.pid_t,
notify_fd: KernelFD,
logger: Logger,
// vfs: VFS, // TODO

virtual_procs: Procs,

pub fn init(allocator: Allocator, notify_fd: KernelFD, child_pid: linux.pid_t) !Self {
    const logger = Logger.init(.supervisor);
    var virtual_procs = Procs.init(allocator);
    errdefer virtual_procs.deinit();
    _ = try virtual_procs.handle_initial_process(child_pid);
    return .{ .allocator = allocator, .init_child_pid = child_pid, .notify_fd = notify_fd, .logger = logger, .virtual_procs = virtual_procs };
}

pub fn deinit(self: *Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.virtual_procs.deinit();
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
