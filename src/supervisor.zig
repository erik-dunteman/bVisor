const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const Notification = @import("seccomp/Notification.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;
const Logger = types.Logger;
const Procs = @import("virtual/proc/Procs.zig");
const Cow = @import("virtual/fs/Cow.zig");
const Tmp = @import("virtual/fs/Tmp.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
init_child_pid: linux.pid_t,
notify_fd: KernelFD,
logger: Logger,

// All procs starting from the initial child proc are assigned a virtual PID and tracked via virtual_procs
// All pros track their own virtual namespaces and file descriptors
virtual_procs: Procs,

// COW filesystem for sandbox isolation
cow: Cow,
// Private /tmp for sandbox isolation
tmp: Tmp,

pub fn init(allocator: Allocator, notify_fd: KernelFD, child_pid: linux.pid_t) !Self {
    const logger = Logger.init(.supervisor);
    var virtual_procs = Procs.init(allocator);
    errdefer virtual_procs.deinit();
    _ = try virtual_procs.handleInitialProcess(child_pid);

    // Generate shared UID for all sandbox directories
    const uid = Cow.generateUid();

    var cow = try Cow.init(uid);
    errdefer cow.deinit();

    var tmp = try Tmp.init(uid);
    errdefer tmp.deinit();

    return .{
        .allocator = allocator,
        .init_child_pid = child_pid,
        .notify_fd = notify_fd,
        .logger = logger,
        .virtual_procs = virtual_procs,
        .cow = cow,
        .tmp = tmp,
    };
}

pub fn deinit(self: *Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.virtual_procs.deinit();
    self.cow.deinit();
    self.tmp.deinit();
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;

        const notification = try Notification.fromNotif(notif);

        // Handle (or prepare passthrough resp)
        const response = try notification.handleSyscall(self);

        // Reply to kernel
        try self.send(response.toNotifResp());
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
