const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;
const types = @import("types.zig");
const syscalls = @import("virtual/syscall/syscalls.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;
const Logger = types.Logger;
const Procs = @import("virtual/proc/Procs.zig");
const Cow = @import("virtual/fs/Cow.zig");
const Tmp = @import("virtual/fs/Tmp.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
io: Io,
init_child_pid: linux.pid_t, // ERIK TODO: stop using child naming here, use guest
notify_fd: KernelFD,
logger: Logger,

// All procs starting from the initial child proc are assigned a virtual PID and tracked via virtual_procs
// All pros track their own virtual namespaces and file descriptors
virtual_procs: Procs, // ERIK TODO: rename to guest_procs

// COW filesystem for sandbox isolation
cow: Cow,
// Private /tmp for sandbox isolation
tmp: Tmp,

pub fn init(allocator: Allocator, io: Io, notify_fd: KernelFD, child_pid: linux.pid_t) !Self {
    const logger = Logger.init(.supervisor);
    var virtual_procs = Procs.init(allocator); // ERIK TODO: rename to guest_procs
    errdefer virtual_procs.deinit();
    _ = try virtual_procs.handleInitialProcess(child_pid); // ERIK TODO: "handle" to "register"

    // Generate shared UID for all sandbox directories
    const uid = Cow.generateUid(); // ERIK TODO: move impl into here, why have it in cow? dumb

    // ERIK TODO: merge COW and TMP into a VFS struct, single init and deinit
    var cow = try Cow.init(io, uid);
    errdefer cow.deinit(io);
    var tmp = try Tmp.init(io, uid);
    errdefer tmp.deinit(io);

    return .{
        .allocator = allocator,
        .io = io,
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
    self.cow.deinit(self.io);
    self.tmp.deinit(self.io);
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    // Supervisor handles syscalls in a single blocking thread. 80/20 solution for now, will rethink once we benchmark
    while (true) {
        // Receive syscall notification from kernel
        // ERIK TODO: by now, it should be guaranteed handleable due to stricter BPF
        const notif = try self.recv() orelse return;
        const resp = syscalls.handle(notif, self);
        try self.send(resp);
    }
}

// ERIK TODO
// inline fn handleNotif(self, notif) notif_resp
// notif id in memory
// syscall enum lookup based on syscall id. It should already be guaranteed virtualized or conditionally virtualized.
// cleaner to do Syscall.from() and then later syscall.handle() instead of a generic Syscall.handle()
// make Syscall a union(linux.SYS) so we can do an enum from int lookup
// just pass raw notif into respective handler. gets rid of parse. could inline that handler fn too.
// annoying thing there is each handler needs to reply in a notif_resp, or we yet again introduce a Notification-like construct
// a standardized reply is nice, even if it's a set of .success or .err or .continue functions (rather than enums) to construct the seccomp.notif
// I like this, add to seccomp/notif.zig and each handler just calls whichever is appropriate. Same as toNotifResp but pure function

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
