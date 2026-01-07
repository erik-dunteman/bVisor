const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const syscall = @import("syscall.zig");
const Notification = @import("Notification.zig");
const Overlay = @import("Overlay.zig");
const Fstatat = @import("syscalls/Fstatat.zig");
const FD = types.FD;
const MemoryBridge = @import("memory_bridge.zig").MemoryBridge;
const Result = types.LinuxResult;
const Logger = types.Logger;

const Self = @This();

notify_fd: FD,
child_pid: linux.pid_t,
logger: Logger,
allocator: std.mem.Allocator,
io: std.Io,
mem_bridge: MemoryBridge,
overlay: Overlay,

pub fn init(notify_fd: FD, child_pid: linux.pid_t, allocator: std.mem.Allocator, io: std.Io) Self {
    return .{
        .notify_fd = notify_fd,
        .child_pid = child_pid,
        .allocator = allocator,
        .io = io,
        .logger = Logger.init(.supervisor),
        .mem_bridge = MemoryBridge.init(child_pid),
        .overlay = Overlay.init(allocator, io),
    };
}

pub fn deinit(self: *Self) void {
    self.overlay.deinit();
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;

        // Update mem_bridge to use pid from notification (handles forked children)
        self.mem_bridge = MemoryBridge.init(@intCast(notif.pid));
        const notification = try Notification.fromNotif(self.mem_bridge, notif);

        // Handle (or prepare passthrough resp)
        const response = try notification.handle(self);

        // Reply to kernel
        try self.send(response.toNotifResp());
    }
}

fn recv(self: *const Self) !?linux.SECCOMP.notif {
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

fn send(self: *const Self, resp: linux.SECCOMP.notif_resp) !void {
    _ = try Result(usize).from(
        linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
    ).unwrap();
}

// ============================================================================
// E2E Tests
// ============================================================================

const testing = std.testing;

fn makeNotif(syscall_nr: linux.SYS, args: struct { arg0: u64 = 0, arg1: u64 = 0, arg2: u64 = 0, arg3: u64 = 0 }) linux.SECCOMP.notif {
    var notif = std.mem.zeroes(linux.SECCOMP.notif);
    notif.id = 1;
    notif.data.nr = @intCast(@intFromEnum(syscall_nr));
    notif.data.arg0 = args.arg0;
    notif.data.arg1 = args.arg1;
    notif.data.arg2 = args.arg2;
    notif.data.arg3 = args.arg3;
    return notif;
}

test "openat with O_CREAT creates virtual FD" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Path buffer in local memory (TestingMemoryBridge reads it directly)
    const path_buf = "/test.txt";

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)), // dirfd
        .arg1 = @intFromPtr(path_buf.ptr), // pathname (string literal is null-terminated)
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644, // mode
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return success with FD >= 3
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expect(resp.val >= 3);
    try testing.expectEqual(@as(u32, 0), resp.flags); // Not passthrough
}

test "openat read-only on missing file returns ENOENT" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path_buf = "/missing.txt";

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY, no O_CREAT
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // File not found returns ENOENT (full virtualization model)
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOENT)), resp.@"error");
}

test "write to virtual FD returns bytes written" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // First open a file
    const path_buf = "/test.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });

    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Now write to it
    const write_buf = "Hello world!";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 12, // count
    });

    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    const write_response = try write_notification.handle(&supervisor);
    const write_resp = write_response.toNotifResp();

    // Should return 12 bytes written
    try testing.expectEqual(@as(i32, 0), write_resp.@"error");
    try testing.expectEqual(@as(i64, 12), write_resp.val);
}

test "write to stdout (fd=1) passthroughs" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const write_buf = "hello";
    const notif = makeNotif(.write, .{
        .arg0 = 1, // stdout
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should passthrough (USER_NOTIF_FLAG_CONTINUE)
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "write to stderr (fd=2) passthroughs" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const write_buf = "error";
    const notif = makeNotif(.write, .{
        .arg0 = 2, // stderr
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should passthrough
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "write to unknown FD returns EBADF" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const write_buf = "hello";
    const notif = makeNotif(.write, .{
        .arg0 = 999, // unknown FD
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Unknown FDs return EBADF (full virtualization model)
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.BADF)), resp.@"error");
}

test "close virtual FD returns success" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // First open a file
    const path_buf = "/test.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o101,
        .arg3 = 0o644,
    });

    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Now close it
    const close_notif = makeNotif(.close, .{
        .arg0 = @intCast(fd),
    });

    const close_notification = try Notification.fromNotif(supervisor.mem_bridge, close_notif);
    const close_response = try close_notification.handle(&supervisor);
    const close_resp = close_response.toNotifResp();

    // Should return success
    try testing.expectEqual(@as(i32, 0), close_resp.@"error");
    try testing.expectEqual(@as(i64, 0), close_resp.val);
}

test "close stdin (fd=0) passthroughs" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{
        .arg0 = 0, // stdin
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should passthrough
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "read from virtual FD returns data" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Open a file for writing
    const path_buf = "/test.txt";
    const open_write_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });
    const open_write_notification = try Notification.fromNotif(supervisor.mem_bridge, open_write_notif);
    const open_write_response = try open_write_notification.handle(&supervisor);
    const write_fd = open_write_response.toNotifResp().val;

    // Write data
    const write_data = "Hello from VFS!";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(write_fd),
        .arg1 = @intFromPtr(write_data.ptr),
        .arg2 = write_data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);
    supervisor.overlay.close(@intCast(write_fd));

    // Open for reading
    const open_read_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY
        .arg3 = 0,
    });
    const open_read_notification = try Notification.fromNotif(supervisor.mem_bridge, open_read_notif);
    const open_read_response = try open_read_notification.handle(&supervisor);
    const read_fd = open_read_response.toNotifResp().val;

    // Read data back
    var read_buf: [32]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .arg0 = @intCast(read_fd),
        .arg1 = @intFromPtr(&read_buf),
        .arg2 = read_buf.len,
    });
    const read_notification = try Notification.fromNotif(supervisor.mem_bridge, read_notif);
    const read_response = try read_notification.handle(&supervisor);
    const read_resp = read_response.toNotifResp();

    // Should return 15 bytes read
    try testing.expectEqual(@as(i32, 0), read_resp.@"error");
    try testing.expectEqual(@as(i64, 15), read_resp.val);
    try testing.expectEqualStrings("Hello from VFS!", read_buf[0..15]);
}

test "read from stdin (fd=0) passthroughs" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    var read_buf: [32]u8 = undefined;
    const notif = makeNotif(.read, .{
        .arg0 = 0, // stdin
        .arg1 = @intFromPtr(&read_buf),
        .arg2 = 32,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should passthrough
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "read from unknown FD returns EBADF" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    var read_buf: [32]u8 = undefined;
    const notif = makeNotif(.read, .{
        .arg0 = 999, // unknown FD
        .arg1 = @intFromPtr(&read_buf),
        .arg2 = 32,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Unknown FDs return EBADF (full virtualization model)
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.BADF)), resp.@"error");
}

test "openat blocks dangerous /proc paths" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Test exact blocked path
    const path_buf = "/proc/sysrq-trigger";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return EACCES, not passthrough
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

test "openat blocks dangerous /sys prefix paths" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Test prefix blocked path
    const path_buf = "/sys/fs/cgroup/memory/tasks";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return EACCES
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

test "openat allows safe /proc paths - returns ENOENT if file missing" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Test safe /proc path that doesn't exist on macOS test runner
    // With full virtualization, we handle it (returns ENOENT if not found)
    const path_buf = "/proc/cpuinfo";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Full virtualization: file not in overlay or host, returns ENOENT
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOENT)), resp.@"error");
}

test "openat blocks dangerous /dev paths" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Test blocked /dev/mem
    const path_buf = "/dev/mem";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return EACCES
    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

test "openat blocks /dev/cpu MSR access" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Test blocked /dev/cpu/0/msr prefix
    const path_buf = "/dev/cpu/0/msr";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0,
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

test "symlinkat creates virtual symlink" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const target = "/target/file";
    const linkpath = "/link";

    const notif = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr), // target
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)), // newdirfd
        .arg2 = @intFromPtr(linkpath.ptr), // linkpath
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return success
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Symlink should exist in overlay
    try testing.expect(supervisor.overlay.isSymlink("/link"));
    try testing.expectEqualStrings("/target/file", supervisor.overlay.readlink("/link").?);
}

test "symlinkat fails on existing path" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const target = "/target";
    const linkpath = "/existing";

    // Create first symlink
    const notif1 = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });
    const notification1 = try Notification.fromNotif(supervisor.mem_bridge, notif1);
    _ = try notification1.handle(&supervisor);

    // Try to create symlink at same path - should fail with EEXIST
    const notif2 = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });
    const notification2 = try Notification.fromNotif(supervisor.mem_bridge, notif2);
    const response2 = try notification2.handle(&supervisor);
    const resp2 = response2.toNotifResp();

    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.EXIST)), resp2.@"error");
}

test "mkdirat creates virtual directory" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path = "/newdir";

    const notif = makeNotif(.mkdirat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)), // dirfd
        .arg1 = @intFromPtr(path.ptr), // pathname
        .arg2 = 0o755, // mode
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should return success
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Directory should exist in overlay
    try testing.expect(supervisor.overlay.isDirectory("/newdir"));
}

test "mkdirat fails on existing path" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path = "/existingdir";

    // Create directory
    const notif1 = makeNotif(.mkdirat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o755,
    });
    const notification1 = try Notification.fromNotif(supervisor.mem_bridge, notif1);
    _ = try notification1.handle(&supervisor);

    // Try to create again - should fail with EEXIST
    const notif2 = makeNotif(.mkdirat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o755,
    });
    const notification2 = try Notification.fromNotif(supervisor.mem_bridge, notif2);
    const response2 = try notification2.handle(&supervisor);
    const resp2 = response2.toNotifResp();

    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.EXIST)), resp2.@"error");
}

test "fstatat returns VFS file stats" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create a virtual file
    const path = "/testfile";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Write some data
    const data = "hello world";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // Stat the file
    var statbuf: Fstatat.LinuxStat = undefined;
    const stat_notif = makeNotif(.fstatat64, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = @intFromPtr(&statbuf),
        .arg3 = 0, // flags
    });
    const stat_notification = try Notification.fromNotif(supervisor.mem_bridge, stat_notif);
    const stat_response = try stat_notification.handle(&supervisor);
    const stat_resp = stat_response.toNotifResp();

    // Should return success
    try testing.expectEqual(@as(i32, 0), stat_resp.@"error");
    try testing.expectEqual(@as(u32, 0), stat_resp.flags);

    // Check stat values
    try testing.expectEqual(@as(i64, 11), statbuf.size);
    try testing.expect((statbuf.mode & linux.S.IFREG) != 0); // Is regular file
}

test "fstatat on directory returns directory stats" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create a directory
    const path = "/mydir";
    const mkdir_notif = makeNotif(.mkdirat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o755,
    });
    const mkdir_notification = try Notification.fromNotif(supervisor.mem_bridge, mkdir_notif);
    _ = try mkdir_notification.handle(&supervisor);

    // Stat the directory
    var statbuf: Fstatat.LinuxStat = undefined;
    const stat_notif = makeNotif(.fstatat64, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = @intFromPtr(&statbuf),
        .arg3 = 0,
    });
    const stat_notification = try Notification.fromNotif(supervisor.mem_bridge, stat_notif);
    const stat_response = try stat_notification.handle(&supervisor);
    const stat_resp = stat_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), stat_resp.@"error");
    try testing.expect((statbuf.mode & linux.S.IFDIR) != 0); // Is directory
}

test "fstatat on unknown path passthroughs" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path = "/nonexistent";
    var statbuf: Fstatat.LinuxStat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = @intFromPtr(&statbuf),
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    // Should passthrough to kernel
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "unlinkat removes virtual file" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create a file
    const path = "/todelete.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    _ = try open_notification.handle(&supervisor);

    // Verify file exists in overlay
    try testing.expect(supervisor.overlay.pathExists("/todelete.txt"));

    // Delete the file
    const unlink_notif = makeNotif(.unlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0, // flags (not AT_REMOVEDIR)
    });
    const unlink_notification = try Notification.fromNotif(supervisor.mem_bridge, unlink_notif);
    const unlink_response = try unlink_notification.handle(&supervisor);
    const unlink_resp = unlink_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), unlink_resp.@"error");

    // File should be gone from overlay
    try testing.expect(!supervisor.overlay.pathExists("/todelete.txt"));
}

test "unlinkat with AT_REMOVEDIR removes virtual directory" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create a directory
    const path = "/toremove";
    const mkdir_notif = makeNotif(.mkdirat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o755,
    });
    const mkdir_notification = try Notification.fromNotif(supervisor.mem_bridge, mkdir_notif);
    _ = try mkdir_notification.handle(&supervisor);

    try testing.expect(supervisor.overlay.isDirectory("/toremove"));

    // Remove directory
    const rmdir_notif = makeNotif(.unlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0x200, // AT_REMOVEDIR
    });
    const rmdir_notification = try Notification.fromNotif(supervisor.mem_bridge, rmdir_notif);
    const rmdir_response = try rmdir_notification.handle(&supervisor);
    const rmdir_resp = rmdir_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), rmdir_resp.@"error");
    try testing.expect(!supervisor.overlay.isDirectory("/toremove"));
}

test "readlinkat returns symlink target" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create symlink
    const target = "/real/target";
    const linkpath = "/mylink";
    const symlink_notif = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });
    const symlink_notification = try Notification.fromNotif(supervisor.mem_bridge, symlink_notif);
    _ = try symlink_notification.handle(&supervisor);

    // Read the symlink
    var buf: [256]u8 = undefined;
    const readlink_notif = makeNotif(.readlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(linkpath.ptr),
        .arg2 = @intFromPtr(&buf),
        .arg3 = buf.len,
    });
    const readlink_notification = try Notification.fromNotif(supervisor.mem_bridge, readlink_notif);
    const readlink_response = try readlink_notification.handle(&supervisor);
    const readlink_resp = readlink_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), readlink_resp.@"error");
    try testing.expectEqual(@as(i64, 12), readlink_resp.val); // "/real/target" = 12 chars
    try testing.expectEqualStrings("/real/target", buf[0..12]);
}

test "lseek changes file offset" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create and write to file
    const path = "/seektest.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102, // O_RDWR | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "hello world";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // Seek to beginning (SEEK_SET = 0)
    const seek_notif = makeNotif(.lseek, .{
        .arg0 = @intCast(fd),
        .arg1 = 0, // offset
        .arg2 = 0, // SEEK_SET
    });
    const seek_notification = try Notification.fromNotif(supervisor.mem_bridge, seek_notif);
    const seek_response = try seek_notification.handle(&supervisor);
    const seek_resp = seek_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), seek_resp.@"error");
    try testing.expectEqual(@as(i64, 0), seek_resp.val);

    // Read should now work from beginning
    var buf: [32]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });
    const read_notification = try Notification.fromNotif(supervisor.mem_bridge, read_notif);
    const read_response = try read_notification.handle(&supervisor);
    const read_resp = read_response.toNotifResp();

    try testing.expectEqual(@as(i64, 11), read_resp.val);
    try testing.expectEqualStrings("hello world", buf[0..11]);
}

test "pread64 reads at offset without changing position" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file with content
    const path = "/preadtest.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102, // O_RDWR | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "0123456789";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // pread at offset 5
    var buf: [5]u8 = undefined;
    const pread_notif = makeNotif(.pread64, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 5, // offset
    });
    const pread_notification = try Notification.fromNotif(supervisor.mem_bridge, pread_notif);
    const pread_response = try pread_notification.handle(&supervisor);
    const pread_resp = pread_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), pread_resp.@"error");
    try testing.expectEqual(@as(i64, 5), pread_resp.val);
    try testing.expectEqualStrings("56789", &buf);
}

test "pwrite64 writes at offset without changing position" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/pwritetest.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102, // O_RDWR | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Write initial content
    const data = "aaaaaaaaaa";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // pwrite "XYZ" at offset 3
    const new_data = "XYZ";
    const pwrite_notif = makeNotif(.pwrite64, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(new_data.ptr),
        .arg2 = new_data.len,
        .arg3 = 3, // offset
    });
    const pwrite_notification = try Notification.fromNotif(supervisor.mem_bridge, pwrite_notif);
    const pwrite_response = try pwrite_notification.handle(&supervisor);
    const pwrite_resp = pwrite_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), pwrite_resp.@"error");
    try testing.expectEqual(@as(i64, 3), pwrite_resp.val);

    // Verify content via stat
    const stat = supervisor.overlay.stat("/pwritetest.txt").?;
    try testing.expectEqual(@as(u64, 10), stat.size);
}

// ============================================================================
// Security Edge Case Tests
// ============================================================================

test "openat blocks /dev/mem physical memory access" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path_buf = "/dev/mem";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0,
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

test "openat blocks raw block device prefix /dev/sda" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const path_buf = "/dev/sda1";
    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0,
        .arg3 = 0,
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    try testing.expectEqual(@as(u32, 0), resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.ACCES)), resp.@"error");
}

// ============================================================================
// Zero-Length Operation Tests
// ============================================================================

test "write zero bytes returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/zerowrite.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Write zero bytes
    const data = "";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = 0,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    const write_response = try write_notification.handle(&supervisor);
    const write_resp = write_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), write_resp.@"error");
    try testing.expectEqual(@as(i64, 0), write_resp.val);
}

test "read zero bytes returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file with content
    const path = "/zeroread.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102, // O_RDWR | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "content";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // Seek to start
    const seek_notif = makeNotif(.lseek, .{
        .arg0 = @intCast(fd),
        .arg1 = 0,
        .arg2 = 0,
    });
    const seek_notification = try Notification.fromNotif(supervisor.mem_bridge, seek_notif);
    _ = try seek_notification.handle(&supervisor);

    // Read zero bytes
    var buf: [1]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = 0, // zero count
    });
    const read_notification = try Notification.fromNotif(supervisor.mem_bridge, read_notif);
    const read_response = try read_notification.handle(&supervisor);
    const read_resp = read_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), read_resp.@"error");
    try testing.expectEqual(@as(i64, 0), read_resp.val);
}

// ============================================================================
// Lseek Edge Case Tests
// ============================================================================

test "lseek negative offset from SEEK_SET returns EINVAL" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/seekneg.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Try to seek to negative offset
    const seek_notif = makeNotif(.lseek, .{
        .arg0 = @intCast(fd),
        .arg1 = @bitCast(@as(i64, -100)),
        .arg2 = 0, // SEEK_SET
    });
    const seek_notification = try Notification.fromNotif(supervisor.mem_bridge, seek_notif);
    const seek_response = try seek_notification.handle(&supervisor);
    const seek_resp = seek_response.toNotifResp();

    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.INVAL)), seek_resp.@"error");
}

test "lseek SEEK_END with negative offset past beginning returns EINVAL" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file with some content
    const path = "/seekend.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "short";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // SEEK_END with -1000 (file is only 5 bytes)
    const seek_notif = makeNotif(.lseek, .{
        .arg0 = @intCast(fd),
        .arg1 = @bitCast(@as(i64, -1000)),
        .arg2 = 2, // SEEK_END
    });
    const seek_notification = try Notification.fromNotif(supervisor.mem_bridge, seek_notif);
    const seek_response = try seek_notification.handle(&supervisor);
    const seek_resp = seek_response.toNotifResp();

    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.INVAL)), seek_resp.@"error");
}

test "lseek past EOF then read returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/seekpast.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "hello";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // Seek past EOF
    const seek_notif = makeNotif(.lseek, .{
        .arg0 = @intCast(fd),
        .arg1 = 1000,
        .arg2 = 0, // SEEK_SET
    });
    const seek_notification = try Notification.fromNotif(supervisor.mem_bridge, seek_notif);
    const seek_response = try seek_notification.handle(&supervisor);
    try testing.expectEqual(@as(i64, 1000), seek_response.toNotifResp().val);

    // Read should return 0 (EOF)
    var buf: [32]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });
    const read_notification = try Notification.fromNotif(supervisor.mem_bridge, read_notif);
    const read_response = try read_notification.handle(&supervisor);
    const read_resp = read_response.toNotifResp();

    try testing.expectEqual(@as(i64, 0), read_resp.val);
}

// ============================================================================
// Close Edge Case Tests
// ============================================================================

test "close unknown FD returns EBADF" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Close FD that was never opened in VFS
    const close_notif = makeNotif(.close, .{
        .arg0 = 999,
    });
    const close_notification = try Notification.fromNotif(supervisor.mem_bridge, close_notif);
    const close_response = try close_notification.handle(&supervisor);
    const close_resp = close_response.toNotifResp();

    // Unknown FDs return EBADF (full virtualization model)
    try testing.expectEqual(@as(u32, 0), close_resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.BADF)), close_resp.@"error");
}

test "close virtual FD twice - second is no-op" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/closeme.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Close first time - should succeed
    const close1_notif = makeNotif(.close, .{
        .arg0 = @intCast(fd),
    });
    const close1_notification = try Notification.fromNotif(supervisor.mem_bridge, close1_notif);
    const close1_response = try close1_notification.handle(&supervisor);
    try testing.expectEqual(@as(i32, 0), close1_response.toNotifResp().@"error");

    // Close second time - returns EBADF (full virtualization model)
    const close2_notif = makeNotif(.close, .{
        .arg0 = @intCast(fd),
    });
    const close2_notification = try Notification.fromNotif(supervisor.mem_bridge, close2_notif);
    const close2_response = try close2_notification.handle(&supervisor);
    const close2_resp = close2_response.toNotifResp();
    try testing.expectEqual(@as(u32, 0), close2_resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.BADF)), close2_resp.@"error");
}

// ============================================================================
// Symlink Edge Case Tests
// ============================================================================

test "symlinkat self-loop allowed (just stores the string)" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    const target = "/selfloop";
    const linkpath = "/selfloop";
    const notif = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });

    const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expectEqualStrings("/selfloop", supervisor.overlay.readlink("/selfloop").?);
}

test "symlinkat chain does not cause recursion" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create chain: /a -> /b, /b -> /c
    const targets = [_][]const u8{ "/b", "/c" };
    const links = [_][]const u8{ "/a", "/b" };

    for (targets, links) |target, link| {
        const notif = makeNotif(.symlinkat, .{
            .arg0 = @intFromPtr(target.ptr),
            .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
            .arg2 = @intFromPtr(link.ptr),
        });
        const notification = try Notification.fromNotif(supervisor.mem_bridge, notif);
        _ = try notification.handle(&supervisor);
    }

    // readlink should just return direct target, not follow chain
    try testing.expectEqualStrings("/b", supervisor.overlay.readlink("/a").?);
    try testing.expectEqualStrings("/c", supervisor.overlay.readlink("/b").?);
}

test "readlinkat on non-symlink passthroughs to kernel" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create a regular file
    const path = "/regularfile.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    _ = try open_notification.handle(&supervisor);

    // Try to readlink the regular file - handler only checks symlinks map
    // so it passthroughs to kernel for regular files
    var buf: [256]u8 = undefined;
    const readlink_notif = makeNotif(.readlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = @intFromPtr(&buf),
        .arg3 = buf.len,
    });
    const readlink_notification = try Notification.fromNotif(supervisor.mem_bridge, readlink_notif);
    const readlink_response = try readlink_notification.handle(&supervisor);
    const readlink_resp = readlink_response.toNotifResp();

    // Current behavior: passthroughs (VFS only tracks symlinks, not file types)
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, readlink_resp.flags);
}

test "readlinkat with zero buffer size returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create symlink
    const target = "/target";
    const linkpath = "/zerobuf";
    const symlink_notif = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });
    const symlink_notification = try Notification.fromNotif(supervisor.mem_bridge, symlink_notif);
    _ = try symlink_notification.handle(&supervisor);

    // readlink with bufsiz=0
    var buf: [1]u8 = undefined;
    const readlink_notif = makeNotif(.readlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(linkpath.ptr),
        .arg2 = @intFromPtr(&buf),
        .arg3 = 0, // zero buffer size
    });
    const readlink_notification = try Notification.fromNotif(supervisor.mem_bridge, readlink_notif);
    const readlink_response = try readlink_notification.handle(&supervisor);
    const readlink_resp = readlink_response.toNotifResp();

    try testing.expectEqual(@as(i32, 0), readlink_resp.@"error");
    try testing.expectEqual(@as(i64, 0), readlink_resp.val);
}

// ============================================================================
// Unlink Edge Case Tests
// ============================================================================

test "unlinkat removes file from path lookup" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file (don't keep it open - close immediately)
    const path = "/unlinktest.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    // Close the file first
    const close_notif = makeNotif(.close, .{
        .arg0 = @intCast(fd),
    });
    const close_notification = try Notification.fromNotif(supervisor.mem_bridge, close_notif);
    _ = try close_notification.handle(&supervisor);

    // File should exist in overlay
    try testing.expect(supervisor.overlay.pathExists("/unlinktest.txt"));

    // Unlink the file
    const unlink_notif = makeNotif(.unlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0,
    });
    const unlink_notification = try Notification.fromNotif(supervisor.mem_bridge, unlink_notif);
    const unlink_response = try unlink_notification.handle(&supervisor);
    try testing.expectEqual(@as(i32, 0), unlink_response.toNotifResp().@"error");

    // File should be gone from overlay
    try testing.expect(!supervisor.overlay.pathExists("/unlinktest.txt"));

    // Trying to open without O_CREAT should fail with ENOENT
    const reopen_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o0, // O_RDONLY, no O_CREAT
        .arg3 = 0,
    });
    const reopen_notification = try Notification.fromNotif(supervisor.mem_bridge, reopen_notif);
    const reopen_response = try reopen_notification.handle(&supervisor);
    // Not in overlay or on host, returns ENOENT
    const reopen_resp = reopen_response.toNotifResp();
    try testing.expectEqual(@as(u32, 0), reopen_resp.flags);
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOENT)), reopen_resp.@"error");
}

test "unlinkat symlink does not delete target" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create target file
    const target_path = "/target.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(target_path.ptr),
        .arg2 = 0o101,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    _ = try open_notification.handle(&supervisor);

    // Create symlink to target
    const linkpath = "/link.txt";
    const symlink_notif = makeNotif(.symlinkat, .{
        .arg0 = @intFromPtr(target_path.ptr),
        .arg1 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg2 = @intFromPtr(linkpath.ptr),
    });
    const symlink_notification = try Notification.fromNotif(supervisor.mem_bridge, symlink_notif);
    _ = try symlink_notification.handle(&supervisor);

    // Unlink the symlink
    const unlink_notif = makeNotif(.unlinkat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(linkpath.ptr),
        .arg2 = 0,
    });
    const unlink_notification = try Notification.fromNotif(supervisor.mem_bridge, unlink_notif);
    const unlink_response = try unlink_notification.handle(&supervisor);
    try testing.expectEqual(@as(i32, 0), unlink_response.toNotifResp().@"error");

    // Symlink should be gone
    try testing.expect(!supervisor.overlay.isSymlink("/link.txt"));

    // Target should still exist
    try testing.expect(supervisor.overlay.pathExists("/target.txt"));
}

// ============================================================================
// pread64/pwrite64 Edge Case Tests
// ============================================================================

test "pread64 at EOF returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/preadeof.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "12345";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // pread at exact EOF (offset=5, file size=5)
    var buf: [10]u8 = undefined;
    const pread_notif = makeNotif(.pread64, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 5, // at EOF
    });
    const pread_notification = try Notification.fromNotif(supervisor.mem_bridge, pread_notif);
    const pread_response = try pread_notification.handle(&supervisor);
    const pread_resp = pread_response.toNotifResp();

    try testing.expectEqual(@as(i64, 0), pread_resp.val);
}

test "pread64 beyond EOF returns 0" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var supervisor = Self.init(-1, 0, testing.allocator, io);
    defer supervisor.deinit();

    // Create file
    const path = "/preadbeyond.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0o102,
        .arg3 = 0o644,
    });
    const open_notification = try Notification.fromNotif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.toNotifResp().val;

    const data = "short";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });
    const write_notification = try Notification.fromNotif(supervisor.mem_bridge, write_notif);
    _ = try write_notification.handle(&supervisor);

    // pread way beyond EOF
    var buf: [10]u8 = undefined;
    const pread_notif = makeNotif(.pread64, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 1000,
    });
    const pread_notification = try Notification.fromNotif(supervisor.mem_bridge, pread_notif);
    const pread_response = try pread_notification.handle(&supervisor);
    const pread_resp = pread_response.toNotifResp();

    try testing.expectEqual(@as(i64, 0), pread_resp.val);
}
