const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const FD = @import("../../fs/FD.zig").FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

kernel_pid: Proc.KernelPID,
fd: i32, // virtual fd from child
buf_ptr: u64, // child's buffer address
count: usize, // requested write count

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{
        .kernel_pid = @intCast(notif.pid),
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @truncate(notif.data.arg2),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating write: fd={d} count={d}", .{ self.fd, self.count });

    // Handle stdout/stderr - log and return success (like writev)
    switch (self.fd) {
        linux.STDOUT_FILENO => {
            var buf: [4096]u8 = undefined;
            const read_count = @min(self.count, buf.len);
            try memory_bridge.readSlice(buf[0..read_count], self.kernel_pid, self.buf_ptr);
            logger.log("stdout:\n\n{s}", .{std.mem.sliceTo(buf[0..read_count], 0)});
            return Result.replySuccess(@intCast(read_count));
        },
        linux.STDERR_FILENO => {
            var buf: [4096]u8 = undefined;
            const read_count = @min(self.count, buf.len);
            try memory_bridge.readSlice(buf[0..read_count], self.kernel_pid, self.buf_ptr);
            logger.log("stderr:\n\n{s}", .{std.mem.sliceTo(buf[0..read_count], 0)});
            return Result.replySuccess(@intCast(read_count));
        },
        else => {},
    }

    // Look up the calling process
    const proc = supervisor.virtual_procs.get(self.kernel_pid) catch {
        logger.log("write: process not found for pid={d}", .{self.kernel_pid});
        return Result.replyErr(.SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(self.fd) orelse {
        logger.log("write: EBADF for fd={d}", .{self.fd});
        return Result.replyErr(.BADF);
    };

    // Read data from child's buffer
    var buf: [4096]u8 = undefined;
    const write_count = @min(self.count, buf.len);
    try memory_bridge.readSlice(buf[0..write_count], self.kernel_pid, self.buf_ptr);

    // Write to the FD
    const n = fd_ptr.write(buf[0..write_count]) catch |err| {
        logger.log("write: error writing to fd: {s}", .{@errorName(err)});
        return Result.replyErr(.IO);
    };

    logger.log("write: wrote {d} bytes", .{n});
    return Result.replySuccess(@intCast(n));
}

test "write to stdout returns success" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "hello stdout";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = linux.STDOUT_FILENO,
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(!res.isError());
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), res.reply.val);
}

test "write to stderr returns success" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "hello stderr";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = linux.STDERR_FILENO,
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(!res.isError());
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), res.reply.val);
}

test "write to invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "test";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res.isError());
    try testing.expectEqual(linux.E.BADF, @as(linux.E, @enumFromInt(res.reply.errno)));
}

test "write to kernel fd works" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    // Create a temp file and open it
    const OpenAt = @import("OpenAt.zig");
    const test_path = "/tmp/bvisor_write_test.txt";

    // Set up I/O for file operations
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    // Clean up any existing file
    std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};
    defer std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};

    // Open file for writing
    const open_notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(test_path),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true }))),
        .arg3 = 0o644,
    });
    const open_parsed = try OpenAt.parse(open_notif);
    const open_res = try open_parsed.handle(&supervisor);
    try testing.expect(!open_res.isError());
    const vfd: i32 = @intCast(open_res.reply.val);

    // Write to the file
    const test_data = "hello write";
    const write_notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const write_parsed = Self.parse(write_notif);
    const write_res = try write_parsed.handle(&supervisor);
    try testing.expect(!write_res.isError());
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), write_res.reply.val);

    // Close and verify by reading the file
    const proc = supervisor.virtual_procs.lookup.get(child_pid).?;
    var fd = proc.fd_table.get(vfd).?;
    fd.close();
    _ = proc.fd_table.remove(vfd);

    // Read back via a new open - COW should have the content
    const read_notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(test_path),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });
    const read_open_parsed = try OpenAt.parse(read_notif);
    const read_open_res = try read_open_parsed.handle(&supervisor);
    try testing.expect(!read_open_res.isError());

    const read_vfd: i32 = @intCast(read_open_res.reply.val);
    const proc2 = supervisor.virtual_procs.lookup.get(child_pid).?;
    var read_fd = proc2.fd_table.get(read_vfd).?;
    var buf: [64]u8 = undefined;
    const n = try read_fd.read(&buf);
    try testing.expectEqualStrings(test_data, buf[0..n]);

    read_fd.close();
}
