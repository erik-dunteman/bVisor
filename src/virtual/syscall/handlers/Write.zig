const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const FD = @import("../../fs/FD.zig").FD;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const kernel_pid: Proc.KernelPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_ptr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);
    const logger = supervisor.logger;

    logger.log("Emulating write: fd={d} count={d}", .{ fd, count });

    // Handle stdout/stderr - log and return success (like writev)
    // ERIK TODO: make less ugly
    switch (fd) {
        linux.STDOUT_FILENO => {
            var buf: [4096]u8 = undefined;
            const read_count = @min(count, buf.len);
            try memory_bridge.readSlice(buf[0..read_count], kernel_pid, buf_ptr);
            logger.log("stdout:\n\n{s}", .{std.mem.sliceTo(buf[0..read_count], 0)});
            return replySuccess(notif.id, @intCast(read_count));
        },
        linux.STDERR_FILENO => {
            var buf: [4096]u8 = undefined;
            const read_count = @min(count, buf.len);
            try memory_bridge.readSlice(buf[0..read_count], kernel_pid, buf_ptr);
            logger.log("stderr:\n\n{s}", .{std.mem.sliceTo(buf[0..read_count], 0)});
            return replySuccess(notif.id, @intCast(read_count));
        },
        else => {},
    }

    // Look up the calling process
    const proc = supervisor.virtual_procs.get(kernel_pid) catch {
        logger.log("write: process not found for pid={d}", .{kernel_pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(fd) orelse {
        logger.log("write: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Write up to min(count, 4096) - short writes are valid POSIX behavior
    var buf: [4096]u8 = undefined;
    const write_size = @min(count, buf.len);
    try memory_bridge.readSlice(buf[0..write_size], kernel_pid, buf_ptr);

    const n = fd_ptr.write(buf[0..write_size]) catch |err| {
        logger.log("write: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("write: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

test "write to stdout returns success" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "hello stdout";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = linux.STDOUT_FILENO,
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), resp.val);
}

test "write to stderr returns success" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "hello stderr";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = linux.STDERR_FILENO,
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), resp.val);
}

test "write to invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    const test_data = "test";
    const notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(linux.E.BADF, @as(linux.E, @enumFromInt(resp.@"error")));
}

test "write to kernel fd works" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
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
    const open_res = OpenAt.handle(open_notif, &supervisor);
    try testing.expect(!isError(open_res));
    const vfd: i32 = @intCast(open_res.val);

    // Write to the file
    const test_data = "hello write";
    const write_notif = makeNotif(.write, .{
        .pid = child_pid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const write_res = handle(write_notif, &supervisor);
    try testing.expect(!isError(write_res));
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), write_res.val);

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
    const read_open_res = OpenAt.handle(read_notif, &supervisor);
    try testing.expect(!isError(read_open_res));

    const read_vfd: i32 = @intCast(read_open_res.val);
    const proc2 = supervisor.virtual_procs.lookup.get(child_pid).?;
    var read_fd = proc2.fd_table.get(read_vfd).?;
    var buf: [64]u8 = undefined;
    const n = try read_fd.read(&buf);
    try testing.expectEqualStrings(test_data, buf[0..n]);

    read_fd.close();
}
