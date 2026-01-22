const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const FD = @import("../../fs/FD.zig").FD;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const kernel_pid: Proc.KernelPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_ptr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    const logger = supervisor.logger;

    logger.log("Emulating read: fd={d} count={d}", .{ fd, count });

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("read: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Look up the calling process
    const proc = supervisor.virtual_procs.get(kernel_pid) catch {
        logger.log("read: process not found for pid={d}", .{kernel_pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(fd) orelse {
        logger.log("read: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read up to min(count, 4096) - short reads are valid POSIX behavior
    var buf: [4096]u8 = undefined;
    const read_size = @min(count, buf.len);

    const n = fd_ptr.read(buf[0..read_size]) catch |err| {
        logger.log("read: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    if (n > 0) {
        try memory_bridge.writeSlice(buf[0..n], kernel_pid, buf_ptr);
    }

    logger.log("read: read {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

test "read from proc fd returns pid" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    // First open a /proc/self fd
    const OpenAt = @import("OpenAt.zig");
    const open_notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });
    const open_res = OpenAt.handle(open_notif, &supervisor);
    try testing.expect(!isError(open_res));
    const vfd: i32 = @intCast(open_res.val);

    // Now read from it
    var child_buf: [64]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(u64, @intCast(vfd))),
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const read_res = handle(read_notif, &supervisor);
    try testing.expect(!isError(read_res));
    const n: usize = @intCast(read_res.val);
    // The proc fd should return "100\n" (the pid)
    try testing.expectEqualStrings("100\n", child_buf[0..n]);
}

test "read from invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    var child_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const res = handle(notif, &supervisor);
    try testing.expect(isError(res));
    try testing.expectEqual(linux.E.BADF, @as(linux.E, @enumFromInt(res.@"error")));
}

test "read from stdin returns use_kernel" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, child_pid);
    defer supervisor.deinit();

    var child_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const res = handle(notif, &supervisor);
    try testing.expect(isContinue(res));
}
