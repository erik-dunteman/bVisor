const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const AbsPid = Proc.AbsPid;
const OpenFile = @import("../../fs/OpenFile.zig").OpenFile;
const openat = @import("openat.zig");
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

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const supervisor_pid: AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);
    var iovecs: [MAX_IOV]posix.iovec = undefined;
    // read iovec array from child memory
    var total_requested: usize = 0;
    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec);
        iovecs[i] = memory_bridge.read(posix.iovec, supervisor_pid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
        total_requested += iovecs[i].len;
    }

    const logger = supervisor.logger;

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("readv: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Look up the calling process
    const proc = supervisor.guest_procs.get(supervisor_pid) catch {
        logger.log("readv: process not found for pid={d}", .{supervisor_pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(fd) orelse {
        logger.log("readv: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read into a local buffer first
    var buf: [4096]u8 = undefined;
    const read_count = @min(total_requested, buf.len);

    const n = fd_ptr.read(buf[0..read_count]) catch |err| {
        logger.log("readv: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    // Distribute the read data across the child's iovec buffers
    var bytes_written: usize = 0;
    for (0..iovec_count) |i| {
        if (bytes_written >= n) break;

        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const remaining = n - bytes_written;
        const to_write = @min(iov.len, remaining);

        if (to_write > 0) {
            memory_bridge.writeSlice(buf[bytes_written..][0..to_write], supervisor_pid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            bytes_written += to_write;
        }
    }

    logger.log("readv: read {d} bytes into {d} iovecs", .{ n, iovec_count });
    return replySuccess(notif.id, @intCast(n));
}

test "readv from proc fd returns pid" {
    const allocator = testing.allocator;
    const guest_pid: AbsPid = 200;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    defer supervisor.deinit();

    // First open a /proc/self fd
    const open_notif = makeNotif(.openat, .{
        .pid = guest_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });
    const open_res = openat.handle(open_notif, &supervisor);
    try testing.expect(!isError(open_res));
    const vfd: i32 = @intCast(open_res.val);

    // Set up iovecs - split the read across multiple buffers
    var buf1: [2]u8 = undefined;
    var buf2: [8]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf1, .len = buf1.len },
        .{ .base = &buf2, .len = buf2.len },
    };

    const read_notif = makeNotif(.readv, .{
        .pid = guest_pid,
        .arg0 = @bitCast(@as(u64, @intCast(vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const read_res = handle(read_notif, &supervisor);
    try testing.expect(!isError(read_res));

    const n: usize = @intCast(read_res.val);
    // The proc fd should return "200\n" (the pid) - 4 bytes
    try testing.expectEqual(@as(usize, 4), n);
    // First 2 bytes in buf1
    try testing.expectEqualStrings("20", &buf1);
    // Remaining 2 bytes in buf2
    try testing.expectEqualStrings("0\n", buf2[0..2]);
}

test "readv from invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const guest_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = guest_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const res = handle(notif, &supervisor);
    try testing.expect(isError(res));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.BADF)), res.@"error");
}

test "readv from stdin returns continue" {
    const allocator = testing.allocator;
    const guest_pid: AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = guest_pid,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const res = handle(notif, &supervisor);
    try testing.expect(isContinue(res));
}
