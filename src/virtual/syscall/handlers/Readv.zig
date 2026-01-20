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

const MAX_IOV = 16;

kernel_pid: Proc.KernelPID,
fd: i32, // virtual fd from child
iovec_ptr: u64,
iovec_count: usize,
// Store the iovec array parsed from child memory
iovecs: [MAX_IOV]posix.iovec,

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .kernel_pid = @intCast(notif.pid),
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iovec_ptr = notif.data.arg1,
        .iovec_count = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
    };

    // Read iovec array from child memory
    for (0..self.iovec_count) |i| {
        const iov_addr = self.iovec_ptr + i * @sizeOf(posix.iovec);
        self.iovecs[i] = try memory_bridge.read(posix.iovec, @intCast(notif.pid), iov_addr);
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Calculate total bytes requested
    var total_requested: usize = 0;
    for (0..self.iovec_count) |i| {
        total_requested += self.iovecs[i].len;
    }

    logger.log("Emulating readv: fd={d} iovec_count={d} total_bytes={d}", .{
        self.fd,
        self.iovec_count,
        total_requested,
    });

    // Handle stdin - passthrough to kernel
    if (self.fd == linux.STDIN_FILENO) {
        logger.log("readv: passthrough for stdin", .{});
        return .use_kernel;
    }

    // Look up the calling process
    const proc = supervisor.virtual_procs.get(self.kernel_pid) catch {
        logger.log("readv: process not found for pid={d}", .{self.kernel_pid});
        return Result.replyErr(.SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(self.fd) orelse {
        logger.log("readv: EBADF for fd={d}", .{self.fd});
        return Result.replyErr(.BADF);
    };

    // Read into a local buffer first
    var buf: [4096]u8 = undefined;
    const read_count = @min(total_requested, buf.len);

    const n = fd_ptr.read(buf[0..read_count]) catch |err| {
        logger.log("readv: error reading from fd: {s}", .{@errorName(err)});
        return Result.replyErr(.IO);
    };

    // Distribute the read data across the child's iovec buffers
    var bytes_written: usize = 0;
    for (0..self.iovec_count) |i| {
        if (bytes_written >= n) break;

        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const remaining = n - bytes_written;
        const to_write = @min(iov.len, remaining);

        if (to_write > 0) {
            try memory_bridge.writeSlice(buf[bytes_written..][0..to_write], self.kernel_pid, buf_ptr);
            bytes_written += to_write;
        }
    }

    logger.log("readv: read {d} bytes into {d} iovecs", .{ n, self.iovec_count });
    return Result.replySuccess(@intCast(n));
}

test "readv from proc fd returns pid" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 200;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    // First open a /proc/self fd
    const OpenAt = @import("OpenAt.zig");
    const open_notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });
    const open_parsed = try OpenAt.parse(open_notif);
    const open_res = try open_parsed.handle(&supervisor);
    try testing.expect(!open_res.isError());
    const vfd: i32 = @intCast(open_res.reply.val);

    // Set up iovecs - split the read across multiple buffers
    var buf1: [2]u8 = undefined;
    var buf2: [8]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf1, .len = buf1.len },
        .{ .base = &buf2, .len = buf2.len },
    };

    const read_notif = makeNotif(.readv, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(u64, @intCast(vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const read_parsed = try Self.parse(read_notif);
    const read_res = try read_parsed.handle(&supervisor);
    try testing.expect(!read_res.isError());

    const n: usize = @intCast(read_res.reply.val);
    // The proc fd should return "200\n" (the pid) - 4 bytes
    try testing.expectEqual(@as(usize, 4), n);
    // First 2 bytes in buf1
    try testing.expectEqualStrings("20", &buf1);
    // Remaining 2 bytes in buf2
    try testing.expectEqualStrings("0\n", buf2[0..2]);
}

test "readv from invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = child_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res.isError());
    try testing.expectEqual(linux.E.BADF, @as(linux.E, @enumFromInt(res.reply.errno)));
}

test "readv from stdin returns use_kernel" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = child_pid,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .use_kernel);
}
