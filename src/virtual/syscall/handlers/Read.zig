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
count: usize, // requested read count

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

    logger.log("Emulating read: fd={d} count={d}", .{ self.fd, self.count });

    // Handle stdin - passthrough to kernel
    if (self.fd == linux.STDIN_FILENO) {
        logger.log("read: passthrough for stdin", .{});
        return .use_kernel;
    }

    // Look up the calling process
    const proc = supervisor.virtual_procs.get(self.kernel_pid) catch {
        logger.log("read: process not found for pid={d}", .{self.kernel_pid});
        return Result.replyErr(.SRCH);
    };

    // Look up the virtual FD
    const fd_ptr = proc.fd_table.get(self.fd) orelse {
        logger.log("read: EBADF for fd={d}", .{self.fd});
        return Result.replyErr(.BADF);
    };

    // Allocate stack buffer and read
    var buf: [4096]u8 = undefined;
    const read_count = @min(self.count, buf.len);

    const n = fd_ptr.read(buf[0..read_count]) catch |err| {
        logger.log("read: error reading from fd: {s}", .{@errorName(err)});
        return Result.replyErr(.IO);
    };

    // Write data back to child's buffer
    if (n > 0) {
        try memory_bridge.writeSlice(buf[0..n], self.kernel_pid, self.buf_ptr);
    }

    logger.log("read: read {d} bytes", .{n});
    return Result.replySuccess(@intCast(n));
}

test "read from proc fd returns pid" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
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

    // Now read from it
    var child_buf: [64]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(u64, @intCast(vfd))),
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const read_parsed = Self.parse(read_notif);
    const read_res = try read_parsed.handle(&supervisor);
    try testing.expect(!read_res.isError());

    const n: usize = @intCast(read_res.reply.val);
    // The proc fd should return "100\n" (the pid)
    try testing.expectEqualStrings("100\n", child_buf[0..n]);
}

test "read from invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    var child_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res.isError());
    try testing.expectEqual(linux.E.BADF, @as(linux.E, @enumFromInt(res.reply.errno)));
}

test "read from stdin returns use_kernel" {
    const allocator = testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    var child_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = child_pid,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&child_buf),
        .arg2 = child_buf.len,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .use_kernel);
}
