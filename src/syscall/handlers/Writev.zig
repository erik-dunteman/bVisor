const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../types.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../Supervisor.zig");

// comptime dependency injection
const deps = @import("../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

const MAX_IOV = 16;

fd: FD,
iovec_ptr: u64,
iovec_count: usize,
// Store the iovec array and buffer data
iovecs: [MAX_IOV]posix.iovec_const,
// Total data to write (concatenated from all iovecs)
data_buf: [4096]u8,
data_len: usize,

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iovec_ptr = notif.data.arg1,
        .iovec_count = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
        .data_buf = undefined,
        .data_len = 0,
    };

    // Read iovec array from child memory
    for (0..self.iovec_count) |i| {
        const iov_addr = self.iovec_ptr + i * @sizeOf(posix.iovec_const);
        self.iovecs[i] = try memory_bridge.read(posix.iovec_const, @intCast(notif.pid), iov_addr);
    }

    // Read buffer data from child memory for each iovec (one syscall per iovec)
    for (0..self.iovec_count) |i| {
        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, self.data_buf.len - self.data_len);

        if (buf_len > 0) {
            const dest = self.data_buf[self.data_len..][0..buf_len];
            try memory_bridge.readSlice(dest, @intCast(notif.pid), buf_ptr);
            self.data_len += buf_len;
        }
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    // TODO: supervisor.fs

    logger.log("Emulating writev: fd={d} iovec_count={d} total_bytes={d}", .{
        self.fd,
        self.iovec_count,
        self.data_len,
    });

    // Only handle stdout = stderr
    const data = self.data_buf[0..self.data_len];
    switch (self.fd) {
        linux.STDOUT_FILENO => {
            logger.log("stdout:\n\n{s}", .{std.mem.sliceTo(data, 0)});
        },
        linux.STDERR_FILENO => {
            logger.log("stderr:\n\n{s}", .{std.mem.sliceTo(data, 0)});
        },
        else => {
            logger.log("writev: passthrough for non-stdout/stderr fd={d}", .{self.fd});
            return .{ .passthrough = {} };
        },
    }

    return .{ .handled = Result.Handled.success(@intCast(self.data_len)) };
}
