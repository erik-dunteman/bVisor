const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const KernelFD = types.KernelFD;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);
    var iovecs: [MAX_IOV]posix.iovec_const = undefined;
    const data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    // Read iovec array from child memory
    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec_const);
        iovecs[i] = try memory_bridge.read(posix.iovec_const, @intCast(notif.pid), iov_addr);
    }

    // Read buffer data from child memory for each iovec (one syscall per iovec)
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            try memory_bridge.readSlice(dest, @intCast(notif.pid), buf_ptr);
            data_len += buf_len;
        }
    }

    const logger = supervisor.logger;
    // TODO: supervisor.fs

    logger.log("Emulating writev: fd={d} iovec_count={d} total_bytes={d}", .{
        notif.data.arg0,
        iovec_count,
        notif.data.arg2,
    });

    // Only handle stdout = stderr
    const data = data_buf[0..data_len];
    switch (fd) {
        linux.STDOUT_FILENO => {
            logger.log("stdout:\n\n{s}", .{std.mem.sliceTo(data, 0)});
        },
        linux.STDERR_FILENO => {
            logger.log("stderr:\n\n{s}", .{std.mem.sliceTo(data, 0)});
        },
        else => {
            logger.log("writev: passthrough for non-stdout/stderr fd={d}", .{fd});
            return replyContinue(notif.id);
        },
    }

    return replySuccess(notif.id, @intCast(data_len));
}
