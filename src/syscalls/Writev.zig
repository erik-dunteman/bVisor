const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../Supervisor.zig");

const Self = @This();

const MAX_IOV = 16;

fd: FD,
iov_ptr: u64,
iovcnt: usize,
// Store the iovec array and buffer data
iovecs: [MAX_IOV]posix.iovec_const,
// Total data to write (concatenated from all iovecs)
data_buf: [4096]u8,
data_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iov_ptr = notif.data.arg1,
        .iovcnt = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
        .data_buf = undefined,
        .data_len = 0,
    };

    // Read iovec array from child memory
    for (0..self.iovcnt) |i| {
        const iov_addr = self.iov_ptr + i * @sizeOf(posix.iovec_const);
        self.iovecs[i] = try mem_bridge.read(posix.iovec_const, iov_addr);
    }

    // Read buffer data from child memory for each iovec (one syscall per iovec)
    for (0..self.iovcnt) |i| {
        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, self.data_buf.len - self.data_len);

        if (buf_len > 0) {
            const dest = self.data_buf[self.data_len..][0..buf_len];
            try mem_bridge.readSlice(dest, buf_ptr);
            self.data_len += buf_len;
        }
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating writev: fd={d} iovcnt={d} total_bytes={d}", .{
        self.fd,
        self.iovcnt,
        self.data_len,
    });

    // Check if FD is tracked by overlay (including redirected stdio)
    if (overlay.hasFD(self.fd)) {
        // FD is in overlay - handle it
    } else if (self.fd >= 0 and self.fd <= 2) {
        // Real stdio (not redirected) - passthrough
        logger.log("writev: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    } else {
        // Unknown FD > 2 - return EBADF (full virtualization)
        logger.log("writev: EBADF for unknown fd={d}", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    // Write to overlay (handles COW automatically)
    const data = self.data_buf[0..self.data_len];
    const bytes_written = overlay.write(self.fd, data) catch |err| {
        logger.log("writev failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForWriting => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("writev: wrote {d} bytes to fd={d}", .{ bytes_written, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_written)) };
}
