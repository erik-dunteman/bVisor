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
// Store the iovec array (buffer addresses and lengths)
iovecs: [MAX_IOV]posix.iovec,
total_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iov_ptr = notif.data.arg1,
        .iovcnt = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
        .total_len = 0,
    };

    // Read iovec array from child memory
    for (0..self.iovcnt) |i| {
        const iov_addr = self.iov_ptr + i * @sizeOf(posix.iovec);
        self.iovecs[i] = try mem_bridge.read(posix.iovec, iov_addr);
        self.total_len += self.iovecs[i].len;
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating readv: fd={d} iovcnt={d} total_len={d}", .{
        self.fd,
        self.iovcnt,
        self.total_len,
    });

    // Check if FD is tracked by overlay (including redirected stdio)
    if (overlay.hasFD(self.fd)) {
        // FD is in overlay - handle it
    } else if (self.fd >= 0 and self.fd <= 2) {
        // Real stdio (not redirected) - passthrough
        logger.log("readv: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    } else {
        // Unknown FD > 2 - return EBADF (full virtualization)
        logger.log("readv: EBADF for unknown fd={d}", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    // Read from overlay
    const read_len = @min(self.total_len, 4096);
    var local_buf: [4096]u8 = undefined;
    const bytes_read = overlay.read(self.fd, local_buf[0..read_len]) catch |err| {
        logger.log("readv failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForReading => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    // Write data to child's iovec buffers
    var offset: usize = 0;
    for (0..self.iovcnt) |i| {
        if (offset >= bytes_read) break;

        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const to_copy = @min(iov.len, bytes_read - offset);

        if (to_copy > 0) {
            try supervisor.mem_bridge.writeSlice(local_buf[offset..][0..to_copy], buf_ptr);
            offset += to_copy;
        }
    }

    logger.log("readv: read {d} bytes from fd={d}", .{ bytes_read, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_read)) };
}
