const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../Supervisor.zig");

const Self = @This();

fd: FD,
buf_ptr: u64,
count: usize,
// Buffer to hold the data
data_buf: [4096]u8,
data_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @min(@as(usize, @truncate(notif.data.arg2)), 4096),
        .data_buf = undefined,
        .data_len = 0,
    };

    // Read buffer data from child memory in one syscall
    try mem_bridge.readSlice(self.data_buf[0..self.count], self.buf_ptr);
    self.data_len = self.count;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    logger.log("Emulating write: fd={d} count={d}", .{ self.fd, self.data_len });

    // Check if FD is tracked by overlay (including redirected stdio)
    if (overlay.hasFD(self.fd)) {
        // FD is in overlay - handle it
    } else if (self.fd >= 0 and self.fd <= 2) {
        // Real stdio (not redirected) - passthrough
        logger.log("write: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    } else {
        // Unknown FD > 2 - return EBADF (full virtualization)
        logger.log("write: EBADF for unknown fd={d}", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    // Write to overlay (handles COW automatically)
    const data = self.data_buf[0..self.data_len];
    const bytes_written = overlay.write(self.fd, data) catch |err| {
        logger.log("write failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForWriting => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("write: wrote {d} bytes to fd={d}", .{ bytes_written, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_written)) };
}
