const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,
buf_ptr: u64,
count: usize,
offset: u64,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @truncate(notif.data.arg2),
        .offset = notif.data.arg3,
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;
    const mem_bridge = supervisor.mem_bridge;

    logger.log("Emulating pread64: fd={d} count={d} offset={d}", .{
        self.fd,
        self.count,
        self.offset,
    });

    // stdio passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("pread64: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Use stack buffer for small reads, otherwise this would need heap
    var buf: [4096]u8 = undefined;
    const read_size = @min(self.count, buf.len);

    const bytes_read = overlay.pread(self.fd, buf[0..read_size], self.offset) catch |err| {
        logger.log("pread64: failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForReading => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    if (bytes_read > 0) {
        try mem_bridge.writeSlice(buf[0..bytes_read], self.buf_ptr);
    }

    logger.log("pread64: read {d} bytes", .{bytes_read});
    return .{ .handled = Result.Handled.success(@intCast(bytes_read)) };
}
