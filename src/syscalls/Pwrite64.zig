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

    logger.log("Emulating pwrite64: fd={d} count={d} offset={d}", .{
        self.fd,
        self.count,
        self.offset,
    });

    // stdio passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("pwrite64: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Read data from child memory
    var buf: [4096]u8 = undefined;
    const write_size = @min(self.count, buf.len);
    try mem_bridge.readSlice(buf[0..write_size], self.buf_ptr);

    const bytes_written = overlay.pwrite(self.fd, buf[0..write_size], self.offset) catch |err| {
        logger.log("pwrite64: failed: {}", .{err});
        return switch (err) {
            error.BadFD => .{ .handled = Result.Handled.err(.BADF) },
            error.NotOpenForWriting => .{ .handled = Result.Handled.err(.BADF) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("pwrite64: wrote {d} bytes", .{bytes_written});
    return .{ .handled = Result.Handled.success(@intCast(bytes_written)) };
}
