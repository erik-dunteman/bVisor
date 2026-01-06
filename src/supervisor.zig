const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const FD = types.FD;
const MemoryBridge = types.MemoryBridge;
const Result = types.Result;
const Logger = types.Logger;

pub fn handle_notifications(notify_fd: FD, mem_bridge: MemoryBridge) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Starting notification handler on fd {d}", .{notify_fd});

    while (true) {
        // Receive notification from kernel
        var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
        const recv_result = linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
        switch (Result(usize).from(recv_result)) {
            .Ok => {},
            .Error => |err| switch (err) {
                .NOENT => {
                    // Thrown when child exits
                    logger.log("Child exited, stopping notification handler", .{});
                    break;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }

        // Parse request and execute (or passthrough)
        const sys_call = try Request.from_notif(mem_bridge, notif);
        const response = try sys_call.handle(mem_bridge, logger);

        const notif_resp = response.to_notif_resp();
        _ = try Result(usize).from(
            linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&notif_resp)),
        ).unwrap();
    }
}

const ClockNanosleep = struct {
    clock_id: linux.clockid_t,
    flags: linux.TIMER,
    request_ptr: u64,
    request: linux.timespec,
    remain_ptr: u64, // may be 0 (null)

    const Self = @This();

    pub fn from_notif(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
        return .{
            .clock_id = @enumFromInt(notif.data.arg0),
            .flags = @bitCast(@as(u32, @truncate(notif.data.arg1))),
            .request_ptr = notif.data.arg2,
            .request = try mem_bridge.read(linux.timespec, notif.data.arg2),
            .remain_ptr = notif.data.arg3,
        };
    }

    fn handle(self: Self, mem_bridge: MemoryBridge, logger: Logger) !EmulationResponse {
        logger.log("Emulating clock_nanosleep: clock={s} sec={d}.{d}", .{
            @tagName(self.clock_id),
            self.request.sec,
            self.request.nsec,
        });

        var remain: linux.timespec = undefined;
        const result = linux.clock_nanosleep(self.clock_id, self.flags, &self.request, &remain);
        const err_code = linux.errno(result);

        if (err_code == .SUCCESS) {
            logger.log("clock_nanosleep completed successfully", .{});
            return EmulationResponse.success(0);
        }

        if (err_code == .INTR and self.remain_ptr != 0) {
            logger.log("clock_nanosleep interrupted, remain={d}.{d}", .{ remain.sec, remain.nsec });
            mem_bridge.write(linux.timespec, remain, self.remain_ptr) catch |write_err| {
                logger.log("Failed to write remain: {}", .{write_err});
            };
        }

        return EmulationResponse.err(err_code);
    }
};

const EmulatedSyscall = union(enum) {
    clock_nanosleep: ClockNanosleep,

    const Self = @This();

    fn handle(self: Self, mem_bridge: MemoryBridge, logger: Logger) !EmulationResponse {
        return switch (self) {
            inline else => |inner| inner.handle(mem_bridge, logger),
        };
    }
};

const EmulationResponse = struct {
    val: i64,
    errno: i32,

    const Self = @This();

    pub fn success(val: i64) Self {
        return .{ .val = val, .errno = 0 };
    }

    pub fn err(errno: linux.E) Self {
        return .{ .val = 0, .errno = @intFromEnum(errno) };
    }
};

const Response = struct {
    id: u64,
    handler: union(enum) {
        passthrough: void,
        emulated: EmulationResponse,
    },

    const Self = @This();

    pub fn to_notif_resp(self: Self) linux.SECCOMP.notif_resp {
        return switch (self.handler) {
            .passthrough => .{
                .id = self.id,
                .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                .val = 0,
                .@"error" = 0,
            },
            .emulated => |emulated| .{
                .id = self.id,
                .flags = 0,
                .val = emulated.val,
                .@"error" = emulated.errno,
            },
        };
    }
};

const Request = struct {
    id: u64,
    handler: union(enum) {
        passthrough: linux.SYS,
        emulated: EmulatedSyscall,
    },

    const Self = @This();

    /// Parses a seccomp notification into a SysCall.
    fn from_notif(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        return .{
            .id = notif.id,
            .handler = switch (sys_code) {
                .clock_nanosleep => .{ .emulated = .{ .clock_nanosleep = try ClockNanosleep.from_notif(mem_bridge, notif) } },
                else => .{ .passthrough = sys_code },
            },
        };
    }

    fn handle(self: Self, mem_bridge: MemoryBridge, logger: Logger) !Response {
        return .{
            .id = self.id,
            .handler = switch (self.handler) {
                .passthrough => |sys_code| blk: {
                    logger.log("Syscall: passthrough: {s}", .{@tagName(sys_code)});
                    break :blk .{ .passthrough = {} };
                },
                .emulated => |emulated| .{ .emulated = try emulated.handle(mem_bridge, logger) },
            },
        };
    }
};
