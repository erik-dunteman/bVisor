const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const Self = @This();

kernel_pid: Proc.KernelPID, // caller's kernel pid
target_pid: Proc.KernelPID, // arg0 (pid_t pid) - now kernel PID
signal: u6, // arg1 (int sig)

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{
        .kernel_pid = @intCast(notif.pid),
        .target_pid = @intCast(@as(i64, @bitCast(notif.data.arg0))),
        .signal = @truncate(notif.data.arg1),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    // Negative PIDs (process groups) not supported
    if (self.target_pid <= 0) {
        return Result.reply_err(.NOSYS);
    }

    // Get caller's process (lazy registration if needed)
    const caller = supervisor.virtual_procs.get(self.kernel_pid) catch
        return Result.reply_err(.SRCH);

    // Get target process (lazy registration if needed)
    const target = supervisor.virtual_procs.get(self.target_pid) catch
        return Result.reply_err(.SRCH);

    // Check visibility - caller must be able to see target
    if (!caller.can_see(target)) {
        return Result.reply_err(.SRCH);
    }

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(self.signal);
    posix.kill(@intCast(target.pid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return Result.reply_err(errno);
    };

    return Result.reply_success(0);
}

test "parse extracts target pid and signal" {
    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 200, // target kernel pid
        .arg1 = 9, // SIGKILL
    });

    const parsed = Self.parse(notif);
    try testing.expectEqual(@as(Proc.KernelPID, 100), parsed.kernel_pid);
    try testing.expectEqual(@as(Proc.KernelPID, 200), parsed.target_pid);
    try testing.expectEqual(@as(u6, 9), parsed.signal);
}

test "kill with negative pid returns ENOSYS" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = @as(u64, @bitCast(@as(i64, -1))), // -1 = all processes
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOSYS)), res.reply.errno);
}

test "kill with zero pid returns ENOSYS" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 0, // process group
        .arg1 = 9,
    });

    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(res.is_error());
    try testing.expectEqual(@as(i32, @intFromEnum(linux.E.NOSYS)), res.reply.errno);
}
