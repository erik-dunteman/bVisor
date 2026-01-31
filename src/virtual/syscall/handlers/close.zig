const std = @import("std");
const linux = std.os.linux;
const Proc = @import("../../proc/Proc.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    // Passthrough stdin/stdout/stderr
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        logger.log("close: passthrough for fd={d}", .{fd});
        return replyContinue(notif.id);
    }

    const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
        logger.log("close: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file in the fd table
    const file = caller.fd_table.get(fd) orelse {
        logger.log("close: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Close the file
    file.close();

    // Remove from fd table
    _ = caller.fd_table.remove(fd);

    logger.log("close: closed fd={d}", .{fd});
    return replySuccess(notif.id, 0);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const File = @import("../../fs/file.zig").File;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;

test "close virtual FD returns success and removes from table" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const caller = supervisor.guest_procs.lookup.get(init_pid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    const notif = makeNotif(.close, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);

    // VFD should be gone
    try testing.expect(caller.fd_table.get(vfd) == null);
}

test "after close, read same VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const caller = supervisor.guest_procs.lookup.get(init_pid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    // Close it
    const close_notif = makeNotif(.close, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
    });
    _ = handle(close_notif, &supervisor);

    // Now try to read - should EBADF
    const read_handler = @import("read.zig");
    var result_buf: [64]u8 = undefined;
    const read_notif = makeNotif(.read, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = read_handler.handle(read_notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "close FD 0 (stdin) returns replyContinue" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{ .pid = init_pid, .arg0 = 0 });
    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "close FD 1 (stdout) returns replyContinue" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{ .pid = init_pid, .arg0 = 1 });
    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "close FD 2 (stderr) returns replyContinue" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{ .pid = init_pid, .arg0 = 2 });
    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "close non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{ .pid = init_pid, .arg0 = 99 });
    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "double close - first succeeds, second EBADF" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const caller = supervisor.guest_procs.lookup.get(init_pid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    const notif = makeNotif(.close, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
    });

    // First close succeeds
    const resp1 = handle(notif, &supervisor);
    try testing.expect(!isError(resp1));

    // Second close returns EBADF
    const resp2 = handle(notif, &supervisor);
    try testing.expect(isError(resp2));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp2.@"error");
}

test "close with unknown caller PID returns ESRCH" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{ .pid = 999, .arg0 = 3 });
    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}
