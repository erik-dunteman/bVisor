const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);

    // Continue in case of stdout or stderr
    // TODO: virtualize this ourselves for more control of where logs go
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("writev: process not found for pid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Look up the File
    const file = caller.fd_table.get(fd) orelse {
        logger.log("writev: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]posix.iovec_const = undefined;
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec_const);
        iovecs[i] = memory_bridge.read(posix.iovec_const, caller_tid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    // Read buffer data from child memory for each iovec
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            memory_bridge.readSlice(dest, caller_tid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            data_len += buf_len;
        }
    }

    // Write to the File
    const n = file.write(data_buf[0..data_len]) catch |err| {
        logger.log("writev: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("writev: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const FdTable = @import("../../fs/FdTable.zig");
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;

test "writev single iovec writes data" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const tmp_file = try Tmp.open(&supervisor.overlay, "/tmp/writev_test1", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const vfd = try caller.fd_table.insert(File{ .tmp = tmp_file });

    const data = "hello";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "writev multiple iovecs concatenated write" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const tmp_file = try Tmp.open(&supervisor.overlay, "/tmp/writev_test2", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const vfd = try caller.fd_table.insert(File{ .tmp = tmp_file });

    const d1 = "hel";
    const d2 = "lo ";
    const d3 = "world";
    var iovecs = [_]posix.iovec_const{
        .{ .base = d1.ptr, .len = d1.len },
        .{ .base = d2.ptr, .len = d2.len },
        .{ .base = d3.ptr, .len = d3.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 3,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 11), resp.val);
}

test "writev FD 1 (stdout) returns replyContinue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const data = "hello";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 1, // stdout
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "writev FD 2 (stderr) returns replyContinue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const data = "error";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 2, // stderr
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "writev non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const data = "hello";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}
