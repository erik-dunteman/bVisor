const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("readv: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Critical section: File lookup
    // File refcounting allows us to keep a pointer to the file outside of the critical section
    var file: *File = undefined;
    {
        supervisor.mutex.lock();
        defer supervisor.mutex.unlock();

        const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
            logger.log("readv: process not found for pid={d}: {}", .{ caller_pid, err });
            return replyErr(notif.id, .SRCH);
        };

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("readv: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]posix.iovec = undefined;
    var total_requested: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec);
        iovecs[i] = memory_bridge.read(posix.iovec, caller_pid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
        total_requested += iovecs[i].len;
    }

    // Perform read into supervisor-local buf
    // It's ok to only partially resolve count if count is larger than we're willing to stack allocate
    // This is valid POSIX behavior
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(total_requested, max_len);
    const read_buf: []u8 = max_buf[0..max_count];
    const n = file.read(read_buf) catch |err| {
        logger.log("readv: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    // Distribute the read data across the child's iovec buffers
    var bytes_written: usize = 0;
    for (0..iovec_count) |i| {
        if (bytes_written >= n) break;

        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const remaining = n - bytes_written;
        const to_write = @min(iov.len, remaining);

        if (to_write > 0) {
            memory_bridge.writeSlice(read_buf[bytes_written..][0..to_write], caller_pid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            bytes_written += to_write;
        }
    }

    logger.log("readv: read {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

const Procs = @import("../../proc/Procs.zig");
const FdTable = @import("../../fs/FdTable.zig");
const ProcFileMod = @import("../../fs/backend/procfile.zig");
const ProcFile = ProcFileMod.ProcFile;

test "readv single iovec reads data correctly" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const caller = supervisor.guest_procs.lookup.get(init_pid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }));

    // Set up a single iovec
    var result_buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &result_buf, .len = result_buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expect(resp.val > 0);
    try testing.expectEqualStrings("100\n", result_buf[0..@intCast(resp.val)]);
}

test "readv multiple iovecs distributes data across buffers" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const caller = supervisor.guest_procs.lookup.get(init_pid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }));

    // Content is "100\n" (4 bytes), distribute across 2-byte buffers
    var buf1: [2]u8 = undefined;
    var buf2: [2]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf1, .len = 2 },
        .{ .base = &buf2, .len = 2 },
    };

    const notif = makeNotif(.readv, .{
        .pid = init_pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 2,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 4), resp.val);
    try testing.expectEqualStrings("10", &buf1);
    try testing.expectEqualStrings("0\n", &buf2);
}

test "readv FD 0 returns replyContinue" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = init_pid,
        .arg0 = 0, // stdin
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "readv non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = init_pid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}
