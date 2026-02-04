const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/file.zig").File;
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

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("read: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("read: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Look up the virtual FD
    const file = caller.fd_table.get(fd) orelse {
        logger.log("read: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Perform read into supervisor-local buf
    // It's ok to only partially resolve count if count is larger than we're willing to stack allocate
    // This is valid POSIX behavior
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const read_buf: []u8 = max_buf[0..max_count];

    const n = file.read(read_buf) catch |err| {
        logger.log("read: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    // Copy into child memory space
    if (n > 0) {
        memory_bridge.writeSlice(read_buf[0..n], @intCast(notif.pid), buf_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    logger.log("read: read {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

const Threads = @import("../../proc/Threads.zig");
const FdTable = @import("../../fs/FdTable.zig");
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;

test "read from virtual file returns data" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    // Insert a proc file into the fd table (content "100\n")
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    // Create a buffer for the result
    var result_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expect(resp.val > 0);
    try testing.expectEqualStrings("100\n", result_buf[0..@intCast(resp.val)]);
}

test "read count=5 from larger file returns at most 5 bytes" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    var result_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = 5,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expect(resp.val <= 5);
}

test "read from FD 0 (stdin) returns replyContinue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = init_tid,
        .arg0 = 0, // stdin
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "read count=0 returns 0" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(File{ .proc = proc_file });

    var result_buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "read from non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = init_tid,
        .arg0 = 99, // non-existent vfd
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "read with unknown caller PID returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = 999, // unknown pid
        .arg0 = 3,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}
