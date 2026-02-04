const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const testing = std.testing;

const Supervisor = @import("../../Supervisor.zig");
const Proc = @import("../proc/Proc.zig");
const Procs = @import("../proc/Procs.zig");
const File = @import("../fs/file.zig").File;
const ProcFile = @import("../fs/backend/procfile.zig").ProcFile;
const Tmp = @import("../fs/backend/tmp.zig").Tmp;

const makeNotif = @import("../../seccomp/notif.zig").makeNotif;
const isError = @import("../../seccomp/notif.zig").isError;
const isContinue = @import("../../seccomp/notif.zig").isContinue;

const openat_handler = @import("handlers/openat.zig").handle;
const read_handler = @import("handlers/read.zig").handle;
const write_handler = @import("handlers/write.zig").handle;
const close_handler = @import("handlers/close.zig").handle;
const readv_handler = @import("handlers/readv.zig").handle;
const writev_handler = @import("handlers/writev.zig").handle;

const proc_info = @import("../../deps/deps.zig").proc_info;

fn makeOpenatNotif(pid: Proc.AbsPid, path: [*:0]const u8, flags: u32, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.openat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = flags,
        .arg3 = mode,
    });
}

fn makeReadNotif(pid: Proc.AbsPid, vfd: i32, buf: *anyopaque, count: usize) linux.SECCOMP.notif {
    return makeNotif(.read, .{
        .pid = pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(buf),
        .arg2 = count,
    });
}

fn makeWriteNotif(pid: Proc.AbsPid, vfd: i32, buf: *const anyopaque, count: usize) linux.SECCOMP.notif {
    return makeNotif(.write, .{
        .pid = pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(buf),
        .arg2 = count,
    });
}

fn makeCloseNotif(pid: Proc.AbsPid, vfd: i32) linux.SECCOMP.notif {
    return makeNotif(.close, .{
        .pid = pid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
    });
}

// ============================================================================
// E2E-01: Open proc -> read -> close (returns NsPid)
// ============================================================================

test "open proc -> read -> close returns NsPid" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Open /proc/self
    const open_resp = openat_handler(
        makeOpenatNotif(init_pid, "/proc/self", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(open_resp));
    const vfd: i32 = @intCast(open_resp.val);
    try testing.expect(vfd >= 3);

    // Read
    var buf: [64]u8 = undefined;
    const read_resp = read_handler(
        makeReadNotif(init_pid, vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(read_resp));
    try testing.expectEqualStrings("100\n", buf[0..@intCast(read_resp.val)]);

    // Close
    const close_resp = close_handler(
        makeCloseNotif(init_pid, vfd),
        &supervisor,
    );
    try testing.expect(!isError(close_resp));
}

// ============================================================================
// E2E-02: Open tmp CREAT -> write -> close -> reopen RDONLY -> read -> close
// ============================================================================

test "open tmp -> write -> close -> reopen -> read -> close" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Open /tmp/e2e_test.txt with CREAT|WRONLY|TRUNC
    const creat_flags: u32 = @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const open_resp1 = openat_handler(
        makeOpenatNotif(init_pid, "/tmp/e2e_test.txt", creat_flags, 0o644),
        &supervisor,
    );
    try testing.expect(!isError(open_resp1));
    const write_vfd: i32 = @intCast(open_resp1.val);

    // Write data
    var write_data = "hello e2e".*;
    const write_resp = write_handler(
        makeWriteNotif(init_pid, write_vfd, &write_data, write_data.len),
        &supervisor,
    );
    try testing.expect(!isError(write_resp));
    try testing.expectEqual(@as(i64, 9), write_resp.val);

    // Close
    const close_resp1 = close_handler(
        makeCloseNotif(init_pid, write_vfd),
        &supervisor,
    );
    try testing.expect(!isError(close_resp1));

    // Reopen RDONLY
    const open_resp2 = openat_handler(
        makeOpenatNotif(init_pid, "/tmp/e2e_test.txt", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(open_resp2));
    const read_vfd: i32 = @intCast(open_resp2.val);

    // Read back
    var buf: [64]u8 = undefined;
    const read_resp = read_handler(
        makeReadNotif(init_pid, read_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(read_resp));
    try testing.expectEqualStrings("hello e2e", buf[0..@intCast(read_resp.val)]);

    // Close
    const close_resp2 = close_handler(
        makeCloseNotif(init_pid, read_vfd),
        &supervisor,
    );
    try testing.expect(!isError(close_resp2));
}

// ============================================================================
// E2E-06: Three files open simultaneously, each returns correct data
// ============================================================================

test "three files open simultaneously, each returns correct data" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Open a proc file
    const proc_resp = openat_handler(
        makeOpenatNotif(init_pid, "/proc/self", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(proc_resp));
    const proc_vfd: i32 = @intCast(proc_resp.val);

    // Open /dev/null
    const devnull_resp = openat_handler(
        makeOpenatNotif(init_pid, "/dev/null", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(devnull_resp));
    const devnull_vfd: i32 = @intCast(devnull_resp.val);

    // Open a tmp file
    const creat_flags: u32 = @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const tmp_resp = openat_handler(
        makeOpenatNotif(init_pid, "/tmp/e2e_multi.txt", creat_flags, 0o644),
        &supervisor,
    );
    try testing.expect(!isError(tmp_resp));
    const tmp_vfd: i32 = @intCast(tmp_resp.val);

    // All VFDs should be different
    try testing.expect(proc_vfd != devnull_vfd);
    try testing.expect(proc_vfd != tmp_vfd);
    try testing.expect(devnull_vfd != tmp_vfd);

    // Read from proc file
    var buf: [64]u8 = undefined;
    const proc_read = read_handler(
        makeReadNotif(init_pid, proc_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(proc_read));
    try testing.expectEqualStrings("100\n", buf[0..@intCast(proc_read.val)]);

    // Read from /dev/null - should return 0 (EOF)
    const devnull_read = read_handler(
        makeReadNotif(init_pid, devnull_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(devnull_read));
    try testing.expectEqual(@as(i64, 0), devnull_read.val);

    // Close all
    _ = close_handler(makeCloseNotif(init_pid, proc_vfd), &supervisor);
    _ = close_handler(makeCloseNotif(init_pid, devnull_vfd), &supervisor);
    _ = close_handler(makeCloseNotif(init_pid, tmp_vfd), &supervisor);
}

// ============================================================================
// E2E-07: Close one of three, other two remain accessible
// ============================================================================

test "close one of three, other two remain accessible, closed one EBADF" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Open three files
    const vfd1: i32 = @intCast(openat_handler(
        makeOpenatNotif(init_pid, "/proc/self", 0, 0),
        &supervisor,
    ).val);
    const vfd2: i32 = @intCast(openat_handler(
        makeOpenatNotif(init_pid, "/dev/null", 0, 0),
        &supervisor,
    ).val);
    const vfd3: i32 = @intCast(openat_handler(
        makeOpenatNotif(init_pid, "/dev/zero", 0, 0),
        &supervisor,
    ).val);

    // Close the middle one
    const close_resp = close_handler(
        makeCloseNotif(init_pid, vfd2),
        &supervisor,
    );
    try testing.expect(!isError(close_resp));

    // vfd1 and vfd3 should still be readable
    var buf: [64]u8 = undefined;
    const read1 = read_handler(
        makeReadNotif(init_pid, vfd1, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(read1));

    const read3 = read_handler(
        makeReadNotif(init_pid, vfd3, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(read3));

    // vfd2 should EBADF
    const read2 = read_handler(
        makeReadNotif(init_pid, vfd2, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(isError(read2));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), read2.@"error");

    // Cleanup
    _ = close_handler(makeCloseNotif(init_pid, vfd1), &supervisor);
    _ = close_handler(makeCloseNotif(init_pid, vfd3), &supervisor);
}

// ============================================================================
// E2E-08: VFD monotonicity - open close open gets next VFD
// ============================================================================

test "open -> close -> open -> second open gets next VFD (no reuse)" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Open first file
    const resp1 = openat_handler(
        makeOpenatNotif(init_pid, "/dev/null", 0, 0),
        &supervisor,
    );
    const vfd1: i32 = @intCast(resp1.val);

    // Close it
    _ = close_handler(makeCloseNotif(init_pid, vfd1), &supervisor);

    // Open another file
    const resp2 = openat_handler(
        makeOpenatNotif(init_pid, "/dev/null", 0, 0),
        &supervisor,
    );
    const vfd2: i32 = @intCast(resp2.val);

    // Second VFD should be strictly greater (no reuse)
    try testing.expect(vfd2 > vfd1);
}

// ============================================================================
// E2E-09: CLONE_FILES fork - child sees parent's FDs
// ============================================================================

test "CLONE_FILES fork - child sees parents FDs, parent sees childs" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Parent opens a file
    const parent_open = openat_handler(
        makeOpenatNotif(init_pid, "/proc/self", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(parent_open));
    const parent_vfd: i32 = @intCast(parent_open.val);

    // Fork with CLONE_FILES
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, 200, Procs.CloneFlags.from(linux.CLONE.FILES));

    // Child should see parent's FD (shared fd_table)
    const child = supervisor.guest_procs.lookup.get(200).?;
    const child_ref = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref) |f| f.unref();
    try testing.expect(child_ref != null);

    // Child opens a new file - parent should see it too (shared table)
    const child_open = openat_handler(
        makeOpenatNotif(200, "/dev/null", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(child_open));
    const child_vfd: i32 = @intCast(child_open.val);
    const parent_ref = parent.fd_table.get_ref(child_vfd);
    defer if (parent_ref) |f| f.unref();
    try testing.expect(parent_ref != null);

    // Cleanup
    _ = close_handler(makeCloseNotif(init_pid, parent_vfd), &supervisor);
    _ = close_handler(makeCloseNotif(200, child_vfd), &supervisor);
}

// ============================================================================
// E2E-10: Non-CLONE_FILES fork - independent tables
// ============================================================================

test "non-CLONE_FILES fork - independent tables, parent close doesnt affect child" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Parent opens a file
    const parent_open = openat_handler(
        makeOpenatNotif(init_pid, "/proc/self", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(parent_open));
    const parent_vfd: i32 = @intCast(parent_open.val);

    // Fork without CLONE_FILES (independent copy)
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    _ = try supervisor.guest_procs.registerChild(parent, 200, Procs.CloneFlags.from(0));
    const child = supervisor.guest_procs.lookup.get(200).?;

    // Child should have a copy of the VFD
    const child_ref1 = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref1) |f| f.unref();
    try testing.expect(child_ref1 != null);

    // Parent closes - should not affect child
    _ = close_handler(makeCloseNotif(init_pid, parent_vfd), &supervisor);
    const parent_ref = parent.fd_table.get_ref(parent_vfd);
    defer if (parent_ref) |f| f.unref();
    try testing.expect(parent_ref == null);
    const child_ref2 = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref2) |f| f.unref();
    try testing.expect(child_ref2 != null);
}

// ============================================================================
// E2E-11: Child namespace reads /proc/self -> sees NsPid in own namespace
// ============================================================================

test "child namespace reads /proc/self -> sees NsPid 1" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();
    defer proc_info.testing.reset(allocator);

    // Create child in new namespace
    const parent = supervisor.guest_procs.lookup.get(init_pid).?;
    const nspids = [_]Proc.NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &nspids);
    _ = try supervisor.guest_procs.registerChild(parent, 200, Procs.CloneFlags.from(linux.CLONE.NEWPID));

    // Child opens /proc/self
    const open_resp = openat_handler(
        makeOpenatNotif(200, "/proc/self", 0, 0),
        &supervisor,
    );
    try testing.expect(!isError(open_resp));
    const vfd: i32 = @intCast(open_resp.val);

    // Read should show NsPid 1 (child's view)
    var buf: [64]u8 = undefined;
    const read_resp = read_handler(
        makeReadNotif(200, vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expect(!isError(read_resp));
    try testing.expectEqualStrings("1\n", buf[0..@intCast(read_resp.val)]);

    _ = close_handler(makeCloseNotif(200, vfd), &supervisor);
}

// ============================================================================
// E2E-12: openat with traversal through /tmp to /sys -> blocked EPERM
// ============================================================================

test "openat /tmp/../sys/class/net normalizes to blocked EPERM" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const resp = openat_handler(
        makeOpenatNotif(init_pid, "/tmp/../sys/class/net", 0, 0),
        &supervisor,
    );
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.PERM))), resp.@"error");
}

// ============================================================================
// E2E-15: Unknown VFD returns EBADF across read, write, readv, writev, close
// ============================================================================

test "unknown VFD returns EBADF across all handlers" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const bad_vfd: i32 = 99;
    var buf: [64]u8 = undefined;
    const ebadf = -@as(i32, @intCast(@intFromEnum(linux.E.BADF)));

    // read
    const read_resp = read_handler(
        makeReadNotif(init_pid, bad_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqual(ebadf, read_resp.@"error");

    // write
    var wdata = "test".*;
    const write_resp = write_handler(
        makeWriteNotif(init_pid, bad_vfd, &wdata, wdata.len),
        &supervisor,
    );
    try testing.expectEqual(ebadf, write_resp.@"error");

    // close
    const close_resp = close_handler(
        makeCloseNotif(init_pid, bad_vfd),
        &supervisor,
    );
    try testing.expectEqual(ebadf, close_resp.@"error");

    // readv
    var iovecs_r = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };
    const readv_resp = readv_handler(
        makeNotif(.readv, .{
            .pid = init_pid,
            .arg0 = @as(u64, @bitCast(@as(i64, bad_vfd))),
            .arg1 = @intFromPtr(&iovecs_r),
            .arg2 = 1,
        }),
        &supervisor,
    );
    try testing.expectEqual(ebadf, readv_resp.@"error");

    // writev
    const wv_data = "test";
    var iovecs_w = [_]posix.iovec_const{
        .{ .base = wv_data.ptr, .len = wv_data.len },
    };
    const writev_resp = writev_handler(
        makeNotif(.writev, .{
            .pid = init_pid,
            .arg0 = @as(u64, @bitCast(@as(i64, bad_vfd))),
            .arg1 = @intFromPtr(&iovecs_w),
            .arg2 = 1,
        }),
        &supervisor,
    );
    try testing.expectEqual(ebadf, writev_resp.@"error");
}

// ============================================================================
// E2E-16: Unknown PID returns ESRCH across all handlers
// ============================================================================

test "unknown PID returns ESRCH across all handlers" {
    const allocator = testing.allocator;
    const init_pid: Proc.AbsPid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    const bad_pid: Proc.AbsPid = 999;
    const esrch = -@as(i32, @intCast(@intFromEnum(linux.E.SRCH)));
    var buf: [64]u8 = undefined;

    // openat
    const openat_resp = openat_handler(
        makeOpenatNotif(bad_pid, "/dev/null", 0, 0),
        &supervisor,
    );
    try testing.expectEqual(esrch, openat_resp.@"error");

    // read (non-stdin fd)
    const read_resp = read_handler(
        makeReadNotif(bad_pid, 3, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqual(esrch, read_resp.@"error");

    // write (non-stdout/stderr fd)
    var wdata = "test".*;
    const write_resp = write_handler(
        makeWriteNotif(bad_pid, 3, &wdata, wdata.len),
        &supervisor,
    );
    try testing.expectEqual(esrch, write_resp.@"error");

    // close (non-stdio fd)
    const close_resp = close_handler(
        makeCloseNotif(bad_pid, 3),
        &supervisor,
    );
    try testing.expectEqual(esrch, close_resp.@"error");
}
