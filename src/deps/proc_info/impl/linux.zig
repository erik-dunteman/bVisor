const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const types = @import("../../../types.zig");
const LinuxResult = types.LinuxResult;

const Thread = @import("../../../virtual/proc/Thread.zig");
// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const Threads = @import("../../../virtual/proc/Threads.zig");
pub const CloneFlags = Threads.CloneFlags;
const ThreadReadResult = @import("../../../virtual/proc/ThreadReadResult.zig");
const ThreadStatus = @import("../../../virtual/proc/ThreadStatus.zig");
const MAX_NS_DEPTH = ThreadStatus.MAX_NS_DEPTH;

// kcmp types from linux/kcmp.h
const KCMP_FILES: u5 = 2;

/// Resolve a Thread's TGID from its TID by reading /proc/{tid}/status.
/// This works because the kernel maintains /proc/{tid} entries for all tasks.
pub fn getTgidFromTid(tid: AbsTid) !AbsTgid {
    var path_buf: [32:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/status", .{tid}) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &file_buf, file_buf.len),
    ).unwrap();

    var lines = std.mem.splitScalar(u8, file_buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Tgid:")) {
            const tgid_str = std.mem.trim(u8, line[5..], " \t");
            return std.fmt.parseInt(AbsTgid, tgid_str, 10) catch return error.ParseError;
        }
    }

    return error.TgidNotFound;
}

/// Reads NSpid field and returns NsTid-s
/// from /proc/[tgid]/task/[tid]/status.
/// Follows outermost to innermost namespace.
pub fn readNsTids(tgid: AbsTgid, tid: AbsTid, nstid_buf: []NsTid) ![]NsTid {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/task/{d}/status", .{ tgid, tid }) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &file_buf, file_buf.len),
    ).unwrap();

    var nstids: []NsTid = &.{};

    var lines = std.mem.splitScalar(u8, file_buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            nstids = try parseNsField(NsTid, line[6..], nstid_buf);
            break;
        }
    }

    // Validate the field was found
    if (nstids.len == 0) return error.NSpidNotFound;

    return nstids;
}

/// Reads and returns
///     NsTgids (NStgid field), and
///     NsTids  (NSpid field)
/// from /proc/[tgid]/task/[tid]/status.
/// Follows outermost to innermost namespace.
pub fn readNsIds(tgid: AbsTgid, tid: AbsTid, nstgid_buf: []NsTgid, nstid_buf: []NsTid) !ThreadReadResult {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/task/{d}/status", .{ tgid, tid }) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &file_buf, file_buf.len),
    ).unwrap();

    var result: ThreadReadResult = .{
        .nstgids = &.{},
        .nstids = &.{},
    };

    var lines = std.mem.splitScalar(u8, file_buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NStgid:")) {
            result.nstgids = try parseNsField(NsTgid, line[7..], nstgid_buf);
        } else if (std.mem.startsWith(u8, line, "NSpid:")) {
            result.nstids = try parseNsField(NsTid, line[6..], nstid_buf);
        }

        // Early exit once found both fields: NStgid & NSpid
        if (result.nstgids.len > 0 and result.nstids.len > 0) break;
    }

    // Validate both fields found
    if (result.nstgids.len == 0) return error.NStgidNotFound;
    if (result.nstids.len == 0) return error.NSpidNotFound;

    return result;
}

/// Parser for namespace ID fields
fn parseNsField(comptime IdType: type, field_data: []const u8, buf: []IdType) ![]IdType {
    const ids_str = std.mem.trim(u8, field_data, " \t");
    var count: usize = 0;
    var iter = std.mem.tokenizeAny(u8, ids_str, " \t");
    while (iter.next()) |id_str| {
        if (count >= buf.len) return error.BufferTooSmall;
        buf[count] = std.fmt.parseInt(IdType, id_str, 10) catch return error.ParseError;
        count += 1;
    }
    if (count == 0) return error.FieldEmpty;
    return buf[0..count];
}

/// Get the status of a given Thread using only its TID.
/// Reads from /proc/{tid}/status (kernel maintains this for all tasks).
/// The TGID is parsed from the file's Tgid: field.
pub fn getStatus(tid: AbsTid) !ThreadStatus {
    var path_buf: [32:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/status", .{tid}) catch unreachable;

    const fd = try LinuxResult(linux.fd_t).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &buf, buf.len),
    ).unwrap();

    var status = ThreadStatus{
        .tid = tid,
        .tgid = undefined,
        .ptid = undefined,
    };

    var tgid_found: ?AbsTgid = null;
    var ptid_found: ?AbsTid = null;
    var nstgid_found = false;
    var nstid_found = false;

    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        // Parse "Tgid:\t<tgid>" line
        if (std.mem.startsWith(u8, line, "Tgid:")) {
            const tgid_str = std.mem.trim(u8, line[5..], " \t");
            tgid_found = std.fmt.parseInt(AbsTgid, tgid_str, 10) catch return error.ParseError;
        }
        // Parse "PPid:\t<pid>" line
        else if (std.mem.startsWith(u8, line, "PPid:")) {
            const ptid_str = std.mem.trim(u8, line[5..], " \t");
            ptid_found = std.fmt.parseInt(AbsTid, ptid_str, 10) catch return error.ParseError;
        }
        // Parse "NStgid:\t<tgid>[\t<tgid>...]" line
        else if (std.mem.startsWith(u8, line, "NStgid:")) {
            const tgids_str = std.mem.trim(u8, line[7..], " \t");
            var iter = std.mem.tokenizeAny(u8, tgids_str, " \t");

            while (iter.next()) |tgid_str| {
                if (status.nstgids_len >= MAX_NS_DEPTH) return error.BufferTooSmall;
                status.nstgids_buf[status.nstgids_len] = std.fmt.parseInt(NsTgid, tgid_str, 10) catch return error.ParseError;
                status.nstgids_len += 1;
            }
            nstgid_found = true;
        }
        // Parse "NSpid:\t<tid>[\t<tid>...]" line
        else if (std.mem.startsWith(u8, line, "NSpid:")) {
            const tids_str = std.mem.trim(u8, line[6..], " \t");
            var iter = std.mem.tokenizeAny(u8, tids_str, " \t");

            while (iter.next()) |tid_str| {
                if (status.nstids_len >= MAX_NS_DEPTH) return error.BufferTooSmall;
                status.nstids_buf[status.nstids_len] = std.fmt.parseInt(NsTid, tid_str, 10) catch return error.ParseError;
                status.nstids_len += 1;
            }
            nstid_found = true;
        }

        // Early exit once found all fields
        if (tgid_found != null and ptid_found != null and nstgid_found and nstid_found) break;
    }

    status.tgid = tgid_found orelse return error.TgidNotFound;
    status.ptid = ptid_found orelse return error.PtidNotFound;
    if (status.nstgids_len == 0) return error.NStgidNotFound;
    if (status.nstids_len == 0) return error.NSpidNotFound;

    return status;
}

/// Detect clone flags by querying kernel state
pub fn detectCloneFlags(parent_tid: AbsTid, child_tid: AbsTid) CloneFlags {
    var flags: u64 = 0;

    // Check CLONE_NEWPID via Namespace inode comparison
    if (!sameTidNamespace(parent_tid, child_tid)) {
        flags |= linux.CLONE.NEWPID;
    }

    // Check CLONE_FILES via kcmp syscall
    if (sharesFdTable(parent_tid, child_tid)) {
        flags |= linux.CLONE.FILES;
    }

    return CloneFlags.from(flags);
}

/// List all Tgids from /proc directory
pub fn listTgids(allocator: Allocator) ![]AbsTgid {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var tgids: std.ArrayListUnmanaged(AbsTgid) = .empty;
    errdefer tgids.deinit(allocator);

    var dir_iter = proc_dir.iterate();
    while (try dir_iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const tgid = std.fmt.parseInt(AbsTgid, entry.name, 10) catch continue;
        try tgids.append(allocator, tgid);
    }

    return tgids.toOwnedSlice(allocator);
}

/// List all Tids within directories of the form /proc/[tgid]/task/[tid]
pub fn listTids(allocator: Allocator) ![]AbsTid {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var tids: std.ArrayListUnmanaged(AbsTid) = .empty;
    errdefer tids.deinit(allocator);

    // Iterate through all /proc/[tgid] (process directories)
    var proc_iter = proc_dir.iterate();
    while (try proc_iter.next(io)) |proc_entry| {
        if (proc_entry.kind != .directory) continue;
        const tgid = std.fmt.parseInt(AbsTgid, proc_entry.name, 10) catch continue;

        // Now open /proc/[tgid]/task to find all threads
        var task_path_buf: [64]u8 = undefined;
        const task_path = std.fmt.bufPrint(&task_path_buf, "/proc/{d}/task", .{tgid}) catch continue;

        var task_dir = std.Io.Dir.openDirAbsolute(io, task_path, .{ .iterate = true }) catch continue;
        defer task_dir.close(io);

        var task_iter = task_dir.iterate();
        while (try task_iter.next(io)) |task_entry| {
            if (task_entry.kind != .directory) continue;
            const tid = std.fmt.parseInt(AbsTid, task_entry.name, 10) catch continue;
            try tids.append(allocator, tid);
        }
    }

    return tids.toOwnedSlice(allocator);
}

/// Check whether two threads share the same PID namespace (according to the kernel).
/// Uses /proc/{tid}/ns/pid which the kernel maintains for all tasks.
fn sameTidNamespace(tid1: AbsTid, tid2: AbsTid) bool {
    const ino1 = getNsInode(tid1, "pid") orelse return true;
    const ino2 = getNsInode(tid2, "pid") orelse return true;
    return ino1 == ino2;
}

/// Get namespace inode for a Thread by reading /proc/{tid}/ns/{ns_type}.
/// The kernel maintains /proc/{tid} entries for all tasks (threads), so we can
/// access namespace info directly without needing the TGID.
fn getNsInode(tid: AbsTid, ns_type: []const u8) ?u64 {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/ns/{s}", .{ tid, ns_type }) catch return null;

    var stat_buf: linux.Statx = undefined;
    LinuxResult(void).from(linux.statx(
        linux.AT.FDCWD,
        path.ptr,
        0,
        @bitCast(linux.STATX{ .INO = true }),
        &stat_buf,
    )).unwrap() catch return null;

    return stat_buf.ino;
}

/// Check whether two Threads share the same FD table (according to the kernel) using kcmp.
/// The kcmp syscall takes PIDs which in kernel terminology are TIDs.
fn sharesFdTable(tid1: AbsTid, tid2: AbsTid) bool {
    // kcmp returns: 0 = equal, positive = different, negative = error
    // Only 0 means they share the same FD table
    const result = linux.syscall5(
        .kcmp,
        @intCast(tid1),
        @intCast(tid2),
        KCMP_FILES,
        0,
        0,
    );
    return result == 0;
}
