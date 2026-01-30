const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const types = @import("../../../types.zig");
const LinuxResult = types.LinuxResult;
const SupervisorFD = types.SupervisorFD;

const Proc = @import("../../../virtual/proc/Proc.zig");
const Procs = @import("../../../virtual/proc/Procs.zig");
pub const AbsPid = Proc.AbsPid;
pub const NsPid = Proc.NsPid;
const ProcStatus = @import("../../../virtual/proc/ProcStatus.zig");
const MAX_NS_DEPTH = ProcStatus.MAX_NS_DEPTH;
pub const CloneFlags = @import("../../../virtual/proc/Procs.zig").CloneFlags;

// kcmp types from linux/kcmp.h
const KCMP_FILES: u5 = 2;

/// Read NSpid (namespace PID chain) from /proc/[pid]/status.
/// Returns a slice of PIDs from outermost (root) to innermost (process's own namespace).
/// Example: NSpid: 15234  892  7  1 -> [15234, 892, 7, 1]
/// The last element is the PID in the process's own namespace.
pub fn readNsPids(pid: AbsPid, buf: []NsPid) ![]NsPid {
    var path_buf: [32:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/status", .{pid}) catch unreachable;

    const fd = try LinuxResult(SupervisorFD).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &file_buf, file_buf.len),
    ).unwrap();

    // Parse "NSpid:\t<pid>[\t<pid>...]" line
    var lines = std.mem.splitScalar(u8, file_buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            const pids_str = std.mem.trim(u8, line[6..], " \t");
            var count: usize = 0;
            var iter = std.mem.tokenizeAny(u8, pids_str, " \t");
            while (iter.next()) |pid_str| {
                if (count >= buf.len) return error.BufferTooSmall;
                buf[count] = std.fmt.parseInt(NsPid, pid_str, 10) catch return error.ParseError;
                count += 1;
            }
            if (count == 0) return error.NSpidNotFound;
            return buf[0..count];
        }
    }
    return error.NSpidNotFound;
}

/// Report the status of a given process using its kernel PID
pub fn getStatus(pid: AbsPid) !ProcStatus {
    var path_buf: [32:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/status", .{pid}) catch unreachable;

    const fd = try LinuxResult(SupervisorFD).from(
        linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &buf, buf.len),
    ).unwrap();

    var status = ProcStatus{ .pid = pid, .ppid = undefined };

    var ppid_found: ?AbsPid = null;
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        // Parse "PPid:\t<pid>" line
        if (std.mem.startsWith(u8, line, "PPid:")) {
            const ppid_str = std.mem.trim(u8, line[5..], " \t");
            ppid_found = std.fmt.parseInt(AbsPid, ppid_str, 10) catch return error.ParseError;
        }

        // Parse "NSpid:\t<pid>[\t<pid>...]" line
        // Example: NSpid: 15234  892  7  1 -> [15234, 892, 7, 1]
        if (std.mem.startsWith(u8, line, "NSpid:")) {
            const pids_str = std.mem.trim(u8, line[6..], " \t");
            var iter = std.mem.tokenizeAny(u8, pids_str, " \t");

            while (iter.next()) |pid_str| {
                if (status.nspids_len >= MAX_NS_DEPTH) return error.BufferTooSmall;
                status.nspids_buf[status.nspids_len] = std.fmt.parseInt(NsPid, pid_str, 10) catch return error.ParseError;
                status.nspids_len += 1;
            }
        }
    }

    status.ppid = ppid_found orelse return error.PPidNotFound;
    if (status.nspids_len == 0) return error.NSpidNotFound;

    return status;
}

/// Detect clone flags by querying kernel state
pub fn detectCloneFlags(parent_pid: AbsPid, child_pid: AbsPid) CloneFlags {
    var flags: u64 = 0;

    // Check CLONE_NEWPID via namespace inode comparison
    if (!samePidNamespace(parent_pid, child_pid)) {
        flags |= linux.CLONE.NEWPID;
    }

    // Check CLONE_FILES via kcmp syscall
    if (sharesFdTable(parent_pid, child_pid)) {
        flags |= linux.CLONE.FILES;
    }

    return CloneFlags.from(flags);
}

/// List all PIDs from /proc directory
pub fn listPids(allocator: Allocator) ![]AbsPid {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var pids: std.ArrayListUnmanaged(AbsPid) = .empty;
    errdefer pids.deinit(allocator);

    var dir_iter = proc_dir.iterate();
    while (try dir_iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const pid = std.fmt.parseInt(AbsPid, entry.name, 10) catch continue;
        try pids.append(allocator, pid);
    }

    return pids.toOwnedSlice(allocator);
}

/// Check if two processes share the same PID namespace
fn samePidNamespace(pid1: AbsPid, pid2: AbsPid) bool {
    const ino1 = getNsInode(pid1, "pid") orelse return true;
    const ino2 = getNsInode(pid2, "pid") orelse return true;
    return ino1 == ino2;
}

/// Get namespace inode for a process
fn getNsInode(pid: AbsPid, ns_type: []const u8) ?u64 {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/ns/{s}", .{ pid, ns_type }) catch return null;

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

/// Check if two processes share the same fd table using kcmp
fn sharesFdTable(pid1: AbsPid, pid2: AbsPid) bool {
    // kcmp returns: 0 = equal, positive = different, negative = error
    // Only 0 means they share the same fd table
    const result = linux.syscall5(
        .kcmp,
        @intCast(pid1),
        @intCast(pid2),
        KCMP_FILES,
        0,
        0,
    );
    return result == 0;
}
