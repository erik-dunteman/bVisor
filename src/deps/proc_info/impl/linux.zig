const std = @import("std");
const linux = std.os.linux;

const types = @import("../../../types.zig");
const LinuxResult = types.LinuxResult;
const KernelFD = types.KernelFD;

pub const KernelPID = @import("../../../virtual/proc/Proc.zig").KernelPID;
pub const CloneFlags = @import("../../../virtual/proc/Procs.zig").CloneFlags;

// kcmp types from linux/kcmp.h
const KCMP_FILES: u5 = 2;

/// Read parent PID from /proc/[pid]/status
pub fn read_ppid(pid: KernelPID) !KernelPID {
    var path_buf: [32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{pid}) catch unreachable;

    const fd = try LinuxResult(KernelFD).from(
        linux.open(@ptrCast(path.ptr), .{ .ACCMODE = .RDONLY }, 0),
    ).unwrap();
    defer _ = linux.close(fd);

    var buf: [1024]u8 = undefined;
    const n = try LinuxResult(usize).from(
        linux.read(fd, &buf, buf.len),
    ).unwrap();

    // Parse "PPid:\t<pid>" line
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PPid:")) {
            const ppid_str = std.mem.trim(u8, line[5..], " \t");
            return std.fmt.parseInt(KernelPID, ppid_str, 10) catch return error.CannotReadProc;
        }
    }

    return error.CannotReadProc;
}

/// Detect clone flags by querying kernel state
pub fn detect_clone_flags(parent_pid: KernelPID, child_pid: KernelPID) CloneFlags {
    var flags: u64 = 0;

    // Check CLONE_NEWPID via namespace inode comparison
    if (!same_pid_namespace(parent_pid, child_pid)) {
        flags |= linux.CLONE.NEWPID;
    }

    // Check CLONE_FILES via kcmp syscall
    if (shares_fd_table(parent_pid, child_pid)) {
        flags |= linux.CLONE.FILES;
    }

    return CloneFlags.from(flags);
}

/// Check if two processes share the same PID namespace
fn same_pid_namespace(pid1: KernelPID, pid2: KernelPID) bool {
    const ino1 = get_ns_inode(pid1, "pid") orelse return true;
    const ino2 = get_ns_inode(pid2, "pid") orelse return true;
    return ino1 == ino2;
}

/// Get namespace inode for a process
fn get_ns_inode(pid: KernelPID, ns_type: []const u8) ?u64 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{ pid, ns_type }) catch return null;

    var stat_buf: linux.Statx = undefined;
    LinuxResult(void).from(linux.statx(
        linux.AT.FDCWD,
        @ptrCast(path.ptr),
        0,
        @bitCast(linux.STATX{ .INO = true }),
        &stat_buf,
    )).unwrap() catch return null;

    return stat_buf.ino;
}

/// Check if two processes share the same fd table using kcmp
fn shares_fd_table(pid1: KernelPID, pid2: KernelPID) bool {
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
