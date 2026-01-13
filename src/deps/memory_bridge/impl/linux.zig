const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const LinuxResult = types.LinuxResult;
const FD = types.FD;

/// Read an object of type T from child_addr in child's address space
/// This creates a copy in the local process
/// Remember any nested pointers returned are still in child's address space
pub inline fn read(T: type, child_pid: linux.pid_t, child_addr: u64) !T {
    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = @sizeOf(T),
    }};
    var local_T: T = undefined;
    const local_iovec: [1]posix.iovec = .{.{
        .base = @ptrCast(&local_T),
        .len = @sizeOf(T),
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_readv(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
    return local_T;
}

/// Read bytes from child's address space into a local buffer
pub inline fn readSlice(dest: []u8, child_pid: linux.pid_t, child_addr: u64) !void {
    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = dest.len,
    }};

    const local_iovec: [1]posix.iovec = .{.{
        .base = dest.ptr,
        .len = dest.len,
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_readv(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Read a null-terminated string from addr into buf
/// Returns the slice up to (but not including) the null terminator
/// Returns error if no null terminator is found
pub inline fn readString(buf: []u8, child_pid: linux.pid_t, child_addr: u64) ![]const u8 {
    try readSlice(buf, child_pid, child_addr);
    const len = std.mem.indexOfScalar(u8, buf, 0) orelse return error.InsufficientBufferLength;
    return buf[0..len];
}

/// Write an object of type T into child's address space at child_addr
/// Misuse could seriously corrupt child process
pub inline fn write(T: type, child_pid: linux.pid_t, val: T, child_addr: u64) !void {
    const local_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrCast(&val),
        .len = @sizeOf(T),
    }};

    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = @sizeOf(T),
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_writev(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write bytes from local buffer into child's address space
pub inline fn writeSlice(src: []const u8, child_pid: linux.pid_t, child_addr: u64) !void {
    const local_iovec: [1]posix.iovec_const = .{.{
        .base = src.ptr,
        .len = src.len,
    }};

    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = src.len,
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_writev(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write a null-terminated string from src to addr
pub inline fn writeString(src: []const u8, child_pid: linux.pid_t, child_addr: u64) !void {
    try writeSlice(src, child_pid, child_addr);
    try write(u8, child_pid, 0, child_addr + src.len);
}
