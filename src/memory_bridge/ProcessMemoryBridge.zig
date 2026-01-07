const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const LinuxResult = @import("../types.zig").LinuxResult;

const Self = @This();

child_pid: linux.pid_t,

pub fn init(child_pid: linux.pid_t) Self {
    return .{ .child_pid = child_pid };
}

/// Read an object of type T from child_addr in child's address space
/// This creates a copy in the local process
/// Remember any nested pointers returned are still in child's address space
pub fn read(self: Self, T: type, child_addr: u64) !T {
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
            self.child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
    return local_T;
}

/// Read bytes from child's address space into a local buffer
pub fn readSlice(self: Self, dest: []u8, child_addr: u64) !void {
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
            self.child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write an object of type T into child's address space at child_addr
/// Misuse could seriously corrupt child process
pub fn write(self: Self, T: type, val: T, child_addr: u64) !void {
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
            self.child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write bytes from local buffer into child's address space
pub fn writeSlice(self: Self, src: []const u8, child_addr: u64) !void {
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
            self.child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}
