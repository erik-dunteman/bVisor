const std = @import("std");
const linux = std.os.linux;

/// Read an object of type T from addr (treated as local pointer)
pub inline fn read(T: type, _: linux.pid_t, addr: u64) !T {
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

/// Read bytes from addr into buf (local memcpy)
pub inline fn readSlice(buf: []u8, _: linux.pid_t, addr: u64) !void {
    const src: [*]const u8 = @ptrFromInt(addr);
    @memcpy(buf, src[0..buf.len]);
}

/// Read a null-terminated string from addr into buf
/// Returns the slice up to (but not including) the null terminator
/// Returns error if no null terminator is found
pub inline fn readString(buf: []u8, _pid: linux.pid_t, addr: u64) ![]const u8 {
    try readSlice(buf, _pid, addr);
    const len = std.mem.indexOfScalar(u8, buf, 0) orelse return error.InsufficientBufferLength;
    return buf[0..len];
}

/// Write val to addr (treated as local pointer)
pub inline fn write(T: type, _: linux.pid_t, val: T, addr: u64) !void {
    const ptr: *T = @ptrFromInt(addr);
    ptr.* = val;
}

/// Write bytes from src to addr (local memcpy)
pub inline fn writeSlice(src: []const u8, _: linux.pid_t, addr: u64) !void {
    const dest: [*]u8 = @ptrFromInt(addr);
    @memcpy(dest[0..src.len], src);
}

/// Write a null-terminated string from src to addr
pub inline fn writeString(src: []const u8, pid: linux.pid_t, addr: u64) !void {
    try writeSlice(src, pid, addr);
    try write(u8, pid, 0, addr + src.len);
}
