const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Result = types.LinuxResult;

pub inline fn lookupGuestFd(_: linux.pid_t, local_fd: linux.fd_t) !linux.fd_t {
    return local_fd;
}

pub inline fn lookupGuestFdWithRetry(_: linux.pid_t, local_fd: linux.fd_t, _: std.Io) !linux.fd_t {
    return local_fd;
}
