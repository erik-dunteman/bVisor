const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;

pub inline fn lookup_child_fd(_: linux.pid_t, local_fd: KernelFD) !KernelFD {
    return local_fd;
}

pub inline fn lookup_child_fd_with_retry(_: linux.pid_t, local_fd: KernelFD, _: std.Io) !KernelFD {
    return local_fd;
}
