const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;

pub inline fn lookup_child_fd(child_pid: linux.pid_t, local_fd: KernelFD) !KernelFD {
    const child_fd_table: KernelFD = try Result(KernelFD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    return Result(KernelFD).from(
        linux.pidfd_getfd(child_fd_table, local_fd, 0),
    ).unwrap();
}

pub inline fn lookup_child_fd_with_retry(child_pid: linux.pid_t, local_fd: KernelFD, io: std.Io) !KernelFD {
    const child_fd_table: KernelFD = try Result(KernelFD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, local_fd, 0);
        switch (Result(KernelFD).from(result)) {
            .Ok => |value| return value,
            .Error => |err| switch (err) {
                .BADF => {
                    // KernelFD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(1), .awake);
                    continue;
                },
                else => return posix.unexpectedErrno(err),
            },
        }
    }
    return error.NotifyFdTimeout;
}
