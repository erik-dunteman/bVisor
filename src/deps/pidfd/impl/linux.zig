const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Result = types.LinuxResult;

pub inline fn lookupGuestFd(child_pid: linux.pid_t, local_fd: linux.fd_t) !linux.fd_t {
    const child_fd_table: linux.fd_t = try Result(linux.fd_t).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    return Result(linux.fd_t).from(
        linux.pidfd_getfd(child_fd_table, local_fd, 0),
    ).unwrap();
}

pub inline fn lookupGuestFdWithRetry(child_pid: linux.pid_t, local_fd: linux.fd_t, io: std.Io) !linux.fd_t {
    const child_fd_table: linux.fd_t = try Result(linux.fd_t).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, local_fd, 0);
        switch (Result(linux.fd_t).from(result)) {
            .Ok => |value| return value,
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    // ERIK TODO: why 1ms? why not exponential backoff? polling also seems gross
                    try io.sleep(std.Io.Duration.fromMilliseconds(1), .awake);
                    continue;
                },
                else => return posix.unexpectedErrno(err),
            },
        }
    }
    return error.NotifyFdTimeout;
}
