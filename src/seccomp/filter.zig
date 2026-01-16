const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;

const BPFInstruction = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const BPFFilterProgram = extern struct {
    len: u16,
    filter: [*]const BPFInstruction,
};

/// Predict the next available FD (used for pre-sending notify FD to supervisor).
/// Caller must ensure no FDs are opened between this call and install().
pub fn predict_notify_fd() !KernelFD {
    // dup(0) returns the lowest available fd
    const next_fd: KernelFD = try posix.dup(0);
    posix.close(next_fd);
    return next_fd;
}

/// Install seccomp filter that intercepts all syscalls via USER_NOTIF.
/// Returns the notify FD that the supervisor should listen on.
/// Requires NO_NEW_PRIVS to be set first.
pub fn install() !KernelFD {
    // BPF program that triggers USER_NOTIF for all syscalls
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    // Set NO_NEW_PRIVS mode
    // Required before installing seccomp filter
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });

    return try Result(KernelFD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();
}

/// Get notify FD from child process (supervisor side).
/// Polls child's FD table until the FD becomes visible.
pub fn get_notify_fd_from_child(child_pid: linux.pid_t, child_notify_fd: KernelFD, io: std.Io) !KernelFD {
    const child_fd_table: KernelFD = try Result(KernelFD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, child_notify_fd, 0);
        switch (Result(KernelFD).from(result)) {
            .Ok => |value| return value,
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
                    continue;
                },
                else => return posix.unexpectedErrno(err),
            },
        }
    }
    return error.NotifyFdTimeout;
}
