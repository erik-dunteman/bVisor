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
pub fn predictNotifyFd() !KernelFD {
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
    // In the future we can make this more restrictive

    // ERIK TODO: need a better, unified way of replying to syscalls. We have too many abstractions
    // Also hard blocks should come from here. Maybe comptime build this based on syscall coverage, that'd be sick
    // Have syscall enums somewhere, get a get_blocked and get_passthrough comptime function so we don't have to litter
    // The syscall enum with BPF concerns, still doing it here.
    // Only fully virtualized syscalls and conditionally virtualized syscalls should make it to supervisor
    // One big ol' syscalls enum with every syscall, of a variant.
    // Then a handled_syscalls or otherwise named thing containing implementations. It shouldn't be too complicated.
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
