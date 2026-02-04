const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Supervisor = @import("../../Supervisor.zig");
const replyErr = @import("../../seccomp/notif.zig").replyErr;
const replyContinue = @import("../../seccomp/notif.zig").replyContinue;

const read = @import("handlers/read.zig");
const write = @import("handlers/write.zig");
const readv = @import("handlers/readv.zig");
const writev = @import("handlers/writev.zig");
const openat = @import("handlers/openat.zig");
const close = @import("handlers/close.zig");
const getpid = @import("handlers/getpid.zig");
const getppid = @import("handlers/getppid.zig");
const gettid = @import("handlers/gettid.zig");
const kill = @import("handlers/kill.zig");
const tkill = @import("handlers/tkill.zig");
const exit_ = @import("handlers/exit.zig");
const exit_group = @import("handlers/exit_group.zig");

pub inline fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const sys: linux.SYS = @enumFromInt(notif.data.nr);
    std.debug.print("\n", .{});
    supervisor.logger.log("Handling syscall: {s}", .{@tagName(sys)});
    return switch (sys) {
        // Implemented - files
        .openat => openat.handle(notif, supervisor),
        .close => close.handle(notif, supervisor),
        .read => read.handle(notif, supervisor),
        .write => write.handle(notif, supervisor),
        .readv => readv.handle(notif, supervisor),
        .writev => writev.handle(notif, supervisor),
        // Implemented - process
        .getpid => getpid.handle(notif, supervisor),
        .getppid => getppid.handle(notif, supervisor),
        .gettid => gettid.handle(notif, supervisor),
        .kill => kill.handle(notif, supervisor),
        .tkill => tkill.handle(notif, supervisor),
        .exit => exit_.handle(notif, supervisor),
        .exit_group => exit_group.handle(notif, supervisor),

        // Passthrough - create child process (kernel only, we lazily discover child later)
        .clone => replyContinue(notif.id),
        // Passthrough - wait for child (kernel handles blocking, exit_group handles proc cleanup)
        .wait4 => replyContinue(notif.id),

        // To implement - files
        .fstat,
        .fstatat64,
        .fcntl,
        .ioctl,
        .dup,
        .dup3,
        .pipe2,
        .lseek,
        .getcwd,
        .chdir,
        .fchdir,
        .getdents64,
        .faccessat,
        // To implement - process
        .set_tid_address,
        .execve,
        // To implement - should virtualize (info leak in multitenant)
        .uname, // leaks kernel version, hostname
        .sysinfo, // leaks total RAM, uptime, load
        .getrlimit, // leaks resource config
        .getrusage, // leaks resource usage
        => {
            supervisor.logger.log("Not implemented: {s}", .{@tagName(sys)});
            return replyErr(notif.id, .NOSYS);
        },

        // Passthrough - user identity (read-only)
        .getuid,
        .geteuid,
        .getgid,
        .getegid,
        // Passthrough - memory (process-local, no leak)
        .brk,
        .mmap,
        .mprotect,
        .munmap,
        .mremap,
        .madvise,
        // Passthrough - signals (process-local)
        .rt_sigaction,
        .rt_sigprocmask,
        .rt_sigreturn,
        .rt_sigsuspend,
        .rt_sigpending,
        .rt_sigtimedwait,
        .sigaltstack,
        .restart_syscall,
        // Passthrough - time (read-only)
        .clock_gettime,
        .clock_getres,
        .gettimeofday,
        .nanosleep,
        .clock_nanosleep,
        // Passthrough - futex (process-local sync)
        .futex,
        .futex_wait,
        .futex_wake,
        .futex_requeue,
        .futex_waitv,
        // Passthrough - random (safe)
        .getrandom,
        // Passthrough - runtime (process-local)
        .set_robust_list,
        .rseq,
        => replyContinue(notif.id),

        // Blocked - escape/privilege (return ENOSYS to indicate unavailable)
        .ptrace,
        .mount,
        .umount2,
        .chroot,
        .pivot_root,
        .reboot,
        .setns,
        .unshare,
        .seccomp,
        .bpf,
        .process_vm_readv,
        .process_vm_writev,
        .kexec_load,
        .kexec_file_load,
        .init_module,
        .finit_module,
        .delete_module,
        // Blocked - resource control (prevent guest from raising limits)
        .setrlimit,
        .prlimit64,
        // Blocked - execution domain exploits
        .personality,
        => replyErr(notif.id, .NOSYS),

        else => {
            supervisor.logger.log("Not supported: {s}", .{@tagName(sys)});
            return replyErr(notif.id, .NOSYS);
        },
    };
}
