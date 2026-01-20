const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Logger = types.Logger;
const Supervisor = @import("../../Supervisor.zig");

// All supported syscalls
const Read = @import("handlers/Read.zig");
const Write = @import("handlers/Write.zig");
const Readv = @import("handlers/Readv.zig");
const Writev = @import("handlers/Writev.zig");
const OpenAt = @import("handlers/OpenAt.zig");
const Clone = @import("handlers/Clone.zig");
const GetPid = @import("handlers/GetPid.zig");
const GetTid = @import("handlers/GetTid.zig");
const GetPPid = @import("handlers/GetPPid.zig");
const Kill = @import("handlers/Kill.zig");
const ExitGroup = @import("handlers/ExitGroup.zig");

/// Union of all virtualized syscalls.
pub const Syscall = union(enum) {
    _blocked: Blocked, // TODO: implement at bpf layer
    _to_implement: ToImplement,
    read: Read,
    write: Write,
    readv: Readv,
    writev: Writev,
    openat: OpenAt,
    clone: Clone,
    getpid: GetPid,
    gettid: GetTid,
    getppid: GetPPid,
    kill: Kill,
    exit_group: ExitGroup,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall should passthrough // todo: implement at bpf layer
    pub fn parse(notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            // Always blocked
            // Sandbox escape
            .ptrace,
            .mount,
            .umount2,
            .chroot,
            .pivot_root,
            .reboot,
            // Namespace/isolation bypass
            .setns,
            .unshare,
            .seccomp,
            => return .{ ._blocked = Blocked.parse(notif) },

            // Essential syscalls pass through to kernel
            // Must be safe and not leak state between procs
            // User identity
            .getuid,
            .geteuid,
            .getgid,
            .getegid,
            // Memory management
            .brk,
            .mmap, // note: mmap with MAP_SHARED on files could enable IPC if two sandboxes access the same file. Safe for now since openat is virtualized and controls file access.
            .mprotect,
            .munmap,
            .mremap,
            .madvise,
            // Signals
            .rt_sigaction,
            .rt_sigprocmask,
            .rt_sigreturn,
            .sigaltstack,
            // Time
            .clock_gettime,
            .clock_getres,
            .gettimeofday,
            .nanosleep,
            // Runtime
            .futex,
            .set_robust_list,
            .rseq,
            .prlimit64,
            .getrlimit,
            .getrandom,
            .uname,
            .sysinfo,
            => return null,

            // Implemented
            // I/O
            .read => return .{ .read = Read.parse(notif) },
            .write => return .{ .write = Write.parse(notif) },
            .readv => return .{ .readv = try Readv.parse(notif) },
            .writev => return .{ .writev = try Writev.parse(notif) },
            // Filesystem
            .openat => return .{ .openat = try OpenAt.parse(notif) },
            // Process management
            .clone => return .{ .clone = try Clone.parse(notif) },
            .getpid => return .{ .getpid = GetPid.parse(notif) },
            .gettid => return .{ .gettid = GetTid.parse(notif) },
            .getppid => return .{ .getppid = GetPPid.parse(notif) },
            .kill => return .{ .kill = Kill.parse(notif) },
            .exit_group => return .{ .exit_group = ExitGroup.parse(notif) },

            // To Implement
            // FD operations (need virtual FD translation)
            .close,
            .dup,
            .dup3,
            .pipe2,
            .lseek,
            .fstat,
            .fstatat64,
            .statx,
            .ioctl,
            .fcntl,
            // Filesystem (need path/FD virtualization)
            .getcwd,
            .chdir,
            .mkdirat,
            .unlinkat,
            .faccessat,
            .getdents64,
            // Process/threads groups/session
            .set_tid_address,
            .tkill,
            .tgkill,
            .getpgid,
            .setpgid,
            .getsid,
            .setsid,
            // Process lifecycle
            .wait4,
            .waitid,
            .execve,
            // Security-sensitive
            .prctl,
            => return .{ ._to_implement = ToImplement.parse(notif) },

            else => return .{ ._blocked = Blocked.parse(notif) },
        }
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
        return switch (self) {
            // Inline else forces all enum variants to have .handle(supervisor) signatures
            inline else => |inner| inner.handle(supervisor),
        };
    }

    pub const Result = union(enum) {
        use_kernel: void,
        reply: Reply,

        pub const Reply = struct {
            val: i64,
            errno: i32,
        };

        pub fn replySuccess(val: i64) @This() {
            return .{ .reply = .{ .val = val, .errno = 0 } };
        }

        pub fn replyErr(errno: linux.E) @This() {
            return .{ .reply = .{ .val = 0, .errno = @intFromEnum(errno) } };
        }

        pub fn isError(self: @This()) bool {
            return switch (self) {
                .use_kernel => false,
                .reply => |reply| reply.errno != 0,
            };
        }
    };
};

const Blocked = struct {
    const Self = @This();
    sys_nr: i32,
    pid: linux.pid_t,

    pub fn parse(notif: linux.SECCOMP.notif) Self {
        return .{ .sys_nr = notif.data.nr, .pid = @intCast(notif.pid) };
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Syscall.Result {
        supervisor.logger.log("Blocked syscall: {d} from pid {d}", .{ self.sys_nr, self.pid });
        return Syscall.Result.replyErr(.NOSYS);
    }
};

const ToImplement = struct {
    const Self = @This();
    sys_nr: i32,
    pid: linux.pid_t,

    pub fn parse(notif: linux.SECCOMP.notif) Self {
        return .{ .sys_nr = notif.data.nr, .pid = @intCast(notif.pid) };
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Syscall.Result {
        supervisor.logger.log("ToImplement syscall: {d} from pid {d}", .{ self.sys_nr, self.pid });
        return Syscall.Result.replyErr(.NOSYS);
    }
};
