const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Logger = types.Logger;
const Supervisor = @import("../../Supervisor.zig");
const replyErr = @import("../../seccomp/notif.zig").replyErr;
const replyContinue = @import("../../seccomp/notif.zig").replyContinue;

// All handled syscalls
const read = @import("handlers/read.zig");
const write = @import("handlers/write.zig");
const readv = @import("handlers/readv.zig");
const writev = @import("handlers/writev.zig");
const openat = @import("handlers/openat.zig");
const getpid = @import("handlers/getpid.zig");
const getppid = @import("handlers/getppid.zig");
const kill = @import("handlers/kill.zig");
const exit_group = @import("handlers/exit_group.zig");

// HandlerFn is the function signature all syscall handlers must adhere to
const HandlerFn = *const fn (notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif.resp;
const Route = union(enum) {
    // comptime routes, used by BPF filter builder
    block: void, // always block at the BPF level with this code
    continue_kernel: void, // reply continue, let kernel handle

    // runtime routes for handling seccomp notifications
    handle: HandlerFn,
    to_implement: void, // returns error for now. syscalls we know we want to eventually handle.
    undecided: void, // returns error for now. syscalls we haven't decided on.
};

fn route(sys: linux.SYS) Route {
    return switch (sys) {
        // exhaustive switch on underlying enum
        // all cases
        // TODO erik
        .clone => .continue_kernel, // only kernel can handle clone. Newly spawned processes are lazily-discovered when referenced.
        .exit_group => .{ .handle = exit_group.handle },
        .getpid => .{ .handle = getpid.handle },
        .getppid => .{ .handle = getppid.handle },
        .kill => .{ .handle = kill.handle },
        .openat => .{ .handle = openat.handle },
        .read => .{ .handle = read.handle },
        .readv => .{ .handle = readv.handle },
        .write => .{ .handle = write.handle },
        .writev => .{ .handle = writev.handle },

        else => .undecided,
    };
}

pub inline fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif.resp {
    std.debug.print("PID: {d}\tSYSCALL: {s}\n", .{ notif.pid, @tagName(@intFromEnum(notif.data.nr)) });
    return switch (route(notif.data.nr)) {
        // In the future, blocked and passthrough are more efficiently handled in the BPF layer
        // but for now we explicitly handle, to help debug
        .block => replyErr(.PERM),
        .cont => replyContinue(),
        .handle => |handler| handler(notif, supervisor),
        .to_implement => {
            std.debug.print("ToImplement");
            return replyErr(.NOSYS);
        },
        .undecided => {
            std.debug.print("Undecided");
            return replyErr(.NOSYS);
        },
    };
}
// /// Union of all virtualized syscalls.
// pub const Syscall = union(enum) {
//     _blocked: Blocked, // TODO: implement at bpf layer
//     _to_implement: ToImplement,
//     read: Read,
//     write: Write,
//     readv: Readv,
//     writev: Writev,
//     openat: OpenAt,
//     clone: Clone,
//     getpid: GetPid,
//     gettid: GetTid,
//     getppid: GetPPid,
//     kill: Kill,
//     exit_group: ExitGroup,

//     const Self = @This();

//     /// Parse seccomp notif into Syscall
//     /// Null return means the syscall should passthrough // todo: implement at bpf layer
//     pub fn parse(notif: linux.SECCOMP.notif) !?Self {
//         const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
//         // ERIK TODO
//         // using linux.SYS as the tag on this Syscall enum should make things much simpler
//         switch (sys_code) {
//             // Always blocked
//             // Sandbox escape
//             .ptrace,
//             .mount,
//             .umount2,
//             .chroot,
//             .pivot_root,
//             .reboot,
//             // Namespace/isolation bypass
//             .setns,
//             .unshare,
//             .seccomp,
//             => return .{ ._blocked = Blocked.parse(notif) },

//             // Essential syscalls pass through to kernel
//             // Must be safe and not leak state between procs
//             // User identity
//             .getuid,
//             .geteuid,
//             .getgid,
//             .getegid,
//             // Memory management
//             .brk,
//             .mmap, // note: mmap with MAP_SHARED on files could enable IPC if two sandboxes access the same file. Safe for now since openat is virtualized and controls file access.
//             .mprotect,
//             .munmap,
//             .mremap,
//             .madvise,
//             // Signals
//             .rt_sigaction,
//             .rt_sigprocmask,
//             .rt_sigreturn,
//             .sigaltstack,
//             // Time
//             .clock_gettime,
//             .clock_getres,
//             .gettimeofday,
//             .nanosleep,
//             // Runtime
//             .futex,
//             .set_robust_list,
//             .rseq,
//             .prlimit64,
//             .getrlimit,
//             .getrandom,
//             .uname,
//             .sysinfo,
//             => return null,

//             // Implemented
//             // I/O
//             .read => return .{ .read = Read.parse(notif) },
//             .write => return .{ .write = Write.parse(notif) },
//             .readv => return .{ .readv = try Readv.parse(notif) },
//             .writev => return .{ .writev = try Writev.parse(notif) },
//             // Filesystem
//             .openat => return .{ .openat = try OpenAt.parse(notif) },
//             // Process management
//             .clone => return .{ .clone = try Clone.parse(notif) },
//             .getpid => return .{ .getpid = GetPid.parse(notif) },
//             .gettid => return .{ .gettid = GetTid.parse(notif) },
//             .getppid => return .{ .getppid = GetPPid.parse(notif) },
//             .kill => return .{ .kill = Kill.parse(notif) },
//             .exit_group => return .{ .exit_group = ExitGroup.parse(notif) },

//             // To Implement
//             // FD operations (need virtual FD translation)
//             .close,
//             .dup,
//             .dup3,
//             .pipe2,
//             .lseek,
//             .fstat,
//             .fstatat64,
//             .statx,
//             .ioctl,
//             .fcntl,
//             // Filesystem (need path/FD virtualization)
//             .getcwd,
//             .chdir,
//             .mkdirat,
//             .unlinkat,
//             .faccessat,
//             .getdents64,
//             // Process/threads groups/session
//             .set_tid_address,
//             .tkill,
//             .tgkill,
//             .getpgid,
//             .setpgid,
//             .getsid,
//             .setsid,
//             // Process lifecycle
//             .wait4,
//             .waitid,
//             .execve,
//             // Security-sensitive
//             .prctl,
//             => return .{ ._to_implement = ToImplement.parse(notif) },

//             else => return .{ ._blocked = Blocked.parse(notif) },
//         }
//     }

//     pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
//         return switch (self) {
//             // Inline else forces all enum variants to have .handle(supervisor) signatures
//             inline else => |inner| inner.handle(supervisor),
//         };
//     }

//     pub const Result = union(enum) {
//         // ERIK TODO: get rid of this, just use response prep tools in seccomp/notif.zig
//         use_kernel: void,
//         reply: Reply,

//         pub const Reply = struct {
//             val: i64,
//             errno: i32,
//         };

//         pub fn replySuccess(val: i64) @This() {
//             return .{ .reply = .{ .val = val, .errno = 0 } };
//         }

//         pub fn replyErr(errno: linux.E) @This() {
//             return .{ .reply = .{ .val = 0, .errno = @intFromEnum(errno) } };
//         }

//         pub fn isError(self: @This()) bool {
//             return switch (self) {
//                 .use_kernel => false,
//                 .reply => |reply| reply.errno != 0,
//             };
//         }
//     };
// };

// const Blocked = struct {
//     const Self = @This();
//     sys_nr: i32,
//     pid: linux.pid_t,

//     pub fn parse(notif: linux.SECCOMP.notif) Self {
//         return .{ .sys_nr = notif.data.nr, .pid = @intCast(notif.pid) };
//     }

//     pub fn handle(self: Self, supervisor: *Supervisor) !Syscall.Result {
//         supervisor.logger.log("Blocked syscall: {d} from pid {d}", .{ self.sys_nr, self.pid });
//         return Syscall.Result.replyErr(.NOSYS);
//     }
// };

// const ToImplement = struct {
//     const Self = @This();
//     sys_nr: i32,
//     pid: linux.pid_t,

//     pub fn parse(notif: linux.SECCOMP.notif) Self {
//         return .{ .sys_nr = notif.data.nr, .pid = @intCast(notif.pid) };
//     }

//     pub fn handle(self: Self, supervisor: *Supervisor) !Syscall.Result {
//         supervisor.logger.log("ToImplement syscall: {d} from pid {d}", .{ self.sys_nr, self.pid });
//         return Syscall.Result.replyErr(.NOSYS);
//     }
// };
