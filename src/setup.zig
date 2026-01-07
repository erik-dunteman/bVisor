const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const FD = types.FD;
const Result = types.LinuxResult;
const MemoryBridge = types.MemoryBridge;
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");
const Cgroups = @import("cgroups.zig");

/// Run an external command in the sandbox
pub fn runCommand(argv: []const [:0]const u8, cgroup_config: Cgroups.Config, allocator: std.mem.Allocator) !void {
    _ = &cgroup_config; // Used in parent branch after fork
    const logger = Logger.init(.prefork);

    // Cgroup will be set up after fork with the child PID
    var cgroup: ?Cgroups = null;
    defer if (cgroup) |*cg| {
        cg.cleanup();
        cg.deinit();
    };

    const socket_pair: [2]FD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock: FD, const supervisor_sock: FD = socket_pair;

    const fork_result = try std.posix.fork();
    if (fork_result == 0) {
        posix.close(supervisor_sock);
        try childProcessExec(child_sock, argv);
    } else {
        posix.close(child_sock);
        const child_pid: linux.pid_t = fork_result;

        // Set up cgroup with child PID as unique name
        if (cgroup_config.hasLimits()) {
            var name_buf: [32]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "{d}", .{child_pid}) catch "sandbox";
            cgroup = Cgroups.init(allocator, name, cgroup_config) catch |err| {
                logger.log("Warning: cgroup init failed: {} (continuing without cgroups)", .{err});
                return try supervisorProcess(supervisor_sock, child_pid);
            };

            if (cgroup) |*cg| {
                logger.log("Setting up cgroup: {s}", .{cg.cgroup_path});
                cg.setup() catch |err| {
                    logger.log("Warning: cgroup setup failed: {} (continuing without cgroups)", .{err});
                    cg.deinit();
                    cgroup = null;
                };
            }

            if (cgroup) |*cg| {
                cg.addProcess(child_pid) catch |err| {
                    logger.log("Warning: failed to add process to cgroup: {}", .{err});
                };
            }
        }

        try supervisorProcess(supervisor_sock, child_pid);
    }
}

pub fn run(runnable: *const fn (io: std.Io) void) !void {
    // Create socket pair for child and supervisor
    // To allow inter-process communication
    const socket_pair: [2]FD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock: FD, const supervisor_sock: FD = socket_pair;

    // Fork into both subprocesses
    const fork_result = try std.posix.fork();
    if (fork_result == 0) {
        // Child process
        posix.close(supervisor_sock);
        try childProcess(child_sock, runnable);
    } else {
        // Supervisor process
        posix.close(child_sock);

        // fork_result is the child PID, needed for looking up the notify FD
        const child_pid: linux.pid_t = fork_result;
        try supervisorProcess(supervisor_sock, child_pid);
    }
}

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

// BPF instruction helpers
const BPF = linux.BPF;
const SECCOMP_RET = linux.SECCOMP.RET;

// Blocked syscalls - these are dangerous and should return -EPERM
// Phase 3.1: Escape syscalls
// Phase 3.2: Privilege syscalls
// Phase 3.3: Kernel manipulation
// Phase 3.4: Dangerous misc
const blocked_syscalls = [_]linux.SYS{
    // Phase 3.1: Escape syscalls
    .mount,
    .umount2,
    .pivot_root,
    .chroot,
    .setns,
    .unshare,
    .ptrace,
    // Phase 3.2: Privilege syscalls
    .setuid,
    .setgid,
    .setreuid,
    .setregid,
    .setresuid,
    .setresgid,
    .setgroups,
    // Phase 3.3: Kernel manipulation
    .init_module,
    .finit_module,
    .delete_module,
    .kexec_load,
    .kexec_file_load,
    // Phase 3.4: Dangerous misc
    .reboot,
    .swapon,
    .swapoff,
    .acct,
    .perf_event_open,
    .bpf,
    .userfaultfd,
    .io_uring_setup,
    .io_uring_enter,
    .io_uring_register,
};

/// Build BPF filter that blocks dangerous syscalls and sends rest to USER_NOTIF
fn buildSeccompFilter(buf: []BPFInstruction) []BPFInstruction {
    var i: usize = 0;

    // Load syscall number: LD [0] (offset 0 = nr field in seccomp_data)
    buf[i] = .{
        .code = BPF.LD | BPF.W | BPF.ABS,
        .jt = 0,
        .jf = 0,
        .k = 0, // offset of nr in seccomp_data
    };
    i += 1;

    // For each blocked syscall, add a jump-if-equal to the ERRNO return
    // Jump targets: jt = distance to ERRNO ret, jf = 0 (continue)
    const num_blocked = blocked_syscalls.len;
    for (blocked_syscalls, 0..) |syscall, idx| {
        // Distance to ERRNO return: remaining comparisons + 1 (for USER_NOTIF ret)
        const remaining = num_blocked - idx - 1;
        const jump_to_errno: u8 = @intCast(remaining + 1);

        buf[i] = .{
            .code = BPF.JMP | BPF.JEQ | BPF.K,
            .jt = jump_to_errno, // jump to ERRNO if equal
            .jf = 0, // continue to next check
            .k = @truncate(@intFromEnum(syscall)),
        };
        i += 1;
    }

    // Default: return USER_NOTIF (allow syscall to be handled by supervisor)
    buf[i] = .{
        .code = BPF.RET | BPF.K,
        .jt = 0,
        .jf = 0,
        .k = SECCOMP_RET.USER_NOTIF,
    };
    i += 1;

    // Blocked syscall return: ERRNO | EPERM
    buf[i] = .{
        .code = BPF.RET | BPF.K,
        .jt = 0,
        .jf = 0,
        .k = SECCOMP_RET.ERRNO | @as(u32, @intFromEnum(linux.E.PERM)),
    };
    i += 1;

    return buf[0..i];
}

fn childProcess(socket: FD, runnable: *const fn (io: std.Io) void) !void {
    const logger = Logger.init(.child);
    logger.log("Child process starting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Before starting seccomp, there's a chicken-and-egg issue
    // The supervisor needs seccomp's FD to listen on
    // But we can't send that FD across the socket once seccomp is running
    // since that .write command to the socket would get blocked

    // To get around this, we predict the FD that seccomp will use
    // and send it on the socket before starting seccomp

    // Posix.dup(0) returns the lowest available fd, which we immediately close
    const next_fd: FD = try posix.dup(0);
    posix.close(next_fd);

    // Send to supervisor then close socket
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(FD, &fd_bytes, next_fd, .little);
    _ = try posix.write(socket, &fd_bytes);
    // posix.close(socket);

    // ===== SECCOMP SETUP =====

    // Set "No New Privileges" mode to prevent this process (and children)
    // from re-elevating their permissions. Required by seccomp.
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
    logger.log("Privilege elevation locked", .{});

    // Build BPF program that blocks dangerous syscalls and sends rest to USER_NOTIF
    var filter_buf: [blocked_syscalls.len + 3]BPFInstruction = undefined;
    const filter = buildSeccompFilter(&filter_buf);
    var prog = BPFFilterProgram{
        .len = @intCast(filter.len),
        .filter = filter.ptr,
    };

    logger.log("Entering seccomp mode (blocking {d} dangerous syscalls)", .{blocked_syscalls.len});

    // Install program using seccomp
    const notify_fd: FD = try Result(FD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        // Prediction failed - exit
        // Can't print, since seccomp is running without a supervisor listening
        return error.PredictionFailed;
    }

    // Now we just run some other process!
    // Shell out to bash with cmd in the future
    @call(.never_inline, runnable, .{io});
}

fn childProcessExec(socket: FD, argv: []const [:0]const u8) !void {
    const logger = Logger.init(.child);
    logger.log("Child process starting (exec mode)", .{});

    // Predict the FD that seccomp will use
    const next_fd: FD = try posix.dup(0);
    posix.close(next_fd);

    // Send to supervisor then close socket
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(FD, &fd_bytes, next_fd, .little);
    _ = try posix.write(socket, &fd_bytes);

    // Set "No New Privileges" mode
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
    logger.log("Privilege elevation locked", .{});

    // Build BPF program that blocks dangerous syscalls and sends rest to USER_NOTIF
    var filter_buf: [blocked_syscalls.len + 3]BPFInstruction = undefined;
    const filter = buildSeccompFilter(&filter_buf);
    var prog = BPFFilterProgram{
        .len = @intCast(filter.len),
        .filter = filter.ptr,
    };

    logger.log("Entering seccomp mode (blocking {d} dangerous syscalls)", .{blocked_syscalls.len});

    // Install program using seccomp
    const notify_fd: FD = try Result(FD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        return error.PredictionFailed;
    }

    // Convert argv to null-terminated array for execve
    var argv_buf: [64:null]?[*:0]const u8 = undefined;
    for (argv, 0..) |arg, i| {
        if (i >= 64) break;
        argv_buf[i] = arg.ptr;
    }
    argv_buf[argv.len] = null;

    logger.log("Executing command: {s}", .{argv[0]});

    // execve replaces the current process - doesn't return on success
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
    const err = posix.execveZ(argv_buf[0].?, &argv_buf, envp);
    std.debug.print("execve failed: {}\n", .{err});
}

fn supervisorProcess(socket: FD, child_pid: linux.pid_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ===== Dereferencing notify FD =====
    // The child sends its process-local notify FD across the socket
    // We use its own PID + FD to look up the actual FD

    var child_notify_fd_bytes: [4]u8 = undefined;
    const bytes_read = try posix.read(socket, &child_notify_fd_bytes);
    if (bytes_read != 4) {
        std.debug.print("failed to read fd from socket\n", .{});
        return error.ReadFailed;
    }
    const child_notify_fd: FD = std.mem.readInt(i32, &child_notify_fd_bytes, .little);

    // Use child PID to look up its FD table
    const child_fd_table: FD = try Result(FD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    // Since notify FD was sent eagerly, poll child's FD table until FD is visible
    // Otherwise we'd have race condition
    var notify_fd: FD = undefined;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, child_notify_fd, 0);
        switch (Result(FD).from(result)) {
            .Ok => |value| {
                notify_fd = value;
                break;
            },
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
                    continue;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }
    } else {
        return error.PidfdGetfdFailed;
    }

    var supervisor = Supervisor.init(notify_fd, child_pid, gpa, io);
    defer supervisor.deinit();
    try supervisor.run();
}
