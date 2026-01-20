const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

/// TDD-style smoke test scorecard for bVisor sandbox.
/// Each test exercises real behavior. Failures inform what to implement next.
///
/// README goal: Run bash commands like echo, ls, touch, curl, npm, sleep
/// Many tests will fail initially - that's expected and guides implementation.
///
/// Run with: docker run --rm --cap-add=SYS_PTRACE -v ./zig-out:/zig-out alpine /zig-out/bin/bVisor
pub fn smoke_test(_: std.Io) void {
    std.debug.print("\n=== bVisor Smoke Test Scorecard ===\n\n", .{});

    const tests = .{
        // Process Identity (needed for any process)
        .{ "getpid", test_getpid },
        .{ "getppid", test_getppid },
        .{ "gettid", test_gettid },
        .{ "getuid", test_getuid },
        .{ "getgid", test_getgid },

        // Process Hierarchy (needed for bash to spawn subprocesses)
        .{ "fork", test_fork },
        .{ "fork_child_identity", test_fork_child_identity },
        .{ "execve", test_execve },
        .{ "wait4", test_wait4 },

        // File I/O (needed for echo, cat, file operations)
        .{ "openat", test_openat },
        .{ "read_write", test_read_write },
        .{ "close", test_close },
        .{ "dup3", test_dup3 },
        .{ "pipe", test_pipe },
        .{ "lseek", test_lseek },
        .{ "fstat", test_fstat },
        .{ "fcntl_getfl", test_fcntl_getfl },

        // Directory Operations (needed for ls)
        .{ "getdents64", test_getdents64 },
        .{ "readlinkat", test_readlinkat },

        // Filesystem (needed for touch, mkdir, rm, cd)
        .{ "getcwd", test_getcwd },
        .{ "chdir", test_chdir },
        .{ "stat", test_stat },
        .{ "faccessat", test_faccessat },
        .{ "mkdirat", test_mkdirat },
        .{ "unlinkat", test_unlinkat },

        // Memory (passthrough, needed for any process)
        .{ "brk", test_brk },
        .{ "mmap_anon", test_mmap_anon },
        .{ "mprotect", test_mprotect },
        .{ "munmap", test_munmap },

        // Time (needed for sleep)
        .{ "nanosleep", test_nanosleep },
        .{ "clock_gettime", test_clock_gettime },
        .{ "gettimeofday", test_gettimeofday },

        // Signals (needed for job control, ctrl-c)
        .{ "kill_self", test_kill_self },
        .{ "kill_child", test_kill_child },
        .{ "kill_unknown_esrch", test_kill_unknown_esrch },

        // Runtime (passthrough, needed for libc/runtime)
        .{ "getrandom", test_getrandom },
        .{ "uname", test_uname },

        // Blocked syscalls (expect EPERM - sandbox escape prevention)
        .{ "ptrace_blocked", test_ptrace_blocked },
        .{ "mount_blocked", test_mount_blocked },
        .{ "chroot_blocked", test_chroot_blocked },
        .{ "pivot_root_blocked", test_pivot_root_blocked },
        .{ "setns_blocked", test_setns_blocked },
        .{ "unshare_blocked", test_unshare_blocked },
    };

    var passed: usize = 0;
    inline for (tests) |t| {
        const result = t[1]();
        if (result) {
            std.debug.print("PASS: {s}\n", .{t[0]});
            passed += 1;
        } else {
            std.debug.print("FAIL: {s}\n", .{t[0]});
        }
    }

    std.debug.print("\n{d}/{d} passing\n", .{ passed, tests.len });
}

// =============================================================================
// Process Identity Tests
// =============================================================================

fn test_getpid() bool {
    const pid = linux.getpid();
    return pid > 0;
}

fn test_getppid() bool {
    const ppid = linux.getppid();
    return ppid == 0; // init has no parent
}

fn test_gettid() bool {
    // For the main thread, tid should equal pid
    const tid = linux.gettid();
    const pid = linux.getpid();
    return tid == pid;
}

fn test_getuid() bool {
    const result = linux.getuid();
    _ = result;
    return true; // passthrough, any value is fine
}

fn test_getgid() bool {
    const result = linux.getgid();
    _ = result;
    return true; // passthrough, any value is fine
}

// =============================================================================
// Process Hierarchy Tests (for bash spawning subprocesses)
// =============================================================================

fn test_fork() bool {
    const fork_result = posix.fork() catch return false;

    if (fork_result == 0) {
        // Child: exit immediately
        linux.exit_group(0);
    }

    return fork_result > 1;
}

fn test_fork_child_identity() bool {
    const fork_result = posix.fork() catch return false;

    if (fork_result == 0) {
        // Child: verify pid/ppid
        const child_pid = linux.getpid();
        const child_ppid = linux.getppid();
        // Child should be vpid 3 (after previous fork's child was vpid 2)
        // and parent should be vpid 1
        if (child_ppid != 1) {
            linux.exit_group(1);
        }
        // Child pid should be > 1
        if (child_pid <= 1) {
            linux.exit_group(2);
        }
        linux.exit_group(0);
    }

    // Parent: wait and check exit status
    var status: u32 = 0;
    var rusage: linux.rusage = undefined;
    const wait_result = linux.wait4(fork_result, &status, 0, &rusage);
    if (linux.errno(wait_result) != .SUCCESS) return false;

    return linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0;
}

fn test_execve() bool {
    const fork_result = posix.fork() catch return false;

    if (fork_result == 0) {
        // Child: exec /bin/true (or /bin/sh -c true on systems without /bin/true)
        const argv = [_:null]?[*:0]const u8{"/bin/true"};
        const envp = [_:null]?[*:0]const u8{};
        _ = linux.execve("/bin/true", &argv, &envp);
        // If execve returns, it failed
        linux.exit_group(1);
    }

    // Parent: wait for child
    var status: u32 = 0;
    var rusage: linux.rusage = undefined;
    const wait_result = linux.wait4(fork_result, &status, 0, &rusage);
    if (linux.errno(wait_result) != .SUCCESS) return false;

    return linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0;
}

fn test_wait4() bool {
    const fork_result = posix.fork() catch return false;

    if (fork_result == 0) {
        linux.exit_group(42);
    }

    var status: u32 = 0;
    var rusage: linux.rusage = undefined;
    const wait_result = linux.wait4(fork_result, &status, 0, &rusage);
    if (linux.errno(wait_result) != .SUCCESS) return false;

    return linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 42;
}

// =============================================================================
// File I/O Tests (for echo, cat, file operations)
// =============================================================================

fn test_openat() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_openat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch return false;
    posix.close(fd);
    return true;
}

fn test_read_write() bool {
    const wfd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_rw.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644) catch return false;
    defer posix.close(wfd);

    const write_result = linux.write(wfd, "hello", 5);
    if (linux.errno(write_result) != .SUCCESS) return false;

    const rfd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_rw.txt", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer posix.close(rfd);

    var buf: [16]u8 = undefined;
    const read_result = linux.read(rfd, &buf, buf.len);
    if (linux.errno(read_result) != .SUCCESS) return false;

    const n = @min(read_result, buf.len);
    return std.mem.eql(u8, buf[0..n], "hello");
}

fn test_close() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_close.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch return false;
    posix.close(fd);
    // Try to close again - should fail (fd already closed)
    const result = linux.close(fd);
    return linux.errno(result) == .BADF;
}

fn test_dup3() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_dup.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch return false;
    defer posix.close(fd);

    const new_fd: linux.fd_t = 100;
    const result = linux.dup3(fd, new_fd, 0);
    if (linux.errno(result) != .SUCCESS) return false;

    posix.close(new_fd);
    return true;
}

fn test_pipe() bool {
    var fds: [2]linux.fd_t = undefined;
    const pipe_result = linux.pipe2(&fds, .{});
    if (linux.errno(pipe_result) != .SUCCESS) return false;
    defer {
        posix.close(fds[0]);
        posix.close(fds[1]);
    }

    const write_result = linux.write(fds[1], "pipe", 4);
    if (linux.errno(write_result) != .SUCCESS) return false;

    var buf: [16]u8 = undefined;
    const read_result = linux.read(fds[0], &buf, buf.len);
    if (linux.errno(read_result) != .SUCCESS) return false;

    const n = @min(read_result, buf.len);
    return std.mem.eql(u8, buf[0..n], "pipe");
}

fn test_lseek() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_lseek.txt", .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o644) catch return false;
    defer posix.close(fd);

    // Write some data
    _ = linux.write(fd, "hello world", 11);

    // Seek back to beginning
    const result = linux.lseek(fd, 0, linux.SEEK.SET);
    if (linux.errno(result) != .SUCCESS) return false;

    // Read and verify
    var buf: [16]u8 = undefined;
    const read_result = linux.read(fd, &buf, buf.len);
    if (linux.errno(read_result) != .SUCCESS) return false;

    const n = @min(read_result, buf.len);
    return std.mem.eql(u8, buf[0..n], "hello world");
}

fn test_fstat() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer posix.close(fd);

    var statx_buf: linux.Statx = undefined;
    const result = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &statx_buf);
    return linux.errno(result) == .SUCCESS;
}

fn test_fcntl_getfl() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_fcntl.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch return false;
    defer posix.close(fd);

    // F_GETFL = 3
    const result = linux.fcntl(fd, linux.F.GETFL, 0);
    return linux.errno(result) == .SUCCESS;
}

// =============================================================================
// Directory Operations Tests (for ls)
// =============================================================================

fn test_getdents64() bool {
    const fd = posix.openat(linux.AT.FDCWD, "/tmp", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer posix.close(fd);

    var buf: [1024]u8 = undefined;
    const result = linux.getdents64(fd, &buf, buf.len);
    // Should return > 0 (bytes read) for non-empty directory
    return linux.errno(result) == .SUCCESS and result > 0;
}

fn test_readlinkat() bool {
    // /proc/self/exe is a symlink - try to read it
    // Note: this may fail if /proc isn't mounted or virtualized
    var buf: [256]u8 = undefined;
    const result = linux.readlinkat(linux.AT.FDCWD, "/proc/self/exe", &buf, buf.len);
    // Either it works or returns ENOENT (if /proc not available)
    const err = linux.errno(result);
    return err == .SUCCESS or err == .NOENT;
}

// =============================================================================
// Filesystem Tests (for touch, mkdir, rm, cd)
// =============================================================================

fn test_getcwd() bool {
    var buf: [256]u8 = undefined;
    const result = linux.getcwd(&buf, buf.len);
    return linux.errno(result) == .SUCCESS;
}

fn test_chdir() bool {
    var orig_buf: [256]u8 = undefined;
    if (linux.errno(linux.getcwd(&orig_buf, orig_buf.len)) != .SUCCESS) return false;

    if (linux.errno(linux.chdir("/tmp")) != .SUCCESS) return false;

    // Change back
    const orig_len = std.mem.indexOfScalar(u8, &orig_buf, 0) orelse return false;
    var path_buf: [256:0]u8 = undefined;
    @memcpy(path_buf[0..orig_len], orig_buf[0..orig_len]);
    path_buf[orig_len] = 0;
    if (linux.errno(linux.chdir(&path_buf)) != .SUCCESS) return false;

    return true;
}

fn test_stat() bool {
    var statx_buf: linux.Statx = undefined;
    const result = linux.statx(linux.AT.FDCWD, "/tmp", 0, linux.STATX.BASIC_STATS, &statx_buf);
    return linux.errno(result) == .SUCCESS;
}

fn test_faccessat() bool {
    // Check if /tmp is accessible (should always be)
    const result = linux.faccessat(linux.AT.FDCWD, "/tmp", linux.F_OK, 0);
    return linux.errno(result) == .SUCCESS;
}

fn test_mkdirat() bool {
    // Try to create a directory
    const result = linux.mkdirat(linux.AT.FDCWD, "/tmp/smoke_mkdir_test", 0o755);
    const err = linux.errno(result);
    // Success or already exists
    if (err != .SUCCESS and err != .EXIST) return false;

    // Clean up
    _ = linux.unlinkat(linux.AT.FDCWD, "/tmp/smoke_mkdir_test", linux.AT.REMOVEDIR);
    return true;
}

fn test_unlinkat() bool {
    // Create a file then delete it
    const fd = posix.openat(linux.AT.FDCWD, "/tmp/smoke_unlink.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch return false;
    posix.close(fd);

    const result = linux.unlinkat(linux.AT.FDCWD, "/tmp/smoke_unlink.txt", 0);
    return linux.errno(result) == .SUCCESS;
}

// =============================================================================
// Memory Tests (passthrough)
// =============================================================================

fn test_brk() bool {
    const result = linux.syscall1(.brk, 0);
    return result != 0;
}

fn test_mmap_anon() bool {
    const ptr = linux.mmap(null, 4096, linux.PROT.READ | linux.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return false;

    const slice: [*]u8 = @ptrFromInt(ptr);
    slice[0] = 42;

    _ = linux.munmap(slice, 4096);
    return true;
}

fn test_mprotect() bool {
    const ptr = linux.mmap(null, 4096, linux.PROT.READ | linux.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return false;
    defer _ = linux.munmap(@ptrFromInt(ptr), 4096);

    const result = linux.mprotect(@ptrFromInt(ptr), 4096, linux.PROT.READ);
    return linux.errno(result) == .SUCCESS;
}

fn test_munmap() bool {
    const ptr = linux.mmap(null, 4096, linux.PROT.READ | linux.PROT.WRITE, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(ptr) != .SUCCESS) return false;

    const result = linux.munmap(@ptrFromInt(ptr), 4096);
    return linux.errno(result) == .SUCCESS;
}

// =============================================================================
// Time Tests (for sleep)
// =============================================================================

fn test_nanosleep() bool {
    const req = linux.timespec{ .sec = 0, .nsec = 1_000_000 }; // 1ms
    var rem: linux.timespec = undefined;
    const result = linux.nanosleep(&req, &rem);
    return linux.errno(result) == .SUCCESS;
}

fn test_clock_gettime() bool {
    var ts: linux.timespec = undefined;
    const result = linux.clock_gettime(.REALTIME, &ts);
    return linux.errno(result) == .SUCCESS;
}

fn test_gettimeofday() bool {
    var tv: linux.timeval = undefined;
    const result = linux.syscall2(.gettimeofday, @intFromPtr(&tv), 0);
    return linux.errno(result) == .SUCCESS;
}

// =============================================================================
// Signal Tests (for job control, ctrl-c)
// =============================================================================

fn test_kill_self() bool {
    const pid = linux.getpid();
    // Signal 0 checks if process exists without sending signal
    const result = linux.kill(pid, @enumFromInt(0));
    return linux.errno(result) == .SUCCESS;
}

fn test_kill_child() bool {
    const fork_result = posix.fork() catch return false;

    if (fork_result == 0) {
        // Child: sleep forever (will be killed)
        const req = linux.timespec{ .sec = 10, .nsec = 0 };
        var rem: linux.timespec = undefined;
        _ = linux.nanosleep(&req, &rem);
        linux.exit_group(0);
    }

    // Parent: kill the child
    const kill_result = linux.kill(@intCast(fork_result), linux.SIG.KILL);
    if (linux.errno(kill_result) != .SUCCESS) return false;

    // Wait for child to be reaped
    var status: u32 = 0;
    var rusage: linux.rusage = undefined;
    const wait_result = linux.wait4(fork_result, &status, 0, &rusage);
    if (linux.errno(wait_result) != .SUCCESS) return false;

    // Child should have been killed by signal
    return linux.W.IFSIGNALED(status) and linux.W.TERMSIG(status) == @intFromEnum(linux.SIG.KILL);
}

fn test_kill_unknown_esrch() bool {
    // Killing a non-existent PID outside the sandbox should return ESRCH
    // Use a very high PID that's unlikely to exist
    const result = linux.kill(999999, @enumFromInt(0));
    return linux.errno(result) == .SRCH;
}

// =============================================================================
// Runtime Tests (passthrough)
// =============================================================================

fn test_getrandom() bool {
    var buf: [16]u8 = undefined;
    const result = linux.getrandom(&buf, buf.len, 0);
    return linux.errno(result) == .SUCCESS;
}

fn test_uname() bool {
    var uts: linux.utsname = undefined;
    const result = linux.uname(&uts);
    return linux.errno(result) == .SUCCESS;
}

// =============================================================================
// Blocked Syscall Tests (expect ENOSYS - sandbox escape prevention)
// =============================================================================

fn test_ptrace_blocked() bool {
    const PTRACE_TRACEME = 0;
    const result = linux.ptrace(PTRACE_TRACEME, 0, 0, 0, 0);
    return linux.errno(result) == .NOSYS;
}

fn test_mount_blocked() bool {
    const result = linux.mount("none", "/mnt", "tmpfs", 0, 0);
    return linux.errno(result) == .NOSYS;
}

fn test_chroot_blocked() bool {
    const result = linux.chroot("/");
    return linux.errno(result) == .NOSYS;
}

fn test_pivot_root_blocked() bool {
    const result = linux.pivot_root("/tmp", "/tmp");
    return linux.errno(result) == .NOSYS;
}

fn test_setns_blocked() bool {
    // setns with invalid fd should return ENOSYS (blocked) not EBADF
    const result = linux.syscall2(.setns, @as(u64, @bitCast(@as(i64, -1))), 0);
    return linux.errno(result) == .NOSYS;
}

fn test_unshare_blocked() bool {
    // Try to unshare mount namespace
    const CLONE_NEWNS = 0x00020000;
    const result = linux.unshare(CLONE_NEWNS);
    return linux.errno(result) == .NOSYS;
}
