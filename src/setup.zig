const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const seccomp = @import("seccomp/filter.zig");
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");

// comptime dependency injection
const deps = @import("deps/deps.zig");
// ERIK TODO: now that we have unit tests in docker, consider removing deps comptime switch entirely
const lookupGuestFd = deps.pidfd.lookupGuestFdWithRetry;

/// seccomp.install() allocates the lowest available fd. After fork the guest
/// has only 0/1/2, so the notify fd will be 3. Both sides hardcode this to
/// avoid IPC. If anything opens an fd before seccomp.install(), this will
/// fail with NotifyFdMismatch.
const guest_notify_fd: linux.fd_t = 3;

pub fn setupAndRun(runnable: *const fn () void) !void {
    const fork_result = try posix.fork();
    if (fork_result == 0) {
        try guestProcess(runnable);
    } else {
        const init_guest_pid: linux.pid_t = fork_result;
        try supervisorProcess(init_guest_pid);
    }
}

fn guestProcess(runnable: *const fn () void) !void {
    const logger = Logger.init(.guest);
    logger.log("Guest process starting", .{});
    logger.log("Entering seccomp mode", .{});
    const notify_fd = try seccomp.install();

    if (notify_fd != guest_notify_fd) {
        return error.NotifyFdMismatch;
    }

    @call(.never_inline, runnable, .{});
}

fn supervisorProcess(init_guest_pid: linux.pid_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const notify_fd = try lookupGuestFd(init_guest_pid, guest_notify_fd, io);

    var supervisor = try Supervisor.init(gpa, io, notify_fd, init_guest_pid);
    defer supervisor.deinit();
    try supervisor.run();
}
