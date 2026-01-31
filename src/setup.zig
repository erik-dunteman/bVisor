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

pub fn setupAndRun(runnable: *const fn (io: std.Io) void) !void {
    // Create socket pair for IPC between child and supervisor
    const socket_pair: [2]linux.fd_t = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const guest_sock, const supervisor_sock = socket_pair;

    const fork_result = try posix.fork();
    if (fork_result == 0) {
        posix.close(supervisor_sock);
        try guestProcess(guest_sock, runnable);
    } else {
        posix.close(guest_sock);
        const init_guest_pid: linux.pid_t = fork_result;
        try supervisorProcess(supervisor_sock, init_guest_pid);
    }
}

fn guestProcess(socket: linux.fd_t, runnable: *const fn (io: std.Io) void) !void {
    const logger = Logger.init(.guest);
    logger.log("Guest process starting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Predict notify FD and send to supervisor before installing seccomp
    // (can't send after since socket write would be intercepted)
    // Don't close socket until after install() so fd numbers stay stable
    const predicted_fd = try seccomp.predictNotifyFd();
    try sendFd(socket, predicted_fd);

    logger.log("Entering seccomp mode", .{});
    const notify_fd = try seccomp.install();
    posix.close(socket);

    if (notify_fd != predicted_fd) {
        return error.NotifyFdPredictionFailed;
    }

    // Run the sandboxed code
    @call(.never_inline, runnable, .{io});
}

fn supervisorProcess(socket: linux.fd_t, init_guest_pid: linux.pid_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const guest_notify_fd = try recvFd(socket);
    posix.close(socket);

    const notify_fd = try lookupGuestFd(init_guest_pid, guest_notify_fd, io);

    var supervisor = try Supervisor.init(gpa, io, notify_fd, init_guest_pid);
    defer supervisor.deinit();
    try supervisor.run();
}

fn sendFd(socket: linux.fd_t, fd: linux.fd_t) !void {
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(linux.fd_t, &fd_bytes, fd, .little);
    _ = try posix.write(socket, &fd_bytes);
}

fn recvFd(socket: linux.fd_t) !linux.fd_t {
    var fd_bytes: [4]u8 = undefined;
    const bytes_read = try posix.read(socket, &fd_bytes);
    if (bytes_read != 4) {
        return error.FdReadFailed;
    }
    return std.mem.readInt(linux.fd_t, &fd_bytes, .little);
}
