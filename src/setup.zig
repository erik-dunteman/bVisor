const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const seccomp = @import("seccomp/filter.zig");
const KernelFD = types.KernelFD;
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");

// comptime dependency injection
const deps = @import("deps/deps.zig");
const lookup_child_fd = deps.pidfd.lookup_child_fd_with_retry;

pub fn setup_and_run(runnable: *const fn (io: std.Io) void) !void {
    // Create socket pair for IPC between child and supervisor
    const socket_pair: [2]KernelFD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock, const supervisor_sock = socket_pair;

    const fork_result = try posix.fork();
    if (fork_result == 0) {
        // Child process
        posix.close(supervisor_sock);
        try child_process(child_sock, runnable);
    } else {
        // Supervisor process
        posix.close(child_sock);
        const child_pid: linux.pid_t = fork_result;
        try supervisor_process(supervisor_sock, child_pid);
    }
}

fn child_process(socket: KernelFD, runnable: *const fn (io: std.Io) void) !void {
    const logger = Logger.init(.child);
    logger.log("Child process starting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Predict notify FD and send to supervisor before installing seccomp
    // (can't send after since socket write would be intercepted)
    const predicted_fd = try seccomp.predict_notify_fd();
    try send_fd(socket, predicted_fd);

    logger.log("Entering seccomp mode", .{});
    const notify_fd = try seccomp.install();

    if (notify_fd != predicted_fd) {
        return error.NotifyFdPredictionFailed;
    }

    // Run the sandboxed code
    @call(.never_inline, runnable, .{io});
}

fn supervisor_process(socket: KernelFD, child_pid: linux.pid_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Receive predicted notify FD from child
    const child_notify_fd = try recv_fd(socket);

    // Get actual notify FD by looking up child's FD table
    const notify_fd = try lookup_child_fd(child_pid, child_notify_fd, io);

    // Run the supervisor loop
    var supervisor = Supervisor.init(notify_fd, child_pid);
    try supervisor.run();
}

fn send_fd(socket: KernelFD, fd: KernelFD) !void {
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(KernelFD, &fd_bytes, fd, .little);
    _ = try posix.write(socket, &fd_bytes);
}

fn recv_fd(socket: KernelFD) !KernelFD {
    var fd_bytes: [4]u8 = undefined;
    const bytes_read = try posix.read(socket, &fd_bytes);
    if (bytes_read != 4) {
        return error.FdReadFailed;
    }
    return std.mem.readInt(KernelFD, &fd_bytes, .little);
}
