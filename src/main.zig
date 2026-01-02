const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

// File Descriptor
const FD = i32;

pub fn main() !void {
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
        try child_process(child_sock);
        std.debug.print("Child process exiting\n", .{});
    } else {
        // Supervisor process
        posix.close(child_sock);

        // fork_result is the child PID, needed for looking up the notify FD
        const child_pid: linux.pid_t = fork_result;
        try supervisor_process(supervisor_sock, child_pid);

        std.debug.print("Supervisor process exiting\n", .{});
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

fn child_process(socket: FD) !void {
    std.debug.print("Child process starting\n", .{});

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

    // Write a BPF program that instructs the kernel to intercept all syscalls
    // and trigger USER_NOTIF
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    // Install program using seccomp
    const notify_fd: FD = try unwrap_result(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    );

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        // Prediction failed - exit
        // Can't print, since seccomp is running without a supervisor listening
        return error.PredictionFailed;
    }

    // Now we just run some other process!
    // Shell out to bash with cmd in the future
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        std.debug.print("Child process: {}\n", .{i});
        try io.sleep(std.Io.Duration.fromMilliseconds(500), .awake);
    }
    std.debug.print("Child done!\n", .{});
}

fn unwrap_result(result: usize) !i32 {
    if (result > std.math.maxInt(isize)) {
        // todo: cleaner prints
        std.debug.print("result unwrap failed\n", .{});
        return error.ResultUnwrapFailed;
    }
    return @intCast(result);
}

fn supervisor_process(socket: FD, child_pid: linux.pid_t) !void {
    std.debug.print("Supervisor process starting\n", .{});

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
    const child_fd_table: FD = try unwrap_result(
        linux.pidfd_open(child_pid, 0),
    );

    // Since notify FD was sent eagerly, poll child's FD table until FD is visible
    // Otherwise we'd have race condition
    var notify_fd: FD = undefined;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        // Try to get the notify FD from the child's FD table
        // This is the FD visible from our supervisor process
        const notify_fd_result = linux.pidfd_getfd(
            child_fd_table,
            child_notify_fd,
            0,
        );
        std.debug.print("fd{d} @pid{d} should soon be visible\n", .{ child_notify_fd, child_pid });
        if (notify_fd_result > std.math.maxInt(isize)) {
            // two's compliment ints, so this means a negative code
            // TODO: extract specifically the fd not exists code
            std.debug.print("fd{d} @pid{d} not found, retrying...\n", .{ child_notify_fd, child_pid });
            try io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
            continue;
        }

        notify_fd = @intCast(notify_fd_result);
        std.debug.print("fd{d} @pid{d} = {d}\n", .{ child_notify_fd, child_pid, notify_fd });
        break;
    } else {
        std.debug.print("pidfd_getfd failed after {} attempts\n", .{attempts});
        return error.PidfdGetfdFailed;
    }

    // Now we have the notify fd! Start handling notifications
    try handle_notifications(notify_fd);
}

fn handle_notifications(notify_fd: FD) !void {
    std.debug.print("Starting notification handler on fd {}\n", .{notify_fd});

    // Allocate zeroed structures
    var req: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    var resp: linux.SECCOMP.notif_resp = std.mem.zeroes(linux.SECCOMP.notif_resp);

    while (true) : ({
        // On continue, re-zero buffers
        req = std.mem.zeroes(linux.SECCOMP.notif);
        resp = std.mem.zeroes(linux.SECCOMP.notif_resp);
    }) {
        // Receive notification
        _ = try unwrap_result(
            linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&req)),
        );

        std.debug.print("Intercepted syscall {} from pid {}, id={}\n", .{ req.data.nr, req.pid, req.id });

        // Allow the syscall to proceed (passthrough mode)
        resp.id = req.id;
        resp.@"error" = 0;
        resp.val = 0;
        resp.flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE;

        _ = try unwrap_result(
            linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
        );

        std.debug.print("Passe through syscall {}\n", .{req.data.nr});
    }
}
