const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Passthrough = @import("../../fs/backend/passthrough.zig").Passthrough;
const Cow = @import("../../fs/backend/cow.zig").Cow;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const path_router = @import("../../path.zig");
const Supervisor = @import("../../../Supervisor.zig");
const types = @import("../../../types.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    const pid: Proc.AbsPid = @intCast(notif.pid);

    const proc = supervisor.guest_procs.get(pid) catch |err| {
        logger.log("openat: process not found for pid={d}: {}", .{ pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Read path from guest memory
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, pid, path_ptr) catch |err| {
        logger.log("openat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // Only absolute paths supported for now
    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    _ = dirfd; // dirfd only matters for relative paths
    if (path.len == 0 or path[0] != '/') {
        logger.log("openat: path must be absolute: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    }

    // Route the path to determine which backend handles it
    const route_result = path_router.route(path) catch {
        logger.log("openat: path normalization failed for: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    };

    switch (route_result) {
        .block => {
            logger.log("openat: blocked path: {s}", .{path});
            return replyErr(notif.id, .PERM);
        },
        .handle => |backend| {
            // Convert linux.O to posix.O
            const linux_flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));
            const flags = linuxToPosixFlags(linux_flags);
            const mode: posix.mode_t = @truncate(notif.data.arg3);

            // Special case: if we're in the /proc filepath
            // We need to sync guest_procs with the kernel to ensure all current PIDs are registered
            if (backend == .proc) {
                supervisor.guest_procs.syncNewProcs() catch |err| {
                    logger.log("openat: syncNewProcs failed: {}", .{err});
                    return replyErr(notif.id, .NOSYS);
                };
            }

            // Open the file via the appropriate backend
            const file: File = switch (backend) {
                .passthrough => .{ .passthrough = Passthrough.open(&supervisor.overlay, path, flags, mode) catch |err| {
                    logger.log("openat: failed to open {s}: {s}", .{ path, @errorName(err) });
                    return replyErr(notif.id, .IO);
                } },
                .cow => .{ .cow = Cow.open(&supervisor.overlay, path, flags, mode) catch |err| {
                    logger.log("openat: failed to open {s}: {s}", .{ path, @errorName(err) });
                    return replyErr(notif.id, .IO);
                } },
                .tmp => .{ .tmp = Tmp.open(&supervisor.overlay, path, flags, mode) catch |err| {
                    logger.log("openat: failed to open {s}: {s}", .{ path, @errorName(err) });
                    return replyErr(notif.id, .IO);
                } },
                .proc => .{ .proc = ProcFile.open(proc, path) catch |err| {
                    logger.log("openat: failed to open {s}: {s}", .{ path, @errorName(err) });
                    return replyErr(notif.id, if (err == error.FileNotFound) .NOENT else .IO);
                } },
            };

            // Insert into fd table and return the virtual fd
            const vfd = proc.fd_table.insert(file) catch {
                logger.log("openat: failed to insert fd", .{});
                return replyErr(notif.id, .MFILE);
            };

            logger.log("openat: opened {s} as vfd={d}", .{ path, vfd });
            return replySuccess(notif.id, @intCast(vfd));
        },
    }
}

/// Convert linux.O flags to posix.O flags at the syscall boundary
fn linuxToPosixFlags(linux_flags: linux.O) posix.O {
    var flags: posix.O = .{};

    flags.ACCMODE = switch (linux_flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };

    if (linux_flags.CREAT) flags.CREAT = true;
    if (linux_flags.EXCL) flags.EXCL = true;
    if (linux_flags.TRUNC) flags.TRUNC = true;
    if (linux_flags.APPEND) flags.APPEND = true;
    if (linux_flags.NONBLOCK) flags.NONBLOCK = true;
    if (linux_flags.CLOEXEC) flags.CLOEXEC = true;
    if (linux_flags.DIRECTORY) flags.DIRECTORY = true;

    return flags;
}
