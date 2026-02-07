const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const statxToStat = File.statxToStat;
const path_router = @import("../../path.zig");

const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const AT_EMPTY_PATH: u32 = 0x1000;

// fstatat64(dirfd, pathname, statbuf, flags)
//   Mode 1: AT_EMPTY_PATH + empty pathname → equivalent to fstat(dirfd)
//   Mode 2: Non-empty pathname → stat by path (no file opened)
// TODO: relative paths (dirfd-relative)
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const pathname_ptr: u64 = notif.data.arg1;
    const statbuf_addr: u64 = notif.data.arg2;
    const at_flags: u32 = @truncate(notif.data.arg3);

    // Read pathname from guest memory
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, caller_tid, pathname_ptr) catch |err| {
        logger.log("fstatat64: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // AT_EMPTY_PATH + empty pathname -> fd-based stat (same as fstat)
    if ((at_flags & AT_EMPTY_PATH) != 0 and path.len == 0) {
        // stdio: passthrough
        if (dirfd >= 0 and dirfd <= 2) {
            logger.log("fstatat64: passthrough for stdio fd={d}", .{dirfd});
            return replyContinue(notif.id);
        }

        var file: *File = undefined;
        {
            supervisor.mutex.lock();
            defer supervisor.mutex.unlock();

            const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                std.log.err("fstatat64: Thread not found with tid={d}: {}", .{ caller_tid, err });
                return replyContinue(notif.id);
            };
            std.debug.assert(caller.tid == caller_tid);

            file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("fstatat64: EBADF for fd={d}", .{dirfd});
                return replyErr(notif.id, .BADF);
            };
        }
        defer file.unref();

        const statx_buf = file.statx() catch |err| {
            logger.log("fstatat64: statx failed for fd={d}: {}", .{ dirfd, err });
            return replyErr(notif.id, .IO);
        };

        return writeStatResponse(notif, statx_buf, statbuf_addr);
    }

    // path-based stat
    // TODO: Only absolute paths supported for now
    if (path.len == 0 or path[0] != '/') {
        logger.log("fstatat64: path must be absolute: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    }

    const route_result = path_router.route(path) catch {
        logger.log("fstatat64: path normalization failed: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    };

    switch (route_result) {
        .block => {
            logger.log("fstatat64: blocked path: {s}", .{path});
            return replyErr(notif.id, .PERM);
        },
        .handle => |backend| {
            // Note all are lock-free (independent of internal Supervisor state) except for proc
            // For proc, sync Threads and get caller
            var caller: ?*Thread = null;
            if (backend == .proc) {
                supervisor.mutex.lock();
                defer supervisor.mutex.unlock();

                supervisor.guest_threads.syncNewThreads() catch |err| {
                    logger.log("fstatat64: syncNewThreads failed: {}", .{err});
                    return replyErr(notif.id, .NOSYS);
                };

                caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                    logger.log("fstatat64: Thread not found for tid={d}: {}", .{ caller_tid, err });
                    return replyErr(notif.id, .SRCH);
                };
            }

            const statx_buf = File.statxByPath(backend, &supervisor.overlay, path, caller) catch |err| {
                logger.log("fstatat64: statx failed for {s}: {s}", .{ path, @errorName(err) });
                return replyErr(notif.id, if (err == error.FileNotFound) .NOENT else .IO);
            };

            return writeStatResponse(notif, statx_buf, statbuf_addr);
        },
    }
}

fn writeStatResponse(notif: linux.SECCOMP.notif, statx_buf: linux.Statx, statbuf_addr: u64) linux.SECCOMP.notif_resp {
    const stat_buf = statxToStat(statx_buf);
    const stat_bytes = std.mem.asBytes(&stat_buf);
    memory_bridge.writeSlice(stat_bytes, @intCast(notif.pid), statbuf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };
    return replySuccess(notif.id, 0);
}
