const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const FdTable = @import("../../fs/FdTable.zig");
const types = @import("../../../types.zig");
const Supervisor = @import("../../../Supervisor.zig");
const SupervisorFD = types.SupervisorFD;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const route = @import("../../path.zig").route;
const File = @import("../../fs/file.zig").File;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const pid: Proc.SupervisorPID = @intCast(notif.pid);

    // Ensure calling process exists
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("openat: process lookup failed for pid: {d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Parse arguments
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path_slice = memory_bridge.readString(
        &path_buf,
        @intCast(notif.pid),
        path_ptr,
    ) catch |err| {
        logger.log("openat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // Only absolute paths supported for now
    const dirfd: SupervisorFD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    _ = dirfd; // dirfd only matters for relative paths
    if (path_slice.len == 0 or path_slice[0] != '/') {
        logger.log("openat: invalid path: {s}, must be absolute", .{path_slice});
        return replyErr(notif.id, .INVAL);
    }

    //todo: implement once File backends are ready
    _ = proc;
    _ = notif.data.arg2; // flags
    _ = notif.data.arg3; // mode
    return replyErr(notif.id, .NOSYS);
}
