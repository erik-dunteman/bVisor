const std = @import("std");
const linux = std.os.linux;
const Proc = @import("../../proc/Proc.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const pid: Proc.AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    // Passthrough stdin/stdout/stderr
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        logger.log("close: passthrough for fd={d}", .{fd});
        return replyContinue(notif.id);
    }

    const proc = supervisor.guest_procs.get(pid) catch |err| {
        logger.log("close: process not found for pid={d}: {}", .{ pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file in the fd table
    const file = proc.fd_table.get(fd) orelse {
        logger.log("close: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Close the file
    file.close();

    // Remove from fd table
    _ = proc.fd_table.remove(fd);

    logger.log("close: closed fd={d}", .{fd});
    return replySuccess(notif.id, 0);
}
