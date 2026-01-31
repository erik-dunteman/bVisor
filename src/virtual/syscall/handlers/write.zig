const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Continue in case of stdout or stderr
    // In the future we'll virtualize this ourselves for more control of where logs go
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
        logger.log("write: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file object
    const file = caller.fd_table.get(fd) orelse {
        logger.log("write: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Copy guest process buf to local
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const buf: []u8 = max_buf[0..max_count];
    memory_bridge.readSlice(buf, @intCast(caller_pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    // Write local buf to file
    const n = file.write(buf) catch |err| {
        logger.log("write: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("write: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}
