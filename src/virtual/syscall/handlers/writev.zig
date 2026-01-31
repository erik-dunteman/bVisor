const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const SupervisorFD = types.SupervisorFD;
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_pid: Proc.AbsPid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);

    // Continue in case of stdout or stderr
    // In the future we'll virtualize this ourselves for more control of where logs go
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    const caller = supervisor.guest_procs.get(caller_pid) catch |err| {
        logger.log("writev: process not found for pid={d}: {}", .{ caller_pid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file object
    const file = caller.fd_table.get(fd) orelse {
        logger.log("writev: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]posix.iovec_const = undefined;
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec_const);
        iovecs[i] = memory_bridge.read(posix.iovec_const, caller_pid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    // Read buffer data from child memory for each iovec
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            memory_bridge.readSlice(dest, caller_pid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            data_len += buf_len;
        }
    }

    // Write to the file
    const n = file.write(data_buf[0..data_len]) catch |err| {
        logger.log("writev: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("writev: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}
