const std = @import("std");
const linux = std.os.linux;

/// Convenience function for creating synthetic notifs for testing
pub fn makeNotif(syscall_nr: linux.SYS, args: struct {
    pid: linux.pid_t = 0,
    arg0: u64 = 0,
    arg1: u64 = 0,
    arg2: u64 = 0,
    arg3: u64 = 0,
}) linux.SECCOMP.notif {
    var notif = std.mem.zeroes(linux.SECCOMP.notif);
    notif.id = 1;
    notif.pid = @bitCast(args.pid);
    notif.data.nr = @intCast(@intFromEnum(syscall_nr));
    notif.data.arg0 = args.arg0;
    notif.data.arg1 = args.arg1;
    notif.data.arg2 = args.arg2;
    notif.data.arg3 = args.arg3;
    return notif;
}

pub fn replyContinue(id: u64) linux.SECCOMP.notif_resp {
    std.debug.print("Continuing syscall\n", .{});
    return .{
        .id = id,
        .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
        .val = 0,
        .@"error" = 0,
    };
}

pub fn replySuccess(id: u64, val: i64) linux.SECCOMP.notif_resp {
    std.debug.print("Success: {d}\n", .{val});
    return .{
        .id = id,
        .flags = 0,
        .val = val,
        .@"error" = 0,
    };
}

pub fn replyErr(id: u64, err: linux.E) linux.SECCOMP.notif_resp {
    std.debug.print("Error: {s}\n", .{@tagName(err)});
    return .{
        .id = id,
        .flags = 0,
        .val = 0,
        .@"error" = @intFromEnum(err),
    };
}

pub fn isError(resp: linux.SECCOMP.notif_resp) bool {
    return resp.@"error" != 0;
}

pub fn isContinue(resp: linux.SECCOMP.notif_resp) bool {
    return resp.flags == linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE;
}
