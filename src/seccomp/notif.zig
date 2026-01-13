const std = @import("std");
const linux = std.os.linux;

/// Convenience function for creating synthetic notifs for testing
pub fn makeNotif(syscall_nr: linux.SYS, args: struct { arg0: u64 = 0, arg1: u64 = 0, arg2: u64 = 0, arg3: u64 = 0 }) linux.SECCOMP.notif {
    var notif = std.mem.zeroes(linux.SECCOMP.notif);
    notif.id = 1;
    notif.data.nr = @intCast(@intFromEnum(syscall_nr));
    notif.data.arg0 = args.arg0;
    notif.data.arg1 = args.arg1;
    notif.data.arg2 = args.arg2;
    notif.data.arg3 = args.arg3;
    return notif;
}
