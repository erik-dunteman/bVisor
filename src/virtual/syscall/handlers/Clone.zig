const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const Self = @This();

parent_pid: Proc.KernelPID,
clone_flags: Procs.CloneFlags,

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    return .{
        .parent_pid = @intCast(notif.pid),
        .clone_flags = Procs.CloneFlags.from(notif.data.arg0),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    _ = self;
    _ = supervisor;
    // Let the kernel execute the clone syscall.
    // Child will be lazily registered when it makes its first syscall,
    // and clone flags will be detected from kernel state via kcmp/ns comparison.
    return .use_kernel;
}

test "parse extracts clone flags" {
    const notif = makeNotif(.clone, .{
        .pid = 100,
        .arg0 = linux.CLONE.NEWPID | linux.CLONE.FILES,
    });

    const parsed = try Self.parse(notif);
    try testing.expectEqual(@as(Proc.KernelPID, 100), parsed.parent_pid);
    try testing.expect(parsed.clone_flags.create_pid_namespace());
    try testing.expect(parsed.clone_flags.share_files());
}

test "handle returns use_kernel" {
    const allocator = testing.allocator;

    const initial_pid = 100;
    var supervisor = try Supervisor.init(allocator, -1, initial_pid);
    defer supervisor.deinit();

    const handler = Self{
        .parent_pid = initial_pid,
        .clone_flags = Procs.CloneFlags.from(linux.CLONE.NEWPID),
    };

    const result = try handler.handle(&supervisor);
    try testing.expect(result == .use_kernel);
}
