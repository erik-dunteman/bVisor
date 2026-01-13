const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Supervisor = @import("../../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const testing = std.testing;
const makeNotif = @import("../../seccomp/notif.zig").makeNotif;

// comptime dependency injection
const deps = @import("../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

dirfd: FD,
path_len: usize,
path_buf: [256]u8, // fixed stack buffer, limits size of string read
flags: linux.O,

pub fn path(self: *const Self) []const u8 {
    return self.path_buf[0..self.path_len];
}

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path_slice = try memory_bridge.readString(
        &path_buf,
        @intCast(notif.pid),
        path_ptr,
    );

    const dirfd: FD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));

    return .{
        .dirfd = dirfd,
        .path_len = path_slice.len,
        .path_buf = path_buf,
        .flags = flags,
    };
}

// Path resolution rules

pub const Action = enum {
    block,
    allow,
    // Special handlers
    virtualize_proc,
};

pub const Rule = union(enum) {
    /// Terminal - this prefix resolves to an action
    terminal: Action,
    /// Branch - check children, with a default if none match
    branch: struct {
        children: []const PathRule,
        default: Action,
    },
};

pub const PathRule = struct {
    prefix: []const u8,
    rule: Rule,
};

/// The root filesystem rules
pub const default_action: Action = .block;
pub const fs_rules: []const PathRule = &.{
    // Hard blocks
    .{ .prefix = "/sys/", .rule = .{ .terminal = .block } },
    .{ .prefix = "/run/", .rule = .{ .terminal = .block } },

    // Virtualized
    .{ .prefix = "/proc/", .rule = .{ .terminal = .virtualize_proc } },
};

/// Resolve a path to an action. Works at comptime or runtime.
pub fn resolve(path_str: []const u8) Action {
    return resolveWithRules(path_str, fs_rules, default_action);
}

fn resolveWithRules(path_str: []const u8, rules: []const PathRule, default: Action) Action {
    for (rules) |rule| {
        if (std.mem.startsWith(u8, path_str, rule.prefix)) {
            const remainder = path_str[rule.prefix.len..];
            switch (rule.rule) {
                .terminal => |action| return action,
                .branch => |branch| {
                    // Recurse into children with remainder
                    return resolveWithRules(remainder, branch.children, branch.default);
                },
            }
        }
    }
    return default;
}

// Comptime validation that rules work
comptime {
    std.debug.assert(resolve("/sys/class/net") == .block);
    std.debug.assert(resolve("/run/docker.sock") == .block);
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating openat: dirfd={d} path={s} flags={any}", .{
        self.dirfd,
        self.path(),
        self.flags,
    });

    const action = resolve(self.path());
    logger.log("Action: {s}", .{@tagName(action)});
    switch (action) {
        .block => {
            logger.log("openat: blocked path: {s}", .{self.path()});
            return .{ .handled = Result.Handled.err(linux.E.PERM) };
        },
        .allow => {
            logger.log("openat: allowed path: {s}", .{self.path()});
            return .{ .passthrough = {} };
        },
        .virtualize_proc => {
            logger.log("openat: virtualizing proc path: {s}", .{self.path()});
            return error.NotImplemented;
        },
    }
}

test "openat" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();
    _ = io;

    var supervisor = Supervisor.init(-1, 0);
    defer supervisor.deinit();

    const flags = linux.O{
        .ACCMODE = .RDONLY,
        .CREAT = true,
    };

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/test.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(flags))),
        .arg3 = 0,
    });

    const parsed = try Self.parse(notif);
    std.debug.print("path: {s}\n", .{parsed.path()});
    try testing.expectEqualStrings("/test.txt", parsed.path());
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}
