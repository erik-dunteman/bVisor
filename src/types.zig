const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");

// File Descriptor
pub const FD = i32;

pub fn LinuxResult(comptime T: type) type {
    return union(enum) {
        Ok: T,
        Error: linux.E,

        const Self = @This();

        pub fn from(result: usize) Self {
            return switch (linux.errno(result)) {
                .SUCCESS => Self{ .Ok = @intCast(result) },
                else => Self{ .Error = linux.errno(result) },
            };
        }

        /// Returns inner value, or throws a general error
        /// If specific error types are needed, prefer to switch on Result then switch on Error branch
        pub fn unwrap(self: Self) !T {
            return switch (self) {
                .Ok => |value| value,
                .Error => |_| error.SyscallFailed, // Some general error
            };
        }
    };
}

pub const Logger = struct {
    const Self = @This();

    pub const Name = enum {
        prefork,
        child,
        supervisor,
    };

    name: Name,

    pub fn init(name: Name) Self {
        return .{ .name = name };
    }

    pub fn log(self: Self, comptime format: []const u8, args: anytype) void {
        // Disable logging during tests to avoid interfering with test runner IPC
        if (builtin.is_test) return;

        var buf: [1024]u8 = undefined;
        const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
        const color = switch (self.name) {
            .prefork => "\x1b[96m",
            .child => "\x1b[92m",
            .supervisor => "\x1b[95m",
        };
        const padding: []const u8 = switch (self.name) {
            .prefork => "      ",
            .child => "        ",
            .supervisor => "   ",
        };

        std.debug.print("{s}[{s}]{s}{s}\x1b[0m\n", .{ color, @tagName(self.name), padding, fmtlog });
    }
};
