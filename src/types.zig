const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub fn LinuxResult(comptime T: type) type {
    return union(enum) {
        Ok: T,
        Error: linux.E,

        const Self = @This();

        pub fn from(result: usize) Self {
            const err = linux.errno(result);
            if (err != .SUCCESS) {
                return Self{ .Error = err };
            }
            // Type-specific success value handling
            const ok_value: T = switch (@typeInfo(T)) {
                .bool => true,
                .void => {},
                else => @intCast(result),
            };
            return Self{ .Ok = ok_value };
        }

        /// Returns inner value, or throws a general error
        /// If specific error types are needed, prefer to switch on Result then switch on Error branch
        pub fn unwrap(self: Self) !T {
            return switch (self) {
                .Ok => |value| value,
                .Error => |_| error.SyscallFailed,
            };
        }
    };
}

pub const Logger = struct {
    pub const Name = enum {
        prefork,
        guest,
        supervisor,
    };

    name: Name,

    pub fn init(name: Name) @This() {
        return .{ .name = name };
    }

    pub fn log(self: @This(), comptime format: []const u8, args: anytype) void {
        if (builtin.is_test) return;

        var buf: [1024]u8 = undefined;
        const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
        const color = switch (self.name) {
            .prefork => "\x1b[96m",
            .guest => "\x1b[92m",
            .supervisor => "\x1b[95m",
        };
        const padding: []const u8 = switch (self.name) {
            .prefork => "      ",
            .guest => "        ",
            .supervisor => "   ",
        };

        std.debug.print("{s}[{s}]{s}{s}\x1b[0m\n", .{ color, @tagName(self.name), padding, fmtlog });
    }
};
