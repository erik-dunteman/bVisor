const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../types.zig");
const Namespace = @import("../proc/Namespace.zig");

const VirtualPID = Namespace.VirtualPID;

/// Virtual file descriptor - represents a virtualized file.
/// This is a tagged union representing different types of virtual files.
pub const FD = union(enum) {
    kernel: types.KernelFD, // supervisor maintains virtual FDs for every fd, for consistency
    proc: Proc, // virtualized proc file
    cow: Cow, // copy-on-write file, created only if user requests more than read perms

    const Self = @This();

    pub const Proc = union(enum) {
        self: struct {
            vpid: VirtualPID,
            offset: usize = 0,
        },

        pub fn read(self: *Proc, buf: []u8) usize {
            switch (self.*) {
                .self => |*s| {
                    var tmp: [16]u8 = undefined;
                    const content = std.fmt.bufPrint(&tmp, "{d}\n", .{s.vpid}) catch unreachable;
                    const remaining = content[s.offset..];
                    const n = @min(buf.len, remaining.len);
                    @memcpy(buf[0..n], remaining[0..n]);
                    s.offset += n;
                    return n;
                },
            }
        }
    };

    pub const Cow = struct {
        mount_path: []const u8,
        backing_fd: types.KernelFD, // hidden from user, the actual FD
        offset: usize = 0,

        pub fn read(self: *Cow, buf: []u8) !usize {
            _ = self;
            _ = buf;
            return error.NotImplemented;
        }
    };

    /// Read from the virtual file descriptor
    pub fn read(self: *Self, buf: []u8) !usize {
        switch (self.*) {
            .kernel => |kfd| return posix.read(kfd, buf),
            .proc => |*p| return p.read(buf),
            .cow => |*c| return c.read(buf),
        }
    }
};

const testing = std.testing;

test "FD.Proc.self read returns vpid" {
    var proc_fd: FD.Proc = .{ .self = .{ .vpid = 42 } };
    var buf: [16]u8 = undefined;
    const n = proc_fd.read(&buf);
    try testing.expectEqualStrings("42\n", buf[0..n]);
}

test "FD.Proc.self read tracks offset" {
    var proc_fd: FD.Proc = .{ .self = .{ .vpid = 123 } };
    var buf: [2]u8 = undefined;

    const n1 = proc_fd.read(&buf);
    try testing.expectEqual(2, n1);
    try testing.expectEqualStrings("12", buf[0..n1]);

    const n2 = proc_fd.read(&buf);
    try testing.expectEqual(2, n2);
    try testing.expectEqualStrings("3\n", buf[0..n2]);

    const n3 = proc_fd.read(&buf);
    try testing.expectEqual(0, n3);
}

test "FD union read dispatches to proc" {
    var fd: FD = .{ .proc = .{ .self = .{ .vpid = 7 } } };
    var buf: [16]u8 = undefined;
    const n = try fd.read(&buf);
    try testing.expectEqualStrings("7\n", buf[0..n]);
}
