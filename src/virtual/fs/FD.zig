const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../types.zig");
const Proc = @import("../proc/Proc.zig");

const KernelPID = Proc.KernelPID;

/// Virtual file descriptor - represents a virtualized file.
/// This is a tagged union representing different types of virtual files.
pub const FD = union(enum) {
    kernel: types.KernelFD, // supervisor maintains virtual FDs for every fd, for consistency
    proc: ProcFD, // virtualized proc file
    cow: CowFD, // copy-on-write file, created only if user requests more than read perms

    const Self = @This();

    pub const ProcFD = union(enum) {
        self: struct {
            pid: KernelPID,
            offset: usize = 0,
        },

        pub fn read(self: *ProcFD, buf: []u8) usize {
            switch (self.*) {
                .self => |*s| {
                    var tmp: [16]u8 = undefined;
                    const content = std.fmt.bufPrint(&tmp, "{d}\n", .{s.pid}) catch unreachable;
                    const remaining = content[s.offset..];
                    const n = @min(buf.len, remaining.len);
                    @memcpy(buf[0..n], remaining[0..n]);
                    s.offset += n;
                    return n;
                },
            }
        }
    };

    /// Copy-on-write file descriptor.
    /// The backing_fd points to a file in the COW root directory.
    pub const CowFD = struct {
        backing_fd: types.KernelFD,

        pub fn read(self: *CowFD, buf: []u8) !usize {
            return posix.read(self.backing_fd, buf);
        }

        pub fn write(self: *CowFD, data: []const u8) !usize {
            return posix.write(self.backing_fd, data);
        }

        pub fn close(self: *CowFD) void {
            posix.close(self.backing_fd);
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

    /// Write to the virtual file descriptor
    pub fn write(self: *Self, data: []const u8) !usize {
        switch (self.*) {
            .kernel => |kfd| return posix.write(kfd, data),
            .proc => return error.ReadOnlyFileSystem,
            .cow => |*c| return c.write(data),
        }
    }

    /// Close the virtual file descriptor
    pub fn close(self: *Self) void {
        switch (self.*) {
            .kernel => |kfd| posix.close(kfd),
            .proc => {}, // nothing to close for virtual proc files
            .cow => |*c| c.close(),
        }
    }
};

const testing = std.testing;

test "FD.ProcFD.self read returns pid" {
    var proc_fd: FD.ProcFD = .{ .self = .{ .pid = 42 } };
    var buf: [16]u8 = undefined;
    const n = proc_fd.read(&buf);
    try testing.expectEqualStrings("42\n", buf[0..n]);
}

test "FD.ProcFD.self read tracks offset" {
    var proc_fd: FD.ProcFD = .{ .self = .{ .pid = 123 } };
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
    var fd: FD = .{ .proc = .{ .self = .{ .pid = 7 } } };
    var buf: [16]u8 = undefined;
    const n = try fd.read(&buf);
    try testing.expectEqualStrings("7\n", buf[0..n]);
}
