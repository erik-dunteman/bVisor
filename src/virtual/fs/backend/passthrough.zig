const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

/// Passthrough backend - directly wraps a kernel file descriptor.
/// Used for safe device files like /dev/null, /dev/zero, /dev/urandom.
pub const Passthrough = struct {
    fd: posix.fd_t,

    pub fn open(_: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Passthrough {
        const fd = try posix.open(path, flags, mode);
        return .{ .fd = fd };
    }

    pub fn read(self: *Passthrough, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn write(self: *Passthrough, data: []const u8) !usize {
        return posix.write(self.fd, data);
    }

    pub fn close(self: *Passthrough) void {
        posix.close(self.fd);
    }
};

const testing = std.testing;
const builtin = @import("builtin");

// For testing we use known /dev paths

test "open /dev/null succeeds" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .RDWR }, 0);
    defer file.close();

    try testing.expect(file.fd >= 0);
}

test "write to /dev/null succeeds" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    defer file.close();

    const n = try file.write("hello");
    try testing.expectEqual(5, n);
}

test "read from /dev/null returns 0 (EOF)" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    defer file.close();

    var buf: [16]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(0, n);
}

test "read from /dev/zero returns zeros" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/zero", .{ .ACCMODE = .RDONLY }, 0);
    defer file.close();

    var buf: [16]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(16, n);

    const zeros: [16]u8 = .{0} ** 16;
    try testing.expectEqualSlices(u8, &zeros, buf[0..n]);
}
