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

test "read from /dev/urandom returns non-zero data" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/urandom", .{ .ACCMODE = .RDONLY }, 0);
    defer file.close();

    var buf: [32]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(32, n);

    // At least some bytes should be non-zero (with overwhelming probability)
    var all_zero = true;
    for (buf[0..n]) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "close releases fd without error" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .RDWR }, 0);
    file.close();
    // No error = success
}

test "multiple reads from /dev/zero return zeroes (infinite source)" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/zero", .{ .ACCMODE = .RDONLY }, 0);
    defer file.close();

    const zeros: [16]u8 = .{0} ** 16;
    var buf: [16]u8 = undefined;

    // First read
    var n = try file.read(&buf);
    try testing.expectEqual(16, n);
    try testing.expectEqualSlices(u8, &zeros, buf[0..n]);

    // Second read
    n = try file.read(&buf);
    try testing.expectEqual(16, n);
    try testing.expectEqualSlices(u8, &zeros, buf[0..n]);
}

test "write then read /dev/null RDWR - write consumed, read EOF" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .RDWR }, 0);
    defer file.close();

    // Write returns the byte count
    const written = try file.write("0123456789");
    try testing.expectEqual(10, written);

    // Read returns 0 (EOF)
    var buf: [16]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(0, n);
}

test "zero-length read from /dev/zero returns 0" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/zero", .{ .ACCMODE = .RDONLY }, 0);
    defer file.close();

    var buf: [0]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqual(0, n);
}

test "zero-length write to /dev/null returns 0" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Passthrough.open(&overlay, "/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    defer file.close();

    const n = try file.write("");
    try testing.expectEqual(0, n);
}
