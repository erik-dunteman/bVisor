const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

pub const Tmp = struct {
    fd: posix.fd_t,

    pub fn open(overlay: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Tmp {
        var buf: [512]u8 = undefined;
        const resolved = try overlay.resolveTmp(path, &buf);
        const fd = try posix.open(resolved, flags, mode);
        return .{ .fd = fd };
    }

    pub fn read(self: *Tmp, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn write(self: *Tmp, data: []const u8) !usize {
        return posix.write(self.fd, data);
    }

    pub fn close(self: *Tmp) void {
        posix.close(self.fd);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "create, write, and read back a file" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest01".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Write
    {
        var file = try Tmp.open(&overlay, "/tmp/test.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer file.close();
        const n = try file.write("hello tmp");
        try testing.expectEqual(9, n);
    }

    // Read back
    {
        var file = try Tmp.open(&overlay, "/tmp/test.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer file.close();
        var buf: [64]u8 = undefined;
        const n = try file.read(&buf);
        try testing.expectEqualStrings("hello tmp", buf[0..n]);
    }
}

test "two overlays have isolated /tmp" {
    const io = testing.io;
    const uid_a: [16]u8 = "tmptesttmptest0A".*;
    const uid_b: [16]u8 = "tmptesttmptest0B".*;

    var overlay_a = try OverlayRoot.init(io, uid_a);
    defer overlay_a.deinit();
    var overlay_b = try OverlayRoot.init(io, uid_b);
    defer overlay_b.deinit();

    // Write different content to /tmp/test.txt in each overlay
    {
        var fa = try Tmp.open(&overlay_a, "/tmp/test.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer fa.close();
        _ = try fa.write("from A");
    }
    {
        var fb = try Tmp.open(&overlay_b, "/tmp/test.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer fb.close();
        _ = try fb.write("from B");
    }

    // Read back and verify isolation
    var buf: [64]u8 = undefined;
    {
        var fa = try Tmp.open(&overlay_a, "/tmp/test.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer fa.close();
        const n = try fa.read(&buf);
        try testing.expectEqualStrings("from A", buf[0..n]);
    }
    {
        var fb = try Tmp.open(&overlay_b, "/tmp/test.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer fb.close();
        const n = try fb.read(&buf);
        try testing.expectEqualStrings("from B", buf[0..n]);
    }
}
