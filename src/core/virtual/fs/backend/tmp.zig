const std = @import("std");
const linux = std.os.linux;
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

    // Use system.close instead of posix.close: posix.close panics on EBADF,
    // but tests create Files with fake fds that were never opened.
    pub fn close(self: *Tmp) void {
        _ = std.posix.system.close(self.fd);
    }

    pub fn statx(self: *Tmp) !linux.Statx {
        var statx_buf: linux.Statx = std.mem.zeroes(linux.Statx);

        const rc = linux.statx(
            self.fd,
            "",
            linux.AT.EMPTY_PATH,
            linux.STATX.BASIC_STATS,
            &statx_buf,
        );
        if (linux.errno(rc) != .SUCCESS) return error.StatxFail;
        return statx_buf;
    }

    pub fn statxByPath(overlay: *OverlayRoot, path: []const u8) !linux.Statx {
        var resolve_buf: [512]u8 = undefined;
        const resolved = try overlay.resolveTmp(path, &resolve_buf);

        const fd = try posix.open(resolved, .{ .PATH = true }, 0);
        defer posix.close(fd);

        var statx_buf: linux.Statx = std.mem.zeroes(linux.Statx);
        const rc = linux.statx(
            fd,
            "",
            linux.AT.EMPTY_PATH,
            linux.STATX.BASIC_STATS,
            &statx_buf,
        );
        if (linux.errno(rc) != .SUCCESS) return error.StatxFail;
        return statx_buf;
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

test "sandbox B cannot see sandbox A's /tmp files" {
    const io = testing.io;
    const uid_a: [16]u8 = "tmptesttmptest5A".*;
    const uid_b: [16]u8 = "tmptesttmptest5B".*;

    var overlay_a = try OverlayRoot.init(io, uid_a);
    defer overlay_a.deinit();
    var overlay_b = try OverlayRoot.init(io, uid_b);
    defer overlay_b.deinit();

    // A creates a file
    {
        var fa = try Tmp.open(&overlay_a, "/tmp/secret.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer fa.close();
        _ = try fa.write("secret data");
    }

    // B tries to open it RDONLY (no CREAT) - should get file-not-found
    const result = Tmp.open(&overlay_b, "/tmp/secret.txt", .{ .ACCMODE = .RDONLY }, 0);
    try testing.expectError(error.FileNotFound, result);
}

test "resolveTmp on non-/tmp path returns InvalidPath" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest07".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    try testing.expectError(error.InvalidPath, overlay.resolveTmp("/etc/passwd", &buf));
}

test "fresh sandbox open /tmp/anything RDONLY without CREAT fails" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest08".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    const result = Tmp.open(&overlay, "/tmp/anything", .{ .ACCMODE = .RDONLY }, 0);
    try testing.expectError(error.FileNotFound, result);
}

test "overwrite existing tmp file with TRUNC" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest09".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Write "first"
    {
        var file = try Tmp.open(&overlay, "/tmp/overwrite.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer file.close();
        _ = try file.write("first");
    }

    // Overwrite with "second"
    {
        var file = try Tmp.open(&overlay, "/tmp/overwrite.txt", .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();
        _ = try file.write("second");
    }

    // Read back
    {
        var file = try Tmp.open(&overlay, "/tmp/overwrite.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer file.close();
        var buf: [64]u8 = undefined;
        const n = try file.read(&buf);
        try testing.expectEqualStrings("second", buf[0..n]);
    }
}

test "zero-length write to tmp returns 0" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest10".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Tmp.open(&overlay, "/tmp/empty.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer file.close();

    const n = try file.write("");
    try testing.expectEqual(0, n);
}

test "multiple files in /tmp are independent" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest03".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Create two files with different content
    {
        var f1 = try Tmp.open(&overlay, "/tmp/file1.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer f1.close();
        _ = try f1.write("content1");
    }
    {
        var f2 = try Tmp.open(&overlay, "/tmp/file2.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer f2.close();
        _ = try f2.write("content2");
    }

    // Read back and verify independence
    var buf: [64]u8 = undefined;
    {
        var f1 = try Tmp.open(&overlay, "/tmp/file1.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer f1.close();
        const n = try f1.read(&buf);
        try testing.expectEqualStrings("content1", buf[0..n]);
    }
    {
        var f2 = try Tmp.open(&overlay, "/tmp/file2.txt", .{ .ACCMODE = .RDONLY }, 0);
        defer f2.close();
        const n = try f2.read(&buf);
        try testing.expectEqualStrings("content2", buf[0..n]);
    }
}

test "resolveTmp maps /tmp/foo to overlay tmp dir" {
    const io = testing.io;
    const uid: [16]u8 = "tmptesttmptest06".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveTmp("/tmp/foo", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/tmp/foo", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}
