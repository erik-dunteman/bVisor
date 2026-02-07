const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

const BackingFD = posix.fd_t;

pub const Cow = union(enum) {
    readthrough: BackingFD,
    writecopy: BackingFD,

    pub fn open(overlay: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Cow {
        const has_write_flags = flags.ACCMODE == .WRONLY or flags.ACCMODE == .RDWR or flags.CREAT or flags.TRUNC;
        const cow_exists = overlay.cowExists(path);

        var cow_path_buf: [512]u8 = undefined;

        if (cow_exists) {
            // COW copy already exists - open it directly
            const cow_path = try overlay.resolveCow(path, &cow_path_buf);
            const cow_fd = try posix.open(cow_path, flags, mode);
            return .{ .writecopy = cow_fd };
        } else if (has_write_flags) {
            // First write to this file - copy original to cow, then open
            const cow_path = try overlay.resolveCow(path, &cow_path_buf);
            try overlay.createCowParentDirs(path);
            try copyFile(path, cow_path);
            const cow_fd = try posix.open(cow_path, flags, mode);
            return .{ .writecopy = cow_fd };
        } else {
            // Read-only, no cow exists - readthrough to original
            const readthrough_fd = try posix.open(path, flags, mode);
            return .{ .readthrough = readthrough_fd };
        }
    }

    pub fn read(self: *Cow, buf: []u8) !usize {
        switch (self.*) {
            .readthrough => |fd| return posix.read(fd, buf),
            .writecopy => |fd| return posix.read(fd, buf),
        }
    }

    pub fn write(self: *Cow, data: []const u8) !usize {
        switch (self.*) {
            .readthrough => return error.ReadOnlyFileSystem,
            .writecopy => |fd| return posix.write(fd, data),
        }
    }

    // Use system.close instead of posix.close: posix.close panics on EBADF,
    // but tests create Files with fake fds that were never opened.
    pub fn close(self: *Cow) void {
        switch (self.*) {
            inline else => |fd| _ = std.posix.system.close(fd),
        }
    }

    pub fn statx(self: *Cow) !linux.Statx {
        var statx_buf: linux.Statx = std.mem.zeroes(linux.Statx);

        const backing_fd = switch (self.*) {
            .readthrough => |fd| fd,
            .writecopy => |fd| fd,
        };

        const rc = linux.statx(
            backing_fd,
            "",
            linux.AT.EMPTY_PATH,
            linux.STATX.BASIC_STATS,
            &statx_buf,
        );
        if (linux.errno(rc) != .SUCCESS) return error.StatxFail;
        return statx_buf;
    }

    pub fn statxByPath(overlay: *OverlayRoot, path: []const u8) !linux.Statx {
        var cow_path_buf: [512]u8 = undefined;
        const real_path = if (overlay.cowExists(path))
            try overlay.resolveCow(path, &cow_path_buf)
        else
            path;

        const fd = try posix.open(real_path, .{ .PATH = true }, 0);
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

/// Copy a file from src to dst using posix calls.
fn copyFile(src: []const u8, dst: []const u8) !void {
    const src_fd = try posix.open(src, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(src_fd);

    const dst_fd = try posix.open(dst, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer posix.close(dst_fd);

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try posix.read(src_fd, &buf);
        if (n == 0) break;
        _ = try posix.write(dst_fd, buf[0..n]);
    }
}

const testing = std.testing;
const ls_path = "/bin/ls";

test "opening /usr/bin/ls opens in readthrough mode" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY }, 0o644);
    defer file.close();

    try testing.expect(file == .readthrough);

    // just read a couple bytes
    var buf: [16]u8 = undefined;
    const n = try file.read(&buf); // ls is more than 16 bytes so n should be full
    try testing.expectEqual(16, n);
}

test "write to readthrough returns error" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY }, 0o644);
    defer file.close();

    // Writing to a readthrough file should fail with ReadOnlyFileSystem
    try testing.expectError(error.ReadOnlyFileSystem, file.write("test"));
}

test "opening /usr/bin/ls for write triggers copy to overlay" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Opening with write flags should trigger COW and return writecopy variant
    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .WRONLY }, 0o644);
    defer file.close();

    try testing.expect(file == .writecopy);

    // Ensure cow path exists
    var cow_path_buf: [512]u8 = undefined;
    const cow_path = try overlay.resolveCow(ls_path, &cow_path_buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/cow{s}", .{ uid, ls_path });
    defer testing.allocator.free(expected);
    try testing.expect(std.fs.path.isAbsolute(cow_path));
    try testing.expectEqualStrings(expected, cow_path);

    // Verify the COW file actually exists on disk
    try std.Io.Dir.accessAbsolute(io, cow_path, .{});
}

test "write to writecopy succeeds and leaves original untouched" {
    const io = testing.io;
    const uid: [16]u8 = "testtesttesttest".*;

    // Use a temp file that we can write to
    const ls_clone_path = "/tmp/bvisor_test_ls_clone";
    try std.Io.Dir.copyFileAbsolute(ls_path, ls_clone_path, io, .{});
    defer std.Io.Dir.deleteFileAbsolute(io, ls_clone_path) catch {};

    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // First, read original content from ls_clone_path
    var original_buf: [16]u8 = undefined;
    {
        var orig_file = try Cow.open(&overlay, ls_clone_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer orig_file.close();
        _ = try orig_file.read(&original_buf);
    }

    // Open for write (creates COW copy) and write to it
    // Overwrites due to TRUNC
    {
        var file = try Cow.open(&overlay, ls_clone_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();

        const written = try file.write("MODIFIED");
        try testing.expectEqual(8, written);
    }

    // Verify original ls_clone_path is unchanged by opening directly
    const original_fd = try posix.open(ls_clone_path, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(original_fd);
    var verify_buf: [16]u8 = undefined;
    _ = try posix.read(original_fd, &verify_buf);
    try testing.expectEqualSlices(u8, &original_buf, &verify_buf);

    // Verify that future attempts to reopen this path, even read will do so as writecopy
    {
        // Write mode (obv should be writecopy)
        var file = try Cow.open(&overlay, ls_clone_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();
        try testing.expect(file == .writecopy);
    }
    {
        // Read mode (should be writecopy because cow exists)
        var file = try Cow.open(&overlay, ls_clone_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer file.close();
        try testing.expect(file == .writecopy);
    }
}

test "read from readthrough returns original file content" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest02".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY }, 0o644);
    defer file.close();

    // Read original content via COW readthrough
    var cow_buf: [16]u8 = undefined;
    const cow_n = try file.read(&cow_buf);

    // Read original directly for comparison
    const orig_fd = try posix.open(ls_path, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(orig_fd);
    var orig_buf: [16]u8 = undefined;
    const orig_n = try posix.read(orig_fd, &orig_buf);

    try testing.expectEqual(orig_n, cow_n);
    try testing.expectEqualSlices(u8, orig_buf[0..orig_n], cow_buf[0..cow_n]);
}

test "close readthrough completes without error" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest03".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY }, 0o644);
    file.close();
    // No error = success
}

test "read from writecopy after write+reopen returns modified content" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest06".*;

    const src_path = "/tmp/bvisor_test_cow06";
    {
        const fd = try posix.open(src_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer posix.close(fd);
        _ = try posix.write(fd, "original content");
    }
    defer std.Io.Dir.deleteFileAbsolute(io, src_path) catch {};

    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Open for write, modify
    {
        var file = try Cow.open(&overlay, src_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();
        _ = try file.write("modified content");
    }

    // Reopen RDONLY and verify modified content
    {
        var file = try Cow.open(&overlay, src_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer file.close();
        var buf: [64]u8 = undefined;
        const n = try file.read(&buf);
        try testing.expectEqualStrings("modified content", buf[0..n]);
    }
}

test "successive write opens accumulate on single COW copy" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest10".*;

    const src_path = "/tmp/bvisor_test_cow10";
    {
        const fd = try posix.open(src_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer posix.close(fd);
        _ = try posix.write(fd, "initial");
    }
    defer std.Io.Dir.deleteFileAbsolute(io, src_path) catch {};

    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // First write creates COW, truncates, writes "first"
    {
        var file = try Cow.open(&overlay, src_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();
        _ = try file.write("first");
    }

    // Second write opens existing COW, truncates, writes "second"
    {
        var file = try Cow.open(&overlay, src_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer file.close();
        _ = try file.write("second");
    }

    // Read back shows "second" (accumulated/replaced on same copy)
    {
        var file = try Cow.open(&overlay, src_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer file.close();
        var buf: [64]u8 = undefined;
        const n = try file.read(&buf);
        try testing.expectEqualStrings("second", buf[0..n]);
    }
}

test "O_WRONLY triggers COW" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest11".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .WRONLY }, 0o644);
    defer file.close();
    try testing.expect(file == .writecopy);
}

test "O_RDWR triggers COW" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest12".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDWR }, 0o644);
    defer file.close();
    try testing.expect(file == .writecopy);
}

test "O_CREAT triggers COW" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest13".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY, .CREAT = true }, 0o644);
    defer file.close();
    try testing.expect(file == .writecopy);
}

test "O_TRUNC triggers COW" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest14".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY, .TRUNC = true }, 0o644);
    defer file.close();
    try testing.expect(file == .writecopy);
}

test "O_RDONLY alone stays readthrough" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest15".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var file = try Cow.open(&overlay, ls_path, .{ .ACCMODE = .RDONLY }, 0o644);
    defer file.close();
    try testing.expect(file == .readthrough);
}

test "open non-existent file RDONLY returns ENOENT" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest17".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    const result = Cow.open(&overlay, "/nonexistent/path/file.txt", .{ .ACCMODE = .RDONLY }, 0o644);
    try testing.expectError(error.FileNotFound, result);
}

test "open non-existent file WRONLY without CREAT fails" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest18".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    const result = Cow.open(&overlay, "/nonexistent/path/file.txt", .{ .ACCMODE = .WRONLY }, 0o644);
    try testing.expectError(error.FileNotFound, result);
}

test "COW open deep path creates parent dirs in overlay" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest19".*;

    // Create a deep source file
    const deep_path = "/tmp/bvisor_test_cow19_src";
    {
        const fd = try posix.open(deep_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer posix.close(fd);
        _ = try posix.write(fd, "deep content");
    }
    defer std.Io.Dir.deleteFileAbsolute(io, deep_path) catch {};

    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    // Opening for write should create cow parent dirs automatically
    var file = try Cow.open(&overlay, deep_path, .{ .ACCMODE = .WRONLY }, 0o644);
    defer file.close();

    // Verify the cow file exists
    var buf: [512]u8 = undefined;
    const cow_path = try overlay.resolveCow(deep_path, &buf);
    try std.Io.Dir.accessAbsolute(io, cow_path, .{});
}

test "cow path resolution /etc/passwd -> overlay/cow/etc/passwd" {
    const io = testing.io;
    const uid: [16]u8 = "cowtestcowtest21".*;
    var overlay = try OverlayRoot.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveCow("/etc/passwd", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/cow/etc/passwd", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}

test "two overlays COW same path -> independent copies, original untouched" {
    const io = testing.io;
    const uid_a: [16]u8 = "cowtestcowtest2A".*;
    const uid_b: [16]u8 = "cowtestcowtest2B".*;

    const src_path = "/tmp/bvisor_test_cow22";
    {
        const fd = try posix.open(src_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer posix.close(fd);
        _ = try posix.write(fd, "original");
    }
    defer std.Io.Dir.deleteFileAbsolute(io, src_path) catch {};

    var overlay_a = try OverlayRoot.init(io, uid_a);
    defer overlay_a.deinit();
    var overlay_b = try OverlayRoot.init(io, uid_b);
    defer overlay_b.deinit();

    // Write different content in each overlay
    {
        var fa = try Cow.open(&overlay_a, src_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer fa.close();
        _ = try fa.write("from A");
    }
    {
        var fb = try Cow.open(&overlay_b, src_path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0o644);
        defer fb.close();
        _ = try fb.write("from B");
    }

    // Read back from each overlay
    var buf: [64]u8 = undefined;
    {
        var fa = try Cow.open(&overlay_a, src_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer fa.close();
        const n = try fa.read(&buf);
        try testing.expectEqualStrings("from A", buf[0..n]);
    }
    {
        var fb = try Cow.open(&overlay_b, src_path, .{ .ACCMODE = .RDONLY }, 0o644);
        defer fb.close();
        const n = try fb.read(&buf);
        try testing.expectEqualStrings("from B", buf[0..n]);
    }

    // Verify original is untouched
    {
        const fd = try posix.open(src_path, .{ .ACCMODE = .RDONLY }, 0);
        defer posix.close(fd);
        const n = try posix.read(fd, &buf);
        try testing.expectEqualStrings("original", buf[0..n]);
    }
}
