const std = @import("std");
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

    pub fn close(self: *Cow) void {
        switch (self.*) {
            .readthrough => |fd| posix.close(fd),
            .writecopy => |fd| posix.close(fd),
        }
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
const builtin = @import("builtin");

const ls_path = if (builtin.os.tag == .linux) "/usr/bin/ls" else "/bin/ls";

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
