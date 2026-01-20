const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("../../types.zig");
const KernelFD = types.KernelFD;

const Self = @This();

/// 16-char hex string UUID (from 8 random bytes)
uid: [16]u8,
/// Private tmp root path: "/tmp/.bvisor/sb/<uid>/tmp"
root: [48]u8,
root_len: usize,

/// Initialize private /tmp with random UUID.
/// Creates directory structure: /tmp/.bvisor/sb/<uid>/tmp/
pub fn init(uid: [16]u8) !Self {
    // Build root path: /tmp/.bvisor/sb/<uid>/tmp
    var root: [48]u8 = undefined;
    const root_slice = std.fmt.bufPrint(&root, "/tmp/.bvisor/sb/{s}/tmp", .{uid}) catch unreachable;
    const root_len = root_slice.len;

    // Create parent directories
    const parents = [_][]const u8{ "/tmp/.bvisor", "/tmp/.bvisor/sb" };
    for (parents) |dir| {
        posix.mkdirat(linux.AT.FDCWD, dir, 0o755) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Create UUID-specific directory
    var sb_uid_buf: [48]u8 = undefined;
    const sb_uid_path = std.fmt.bufPrint(&sb_uid_buf, "/tmp/.bvisor/sb/{s}", .{uid}) catch unreachable;
    posix.mkdirat(linux.AT.FDCWD, sb_uid_path, 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Create the tmp directory
    posix.mkdirat(linux.AT.FDCWD, root_slice, 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    return .{ .uid = uid, .root = root, .root_len = root_len };
}

/// Cleanup private tmp directory (optional)
pub fn deinit(self: *Self) void {
    _ = self;
}

/// Build private path for a /tmp path.
/// Example: "/tmp/foo.txt" -> "/tmp/.bvisor/sb/<uid>/tmp/foo.txt"
/// Input path MUST start with "/tmp"
pub fn privatePath(self: *const Self, tmp_path: []const u8, buf: []u8) ![:0]const u8 {
    // Strip "/tmp" prefix to get the suffix
    const suffix = if (std.mem.startsWith(u8, tmp_path, "/tmp"))
        tmp_path[4..] // everything after "/tmp"
    else
        return error.InvalidPath;

    const root = self.root[0..self.root_len];
    const total_len = root.len + suffix.len;

    if (total_len >= buf.len) return error.PathTooLong;

    @memcpy(buf[0..root.len], root);
    @memcpy(buf[root.len..][0..suffix.len], suffix);
    buf[total_len] = 0;

    return buf[0..total_len :0];
}

/// Create parent directories for a private tmp path.
pub fn createParentDirs(self: *const Self, tmp_path: []const u8) !void {
    var buf: [512]u8 = undefined;
    const private_path = try self.privatePath(tmp_path, &buf);

    // Find last slash to get parent directory
    const last_slash = std.mem.lastIndexOfScalar(u8, private_path, '/') orelse return;
    if (last_slash == 0) return;

    // Create parent directories one by one
    var i: usize = self.root_len + 1;
    while (i < last_slash) {
        if (buf[i] == '/') {
            buf[i] = 0;
            posix.mkdirat(linux.AT.FDCWD, buf[0..i :0], 0o755) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            buf[i] = '/';
        }
        i += 1;
    }

    // Create the final parent directory
    buf[last_slash] = 0;
    posix.mkdirat(linux.AT.FDCWD, buf[0..last_slash :0], 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// Open a file in the private /tmp.
/// All reads and writes are redirected here - no copy-on-write logic.
pub fn open(self: *const Self, tmp_path: []const u8, flags: linux.O, mode: linux.mode_t) !KernelFD {
    var buf: [512]u8 = undefined;
    const private_path = try self.privatePath(tmp_path, &buf);

    // Convert linux.O flags to posix.O flags
    var posix_flags: posix.O = .{};
    posix_flags.ACCMODE = switch (flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };
    if (flags.CREAT) posix_flags.CREAT = true;
    if (flags.EXCL) posix_flags.EXCL = true;
    if (flags.TRUNC) posix_flags.TRUNC = true;
    if (flags.APPEND) posix_flags.APPEND = true;
    if (flags.NONBLOCK) posix_flags.NONBLOCK = true;
    if (flags.CLOEXEC) posix_flags.CLOEXEC = true;
    if (flags.DIRECTORY) posix_flags.DIRECTORY = true;

    // Try to open the file
    if (posix.openat(linux.AT.FDCWD, private_path, posix_flags, @truncate(mode))) |fd| {
        return fd;
    } else |err| {
        // If file not found and we're creating, make parent dirs first
        if (err == error.FileNotFound and flags.CREAT) {
            try self.createParentDirs(tmp_path);
            return posix.openat(linux.AT.FDCWD, private_path, posix_flags, @truncate(mode));
        }
        return err;
    }
}

const testing = std.testing;

test "Tmp.init creates directory" {
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(uid);
    defer tmp.deinit();

    // Verify root path format
    const root = tmp.root[0..tmp.root_len];
    try testing.expect(std.mem.startsWith(u8, root, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, root, "/tmp"));
}

test "Tmp.privatePath builds correct path" {
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(uid);
    defer tmp.deinit();

    var buf: [512]u8 = undefined;
    const path = try tmp.privatePath("/tmp/foo/bar.txt", &buf);

    try testing.expect(std.mem.startsWith(u8, path, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, path, "/tmp/foo/bar.txt"));
}

test "Tmp.privatePath rejects non-tmp paths" {
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(uid);
    defer tmp.deinit();

    var buf: [512]u8 = undefined;
    try testing.expectError(error.InvalidPath, tmp.privatePath("/etc/passwd", &buf));
}

test "Tmp.open creates and reads file" {
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(uid);
    defer tmp.deinit();

    // Open for writing
    const wfd = try tmp.open("/tmp/test_tmp.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    _ = try posix.write(wfd, "private tmp");
    posix.close(wfd);

    // Open for reading
    const rfd = try tmp.open("/tmp/test_tmp.txt", .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(rfd);

    var buf: [64]u8 = undefined;
    const n = try posix.read(rfd, &buf);
    try testing.expectEqualStrings("private tmp", buf[0..n]);
}
