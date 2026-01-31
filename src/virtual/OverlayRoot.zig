const std = @import("std");
const posix = std.posix;

const Self = @This();

uid: [16]u8,
root_path_buf: [root_fmt_str.len + 16]u8,
root_path_len: usize,
root_dir: std.Io.Dir,
io: std.Io,

const root_fmt_str = "/tmp/.bvisor/sb/{s}";
const subdirs = .{ "cow", "tmp" };

/// Returns the root path as a slice.
pub fn rootPath(self: *const Self) []const u8 {
    return self.root_path_buf[0..self.root_path_len];
}

pub fn init(io: std.Io, uid: [16]u8) !Self {
    var self = Self{
        .uid = uid,
        .root_path_buf = undefined,
        .root_path_len = 0,
        .root_dir = undefined,
        .io = io,
    };
    const path = std.fmt.bufPrint(&self.root_path_buf, root_fmt_str, .{uid}) catch return error.NameTooLong;
    self.root_path_len = path.len;
    self.root_dir = try std.Io.Dir.cwd().createDirPathOpen(io, path, .{});

    inline for (subdirs) |subdir| {
        _ = try self.root_dir.createDirPathOpen(io, subdir, .{});
    }

    return self;
}

pub fn deinit(self: *Self) void {
    self.root_dir.close(self.io);
    const parent_dir = std.Io.Dir.openDirAbsolute(self.io, "/tmp/.bvisor/sb", .{}) catch return;
    defer parent_dir.close(self.io);
    parent_dir.deleteTree(self.io, &self.uid) catch |err| {
        std.debug.print("Warning: Failed to delete overlay root: {s}\n", .{@errorName(err)});
    };
}

/// Creates necessary parent directories when copying to COW
/// eg open /usr/bin/ls for write should populate sandbox's cow dir with /usr/bin
pub fn createCowParentDirs(self: *Self, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    const relative_parent = if (parent.len > 0 and parent[0] == '/') parent[1..] else parent;
    if (relative_parent.len == 0) return;
    var subpath_buf: [512]u8 = undefined;
    const subpath = std.fmt.bufPrint(&subpath_buf, "cow/{s}", .{relative_parent}) catch return error.NameTooLong;
    self.root_dir.createDirPath(self.io, subpath) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// Resolves a path to its COW overlay location.
/// e.g., /usr/bin/ls -> {root_path}/cow/usr/bin/ls
pub fn resolveCow(self: *const Self, path: []const u8, buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/cow{s}", .{ self.rootPath(), path }) catch error.NameTooLong;
}

/// Resolves a path to its tmp overlay location.
/// e.g., /tmp/foo -> {root_path}/tmp/foo (strips /tmp prefix)
pub fn resolveTmp(self: *const Self, path: []const u8, buf: []u8) ![]const u8 {
    const tmp_prefix = "/tmp";
    if (!std.mem.startsWith(u8, path, tmp_prefix)) {
        return error.InvalidPath;
    }
    // Strip /tmp prefix: /tmp/foo -> /foo, then format as {root_path}/tmp/foo
    const suffix = path[tmp_prefix.len..];
    return std.fmt.bufPrint(buf, "{s}/tmp{s}", .{ self.rootPath(), suffix }) catch error.NameTooLong;
}

/// Checks if a COW copy exists for the given path.
pub fn cowExists(self: *const Self, path: []const u8) bool {
    var buf: [512]u8 = undefined;
    const cow_path = self.resolveCow(path, &buf) catch return false;
    // Try to open the file - if it succeeds, it exists
    const fd = posix.open(cow_path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    posix.close(fd);
    return true;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "init creates cow and tmp subdirectories" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0001".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    // Verify cow subdir exists
    var cow_buf: [512]u8 = undefined;
    const cow_dir = std.fmt.bufPrint(&cow_buf, "{s}/cow", .{overlay.rootPath()}) catch unreachable;
    try std.Io.Dir.accessAbsolute(io, cow_dir, .{});

    // Verify tmp subdir exists
    var tmp_buf: [512]u8 = undefined;
    const tmp_dir = std.fmt.bufPrint(&tmp_buf, "{s}/tmp", .{overlay.rootPath()}) catch unreachable;
    try std.Io.Dir.accessAbsolute(io, tmp_dir, .{});
}

test "root path formatted as /tmp/.bvisor/sb/{uid}" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0002".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, overlay.rootPath());
}

test "resolveCow maps /etc/passwd to overlay cow dir" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0003".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveCow("/etc/passwd", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/cow/etc/passwd", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}

test "resolveTmp maps /tmp/myfile to overlay tmp dir" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0004".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    const resolved = try overlay.resolveTmp("/tmp/myfile", &buf);
    const expected = try std.fmt.allocPrint(testing.allocator, "/tmp/.bvisor/sb/{s}/tmp/myfile", .{uid});
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, resolved);
}

test "resolveTmp on non-/tmp path returns InvalidPath" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0005".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    var buf: [512]u8 = undefined;
    try testing.expectError(error.InvalidPath, overlay.resolveTmp("/etc/passwd", &buf));
}

test "cowExists before any COW returns false" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0006".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    try testing.expect(!overlay.cowExists("/etc/passwd"));
}

test "cowExists after creating COW copy returns true" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0007".*;
    var overlay = try Self.init(io, uid);
    defer overlay.deinit();

    // Manually create a cow file to simulate copyFile
    try overlay.createCowParentDirs("/etc/passwd");
    var buf: [512]u8 = undefined;
    const cow_path = try overlay.resolveCow("/etc/passwd", &buf);
    const fd = try posix.open(cow_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    posix.close(fd);

    try testing.expect(overlay.cowExists("/etc/passwd"));
}

test "deinit deletes root directory tree" {
    const io = testing.io;
    const uid: [16]u8 = "ovtestovtest0008".*;
    var overlay = try Self.init(io, uid);

    // Capture root path before deinit
    var root_buf: [128]u8 = undefined;
    const root_len = overlay.rootPath().len;
    @memcpy(root_buf[0..root_len], overlay.rootPath());
    const saved_root = root_buf[0..root_len];

    overlay.deinit();

    // Root should no longer exist
    const access_result = std.Io.Dir.accessAbsolute(io, saved_root, .{});
    try testing.expectError(error.FileNotFound, access_result);
}
