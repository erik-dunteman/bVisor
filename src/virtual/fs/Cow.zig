const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("../../types.zig");
const KernelFD = types.KernelFD;

const Self = @This();

/// 16-char hex string UUID (from 8 random bytes)
uid: [16]u8,
/// COW root path: "/tmp/.bvisor/sb/<uid>/vfs/cow"
root: [64]u8,
root_len: usize,

/// Generate a random sandbox UID (16-char hex string)
pub fn generateUid() [16]u8 {
    var uid_bytes: [8]u8 = undefined;
    if (builtin.is_test) {
        @memcpy(&uid_bytes, "testtest");
    } else {
        std.crypto.random.bytes(&uid_bytes);
    }
    return std.fmt.bytesToHex(uid_bytes, .lower);
}

/// Initialize COW filesystem with given UUID.
/// Creates directory structure: /tmp/.bvisor/sb/<uid>/vfs/cow/
pub fn init(uid: [16]u8) !Self {

    // Build root path: /tmp/.bvisor/sb/<uid>/vfs/cow
    var root: [64]u8 = undefined;
    const root_slice = std.fmt.bufPrint(&root, "/tmp/.bvisor/sb/{s}/vfs/cow", .{uid}) catch unreachable;
    const root_len = root_slice.len;

    // Create directory structure
    // We create each level separately since makePath isn't available for all dir types
    const dirs = [_][]const u8{
        "/tmp/.bvisor",
        "/tmp/.bvisor/sb",
    };

    for (dirs) |dir| {
        posix.mkdirat(linux.AT.FDCWD, dir, 0o755) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Create the UUID-specific directories
    var buf: [64]u8 = undefined;
    const sb_uid_path = std.fmt.bufPrint(&buf, "/tmp/.bvisor/sb/{s}", .{uid}) catch unreachable;
    posix.mkdirat(linux.AT.FDCWD, sb_uid_path, 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var buf2: [64]u8 = undefined;
    const vfs_path = std.fmt.bufPrint(&buf2, "/tmp/.bvisor/sb/{s}/vfs", .{uid}) catch unreachable;
    posix.mkdirat(linux.AT.FDCWD, vfs_path, 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Create the cow directory
    posix.mkdirat(linux.AT.FDCWD, root_slice, 0o755) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    return .{ .uid = uid, .root = root, .root_len = root_len };
}

/// Cleanup COW directory (optional, could leave for debugging)
pub fn deinit(self: *Self) void {
    // For now, don't delete - useful for debugging
    // In production, would recursively delete self.root
    _ = self;
}

/// Build COW path for a virtual path.
/// Example: "/etc/passwd" -> "/tmp/.bvisor/sb/<uid>/vfs/cow/etc/passwd"
pub fn cowPath(self: *const Self, virtual_path: []const u8, buf: []u8) ![:0]const u8 {
    // Strip leading slash from virtual_path for concatenation
    const path_suffix = if (virtual_path.len > 0 and virtual_path[0] == '/')
        virtual_path[1..]
    else
        virtual_path;

    const root = self.root[0..self.root_len];
    const total_len = root.len + 1 + path_suffix.len; // +1 for /

    if (total_len >= buf.len) return error.PathTooLong;

    @memcpy(buf[0..root.len], root);
    buf[root.len] = '/';
    @memcpy(buf[root.len + 1 ..][0..path_suffix.len], path_suffix);
    buf[total_len] = 0;

    return buf[0..total_len :0];
}

/// Check if COW file exists for virtual path
pub fn exists(self: *const Self, virtual_path: []const u8) bool {
    var buf: [512]u8 = undefined;
    const cow_path = self.cowPath(virtual_path, &buf) catch return false;

    // Try to open the file read-only to check existence
    const fd = posix.openat(linux.AT.FDCWD, cow_path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    posix.close(fd);
    return true;
}

/// Create parent directories for a COW path.
/// For "/etc/passwd", creates "/tmp/.bvisor/sb/<uid>/vfs/cow/etc/"
pub fn createParentDirs(self: *const Self, virtual_path: []const u8) !void {
    var buf: [512]u8 = undefined;
    const cow_path = self.cowPath(virtual_path, &buf) catch return error.PathTooLong;

    // Find last slash to get parent directory
    const last_slash = std.mem.lastIndexOfScalar(u8, cow_path, '/') orelse return;
    if (last_slash == 0) return; // Root directory, nothing to create

    // Create parent directories one by one
    var i: usize = self.root_len + 1; // Start after COW root
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

/// Open or create a COW file.
/// If COW file doesn't exist and original does, copies original to COW first.
pub fn open(self: *const Self, virtual_path: []const u8, flags: linux.O, mode: linux.mode_t) !KernelFD {
    var buf: [512]u8 = undefined;
    const cow_path = self.cowPath(virtual_path, &buf) catch return error.NameTooLong;

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

    // Try to open existing COW file first
    if (posix.openat(linux.AT.FDCWD, cow_path, posix_flags, @truncate(mode))) |fd| {
        return fd;
    } else |err| {
        if (err != error.FileNotFound) return err;
    }

    // COW file doesn't exist - need to create it
    try self.createParentDirs(virtual_path);

    // Check if original file exists and copy it
    // Use null-terminated virtual path
    var vpath_buf: [256]u8 = undefined;
    if (virtual_path.len >= vpath_buf.len) return error.NameTooLong;
    @memcpy(vpath_buf[0..virtual_path.len], virtual_path);
    vpath_buf[virtual_path.len] = 0;
    const vpath_z = vpath_buf[0..virtual_path.len :0];

    if (posix.openat(linux.AT.FDCWD, vpath_z, .{ .ACCMODE = .RDONLY }, 0)) |orig_fd| {
        defer posix.close(orig_fd);

        // Create COW file and copy contents
        const cow_fd = try posix.openat(linux.AT.FDCWD, cow_path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
        }, @truncate(mode));
        errdefer posix.close(cow_fd);

        // Copy original to COW
        var copy_buf: [4096]u8 = undefined;
        while (true) {
            const n = posix.read(orig_fd, &copy_buf) catch |err| {
                posix.close(cow_fd);
                return err;
            };
            if (n == 0) break;

            // Handle partial writes
            var written: usize = 0;
            while (written < n) {
                written += posix.write(cow_fd, copy_buf[written..n]) catch |err| {
                    posix.close(cow_fd);
                    return err;
                };
            }
        }

        // Close and reopen with requested flags
        posix.close(cow_fd);

        // For the reopen, add CREAT since we just created it
        var reopen_flags = posix_flags;
        reopen_flags.CREAT = true;
        return posix.openat(linux.AT.FDCWD, cow_path, reopen_flags, @truncate(mode));
    } else |_| {
        // Original doesn't exist either - just create empty COW file
        var create_flags = posix_flags;
        create_flags.CREAT = true;
        return posix.openat(linux.AT.FDCWD, cow_path, create_flags, @truncate(mode));
    }
}

const testing = std.testing;

test "Cow.init creates directory structure" {
    const uid = generateUid();
    var cow = try Self.init(uid);
    defer cow.deinit();

    try testing.expectEqualStrings("7465737474657374", &cow.uid); // "testtest" as hex

    // Verify root path format
    const root = cow.root[0..cow.root_len];
    try testing.expect(std.mem.startsWith(u8, root, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, root, "/vfs/cow"));
}

test "Cow.cowPath builds correct path" {
    const uid = generateUid();
    var cow = try Self.init(uid);
    defer cow.deinit();

    var buf: [512]u8 = undefined;
    const path = try cow.cowPath("/etc/passwd", &buf);

    try testing.expect(std.mem.startsWith(u8, path, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, path, "/vfs/cow/etc/passwd"));
}

test "Cow.exists returns false for nonexistent file" {
    const uid = generateUid();
    var cow = try Self.init(uid);
    defer cow.deinit();

    try testing.expect(!cow.exists("/nonexistent/path/file.txt"));
}

test "Cow.open creates COW file" {
    const uid = generateUid();
    var cow = try Self.init(uid);
    defer cow.deinit();

    // Open a new file for writing
    const fd = try cow.open("/test_cow_file.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    defer posix.close(fd);

    // Write some data
    _ = try posix.write(fd, "hello cow");

    // Verify COW file now exists
    try testing.expect(cow.exists("/test_cow_file.txt"));

    // Read it back via a new open
    const fd2 = try cow.open("/test_cow_file.txt", .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(fd2);

    var buf: [64]u8 = undefined;
    const n = try posix.read(fd2, &buf);
    try testing.expectEqualStrings("hello cow", buf[0..n]);
}
