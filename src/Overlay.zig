const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const types = @import("types.zig");
const FD = types.FD;

const Self = @This();

const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const O_DIRECTORY: u32 = 0o200000;

/// Where a FD's data lives
pub const OpenFile = struct {
    file: ?File, // null for directories
    path: []const u8, // owned
    offset: usize,
    flags: u32,
    in_overlay: bool, // true if file is in overlay (can write)
    is_directory: bool, // true if this is a directory FD
};

allocator: std.mem.Allocator,
io: Io,
/// Session ID (hex string)
session_id: [32]u8,
/// Overlay root directory handle
overlay_root: ?Dir,
/// Open file descriptors
open_fds: std.AutoHashMap(FD, OpenFile),
next_fd: FD = 3, // 0,1,2 are stdio

/// Creates a new overlay with a random session ID.
/// The overlay directory is created at /tmp/bvisor-<session>/root/
pub fn init(allocator: std.mem.Allocator, io: Io) Self {
    // Generate random session ID
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    // Convert to hex using bytesToHex
    const session_id = std.fmt.bytesToHex(random_bytes, .lower);

    return .{
        .allocator = allocator,
        .io = io,
        .session_id = session_id,
        .overlay_root = null,
        .open_fds = std.AutoHashMap(FD, OpenFile).init(allocator),
    };
}

/// Ensures the overlay directory exists and returns the root Dir handle.
pub fn ensureOverlayRoot(self: *Self) !Dir {
    if (self.overlay_root) |root| return root;

    // Build path: /tmp/bvisor-<session>/root
    var path_buf: [128]u8 = undefined;
    const overlay_path = std.fmt.bufPrint(&path_buf, "/tmp/bvisor-{s}/root", .{self.session_id}) catch return error.PathTooLong;

    // Create the full path (including parent dirs)
    Dir.createDirPath(.cwd(), self.io, overlay_path) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.OverlaySetupFailed,
    };

    // Open the directory
    self.overlay_root = Dir.openDirAbsolute(self.io, overlay_path, .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.OverlaySetupFailed,
    };

    return self.overlay_root.?;
}

/// Get the overlay path for a given virtual path.
/// Virtual path "/foo/bar" -> overlay subpath "foo/bar" (strip leading /)
pub fn overlaySubpath(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') {
        return path[1..];
    }
    return path;
}

/// Check if a file exists in the overlay directory (including broken symlinks).
pub fn existsInOverlay(self: *Self, path: []const u8) bool {
    const root = self.ensureOverlayRoot() catch return false;
    const subpath = overlaySubpath(path);
    if (subpath.len == 0) return true; // root always exists

    // Don't follow symlinks - we want to check if the path itself exists
    root.access(self.io, subpath, .{ .follow_symlinks = false }) catch return false;
    return true;
}

/// Check if a file exists on the host filesystem.
pub fn existsOnHost(self: *Self, path: []const u8) bool {
    if (!std.fs.path.isAbsolute(path)) return false;
    Dir.accessAbsolute(self.io, path, .{}) catch return false;
    return true;
}

/// Get the full overlay filesystem path for a virtual path.
/// Writes to provided buffer and returns slice, or null if buffer too small.
pub fn getOverlayPath(self: *Self, virtual_path: []const u8, out_buf: []u8) ?[]const u8 {
    _ = self.ensureOverlayRoot() catch return null;

    const subpath = overlaySubpath(virtual_path);

    if (subpath.len == 0) {
        // Just the overlay root
        const overlay_base = std.fmt.bufPrint(out_buf, "/tmp/bvisor-{s}/root", .{self.session_id}) catch return null;
        return overlay_base;
    }

    // Build full path: /tmp/bvisor-<session>/root/<subpath>
    const result = std.fmt.bufPrint(out_buf, "/tmp/bvisor-{s}/root/{s}", .{ self.session_id, subpath }) catch return null;
    return result;
}

/// Open a file or directory. Implements COW semantics:
/// 1. If file exists in overlay, open from overlay
/// 2. If reading and file exists on host, open from host
/// 3. If writing and file exists on host, copy to overlay first (COW)
/// 4. If creating, create in overlay
pub fn open(self: *Self, path: []const u8, flags: u32, mode: u32) !FD {
    _ = mode; // TODO: use for file permissions

    // Handle directory opens (O_DIRECTORY flag or path is a directory)
    const is_dir_open = (flags & O_DIRECTORY) != 0 or self.isDirectory(path);
    if (is_dir_open) {
        return self.openDirectory(path, flags);
    }

    const access_mode = flags & O_ACCMODE;
    const wants_write = access_mode == O_WRONLY or access_mode == O_RDWR or (flags & O_CREAT) != 0;

    // Check overlay first
    if (self.existsInOverlay(path)) {
        return self.openFromOverlay(path, flags);
    }

    // Not in overlay
    if (!wants_write) {
        // Read-only: open from host if it exists
        if (self.existsOnHost(path)) {
            return self.openFromHost(path, flags);
        }
        return error.FileNotFound;
    }

    // Write access requested
    if (self.existsOnHost(path)) {
        // COW: copy host file to overlay, then open from overlay
        try self.copyToOverlay(path);
        return self.openFromOverlay(path, flags);
    }

    // Creating new file in overlay
    if ((flags & O_CREAT) != 0) {
        return self.createInOverlay(path, flags);
    }

    return error.FileNotFound;
}

/// Open a directory (for getdents64)
fn openDirectory(self: *Self, path: []const u8, flags: u32) !FD {
    // Verify directory exists
    if (!self.existsInOverlay(path) and !self.existsOnHost(path)) {
        return error.FileNotFound;
    }

    const owned_path = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(owned_path);

    const fd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(fd, .{
        .file = null, // No file handle for directories
        .path = owned_path,
        .offset = 0,
        .flags = flags,
        .in_overlay = self.existsInOverlay(path),
        .is_directory = true,
    });

    return fd;
}

fn openFromOverlay(self: *Self, path: []const u8, flags: u32) !FD {
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    const access_mode = flags & O_ACCMODE;
    const file_flags: File.OpenFlags = .{
        .mode = switch (access_mode) {
            O_RDONLY => .read_only,
            O_WRONLY => .write_only,
            O_RDWR => .read_write,
            else => .read_only,
        },
    };

    const file = root.openFile(self.io, subpath, file_flags) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.AccessDenied, error.PermissionDenied => return error.PermissionDenied,
        error.Canceled => return error.Canceled,
        else => return error.OpenFailed,
    };

    const owned_path = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(owned_path);

    const fd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(fd, .{
        .file = file,
        .path = owned_path,
        .offset = 0,
        .flags = flags,
        .in_overlay = true,
        .is_directory = false,
    });

    return fd;
}

fn openFromHost(self: *Self, path: []const u8, flags: u32) !FD {
    const access_mode = flags & O_ACCMODE;
    const file_flags: File.OpenFlags = .{
        .mode = switch (access_mode) {
            O_RDONLY => .read_only,
            O_WRONLY => .write_only,
            O_RDWR => .read_write,
            else => .read_only,
        },
    };

    const file = Dir.openFileAbsolute(self.io, path, file_flags) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.AccessDenied, error.PermissionDenied => return error.PermissionDenied,
        error.Canceled => return error.Canceled,
        else => return error.OpenFailed,
    };

    const owned_path = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(owned_path);

    const fd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(fd, .{
        .file = file,
        .path = owned_path,
        .offset = 0,
        .flags = flags,
        .in_overlay = false, // Host file, read-only until COW
        .is_directory = false,
    });

    return fd;
}

fn createInOverlay(self: *Self, path: []const u8, flags: u32) !FD {
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    // Ensure parent directories exist in overlay
    if (std.fs.path.dirname(subpath)) |parent| {
        if (parent.len > 0) {
            root.createDirPath(self.io, parent) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {}, // May already exist
            };
        }
    }

    const file = root.createFile(self.io, subpath, .{
        .read = true,
        .truncate = (flags & O_TRUNC) != 0,
    }) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.PermissionDenied,
        error.Canceled => return error.Canceled,
        else => return error.OpenFailed,
    };

    const owned_path = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(owned_path);

    const fd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(fd, .{
        .file = file,
        .path = owned_path,
        .offset = 0,
        .flags = flags,
        .in_overlay = true,
        .is_directory = false,
    });

    return fd;
}

/// Copy a host file to the overlay (COW).
fn copyToOverlay(self: *Self, path: []const u8) !void {
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    // Ensure parent directories exist
    if (std.fs.path.dirname(subpath)) |parent| {
        if (parent.len > 0) {
            root.createDirPath(self.io, parent) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {}, // May already exist
            };
        }
    }

    // Open source file on host
    const src_file = Dir.openFileAbsolute(self.io, path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.Canceled => return error.Canceled,
        else => return error.CopyFailed,
    };
    defer src_file.close(self.io);

    // Create destination file in overlay
    const dst_file = root.createFile(self.io, subpath, .{ .read = false, .truncate = true }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.CopyFailed,
    };
    defer dst_file.close(self.io);

    // Copy content
    var buf: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const bufs: [1][]u8 = .{&buf};
        const bytes_read = self.io.vtable.fileReadPositional(self.io.userdata, src_file, &bufs, offset) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.CopyFailed,
        };
        if (bytes_read == 0) break;

        const data_bufs: [1][]const u8 = .{buf[0..bytes_read]};
        _ = self.io.vtable.fileWritePositional(self.io.userdata, dst_file, "", &data_bufs, 1, offset) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.CopyFailed,
        };
        offset += bytes_read;
    }
}

pub fn read(self: *Self, fd: FD, buf: []u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;

    // Directories can't be read with read()
    if (entry.is_directory) return error.IsDirectory;

    const access_mode = entry.flags & O_ACCMODE;
    if (access_mode != O_RDONLY and access_mode != O_RDWR) {
        return error.NotOpenForReading;
    }

    const file = entry.file orelse return error.BadFD;
    const bufs: [1][]u8 = .{buf};
    const bytes_read = self.io.vtable.fileReadPositional(self.io.userdata, file, &bufs, entry.offset) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ReadFailed,
    };

    entry.offset += bytes_read;
    return bytes_read;
}

pub fn write(self: *Self, fd: FD, data: []const u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;

    // Directories can't be written with write()
    if (entry.is_directory) return error.IsDirectory;

    const access_mode = entry.flags & O_ACCMODE;
    if (access_mode != O_WRONLY and access_mode != O_RDWR) {
        return error.NotOpenForWriting;
    }

    // If file is from host (not in overlay), perform COW
    if (!entry.in_overlay) {
        try self.cowUpgrade(fd, entry);
    }

    const file = entry.file orelse return error.BadFD;

    // Handle O_APPEND: always write to end of file
    var write_offset = entry.offset;
    if ((entry.flags & O_APPEND) != 0) {
        const file_stat = file.stat(self.io) catch return error.WriteFailed;
        write_offset = file_stat.size;
    }

    const data_bufs: [1][]const u8 = .{data};
    const bytes_written = self.io.vtable.fileWritePositional(self.io.userdata, file, "", &data_bufs, 1, write_offset) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.WriteFailed,
    };

    entry.offset = write_offset + bytes_written;
    return bytes_written;
}

/// Upgrade a host file to overlay (COW on write).
fn cowUpgrade(self: *Self, fd: FD, entry: *OpenFile) !void {
    // Close host file handle
    if (entry.file) |f| f.close(self.io);

    // Copy to overlay
    try self.copyToOverlay(entry.path);

    // Reopen from overlay
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(entry.path);

    const access_mode = entry.flags & O_ACCMODE;
    const file_flags: File.OpenFlags = .{
        .mode = switch (access_mode) {
            O_RDONLY => .read_only,
            O_WRONLY => .write_only,
            O_RDWR => .read_write,
            else => .read_only,
        },
    };

    entry.file = root.openFile(self.io, subpath, file_flags) catch return error.CowFailed;
    entry.in_overlay = true;

    // Update the hashmap entry
    self.open_fds.putAssumeCapacity(fd, entry.*);
}

pub fn close(self: *Self, fd: FD) void {
    if (self.open_fds.fetchRemove(fd)) |kv| {
        if (kv.value.file) |f| f.close(self.io);
        self.allocator.free(kv.value.path);
    }
}

/// Duplicate a file descriptor. Returns the new FD number.
/// Note: This creates a new file handle to the same path - offsets are NOT shared
/// between the original and duplicated FD (simplified implementation).
pub fn dup(self: *Self, oldfd: FD) !FD {
    const entry = self.open_fds.get(oldfd) orelse return error.BadFD;

    const owned_path = try self.allocator.dupe(u8, entry.path);
    errdefer self.allocator.free(owned_path);

    const newfd = self.next_fd;
    self.next_fd += 1;

    // For directories, just copy the entry (no file handle to reopen)
    if (entry.is_directory) {
        try self.open_fds.put(newfd, .{
            .file = null,
            .path = owned_path,
            .offset = entry.offset,
            .flags = entry.flags,
            .in_overlay = entry.in_overlay,
            .is_directory = true,
        });
        return newfd;
    }

    // Re-open the same file (simplified - doesn't share offset with original)
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(entry.path);

    const access_mode = entry.flags & O_ACCMODE;
    const file_flags: File.OpenFlags = .{
        .mode = switch (access_mode) {
            O_RDONLY => .read_only,
            O_WRONLY => .write_only,
            O_RDWR => .read_write,
            else => .read_only,
        },
    };

    const file = if (entry.in_overlay)
        root.openFile(self.io, subpath, file_flags) catch return error.DupFailed
    else
        Dir.openFileAbsolute(self.io, entry.path, file_flags) catch return error.DupFailed;

    try self.open_fds.put(newfd, .{
        .file = file,
        .path = owned_path,
        .offset = entry.offset, // Copy current offset
        .flags = entry.flags,
        .in_overlay = entry.in_overlay,
        .is_directory = false,
    });

    return newfd;
}

/// Duplicate a file descriptor to a specific FD number.
/// If newfd is already open, it is closed first.
pub fn dup2(self: *Self, oldfd: FD, newfd: FD) !FD {
    if (oldfd == newfd) {
        // If same FD, just verify oldfd is valid
        if (self.open_fds.get(oldfd) == null) return error.BadFD;
        return newfd;
    }

    const entry = self.open_fds.get(oldfd) orelse return error.BadFD;

    // Close newfd if it's open
    self.close(newfd);

    const owned_path = try self.allocator.dupe(u8, entry.path);
    errdefer self.allocator.free(owned_path);

    // For directories, just copy the entry (no file handle to reopen)
    if (entry.is_directory) {
        try self.open_fds.put(newfd, .{
            .file = null,
            .path = owned_path,
            .offset = entry.offset,
            .flags = entry.flags,
            .in_overlay = entry.in_overlay,
            .is_directory = true,
        });
        return newfd;
    }

    // Re-open the same file for newfd
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(entry.path);

    const access_mode = entry.flags & O_ACCMODE;
    const file_flags: File.OpenFlags = .{
        .mode = switch (access_mode) {
            O_RDONLY => .read_only,
            O_WRONLY => .write_only,
            O_RDWR => .read_write,
            else => .read_only,
        },
    };

    const file = if (entry.in_overlay)
        root.openFile(self.io, subpath, file_flags) catch return error.DupFailed
    else
        Dir.openFileAbsolute(self.io, entry.path, file_flags) catch return error.DupFailed;

    try self.open_fds.put(newfd, .{
        .file = file,
        .path = owned_path,
        .offset = entry.offset,
        .flags = entry.flags,
        .in_overlay = entry.in_overlay,
        .is_directory = false,
    });

    return newfd;
}

/// Check if an FD is tracked by the overlay.
pub fn hasFD(self: *Self, fd: FD) bool {
    return self.open_fds.contains(fd);
}

pub fn pread(self: *Self, fd: FD, buf: []u8, offset: u64) !usize {
    const entry = self.open_fds.get(fd) orelse return error.BadFD;

    if (entry.is_directory) return error.IsDirectory;

    const access_mode = entry.flags & O_ACCMODE;
    if (access_mode != O_RDONLY and access_mode != O_RDWR) {
        return error.NotOpenForReading;
    }

    const file = entry.file orelse return error.BadFD;
    const bufs: [1][]u8 = .{buf};
    const bytes_read = self.io.vtable.fileReadPositional(self.io.userdata, file, &bufs, offset) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ReadFailed,
    };

    return bytes_read;
}

pub fn pwrite(self: *Self, fd: FD, data: []const u8, offset: u64) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;

    if (entry.is_directory) return error.IsDirectory;

    const access_mode = entry.flags & O_ACCMODE;
    if (access_mode != O_WRONLY and access_mode != O_RDWR) {
        return error.NotOpenForWriting;
    }

    // COW if needed
    if (!entry.in_overlay) {
        try self.cowUpgrade(fd, entry);
    }

    const file = entry.file orelse return error.BadFD;
    const data_bufs: [1][]const u8 = .{data};
    const bytes_written = self.io.vtable.fileWritePositional(self.io.userdata, file, "", &data_bufs, 1, offset) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.WriteFailed,
    };

    return bytes_written;
}

pub const SeekWhence = enum(u32) {
    SET = 0,
    CUR = 1,
    END = 2,
};

pub fn lseek(self: *Self, fd: FD, offset: i64, whence: SeekWhence) !i64 {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;

    // For directories, lseek just updates the offset (used for getdents64 position)
    if (entry.is_directory) {
        const new_offset: i64 = switch (whence) {
            .SET => offset,
            .CUR => @as(i64, @intCast(entry.offset)) + offset,
            .END => return error.InvalidSeek, // Can't seek to end of directory
        };
        if (new_offset < 0) return error.InvalidSeek;
        entry.offset = @intCast(new_offset);
        return new_offset;
    }

    const file = entry.file orelse return error.BadFD;
    const current: i64 = @intCast(entry.offset);

    const new_offset: i64 = switch (whence) {
        .SET => offset,
        .CUR => current + offset,
        .END => blk: {
            const file_len = file.stat(self.io) catch return error.InvalidSeek;
            const file_size: i64 = @intCast(file_len.size);
            break :blk file_size + offset;
        },
    };

    if (new_offset < 0) return error.InvalidSeek;

    entry.offset = @intCast(new_offset);
    return new_offset;
}

/// Create a directory in the overlay.
pub fn mkdir(self: *Self, path: []const u8, mode: u32) !void {
    _ = mode; // TODO: use for permissions
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    root.createDir(self.io, subpath, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return error.FileExists,
        error.Canceled => return error.Canceled,
        else => return error.MkdirFailed,
    };
}

/// Create a symlink in the overlay.
pub fn symlink(self: *Self, target: []const u8, linkpath: []const u8) !void {
    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(linkpath);

    // Ensure parent directories exist
    if (std.fs.path.dirname(subpath)) |parent| {
        if (parent.len > 0) {
            root.createDirPath(self.io, parent) catch {};
        }
    }

    root.symLink(self.io, target, subpath, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => return error.FileExists,
        error.Canceled => return error.Canceled,
        else => return error.SymlinkFailed,
    };
}

/// Check if a path exists in overlay or host.
pub fn pathExists(self: *Self, path: []const u8) bool {
    return self.existsInOverlay(path) or self.existsOnHost(path);
}

pub fn getFDBackend(self: *Self, fd: FD) ?OpenFile {
    return self.open_fds.get(fd);
}

/// Stat result matching VirtualFilesystem for compatibility
pub const StatResult = struct {
    pub const FileType = enum { regular, directory, symlink };
    size: u64,
    mode: u32,
    file_type: FileType,
};

/// Stat a file by path (overlay-first, then host).
pub fn stat(self: *Self, path: []const u8) ?StatResult {
    // Try overlay first
    if (self.existsInOverlay(path)) {
        return self.statOverlay(path);
    }
    // Try host
    if (self.existsOnHost(path)) {
        return self.statHost(path);
    }
    return null;
}

fn statOverlay(self: *Self, path: []const u8) ?StatResult {
    const root = self.ensureOverlayRoot() catch return null;
    const subpath = overlaySubpath(path);
    if (subpath.len == 0) {
        // Root directory
        return .{ .size = 0, .mode = 0o755, .file_type = .directory };
    }

    const file_stat = root.statFile(self.io, subpath, .{}) catch return null;

    const file_type: StatResult.FileType = switch (file_stat.kind) {
        .sym_link => .symlink,
        .directory => .directory,
        else => .regular,
    };

    return .{
        .size = file_stat.size,
        .mode = 0o644, // Default mode since permissions aren't directly comparable
        .file_type = file_type,
    };
}

fn statHost(self: *Self, path: []const u8) ?StatResult {
    // Open file to stat it, then close
    const file = Dir.openFileAbsolute(self.io, path, .{ .mode = .read_only }) catch return null;
    defer file.close(self.io);

    const file_stat = file.stat(self.io) catch return null;

    const file_type: StatResult.FileType = switch (file_stat.kind) {
        .sym_link => .symlink,
        .directory => .directory,
        else => .regular,
    };

    return .{
        .size = file_stat.size,
        .mode = 0o644, // Default mode
        .file_type = file_type,
    };
}

/// Stat an open FD.
pub fn fstat(self: *Self, fd: FD) ?StatResult {
    const entry = self.open_fds.get(fd) orelse return null;

    // For directories, return directory stat
    if (entry.is_directory) {
        return .{
            .size = 0,
            .mode = 0o755,
            .file_type = .directory,
        };
    }

    const file = entry.file orelse return null;
    const file_stat = file.stat(self.io) catch return null;

    return .{
        .size = file_stat.size,
        .mode = 0o644, // Default mode
        .file_type = .regular,
    };
}

/// Remove a file or symlink from the overlay.
pub fn unlink(self: *Self, path: []const u8) !void {
    // Only delete from overlay, not host
    if (!self.existsInOverlay(path)) {
        return error.FileNotFound;
    }

    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    root.deleteFile(self.io, subpath) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.IsDir => return error.IsDirectory,
        error.Canceled => return error.Canceled,
        else => return error.UnlinkFailed,
    };
}

/// Remove a directory from the overlay.
pub fn rmdir(self: *Self, path: []const u8) !void {
    if (!self.existsInOverlay(path)) {
        return error.FileNotFound;
    }

    const root = try self.ensureOverlayRoot();
    const subpath = overlaySubpath(path);

    root.deleteDir(self.io, subpath) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.DirNotEmpty => return error.DirectoryNotEmpty,
        error.Canceled => return error.Canceled,
        else => return error.RmdirFailed,
    };
}

/// Read symlink target. Returns a slice into a thread-local buffer.
/// The caller must use it immediately or copy it.
pub fn readlink(self: *Self, path: []const u8) ?[]const u8 {
    // Only check overlay (symlinks are only created in overlay)
    if (!self.existsInOverlay(path)) {
        return null;
    }

    const root = self.ensureOverlayRoot() catch return null;
    const subpath = overlaySubpath(path);

    // Use a thread-local buffer for readlink
    const S = struct {
        threadlocal var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    };
    const len = root.readLink(self.io, subpath, &S.link_buf) catch return null;

    return S.link_buf[0..len];
}

/// Check if path is a symlink (in overlay only).
pub fn isSymlink(self: *Self, path: []const u8) bool {
    if (!self.existsInOverlay(path)) {
        return false;
    }

    const root = self.ensureOverlayRoot() catch return false;
    const subpath = overlaySubpath(path);

    // Don't follow symlinks - we want to check if the path itself is a symlink
    const file_stat = root.statFile(self.io, subpath, .{ .follow_symlinks = false }) catch return false;
    return file_stat.kind == .sym_link;
}

/// Check if path is a directory.
pub fn isDirectory(self: *Self, path: []const u8) bool {
    if (self.stat(path)) |s| {
        return s.file_type == .directory;
    }
    return false;
}

/// Directory entry for listing
pub const DirEntry = struct {
    name: []const u8,
    kind: enum { file, directory, symlink, unknown },
    inode: u64,
};

/// List directory contents. Merges overlay entries with host entries.
/// Returns entries via callback to avoid allocation.
/// Callback returns false to stop iteration.
pub fn listDirectory(
    self: *Self,
    path: []const u8,
    comptime callback: fn (entry: DirEntry, ctx: anytype) bool,
    ctx: anytype,
) !void {
    var seen = std.StringHashMap(void).init(self.allocator);
    defer seen.deinit();

    // First list overlay entries (these take precedence)
    if (self.existsInOverlay(path)) {
        const root = try self.ensureOverlayRoot();
        const subpath = overlaySubpath(path);

        // Open directory for iteration
        const dir = if (subpath.len == 0)
            root
        else
            root.openDir(self.io, subpath, .{ .iterate = true }) catch null;

        if (dir) |d| {
            defer if (subpath.len > 0) d.close(self.io);

            var iter = d.iterate();
            while (iter.next(self.io) catch null) |entry| {
                // Track seen entries
                seen.put(entry.name, {}) catch continue;

                const kind: DirEntry.kind = switch (entry.kind) {
                    .directory => .directory,
                    .sym_link => .symlink,
                    .file => .file,
                    else => .unknown,
                };

                if (!callback(.{
                    .name = entry.name,
                    .kind = kind,
                    .inode = entry.inode,
                }, ctx)) return;
            }
        }
    }

    // Then list host entries (skip if already seen in overlay)
    if (self.existsOnHost(path)) {
        const dir = Dir.openDirAbsolute(self.io, path, .{ .iterate = true }) catch return;
        defer dir.close(self.io);

        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            // Skip if already seen in overlay
            if (seen.contains(entry.name)) continue;

            const kind: DirEntry.kind = switch (entry.kind) {
                .directory => .directory,
                .sym_link => .symlink,
                .file => .file,
                else => .unknown,
            };

            if (!callback(.{
                .name = entry.name,
                .kind = kind,
                .inode = entry.inode,
            }, ctx)) return;
        }
    }
}

pub fn deinit(self: *Self) void {
    // Close all open files
    var it = self.open_fds.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.file) |f| f.close(self.io);
        self.allocator.free(entry.value_ptr.path);
    }
    self.open_fds.deinit();

    // Close overlay root handle
    if (self.overlay_root) |root| {
        root.close(self.io);
    }
    // Note: We don't delete the overlay directory (keep for debugging per user request)
}

// ============================================================================
// Tests
// ============================================================================

test "init creates random session id" {
    var threaded: Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    var overlay = Self.init(std.testing.allocator, io);
    defer overlay.deinit();

    // Session ID should be 32 hex chars
    try std.testing.expectEqual(@as(usize, 32), overlay.session_id.len);
}

test "overlay subpath strips leading slash" {
    try std.testing.expectEqualStrings("foo/bar", overlaySubpath("/foo/bar"));
    try std.testing.expectEqualStrings("test.txt", overlaySubpath("/test.txt"));
    try std.testing.expectEqualStrings("", overlaySubpath("/"));
    try std.testing.expectEqualStrings("relative", overlaySubpath("relative"));
}
