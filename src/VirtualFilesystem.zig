const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const types = @import("types.zig");
const FD = types.FD;

const Self = @This();

const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

/// Where a FD's operations are handled.
pub const FDBackend = union(enum) {
    /// Fully virtualized file in VFS
    virtual: VirtualFile.Handle,
    /// Supervisor-owned kernel FD (for read-only proxying to host files)
    kernel_proxy: KernelProxy,

    pub const KernelProxy = struct {
        supervisor_fd: FD, // FD owned by supervisor process
        path: []const u8, // path for COW on write
        offset: usize, // current position
        flags: u32, // open flags
    };
};

allocator: std.mem.Allocator,
virtual_files: std.StringHashMap(*VirtualFile), // persists after close
symlinks: std.StringHashMap([]const u8), // path -> target
directories: std.StringHashMap(u32), // path -> mode
open_fds: std.AutoHashMap(FD, FDBackend),
next_fd: FD = 3, // 0,1,2 are stdio

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .allocator = allocator,
        .virtual_files = std.StringHashMap(*VirtualFile).init(allocator),
        .symlinks = std.StringHashMap([]const u8).init(allocator),
        .directories = std.StringHashMap(u32).init(allocator),
        .open_fds = std.AutoHashMap(FD, FDBackend).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    // Debug: dump VFS contents BEFORE freeing (skip in tests)
    if (!builtin.is_test and self.virtual_files.count() > 0) {
        std.debug.print("\n\x1b[93m=== Virtual Filesystem Contents ===\x1b[0m\n", .{});
        var debug_it = self.virtual_files.iterator();
        while (debug_it.next()) |entry| {
            const path = entry.key_ptr.*;
            const file = entry.value_ptr.*;
            std.debug.print("\x1b[96m{s}\x1b[0m ({d} bytes, mode=0o{o}):\n", .{
                path,
                file.data.items.len,
                file.mode,
            });
            if (file.data.items.len > 0) {
                std.debug.print("{s}\n", .{file.data.items});
            }
        }
        std.debug.print("\x1b[93m===================================\x1b[0m\n\n", .{});
    }

    // Free allocated paths and close supervisor FDs tracked in open_fds
    var fd_it = self.open_fds.iterator();
    while (fd_it.next()) |entry| {
        switch (entry.value_ptr.*) {
            .virtual => {},
            .kernel_proxy => |proxy| {
                _ = linux.close(@intCast(proxy.supervisor_fd));
                self.allocator.free(proxy.path);
            },
        }
    }
    self.open_fds.deinit();

    // Free allocated virtual files
    var file_it = self.virtual_files.iterator();
    while (file_it.next()) |entry| {
        entry.value_ptr.*.data.deinit(self.allocator);
        self.allocator.destroy(entry.value_ptr.*);
        self.allocator.free(entry.key_ptr.*);
    }
    self.virtual_files.deinit();

    // Free symlinks
    var sym_it = self.symlinks.iterator();
    while (sym_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.symlinks.deinit();

    // Free directories
    var dir_it = self.directories.iterator();
    while (dir_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
    }
    self.directories.deinit();
}

/// Open or create a file. Pass content for COW from host.
pub fn open(self: *Self, path: []const u8, flags: u32, mode: u32, content: ?[]const u8) !FD {
    const access_mode = flags & O_ACCMODE;
    var file: *VirtualFile = undefined;
    if (self.virtual_files.get(path)) |existing| {
        file = existing;
        const owner_read = (file.mode & 0o400) != 0;
        const owner_write = (file.mode & 0o200) != 0;

        if (access_mode == O_RDONLY and !owner_read) {
            return error.PermissionDenied;
        }
        if (access_mode == O_WRONLY and !owner_write) {
            return error.PermissionDenied;
        }
        if (access_mode == O_RDWR and (!owner_read or !owner_write)) {
            return error.PermissionDenied;
        }
        if ((flags & O_TRUNC) != 0 and (access_mode == O_WRONLY or access_mode == O_RDWR)) {
            file.data.clearRetainingCapacity();
        }
    } else {
        if ((flags & O_CREAT) == 0 and content == null) return error.FileNotFound;

        const new_file = try self.allocator.create(VirtualFile);
        new_file.* = .{ .mode = mode & 0o777 };
        if (content) |c| try new_file.data.appendSlice(self.allocator, c);
        const owned_path = try self.allocator.dupe(u8, path);
        try self.virtual_files.put(owned_path, new_file);
        file = new_file;
    }

    const fd = self.next_fd;
    self.next_fd += 1;
    try self.open_fds.put(fd, .{ .virtual = .{ .file = file, .offset = 0, .flags = flags } });
    return fd;
}

pub fn write(self: *Self, fd: FD, data: []const u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    switch (entry.*) {
        .virtual => |*handle| {
            const access_mode = handle.flags & O_ACCMODE;
            if (access_mode != O_WRONLY and access_mode != O_RDWR) {
                return error.NotOpenForWriting;
            }
            try handle.file.data.appendSlice(self.allocator, data);
            handle.offset += data.len;
            return data.len;
        },
        .kernel_proxy => |*proxy| {
            const access_mode = proxy.flags & O_ACCMODE;
            if (access_mode != O_WRONLY and access_mode != O_RDWR) {
                return error.NotOpenForWriting;
            }
            // COW: upgrade to virtual file
            try self.cowUpgrade(fd, proxy);
            // Now write to the virtual file
            return self.write(fd, data);
        },
    }
}

pub fn read(self: *Self, fd: FD, buf: []u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    switch (entry.*) {
        .virtual => |*handle| {
            const access_mode = handle.flags & O_ACCMODE;
            if (access_mode != O_RDONLY and access_mode != O_RDWR) {
                return error.NotOpenForReading;
            }

            const file_data = handle.file.data.items;
            const remaining = file_data.len - @min(handle.offset, file_data.len);
            const to_read = @min(buf.len, remaining);

            if (to_read > 0) {
                @memcpy(buf[0..to_read], file_data[handle.offset..][0..to_read]);
                handle.offset += to_read;
            }
            return to_read;
        },
        .kernel_proxy => |*proxy| {
            const access_mode = proxy.flags & O_ACCMODE;
            if (access_mode != O_RDONLY and access_mode != O_RDWR) {
                return error.NotOpenForReading;
            }

            // Read from supervisor's kernel FD using pread (doesn't change supervisor's offset)
            const result = linux.pread(
                @intCast(proxy.supervisor_fd),
                buf.ptr,
                buf.len,
                @intCast(proxy.offset),
            );

            if (@as(isize, @bitCast(result)) < 0) {
                return error.ReadFailed;
            }

            const bytes_read: usize = @intCast(result);
            proxy.offset += bytes_read;
            return bytes_read;
        },
    }
}

/// Close FD but keep file data.
pub fn close(self: *Self, fd: FD) void {
    if (self.open_fds.fetchRemove(fd)) |entry| {
        switch (entry.value) {
            .virtual => {},
            .kernel_proxy => |proxy| {
                _ = linux.close(@intCast(proxy.supervisor_fd));
                self.allocator.free(proxy.path);
            },
        }
    }
}

pub fn getFDBackend(self: *Self, fd: FD) ?FDBackend {
    return self.open_fds.get(fd);
}

/// Register a supervisor-owned kernel FD for proxying.
/// The supervisor_fd is owned by this VFS and will be closed when the virtual FD is closed.
pub fn registerKernelProxy(self: *Self, supervisor_fd: FD, path: []const u8, flags: u32) !FD {
    const owned_path = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(owned_path);

    const vfd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(vfd, .{
        .kernel_proxy = .{
            .supervisor_fd = supervisor_fd,
            .path = owned_path,
            .offset = 0,
            .flags = flags,
        },
    });

    return vfd;
}

/// Upgrade a kernel proxy to a virtual file by reading all content (COW).
fn cowUpgrade(self: *Self, fd: FD, proxy: *FDBackend.KernelProxy) !void {
    // Read all content from the kernel FD
    var content: std.ArrayListUnmanaged(u8) = .{};
    errdefer content.deinit(self.allocator);

    var buf: [4096]u8 = undefined;
    var read_offset: usize = 0;
    while (true) {
        const result = linux.pread(
            @intCast(proxy.supervisor_fd),
            &buf,
            buf.len,
            @intCast(read_offset),
        );

        if (@as(isize, @bitCast(result)) < 0) {
            return error.ReadFailed;
        }

        const bytes_read: usize = @intCast(result);
        if (bytes_read == 0) break;

        try content.appendSlice(self.allocator, buf[0..bytes_read]);
        read_offset += bytes_read;
    }

    // Create or update virtual file
    var file: *VirtualFile = undefined;
    if (self.virtual_files.get(proxy.path)) |existing| {
        file = existing;
        file.data.clearRetainingCapacity();
        try file.data.appendSlice(self.allocator, content.items);
    } else {
        const new_file = try self.allocator.create(VirtualFile);
        new_file.* = .{ .mode = 0o644 }; // Default mode for COW files
        try new_file.data.appendSlice(self.allocator, content.items);
        const owned_path = try self.allocator.dupe(u8, proxy.path);
        try self.virtual_files.put(owned_path, new_file);
        file = new_file;
    }

    // Close the supervisor's kernel FD
    _ = linux.close(@intCast(proxy.supervisor_fd));

    // Free the old path
    self.allocator.free(proxy.path);

    // We've transferred content to the file, clear so errdefer doesn't free
    content = .{};

    // Update the FD backend to virtual
    const current_offset = proxy.offset;
    const flags = proxy.flags;
    self.open_fds.putAssumeCapacity(fd, .{
        .virtual = .{
            .file = file,
            .offset = current_offset,
            .flags = flags,
        },
    });
}

pub fn virtualPathExists(self: *Self, path: []const u8) bool {
    return self.virtual_files.contains(path) or self.symlinks.contains(path) or self.directories.contains(path);
}

// ============================================================================
// Symlink operations
// ============================================================================

pub fn createSymlink(self: *Self, target: []const u8, linkpath: []const u8) !void {
    // Check if something already exists at linkpath
    if (self.virtual_files.contains(linkpath) or self.symlinks.contains(linkpath) or self.directories.contains(linkpath)) {
        return error.FileExists;
    }

    const owned_linkpath = try self.allocator.dupe(u8, linkpath);
    errdefer self.allocator.free(owned_linkpath);
    const owned_target = try self.allocator.dupe(u8, target);
    errdefer self.allocator.free(owned_target);

    try self.symlinks.put(owned_linkpath, owned_target);
}

pub fn readlink(self: *Self, path: []const u8) ?[]const u8 {
    return self.symlinks.get(path);
}

pub fn isSymlink(self: *Self, path: []const u8) bool {
    return self.symlinks.contains(path);
}

// ============================================================================
// Directory operations
// ============================================================================

pub fn mkdir(self: *Self, path: []const u8, mode: u32) !void {
    // Check if something already exists at path
    if (self.virtual_files.contains(path) or self.symlinks.contains(path) or self.directories.contains(path)) {
        return error.FileExists;
    }

    const owned_path = try self.allocator.dupe(u8, path);
    try self.directories.put(owned_path, mode & 0o777);
}

pub fn isDirectory(self: *Self, path: []const u8) bool {
    return self.directories.contains(path);
}

pub fn getDirectoryMode(self: *Self, path: []const u8) ?u32 {
    return self.directories.get(path);
}

pub fn rmdir(self: *Self, path: []const u8) !void {
    if (self.directories.fetchRemove(path)) |entry| {
        self.allocator.free(entry.key);
    } else {
        return error.FileNotFound;
    }
}

// ============================================================================
// Unlink operations
// ============================================================================

pub fn unlink(self: *Self, path: []const u8) !void {
    // Try files first
    if (self.virtual_files.fetchRemove(path)) |entry| {
        entry.value.data.deinit(self.allocator);
        self.allocator.destroy(entry.value);
        self.allocator.free(entry.key);
        return;
    }

    // Try symlinks
    if (self.symlinks.fetchRemove(path)) |entry| {
        self.allocator.free(entry.key);
        self.allocator.free(entry.value);
        return;
    }

    return error.FileNotFound;
}

// ============================================================================
// Lseek operations
// ============================================================================

pub const SeekWhence = enum(u32) {
    SET = 0,
    CUR = 1,
    END = 2,
};

pub fn lseek(self: *Self, fd: FD, offset: i64, whence: SeekWhence) !i64 {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    switch (entry.*) {
        .virtual => |*handle| {
            const file_size: i64 = @intCast(handle.file.data.items.len);
            const current: i64 = @intCast(handle.offset);

            const new_offset: i64 = switch (whence) {
                .SET => offset,
                .CUR => current + offset,
                .END => file_size + offset,
            };

            if (new_offset < 0) return error.InvalidSeek;

            handle.offset = @intCast(new_offset);
            return new_offset;
        },
        .kernel_proxy => |*proxy| {
            // For kernel proxy, we need to know file size for SEEK_END
            // Use lseek on supervisor FD to get size
            const current: i64 = @intCast(proxy.offset);

            const new_offset: i64 = switch (whence) {
                .SET => offset,
                .CUR => current + offset,
                .END => blk: {
                    // Get file size via lseek
                    const end_result = linux.lseek(@intCast(proxy.supervisor_fd), 0, linux.SEEK.END);
                    if (@as(isize, @bitCast(end_result)) < 0) return error.InvalidSeek;
                    const file_size: i64 = @intCast(end_result);
                    break :blk file_size + offset;
                },
            };

            if (new_offset < 0) return error.InvalidSeek;

            proxy.offset = @intCast(new_offset);
            return new_offset;
        },
    }
}

// ============================================================================
// Positional read/write (don't change offset)
// ============================================================================

pub fn pread(self: *Self, fd: FD, buf: []u8, offset: u64) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    switch (entry.*) {
        .virtual => |handle| {
            const access_mode = handle.flags & O_ACCMODE;
            if (access_mode != O_RDONLY and access_mode != O_RDWR) {
                return error.NotOpenForReading;
            }

            const file_data = handle.file.data.items;
            if (offset >= file_data.len) return 0;

            const remaining = file_data.len - offset;
            const to_read = @min(buf.len, remaining);

            if (to_read > 0) {
                @memcpy(buf[0..to_read], file_data[offset..][0..to_read]);
            }
            return to_read;
        },
        .kernel_proxy => |proxy| {
            const access_mode = proxy.flags & O_ACCMODE;
            if (access_mode != O_RDONLY and access_mode != O_RDWR) {
                return error.NotOpenForReading;
            }

            const result = linux.pread(
                @intCast(proxy.supervisor_fd),
                buf.ptr,
                buf.len,
                @intCast(offset),
            );

            if (@as(isize, @bitCast(result)) < 0) {
                return error.ReadFailed;
            }

            return @intCast(result);
        },
    }
}

pub fn pwrite(self: *Self, fd: FD, data: []const u8, offset: u64) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    switch (entry.*) {
        .virtual => |*handle| {
            const access_mode = handle.flags & O_ACCMODE;
            if (access_mode != O_WRONLY and access_mode != O_RDWR) {
                return error.NotOpenForWriting;
            }

            const end_pos = offset + data.len;
            const current_len = handle.file.data.items.len;

            // Extend file if write goes beyond current length
            if (end_pos > current_len) {
                if (offset > current_len) {
                    // Fill gap with zeros
                    const gap_size = offset - current_len;
                    try handle.file.data.ensureUnusedCapacity(self.allocator, gap_size + data.len);
                    handle.file.data.items.len += gap_size;
                    @memset(handle.file.data.items[current_len..][0..gap_size], 0);
                }
                // Extend to accommodate data
                const new_len = end_pos;
                try handle.file.data.ensureUnusedCapacity(self.allocator, new_len - handle.file.data.items.len);
                handle.file.data.items.len = new_len;
            }

            // Write at offset position
            @memcpy(handle.file.data.items[offset..][0..data.len], data);

            return data.len;
        },
        .kernel_proxy => |*proxy| {
            const access_mode = proxy.flags & O_ACCMODE;
            if (access_mode != O_WRONLY and access_mode != O_RDWR) {
                return error.NotOpenForWriting;
            }
            // COW: upgrade to virtual file, then pwrite
            try self.cowUpgrade(fd, proxy);
            return self.pwrite(fd, data, offset);
        },
    }
}

// ============================================================================
// Stat operations
// ============================================================================

pub const StatResult = struct {
    mode: u32,
    size: u64,
    file_type: FileType,

    pub const FileType = enum { regular, directory, symlink };
};

pub fn stat(self: *Self, path: []const u8) ?StatResult {
    // Check files first
    if (self.virtual_files.get(path)) |file| {
        return .{
            .mode = file.mode,
            .size = file.data.items.len,
            .file_type = .regular,
        };
    }

    // Check directories
    if (self.directories.get(path)) |mode| {
        return .{
            .mode = mode,
            .size = 4096, // Standard directory size
            .file_type = .directory,
        };
    }

    // Check symlinks
    if (self.symlinks.get(path)) |target| {
        return .{
            .mode = 0o777, // Symlinks typically have 777 permissions
            .size = target.len,
            .file_type = .symlink,
        };
    }

    return null;
}

pub fn fstat(self: *Self, fd: FD) ?StatResult {
    const backend = self.open_fds.get(fd) orelse return null;
    switch (backend) {
        .virtual => |handle| {
            return .{
                .mode = handle.file.mode,
                .size = handle.file.data.items.len,
                .file_type = .regular,
            };
        },
        .kernel_proxy => |proxy| {
            // Get file size via lseek
            const current = linux.lseek(@intCast(proxy.supervisor_fd), 0, linux.SEEK.CUR);
            const end = linux.lseek(@intCast(proxy.supervisor_fd), 0, linux.SEEK.END);
            // Restore position
            _ = linux.lseek(@intCast(proxy.supervisor_fd), @bitCast(current), linux.SEEK.SET);

            if (@as(isize, @bitCast(end)) < 0) return null;

            return .{
                .mode = 0o644, // Default mode for proxied files
                .size = @intCast(end),
                .file_type = .regular,
            };
        },
    }
}

/// A virtual file containing its data in memory
pub const VirtualFile = struct {
    data: std.ArrayListUnmanaged(u8) = .{},
    mode: u32,

    pub const Handle = struct {
        file: *VirtualFile,
        offset: usize,
        flags: u32,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "open and write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);
}

test "persitence: open, write, close, reopen, read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Write and close
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "persistent data");
    vfs.close(fd1);

    // Reopen and read
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0o644, null);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd2, &buf);
    try std.testing.expectEqualStrings("persistent data", buf[0..n]);
}

test "file not found without O_CREAT" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.open("/nonexistent.txt", O_RDONLY, 0o644, null);
    try std.testing.expectError(error.FileNotFound, result);
}

test "bad FD on write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.write(999, "data");
    try std.testing.expectError(error.BadFD, result);
}

test "bad FD on read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    var buf: [32]u8 = undefined;
    const result = vfs.read(999, &buf);
    try std.testing.expectError(error.BadFD, result);
}

test "getFDBackend" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // stdin/stdout/stderr are not tracked
    try std.testing.expect(vfs.getFDBackend(0) == null);
    try std.testing.expect(vfs.getFDBackend(1) == null);
    try std.testing.expect(vfs.getFDBackend(2) == null);

    // Open a file, check it's virtual
    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    try std.testing.expect(vfs.getFDBackend(fd).? == .virtual);

    // Close it, no longer tracked
    vfs.close(fd);
    try std.testing.expect(vfs.getFDBackend(fd) == null);
}

test "permission denied - read-only file, open for write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/readonly.txt", O_WRONLY | O_CREAT, 0o400, null);
    vfs.close(fd1);

    // Try to open for writing
    const result = vfs.open("/readonly.txt", O_WRONLY, 0o400, null);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - write-only file, open for read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create write-only file
    const fd1 = try vfs.open("/writeonly.txt", O_WRONLY | O_CREAT, 0o200, null);
    vfs.close(fd1);

    // Try to open for reading
    const result = vfs.open("/writeonly.txt", O_RDONLY, 0o200, null);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - no permissions" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with no permissions
    const fd1 = try vfs.open("/noperm.txt", O_WRONLY | O_CREAT, 0o000, null);
    vfs.close(fd1);

    // Can't read
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDONLY, 0, null));
    // Can't write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_WRONLY, 0, null));
    // Can't read-write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDWR, 0, null));
}

test "permission denied - O_RDWR needs both bits" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/ro.txt", O_WRONLY | O_CREAT, 0o400, null);
    vfs.close(fd1);

    // O_RDWR should fail (missing write permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/ro.txt", O_RDWR, 0, null));

    // Create write-only file
    const fd2 = try vfs.open("/wo.txt", O_WRONLY | O_CREAT, 0o200, null);
    vfs.close(fd2);

    // O_RDWR should fail (missing read permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/wo.txt", O_RDWR, 0, null));
}

test "write to read-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with rw permissions
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "data");
    vfs.close(fd1);

    // Open read-only
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    const result = vfs.write(fd2, "more");
    try std.testing.expectError(error.NotOpenForWriting, result);
}

test "read from write-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    var buf: [32]u8 = undefined;
    const result = vfs.read(fd, &buf);
    try std.testing.expectError(error.NotOpenForReading, result);
}

test "O_TRUNC truncates existing file" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create and write
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "original content");
    vfs.close(fd1);

    // Reopen with O_TRUNC
    const fd2 = try vfs.open("/test.txt", O_RDWR | O_TRUNC, 0, null);
    _ = try vfs.write(fd2, "new");
    vfs.close(fd2);

    // Read back
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd3, &buf);
    try std.testing.expectEqualStrings("new", buf[0..n]);
}

test "multiple FDs same file have independent offsets" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with content
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "abcdefghij");
    vfs.close(fd1);

    // Open twice for reading
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0, null);

    var buf2: [3]u8 = undefined;
    var buf3: [5]u8 = undefined;

    // Read 3 from fd2
    _ = try vfs.read(fd2, &buf2);
    try std.testing.expectEqualStrings("abc", &buf2);

    // Read 5 from fd3 (should start at beginning)
    _ = try vfs.read(fd3, &buf3);
    try std.testing.expectEqualStrings("abcde", &buf3);

    // Read 3 more from fd2 (should continue from offset 3)
    _ = try vfs.read(fd2, &buf2);
    try std.testing.expectEqualStrings("def", &buf2);
}

test "read at EOF returns 0" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "short");
    vfs.close(fd1);

    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    var buf: [32]u8 = undefined;

    // Read all
    const n1 = try vfs.read(fd2, &buf);
    try std.testing.expectEqual(5, n1);

    // Read again at EOF
    const n2 = try vfs.read(fd2, &buf);
    try std.testing.expectEqual(0, n2);
}

test "O_RDWR allows both read and write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);

    // Write should work
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);

    // Read should work (but returns 0 since offset is at end)
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(0, n);
}

test "pwrite with partial overlap extends file correctly" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with 5 bytes: "ABCDE"
    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "ABCDE");

    // pwrite 3 bytes "xyz" at offset 3 -> should give "ABCxyz" (6 bytes)
    const written = try vfs.pwrite(fd, "xyz", 3);
    try std.testing.expectEqual(3, written);

    // Seek to start and read back
    _ = try vfs.lseek(fd, 0, .SET);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(6, n);
    try std.testing.expectEqualStrings("ABCxyz", buf[0..n]);
}

test "pwrite with gap fills zeros" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with 3 bytes: "ABC"
    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "ABC");

    // pwrite 2 bytes "XY" at offset 5 -> should give "ABC\x00\x00XY" (7 bytes)
    const written = try vfs.pwrite(fd, "XY", 5);
    try std.testing.expectEqual(2, written);

    // Seek to start and read back
    _ = try vfs.lseek(fd, 0, .SET);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(7, n);
    try std.testing.expectEqualStrings("ABC", buf[0..3]);
    try std.testing.expectEqual(@as(u8, 0), buf[3]);
    try std.testing.expectEqual(@as(u8, 0), buf[4]);
    try std.testing.expectEqualStrings("XY", buf[5..7]);
}

test "pwrite within existing file does not extend" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with 10 bytes
    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "0123456789");

    // pwrite 3 bytes at offset 2 -> should give "01abc56789" (still 10 bytes)
    _ = try vfs.pwrite(fd, "abc", 2);

    _ = try vfs.lseek(fd, 0, .SET);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(10, n);
    try std.testing.expectEqualStrings("01abc56789", buf[0..n]);
}

test "pread at exact EOF returns 0" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "12345");

    var buf: [10]u8 = undefined;
    const n = try vfs.pread(fd, &buf, 5); // exactly at EOF
    try std.testing.expectEqual(0, n);
}

test "pread beyond EOF returns 0" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "ABC");

    var buf: [10]u8 = undefined;
    const n = try vfs.pread(fd, &buf, 1000);
    try std.testing.expectEqual(0, n);
}

test "lseek SEEK_CUR with negative offset" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "0123456789");

    // Move to position 5
    _ = try vfs.lseek(fd, 5, .SET);

    // Move back 3 positions
    const pos = try vfs.lseek(fd, -3, .CUR);
    try std.testing.expectEqual(2, pos);
}

test "lseek SEEK_END positions at file end" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "hello");

    const pos = try vfs.lseek(fd, 0, .END);
    try std.testing.expectEqual(5, pos);
}

test "lseek past EOF allowed" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "hi");

    const pos = try vfs.lseek(fd, 1000, .SET);
    try std.testing.expectEqual(1000, pos);
}

test "symlink and directory existence checks" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    try vfs.createSymlink("/target", "/mylink");
    try vfs.mkdir("/mydir", 0o755);

    try std.testing.expect(vfs.isSymlink("/mylink"));
    try std.testing.expect(!vfs.isSymlink("/mydir"));
    try std.testing.expect(vfs.isDirectory("/mydir"));
    try std.testing.expect(!vfs.isDirectory("/mylink"));
}

test "stat returns correct file types" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create regular file
    const fd = try vfs.open("/file.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd, "content");
    vfs.close(fd);

    // Create directory
    try vfs.mkdir("/dir", 0o755);

    // Create symlink
    try vfs.createSymlink("/somewhere", "/link");

    // Check stats
    const file_stat = vfs.stat("/file.txt").?;
    try std.testing.expectEqual(.regular, file_stat.file_type);
    try std.testing.expectEqual(@as(u64, 7), file_stat.size);

    const dir_stat = vfs.stat("/dir").?;
    try std.testing.expectEqual(.directory, dir_stat.file_type);

    const link_stat = vfs.stat("/link").?;
    try std.testing.expectEqual(.symlink, link_stat.file_type);
    try std.testing.expectEqual(@as(u64, 10), link_stat.size); // "/somewhere".len
}

test "rmdir removes directory" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    try vfs.mkdir("/toremove", 0o755);
    try std.testing.expect(vfs.isDirectory("/toremove"));

    try vfs.rmdir("/toremove");
    try std.testing.expect(!vfs.isDirectory("/toremove"));
}

test "rmdir on non-existent returns error" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.rmdir("/nonexistent");
    try std.testing.expectError(error.FileNotFound, result);
}

test "unlink removes file" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/todelete.txt", O_WRONLY | O_CREAT, 0o644, null);
    vfs.close(fd);

    try std.testing.expect(vfs.virtualPathExists("/todelete.txt"));
    try vfs.unlink("/todelete.txt");
    try std.testing.expect(!vfs.virtualPathExists("/todelete.txt"));
}

test "unlink removes symlink" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    try vfs.createSymlink("/target", "/symtodelete");
    try std.testing.expect(vfs.isSymlink("/symtodelete"));

    try vfs.unlink("/symtodelete");
    try std.testing.expect(!vfs.isSymlink("/symtodelete"));
}
