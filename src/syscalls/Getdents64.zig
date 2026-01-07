const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const Overlay = @import("../Overlay.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,
dirp: u64, // pointer to buffer in child memory
count: usize,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .dirp = notif.data.arg1,
        .count = @truncate(notif.data.arg2),
    };
}

/// Linux dirent64 structure layout:
/// d_ino:    8 bytes at offset 0
/// d_off:    8 bytes at offset 8
/// d_reclen: 2 bytes at offset 16
/// d_type:   1 byte at offset 18
/// d_name:   variable length at offset 19
const DIRENT64_NAME_OFFSET: usize = 19;

const DT_UNKNOWN: u8 = 0;
const DT_REG: u8 = 8;
const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;
    const mem_bridge = supervisor.mem_bridge;

    logger.log("Emulating getdents64: fd={d} count={d}", .{ self.fd, self.count });

    // stdio passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("getdents64: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Check if this FD is tracked in overlay
    const backend = overlay.getFDBackend(self.fd) orelse {
        // Not tracked - passthrough to kernel
        logger.log("getdents64: passthrough for untracked fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    };

    // Get the directory path from the open file entry
    const dir_path = backend.path;

    // Use the stored offset to track position in directory listing
    // offset is used as entry index (simplified approach)
    const start_offset = backend.offset;

    // Build directory entries into a local buffer
    var local_buf: [4096]u8 = undefined;
    const buf_size = @min(self.count, local_buf.len);
    var buf_pos: usize = 0;
    var entry_index: usize = 0;
    var entries_returned: usize = 0;

    // Track seen entries to handle overlay/host merging
    // We use the hashmap to store owned strings that need to be freed
    var seen = std.StringHashMap(void).init(supervisor.allocator);
    defer {
        // Free all allocated keys
        var iter = seen.keyIterator();
        while (iter.next()) |key| {
            supervisor.allocator.free(key.*);
        }
        seen.deinit();
    }

    // First iterate overlay entries using linux getdents64 directly
    if (overlay.existsInOverlay(dir_path)) {
        var overlay_path_buf: [4096]u8 = undefined;
        if (overlay.getOverlayPath(dir_path, &overlay_path_buf)) |path| {
            // Null-terminate the path
            if (path.len < overlay_path_buf.len) {
                overlay_path_buf[path.len] = 0;

                const dir_fd = posix.openatZ(
                    posix.AT.FDCWD,
                    @ptrCast(&overlay_path_buf),
                    .{ .DIRECTORY = true },
                    0,
                ) catch null;

                if (dir_fd) |fd| {
                    defer posix.close(fd);
                    iterateDirectory(fd, &seen, &local_buf, buf_size, &buf_pos, &entry_index, &entries_returned, start_offset, supervisor.allocator);
                }
            }
        }
    }

    // For host directories, use linux getdents64 directly
    if (overlay.existsOnHost(dir_path) and buf_pos < buf_size) {
        // Null-terminate the path
        var path_buf: [4096]u8 = undefined;
        if (dir_path.len < path_buf.len) {
            @memcpy(path_buf[0..dir_path.len], dir_path);
            path_buf[dir_path.len] = 0;

            const dir_fd = posix.openatZ(
                posix.AT.FDCWD,
                @ptrCast(&path_buf),
                .{ .DIRECTORY = true },
                0,
            ) catch null;

            if (dir_fd) |fd| {
                defer posix.close(fd);
                iterateDirectory(fd, &seen, &local_buf, buf_size, &buf_pos, &entry_index, &entries_returned, start_offset, supervisor.allocator);
            }
        }
    }

    // Write buffer to child memory
    if (buf_pos > 0) {
        try mem_bridge.writeSlice(local_buf[0..buf_pos], self.dirp);

        // Update offset in overlay to track position
        const entry_ptr = overlay.open_fds.getPtr(self.fd);
        if (entry_ptr) |e| {
            e.offset = entry_index;
        }
    }

    logger.log("getdents64: returned {d} bytes ({d} entries) for path=\"{s}\"", .{
        buf_pos,
        entries_returned,
        dir_path,
    });
    return .{ .handled = Result.Handled.success(@intCast(buf_pos)) };
}

/// Iterate directory using linux.getdents64 directly
fn iterateDirectory(
    fd: posix.fd_t,
    seen: *std.StringHashMap(void),
    local_buf: *[4096]u8,
    buf_size: usize,
    buf_pos: *usize,
    entry_index: *usize,
    entries_returned: *usize,
    start_offset: usize,
    allocator: std.mem.Allocator,
) void {
    var kernel_buf: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;

    while (true) {
        const rc = linux.getdents64(fd, &kernel_buf, kernel_buf.len);
        const signed_rc: isize = @bitCast(rc);

        if (signed_rc < 0) break; // Error
        if (rc == 0) break; // End of directory

        var offset: usize = 0;
        while (offset < rc) {
            const entry: *linux.dirent64 = @alignCast(@ptrCast(&kernel_buf[offset]));
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const name = std.mem.span(name_ptr);

            // Skip . and ..
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
                offset += entry.reclen;
                continue;
            }

            // Check if already seen (for overlay merging)
            if (seen.contains(name)) {
                offset += entry.reclen;
                continue;
            }

            // Track this entry
            const name_copy = allocator.dupe(u8, name) catch {
                offset += entry.reclen;
                continue;
            };
            seen.put(name_copy, {}) catch {
                allocator.free(name_copy);
                offset += entry.reclen;
                continue;
            };

            // Skip entries before our offset
            if (entry_index.* < start_offset) {
                entry_index.* += 1;
                offset += entry.reclen;
                continue;
            }

            const written = buildDirent(
                local_buf[buf_pos.*..buf_size],
                entry.ino,
                entry_index.* + 1,
                entry.type,
                name,
            ) orelse break; // Buffer full

            buf_pos.* += written;
            entry_index.* += 1;
            entries_returned.* += 1;

            offset += entry.reclen;
        }
    }
}

/// Build a dirent64 entry into the buffer, returns bytes written or null if not enough space
fn buildDirent(buf: []u8, ino: u64, off: u64, dtype: u8, name: []const u8) ?usize {
    // reclen must be 8-byte aligned and include: header (19 bytes) + name + null terminator
    const name_with_null = name.len + 1;
    const unaligned_size = DIRENT64_NAME_OFFSET + name_with_null;
    const reclen = (unaligned_size + 7) & ~@as(usize, 7); // align to 8 bytes

    if (buf.len < reclen) return null;

    // Zero the entire entry first
    @memset(buf[0..reclen], 0);

    // Write fields manually at correct offsets
    // d_ino at offset 0 (8 bytes, little-endian)
    std.mem.writeInt(u64, buf[0..8], ino, .little);
    // d_off at offset 8 (8 bytes, little-endian)
    std.mem.writeInt(u64, buf[8..16], off, .little);
    // d_reclen at offset 16 (2 bytes, little-endian)
    std.mem.writeInt(u16, buf[16..18], @intCast(reclen), .little);
    // d_type at offset 18 (1 byte)
    buf[18] = dtype;
    // d_name at offset 19 (variable length, null-terminated)
    @memcpy(buf[DIRENT64_NAME_OFFSET..][0..name.len], name);
    // null terminator already set by memset

    return reclen;
}
