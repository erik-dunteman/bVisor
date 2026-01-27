const std = @import("std");
const posix = std.posix;
const Cow = @import("backend/cow.zig").Cow;
const Tmp = @import("backend/tmp.zig").Tmp;
const Proc = @import("backend/proc.zig").Proc;
const OverlayRoot = @import("../OverlayRoot.zig");

pub const FileBackend = enum { cow, tmp, proc };

pub const File = union(FileBackend) {
    cow: Cow,
    tmp: Tmp,
    proc: Proc,

    pub fn open(backend: FileBackend, path: []const u8, flags: posix.O, mode: posix.mode_t, overlay: *OverlayRoot) !File {
        return switch (backend) {
            .cow => .{ .cow = try Cow.open(path, flags, mode, overlay) },
            .tmp => .{ .tmp = try Tmp.open(path, flags, mode, overlay) },
            .proc => .{ .proc = try Proc.open(path, flags, mode) },
        };
    }

    pub fn read(self: *File, buf: []u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.read(buf),
        }
    }

    pub fn write(self: *File, data: []const u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.write(data),
        }
    }

    pub fn close(self: *File) void {
        switch (self.*) {
            inline else => |*f| f.close(),
        }
    }
};
