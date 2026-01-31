const std = @import("std");
const posix = std.posix;

const Cow = @import("backend/cow.zig").Cow;
const Tmp = @import("backend/tmp.zig").Tmp;
const ProcFile = @import("backend/procfile.zig").ProcFile;
const Passthrough = @import("backend/passthrough.zig").Passthrough;

pub const FileBackend = enum { passthrough, cow, tmp, proc };

pub const File = union(FileBackend) {
    passthrough: Passthrough,
    cow: Cow,
    tmp: Tmp,
    proc: ProcFile,

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
