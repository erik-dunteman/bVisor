const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

pub const Cow = union(enum) {
    passthrough: posix.fd_t,
    writecopy: posix.fd_t,

    pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t, overlay: *OverlayRoot) !Cow {
        _ = path;
        _ = flags;
        _ = mode;
        _ = overlay;
        //todo: if wants_write or overlay.cowExists(path) -> writecopy, else passthrough
        return error.NotImplemented;
    }

    pub fn read(self: *Cow, buf: []u8) !usize {
        _ = self;
        _ = buf;
        //todo: posix.read on either variant's fd
        return error.NotImplemented;
    }

    pub fn write(self: *Cow, data: []const u8) !usize {
        _ = self;
        _ = data;
        //todo: passthrough -> error.ReadOnlyFileSystem, writecopy -> posix.write
        return error.NotImplemented;
    }

    pub fn close(self: *Cow) void {
        _ = self;
        //todo: posix.close on fd
    }
};
