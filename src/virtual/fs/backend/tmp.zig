const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

pub const Tmp = struct {
    fd: posix.fd_t,

    pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t, overlay: *OverlayRoot) !Tmp {
        _ = path;
        _ = flags;
        _ = mode;
        _ = overlay;
        //todo: resolve via overlay.resolveTmp(), posix.open
        return error.NotImplemented;
    }

    pub fn read(self: *Tmp, buf: []u8) !usize {
        _ = self;
        _ = buf;
        //todo: posix.read(self.fd, buf)
        return error.NotImplemented;
    }

    pub fn write(self: *Tmp, data: []const u8) !usize {
        _ = self;
        _ = data;
        //todo: posix.write(self.fd, data)
        return error.NotImplemented;
    }

    pub fn close(self: *Tmp) void {
        _ = self;
        //todo: posix.close(self.fd)
    }
};
