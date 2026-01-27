const std = @import("std");
const posix = std.posix;

pub const Proc = struct {
    //todo: guest_pid, offset fields

    pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t) !Proc {
        _ = path;
        _ = flags;
        _ = mode;
        //todo: parse /proc/self or /proc/<pid>, return Proc with guest pid
        return error.NotImplemented;
    }

    pub fn read(self: *Proc, buf: []u8) !usize {
        _ = self;
        _ = buf;
        //todo: format guest pid as string, track offset
        return error.NotImplemented;
    }

    pub fn write(self: *Proc, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.ReadOnlyFileSystem;
    }

    pub fn close(self: *Proc) void {
        _ = self;
        // nothing to close
    }
};
