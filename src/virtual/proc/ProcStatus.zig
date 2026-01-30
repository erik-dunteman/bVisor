const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");
const NsPid = Proc.NsPid;
const AbsPid = Proc.AbsPid;

const Self = @This();

pub const MAX_NS_DEPTH = 128;

pid: AbsPid,
ppid: AbsPid,
nspids_buf: [MAX_NS_DEPTH]NsPid = undefined,
nspids_len: usize = 0,

pub fn nspids(self: *const Self) []const NsPid {
    return self.nspids_buf[0..self.nspids_len];
}
