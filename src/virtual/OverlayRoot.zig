const std = @import("std");
const posix = std.posix;

const Self = @This();

uid: [16]u8,

pub fn init(io: std.Io) !Self {
    _ = io;
    //todo: generate uid, create /tmp/.bvisor/sb/<uid>/{cow,tmp}
    return .{ .uid = undefined };
}

pub fn deinit(self: *Self, io: std.Io) void {
    _ = self;
    _ = io;
    //todo: close directory handles
}

pub fn resolveCow(self: *Self, path: []const u8, buf: []u8) ![]const u8 {
    _ = self;
    _ = path;
    _ = buf;
    //todo: return "<root>/cow/<path>", ensure parent dirs exist
    return error.NotImplemented;
}

pub fn resolveTmp(self: *Self, path: []const u8, buf: []u8) ![]const u8 {
    _ = self;
    _ = path;
    _ = buf;
    //todo: return "<root>/tmp/<path-without-/tmp-prefix>", ensure parent dirs exist
    return error.NotImplemented;
}

pub fn cowExists(self: *Self, path: []const u8) bool {
    _ = self;
    _ = path;
    //todo: check if <root>/cow/<path> exists
    return false;
}
