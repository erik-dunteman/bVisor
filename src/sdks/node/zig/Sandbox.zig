const napi = @import("napi.zig");
const c = napi.c;
const std = @import("std");

counter: i32 = 0,

const Self = @This();

// Lifecycle helpers expect init/deinit
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{};
    return self;
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    allocator.destroy(self);
}

// Public API must follow napi interface
// Returns JS type (RunCmdResult)
pub fn runCmd(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const self = napi.ZigExternal(Self).unwrap(env, info) catch return null;
    _ = self;

    // TODO: actually run command
    var stdout: ?*Stream = Stream.init(napi.allocator) catch return null;
    errdefer if (stdout) |s| s.deinit(napi.allocator);
    var stderr: ?*Stream = Stream.init(napi.allocator) catch return null;
    errdefer if (stderr) |s| s.deinit(napi.allocator);

    // Wrap into externals - after wrap(), JS owns the memory via GC finalizer
    const stdoutExternal = napi.ZigExternal(Stream).wrap(env, stdout.?) catch return null;
    stdout = null; // Transfer ownership to JS, effectively cancelling errdefer
    const stderrExternal = napi.ZigExternal(Stream).wrap(env, stderr.?) catch return null;
    stderr = null; // Transfer ownership to JS, effectively cancelling errdefer

    // Create object to return
    const result = napi.createObject(env) catch return null;
    if (result == null) return null;

    // Register externals as properties on object
    napi.setProperty(env, result, "stdout", stdoutExternal) catch return null;
    napi.setProperty(env, result, "stderr", stderrExternal) catch return null;

    return result;
}

pub const Stream = struct {
    content: []const u8 = "a b c d e f g h i j k l m n o p q r s t u v w x y z",
    cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !*Stream {
        const self = try allocator.create(Stream);
        self.* = .{};
        return self;
    }

    pub fn deinit(self: *Stream, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    /// Returns JS type (Uint8array | none)
    pub fn next(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
        const self = napi.ZigExternal(Stream).unwrap(env, info) catch return null;

        if (self.cursor >= self.content.len) return napi.getNull(env) catch return null;

        const chunk = self.content[self.cursor..@min(self.cursor + 5, self.content.len)];
        defer self.cursor += 5;

        if (chunk.len == 0) return napi.getNull(env) catch return null;
        return napi.createUint8Array(env, chunk.ptr, chunk.len) catch return null;
    }
};
