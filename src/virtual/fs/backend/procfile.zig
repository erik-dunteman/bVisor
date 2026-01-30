const std = @import("std");
const Proc = @import("../../proc/Proc.zig");
const Namespace = @import("../../proc/Namespace.zig");

/// Procfile handles all internals of /proc/<pid_or_self>/...
/// Its trick is that the content is generated at opentime
/// To avoid tracking different variants of ProcFile
pub const ProcFile = struct {
    content: [256]u8,
    content_len: usize,
    offset: usize,

    pub const ProcTarget = union(enum) {
        self_pid,
        self_status,
        pid: Proc.NsPid,
        pid_status: Proc.NsPid,
    };

    pub fn parseProcPath(path: []const u8) !ProcTarget {
        // path comes in as the full path e.g. "/proc/self" or "/proc/123/status"
        const prefix = "/proc/";
        if (!std.mem.startsWith(u8, path, prefix)) return error.InvalidPath;
        const remainder = path[prefix.len..];
        if (remainder.len == 0) return error.InvalidPath;

        // /proc/self or /proc/self/status
        if (std.mem.startsWith(u8, remainder, "self")) {
            const after_self = remainder["self".len..];
            if (after_self.len == 0) return .self_pid;
            if (std.mem.eql(u8, after_self, "/status")) return .self_status;
            return error.InvalidPath;
        }

        // /proc/<N> or /proc/<N>/status
        const slash_pos = std.mem.indexOfScalar(u8, remainder, '/');
        const pid_str = if (slash_pos) |pos| remainder[0..pos] else remainder;

        const pid = std.fmt.parseInt(Proc.NsPid, pid_str, 10) catch return error.InvalidPath;
        if (pid <= 0) return error.InvalidPath;

        if (slash_pos) |pos| {
            const subpath = remainder[pos..];
            if (std.mem.eql(u8, subpath, "/status")) return .{ .pid_status = pid };
            return error.InvalidPath;
        }

        return .{ .pid = pid };
    }

    pub fn open(caller: *Proc, path: []const u8) !ProcFile {
        const target = try parseProcPath(path);

        var self = ProcFile{
            .content = undefined,
            .content_len = 0,
            .offset = 0,
        };

        switch (target) {
            .self_pid => {
                const guest_pid = caller.namespace.getNsPid(caller) orelse return error.FileNotFound;
                self.content_len = formatPid(&self.content, guest_pid);
            },
            .self_status => {
                self.content_len = formatStatus(&self.content, caller);
            },
            .pid => |guest_pid| {
                // Note: this depends on syncNewProcs being called proactively, else risk a not-registered PID.
                // This syncNewProcs is called one level up, in openat.
                const target_proc = caller.namespace.procs.get(guest_pid) orelse return error.FileNotFound;
                _ = target_proc;
                self.content_len = formatPid(&self.content, guest_pid);
            },
            .pid_status => |guest_pid| {
                // Same case as above re: syncNewProcs
                const target_proc = caller.namespace.procs.get(guest_pid) orelse return error.FileNotFound;
                self.content_len = formatStatus(&self.content, target_proc);
            },
        }

        return self;
    }

    fn formatPid(buf: *[256]u8, pid: Proc.NsPid) usize {
        const slice = std.fmt.bufPrint(buf, "{d}\n", .{pid}) catch unreachable;
        return slice.len;
    }

    fn formatStatus(buf: *[256]u8, target: *Proc) usize {
        const guest_pid = target.namespace.getNsPid(target) orelse 0;

        // PPid: if target has a parent visible in the same namespace, use its guest PID. Otherwise 0.
        const ppid: Proc.NsPid = if (target.parent) |parent|
            target.namespace.getNsPid(parent) orelse 0
        else
            0;

        // TODO: support more status content lookup, this isn't 100% compatible
        // We also use the same name for everything
        const name = "bvisor-guest";
        const slice = std.fmt.bufPrint(buf, "Name:\t{s}\nPid:\t{d}\nPPid:\t{d}\n", .{ name, guest_pid, ppid }) catch unreachable;
        return slice.len;
    }

    pub fn read(self: *ProcFile, buf: []u8) !usize {
        const remaining = self.content[self.offset..self.content_len];
        if (remaining.len == 0) return 0;
        const n = @min(buf.len, remaining.len);
        @memcpy(buf[0..n], remaining[0..n]);
        self.offset += n;
        return n;
    }

    pub fn write(self: *ProcFile, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.ReadOnlyFileSystem;
    }

    pub fn close(self: *ProcFile) void {
        _ = self;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const Procs = @import("../../proc/Procs.zig");
const proc_info = @import("../../../deps/proc_info/proc_info.zig");

test "parseProcPath - /proc/self" {
    const target = try ProcFile.parseProcPath("/proc/self");
    try testing.expect(target == .self_pid);
}

test "parseProcPath - /proc/self/status" {
    const target = try ProcFile.parseProcPath("/proc/self/status");
    try testing.expect(target == .self_status);
}

test "parseProcPath - /proc/123" {
    const target = try ProcFile.parseProcPath("/proc/123");
    try testing.expectEqual(ProcFile.ProcTarget{ .pid = 123 }, target);
}

test "parseProcPath - /proc/123/status" {
    const target = try ProcFile.parseProcPath("/proc/123/status");
    try testing.expectEqual(ProcFile.ProcTarget{ .pid_status = 123 }, target);
}

test "parseProcPath - /proc/ alone is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/"));
}

test "parseProcPath - /proc/self/bogus is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/self/bogus"));
}

test "parseProcPath - /proc/abc is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/abc"));
}

test "parseProcPath - /proc/123/bogus is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/123/bogus"));
}

test "parseProcPath - /wrong/prefix is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/wrong/self"));
}

test "open /proc/self returns guest pid" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const proc = v_procs.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    // Guest PID for root process is 100 (the supervisor PID used as guest PID in root namespace)
    try testing.expectEqualStrings("100\n", buf[0..n]);
}

test "open /proc/self/status contains Pid and PPid" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;

    // Add a child
    _ = try v_procs.registerChild(root, 200, Procs.CloneFlags.from(0));
    const child = v_procs.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    // Child's guest PID is 200, parent is 100
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t200\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t100\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "Name:\tbvisor-guest\n") != null);
}

test "open /proc/<N> returns pid for visible process" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;
    _ = try v_procs.registerChild(root, 200, Procs.CloneFlags.from(0));

    // Root can see child at guest PID 200
    var file = try ProcFile.open(root, "/proc/200");
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqualStrings("200\n", buf[0..n]);
}

test "open /proc/<N> returns error for non-existent pid" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;

    try testing.expectError(error.FileNotFound, ProcFile.open(root, "/proc/999"));
}

test "open /proc/<N>/status for visible process" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();
    defer proc_info.testing.reset(allocator);

    try v_procs.handleInitialProcess(100);
    const root = v_procs.lookup.get(100).?;

    // Create child in new namespace
    const nspids = [_]Proc.NsPid{ 200, 1 };
    try proc_info.testing.setupNsPids(allocator, 200, &nspids);
    _ = try v_procs.registerChild(root, 200, Procs.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_procs.lookup.get(200).?;

    // From child's namespace, child is PID 1. PPid is 0 (parent not visible in child ns)
    var file = try ProcFile.open(child, "/proc/1/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t1\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t0\n") != null);
}

test "write returns ReadOnlyFileSystem" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const proc = v_procs.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    try testing.expectError(error.ReadOnlyFileSystem, file.write("test"));
}

test "offset tracking works across multiple reads" {
    const allocator = testing.allocator;
    var v_procs = Procs.init(allocator);
    defer v_procs.deinit();

    try v_procs.handleInitialProcess(100);
    const proc = v_procs.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    // Content is "100\n" (4 bytes)

    // Read 2 bytes at a time
    var buf: [2]u8 = undefined;
    var n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("10", buf[0..n]);

    n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("0\n", buf[0..n]);

    // EOF
    n = try file.read(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}
