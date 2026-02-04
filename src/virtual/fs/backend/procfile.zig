const std = @import("std");
const Thread = @import("../../proc/Thread.zig");
const NsTgid = Thread.NsTgid;
const Namespace = @import("../../proc/Namespace.zig");

/// Procfile handles all internals of /proc/<nstgid_or_self>/...
/// The trick is that the content is generated at opentime
/// To avoid tracking different variants of ProcFile
pub const ProcFile = struct {
    content: [256]u8,
    content_len: usize,
    offset: usize,

    pub const ProcTarget = union(enum) {
        self_nstgid,
        self_status,
        nstgid: NsTgid,
        nstgid_status: NsTgid,
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
            if (after_self.len == 0) return .self_nstgid;
            if (std.mem.eql(u8, after_self, "/status")) return .self_status;
            return error.InvalidPath;
        }

        // /proc/<N> or /proc/<N>/status
        const slash_pos = std.mem.indexOfScalar(u8, remainder, '/');
        const nstgid_str = if (slash_pos) |pos| remainder[0..pos] else remainder;

        const nstgid = std.fmt.parseInt(NsTgid, nstgid_str, 10) catch return error.InvalidPath;
        if (nstgid <= 0) return error.InvalidPath;

        if (slash_pos) |pos| {
            const subpath = remainder[pos..];
            if (std.mem.eql(u8, subpath, "/status")) return .{ .nstgid_status = nstgid };
            return error.InvalidPath;
        }

        return .{ .nstgid = nstgid };
    }

    pub fn open(caller: *Thread, path: []const u8) !ProcFile {
        const target = try parseProcPath(path);

        var self = ProcFile{
            .content = undefined,
            .content_len = 0,
            .offset = 0,
        };

        switch (target) {
            .self_nstgid => {
                const leader = try caller.thread_group.getLeader();
                const nstgid = caller.namespace.getNsTid(leader) orelse return error.FileNotFound;
                self.content_len = formatPid(&self.content, nstgid);
            },
            .self_status => {
                self.content_len = try formatStatus(&self.content, caller);
            },
            .nstgid => |nstgid| {
                // Note: this depends on syncNewThreads being called proactively, else risk a not-registered NsTgid.
                // This syncNewThreads is called one level up, in openat.
                const target_thread = caller.namespace.threads.get(nstgid) orelse return error.FileNotFound;
                _ = target_thread;
                self.content_len = formatPid(&self.content, nstgid);
            },
            .nstgid_status => |nstgid| {
                // Same case as above re: syncNewThreads
                const target_thread = caller.namespace.threads.get(nstgid) orelse return error.FileNotFound;
                self.content_len = try formatStatus(&self.content, target_thread);
            },
        }

        return self;
    }

    fn formatPid(buf: *[256]u8, nstgid: i32) usize {
        const slice = std.fmt.bufPrint(buf, "{d}\n", .{nstgid}) catch unreachable;
        return slice.len;
    }

    fn formatStatus(buf: *[256]u8, target: *Thread) !usize {
        const leader = try target.thread_group.getLeader();
        const nstgid = target.namespace.getNsTid(leader) orelse 0;

        const nsptgid: NsTgid = if (target.thread_group.parent) |parent_process| blk: {
            const parent = try parent_process.getLeader();
            break :blk target.namespace.getNsTid(parent) orelse 0;
        } else 0;

        // TODO: support more status content lookup, this isn't 100% compatible
        // We also use the same name for everything
        const name = "bvisor-guest";
        const slice = std.fmt.bufPrint(buf, "Name:\t{s}\nPid:\t{d}\nPPid:\t{d}\n", .{ name, nstgid, nsptgid }) catch unreachable;
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
const Threads = @import("../../proc/Threads.zig");
const proc_info = @import("../../../deps/proc_info/proc_info.zig");

test "parseProcPath - /proc/self" {
    const target = try ProcFile.parseProcPath("/proc/self");
    try testing.expect(target == .self_nstgid);
}

test "parseProcPath - /proc/self/status" {
    const target = try ProcFile.parseProcPath("/proc/self/status");
    try testing.expect(target == .self_status);
}

test "parseProcPath - /proc/123" {
    const target = try ProcFile.parseProcPath("/proc/123");
    try testing.expectEqual(ProcFile.ProcTarget{ .nstgid = 123 }, target);
}

test "parseProcPath - /proc/123/status" {
    const target = try ProcFile.parseProcPath("/proc/123/status");
    try testing.expectEqual(ProcFile.ProcTarget{ .nstgid_status = 123 }, target);
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

test "open /proc/self returns guest nstgid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    // Root Thread NsTgid is 100 (the AbsTgid used as NsTgid in root namespace)
    try testing.expectEqualStrings("100\n", buf[0..n]);
}

test "open /proc/self/status contains Pid and PPid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Add a child
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    // Child's NsTgid is 200, parent is 100
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t200\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t100\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "Name:\tbvisor-guest\n") != null);
}

test "open /proc/<N> returns pid for visible Thread" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));

    // Root can see child at NsTgid 200
    var file = try ProcFile.open(root, "/proc/200");
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqualStrings("200\n", buf[0..n]);
}

test "open /proc/<N> returns error for non-existent pid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    try testing.expectError(error.FileNotFound, ProcFile.open(root, "/proc/999"));
}

test "open /proc/<N>/status for visible Thread" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Create child in new namespace
    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

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
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    try testing.expectError(error.ReadOnlyFileSystem, file.write("test"));
}

test "parseProcPath - /proc/0 (zero PID) is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/0"));
}

test "parseProcPath - /proc/-1 (negative) is invalid" {
    try testing.expectError(error.InvalidPath, ProcFile.parseProcPath("/proc/-1"));
}

test "child in new namespace (CLONE_NEWPID) /proc/self returns 1" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Child in new namespace gets NsTgid 1
    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self");
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqualStrings("1\n", buf[0..n]);
}

test "open /proc/self/status - child with parent invisible (new namespace) has PPid 0" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t0\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t1\n") != null);
}

test "open /proc/self/status - child with visible parent has correct PPid" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));
    const child = v_threads.lookup.get(200).?;

    var file = try ProcFile.open(child, "/proc/self/status");
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    const content = buf[0..n];

    try testing.expect(std.mem.indexOf(u8, content, "Pid:\t200\n") != null);
    try testing.expect(std.mem.indexOf(u8, content, "PPid:\t100\n") != null);
}

test "open /proc/N where N is in different namespace returns FileNotFound" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Child in new namespace
    const nstids = [_]NsTgid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &nstids);
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(std.os.linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    // Child cannot see root (NsTgid 100) since root is not in child's namespace
    try testing.expectError(error.FileNotFound, ProcFile.open(child, "/proc/100"));
}

test "read past end returns 0 (EOF)" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    // Content is "100\n" (4 bytes)

    // Read all content
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expect(n > 0);

    // Second read should return 0 (EOF)
    const n2 = try file.read(&buf);
    try testing.expectEqual(@as(usize, 0), n2);
}

test "read with 1-byte buffer walks through content" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(5);
    const proc = v_threads.lookup.get(5).?;

    var file = try ProcFile.open(proc, "/proc/self");
    // Content is "5\n" (2 bytes)

    var byte_buf: [1]u8 = undefined;
    var n = try file.read(&byte_buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, '5'), byte_buf[0]);

    n = try file.read(&byte_buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, '\n'), byte_buf[0]);

    n = try file.read(&byte_buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "close is no-op" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

    var file = try ProcFile.open(proc, "/proc/self");
    file.close();
    // No error = success
}

test "content frozen at open time (snapshot semantics)" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    // Open /proc/self/status for root (should show child count context)
    var file = try ProcFile.open(root, "/proc/self");
    // Content is "100\n" captured at open time

    // Now add a child - this shouldn't affect the already-opened file
    _ = try v_threads.registerChild(root, 200, Threads.CloneFlags.from(0));

    // Read from the already-opened file - should still show original content
    var buf: [64]u8 = undefined;
    const n = try file.read(&buf);
    try testing.expectEqualStrings("100\n", buf[0..n]);
}

test "offset tracking works across multiple reads" {
    const allocator = testing.allocator;
    var v_threads = Threads.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const proc = v_threads.lookup.get(100).?;

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
