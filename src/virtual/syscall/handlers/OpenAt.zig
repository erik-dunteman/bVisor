const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Proc = @import("../../../virtual/proc/Proc.zig");
const Procs = @import("../../../virtual/proc/Procs.zig");
const FD = @import("../../../virtual/fs/FD.zig").FD;
const FdTable = @import("../../../virtual/fs/FdTable.zig");
const types = @import("../../../types.zig");
const Supervisor = @import("../../../Supervisor.zig");
const KernelFD = types.KernelFD;
const Result = @import("../syscall.zig").Syscall.Result;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

kernel_pid: Proc.KernelPID,
dirfd: KernelFD,
path_len: usize,
path_buf: [256]u8, // fixed stack buffer, limits size of string read
flags: linux.O,
mode: linux.mode_t,

pub fn path(self: *const Self) []const u8 {
    return self.path_buf[0..self.path_len];
}

/// Normalize a path, resolving . and .. components.
/// Returns the normalized path in the provided buffer, or error if buffer too small.
pub fn normalizePath(path_str: []const u8, buf: []u8) ![]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    return std.fs.path.resolvePosix(fba.allocator(), &.{path_str}) catch |err| switch (err) {
        error.OutOfMemory => return error.PathTooLong,
    };
}

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path_slice = try memory_bridge.readString(
        &path_buf,
        @intCast(notif.pid),
        path_ptr,
    );

    const dirfd: KernelFD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));
    const mode: linux.mode_t = @truncate(notif.data.arg3);

    return .{
        .kernel_pid = @intCast(notif.pid),
        .dirfd = dirfd,
        .path_len = path_slice.len,
        .path_buf = path_buf,
        .flags = flags,
        .mode = mode,
    };
}

// Path resolution rules

pub const Action = enum {
    block,
    allow,
    // Special handlers
    virtualize_proc,
};

pub const Rule = union(enum) {
    /// Terminal - this prefix resolves to an action
    terminal: Action,
    /// Branch - check children, with a default if none match
    branch: struct {
        children: []const PathRule,
        default: Action,
    },
};

pub const PathRule = struct {
    prefix: []const u8,
    rule: Rule,
};

/// The root filesystem rules
pub const default_action: Action = .block;
pub const fs_rules: []const PathRule = &.{
    // Hard blocks
    .{ .prefix = "/sys", .rule = .{ .terminal = .block } },
    .{ .prefix = "/run", .rule = .{ .terminal = .block } },

    // Allowed (passthrough)
    .{ .prefix = "/tmp", .rule = .{ .terminal = .allow } },

    // Virtualized
    .{ .prefix = "/proc", .rule = .{ .terminal = .virtualize_proc } },
};

/// Resolve a path to an action, normalizing it first to handle .. components.
pub fn resolve(path_str: []const u8) !Action {
    var buf: [512]u8 = undefined;
    const normalized = try normalizePath(path_str, &buf);
    return resolveWithRules(normalized, fs_rules, default_action);
}

/// Check if path matches a directory prefix (handles trailing slash variations)
/// Matches: /tmp -> /tmp, /tmp/, /tmp/foo but NOT /tmpfoo
/// Returns remainder after prefix (e.g., /tmp/foo with /tmp returns "foo"), or null if no match
fn matchesPrefix(path_str: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path_str, prefix)) return null;
    if (path_str.len == prefix.len) return ""; // exact match
    if (path_str[prefix.len] == '/') return path_str[prefix.len + 1 ..]; // skip the /
    return null; // e.g., /tmpfoo doesn't match /tmp
}

fn resolveWithRules(path_str: []const u8, rules: []const PathRule, default: Action) Action {
    for (rules) |rule| {
        if (matchesPrefix(path_str, rule.prefix)) |remainder| {
            switch (rule.rule) {
                .terminal => |action| return action,
                .branch => |branch| return resolveWithRules(remainder, branch.children, branch.default),
            }
        }
    }
    return default;
}

/// Returns true if the flags indicate a write operation requiring VFS redirect
pub fn useVFS(flags: linux.O) bool {
    return flags.ACCMODE == .WRONLY or flags.ACCMODE == .RDWR or flags.CREAT;
}

/// Convert linux.O flags to posix.O flags.
/// Required because linux and darwin have different bit layouts for O flags.
fn linuxOToPosixO(flags: linux.O) posix.O {
    var result: posix.O = .{};

    // Access mode (RDONLY=0, WRONLY=1, RDWR=2)
    result.ACCMODE = switch (flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };

    // Individual flags
    if (flags.CREAT) result.CREAT = true;
    if (flags.EXCL) result.EXCL = true;
    if (flags.NOCTTY) result.NOCTTY = true;
    if (flags.TRUNC) result.TRUNC = true;
    if (flags.APPEND) result.APPEND = true;
    if (flags.NONBLOCK) result.NONBLOCK = true;
    if (flags.DIRECTORY) result.DIRECTORY = true;
    if (flags.NOFOLLOW) result.NOFOLLOW = true;
    if (flags.CLOEXEC) result.CLOEXEC = true;
    if (flags.SYNC) result.SYNC = true;

    return result;
}

fn posixErrorToLinuxErrno(err: posix.OpenError) linux.E {
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.FileNotFound => .NOENT,
        error.IsDir => .ISDIR,
        error.NotDir => .NOTDIR,
        error.PathAlreadyExists => .EXIST,
        error.NoSpaceLeft => .NOSPC,
        error.FileBusy => .BUSY,
        error.NameTooLong => .NAMETOOLONG,
        error.SymLinkLoop => .LOOP,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => .MFILE,
        error.NoDevice => .NODEV,
        error.SystemResources => .NOMEM,
        error.FileTooBig => .FBIG,
        error.WouldBlock => .AGAIN,
        error.PermissionDenied => .PERM,
        else => .IO,
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating openat: dirfd={d} path={s} flags={any}", .{
        self.dirfd,
        self.path(),
        self.flags,
    });

    const action = try resolve(self.path());
    logger.log("Action: {s}", .{@tagName(action)});
    switch (action) {
        .block => {
            logger.log("openat: blocked path: {s}", .{self.path()});
            return Result.reply_err(.PERM);
        },
        .allow => {
            logger.log("openat: allowed path: {s}", .{self.path()});
            return self.handleAllow(supervisor);
        },
        .virtualize_proc => {
            logger.log("openat: virtualizing proc path: {s}", .{self.path()});
            return self.handleVirtualizeProc(supervisor);
        },
    }
}

fn handleVirtualizeProc(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Look up the calling process
    const proc = supervisor.virtual_procs.lookup.get(self.kernel_pid) orelse {
        logger.log("openat: kernel pid {d} not found in virtual_procs", .{self.kernel_pid});
        return Result.reply_err(.NOENT);
    };

    // Parse the /proc path to get target pid
    const path_str = self.path();

    var parts = std.mem.tokenizeScalar(u8, path_str, '/');
    _ = parts.next(); // skip "proc"
    const pid_part = parts.next() orelse return Result.reply_err(.NOENT);

    // Determine target pid
    // Format: /proc/self/..., /proc/<pid>/..., or global files like /proc/meminfo
    const target_pid: Proc.KernelPID = if (std.mem.eql(u8, pid_part, "self"))
        proc.pid
    else
        std.fmt.parseInt(Proc.KernelPID, pid_part, 10) catch
            // Not a numeric pid - global proc file (e.g., meminfo, cpuinfo)
            // Use caller's pid as placeholder
            proc.pid;

    const virtual_fd = FD{ .proc = .{ .self = .{ .pid = target_pid } } };

    // Insert into the process's fd_table and get virtual fd number
    const vfd = try proc.fd_table.open(virtual_fd);

    logger.log("openat: opened virtual fd={d}", .{vfd});

    return Result.reply_success(@intCast(vfd));
}

fn handleAllow(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Look up the calling process
    const proc = supervisor.virtual_procs.lookup.get(self.kernel_pid) orelse {
        logger.log("openat: kernel pid {d} not found in virtual_procs", .{self.kernel_pid});
        return Result.reply_err(.NOENT);
    };

    // Perform the open ourselves using posix (works on both Linux and macOS for tests)
    // Note: dirfd translation would be needed for relative paths with non-AT_FDCWD dirfd
    const path_slice = self.path_buf[0..self.path_len :0];

    // Convert linux.O flags to posix.O flags (different bit layouts on Linux vs Darwin)
    const posix_flags = linuxOToPosixO(self.flags);

    const kfd = posix.openat(self.dirfd, path_slice, posix_flags, @truncate(self.mode)) catch |err| {
        const errno = posixErrorToLinuxErrno(err);
        logger.log("openat: kernel open failed: {s}", .{@tagName(errno)});
        return Result.reply_err(errno);
    };

    // Store in fd_table as kernel fd
    const vfd = try proc.fd_table.open(.{ .kernel = kfd });

    logger.log("openat: opened kernel fd={d} as vfd={d}", .{ kfd, vfd });

    return Result.reply_success(@intCast(vfd));
}

test "openat blocks /sys and /run paths" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const blocked_paths = [_][*:0]const u8{
        "/sys/class/net",
        "/run/docker.sock",
    };

    for (blocked_paths) |path_ptr| {
        const notif = makeNotif(.openat, .{
            .pid = child_pid,
            .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
            .arg1 = @intFromPtr(path_ptr),
            .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
        });

        const parsed = try Self.parse(notif);
        const res = try parsed.handle(&supervisor);
        try testing.expect(res == .reply);
        try testing.expect(res.is_error());
    }
}

test "useVFS detects write modes" {
    try testing.expect(!useVFS(linux.O{ .ACCMODE = .RDONLY }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .WRONLY }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .RDWR }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .RDONLY, .CREAT = true }));
}

test "openat virtualizes /proc paths" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .reply);
    try testing.expect(!res.is_error());
}

test "openat handles allowed paths (returns NOENT for missing file)" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/tmp/nonexistent_test_file.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .reply);
    try testing.expect(res.is_error());
    try testing.expectEqual(linux.E.NOENT, @as(linux.E, @enumFromInt(res.reply.errno)));
}

test "openat O_CREAT creates file, write and read back" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const test_path = "/tmp/bvisor_test_creat.txt";
    const test_content = "hello bvisor";

    // Set up I/O for file operations
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    // Clean up any existing file first
    std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};
    defer std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};

    // Step 1: Create and write to file
    {
        const notif = makeNotif(.openat, .{
            .pid = child_pid,
            .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
            .arg1 = @intFromPtr(test_path),
            .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true }))),
            .arg3 = 0o644,
        });

        const parsed = try Self.parse(notif);
        const res = try parsed.handle(&supervisor);
        try testing.expect(res == .reply);
        try testing.expect(!res.is_error());

        const vfd: FdTable.VirtualFD = @intCast(res.reply.val);
        try testing.expectEqual(@as(FdTable.VirtualFD, 3), vfd);

        // Get the FD and write to it
        const proc = supervisor.virtual_procs.lookup.get(child_pid).?;
        var fd = proc.fd_table.get(vfd).?;
        const kfd = fd.kernel; // get the kernel fd
        _ = try posix.write(kfd, test_content);
        posix.close(kfd);
        _ = proc.fd_table.remove(vfd);
    }

    // Step 2: Open for read and verify content
    {
        const notif = makeNotif(.openat, .{
            .pid = child_pid,
            .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
            .arg1 = @intFromPtr(test_path),
            .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
        });

        const parsed = try Self.parse(notif);
        const res = try parsed.handle(&supervisor);
        try testing.expect(res == .reply);
        try testing.expect(!res.is_error());

        const vfd: FdTable.VirtualFD = @intCast(res.reply.val);

        // Read via FD.read
        const proc = supervisor.virtual_procs.lookup.get(child_pid).?;
        var fd = proc.fd_table.get(vfd).?;
        var buf: [64]u8 = undefined;
        const n = try fd.read(&buf);
        try testing.expectEqualStrings(test_content, buf[0..n]);

        posix.close(fd.kernel);
    }
}

test "resolve /proc/self triggers virtualize" {
    try testing.expect(try resolve("/proc/self") == .virtualize_proc);
}

test "path traversal /proc/../etc/passwd does not virtualize" {
    try testing.expect(try resolve("/proc/../etc/passwd") == .block);
}
