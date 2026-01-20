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
    virtualize_tmp,
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

    // Virtualized - private /tmp (all reads/writes redirected)
    // Block .bvisor internal directory, allow everything else in /tmp
    .{ .prefix = "/tmp", .rule = .{ .branch = .{
        .children = &.{
            .{ .prefix = ".bvisor", .rule = .{ .terminal = .block } },
        },
        .default = .virtualize_tmp,
    } } },

    // Virtualized - /proc
    .{ .prefix = "/proc", .rule = .{ .terminal = .virtualize_proc } },
};

/// Resolve a path to an action, normalizing it first to handle .. components.
pub fn resolve(path_str: []const u8) !Action {
    var buf: [512]u8 = undefined;
    const normalized = try normalizePath(path_str, &buf);
    return resolveWithRules(normalized, fs_rules, default_action);
}

/// Check if path matches a directory prefix (handles trailing slash variations)
/// Returns remainder after prefix, or null if no match
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
            return Result.replyErr(.PERM);
        },
        .allow => {
            logger.log("openat: allowed path: {s}", .{self.path()});
            return self.handleAllow(supervisor);
        },
        .virtualize_proc => {
            logger.log("openat: virtualizing proc path: {s}", .{self.path()});
            return self.handleVirtualizeProc(supervisor);
        },
        .virtualize_tmp => {
            logger.log("openat: virtualizing tmp path: {s}", .{self.path()});
            return self.handleVirtualizeTmp(supervisor);
        },
    }
}

fn handleVirtualizeProc(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Look up the calling process
    const proc = try supervisor.virtual_procs.get(self.kernel_pid);

    // Parse the /proc path to get target pid
    const path_str = self.path();

    var parts = std.mem.tokenizeScalar(u8, path_str, '/');
    _ = parts.next(); // skip "proc"
    const pid_part = parts.next() orelse return Result.replyErr(.NOENT);

    // Determine target pid
    // Format: /proc/self/..., /proc/<pid>/..., or global files like /proc/meminfo
    const target_pid: Proc.KernelPID = if (std.mem.eql(u8, pid_part, "self"))
        proc.pid
    else
        std.fmt.parseInt(Proc.KernelPID, pid_part, 10) catch
            // Not a numeric pid - global proc file (e.g., meminfo, cpuinfo)
            // Use caller's pid as placeholder
            proc.pid;

    // Ensure calling proc can see target proc
    // Return ENOENT for all lookup failures - matches how Linux /proc hides inaccessible processes
    const target_proc = supervisor.virtual_procs.get(target_pid) catch
        return Result.replyErr(.NOENT);

    if (!proc.canSee(target_proc)) {
        return Result.replyErr(.NOENT);
    }

    const virtual_fd = FD{ .proc = .{ .self = .{ .pid = target_pid } } };

    // Insert into the process's fd_table and get virtual fd number
    const vfd = try proc.fd_table.open(virtual_fd);

    logger.log("openat: opened virtual fd={d}", .{vfd});

    return Result.replySuccess(@intCast(vfd));
}

fn handleVirtualizeTmp(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Look up the calling process
    const proc = supervisor.virtual_procs.lookup.get(self.kernel_pid) orelse {
        std.debug.panic("openat: supervisor invariant violated - kernel pid {d} not in virtual_procs", .{self.kernel_pid});
    };

    const path_slice = self.path();

    // Open via private tmp - all reads and writes go to sandbox-local directory
    const tmp_fd = supervisor.tmp.open(path_slice, self.flags, self.mode) catch |err| {
        const errno = tmpErrorToLinuxErrno(err);
        logger.log("openat: tmp open failed: {s}", .{@tagName(errno)});
        return Result.replyErr(errno);
    };

    // Store in fd_table - use kernel fd type since it's a real fd to a real file
    const vfd = try proc.fd_table.open(.{ .kernel = tmp_fd });

    logger.log("openat: opened private tmp fd={d} as vfd={d}", .{ tmp_fd, vfd });

    return Result.replySuccess(@intCast(vfd));
}

fn tmpErrorToLinuxErrno(err: anytype) linux.E {
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.FileNotFound => .NOENT,
        error.IsDir => .ISDIR,
        error.NotDir => .NOTDIR,
        error.PathAlreadyExists => .EXIST,
        error.NoSpaceLeft => .NOSPC,
        error.NameTooLong => .NAMETOOLONG,
        error.InvalidPath => .INVAL,
        error.SymLinkLoop => .LOOP,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => .MFILE,
        error.SystemResources => .NOMEM,
        else => .IO,
    };
}

fn handleAllow(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    // Look up the calling process
    const proc = supervisor.virtual_procs.lookup.get(self.kernel_pid) orelse {
        // If the calling process isn't tracked, it's a supervisor invariant violation
        std.debug.panic("openat: supervisor invariant violated - kernel pid {d} not in virtual_procs", .{self.kernel_pid});
    };

    const path_slice = self.path_buf[0..self.path_len :0];

    // Normalize the path for COW lookup
    var norm_buf: [512]u8 = undefined;
    const normalized_path = normalizePath(path_slice, &norm_buf) catch path_slice;

    // Check if we should use COW: either writing or COW file already exists
    const should_use_cow = useVFS(self.flags) or supervisor.cow.exists(normalized_path);

    if (should_use_cow) {
        logger.log("openat: using COW for path: {s}", .{normalized_path});

        // Use COW filesystem
        const cow_fd = supervisor.cow.open(normalized_path, self.flags, self.mode) catch |err| {
            const errno = cowErrorToLinuxErrno(err);
            logger.log("openat: COW open failed: {s}", .{@tagName(errno)});
            return Result.replyErr(errno);
        };

        // Store in fd_table as COW fd
        const vfd = try proc.fd_table.open(.{ .cow = .{ .backing_fd = cow_fd } });

        logger.log("openat: opened COW fd={d} as vfd={d}", .{ cow_fd, vfd });

        return Result.replySuccess(@intCast(vfd));
    }

    // Read-only access with no existing COW - open original file directly
    logger.log("openat: passthrough for read-only path: {s}", .{path_slice});

    // Convert linux.O flags to posix.O flags (different bit layouts on Linux vs Darwin)
    const posix_flags = linuxOToPosixO(self.flags);

    const kfd = posix.openat(self.dirfd, path_slice, posix_flags, @truncate(self.mode)) catch |err| {
        const errno = posixErrorToLinuxErrno(err);
        logger.log("openat: kernel open failed: {s}", .{@tagName(errno)});
        return Result.replyErr(errno);
    };

    // Store in fd_table as kernel fd
    const vfd = try proc.fd_table.open(.{ .kernel = kfd });

    logger.log("openat: opened kernel fd={d} as vfd={d}", .{ kfd, vfd });

    return Result.replySuccess(@intCast(vfd));
}

fn cowErrorToLinuxErrno(err: anytype) linux.E {
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.FileNotFound => .NOENT,
        error.IsDir => .ISDIR,
        error.NotDir => .NOTDIR,
        error.PathAlreadyExists => .EXIST,
        error.NoSpaceLeft => .NOSPC,
        error.NameTooLong => .NAMETOOLONG,
        error.SymLinkLoop => .LOOP,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => .MFILE,
        error.SystemResources => .NOMEM,
        else => .IO,
    };
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
        try testing.expect(res.isError());
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
    try testing.expect(!res.isError());
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
    try testing.expect(res.isError());
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

    // Step 1: Create and write to file (now goes to COW)
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
        try testing.expect(!res.isError());

        const vfd: FdTable.VirtualFD = @intCast(res.reply.val);
        try testing.expectEqual(@as(FdTable.VirtualFD, 3), vfd);

        // Get the FD and write to it (now via FD.write)
        const proc = supervisor.virtual_procs.lookup.get(child_pid).?;
        var fd = proc.fd_table.get(vfd).?;
        _ = try fd.write(test_content);
        fd.close();
        _ = proc.fd_table.remove(vfd);
    }

    // Step 2: Open for read and verify content (should read from COW)
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
        try testing.expect(!res.isError());

        const vfd: FdTable.VirtualFD = @intCast(res.reply.val);

        // Read via FD.read
        const proc = supervisor.virtual_procs.lookup.get(child_pid).?;
        var fd = proc.fd_table.get(vfd).?;
        var buf: [64]u8 = undefined;
        const n = try fd.read(&buf);
        try testing.expectEqualStrings(test_content, buf[0..n]);

        fd.close();
    }
}

test "resolve /proc/self triggers virtualize" {
    try testing.expect(try resolve("/proc/self") == .virtualize_proc);
}

test "path traversal /proc/../etc/passwd does not virtualize" {
    try testing.expect(try resolve("/proc/../etc/passwd") == .block);
}

test "resolve /tmp triggers virtualize_tmp" {
    try testing.expect(try resolve("/tmp") == .virtualize_tmp);
    try testing.expect(try resolve("/tmp/foo.txt") == .virtualize_tmp);
    try testing.expect(try resolve("/tmp/subdir/file") == .virtualize_tmp);
}

test "resolve /tmp/.bvisor is blocked" {
    try testing.expect(try resolve("/tmp/.bvisor") == .block);
    try testing.expect(try resolve("/tmp/.bvisor/sb/abc123/tmp/foo") == .block);
}
