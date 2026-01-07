const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const FD = @import("types.zig").FD;

const Self = @This();

/// Cgroup resource limits configuration
pub const Config = struct {
    /// Memory limit in bytes (0 = unlimited)
    memory_max: u64 = 0,
    /// Maximum number of processes (0 = unlimited)
    pids_max: u32 = 0,
    /// CPU quota as percentage (0 = unlimited, 100 = 1 core, 200 = 2 cores)
    cpu_percent: u32 = 0,

    pub fn hasLimits(self: Config) bool {
        return self.memory_max > 0 or self.pids_max > 0 or self.cpu_percent > 0;
    }
};

allocator: std.mem.Allocator,
cgroup_path: []const u8,
config: Config,

/// Initialize cgroup manager. Call setup() to create the cgroup.
pub fn init(allocator: std.mem.Allocator, name: []const u8, config: Config) !Self {
    // Build cgroup path: /sys/fs/cgroup/bvisor-<name>
    const cgroup_path = try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/bvisor-{s}", .{name});

    return .{
        .allocator = allocator,
        .cgroup_path = cgroup_path,
        .config = config,
    };
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.cgroup_path);
}

/// Create cgroup and configure limits. Must be called before adding processes.
pub fn setup(self: *Self) !void {
    // Create cgroup directory
    posix.mkdiratZ(posix.AT.FDCWD, @ptrCast(self.cgroup_path.ptr), 0o755) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Configure memory limit
    if (self.config.memory_max > 0) {
        try self.writeControl("memory.max", self.config.memory_max);
    }

    // Configure pids limit
    if (self.config.pids_max > 0) {
        try self.writeControl("pids.max", self.config.pids_max);
    }

    // Configure CPU quota (cpu.max format: "quota period")
    // Period is typically 100000 (100ms), quota = period * percent / 100
    if (self.config.cpu_percent > 0) {
        const period: u64 = 100000;
        const quota = period * self.config.cpu_percent / 100;
        try self.writeCpuMax(quota, period);
    }
}

/// Add a process to this cgroup
pub fn addProcess(self: *Self, pid: linux.pid_t) !void {
    var path_buf: [256:0]u8 = undefined;
    const len = (std.fmt.bufPrint(&path_buf, "{s}/cgroup.procs", .{self.cgroup_path}) catch return error.PathTooLong).len;
    path_buf[len] = 0;

    var pid_buf: [16]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});

    try writeToFile(&path_buf, pid_str);
}

/// Clean up cgroup (remove directory). Only works if no processes are in it.
pub fn cleanup(self: *Self) void {
    // Try to remove the cgroup directory using rmdir
    var path_buf: [256:0]u8 = undefined;
    @memcpy(path_buf[0..self.cgroup_path.len], self.cgroup_path);
    path_buf[self.cgroup_path.len] = 0;
    _ = linux.rmdir(&path_buf);
}

fn writeControl(self: *Self, control: []const u8, value: anytype) !void {
    var path_buf: [256:0]u8 = undefined;
    const len = (std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.cgroup_path, control }) catch return error.PathTooLong).len;
    path_buf[len] = 0;

    var value_buf: [32]u8 = undefined;
    const value_str = try std.fmt.bufPrint(&value_buf, "{d}", .{value});
    try writeToFile(&path_buf, value_str);
}

fn writeCpuMax(self: *Self, quota: u64, period: u64) !void {
    var path_buf: [256:0]u8 = undefined;
    const len = (std.fmt.bufPrint(&path_buf, "{s}/cpu.max", .{self.cgroup_path}) catch return error.PathTooLong).len;
    path_buf[len] = 0;

    var value_buf: [64]u8 = undefined;
    const value_str = try std.fmt.bufPrint(&value_buf, "{d} {d}", .{ quota, period });
    try writeToFile(&path_buf, value_str);
}

fn writeToFile(path: [*:0]const u8, data: []const u8) !void {
    const fd = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0);
    if (@as(isize, @bitCast(fd)) < 0) {
        return error.OpenFailed;
    }
    defer _ = linux.close(@intCast(fd));

    const written = linux.write(@intCast(fd), data.ptr, data.len);
    if (@as(isize, @bitCast(written)) < 0) {
        return error.WriteFailed;
    }
}

/// Parse a memory size string (e.g., "100M", "1G", "512K")
pub fn parseMemorySize(str: []const u8) !u64 {
    if (str.len == 0) return 0;

    var value: u64 = 0;
    var i: usize = 0;

    // Parse numeric part
    while (i < str.len and str[i] >= '0' and str[i] <= '9') : (i += 1) {
        value = value * 10 + (str[i] - '0');
    }

    if (i == 0) return error.InvalidFormat;

    // Parse suffix
    if (i >= str.len) return value;

    const suffix = str[i];
    return switch (suffix) {
        'k', 'K' => value * 1024,
        'm', 'M' => value * 1024 * 1024,
        'g', 'G' => value * 1024 * 1024 * 1024,
        else => error.InvalidFormat,
    };
}

test "parseMemorySize" {
    try std.testing.expectEqual(@as(u64, 1024), parseMemorySize("1K"));
    try std.testing.expectEqual(@as(u64, 1024 * 1024), parseMemorySize("1M"));
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), parseMemorySize("1G"));
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), parseMemorySize("512M"));
    try std.testing.expectEqual(@as(u64, 100), parseMemorySize("100"));
}
