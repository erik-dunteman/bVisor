const std = @import("std");
const FileBackend = @import("fs/file.zig").FileBackend;

pub const RouteResult = union(enum) {
    block: void, // deny access with EPERM
    handle: FileBackend,
};

pub fn route(path: []const u8) !RouteResult {
    // normalize ".." out of path
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const normalized = try std.fs.path.resolvePosix(fba.allocator(), &.{path});

    // route through prefix tree
    return routeByPrefix(normalized, router_rules, global_default);
}

fn routeByPrefix(path: []const u8, rules: []const Rule, default: RouteResult) RouteResult {
    for (rules) |rule| {
        if (matchesPrefix(path, rule.prefix)) |remainder| {
            switch (rule.node) {
                .terminal => |result| return result,
                .branch => |branch| return routeByPrefix(remainder, branch.subrules, branch.default),
            }
        }
    }
    return default;
}

/// Check if path matches a directory prefix (handles trailing slash variations)
/// Returns remainder after prefix, or null if no match
fn matchesPrefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (path.len == prefix.len) return ""; // exact match
    if (path[prefix.len] == '/') return path[prefix.len + 1 ..]; // skip the /
    return null; // e.g., /tmpfoo doesn't match /tmp
}

// Routing rules
const global_default: RouteResult = .{ .handle = .cow };

const router_rules: []const Rule = &.{
    // Hard blocks
    .{ .prefix = "/sys", .node = .{ .terminal = .block } },
    .{ .prefix = "/run", .node = .{ .terminal = .block } },

    // Block /dev by default
    // Except safe devs
    .{ .prefix = "/dev", .node = .{ .branch = .{
        .subrules = &.{
            .{ .prefix = "null", .node = .{ .terminal = .{ .handle = .passthrough } } },
            .{ .prefix = "zero", .node = .{ .terminal = .{ .handle = .passthrough } } },
            .{ .prefix = "random", .node = .{ .terminal = .{ .handle = .passthrough } } },
            .{ .prefix = "urandom", .node = .{ .terminal = .{ .handle = .passthrough } } },
        },
        .default = .block,
    } } },

    // Proc symbolic path gets special virtualization
    .{ .prefix = "/proc", .node = .{ .terminal = .{ .handle = .proc } } },

    // /tmp/.bvisor contains per-sandbox data like cow and private /tmp files
    // block access to .bvisor
    // and redirect all others to virtual /tmp
    .{ .prefix = "/tmp", .node = .{ .branch = .{
        .subrules = &.{
            .{ .prefix = ".bvisor", .node = .{ .terminal = .block } },
        },
        .default = .{ .handle = .tmp },
    } } },
};

const Node = union(enum) {
    terminal: RouteResult,
    branch: struct {
        subrules: []const Rule,
        default: RouteResult,
    },
};

const Rule = struct {
    prefix: []const u8,
    node: Node,
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "/etc/passwd routes to cow" {
    const result = try route("/etc/passwd");
    try testing.expectEqual(RouteResult{ .handle = .cow }, result);
}

test "/usr/bin/ls routes to cow" {
    const result = try route("/usr/bin/ls");
    try testing.expectEqual(RouteResult{ .handle = .cow }, result);
}

test "/proc/self routes to proc" {
    const result = try route("/proc/self");
    try testing.expectEqual(RouteResult{ .handle = .proc }, result);
}

test "/proc/123/status routes to proc" {
    const result = try route("/proc/123/status");
    try testing.expectEqual(RouteResult{ .handle = .proc }, result);
}

test "/tmp/foo.txt routes to tmp" {
    const result = try route("/tmp/foo.txt");
    try testing.expectEqual(RouteResult{ .handle = .tmp }, result);
}

test "/tmp/.bvisor/secret is blocked" {
    const result = try route("/tmp/.bvisor/secret");
    try testing.expectEqual(RouteResult.block, result);
}

test "/sys/class/net is blocked" {
    const result = try route("/sys/class/net");
    try testing.expectEqual(RouteResult.block, result);
}

test "/run/lock is blocked" {
    const result = try route("/run/lock");
    try testing.expectEqual(RouteResult.block, result);
}

test "/dev/sdb is blocked" {
    const result = try route("/dev/sdb");
    try testing.expectEqual(RouteResult.block, result);
}

test "/dev/null is allowed" {
    const result = try route("/dev/null");
    try testing.expectEqual(RouteResult{ .handle = .passthrough }, result);
}

test "path traversal /../etc/passwd normalized to /etc/passwd routes to cow" {
    const result = try route("/../etc/passwd");
    try testing.expectEqual(RouteResult{ .handle = .cow }, result);
}

test "path traversal /tmp/../etc/passwd routes to cow (escaped /tmp)" {
    const result = try route("/tmp/../etc/passwd");
    try testing.expectEqual(RouteResult{ .handle = .cow }, result);
}
