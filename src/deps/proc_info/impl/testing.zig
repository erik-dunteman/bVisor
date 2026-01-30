const std = @import("std");
const Allocator = std.mem.Allocator;

const Proc = @import("../../../virtual/proc/Proc.zig");
pub const AbsPid = Proc.AbsPid;
pub const NsPid = Proc.NsPid;
pub const ProcStatus = @import("../../..//virtual/proc/ProcStatus.zig");
pub const CloneFlags = @import("../../../virtual/proc/Procs.zig").CloneFlags;

/// Max depth of namespace hierarchy for mock NsPids
const MAX_NS_DEPTH = 128;

/// Mock parent PID map: child_pid -> parent_pid
pub var mock_ppid_map: std.AutoHashMapUnmanaged(AbsPid, AbsPid) = .empty;

/// Mock clone flags map: child_pid -> CloneFlags
pub var mock_clone_flags: std.AutoHashMapUnmanaged(AbsPid, CloneFlags) = .empty;

/// Mock NSpid map: supervisor_pid -> array of guest PIDs (outermost to innermost)
pub var mock_nspids: std.AutoHashMapUnmanaged(AbsPid, []const NsPid) = .empty;

/// Return mock clone flags for a child
pub fn detectCloneFlags(parent_pid: AbsPid, child_pid: AbsPid) CloneFlags {
    _ = parent_pid;
    return mock_clone_flags.get(child_pid) orelse CloneFlags{};
}

/// Read NSpid chain from mock map.
/// If not explicitly configured, returns [pid] as a single-element array,
/// which is correct for a process in a single (root) namespace.
pub fn readNsPids(pid: AbsPid, buf: []NsPid) ![]NsPid {
    if (mock_nspids.get(pid)) |nspids| {
        if (nspids.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[0..nspids.len], nspids);
        return buf[0..nspids.len];
    }
    // Default: single namespace, guest PID = supervisor PID
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = pid;
    return buf[0..1];
}

pub fn getStatus(pid: AbsPid) !ProcStatus {

    // Read parent PID from mock map
    const ppid = mock_ppid_map.get(pid) orelse return error.ProcNotInKernel;

    var status = ProcStatus{ .pid = pid, .ppid = ppid };
    const nspids = mock_nspids.get(pid) orelse &[_]NsPid{pid};
    @memcpy(status.nspids_buf[0..nspids.len], nspids);
    status.nspids_len = nspids.len;

    return status;
}

/// Reset mock state - call in test cleanup
pub fn reset(allocator: Allocator) void {
    mock_ppid_map.deinit(allocator);
    mock_clone_flags.deinit(allocator);
    mock_nspids.deinit(allocator);
    mock_ppid_map = .empty;
    mock_clone_flags = .empty;
    mock_nspids = .empty;
}

/// Setup a parent relationship in the mock
pub fn setupParent(allocator: Allocator, child: AbsPid, parent: AbsPid) !void {
    try mock_ppid_map.put(allocator, child, parent);
}

/// Setup clone flags for a child in the mock
pub fn setupCloneFlags(allocator: Allocator, child: AbsPid, flags: CloneFlags) !void {
    try mock_clone_flags.put(allocator, child, flags);
}

/// Setup NSpid chain for a process in the mock.
/// nspids should be ordered from outermost (root) to innermost (process's own namespace).
pub fn setupNsPids(allocator: Allocator, pid: AbsPid, nspids: []const NsPid) !void {
    try mock_nspids.put(allocator, pid, nspids);
}

/// List all PIDs from mock - returns keys from mock_ppid_map
pub fn listPids(allocator: Allocator) ![]AbsPid {
    var pids: std.ArrayListUnmanaged(AbsPid) = .empty;
    errdefer pids.deinit(allocator);

    var iter = mock_ppid_map.keyIterator();
    while (iter.next()) |pid_ptr| {
        try pids.append(allocator, pid_ptr.*);
    }

    return pids.toOwnedSlice(allocator);
}
