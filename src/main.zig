const std = @import("std");
const types = @import("types.zig");
const Logger = types.Logger;
const setup_and_run = @import("setup.zig").setup_and_run;

test {
    _ = @import("Supervisor.zig");
    _ = @import("virtual/proc/Procs.zig");
    _ = @import("virtual/fs/FD.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("syscall/handlers/OpenAt.zig");
}

// Example child process, could be a bash command or anything else
// For now we'll mock it with zig code
fn example_child(io: std.Io) void {
    // Sleep for 5 seconds then exit
    std.debug.print("Child starting\n", .{});
    for (0..5) |i| {
        std.debug.print("Countdown: {}\n", .{5 - i});
        io.sleep(std.Io.Duration.fromMilliseconds(1000), .awake) catch unreachable;
    }
    std.debug.print("Child done!\n", .{});
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const logger = Logger.init(.prefork);

    // First run normal
    logger.log("Running child unmodified:", .{});
    example_child(io);

    // Then run in syscall interception mode
    logger.log("Running child with syscall interception:", .{});
    try setup_and_run(example_child);
}
