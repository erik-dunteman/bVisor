const std = @import("std");
const types = @import("types.zig");
const Logger = types.Logger;
const setupAndRun = @import("setup.zig").setupAndRun;
const smokeTest = @import("smoke_test.zig").smokeTest;

test {
    _ = @import("Supervisor.zig");
    _ = @import("virtual/proc/Procs.zig");
    _ = @import("virtual/fs/FD.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("virtual/syscall/handlers/OpenAt.zig");
    _ = @import("virtual/syscall/handlers/Clone.zig");
    _ = @import("virtual/syscall/handlers/GetPid.zig");
    _ = @import("virtual/syscall/handlers/GetPPid.zig");
    _ = @import("virtual/syscall/handlers/Kill.zig");
    _ = @import("virtual/syscall/handlers/ExitGroup.zig");
    _ = @import("virtual/syscall/handlers/Read.zig");
    _ = @import("virtual/syscall/handlers/Readv.zig");
}

pub fn main() !void {
    const logger = Logger.init(.prefork);

    // Run the smoke test inside the sandbox
    logger.log("Running smoke test with syscall interception:", .{});
    try setupAndRun(smokeTest);
}
