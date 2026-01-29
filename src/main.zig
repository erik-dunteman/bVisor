const std = @import("std");
const types = @import("types.zig"); // ERIK TODO: kitchen sink utils, think about what else we could do here
const Logger = types.Logger;
const setupAndRun = @import("setup.zig").setupAndRun;
const smokeTest = @import("smoke_test.zig").smokeTest;

test {
    _ = @import("Supervisor.zig");
    _ = @import("deps/proc_info/impl/linux.zig");
    _ = @import("virtual/proc/Procs.zig");
    _ = @import("virtual/fs/OpenFile.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("virtual/fs/Cow.zig");
    _ = @import("virtual/fs/Tmp.zig");
    _ = @import("virtual/syscall/handlers/exit_group.zig");
    _ = @import("virtual/syscall/handlers/getpid.zig");
    _ = @import("virtual/syscall/handlers/getppid.zig");
    _ = @import("virtual/syscall/handlers/kill.zig");
    _ = @import("virtual/syscall/handlers/openat.zig");
    _ = @import("virtual/syscall/handlers/read.zig");
    _ = @import("virtual/syscall/handlers/readv.zig");
    _ = @import("virtual/syscall/handlers/write.zig");
    _ = @import("virtual/syscall/handlers/writev.zig");
}

pub fn main() !void {
    const logger = Logger.init(.prefork);
    logger.log("Running smoke test with syscall interception:", .{});

    // Run the smoke test inside the sandbox
    try setupAndRun(smokeTest);
}
