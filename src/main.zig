const std = @import("std");
const types = @import("types.zig");
const Logger = types.Logger;
const setup = @import("setup.zig");
const Cgroups = @import("cgroups.zig");

test {
    // Zig tests must be imported from the test root,
    // Otherwise they're not included
    _ = @import("VirtualFilesystem.zig");
    _ = @import("Supervisor.zig");
    _ = @import("cgroups.zig");
    _ = @import("Overlay.zig");
}

const usage =
    \\Usage: bVisor [options] <command> [args...]
    \\
    \\Options:
    \\  -m, --memory <size>   Memory limit (e.g., 100M, 1G)
    \\  -p, --pids <n>        Maximum number of processes
    \\  -c, --cpu <percent>   CPU quota percentage (100 = 1 core)
    \\  -h, --help            Show this help message
    \\
    \\Examples:
    \\  bVisor /bin/sh -c 'echo hello'
    \\  bVisor --memory=256M --pids=50 /bin/sh
    \\  bVisor -m 1G -p 100 -c 50 /bin/bash
    \\
;

pub fn main() !void {
    const logger = Logger.init(.prefork);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command-line arguments
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    // Parse options and collect command
    var cgroup_config = Cgroups.Config{};
    var argv_buf: [64][:0]const u8 = undefined;
    var argc: usize = 0;
    var parsing_options = true;

    while (args.next()) |arg| {
        if (parsing_options) {
            // Check for help
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                std.debug.print("{s}", .{usage});
                return;
            }

            // Check for option terminator
            if (std.mem.eql(u8, arg, "--")) {
                parsing_options = false;
                continue;
            }

            // Parse memory option
            if (parseOption(arg, "-m", "--memory")) |value| {
                cgroup_config.memory_max = Cgroups.parseMemorySize(value) catch {
                    std.debug.print("Invalid memory size: {s}\n", .{value});
                    return;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--memory")) {
                if (args.next()) |value| {
                    cgroup_config.memory_max = Cgroups.parseMemorySize(value) catch {
                        std.debug.print("Invalid memory size: {s}\n", .{value});
                        return;
                    };
                    continue;
                } else {
                    std.debug.print("Missing value for {s}\n", .{arg});
                    return;
                }
            }

            // Parse pids option
            if (parseOption(arg, "-p", "--pids")) |value| {
                cgroup_config.pids_max = std.fmt.parseInt(u32, value, 10) catch {
                    std.debug.print("Invalid pids value: {s}\n", .{value});
                    return;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--pids")) {
                if (args.next()) |value| {
                    cgroup_config.pids_max = std.fmt.parseInt(u32, value, 10) catch {
                        std.debug.print("Invalid pids value: {s}\n", .{value});
                        return;
                    };
                    continue;
                } else {
                    std.debug.print("Missing value for {s}\n", .{arg});
                    return;
                }
            }

            // Parse cpu option
            if (parseOption(arg, "-c", "--cpu")) |value| {
                cgroup_config.cpu_percent = std.fmt.parseInt(u32, value, 10) catch {
                    std.debug.print("Invalid cpu value: {s}\n", .{value});
                    return;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--cpu")) {
                if (args.next()) |value| {
                    cgroup_config.cpu_percent = std.fmt.parseInt(u32, value, 10) catch {
                        std.debug.print("Invalid cpu value: {s}\n", .{value});
                        return;
                    };
                    continue;
                } else {
                    std.debug.print("Missing value for {s}\n", .{arg});
                    return;
                }
            }

            // If starts with -, it's an unknown option
            if (arg.len > 0 and arg[0] == '-') {
                std.debug.print("Unknown option: {s}\n", .{arg});
                std.debug.print("{s}", .{usage});
                return;
            }

            // Not an option, start of command
            parsing_options = false;
        }

        // Collect command arguments
        if (argc >= 64) break;
        argv_buf[argc] = arg;
        argc += 1;
    }

    if (argc == 0) {
        std.debug.print("{s}", .{usage});
        return;
    }

    const argv = argv_buf[0..argc];

    // Log configuration
    if (cgroup_config.hasLimits()) {
        logger.log("Cgroup limits: memory={d}, pids={d}, cpu={d}%", .{
            cgroup_config.memory_max,
            cgroup_config.pids_max,
            cgroup_config.cpu_percent,
        });
    }

    logger.log("Running command in sandbox: {s}", .{argv[0]});
    try setup.runCommand(argv, cgroup_config, allocator);
}

/// Parse an option that can be in form "-x=value" or "--long=value"
/// Returns the value if matched, null otherwise
fn parseOption(arg: []const u8, short: []const u8, long: []const u8) ?[]const u8 {
    // Check short form: -x=value
    if (arg.len > short.len + 1 and std.mem.startsWith(u8, arg, short) and arg[short.len] == '=') {
        return arg[short.len + 1 ..];
    }
    // Check long form: --long=value
    if (arg.len > long.len + 1 and std.mem.startsWith(u8, arg, long) and arg[long.len] == '=') {
        return arg[long.len + 1 ..];
    }
    return null;
}
