const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const use_docker = b.option(bool, "use-docker", "Run tests in Docker container") orelse false;

    // Target multiple platforms based on testing flags
    const linux_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64, // ARM64 for Apple Silicon Macs running Docker, update for other targets
        .os_tag = .linux,
        .abi = .musl,
    });
    const host_target = b.graph.host;

    // Build node bindings library for each platform
    const node_api = b.dependency("node_api", .{});

    const node_platforms = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        abi: std.Target.Abi,
        dest_dir: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-arm64-musl" },
        .{ .cpu_arch = .aarch64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-arm64-gnu" },
        .{ .cpu_arch = .x86_64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-x64-musl" },
        .{ .cpu_arch = .x86_64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-x64-gnu" },
    };

    for (node_platforms) |platform| {
        const target = b.resolveTargetQuery(.{
            .cpu_arch = platform.cpu_arch,
            .os_tag = .linux,
            .abi = platform.abi,
        });

        const node_lib = b.addLibrary(.{
            .name = "libbvisor",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sdks/node/zig/lib.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        node_lib.root_module.addIncludePath(node_api.path("include"));
        node_lib.linker_allow_shlib_undefined = true;

        const install = b.addInstallArtifact(node_lib, .{
            .dest_dir = .{ .override = .{ .custom = platform.dest_dir } },
            .dest_sub_path = "libbvisor.node",
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // Build and install linux executable
    // to ./zig-out/bin
    const linux_exe = b.addExecutable(.{
        .name = "bVisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(linux_exe);

    // Build zig tests for running on host
    const host_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/main.zig"),
            .target = host_target,
            .optimize = optimize,
        }),
    });

    // Build and install zig tests for running in linux container
    const linux_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    const test_install = b.addInstallArtifact(linux_tests, .{ .dest_sub_path = "tests" });
    b.getInstallStep().dependOn(&test_install.step);

    // 'run' mounts built linux exe into a linux container and runs it there
    const run_cli_step = b.step("run", "Run executable in a Linux container");
    const run_args = [_][]const u8{ "docker", "run", "--rm", "--cap-add=SYS_PTRACE", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/bVisor" };
    const run_cmd = b.addSystemCommand(&run_args);
    run_cmd.step.dependOn(b.getInstallStep()); // docker run depends on linux exe being built
    run_cli_step.dependOn(&run_cmd.step);

    // 'test' runs unit tests (use -Duse-docker to run in container)
    const test_cli_step = b.step("test", "Run unit tests (-Duse-docker for Linux container)");
    if (use_docker) {
        const docker_args = [_][]const u8{ "docker", "run", "--rm", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/tests" };
        const docker_cmd = b.addSystemCommand(&docker_args);
        docker_cmd.step.dependOn(b.getInstallStep());
        test_cli_step.dependOn(&docker_cmd.step);
    } else {
        const run_tests = b.addRunArtifact(host_tests);
        test_cli_step.dependOn(&run_tests.step);
    }
}
