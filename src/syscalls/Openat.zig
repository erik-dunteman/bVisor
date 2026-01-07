const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const Supervisor = @import("../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

// Blocked paths - these are dangerous and could allow escape or host disruption
const blocked_paths = [_][]const u8{
    // /proc paths that can crash/modify host
    "/proc/sysrq-trigger", // can crash/reboot host
    "/proc/sys/kernel/core_pattern", // code execution on crash
    "/proc/sys/kernel/modprobe", // module loading path
    "/proc/kcore", // kernel memory
    "/proc/kmem", // kernel memory
    "/proc/kallsyms", // kernel symbols (info leak)
    "/proc/self/mem", // process memory access
    "/proc/config.gz", // kernel config (info leak)
    // Dangerous devices - memory/hardware access
    "/dev/mem", // physical memory access
    "/dev/kmem", // kernel memory access
    "/dev/port", // I/O port access
    "/dev/hpet", // high precision timer (timing attacks)
    "/dev/fuse", // FUSE mounting (escape vector)
    "/dev/kvm", // KVM virtualization
    "/dev/vhost-net", // vhost networking
    "/dev/vhost-vsock", // vhost vsock
};

// Blocked path prefixes - block entire subtrees
const blocked_prefixes = [_][]const u8{
    // /proc - kernel and system configuration
    "/proc/sys/kernel/", // kernel parameters
    "/proc/sys/vm/", // memory configuration
    "/proc/sys/net/", // network configuration
    "/proc/sys/fs/", // filesystem settings
    "/proc/acpi/", // ACPI interface
    "/proc/bus/", // bus devices
    "/proc/scsi/", // SCSI control
    // /sys - sysfs kernel interface
    "/sys/fs/cgroup/", // cgroup escape
    "/sys/kernel/", // kernel parameters
    "/sys/module/", // kernel module parameters
    "/sys/firmware/", // firmware/EFI (can brick system)
    "/sys/power/", // power management (suspend/hibernate)
    "/sys/class/", // device classes
    "/sys/bus/", // bus devices
    "/sys/block/", // block device control
    "/sys/devices/virtual/powercap/", // RAPL side-channel
    // /dev - devices
    "/dev/cpu/", // MSR access (/dev/cpu/*/msr)
    "/dev/sd", // raw block devices
    "/dev/nvme", // raw NVMe devices
    "/dev/vd", // raw virtio devices
    "/dev/loop", // loop devices (mount images)
    "/dev/dm-", // device mapper
    "/dev/mapper/", // device mapper
    "/dev/dri/", // GPU access (side channels)
    "/dev/fb", // framebuffer
    "/dev/input/", // input devices (keyloggers)
    "/dev/snd/", // sound devices
    "/dev/video", // video capture
    // /boot - bootloader
    "/boot/", // kernel/bootloader images
};

// Paths that are read-only (block write access)
const readonly_paths = [_][]const u8{
    "/proc/self/exe", // symlink to executable - never writeable
};

const readonly_prefixes = [_][]const u8{
    "/proc/self/fd/", // FD symlinks - read-only
};

fn isBlockedPath(path: []const u8) bool {
    // Check exact matches
    for (blocked_paths) |blocked| {
        if (std.mem.eql(u8, path, blocked)) return true;
    }
    // Check prefix matches
    for (blocked_prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

fn isReadonlyPath(path: []const u8) bool {
    // Check exact matches
    for (readonly_paths) |ro| {
        if (std.mem.eql(u8, path, ro)) return true;
    }
    // Check prefix matches
    for (readonly_prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

// Access mode is in the bottom 2 bits of flags
const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
flags: u32,
mode: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .flags = @truncate(notif.data.arg2),
        .mode = @truncate(notif.data.arg3),
    };

    // Read pathname from child memory (null-terminated string)
    // Read up to 256 bytes
    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);

    // Find null terminator
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const overlay = &supervisor.overlay;

    const path = self.pathname[0..self.pathname_len];

    // Block dangerous paths first - before any other processing
    if (isBlockedPath(path)) {
        logger.log("openat: BLOCKED dangerous path=\"{s}\"", .{path});
        return .{ .handled = Result.Handled.err(.ACCES) };
    }

    const access_mode = self.flags & O_ACCMODE;

    // Block write access to read-only paths
    if (isReadonlyPath(path)) {
        const wants_write_ro = access_mode == O_WRONLY or access_mode == O_RDWR or (self.flags & O_CREAT) != 0;
        if (wants_write_ro) {
            logger.log("openat: BLOCKED write to read-only path=\"{s}\"", .{path});
            return .{ .handled = Result.Handled.err(.ACCES) };
        }
    }

    const wants_write = access_mode == O_WRONLY or access_mode == O_RDWR or (self.flags & O_CREAT) != 0;

    logger.log("Emulating openat: dirfd={d} path=\"{s}\" flags=0x{x} mode=0o{o} wants_write={}", .{
        self.dirfd,
        path,
        self.flags,
        self.mode,
        wants_write,
    });

    // Use the Overlay for all file operations
    // Overlay handles: check overlay first, fallback to host, COW on write
    const fd = overlay.open(path, self.flags, self.mode) catch |err| {
        logger.log("openat: overlay open failed: {}", .{err});
        return switch (err) {
            error.PermissionDenied => .{ .handled = Result.Handled.err(.ACCES) },
            error.FileNotFound => .{ .handled = Result.Handled.err(.NOENT) },
            error.OutOfMemory => .{ .handled = Result.Handled.err(.NOMEM) },
            error.Canceled => .{ .handled = Result.Handled.err(.INTR) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("openat: opened fd={d} path=\"{s}\"", .{ fd, path });
    return .{ .handled = Result.Handled.success(fd) };
}

