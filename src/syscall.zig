const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const MemoryBridge = @import("memory_bridge.zig").MemoryBridge;
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");

// All supported syscalls
const ClockNanosleep = @import("syscalls/ClockNanosleep.zig");
const Openat = @import("syscalls/Openat.zig");
const Read = @import("syscalls/Read.zig");
const Readv = @import("syscalls/Readv.zig");
const Write = @import("syscalls/Write.zig");
const Writev = @import("syscalls/Writev.zig");
const Close = @import("syscalls/Close.zig");
const Symlinkat = @import("syscalls/Symlinkat.zig");
const Fstatat = @import("syscalls/Fstatat.zig");
const Mkdirat = @import("syscalls/Mkdirat.zig");
const Unlinkat = @import("syscalls/Unlinkat.zig");
const Readlinkat = @import("syscalls/Readlinkat.zig");
const Lseek = @import("syscalls/Lseek.zig");
const Pread64 = @import("syscalls/Pread64.zig");
const Pwrite64 = @import("syscalls/Pwrite64.zig");
const Getdents64 = @import("syscalls/Getdents64.zig");
const Dup = @import("syscalls/Dup.zig");
const Dup3 = @import("syscalls/Dup3.zig");
const Fcntl = @import("syscalls/Fcntl.zig");
const Ioctl = @import("syscalls/Ioctl.zig");
const Faccessat = @import("syscalls/Faccessat.zig");
const Getcwd = @import("syscalls/Getcwd.zig");
const Pipe2 = @import("syscalls/Pipe2.zig");

/// Union of all emulated syscalls.
pub const Syscall = union(enum) {
    clock_nanosleep: ClockNanosleep,
    openat: Openat,
    read: Read,
    readv: Readv,
    write: Write,
    writev: Writev,
    close: Close,
    symlinkat: Symlinkat,
    fstatat: Fstatat,
    mkdirat: Mkdirat,
    unlinkat: Unlinkat,
    readlinkat: Readlinkat,
    lseek: Lseek,
    pread64: Pread64,
    pwrite64: Pwrite64,
    getdents64: Getdents64,
    dup: Dup,
    dup3: Dup3,
    fcntl: Fcntl,
    ioctl: Ioctl,
    faccessat: Faccessat,
    getcwd: Getcwd,
    pipe2: Pipe2,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall is not supported and should passthrough
    pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            .clock_nanosleep => return .{ .clock_nanosleep = try ClockNanosleep.parse(mem_bridge, notif) },
            .openat => return .{ .openat = try Openat.parse(mem_bridge, notif) },
            .read => return .{ .read = try Read.parse(mem_bridge, notif) },
            .readv => return .{ .readv = try Readv.parse(mem_bridge, notif) },
            .write => return .{ .write = try Write.parse(mem_bridge, notif) },
            .writev => return .{ .writev = try Writev.parse(mem_bridge, notif) },
            .close => return .{ .close = try Close.parse(mem_bridge, notif) },
            .symlinkat => return .{ .symlinkat = try Symlinkat.parse(mem_bridge, notif) },
            .fstatat64 => return .{ .fstatat = try Fstatat.parse(mem_bridge, notif) },
            .mkdirat => return .{ .mkdirat = try Mkdirat.parse(mem_bridge, notif) },
            .unlinkat => return .{ .unlinkat = try Unlinkat.parse(mem_bridge, notif) },
            .readlinkat => return .{ .readlinkat = try Readlinkat.parse(mem_bridge, notif) },
            .lseek => return .{ .lseek = try Lseek.parse(mem_bridge, notif) },
            .pread64 => return .{ .pread64 = try Pread64.parse(mem_bridge, notif) },
            .pwrite64 => return .{ .pwrite64 = try Pwrite64.parse(mem_bridge, notif) },
            .getdents64 => return .{ .getdents64 = try Getdents64.parse(mem_bridge, notif) },
            .dup => return .{ .dup = try Dup.parse(mem_bridge, notif) },
            .dup3 => return .{ .dup3 = try Dup3.parse(mem_bridge, notif) },
            .fcntl => return .{ .fcntl = try Fcntl.parse(mem_bridge, notif) },
            .ioctl => return .{ .ioctl = try Ioctl.parse(mem_bridge, notif) },
            .faccessat => return .{ .faccessat = try Faccessat.parse(mem_bridge, notif) },
            .getcwd => return .{ .getcwd = try Getcwd.parse(mem_bridge, notif) },
            .pipe2 => return .{ .pipe2 = try Pipe2.parse(mem_bridge, notif) },
            else => return null,
        }
    }

    /// Handle the syscall, passing supervisor for access to mem_bridge, logger, filesystem
    pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
        return switch (self) {
            inline else => |inner| inner.handle(supervisor),
        };
    }

    pub const Result = union(enum) {
        passthrough: void, // If the handler implementation decided to passthrough
        handled: Handled,

        pub const Handled = struct {
            val: i64,
            errno: i32,

            pub fn success(val: i64) @This() {
                return .{ .val = val, .errno = 0 };
            }

            pub fn err(errno: linux.E) @This() {
                return .{ .val = 0, .errno = @intFromEnum(errno) };
            }
        };
    };
};
