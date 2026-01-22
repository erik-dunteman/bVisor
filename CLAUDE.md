# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bVisor is an in-process Linux sandbox SDK and runtime written in Zig. It intercepts and virtualizes Linux syscalls from userspace using seccomp user notifier, providing isolation without VM overhead. Unlike gVisor (which runs as a separate service), bVisor runs directly in your application for millisecond-level sandbox lifecycle.

The goal of bVisor is to be a lightweight sandbox for untrusted user or LLM-generated code run on the server. Its most minimal implementation creates a virtualized filesystem and runs a bash command inside of it, but the goal is to increase sandboxing over time. This is intended as alternative to docker, gvisor, or other vm-based sandboxes.

**Status**: Early proof-of-concept. Core seccomp interception works; syscall virtualization is incomplete.

**Greenfield project**: No users, no backward compatibility concerns. Delete dead code freely.

## Build Commands

```bash
zig build                    # Build for aarch64-linux-musl
zig build test               # Run unit tests on host
zig build test -Duse-docker  # Run unit tests in Docker container
zig build run                # Run executable in Docker container
```

The build targets aarch64 Linux with musl ABI (for ARM64/Apple Silicon Docker). Modify `build.zig` lines 9-11 for other targets.

**Requires**: Zig 0.16.0-dev or later


## Architecture

**Supervisor-child process model with syscall interception:**

```
src/
  main.zig              # Entry point, demonstrates sandbox usage
  setup.zig             # Fork into child/supervisor, seccomp BPF installation
  supervisor.zig        # Main loop: recv notif → handle → send response
  types.zig             # LinuxResult, Logger, SupervisorFD
  smoke_test.zig        # TDD-style smoke test exercising sandbox syscall handling

  seccomp/
    filter.zig          # BPF filter installation, returns notify FD
    notif.zig           # Helper to construct test notifications

  deps/                 # Comptime dependency injection for testability
    deps.zig            # Re-exports pidfd, memory_bridge, proc_info
    memory_bridge/
      memory_bridge.zig # Comptime selector for implementation
      impl/linux.zig    # Production: process_vm_readv/writev
      impl/testing.zig  # Testing: local pointer access
    pidfd/
      pidfd.zig         # Comptime selector for implementation
      impl/linux.zig    # Production: pidfd_open/pidfd_getfd
      impl/testing.zig  # Testing: mock implementation
    proc_info/
      proc_info.zig       # Comptime selector for implementation
      impl/linux.zig      # Production: Parent PID and clone flags detection
      impl/testing.zig    # Testing: mock implementation

  virtual/              # Virtualization layer
    proc/               # Process virtualization
      Procs.zig         # Manages all virtual processes, kernel→virtual PID mapping
      Proc.zig          # Single process: pid, namespace, fd_table, parent/children
      Namespace.zig     # PID namespace with refcounting, vpid allocation
    fs/                 # File descriptor virtualization
      FdTable.zig       # Per-process fd table, refcounted (shared on CLONE_FILES)
      OpenFile.zig            # Virtual FD union: kernel passthrough, proc files, COW files
    syscall/            # Syscall handlers
      syscalls.zig      # Switch statement over syscalls, parseing notifications
      handlers/
        OpenAt.zig      # openat handler with path rules (block/allow/virtualize)
        Writev.zig      # writev handler
        ...             # handlers for other any other implemented syscalls
```

**Syscall flow**: Child syscall → kernel USER_NOTIF → Supervisor.recv() → Notification.handle() → Syscall handler or passthrough → Supervisor.send()

**Process virtualization**:
- `Procs` tracks all sandboxed processes with kernel PID (from the perspective of the supervisor) → guest PID (from the perspective of the guest) mapping
- Each `Proc` has its own `FdTable` and belongs to a `Namespace`
- `CLONE_FILES` shares fd_table (refcounted), otherwise cloned
- `CLONE_NEWPID` creates new namespace, otherwise inherited
- Killing a process kills its entire subtree (including nested namespaces)

**FD handling**: Uses virtual FD abstraction with `OpenFile` union enum:
- `.kernel` - passthrough to real kernel FD (from the perspective of the supervisor)
- `.proc` - virtualized `src//proc` files (e.g., `src/proc/self` returns guest PID)
- `.cow` - copy-on-write files (not yet implemented)
- FDs 0,1,2 (stdin/stdout/stderr) are handled specially

**Path resolution in OpenAt**:
- Paths are normalized (resolving any `..`) before matching
- Rules: `/sys/` and `/run/` are blocked, `/tmp/` is allowed, `/proc/` is virtualized
- Path traversal attacks like `src/proc/../etc/passwd` are blocked

**Adding a new emulated syscall:**
When implementing a new emulated syscall,
1. Create `src/virtual/syscall/handlers/{NewSyscall}.zig` with `parse()` and `handle()` methods
2. Update the corresponding case in the switch in `src/virtual/syscall/syscalls.zig`

## Testing

**Comptime dependency injection**: `src/deps/` modules use `builtin.is_test` to select implementation:
```zig
const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");
```

**Test discovery**: Zig only runs tests from files transitively imported by the test root. Tests in standalone files must be explicitly imported in `src/main.zig`:
```zig
test {
     _ = @import("Supervisor.zig");
    _ = @import("virtual/proc/Procs.zig");
    _ = @import("virtual/fs/OpenFile.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("virtual/fs/Cow.zig");
    _ = @import("virtual/fs/Tmp.zig");
    _ = @import("virtual/syscall/handlers/exit_group.zig");
    _ = @import("virtual/syscall/handlers/GetPid.zig");
    _ = @import("virtual/syscall/handlers/GetPPid.zig");
    _ = @import("virtual/syscall/handlers/Kill.zig");
    _ = @import("virtual/syscall/handlers/OpenAt.zig");
    _ = @import("virtual/syscall/handlers/Read.zig");
    _ = @import("virtual/syscall/handlers/Readv.zig");
    _ = @import("virtual/syscall/handlers/Write.zig");
    _ = @import("virtual/syscall/handlers/Writev.zig");
}
```

**E2E tests**: Use `makeNotif()` from `src/seccomp/notif.zig` to construct test notifications. `TestingMemoryBridge` treats addresses as local pointers, enabling full syscall handler testing without a real child process.

**Logger**: Disabled during tests (`builtin.is_test`) to avoid interfering with `zig build test` IPC.

## Key Linux APIs Used
- Seccomp user notifier (`SECCOMP_SET_MODE_FILTER`, `SECCOMP_IOCTL_NOTIF_*`)
- BPF filter programs
- `process_vm_readv`/`process_vm_writev` for cross-process memory
- `pidfd_open`/`pidfd_getfd` for FD operations across processes

**Preference**: Use `pidfd_getfd` to access child FDs rather than `src/proc/pid/fd` symlinks. This is more reliable and doesn't require filesystem access.

## Zig Guidelines
- Zig 0.16 is required, and includes a new `std.Io` module that provides a unified interface for asynchronous I/O.
- The std lib can be found in the same directory as the Zig binary, plus ./lib/std. Use grep to find the current APIs. If further documentation is needed, use https://ziglang.org/documentation/master/std/ as a reference.
- Use the installed ZLS language server for up-to-date feedback on 0.16 features.
- Where possible, keep structs as individual files, using the file-as-struct pattern with `const Self = @This()`.
- Prefer the `try` keyword over `catch` when possible.
- Prefer enums with switches for dynamic dispatch. Inline else to enforce that all enum variants contain methods of a certain signature (see syscall.zig for ref).
- Use dependency injection where possible to help keep testing free of IO and side effects.
- Prefer to use stack buffers over heap allocation when possible.
- PascalCase for types (and functions returning types), snake_case for variables, camelCase for functions.
- Use init(...) as constructor, and a deferrable deinit(...) if destructor is needed.
- Use std.linux specific APIs rather than calling syscalls directly. When in doubt, grep std.linux. The std lib can be found in the same directory as the Zig binary, plus `./lib/std/os/linux.zig`.
- Batch operations when possible - avoid syscall-per-byte patterns (e.g., use `readSlice` to read known-length buffers in one call).