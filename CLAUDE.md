# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bVisor is an in-process Linux sandbox SDK and runtime written in Zig. It intercepts and virtualizes Linux syscalls from userspace using seccomp user notifier, providing isolation without VM overhead. Unlike gVisor (which runs as a separate service), bVisor runs directly in your application for millisecond-level sandbox lifecycle.

The goal of bVisor is to be lightweight sandbox for untrusted user or LLM-generated code run on the server. Its most minimal implementation creates a virtualized filesystem and runs a bash command inside of it, but the goal is to increase sandboxing over time. This is intended as alternative to docker, gvisor, or other vm-based sandboxes.

**Status**: Early proof-of-concept. Core seccomp interception works; syscall virtualization is incomplete.

## Build Commands

```bash
zig build              # Build for aarch64-linux-musl
zig build test         # Run tests
```

The build targets aarch64 Linux with musl ABI (for ARM64/Apple Silicon Docker). Modify `build.zig` line 6-8 for other targets.

**Requires**: Zig 0.16.0-dev or later

## Running on macOS

Seccomp only works on Linux. To test on macOS, use Docker:

```bash
zig build
docker run --rm -v ./zig-out:/zig-out alpine /zig-out/bin/bVisor
# Inside container: /zig-out/bin/bVisor
```

## Architecture

**Supervisor-child process model with syscall interception:**

1. `main.zig` - Entry point, demonstrates sandbox usage
2. `setup.zig` - Logic to fork into child and supervisor processes, and seccomp initialization
3. `supervisor.zig` - Syscall handling event loop
   - Receives syscall notifications via ioctl
   - Routes to handlers or passthrough
4. `types.zig` - Common types
   - `Result(T)` union for Linux error handling
   - `MemoryBridge` for cross-process memory access via process_vm_readv/writev
   - `Logger` with color-coded process prefixes

**Syscall flow**: Child syscall → kernel USER_NOTIF → supervisor receives → syscall is handled or passthrough

## Key Linux APIs Used
- Seccomp user notifier (`SECCOMP_SET_MODE_FILTER`, `SECCOMP_IOCTL_NOTIF_*`)
- BPF filter programs
- `process_vm_readv`/`process_vm_writev` for cross-process memory
- `pidfd_open`/`pidfd_getfd` for FD operations across processes

## Zig Guidelines
- Zig 0.16 is required, and includes a new `std.Io` module that provides a unified interface for asynchronous I/O.
- The std lib can be found in the same directory as the Zig binary, plus ./lib/std. Use grep to find the current APIs. If further documentation is needed, use https://ziglang.org/documentation/master/std/ as a reference.
- Use the installed ZLS language server for up-to-date feedback on 0.16 features. 
- Where possible, keep structs as individual files, using the file-as-struct pattern with `const Self = @This()`.
- Prefer the `try` keyword over `catch` when possible.
- Prefer to use stack buffers over heap allocation when possible.
- PascalCase for types (and functions returning types), snake_case for variables, camelCase for functions.
- Use init(...) as constructor, and a deferrable deinit(...) if destructor is needed.
- Use std.linux specific APIs rather than calling syscalls directly. When in doubt, grep std.linux. The std lib can be found in the same directory as the Zig binary, plus ./lib/std/os/linux.zig.