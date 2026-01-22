### bVisor is an in-process linux sandbox.

bVisor is an SDK and runtime for securely running Linux sandboxes, locally.

Inspired by [gVisor](https://github.com/google/gVisor), bVisor runs workloads directly on the host machine, providing isolation by intercepting and virtualizing [linux syscalls](https://en.wikipedia.org/wiki/System_call) from userspace, allowing for secure and isolated I/O without the overhead of a virtual machine or remote infra.

Unlike gVisor, bVisor is built to run directly in your application, spinning up and tearing down sandboxes in milliseconds. This makes it ideal for ephemeral tasks commonly performed by LLM agents, such as code execution or filesystem operations.

## Architecture

bVisor is built on [Seccomp user notifier](https://man7.org/linux/man-pages/man2/seccomp.2.html), a Linux kernel feature that allows userspace processes to intercept and optionally handle syscalls from a child process. This allows bVisor to block or mock the kernel API (such as filesystem read/write, network access, etc.) to ensure the child process remains sandboxed. 

Other than the overhead of syscall emulation, child processes run natively.

### Goal

bVisor is ~complete once it can embed into higher-level languages, such as python or typescript, as an alternative "bash" subprocess runner.

For example, embedded into a python SDK:
```python
from bvisor import Sandbox

with Sandbox() as sb:
    sb.bash("echo 'Hello, world!'")
    sb.bash("ls /")  # serves virtual "/"
    sb.bash("touch /tmp/test.txt")
    sb.bash("curl https://www.google.com")
    sb.bash("npm install")
    sb.bash("sleep 5")

    try:
        sb.bash("chroot /tmp")  # blocked
    except Exception as e:
        pass  # as expected
```

Or similarly in typescript:
```typescript
import { Sandbox } from "bvisor";

using sb = await Sandbox.create();

await sb.bash("echo 'Hello, world!'");
// etc ...
```

## Status

bVisor is an early proof-of-concept. Core syscall interception works via seccomp. Process isolation works via virtual namespaces. Now just working through the laundry list of misc syscalls.


#### 1. Process Visibility Isolation - *in progress*

Sandboxed processes can only see and signal other processes within the same namespace. Processes use real kernel PIDs, but namespace boundaries control visibility.

- [x] Virtual namespaces with parent/child relationships.
- [x] `kill` restricted to processes within namespace
- [x] `/proc` reads filtered to visible processes only
- [x] `clone`/`fork` inherit namespaces, mimicking real kernel behavior
- [x] Per-process virtual FD tables
- [ ] `wait4`/`waitid` for process reaping
- [ ] `execve` for program execution

#### 2. Copy-on-Write Filesystem - *in progress*

bVisor is imageless, meaning it does not require a base image to run. It runs with direct visibility to the host filesystem. This allows system dependencies such as `npm` to work out of the box.

Isolation is achieved via a copy-on-write overlay on top of the host filesystem. Files opened with write flags are copied to a sandbox-local directory. Read-only files are passed through to the real filesystem. 

- [x] Path normalization (blocks `..` traversal attacks)
- [x] `openat` with path-based allow/block rules
- [ ] COW (copy-on-write) layer for write operations
- [ ] Storage backend for COW (plans for /tmp, local, s3)
- [ ] FD operations (`read`, `write`, `close`, `dup`, `lseek`, `fstat`, `fcntl`)
- [ ] Directory operations (`getcwd`, `chdir`, `mkdirat`, `unlinkat`, `getdents64`)

#### 3. Network Isolation - *not started*

- [ ] Block or virtualize network syscalls
- [ ] Optional allowlist for specific hosts/ports

#### 4. Resource Limits (cgroups) - *not started*

- [ ] CPU/memory limits
- [ ] I/O throttling

#### 5. Host Info Virtualization - *not started*

Prevent leaking host system details in multi-tenant environments.

- [ ] `uname` - kernel version, hostname
- [ ] `sysinfo` - total RAM, uptime, load
- [ ] `getrlimit` - resource configuration
- [ ] `getrusage` - resource usage stats

### Infrastructure

**Core**
- [x] Seccomp user notifier interception
- [x] Supervisor/child process model
- [x] BPF filter installation
- [x] Cross-process memory access (`process_vm_readv`/`writev`)
- [x] `writev` emulation (stdout/stderr capture)

**Blocked Dangerous Syscalls**
- [x] `ptrace`, `mount`, `umount2`, `chroot`, `pivot_root`, `setns`, `unshare`, `seccomp`, `reboot`, `prlimit64`

**Passthrough** (kernel handles directly)
- [x] Memory: `brk`, `mmap`, `mprotect`, `munmap`
- [x] Time: `clock_gettime`, `gettimeofday`, `nanosleep`
- [x] Identity: `getuid`, `geteuid`, `getgid`, `getegid`
- [x] Runtime: `getrandom`, `futex`

### Platform Support

- [x] Linux (aarch64, x86_64)
- [ ] macOS - requires alternative to seccomp (no equivalent exists)

### SDK

- [ ] Compile runtime for distribution
- [ ] Python bindings
- [ ] TypeScript bindings

## Development

#### Zig
bVisor is written in Zig. Zig is pre-1.0, so compilation is only guaranteed with the exact zig build. We're using a tagged commit on 0.16 dev, which includes major breaking changes (Io) compared to previous versions, so please use the exact version specified in the `build.zig.zon` file.
It's also recommended to compile ZLS from source using a tagged commit compatible with Zig. You'll be flying blind otherwise.

#### Cross-compilation
bVisor depends on Linux kernel features, though it's developed primarily on Arm Macs and tested via docker. The `build.zig` is currently configured to cross-compile aarch64-linux-musl, so running `zig build` will produce a binary in `zig-out/bin/bVisor` which will only run in a Linux container. Use `zig build run` to execute the binary in a container.

#### Testing
There are three ways to test:

**Native unit tests**
- `zig build test` runs unit tests **on your mac**. It's intended for quick correctness checks for anything behind the seccomp notification layer (syscall handlers, namespace isolation, virtual filesystem, etc). Prefer to use posix apis over linux where possible, to allow more tests to natively run on mac. If posix apis are not available, we can do comptime dependency injection (see `src/deps`) to use mac-compatible mocks when running on mac.

**Containerized unit tests**
- `zig build test -Duse-docker` runs the same tests as `zig build test` but in a linux container. This exercises the linux deps in `src/deps`.

**E2E test in linux container**
- `zig build run` runs the full executable in a linux container, executing `smoke_test.zig` as a sandboxed guest process. It will print out a scorecard of which features are supported so far. The goal is to get it to 100%, then add more tests!

