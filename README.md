### bVisor is an in-process linux sandbox.

bVisor is an SDK and runtime for securely running Linux sandboxes, locally.

Inspired by [gVisor](https://github.com/google/gVisor), bVisor runs workloads directly on the host machine, providing isolation by intercepting and virtualizing [linux syscalls](https://en.wikipedia.org/wiki/System_call) from userspace, allowing for secure and isolated I/O without the overhead of a virtual machine or remote infra.

Unlike gVisor, bVisor is built to run directly in your application, spinning up and tearing down sandboxes in milliseconds. This makes it ideal for ephemeral tasks commonly performed by LLM agents, such as code execution or filesystem operations.

## Architecture

bVisor is built on [Seccomp user notifier](https://man7.org/linux/man-pages/man2/seccomp.2.html), a Linux kernel feature that allows userspace processes to intercept and optionally handle syscalls from a child process. This allows bVisor to block or mock the kernel API (such as filesystem read/write, network access, etc.) to ensure the child process remains sandboxed. 

Other than the overhead of syscall emulation, child processes run natively.

## Status
bVisor is not yet complete.

### Goal:

bVisor is ~complete when the following code works

```python
from bvisor import Sandbox

with Sandbox() as sb:
    # Common operations virtualized
    sb.bash("echo 'Hello, world!'")
    sb.bash("ls /")  # serves virtual "/" 
    sb.bash("touch /tmp/test.txt")
    sb.bash("curl https://www.google.com")
    sb.bash("npm install") 
    sb.bash("sleep 5") 

    try:
        # Escape operations blocked
        sb.bash("chroot /tmp") 
    except Exception as e:
        # As espected
```

```typescript
import { Sandbox } from "bvisor";

using sb = await Sandbox.create();

// Common operations virtualized
await sb.bash("echo 'Hello, world!'");
await sb.bash("ls /");  // serves virtual "/"
await sb.bash("touch /tmp/test.txt");
await sb.bash("curl https://www.google.com");
await sb.bash("npm install");
await sb.bash("sleep 5");

try {
    // Escape operations blocked
    await sb.bash("chroot /tmp");
} catch (e) {
    // As expected
}
```

### Milestones
At a high level:

- [ ] Runtime on Linux host
  - [x] Get seccomp working on a child process
  - [x] Allow passthrough of ALL syscalls
  - [ ] Spawn arbitrary bash command as child
  - [ ] Virtualize stdout/stderr/stdin
  - [ ] Virtualize other filesystem operations
  - [ ] Virtualize network operations
  - [ ] Block unsafe operations
  - [ ] ... (huge list of unknowns)

- [ ] Runtime on macOS host
  - [ ] (to my knowledge, macOS does not have a seccomp user notifier equivalent)

- [ ] SDK
- 
  - [ ] Compile runtime for distribution 
  - [ ] Python SDK
    - [ ] Bindings
  - [ ] TypeScript SDK
    - [ ] Bindings

