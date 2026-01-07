#!/bin/bash
# Test that dangerous /proc and /sys paths are blocked
# These paths could allow escape or host disruption if accessible

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine /bin/sh -c '
  FAILED=0

  # Test blocked exact paths - check for BLOCKED message in output
  for path in /proc/sysrq-trigger /proc/sys/kernel/core_pattern /proc/sys/kernel/modprobe /proc/kcore /proc/kmem /proc/kallsyms /proc/self/mem; do
    OUTPUT=$(/zig-out/bin/bVisor /bin/sh -c "cat $path" 2>&1)
    if ! echo "$OUTPUT" | grep -q "BLOCKED dangerous path"; then
      echo "FAIL: $path was not blocked"
      FAILED=1
    fi
  done

  # Test blocked prefix paths
  for path in /proc/sys/vm/swappiness /sys/fs/cgroup/memory /sys/kernel/debug /sys/devices/virtual/powercap/intel-rapl; do
    OUTPUT=$(/zig-out/bin/bVisor /bin/sh -c "cat $path" 2>&1)
    if ! echo "$OUTPUT" | grep -q "BLOCKED dangerous path"; then
      echo "FAIL: $path was not blocked"
      FAILED=1
    fi
  done

  if [ $FAILED -eq 0 ]; then
    echo "PASS: All dangerous paths blocked"
  fi
  exit $FAILED
'
