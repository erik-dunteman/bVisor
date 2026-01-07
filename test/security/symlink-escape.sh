#!/bin/bash
# CVE-2021-30465: Symlink-Exchange Mount Escape
# TOCTOU race swapping symlink during mount

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine /bin/sh -c '
  # Attempt symlink to escape
  /zig-out/bin/bVisor /bin/sh -c "ln -s /etc/passwd /tmp/escape && cat /tmp/escape" 2>/dev/null || true

  # Symlink should not exist in container filesystem
  if [ -L /tmp/escape ]; then
    echo "FAIL: Symlink escaped to container filesystem"
    exit 1
  fi
  echo "PASS: Symlink contained in VFS"
  exit 0
'
