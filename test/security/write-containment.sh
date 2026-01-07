#!/bin/bash
# Write Containment (Phase 1: Core Filesystem)
# Writes inside sandbox should NOT affect container filesystem

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine /bin/sh -c '
  # Write a file inside bVisor
  /zig-out/bin/bVisor /bin/sh -c "echo SANDBOX_DATA > /test.txt"

  # File should NOT exist in container filesystem
  if [ -f /test.txt ]; then
    echo "FAIL: Write escaped to container filesystem"
    exit 1
  fi
  echo "PASS: Write contained in VFS"
  exit 0
'
