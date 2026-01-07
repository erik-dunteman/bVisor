#!/bin/bash
# /etc/passwd Protection (Phase 1: Core Filesystem)
# Writes to /etc/passwd should NOT modify the real file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine /bin/sh -c '
  BEFORE=$(md5sum /etc/passwd | cut -d" " -f1)

  # Attempt to modify /etc/passwd inside bVisor
  /zig-out/bin/bVisor /bin/sh -c "echo PWNED >> /etc/passwd" 2>/dev/null || true

  AFTER=$(md5sum /etc/passwd | cut -d" " -f1)

  if [ "$BEFORE" = "$AFTER" ]; then
    echo "PASS: /etc/passwd unchanged"
    exit 0
  else
    echo "FAIL: /etc/passwd was modified!"
    exit 1
  fi
'
