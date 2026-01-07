#!/bin/bash
# Path Traversal Attack
# Attempt to escape sandbox via ../../../ paths

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine /bin/sh -c '
  BEFORE=$(md5sum /etc/passwd | cut -d" " -f1)

  /zig-out/bin/bVisor /bin/sh -c "echo PWNED > /../../../etc/passwd" 2>/dev/null || true
  /zig-out/bin/bVisor /bin/sh -c "echo PWNED > /....//....//etc/passwd" 2>/dev/null || true

  AFTER=$(md5sum /etc/passwd | cut -d" " -f1)

  if [ "$BEFORE" = "$AFTER" ]; then
    echo "PASS: Path traversal blocked"
    exit 0
  else
    echo "FAIL: /etc/passwd modified via traversal"
    exit 1
  fi
'
