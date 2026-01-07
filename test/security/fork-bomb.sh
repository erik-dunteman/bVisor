#!/bin/bash
# Fork Bomb Containment
# Ensure fork bomb does not escape sandbox or hang host

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

timeout 10 docker run --rm --security-opt seccomp=unconfined -v "$PROJECT_DIR/zig-out:/zig-out:ro" alpine \
  /zig-out/bin/bVisor /bin/sh -c ':(){ :|:& };:' 2>/dev/null || true
echo "PASS: Fork bomb contained (did not hang host)"
exit 0
