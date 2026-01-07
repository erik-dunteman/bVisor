#!/bin/bash
# Security test suite runner for bVisor
# Runs all security tests in Docker to protect host machine

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================="
echo "bVisor Security Test Suite"
echo "=================================="
echo ""

# Build bVisor first
echo "Building bVisor..."
cd "$PROJECT_DIR"
zig build
echo ""

# Count results
PASSED=0
FAILED=0
SKIPPED=0

# Run each test
for test_script in "$SCRIPT_DIR"/security/*.sh; do
    if [ ! -f "$test_script" ]; then
        continue
    fi

    test_name=$(basename "$test_script" .sh)
    echo -n "Running $test_name... "

    # Run test and capture output
    if output=$(bash "$test_script" 2>&1); then
        if echo "$output" | grep -q "PASS"; then
            echo -e "${GREEN}PASS${NC}"
            ((PASSED++))
        elif echo "$output" | grep -q "SKIP"; then
            echo -e "${YELLOW}SKIP${NC}"
            ((SKIPPED++))
        else
            echo -e "${GREEN}PASS${NC} (no explicit PASS message)"
            ((PASSED++))
        fi
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Output: $output"
        ((FAILED++))
    fi
done

echo ""
echo "=================================="
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"
echo "=================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
