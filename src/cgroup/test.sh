#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# test.sh - One-click test script for cgroup eBPF tutorial
#
# This script:
# 1. Builds the program if needed
# 2. Starts test HTTP servers
# 3. Runs the cgroup_guard loader
# 4. Executes tests from within the cgroup
# 5. Cleans up everything

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CGROUP_PATH="/sys/fs/cgroup/ebpf_demo"
BLOCK_PORT=9090
DENY_DEVICE="1:3"
DENY_SYSCTL="kernel/hostname"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    echo -e "\n${YELLOW}=== Cleaning up ===${NC}"

    # Kill our processes
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi

    if [ -n "$SERVER_8080_PID" ] && kill -0 "$SERVER_8080_PID" 2>/dev/null; then
        kill "$SERVER_8080_PID" 2>/dev/null || true
    fi

    if [ -n "$SERVER_9090_PID" ] && kill -0 "$SERVER_9090_PID" 2>/dev/null; then
        kill "$SERVER_9090_PID" 2>/dev/null || true
    fi

    # Remove test cgroup (will fail if processes still in it, which is fine)
    if [ -d "$CGROUP_PATH" ]; then
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Build if needed
if [ ! -f "./cgroup_guard" ]; then
    echo -e "${YELLOW}=== Building cgroup_guard ===${NC}"
    make
fi

echo -e "${YELLOW}=== Starting test HTTP servers ===${NC}"
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER_8080_PID=$!
python3 -m http.server 9090 --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER_9090_PID=$!
sleep 1
echo "HTTP server on port 8080 (PID: $SERVER_8080_PID)"
echo "HTTP server on port 9090 (PID: $SERVER_9090_PID)"

echo -e "\n${YELLOW}=== Starting cgroup_guard ===${NC}"
./cgroup_guard \
    --cgroup "$CGROUP_PATH" \
    --block-port "$BLOCK_PORT" \
    --deny-device "$DENY_DEVICE" \
    --deny-sysctl "$DENY_SYSCTL" &
LOADER_PID=$!
sleep 2

echo -e "\n${YELLOW}=== Running tests from within cgroup ===${NC}"
echo "Testing from cgroup: $CGROUP_PATH"
echo ""

# Create a temp file outside the test for output (since /dev/null is blocked in cgroup)
TMPOUT=$(mktemp)
trap "rm -f $TMPOUT" EXIT

# Run tests in a subshell that joins the cgroup
# Note: We can't use /dev/null redirects inside the cgroup since it's blocked
bash -c "
echo \$\$ > $CGROUP_PATH/cgroup.procs

echo '--- TCP Connection Test ---'
# Test port 8080 - should work (write to temp file to avoid /dev/null)
curl -s --connect-timeout 2 -o $TMPOUT http://127.0.0.1:8080 2>$TMPOUT.err
if [ \$? -eq 0 ]; then
    echo -e '${GREEN}[PASS]${NC} Port 8080: Connection allowed'
else
    echo -e '${RED}[FAIL]${NC} Port 8080: Connection failed (should be allowed)'
fi

# Test port 9090 - should be blocked
curl -s --connect-timeout 2 -o $TMPOUT http://127.0.0.1:9090 2>$TMPOUT.err
if [ \$? -eq 0 ]; then
    echo -e '${RED}[FAIL]${NC} Port 9090: Connection allowed (should be blocked!)'
else
    echo -e '${GREEN}[PASS]${NC} Port 9090: Connection blocked'
fi

echo ''
echo '--- Device Access Test ---'
# Test /dev/null (1:3) - should be blocked
cat /dev/null >$TMPOUT 2>$TMPOUT.err
if [ \$? -eq 0 ]; then
    echo -e '${RED}[FAIL]${NC} /dev/null (1:3): Access allowed (should be blocked!)'
else
    echo -e '${GREEN}[PASS]${NC} /dev/null (1:3): Access blocked'
fi

echo ''
echo '--- Sysctl Read Test ---'
# Test kernel/hostname - should be blocked
cat /proc/sys/kernel/hostname >$TMPOUT 2>$TMPOUT.err
if [ \$? -eq 0 ]; then
    echo -e '${RED}[FAIL]${NC} kernel/hostname: Read allowed (should be blocked!)'
else
    echo -e '${GREEN}[PASS]${NC} kernel/hostname: Read blocked'
fi
"

# Clean up temp files
rm -f "$TMPOUT" "$TMPOUT.err" 2>/dev/null || true

echo ""
echo -e "${GREEN}=== All tests completed ===${NC}"
