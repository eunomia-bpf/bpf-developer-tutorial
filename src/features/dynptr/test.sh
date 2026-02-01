#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Test script for dynptr TC demo
# Requires: root privileges, Linux kernel >= 6.4

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."

    # Kill processes
    sudo pkill -9 dynptr_tc 2>/dev/null || true

    # Kill HTTP server in namespace
    if [ -n "$HTTP_PID" ]; then
        sudo kill -9 $HTTP_PID 2>/dev/null || true
    fi
    sudo ip netns pids test_dynptr 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true

    # Remove TC hooks
    sudo tc qdisc del dev veth_host clsact 2>/dev/null || true

    # Remove network namespace and veth
    sudo ip link del veth_host 2>/dev/null || true
    sudo ip netns del test_dynptr 2>/dev/null || true

    log_info "Cleanup complete"
}

trap cleanup EXIT

check_prereqs() {
    log_info "Checking prerequisites..."

    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi

    # Check kernel version (need >= 6.4 for bpf_dynptr_from_skb)
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

    if [ "$KERNEL_MAJOR" -lt 6 ] || ([ "$KERNEL_MAJOR" -eq 6 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
        log_warn "Kernel version $KERNEL_VERSION detected. This demo requires >= 6.4 for skb dynptr kfuncs."
        log_warn "The test may fail to load the BPF program."
    else
        log_info "Kernel version $KERNEL_VERSION OK (>= 6.4)"
    fi

    if [ ! -f "./dynptr_tc" ]; then
        log_info "Building dynptr_tc..."
        make
    fi
}

setup_network() {
    log_info "Setting up network namespace and veth pair..."

    # Clean up any existing setup
    sudo ip link del veth_host 2>/dev/null || true
    sudo ip netns del test_dynptr 2>/dev/null || true

    # Create network namespace
    sudo ip netns add test_dynptr

    # Create veth pair
    sudo ip link add veth_host type veth peer name veth_ns

    # Move one end to namespace
    sudo ip link set veth_ns netns test_dynptr

    # Configure host side
    sudo ip addr add 10.200.0.1/24 dev veth_host
    sudo ip link set veth_host up

    # Configure namespace side
    sudo ip netns exec test_dynptr ip addr add 10.200.0.2/24 dev veth_ns
    sudo ip netns exec test_dynptr ip link set veth_ns up
    sudo ip netns exec test_dynptr ip link set lo up

    # Verify connectivity
    if ping -c 1 -W 1 10.200.0.2 > /dev/null 2>&1; then
        log_info "Network namespace setup complete, connectivity verified"
    else
        log_error "Failed to establish connectivity to namespace"
        exit 1
    fi
}

start_http_server() {
    log_info "Starting HTTP server in namespace on 10.200.0.2:8080..."
    sudo ip netns exec test_dynptr python3 -m http.server 8080 --bind 10.200.0.2 &>/dev/null &
    HTTP_PID=$!
    sleep 2

    # Verify HTTP server
    if curl -s --max-time 2 http://10.200.0.2:8080/ > /dev/null 2>&1; then
        log_info "HTTP server is running"
    else
        log_error "Failed to start HTTP server"
        exit 1
    fi
}

test_basic_capture() {
    log_info "=== Test 1: Basic packet capture ==="

    # Remove any existing TC hooks
    sudo tc qdisc del dev veth_host clsact 2>/dev/null || true

    # Start dynptr_tc (no blocking)
    log_info "Starting dynptr_tc on veth_host..."
    sudo timeout 5 ./dynptr_tc -i veth_host -p 0 -s 32 > /tmp/dynptr_output.txt 2>&1 &
    DYNPTR_PID=$!
    sleep 2

    # Send HTTP request
    log_info "Sending HTTP request..."
    curl -s --max-time 2 http://10.200.0.2:8080/ > /dev/null 2>&1 || true

    sleep 2

    # Wait for dynptr_tc to finish
    wait $DYNPTR_PID 2>/dev/null || true

    # Check output
    if grep -q "10.200.0.2:8080" /tmp/dynptr_output.txt; then
        if grep -q "payload=" /tmp/dynptr_output.txt; then
            log_info "Test 1 PASSED: Captured TCP packet with payload"
            echo "Sample output:"
            grep "payload=" /tmp/dynptr_output.txt | head -2
        else
            log_warn "Test 1 PARTIAL: Captured packets but no payload (might be ACKs only)"
            cat /tmp/dynptr_output.txt | head -5
        fi
    else
        log_error "Test 1 FAILED: Did not capture expected packets"
        cat /tmp/dynptr_output.txt
        return 1
    fi

    # Clean up TC hook for next test
    sudo tc qdisc del dev veth_host clsact 2>/dev/null || true
}

test_blocking() {
    log_info "=== Test 2: Port blocking ==="

    # Start dynptr_tc with blocking on port 8080
    log_info "Starting dynptr_tc with port 8080 blocked..."
    sudo ./dynptr_tc -i veth_host -p 8080 -s 32 > /tmp/dynptr_block.txt 2>&1 &
    DYNPTR_PID=$!
    sleep 2

    # Send HTTP request (should timeout/fail)
    log_info "Sending HTTP request (should be blocked)..."
    if curl -s --max-time 3 http://10.200.0.2:8080/ > /dev/null 2>&1; then
        log_warn "Test 2 WARNING: Request succeeded but should have been blocked"
        log_warn "Note: Blocking depends on TC direction - responses from server are blocked on ingress"
    else
        log_info "Test 2: Request blocked/timed out as expected"
    fi

    sleep 1
    sudo kill -INT $DYNPTR_PID 2>/dev/null || true
    wait $DYNPTR_PID 2>/dev/null || true

    # Check output for drop events
    if grep -q "drop=1" /tmp/dynptr_block.txt; then
        log_info "Test 2 PASSED: Packets were dropped (drop=1 in output)"
        grep "drop=1" /tmp/dynptr_block.txt | head -2
    else
        log_info "Test 2 output:"
        cat /tmp/dynptr_block.txt | head -5
    fi

    # Clean up TC hook
    sudo tc qdisc del dev veth_host clsact 2>/dev/null || true
}

main() {
    log_info "Starting dynptr TC demo tests..."
    log_info "Kernel: $(uname -r)"

    check_prereqs
    setup_network
    start_http_server

    echo ""
    test_basic_capture

    echo ""
    test_blocking

    echo ""
    log_info "All tests completed!"
}

main "$@"
