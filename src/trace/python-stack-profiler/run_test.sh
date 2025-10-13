#!/bin/bash
# Test script for Python stack profiler

set -e

echo "=== Python Stack Profiler Test ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (required for eBPF)"
    exit 1
fi

# Build the profiler
echo "Building Python stack profiler..."
make clean
make

if [ ! -f "./python-stack" ]; then
    echo "Error: Build failed"
    exit 1
fi

echo "Build successful!"
echo ""

# Start Python test program in background
echo "Starting Python test program..."
python3 test_program.py &
PYTHON_PID=$!

echo "Python test program PID: $PYTHON_PID"
echo "Waiting 2 seconds for it to start..."
sleep 2

# Run the profiler
echo ""
echo "Running profiler for 5 seconds..."
./python-stack -p $PYTHON_PID -d 5 -F 49

# Cleanup
echo ""
echo "Cleaning up..."
kill $PYTHON_PID 2>/dev/null || true
wait $PYTHON_PID 2>/dev/null || true

echo ""
echo "=== Test Complete ==="
echo ""
echo "To generate a flamegraph:"
echo "  1. Run: ./python-stack -p <PID> -f > stacks.txt"
echo "  2. Generate SVG: flamegraph.pl stacks.txt > flamegraph.svg"
