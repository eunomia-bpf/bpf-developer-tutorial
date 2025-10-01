#!/bin/bash

set -e

echo "=============================================="
echo "Combined Profiler Demonstration"
echo "=============================================="
echo

# Build the test program
echo "🔨 Building test program..."
gcc -o test_program tests/test_combined.c 
echo "✅ Test program built successfully"
echo

# Make the profiler script executable
chmod +x combined_profiler.py

echo "🚀 Starting test program in background..."
./test_program &
TEST_PID=$!

echo "📊 Test program PID: $TEST_PID"
echo "⏱️  Waiting 3 seconds for test program to stabilize..."
sleep 3

echo
echo "🔥 Starting combined profiling for 15 seconds..."
echo "   This will capture both CPU usage and blocking behavior"
echo "   Note: Requires root privileges for BPF access"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Not running as root. The profiler may fail to access BPF features."
    echo "   Consider running: sudo ./demo.sh"
    echo
fi

# Run the combined profiler
python3 combined_profiler.py $TEST_PID -d 15 -f 99 -m 500 -o demo_results

echo
echo "🧹 Cleaning up test program..."

# Kill the test program gracefully
kill $TEST_PID 2>/dev/null || true
wait $TEST_PID 2>/dev/null || true

echo "✅ Test program stopped"
echo
echo "=============================================="
echo "Demo Complete!"
echo "=============================================="
echo
echo "Generated files should include:"
echo "• demo_results.folded - Raw flamegraph data"
echo "• demo_results.svg    - Interactive flamegraph visualization"
echo
echo "Open demo_results.svg in a web browser to explore the results!"
echo
echo "What to look for in the flamegraph:"
echo "• 'oncpu:' sections show CPU-intensive operations (cpu_work function)"
echo "• 'offcpu:' sections show blocking operations (usleep calls)"
echo "• Width indicates time spent - wider = more time"