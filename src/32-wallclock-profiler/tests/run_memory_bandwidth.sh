#!/bin/bash

set -e

echo "=============================================="
echo "Multi-threaded Profiler Test"
echo "=============================================="
echo

# Build the multi-threaded test program
echo "🔨 Building multi-threaded test program..."
g++ -o test_multithread tests/double_bandwidth.cpp -g -fno-omit-frame-pointer -lpthread -lrt -lm -O3
# gcc -o test_multithread tests/double_bandwidth.c -g -fno-omit-frame-pointer -lpthread -lrt -lm -O3
# gcc -o test_multithread tests/test_multithread.c -lpthread -lrt -lm
echo "✅ Multi-threaded test program built successfully"
echo

# Make the profiler script executable
chmod +x combined_profiler.py

echo "🚀 Starting multi-threaded web server simulation..."
./test_multithread &
TEST_PID=$!

echo "📊 Multi-threaded test PID: $TEST_PID"
echo "⏱️  Waiting 5 seconds for application to stabilize and generate load..."
sleep 5

echo
echo "🧵 Discovering threads..."
ps -T -p $TEST_PID
echo

echo "🔥 Starting per-thread profiling for 20 seconds..."
echo "   This will profile each thread individually with:"
echo "   - On-CPU profiling to show CPU-intensive work"
echo "   - Off-CPU profiling to show blocking I/O operations"
echo "   - Individual flamegraphs for each thread"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Not running as root. The profiler may fail to access BPF features."
    echo "   Consider running: sudo $0"
    echo
fi

# Run the multi-threaded profiler
python3 combined_profiler.py $TEST_PID -d 60 -f 99 -m 1000
# python3 combined_profiler.py $TEST_PID -d 30 -f 99 -m 1000


echo
echo "🧹 Cleaning up test program..."

# Kill the test program gracefully
kill $TEST_PID 2>/dev/null || true
wait $TEST_PID 2>/dev/null || true

echo "✅ Test program stopped"
echo
echo "=============================================="
echo "Multi-threaded Profiling Test Complete!"
echo "=============================================="
echo
echo "Generated files should include:"
echo "• Individual .folded files for each thread"
echo "• Individual .svg flamegraphs for each thread"  
echo "• Thread analysis summary file"
echo
echo "What to look for in the thread-specific flamegraphs:"
echo "🔧 Worker threads:"
echo "   • CPU-intensive sections (compute work)"
echo "   • I/O blocking sections (file operations, network calls)"
echo "   • Database operation latencies"
echo
echo "📈 Request generator thread:"
echo "   • Light CPU usage for request creation"
echo "   • Some blocking on queue operations"
echo
echo "📊 Statistics monitor thread:"
echo "   • Mostly sleeping (off-CPU time)"
echo "   • Periodic wake-ups for statistics collection"
echo
echo "🎯 Analysis tips:"
echo "   • Compare thread roles and their performance patterns"
echo "   • Identify which threads are CPU-bound vs I/O-bound"
echo "   • Look for synchronization bottlenecks"
echo "   • Check for load balancing across worker threads" 