#!/bin/bash
# Script to compare eBPF and traditional energy monitoring approaches

set -e

echo "Energy Monitor Comparison Tool"
echo "=============================="
echo ""

# Check if we're running as root (required for eBPF)
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (required for eBPF)"
    exit 1
fi

# Default parameters
DURATION=10
CPU_POWER=15.0
WORKLOAD=""

# Parse arguments
while getopts "d:p:w:" opt; do
    case $opt in
        d) DURATION=$OPTARG ;;
        p) CPU_POWER=$OPTARG ;;
        w) WORKLOAD=$OPTARG ;;
        ?) echo "Usage: $0 [-d duration] [-p power_watts] [-w 'workload command']"
           exit 1 ;;
    esac
done

# Build eBPF program if needed
if [ ! -f "energy_monitor" ]; then
    echo "Building eBPF energy monitor..."
    make energy_monitor
fi

# Function to run a monitor
run_monitor() {
    local monitor_type=$1
    local output_file=$2
    
    echo "Running $monitor_type monitor for ${DURATION} seconds..."
    
    if [ "$monitor_type" = "eBPF" ]; then
        ./energy_monitor -d $DURATION -p $CPU_POWER > $output_file 2>&1
    else
        ./energy_monitor_traditional.sh -d $DURATION -p $CPU_POWER -i 0.1 > $output_file 2>&1
    fi
}

# Start workload if specified
if [ -n "$WORKLOAD" ]; then
    echo "Starting workload: $WORKLOAD"
    eval "$WORKLOAD" &
    WORKLOAD_PID=$!
    sleep 1
fi

# Run traditional monitor
echo ""
echo "Phase 1: Traditional /proc-based monitoring"
echo "-------------------------------------------"
START_TIME=$(date +%s.%N)
run_monitor "traditional" /tmp/traditional_output.txt
END_TIME=$(date +%s.%N)
TRADITIONAL_TIME=$(echo "$END_TIME - $START_TIME" | bc)

# Extract traditional results
TRADITIONAL_TOTAL=$(grep "Total estimated energy:" /tmp/traditional_output.txt | awk '{print $4}')
TRADITIONAL_SAMPLES=$(grep "Samples collected:" /tmp/traditional_output.txt | awk '{print $3}')

# Wait a bit between tests
sleep 2

# Run eBPF monitor
echo ""
echo "Phase 2: eBPF-based monitoring"
echo "------------------------------"
START_TIME=$(date +%s.%N)
run_monitor "eBPF" /tmp/ebpf_output.txt
END_TIME=$(date +%s.%N)
EBPF_TIME=$(echo "$END_TIME - $START_TIME" | bc)

# Extract eBPF results
EBPF_TOTAL=$(grep "Total estimated energy:" /tmp/ebpf_output.txt | grep -oE '[0-9]+\.[0-9]+ J' | awk '{print $1}')

# Stop workload if running
if [ -n "$WORKLOAD_PID" ]; then
    kill $WORKLOAD_PID 2>/dev/null || true
    wait $WORKLOAD_PID 2>/dev/null || true
fi

# Display comparison
echo ""
echo "Comparison Results"
echo "=================="
echo ""
printf "%-25s %-15s %-15s\n" "Metric" "Traditional" "eBPF"
printf "%-25s %-15s %-15s\n" "-------------------------" "---------------" "---------------"
printf "%-25s %-15s %-15s\n" "Total Energy (J)" "$TRADITIONAL_TOTAL" "$EBPF_TOTAL"
printf "%-25s %-15s %-15s\n" "Monitoring Time (s)" "$TRADITIONAL_TIME" "$EBPF_TIME"
printf "%-25s %-15s %-15s\n" "Samples/Events" "$TRADITIONAL_SAMPLES" "Continuous"

# Calculate overhead
OVERHEAD_PERCENT=$(echo "scale=2; ($TRADITIONAL_TIME - $EBPF_TIME) / $EBPF_TIME * 100" | bc)
echo ""
echo "Performance Analysis:"
echo "- Traditional monitoring overhead: ${OVERHEAD_PERCENT}% compared to eBPF"
echo "- eBPF provides per-context-switch granularity"
echo "- Traditional samples at fixed intervals (100ms)"

# Show top processes from both
echo ""
echo "Top Energy Consumers (Traditional):"
echo "-----------------------------------"
grep -A 5 "PID.*COMM.*Runtime.*Energy" /tmp/traditional_output.txt | head -6

echo ""
echo "Top Energy Consumers (eBPF):"
echo "----------------------------"
grep -A 5 "PID.*COMM.*Runtime.*Energy" /tmp/ebpf_output.txt | head -6

# Cleanup
rm -f /tmp/traditional_output.txt /tmp/ebpf_output.txt

echo ""
echo "Comparison complete!"