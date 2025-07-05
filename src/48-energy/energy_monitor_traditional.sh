#!/bin/bash
# Traditional energy monitoring script using /proc filesystem
# This script monitors CPU usage and estimates energy consumption

# Default values
DURATION=0
CPU_POWER=15.0  # Default 15W per CPU
VERBOSE=0
INTERVAL=0.1    # Sampling interval in seconds

# Parse command line arguments
while getopts "vd:p:i:" opt; do
    case $opt in
        v) VERBOSE=1 ;;
        d) DURATION=$OPTARG ;;
        p) CPU_POWER=$OPTARG ;;
        i) INTERVAL=$OPTARG ;;
        ?) echo "Usage: $0 [-v] [-d duration] [-p power_watts] [-i interval]"
           exit 1 ;;
    esac
done

echo "Traditional Energy Monitor Started..."
echo "CPU Power: ${CPU_POWER}W"
echo "Sampling Interval: ${INTERVAL}s"
[ $DURATION -gt 0 ] && echo "Duration: ${DURATION}s"
echo ""

# Get number of CPUs
NUM_CPUS=$(nproc)

# Associative arrays to store data
declare -A prev_cpu_time
declare -A prev_total_time
declare -A process_energy
declare -A process_runtime
declare -A process_comm

# Function to read CPU stats
read_cpu_stats() {
    local cpu_line
    cpu_line=$(grep "^cpu " /proc/stat)
    echo "$cpu_line" | awk '{print $2+$3+$4+$5+$6+$7+$8}'
}

# Function to read process stats
read_process_stats() {
    local pid=$1
    if [ -f "/proc/$pid/stat" ]; then
        # Get process name
        local comm=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
        process_comm[$pid]="$comm"
        
        # Get CPU time (user + system time in clock ticks)
        local cpu_time=$(awk '{print $14 + $15}' /proc/$pid/stat 2>/dev/null || echo 0)
        echo "$cpu_time"
    else
        echo "0"
    fi
}

# Get clock ticks per second
CLK_TCK=$(getconf CLK_TCK)

# Initialize start time
start_time=$(date +%s)
sample_count=0

# Main monitoring loop
while true; do
    # Get current total CPU time
    total_cpu_time=$(read_cpu_stats)
    
    # Get list of all processes
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        if [ -d "/proc/$pid" ]; then
            current_cpu_time=$(read_process_stats $pid)
            
            # Calculate delta if we have previous data
            if [ -n "${prev_cpu_time[$pid]}" ]; then
                delta_ticks=$((current_cpu_time - prev_cpu_time[$pid]))
                
                if [ $delta_ticks -gt 0 ]; then
                    # Convert ticks to seconds
                    delta_seconds=$(echo "scale=6; $delta_ticks / $CLK_TCK" | bc)
                    
                    # Calculate energy (Joules = Watts * seconds)
                    energy=$(echo "scale=6; $CPU_POWER * $delta_seconds / $NUM_CPUS" | bc)
                    
                    # Accumulate energy
                    if [ -n "${process_energy[$pid]}" ]; then
                        process_energy[$pid]=$(echo "scale=6; ${process_energy[$pid]} + $energy" | bc)
                        process_runtime[$pid]=$(echo "scale=6; ${process_runtime[$pid]} + $delta_seconds" | bc)
                    else
                        process_energy[$pid]=$energy
                        process_runtime[$pid]=$delta_seconds
                    fi
                    
                    if [ $VERBOSE -eq 1 ]; then
                        printf "%-16s pid=%-6d runtime=%.3fs energy=%.6fJ\n" \
                            "${process_comm[$pid]}" "$pid" "$delta_seconds" "$energy"
                    fi
                fi
            fi
            
            prev_cpu_time[$pid]=$current_cpu_time
        fi
    done
    
    # Clean up terminated processes
    for pid in "${!prev_cpu_time[@]}"; do
        if [ ! -d "/proc/$pid" ]; then
            unset prev_cpu_time[$pid]
        fi
    done
    
    sample_count=$((sample_count + 1))
    
    # Check if we should exit
    if [ $DURATION -gt 0 ]; then
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        if [ $elapsed -ge $DURATION ]; then
            break
        fi
    fi
    
    # Handle Ctrl+C through trap
    
    # Sleep for interval
    sleep $INTERVAL
done

# Print summary
echo ""
echo "=== Energy Usage Summary ==="
printf "%-10s %-16s %-15s %-15s\n" "PID" "COMM" "Runtime (s)" "Energy (J)"
printf "%-10s %-16s %-15s %-15s\n" "----------" "----------------" "---------------" "---------------"

total_energy=0
total_runtime=0

# Sort by energy consumption
for pid in $(for p in "${!process_energy[@]}"; do 
    echo "$p ${process_energy[$p]}"
done | sort -k2 -nr | head -20 | awk '{print $1}'); do
    if [ -n "${process_energy[$pid]}" ] && [ "${process_energy[$pid]}" != "0" ]; then
        printf "%-10d %-16s %-15.3f %-15.6f\n" \
            "$pid" "${process_comm[$pid]}" "${process_runtime[$pid]}" "${process_energy[$pid]}"
        
        total_energy=$(echo "scale=6; $total_energy + ${process_energy[$pid]}" | bc)
        total_runtime=$(echo "scale=6; $total_runtime + ${process_runtime[$pid]}" | bc)
    fi
done

echo ""
echo "Total CPU time: ${total_runtime}s"
echo "Total estimated energy: ${total_energy}J"
echo "CPU power setting: ${CPU_POWER}W"
echo "Samples collected: $sample_count"

# Trap Ctrl+C to clean exit
cleanup() {
    echo -e "\nStopping energy monitor..."
}
trap cleanup INT