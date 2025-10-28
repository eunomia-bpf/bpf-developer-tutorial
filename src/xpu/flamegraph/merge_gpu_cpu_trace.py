#!/usr/bin/env python3
"""
Merge GPU and CPU traces into folded flamegraph format
Correlates CPU stack traces from cudaLaunchKernel uprobe with GPU kernel execution
using CUPTI correlation IDs and timestamp matching
"""

import json
import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional
from collections import defaultdict


class GPUKernelEvent:
    """Represents a GPU kernel execution event - timestamps kept in microseconds"""
    def __init__(self, name: str, start_us: float, end_us: float, correlation_id: int):
        self.name = name
        self.start_us = start_us  # Keep in microseconds (native GPU format)
        self.end_us = end_us
        self.correlation_id = correlation_id

    def __repr__(self):
        return f"GPUKernel({self.name}, {self.start_us}-{self.end_us} us, corr={self.correlation_id})"


class CudaLaunchEvent:
    """Represents a cudaLaunchKernel runtime API call - timestamps kept in microseconds"""
    def __init__(self, start_us: float, end_us: float, correlation_id: int):
        self.start_us = start_us  # Keep in microseconds (native GPU format)
        self.end_us = end_us
        self.correlation_id = correlation_id

    def __repr__(self):
        return f"CudaLaunch({self.start_us}-{self.end_us} us, corr={self.correlation_id})"


class CPUStack:
    """Represents a CPU stack trace from cudaLaunchKernel uprobe in extended folded format"""
    def __init__(self, timestamp_ns: int, comm: str, pid: int, tid: int, cpu: int, stack: List[str]):
        self.timestamp_ns = timestamp_ns
        self.comm = comm
        self.pid = pid
        self.tid = tid
        self.cpu = cpu
        self.stack = stack  # List of function names from bottom to top

    def __repr__(self):
        return f"CPUStack({self.timestamp_ns}, pid={self.pid}, tid={self.tid}, depth={len(self.stack)})"


class TraceMerger:
    """Merges GPU CUPTI traces with CPU stack traces from cudaLaunchKernel hooks"""

    def __init__(self, timestamp_tolerance_ms=10.0):
        self.gpu_kernels = []  # List of GPUKernelEvent
        self.cuda_launches = {}  # correlation_id -> CudaLaunchEvent
        self.cpu_stacks = []  # List of CPUStack from uprobe (extended folded format)
        self.merged_stacks = defaultdict(int)  # stack_string -> count
        self.timestamp_tolerance_ns = int(timestamp_tolerance_ms * 1_000_000)

    def parse_cpu_trace(self, cpu_file: str):
        """Parse CPU trace file in extended folded format from Rust profiler"""
        print(f"Parsing CPU uprobe trace (extended folded format): {cpu_file}")

        with open(cpu_file, 'r') as f:
            lines = f.readlines()

        stack_count = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extended folded format: timestamp_ns comm pid tid cpu stack1;stack2;stack3
            parts = line.split(None, 5)  # Split on whitespace, max 6 parts
            if len(parts) < 6:
                continue

            try:
                timestamp_ns = int(parts[0])
                comm = parts[1]
                pid = int(parts[2])
                tid = int(parts[3])
                cpu = int(parts[4])
                stack_str = parts[5]

                # Parse stack frames (separated by semicolons)
                stack_frames = []
                seen_cuda_launch = False
                if stack_str:
                    frames = stack_str.split(';')
                    for frame in frames:
                        frame = frame.strip()
                        if frame and frame not in ['<no-symbol>', '_start', '__libc_start_main']:
                            # Clean up cudaLaunchKernel variations - keep only first occurrence
                            if 'cudaLaunchKernel' in frame or '__device_stub__' in frame:
                                if not seen_cuda_launch:
                                    frame = 'cudaLaunchKernel'
                                    stack_frames.append(frame)
                                    seen_cuda_launch = True
                            else:
                                stack_frames.append(frame)

                if stack_frames:
                    self.cpu_stacks.append(CPUStack(
                        timestamp_ns, comm, pid, tid, cpu, stack_frames
                    ))
                    stack_count += 1

            except (ValueError, IndexError) as e:
                print(f"Warning: Failed to parse line: {line[:100]}... Error: {e}")
                continue

        print(f"Parsed {stack_count} CPU stack traces from cudaLaunchKernel hooks")

    def parse_gpu_trace(self, gpu_json_file: str):
        """Parse GPU trace JSON file and extract kernel events and launch correlations"""
        print(f"Parsing GPU CUPTI trace: {gpu_json_file}")

        with open(gpu_json_file, 'r') as f:
            data = json.load(f)

        events = data.get('traceEvents', [])
        kernel_count = 0
        launch_count = 0

        for event in events:
            name = event.get('name', '')
            category = event.get('cat', '')
            correlation_id = event.get('args', {}).get('correlationId', 0)

            # Extract cudaLaunchKernel runtime events
            if category == 'CUDA_Runtime' and 'LaunchKernel' in name:
                start_us = event.get('ts', 0)
                duration_us = event.get('dur', 0)

                if start_us > 0 and duration_us > 0 and correlation_id > 0:
                    # Keep timestamps in microseconds (native GPU format)
                    end_us = start_us + duration_us

                    self.cuda_launches[correlation_id] = CudaLaunchEvent(
                        start_us, end_us, correlation_id
                    )
                    launch_count += 1

            # Extract actual GPU kernel executions
            elif category == 'GPU_Kernel' or name.startswith('Kernel:'):
                kernel_name = name.replace('Kernel: ', '')
                start_us = event.get('ts', 0)
                duration_us = event.get('dur', 0)

                if start_us > 0 and duration_us > 0 and correlation_id > 0:
                    # Keep timestamps in microseconds (native GPU format)
                    end_us = start_us + duration_us

                    self.gpu_kernels.append(GPUKernelEvent(
                        kernel_name,
                        start_us,
                        end_us,
                        correlation_id
                    ))
                    kernel_count += 1

        # Sort by correlation ID for efficient lookup
        self.gpu_kernels.sort(key=lambda k: k.correlation_id)

        print(f"Parsed {kernel_count} GPU kernel events")
        print(f"Parsed {launch_count} cudaLaunchKernel runtime events")

    def calculate_clock_offset(self):
        """
        Calculate the offset between CPU and GPU clocks.
        CPU and GPU use different time bases, so we need to align them.

        Strategy: Use the median offset from the first few events to be robust against outliers.
        Also report drift to help diagnose correlation issues.
        """
        if not self.cpu_stacks or not self.cuda_launches:
            return 0.0

        # Sample first 100 events from each to calculate offset
        sample_size = min(100, len(self.cpu_stacks), len(self.cuda_launches))

        sorted_cpu = sorted(self.cpu_stacks[:sample_size], key=lambda x: x.timestamp_ns)
        sorted_gpu = sorted(self.cuda_launches.values(), key=lambda x: x.start_us)[:sample_size]

        offsets = []
        for cpu, gpu in zip(sorted_cpu, sorted_gpu):
            cpu_us = cpu.timestamp_ns / 1000.0
            offset = cpu_us - gpu.start_us
            offsets.append(offset)

        # Use median to be robust against outliers
        offsets.sort()
        median_offset = offsets[len(offsets) // 2]

        # Calculate drift across entire trace to warn about correlation issues
        if len(self.cpu_stacks) > 100 and len(self.cuda_launches) > 100:
            # Sample at start and end
            cpu_first = min(self.cpu_stacks, key=lambda x: x.timestamp_ns)
            cpu_last = max(self.cpu_stacks, key=lambda x: x.timestamp_ns)
            gpu_first = min(self.cuda_launches.values(), key=lambda x: x.start_us)
            gpu_last = max(self.cuda_launches.values(), key=lambda x: x.start_us)

            offset_start = cpu_first.timestamp_ns / 1000.0 - gpu_first.start_us
            offset_end = cpu_last.timestamp_ns / 1000.0 - gpu_last.start_us
            drift = offset_end - offset_start

            cpu_duration = (cpu_last.timestamp_ns - cpu_first.timestamp_ns) / 1_000_000  # ms

            print(f"Clock offset: {median_offset / 1000:.3f} ms (CPU - GPU)")
            print(f"Clock drift: {drift / 1000:.3f} ms over {cpu_duration:.1f} ms trace duration")
            if abs(drift) > 1000:  # More than 1ms drift
                print(f"WARNING: Significant clock drift detected ({drift / cpu_duration:.3f} ms/ms)")
                print(f"         This may cause timestamp correlation issues")
        else:
            print(f"Calculated clock offset: {median_offset / 1000:.3f} ms (CPU - GPU)")

        return median_offset

    def find_matching_kernel(self, cpu_stack: CPUStack) -> Optional[GPUKernelEvent]:
        """
        Find GPU kernel that matches the CPU stack trace.
        Strategy:
        1. Convert CPU nanosecond timestamp to microseconds
        2. Apply clock offset to align CPU and GPU time bases
        3. Use binary search to find cudaLaunchKernel runtime call within timestamp tolerance
        4. Use correlation ID to find actual GPU kernel execution
        """
        import bisect

        # Convert CPU timestamp from nanoseconds to microseconds
        cpu_timestamp_us = cpu_stack.timestamp_ns / 1000.0

        # Apply clock offset to align CPU and GPU timestamps
        cpu_timestamp_aligned = cpu_timestamp_us - self.clock_offset_us

        tolerance_us = self.timestamp_tolerance_ns / 1000.0

        # Binary search to find nearest GPU launch timestamp
        idx = bisect.bisect_left(self.launch_timestamps, cpu_timestamp_aligned)

        # Check surrounding launches (idx-1, idx, idx+1) for best match
        candidates = []
        for i in [idx - 1, idx, idx + 1]:
            if 0 <= i < len(self.sorted_launches):
                launch = self.sorted_launches[i]
                time_diff = abs(cpu_timestamp_aligned - launch.start_us)
                if time_diff < tolerance_us:
                    candidates.append((time_diff, launch))

        if not candidates:
            return None

        # Get launch with smallest time difference
        candidates.sort(key=lambda x: x[0])
        best_launch = candidates[0][1]

        # Find GPU kernel with matching correlation ID (using pre-built map)
        if not hasattr(self, 'corr_to_kernel'):
            self.corr_to_kernel = {k.correlation_id: k for k in self.gpu_kernels}

        return self.corr_to_kernel.get(best_launch.correlation_id)

    def merge_traces(self):
        """Correlate CPU stacks with GPU kernels using correlation IDs and timestamps"""
        print("Correlating CPU stacks with GPU kernels...")

        # Calculate clock offset between CPU and GPU timestamps
        self.clock_offset_us = self.calculate_clock_offset()

        # Pre-sort GPU launches by timestamp for efficient binary search
        self.sorted_launches = sorted(self.cuda_launches.values(), key=lambda x: x.start_us)
        self.launch_timestamps = [l.start_us for l in self.sorted_launches]

        matched_count = 0
        unmatched_count = 0

        for cpu_stack in self.cpu_stacks:
            # Find matching GPU kernel
            gpu_kernel = self.find_matching_kernel(cpu_stack)

            # Build merged stack
            merged_stack = cpu_stack.stack.copy()

            if gpu_kernel:
                # Add GPU kernel to the top of the stack
                merged_stack.append(f"[GPU_Kernel]{gpu_kernel.name}")
                matched_count += 1

                # Create folded stack string - only add matched stacks
                stack_str = ';'.join(merged_stack)
                self.merged_stacks[stack_str] += 1
            else:
                # Skip unmatched launches - don't add to merged output
                unmatched_count += 1

        print(f"Matched {matched_count} CPU stacks with GPU kernels")
        if unmatched_count > 0:
            print(f"WARNING: {unmatched_count} CPU stacks could not be correlated with GPU kernels")
            print(f"         This may indicate profiler timing mismatch or clock drift")
        print(f"Total unique stacks: {len(self.merged_stacks)}")

    def write_folded_output(self, output_file: str):
        """Write folded stack format for flamegraph generation"""
        print(f"Writing folded output to: {output_file}")

        with open(output_file, 'w') as f:
            for stack, count in sorted(self.merged_stacks.items()):
                # Folded format: stack_frame1;stack_frame2;... count
                f.write(f"{stack} {count}\n")

        total_samples = sum(self.merged_stacks.values())
        print(f"Wrote {len(self.merged_stacks)} unique stacks ({total_samples} total samples)")

    def generate_summary(self):
        """Generate summary statistics"""
        print("\n=== Summary Statistics ===")

        # CPU statistics
        if self.cpu_stacks:
            cpu_start = min(s.timestamp_ns for s in self.cpu_stacks)
            cpu_end = max(s.timestamp_ns for s in self.cpu_stacks)
            cpu_duration_ms = (cpu_end - cpu_start) / 1_000_000
            print(f"CPU trace duration: {cpu_duration_ms:.2f} ms")
            print(f"CPU stacks captured: {len(self.cpu_stacks)}")

        # GPU statistics
        if self.gpu_kernels:
            print(f"\nGPU kernels executed: {len(self.gpu_kernels)}")
            print(f"CUDA launch events: {len(self.cuda_launches)}")

            total_kernel_time = sum(k.end_us - k.start_us for k in self.gpu_kernels) / 1_000
            print(f"Total kernel execution time: {total_kernel_time:.2f} ms")

            # Show kernel breakdown
            kernel_names = defaultdict(int)
            for k in self.gpu_kernels:
                kernel_names[k.name] += 1

            print("\nKernel execution counts:")
            for name, count in sorted(kernel_names.items(), key=lambda x: -x[1]):
                print(f"  {name}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description='Merge GPU CUPTI traces with CPU cudaLaunchKernel stack traces'
    )
    parser.add_argument(
        '-c', '--cpu',
        default='cpu_results.txt',
        help='CPU uprobe trace file (extended folded format, default: cpu_results.txt)'
    )
    parser.add_argument(
        '-g', '--gpu',
        default='gpu_results.json',
        help='GPU CUPTI trace JSON file (default: gpu_results.json)'
    )
    parser.add_argument(
        '-o', '--output',
        default='merged_trace.folded',
        help='Output folded stack file (default: merged_trace.folded)'
    )
    parser.add_argument(
        '-t', '--tolerance',
        type=float,
        default=10.0,
        help='Timestamp matching tolerance in milliseconds (default: 10.0)'
    )
    parser.add_argument(
        '-s', '--summary',
        action='store_true',
        help='Print summary statistics'
    )

    args = parser.parse_args()

    # Check input files exist
    if not Path(args.cpu).exists():
        print(f"Error: CPU trace file not found: {args.cpu}", file=sys.stderr)
        sys.exit(1)

    if not Path(args.gpu).exists():
        print(f"Error: GPU trace file not found: {args.gpu}", file=sys.stderr)
        sys.exit(1)

    # Create merger and process traces
    merger = TraceMerger(timestamp_tolerance_ms=args.tolerance)

    # Parse inputs
    merger.parse_cpu_trace(args.cpu)
    merger.parse_gpu_trace(args.gpu)

    # Merge traces
    merger.merge_traces()

    # Write output
    merger.write_folded_output(args.output)

    # Print summary if requested
    if args.summary:
        merger.generate_summary()

    print(f"\nTo generate flamegraph:")
    print(f"  flamegraph.pl {args.output} > merged_flamegraph.svg")
    print(f"\nOr use online viewer:")
    print(f"  https://www.speedscope.app/ (upload {args.output})")


if __name__ == '__main__':
    main()
