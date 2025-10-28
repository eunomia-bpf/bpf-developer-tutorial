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
    """Represents a GPU kernel execution event"""
    def __init__(self, name: str, start_ns: int, end_ns: int, correlation_id: int):
        self.name = name
        self.start_ns = start_ns
        self.end_ns = end_ns
        self.correlation_id = correlation_id

    def __repr__(self):
        return f"GPUKernel({self.name}, {self.start_ns}-{self.end_ns}, corr={self.correlation_id})"


class CudaLaunchEvent:
    """Represents a cudaLaunchKernel runtime API call"""
    def __init__(self, start_ns: int, end_ns: int, correlation_id: int):
        self.start_ns = start_ns
        self.end_ns = end_ns
        self.correlation_id = correlation_id

    def __repr__(self):
        return f"CudaLaunch({self.start_ns}-{self.end_ns}, corr={self.correlation_id})"


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
                    start_ns = int(start_us * 1000)
                    end_ns = int((start_us + duration_us) * 1000)

                    self.cuda_launches[correlation_id] = CudaLaunchEvent(
                        start_ns, end_ns, correlation_id
                    )
                    launch_count += 1

            # Extract actual GPU kernel executions
            elif category == 'GPU_Kernel' or name.startswith('Kernel:'):
                kernel_name = name.replace('Kernel: ', '')
                start_us = event.get('ts', 0)
                duration_us = event.get('dur', 0)

                if start_us > 0 and duration_us > 0 and correlation_id > 0:
                    start_ns = int(start_us * 1000)
                    end_ns = int((start_us + duration_us) * 1000)

                    self.gpu_kernels.append(GPUKernelEvent(
                        kernel_name,
                        start_ns,
                        end_ns,
                        correlation_id
                    ))
                    kernel_count += 1

        # Sort by correlation ID for efficient lookup
        self.gpu_kernels.sort(key=lambda k: k.correlation_id)

        print(f"Parsed {kernel_count} GPU kernel events")
        print(f"Parsed {launch_count} cudaLaunchKernel runtime events")

    def find_matching_kernel(self, cpu_stack: CPUStack) -> Optional[GPUKernelEvent]:
        """
        Find GPU kernel that matches the CPU stack trace.
        Strategy:
        1. Find cudaLaunchKernel runtime call within timestamp tolerance
        2. Use correlation ID to find actual GPU kernel execution
        """

        # Find cudaLaunchKernel runtime event that matches timestamp
        best_launch = None
        min_time_diff = self.timestamp_tolerance_ns

        for launch in self.cuda_launches.values():
            # Check if CPU stack timestamp is close to launch time
            time_diff = abs(cpu_stack.timestamp_ns - launch.start_ns)

            if time_diff < min_time_diff:
                min_time_diff = time_diff
                best_launch = launch

        if not best_launch:
            return None

        # Find GPU kernel with matching correlation ID
        for kernel in self.gpu_kernels:
            if kernel.correlation_id == best_launch.correlation_id:
                return kernel

        return None

    def merge_traces(self):
        """Correlate CPU stacks with GPU kernels using correlation IDs and timestamps"""
        print("Correlating CPU stacks with GPU kernels...")

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
            else:
                # Mark as unmatched launch (may happen if kernel hasn't executed yet)
                merged_stack.append("[GPU_Launch_Pending]")
                unmatched_count += 1

            # Create folded stack string
            if merged_stack:
                stack_str = ';'.join(merged_stack)
                self.merged_stacks[stack_str] += 1

        print(f"Matched {matched_count} CPU stacks with GPU kernels")
        print(f"Unmatched: {unmatched_count}")
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

            total_kernel_time = sum(k.end_ns - k.start_ns for k in self.gpu_kernels) / 1_000_000
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
