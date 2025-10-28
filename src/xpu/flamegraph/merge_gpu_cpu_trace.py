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
    def __init__(self, start_us: float, end_us: float, correlation_id: int, pid: int = 0, tid: int = 0):
        self.start_us = start_us  # Keep in microseconds (native GPU format)
        self.end_us = end_us
        self.correlation_id = correlation_id
        self.pid = pid
        self.tid = tid

    def __repr__(self):
        return f"CudaLaunch({self.start_us}-{self.end_us} us, corr={self.correlation_id}, pid={self.pid}, tid={self.tid})"


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
        self.cpu_stacks_by_thread = defaultdict(list)  # (pid, tid) -> List[CPUStack]
        self.merged_stacks = defaultdict(int)  # stack_string -> count
        self.timestamp_tolerance_ns = int(timestamp_tolerance_ms * 1_000_000)

    def parse_cpu_trace(self, cpu_file: str):
        """Parse CPU trace file in extended folded format from Rust profiler"""
        print(f"Parsing CPU uprobe trace (extended folded format): {cpu_file}")

        with open(cpu_file, 'r') as f:
            lines = f.readlines()

        # ANSI escape sequence pattern
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        stack_count = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Remove ANSI color codes if present
            line = ansi_escape.sub('', line)

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
                            # Keep __device_stub__ as it shows which kernel is launched
                            # Only collapse the final cudaLaunchKernel wrapper
                            if 'cudaLaunchKernel' in frame and '__device_stub__' not in frame:
                                if not seen_cuda_launch:
                                    frame = 'cudaLaunchKernel'
                                    stack_frames.append(frame)
                                    seen_cuda_launch = True
                            else:
                                stack_frames.append(frame)

                if stack_frames:
                    cpu_stack = CPUStack(timestamp_ns, comm, pid, tid, cpu, stack_frames)
                    self.cpu_stacks.append(cpu_stack)
                    # Also index by thread for per-thread matching
                    self.cpu_stacks_by_thread[(pid, tid)].append(cpu_stack)
                    stack_count += 1

            except (ValueError, IndexError) as e:
                print(f"Warning: Failed to parse line: {line[:100]}... Error: {e}")
                continue

        print(f"Parsed {stack_count} CPU stack traces from cudaLaunchKernel hooks")
        print(f"Found {len(self.cpu_stacks_by_thread)} unique threads")

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
            # Extract PID/TID from Chrome trace format
            pid = event.get('pid', 0)
            tid = event.get('tid', 0)

            # Extract cudaLaunchKernel runtime events
            if category == 'CUDA_Runtime' and 'LaunchKernel' in name:
                start_us = event.get('ts', 0)
                duration_us = event.get('dur', 0)

                if start_us > 0 and duration_us > 0 and correlation_id > 0:
                    # Keep timestamps in microseconds (native GPU format)
                    end_us = start_us + duration_us

                    self.cuda_launches[correlation_id] = CudaLaunchEvent(
                        start_us, end_us, correlation_id, pid, tid
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


    def merge_traces(self):
        """Correlate CPU stacks with GPU kernels using optimal matching strategy"""
        print("Correlating CPU stacks with GPU kernels...")

        # Sort CPU stacks by thread and timestamp
        for thread_id in self.cpu_stacks_by_thread:
            self.cpu_stacks_by_thread[thread_id].sort(key=lambda x: x.timestamp_ns)

        # Group GPU launches by PID only (TID from CUPTI may not match Linux TID)
        launches_by_thread = defaultdict(list)
        for launch in self.cuda_launches.values():
            try:
                pid = int(launch.pid) if launch.pid else 0
                if pid > 0:
                    for thread_id in self.cpu_stacks_by_thread.keys():
                        if thread_id[0] == pid:  # Match by PID
                            launches_by_thread[thread_id].append(launch)
                            break
            except (ValueError, TypeError):
                continue

        # Sort GPU launches by timestamp
        for thread_id in launches_by_thread:
            launches_by_thread[thread_id].sort(key=lambda x: x.start_us)

        # Build correlation ID to kernel mapping once
        self.corr_to_kernel = {k.correlation_id: k for k in self.gpu_kernels}

        matched_count = 0
        unmatched_count = 0

        # Process each thread
        for thread_id, cpu_stacks in self.cpu_stacks_by_thread.items():
            gpu_launches = launches_by_thread.get(thread_id, [])
            if not gpu_launches:
                unmatched_count += len(cpu_stacks)
                continue

            # Check if counts match for sequential matching
            if len(cpu_stacks) == len(gpu_launches):
                print(f"  Thread {thread_id}: Using sequential matching ({len(cpu_stacks)} events)")
                # Perfect 1:1 correspondence - use simple index matching
                for i, cpu_stack in enumerate(cpu_stacks):
                    gpu_kernel = self.corr_to_kernel.get(gpu_launches[i].correlation_id)
                    if gpu_kernel:
                        merged_stack = cpu_stack.stack.copy()
                        merged_stack.append(f"[GPU_Kernel]{gpu_kernel.name}")
                        stack_str = ';'.join(merged_stack)
                        kernel_duration_us = int(gpu_kernel.end_us - gpu_kernel.start_us)
                        self.merged_stacks[stack_str] += kernel_duration_us
                        matched_count += 1
                    else:
                        unmatched_count += 1
            else:
                # More GPU events than CPU - use sequential with time window validation
                print(f"  Thread {thread_id}: Using sequential+time matching (CPU={len(cpu_stacks)}, GPU={len(gpu_launches)})")

                # Estimate clock offset from first events
                if cpu_stacks and gpu_launches:
                    cpu_first_us = cpu_stacks[0].timestamp_ns / 1000.0
                    gpu_first_us = gpu_launches[0].start_us
                    clock_offset_us = gpu_first_us - cpu_first_us
                    print(f"    Estimated clock offset: {clock_offset_us/1000:.2f} ms")
                else:
                    clock_offset_us = 0

                # Tolerance window (default 10ms)
                tolerance_us = self.timestamp_tolerance_ns / 1000.0

                gpu_idx = 0
                skipped_cpu = 0
                skipped_gpu = 0

                for cpu_stack in cpu_stacks:
                    cpu_ts_us = (cpu_stack.timestamp_ns / 1000.0) + clock_offset_us

                    # Skip GPU events that are too far behind CPU
                    while gpu_idx < len(gpu_launches):
                        gpu_ts_us = gpu_launches[gpu_idx].start_us
                        time_diff = cpu_ts_us - gpu_ts_us

                        if time_diff > tolerance_us:
                            # GPU event is too old, skip it
                            gpu_idx += 1
                            skipped_gpu += 1
                        else:
                            break

                    # Check if GPU exhausted
                    if gpu_idx >= len(gpu_launches):
                        unmatched_count += 1
                        skipped_cpu += 1
                        continue

                    # Check if current GPU is within window
                    gpu_ts_us = gpu_launches[gpu_idx].start_us
                    time_diff = abs(cpu_ts_us - gpu_ts_us)

                    if time_diff <= tolerance_us:
                        # Within window - match!
                        gpu_kernel = self.corr_to_kernel.get(gpu_launches[gpu_idx].correlation_id)

                        if gpu_kernel:
                            merged_stack = cpu_stack.stack.copy()
                            merged_stack.append(f"[GPU_Kernel]{gpu_kernel.name}")
                            stack_str = ';'.join(merged_stack)
                            kernel_duration_us = int(gpu_kernel.end_us - gpu_kernel.start_us)
                            self.merged_stacks[stack_str] += kernel_duration_us
                            matched_count += 1
                            gpu_idx += 1
                        else:
                            unmatched_count += 1
                    else:
                        # CPU is too far ahead - skip this CPU sample
                        unmatched_count += 1
                        skipped_cpu += 1

                if skipped_cpu > 0 or skipped_gpu > 0:
                    print(f"    Skipped: {skipped_cpu} CPU events, {skipped_gpu} GPU events (outside time window)")

        print(f"Matched {matched_count} CPU stacks with GPU kernels")
        if unmatched_count > 0:
            print(f"Unmatched: {unmatched_count} CPU stacks (may indicate missing GPU events)")
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
