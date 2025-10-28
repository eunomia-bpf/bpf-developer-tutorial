#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import tempfile
import atexit
import time
import json
from pathlib import Path
from cupti_trace_parser import CuptiTraceParser
from merge_gpu_cpu_trace import TraceMerger

class GPUPerf:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.injection_lib = self.script_dir / "cupti_trace/libcupti_trace_injection.so"
        self.output_file = None
        self.temp_trace_file = None
        self.profiler_proc = None
        self.profiler_output = None
        self.parser = CuptiTraceParser()  # Initialize the parser
        
        # Path to CPU profiler
        script_dir = Path(__file__).parent.resolve()
        self.cpu_profiler = script_dir / "profiler/target/release/profile"
        if not self.cpu_profiler.exists():
            print(f"Warning: CPU profiler not found at {self.cpu_profiler}", file=sys.stderr)
            self.cpu_profiler = None
        
        # Find CUPTI library path
        cuda_paths = [
            "/usr/local/cuda-13.0/extras/CUPTI/lib64",
            "/usr/local/cuda/extras/CUPTI/lib64",
            "/usr/local/cuda-12.0/extras/CUPTI/lib64",
        ]
        
        self.cupti_lib = None
        for path in cuda_paths:
            cupti_path = Path(path) / "libcupti.so"
            if cupti_path.exists():
                self.cupti_lib = str(cupti_path)
                self.cupti_lib_dir = str(Path(path))
                break
                
        if not self.cupti_lib:
            print("Warning: Could not find CUPTI library. NVTX annotations may not work.", file=sys.stderr)
    
    def parse_cupti_trace(self, filename):
        """Parse CUPTI trace data using the parser module"""
        return self.parser.parse_file(filename)
    
    def start_cpu_profiler(self, pid=None, cpu_output_file=None, cuda_lib_path=None):
        """Start CPU profiler with cudaLaunchKernel uprobe"""
        if not self.cpu_profiler:
            return None

        if not cpu_output_file:
            cpu_output_file = f"cpu_profile_{pid if pid else 'cuda'}.txt"

        # Convert to absolute path to handle working directory changes
        self.profiler_output = str(Path(cpu_output_file).absolute())

        # Find CUDA runtime library if not specified
        if not cuda_lib_path:
            cuda_paths = [
                "/usr/local/cuda-12.9/lib64/libcudart.so.12",
                "/usr/local/cuda-13.0/lib64/libcudart.so.12",
                "/usr/local/cuda/lib64/libcudart.so.12",
                "/usr/local/cuda-12.8/lib64/libcudart.so.12",
            ]
            for path in cuda_paths:
                if Path(path).exists():
                    cuda_lib_path = path
                    break

        if not cuda_lib_path:
            print("Warning: Could not find CUDA runtime library for uprobe", file=sys.stderr)
            return None

        print(f"Starting CPU profiler with cudaLaunchKernel hook")
        print(f"  CUDA library: {cuda_lib_path}")
        print(f"  Output: {cpu_output_file}")

        try:
            # Run profiler with cudaLaunchKernel uprobe in extended folded format
            # Format: timestamp_ns comm pid tid cpu stack1;stack2;stack3
            cmd = ["sudo", str(self.cpu_profiler),
                   "--uprobe", f"{cuda_lib_path}:cudaLaunchKernel",
                   "-E"]  # -E for extended folded format with timestamps

            self.profiler_proc = subprocess.Popen(
                cmd,
                stdout=open(cpu_output_file, 'w'),
                stderr=subprocess.PIPE
            )
            # Give it a moment to attach
            time.sleep(1.0)
            return self.profiler_proc
        except Exception as e:
            print(f"Warning: Failed to start CPU profiler: {e}", file=sys.stderr)
            return None
    
    def stop_cpu_profiler(self):
        """Stop the CPU profiler gracefully"""
        if self.profiler_proc and self.profiler_proc.poll() is None:
            print("Stopping CPU profiler...")
            self.profiler_proc.terminate()
            try:
                self.profiler_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.profiler_proc.kill()
                self.profiler_proc.wait()
            
            if self.profiler_output and os.path.exists(self.profiler_output):
                print(f"CPU profile saved to: {self.profiler_output}")
    
    def run_with_trace(self, command, output_trace=None, chrome_trace=None, cpu_profile=None, merged_trace=None, no_merge=False):
        """Run a command with CUPTI tracing and optional CPU profiling enabled"""
        
        # Determine if we're doing GPU profiling
        do_gpu_profiling = output_trace is not None or chrome_trace is not None
        
        # Check if injection library exists (only if we're doing GPU profiling)
        if do_gpu_profiling and not self.injection_lib.exists():
            print(f"Error: CUPTI injection library not found at {self.injection_lib}", file=sys.stderr)
            print("Please build it first using 'make' in the cupti_trace directory", file=sys.stderr)
            return 1
        
        # Set up trace output file for GPU profiling
        trace_file = None
        if do_gpu_profiling:
            if output_trace:
                # Convert to absolute path to handle target process changing directories
                trace_file = str(Path(output_trace).absolute())
            else:
                # Create temporary file for trace output
                fd, trace_file = tempfile.mkstemp(suffix=".txt", prefix="gpuperf_trace_")
                os.close(fd)
                self.temp_trace_file = trace_file
                atexit.register(self.cleanup_temp_files)

        # Set up environment variables
        env = os.environ.copy()
        env['CUDA_INJECTION64_PATH'] = str(self.injection_lib)
        env['CUPTI_TRACE_OUTPUT_FILE'] = trace_file
        
        if self.cupti_lib:
            env['NVTX_INJECTION64_PATH'] = self.cupti_lib
            if 'LD_LIBRARY_PATH' in env:
                env['LD_LIBRARY_PATH'] = f"{self.cupti_lib_dir}:{env['LD_LIBRARY_PATH']}"
            else:
                env['LD_LIBRARY_PATH'] = self.cupti_lib_dir
        
        print(f"Running command with GPU profiling: {' '.join(command)}")
        print(f"Trace output: {trace_file}")
        
        # Start the target process
        target_proc = None

        try:
            # Start CPU profiler FIRST if available and requested
            if cpu_profile and self.cpu_profiler:
                # Start profiler BEFORE target process to catch all kernel launches
                self.start_cpu_profiler(cpu_output_file=cpu_profile)

            # Then start the target process
            target_proc = subprocess.Popen(command, env=env)
            target_pid = target_proc.pid
            print(f"Started target process with PID: {target_pid}")
            
            # Wait for the target process to complete
            return_code = target_proc.wait()
            
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            if target_proc:
                target_proc.terminate()
                try:
                    target_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    target_proc.kill()
            return_code = 130
        except Exception as e:
            print(f"Error running command: {e}", file=sys.stderr)
            return_code = 1
        finally:
            # Give CUPTI time to flush remaining buffered events
            # CUPTI may continue recording events after target exits
            time.sleep(0.5)

            # Stop CPU profiler if running
            self.stop_cpu_profiler()
        
        # Convert to Chrome trace if requested
        if chrome_trace and os.path.exists(trace_file):
            print(f"\nConverting trace to Chrome format: {chrome_trace}")
            try:
                events = self.parse_cupti_trace(trace_file)
                print(f"Parsed {len(events)} events")
                
                metadata = {
                    "tool": "gpuperf - GPU Performance Profiler",
                    "format": "Chrome Trace Format",
                    "command": ' '.join(command)
                }
                
                self.parser.save_chrome_trace(events, chrome_trace, metadata)
                
                print(f"\nChrome trace file written to: {chrome_trace}")
                print("\nTo visualize the trace:")
                print("1. Open Chrome or Edge browser")
                print("2. Navigate to chrome://tracing or edge://tracing")
                print("3. Click 'Load' and select the generated JSON file")
                print("\nAlternatively, visit https://ui.perfetto.dev/ and drag the JSON file there")
            except Exception as e:
                print(f"Error converting trace: {e}", file=sys.stderr)
        
        # Clean up temporary file if not keeping raw trace
        if not output_trace and self.temp_trace_file:
            try:
                os.unlink(self.temp_trace_file)
            except:
                pass
        
        # Generate merged folded trace if both CPU and GPU traces are available (and not disabled)
        if not no_merge and cpu_profile and (chrome_trace or output_trace):
            merged_output = merged_trace if merged_trace else "merged_trace.folded"
            self.generate_merged_trace(
                cpu_trace=cpu_profile,
                gpu_trace=chrome_trace if chrome_trace else None,
                gpu_raw_trace=trace_file if do_gpu_profiling else None,
                output_file=merged_output
            )
        
        return return_code
    
    def generate_merged_trace(self, cpu_trace=None, gpu_trace=None, gpu_raw_trace=None, output_file=None):
        """Generate merged CPU+GPU folded trace using TraceMerger"""
        if not cpu_trace or not (gpu_trace or gpu_raw_trace):
            return  # Need both CPU and GPU traces
        
        if not output_file:
            output_file = "merged_trace.folded"
        
        print(f"\nGenerating merged CPU+GPU trace: {output_file}")
        
        try:
            merger = TraceMerger()
            
            # Parse CPU trace
            if os.path.exists(cpu_trace):
                merger.parse_cpu_trace(cpu_trace)
            else:
                print(f"Warning: CPU trace not found: {cpu_trace}")
                return
            
            # Parse GPU trace (prefer JSON, fallback to raw)
            if gpu_trace and os.path.exists(gpu_trace):
                merger.parse_gpu_trace(gpu_trace)
            elif gpu_raw_trace and os.path.exists(gpu_raw_trace):
                # Convert raw trace to events first
                events = self.parse_cupti_trace(gpu_raw_trace)
                # Create temporary JSON for merger
                import json
                temp_json = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                json.dump({"traceEvents": events}, temp_json)
                temp_json.close()
                merger.parse_gpu_trace(temp_json.name)
                os.unlink(temp_json.name)
            else:
                print(f"Warning: GPU trace not found")
                return
            
            # Merge traces
            merger.merge_traces()
            
            # Write folded output
            merger.write_folded_output(output_file)
            
            print(f"✓ Merged trace generated: {output_file}")
            print(f"\nTo generate flamegraph:")
            print(f"  /root/yunwei37/systemscope/cpu-tools/combined_flamegraph.pl {output_file} > merged_flamegraph.svg")
            
        except Exception as e:
            print(f"Error generating merged trace: {e}", file=sys.stderr)
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        if self.temp_trace_file and os.path.exists(self.temp_trace_file):
            try:
                os.unlink(self.temp_trace_file)
            except:
                pass
    
    def convert_trace(self, input_file, output_file):
        """Convert existing CUPTI trace to Chrome format"""
        
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' not found", file=sys.stderr)
            return 1
        
        print(f"Converting CUPTI trace to Chrome format...")
        print(f"Input: {input_file}")
        print(f"Output: {output_file}")
        
        try:
            events = self.parse_cupti_trace(input_file)
            print(f"Parsed {len(events)} events")
            
            metadata = {
                "tool": "gpuperf - GPU Performance Profiler",
                "format": "Chrome Trace Format"
            }
            
            self.parser.save_chrome_trace(events, output_file, metadata)
            
            print(f"\nChrome trace file written to: {output_file}")
            print("\nTo visualize the trace:")
            print("1. Open Chrome or Edge browser")
            print("2. Navigate to chrome://tracing or edge://tracing")
            print("3. Click 'Load' and select the generated JSON file")
            print("\nAlternatively, visit https://ui.perfetto.dev/ and drag the JSON file there")
            
            return 0
        except Exception as e:
            print(f"Error converting trace: {e}", file=sys.stderr)
            return 1

def main():
    # Check if first argument is 'convert' for conversion mode
    if len(sys.argv) > 1 and sys.argv[1] == 'convert':
        parser = argparse.ArgumentParser(
            prog='gpuperf convert',
            description='Convert existing CUPTI trace to Chrome format'
        )
        parser.add_argument('mode', help='Operation mode')  # This will be 'convert'
        parser.add_argument('-i', '--input', required=True, help='Input CUPTI trace file')
        parser.add_argument('-o', '--output', default='trace.json', help='Output Chrome trace JSON file')
        args = parser.parse_args()
        
        profiler = GPUPerf()
        return profiler.convert_trace(args.input, args.output)
    
    # Regular run mode
    parser = argparse.ArgumentParser(
        description='gpuperf - GPU and CPU Performance Profiler',
        usage='gpuperf [options] command [args...]\n       gpuperf convert -i input.txt -o output.json'
    )
    
    parser.add_argument('-o', '--output', help='Save raw CUPTI trace to file (default: gpu_results.txt)')
    parser.add_argument('-c', '--chrome', help='Convert trace to Chrome format and save to file (default: gpu_results.json)')
    parser.add_argument('-p', '--cpu-profile', help='Also capture CPU profile and save to file (default: cpu_results.txt)')
    parser.add_argument('-m', '--merged', help='Save merged CPU+GPU folded trace (default: merged_trace.folded)')
    parser.add_argument('--cpu-only', action='store_true', help='Only run CPU profiler without GPU tracing')
    parser.add_argument('--no-gpu', action='store_true', help='Disable GPU profiling')
    parser.add_argument('--no-cpu', action='store_true', help='Disable CPU profiling')
    parser.add_argument('--no-merge', action='store_true', help='Disable automatic merged trace generation')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='Command to run with profiling')
    
    args = parser.parse_args()
    
    profiler = GPUPerf()
    
    # Handle run mode
    if not args.command:
        parser.print_help()
        return 1
    
    # Use the command directly from REMAINDER
    full_command = args.command
    
    # CPU-only mode
    if args.cpu_only:
        if not profiler.cpu_profiler:
            print("Error: CPU profiler not available", file=sys.stderr)
            return 1
        
        # Start the process and immediately profile it
        try:
            target_proc = subprocess.Popen(full_command)
            target_pid = target_proc.pid
            print(f"Started target process with PID: {target_pid}")
            
            cpu_output = args.cpu_profile or "cpu_results.txt"
            profiler.start_cpu_profiler(target_pid, cpu_output)
            
            return_code = target_proc.wait()
            profiler.stop_cpu_profiler()
            return return_code
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    # Set up default values
    gpu_output = args.output if args.output else ("gpu_results.txt" if not args.no_gpu else None)
    chrome_output = args.chrome if args.chrome else ("gpu_results.json" if not args.no_gpu else None)
    cpu_output = args.cpu_profile if args.cpu_profile else ("cpu_results.txt" if not args.no_cpu else None)
    
    # If user explicitly disabled GPU, don't run GPU profiling
    if args.no_gpu:
        gpu_output = None
        chrome_output = None
    
    # If user explicitly disabled CPU, don't run CPU profiling  
    if args.no_cpu:
        cpu_output = None
    
    # Combined GPU and CPU profiling (or just one based on flags)
    return profiler.run_with_trace(
        full_command, 
        output_trace=gpu_output, 
        chrome_trace=chrome_output,
        cpu_profile=cpu_output,
        merged_trace=args.merged,
        no_merge=args.no_merge
    )

if __name__ == '__main__':
    sys.exit(main())