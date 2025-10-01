#!/usr/bin/env python3
"""
Combined On-CPU and Off-CPU Profiler

This script runs both 'oncputime' and 'offcputime' tools simultaneously to capture
both on-CPU and off-CPU activity for a given process, then combines the results
into a unified flamegraph.

Usage:
    python3 combined_profiler.py <PID> [OPTIONS]
"""

import argparse
import subprocess
import sys
import os
import threading
import time
import tempfile
from pathlib import Path
from collections import defaultdict

class CombinedProfiler:
    def __init__(self, pid, duration=30, freq=49, min_block_us=1000):
        self.pid = pid
        self.duration = duration
        self.freq = freq
        self.min_block_us = min_block_us
        self.profile_output = []
        self.offcpu_output = []
        self.profile_error = None
        self.offcpu_error = None
        
        # Find tool paths
        self.script_dir = Path(__file__).parent
        self.oncpu_tool = self.script_dir / "oncputime"
        self.offcpu_tool = self.script_dir / "offcputime"
        
        # Check if tools exist
        if not self.oncpu_tool.exists():
            raise FileNotFoundError(f"Oncputime tool not found at {self.oncpu_tool}")
        if not self.offcpu_tool.exists():
            raise FileNotFoundError(f"Offcputime tool not found at {self.offcpu_tool}")

    def discover_threads(self):
        """Discover threads and determine if multi-threaded"""
        try:
            result = subprocess.run(
                ["ps", "-T", "-p", str(self.pid)], 
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return False, []
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            threads = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    pid, tid, tty, time_str, *cmd_parts = parts
                    tid = int(tid)
                    cmd = ' '.join(cmd_parts)
                    threads.append((tid, cmd))
            
            return len(threads) > 1, threads
            
        except Exception:
            return False, []

    def run_oncpu_tool(self):
        """Run the oncputime tool in a separate thread"""
        try:
            cmd = [
                str(self.oncpu_tool),
                # "./profiler oncputime",
                "-p", str(self.pid),
                "-F", str(self.freq),
                "-f",  # Folded output format
                str(self.duration)
            ]
            
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.duration + 10)
            
            if result.returncode != 0:
                self.profile_error = f"Oncputime tool failed: {result.stderr}"
                return
                
            self.profile_output = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
        except subprocess.TimeoutExpired:
            self.profile_error = "Oncputime tool timed out"
        except Exception as e:
            self.profile_error = f"Oncputime tool error: {str(e)}"

    def run_offcpu_tool(self):
        """Run the offcputime tool in a separate thread"""
        try:
            cmd = [
                str(self.offcpu_tool),
                # "./profiler offcputime",
                "-p", str(self.pid),
                "-m", str(self.min_block_us),
                "-f",  # Folded output format
                str(self.duration)
            ]
            
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.duration + 10)
            
            if result.returncode != 0:
                self.offcpu_error = f"Offcputime tool failed: {result.stderr}"
                return
                
            self.offcpu_output = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
        except subprocess.TimeoutExpired:
            self.offcpu_error = "Offcputime tool timed out"
        except Exception as e:
            self.offcpu_error = f"Offcputime tool error: {str(e)}"

    def run_profiling(self):
        """Run both profiling tools simultaneously"""
        # Check if multi-threaded first
        is_multithread, threads = self.discover_threads()
        
        if is_multithread:
            print(f"Multi-threaded application detected ({len(threads)} threads)")
            print(f"Profiling each thread separately...")
            self.profile_individual_threads(threads)
        else:
            print(f"Starting combined profiling for PID {self.pid} for {self.duration} seconds...")
            
            # Create threads for both tools
            oncpu_thread = threading.Thread(target=self.run_oncpu_tool)
            offcpu_thread = threading.Thread(target=self.run_offcpu_tool)
            
            # Start both threads
            oncpu_thread.start()
            offcpu_thread.start()
            
            # Wait for both to complete
            oncpu_thread.join()
            offcpu_thread.join()
            
            # Check for errors
            if self.profile_error:
                print(f"Oncpu tool error: {self.profile_error}", file=sys.stderr)
            if self.offcpu_error:
                print(f"Offcpu tool error: {self.offcpu_error}", file=sys.stderr)
                
            if self.profile_error and self.offcpu_error:
                raise RuntimeError("Both profiling tools failed")

    def profile_individual_threads(self, threads):
        """Profile each thread individually but simultaneously"""
        self.thread_results = {}
        
        print(f"Starting simultaneous profiling of all {len(threads)} threads for {self.duration} seconds...")
        
        # Create profiling threads for parallel execution
        profiling_threads = []
        thread_data = {}
        
        for tid, cmd in threads:
            # Initialize result storage
            thread_data[tid] = {
                'cmd': cmd,
                'oncpu_data': [],
                'offcpu_data': [],
                'oncpu_error': None,
                'offcpu_error': None
            }
            
            # Create on-CPU profiling thread
            oncpu_thread = threading.Thread(
                target=self._profile_thread_oncpu_worker,
                args=(tid, thread_data[tid])
            )
            profiling_threads.append(oncpu_thread)
            
            # Create off-CPU profiling thread  
            offcpu_thread = threading.Thread(
                target=self._profile_thread_offcpu_worker,
                args=(tid, thread_data[tid])
            )
            profiling_threads.append(offcpu_thread)
        
        # Start all profiling threads simultaneously
        start_time = time.time()
        for thread in profiling_threads:
            thread.start()
        
        # Wait for all to complete
        for thread in profiling_threads:
            thread.join()
        
        end_time = time.time()
        actual_duration = end_time - start_time
        print(f"Profiling completed in {actual_duration:.1f} seconds")
        
        # Store results
        self.thread_results = thread_data
        
        # Report any errors
        for tid, data in thread_data.items():
            if data['oncpu_error']:
                print(f"On-CPU profiling error for thread {tid}: {data['oncpu_error']}")
            if data['offcpu_error']:
                print(f"Off-CPU profiling error for thread {tid}: {data['offcpu_error']}")

    def _profile_thread_oncpu_worker(self, tid, thread_data):
        """Worker function for on-CPU profiling of a specific thread"""
        try:
            cmd = [
                str(self.oncpu_tool),
                "-L", str(tid),  # Specific thread
                "-F", str(self.freq),
                "-f",  # Folded output
                str(self.duration)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.duration + 10)
            
            if result.returncode == 0 and result.stdout.strip():
                thread_data['oncpu_data'] = result.stdout.strip().split('\n')
            else:
                thread_data['oncpu_data'] = []
                if result.stderr:
                    thread_data['oncpu_error'] = result.stderr
                
        except Exception as e:
            thread_data['oncpu_error'] = str(e)
            thread_data['oncpu_data'] = []

    def _profile_thread_offcpu_worker(self, tid, thread_data):
        """Worker function for off-CPU profiling of a specific thread"""
        try:
            cmd = [
                str(self.offcpu_tool),
                "-t", str(tid),  # Specific thread
                "-m", str(self.min_block_us),
                "-f",  # Folded output
                str(self.duration)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.duration + 10)
            
            if result.returncode == 0 and result.stdout.strip():
                thread_data['offcpu_data'] = result.stdout.strip().split('\n')
            else:
                thread_data['offcpu_data'] = []
                if result.stderr:
                    thread_data['offcpu_error'] = result.stderr
                
        except Exception as e:
            thread_data['offcpu_error'] = str(e)
            thread_data['offcpu_data'] = []

    def parse_folded_line(self, line):
        """Parse a folded format line into stack trace and value"""
        if not line.strip():
            return None, None
            
        parts = line.rsplit(' ', 1)
        if len(parts) != 2:
            return None, None
            
        stack_trace = parts[0]
        try:
            value = int(parts[1])
            return stack_trace, value
        except ValueError:
            return None, None

    def normalize_and_combine_stacks(self):
        """Combine and normalize stack traces from both tools"""
        oncpu_stacks = {}
        offcpu_stacks = {}
        
        # Process on-CPU data (oncputime tool)
        print(f"Processing {len(self.profile_output)} on-CPU stack traces...")
        oncpu_total_samples = 0
        for line in self.profile_output:
            stack, value = self.parse_folded_line(line)
            if stack and value:
                oncpu_total_samples += value
                # remove the first part of the stack trace and add annotation
                stack_parts = stack.split(";")[1:]
                # Add _[c] annotation for CPU-intensive (on-CPU) stacks
                annotated_stack = ";".join(stack_parts) + "_[c]"
                oncpu_stacks[annotated_stack] = oncpu_stacks.get(annotated_stack, 0) + value
        
        # Process off-CPU data (offcputime tool) 
        print(f"Processing {len(self.offcpu_output)} off-CPU stack traces...")
        offcpu_total_us = 0
        for line in self.offcpu_output:
            stack, value = self.parse_folded_line(line)
            if stack and value:
                offcpu_total_us += value
                # remove the first part of the stack trace and add annotation
                stack_parts = stack.split(";")[1:]
                # Add _[o] annotation for off-CPU (I/O/blocking) stacks
                annotated_stack = ";".join(stack_parts) + "_[o]"
                offcpu_stacks[annotated_stack] = offcpu_stacks.get(annotated_stack, 0) + value
        
        # Store counts for summary
        self.oncpu_count = len(oncpu_stacks)
        self.offcpu_count = len(offcpu_stacks)
        
        # Combine stacks with annotations
        combined_stacks = {}
        
        # Add on-CPU stacks directly
        for stack, value in oncpu_stacks.items():
            combined_stacks[stack] = combined_stacks.get(stack, 0) + value
        
        # Normalize and add off-CPU stacks
        if offcpu_total_us > 0 and oncpu_total_samples > 0:
            # Calculate normalization factor
            # Assume each on-CPU sample represents 1/freq seconds of CPU time
            avg_oncpu_sample_us = (1.0 / self.freq) * 1_000_000  # microseconds per sample
            normalization_factor = avg_oncpu_sample_us  # Use microseconds directly
            
            # Calculate expected vs actual samples
            expected_samples = self.duration * self.freq
            sample_rate = (oncpu_total_samples / expected_samples) * 100 if expected_samples > 0 else 0
            
            print(f"On-CPU: {oncpu_total_samples} samples (expected: {expected_samples}, {sample_rate:.1f}% sampled)")
            print(f"Off-CPU: {offcpu_total_us:,} μs ({offcpu_total_us/1_000_000:.2f} seconds)")
            print(f"Normalization factor: {normalization_factor:.0f} μs/sample")
            
            # Add normalized off-CPU stacks
            for stack, value in offcpu_stacks.items():
                # Convert microseconds to equivalent samples
                normalized_value = int(value / normalization_factor)
                if normalized_value > 0:  # Only include if it results in at least 1 equivalent sample
                    combined_stacks[stack] = combined_stacks.get(stack, 0) + normalized_value
        else:
            # If no normalization needed, just add off-CPU stacks as-is
            for stack, value in offcpu_stacks.items():
                combined_stacks[stack] = combined_stacks.get(stack, 0) + value
        
        return combined_stacks

    def setup_flamegraph_tools(self):
        """Ensure FlameGraph tools are available and create custom color palette"""
        flamegraph_dir = self.script_dir / "FlameGraph"
        flamegraph_script = flamegraph_dir / "flamegraph.pl"
        
        if flamegraph_script.exists():
            # Create a custom flamegraph script with our color palette
            custom_script = self.script_dir / "combined_flamegraph.pl"
            self.create_custom_flamegraph_script(flamegraph_script, custom_script)
            return custom_script
        
        print("FlameGraph tools not found, cloning repository...")
        try:
            result = subprocess.run([
                "git", "clone", 
                "https://github.com/brendangregg/FlameGraph.git",
                str(flamegraph_dir), "--depth=1"
            ], capture_output=True, text=True, cwd=self.script_dir)
            
            if result.returncode != 0:
                print(f"Failed to clone FlameGraph: {result.stderr}")
                return None
                
            if flamegraph_script.exists():
                # Make it executable
                os.chmod(flamegraph_script, 0o755)
                print("FlameGraph tools cloned successfully")
                # Create custom script
                custom_script = self.script_dir / "combined_flamegraph.pl"
                self.create_custom_flamegraph_script(flamegraph_script, custom_script)
                return custom_script
            else:
                print("FlameGraph script not found after cloning")
                return None
                
        except Exception as e:
            print(f"Error setting up FlameGraph tools: {e}")
            return None

    def create_custom_flamegraph_script(self, original_script, custom_script):
        """Create a custom flamegraph script with our color palette"""
        try:
            with open(original_script, 'r') as f:
                content = f.read()
            
            # Add our custom color palette for combined profiling
            # Insert after the existing "chain" palette logic
            custom_palette = '''
	if (defined $type and $type eq "combined") {
		if ($name =~ m:_\\[c\\]$:) {	# CPU annotation (on-CPU)
			$type = "red";
		} elsif ($name =~ m:_\\[o\\]$:) {	# off-CPU annotation (I/O/blocking)
			$type = "blue";
		} else {			# default
			$type = "yellow";
		}
		# fall-through to color palettes
	}'''
            
            # Find the insertion point after the chain palette
            insertion_point = content.find('	if (defined $type and $type eq "chain") {')
            if insertion_point != -1:
                # Find the end of the chain block
                end_point = content.find('\t# color palettes', insertion_point)
                if end_point != -1:
                    # Insert our custom palette before the color palettes section
                    content = content[:end_point] + custom_palette + '\n\n\t' + content[end_point:]
            
            with open(custom_script, 'w') as f:
                f.write(content)
            
            # Make it executable
            os.chmod(custom_script, 0o755)
            print("Custom flamegraph script created with combined color palette")
            
        except Exception as e:
            print(f"Error creating custom flamegraph script: {e}")
            # Fall back to original script
            return original_script

    def generate_flamegraph_data(self, output_prefix=None):
        """Generate combined flamegraph data and SVG"""
        # Check if multi-threaded
        is_multithread, threads = self.discover_threads()
        
        if is_multithread and hasattr(self, 'thread_results'):
            return self.generate_multithread_flamegraphs(output_prefix)
        else:
            return self.generate_single_flamegraph(output_prefix)

    def generate_single_flamegraph(self, output_prefix):
        """Generate single flamegraph for single-threaded or combined analysis"""
        if output_prefix is None:
            output_prefix = f"combined_profile_pid{self.pid}_{int(time.time())}"
        
        folded_file = f"{output_prefix}.folded"
        svg_file = f"{output_prefix}.svg"
        
        combined_stacks = self.normalize_and_combine_stacks()
        
        if not combined_stacks:
            print("No stack traces collected from either tool")
            return None, None
        
        # Calculate time statistics for single thread case
        single_thread_times = self.calculate_thread_times(self.profile_output, self.offcpu_output)
        
        # Sort by value for better visualization
        sorted_stacks = sorted(combined_stacks.items(), key=lambda x: x[1], reverse=True)
        
        # Generate folded output
        output_lines = []
        for stack, value in sorted_stacks:
            output_lines.append(f"{stack} {value}")
        
        # Write folded data to file
        try:
            with open(folded_file, 'w') as f:
                f.write('\n'.join(output_lines))
            print(f"Combined flamegraph data written to: {folded_file}")
        except Exception as e:
            print(f"Error writing folded data: {e}")
            return None, None
        
        # Generate SVG flamegraph
        svg_file = self.generate_svg_from_folded(folded_file, svg_file)
        
        # Generate time analysis file for single thread
        self.generate_single_thread_analysis_file(output_prefix, single_thread_times)
        
        # Print summary
        print(f"\nSummary:")
        print(f"Total unique stack traces: {len(sorted_stacks)}")
        oncpu_stacks = sum(1 for stack, _ in sorted_stacks if stack.endswith("_[c]"))
        offcpu_stacks = sum(1 for stack, _ in sorted_stacks if stack.endswith("_[o]"))
        print(f"On-CPU stack traces: {oncpu_stacks}")
        print(f"Off-CPU stack traces: {offcpu_stacks}")
        
        # Print time verification
        print(f"\nTime Analysis:")
        print(f"On-CPU time: {single_thread_times['oncpu_time_sec']:.3f}s")
        print(f"Off-CPU time: {single_thread_times['offcpu_time_sec']:.3f}s")
        print(f"Total measured time: {single_thread_times['total_time_sec']:.3f}s")
        print(f"Wall clock coverage: {single_thread_times['wall_clock_coverage_pct']:.1f}% of {self.duration}s profiling duration")
        
        return folded_file, svg_file

    def generate_multithread_flamegraphs(self, output_prefix):
        """Generate separate flamegraphs for each thread"""
        base_name = f"combined_profile_pid{self.pid}_{int(time.time())}"
        output_dir = f"multithread_{base_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"Results will be saved to: {output_dir}/")
        
        generated_files = []
        total_threads_with_data = 0
        
        for tid, thread_data in self.thread_results.items():
            cmd = thread_data['cmd']
            oncpu_data = thread_data['oncpu_data']
            offcpu_data = thread_data['offcpu_data']
            
            # Skip threads with no data
            if not oncpu_data and not offcpu_data:
                continue
                
            total_threads_with_data += 1
            
            # Determine thread role
            role = self.get_thread_role(tid, cmd)
            
            # Generate combined folded file for this thread
            folded_file = f"{output_dir}/thread_{tid}_{role}.folded"
            
            combined_stacks = self.combine_thread_stacks(oncpu_data, offcpu_data)
            
            if combined_stacks:
                # Write folded data
                with open(folded_file, 'w') as f:
                    for stack, value in sorted(combined_stacks.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"{stack} {value}\n")
                
                # Generate SVG
                svg_file = f"{output_dir}/thread_{tid}_{role}.svg"
                svg_file = self.generate_svg_from_folded(folded_file, svg_file, f"Thread {tid} ({role})")
                
                # Generate individual thread analysis report
                analysis_file = f"{output_dir}/thread_{tid}_{role}_analysis.txt"
                self.generate_individual_thread_analysis(analysis_file, tid, thread_data, combined_stacks, role)
                
                generated_files.append((folded_file, svg_file))
                print(f"Generated: {folded_file} and {svg_file}")
        
        # Generate thread analysis
        self.generate_thread_analysis_file(output_dir, base_name)
        
        print(f"\nGenerated {len(generated_files)} thread profiles with data out of {len(self.thread_results)} total threads")
        
        return generated_files[0] if generated_files else (None, None)

    def get_thread_role(self, tid, cmd):
        """Get thread role based on TID and command"""
        if tid == self.pid:
            return "main"
        elif "cuda" in cmd.lower() and "evthandlr" in cmd.lower():
            return "cuda-event"
        elif "cuda" in cmd.lower():
            return "cuda-compute"
        elif "eal-intr" in cmd.lower():
            return "dpdk-interrupt"
        elif "rte_mp" in cmd.lower():
            return "dpdk-multiprocess"
        elif "telemetry" in cmd.lower():
            return "telemetry"
        else:
            return cmd.lower().replace(' ', '_').replace('-', '_') + f"_{tid}"

    def combine_thread_stacks(self, oncpu_data, offcpu_data):
        """Combine on-CPU and off-CPU data for a single thread"""
        combined_stacks = {}
        
        # Process on-CPU data
        for line in oncpu_data:
            parts = line.rsplit(' ', 1)
            if len(parts) == 2:
                stack, count_str = parts
                try:
                    count = int(count_str)
                    # Remove process name prefix and add CPU annotation
                    clean_stack = ';'.join(stack.split(';')[1:]) + '_[c]'
                    combined_stacks[clean_stack] = combined_stacks.get(clean_stack, 0) + count
                except ValueError:
                    continue
        
        # Process off-CPU data with normalization
        if offcpu_data:
            norm_factor = (1.0 / self.freq) * 1_000_000  # microseconds per sample
            for line in offcpu_data:
                parts = line.rsplit(' ', 1)
                if len(parts) == 2:
                    stack, time_str = parts
                    try:
                        time_us = int(time_str)
                        normalized_samples = max(1, int(time_us / norm_factor))
                        # Remove process name prefix and add off-CPU annotation
                        clean_stack = ';'.join(stack.split(';')[1:]) + '_[o]'
                        combined_stacks[clean_stack] = combined_stacks.get(clean_stack, 0) + normalized_samples
                    except ValueError:
                        continue
        
        return combined_stacks

    def generate_svg_from_folded(self, folded_file, svg_file, title=None):
        """Generate SVG flamegraph from folded file"""
        flamegraph_script = self.setup_flamegraph_tools()
        if flamegraph_script:
            try:
                cmd_args = [
                    "perl", str(flamegraph_script), 
                    "--colors", "combined",
                    folded_file
                ]
                
                if title:
                    cmd_args.extend(["--title", title])
                else:
                    cmd_args.extend(["--title", "Combined On-CPU and Off-CPU Profile"])
                
                result = subprocess.run(cmd_args, capture_output=True, text=True)
                
                if result.returncode == 0:
                    with open(svg_file, 'w') as f:
                        f.write(result.stdout)
                    return svg_file
                else:
                    print(f"Error generating flamegraph {svg_file}: {result.stderr}")
                    return None
            except Exception as e:
                print(f"Error running flamegraph.pl: {e}")
                return None
        else:
            print("FlameGraph tools not available, skipping SVG generation")
            return None

    def generate_individual_thread_analysis(self, analysis_file, tid, thread_data, combined_stacks, role):
        """Generate individual thread-level analysis report"""
        time_stats = self.calculate_thread_times(thread_data['oncpu_data'], thread_data['offcpu_data'])
        
        # Count stack types
        oncpu_stacks = sum(1 for stack in combined_stacks.keys() if stack.endswith('_[c]'))
        offcpu_stacks = sum(1 for stack in combined_stacks.keys() if stack.endswith('_[o]'))
        
        with open(analysis_file, 'w') as f:
            f.write("Thread-Level Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("Profiling Parameters:\n")
            f.write(f"Duration: {self.duration} seconds\n")
            f.write(f"Sampling frequency: {self.freq} Hz\n")
            f.write(f"\n")
            
            f.write("Thread Information:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Thread ID: {tid}\n")
            f.write(f"Role: {role}\n")
            f.write(f"Command: {thread_data['cmd']}\n")
            f.write(f"\n")
            
            f.write("Time Analysis:\n")
            f.write("-" * 40 + "\n")
            oncpu_us = int(time_stats['oncpu_time_sec'] * 1_000_000)
            f.write(f"On-CPU time: {time_stats['oncpu_time_sec']:.3f}s ({oncpu_us:,} μs)\n")
            f.write(f"Off-CPU time: {time_stats['offcpu_time_sec']:.3f}s ({time_stats['offcpu_us']:,} μs)\n")
            f.write(f"Total measured time: {time_stats['total_time_sec']:.3f}s\n")
            f.write(f"Wall clock coverage: {time_stats['wall_clock_coverage_pct']:.3f}% of {self.duration}s actual process runtime\n")
            f.write(f"\n")
            
            f.write("Stack Trace Summary:\n")
            f.write("-" * 40 + "\n")
            f.write(f"On-CPU stack traces: {oncpu_stacks}\n")
            f.write(f"Off-CPU stack traces: {offcpu_stacks}\n")
            f.write(f"Total unique stacks: {len(combined_stacks)}\n")
            f.write(f"\n")
            
            f.write("Coverage Assessment:\n")
            f.write("-" * 40 + "\n")
            if time_stats['wall_clock_coverage_pct'] < 50:
                f.write("⚠️  Low coverage - thread may be mostly idle or data collection incomplete\n")
            elif time_stats['wall_clock_coverage_pct'] > 150:
                f.write("⚠️  High coverage - possible overlap or measurement anomaly\n")
            else:
                f.write("✓ Coverage appears reasonable for active process\n")
            f.write(f"\n")
        
        print(f"Generated thread analysis: {analysis_file}")
    
    def generate_thread_analysis_file(self, output_dir, base_name):
        """Generate thread analysis summary file"""
        summary_file = f"{output_dir}/{base_name}_thread_analysis.txt"
        
        # Calculate time statistics for all threads
        total_process_oncpu_time = 0
        total_process_offcpu_time = 0
        thread_time_data = {}
        
        for tid, data in self.thread_results.items():
            time_stats = self.calculate_thread_times(data['oncpu_data'], data['offcpu_data'])
            thread_time_data[tid] = time_stats
            total_process_oncpu_time += time_stats['oncpu_time_sec']
            total_process_offcpu_time += time_stats['offcpu_time_sec']
        
        total_process_time = total_process_oncpu_time + total_process_offcpu_time
        
        with open(summary_file, 'w') as f:
            f.write("Multi-Thread Analysis Report\n")
            f.write("="*50 + "\n\n")
            f.write(f"Process ID: {self.pid}\n")
            f.write(f"Total threads: {len(self.thread_results)}\n")
            f.write(f"Profiling duration: {self.duration} seconds\n")
            f.write(f"Sampling frequency: {self.freq} Hz\n\n")
            
            # Wall clock time analysis
            f.write("Time Analysis Summary:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Expected wall clock time: {self.duration:.1f} seconds\n")
            f.write(f"Total measured on-CPU time: {total_process_oncpu_time:.3f} seconds\n")
            f.write(f"Total measured off-CPU time: {total_process_offcpu_time:.3f} seconds\n")
            f.write(f"Total measured time: {total_process_time:.3f} seconds\n")
            
            if self.duration > 0:
                coverage_pct = (total_process_time / self.duration) * 100
                f.write(f"Wall clock coverage: {coverage_pct:.1f}% of expected duration\n")
                
                if coverage_pct < 50:
                    f.write("⚠️  Low coverage - threads may be mostly idle or data collection incomplete\n")
                elif coverage_pct > 150:
                    f.write("⚠️  High coverage - possible overlap or measurement anomaly\n")
                else:
                    f.write("✓ Coverage appears reasonable for active threads\n")
            f.write("\n")
            
            f.write("Thread Details:\n")
            f.write("-" * 40 + "\n")
            for tid, data in self.thread_results.items():
                role = self.get_thread_role(tid, data['cmd'])
                oncpu_count = len(data['oncpu_data'])
                offcpu_count = len(data['offcpu_data'])
                time_stats = thread_time_data[tid]
                
                f.write(f"TID {tid:8} ({role:15}): {data['cmd']}\n")
                f.write(f"  Events: on-CPU: {oncpu_count}, off-CPU: {offcpu_count}\n")
                f.write(f"  Times:  on-CPU: {time_stats['oncpu_time_sec']:.3f}s, off-CPU: {time_stats['offcpu_time_sec']:.3f}s\n")
                f.write(f"  Total:  {time_stats['total_time_sec']:.3f}s ({time_stats['wall_clock_coverage_pct']:.1f}% of wall clock)\n")
                f.write(f"  Samples: on-CPU: {time_stats['oncpu_samples']}, off-CPU: {time_stats['offcpu_us']:,} μs\n\n")
            
            f.write(f"Individual Analysis:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Each thread has been profiled separately.\n")
            f.write(f"Individual flamegraph files show per-thread behavior.\n")
            f.write(f"Compare thread profiles to identify bottlenecks and parallelization opportunities.\n\n")
            
            f.write(f"Time Verification Notes:\n")
            f.write("-" * 40 + "\n")
            f.write(f"• On-CPU time = samples / sampling_frequency ({self.freq} Hz)\n")
            f.write(f"• Off-CPU time = blocking_time_μs / 1,000,000\n")
            f.write(f"• Total time per thread = on-CPU + off-CPU time\n")
            f.write(f"• Wall clock coverage shows how much of the profiling period was active\n")
            f.write(f"• Low coverage may indicate idle threads or missed events\n")
            f.write(f"• High coverage (>100%) may indicate overlapping measurements or high activity\n")
        
        print(f"Thread analysis saved to: {summary_file}")

    def calculate_thread_times(self, oncpu_data, offcpu_data):
        """Calculate actual wall clock times from profiling data"""
        # Calculate on-CPU time from samples
        oncpu_samples = 0
        for line in oncpu_data:
            parts = line.rsplit(' ', 1)
            if len(parts) == 2:
                try:
                    count = int(parts[1])
                    oncpu_samples += count
                except ValueError:
                    continue
        
        # Calculate off-CPU time from microseconds
        offcpu_us = 0
        for line in offcpu_data:
            parts = line.rsplit(' ', 1)
            if len(parts) == 2:
                try:
                    time_us = int(parts[1])
                    offcpu_us += time_us
                except ValueError:
                    continue
        
        # Convert to wall clock times
        oncpu_time_sec = oncpu_samples / self.freq if self.freq > 0 else 0
        offcpu_time_sec = offcpu_us / 1_000_000
        total_time_sec = oncpu_time_sec + offcpu_time_sec
        
        return {
            'oncpu_samples': oncpu_samples,
            'oncpu_time_sec': oncpu_time_sec,
            'offcpu_us': offcpu_us,
            'offcpu_time_sec': offcpu_time_sec,
            'total_time_sec': total_time_sec,
            'wall_clock_coverage_pct': (total_time_sec / self.duration * 100) if self.duration > 0 else 0
        }

    def generate_single_thread_analysis_file(self, output_prefix, single_thread_times):
        """Generate single thread analysis file"""
        analysis_file = f"{output_prefix}_single_thread_analysis.txt"
        
        with open(analysis_file, 'w') as f:
            f.write("Single-Thread Analysis Report\n")
            f.write("="*50 + "\n\n")
            f.write(f"Process ID: {self.pid}\n")
            f.write(f"Profiling duration: {self.duration} seconds\n")
            f.write(f"Sampling frequency: {self.freq} Hz\n\n")
            
            # Time analysis
            f.write("Time Analysis:\n")
            f.write("-" * 40 + "\n")
            f.write(f"On-CPU time: {single_thread_times['oncpu_time_sec']:.3f}s\n")
            f.write(f"Off-CPU time: {single_thread_times['offcpu_time_sec']:.3f}s\n")
            f.write(f"Total measured time: {single_thread_times['total_time_sec']:.3f}s\n")
            f.write(f"Wall clock coverage: {single_thread_times['wall_clock_coverage_pct']:.1f}% of {self.duration}s profiling duration\n")
            
            if single_thread_times['wall_clock_coverage_pct'] < 50:
                f.write("⚠️  Low coverage - thread may be mostly idle or data collection incomplete\n")
            elif single_thread_times['wall_clock_coverage_pct'] > 150:
                f.write("⚠️  High coverage - possible overlap or measurement anomaly\n")
            else:
                f.write("✓ Coverage appears reasonable for active thread\n")
            
            f.write(f"\nTime Verification Notes:\n")
            f.write("-" * 40 + "\n")
            f.write(f"• On-CPU time = samples / sampling_frequency ({self.freq} Hz)\n")
            f.write(f"• Off-CPU time = blocking_time_μs / 1,000,000\n")
            f.write(f"• Total time = on-CPU + off-CPU time\n")
            f.write(f"• Wall clock coverage shows how much of the profiling period was active\n")
            f.write(f"• Coverage values depend on thread activity and system load\n")
        
        print(f"Single thread analysis saved to: {analysis_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Combined On-CPU and Off-CPU Profiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Profile PID 1234 for 30 seconds (default)
  python3 combined_profiler.py 1234
  
  # Profile for 60 seconds with custom sampling frequency
  python3 combined_profiler.py 1234 -d 60 -f 99
  
  # Use custom output prefix for generated files
  python3 combined_profiler.py 1234 -o myapp_profile -m 5000
  
  # Build and run test program first:
  gcc -o test_program test_program.c
  ./test_program &
  python3 combined_profiler.py $!
        """
    )
    
    parser.add_argument("pid", type=int, help="Process ID to profile")
    parser.add_argument("-d", "--duration", type=int, default=30,
                        help="Duration to profile in seconds (default: 30)")
    parser.add_argument("-f", "--frequency", type=int, default=49,
                        help="On-CPU sampling frequency in Hz (default: 49)")
    parser.add_argument("-m", "--min-block-us", type=int, default=1000,
                        help="Minimum off-CPU block time in microseconds (default: 1000)")
    parser.add_argument("-o", "--output", type=str,
                        help="Output file prefix for generated files (default: combined_profile_pid<PID>_<timestamp>)")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: This script typically requires root privileges to access BPF features", 
              file=sys.stderr)
    
    # Check if PID exists
    try:
        os.kill(args.pid, 0)
    except OSError:
        print(f"Error: Process {args.pid} does not exist", file=sys.stderr)
        sys.exit(1)
    
    try:
        profiler = CombinedProfiler(
            pid=args.pid,
            duration=args.duration,
            freq=args.frequency,
            min_block_us=args.min_block_us
        )
        
        profiler.run_profiling()
        folded_file, svg_file = profiler.generate_flamegraph_data(args.output)
        
        print(f"\n" + "="*60)
        print("PROFILING COMPLETE")
        print("="*60)
        if folded_file:
            print(f"📊 Folded data: {folded_file}")
        if svg_file:
            print(f"🔥 Flamegraph:  {svg_file}")
            print(f"   Open {svg_file} in a web browser to view the interactive flamegraph")
        else:
            print("⚠️  SVG flamegraph generation failed")
            if folded_file:
                print(f"   You can manually generate it with:")
                print(f"   ./FlameGraph/flamegraph.pl {folded_file} > flamegraph.svg")
        
        print("\n📝 Interpretation guide:")
        print("   • Red frames show CPU-intensive code paths (on-CPU) marked with _[c]")
        print("   • Blue frames show blocking/waiting operations (off-CPU) marked with _[o]")
        print("   • Wider sections represent more time spent in those functions")
        print("   • Values are normalized to make on-CPU and off-CPU time comparable")
        
    except KeyboardInterrupt:
        print("\nProfiling interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 