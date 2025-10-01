# BPF Profiling Tools

This directory contains two powerful BPF-based profiling tools derived from BCC libbpf-tools:

- **offcputime** - Traces off-CPU time by stack traces
- **oncputime** - Profiles CPU usage by sampling stack traces

## Overview

These tools use eBPF (Extended Berkeley Packet Filter) to efficiently collect profiling data directly in the kernel with minimal overhead. They provide insights into where your applications spend time, both on and off the CPU.

## Tools

### offcputime

`offcputime` traces threads that are blocked and not running on-CPU, showing stack traces and the time spent blocked. This is useful for identifying I/O bottlenecks, lock contention, and other blocking operations.

#### How it works
- Hooks into kernel scheduler switch events (`sched_switch`)
- Records timestamps when threads go off-CPU and when they return
- Captures user and kernel stack traces at the point of blocking
- Calculates time spent off-CPU and aggregates by stack trace
- Filters can be applied by PID, TID, minimum/maximum block time, and thread types

#### Usage
```bash
# Basic usage - trace all threads until Ctrl+C
./offcputime

# Trace for 5 seconds
./offcputime 5

# Trace only events lasting more than 1ms (1000 microseconds)
./offcputime -m 1000

# Trace only events lasting less than 10ms
./offcputime -M 10000

# Trace specific PIDs
./offcputime -p 185,175,165

# Trace specific threads (TIDs)
./offcputime -t 188,120,134

# Trace only user threads (exclude kernel threads)
./offcputime -u

# Trace only kernel threads (exclude user threads)
./offcputime -k

# Output in folded format for flame graphs
./offcputime -f

# Folded format with delimiter between kernel/user stacks
./offcputime -fd
```

#### Command Line Options
- `-m, --min-block-time`: Minimum block time in microseconds (default: 1)
- `-M, --max-block-time`: Maximum block time in microseconds (default: unlimited)
- `-p, --pid`: Trace specific PIDs (comma-separated)
- `-t, --tid`: Trace specific TIDs (comma-separated)
- `-u, --user-threads-only`: Trace only user threads
- `-k, --kernel-threads-only`: Trace only kernel threads
- `-U, --user-stacks-only`: Show only user space stack traces
- `-K, --kernel-stacks-only`: Show only kernel space stack traces
- `-f, --folded`: Output in folded format for flame graphs
- `-d, --delimited`: Insert delimiter between kernel/user stacks
- `--perf-max-stack-depth`: Maximum stack trace depth (default: 127)
- `--stack-storage-size`: Number of unique stack traces to store (default: 1024)
- `--state`: Filter by thread state bitmask
- `-v, --verbose`: Verbose debug output

### oncputime

`oncputime` samples CPU usage by capturing stack traces at regular intervals, showing where CPU time is being spent. This is useful for identifying CPU hotspots and performance bottlenecks.

#### How it works
- Uses perf events to sample at timed intervals (default: 49 Hz)
- Captures user and kernel stack traces when samples are taken
- Aggregates sample counts by unique stack trace
- Higher sample counts indicate more CPU time spent in those code paths

#### Usage
```bash
# Basic usage - profile at 49 Hz until Ctrl+C
./oncputime

# Profile at 99 Hz sampling rate
./oncputime -F 99

# Profile for 5 seconds only
./oncputime 5

# Profile specific PID
./oncputime -p 185

# Profile specific thread (TID)
./oncputime -L 185

# Show only user space stacks
./oncputime -U

# Show only kernel space stacks
./oncputime -K

# Output in folded format for flame graphs
./oncputime -f

# Profile specific CPU core
./oncputime -C 0

# Include idle CPU time in results
./oncputime -I
```

#### Command Line Options
- `-F, --frequency`: Sampling frequency in Hz (default: 49)
- `-p, --pid`: Profile specific PIDs (comma-separated)
- `-L, --tid`: Profile specific TIDs (comma-separated)
- `-U, --user-stacks-only`: Show only user space stack traces
- `-K, --kernel-stacks-only`: Show only kernel space stack traces
- `-f, --folded`: Output in folded format for flame graphs
- `-d, --delimited`: Insert delimiter between kernel/user stacks
- `-C, --cpu`: Profile specific CPU core
- `-I, --include-idle`: Include CPU idle stacks
- `--perf-max-stack-depth`: Maximum stack trace depth (default: 127)
- `--stack-storage-size`: Number of unique stack traces to store (default: 1024)
- `-v, --verbose`: Verbose debug output

## Building

### Prerequisites
- Linux kernel with BPF support (4.4+)
- libbpf development headers
- clang/LLVM
- bpftool
- blazesym library (for symbol resolution)

### Build Steps
```bash
# Build both tools
make all

# Build specific tool
make offcputime
make oncputime

# Clean build artifacts
make clean
```

The Makefile automatically handles:
- Building libbpf static library
- Compiling BPF programs with clang
- Generating BPF skeletons with bpftool
- Building blazesym for symbol resolution
- Linking final executables

## Output Formats

### Standard Format
Both tools support a multi-line output format showing complete stack traces:

```
    do_nanosleep
    hrtimer_nanosleep
    sys_nanosleep
    do_syscall_64
    entry_SYSCALL_64_after_hwframe
    nanosleep
    main
    __libc_start_main
    _start
    -                python (12345)
        1000523
```

### Folded Format (-f)
Suitable for generating flame graphs with FlameGraph tools:

```
python;_start;__libc_start_main;main;nanosleep;entry_SYSCALL_64_after_hwframe;do_syscall_64;sys_nanosleep;hrtimer_nanosleep;do_nanosleep 1000523
```

## Interpreting Results

### offcputime Results
- **Stack traces**: Show the code path where blocking occurred
- **Time values**: Time spent off-CPU in microseconds
- **Thread info**: Process name and PID of the blocked thread
- **High values**: Indicate significant blocking/waiting time

**Common patterns to look for:**
- **I/O operations**: File system calls, network operations
- **Lock contention**: Mutex/semaphore waits
- **Sleep/delays**: Explicit sleeps or timer waits
- **Page faults**: Memory allocation and swapping

### oncputime Results
- **Stack traces**: Show the code path where CPU cycles were spent
- **Count values**: Number of samples captured (higher = more CPU time)
- **Thread info**: Process name and PID consuming CPU
- **Hot paths**: Functions with high sample counts

**Common patterns to look for:**
- **CPU hotspots**: Functions with high sample counts
- **System calls**: Time spent in kernel vs user space
- **Library functions**: Third-party library performance
- **Algorithm efficiency**: Loops and computational bottlenecks

## Creating Flame Graphs

Both tools support folded output format that can be used with Brendan Gregg's FlameGraph tools:

```bash
# Generate flame graph from offcputime
./offcputime -f 30 > out.folded
git clone https://github.com/brendangregg/FlameGraph
./FlameGraph/flamegraph.pl out.folded > offcpu.svg

# Generate flame graph from oncputime  
./oncputime -f 30 > out.folded
./FlameGraph/flamegraph.pl out.folded > oncpu.svg
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Run as root or with CAP_BPF/CAP_SYS_ADMIN capabilities
2. **BPF not supported**: Ensure kernel has CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y
3. **Missing symbols**: Install debug symbols for better stack trace resolution
4. **High overhead**: Reduce sampling frequency or increase filtering

### Performance Considerations

- `offcputime` has minimal overhead as it only triggers on scheduler events
- `oncputime` overhead increases with sampling frequency - start with lower rates
- Use filtering options (-p, -t) to reduce data collection scope
- Increase `--stack-storage-size` if you see "stack traces could not be displayed" warnings

## Architecture

### File Structure
- `*.h` - Header files with data structures and constants
- `*.bpf.c` - BPF kernel programs (compiled to bytecode)
- `*.c` - User-space programs that load and interact with BPF programs
- `arg_parse.h` - Common argument parsing for both tools
- `common.h` - Shared utility functions for stack trace display
- `Makefile` - Build configuration and dependencies

### Dependencies
- **libbpf**: BPF program loading and management
- **blazesym**: Symbol resolution for stack traces
- **bpftool**: BPF skeleton generation
- **vmlinux.h**: Kernel type definitions

These tools demonstrate modern BPF-based observability, providing production-ready profiling capabilities with minimal system impact. 