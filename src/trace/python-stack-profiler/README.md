# eBPF Tutorial: Python Stack Profiler

Profile Python applications at the OS level using eBPF to capture native and Python call stacks, helping identify performance bottlenecks in Python programs including data science workloads, web servers, and ML inference.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/trace/python-stack-profiler>

## Overview

Python profiling traditionally relies on instrumentation (cProfile) or sampling within the interpreter (py-spy). These approaches have limitations:
- **cProfile**: High overhead, requires code modification
- **py-spy**: Samples from userspace, may miss short-lived functions
- **perf**: Captures native stacks but can't see Python function names

This tutorial shows how to use eBPF to capture both native C stacks AND Python interpreter stacks, giving you complete visibility into where your Python application spends time.

## What You'll Learn

1. How to attach eBPF probes to Python processes
2. Walking Python interpreter frame structures from kernel space
3. Extracting Python function names, filenames, and line numbers
4. Combining native and Python stacks for complete profiling
5. Generating flamegraphs for Python applications

## Prerequisites

- Linux kernel 5.15+ (for BPF ring buffer support)
- Python 3.8+ running on your system
- Root access (for loading eBPF programs)
- Understanding of stack traces and profiling concepts

## Quick Start

```bash
# Build the profiler
make

# Run the test
sudo ./run_test.sh

# Or profile a specific Python process
sudo ./python-stack -p <PID> -d 10
```

## Building and Running

### Build

```bash
make
```

### Profile All Python Processes

```bash
sudo ./python-stack -d 10
```

### Profile Specific Process

```bash
# Find your Python process
ps aux | grep python

# Profile it
sudo ./python-stack -p 12345 -d 30
```

### Generate Flamegraph

```bash
# Collect folded stacks
sudo ./python-stack -p 12345 -f -d 10 > stacks.txt

# Generate flamegraph (requires flamegraph.pl from Brendan Gregg)
flamegraph.pl stacks.txt > flamegraph.svg
```

## How It Works

The profiler samples Python processes at a regular interval (e.g., 49Hz to avoid lock-step with scheduler). For each sample:

1. **Capture native stack**: Use BPF stack helpers to get kernel and userspace stacks
2. **Identify Python threads**: Check if the process is running Python interpreter
3. **Walk Python frames**: Read PyFrameObject chain from CPython internals
4. **Extract symbols**: Get function names, filenames, line numbers from PyCodeObject
5. **Aggregate data**: Count stack occurrences for flamegraph generation

## Python Internals

CPython's frame structure (simplified):

```c
struct _frame {
    struct _frame *f_back;      // Previous frame
    PyCodeObject *f_code;       // Code object
    int f_lineno;               // Current line number
};

struct PyCodeObject {
    PyObject *co_filename;      // Source filename
    PyObject *co_name;          // Function name
};
```

## Example Output

```
python-script.py:main;process_data;expensive_function 247
python-script.py:main;load_model;torch.load 189
python-script.py:main;preprocess;np.array 156
```

Each line shows the stack trace and sample count.

## Use Cases

- **ML/AI workloads**: Profile PyTorch, TensorFlow, NumPy operations
- **Web servers**: Find bottlenecks in Flask, Django, FastAPI
- **Data processing**: Optimize pandas, polars operations
- **General Python**: Any Python application performance analysis

## Current Limitations

This is an educational implementation demonstrating the concepts. For production use, you would need:

1. **Python Thread State Discovery**: The current implementation requires manually populating the `python_thread_states` map. A complete implementation would:
   - Parse `/proc/<pid>/maps` to find `libpython.so`
   - Read Python's global interpreter state (`_PyRuntime`)
   - Walk the thread state list to find each thread's `PyThreadState`
   - Use uprobes on Python's thread creation functions

2. **Python Version Compatibility**: Python internal structures vary between versions (3.8, 3.9, 3.10, 3.11, 3.12). A robust implementation would:
   - Detect Python version from the binary
   - Use different struct layouts per version
   - Support both debug and release builds

3. **Symbol Resolution**: Native stack addresses need symbol resolution via:
   - `/proc/<pid>/maps` for address ranges
   - DWARF/ELF parsing for function names
   - Integration with blazesym (like in oncputime)

## Production Alternatives

For production Python profiling, consider:
- **py-spy**: Sampling profiler that doesn't require instrumentation
- **Austin**: Frame stack sampler for CPython
- **Pyroscope**: Continuous profiling platform with Python support
- **pyperf** with **eBPF backend**: Official Python profiling with eBPF

## Next Steps

Extend this tutorial to:
- Implement Python thread state discovery via `/proc` parsing
- Add multi-version Python struct support (3.8-3.12)
- Integrate blazesym for native symbol resolution
- Capture GIL contention events
- Track Python object allocation
- Measure function-level CPU time
- Support PyPy and other Python implementations

## References

- [CPython Internals](https://realpython.com/cpython-source-code-guide/)
- [Python Frame Objects](https://docs.python.org/3/c-api/frame.html)
- [eBPF Stack Traces](https://www.brendangregg.com/blog/2016-01-20/ebpf-offcpu-flame-graph.html)
