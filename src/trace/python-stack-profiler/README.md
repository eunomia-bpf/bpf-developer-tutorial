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

## Building and Running

```bash
make
sudo ./python-stack
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

## Next Steps

- Extend to capture GIL contention
- Add Python object allocation tracking
- Integrate with other eBPF metrics (CPU, memory)
- Build flamegraph visualization

## References

- [CPython Internals](https://realpython.com/cpython-source-code-guide/)
- [Python Frame Objects](https://docs.python.org/3/c-api/frame.html)
- [eBPF Stack Traces](https://www.brendangregg.com/blog/2016-01-20/ebpf-offcpu-flame-graph.html)
