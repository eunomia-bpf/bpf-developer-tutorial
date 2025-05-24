# Tracing CUDA Events with eBPF

This tutorial demonstrates how to use eBPF to trace CUDA runtime API calls using uprobes. This allows you to monitor CUDA applications and gain insights into memory operations, kernel launches, stream operations, and device management.

## Overview

CUDA (Compute Unified Device Architecture) is NVIDIA's parallel computing platform and API model. When developing or troubleshooting CUDA applications, it's often useful to trace CUDA runtime API calls to understand:

- Memory allocation patterns (cudaMalloc, cudaFree)
- Data transfer between host and device (cudaMemcpy)
- Kernel execution (cudaLaunchKernel)
- Stream and event usage (cudaStreamCreate, cudaEventRecord)
- Device management (cudaGetDevice, cudaSetDevice)

eBPF's uprobes feature allows us to attach tracing points to user-space functions in shared libraries like NVIDIA's CUDA Runtime API library (`libcudart.so`), making it an excellent tool for this purpose.

## Prerequisites

- Linux kernel 4.18+ with eBPF support
- NVIDIA CUDA Toolkit installed
- bpftrace installed (for the bpftrace script approach)
- libbpf development libraries (for the libbpf-based approach)

## Approach 1: Using bpftrace (Easier)

The `cuda_events.bt` script uses bpftrace's uprobe functionality to trace important CUDA API calls.

### Locating the CUDA Runtime Library

First, locate your CUDA runtime library:

```bash
# Common locations:
ls -l /usr/local/cuda/lib64/libcudart.so*
ls -l /usr/lib/x86_64-linux-gnu/libcudart.so*
```

Update the library path in the script if it's different from the default `/usr/local/cuda/lib64/libcudart.so`. You'll need to modify every probe definition in the script.

### Running the Script

```bash
sudo bpftrace cuda_events.bt
```

In another terminal, run your CUDA application, and you'll see the traced CUDA API calls.

### Output Format

The script provides detailed output with the following columns:

- `TIME(ms)`: Timestamp in milliseconds since tracing started
- `PROCESS`: Name of the process making the CUDA call
- `PID`: Process ID
- `EVENT`: CUDA function name
- `DETAILS`: Call-specific information (sizes, pointers, return codes)

### Example Output

```
TIME(ms)   PROCESS         PID        EVENT                DETAILS
1234       my_cuda_app     12345      cudaMalloc           size=1048576 bytes
1235       my_cuda_app     12345      cudaMalloc           returned=0 (success)
1236       my_cuda_app     12345      cudaMemcpy           size=1048576 bytes, kind=1
1237       my_cuda_app     12345      cudaMemcpy           returned=0 (success)
1240       my_cuda_app     12345      cudaLaunchKernel     function=0x7f8b3c4d2a00
1241       my_cuda_app     12345      cudaLaunchKernel     returned=0 (success)
```

## What We're Tracing

The script traces the following CUDA functions:

### Memory Management
- `cudaMalloc`: Allocates memory on the GPU
- `cudaFree`: Frees memory on the GPU
- `cudaMemcpy`: Copies data between host and device memory

### Kernel Execution
- `cudaLaunchKernel`: Launches a CUDA kernel

### Stream Operations
- `cudaStreamCreate`: Creates a CUDA stream
- `cudaStreamSynchronize`: Waits for all operations in a stream to complete

### Device Management
- `cudaGetDevice`: Gets the current CUDA device
- `cudaSetDevice`: Sets the current CUDA device

### Event Management
- `cudaEventCreate`: Creates a CUDA event
- `cudaEventRecord`: Records an event in a stream
- `cudaEventSynchronize`: Waits for an event to complete

## Test Application

The `cuda_events_test.c` file provides a simple CUDA application that performs vector addition. You can compile and run it to generate CUDA API calls for testing:

```bash
nvcc -o cuda_events_test cuda_events_test.c
```

Then run the bpftrace script in one terminal:

```bash
sudo bpftrace cuda_events.bt
```

And the test application in another:

```bash
./cuda_events_test
```

## Limitations

- The script only traces the main CUDA Runtime API functions. It doesn't trace CUDA driver API calls or CUDA library functions.
- The path to `libcudart.so` needs to be updated manually if it's different from the default.
- To capture more CUDA driver API functions, you would need to add additional probes for functions in `libcuda.so`.

## Troubleshooting

If you encounter issues:

1. **Library Path**: Ensure the path to `libcudart.so` in the script is correct for your system
2. **Permission Issues**: Make sure you're running with sudo
3. **Missing Symbols**: Some CUDA library versions might have different function signatures or optimized symbols

## Conclusion

eBPF and uprobes provide a powerful way to trace CUDA applications without modifying source code or recompiling. This non-intrusive approach allows developers to debug CUDA applications and analyze GPU utilization patterns easily.

By tracing CUDA API calls, you can:
- Debug memory leaks in CUDA applications
- Understand data transfer patterns between CPU and GPU
- Profile kernel execution patterns
- Verify proper event and stream synchronization

## Further Reading

- [CUDA Toolkit Documentation](https://docs.nvidia.com/cuda/)
- [bpftrace Reference Guide](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [Using uprobes with BPF](https://www.brendangregg.com/blog/2016-10-12/linux-bcc-nodejs-uprobes.html)
