# eBPF Tutorial: Tracing CUDA GPU Operations

Have you ever wondered what's happening under the hood when your CUDA application is running? GPU operations can be challenging to debug and profile because they happen in a separate device with its own memory space. In this tutorial, we'll build a powerful eBPF-based tracing tool that lets you peek into CUDA API calls in real time.

## Introduction to CUDA and GPU Tracing

CUDA (Compute Unified Device Architecture) is NVIDIA's parallel computing platform and programming model that enables developers to use NVIDIA GPUs for general-purpose processing. When you run a CUDA application, several things happen behind the scenes:

1. The host (CPU) allocates memory on the device (GPU)
2. Data is transferred from host to device memory
3. GPU kernels (functions) are launched to process the data
4. Results are transferred back from device to host
5. Device memory is freed

Each of these operations involves CUDA API calls like `cudaMalloc`, `cudaMemcpy`, and `cudaLaunchKernel`. Tracing these calls can provide valuable insights for debugging and performance optimization, but this isn't straightforward. GPU operations happen asynchronously, and traditional debugging tools often can't access GPU internals.

This is where eBPF comes to the rescue! By using uprobes, we can intercept CUDA API calls in the user-space CUDA runtime library (`libcudart.so`) before they reach the GPU. This gives us visibility into:

- Memory allocation sizes and patterns
- Data transfer directions and sizes
- Kernel launch parameters
- Error codes and failures
- Timing of operations

This blog mainly focuses on the CPU side of the CUDA API calls, for fined-grained tracing of GPU operations, you can see [eGPU](https://dl.acm.org/doi/10.1145/3723851.3726984) paper and [bpftime](https://github.com/eunomia-bpf/bpftime) project.

## Key CUDA Functions We Trace

Our tracer monitors several critical CUDA functions that represent the main operations in GPU computing. Understanding these functions helps you interpret the tracing results and diagnose issues in your CUDA applications:

### Memory Management

- **`cudaMalloc`**: Allocates memory on the GPU device. By tracing this, we can see how much memory is being requested, when, and whether it succeeds. Memory allocation failures are a common source of problems in CUDA applications.
  ```c
  cudaError_t cudaMalloc(void** devPtr, size_t size);
  ```

- **`cudaFree`**: Releases previously allocated memory on the GPU. Tracing this helps identify memory leaks (allocated memory that's never freed) and double-free errors.
  ```c
  cudaError_t cudaFree(void* devPtr);
  ```

### Data Transfer

- **`cudaMemcpy`**: Copies data between host (CPU) and device (GPU) memory, or between different locations in device memory. The direction parameter (`kind`) tells us whether data is moving to the GPU, from the GPU, or within the GPU.
  ```c
  cudaError_t cudaMemcpy(void* dst, const void* src, size_t count, cudaMemcpyKind kind);
  ```
  
  The `kind` parameter can be:
  - `cudaMemcpyHostToDevice` (1): Copying from CPU to GPU
  - `cudaMemcpyDeviceToHost` (2): Copying from GPU to CPU
  - `cudaMemcpyDeviceToDevice` (3): Copying within GPU memory

### Kernel Execution

- **`cudaLaunchKernel`**: Launches a GPU kernel (function) to run on the device. This is where the actual parallel computation happens. Tracing this shows when kernels are launched and whether they succeed.
  ```c
  cudaError_t cudaLaunchKernel(const void* func, dim3 gridDim, dim3 blockDim, 
                              void** args, size_t sharedMem, cudaStream_t stream);
  ```

### Streams and Synchronization

CUDA uses streams for managing concurrency and asynchronous operations:

- **`cudaStreamCreate`**: Creates a new stream for executing operations in order but potentially concurrently with other streams.
  ```c
  cudaError_t cudaStreamCreate(cudaStream_t* pStream);
  ```

- **`cudaStreamSynchronize`**: Waits for all operations in a stream to complete. This is a key synchronization point that can reveal performance bottlenecks.
  ```c
  cudaError_t cudaStreamSynchronize(cudaStream_t stream);
  ```

### Events

CUDA events are used for timing and synchronization:

- **`cudaEventCreate`**: Creates an event object for timing operations.
  ```c
  cudaError_t cudaEventCreate(cudaEvent_t* event);
  ```

- **`cudaEventRecord`**: Records an event in a stream, which can be used for timing or synchronization.
  ```c
  cudaError_t cudaEventRecord(cudaEvent_t event, cudaStream_t stream);
  ```

- **`cudaEventSynchronize`**: Waits for an event to complete, which is another synchronization point.
  ```c
  cudaError_t cudaEventSynchronize(cudaEvent_t event);
  ```

### Device Management

- **`cudaGetDevice`**: Gets the current device being used.
  ```c
  cudaError_t cudaGetDevice(int* device);
  ```

- **`cudaSetDevice`**: Sets the device to be used for GPU executions.
  ```c
  cudaError_t cudaSetDevice(int device);
  ```

By tracing these functions, we gain complete visibility into the lifecycle of GPU operations, from device selection and memory allocation to data transfer, kernel execution, and synchronization. This enables us to identify bottlenecks, diagnose errors, and understand the behavior of CUDA applications.

## Architecture Overview

Our CUDA events tracer consists of three main components:

1. **Header File (`cuda_events.h`)**: Defines data structures for communication between kernel and user space
2. **eBPF Program (`cuda_events.bpf.c`)**: Implements kernel-side hooks for CUDA functions using uprobes
3. **User-Space Application (`cuda_events.c`)**: Loads the eBPF program, processes events, and displays them to the user

The tool uses eBPF uprobes to attach to CUDA API functions in the CUDA runtime library. When a CUDA function is called, the eBPF program captures the parameters and results, sending them to user space through a ring buffer.

## Key Data Structures

The central data structure for our tracer is the `struct event` defined in `cuda_events.h`:

```c
struct event {
    /* Common fields */
    int pid;                  /* Process ID */
    char comm[TASK_COMM_LEN]; /* Process name */
    enum cuda_event_type type;/* Type of CUDA event */
    
    /* Event-specific data (union to save space) */
    union {
        struct { size_t size; } mem;                 /* For malloc/memcpy */
        struct { void *ptr; } free_data;             /* For free */
        struct { size_t size; int kind; } memcpy_data; /* For memcpy */
        struct { void *func; } launch;               /* For kernel launch */
        struct { int device; } device;               /* For device operations */
        struct { void *handle; } handle;             /* For stream/event operations */
    };
    
    bool is_return;           /* True if this is from a return probe */
    int ret_val;              /* Return value (for return probes) */
    char details[MAX_DETAILS_LEN]; /* Additional details as string */
};
```

This structure is designed to efficiently capture information about different types of CUDA operations. The `union` is a clever space-saving technique since each event only needs one type of data at a time. For example, a memory allocation event needs to store the size, while a free event needs to store a pointer.

The `cuda_event_type` enum helps us categorize different CUDA operations:

```c
enum cuda_event_type {
    CUDA_EVENT_MALLOC = 0,
    CUDA_EVENT_FREE,
    CUDA_EVENT_MEMCPY,
    CUDA_EVENT_LAUNCH_KERNEL,
    CUDA_EVENT_STREAM_CREATE,
    CUDA_EVENT_STREAM_SYNC,
    CUDA_EVENT_GET_DEVICE,
    CUDA_EVENT_SET_DEVICE,
    CUDA_EVENT_EVENT_CREATE,
    CUDA_EVENT_EVENT_RECORD,
    CUDA_EVENT_EVENT_SYNC
};
```

This enum covers the main CUDA operations we want to trace, from memory management to kernel launches and synchronization.

## The eBPF Program Implementation

Let's dive into the eBPF program (`cuda_events.bpf.c`) that hooks into CUDA functions. The full code is available in the repository, but here are the key parts:

First, we create a ring buffer to communicate with user space:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

The ring buffer is a crucial component for our tracer. It acts as a high-performance queue where the eBPF program can submit events, and the user-space application can retrieve them. We set a generous size of 256KB to handle bursts of events without losing data.

For each CUDA operation, we implement a helper function to collect relevant data. Let's look at the `submit_malloc_event` function as an example:

```c
static inline int submit_malloc_event(size_t size, bool is_return, int ret_val) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    /* Fill common fields */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = CUDA_EVENT_MALLOC;
    e->is_return = is_return;
    
    /* Fill event-specific data */
    if (is_return) {
        e->ret_val = ret_val;
    } else {
        e->mem.size = size;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

This function first reserves space in the ring buffer for our event. Then it fills in common fields like the process ID and name. For a malloc event, we store either the requested size (on function entry) or the return value (on function exit). Finally, we submit the event to the ring buffer.

The actual probes are attached to CUDA functions using SEC annotations. For cudaMalloc, we have:

```c
SEC("uprobe")
int BPF_KPROBE(cuda_malloc_enter, void **ptr, size_t size) {
    return submit_malloc_event(size, false, 0);
}

SEC("uretprobe")
int BPF_KRETPROBE(cuda_malloc_exit, int ret) {
    return submit_malloc_event(0, true, ret);
}
```

The first function is called when `cudaMalloc` is entered, capturing the requested size. The second is called when `cudaMalloc` returns, capturing the error code. This pattern is repeated for each CUDA function we want to trace.

One interesting case is `cudaMemcpy`, which transfers data between host and device:

```c
SEC("uprobe")
int BPF_KPROBE(cuda_memcpy_enter, void *dst, const void *src, size_t size, int kind) {
    return submit_memcpy_event(size, kind, false, 0);
}
```

Here, we capture not just the size but also the "kind" parameter, which indicates the direction of the transfer (host-to-device, device-to-host, or device-to-device). This gives us valuable information about data movement patterns.

## User-Space Application Details

The user-space application (`cuda_events.c`) is responsible for loading the eBPF program, processing events from the ring buffer, and displaying them in a user-friendly format.

First, the program parses command-line arguments to configure its behavior:

```c
static struct env {
    bool verbose;
    bool print_timestamp;
    char *cuda_library_path;
    bool include_returns;
    int target_pid;
} env = {
    .print_timestamp = true,
    .include_returns = true,
    .cuda_library_path = NULL,
    .target_pid = -1,
};
```

This structure stores configuration options like whether to print timestamps or include return probes. The default values provide a sensible starting point.

The program uses `libbpf` to load and attach the eBPF program to CUDA functions:

```c
int attach_cuda_func(struct cuda_events_bpf *skel, const char *lib_path, 
                    const char *func_name, struct bpf_program *prog_entry,
                    struct bpf_program *prog_exit) {
    /* Attach entry uprobe */
    if (prog_entry) {
        uprobe_opts.func_name = func_name;
        struct bpf_link *link = bpf_program__attach_uprobe_opts(prog_entry, 
                                env.target_pid, lib_path, 0, &uprobe_opts);
        /* Error handling... */
    }
    
    /* Attach exit uprobe */
    if (prog_exit) {
        /* Similar for return probe... */
    }
}
```

This function takes a function name (like "cudaMalloc") and the corresponding eBPF programs for entry and exit. It then attaches these programs as uprobes to the specified library.

One of the most important functions is `handle_event`, which processes events from the ring buffer:

```c
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    char details[MAX_DETAILS_LEN];
    time_t t;

    /* Skip return probes if requested */
    if (e->is_return && !env.include_returns)
        return 0;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    get_event_details(e, details, sizeof(details));

    if (env.print_timestamp) {
        printf("%-8s ", ts);
    }

    printf("%-16s %-7d %-20s %8s %s\n", 
           e->comm, e->pid, 
           event_type_str(e->type),
           e->is_return ? "[EXIT]" : "[ENTER]",
           details);

    return 0;
}
```

This function formats and displays event information, including timestamps, process details, event type, and specific parameters or return values.

The `get_event_details` function converts raw event data into human-readable form:

```c
static void get_event_details(const struct event *e, char *details, size_t len) {
    switch (e->type) {
    case CUDA_EVENT_MALLOC:
        if (!e->is_return)
            snprintf(details, len, "size=%zu bytes", e->mem.size);
        else
            snprintf(details, len, "returned=%s", cuda_error_str(e->ret_val));
        break;
    
    /* Similar cases for other event types... */
    }
}
```

This function handles each event type differently. For example, a malloc event shows the requested size on entry and the error code on exit.

The main event loop is remarkably simple:

```c
while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Error handling... */
}
```

This polls the ring buffer for events, calling `handle_event` for each one. The 100ms timeout ensures the program remains responsive to signals like Ctrl+C.

## CUDA Error Handling and Reporting

An important aspect of our tracer is translating CUDA error codes into human-readable messages. CUDA has over 100 different error codes, from simple ones like "out of memory" to complex ones like "unsupported PTX version."

Our tool includes a comprehensive `cuda_error_str` function that maps these numeric codes to string descriptions:

```c
static const char *cuda_error_str(int error) {
    switch (error) {
    case 0:  return "Success";
    case 1:  return "InvalidValue";
    case 2:  return "OutOfMemory";
    /* Many more error codes... */
    default: return "Unknown";
    }
}
```

This makes the output much more useful for debugging. Instead of seeing "error 2", you'll see "OutOfMemory", which immediately tells you what went wrong.

## Compilation and Execution

Building the tracer is straightforward with the provided Makefile:

```bash
# Build both the tracer and the example
make
```

This creates two binaries:
- `cuda_events`: The eBPF-based CUDA tracing tool
- `basic02`: A simple CUDA example application

The build system is smart enough to detect your GPU architecture using `nvidia-smi` and compile the CUDA code with the appropriate flags.

Running the tracer is just as easy:

```bash
# Start the tracing tool
sudo ./cuda_events -p ./basic02

# In another terminal, run the CUDA example
./basic02
```

You can also trace a specific process by PID:

```bash
# Run the CUDA example
./basic02 &
PID=$!

# Start the tracing tool with PID filtering
sudo ./cuda_events -p ./basic02 -d $PID
```

The example output shows detailed information about each CUDA operation:

```
Using CUDA library: ./basic02
TIME     PROCESS          PID     EVENT                 TYPE    DETAILS
17:35:41 basic02          12345   cudaMalloc          [ENTER]  size=4000 bytes
17:35:41 basic02          12345   cudaMalloc           [EXIT]  returned=Success
17:35:41 basic02          12345   cudaMalloc          [ENTER]  size=4000 bytes
17:35:41 basic02          12345   cudaMalloc           [EXIT]  returned=Success
17:35:41 basic02          12345   cudaMemcpy          [ENTER]  size=4000 bytes, kind=1
17:35:41 basic02          12345   cudaMemcpy           [EXIT]  returned=Success
17:35:41 basic02          12345   cudaLaunchKernel    [ENTER]  func=0x7f1234567890
17:35:41 basic02          12345   cudaLaunchKernel     [EXIT]  returned=Success
17:35:41 basic02          12345   cudaMemcpy          [ENTER]  size=4000 bytes, kind=2
17:35:41 basic02          12345   cudaMemcpy           [EXIT]  returned=Success
17:35:41 basic02          12345   cudaFree            [ENTER]  ptr=0x7f1234568000
17:35:41 basic02          12345   cudaFree             [EXIT]  returned=Success
17:35:41 basic02          12345   cudaFree            [ENTER]  ptr=0x7f1234569000
17:35:41 basic02          12345   cudaFree             [EXIT]  returned=Success
```

This output shows the typical flow of a CUDA application:
1. Allocate memory on the device
2. Copy data from host to device (kind=1)
3. Launch a kernel to process the data
4. Copy results back from device to host (kind=2)
5. Free device memory

## benchmark

We also provide a benchmark tool to test the performance of the tracer and the latency of the CUDA API calls.

```bash
make
sudo ./cuda_events -p ./bench
./bench
```

When there is no tracing, the result is like this:

```
Data size: 1048576 bytes (1024 KB)
Iterations: 10000

Summary (average time per operation):
-----------------------------------
cudaMalloc:           113.14 µs
cudaMemcpyH2D:        365.85 µs
cudaLaunchKernel:       7.82 µs
cudaMemcpyD2H:        393.55 µs
cudaFree:               0.00 µs
```

When the tracer is attached, the result is like this:

```
Data size: 1048576 bytes (1024 KB)
Iterations: 10000

Summary (average time per operation):
-----------------------------------
cudaMalloc:           119.81 µs
cudaMemcpyH2D:        367.16 µs
cudaLaunchKernel:       8.77 µs
cudaMemcpyD2H:        383.66 µs
cudaFree:               0.00 µs
```

The tracer adds about 2us overhead to each CUDA API call, which is negligible for most cases. To further reduce the overhead, you can try using the [bpftime](https://github.com/eunomia-bpf/bpftime) userspace runtime to optimize the eBPF program.

## Command Line Options

The `cuda_events` tool supports these options:

- `-v`: Enable verbose output for debugging
- `-t`: Don't print timestamps
- `-r`: Don't show function returns (only show function entries)
- `-p PATH`: Specify the path to the CUDA runtime library or application
- `-d PID`: Trace only the specified process ID

## Next Steps

Once you're comfortable with this basic CUDA tracing tool, you could extend it to:

1. Add support for more CUDA API functions
2. Add timing information to analyze performance bottlenecks
3. Implement correlation between related operations (e.g., matching mallocs with frees)
4. Create visualizations of CUDA operations for easier analysis
5. Add support for other GPU frameworks like OpenCL or ROCm

For more detail about the cuda example and tutorial, you can checkout out repo and the code in [https://github.com/eunomia-bpf/basic-cuda-tutorial](https://github.com/eunomia-bpf/basic-cuda-tutorial)

The code of this tutorial is in [https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events)


## References

- CUDA Programming Guide: [https://docs.nvidia.com/cuda/cuda-c-programming-guide/](https://docs.nvidia.com/cuda/cuda-c-programming-guide/)
- NVIDIA CUDA Runtime API: [https://docs.nvidia.com/cuda/cuda-runtime-api/](https://docs.nvidia.com/cuda/cuda-runtime-api/)
- libbpf Documentation: [https://libbpf.readthedocs.io/](https://libbpf.readthedocs.io/)
- Linux uprobes Documentation: [https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt](https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt)

If you'd like to dive deeper into eBPF, check out our tutorial repository at [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or visit our website at [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/). 
