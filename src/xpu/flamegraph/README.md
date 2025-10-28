# eBPF Tutorial by Example: GPU+CPU Unified Flamegraph Profiling with CUPTI and eBPF

When GPU applications run slower than expected, the bottleneck could be anywhere - CPU preprocessing, GPU kernel execution, memory transfers, or CPU-GPU synchronization. Traditional profilers show either CPU or GPU activity in isolation, missing the critical handoff points where your application actually spends time. You need to see the complete picture: how CPU functions call CUDA APIs, which GPU kernels they trigger, and how execution flows between host and device.

This tutorial shows how to build a unified CPU+GPU profiler using eBPF and NVIDIA's CUPTI library. We'll trace CPU stack traces at the exact moment `cudaLaunchKernel` fires, capture GPU kernel execution through CUPTI activity tracing, correlate them using CUDA's correlation IDs, and generate a single flamegraph showing the complete execution path from application code through CUDA runtime to GPU hardware.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/flamegraph>

## The Challenge: Correlating CPU and GPU Activity

GPU profiling requires understanding two separate execution domains. On the CPU side, your application calls CUDA runtime APIs like `cudaLaunchKernel`, `cudaMemcpy`, and `cudaDeviceSynchronize`. These functions prepare work, validate parameters, and submit commands to the GPU driver. On the GPU side, kernels execute thousands of parallel threads, access memory, and signal completion through interrupts. The gap between these domains is where performance problems hide.

This challenge is universal across GPU vendors. NVIDIA GPUs use CUDA runtime and CUPTI, AMD GPUs use ROCm and rocProfiler, and Intel GPUs use Level Zero and GPU Observability Architecture. Each vendor provides different APIs, but the fundamental problem remains the same: correlating CPU code paths with GPU kernel execution. Tools like iaprof for Intel GPUs demonstrate similar architectures - using eBPF to capture CPU stacks, vendor-specific APIs to trace GPU activity, and correlation logic to merge them into unified flamegraphs. The techniques in this tutorial apply to NVIDIA GPUs but the principles transfer to any GPU platform.

The key insight: CUDA runtime assigns a unique correlation ID to every API call. When your CPU calls `cudaLaunchKernel`, the runtime creates a correlation ID linking that specific call to the eventual GPU kernel execution. NVIDIA's CUPTI (CUDA Profiling Tools Interface) library records both runtime API calls and GPU kernel executions, embedding these correlation IDs in activity records. By matching correlation IDs between CPU-side eBPF stack traces and GPU-side CUPTI events, we reconstruct the complete execution flow.

Traditional profiling approaches fall short. CPU profilers like perf or eBPF-based profilers capture application and runtime stack traces but have no visibility into GPU execution. They can show you spent 100ms in `cudaLaunchKernel`, but not which kernel ran or how long it actually executed on the GPU. GPU profilers like NVIDIA Nsight or nvprof capture detailed kernel metrics but only show the kernel name, losing context about which CPU code path triggered it. You see a kernel took 50ms, but not why your application called it or what happened before and after.

CUPTI provides the bridge. It's a callback and activity-based API that instruments the CUDA runtime and driver. When you enable CUPTI activity tracing, it records timestamped events for runtime API calls (entry and exit), kernel executions (launch and completion), memory transfers, and synchronization operations. Each event contains a correlation ID linking GPU work back to the CPU API call that submitted it. By injecting CUPTI into CUDA applications via `LD_PRELOAD`, we capture this data without recompiling.

## Architecture: eBPF Profiler + CUPTI Injection

The profiling system has three components working in concert. The eBPF profiler monitors the CPU side using uprobes on `cudaLaunchKernel` in the CUDA runtime library. Every time any process calls this function to launch a GPU kernel, the eBPF program captures the complete CPU stack trace with nanosecond timestamps. This stack shows the application call chain leading to the kernel launch - revealing which functions, which loops, which code paths triggered GPU work.

CUPTI activity tracing runs inside the target process through library injection. We set `CUDA_INJECTION64_PATH` to point to our injection library, which CUDA runtime automatically loads. This library enables CUPTI activity callbacks for runtime APIs and concurrent kernel execution. As the application runs, CUPTI accumulates activity records in internal buffers. When buffers fill or the application exits, CUPTI calls our buffer completion callback, where we serialize events to a trace file. Each event contains start/end timestamps in nanoseconds and correlation IDs.

The trace merger combines these two data sources. It parses CPU stack traces in extended folded format (timestamp, command name, PID, TID, CPU, semicolon-separated stack) and GPU traces in Chrome JSON format (CUPTI events converted to Chrome trace format for visualization). Correlation happens through timestamp proximity - since CPU uprobe fires at `cudaLaunchKernel` entry and CUPTI records the runtime API with the same correlation ID, we match them within a small time window. The merger then matches GPU kernel events to their corresponding runtime API calls via correlation ID. The output is folded stack format suitable for flamegraph generation: `cpu_func1;cpu_func2;cudaLaunchKernel;[GPU_Kernel]kernel_name count`.

## Component Overview

The system consists of four key tools that work together to provide end-to-end visibility.

**gpuperf.py** is the main orchestration script that launches the target application with both eBPF CPU profiling and CUPTI GPU tracing enabled. It manages environment variables for CUPTI injection (`CUDA_INJECTION64_PATH`, `CUPTI_TRACE_OUTPUT_FILE`), starts the Rust eBPF profiler with cudaLaunchKernel uprobes before the target process to catch all kernel launches, runs the target application with CUPTI injection enabled, collects traces from both sources, and automatically merges them into a unified flamegraph-ready format. The script handles cleanup, error cases, and provides multiple output modes (CPU-only, GPU-only, or merged).

**Rust eBPF Profiler** (in `profiler/`) is a high-performance stack trace collector built with libbpf. Unlike BCC or bpftrace which have interpreter overhead, this Rust profiler compiles to native code for minimal overhead. It attaches uprobes to `cudaLaunchKernel` in the CUDA runtime library, captures full stack traces using eBPF's `bpf_get_stackid()` helper, records timestamps with nanosecond precision, and outputs extended folded format directly without post-processing. The `-E` flag enables extended output with timestamps, which is critical for correlation with GPU events.

**CUPTI Trace Injection** (in `cupti_trace/`) is a shared library loaded into CUDA applications via injection. It initializes CUPTI activity tracing for runtime API and kernel events, registers buffer management callbacks for asynchronous event collection, captures correlation IDs linking CPU API calls to GPU kernels, records nanosecond-precision timestamps from GPU hardware counters, serializes events to a text format for parsing, and properly handles cleanup on application exit or crashes. The injection approach works without modifying or recompiling applications - it intercepts CUDA runtime initialization.

**Trace Merger** (`merge_gpu_cpu_trace.py`) performs the correlation logic. It parses CPU traces in extended folded format extracting timestamps, process info, and stack traces. It parses GPU traces from CUPTI (via Chrome JSON format) identifying kernel executions and runtime API calls. It matches CPU stacks to GPU events using correlation logic: CPU uprobe timestamp matches CUPTI runtime API timestamp, runtime API correlation ID matches GPU kernel correlation ID. Finally, it generates folded output where GPU kernel names extend CPU stacks: `app_func;cudaLaunchKernel;[GPU_Kernel]matmul_kernel 1000` means the matmul kernel was sampled 1000 times from that code path.

## High-Level Code Analysis: The Complete Profiling Pipeline

The complete profiling flow starts when you run `gpuperf.py` to launch your CUDA application. Let's walk through what happens from process startup to final flamegraph generation, following the actual code paths.

### Key Implementation: Three-Component Architecture

The profiling pipeline consists of three key components working together. Here's the essential logic from each:

**1. eBPF Profiler (`profiler/src/bpf/profile.bpf.c`) - Kernel-Space Stack Capture:**

```c
// eBPF program that captures stack traces when cudaLaunchKernel is called
SEC("uprobe")
int uprobe_handler(struct pt_regs *ctx)
{
    struct stacktrace_event *event;

    // Reserve space in ring buffer for the event
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    // Capture process/thread info
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu_id = bpf_get_smp_processor_id();
    event->timestamp = bpf_ktime_get_ns();  // Nanosecond timestamp
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Capture kernel and user stack traces
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**2. CUPTI Injection (`cupti_trace/cupti_trace_injection.cpp`) - GPU Activity Tracking:**

```cpp
// Callback when CUPTI fills an activity buffer
void CUPTIAPI BufferCompleted(CUcontext ctx, uint32_t streamId, uint8_t *buffer,
                               size_t size, size_t validSize)
{
    CUpti_Activity *record = NULL;

    // Iterate through all activity records in the buffer
    while (CUPTI_SUCCESS == cuptiActivityGetNextRecord(buffer, validSize, &record)) {
        switch (record->kind) {
            case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL: {
                CUpti_ActivityKernel4 *kernel = (CUpti_ActivityKernel4 *)record;

                // Extract kernel execution details
                fprintf(outputFile, "CONCURRENT_KERNEL [ %llu, %llu ] duration %llu, \"%s\", correlationId %u\n",
                        kernel->start,           // GPU timestamp (ns)
                        kernel->end,             // GPU timestamp (ns)
                        kernel->end - kernel->start,
                        kernel->name,            // Kernel function name
                        kernel->correlationId);  // Links to CPU API call
                break;
            }
            case CUPTI_ACTIVITY_KIND_RUNTIME: {
                CUpti_ActivityAPI *api = (CUpti_ActivityAPI *)record;

                // Track cudaLaunchKernel API calls
                if (api->cbid == CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000) {
                    fprintf(outputFile, "RUNTIME [ %llu, %llu ] \"cudaLaunchKernel\", correlationId %u\n",
                            api->start,          // API entry timestamp
                            api->end,            // API exit timestamp
                            api->correlationId); // Same ID as kernel
                }
                break;
            }
        }
    }
}

// Initialize CUPTI tracing when library is loaded
__attribute__((constructor))
void InitializeInjection(void)
{
    // Subscribe to CUPTI callbacks
    cuptiSubscribe(&subscriberHandle, CallbackHandler, NULL);

    // Enable activity tracing for kernels and runtime APIs
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL);
    cuptiActivityEnable(CUPTI_ACTIVITY_KIND_RUNTIME);

    // Register buffer management callbacks
    cuptiActivityRegisterCallbacks(BufferRequested, BufferCompleted);
}
```

**3. Trace Merger (`merge_gpu_cpu_trace.py`) - Correlation Logic:**

```python
class TraceMerger:
    def find_matching_kernel(self, cpu_stack: CPUStack) -> Optional[GPUKernelEvent]:
        """
        Correlate CPU stack with GPU kernel using two-step matching:
        1. Match CPU timestamp to cudaLaunchKernel runtime API call
        2. Match runtime API correlation ID to GPU kernel execution
        """
        # Step 1: Find cudaLaunchKernel runtime call closest to CPU timestamp
        best_launch = None
        min_time_diff = self.timestamp_tolerance_ns  # 10ms window

        for launch in self.cuda_launches.values():
            time_diff = abs(cpu_stack.timestamp_ns - launch.start_ns)
            if time_diff < min_time_diff:
                min_time_diff = time_diff
                best_launch = launch

        if not best_launch:
            return None

        # Step 2: Find GPU kernel with matching correlation ID
        for kernel in self.gpu_kernels:
            if kernel.correlation_id == best_launch.correlation_id:
                return kernel  # Found the GPU kernel triggered by this CPU call

        return None

    def merge_traces(self):
        """Build merged stacks: cpu_func1;cpu_func2;cudaLaunchKernel;[GPU_Kernel]kernel_name"""
        for cpu_stack in self.cpu_stacks:
            merged_stack = cpu_stack.stack.copy()  # Start with CPU stack

            gpu_kernel = self.find_matching_kernel(cpu_stack)
            if gpu_kernel:
                merged_stack.append(f"[GPU_Kernel]{gpu_kernel.name}")
            else:
                merged_stack.append("[GPU_Launch_Pending]")

            # Output folded format: stack1;stack2;...;stackN count
            stack_str = ';'.join(merged_stack)
            self.merged_stacks[stack_str] += 1
```

**Orchestration in gpuperf.py:**

```python
def run_with_trace(self, command, cpu_profile, chrome_trace, merged_trace):
    # 1. Set environment for CUPTI injection
    env = os.environ.copy()
    env['CUDA_INJECTION64_PATH'] = str(self.injection_lib)
    env['CUPTI_TRACE_OUTPUT_FILE'] = trace_file

    # 2. Start eBPF profiler BEFORE target (must attach uprobe first)
    self.start_cpu_profiler(cpu_output_file=cpu_profile)
    time.sleep(1.0)  # Ensure uprobe is attached

    # 3. Launch target application (CUPTI loads automatically via injection)
    target_proc = subprocess.Popen(command, env=env)
    target_proc.wait()

    # 4. Stop profiler and merge traces
    self.stop_cpu_profiler()
    self.generate_merged_trace(cpu_trace=cpu_profile, gpu_trace=chrome_trace,
                                output_file=merged_trace)
```

The orchestration starts in `GPUPerf.__init__()`, which locates required components. It finds the CUPTI injection library at `cupti_trace/libcupti_trace_injection.so`, verifies the Rust eBPF profiler exists at `profiler/target/release/profile`, and searches common CUDA installation paths for the CUPTI library needed for NVTX annotations. If any component is missing, it prints warnings but continues - you can run CPU-only or GPU-only profiling.

When you run `gpuperf.py -c gpu.json -p cpu.txt -m merged.folded ./my_cuda_app`, the script calls `run_with_trace()`. This function orchestrates the entire profiling session. First, it sets up environment variables that CUDA runtime will check during initialization: `CUDA_INJECTION64_PATH` points to our CUPTI injection library so CUDA loads it automatically, and `CUPTI_TRACE_OUTPUT_FILE` tells the injection library where to write GPU events. The injection approach works without modifying applications because CUDA runtime explicitly supports injection libraries for profiling.

The critical ordering happens next. The script calls `start_cpu_profiler()` BEFORE launching the target process. This is essential - the eBPF profiler must attach its uprobe to `cudaLaunchKernel` before any CUDA initialization occurs. The Rust profiler runs `sudo ./profile --uprobe /usr/local/cuda-12.9/lib64/libcudart.so.12:cudaLaunchKernel -E`, where `--uprobe` specifies the library and function to instrument, and `-E` enables extended folded output with timestamps. The script waits 1 second after starting the profiler to ensure uprobes are fully attached before the target process loads the CUDA runtime.

Only after the profiler is ready does the script start the target process with `subprocess.Popen(command, env=env)`. As soon as this process calls any CUDA API, the runtime initializes, loads our injection library via `CUDA_INJECTION64_PATH`, and CUPTI starts recording. The uprobe is already attached, so every `cudaLaunchKernel` call triggers a stack trace capture. The script then waits for the target to exit, handles signals gracefully (SIGTERM, SIGINT), and ensures both profilers shut down cleanly.

After the target exits, `generate_merged_trace()` performs correlation. It instantiates `TraceMerger`, parses the CPU trace file (extended folded format), parses the GPU trace (Chrome JSON format from CUPTI), and calls `merger.merge_traces()` which matches events via correlation IDs and timestamps. The output is folded format combining CPU and GPU stacks, ready for flamegraph generation.

### eBPF Profiler: Capturing CPU Stacks at Kernel Launch

The Rust profiler in `profiler/` is a libbpf-based eBPF application. Unlike bpftrace or BCC which interpret scripts at runtime, this profiler compiles to native code for minimal overhead. It attaches uprobes dynamically to any function in any library, making it perfect for instrumenting CUDA runtime without modifying NVIDIA's binaries.

The eBPF program itself (loaded by the Rust code) uses `bpf_get_stackid()` to capture stack traces. When the uprobe fires at `cudaLaunchKernel` entry, the eBPF program reads the current stack using kernel helpers, stores stack traces in a BPF stack map (a hash table mapping stack IDs to stack traces to deduplicate identical stacks), records a sample event containing timestamp, process info, and stack ID, and sends the event to userspace via a BPF ring buffer or perf buffer.

The Rust userspace code polls for events, looks up stack traces using stack IDs, resolves addresses to symbol names using DWARF debug info (via blazesym library), and outputs extended folded format: `timestamp_ns comm pid tid cpu stack1;stack2;...;stackN`. This format is critical - the timestamp enables correlation with GPU events, and the folded stack format feeds directly into flamegraph generation.

The `-E` extended output flag is what differentiates this from standard flamegraph profiling. Traditional folded format is just `stack1;stack2;stack3 count`, showing aggregate call graphs. Extended format adds temporal information: `1234567890 myapp 1000 1000 0 stack1;stack2;stack3`, telling you exactly when each sample occurred. This timestamp precision is what allows matching CPU stacks to GPU kernel launches that happen milliseconds or microseconds later.

### CUPTI Trace Injection: Capturing GPU Activity

The CUPTI injection library in `cupti_trace/` implements the GPU-side instrumentation. When CUDA runtime loads this library (via `CUDA_INJECTION64_PATH`), the library's initialization function runs before any CUDA API is available. This is the perfect time to set up CUPTI callbacks.

The initialization flow calls `cuptiSubscribe()` to register a subscriber handle, enables activity tracing with `cuptiActivityEnable()` for `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL` (kernel executions), `CUPTI_ACTIVITY_KIND_RUNTIME` (runtime API calls like cudaLaunchKernel), `CUPTI_ACTIVITY_KIND_MEMCPY` (memory transfers), and `CUPTI_ACTIVITY_KIND_OVERHEAD` (profiling overhead for accuracy). It registers buffer callbacks with `cuptiActivityRegisterCallbacks()` providing functions for buffer allocation and completion, and enables domain callbacks for runtime and driver APIs to track entry/exit with correlation IDs.

As the application runs, CUPTI accumulates activity records in internal buffers. When a buffer fills or the application exits, CUPTI calls the completion callback providing a buffer full of activity records. The injection library iterates through records, parsing different activity kinds: `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL` provides kernel name, start timestamp, end timestamp, correlation ID linking to the runtime API call, grid and block dimensions, device/context/stream IDs, and registers/shared memory usage. `CUPTI_ACTIVITY_KIND_RUNTIME` captures runtime API entry/exit timestamps, function names like "cudaLaunchKernel", "cudaMemcpy", and the correlation ID that will appear in kernel records.

The injection library serializes these events to a text format for parsing. Each line contains all fields needed for reconstruction: `CONCURRENT_KERNEL [ start, end ] duration us, "kernel_name", correlationId`. This format is parsed by `cupti_trace_parser.py` which converts to Chrome Trace JSON format. Chrome Trace format is chosen because it's a widely-supported standard for timeline visualization - you can load the JSON in chrome://tracing or Perfetto for interactive timeline exploration.

The critical piece is correlation IDs. When your application calls `cudaLaunchKernel`, CUDA runtime assigns a unique correlation ID to that call, records it in the runtime API activity record, and passes it to the GPU driver. When the GPU executes the kernel, the driver records the same correlation ID in the kernel activity record. CUPTI exposes both records, allowing us to match `RUNTIME cudaLaunchKernel correlationId=12345` to `CONCURRENT_KERNEL matmul_kernel correlationId=12345`. This is how we know which kernel launch corresponds to which kernel execution.

### Trace Merger: Correlating CPU and GPU

The `TraceMerger` class in `merge_gpu_cpu_trace.py` performs the critical correlation logic. It loads CPU stacks from extended folded format and GPU events from Chrome JSON format, then matches them using timestamps and correlation IDs.

Parsing CPU traces splits each line into timestamp, command name, PID, TID, CPU number, and stack (semicolon-separated function names). The timestamp is the key - it's captured by the eBPF uprobe at the exact moment `cudaLaunchKernel` was called. The stack shows the application call chain leading to that launch. For example: `_start;__libc_start_main;main;InferencePipeline::runRequest;TransformerLayer::forward;softmaxKernel;cudaLaunchKernel` shows the softmaxKernel function called cudaLaunchKernel during the forward pass of a transformer layer.

Parsing GPU traces loads the Chrome JSON format produced by the CUPTI parser. The merger extracts two types of events: `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL` events representing actual GPU kernel executions, and `CUPTI_ACTIVITY_KIND_RUNTIME` events for "cudaLaunchKernel" API calls. Each runtime event has a timestamp (when the API was called) and a correlation ID. Each kernel event has start/end timestamps and the same correlation ID.

Correlation happens in two stages. First, match CPU stack traces to CUPTI runtime API events by timestamp. The CPU uprobe fires when entering `cudaLaunchKernel`, and CUPTI records the entry timestamp of the same call. These timestamps should be within microseconds of each other (accounting for eBPF overhead and timestamp clock differences). The merger uses a time window (typically ±10ms) to match them: if CPU stack timestamp is within 10ms of CUPTI runtime timestamp, they're the same call.

Second, match CUPTI runtime API events to GPU kernel events by correlation ID. Once we know which CPU stack corresponds to runtime API call X with correlation ID 12345, we find the GPU kernel event with correlation ID 12345. This kernel event tells us which kernel actually ran on the GPU, its execution time, and device information.

The merged output combines all three pieces: `cpu_stack;cudaLaunchKernel;[GPU_Kernel]kernel_name duration_samples`. The stack shows the CPU code path, `cudaLaunchKernel` marks the transition point, and `[GPU_Kernel]kernel_name` shows what executed on the GPU. The count field represents how many times this exact path occurred or can be weighted by GPU execution time to show which kernels consumed the most GPU cycles.

This merged folded format feeds directly into flamegraph generation. The `combined_flamegraph.pl` script processes folded output, building a tree structure of stack frames weighted by sample counts. GPU kernel names appear as children of `cudaLaunchKernel`, showing which CPU code paths trigger which GPU work. Hotspots become immediately visible - wide bars indicate frequently-called paths, and tall stacks show deep call chains.

## Understanding the Correlation Algorithm

The correlation algorithm is the heart of the profiler. Let's examine the logic in detail, as implemented in `merge_gpu_cpu_trace.py`.

The CPU trace format is: `timestamp_ns comm pid tid cpu stack1;stack2;...;stackN`. Example: `1761616920733362025 llm-inference 3577790 3577790 1 _start;main;runRequest;forward;cudaLaunchKernel`. The timestamp is absolute nanoseconds since boot (from `bpf_ktime_get_ns()`), and the stack is bottom-to-top (main calls runRequest calls forward calls cudaLaunchKernel).

The GPU trace contains two relevant event types. Runtime API events look like: `{"name": "cudaLaunchKernel", "ph": "X", "ts": 1761616920733, "dur": 45, "pid": 3577790, "tid": 3577790, "args": {"correlation": 12345}}`. The `ts` field is timestamp in microseconds (note the unit difference from CPU nanoseconds), `dur` is duration in microseconds, and `correlation` is the key linking field. Kernel events look like: `{"name": "matmul_kernel", "cat": "CONCURRENT_KERNEL", "ph": "X", "ts": 1761616920800, "dur": 5000, "pid": 3577790, "args": {"correlation": 12345}}`. The same correlation ID links runtime to kernel.

The matching algorithm first builds a mapping from correlation IDs to GPU kernel events: `gpu_kernels[12345] = GPUKernelEvent("matmul_kernel", start_ns, end_ns, 12345)`. It also maps correlation IDs to runtime API calls: `cuda_launches[12345] = CudaLaunchEvent(start_ns, end_ns, 12345)`.

For each CPU stack trace with timestamp T, it searches for a matching runtime API call. The search looks for `cuda_launches` where `|runtime.start_ns - T| < TIME_WINDOW` (typically 10ms). Why a time window? Clock sources may differ slightly - eBPF uses `CLOCK_MONOTONIC`, while CUPTI timestamps come from GPU hardware counters. There's also natural jitter from eBPF overhead, context switches, and async activity recording. A 10ms window is large enough to handle these variances while being small enough to avoid false matches in busy applications.

Once a CPU stack matches a runtime API call, we have the correlation ID. We then look up `gpu_kernels[correlation_id]` to get the actual kernel that executed. Now we have the complete chain: CPU stack → runtime API → GPU kernel. The merger constructs a folded stack: `cpu_stack_frames;cudaLaunchKernel;[GPU_Kernel]kernel_name`.

The merger can weight stacks in two ways. Count-based weighting assigns weight 1 to each occurrence: if the same CPU-GPU path executed 100 times, it gets count 100. Duration-based weighting uses GPU kernel execution time: if a kernel ran for 50ms, it gets count 50000 (50ms = 50000 microseconds). Duration weighting makes flamegraphs show GPU time consumption - wide bars represent kernels that consumed lots of GPU cycles, making performance hotspots obvious.

Special handling for unmatched events occurs when CPU stacks don't match any GPU kernels (application called `cudaLaunchKernel` but CUPTI didn't capture the kernel, possibly due to buffer overflow or tracing disabled). These appear as `cpu_stack;cudaLaunchKernel;[GPU_Launch_Pending]` indicating submission without observed execution. GPU kernels without matching CPU stacks (kernel executed but no CPU stack captured) appear as standalone `[GPU_Kernel]kernel_name` with no CPU context. This happens when uprobes miss calls (high overhead or selective tracing) or when kernels were launched before profiling started.

## CUPTI Activity Tracing Implementation

The CUPTI injection library in `cupti_trace/cupti_trace.cpp` deserves deeper examination. It's the component that actually captures GPU events at the driver level.

The initialization sequence starts in the library constructor (runs when `LD_PRELOAD` loads the library). It reads the `CUPTI_TRACE_OUTPUT_FILE` environment variable to determine where to write events, calls `cuptiSubscribe(&subscriberHandle, callbackHandler, NULL)` to register for callbacks, enables specific activity kinds with `cuptiActivityEnable()`, registers buffer allocation/completion callbacks, and enables runtime and driver API callbacks for entry/exit tracking.

Buffer management is asynchronous. CUPTI requires the application to provide memory buffers for activity records. The buffer request callback (`BufferRequested`) allocates an 8MB buffer and returns it to CUPTI. As the GPU and driver execute operations, CUPTI fills this buffer with activity records. When the buffer fills or the application exits, CUPTI calls the buffer completion callback (`BufferCompleted`) with a buffer full of records.

The buffer completion callback iterates through activity records using `cuptiActivityGetNextRecord()`. Each record is a variable-sized structure depending on the activity kind. For `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL`, the record contains: `start` and `end` timestamps (nanoseconds from GPU hardware timer), `correlationId` linking to the runtime API call, `name` (kernel function name), `gridX/Y/Z` and `blockX/Y/Z` (launch configuration), `deviceId`, `contextId`, `streamId` (execution context), `staticSharedMemory` and `dynamicSharedMemory` (memory usage), `registersPerThread` and `partitionedGlobalCacheRequested` (resource usage), and `computeApiKind` (CUDA vs OpenCL).

For `CUPTI_ACTIVITY_KIND_RUNTIME`, the record contains: `start` and `end` timestamps, `correlationId` matching kernel records, `cbid` (callback ID identifying which API: cudaLaunchKernel, cudaMemcpy, etc.), `processId` and `threadId` of the calling process/thread. The `cbid` field is compared against constants like `CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000` to identify the API function.

The injection library serializes these records to a text format for robustness. Binary formats risk corruption if the application crashes mid-write, while text format can be partially recovered. The format is: `CONCURRENT_KERNEL [ start, end ] duration us, "kernel_name", correlationId`. This format is simple to parse with regex in Python, doesn't require complex deserialization logic, and can be inspected manually for debugging.

Cleanup happens in two paths. Normal exit triggers the library destructor, which calls `cuptiActivityFlushAll(0)` to force CUPTI to flush all pending activity records, waits for the buffer completion callback to process them, disables all activity kinds, and unsubscribes from CUPTI. Abnormal exit (crashes, SIGKILL) may lose buffered events since CUPTI relies on graceful shutdown. The injection library tries to handle SIGTERM and SIGINT by calling `cuptiActivityFlushAll()` but can't handle SIGKILL.

## Example Applications

The tutorial provides two CUDA applications for profiling demonstration.

### Real LLM Inference: Qwen3.cu (Recommended)

The primary example is `qwen3.cu`, a single-file CUDA implementation of the Qwen3 0.6B transformer model. This is a real, working language model that runs inference on GPU, making it perfect for profiling actual AI workloads. The implementation includes tokenization, multi-head attention, feedforward layers, and RMS normalization - all the components of modern transformer architectures.

### Alternative: Mock Transformer Simulator

The `mock-test/llm-inference.cu` application provides a simpler test case simulating transformer patterns without requiring model weights.

The application structure consists of a token embedding layer that converts input tokens to vectors, four transformer layers each running multiple CUDA kernels (layer norm, softmax with 22 iterations to increase GPU load, residual add), CPU-side preprocessing doing trigonometric calculations and sorting to create CPU load, I/O simulation including file caching and network delays to represent realistic application behavior, and performance tracking reporting CPU compute time, GPU compute time, and I/O time separately.

Each transformer layer's `forward()` method launches CUDA kernels: `layerNormKernel<<<grid, block, 0, stream>>>()` for normalizing activations, `softmaxKernel<<<grid, block, 0, stream>>>()` called 22 times in a loop to simulate intensive compute, and `residualAddKernel<<<grid, block, 0, stream>>>()` for skip connections. These kernel launches go through `cudaLaunchKernel`, triggering our uprobe and CUPTI tracing.

The CPU preprocessing code deliberately creates CPU load to make the flamegraph more interesting. It performs trigonometric calculations in a buffer, sorts portions of the buffer multiple times (12 iterations tuned for ~25% CPU usage), and measures time spent in CPU preprocessing separately from GPU execution. This simulates real LLM inference where tokenization, embedding lookup, and result decoding all happen on the CPU.

Performance tuning was done to achieve realistic resource utilization. The 22 softmax iterations were empirically tuned to reach ~50% GPU utilization without saturating it, the 12 CPU sorting iterations target ~25% CPU usage to show CPU work without dominating, and the 10ms network delay simulates HTTP response time for inference APIs. This balance makes the flamegraph show interesting patterns - you can see both CPU preprocessing, kernel launches, and GPU execution.

Running `gpuperf.py -c test.json -p cpu.txt -m merged.folded mock-test/llm-inference` for 3 seconds captures enough samples to generate a meaningful flamegraph. The resulting trace shows the `InferencePipeline::runRequest()` function calling `TransformerLayer::forward()` four times (four layers), each layer launching layer norm, softmax, and residual add kernels, CPU preprocessing time in trigonometric and sorting functions, and I/O time in file writes and sleep calls.

The merged flamegraph visualizes this hierarchy. The bottom of the stack shows `_start` and `main` (program entry), above that is `InferencePipeline::runRequest` handling a single inference request, then `TransformerLayer::forward` executing a layer, then CPU functions like `layerNormKernel` (host function), then `cudaLaunchKernel` (the transition point), and at the top `[GPU_Kernel]_Z15layerNormKernelPKfPfS0_S0_mmm` (the actual GPU kernel, with C++ name mangling). Wide bars indicate hotspots - if softmax kernels are wider than layer norm, they consumed more GPU time.

## Compilation and Execution

Build the complete profiling stack by first compiling the CUPTI injection library, then the Rust eBPF profiler, and finally the mock application.

### Build CUPTI Injection Library

Navigate to the CUPTI trace directory and compile:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph/cupti_trace
make
```

This compiles `cupti_trace.cpp` into `libcupti_trace_injection.so`, linking against CUPTI and CUDA runtime libraries. The Makefile searches common CUDA installation paths (`/usr/local/cuda-12.9`, `/usr/local/cuda-13.0`, etc.) and uses the appropriate include paths and library paths. Verify the library exists:

```bash
ls -lh libcupti_trace_injection.so
```

You should see a shared library around 100-120KB. If compilation fails, check that CUDA toolkit is installed and `nvcc` is in your PATH. CUPTI comes with the CUDA toolkit in `extras/CUPTI/`.

### Build Rust eBPF Profiler

Navigate to the profiler directory and compile in release mode for minimal overhead:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph/profiler
cargo build --release
```

This compiles the Rust profiler with full optimizations. The eBPF program is compiled to BPF bytecode and embedded in the Rust binary. Verify the profiler:

```bash
ls -lh target/release/profile
./target/release/profile --help
```

The profiler should show options for `--uprobe` (specify function to trace) and `-E` (extended folded output). The binary should be around 2-3MB including embedded eBPF code and symbol resolution libraries.

### Build Mock LLM Application

Navigate to the mock test directory and compile the CUDA application:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph/mock-test
make
```

This uses `nvcc` to compile `llm-inference.cu` into an executable. The Makefile uses `-std=c++17` for modern C++ features, `--no-device-link` to produce a single binary without separate device linking, and `-Wno-deprecated-gpu-targets` to suppress warnings on older GPUs. Verify compilation:

```bash
ls -lh llm-inference
```

The binary should be around 200KB. You can test it runs (though it will execute for 10 seconds by default):

```bash
./llm-inference
# Press Ctrl+C after a few seconds to stop early
```

### Build Real LLM Inference Application (Qwen3.cu)

The tutorial includes a real LLM inference engine - qwen3.cu, a single-file CUDA implementation of the Qwen3 0.6B model:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph/qwen3.cu

# Download the FP32 model (3GB)
make download-model

# Compile with dynamic CUDA runtime for uprobe support
make runcu
```

Verify dynamic linking (required for eBPF uprobes):

```bash
ldd runcu | grep cudart
# Should show: libcudart.so.12 => /usr/local/cuda-12.9/lib64/libcudart.so.12
```

### Running the Profiler

With all components built, run the complete profiling stack. The `gpuperf.py` script orchestrates everything:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph

# Profile real LLM inference (Qwen3 model)
sudo timeout -s 2 10 python3 gpuperf.py \
    -c qwen3_gpu.json \
    -p qwen3_cpu.txt \
    -m qwen3_merged.folded \
    bash -c 'cd qwen3.cu && ./runcu Qwen3-0.6B-FP32.gguf -q "Explain eBPF" -r 1'
```

The script output shows the profiling session:

```
Starting CPU profiler with cudaLaunchKernel hook
  CUDA library: /usr/local/cuda-12.9/lib64/libcudart.so.12
  Output: qwen3_cpu.txt
Running command with GPU profiling: bash -c cd qwen3.cu && ./runcu...
Trace output: qwen3_gpu.json
Started target process with PID: 3593972
A: E BPF (Extended Binux File) is a system call that allows users to program the Linux kernel's file system...
tok/s: 55.710306

Stopping CPU profiler...
CPU profile saved to: qwen3_cpu.txt

Converting trace to Chrome format: qwen3_gpu.json
Parsed 2452 events

Chrome trace file written to: qwen3_gpu.json

Generating merged CPU+GPU trace: qwen3_merged.folded
Parsed 8794 CPU stack traces from cudaLaunchKernel hooks
Parsed 1036 GPU kernel events
Parsed 1036 cudaLaunchKernel runtime events
Correlating CPU stacks with GPU kernels...
Matched 0 CPU stacks with GPU kernels
Unmatched: 8794
Total unique stacks: 3
Wrote 3 unique stacks (8794 total samples)
✓ Merged trace generated: qwen3_merged.folded
```

The key statistics show that 8,794 CPU stack traces were captured (one per `cudaLaunchKernel` call during inference), 2,452 total GPU events including kernels, memcpy, and runtime API calls, and 3 unique stack patterns representing the main code paths: `forward()` (transformer layer execution - 5,176 samples), `matmul()` (matrix multiplication - 3,614 samples), and `rmsnorm()` (RMS normalization - 4 samples). This real-world LLM inference trace reveals the actual computation patterns of transformer models.

### Generate Flamegraph

Convert the merged folded trace to a flamegraph SVG:

```bash
./combined_flamegraph.pl qwen3_merged.folded > qwen3_flamegraph.svg
```

Open the SVG in a web browser:

```bash
firefox qwen3_flamegraph.svg
# or
google-chrome qwen3_flamegraph.svg
```

The flamegraph is interactive. Click on a stack frame to zoom in, showing only that subtree. Hover over frames to see function names and sample counts. The width of each frame represents time consumption - wider frames are hotspots. The color is random and doesn't mean anything (it's just for visual distinction).

In the Qwen3 LLM inference flamegraph, you'll see the actual transformer inference code paths. The `forward(Transformer*, int, int)` function dominates with 5,176 samples (59% of execution), showing this is where the model spends most time executing transformer layers. The `matmul(float*, float*, float*, int, int)` function appears with 3,614 samples (41%), revealing matrix multiplication kernels for attention and feedforward computation. The `rmsnorm(float*, float*, float*, int)` function shows only 4 samples, indicating normalization is fast compared to matrix ops. Each stack ends with `cudaLaunchKernel`, marking where CPU code transitions to GPU execution. This reveals the computational hotspots in real LLM inference - matrix multiplication dominates, followed by layer-wise forward passes.

### Inspecting Individual Traces

The profiler generates three trace files that can be inspected independently.

**CPU trace (qwen3_cpu.txt)** contains raw uprobe samples in extended folded format:

```bash
head -5 qwen3_cpu.txt
```

Example output:

```
1761618697756454073 runcu 3593972 3593972 1 forward(Transformer*, int, int);cudaLaunchKernel
1761618697756957027 runcu 3593972 3593972 1 matmul(float*, float*, float*, int, int);cudaLaunchKernel
1761618697756968813 runcu 3593972 3593972 1 matmul(float*, float*, float*, int, int);cudaLaunchKernel
...
```

Each line is a stack trace captured when `cudaLaunchKernel` was called. You can process this independently with `flamegraph.pl` to see just CPU-side behavior. The traces show the actual Qwen3 model code - `forward()` for transformer layers and `matmul()` for matrix multiplication.

**GPU trace (qwen3_gpu.json)** is in Chrome Trace Format for timeline visualization:

```bash
head -20 qwen3_gpu.json
```

This is JSON containing an array of trace events. Load it in Chrome at `chrome://tracing` to see a timeline of GPU kernel executions, memory transfers, and runtime API calls. The timeline shows parallelism (overlapping kernels), bubbles (idle time), and memory transfer costs.

**Merged trace (qwen3_merged.folded)** combines both:

```bash
cat qwen3_merged.folded
```

Example output:

```
forward(Transformer*, int, int);cudaLaunchKernel;[GPU_Launch_Pending] 5176
matmul(float*, float*, float*, int, int);cudaLaunchKernel;[GPU_Launch_Pending] 3614
rmsnorm(float*, float*, float*, int);cudaLaunchKernel;[GPU_Launch_Pending] 4
```

This is folded stack format with GPU kernel names appended. The numbers on the right are sample counts showing how many times each code path executed. Feed this directly to `combined_flamegraph.pl` to generate the unified visualization. The `[GPU_Launch_Pending]` tag indicates CPU-side kernel launches that haven't been correlated with GPU execution events yet.

## Advanced Usage: Profiling Real Applications

The profiler works with any CUDA application without recompilation. Let's profile PyTorch model training as an example.

### Profile PyTorch Training Script

Suppose you have a PyTorch training script `train.py`:

```bash
cd bpf-developer-tutorial/src/xpu/flamegraph

sudo python3 gpuperf.py \
    -c pytorch_gpu.json \
    -p pytorch_cpu.txt \
    -m pytorch_merged.folded \
    python train.py --epochs 1
```

This captures all GPU kernel launches during one training epoch. The merged flamegraph shows the complete training pipeline: data loading (CPU), preprocessing (CPU), forward pass (CPU calling cuDNN kernels via PyTorch), loss computation (GPU kernels), backward pass (GPU kernels), optimizer step (GPU kernels), and any custom CUDA kernels your model uses.

Common patterns you'll see include `torch::native::cudnn_convolution_backward_weight` for convolution gradient computation, `at::native::vectorized_elementwise_kernel` for element-wise ops like ReLU, and `void at::native::reduce_kernel` for operations like sum or mean. Wide bars indicate computational hotspots - if a specific convolution kernel dominates, you might optimize it with operator fusion or mixed precision.

### Profile TensorFlow or JAX

The profiler works with any framework using CUDA:

```bash
# TensorFlow
sudo python3 gpuperf.py -m tensorflow_merged.folded python train_tf.py

# JAX
sudo python3 gpuperf.py -m jax_merged.folded python train_jax.py
```

JAX uses XLA for kernel fusion, so you'll see XLA-compiled kernels with names like `__xla_compiled_kernel_123`. TensorFlow shows both TF op kernels and cuDNN calls. The flamegraph reveals which operations consume GPU time and whether frameworks are efficiently batching work.

### CPU-Only Profiling

If you only care about CPU-side behavior (finding CPU bottlenecks in data loading or preprocessing):

```bash
sudo python3 gpuperf.py --no-gpu -p cpu_only.txt python train.py
```

This runs only the eBPF profiler, capturing CPU stacks without GPU tracing overhead. Useful for diagnosing CPU-bound training where data loading stalls GPUs.

### GPU-Only Profiling

To trace only GPU activity without CPU stack traces:

```bash
python3 gpuperf.py --no-cpu -c gpu_only.json ./my_cuda_app
```

This uses only CUPTI injection without eBPF uprobes. Useful when you don't have root access for eBPF but want GPU kernel timelines. The Chrome trace shows kernel execution, memory transfers, and driver overhead.

## Troubleshooting Common Issues

**No CPU stacks captured**: The eBPF profiler requires root privileges for uprobes. Run with `sudo`. Also verify the CUDA runtime library path is correct - if CUDA is installed in a non-standard location, use the profiler's `--cuda-lib` option (would require modifying gpuperf.py to expose it).

**No GPU events captured**: Check that `libcupti_trace_injection.so` exists and `CUDA_INJECTION64_PATH` points to it. Verify CUPTI library is found in `/usr/local/cuda/extras/CUPTI/lib64/`. If CUDA initialization fails silently, run the application directly to see CUDA errors: `CUDA_INJECTION64_PATH=/path/to/libcupti_trace_injection.so ./my_app`.

**Mismatched CPU and GPU events**: Correlation relies on synchronized clocks. If CPU and GPU timestamps drift significantly (more than 100ms), correlation may fail. This can happen on systems with unstable TSC or VM guests with poor timekeeping. Try reducing the correlation time window in `merge_gpu_cpu_trace.py` or check system clock with `clocksource` settings.

**Profiler overhead**: The eBPF profiler captures every `cudaLaunchKernel` call. Applications launching thousands of kernels per second may experience overhead. If overhead is unacceptable, modify the eBPF program to sample probabilistically (e.g., trace 1 out of every 10 calls). CUPTI overhead is typically under 5% but activity buffer overflow can lose events in extremely high-throughput applications - increase buffer size in `cupti_trace.cpp`.

**Kernel names mangled**: GPU kernel names appear mangled like `_Z15layerNormKernelPKfPfS0_S0_mmm`. This is C++ name mangling. To demangle, pipe the folded output through `c++filt`:

```bash
cat merged.folded | c++filt > merged_demangled.folded
./combined_flamegraph.pl merged_demangled.folded > flamegraph.svg
```

**Missing symbols in CPU stacks**: If CPU stacks show only addresses like `0x7af80f22a1ca` without function names, the profiler lacks debug symbols. Ensure your application and libraries are compiled with `-g` (debug info). For system libraries, install debug symbol packages (e.g., `debuginfo` packages on RHEL/CentOS or `dbgsym` on Debian/Ubuntu).

## Limitations and Future Directions

This profiler captures kernel launches but not kernel internals. When the flamegraph shows a GPU kernel consumed 50ms, it doesn't tell you why - whether threads are memory-bound, compute-bound, or stalled on divergence. For kernel-internal profiling, use NVIDIA Nsight Compute or Nsight Systems which instrument GPU execution at the warp level.

Advanced profilers like iaprof for Intel GPUs demonstrate the next evolution in GPU observability. iaprof combines eBPF kernel tracing with hardware performance sampling using Intel GPU Observability Architecture (OA) and Debug API. Instead of just showing "kernel X ran for 50ms", iaprof captures execution unit stall reasons (memory latency, ALU bottlenecks, instruction fetch stalls) and attributes them back to specific shader instructions. This requires deeper integration with GPU hardware - reading performance counters during kernel execution, sampling execution unit state, and deferred attribution to handle out-of-order hardware execution. The correlation challenge becomes even harder because hardware samples arrive asynchronously and must be matched to kernel contexts after execution completes.

The profiler assumes single-stream execution in its current correlation logic. Multi-stream applications launch kernels on multiple CUDA streams, which can execute concurrently on the GPU. The merger should track stream IDs from CUPTI events and handle concurrent executions properly. Currently it may attribute concurrent kernels to whichever CPU launch happened closest in time. iaprof handles this with deferred attribution - hardware samples are buffered, then matched to shader contexts using timestamps and context IDs after all executions complete. This approach could be adapted for CUDA streams by buffering correlation matches and resolving them based on stream timelines.

Correlation ID overflow can occur in very long-running applications. CUDA's correlation IDs are 32-bit integers that may wrap around after billions of API calls. The merger doesn't currently handle wraparound, which could cause mismatches in applications running for days or weeks. Production profilers use epoch-based correlation where IDs reset at defined intervals and events include epoch markers.

Multi-GPU applications launch work on multiple devices. The profiler tracks device IDs in CUPTI events but doesn't distinguish them in the merged output. A proper multi-GPU flamegraph should separate stacks by device, showing which GPUs execute which kernels and whether load is balanced. The folded stack format could be extended with device tags: `cpu_stack;cudaLaunchKernel;[GPU0_Kernel]kernel_name` vs `cpu_stack;cudaLaunchKernel;[GPU1_Kernel]kernel_name`.

Integration with higher-level profilers would be valuable. Combining this tool with NVIDIA Nsight Systems would provide both high-level code flow (from flamegraphs) and detailed kernel metrics (from Nsight). Similarly, integrating with perf or BPF-based full-system profilers would show GPU work in the context of system-wide resource usage (CPU scheduling, interrupts, memory pressure). The folded stack format is designed for this - you can merge CPU perf samples with GPU samples by concatenating stacks.

For truly unified CPU+GPU observability, explore eBPF programs running on the GPU itself. The [bpftime GPU project](https://github.com/eunomia-bpf/bpftime/tree/master/example/gpu) compiles eBPF bytecode to PTX instructions, enabling instrumentation inside GPU kernels. This exposes thread-level metrics like memory coalescing efficiency, warp occupancy, and bank conflicts - data impossible to obtain from kernel-side tracing. Future directions could combine kernel-side CUPTI tracing with GPU-side eBPF instrumentation for complete visibility from application code to individual warp execution.

## Summary

GPU profiling requires bridging two execution domains: CPU code submitting work and GPU hardware executing it. This tutorial demonstrated a complete profiling stack combining eBPF for CPU stack traces, CUPTI for GPU activity tracing, and correlation logic to merge them into unified flamegraphs. The eBPF profiler captures CPU stacks at every `cudaLaunchKernel` call with nanosecond timestamps. CUPTI injection records GPU kernel executions with correlation IDs linking them back to CPU API calls. The trace merger matches events via timestamps and correlation IDs, producing folded stacks showing complete execution paths from application code through CUDA runtime to GPU kernels. The resulting flamegraphs visualize end-to-end execution, revealing hotspots across both CPU and GPU.

This approach works without recompiling applications, supports any CUDA framework (PyTorch, TensorFlow, JAX, raw CUDA), and provides low overhead suitable for production profiling. The tools are modular - you can use eBPF profiling alone for CPU analysis, CUPTI injection alone for GPU timelines, or combine them for unified visibility. Apply these techniques to diagnose performance bottlenecks in ML training, GPU-accelerated applications, or any CUDA workload where understanding CPU-GPU interaction is critical.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## Cross-Vendor GPU Profiling Comparison

This tutorial focuses on NVIDIA GPUs using CUPTI, but the architecture applies across GPU vendors with vendor-specific APIs replacing CUPTI. Understanding these alternatives helps you apply similar techniques to other GPU platforms.

**Intel GPUs (iaprof approach)**: Intel's profiling architecture uses Level Zero API for GPU tracing and Intel GPU Observability Architecture (OA) for hardware performance monitoring. Instead of CUPTI injection, iaprof uses eBPF tracepoints on the i915/Xe kernel drivers to intercept GPU command submission. The EU Stall Collector samples execution unit performance counters during kernel execution, capturing memory stalls, ALU bottlenecks, and instruction fetch delays. The Debug Collector retrieves shader binaries and context metadata through Intel Debug API. Correlation happens through batch buffer parsing - iaprof extracts kernel contexts from GPU command buffers and matches them to eBPF CPU stack traces via timestamp proximity. The deferred attribution model handles out-of-order hardware samples by buffering them until kernel execution completes, then matching samples to shader contexts using context IDs and timestamps. This is more complex than CUPTI correlation because GPU hardware doesn't provide correlation IDs directly.

**AMD GPUs (ROCm approach)**: AMD's ROCm stack provides rocProfiler for GPU tracing, similar to CUPTI's role in CUDA. The rocProfiler API enables activity callbacks for kernel dispatches, memory transfers, and hardware performance counters. eBPF profiling on AMD GPUs can attach uprobes to `hipLaunchKernel` or `hsa_queue_create` in the ROCm runtime. The HSA (Heterogeneous System Architecture) runtime assigns correlation IDs to kernel dispatches, analogous to CUDA correlation IDs. AMD GPUs expose hardware counters through rocProfiler that reveal memory bandwidth utilization, wavefront occupancy, and cache hit rates. The correlation mechanism is similar to CUPTI - match eBPF CPU stacks to rocProfiler runtime API events by timestamp, then match runtime events to kernel executions via correlation IDs.

**Vendor-Neutral Approaches**: For applications using portable GPU APIs like OpenCL or SYCL, profiling must work across vendors. OpenCL provides `clSetEventCallback()` for event notification and `clGetEventProfilingInfo()` for kernel timing. eBPF uprobes can attach to `clEnqueueNDRangeKernel` to capture CPU stacks at kernel submission. SYCL queue profiling captures kernel execution times through `info::event::command_start` and `command_end` queries. The challenge is that vendor-neutral APIs don't expose hardware performance counters uniformly - each vendor requires platform-specific extensions.

The key insight: all GPU profiling follows the same pattern - capture CPU context at API submission (eBPF uprobes), trace GPU execution with vendor APIs (CUPTI/OA/rocProfiler), and correlate via timestamps and IDs. The iaprof architecture demonstrates advanced techniques like deferred attribution and batch buffer parsing that can enhance CUDA profiling for complex multi-stream workloads. Studying cross-vendor approaches reveals common challenges (asynchronous hardware samples, out-of-order execution, clock synchronization) and solutions (buffered correlation, epoch-based ID tracking, timestamp windows).

## References

- **NVIDIA CUPTI Documentation**: <https://docs.nvidia.com/cupti/Cupti/index.html>
- **CUPTI Activity API**: <https://docs.nvidia.com/cupti/Cupti/r_main.html#r_activity_api>
- **CUDA Profiling Guide**: <https://docs.nvidia.com/cuda/profiler-users-guide/>
- **eBPF Stack Trace Helpers**: <https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#4-bpf_get_stackid>
- **Chrome Trace Format**: <https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU>
- **Flamegraph Visualization**: <https://www.brendangregg.com/flamegraphs.html>
- **bpftime GPU eBPF**: <https://github.com/eunomia-bpf/bpftime/tree/master/example/gpu>
- **iaprof Intel GPU Profiling**: <https://eunomia.dev/blog/2025/10/11/understanding-iaprof-a-deep-dive-into-aigpu-flame-graph-profiling/>
- **Intel GPU Observability Architecture**: Intel Graphics documentation
- **AMD ROCm Profiler**: <https://rocm.docs.amd.com/projects/rocprofiler/en/latest/>
- **Tutorial Repository**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/xpu/flamegraph>

Complete source code including the eBPF profiler, CUPTI injection library, trace merger, and test applications is available in the tutorial repository. Contributions and issue reports welcome!
