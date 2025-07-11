# eBPF 与机器学习可观测：追踪 CUDA GPU 操作

你是否曾经想知道CUDA应用程序在运行时底层发生了什么？GPU操作由于发生在具有独立内存空间的设备上，因此调试和性能分析变得极为困难。在本教程中，我们将构建一个强大的基于eBPF的追踪工具，让你实时查看CUDA API调用。

## CUDA和GPU追踪简介

CUDA（Compute Unified Device Architecture，计算统一设备架构）是NVIDIA的并行计算平台和编程模型，使开发者能够利用NVIDIA GPU进行通用计算。当你运行CUDA应用程序时，后台会发生以下步骤：

1. 主机（CPU）在设备（GPU）上分配内存
2. 数据从主机内存传输到设备内存
3. GPU内核（函数）被启动以处理数据
4. 结果从设备传回主机
5. 设备内存被释放

每个操作都涉及CUDA API调用，如`cudaMalloc`、`cudaMemcpy`和`cudaLaunchKernel`。追踪这些调用可以提供宝贵的调试和性能优化信息，但这并不简单。GPU操作是异步的，传统调试工具通常无法访问GPU内部。

这时eBPF就派上用场了！通过使用uprobes，我们可以在用户空间CUDA运行库（`libcudart.so`）中拦截CUDA API调用，在它们到达GPU之前。这使我们能够了解：

- 内存分配大小和模式
- 数据传输方向和大小
- 内核启动参数
- 错误代码和失败原因
- 操作的时间信息

本教程主要关注CPU侧的CUDA API调用，对于细粒度的GPU操作追踪，你可以参考[eGPU](https://dl.acm.org/doi/10.1145/3723851.3726984)论文和[bpftime](https://github.com/eunomia-bpf/bpftime)项目。

## eBPF技术背景与GPU追踪的挑战

eBPF（Extended Berkeley Packet Filter）最初是为网络数据包过滤而设计的，但现在已经发展成为一个强大的内核编程框架，使开发人员能够在内核空间运行用户定义的程序，而无需修改内核源代码或加载内核模块。eBPF的安全性通过静态分析和运行时验证器来保证，这使得它能够在生产环境中安全地运行。

传统的系统追踪方法往往存在显著的性能开销和功能限制。例如，使用strace等工具追踪系统调用会导致每个被追踪的系统调用产生数倍的性能损失，因为它需要在内核空间和用户空间之间频繁切换。相比之下，eBPF程序直接在内核空间执行，可以就地处理事件，只在必要时才将汇总或过滤后的数据传递给用户空间，从而大大减少了上下文切换的开销。

GPU追踪面临着独特的挑战。现代GPU是高度并行的处理器，包含数千个小型计算核心，这些核心可以同时执行数万个线程。GPU具有自己的内存层次结构，包括全局内存、共享内存、常数内存和纹理内存，这些内存的访问模式对性能有着巨大影响。更复杂的是，GPU操作通常是异步的，这意味着当CPU启动一个GPU操作后，它可以继续执行其他任务，而无需等待GPU操作完成。另外，CUDA编程模型的异步特性使得调试变得特别困难。当一个内核函数在GPU上执行时，CPU无法直接观察到GPU的内部状态。错误可能在GPU上发生，但直到后续的同步操作（如cudaDeviceSynchronize或cudaStreamSynchronize）时才被检测到，这使得错误源的定位变得困难。此外，GPU内存错误（如数组越界访问）可能导致静默的数据损坏，而不是立即的程序崩溃，这进一步增加了调试的复杂性。

## 我们追踪的关键CUDA函数

我们的追踪工具监控几个关键CUDA函数，这些函数代表GPU计算中的主要操作。了解这些函数有助于解释追踪结果并诊断CUDA应用程序中的问题：

### 内存管理

- **`cudaMalloc`**：在GPU设备上分配内存。通过追踪这个函数，我们可以看到请求了多少内存、何时请求以及是否成功。内存分配失败是CUDA应用程序中常见的问题来源。
  ```c
  cudaError_t cudaMalloc(void** devPtr, size_t size);
  ```

- **`cudaFree`**：释放先前在GPU上分配的内存。追踪这个函数有助于识别内存泄漏（分配的内存从未被释放）和双重释放错误。
  ```c
  cudaError_t cudaFree(void* devPtr);
  ```

### 数据传输

- **`cudaMemcpy`**：在主机（CPU）和设备（GPU）内存之间，或在设备内存的不同位置之间复制数据。方向参数（`kind`）告诉我们数据是流向GPU、来自GPU还是在GPU内部移动。
  ```c
  cudaError_t cudaMemcpy(void* dst, const void* src, size_t count, cudaMemcpyKind kind);
  ```
  
  `kind`参数可以是：
  - `cudaMemcpyHostToDevice` (1)：从CPU复制到GPU
  - `cudaMemcpyDeviceToHost` (2)：从GPU复制到CPU
  - `cudaMemcpyDeviceToDevice` (3)：在GPU内存内复制

### 内核执行

- **`cudaLaunchKernel`**：启动GPU内核（函数）在设备上运行。这是真正的并行计算发生的地方。追踪这个函数显示内核何时启动以及是否成功。
  ```c
  cudaError_t cudaLaunchKernel(const void* func, dim3 gridDim, dim3 blockDim, 
                              void** args, size_t sharedMem, cudaStream_t stream);
  ```

### 流和同步

CUDA使用流来管理并发和异步操作：

- **`cudaStreamCreate`**：创建一个新的流，用于按顺序执行操作，但可能与其他流并发。
  ```c
  cudaError_t cudaStreamCreate(cudaStream_t* pStream);
  ```

- **`cudaStreamSynchronize`**：等待流中的所有操作完成。这是一个关键的同步点，可以揭示性能瓶颈。
  ```c
  cudaError_t cudaStreamSynchronize(cudaStream_t stream);
  ```

### 事件

CUDA事件用于计时和同步：

- **`cudaEventCreate`**：创建一个事件对象，用于计时操作。
  ```c
  cudaError_t cudaEventCreate(cudaEvent_t* event);
  ```

- **`cudaEventRecord`**：在流中记录一个事件，可用于计时或同步。
  ```c
  cudaError_t cudaEventRecord(cudaEvent_t event, cudaStream_t stream);
  ```

- **`cudaEventSynchronize`**：等待事件完成，这是另一个同步点。
  ```c
  cudaError_t cudaEventSynchronize(cudaEvent_t event);
  ```

### 设备管理

- **`cudaGetDevice`**：获取当前使用的设备。
  ```c
  cudaError_t cudaGetDevice(int* device);
  ```

- **`cudaSetDevice`**：设置用于GPU执行的设备。
  ```c
  cudaError_t cudaSetDevice(int device);
  ```

通过追踪这些函数，我们可以全面了解GPU操作的生命周期，从设备选择和内存分配到数据传输、内核执行和同步。这使我们能够识别瓶颈、诊断错误并了解CUDA应用程序的行为。

## 架构概述

我们的CUDA事件追踪器由三个主要组件组成：

1. **头文件（`cuda_events.h`）**：定义内核空间和用户空间之间通信的数据结构
2. **eBPF程序（`cuda_events.bpf.c`）**：使用uprobes实现对CUDA函数的内核侧钩子
3. **用户空间应用程序（`cuda_events.c`）**：加载eBPF程序，处理事件并向用户显示

该工具使用eBPF uprobes附加到CUDA运行库中的CUDA API函数。当调用CUDA函数时，eBPF程序捕获参数和结果，并通过环形缓冲区将它们发送到用户空间。

## 关键数据结构

我们追踪器的核心数据结构是在`cuda_events.h`中定义的`struct event`：

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

这个结构设计用于高效捕获不同类型的CUDA操作信息。`union`是一种巧妙的节省空间技术，因为每个事件一次只需要一种类型的数据。例如，内存分配事件需要存储大小，而释放事件需要存储指针。

`cuda_event_type`枚举帮助我们对不同的CUDA操作进行分类：

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

这个枚举涵盖了我们要追踪的主要CUDA操作，从内存管理到内核启动和同步。

## eBPF程序实现

让我们深入了解钩入CUDA函数的eBPF程序（`cuda_events.bpf.c`）。完整代码可在仓库中找到，以下是关键部分：

首先，我们创建一个环形缓冲区与用户空间通信：

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

环形缓冲区是我们追踪器的关键组件。它充当一个高性能队列，eBPF程序可以在其中提交事件，用户空间应用程序可以检索它们。我们设置了256KB的大小来处理事件突发而不丢失数据。

对于每种CUDA操作，我们实现了一个辅助函数来收集相关数据。让我们看看`submit_malloc_event`函数为例：

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

这个函数首先在环形缓冲区中为我们的事件保留空间。然后它填充进程ID和名称等常见字段。对于malloc事件，我们存储请求的大小（在函数入口）或返回值（在函数退出时）。最后，我们将事件提交到环形缓冲区。

实际的探针使用SEC注释附加到CUDA函数。对于cudaMalloc，我们有：

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

第一个函数在进入`cudaMalloc`时调用，捕获请求的大小。第二个在`cudaMalloc`返回时调用，捕获错误代码。这个模式对我们要追踪的每个CUDA函数都会重复。

一个有趣的例子是`cudaMemcpy`，它在主机和设备之间传输数据：

```c
SEC("uprobe")
int BPF_KPROBE(cuda_memcpy_enter, void *dst, const void *src, size_t size, int kind) {
    return submit_memcpy_event(size, kind, false, 0);
}
```

在这里，我们不仅捕获了大小，还捕获了"kind"参数，它指示传输的方向（主机到设备、设备到主机或设备到设备）。这为我们提供了关于数据移动模式的宝贵信息。

## 用户空间应用程序详情

用户空间应用程序（`cuda_events.c`）负责加载eBPF程序，处理来自环形缓冲区的事件，并以用户友好的格式显示它们。

首先，程序解析命令行参数以配置其行为：

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

这个结构存储配置选项，如是否打印时间戳或包含返回探针。默认值提供了一个合理的起点。

程序使用`libbpf`加载并附加eBPF程序到CUDA函数：

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

这个函数接受一个函数名（如"cudaMalloc"）和相应的入口和退出eBPF程序。然后它将这些程序作为uprobes附加到指定的库。

最重要的函数之一是`handle_event`，它处理来自环形缓冲区的事件：

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

此函数格式化并显示事件信息，包括时间戳、进程详情、事件类型以及特定参数或返回值。

`get_event_details`函数将原始事件数据转换为人类可读的形式：

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

这个函数对每种事件类型都有不同的处理方式。例如，malloc事件在入口显示请求的大小，在退出时显示错误代码。

主事件循环非常简单：

```c
while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Error handling... */
}
```

这会轮询环形缓冲区的事件，对每个事件调用`handle_event`。100ms超时确保程序对信号（如Ctrl+C）保持响应。

## CUDA错误处理和报告

我们追踪器的一个重要方面是将CUDA错误代码转换为人类可读的消息。CUDA有100多种不同的错误代码，从简单的"内存不足"到复杂的"不支持的PTX版本"。

我们的工具包括一个全面的`cuda_error_str`函数，将这些数字代码映射到字符串描述：

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

这使输出对调试更有用。不是看到"错误2"，而是看到"OutOfMemory"，这立即告诉你出了什么问题。

## 编译和执行

使用提供的Makefile构建追踪器非常简单：

```bash
# 构建追踪器和示例
make
```

这将创建两个二进制文件：
- `cuda_events`：基于eBPF的CUDA追踪工具
- `basic02`：一个简单的CUDA示例应用程序

构建系统足够智能，可以使用`nvidia-smi`检测你的GPU架构，并使用适当的标志编译CUDA代码。

运行追踪器同样简单：

```bash
# 启动追踪工具
sudo ./cuda_events -p ./basic02

# 在另一个终端运行CUDA示例
./basic02
```

你还可以通过PID追踪特定进程：

```bash
# 运行CUDA示例
./basic02 &
PID=$!

# 使用PID过滤启动追踪工具
sudo ./cuda_events -p ./basic02 -d $PID
```

示例输出显示了每个CUDA操作的详细信息：

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

这个输出显示了CUDA应用程序的典型流程：
1. 在设备上分配内存
2. 从主机复制数据到设备（kind=1）
3. 启动内核处理数据
4. 从设备复制结果回主机（kind=2）
5. 释放设备内存

## 基准测试

我们还提供了一个基准测试工具来测试追踪器的性能和CUDA API调用的延迟。

```bash
make
sudo ./cuda_events -p ./bench
./bench
```

当没有追踪时，结果如下：

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

当附加追踪器时，结果如下：

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

追踪器为每个CUDA API调用增加了约2微秒的开销，这对大多数情况来说是可以忽略不计的。为了进一步减少开销，你可以尝试使用[bpftime](https://github.com/eunomia-bpf/bpftime)用户空间运行时来优化eBPF程序。

## 命令行选项

`cuda_events`工具支持以下选项：

- `-v`：启用详细调试输出
- `-t`：不打印时间戳
- `-r`：不显示函数返回（只显示函数入口）
- `-p PATH`：指定CUDA运行库或应用程序的路径
- `-d PID`：仅追踪指定的进程ID

## 下一步

一旦你熟悉了这个基本的CUDA追踪工具，你可以扩展它来：

1. 添加对更多CUDA API函数的支持
2. 添加时间信息以分析性能瓶颈
3. 实现相关操作之间的关联（例如，匹配malloc和free）
4. 创建CUDA操作的可视化，便于分析
5. 添加对其他GPU框架（如OpenCL或ROCm）的支持

更多关于CUDA追踪工具的细节，请查看我们的教程仓库：[https://github.com/eunomia-bpf/basic-cuda-tutorial](https://github.com/eunomia-bpf/basic-cuda-tutorial)

这个教程的代码在[https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events)

## 参考资料

- CUDA编程指南：[https://docs.nvidia.com/cuda/cuda-c-programming-guide/](https://docs.nvidia.com/cuda/cuda-c-programming-guide/)
- NVIDIA CUDA运行时API：[https://docs.nvidia.com/cuda/cuda-runtime-api/](https://docs.nvidia.com/cuda/cuda-runtime-api/)
- libbpf文档：[https://libbpf.readthedocs.io/](https://libbpf.readthedocs.io/)
- Linux uprobes文档：[https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt](https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt)

如果你想深入了解eBPF，请查看我们的教程仓库：[https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或访问我们的网站：[https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/)。
