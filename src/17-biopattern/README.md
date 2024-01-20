# eBPF 入门实践教程十七：编写 eBPF 程序统计随机/顺序磁盘 I/O

eBPF（扩展的伯克利数据包过滤器）是 Linux 内核中的一种新技术，允许用户在内核空间中执行自定义程序，而无需更改内核代码。这为系统管理员和开发者提供了强大的工具，可以深入了解和监控系统的行为，从而进行优化。

在本篇教程中，我们将探索如何使用 eBPF 编写程序来统计随机和顺序的磁盘 I/O。磁盘 I/O 是计算机性能的关键指标之一，特别是在数据密集型应用中。

## 随机/顺序磁盘 I/O

随着技术的进步和数据量的爆炸性增长，磁盘 I/O 成为了系统性能的关键瓶颈。应用程序的性能很大程度上取决于其如何与存储层进行交互。因此，深入了解和优化磁盘 I/O，特别是随机和顺序的 I/O，变得尤为重要。

1. **随机 I/O**：随机 I/O 发生在应用程序从磁盘的非连续位置读取或写入数据时。这种 I/O 模式的主要特点是磁盘头需要频繁地在不同的位置之间移动，导致其通常比顺序 I/O 的速度慢。典型的产生随机 I/O 的场景包括数据库查询、文件系统的元数据操作以及虚拟化环境中的并发任务。

2. **顺序 I/O**：与随机 I/O 相反，顺序 I/O 是当应用程序连续地读取或写入磁盘上的数据块。这种 I/O 模式的优势在于磁盘头可以在一个方向上连续移动，从而大大提高了数据的读写速度。视频播放、大型文件的下载或上传以及连续的日志记录都是产生顺序 I/O 的典型应用。

为了实现存储性能的最优化，了解随机和顺序的磁盘 I/O 是至关重要的。例如，随机 I/O 敏感的应用程序在 SSD 上的性能通常远超于传统硬盘，因为 SSD 在处理随机 I/O 时几乎没有寻址延迟。相反，对于大量顺序 I/O 的应用，如何最大化磁盘的连续读写速度则更为关键。

在本教程的后续部分，我们将详细探讨如何使用 eBPF 工具来实时监控和统计这两种类型的磁盘 I/O。这不仅可以帮助我们更好地理解系统的 I/O 行为，还可以为进一步的性能优化提供有力的数据支持。

## Biopattern

Biopattern 可以统计随机/顺序磁盘I/O次数的比例。

首先，确保你已经正确安装了 libbpf 和相关的工具集，可以在这里找到对应的源代码：[bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

导航到 `biopattern` 的源代码目录，并使用 `make` 命令进行编译：

```bash
cd ~/bpf-developer-tutorial/src/17-biopattern
make
```

编译成功后，你应该可以在当前目录下看到 `biopattern` 的可执行文件。基本的运行命令如下：

```bash
sudo ./biopattern [interval] [count]
```

例如，要每秒打印一次输出，并持续10秒，你可以运行：

```console
$ sudo ./biopattern 1 10
Tracing block device I/O requested seeks... Hit Ctrl-C to end.
DISK     %RND  %SEQ    COUNT     KBYTES
sr0         0   100        3          0
sr1         0   100        8          0
sda         0   100        1          4
sda       100     0       26        136
sda         0   100        1          4
```

输出列的含义如下：

- `DISK`：被追踪的磁盘名称。
- `%RND`：随机 I/O 的百分比。
- `%SEQ`：顺序 I/O 的百分比。
- `COUNT`：在指定的时间间隔内的 I/O 请求次数。
- `KBYTES`：在指定的时间间隔内读写的数据量（以 KB 为单位）。

从上述输出中，我们可以得出以下结论：

- `sr0` 和 `sr1` 设备在观测期间主要进行了顺序 I/O，但数据量很小。
- `sda` 设备在某些时间段内只进行了随机 I/O，而在其他时间段内只进行了顺序 I/O。

这些信息可以帮助我们了解系统的 I/O 模式，从而进行针对性的优化。

## eBPF Biopattern 实现原理

首先，让我们看一下 biopattern 的核心 eBPF 内核态代码：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biopattern.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, struct counter);
} counters SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int handle__block_rq_complete(void *args)
{
    struct counter *counterp, zero = {};
    sector_t sector;
    u32 nr_sector;
    u32 dev;

    if (has_block_rq_completion()) {
        struct trace_event_raw_block_rq_completion___x *ctx = args;
        sector = BPF_CORE_READ(ctx, sector);
        nr_sector = BPF_CORE_READ(ctx, nr_sector);
        dev = BPF_CORE_READ(ctx, dev);
    } else {
        struct trace_event_raw_block_rq_complete___x *ctx = args;
        sector = BPF_CORE_READ(ctx, sector);
        nr_sector = BPF_CORE_READ(ctx, nr_sector);
        dev = BPF_CORE_READ(ctx, dev);
    }

    if (filter_dev && targ_dev != dev)
        return 0;

    counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
    if (!counterp)
        return 0;
    if (counterp->last_sector) {
        if (counterp->last_sector == sector)
            __sync_fetch_and_add(&counterp->sequential, 1);
        else
            __sync_fetch_and_add(&counterp->random, 1);
        __sync_fetch_and_add(&counterp->bytes, nr_sector * 512);
    }
    counterp->last_sector = sector + nr_sector;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

1. 全局变量定义

```c
    const volatile bool filter_dev = false;
    const volatile __u32 targ_dev = 0;
```

这两个全局变量用于设备过滤。`filter_dev` 决定是否启用设备过滤，而 `targ_dev` 是我们想要追踪的目标设备的标识符。

BPF map 定义：

```c
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 64);
        __type(key, u32);
        __type(value, struct counter);
    } counters SEC(".maps");
```

这部分代码定义了一个 BPF map，类型为哈希表。该映射的键是设备的标识符，而值是一个 `counter` 结构体，用于存储设备的 I/O 统计信息。

追踪点函数：

```c
    SEC("tracepoint/block/block_rq_complete")
    int handle__block_rq_complete(void *args)
    {
        struct counter *counterp, zero = {};
        sector_t sector;
        u32 nr_sector;
        u32 dev;

        if (has_block_rq_completion()) {
            struct trace_event_raw_block_rq_completion___x *ctx = args;
            sector = BPF_CORE_READ(ctx, sector);
            nr_sector = BPF_CORE_READ(ctx, nr_sector);
            dev = BPF_CORE_READ(ctx, dev);
        } else {
            struct trace_event_raw_block_rq_complete___x *ctx = args;
            sector = BPF_CORE_READ(ctx, sector);
            nr_sector = BPF_CORE_READ(ctx, nr_sector);
            dev = BPF_CORE_READ(ctx, dev);
        }

        if (filter_dev && targ_dev != dev)
            return 0;

        counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
        if (!counterp)
            return 0;
        if (counterp->last_sector) {
            if (counterp->last_sector == sector)
                __sync_fetch_and_add(&counterp->sequential, 1);
            else
                __sync_fetch_and_add(&counterp->random, 1);
            __sync_fetch_and_add(&counterp->bytes, nr_sector * 512);
        }
        counterp->last_sector = sector + nr_sector;
        return 0;
    }
```

在 Linux 中，每次块设备的 I/O 请求完成时，都会触发一个名为 `block_rq_complete` 的追踪点。这为我们提供了一个机会，通过 eBPF 来捕获这些事件，并进一步分析 I/O 的模式。

主要逻辑分析：

- **提取 I/O 请求信息**：从传入的参数中获取 I/O 请求的相关信息。这里有两种可能的上下文结构，取决于 `has_block_rq_completion` 的返回值。这是因为不同版本的 Linux 内核可能会有不同的追踪点定义。无论哪种情况，我们都从上下文中提取出扇区号 (`sector`)、扇区数量 (`nr_sector`) 和设备标识符 (`dev`)。
- **设备过滤**：如果启用了设备过滤 (`filter_dev` 为 `true`)，并且当前设备不是目标设备 (`targ_dev`)，则直接返回。这允许用户只追踪特定的设备，而不是所有设备。
- **统计信息更新**：
      - **查找或初始化统计信息**：使用 `bpf_map_lookup_or_try_init` 函数查找或初始化与当前设备相关的统计信息。如果映射中没有当前设备的统计信息，它会使用 `zero` 结构体进行初始化。
      - **判断 I/O 模式**：根据当前 I/O 请求与上一个 I/O 请求的扇区号，我们可以判断当前请求是随机的还是顺序的。如果两次请求的扇区号相同，那么它是顺序的；否则，它是随机的。然后，我们使用 `__sync_fetch_and_add` 函数更新相应的统计信息。这是一个原子操作，确保在并发环境中数据的一致性。
      - **更新数据量**：我们还更新了该设备的总数据量，这是通过将扇区数量 (`nr_sector`) 乘以 512（每个扇区的字节数）来实现的。
      - **更新最后一个 I/O 请求的扇区号**：为了下一次的比较，我们更新了 `last_sector` 的值。

在 Linux 内核的某些版本中，由于引入了一个新的追踪点 `block_rq_error`，追踪点的命名和结构发生了变化。这意味着，原先的 `block_rq_complete` 追踪点的结构名称从 `trace_event_raw_block_rq_complete` 更改为 `trace_event_raw_block_rq_completion`。这种变化可能会导致 eBPF 程序在不同版本的内核上出现兼容性问题。

为了解决这个问题，`biopattern` 工具引入了一种机制来动态检测当前内核使用的是哪种追踪点结构，即 `has_block_rq_completion` 函数。

1. **定义两种追踪点结构**：

```c
    struct trace_event_raw_block_rq_complete___x {
        dev_t dev;
        sector_t sector;
        unsigned int nr_sector;
    } __attribute__((preserve_access_index));

    struct trace_event_raw_block_rq_completion___x {
        dev_t dev;
        sector_t sector;
        unsigned int nr_sector;
    } __attribute__((preserve_access_index));
```

这里定义了两种追踪点结构，分别对应于不同版本的内核。每种结构都包含设备标识符 (`dev`)、扇区号 (`sector`) 和扇区数量 (`nr_sector`)。

**动态检测追踪点结构**：

```c
    static __always_inline bool has_block_rq_completion()
    {
        if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
            return true;
        return false;
    }
```

`has_block_rq_completion` 函数使用 `bpf_core_type_exists` 函数来检测当前内核是否存在 `trace_event_raw_block_rq_completion___x` 结构。如果存在，函数返回 `true`，表示当前内核使用的是新的追踪点结构；否则，返回 `false`，表示使用的是旧的结构。在对应的 eBPF 代码中，会根据两种不同的定义分别进行处理，这也是适配不同内核版本之间的变更常见的方案。

### 用户态代码

`biopattern` 工具的用户态代码负责从 BPF 映射中读取统计数据，并将其展示给用户。通过这种方式，系统管理员可以实时监控每个设备的 I/O 模式，从而更好地理解和优化系统的 I/O 性能。

主循环：

```c
    /* main: poll */
    while (1) {
        sleep(env.interval);

        err = print_map(obj->maps.counters, partitions);
        if (err)
            break;

        if (exiting || --env.times == 0)
            break;
    }
```

这是 `biopattern` 工具的主循环，它的工作流程如下：

- **等待**：使用 `sleep` 函数等待指定的时间间隔 (`env.interval`)。
- **打印映射**：调用 `print_map` 函数打印 BPF 映射中的统计数据。
- **退出条件**：如果收到退出信号 (`exiting` 为 `true`) 或者达到指定的运行次数 (`env.times` 达到 0)，则退出循环。

打印映射函数：

```c
    static int print_map(struct bpf_map *counters, struct partitions *partitions)
    {
        __u32 total, lookup_key = -1, next_key;
        int err, fd = bpf_map__fd(counters);
        const struct partition *partition;
        struct counter counter;
        struct tm *tm;
        char ts[32];
        time_t t;

        while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
            err = bpf_map_lookup_elem(fd, &next_key, &counter);
            if (err < 0) {
                fprintf(stderr, "failed to lookup counters: %d\n", err);
                return -1;
            }
            lookup_key = next_key;
            total = counter.sequential + counter.random;
            if (!total)
                continue;
            if (env.timestamp) {
                time(&t);
                tm = localtime(&t);
                strftime(ts, sizeof(ts), "%H:%M:%S", tm);
                printf("%-9s ", ts);
            }
            partition = partitions__get_by_dev(partitions, next_key);
            printf("%-7s %5ld %5ld %8d %10lld\n",
                partition ? partition->name : "Unknown",
                counter.random * 100L / total,
                counter.sequential * 100L / total, total,
                counter.bytes / 1024);
        }

        lookup_key = -1;
        while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
            err = bpf_map_delete_elem(fd, &next_key);
            if (err < 0) {
                fprintf(stderr, "failed to cleanup counters: %d\n", err);
                return -1;
            }
            lookup_key = next_key;
        }

        return 0;
    }
```

`print_map` 函数负责从 BPF 映射中读取统计数据，并将其打印到控制台。其主要逻辑如下：

- **遍历 BPF 映射**：使用 `bpf_map_get_next_key` 和 `bpf_map_lookup_elem` 函数遍历 BPF 映射，获取每个设备的统计数据。
- **计算总数**：计算每个设备的随机和顺序 I/O 的总数。
- **打印统计数据**：如果启用了时间戳 (`env.timestamp` 为 `true`)，则首先打印当前时间。接着，打印设备名称、随机 I/O 的百分比、顺序 I/O 的百分比、总 I/O 数量和总数据量（以 KB 为单位）。
- **清理 BPF 映射**：为了下一次的统计，使用 `bpf_map_get_next_key` 和 `bpf_map_delete_elem` 函数清理 BPF 映射中的所有条目。

## 总结

在本教程中，我们深入探讨了如何使用 eBPF 工具 biopattern 来实时监控和统计随机和顺序的磁盘 I/O。我们首先了解了随机和顺序磁盘 I/O 的重要性，以及它们对系统性能的影响。接着，我们详细介绍了 biopattern 的工作原理，包括如何定义和使用 BPF maps，如何处理不同版本的 Linux 内核中的追踪点变化，以及如何在 eBPF 程序中捕获和分析磁盘 I/O 事件。

您可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。

- 完整代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/17-biopattern>
- bcc 工具：<https://github.com/iovisor/bcc/blob/master/libbpf-tools/biopattern.c>
