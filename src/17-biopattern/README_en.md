# eBPF Tutorial by Example 17: Count Random/Sequential Disk I/O

eBPF (Extended Berkeley Packet Filter) is a new technology in the Linux kernel that allows users to execute custom programmes in kernel space without changing the kernel code. This provides system administrators and developers with powerful tools to gain insight into and monitor system behaviour for optimisation.

In this tutorial, we will explore how to use eBPF to write programs to count random and sequential disk I/O. Disk I/O is one of the key metrics of computer performance, especially in data-intensive applications.

## Random/Sequential Disk I/O

As technology advances and data volumes explode, disk I/O becomes a critical bottleneck in system performance. The performance of an application depends heavily on how it interacts with the storage tier. Therefore, it becomes especially important to deeply understand and optimise disk I/O, especially random and sequential I/O.

1. **Random I/O**: Random I/O occurs when an application reads or writes data from or to a non-sequential location on the disk. The main characteristic of this I/O mode is that the disk head needs to move frequently between locations, causing it to be typically slower than sequential I/O. Typical scenarios that generate random I/O include database queries, file system metadata operations, and concurrent tasks in virtualised environments.

2. **Sequential I/O**: In contrast to random I/O, sequential I/O occurs when an application continuously reads or writes blocks of data to or from disk. The advantage of this I/O mode is that the disk head can move continuously in one direction, which greatly increases the speed at which data can be read and written. Video playback, downloading or uploading large files, and continuous logging are typical applications that generate sequential I/O.

To optimise storage performance, it is critical to understand both random and sequential disk I/O. For example, random I/O-sensitive applications typically perform far better on SSDs than on traditional hard drives because SSDs have virtually no addressing latency when dealing with random I/Os. Conversely, for applications with a lot of sequential I/O, it is much more critical to maximize the sequential read and write speed of the disk.

In the rest of this tutorial, we will discuss in detail how to use the eBPF tool to monitor and count both types of disk I/O in real time, which will not only help us better understand the I/O behaviour of the system, but will also provide us with strong data for further performance optimization.

## Biopattern

Biopattern counts the percentage of random/sequential disk I/Os.

First of all, make sure that you have installed libbpf and the associated toolset correctly, you can find the source code here: [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

Navigate to the `biopattern` source directory and compile it using the `make` command:

```bash
cd ~/bpf-developer-tutorial/src/17-biopattern
make
```

After successful compilation, you should see the `biopattern` executable in the current directory. The basic runtime commands are as follows:

```bash
sudo ./biopattern [interval] [count]
```

For example, to print the output once per second for 10 seconds, you can run:

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

The output columns have the following meanings:

- `DISK`: Name of the disk being tracked.
- `%RND`: Percentage of random I/O.
- `%SEQ`: percentage of sequential I/O.
- `COUNT`: Number of I/O requests in the specified interval.
- `KBYTES`: amount of data (in KB) read and written in the specified time interval.

From the above output, we can draw the following conclusions:

- The `sr0` and `sr1` devices performed mostly sequential I/O during the observation period, but the amount of data was small.
- The `sda` device performed only random I/O during some time periods and only sequential I/O during other time periods.

This information can help us understand the I/O pattern of the system so that we can target optimisation.

## eBPF Biopattern Implementation Principles

First, let's look at the eBPF kernel state code at the heart of biopattern:

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

Global variable definitions:

```c
   const volatile bool filter_dev = false; 
   const volatile __u32 targ_dev = 0;
```

These two global variables are used for device filtering. `filter_dev` determines whether device filtering is enabled or not, and `targ_dev` is the identifier of the target device we want to track.

BPF map definition:

```c
   struct { __uint(type, BPF_MAP_TYPE_HASH); 
            __uint(max_entries, 64); __type(key, u32); 
            __type(value, struct counter); 
    } counters SEC(".maps").
```

This part of the code defines a BPF map of type hash table. The key of the map is the identifier of the device, and the value is a `counter` struct, which is used to store the I/O statistics of the device.

The tracepoint function:

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

In Linux, a trace point called `block_rq_complete` is triggered every time an I/O request for a block device completes. This provides an opportunity to capture these events with eBPF and further analyse the I/O patterns.

Main Logic Analysis:

- **Extracting I/O request information**: get information about the I/O request from the incoming parameters. There are two possible context structures depending on the return value of `has_block_rq_completion`. This is because different versions of the Linux kernel may have different tracepoint definitions. In either case, we extract the sector number `(sector)`, the number of sectors `(nr_sector)` and the device identifier `(dev)` from the context.

- **Device filtering**: If device filtering is enabled `(filter_dev` is `true` ) and the current device is not the target device `(targ_dev` ), it is returned directly. This allows the user to track only specific devices, not all devices.

- **Statistics update**:

  - **Lookup or initialise statistics**: use the `bpf_map_lookup_or_try_init` function to lookup or initialise statistics related to the current device. If there is no statistics for the current device in the map, it will be initialised using the `zero` structure.
- **Determine the I/O mode**: Based on the sector number of the current I/O request and the previous I/O request, we can determine whether the current request is random or sequential. If the sector numbers of the two requests are the same, then it is sequential; otherwise, it is random. We then use the `__sync_fetch_and_add` function to update the corresponding statistics. This is an atomic operation that ensures data consistency in a concurrent environment.
- **Update the amount of data**: we also update the total amount of data for the device, which is done by multiplying the number of sectors `(nr_sector` ) by 512 (the number of bytes per sector).
- **Update the sector number of the last I/O request**: for the next comparison, we update the value of `last_sector`.

In some versions of the Linux kernel, the naming and structure of the tracepoint has changed due to the introduction of a new tracepoint, `block_rq_error`. This means that the structural name of the former `block_rq_complete` tracepoint has been changed from `trace_event_raw_block_rq_complete` to `trace_event_raw_block_rq_completion`, a change which may cause compatibility issues with eBPF programs on different versions of the kernel. This change may cause compatibility issues with eBPF programs on different versions of the kernel.

To address this issue, the `biopattern` utility introduces a mechanism to dynamically detect which trace point structure is currently used by the kernel, namely the `has_block_rq_completion` function.

1. **Define two trace point structures**:

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

Two tracepoint structures are defined here, corresponding to different versions of the kernel. Each structure contains a device identifier `(dev` ), sector number `(sector` ), and number of sectors `(nr_sector` ).

**Dynamic detection of trackpoint structures**:

```c
    static __always_inline bool has_block_rq_completion()
    {
        if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
            return true;
        return false;
    }
```

The `has_block_rq_completion` function uses the `bpf_core_type_exists` function to detect the presence of the structure `trace_event_raw_block_rq_completion___x` in the current kernel. If it exists, the function returns `true`, indicating that the current kernel is using the new tracepoint structure; otherwise, it returns `false`, indicating that it is using the old structure. The two different definitions are handled separately in the corresponding eBPF code, which is a common solution for adapting to changes between kernel versions.

### User State Code

The `biopattern` tool's userland code is responsible for reading statistics from the BPF mapping and presenting them to the user. In this way, system administrators can monitor the I/O patterns of each device in real time to better understand and optimise the I/O performance of the system.

1. Main loop

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

This is the main loop of the `biopattern` utility, and its workflow is as follows:

- **Wait**: use the `sleep` function to wait for the specified interval `(env.interval` ).
- `print_map`: call `print_map` function to print the statistics in BPF map.
- **Exit condition**: if an exit signal is received `(exiting` is `true` ) or if the specified number of runs is reached `(env.times` reaches 0), the loop exits.

Print mapping function:

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

The `print_map` function is responsible for reading statistics from the BPF map and printing them to the console. The main logic is as follows:

- **Traverse the BPF map**: Use the `bpf_map_get_next_key` and `bpf_map_lookup_elem` functions to traverse the BPF map and get the statistics for each device.
- **Calculate totals**: Calculate the total number of random and sequential I/Os for each device.
- **Print statistics**: If timestamp is enabled `(env.timestamp` is `true` ), the current time is printed first. Next, the device name, percentage of random I/O, percentage of sequential I/O, total I/O, and total data in KB are printed.
- **Cleaning up the BPF map**: For the next count, use the `bpf_map_get_next_key` and `bpf_map_delete_elem` functions to clean up all entries in the BPF map.

## Summary

In this tutorial, we have taken an in-depth look at how to use the eBPF tool biopattern to monitor and count random and sequential disk I/O in real-time. we started by understanding the importance of random and sequential disk I/O and their impact on system performance. We then describe in detail how biopattern works, including how to define and use BPF maps, how to deal with tracepoint variations in different versions of the Linux kernel, and how to capture and analyse disk I/O events in an eBPF program.

You can visit our tutorial code repository [at https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [at https://eunomia.dev/zh/tutorials/](https://eunomia.dev/zh/tutorials/) for more examples and a complete tutorial.

- Source repo：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/17-biopattern>
- bcc tool：<https://github.com/iovisor/bcc/blob/master/libbpf-tools/biopattern.c>

> The original link of this article: <https://eunomia.dev/tutorials/17-biopattern>
