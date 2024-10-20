# eBPF Tutorial: Introduction to the BPF Scheduler

Welcome to our deep dive into the world of eBPF with a focus on the BPF scheduler! If you're looking to extend your eBPF knowledge beyond the basics, you're in the right place. 

In this tutorial, we'll explore the **scx_simple scheduler**, a minimal example of the sched_ext scheduler class introduced in Linux kernel version `6.12`. We'll walk you through its architecture, how it leverages BPF programs to define scheduling behavior, and guide you through compiling and running the example. By the end, you'll have a solid understanding of how to create and manage advanced scheduling policies using eBPF.

## Understanding the Extensible BPF Scheduler

At the heart of this tutorial is the **sched_ext** scheduler class. Unlike traditional schedulers, sched_ext allows its behavior to be defined dynamically through a set of BPF programs, making it highly flexible and customizable. This means you can implement any scheduling algorithm on top of sched_ext, tailored to your specific needs.

### Key Features of sched_ext

**sched_ext** offers flexible scheduling algorithms by allowing the implementation of any scheduling policy through BPF programs. It supports dynamic CPU grouping, enabling the BPF scheduler to group CPUs as needed without binding tasks to specific CPUs upon wakeup. The scheduler can be enabled or disabled at runtime without requiring a system reboot. In terms of system integrity, if the BPF scheduler encounters errors, the system gracefully reverts to the default scheduling behavior. Additionally, sched_ext provides comprehensive debugging support through the `sched_ext_dump` tracepoint and SysRq key sequences.

With these features, sched_ext provides a robust foundation for experimenting with and deploying advanced scheduling strategies.

## Introducing scx_simple: A Minimal sched_ext Scheduler

The **scx_simple** scheduler is a straightforward example of a sched_ext scheduler in the Linux tools. It's designed to be easy to understand and serves as a foundation for more complex scheduling policies. scx_simple can operate in two modes: **Global Weighted Virtual Time (vtime) Mode**, which prioritizes tasks based on their virtual time, allowing for fair scheduling across different workloads, and **FIFO (First-In-First-Out) Mode**, a simple queue-based scheduling where tasks are executed in the order they arrive.

scx_simple is particularly effective on single-socket CPUs with a uniform L3 cache topology. While the global FIFO mode can handle many workloads efficiently, it's essential to note that saturating threads might overshadow less active ones. Therefore, scx_simple is best suited for environments where a straightforward scheduling policy meets the performance and fairness requirements.

While scx_simple is minimalistic, it can be deployed in production settings under the right conditions. It is best suited for systems with single-socket CPUs and uniform cache architectures. Additionally, it is ideal for workloads that don't require intricate scheduling policies and can benefit from simple FIFO or weighted vtime scheduling.

## Into the Code: Kernel and User-Space Analysis

Let's explore how scx_simple is implemented both in the kernel and user-space. We'll start by presenting the complete code snippets and then break down their functionalities.

### Kernel-Side Implementation

```c
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could
 * just use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2);   /* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
    return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle) {
        stat_inc(0); /* count local queueing */
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1); /* count global queueing */

    if (fifo_sched) {
        scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    } else {
        u64 vtime = p->scx.dsq_vtime;

        /*
         * Limit the amount of budget that an idling task can accumulate
         * to one slice.
         */
        if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
            vtime = vtime_now - SCX_SLICE_DFL;

        scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
                       enq_flags);
    }
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    if (fifo_sched)
        return;

    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    if (fifo_sched)
        return;

    /*
     * Scale the execution time by the inverse of the weight and charge.
     *
     * Note that the default yield implementation yields by setting
     * @p->scx.slice to zero and the following would treat the yielding task
     * as if it has consumed all its slice. If this penalizes yielding tasks
     * too much, determine the execution time by taking explicit timestamps
     * instead of depending on @p->scx.slice.
     */
    p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
           .select_cpu  = (void *)simple_select_cpu,
           .enqueue   = (void *)simple_enqueue,
           .dispatch  = (void *)simple_dispatch,
           .running   = (void *)simple_running,
           .stopping  = (void *)simple_stopping,
           .enable   = (void *)simple_enable,
           .init   = (void *)simple_init,
           .exit   = (void *)simple_exit,
           .name   = "simple");
```

#### Kernel-Side Breakdown

The kernel-side implementation of scx_simple defines how tasks are selected, enqueued, dispatched, and managed. Here's a high-level overview:

**Initialization and Licensing:** The scheduler is licensed under GPL. A global variable `fifo_sched` determines the scheduling mode (FIFO or weighted vtime).

**Dispatch Queue (DSQ) Management:** A shared DSQ (`SHARED_DSQ`) with ID 0 is created to handle task dispatching. A `stats` map tracks the number of tasks queued locally and globally.

**CPU Selection (`simple_select_cpu`):** This function selects the CPU for a waking task. If the selected CPU is idle, the task is immediately dispatched to the local DSQ.

**Task Enqueueing (`simple_enqueue`):** Depending on the `fifo_sched` flag, tasks are either dispatched to the shared DSQ in FIFO mode or to a priority queue based on virtual time. Virtual time (`vtime`) ensures fair scheduling by accounting for task execution time and weight.

**Task Dispatching (`simple_dispatch`):** This function consumes tasks from the shared DSQ and assigns them to CPUs.

**Running and Stopping Tasks (`simple_running` & `simple_stopping`):** These functions manage the progression of virtual time for tasks, ensuring that scheduling decisions remain fair and balanced.

**Enabling and Exiting:** Handles the enabling of the scheduler and records exit information for debugging.

This modular structure allows scx_simple to be both simple and effective, providing a clear example of how to implement custom scheduling policies using eBPF.

### User-Space Implementation

```c
static void read_stats(struct scx_simple *skel, __u64 *stats)
{
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 cnts[2][nr_cpus];
    __u32 idx;

    memset(stats, 0, sizeof(stats[0]) * 2);

    for (idx = 0; idx < 2; idx++) {
        int ret, cpu;

        ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
                      &idx, cnts[idx]);
        if (ret < 0)
            continue;
        for (cpu = 0; cpu < nr_cpus; cpu++)
            stats[idx] += cnts[idx][cpu];
    }
}

int main(int argc, char **argv)
{
    struct scx_simple *skel;
    struct bpf_link *link;
    __u32 opt;
    __u64 ecode;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
restart:
    skel = SCX_OPS_OPEN(simple_ops, scx_simple);

    while ((opt = getopt(argc, argv, "fvh")) != -1) {
        switch (opt) {
        case 'f':
            skel->rodata->fifo_sched = true;
            break;
        case 'v':
            verbose = true;
            break;
        default:
            fprintf(stderr, help_fmt, basename(argv[0]));
            return opt != 'h';
        }
    }

    SCX_OPS_LOAD(skel, simple_ops, scx_simple, uei);
    link = SCX_OPS_ATTACH(skel, simple_ops, scx_simple);

    while (!exit_req && !UEI_EXITED(skel, uei)) {
        __u64 stats[2];

        read_stats(skel, stats);
        printf("local=%llu global=%llu\n", stats[0], stats[1]);
        fflush(stdout);
        sleep(1);
    }

    bpf_link__destroy(link);
    ecode = UEI_REPORT(skel, uei);
    scx_simple__destroy(skel);

    if (UEI_ECODE_RESTART(ecode))
        goto restart;
    return 0;
}
```

The complete code can be found in <https://github.com/eunomia-bpf/bpf-developer-tutorial>

#### User-Space Breakdown

The user-space component is responsible for interacting with the BPF scheduler, managing its lifecycle, and monitoring its performance.

**Statistics Collection (`read_stats`):** This function reads the number of tasks queued locally and globally from the BPF maps and aggregates statistics across all CPUs for reporting.

**Main Function Workflow:** The main function sets up libbpf, handles signal interrupts, and opens the scx_simple BPF skeleton. It processes command-line options to toggle FIFO scheduling and verbosity, loads the BPF program, and attaches it to the scheduler. The program enters a monitoring loop where it continuously reads and prints scheduling statistics every second. Upon termination, it cleans up by destroying BPF links and handling potential restarts based on exit codes.

This user-space program provides a straightforward interface to monitor and control the scx_simple scheduler, making it easier to understand its behavior in real-time.

## Deep Dive into Key Concepts

To fully grasp how scx_simple operates, let's explore some of the underlying concepts and mechanisms.

### Dispatch Queues (DSQs)

DSQs are central to sched_ext's operation, acting as buffers where tasks are queued before being dispatched to CPUs. They can function as either FIFO queues or priority queues based on virtual time.

Local DSQs (`SCX_DSQ_LOCAL`) ensure that each CPU has its own queue, allowing tasks to be dispatched and consumed efficiently without contention. The Global DSQ (`SCX_DSQ_GLOBAL`) serves as a shared queue where tasks from all CPUs can be queued, providing a fallback when local queues are empty. Developers can also create custom DSQs using `scx_bpf_create_dsq()` for more specialized scheduling needs.

### Virtual Time (vtime)

Virtual time is a mechanism to ensure fairness in scheduling by tracking how much time a task has consumed relative to its weight. In scx_simple's weighted vtime mode, tasks with higher weights consume virtual time more slowly, allowing lower-weighted tasks to run more frequently.

### Scheduling Cycle

Understanding the scheduling cycle is crucial for modifying or extending scx_simple. The following steps detail how a waking task is scheduled and executed:

**Task Wakeup and CPU Selection:** When a task wakes up, `ops.select_cpu()` is invoked. This function provides a suggested CPU for the task to run on and can wake up idle CPUs to prepare them for task execution. If the selected CPU is idle, the task is immediately dispatched to the local DSQ, potentially reducing scheduling latency.

**Immediate Dispatch from `ops.select_cpu()`:** A task can be dispatched directly to a Dispatch Queue (DSQ) from `ops.select_cpu()`. If dispatched to `SCX_DSQ_LOCAL`, the task is placed in the local DSQ of the selected CPU, skipping the `ops.enqueue()` callback.

**Task Enqueueing (`ops.enqueue()`):** If the task was not dispatched in the previous step, `ops.enqueue()` is invoked. This function can dispatch the task to the global DSQ, a local DSQ, or a custom DSQ based on the `fifo_sched` flag and virtual time calculations.

**CPU Scheduling Readiness:** When a CPU is ready to schedule, it first checks its local DSQ for tasks. If the local DSQ is empty, it checks the global DSQ. If no tasks are found, `ops.dispatch()` is invoked to populate the local DSQ. After dispatching, if tasks are available in the local DSQ, the CPU executes the first one. If not, it may attempt to consume a task from the global DSQ or go idle.

This scheduling cycle ensures that tasks are scheduled efficiently while maintaining fairness and responsiveness. By understanding each step, developers can modify or extend scx_simple to implement custom scheduling behaviors that meet specific requirements.

## Compiling and Running scx_simple

Getting scx_simple up and running involves setting up the necessary toolchain and configuring the kernel appropriately. Here's how you can compile and execute the example scheduler.

### Toolchain Dependencies

Before compiling scx_simple, ensure you have the following tools installed:

- **clang >= 16.0.0:** Required for compiling BPF programs. GCC is working on BPF support but lacks essential features like BTF type tags necessary for certain functionalities.
- **pahole >= 1.25:** Used to generate BTF from DWARF, crucial for type information in BPF programs.
- **rust >= 1.70.0:** If you're working with Rust-based schedulers, ensure you have the appropriate Rust toolchain version.
  
Additionally, tools like `make` are required for building the examples.

### Kernel Configuration

To enable and use sched_ext, ensure the following kernel configuration options are set:

```plaintext
CONFIG_BPF=y
CONFIG_SCHED_CLASS_EXT=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_PAHOLE_HAS_BTF_TAG=y
```

These configurations enable the necessary features for BPF scheduling and ensure that sched_ext operates correctly.

### Building scx_simple

Navigate to the kernel's `tools/sched_ext/` directory and run:

```bash
make
```

This command compiles the scx_simple scheduler along with its dependencies.

### Running scx_simple

Once compiled, execute the user-space program to load and monitor the scheduler:

```bash
./scx_simple -f
```

The `-f` flag enables FIFO scheduling mode. You can also use `-v` for verbose output or `-h` for help.

As the program runs, it will display the number of tasks queued locally and globally every second:

```plaintext
local=123 global=456
local=124 global=457
...
```

### Switching Between sched_ext and CFS

sched_ext operates alongside the default Completely Fair Scheduler (CFS). You can switch between sched_ext and CFS dynamically. To enable sched_ext, load the BPF scheduler using scx_simple. To disable sched_ext, terminate the scx_simple program, reverting all tasks back to CFS. Additionally, using SysRq key sequences like `SysRq-S` can help manage the scheduler's state and trigger debug dumps with `SysRq-D`.

## Summary and Next Steps

In this tutorial, we've introduced the **sched_ext** scheduler class and walked through a minimal example, **scx_simple**, demonstrating how to define custom scheduling behaviors using eBPF programs. We've covered the architecture, key concepts like DSQs and virtual time, and provided step-by-step instructions for compiling and running the scheduler.

By mastering scx_simple, you're well-equipped to design and implement more sophisticated scheduling policies tailored to your specific requirements. Whether you're optimizing for performance, fairness, or specific workload characteristics, sched_ext and eBPF offer the flexibility and power to achieve your goals.

> Ready to take your eBPF skills to the next level? Dive deeper into our tutorials and explore more examples by visiting our [tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our [website](https://eunomia.dev/tutorials/).

## References

- **sched_ext Repository:** [https://github.com/sched-ext/scx](https://github.com/sched-ext/scx)
- **Linux Kernel Documentation:** [Scheduler Ext Documentation](https://www.kernel.org/doc/html/next/scheduler/sched-ext.html)
- **Kernel Source Tree:** [Linux Kernel sched_ext Tools](https://github.com/torvalds/linux/tree/master/tools/sched_ext)
- **eBPF Official Documentation:** [https://ebpf.io/docs/](https://ebpf.io/docs/)
- **libbpf Documentation:** [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)

Feel free to explore these resources to expand your understanding and continue your journey into advanced eBPF programming!
