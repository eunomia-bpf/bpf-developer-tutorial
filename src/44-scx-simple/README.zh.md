# eBPF 教程：BPF 调度器入门

欢迎来到我们深入探讨 eBPF 世界的教程，本教程将重点介绍 BPF 调度器！如果你希望将 eBPF 知识扩展到基础之外，你来对地方了。在本教程中，我们将探索 **scx_simple 调度器**，这是 Linux 内核版本 `6.12` 中引入的 sched_ext 调度类的一个最小示例。我们将带你了解其架构，如何利用 BPF 程序定义调度行为，并指导你编译和运行示例。到最后，你将对如何使用 eBPF 创建和管理高级调度策略有一个坚实的理解。

## 理解可扩展的 BPF 调度器

本教程的核心是 **sched_ext** 调度类。与传统调度器不同，sched_ext 允许通过一组 BPF 程序动态定义其行为，使其高度灵活和可定制。这意味着你可以在 sched_ext 之上实现任何调度算法，量身定制以满足你的特定需求。

### sched_ext 的关键特性

- **灵活的调度算法：** 通过编写 BPF 程序实现任何调度策略。
- **动态 CPU 分组：** BPF 调度器可以根据需要分组 CPU，无需在唤醒时将任务绑定到特定 CPU。
- **运行时控制：** 可在不重启的情况下即时启用或禁用 BPF 调度器。
- **系统完整性：** 即使 BPF 调度器遇到错误，系统也会优雅地回退到默认调度行为。
- **调试支持：** 通过 `sched_ext_dump` 跟踪点和 SysRq 键序列提供全面的调试信息。

凭借这些特性，sched_ext 为实验和部署高级调度策略提供了坚实的基础。

## 介绍 scx_simple：一个最小的 sched_ext 调度器

**scx_simple** 调度器是 Linux 工具中 sched_ext 调度器的一个简明示例。它设计简单易懂，并为更复杂的调度策略提供了基础。scx_simple 可以在两种模式下运行：

1. **全局加权虚拟时间 (vtime) 模式：** 根据任务的虚拟时间优先级排序，实现不同工作负载之间的公平调度。
2. **FIFO（先进先出）模式：** 基于简单队列的调度，任务按照到达顺序执行。

### 用例和适用性

scx_simple 在具有单插槽 CPU 和统一 L3 缓存拓扑的系统上尤其有效。虽然全局 FIFO 模式可以高效处理许多工作负载，但需要注意的是，饱和线程可能会压倒较不活跃的线程。因此，scx_simple 最适合在简单的调度策略能够满足性能和公平性要求的环境中使用。

### 生产就绪性

尽管 scx_simple 功能简洁，但在合适的条件下可以部署到生产环境中：

- **硬件约束：** 最适用于具有单插槽 CPU 和统一缓存架构的系统。
- **工作负载特性：** 适用于不需要复杂调度策略且可以受益于简单 FIFO 或加权 vtime 调度的工作负载。

## 代码深入：内核和用户空间分析

让我们深入探讨 scx_simple 在内核和用户空间中的实现。我们将首先展示完整的代码片段，然后分解其功能。

### 内核端实现

```c
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * 内置 DSQ 如 SCX_DSQ_GLOBAL 不能用作优先级队列
 * （意味着，不能用 scx_bpf_dispatch_vtime() 分派）。因此，我们
 * 创建一个 ID 为 0 的单独 DSQ 来分派和消费。如果 scx_simple
 * 只支持全局 FIFO 调度，那么我们可以直接使用 SCX_DSQ_GLOBAL。
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
        stat_inc(0); /* 统计本地队列 */
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1); /* 统计全局队列 */

    if (fifo_sched) {
        scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    } else {
        u64 vtime = p->scx.dsq_vtime;

        /*
         * 限制空闲任务可积累的预算量为一个切片。
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
     * 全局 vtime 随着任务开始执行而总是向前推进。测试和更新可以
     * 从多个 CPU 并发执行，因此存在竞争。如果有错误，应当被
     * 限制并且是临时的。让我们接受它。
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    if (fifo_sched)
        return;

    /*
     * 按照权重和费用的倒数缩放执行时间。
     *
     * 注意，默认的让出实现通过将 @p->scx.slice 设置为零来让出，
     * 以下操作将会将让出的任务视为已消耗所有切片。如果这对
     * 让出任务的惩罚过大，请通过显式时间戳来确定执行时间，
     * 而不是依赖于 @p->scx.slice。
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

#### 内核端分解

scx_simple 的内核端实现定义了如何选择、入队、分派和管理任务。以下是高层次的概述：

1. **初始化和许可：**
   - 调度器的许可证为 GPL。
   - 全局变量 `fifo_sched` 决定调度模式（FIFO 或加权 vtime）。

2. **分派队列（DSQ）管理：**
   - 创建一个共享的 DSQ（`SHARED_DSQ`，ID 为 0）用于任务分派。
   - 使用 `stats` 映射跟踪本地和全局队列中的任务数量。

3. **CPU 选择 (`simple_select_cpu`)：**
   - 为唤醒任务选择 CPU。
   - 如果选择的 CPU 处于空闲状态，任务将立即分派到本地 DSQ。

4. **任务入队 (`simple_enqueue`)：**
   - 根据 `fifo_sched` 标志，将任务分派到共享 DSQ 的 FIFO 模式或基于虚拟时间的优先级队列。
   - 虚拟时间 (`vtime`) 通过考虑任务执行时间和权重，确保公平调度。

5. **任务分派 (`simple_dispatch`)：**
   - 从共享 DSQ 消费任务并将其分配给 CPU。

6. **运行和停止任务 (`simple_running` & `simple_stopping`)：**
   - 管理任务的虚拟时间进度，确保调度决策的公平和平衡。

7. **启用和退出：**
   - 处理调度器的启用，并记录退出信息以便调试。

这种模块化结构使得 scx_simple 既简单又有效，提供了一个清晰的示例，展示如何使用 eBPF 实现自定义调度策略。

### 用户空间实现

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

#### 用户空间分解

用户空间组件负责与 BPF 调度器交互，管理其生命周期，并监控其性能。`read_stats` 函数通过读取 BPF 映射中的本地和全局队列任务数量来收集统计数据，并跨所有 CPU 聚合这些统计数据以进行报告。

在 `main` 函数中，程序初始化 libbpf，处理信号中断，并打开 scx_simple BPF 骨架。它处理命令行选项以切换 FIFO 调度和详细模式，加载 BPF 程序，并将其附加到调度器。监控循环每秒连续读取并打印调度统计数据，提供调度器行为的实时洞察。终止时，程序通过销毁 BPF 链接并根据退出代码处理潜在的重启来清理资源。

这个用户空间程序提供了一个简洁的接口，用于监控和控制 scx_simple 调度器，使得更容易实时理解其行为。

## 关键概念深入

为了充分理解 scx_simple 的运行机制，让我们探讨一些基础概念和机制：

### 分派队列（DSQs）

DSQs 是 sched_ext 运行的核心，充当任务在被分派到 CPU 之前的缓冲区。它们可以根据虚拟时间作为 FIFO 队列或优先级队列运行。

- **本地 DSQs (`SCX_DSQ_LOCAL`)：** 每个 CPU 都有自己的本地 DSQ，确保任务可以高效地分派和消费，而不会发生争用。
- **全局 DSQ (`SCX_DSQ_GLOBAL`)：** 一个共享队列，来自所有 CPU 的任务可以被排队，当本地队列为空时提供回退。
- **自定义 DSQs：** 开发者可以使用 `scx_bpf_create_dsq()` 创建额外的 DSQs，以满足更专业的调度需求。

### 虚拟时间（vtime）

虚拟时间是一种确保调度公平性的机制，通过跟踪任务相对于其权重消耗了多少时间来实现。在 scx_simple 的加权 vtime 模式下，权重较高的任务消耗虚拟时间的速度较慢，允许权重较低的任务更频繁地运行。这种方法基于预定义的权重平衡任务执行，确保没有单个任务垄断 CPU 资源。

### 调度周期

理解调度周期对于修改或扩展 scx_simple 至关重要。以下步骤详细说明了唤醒任务的调度和执行过程：

1. **任务唤醒和 CPU 选择：**
   - 当一个任务被唤醒时，首先调用 `ops.select_cpu()`。
   - 该函数有两个目的：
     - **CPU 选择优化提示：** 提供建议的 CPU 供任务运行。虽然这是一个优化提示而非绑定，但如果 `ops.select_cpu()` 返回的 CPU 与任务最终运行的 CPU 匹配，可以带来性能提升。
     - **唤醒空闲 CPU：** 如果选择的 CPU 处于空闲状态，`ops.select_cpu()` 可以唤醒它，为执行任务做好准备。
   - 注意：如果 CPU 选择无效（例如，超出任务允许的 CPU 掩码），调度器核心将忽略该选择。

2. **从 `ops.select_cpu()` 立即分派：**
   - 任务可以通过调用 `scx_bpf_dispatch()` 直接从 `ops.select_cpu()` 分派到分派队列（DSQ）。
   - 如果分派到 `SCX_DSQ_LOCAL`，任务将被放入 `ops.select_cpu()` 返回的 CPU 的本地 DSQ。
   - 直接从 `ops.select_cpu()` 分派将导致跳过 `ops.enqueue()` 回调，可能减少调度延迟。

3. **任务入队 (`ops.enqueue()`)：**
   - 如果任务未在上一步被分派，`ops.enqueue()` 将被调用。
   - `ops.enqueue()` 可以做出以下几种决定：
     - **立即分派：** 通过调用 `scx_bpf_dispatch()` 将任务分派到全局 DSQ（`SCX_DSQ_GLOBAL`）、本地 DSQ（`SCX_DSQ_LOCAL`）或自定义 DSQ。
     - **在 BPF 端排队：** 在 BPF 程序中排队任务，以便进行自定义调度逻辑。

4. **CPU 调度准备：**
   - 当 CPU 准备好调度时，它按照以下顺序进行：
     - **检查本地 DSQ：** CPU 首先检查其本地 DSQ 是否有任务。
     - **检查全局 DSQ：** 如果本地 DSQ 为空，则检查全局 DSQ。
     - **调用 `ops.dispatch()`：** 如果仍然没有找到任务，调用 `ops.dispatch()` 来填充本地 DSQ。
       - 在 `ops.dispatch()` 内，可以使用以下函数：
         - `scx_bpf_dispatch()`：将任务调度到任何 DSQ（本地、全局或自定义）。注意，该函数目前不能在持有 BPF 锁时调用。
         - `scx_bpf_consume()`：将任务从指定的非本地 DSQ 转移到分派 DSQ。该函数不能在持有任何 BPF 锁时调用，并且会在尝试消费指定 DSQ 之前刷新待分派的任务。

5. **任务执行决策：**
   - `ops.dispatch()` 返回后，如果本地 DSQ 中有任务，CPU 将运行第一个任务。
   - 如果本地 DSQ 仍为空，CPU 将执行以下步骤：
     - **消费全局 DSQ：** 尝试使用 `scx_bpf_consume()` 从全局 DSQ 消费任务。如果成功，执行该任务。
     - **重试分派：** 如果 `ops.dispatch()` 已经分派了任何任务，CPU 将重试检查本地 DSQ。
     - **执行前一个任务：** 如果前一个任务是 SCX 任务且仍然可运行，CPU 将继续执行它（参见 `SCX_OPS_ENQ_LAST`）。
     - **进入空闲状态：** 如果没有可用任务，CPU 将进入空闲状态。

这种调度周期确保任务高效调度，同时保持公平性和响应性。通过理解每一步，开发者可以修改或扩展 scx_simple，以实现满足特定需求的自定义调度行为。

## 编译和运行 scx_simple

要运行 scx_simple，需要设置必要的工具链并正确配置内核。以下是编译和执行示例调度器的方法。

### 工具链依赖

在编译 scx_simple 之前，请确保已安装以下工具：

1. **clang >= 16.0.0**  
   编译 BPF 程序所需。虽然 GCC 正在开发 BPF 支持，但它缺乏某些必要功能，如 BTF 类型标签。

2. **pahole >= 1.25**  
   用于从 DWARF 生成 BTF，对于 BPF 程序中的类型信息至关重要。

3. **rust >= 1.70.0**  
   如果你正在使用基于 Rust 的调度器，请确保拥有适当的 Rust 工具链版本。

此外，还需要 `make` 等工具来构建示例。

### 内核配置

要启用和使用 sched_ext，请确保设置了以下内核配置选项：

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

这些配置启用了 BPF 调度所需的功能，并确保 sched_ext 正常运行。

### 构建 scx_simple

导航到内核的 `tools/sched_ext/` 目录并运行：

```bash
make
```

此命令将编译 scx_simple 调度器及其依赖项。

### 运行 scx_simple

编译完成后，可以执行用户空间程序来加载和监控调度器：

```bash
./scx_simple -f
```

`-f` 标志启用 FIFO 调度模式。你还可以使用 `-v` 进行详细输出，或使用 `-h` 获取帮助。当程序运行时，它将每秒显示本地和全局队列中的任务数量：

```plaintext
local=123 global=456
local=124 global=457
...
```

### 在 sched_ext 和 CFS 之间切换

sched_ext 与默认的完全公平调度器（CFS）并行运行。你可以通过加载或卸载 scx_simple 程序动态切换 sched_ext 和 CFS。

- **启用 sched_ext：** 使用 scx_simple 加载 BPF 调度器。
- **禁用 sched_ext：** 终止 scx_simple 程序，将所有任务恢复到 CFS。

此外，使用 SysRq 键序列如 `SysRq-S` 可以帮助管理调度器的状态，并使用 `SysRq-D` 触发调试转储。

## 总结与下一步

在本教程中，我们介绍了 **sched_ext** 调度类，并通过一个最小示例 **scx_simple** 展示了如何使用 eBPF 程序定义自定义调度行为。我们涵盖了架构、关键概念如 DSQs 和虚拟时间，并提供了编译和运行调度器的分步说明。

掌握 scx_simple 后，你将具备设计和实现更复杂调度策略的能力，以满足特定需求。无论你是优化性能、公平性，还是针对特定工作负载特性，sched_ext 和 eBPF 都提供了实现目标所需的灵活性和强大功能。

> 准备好将你的 eBPF 技能提升到新的水平了吗？深入探索我们的教程并通过访问我们的 [教程仓库 https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或 [网站 https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/) 探索更多示例。

## 参考资料

- **sched_ext 仓库：** [https://github.com/sched-ext/scx](https://github.com/sched-ext/scx)
- **Linux 内核文档：** [Scheduler Ext Documentation](https://www.kernel.org/doc/html/next/scheduler/sched-ext.html)
- **内核源代码树：** [Linux Kernel sched_ext Tools](https://github.com/torvalds/linux/tree/master/tools/sched_ext)
- **eBPF 官方文档：** [https://ebpf.io/docs/](https://ebpf.io/docs/)
- **libbpf 文档：** [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)

