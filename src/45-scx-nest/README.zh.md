# eBPF 示例教程：实现 `scx_nest` 调度器

在系统性能优化不断发展的领域中，自定义和扩展内核行为的能力是非常宝贵的。实现这一目标的最强大工具之一是 eBPF（扩展的 Berkeley 包过滤器）。在本教程中，我们将探讨 `scx_nest` 调度器的实现，这是一个先进的 eBPF 程序，利用了在 Linux 内核版本 `6.12` 中引入的 `sched_ext` 调度器类。在本指南结束时，您将了解如何构建一个复杂的调度器，该调度器根据 CPU 核心频率和利用率动态调整任务分配。

## `sched_ext` 介绍

`sched_ext` 调度器类标志着 Linux 内核调度能力的重大进步。与传统调度器不同，`sched_ext` 允许通过一组 BPF（Berkeley 包过滤器）程序动态定义其行为。这种灵活性使开发人员能够实现针对特定工作负载和系统需求量身定制的自定义调度算法。

## 理解 `scx_nest` 调度器

### 概述

`scx_nest` 调度器受 Inria Paris 论文《[OS Scheduling with Nest: Keeping Tasks Close Together on Warm Cores](https://hal.inria.fr/hal-03612592/file/paper.pdf)》的启发。由 Meta Platforms, Inc. 开发，`scx_nest` 专注于鼓励将任务分配到基于最近使用模式可能以更高频率运行的 CPU 核心上。这种方法旨在通过确保任务在最有效的核心上执行来优化性能。

该调度器作为一个全局加权虚拟时间（vtime）调度器运行，类似于完全公平调度器（CFS），同时利用 Nest 算法在任务唤醒时选择空闲核心。这种双重策略确保任务不仅被公平分配，还被放置在能够最有效执行它们的核心上。

`scx_nest` 旨在优化 CPU 利用率相对较低且可以受益于在少数核心上运行的工作负载。通过将任务集中在较少的核心上，调度器有助于保持这些核心的高频率，从而提升性能。然而，对于那些在分布到多个核心以避免缓存抖动时表现更好的工作负载，`scx_nest` 可能并不是理想选择。评估 `scx_nest` 对特定工作负载的适用性通常需要实验。

鉴于其设计，`scx_nest` 适用于生产环境，前提是满足硬件限制。它在具有统一 L3 缓存拓扑的单个 CCX（核心复合体）或单插槽主机上表现最佳。虽然当前版本未实现抢占，但所有 CPU 共享的调度队列确保队列前端的任务能够及时执行，前提是有足够的 CPU 可用。

## 高级代码分析

`scx_nest` 调度器的实现复杂，涉及各种数据结构、映射和函数，它们协同工作以管理任务分配和 CPU 核心利用率。完整的源代码可在 [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 仓库中找到。下面，我们将剖析调度器的核心组件，详细解释每个部分。

### 核心数据结构和映射

#### 任务上下文 (`task_ctx`)

系统中的每个任务都有一个关联的上下文，用于维护与调度相关的信息。这个上下文对于基于任务的历史和当前状态做出明智的调度决策至关重要。

```c
/* 每个任务的调度上下文 */
struct task_ctx {
    /*
     * 用于计算任务的主掩码和保留掩码的临时 cpumask。
     */
    struct bpf_cpumask __kptr *tmp_mask;

    /*
     * 任务观察到其之前的核心不为空闲的次数。如果连续发生 r_impatient 次，
     * 将尝试从保留 Nest 或回退 Nest 中获取一个核心。
     */
    u32 prev_misses;

    /*
     * 任务“附加”的核心，意味着它至少连续在该核心上执行了两次，
     * 并且在唤醒时首先尝试迁移到该核心。任务只有在附加核心空闲且
     * 在主 Nest 中时才会迁移到附加核心。
     */
    s32 attached_core;

    /*
     * 任务上次执行的核心。这用于确定任务是否应该附加到下一个
     * 执行的核心。
     */
    s32 prev_cpu;
};
```

`task_ctx` 结构体包含一个临时 CPU 掩码 (`tmp_mask`)，用于计算任务的主 CPU 集合和保留 CPU 集合。`prev_misses` 计数器跟踪任务的首选核心不为空闲的次数，影响迁移任务到不同核心的决策。`attached_core` 指示任务当前绑定的核心，确保在可能的情况下在高频率核心上运行。最后，`prev_cpu` 记录任务上次执行的核心，有助于维护任务与核心的亲和性。

#### 每 CPU 上下文 (`pcpu_ctx`)

每个 CPU 都有一个关联的上下文，用于管理定时器和压缩状态。这个上下文有助于确定何时由于不活动而将核心从主 Nest 中降级。

```c
struct pcpu_ctx {
    /* 用于从主 Nest 中压缩核心的定时器。 */
    struct bpf_timer timer;

    /* 当前核心是否已安排进行压缩。 */
    bool scheduled_compaction;
};
```

`pcpu_ctx` 结构体包含一个 `bpf_timer`，用于调度压缩事件，以及一个布尔标志 `scheduled_compaction`，指示是否已为核心安排了压缩。

#### 映射

多个 BPF 映射用于存储上下文和管理定时器：

```c
/* 任务存储映射 */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* 每 CPU 上下文 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");

/* 统计定时器 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stats_timer);
} stats_timer SEC(".maps");
```

- **`task_ctx_stor`:** 该映射存储每个任务的调度上下文，使调度器能够访问和修改特定任务的信息。
- **`pcpu_ctxs`:** 一个数组映射，保存每个 CPU 的上下文，使调度器能够管理每个 CPU 的定时器和压缩状态。
- **`stats_timer`:** 一个单条目的数组映射，用于管理用于收集调度统计信息的中央定时器。

此外，调度器维护了主 CPU 掩码、保留 CPU 掩码、其他 CPU 掩码和空闲 CPU 掩码，以及用于跟踪各种调度器指标的统计映射。

### 核心函数

#### `stat_inc`

一个辅助函数，用于递增调度统计数据：

```c
static __always_inline void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}
```

此函数在 `stats` 映射中查找一个计数器，并在计数器存在时递增它。调度器在各处使用它来跟踪各种事件和状态。

#### `vtime_before`

一个用于比较虚拟时间的实用函数：

```c
static inline bool vtime_before(u64 a, u64 b)
{
    return (s64)(a - b) < 0;
}
```

此函数确定虚拟时间 `a` 是否在 `b` 之前，有助于基于时间的调度决策。

#### `try_make_core_reserved`

尝试将一个核心提升为保留 Nest：

```c
static __always_inline void
try_make_core_reserved(s32 cpu, struct bpf_cpumask * reserved, bool promotion)
{
    s32 tmp_nr_reserved;

    /*
     * 此检查存在竞争，但没关系。如果我们错误地未能将核心提升到保留，
     * 那是因为另一个上下文在这个小窗口中添加或移除了保留中的核心。
     * 这将在随后的唤醒中平衡。
     */
    tmp_nr_reserved = nr_reserved;
    if (tmp_nr_reserved < r_max) {
        /*
         * 这里有可能暂时超过 r_max，但随着更多核心被降级或未能
         * 被提升到保留 Nest，应该会平衡。
         */
        __sync_fetch_and_add(&nr_reserved, 1);
        bpf_cpumask_set_cpu(cpu, reserved);
        if (promotion)
            stat_inc(NEST_STAT(PROMOTED_TO_RESERVED));
        else
            stat_inc(NEST_STAT(DEMOTED_TO_RESERVED));
    } else {
        bpf_cpumask_clear_cpu(cpu, reserved);
        stat_inc(NEST_STAT(RESERVED_AT_CAPACITY));
    }
}
```

`try_make_core_reserved` 函数尝试将一个 CPU 核心添加到保留掩码中。首先检查保留核心的数量 (`nr_reserved`) 是否低于允许的最大值 (`r_max`)。如果是，则递增 `nr_reserved` 计数器并将核心添加到保留掩码中。根据核心是被提升还是降级，递增相应的统计数据。如果保留容量已满，则从保留掩码中清除核心并更新相关统计数据。

#### `update_attached`

根据最近的执行更新任务的附加核心：

```c
static void update_attached(struct task_ctx *tctx, s32 prev_cpu, s32 new_cpu)
{
    if (tctx->prev_cpu == new_cpu)
        tctx->attached_core = new_cpu;
    tctx->prev_cpu = prev_cpu;
}
```

此函数更新任务的 `attached_core`。如果任务连续在同一核心上执行，它会将任务附加到该核心。然后更新 `prev_cpu` 以反映任务最近运行的核心。

#### `compact_primary_core`

处理主核心的压缩，将其降级到保留 Nest：

```c
static int compact_primary_core(void *map, int *key, struct bpf_timer *timer)
{
    struct bpf_cpumask *primary, *reserve;
    s32 cpu = bpf_get_smp_processor_id();
    struct pcpu_ctx *pcpu_ctx;

    stat_inc(NEST_STAT(CALLBACK_COMPACTED));

    /*
     * 如果我们到达此回调，这意味着定时器回调从未被取消，
     * 因此需要将核心从主 Nest 中降级。
     */
    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (!pcpu_ctx) {
        scx_bpf_error("无法查找 pcpu ctx");
        return 0;
    }
    bpf_rcu_read_lock();
    primary = primary_cpumask;
    reserve = reserve_cpumask;
    if (!primary || !reserve) {
        scx_bpf_error("无法找到 primary 或 reserve");
        bpf_rcu_read_unlock();
        return 0;
    }

    bpf_cpumask_clear_cpu(cpu, primary);
    try_make_core_reserved(cpu, reserve, false);
    bpf_rcu_read_unlock();
    pcpu_ctx->scheduled_compaction = false;
    return 0;
}
```

当压缩定时器到期时，将调用 `compact_primary_core`。它通过从主掩码中清除当前 CPU 核心并尝试将其添加到保留掩码中，将当前 CPU 核心从主 Nest 降级到保留 Nest。这确保了不活动的核心得到有效管理，保持性能和资源利用之间的平衡。

#### `nest_select_cpu`

在任务唤醒时确定适当的 CPU：

```c
s32 BPF_STRUCT_OPS(nest_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    struct bpf_cpumask *p_mask, *primary, *reserve;
    s32 cpu;
    struct task_ctx *tctx;
    struct pcpu_ctx *pcpu_ctx;
    bool direct_to_primary = false, reset_impatient = true;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return -ENOENT;

    bpf_rcu_read_lock();
    p_mask = tctx->tmp_mask;
    primary = primary_cpumask;
    reserve = reserve_cpumask;
    if (!p_mask || !primary || !reserve) {
        bpf_rcu_read_unlock();
        return -ENOENT;
    }

    tctx->prev_cpu = prev_cpu;

    bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(primary));

    /* 首先尝试在附加核心上唤醒任务。 */
    if (bpf_cpumask_test_cpu(tctx->attached_core, cast_mask(p_mask)) &&
        scx_bpf_test_and_clear_cpu_idle(tctx->attached_core)) {
        cpu = tctx->attached_core;
        stat_inc(NEST_STAT(WAKEUP_ATTACHED));
        goto migrate_primary;
    }

    /*
     * 如果之前的核心在主集合中，并且没有 hypertwin，则尝试留在之前的核心。
     * 如果之前的核心是任务附加的核心，不需要再尝试，因为我们已经在上面尝试过了。
     */
    if (prev_cpu != tctx->attached_core &&
        bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask)) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        cpu = prev_cpu;
        stat_inc(NEST_STAT(WAKEUP_PREV_PRIMARY));
        goto migrate_primary;
    }

    if (find_fully_idle) {
        /* 然后尝试在主集合中选择任何完全空闲的核心。 */
        cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
                                    SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_PRIMARY));
            goto migrate_primary;
        }
    }

    /* 然后尝试在主集合中选择任何空闲的核心，即使其 hypertwin 正在活动。 */
    cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
    if (cpu >= 0) {
        stat_inc(NEST_STAT(WAKEUP_ANY_IDLE_PRIMARY));
        goto migrate_primary;
    }

    if (r_impatient > 0 && ++tctx->prev_misses >= r_impatient) {
        direct_to_primary = true;
        tctx->prev_misses = 0;
        stat_inc(NEST_STAT(TASK_IMPATIENT));
    }

    reset_impatient = false;

    /* 然后尝试在保留集合中选择任何完全空闲的核心。 */
    bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(reserve));
    if (find_fully_idle) {
        cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
                                    SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_RESERVE));
            goto promote_to_primary;
        }
    }

    /* 然后尝试在保留集合中选择任何空闲的核心，即使其 hypertwin 正在活动。 */
    cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
    if (cpu >= 0) {
        stat_inc(NEST_STAT(WAKEUP_ANY_IDLE_RESERVE));
        goto promote_to_primary;
    }

    /* 然后尝试在任务的 cpumask 中选择任何空闲的核心。 */
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
        /*
         * 我们找到了一个核心（我们认为它不在任何 Nest 中）。
         * 这意味着我们需要将该核心提升到保留 Nest，或者如果由于
         * 超过 r_impatient 而直接提升到主 Nest。
         *
         * 我们必须在这里进行最后一次检查，看看核心是否在主掩码或保留掩码中，
         * 因为我们可能与核心在将主掩码和保留掩码与 p->cpus_ptr 进行 AND
         * 运算之间更改状态，并使用 scx_bpf_pick_idle_cpu() 原子性地保留它。
         * 这在上面的检查中技术上也是如此，但在那些情况下我们只是直接
         * 将核心放入主掩码中，因此问题不大。在这里，我们要确保不会
         * 意外地将已经在主掩码中的核心放入保留 Nest 中。这是不太可能的，
         * 但我们在应该相对冷路径上进行了检查。
         */
        stat_inc(NEST_STAT(WAKEUP_IDLE_OTHER));
        if (bpf_cpumask_test_cpu(cpu, cast_mask(primary)))
            goto migrate_primary;
        else if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve)))
            goto promote_to_primary;
        else if (direct_to_primary)
            goto promote_to_primary;
        else
            try_make_core_reserved(cpu, reserve, true);
        bpf_rcu_read_unlock();
        return cpu;
    }

    bpf_rcu_read_unlock();
    return prev_cpu;

promote_to_primary:
    stat_inc(NEST_STAT(PROMOTED_TO_PRIMARY));
migrate_primary:
    if (reset_impatient)
        tctx->prev_misses = 0;
    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (pcpu_ctx) {
        if (pcpu_ctx->scheduled_compaction) {
            if (bpf_timer_cancel(&pcpu_ctx->timer) < 0)
                scx_bpf_error("取消 pcpu 定时器失败");
            if (bpf_timer_set_callback(&pcpu_ctx->timer, compact_primary_core))
                scx_bpf_error("重新设置 pcpu 定时器回调失败");
            pcpu_ctx->scheduled_compaction = false;
            stat_inc(NEST_STAT(CANCELLED_COMPACTION));
        }
    } else {
        scx_bpf_error("查找 pcpu ctx 失败");
    }
    bpf_cpumask_set_cpu(cpu, primary);
    /*
     * 检查 CPU 是否在保留掩码中。如果是，这可能发生在核心在我们尝试
     * 将当前唤醒任务分配到其上时被并发地压缩。同样，如果我们在
     * 由于超时直接提升到主 Nest，也会发生这种情况。
     *
     * 我们不必担心与其他唤醒任务的竞争，因为我们已经通过（某种
     * 变体的）scx_bpf_pick_idle_cpu() 原子性地保留了该核心。
     */
    if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve))) {
        __sync_sub_and_fetch(&nr_reserved, 1);
        bpf_cpumask_clear_cpu(cpu, reserve);
    }
    bpf_rcu_read_unlock();
    update_attached(tctx, prev_cpu, cpu);
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
    return cpu;
}
```

`nest_select_cpu` 函数是 `scx_nest` 调度器的核心。当任务唤醒时，此函数确定其执行最合适的 CPU 核心。该函数遵循一系列检查，以确保任务被放置在高频率、空闲的核心上，从而提升效率和性能。

最初，它从 `task_ctx_stor` 映射中检索任务的上下文。然后，它锁定读拷贝更新（RCU）锁，以安全地访问主掩码和保留掩码。调度器首先尝试将任务放置在其附加核心上，确保核心亲和性。如果附加核心不空闲，它会尝试先前的核心。根据各种条件，包括任务的急躁程度 (`r_impatient`) 和主 Nest 及保留 Nest 中空闲核心的可用性，调度器决定是否迁移任务、将核心提升到主 Nest，或将核心降级到保留 Nest。

在整个过程中，调度器更新相关统计数据，以提供对其操作的见解。使用 RCU 锁确保调度器的决策是在不干扰其他并发操作的情况下安全做出的。

#### `nest_enqueue`

处理将任务入队到调度队列：

```c
void BPF_STRUCT_OPS(nest_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *tctx;
    u64 vtime = p->scx.dsq_vtime;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx) {
        scx_bpf_error("无法找到任务上下文");
        return;
    }

    /*
     * 将空闲任务的预算限制为一个切片。
     */
    if (vtime_before(vtime, vtime_now - slice_ns))
        vtime = vtime_now - slice_ns;

    scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns, vtime, enq_flags);
}
```

`nest_enqueue` 函数管理任务的入队，调整其虚拟时间 (`vtime`) 以确保公平性并防止任务在空闲时积累过多的执行预算。如果任务的 `vtime` 低于某个阈值，它将被调整以保持调度器内部的平衡。

#### `nest_dispatch`

管理将任务分派到 CPU 核心：

```c
void BPF_STRUCT_OPS(nest_dispatch, s32 cpu, struct task_struct *prev)
{
    struct pcpu_ctx *pcpu_ctx;
    struct bpf_cpumask *primary, *reserve;
    s32 key = cpu;
    bool in_primary;

    primary = primary_cpumask;
    reserve = reserve_cpumask;
    if (!primary || !reserve) {
        scx_bpf_error("没有主或保留 cpumask");
        return;
    }

    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);
    if (!pcpu_ctx) {
        scx_bpf_error("查找 pcpu ctx 失败");
        return;
    }

    if (!scx_bpf_consume(FALLBACK_DSQ_ID)) {
        in_primary = bpf_cpumask_test_cpu(cpu, cast_mask(primary));

        if (prev && (prev->scx.flags & SCX_TASK_QUEUED) && in_primary) {
            scx_bpf_dispatch(prev, SCX_DSQ_LOCAL, slice_ns, 0);
            return;
        }

        stat_inc(NEST_STAT(NOT_CONSUMED));
        if (in_primary) {
            /*
             * 如果主集合中的前一个任务正在死亡，立即降级主核心。
             *
             * 注意，我们选择不压缩掩码中的“第一个” CPU，以鼓励至少保留一个核心在 Nest 中。
             * 最好检查是否仅剩一个核心在 Nest 中，但 BPF 目前没有用于查询
             * cpumask 权重的内核函数。
             */
            if ((prev && prev->__state == TASK_DEAD) &&
                (cpu != bpf_cpumask_first(cast_mask(primary)))) {
                stat_inc(NEST_STAT(EAGERLY_COMPACTED));
                bpf_cpumask_clear_cpu(cpu, primary);
                try_make_core_reserved(cpu, reserve, false);
            } else  {
                pcpu_ctx->scheduled_compaction = true;
                /*
                 * 核心不再被使用。设置定时器以在 p_remove 中移除核心
                 * 如果在那时仍未使用。
                 */
                bpf_timer_start(&pcpu_ctx->timer, p_remove_ns,
                               BPF_F_TIMER_CPU_PIN);
                stat_inc(NEST_STAT(SCHEDULED_COMPACTION));
            }
        }
        return;
    }
    stat_inc(NEST_STAT(CONSUMED));
}
```

`nest_dispatch` 函数负责将任务分派到 CPU 核心。它首先检查回退调度队列 (`FALLBACK_DSQ_ID`) 中是否有可用任务。如果没有任务被消耗，它会评估 CPU 上的前一个任务是否已经死亡。如果是，并且 CPU 不在主掩码中的第一个位置，调度器将核心降级到保留 Nest。否则，它会为核心安排一个压缩定时器，以便在指定时间后可能降级该核心。如果从回退队列成功消耗了一个任务，它会递增相应的统计数据。

#### `nest_running`

当任务开始运行时更新全局虚拟时间：

```c
void BPF_STRUCT_OPS(nest_running, struct task_struct *p)
{
    /*
     * 全局虚拟时间在任务开始执行时总是向前推进。
     * 测试和更新可以从多个 CPU 同时执行，因此存在竞争。
     * 任何错误都应该是可控且暂时的。我们就这样处理。
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}
```

`nest_running` 函数确保全局虚拟时间 (`vtime_now`) 在任务开始执行时向前推进。这一机制有助于维护调度器操作的公平性和时间一致性。

#### `nest_stopping`

处理任务停止运行，调整其虚拟时间：

```c
void BPF_STRUCT_OPS(nest_stopping, struct task_struct *p, bool runnable)
{
    /* 按权重的倒数和费用缩放执行时间 */
    p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;
}
```

当任务停止运行时，`nest_stopping` 根据其执行切片和权重调整其虚拟时间。这一调整确保任务在调度器的虚拟时间计算中得到公平考虑，保持平衡并防止任何单个任务垄断 CPU 资源。

#### `nest_init_task`

初始化新任务的上下文：

```c
s32 BPF_STRUCT_OPS(nest_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    struct task_ctx *tctx;
    struct bpf_cpumask *cpumask;

    /*
     * @p 是新的。确保其 task_ctx 可用。
     * 我们可以在此函数中休眠，以下内容将自动使用 GFP_KERNEL。
     */
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return -ENOMEM;

    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;

    cpumask = bpf_kptr_xchg(&tctx->tmp_mask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);

    tctx->attached_core = -1;
    tctx->prev_cpu = -1;

    return 0;
}
```

`nest_init_task` 函数为新任务初始化调度上下文。它通过从 `task_ctx_stor` 映射中检索任务的上下文来确保任务的上下文可用，创建一个新的 `bpf_cpumask` 进行临时计算，并为 `attached_core` 和 `prev_cpu` 设置初始值。

#### `nest_enable`

通过设置任务的虚拟时间启用调度：

```c
void BPF_STRUCT_OPS(nest_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}
```

`nest_enable` 函数通过将任务的虚拟时间 (`dsq_vtime`) 初始化为当前的全局虚拟时间 (`vtime_now`) 来激活任务的调度。这确保了任务的调度状态与调度器的虚拟时间同步。

#### `stats_timerfn`

处理定期的统计信息收集：

```c
static int stats_timerfn(void *map, int *key, struct bpf_timer *timer)
{
    s32 cpu;
    struct bpf_cpumask *primary, *reserve;
    const struct cpumask *idle;
    stats_primary_mask = 0;
    stats_reserved_mask = 0;
    stats_other_mask = 0;
    stats_idle_mask = 0;
    long err;

    bpf_rcu_read_lock();
    primary = primary_cpumask;
    reserve = reserve_cpumask;
    if (!primary || !reserve) {
        bpf_rcu_read_unlock();
        scx_bpf_error("查找主或保留失败");
        return 0;
    }

    idle = scx_bpf_get_idle_cpumask();
    bpf_for(cpu, 0, nr_cpus) {
        if (bpf_cpumask_test_cpu(cpu, cast_mask(primary)))
            stats_primary_mask |= (1ULL << cpu);
        else if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve)))
            stats_reserved_mask |= (1ULL << cpu);
        else
            stats_other_mask |= (1ULL << cpu);

        if (bpf_cpumask_test_cpu(cpu, idle))
            stats_idle_mask |= (1ULL << cpu);
    }
    bpf_rcu_read_unlock();
    scx_bpf_put_idle_cpumask(idle);

    err = bpf_timer_start(timer, sampling_cadence_ns - 5000, 0);
    if (err)
        scx_bpf_error("启动统计定时器失败");

    return 0;
}
```

`stats_timerfn` 函数由中央定时器定期调用，用于收集和更新调度统计信息。它捕捉当前 CPU 核心的状态，将它们分类到主、保留、其他和空闲掩码中。这些信息提供了调度器如何管理 CPU 资源和任务分配的洞察。在收集统计信息后，该函数重新启动定时器以确保持续监控。

#### `nest_init`

初始化 `scx_nest` 调度器：

```c
s32 BPF_STRUCT_OPS_SLEEPABLE(nest_init)
{
    struct bpf_cpumask *cpumask;
    s32 cpu;
    int err;
    struct bpf_timer *timer;
    u32 key = 0;

    err = scx_bpf_create_dsq(FALLBACK_DSQ_ID, NUMA_NO_NODE);
    if (err) {
        scx_bpf_error("创建回退 DSQ 失败");
        return err;
    }

    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;
    bpf_cpumask_clear(cpumask);
    cpumask = bpf_kptr_xchg(&primary_cpumask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);

    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;

    bpf_cpumask_clear(cpumask);
    cpumask = bpf_kptr_xchg(&reserve_cpumask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);

    bpf_for(cpu, 0, nr_cpus) {
        s32 key = cpu;
        struct pcpu_ctx *ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);

        if (!ctx) {
            scx_bpf_error("查找 pcpu_ctx 失败");
            return -ENOENT;
        }
        ctx->scheduled_compaction = false;
        if (bpf_timer_init(&ctx->timer, &pcpu_ctxs, CLOCK_BOOTTIME)) {
            scx_bpf_error("初始化 pcpu 定时器失败");
            return -EINVAL;
        }
        err = bpf_timer_set_callback(&ctx->timer, compact_primary_core);
        if (err) {
            scx_bpf_error("设置 pcpu 定时器回调失败");
            return -EINVAL;
        }
    }

    timer = bpf_map_lookup_elem(&stats_timer, &key);
    if (!timer) {
        scx_bpf_error("查找中央定时器失败");
        return -ESRCH;
    }
    bpf_timer_init(timer, &stats_timer, CLOCK_BOOTTIME);
    bpf_timer_set_callback(timer, stats_timerfn);
    err = bpf_timer_start(timer, sampling_cadence_ns - 5000, 0);
    if (err)
        scx_bpf_error("启动统计定时器失败");

    return err;
}
```

`nest_init` 函数在系统初始化期间设置 `scx_nest` 调度器。它创建了一个回退调度队列 (`FALLBACK_DSQ_ID`) 并初始化了主掩码和保留掩码。对于每个 CPU，它从 `pcpu_ctxs` 映射中检索每 CPU 上下文，初始化压缩定时器，并将回调设置为 `compact_primary_core`。此外，它初始化并启动中央统计定时器 (`stats_timer`) 及其回调函数 `stats_timerfn`，确保调度器统计信息的持续监控。

#### `nest_exit`

在调度器退出时进行清理：

```c
void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}
```

`nest_exit` 函数记录退出信息并在调度器被移除或系统关闭时执行任何必要的清理操作。这确保所有资源得到适当释放，系统保持稳定。

#### `SCX_OPS_DEFINE`

为 `scx_nest` 调度器定义操作结构：

```c
SCX_OPS_DEFINE(nest_ops,
               .select_cpu        = (void *)nest_select_cpu,
               .enqueue            = (void *)nest_enqueue,
               .dispatch        = (void *)nest_dispatch,
               .running            = (void *)nest_running,
               .stopping        = (void *)nest_stopping,
               .init_task        = (void *)nest_init_task,
               .enable            = (void *)nest_enable,
               .init            = (void *)nest_init,
               .exit            = (void *)nest_exit,
               .flags            = 0,
               .name            = "nest");
```

`SCX_OPS_DEFINE` 宏将调度器的所有函数绑定到 `nest_ops` 结构中，`sched_ext` 框架使用该结构与调度器进行接口。这确保调度器的操作在任务调度事件期间被正确映射和调用。

### 初始化和清理

适当的初始化和清理对于调度器的稳定性和性能至关重要。

#### `nest_init` 函数

`nest_init` 函数负责在系统初始化期间设置调度器。其操作如下：

1. **创建回退调度队列：**
   - 调用 `scx_bpf_create_dsq` 创建回退调度队列 (`FALLBACK_DSQ_ID`)。如果失败，记录错误并退出。

2. **初始化主掩码和保留掩码：**
   - 创建并清除一个新的 `bpf_cpumask` 作为主掩码。
   - 将新创建的掩码与现有的 `primary_cpumask` 交换。如果存在旧掩码，则释放它。
   - 对保留掩码重复相同的过程。

3. **初始化每 CPU 上下文：**
   - 对于每个 CPU，从 `pcpu_ctxs` 映射中检索每 CPU 上下文。
   - 将 `scheduled_compaction` 标志初始化为 `false`。
   - 使用 `bpf_timer_init` 初始化定时器，并使用 `bpf_timer_set_callback` 将回调设置为 `compact_primary_core`。
   - 如果任何步骤失败，记录错误并退出。

4. **初始化并启动统计定时器：**
   - 从 `stats_timer` 映射中检索中央统计定时器。
   - 初始化定时器并将其回调设置为 `stats_timerfn`。
   - 以 `sampling_cadence_ns - 5000` 纳秒的延迟启动定时器。
   - 如果启动定时器失败，记录错误。

5. **返回：**
   - 函数返回定时器初始化的结果，指示成功或失败。

这一初始化过程确保调度器的所有必要组件（包括 CPU 掩码、定时器和调度队列）都已正确设置。

#### `nest_exit` 函数

`nest_exit` 函数在调度器被移除或系统关闭时处理清理工作：

```c
void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}
```

此函数通过 `UEI_RECORD` 宏记录退出信息，确保执行任何必要的清理操作。这对于保持系统稳定性和防止资源泄漏至关重要。

### 最终调度器定义

`SCX_OPS_DEFINE` 宏将调度器的所有函数绑定到单一结构中，供 `sched_ext` 框架使用：

```c
SCX_OPS_DEFINE(nest_ops,
               .select_cpu        = (void *)nest_select_cpu,
               .enqueue            = (void *)nest_enqueue,
               .dispatch        = (void *)nest_dispatch,
               .running            = (void *)nest_running,
               .stopping        = (void *)nest_stopping,
               .init_task        = (void *)nest_init_task,
               .enable            = (void *)nest_enable,
               .init            = (void *)nest_init,
               .exit            = (void *)nest_exit,
               .flags            = 0,
               .name            = "nest");
```

此结构体 `nest_ops` 有效地将调度器的操作注册到 `sched_ext` 框架，确保调度器在各种调度事件和系统状态下做出适当响应。

## 编译和执行

要编译和运行 `scx_nest` 调度器，请按照以下步骤操作：

**编译代码：**

使用 `make` 构建调度器。确保已安装必要的构建工具和内核头文件。

```bash
make
```

**运行调度器：**

执行编译后的调度器二进制文件。根据系统配置和权限，您可能需要以提升的权限运行此命令。

```bash
./scx_nest
```

### 示例输出

运行调度器后，您应该会看到类似以下的输出：

```
# ./scx_nest 

唤醒统计
------------
WAKEUP_ATTACHED=150
WAKEUP_PREV_PRIMARY=61
WAKEUP_FULLY_IDLE_PRIMARY=0
WAKEUP_ANY_IDLE_PRIMARY=103
WAKEUP_FULLY_IDLE_RESERVE=0
WAKEUP_ANY_IDLE_RESERVE=216
WAKEUP_IDLE_OTHER=11


Nest 统计
----------
TASK_IMPATIENT=67
PROMOTED_TO_PRIMARY=217
PROMOTED_TO_RESERVED=8
DEMOTED_TO_RESERVED=212
RESERVED_AT_CAPACITY=6
SCHEDULED_COMPACTION=525
CANCELLED_COMPACTION=314
EAGERLY_COMPACTED=8
CALLBACK_COMPACTED=208


消耗统计
-------------
CONSUMED=166
NOT_CONSUMED=667



掩码
-----
PRIMARY  ( 0): | -------------------------------------------------------------------------------------------------------------------------------- |
RESERVED (10): | ***-*--*--------------------------------------------------------***-*--*-------------------------------------------------------- |
OTHER    (128): | ******************************************************************************************************************************** |
IDLE     (16): | ********--------------------------------------------------------********-------------------------------------------------------- |


^C退出：已从用户空间注销
```

此输出提供了有关任务唤醒、Nest 操作、消耗率和 CPU 掩码状态的全面统计信息。它显示了调度器如何管理任务和 CPU 核心，展示了 `scx_nest` 算法在保持高频率核心利用率和高效任务分配方面的有效性。

## 总结与行动呼吁

在本教程中，我们深入探讨了 `scx_nest` 调度器的实现，这是一个先进的 eBPF 程序，基于核心频率和利用率定制 CPU 调度以优化性能。通过利用 `sched_ext` 框架，`scx_nest` 展示了 eBPF 如何动态定义调度行为，提供超越传统调度器的灵活性和控制力。

主要收获包括：

- 理解 `sched_ext` 调度器类的灵活性和强大功能。
- 探索支撑 `scx_nest` 调度器的复杂数据结构和映射。
- 分析管理任务分配、核心压缩和统计信息收集的核心函数。
- 学习如何编译和执行调度器，并通过详细统计信息观察其影响。

`scx_nest` 调度器是一个极好的例子，展示了如何利用先进的 eBPF 编程以灵活和动态的方式实现复杂的系统功能。

如果您想深入了解 eBPF 并探索更多高级示例，请访问我们的教程仓库 [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或查看我们的网站 [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/)。

## 参考文献

`scx_nest` 调度器的原始源代码可在 [sched-ext/scx](https://github.com/sched-ext/scx) 仓库中找到。

可以增强您理解的其他资源包括：

- **Linux 内核文档:** [Scheduler Ext 文档](https://www.kernel.org/doc/html/next/scheduler/sched-ext.html)
- **内核源树:** [Linux 内核 `sched_ext` 工具](https://github.com/torvalds/linux/tree/master/tools/sched_ext)
- **eBPF 官方文档:** [https://ebpf.io/docs/](https://ebpf.io/docs/)
- **libbpf 文档:** [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)

欢迎探索这些资源，扩展您的知识，继续深入学习高级 eBPF 编程的旅程。