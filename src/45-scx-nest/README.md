# eBPF Tutorial by Example: Implementing the `scx_nest` Scheduler

In the ever-evolving landscape of system performance optimization, the ability to customize and extend kernel behavior is invaluable. One of the most powerful tools for achieving this is eBPF (extended Berkeley Packet Filter). In this tutorial, we'll explore the implementation of the `scx_nest` scheduler, an advanced eBPF program that leverages the `sched_ext` scheduler class introduced in Linux kernel version `6.12`. By the end of this guide, you'll understand how to build a sophisticated scheduler that dynamically adjusts task placement based on CPU core frequencies and utilization.

## Introduction to `sched_ext`

The `sched_ext` scheduler class marks a significant advancement in Linux kernel scheduling capabilities. Unlike traditional schedulers, `sched_ext` allows its behavior to be defined dynamically through a set of BPF (Berkeley Packet Filter) programs. This flexibility enables developers to implement custom scheduling algorithms tailored to specific workloads and system requirements.

## Understanding the `scx_nest` Scheduler

### Overview

The `scx_nest` scheduler is inspired by the Inria Paris paper titled "[OS Scheduling with Nest: Keeping Tasks Close Together on Warm Cores](https://hal.inria.fr/hal-03612592/file/paper.pdf)." Developed by Meta Platforms, Inc., `scx_nest` focuses on encouraging task placement on CPU cores that are likely to run at higher frequencies based on recent usage patterns. This approach aims to optimize performance by ensuring that tasks execute on the most efficient cores available.

The scheduler operates as a global weighted virtual time (vtime) scheduler, similar to the Completely Fair Scheduler (CFS), while utilizing the Nest algorithm to select idle cores during task wakeup. This dual strategy ensures that tasks are not only fairly distributed but also placed on cores that can execute them most effectively.

`scx_nest` is designed to optimize workloads with relatively low CPU utilization that can benefit from running on a subset of cores. By concentrating tasks on fewer cores, the scheduler helps maintain high frequencies on those cores, enhancing performance. However, for workloads that perform better when distributed across many cores to avoid cache thrashing, `scx_nest` may not be the ideal choice. Evaluating the suitability of `scx_nest` for a specific workload often requires experimentation.

Given its design, `scx_nest` is suitable for production environments, provided the hardware constraints are met. It performs optimally on single CCX (Core Complex) or single-socket hosts with a uniform L3 cache topology. While preemption is not implemented in the current version, the shared scheduling queue across all CPUs ensures that tasks at the front of the queue are executed promptly, provided there are enough CPUs available.

## High-Level Code Analysis

The `scx_nest` scheduler's implementation is intricate, involving various data structures, maps, and functions that work in harmony to manage task placement and CPU core utilization. The complete source code is available in the [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) repository. Below, we'll dissect the core components of the scheduler, explaining each part in detail.

### Core Data Structures and Maps

#### Task Context (`task_ctx`)

Each task in the system has an associated context that maintains scheduling-related information. This context is crucial for making informed scheduling decisions based on the task's history and current state.

```c
/* Per-task scheduling context */
struct task_ctx {
    /*
     * A temporary cpumask for calculating a task's primary and reserve
     * mask.
     */
    struct bpf_cpumask __kptr *tmp_mask;

    /*
     * The number of times that a task observes that its previous core is
     * not idle. If this occurs r_impatient times in a row, a core is
     * attempted to be retrieved from either the reserve nest, or the
     * fallback nest.
     */
    u32 prev_misses;

    /*
     * A core that the task is "attached" to, meaning the last core that it
     * executed on at least twice in a row, and the core that it first
     * tries to migrate to on wakeup. The task only migrates to the
     * attached core if it is idle and in the primary nest.
     */
    s32 attached_core;

    /*
     * The last core that the task executed on. This is used to determine
     * if the task should attach to the core that it will execute on next.
     */
    s32 prev_cpu;
};
```

The `task_ctx` structure holds a temporary CPU mask (`tmp_mask`) used for calculating the task's primary and reserve CPU sets. The `prev_misses` counter tracks how often the task's preferred core was not idle, influencing decisions to migrate the task to different cores. The `attached_core` indicates the core the task is currently bound to, ensuring it runs on a high-frequency core when possible. Lastly, `prev_cpu` records the last core the task executed on, aiding in maintaining task-core affinity.

#### Per-CPU Context (`pcpu_ctx`)

Each CPU has an associated context that manages timers and compaction state. This context helps in determining when a core should be demoted from the primary nest due to inactivity.

```c
struct pcpu_ctx {
    /* The timer used to compact the core from the primary nest. */
    struct bpf_timer timer;

    /* Whether the current core has been scheduled for compaction. */
    bool scheduled_compaction;
};
```

The `pcpu_ctx` structure contains a `bpf_timer` used to schedule compaction events and a boolean flag `scheduled_compaction` indicating whether a compaction has been scheduled for the core.

#### Maps

Several BPF maps are utilized to store contexts and manage timers:

```c
/* Task storage map */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* Per-CPU contexts */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");

/* Statistics timer */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stats_timer);
} stats_timer SEC(".maps");
```

- **`task_ctx_stor`:** This map stores the scheduling context for each task, enabling the scheduler to access and modify task-specific information.
- **`pcpu_ctxs`:** An array map that holds the per-CPU contexts, allowing the scheduler to manage timers and compaction states for each CPU.
- **`stats_timer`:** A single-entry array map used to manage a central timer for collecting scheduling statistics.

Additionally, the scheduler maintains masks for primary, reserved, other, and idle CPUs, as well as a statistics map to track various scheduler metrics.

### Core Functions

#### `stat_inc`

A helper function to increment scheduler statistics:

```c
static __always_inline void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}
```

This function looks up a counter in the `stats` map and increments it if the counter exists. It's used throughout the scheduler to track various events and states.

#### `vtime_before`

A utility function to compare virtual times:

```c
static inline bool vtime_before(u64 a, u64 b)
{
    return (s64)(a - b) < 0;
}
```

This function determines if virtual time `a` is before `b`, facilitating time-based scheduling decisions.

#### `try_make_core_reserved`

Attempts to promote a core to the reserved nest:

```c
static __always_inline void
try_make_core_reserved(s32 cpu, struct bpf_cpumask * reserved, bool promotion)
{
    s32 tmp_nr_reserved;

    /*
     * This check is racy, but that's OK. If we incorrectly fail to promote
     * a core to reserve, it's because another context added or removed a
     * core from reserved in this small window. It will balance out over
     * subsequent wakeups.
     */
    tmp_nr_reserved = nr_reserved;
    if (tmp_nr_reserved < r_max) {
        /*
         * It's possible that we could exceed r_max for a time here,
         * but that should balance out as more cores are either demoted
         * or fail to be promoted into the reserve nest.
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

The `try_make_core_reserved` function attempts to add a CPU core to the reserved mask. It first checks if the number of reserved cores (`nr_reserved`) is below the maximum allowed (`r_max`). If so, it increments the `nr_reserved` counter and adds the core to the reserved mask. Depending on whether the core is being promoted or demoted, it increments the corresponding statistic. If the reserved capacity is full, it clears the core from the reserved mask and updates the relevant statistic.

#### `update_attached`

Updates the task's attached core based on recent execution:

```c
static void update_attached(struct task_ctx *tctx, s32 prev_cpu, s32 new_cpu)
{
    if (tctx->prev_cpu == new_cpu)
        tctx->attached_core = new_cpu;
    tctx->prev_cpu = prev_cpu;
}
```

This function updates the `attached_core` for a task. If the task has executed on the same core consecutively, it attaches the task to that core. It then updates the `prev_cpu` to reflect the latest core the task ran on.

#### `compact_primary_core`

Handles the compaction of a primary core by demoting it to the reserve nest:

```c
static int compact_primary_core(void *map, int *key, struct bpf_timer *timer)
{
    struct bpf_cpumask *primary, *reserve;
    s32 cpu = bpf_get_smp_processor_id();
    struct pcpu_ctx *pcpu_ctx;

    stat_inc(NEST_STAT(CALLBACK_COMPACTED));

    /*
     * If we made it to this callback, it means that the timer callback was
     * never cancelled, and so the core needs to be demoted from the
     * primary nest.
     */
    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (!pcpu_ctx) {
        scx_bpf_error("Couldn't lookup pcpu ctx");
        return 0;
    }
    bpf_rcu_read_lock();
    primary = primary_cpumask;
    reserve = reserve_cpumask;
    if (!primary || !reserve) {
        scx_bpf_error("Couldn't find primary or reserve");
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

When the compaction timer expires, `compact_primary_core` is invoked. It demotes the current CPU core from the primary nest to the reserve nest by clearing it from the primary mask and attempting to add it to the reserve mask using `try_make_core_reserved`. This ensures that inactive cores are efficiently managed, maintaining a balance between performance and resource utilization.

#### `nest_select_cpu`

Determines the appropriate CPU for a task upon waking up:

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

    /* First try to wake the task on its attached core. */
    if (bpf_cpumask_test_cpu(tctx->attached_core, cast_mask(p_mask)) &&
        scx_bpf_test_and_clear_cpu_idle(tctx->attached_core)) {
        cpu = tctx->attached_core;
        stat_inc(NEST_STAT(WAKEUP_ATTACHED));
        goto migrate_primary;
    }

    /*
     * Try to stay on the previous core if it's in the primary set, and
     * there's no hypertwin. If the previous core is the core the task is
     * attached to, don't bother as we already just tried that above.
     */
    if (prev_cpu != tctx->attached_core &&
        bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask)) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        cpu = prev_cpu;
        stat_inc(NEST_STAT(WAKEUP_PREV_PRIMARY));
        goto migrate_primary;
    }

    if (find_fully_idle) {
        /* Then try any fully idle core in primary. */
        cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
                                    SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_PRIMARY));
            goto migrate_primary;
        }
    }

    /* Then try _any_ idle core in primary, even if its hypertwin is active. */
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

    /* Then try any fully idle core in reserve. */
    bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(reserve));
    if (find_fully_idle) {
        cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
                                    SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_RESERVE));
            goto promote_to_primary;
        }
    }

    /* Then try _any_ idle core in reserve, even if its hypertwin is active. */
    cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
    if (cpu >= 0) {
        stat_inc(NEST_STAT(WAKEUP_ANY_IDLE_RESERVE));
        goto promote_to_primary;
    }

    /* Then try _any_ idle core in the task's cpumask. */
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
        /*
         * We found a core that (we didn't _think_) is in any nest.
         * This means that we need to either promote the core to the
         * reserve nest, or if we're going direct to primary due to
         * r_impatient being exceeded, promote directly to primary.
         *
         * We have to do one final check here to see if the core is in
         * the primary or reserved cpumask because we could potentially
         * race with the core changing states between AND'ing the
         * primary and reserve masks with p->cpus_ptr above, and
         * atomically reserving it from the idle mask with
         * scx_bpf_pick_idle_cpu(). This is also technically true of
         * the checks above, but in all of those cases we just put the
         * core directly into the primary mask so it's not really that
         * big of a problem. Here, we want to make sure that we don't
         * accidentally put a core into the reserve nest that was e.g.
         * already in the primary nest. This is unlikely, but we check
         * for it on what should be a relatively cold path regardless.
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
                scx_bpf_error("Failed to cancel pcpu timer");
            if (bpf_timer_set_callback(&pcpu_ctx->timer, compact_primary_core))
                scx_bpf_error("Failed to re-arm pcpu timer");
            pcpu_ctx->scheduled_compaction = false;
            stat_inc(NEST_STAT(CANCELLED_COMPACTION));
        }
    } else {
        scx_bpf_error("Failed to lookup pcpu ctx");
    }
    bpf_cpumask_set_cpu(cpu, primary);
    /*
     * Check to see whether the CPU is in the reserved nest. This can
     * happen if the core is compacted concurrently with us trying to place
     * the currently-waking task onto it. Similarly, this is the expected
     * state of the core if we found the core in the reserve nest and are
     * promoting it.
     *
     * We don't have to worry about racing with any other waking task here
     * because we've atomically reserved the core with (some variant of)
     * scx_bpf_pick_idle_cpu().
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

The `nest_select_cpu` function is the heart of the `scx_nest` scheduler. When a task wakes up, this function determines the most suitable CPU core for its execution. The function follows a series of checks to ensure that tasks are placed on high-frequency, idle cores, promoting efficiency and performance.

Initially, it retrieves the task's context from the `task_ctx_stor` map. It then locks the read-copy-update (RCU) lock to safely access the primary and reserve CPU masks. The scheduler first attempts to place the task on its attached core, ensuring core affinity. If the attached core is not idle, it tries the previous core. Depending on various conditions, including the task's impatience (`r_impatient`) and the availability of idle cores in the primary and reserve nests, the scheduler decides whether to migrate the task, promote a core to the primary nest, or demote a core to the reserve nest.

Throughout the process, the scheduler updates relevant statistics to provide insights into its operations. The use of RCU locks ensures that the scheduler's decisions are made safely without interfering with other concurrent operations.

#### `nest_enqueue`

Handles the enqueuing of tasks into the scheduling queue:

```c
void BPF_STRUCT_OPS(nest_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *tctx;
    u64 vtime = p->scx.dsq_vtime;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx) {
        scx_bpf_error("Unable to find task ctx");
        return;
    }

    /*
     * Limit the amount of budget that an idling task can accumulate
     * to one slice.
     */
    if (vtime_before(vtime, vtime_now - slice_ns))
        vtime = vtime_now - slice_ns;

    scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns, vtime, enq_flags);
}
```

The `nest_enqueue` function manages the queuing of tasks, adjusting their virtual time (`vtime`) to ensure fairness and prevent tasks from accumulating excessive execution budget while idling. If a task's `vtime` falls below a certain threshold, it's adjusted to maintain balance within the scheduler.

#### `nest_dispatch`

Manages the dispatching of tasks to CPU cores:

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
        scx_bpf_error("No primary or reserve cpumask");
        return;
    }

    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);
    if (!pcpu_ctx) {
        scx_bpf_error("Failed to lookup pcpu ctx");
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
             * Immediately demote a primary core if the previous
             * task on it is dying
             *
             * Note that we elect to not compact the "first" CPU in
             * the mask so as to encourage at least one core to
             * remain in the nest. It would be better to check for
             * whether there is only one core remaining in the
             * nest, but BPF doesn't yet have a kfunc for querying
             * cpumask weight.
             */
            if ((prev && prev->__state == TASK_DEAD) &&
                (cpu != bpf_cpumask_first(cast_mask(primary)))) {
                stat_inc(NEST_STAT(EAGERLY_COMPACTED));
                bpf_cpumask_clear_cpu(cpu, primary);
                try_make_core_reserved(cpu, reserve, false);
            } else  {
                pcpu_ctx->scheduled_compaction = true;
                /*
                 * The core isn't being used anymore. Set a
                 * timer to remove the core from the nest in
                 * p_remove if it's still unused by that point.
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

The `nest_dispatch` function is responsible for dispatching tasks to CPU cores. It first checks if there's a task available in the fallback dispatch queue (`FALLBACK_DSQ_ID`). If no task is consumed, it evaluates whether the previous task on the CPU is dead. If so, and the CPU is not the first in the primary mask, the scheduler demotes the core to the reserve nest. Otherwise, it schedules a compaction timer to potentially demote the core after a specified duration (`p_remove_ns`). If a task is successfully consumed from the fallback queue, it increments the corresponding statistic.

#### `nest_running`

Updates the global virtual time when a task starts running:

```c
void BPF_STRUCT_OPS(nest_running, struct task_struct *p)
{
    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}
```

The `nest_running` function ensures that the global virtual time (`vtime_now`) progresses forward as tasks start executing. This mechanism helps maintain fairness and temporal consistency across the scheduler's operations.

#### `nest_stopping`

Handles the stopping of a task, adjusting its virtual time:

```c
void BPF_STRUCT_OPS(nest_stopping, struct task_struct *p, bool runnable)
{
    /* scale the execution time by the inverse of the weight and charge */
    p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;
}
```

When a task stops running, `nest_stopping` adjusts its virtual time based on its execution slice and weight. This adjustment ensures that tasks are fairly accounted for in the scheduler's virtual time calculations, maintaining balance and preventing any single task from monopolizing CPU resources.

#### `nest_init_task`

Initializes a new task's context:

```c
s32 BPF_STRUCT_OPS(nest_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    struct task_ctx *tctx;
    struct bpf_cpumask *cpumask;

    /*
     * @p is new. Let's ensure that its task_ctx is available. We can sleep
     * in this function and the following will automatically use GFP_KERNEL.
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

The `nest_init_task` function initializes the scheduling context for a new task. It ensures that the task's context is available by retrieving it from the `task_ctx_stor` map, creating a new `bpf_cpumask` for temporary calculations, and setting initial values for `attached_core` and `prev_cpu`.

#### `nest_enable`

Enables scheduling for a task by setting its virtual time:

```c
void BPF_STRUCT_OPS(nest_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}
```

The `nest_enable` function activates scheduling for a task by initializing its virtual time (`dsq_vtime`) to the current global virtual time (`vtime_now`). This ensures that the task's scheduling state is synchronized with the scheduler's virtual time.

#### `stats_timerfn`

Handles periodic statistics collection:

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
        scx_bpf_error("Failed to lookup primary or reserve");
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
        scx_bpf_error("Failed to arm stats timer");

    return 0;
}
```

The `stats_timerfn` function is invoked periodically by a central timer to collect and update scheduler statistics. It captures the current state of CPU cores, categorizing them into primary, reserve, other, and idle masks. This information provides insights into how the scheduler is managing CPU resources and task placement over time. After collecting the statistics, the function re-arms the timer to ensure continuous monitoring.

#### `nest_init`

Initializes the `scx_nest` scheduler:

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
        scx_bpf_error("Failed to create fallback DSQ");
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
            scx_bpf_error("Failed to lookup pcpu_ctx");
            return -ENOENT;
        }
        ctx->scheduled_compaction = false;
        if (bpf_timer_init(&ctx->timer, &pcpu_ctxs, CLOCK_BOOTTIME)) {
            scx_bpf_error("Failed to initialize pcpu timer");
            return -EINVAL;
        }
        err = bpf_timer_set_callback(&ctx->timer, compact_primary_core);
        if (err) {
            scx_bpf_error("Failed to set pcpu timer callback");
            return -EINVAL;
        }
    }

    timer = bpf_map_lookup_elem(&stats_timer, &key);
    if (!timer) {
        scx_bpf_error("Failed to lookup central timer");
        return -ESRCH;
    }
    bpf_timer_init(timer, &stats_timer, CLOCK_BOOTTIME);
    bpf_timer_set_callback(timer, stats_timerfn);
    err = bpf_timer_start(timer, sampling_cadence_ns - 5000, 0);
    if (err)
        scx_bpf_error("Failed to arm stats timer");

    return err;
}
```

The `nest_init` function sets up the `scx_nest` scheduler during system initialization. It creates a fallback dispatch queue (`FALLBACK_DSQ_ID`) and initializes the primary and reserve CPU masks. For each CPU, it retrieves the per-CPU context from the `pcpu_ctxs` map, initializes a timer for core compaction, and sets the callback to `compact_primary_core`. Additionally, it initializes and starts the central statistics timer (`stats_timer`) with the callback function `stats_timerfn`, ensuring that scheduler statistics are continuously monitored.

#### `nest_exit`

Handles cleanup when the scheduler exits:

```c
void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}
```

The `nest_exit` function records exit information and performs any necessary cleanup when the scheduler is being removed or the system is shutting down. This ensures that all resources are properly released and that the system remains stable.

#### `SCX_OPS_DEFINE`

Defines the operations structure for the `scx_nest` scheduler:

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

The `SCX_OPS_DEFINE` macro binds all the scheduler's functions to the `nest_ops` structure, which the `sched_ext` framework uses to interface with the scheduler. This structure ensures that the scheduler's operations are correctly mapped and invoked by the kernel during task scheduling events.

### Initialization and Cleanup

Proper initialization and cleanup are crucial for the scheduler's stability and performance.

#### `nest_init` Function

The `nest_init` function is responsible for setting up the scheduler during system initialization. Here's how it operates:

1. **Create Fallback Dispatch Queue:**
   - It calls `scx_bpf_create_dsq` to create a fallback dispatch queue (`FALLBACK_DSQ_ID`). If this fails, it logs an error and exits.

2. **Initialize Primary and Reserve CPU Masks:**
   - It creates and clears a new `bpf_cpumask` for the primary mask.
   - It exchanges the newly created mask with the existing `primary_cpumask`. If an old mask exists, it releases it.
   - The same process is repeated for the reserve mask.

3. **Initialize Per-CPU Contexts:**
   - For each CPU, it retrieves the per-CPU context from the `pcpu_ctxs` map.
   - It initializes the `scheduled_compaction` flag to `false`.
   - It initializes the timer using `bpf_timer_init` and sets the callback to `compact_primary_core` using `bpf_timer_set_callback`.
   - If any of these steps fail, it logs an error and exits.

4. **Initialize and Start Statistics Timer:**
   - It retrieves the central statistics timer from the `stats_timer` map.
   - It initializes the timer and sets its callback to `stats_timerfn`.
   - It starts the timer with a delay of `sampling_cadence_ns - 5000` nanoseconds.
   - If starting the timer fails, it logs an error.

5. **Return:**
   - The function returns the result of the timer initialization, indicating success or failure.

This initialization process ensures that all necessary components of the scheduler are correctly set up, including CPU masks, timers, and dispatch queues.

#### `nest_exit` Function

The `nest_exit` function handles cleanup when the scheduler is being removed or the system is shutting down:

```c
void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}
```

This function records exit information through the `UEI_RECORD` macro, ensuring that any necessary cleanup actions are performed. Proper cleanup is essential to maintain system stability and prevent resource leaks.

### Final Scheduler Definition

The `SCX_OPS_DEFINE` macro binds all the scheduler's functions into a single structure used by the `sched_ext` framework:

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

This structure, `nest_ops`, effectively registers the scheduler's operations with the `sched_ext` framework, ensuring that the scheduler responds appropriately to various scheduling events and system states.

## Compilation and Execution

To compile and run the `scx_nest` scheduler, follow these steps:

**Compile the Code:**

Use `make` to build the scheduler. Ensure that you have the necessary build tools and kernel headers installed.

```bash
make
```

**Run the Scheduler:**

Execute the compiled scheduler binary. Depending on your system's configuration and permissions, you might need to run this command with elevated privileges.

```bash
./scx_nest
```

### Sample Output

Upon running the scheduler, you should observe output similar to the following:

```
# ./scx_nest 

Wakeup stats
------------
WAKEUP_ATTACHED=150
WAKEUP_PREV_PRIMARY=61
WAKEUP_FULLY_IDLE_PRIMARY=0
WAKEUP_ANY_IDLE_PRIMARY=103
WAKEUP_FULLY_IDLE_RESERVE=0
WAKEUP_ANY_IDLE_RESERVE=216
WAKEUP_IDLE_OTHER=11


Nest stats
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


Consume stats
-------------
CONSUMED=166
NOT_CONSUMED=667



Masks
-----
PRIMARY  ( 0): | -------------------------------------------------------------------------------------------------------------------------------- |
RESERVED (10): | ***-*--*--------------------------------------------------------***-*--*-------------------------------------------------------- |
OTHER    (128): | ******************************************************************************************************************************** |
IDLE     (16): | ********--------------------------------------------------------********-------------------------------------------------------- |


^CEXIT: unregistered from user space
```

This output provides comprehensive statistics on task wakeups, nest operations, consumption rates, and CPU mask statuses. It indicates how the scheduler is managing tasks and CPU cores, showcasing the effectiveness of the `scx_nest` algorithm in maintaining high-frequency core utilization and efficient task placement.

## Summary and Call to Action

In this tutorial, we've delved into the implementation of the `scx_nest` scheduler, an advanced eBPF program that customizes CPU scheduling to optimize performance based on core frequency and utilization. By leveraging the `sched_ext` framework, `scx_nest` demonstrates how eBPF can dynamically define scheduling behavior, offering flexibility and control beyond traditional schedulers.

Key takeaways include:

- Understanding the flexibility and power of the `sched_ext` scheduler class.
- Exploring the intricate data structures and maps that underpin the `scx_nest` scheduler.
- Analyzing core functions that manage task placement, core compaction, and statistics collection.
- Learning how to compile and execute the scheduler, observing its impact through detailed statistics.

The `scx_nest` scheduler serves as an excellent example of how advanced eBPF programming can be utilized to implement complex system functionalities in a flexible and dynamic manner.

If you'd like to dive deeper into eBPF and explore more advanced examples, visit our tutorial repository at [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or check out our website at [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/).

## References

The original source code for the `scx_nest` scheduler is available in the [sched-ext/scx](https://github.com/sched-ext/scx) repository.

Additional resources that can enhance your understanding include:

- **Linux Kernel Documentation:** [Scheduler Ext Documentation](https://www.kernel.org/doc/html/next/scheduler/sched-ext.html)
- **Kernel Source Tree:** [Linux Kernel `sched_ext` Tools](https://github.com/torvalds/linux/tree/master/tools/sched_ext)
- **eBPF Official Documentation:** [https://ebpf.io/docs/](https://ebpf.io/docs/)
- **libbpf Documentation:** [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)

Feel free to explore these resources to expand your knowledge and continue your journey into advanced eBPF programming!