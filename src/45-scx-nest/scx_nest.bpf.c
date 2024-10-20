/* SPDX-License-Identifier: GPL-2.0 */
/*
 * As described in [0], a Nest scheduler which encourages task placement on
 * cores that are likely to be running at higher frequency, based upon recent usage.
 *
 * [0]: https://hal.inria.fr/hal-03612592/file/paper.pdf
 *
 * It operates as a global weighted vtime scheduler (similarly to CFS), while
 * using the Nest algorithm to choose idle cores at wakup time.
 *
 * It also demonstrates the following niceties.
 *
 * - More robust task placement policies.
 * - Termination notification for userspace.
 *
 * While rather simple, this scheduler should work reasonably well on CPUs with
 * a uniform L3 cache topology. While preemption is not implemented, the fact
 * that the scheduling queue is shared across all CPUs means that whatever is
 * at the front of the queue is likely to be executed fairly quickly given
 * enough number of CPUs.
 *
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <scx/common.bpf.h>

#include "scx_nest.h"

#define TASK_DEAD                       0x00000080

char _license[] SEC("license") = "GPL";

enum {
	FALLBACK_DSQ_ID		= 0,
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC		= NSEC_PER_USEC * USEC_PER_SEC,
};

#define CLOCK_BOOTTIME 7
#define NUMA_NO_NODE -1

const volatile u64 p_remove_ns = 2 * NSEC_PER_MSEC;
const volatile u64 r_max = 5;
const volatile u64 r_impatient = 2;
const volatile u64 slice_ns = SCX_SLICE_DFL;
const volatile bool find_fully_idle = false;
const volatile u64 sampling_cadence_ns = 1 * NSEC_PER_SEC;
const volatile u64 r_depth = 5;

// Used for stats tracking. May be stale at any given time.
u64 stats_primary_mask, stats_reserved_mask, stats_other_mask, stats_idle_mask;

// Used for internal tracking.
static s32 nr_reserved;

static u64 vtime_now;
UEI_DEFINE(uei);

extern unsigned long CONFIG_HZ __kconfig;

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

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct pcpu_ctx {
	/* The timer used to compact the core from the primary nest. */
	struct bpf_timer timer;

	/* Whether the current core has been scheduled for compaction. */
	bool scheduled_compaction;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, s32);
	__type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");

struct stats_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stats_timer);
} stats_timer SEC(".maps");

const volatile u32 nr_cpus = 1; /* !0 for veristat, set during init. */

private(NESTS) struct bpf_cpumask __kptr *primary_cpumask;
private(NESTS) struct bpf_cpumask __kptr *reserve_cpumask;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, NEST_STAT(NR));
} stats SEC(".maps");


static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

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

static void update_attached(struct task_ctx *tctx, s32 prev_cpu, s32 new_cpu)
{
	if (tctx->prev_cpu == new_cpu)
		tctx->attached_core = new_cpu;
	tctx->prev_cpu = prev_cpu;
}

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

s32 BPF_STRUCT_OPS(nest_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
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

	scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns, vtime,
			       enq_flags);
}

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

void BPF_STRUCT_OPS(nest_stopping, struct task_struct *p, bool runnable)
{
	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;
}

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

void BPF_STRUCT_OPS(nest_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

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

void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(nest_ops,
	       .select_cpu		= (void *)nest_select_cpu,
	       .enqueue			= (void *)nest_enqueue,
	       .dispatch		= (void *)nest_dispatch,
	       .running			= (void *)nest_running,
	       .stopping		= (void *)nest_stopping,
	       .init_task		= (void *)nest_init_task,
	       .enable			= (void *)nest_enable,
	       .init			= (void *)nest_init,
	       .exit			= (void *)nest_exit,
	       .flags			= 0,
	       .name			= "nest");

