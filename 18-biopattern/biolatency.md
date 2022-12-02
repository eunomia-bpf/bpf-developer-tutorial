## eBPF 入门实践教程：编写 eBPF 程序 Biolatency: 统计系统中发生的I/O事件

### 背景

Biolatency 可以统计在该工具运行后系统中发生的I/O事件个数，并且计算I/O事件在不同时间段内的分布情况，以
直方图的形式展现给用户。

### 实现原理

Biolatency 主要通过 tracepoint 实现，其在 block_rq_insert, block_rq_issue, 
block_rq_complete 挂载点下设置了处理函数。在 block_rq_insert 和 block_rq_issue 挂载点下，
Biolatency 会将IO操作发生时的request queue和时间计入map中。
```c
int trace_rq_start(struct request *rq, int issue)
{
	if (issue && targ_queued && BPF_CORE_READ(rq->q, elevator))
		return 0;

	u64 ts = bpf_ktime_get_ns();

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int block_rq_insert(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;
    
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx[1], false);
	else
		return trace_rq_start((void *)ctx[0], false);
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue(u64 *ctx)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;
    
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx[1], true);
	else
		return trace_rq_start((void *)ctx[0], true);
}

```
在block_rq_complete 挂载点下，Biolatency 会根据 request queue 从map中读取
上一次操作发生的时间，然后计算与当前时间的差值来判断其在直方图中存在的区域，将该区域内的IO操作
计数加一。
```c
SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error,
	unsigned int nr_bytes)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histp;
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (targ_per_disk) {
		struct gendisk *disk = get_disk(rq);

		hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
					BPF_CORE_READ(disk, first_minor)) : 0;
	}
	if (targ_per_flag)
		hkey.cmd_flags = rq->cmd_flags;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			goto cleanup;
	}

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

```
当用户中止程序时，用户态程序会读取直方图map中的数据，并打印呈现。

### Eunomia中使用方式


### 总结
Biolatency 通过 tracepoint 挂载点实现了对IO事件个数的统计，并且能以直方图的
形式进行展现，可以方便开发者了解系统I/O事件情况。