## eBPF 入门实践教程：编写 eBPF 程序 llcstat 监控 cache miss 和 cache reference

### 背景

为了能更好地优化程序性能，开发者有时需要考虑如何更好地减少cache miss的发生。
但是程序到底可能发生多少次cache miss这是一个难以回答的问题。`llcstat` 通过
ebpf技术，实现了对 cache miss 和 cache reference 的准确追踪，可以极大方便开发者
调试程序，优化性能。

### 实现原理

`llcstat` 引入了linux中的 `perf_event` 机制，程序在用户态载入的时候，
会将现有的c `perf_event` attach到指定的位置。
```c
	if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_MISSES,
					env.sample_period,
					obj->progs.on_cache_miss, mlinks))
		goto cleanup;
	if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_REFERENCES,
					env.sample_period,
					obj->progs.on_cache_ref, rlinks))
```

同时，`llcstat` 在内核态中会在`perf_event`下挂载执行函数，当程序运行到了
挂载点，执行函数会启动并开始计数，将结果写入对应的map中。

```c
static __always_inline
int trace_event(__u64 sample_period, bool miss)
{
	struct key_info key = {};
	struct value_info *infop, zero = {};

	u64 pid_tgid = bpf_get_current_pid_tgid();
	key.cpu = bpf_get_smp_processor_id();
	key.pid = pid_tgid >> 32;
	if (targ_per_thread)
		key.tid = (u32)pid_tgid;
	else
		key.tid = key.pid;

	infop = bpf_map_lookup_or_try_init(&infos, &key, &zero);
	if (!infop)
		return 0;
	if (miss)
		infop->miss += sample_period;
	else
		infop->ref += sample_period;
	bpf_get_current_comm(infop->comm, sizeof(infop->comm));

	return 0;
}

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, true);
}

SEC("perf_event")
int on_cache_ref(struct bpf_perf_event_data *ctx)
{
	return trace_event(ctx->sample_period, false);
}
```

用户态程序会读取map存入的 cache miss 和 cache reference 的计数信息，并
逐进程的进行展示。

### Eunomia中使用方式


### 总结
`llcstat` 运用了ebpf计数，高效简洁地展示了某个线程发生cache miss和cache 
reference的次数，这使得开发者们在优化程序的过程中有了更明确的量化指标。
