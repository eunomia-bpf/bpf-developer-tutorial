## eBPF 入门实践教程：编写 eBPF 程序 syscount 监控慢系统调用

### 背景

`syscount` 可以统计系统或者某个进程发生的各类syscall的总数或者时耗时。 

### 实现原理
`syscount` 的实现逻辑非常直观，他在 `sys_enter` 和 `sys_exit` 这两个 `tracepoint` 下挂载了
执行函数。
```c
SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u32 tid = id;
	u64 ts;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (filter_pid && pid != filter_pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &tid, &ts, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	static const struct data_t zero;
	pid_t pid = id >> 32;
	struct data_t *val;
	u64 *start_ts, lat = 0;
	u32 tid = id;
	u32 key;

	/* this happens when there is an interrupt */
	if (args->id == -1)
		return 0;

	if (filter_pid && pid != filter_pid)
		return 0;
	if (filter_failed && args->ret >= 0)
		return 0;
	if (filter_errno && args->ret != -filter_errno)
		return 0;

	if (measure_latency) {
		start_ts = bpf_map_lookup_elem(&start, &tid);
		if (!start_ts)
			return 0;
		lat = bpf_ktime_get_ns() - *start_ts;
	}

	key = (count_by_process) ? pid : args->id;
	val = bpf_map_lookup_or_try_init(&data, &key, &zero);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
		if (count_by_process)
			save_proc_name(val);
		if (measure_latency)
			__sync_fetch_and_add(&val->total_ns, lat);
	}
	return 0;
}

```
当syscall发生时，`syscount`会记录其tid和发生的时间并存入map中。在syscall完成时，`syscount` 会根据用户
的需求，统计syscall持续的时间，或者是发生的次数。
### Eunomia中使用方式


### 总结
`sycount` 使得用户可以较为方便的追踪某个进程或者是系统内系统调用发生的情况。