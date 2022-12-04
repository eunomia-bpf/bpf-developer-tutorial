## eBPF 入门实践教程：编写 eBPF 程序 Bitesize: 监控块设备 I/O

### 背景

为了能更好的获得 I/O 操作需要的磁盘块大小相关信息，Bitesize 工具被开发。它可以在启动后追踪
不同进程所需要的块大小，并以直方图的形式显示分布

### 实现原理

Biteszie 在 block_rq_issue 追踪点下挂在了处理函数。当进程对磁盘发出了块 I/O 请求操作时，
系统会经过此挂载点，此时处理函数或许请求的信息，将其存入对应的map中。
```c
static int trace_rq_issue(struct request *rq)
{
	struct hist_key hkey;
	struct hist *histp;
	u64 slot;

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	if (!comm_allowed(hkey.comm))
		return 0;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			return 0;
	}
	slot = log2l(rq->__data_len / 1024);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_issue((void *)ctx[0]);
	else
		return trace_rq_issue((void *)ctx[1]);
}
```

当用户发出中止工具的指令后，其用户态代码会将map中存储的数据读出并逐进程的展示追踪结果

### Eunomia中使用方式


### 总结
Bitesize 以进程为粒度，使得开发者可以更好的掌握程序对磁盘 I/O 的请求情况。