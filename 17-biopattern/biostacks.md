##  eBPF 入门实践教程：编写 eBPF 程序 Biostacks: 监控内核 I/O 操作耗时


### 背景
由于有些磁盘I/O操作不是直接由应用发起的，比如元数据读写，因此有些直接捕捉磁盘I/O操作信息可能
会有一些无法解释的I/O操作发生。为此，Biostacks 会直接追踪内核中初始化I/O操作的函数，并将磁
盘I/O操作耗时以直方图的形式展现。

### 实现原理
Biostacks 的挂载点为 fentry/blk_account_io_start, kprobe/blk_account_io_merge_bio 和
fentry/blk_account_io_done。fentry/blk_account_io_start 和 kprobe/blk_account_io_merge_bio
挂载点均时内核需要发起I/O操作中必经的初始化路径。在经过此处时，Biostacks 会根据 request queue ，将数据存入
map中。
```c
static __always_inline
int trace_start(void *ctx, struct request *rq, bool merge_bio)
{
	struct internal_rqinfo *i_rqinfop = NULL, i_rqinfo = {};
	struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
	dev_t dev;

	dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
			BPF_CORE_READ(disk, first_minor)) : 0;
	if (targ_dev != -1 && targ_dev != dev)
		return 0;

	if (merge_bio)
		i_rqinfop = bpf_map_lookup_elem(&rqinfos, &rq);
	if (!i_rqinfop)
		i_rqinfop = &i_rqinfo;

	i_rqinfop->start_ts = bpf_ktime_get_ns();
	i_rqinfop->rqinfo.pid = bpf_get_current_pid_tgid();
	i_rqinfop->rqinfo.kern_stack_size =
		bpf_get_stack(ctx, i_rqinfop->rqinfo.kern_stack,
			sizeof(i_rqinfop->rqinfo.kern_stack), 0);
	bpf_get_current_comm(&i_rqinfop->rqinfo.comm,
			sizeof(&i_rqinfop->rqinfo.comm));
	i_rqinfop->rqinfo.dev = dev;

	if (i_rqinfop == &i_rqinfo)
		bpf_map_update_elem(&rqinfos, &rq, i_rqinfop, 0);
	return 0;
}

SEC("fentry/blk_account_io_start")
int BPF_PROG(blk_account_io_start, struct request *rq)
{
	return trace_start(ctx, rq, false);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(blk_account_io_merge_bio, struct request *rq)
{
	return trace_start(ctx, rq, true);
}

```
在I/O操作完成后，fentry/blk_account_io_done 下的处理函数会从map中读取之前存入的信息，根据当下时间
记录时间差值，得到I/O操作的耗时信息，并更新到存储直方图数据的map中。
```c
SEC("fentry/blk_account_io_done")
int BPF_PROG(blk_account_io_done, struct request *rq)
{
	u64 slot, ts = bpf_ktime_get_ns();
	struct internal_rqinfo *i_rqinfop;
	struct rqinfo *rqinfop;
	struct hist *histp;
	s64 delta;

	i_rqinfop = bpf_map_lookup_elem(&rqinfos, &rq);
	if (!i_rqinfop)
		return 0;
	delta = (s64)(ts - i_rqinfop->start_ts);
	if (delta < 0)
		goto cleanup;
	histp = bpf_map_lookup_or_try_init(&hists, &i_rqinfop->rqinfo, &zero);
	if (!histp)
		goto cleanup;
	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&rqinfos, &rq);
	return 0;
}
```
在用户输入程序退出指令后，其用户态程序会将直方图map中的信息读出并打印。

### Eunomia中使用方式


### 总结
Biostacks 从源头实现了对I/O操作的追踪，可以极大的方便我们掌握磁盘I/O情况。