## eBPF 入门实践教程：编写 eBPF 程序 Biopattern: 统计随机/顺序磁盘 I/O

### 背景

Biopattern 可以统计随机/顺序磁盘I/O次数的比例。

### 实现原理

Biopattern 的ebpf代码在 tracepoint/block/block_rq_complete 挂载点下实现。在磁盘完成IO请求
后，程序会经过此挂载点。Biopattern 内部存有一张以设备号为主键的哈希表，当程序经过挂载点时, Biopattern
会获得操作信息，根据哈希表中该设备的上一次操作记录来判断本次操作是随机IO还是顺序IO，并更新操作计数。

```c
SEC("tracepoint/block/block_rq_complete")
int handle__block_rq_complete(struct trace_event_raw_block_rq_complete *ctx)
{
	sector_t *last_sectorp,  sector = ctx->sector;
	struct counter *counterp, zero = {};
	u32 nr_sector = ctx->nr_sector;
	dev_t dev = ctx->dev;

	if (targ_dev != -1 && targ_dev != dev)
		return 0;

	counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
	if (!counterp)
		return 0;
	if (counterp->last_sector) {
		if (counterp->last_sector == sector)
			__sync_fetch_and_add(&counterp->sequential, 1);
		else
			__sync_fetch_and_add(&counterp->random, 1);
		__sync_fetch_and_add(&counterp->bytes, nr_sector * 512);
	}
	counterp->last_sector = sector + nr_sector;
	return 0;
}

```
当用户停止Biopattern后，用户态程序会读取获得的计数信息，并将其输出给用户。

### Eunomia中使用方式

尚未集成

### 总结

Biopattern 可以展现随机/顺序磁盘I/O次数的比例，对于开发者把握整体I/O情况有较大帮助。