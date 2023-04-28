# eBPF 入门实践教程：编写 eBPF 程序 Memleak 监控内存泄漏

## 背景

内存泄漏对于一个程序而言是一个很严重的问题。倘若放任一个存在内存泄漏的程序运行，久而久之
系统的内存会慢慢被耗尽，导致程序运行速度显著下降。为了避免这一情况，`memleak`工具被提出。
它可以跟踪并匹配内存分配和释放的请求，并且打印出已经被分配资源而又尚未释放的堆栈信息。

## 实现原理

`memleak` 的实现逻辑非常直观。它在我们常用的动态分配内存的函数接口路径上挂载了ebpf程序，
同时在free上也挂载了ebpf程序。在调用分配内存相关函数时，`memleak` 会记录调用者的pid，分配得到
内存的地址，分配得到的内存大小等基本数据。在free之后，`memeleak`则会去map中删除记录的对应的分配
信息。对于用户态常用的分配函数 `malloc`, `calloc` 等，`memleak`使用了 uporbe 技术实现挂载，对于
内核态的函数，比如 `kmalloc` 等，`memleak` 则使用了现有的 tracepoint 来实现。

## 编写 eBPF 程序

```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps"); 

struct alloc_info {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

union combined_alloc_info {
	struct {
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	};
	__u64 bits;
};
```
这段代码定义了memleak工具中使用的5个BPF Map：
+ sizes用于记录程序中每个内存分配请求的大小；
+ allocs用于跟踪每个内存分配请求的详细信息，包括请求的大小、堆栈信息等；
+ combined_allocs的键是堆栈的唯一标识符(stack id)，值是一个combined_alloc_info联合体，用于记录该堆栈的内存分配总大小和内存分配数量；
+ memptrs用于跟踪每个内存分配请求返回的指针，以便在内存释放请求到来时找到对应的内存分配请求；
+ stack_traces是一个堆栈跟踪类型的哈希表，用于存储每个线程的堆栈信息（key为线程id，value为堆栈跟踪信息）以便在内存分配和释放请求到来时能够追踪和分析相应的堆栈信息。

其中combined_alloc_info是一个联合体，其中包含一个结构体和一个unsigned long long类型的变量bits。结构体中的两个成员变量total_size和number_of_allocs分别表示总分配大小和分配的次数。其中40和24分别表示total_size和number_of_allocs这两个成员变量所占用的位数，用来限制其大小。通过这样的位数限制，可以节省combined_alloc_info结构的存储空间。同时，由于total_size和number_of_allocs在存储时是共用一个unsigned long long类型的变量bits，因此可以通过在成员变量bits上进行位运算来访问和修改total_size和number_of_allocs，从而避免了在程序中定义额外的变量和函数的复杂性。

```c
static int gen_alloc_enter(size_t size)
{
	if (size < min_size || size > max_size)
		return 0;

	if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc entered, size = %lu\n", size);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}
```
这个函数用于处理内存分配请求的进入事件。它会首先检查内存分配请求的大小是否在指定的范围内，如果不在范围内，则直接返回0表示不处理该事件。如果启用了采样率(sample_rate > 1)，则该函数会采样内存分配请求的进入事件。如果当前时间戳不是采样周期的倍数，则也会直接返回0，表示不处理该事件。接下来，该函数会获取当前线程的PID并将其存储在pid变量中。然后，它会将当前线程的pid和请求的内存分配大小存储在sizes map中，以便后续收集和分析内存分配信息。如果开启了跟踪模式(trace_all)，该函数会通过bpf_printk打印日志信息，以便用户实时监控内存分配的情况。

最后定义了BPF_KPROBE(malloc_enter, size_t size)，它会在malloc函数被调用时被BPF uprobe拦截执行，并通过gen_alloc_enter来记录内存分配大小。

```c
static void update_statistics_add(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
	if (!existing_cinfo)
		return;

	const union combined_alloc_info incremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}
static int gen_alloc_exit2(void *ctx, u64 address)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	const u64* size = bpf_map_lookup_elem(&sizes, &pid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

		update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all) {
		bpf_printk("alloc exited, size = %lu, result = %lx\n",
				info.size, address);
	}

	return 0;
}
static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}
```

gen_alloc_exit2函数会在内存释放时被调用，它用来记录内存释放的信息，并更新相关的 map。具体地，它首先通过 bpf_get_current_pid_tgid 来获取当前进程的 PID，并将其右移32位，获得PID值，然后使用 bpf_map_lookup_elem 查找 sizes map 中与该 PID 相关联的内存分配大小信息，并将其赋值给 info.size。如果找不到相应的 entry，则返回 0，表示在内存分配时没有记录到该 PID 相关的信息。接着，它会调用 __builtin_memset 来将 info 的所有字段清零，并调用 bpf_map_delete_elem 来删除 sizes map 中与该 PID 相关联的 entry。

如果 address 不为 0，则说明存在相应的内存分配信息，此时它会调用 bpf_ktime_get_ns 来获取当前时间戳，并将其赋值给 info.timestamp_ns。然后，它会调用 bpf_get_stackid 来获取当前函数调用堆栈的 ID，并将其赋值给 info.stack_id。最后，它会调用 bpf_map_update_elem 来将 address 和 info 相关联，即将 address 映射到 info。随后，它会调用 update_statistics_add 函数来更新 combined_allocs map 中与 info.stack_id 相关联的内存分配信息。

最后，如果 trace_all 为真，则会调用 bpf_printk 打印相关的调试信息。

update_statistics_add函数的主要作用是更新内存分配的统计信息，其中参数stack_id是当前内存分配的堆栈ID，sz是当前内存分配的大小。该函数首先通过bpf_map_lookup_or_try_init函数在combined_allocs map中查找与当前堆栈ID相关联的combined_alloc_info结构体，如果找到了，则将新的分配大小和分配次数加入到已有的combined_alloc_info结构体中；如果未找到，则使用initial_cinfo初始化一个新的combined_alloc_info结构体，并添加到combined_allocs map中。

更新combined_alloc_info结构体的方法是使用__sync_fetch_and_add函数，原子地将incremental_cinfo中的值累加到existing_cinfo中的值中。通过这种方式，即使多个线程同时调用update_statistics_add函数，也可以保证计数的正确性。

在gen_alloc_exit函数中，将ctx参数传递给gen_alloc_exit2函数，并将它的返回值作为自己的返回值。这里使用了PT_REGS_RC宏获取函数返回值。

最后定义的BPF_KRETPROBE(malloc_exit)是一个kretprobe类型的函数，用于在malloc函数返回时执行。并调用gen_alloc_exit函数跟踪内存分配和释放的请求。
```c
static void update_statistics_del(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (!existing_cinfo) {
		bpf_printk("failed to lookup combined allocs\n");

		return;
	}

	const union combined_alloc_info decremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

static int gen_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
		bpf_printk("free entered, address = %lx, size = %lu\n",
				address, info->size);
	}

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
	return gen_free_enter(address);
}
```
gen_free_enter函数接收一个地址参数，该函数首先使用allocs map查找该地址对应的内存分配信息。如果未找到，则表示该地址没有被分配，该函数返回0。如果找到了对应的内存分配信息，则使用bpf_map_delete_elem从allocs map中删除该信息。

接下来，调用update_statistics_del函数用于更新内存分配的统计信息，它接收堆栈ID和内存块大小作为参数。首先在combined_allocs map中查找堆栈ID对应的内存分配统计信息。如果没有找到，则输出一条日志，表示查找失败，并且函数直接返回。如果找到了对应的内存分配统计信息，则使用原子操作从内存分配统计信息中减去该内存块大小和1（表示减少了1个内存块）。这是因为堆栈ID对应的内存块数量减少了1，而堆栈ID对应的内存块总大小也减少了该内存块的大小。

最后定义了一个bpf程序BPF_KPROBE(free_enter, void *address)会在进程调用free函数时执行。它会接收参数address，表示正在释放的内存块的地址，并调用gen_free_enter函数来处理该内存块的释放。

## 编译运行

```console
$ git clone https://github.com/iovisor/bcc.git --recurse-submodules 
$ cd libbpf-tools/
$ make memleak
$ sudo ./memleak 
using default object: libc.so.6
using page size: 4096
tracing kernel: true
Tracing outstanding memory allocs...  Hit Ctrl-C to end
[17:17:27] Top 10 stacks with outstanding allocations:
1236992 bytes in 302 allocations from stack
        0 [<ffffffff812c8f43>] <null sym>
        1 [<ffffffff812c8f43>] <null sym>
        2 [<ffffffff812a9d42>] <null sym>
        3 [<ffffffff812aa392>] <null sym>
        4 [<ffffffff810df0cb>] <null sym>
        5 [<ffffffff81edc3fd>] <null sym>
        6 [<ffffffff82000b62>] <null sym>
...
```

## 总结

memleak是一个内存泄漏监控工具，可以用来跟踪内存分配和释放时间对应的调用栈信息。随着时间的推移，这个工具可以显示长期不被释放的内存。

这份代码来自于https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.bpf.c
