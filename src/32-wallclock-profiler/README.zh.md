# eBPF 开发实践教程：示例 32 - 结合 On-CPU 和 Off-CPU 分析的挂钟时间分析

性能瓶颈可能隐藏在两个截然不同的地方。你的代码可能在热循环中消耗 CPU 周期,也可能在空闲地等待 I/O、网络响应或锁竞争。传统的性能分析工具通常只关注故事的一面。但如果你能同时看到两者呢?

本教程介绍了一个完整的挂钟时间分析解决方案,它结合了 on-CPU 和 off-CPU 分析,使用 eBPF 技术实现。我们将展示如何捕获应用程序时间消耗的完整图景,使用两个互补的 eBPF 程序协同工作,追踪执行过程中的每一微秒。无论性能问题来自计算还是等待,你都能在统一的火焰图视图中发现它们。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/32-wallclock-profiler>

## 理解挂钟时间分析

挂钟时间是从开始到结束的实际经过时间,就像看秒表一样。对于任何运行的进程,这段时间分为两类。On-CPU 时间是指代码在处理器上主动执行、完成实际工作的时间。Off-CPU 时间是指进程存在但未运行,等待某些事件(如磁盘 I/O、网络数据包或获取锁)的时间。

传统的 CPU 分析器只展示 on-CPU 的故事。它们在代码运行时以固定间隔采样调用栈,构建出哪些函数消耗 CPU 周期的图景。但这些分析器对 off-CPU 时间视而不见。当你的线程在系统调用上阻塞或等待互斥锁时,分析器就看不到它了。这为那些花费大量时间等待的应用程序创造了巨大的盲点。

Off-CPU 分析器则反其道而行之。它们跟踪线程何时休眠和唤醒,测量阻塞时间并在阻塞点捕获调用栈。这揭示了 I/O 瓶颈和锁竞争问题。但它们错过了纯计算问题。

本教程中的工具通过同时运行两个 eBPF 程序解决了这两个问题。`oncputime` 工具使用 perf 事件采样 on-CPU 执行。`offcputime` 工具挂钩到内核调度器以捕获阻塞操作。一个 Python 脚本组合结果,对时间尺度进行标准化,这样你就能在同一个火焰图中看到 CPU 密集型代码路径(标记为红色)和阻塞操作(标记为蓝色)。这个完整的视图展示了每一微秒的去向。

下面是一个结合 on-CPU 和 off-CPU 分析结果的示例火焰图:

![结合挂钟时间火焰图示例](https://raw.githubusercontent.com/eunomia-bpf/bpf-developer-tutorial/c9d3d65c15fb6528ee378657a05ec0b062eff5b7/src/32-wallclock-profiler/tests/example.svg)

在这个可视化中,你可以清楚地看到 CPU 密集型工作(以红色/暖色显示,标记为 `_[c]`)和阻塞操作(以蓝色/冷色显示,标记为 `_[o]`)之间的区别。相对宽度立即揭示了应用程序在哪里花费了挂钟时间。

## 工具: oncputime 和 offcputime

本教程提供两个互补的分析工具。`oncputime` 工具使用 perf 事件以固定间隔采样你的进程,在代码主动在 CPU 上运行时捕获调用栈。默认速率为 49 Hz,大约每 20 毫秒唤醒一次以记录程序执行位置。输出中的采样计数越高,表示在这些代码路径上花费的 CPU 时间越多。

`offcputime` 工具采用不同的方法。它挂钩到内核调度器的上下文切换机制,具体来说是 `sched_switch` 追踪点。当线程离开 CPU 时,工具记录时间戳并捕获显示阻塞原因的调用栈。当线程恢复运行时,它计算线程休眠的时长。这直接测量 I/O 等待、锁竞争和其他以微秒为单位的阻塞操作。

两个工具都使用 BPF 栈映射以最小的开销高效地捕获内核和用户空间调用链。它们按唯一的调用栈聚合结果,因此同一代码路径的重复执行会被累加在一起。这些工具可以按进程 ID、线程 ID 和各种其他条件进行过滤,以便将分析集中在应用程序的特定部分。

## 实现: 内核空间 eBPF 程序

让我们在 eBPF 层面检查这些工具的工作原理。我们将从 on-CPU 分析器开始,然后看看 off-CPU 分析器,以及它们如何互补。

### 使用 oncputime 进行 On-CPU 分析

On-CPU 分析器使用 perf 事件以固定时间间隔采样执行。这是完整的 eBPF 程序:

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "oncputime.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} tids SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};
	u64 id;
	u32 pid;
	u32 tid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = id;

	if (!include_idle && tid == 0)
		return 0;

	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return 0;

	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap,
						    BPF_F_USER_STACK);

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

程序首先定义几个 BPF 映射。`stackmap` 是用于存储调用栈跟踪的特殊映射类型。当你调用 `bpf_get_stackid()` 时,内核会遍历栈并将指令指针存储在此映射中,返回一个 ID 供你稍后查找。`counts` 映射按包含进程 ID 和栈 ID 的复合键聚合样本。`pids` 和 `tids` 映射充当过滤器,让你可以将分析限制在特定进程或线程上。

主要逻辑位于 `do_perf_event()` 函数中,该函数在每次 perf 事件触发时运行。用户空间程序以特定频率(默认 49 Hz)为每个 CPU 核心设置这些 perf 事件。当 CPU 触发其定时器时,此函数在当时正在运行的任何进程上执行。它首先从当前任务中提取进程和线程 ID,然后应用任何配置的过滤器。如果当前线程应该被采样,它会构建一个包含进程名称和调用栈的键结构。

两次对 `bpf_get_stackid()` 的调用捕获执行上下文的不同部分。第一次调用没有标志,获取内核栈,显示哪些内核函数处于活动状态。第二次调用带有 `BPF_F_USER_STACK`,获取用户空间栈,显示应用程序的函数调用。这些栈 ID 进入键中,程序为该唯一组合递增计数器。随着时间推移,热代码路径被更频繁地采样,累积更高的计数。

### 使用 offcputime 进行 Off-CPU 分析

Off-CPU 分析器挂钩到调度器以测量阻塞时间。这是完整的 eBPF 程序:

```c
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "offcputime.h"

#define PF_KTHREAD		0x00200000

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 0;
const volatile bool filter_by_tgid = false;
const volatile bool filter_by_pid = false;
const volatile long state = -1;

struct internal_key {
	u64 start_ts;
	struct key_t key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct internal_key);
	__uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

static bool allow_record(struct task_struct *t)
{
	u32 tgid = BPF_CORE_READ(t, tgid);
	u32 pid = BPF_CORE_READ(t, pid);

	if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid))
		return false;
	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return false;
	if (user_threads_only && (BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	if (state != -1 && get_task_state(t) != state)
		return false;
	return true;
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct internal_key *i_keyp, i_key;
	struct val_t *valp, val;
	s64 delta;
	u32 pid;

	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		if (!pid)
			pid = bpf_get_smp_processor_id();
		i_key.key.pid = pid;
		i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		i_key.start_ts = bpf_ktime_get_ns();

		if (BPF_CORE_READ(prev, flags) & PF_KTHREAD)
			i_key.key.user_stack_id = -1;
		else
			i_key.key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		i_key.key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		bpf_map_update_elem(&start, &pid, &i_key, 0);
		bpf_probe_read_kernel_str(&val.comm, sizeof(prev->comm), BPF_CORE_READ(prev, comm));
		val.delta = 0;
		bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
	}

	pid = BPF_CORE_READ(next, pid);
	i_keyp = bpf_map_lookup_elem(&start, &pid);
	if (!i_keyp)
		return 0;
	delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
	if (delta < 0)
		goto cleanup;
	if (delta < min_block_ns || delta > max_block_ns)
		goto cleanup;
	delta /= 1000U;
	valp = bpf_map_lookup_elem(&info, &i_keyp->key);
	if (!valp)
		goto cleanup;
	__sync_fetch_and_add(&valp->delta, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
```

Off-CPU 分析器更复杂,因为它需要跨多个事件跟踪时间。`start` 映射存储离开 CPU 的线程的时间戳和栈信息。当线程阻塞时,我们记录何时发生以及为什么(调用栈)。当同一线程恢复运行时,我们计算它阻塞了多长时间。

调度器切换在繁忙系统上每秒发生多次,因此性能很重要。`allow_record()` 函数在执行昂贵操作之前快速过滤掉我们不关心的线程。如果线程通过过滤器,程序使用 `bpf_ktime_get_ns()` 捕获当前时间戳,并记录显示线程阻塞位置的调用栈。

关键洞察在于两阶段方法。`prev` 任务(离开 CPU 的线程)的阻塞点被记录,带有时间戳。当调度器稍后切换到 `next` 任务(唤醒的线程)时,我们查找是否之前记录了这个线程进入睡眠。如果找到记录,我们计算现在与它进入睡眠时之间的差值。这个差值就是以纳秒为单位的 off-CPU 时间,我们将其转换为微秒并添加到该调用栈的累积总数中。

### 用户空间程序: 加载和处理

两个工具在用户空间遵循类似的模式。它们使用 libbpf 加载编译的 eBPF 目标文件并将其附加到适当的事件。对于 `oncputime`,这意味着以所需的采样频率设置 perf 事件。对于 `offcputime`,这意味着附加到调度器追踪点。然后用户空间程序定期读取 BPF 映射,使用符号表将栈 ID 解析为实际函数名,并格式化输出。

符号解析由 blazesym 库处理,该库解析二进制文件中的 DWARF 调试信息。当你看到带有函数名和行号的调用栈时,那就是 blazesym 将原始指令指针地址转换为人类可读形式。用户空间程序以"折叠"格式输出,其中每行包含一个分号分隔的调用栈,后跟计数或时间值。这种格式直接输入到火焰图生成工具。

## 组合 On-CPU 和 Off-CPU 配置文件

真正的力量来自于将两个工具一起运行并合并它们的结果。`wallclock_profiler.py` 脚本编排这个过程。它在目标进程上同时启动两个分析器,等待它们完成,然后组合它们的输出。

挑战在于这两个工具以不同的单位测量不同的东西。On-CPU 分析器计数样本(默认每秒 49 个),而 off-CPU 分析器测量微秒。为了创建统一视图,脚本将 off-CPU 时间标准化为等效的样本计数。如果以 49 Hz 采样,每个样本代表约 20,408 微秒的潜在执行时间。脚本将 off-CPU 微秒除以此值以获得等效样本。

标准化后,脚本添加注释以区分两种类型的时间。On-CPU 调用栈获得 `_[c]` 后缀(表示计算),而 off-CPU 栈获得 `_[o]`(表示 off-CPU 或阻塞)。火焰图工具中的自定义调色板以不同颜色渲染这些,CPU 时间为红色,阻塞时间为蓝色。结果是一个单一的火焰图,你可以看到两种类型的活动及其相对幅度。

脚本还通过分别分析每个线程来处理多线程应用程序。它在启动时检测线程,为每个线程启动并行分析会话,并生成显示每个线程行为的单独火焰图。这有助于识别哪些线程忙碌,哪些空闲,以及你的并行性是否有效。

## 编译和执行

构建工具需要标准的 eBPF 开发环境。教程仓库在 `src/third_party/` 目录中包含所有依赖项。要构建:

```bash
cd src/32-wallclock-profiler
make
```

Makefile 使用 clang 编译 eBPF C 代码,使用 bpftool 生成骨架,构建 blazesym 符号解析器,并将所有内容与 libbpf 链接以创建最终可执行文件。

使用单独的工具:

```bash
# 分析 30 秒的 on-CPU 执行
sudo ./oncputime -p <PID> -F 99 30

# 分析 30 秒的 off-CPU 阻塞
sudo ./offcputime -p <PID> -m 1000 30

# 使用组合分析器(推荐)
sudo python3 wallclock_profiler.py <PID> -d 30 -f 99
```

让我们尝试分析一个同时执行 CPU 工作和阻塞 I/O 的测试程序:

```bash
# 构建并运行测试程序
cd tests
make
./test_combined &
TEST_PID=$!

# 使用组合分析器分析它
cd ..
sudo python3 wallclock_profiler.py $TEST_PID -d 30

# 这会生成:
# - combined_profile_pid<PID>_<timestamp>.folded (原始数据)
# - combined_profile_pid<PID>_<timestamp>.svg (火焰图)
# - combined_profile_pid<PID>_<timestamp>_single_thread_analysis.txt (时间分解)
```

输出的火焰图将显示 `cpu_work()` 函数消耗 CPU 时间的红色帧,以及 `blocking_work()` 函数在睡眠中花费时间的蓝色帧。相对宽度显示每个消耗的挂钟时间量。

对于多线程应用程序,分析器创建一个包含每线程结果的目录:

```bash
# 分析多线程应用程序
sudo python3 wallclock_profiler.py <PID> -d 30

# 输出在 multithread_combined_profile_pid<PID>_<timestamp>/ 中
# - thread_<TID>_main.svg (主线程火焰图)
# - thread_<TID>_<role>.svg (工作线程火焰图)
# - *_thread_analysis.txt (所有线程的时间分析)
```

分析文件显示时间统计,让你验证 on-CPU 加 off-CPU 时间是否正确累加到挂钟分析持续时间。覆盖百分比有助于识别线程是否大多空闲或是否缺少数据。

## 解读结果

在浏览器中打开火焰图 SVG 时,每个水平框代表调用栈中的一个函数。宽度显示在那里花费了多少时间。垂直堆叠的框显示调用链,较低的框调用较高的框。红色框表示 on-CPU 时间,蓝色框显示 off-CPU 时间。

寻找宽的红色部分以找到 CPU 瓶颈。这些是在紧密循环或昂贵算法中消耗周期的函数。宽的蓝色部分表示阻塞操作。常见模式包括文件 I/O(读/写系统调用)、网络操作(recv/send)和锁竞争(futex 调用)。

火焰图是交互式的。单击任何框以放大并查看该子树的详细信息。搜索功能让你突出显示匹配模式的所有帧,这对查找特定函数或库很有用。悬停显示完整的函数名和确切的样本计数或时间值。

注意相对比例。90% 蓝色的应用程序是 I/O 绑定的,可能不会从 CPU 优化中受益太多。大部分红色的应用程序是 CPU 绑定的。红色和蓝色均分的应用程序可能受益于重叠计算和 I/O,例如使用异步 I/O 或线程。

对于多线程配置文件,比较每个线程的火焰图。理想情况下,如果工作负载平衡,工作线程应该显示相似的模式。如果一个线程大多是红色而其他线程大多是蓝色,你可能有负载不平衡。如果所有线程在 futex 等待中显示大量蓝色时间,具有相似的栈,那就是锁竞争。

## 总结

使用 eBPF 进行挂钟时间分析通过结合 on-CPU 和 off-CPU 分析,为你提供应用程序性能的完整可见性。On-CPU 分析器采样执行以查找消耗 CPU 周期的热代码路径。Off-CPU 分析器挂钩到调度器以测量阻塞时间并识别 I/O 瓶颈或锁竞争。它们一起统计挂钟时间的每一微秒,显示应用程序实际花费生命的地方。

这些工具使用 eBPF 的低开销检测来收集这些数据,对目标应用程序的影响最小。调用栈捕获和聚合在内核中进行,避免昂贵的上下文切换。用户空间程序只需要定期读取累积结果并解析符号,即使在生产环境中使用,开销也可以忽略不计。

通过在带有颜色编码的单个火焰图中可视化两种类型的时间,你可以快速识别问题是计算性质还是阻塞性质。这比传统的只显示图景一面的分析方法更有效地指导优化工作。多线程分析支持揭示并行性问题和线程级瓶颈。

> 如果你想更深入地了解 eBPF,请访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/>

## 参考资料

- BCC libbpf-tools offcputime: <https://github.com/iovisor/bcc/tree/master/libbpf-tools>
- BCC libbpf-tools profile: <https://github.com/iovisor/bcc/tree/master/libbpf-tools>
- Blazesym 符号解析: <https://github.com/libbpf/blazesym>
- FlameGraph 可视化: <https://github.com/brendangregg/FlameGraph>
- Brendan Gregg 的 "Off-CPU Analysis": <http://www.brendangregg.com/offcpuanalysis.html>

> 本文原文链接: <https://eunomia.dev/zh/tutorials/32-wallclock-profiler>
