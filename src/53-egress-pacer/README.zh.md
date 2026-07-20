# eBPF 教程：用 BPF Qdisc 实现出口限速

想给测试环境里的一条虚拟网线限个速？比方说，把 veth 压到 64 Kbit/s，看看丢包之前队列能塞多少报文。

本课属于 eBPF Tutorial by Example 系列。eBPF 让用户态把经过 verifier 检查的程序加载到内核，再挂到某个子系统。`struct_ops` 进一步允许 BPF 提供一张操作表，子系统随后调用其中的回调。普通 TC BPF 程序可以检查和处理报文，排队和发送时间仍由原有的 qdisc 管理。Linux 6.16 通过 `struct_ops` 引入了 BPF 实现的 `Qdisc_ops` 回调。程序实现 `enqueue`、`dequeue`、`init`、`reset` 和 `destroy`，可以动态注册为一个 qdisc。

本课的 `egress_pacer` 正是用这种方式构建的 FIFO 限速器。它注册为 root qdisc，自己管理 `skb` 入队，按报文长度计算发送时间，使用 `watchdog` 唤醒 `dequeue`，并在移除时清理队列中的报文。给出速率和队列上限后，它把报文存起来，到点再放，最后报告入队、发送和丢包统计。这个例子用一条聚合 FIFO 展示 `skb` 所有权、发送时序和 qdisc 清理，适合在 `veth`、`TAP` 或 `IFB` 这类受控接口上观察完整流程。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## 普通 TC BPF 与 Qdisc 所有权

普通 TC BPF 程序把队列所有权留给原有的 qdisc，因此只能检查报文和决定放行或丢弃。[第 20 课](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) 展示的就是这条常用路径。`egress_pacer` 用 `struct_ops` 实现 `struct Qdisc_ops`，自己成为 root qdisc，同时拥有入队和出队两个阶段。内核把 skb 交过来之后，排队和发送时间都由这段 BPF 程序决定。

先跟着一个报文走一遍。用户态设置速率和队列上限，加载 `bpf_pacer`，再把它挂到 `TC_H_ROOT`。报文到达时，`enqueue` 把 skb 装进 BPF 管理的节点，并算出它最早可以离开的时间。轮到 `dequeue` 时，到点的报文交还 skb；早到的报文设置 watchdog，等内核稍后再来。最后，用户态移除 qdisc，`reset` 收走仍在队列里的报文。后面的代码都围绕这条路径展开。

![egress_pacer 数据流：从配置、挂载、入队、BPF FIFO、出队到发送路径，包含 policy-drop 分支、watchdog 循环和 reset 生命周期](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/53-egress-pacer/egress-pacer-flow.png)

图中实线从配置和挂载开始，随后跟踪一个 skb 从 enqueue 进入 BPF FIFO，再由 dequeue 交还给发送路径；队列已满或节点分配返回空时走 policy-drop 分支。早到的 dequeue 把节点推回队首，安排 watchdog 并返回 NULL，等 watchdog 唤醒后重新进入 dequeue。虚线表示生命周期路径：移除 root qdisc 后 reset 释放队列中的 skb 并清零 qlen 和 backlog。

## 从共享数据开始搭起 Pacer

共享数据契约在回调之前。BPF 程序负责排队，用户态负责安装和汇报结果，两边先约定相同的统计数据布局。

### 用一个头文件约定统计格式

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EGRESS_PACER_H
#define __EGRESS_PACER_H

struct pacer_stats {
	unsigned long long enqueued;
	unsigned long long dequeued;
	unsigned long long policy_dropped;
	unsigned long long cleanup_dropped;
	unsigned long long bytes_dequeued;
	unsigned long long max_qlen;
};

#endif /* __EGRESS_PACER_H */
```

这六个字段把报文的一生分成几种结果。成功进入和离开 FIFO 的报文分别计入 `enqueued`、`dequeued`。队列已满或节点分配失败时，`policy_dropped` 增加；reset 时仍在队列中的报文则进入 `cleanup_dropped`。`bytes_dequeued` 累计实际交还给发送路径的字节数，`max_qlen` 记住队列最深的一刻。

这些计数器位于 BSS。qdisc 被移除后，加载器直接从 `skel->bss->stats` 读取它们。两端包含同一个头文件，布局始终一致。

### 给旧版头文件补上 qdisc 所需声明

这个示例需要 graph-object kfunc，因此用一个本地兼容头文件补齐 BPF qdisc 声明。这些声明仅存在于本课目录，与仓库统一使用的头文件相互独立。

```c
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EGRESS_PACER_BPF_EXPERIMENTAL_H
#define __EGRESS_PACER_BPF_EXPERIMENTAL_H

#include <bpf/bpf_core_read.h>

#define __contains(name, node) \
	__attribute__((btf_decl_tag("contains:" #name ":" #node)))

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
#define bpf_obj_new(type) \
	((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))

extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

extern int bpf_list_push_front_impl(struct bpf_list_head *head,
				    struct bpf_list_node *node,
				    void *meta, __u64 off) __ksym;
#define bpf_list_push_front(head, node) \
	bpf_list_push_front_impl(head, node, NULL, 0)

extern int bpf_list_push_back_impl(struct bpf_list_head *head,
				   struct bpf_list_node *node,
				   void *meta, __u64 off) __ksym;
#define bpf_list_push_back(head, node) \
	bpf_list_push_back_impl(head, node, NULL, 0)

extern struct bpf_list_node *
bpf_list_pop_front(struct bpf_list_head *head) __ksym;

#endif /* __EGRESS_PACER_BPF_EXPERIMENTAL_H */
```

这个文件只提供构建队列所需的 graph-object 辅助函数。`bpf_obj_new` 创建报文节点，`bpf_obj_drop` 在节点用完后释放它。`bpf_list_push_back` 和 `bpf_list_pop_front` 让这些节点组成 FIFO。`__contains` 生成 BTF tag，告诉 verifier 这个 list head 装的是哪一种节点，使 verifier 可以安全地跟踪链表对象。

把兼容代码留在本课目录还有一个好处：它和限速逻辑是分开的。等仓库生成的 libbpf 头文件提供同样的声明后，可以直接删掉这层胶水，qdisc 实现保持原样。

### 在 BPF 中实现整个 Qdisc 生命周期

现在来看内核态的完整程序。一个文件里放着 qdisc 回调、FIFO、限速时钟和统计更新。代码较长，但主线只有三步：`enqueue` 接管 skb，`dequeue` 在合适时间交还 skb，`reset` 排空剩余队列。

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "egress_pacer.h"

char LICENSE[] SEC("license") = "GPL";

#define NET_XMIT_SUCCESS 0x00
#define NET_XMIT_DROP 0x01
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

struct bpf_sk_buff_ptr {
	struct sk_buff *skb;
};

extern void bpf_qdisc_skb_drop(struct sk_buff *skb,
				       struct bpf_sk_buff_ptr *to_free) __ksym;
extern void bpf_qdisc_watchdog_schedule(struct Qdisc *sch, __u64 expire,
					__u64 delta_ns) __ksym;
extern void bpf_qdisc_bstats_update(struct Qdisc *sch,
				    const struct sk_buff *skb) __ksym;
extern void bpf_kfree_skb(struct sk_buff *skb) __ksym;

const volatile __u64 rate_kbps = 1024;
const volatile __u32 queue_limit = 256;

struct pacer_stats stats;

struct packet_node {
	__u64 eligible_ns;
	__u32 packet_len;
	struct sk_buff __kptr *skb;
	struct bpf_list_node node;
};

private(A) struct bpf_spin_lock queue_lock;
private(A) struct bpf_list_head packet_queue __contains(packet_node, node);
private(A) __u64 next_departure_ns;

static struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static __u32 qdisc_packet_len(const struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

SEC("struct_ops/egress_pacer_enqueue")
int BPF_PROG(egress_pacer_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct packet_node *packet;
	__u64 eligible_ns, interval_ns, now;
	__u32 packet_len;

	packet_len = qdisc_packet_len(skb);
	if (sch->q.qlen >= sch->limit)
		goto drop;

	packet = bpf_obj_new(typeof(*packet));
	if (!packet)
		goto drop;

	now = bpf_ktime_get_ns();
	interval_ns = (__u64)packet_len * 8 * 1000000ULL / rate_kbps;
	if (!interval_ns)
		interval_ns = 1;
	packet->packet_len = packet_len;
	skb = bpf_kptr_xchg(&packet->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&queue_lock);
	eligible_ns = next_departure_ns > now ? next_departure_ns : now;
	next_departure_ns = eligible_ns + interval_ns;
	packet->eligible_ns = eligible_ns;
	bpf_list_push_back(&packet_queue, &packet->node);
	sch->q.qlen++;
	sch->qstats.backlog += packet_len;
	__sync_fetch_and_add(&stats.enqueued, 1);
	if (sch->q.qlen > stats.max_qlen)
		stats.max_qlen = sch->q.qlen;
	bpf_spin_unlock(&queue_lock);
	return NET_XMIT_SUCCESS;

drop:
	bpf_qdisc_skb_drop(skb, to_free);
	__sync_fetch_and_add(&stats.policy_dropped, 1);
	return NET_XMIT_DROP;
}

SEC("struct_ops/egress_pacer_dequeue")
struct sk_buff *BPF_PROG(egress_pacer_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct packet_node *packet;
	struct sk_buff *skb = NULL;
	__u64 expire, now;
	__u32 packet_len;

	bpf_spin_lock(&queue_lock);
	node = bpf_list_pop_front(&packet_queue);
	bpf_spin_unlock(&queue_lock);
	if (!node) {
		return NULL;
	}

	packet = container_of(node, struct packet_node, node);
	now = bpf_ktime_get_ns();
	if (now < packet->eligible_ns) {
		expire = packet->eligible_ns;
		bpf_spin_lock(&queue_lock);
		bpf_list_push_front(&packet_queue, &packet->node);
		bpf_spin_unlock(&queue_lock);
		bpf_qdisc_watchdog_schedule(sch, expire, 0);
		return NULL;
	}

	packet_len = packet->packet_len;
	skb = bpf_kptr_xchg(&packet->skb, skb);
	bpf_spin_lock(&queue_lock);
	sch->q.qlen--;
	sch->qstats.backlog -= packet_len;
	bpf_spin_unlock(&queue_lock);
	bpf_obj_drop(packet);

	if (!skb)
		return NULL;

	bpf_qdisc_bstats_update(sch, skb);
	__sync_fetch_and_add(&stats.dequeued, 1);
	__sync_fetch_and_add(&stats.bytes_dequeued, packet_len);
	return skb;
}

SEC("struct_ops/egress_pacer_init")
int BPF_PROG(egress_pacer_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	(void)opt;
	(void)extack;
	sch->limit = queue_limit;
	return 0;
}

SEC("struct_ops/egress_pacer_reset")
void BPF_PROG(egress_pacer_reset, struct Qdisc *sch)
{
	int queued = sch->q.qlen;
	int i;

	bpf_for(i, 0, queued) {
		struct bpf_list_node *node;
		struct packet_node *packet;
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&queue_lock);
		node = bpf_list_pop_front(&packet_queue);
		bpf_spin_unlock(&queue_lock);
		if (!node)
			break;

		packet = container_of(node, struct packet_node, node);
		skb = bpf_kptr_xchg(&packet->skb, skb);
		if (skb) {
			bpf_kfree_skb(skb);
			__sync_fetch_and_add(&stats.cleanup_dropped, 1);
		}
		bpf_obj_drop(packet);
	}

	bpf_spin_lock(&queue_lock);
	next_departure_ns = 0;
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
	bpf_spin_unlock(&queue_lock);
}

SEC("struct_ops/egress_pacer_destroy")
void BPF_PROG(egress_pacer_destroy, struct Qdisc *sch)
{
	(void)sch;
}

SEC(".struct_ops")
struct Qdisc_ops pacer = {
	.enqueue = (void *)egress_pacer_enqueue,
	.dequeue = (void *)egress_pacer_dequeue,
	.init = (void *)egress_pacer_init,
	.reset = (void *)egress_pacer_reset,
	.destroy = (void *)egress_pacer_destroy,
	.id = "bpf_pacer",
};
```

#### `enqueue`：接管 skb，并排好发送时间

初始化时，`init` 把用户选择的 `queue_limit` 放进 `sch->limit`。此后每次调用 `egress_pacer_enqueue`，程序都必须给传入的 skb 一个明确结果。它先从 `qdisc_skb_cb(skb)->pkt_len` 取得 qdisc 看到的报文长度，再检查队列是否还有位置，最后用 `bpf_obj_new` 创建 `packet_node`。队列已满或节点创建失败都走同一条 policy-drop 路径，并增加 `policy_dropped`。

真正的所有权转移发生在 `bpf_kptr_xchg`。调用成功后，skb 被放进节点的 `__kptr` 字段，节点从此负责保管它。节点还记录报文长度和 `eligible_ns`。程序随后拿住 `queue_lock`，把节点推到 FIFO 尾部，并在同一个临界区内更新 qlen、backlog、`enqueued` 和 `max_qlen`，避免链表内容与计数彼此脱节。

发送间隔随报文长度按目标速率伸缩：

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

队列空闲一段时间后，`next_departure_ns` 会早于当前时间，因此新来的第一个报文可以立刻离开。只要 FIFO 中持续有数据，后面的报文就按自己的长度继续推动这只时钟。这是一个聚合 FIFO 时间表，每个报文的发送间隔由自身长度决定。

#### `dequeue`：watchdog 安排下一次出队

`egress_pacer_dequeue` 每次只看 FIFO 最前面的节点。它取出节点，把 `eligible_ns` 与 `bpf_ktime_get_ns()` 返回的当前时间比较。报文已经可以发送时，第二次 `bpf_kptr_xchg` 把 skb 从节点交回 qdisc。程序接着扣减 qlen 和 backlog，释放已经空掉的节点，更新 qdisc 自身的字节统计，再增加 `dequeued` 和 `bytes_dequeued`。

如果队首报文来早了，程序把节点放回队首，用 `bpf_qdisc_watchdog_schedule(sch, expire, 0)` 预约下一次唤醒，然后返回 `NULL`。qdisc 核心在 `eligible_ns` 附近再次调用 dequeue。等待期间由内核 watchdog 负责，BPF 代码立即返回。

#### `reset`：为队列里剩下的 skb 收尾

`egress_pacer_reset` 负责释放移除 qdisc 时队列中仍然保留的 skb。它按当前 qlen 用 `bpf_for` 逐个取出节点，调用 `bpf_kfree_skb` 释放其中的 skb，再销毁节点对象。这里清掉的报文计入 `cleanup_dropped`，与 enqueue 阶段的 `policy_dropped` 分开。链表排空后，reset 把限速时钟、qlen 和 backlog 一起归零。

这样一来，每个计数器都有清楚的更新位置，也能对应到一种可观察的结果：

| 字段 | 含义 |
| --- | --- |
| `enqueued` | 成功进入 FIFO 的报文数 |
| `dequeued` | 已返回给发送路径的报文数 |
| `policy_dropped` | 队列达到上限或节点分配失败时拒绝的报文数 |
| `cleanup_dropped` | qdisc reset 时排空的报文数 |
| `bytes_dequeued` | dequeue 返回的 qdisc 报文总字节数 |
| `max_qlen` | FIFO 的报文占用峰值 |

### 用用户态程序安装和移除 Qdisc

内核态代码只定义 qdisc 怎样工作。下面的用户态程序负责把配置写进去，完成加载和注册，把 qdisc 安装到指定接口，并在运行时间结束后安全移除它。

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <getopt.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "egress_pacer.h"
#include "egress_pacer.skel.h"

static volatile sig_atomic_t exiting;

static struct env {
	const char *interface;
	unsigned long long rate_kbps;
	unsigned int queue_limit;
	unsigned int duration;
	bool verbose;
} env = {
	.rate_kbps = 1024,
	.queue_limit = 256,
	.duration = 10,
};

static void handle_signal(int signal)
{
	(void)signal;
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s --interface IFACE [--rate-kbps KBPS] "
		"[--queue-limit PACKETS] [--duration SEC] [--verbose]\n\n"
		"Temporarily pace one interface with a bounded BPF qdisc.\n\n"
		"Options:\n"
		"  -i, --interface IFACE       interface to control (required)\n"
		"  -r, --rate-kbps KBPS       egress rate, 8-100000000 "
		"(default: 1024)\n"
		"  -q, --queue-limit PACKETS  queue capacity, 1-65535 "
		"(default: 256)\n"
		"  -d, --duration SEC         control window, 1-86400 "
		"(default: 10)\n"
		"  -v, --verbose              print libbpf diagnostics\n"
		"  -h, --help                 show this help\n",
		program);
}

static int parse_u64(const char *value, unsigned long long maximum,
			     unsigned long long *result)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || end == value || *end || parsed > maximum)
		return -EINVAL;
	*result = parsed;
	return 0;
}

static int parse_rate(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 100000000, &parsed) || parsed < 8) {
		fprintf(stderr, "invalid rate in Kbit/s: %s\n", value);
		return -EINVAL;
	}
	env.rate_kbps = parsed;
	return 0;
}

static int parse_queue_limit(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 65535, &parsed) || parsed == 0) {
		fprintf(stderr, "invalid queue limit: %s\n", value);
		return -EINVAL;
	}
	env.queue_limit = parsed;
	return 0;
}

static int parse_duration(const char *value)
{
	unsigned long long parsed;

	if (parse_u64(value, 86400, &parsed) || parsed == 0) {
		fprintf(stderr, "invalid duration in seconds: %s\n", value);
		return -EINVAL;
	}
	env.duration = parsed;
	return 0;
}

static int parse_option(int option, const char *program)
{
	switch (option) {
	case 'i':
		env.interface = optarg;
		return 0;
	case 'r':
		return parse_rate(optarg);
	case 'q':
		return parse_queue_limit(optarg);
	case 'd':
		return parse_duration(optarg);
	case 'v':
		env.verbose = true;
		return 0;
	case 'h':
		usage(program);
		exit(0);
	default:
		return -EINVAL;
	}
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "rate-kbps", required_argument, NULL, 'r' },
		{ "queue-limit", required_argument, NULL, 'q' },
		{ "duration", required_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int error, option;

	while ((option = getopt_long(argc, argv, "i:r:q:d:vh", options, NULL)) != -1) {
		error = parse_option(option, argv[0]);
		if (error)
			return error;
	}

	if (!env.interface) {
		fprintf(stderr, "--interface is required\n");
		return -EINVAL;
	}
	if (optind != argc)
		return -EINVAL;
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec timestamp;

	if (clock_gettime(CLOCK_MONOTONIC, &timestamp))
		return -errno;
	return timestamp.tv_sec * 1000LL + timestamp.tv_nsec / 1000000;
}

static int wait_for_duration(void)
{
	struct timespec interval = { .tv_nsec = 100000000 };
	long long deadline, now;

	now = monotonic_milliseconds();
	if (now < 0)
		return (int)now;
	deadline = now + env.duration * 1000LL;

	while (!exiting) {
		now = monotonic_milliseconds();
		if (now < 0)
			return (int)now;
		if (now >= deadline)
			break;
		if (nanosleep(&interval, NULL) && errno != EINTR)
			return -errno;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct egress_pacer_bpf *skel = NULL;
	struct pacer_stats final_stats = {};
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.attach_point = BPF_TC_QDISC,
		.parent = TC_H_ROOT,
		.handle = TC_H_MAKE(1 << 16, 0),
		.qdisc = "bpf_pacer",
	};
	bool qdisc_created = false;
	unsigned int ifindex;
	int cleanup_err;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(env.interface);
	if (!ifindex) {
		fprintf(stderr, "interface does not exist: %s\n", env.interface);
		return 1;
	}
	hook.ifindex = ifindex;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = egress_pacer_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->rate_kbps = env.rate_kbps;
	skel->rodata->queue_limit = env.queue_limit;

	err = egress_pacer_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load BPF qdisc: %s\n"
			"This tool requires Linux 6.16+, CONFIG_NET_SCH_BPF, "
			"BTF, and BPF JIT.\n",
			strerror(-err));
		goto cleanup;
	}

	err = egress_pacer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to register bpf_pacer qdisc: %s\n",
			strerror(-err));
		goto cleanup;
	}

	err = bpf_tc_hook_create(&hook);
	if (err) {
		if (err == -EEXIST)
			fprintf(stderr,
				"refusing to replace the existing root qdisc on %s\n",
				env.interface);
		else
			fprintf(stderr, "failed to attach bpf_pacer to %s: %s\n",
				env.interface, strerror(-err));
		goto cleanup;
	}
	qdisc_created = true;

	printf("READY interface=%s rate_kbps=%llu queue_limit=%u duration=%u\n",
	       env.interface, env.rate_kbps, env.queue_limit, env.duration);
	fflush(stdout);

	err = wait_for_duration();

cleanup:
	if (qdisc_created) {
		cleanup_err = bpf_tc_hook_destroy(&hook);
		if (cleanup_err) {
			fprintf(stderr, "failed to remove bpf_pacer from %s: %s\n",
				env.interface, strerror(-cleanup_err));
			if (!err)
				err = cleanup_err;
		}
	}
	if (skel && skel->bss)
		final_stats = skel->bss->stats;
	if (qdisc_created) {
		printf("SUMMARY enqueued=%llu dequeued=%llu policy_dropped=%llu "
		       "cleanup_dropped=%llu bytes_dequeued=%llu max_qlen=%llu\n",
		       final_stats.enqueued, final_stats.dequeued,
		       final_stats.policy_dropped, final_stats.cleanup_dropped,
		       final_stats.bytes_dequeued, final_stats.max_qlen);
	}
	egress_pacer_bpf__destroy(skel);
	return err != 0;
}
```

#### 从配置到清理，始终只操作目标接口

加载器解析完参数后，先把速率和队列上限写入 `skel->rodata->rate_kbps` 与 `skel->rodata->queue_limit`。加载步骤冻结 rodata，因此配置必须发生在 `egress_pacer_bpf__load()` 之前。内核验证程序通过后，attach skeleton 注册 `struct_ops` 实现。最后，`bpf_tc_hook_create` 在目标 ifindex 的 `BPF_TC_QDISC`、`TC_H_ROOT` 位置创建名为 `bpf_pacer` 的 root qdisc。

创建请求带着独占语义。目标接口已经有 root qdisc 时，内核返回 `-EEXIST`，程序立即停止，保留现有配置。这种独占做法限制了教程代码的作用范围，因此适合把它用在专门创建的测试接口上。

安装成功后，程序打印 `READY`，再每隔 100 ms 检查运行时间和 `exiting` 标志。时间到、SIGINT 和 SIGTERM 都汇入同一个 cleanup 标签。清理顺序保证 `SUMMARY` 包含 reset 清掉的报文：先调用 `bpf_tc_hook_destroy` 触发 reset，再读取 `skel->bss->stats`，最后销毁 skeleton 并注销 `struct_ops` link。

## 编译、运行，再观察队列行为

本课的 [`Makefile`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/53-egress-pacer/Makefile) 会生成 BPF 对象、skeleton 和用户态加载器。普通用户即可完成编译：

```bash
cd src/53-egress-pacer
make clean
make -j2
```

第一次运行可以直接使用[集成测试程序](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/53-egress-pacer/tests/test_egress_pacer.py)，它会创建一次性的 `epac_tx`/`epac_rx` veth 对，完成测试后删除。加载 BPF 和修改 qdisc 需要 root：

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

下面是一次已经完成的运行。环境为 x86_64，内核是从 commit `a03114efd0720dff230388f7e160e427e54ea31b` 构建的 `7.0.0-rc2+`：

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

这段输出展示主要路径的功能正确性：队列上限、限速调度和计数一致。测试向一个 64 Kbit/s、最多容纳 8 个报文的队列连续发送 40 个 1024 字节 EtherType `0x88B5` 原始帧。本次运行中，接收端看到 9 个报文，首尾相隔 1024 ms；另外 31 次发送走到 `policy_dropped`。换一个系统或时序，这些具体数字会有所不同。

测试同时覆盖冲突检测、信号清理和异常恢复。它会预先安装一个冲突的 `pfifo`，确认加载器保留现有配置；制造 backlog 后发送 SIGTERM，检查 `cleanup_dropped` 大于零，并验证 `enqueued = dequeued + cleanup_dropped`。最后的 SIGKILL 由测试程序接管：用 `tc` 删除残留的 qdisc，确认接口恢复正常，并在 Python 的 `finally` 块中清掉 veth 对。

理解自动测试后，也可以手动观察。选择一个完全由你控制的接口，先查看它当前使用的 root qdisc：

```bash
tc qdisc show dev veth-service
```

确认接口可以安全使用后，让 pacer 持续 30 秒：

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]
```

| 选项 | 取值范围 | 默认值 |
| --- | --- | --- |
| `--interface` | 必选 | 无 |
| `--rate-kbps` | 8 到 100000000 | 1024 |
| `--queue-limit` | 1 到 65535 个报文 | 256 |
| `--duration` | 1 到 86400 秒 | 10 |
| `--verbose` | 开关 | 关闭 |

看到 `READY` 就表示 qdisc 已经安装。运行结束并成功移除后，程序打印 `SUMMARY`。下面只展示输出格式，省略号是每次运行的实际值占位符：

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

## 运行环境与扩展方向

这个功能从 Linux 6.16 开始可用。[BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) 包含了核心支持。内核需要启用 BTF 和 BPF JIT，并至少包含 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_NET_SCHED=y` 与 `CONFIG_NET_SCH_BPF=y`。

BPF qdisc TC hook 需要 libbpf 1.6.0 或更新版本。仓库已经在 `src/third_party` 中集成 libbpf 和 bpftool；对应的 [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) 和 [1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0) 给出了版本边界。运行时需要 root 权限。集成测试另外依赖 Python 3、原始报文套接字，以及 `iproute2` 中的 `ip` 和 `tc`。一个受控的 veth 对就足够了；本课验证的架构是 x86_64。

这个调度器实现一条聚合 FIFO，队列上限按报文个数计算，发送间隔使用 `qdisc_skb_cb(skb)->pkt_len` 推导。速率和队列上限在加载时固定，队列和统计使用全局 BSS 状态。

本课适合在受控接口上验证功能正确性，更完整的调度器可以在此基础上加入公平性、动态策略和持久化恢复。

## 小结

本课用一条聚合 FIFO 走完了 BPF qdisc 的完整生命周期。`enqueue` 接管 skb 并按报文长度安排发送时间；watchdog 让 `dequeue` 在适当时刻被唤醒；`reset` 释放移除时仍在队列里的 skb。这三段所有权和时序处理构成可复用的 qdisc 模式。

> 想继续动手学习 eBPF，可以在[教程仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial)中找到更多完整示例。

## 参考资料

- [Linux BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog 后续 commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook 支持](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [上游 BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [上游 BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
