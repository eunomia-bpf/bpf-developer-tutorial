# eBPF 教程：用 BPF Qdisc 实现出口限速

假设你需要在测试环境中验证应用程序在低带宽条件下的行为。你创建了一对 veth 接口模拟网络链路，现在想把出口速率限制到 64 Kbit/s，同时观察队列深度达到上限时的丢包行为。传统的限速方案需要复杂的 tc 配置或用户态代理，而 Linux 6.16 引入的 BPF qdisc 允许你用 eBPF 程序直接实现完整的排队规则。

本教程展示如何使用 `struct_ops` 实现一个 FIFO 限速器。程序注册为 root qdisc，自己管理 skb 入队和出队，按报文长度计算发送时间，使用 watchdog 调度下一次出队，并在 qdisc 移除时清理队列中的报文。这是一个完整的 qdisc 生命周期示例，适合在 veth、TAP 或 IFB 这类受控接口上验证 skb 所有权、发送时序和资源清理。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## 为什么需要 BPF Qdisc

传统的流量整形方案有明显的局限性。

tc 提供了丰富的 qdisc 选项，如 TBF（Token Bucket Filter）和 HTB（Hierarchical Token Bucket），但这些都是内核中预定义的算法。如果你需要一种特殊的调度策略，比如按应用程序类型区分优先级，或者根据实时指标动态调整速率，就必须修改内核代码或使用复杂的 tc 分类器组合。

普通的 TC BPF 程序可以检查和处理报文，但排队和发送时间仍由原有的 qdisc 管理。[第 20 课](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) 展示的就是这种模式：BPF 程序决定放行或丢弃，但无法控制报文何时发送。如果你想实现自定义的排队策略，TC BPF 的能力是不够的。

用户态限速方案如 tc-netem 配合外部工具或 DPDK 可以实现复杂的流量整形，但引入了额外的上下文切换和复杂的部署依赖。在测试环境中，你可能只想快速验证一个想法，而不是搭建完整的用户态网络栈。

Linux 6.16 通过 `struct_ops` 引入了 BPF 实现的 `Qdisc_ops` 回调。程序实现 `enqueue`、`dequeue`、`init`、`reset` 和 `destroy`，可以动态注册为一个 qdisc。这意味着你可以用 BPF 程序完全控制报文的排队和发送时序，同时保持内核网络栈的性能优势。本课的 `egress_pacer` 就是用这种方式构建的 FIFO 限速器。

## BPF Qdisc 的工作原理

在深入代码之前，先理解 BPF qdisc 的整体流程。与普通 TC BPF 程序不同，qdisc BPF 程序注册为 root qdisc，完全接管报文的排队和发送。

用户态程序首先设置速率和队列上限，加载 BPF 程序并注册 `struct_ops` 实现，然后把它挂载到指定接口的 `TC_H_ROOT` 位置。此后所有经过该接口的出口报文都由 BPF 程序处理。

当内核需要发送报文时，它调用 `enqueue` 回调。BPF 程序创建一个节点来保存 skb，根据报文长度计算最早可以发送的时间，然后把节点加入 FIFO 队列。如果队列已满或节点分配失败，程序丢弃报文并更新统计。

当内核尝试取出报文发送时，它调用 `dequeue` 回调。BPF 程序检查队首节点的发送时间。如果当前时间已经到达或超过该时间，程序取出 skb 返回给内核；如果还没到发送时间，程序用 `bpf_qdisc_watchdog_schedule` 设置一个定时器，然后返回 NULL。定时器到期后，内核会再次调用 `dequeue`。

当用户态程序移除 qdisc 时，内核调用 `reset` 回调。BPF 程序遍历队列中所有未发送的报文，释放它们占用的资源，并清零计数器。

整个生命周期中，BPF 程序完全控制 skb 的所有权。从 `enqueue` 接收 skb 开始，到 `dequeue` 返回 skb 或 `reset` 释放 skb 为止，报文都由 BPF 管理的数据结构保存。

![egress_pacer 数据流：从配置、挂载、入队、BPF FIFO、出队到发送路径，包含 policy-drop 分支、watchdog 循环和 reset 生命周期](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/53-egress-pacer/egress-pacer-flow.png)

图中实线从配置和挂载开始，随后跟踪一个 skb 从 enqueue 进入 BPF FIFO，再由 dequeue 交还给发送路径。队列已满或节点分配返回空时走 policy-drop 分支。早到的 dequeue 把节点推回队首，安排 watchdog 并返回 NULL，等 watchdog 唤醒后重新进入 dequeue。虚线表示生命周期路径：移除 root qdisc 后 reset 释放队列中的 skb 并清零 qlen 和 backlog。

## 代码实现

本工具由四个文件组成：共享头文件定义统计结构、兼容头文件提供 graph-object kfunc 声明、BPF 程序实现 qdisc 回调、用户空间加载器管理生命周期并打印结果。

### 共享头文件

`egress_pacer.h` 定义了 BPF 和用户空间共享的统计结构。这六个字段把报文的一生分成几种结果，位于 BSS 段作为结果通道。

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

成功进入和离开 FIFO 的报文分别计入 `enqueued` 和 `dequeued`。队列已满或节点分配失败时，`policy_dropped` 增加。reset 时仍在队列中的报文计入 `cleanup_dropped`。`bytes_dequeued` 累计实际交还给发送路径的字节数，`max_qlen` 记录队列的峰值深度。

### 兼容头文件

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

这个文件提供构建队列所需的 graph-object 辅助函数。`bpf_obj_new` 创建报文节点，`bpf_obj_drop` 在节点用完后释放它。`bpf_list_push_back` 和 `bpf_list_pop_front` 让这些节点组成 FIFO。`__contains` 生成 BTF tag，告诉 verifier 这个 list head 装的是哪一种节点，使 verifier 可以安全地跟踪链表对象。

### BPF 程序

`egress_pacer.bpf.c` 使用 `SEC(".struct_ops")` 声明 `Qdisc_ops` 实现。内核在加载时注册这些回调，使 BPF 程序成为一个完整的 qdisc。

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

程序结构围绕 qdisc 的三个核心阶段展开。两个 `const volatile` 变量 `rate_kbps` 和 `queue_limit` 位于 `.rodata` 段，用户态在 `open()` 之后、`load()` 之前写入速率和队列上限，验证器将它们视为编译期常量。`packet_node` 结构体定义了队列中的节点，包含发送时间、报文长度、skb 指针和链表节点。`__kptr` 标记告诉 verifier 这个字段持有内核指针的所有权。

`egress_pacer_enqueue` 是入队回调。它首先从 `qdisc_skb_cb(skb)->pkt_len` 取得 qdisc 看到的报文长度，然后检查队列是否还有空间。如果队列已满或节点创建失败，程序调用 `bpf_qdisc_skb_drop` 丢弃报文并递增 `policy_dropped`。真正的所有权转移发生在 `bpf_kptr_xchg`：调用成功后，skb 被放进节点的 `__kptr` 字段，节点从此负责保管它。程序随后在持有 `queue_lock` 的情况下计算发送时间、把节点加入 FIFO 尾部、更新 qlen 和 backlog。发送间隔按 `packet_len * 8 * 1000000 / rate_kbps` 计算，单位是纳秒。队列空闲一段时间后，`next_departure_ns` 会早于当前时间，新来的第一个报文可以立刻离开。

`egress_pacer_dequeue` 是出队回调。它从队首取出节点，比较 `eligible_ns` 与当前时间。如果报文已经可以发送，程序用 `bpf_kptr_xchg` 把 skb 从节点取回，扣减 qlen 和 backlog，释放节点，然后调用 `bpf_qdisc_bstats_update` 更新 qdisc 统计并返回 skb。如果还没到发送时间，程序把节点放回队首，调用 `bpf_qdisc_watchdog_schedule` 设置定时器，然后返回 NULL。内核会在指定时间再次调用 dequeue。

`egress_pacer_reset` 负责清理。当 qdisc 被移除时，队列中可能还有未发送的报文。程序用 `bpf_for` 逐个取出节点，调用 `bpf_kfree_skb` 释放 skb，然后销毁节点对象。清掉的报文计入 `cleanup_dropped`，与 enqueue 阶段的 `policy_dropped` 分开。链表排空后，程序把 `next_departure_ns`、qlen 和 backlog 一起归零。

程序末尾的 `SEC(".struct_ops")` 块把所有回调注册为 `Qdisc_ops` 结构体。`id` 字段指定 qdisc 名称为 `bpf_pacer`，用户态通过这个名称创建 qdisc 实例。

### 用户空间加载器

`egress_pacer.c` 解析命令行参数、配置 BPF 常量、创建 qdisc 并等待指定时间后清理。

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

加载器的流程比较标准。解析命令行后，用 `if_nametoindex` 验证接口存在。打开 skeleton 后把速率和队列上限写入 `.rodata` 段，然后调用 `load` 完成 BPF 程序加载。加载成功后调用 `attach` 注册 `struct_ops` 实现，使 `bpf_pacer` 成为可用的 qdisc 类型。

接下来的 `bpf_tc_hook_create` 在目标接口的 `TC_H_ROOT` 位置创建名为 `bpf_pacer` 的 root qdisc。这个调用带着独占语义：目标接口已经有 root qdisc 时，内核返回 `-EEXIST`，程序立即停止，保留现有配置。这种独占做法限制了工具的作用范围，适合把它用在专门创建的测试接口上。

安装成功后，程序打印 `READY` 行，然后每隔 100 ms 检查运行时间和 `exiting` 标志。SIGINT、SIGTERM 或时间到期都会退出等待循环。清理顺序保证 `SUMMARY` 包含 reset 清掉的报文：先调用 `bpf_tc_hook_destroy` 触发 reset，再读取 `skel->bss->stats`，最后销毁 skeleton 并注销 `struct_ops` link。

## 编译与运行

从源码构建：

```bash
cd src/53-egress-pacer
make clean
make -j2
```

第一次运行可以直接使用集成测试程序，它会创建一次性的 `epac_tx`/`epac_rx` veth 对，完成测试后删除。加载 BPF 和修改 qdisc 需要 root：

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

手动运行时，选择一个完全由你控制的接口，先查看它当前使用的 root qdisc：

```bash
tc qdisc show dev veth-service
```

确认接口可以安全使用后，让 pacer 持续 30 秒：

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

命令行参数：

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]

Options:
  -i, --interface IFACE       目标接口（必选）
  -r, --rate-kbps KBPS        出口速率，8-100000000（默认：1024）
  -q, --queue-limit PACKETS   队列容量，1-65535 个报文（默认：256）
  -d, --duration SEC          控制时长，1-86400 秒（默认：10）
  -v, --verbose               打印 libbpf 诊断信息
  -h, --help                  显示帮助
```

看到 `READY` 就表示 qdisc 已经安装。运行结束并成功移除后，程序打印 `SUMMARY`。

### 环境要求

这个功能从 Linux 6.16 开始可用。内核需要启用 BTF 和 BPF JIT，并至少包含 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_NET_SCHED=y` 与 `CONFIG_NET_SCH_BPF=y`。

BPF qdisc TC hook 需要 libbpf 1.6.0 或更新版本。仓库已经在 `src/third_party` 中集成 libbpf 和 bpftool。运行时需要 root 权限。集成测试另外依赖 Python 3、原始报文套接字，以及 `iproute2` 中的 `ip` 和 `tc`。一个受控的 veth 对就足够了；本课验证的架构是 x86_64。

## 总结

本教程展示了如何使用 `struct_ops` 实现一个完整的 BPF qdisc。`enqueue` 接管 skb 并按报文长度安排发送时间，`dequeue` 用 watchdog 在适当时刻被唤醒并返回 skb，`reset` 释放移除时仍在队列里的报文。这三段所有权和时序处理构成可复用的 qdisc 模式。

这个调度器实现一条聚合 FIFO，队列上限按报文个数计算，发送间隔使用 qdisc 报文长度推导。速率和队列上限在加载时固定，适合在受控接口上验证功能正确性。更完整的调度器可以在此基础上加入公平性、动态策略和持久化恢复。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog 后续 commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook 支持](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [上游 BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [上游 BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
