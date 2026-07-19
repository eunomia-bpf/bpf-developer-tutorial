# eBPF 教程：用 BPF Qdisc 实现出口限速

常见的流量控制 BPF 程序只负责检查报文并给出处理结果，真正的排队和发送时机仍由内核 qdisc 决定。Linux 6.16 开始允许 BPF `struct_ops` 直接实现 qdisc，这意味着 BPF 程序也可以接管队列本身。

本课用这个接口实现 `egress_pacer`。它是一个刻意保持简单的 FIFO 限速器，适合运行在一次性的 veth、TAP 或 IFB 接口上。给它一个速率和队列上限，它就会保存 skb，等到发送时间后再交还给网络栈，并在结束时报告入队、出队和丢包统计。

这不是面向生产网卡的通用调度器。它的作用是把 qdisc 最关键的责任完整展示出来，包括 skb 所有权、队列统计、发送时间、watchdog 唤醒和 reset 清理。完整项目位于 [`53-egress-pacer` 源码目录](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer)。

## 从检查报文到管理队列

普通 TC classifier 运行时，队列仍由另一个 qdisc 管理。[第 20 课](../20-tc/README.zh.md) 展示的就是这种模式。`egress_pacer` 则再向下走了一层。它通过 `struct_ops` 实现 `struct Qdisc_ops`，把自己注册为 root qdisc，并对接收的每个 skb 负责。

我们可以跟着一个报文看完整流程。用户态先写入速率和报文上限，再加载并注册 `bpf_pacer`，最后把它创建在 `TC_H_ROOT`。报文到达后，`enqueue` 回调把 skb 移进 BPF 管理的节点，并计算允许发送的时间。`dequeue` 回调随后决定立即返回报文，还是让 qdisc watchdog 到点后再来取。移除 qdisc 时，`reset` 负责释放仍在等待的报文。

后面的代码分析都会沿着这条路径展开。

## 完整源码

共享头文件定义了 BPF 程序与用户态共同使用的统计结构。

<details>
<summary><code>egress_pacer.h</code>：共享统计结构</summary>

<!-- BEGIN FULL SOURCE: src/53-egress-pacer/egress_pacer.h -->
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
<!-- END FULL SOURCE -->

</details>

仓库中较早生成的头文件缺少部分 BPF qdisc 定义。下面这个本地兼容头文件补齐了所需声明，不会修改仓库全局集成的头文件。

<details>
<summary><code>bpf_experimental.h</code>：本地兼容声明</summary>

<!-- BEGIN FULL SOURCE: src/53-egress-pacer/bpf_experimental.h -->
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
<!-- END FULL SOURCE -->

</details>

内核态程序实现 qdisc 操作、报文队列、限速时钟和统计计数。

<details>
<summary><code>egress_pacer.bpf.c</code>：BPF qdisc 实现</summary>

<!-- BEGIN FULL SOURCE: src/53-egress-pacer/egress_pacer.bpf.c -->
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
<!-- END FULL SOURCE -->

</details>

用户态加载器负责检查参数、注册 BPF qdisc、把它安装到一个接口，等待指定时间后再将其移除。

<details>
<summary><code>egress_pacer.c</code>：加载器与 qdisc 生命周期</summary>

<!-- BEGIN FULL SOURCE: src/53-egress-pacer/egress_pacer.c -->
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
<!-- END FULL SOURCE -->

</details>

## 接管 skb，并算出发送时间

qdisc 的 `init` 回调先把 `queue_limit` 写入 `sch->limit`。从这一步开始，`egress_pacer_enqueue` 必须明确处理每个 skb，要么接管它，要么拒绝它。回调读取 `qdisc_skb_cb(skb)->pkt_len`，检查报文数是否达到上限，再用 `bpf_obj_new` 分配 `packet_node`。队列已满和节点分配失败共用同一条丢弃路径，因此都会增加 `policy_dropped`。

报文可以入队时，`bpf_kptr_xchg` 会把 skb 转移到节点的 `__kptr` 字段。这个节点随后同时保存报文、qdisc 记录的长度和 `eligible_ns` 时间戳。节点进入 FIFO 时，spin lock 保护链表、限速时钟、qlen 和 backlog。入队成功后，程序增加 `enqueued`，并用 `max_qlen` 记录本次运行中的队列峰值。

发送时间来自报文在目标速率下的序列化时间：

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

队列空闲一段时间后，`next_departure_ns` 已经落在当前时间之前，所以第一个报文可以立即离开。后续报文再按各自长度推进时钟。这样得到的是一个聚合 FIFO 发送计划，不是 token bucket，也没有额外的突发额度。

## 让 watchdog 等待，而不是让 BPF 忙等

`egress_pacer_dequeue` 先取出队首节点，再比较 `eligible_ns` 和 `bpf_ktime_get_ns()`。到达发送时间后，另一次 `bpf_kptr_xchg` 把 skb 从节点中取出。回调随后减少 qlen 和 backlog，释放空节点，更新 qdisc 字节统计，并增加 `dequeued` 和 `bytes_dequeued`。

如果时间还没到，回调会把节点放回队首，调用 `bpf_qdisc_watchdog_schedule(sch, expire, 0)`，然后返回 `NULL`。qdisc 核心会在 `eligible_ns` 到来时重新唤醒队列，BPF 程序不需要自己循环等待。

移除 qdisc 时，skb 所有权也必须有明确去处。`egress_pacer_reset` 使用 `bpf_for` 排空当前 qlen，通过 `bpf_kfree_skb` 释放每个残留 skb，再销毁节点。这里释放的报文计入 `cleanup_dropped`，而正常入队期间的准入失败计入 `policy_dropped`。reset 最后还会清零限速时钟、qlen 和 backlog。

最终的 BSS `pacer_stats` 统计分别回答六个问题：

| 字段 | 含义 |
| --- | --- |
| `enqueued` | 成功进入 FIFO 的报文数 |
| `dequeued` | 已返回给发送路径的报文数 |
| `policy_dropped` | 队列达到上限或节点分配失败时拒绝的报文数 |
| `cleanup_dropped` | qdisc reset 时排空的报文数 |
| `bytes_dequeued` | dequeue 返回的 qdisc 报文总字节数 |
| `max_qlen` | FIFO 的报文占用峰值 |

## 把实验限制在一个接口内

调用 `egress_pacer_bpf__load()` 之前，命令行程序会把速率和队列上限写入 `skel->rodata->rate_kbps` 与 `skel->rodata->queue_limit`。加载阶段由内核验证器检查程序，挂载 skeleton 会注册 `struct_ops` 实现，随后 `bpf_tc_hook_create` 在目标 ifindex 的 `BPF_TC_QDISC`、`TC_H_ROOT` 位置创建 `bpf_pacer`。

创建操作采用独占模式。如果接口已经有 root qdisc，操作会返回 `-EEXIST`。加载器不会查看、替换、叠加、保存或恢复它，而是直接拒绝继续。因此，这个示例只能用于专门为实验创建的接口。

打印 `READY` 后，加载器每隔 100 ms 检查一次，直到运行时间结束或信号处理函数设置 `exiting`。正常结束、SIGINT 和 SIGTERM 最终都会进入同一条清理路径。程序先调用 `bpf_tc_hook_destroy`，再读取 `skel->bss->stats`，因此 reset 阶段丢弃的报文也会出现在 `SUMMARY` 中。如果移除失败，程序会打印错误和当时还能读取到的统计，返回失败，并把接口留给用户检查。最后销毁 skeleton 时，`struct_ops` link 也会注销。

## 编译和运行

使用本课的 [`Makefile`](./Makefile) 编译 BPF 对象和加载器，这一步不需要 root：

```bash
cd src/53-egress-pacer
make clean
make -j2
```

第一次运行最好使用[集成测试程序](./tests/test_egress_pacer.py)。它会自动创建并删除一次性的 `epac_tx`/`epac_rx` veth 对，实际加载 BPF 和操作 qdisc 时需要 root：

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

最终二进制先在宿主机上完成干净编译，再放入复用的 `bpf-benchmark` KVM 客户机运行。客户机为 x86_64，使用从 commit `a03114efd0720dff230388f7e160e427e54ea31b` 构建的 `7.0.0-rc2+` 内核。测试输出如下：

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

这是一项功能性冒烟测试，不是吞吐量或限速精度基准。测试程序向速率为 64 Kbit/s、上限为 8 个报文的队列发送 40 个 1024 字节的 EtherType `0x88B5` 原始帧。本次运行收到 9 个报文，首尾时间相隔 1024 ms，另外 31 次发送进入 `policy_dropped` 路径。这些数字只代表这次测试。

同一个测试程序也覆盖了异常路径。它先安装冲突的 `pfifo`，确认加载器不会替换现有 qdisc。随后，测试程序制造 backlog 并发送 SIGTERM，要求 `cleanup_dropped` 大于零，同时验证 `enqueued = dequeued + cleanup_dropped`。最后一轮发送 SIGKILL。这个无法捕获的信号在测试客户机中留下了 `bpf_pacer`，测试程序因此用 `tc` 将其删除，确认接口恢复，并在 Python `finally` 块中清理 veth 对。

手动运行时，只能选择自己控制的接口。先查看它当前的 root qdisc：

```bash
tc qdisc show dev veth-service
```

然后让 pacer 运行 30 秒：

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

qdisc 安装完成后，加载器会打印 `READY`。成功移除后，它会打印 `SUMMARY`。下面的省略号只表示输出格式，不是实测值：

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

如果接口已经存在 root qdisc，独占创建会失败，并输出：

```text
refusing to replace the existing root qdisc on IFACE
```

## 运行要求和适用边界

- Linux 6.16 或更新版本，并启用 BTF 和 BPF JIT。[BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) 引入了所需支持。
- 内核配置包含 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_NET_SCHED=y` 和 `CONFIG_NET_SCH_BPF=y`。
- libbpf 1.6.0 或更新版本，用于 BPF qdisc TC hook。仓库在 `src/third_party` 中集成了 libbpf 和 bpftool。相关 [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) 与 [1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0) 记录了版本边界。
- 加载 BPF、创建和销毁 qdisc 需要 root 权限。
- 集成测试还需要 Python 3、原始报文套接字，以及 `iproute2` 提供的 `ip` 和 `tc`。
- 需要一个受控接口，veth 对已经足够。当前测试配置为 x86_64。

这个调度器只有一个聚合 FIFO，不提供公平调度、每流隔离、每 cgroup 策略、类别、优先级、ECN、拥塞控制集成或 token bucket 的突发额度。队列上限按报文数计算，速率计算使用 `qdisc_skb_cb(skb)->pkt_len`。队列空闲时，第一个报文可以立即离开。

每次运行的速率和队列上限都是固定的。全局队列与 BSS 状态也限制了一个加载器进程只能管理一个 root qdisc 实例。这个命令行程序只运行指定时长，不是守护进程、控制器、指标导出器或持久策略管理器。

测试覆盖按时长退出和 SIGTERM 清理。SIGINT 使用同一个处理函数，但没有单独执行测试。SIGKILL 和其他异常终止可能留下 qdisc。宿主机崩溃、重启、GSO/TSO、驱动或硬件卸载、真实网卡的限速精度、吞吐量和硬件时序都不在本次测试范围内。

异常退出后，先检查接口：

```bash
tc qdisc show dev IFACE
```

如果 `bpf_pacer` 仍然存在，只能在自己控制的接口上将它删除：

```bash
sudo tc qdisc del dev IFACE root
```

删除 qdisc 会改变接口的流量调度，因此只能在自己控制的接口上执行这条恢复命令。

## 总结

这个小型 FIFO 展示了完整的 BPF qdisc 生命周期。`enqueue` 接管 skb 并计算发送时间，watchdog 在不忙等的情况下重新唤醒 `dequeue`，`reset` 则处理移除时仍留在队列中的报文。真正可以复用的是这些机制。如果要加入公平性、并发状态、动态策略、持久化和更强的故障恢复，就需要设计一个更完整的调度器。

> 如果你想继续深入学习 eBPF，可以查看我们的 [教程仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial)，或访问 [eunomia 教程网站](https://eunomia.dev/tutorials/)。

## 参考资料

- [Linux BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog 后续 commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook 支持](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [上游 BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [上游 BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
