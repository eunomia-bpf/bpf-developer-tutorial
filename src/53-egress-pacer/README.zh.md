# eBPF 教程：用 BPF Qdisc 控制出口流量

实验服务突然向 veth 接口发送一阵流量。队列随之增长，延迟开始抖动，部分报文消失了，却没有留下清晰的丢包统计。遇到这种情况，我们需要把突发限制在已知速率内，给队列设定上限，还要知道报文究竟已经发出，还是在队列中被丢弃。本课实现的 `egress_pacer` 就是这样一个小工具。它使用 Linux 6.16 引入的 BPF `struct_ops` 注册一个 FIFO qdisc，为每个报文计算允许发送的时间，并在运行结束时报告入队、出队、字节数和丢包统计。加载器采用独占创建；如果操作返回 `-EEXIST`，它就拒绝继续。测试中安装冲突 `pfifo` 的场景会触发这条路径。

这个示例面向受控的 veth、TAP 或 IFB 接口，不是通用物理网卡上的生产调度器。读完后，你会理解 BPF qdisc 如何持有 skb、qdisc watchdog 如何避免忙等待，以及用户态如何在一个有时限的实验中安装并移除 qdisc。

完整项目位于 [`53-egress-pacer` 源码目录](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer)。

## 为什么要在 qdisc 中限速

Linux 会让出口报文经过队列规则，也就是 qdisc。普通 TC classifier 可以检查报文并返回处理动作，但报文队列仍由另一个内核 qdisc 管理。[TC classifier 教程](../20-tc/README.zh.md) 采用的就是这种方式。

本例走的是另一条路径。BPF `struct_ops` 对象直接实现 `struct Qdisc_ops`，把 `bpf_pacer` 注册成 root qdisc。报文能否入队、队首何时可以发送，以及 reset 时如何释放残留 skb，都由这个 BPF 程序决定。

这种控制能力也带来了生命周期风险。替换 root qdisc 会改变实时流量，所以加载器请求独占创建，并在操作返回 `-EEXIST` 时停止。程序只运行指定时长，并在正常结束或处理 SIGINT、SIGTERM 后移除 qdisc。SIGKILL 无法捕获，可能留下已经安装的 qdisc，因此文末还给出了显式恢复方法。

## 一个报文如何经过整个工具

内核态与用户态按照下面的顺序协作：

1. 加载器解析受控接口，把速率和报文上限写入 BPF 只读数据，然后加载 BPF object。
2. 挂载 `struct_ops` map 后，内核注册 `bpf_pacer`。加载器再通过 libbpf 的 qdisc TC hook，把它创建在 `TC_H_ROOT`。
3. 流量到来前，qdisc 的 `init` 回调把 `queue_limit` 写入 `sch->limit`。
4. `egress_pacer_enqueue` 在队列达到上限时丢包，否则把 skb 移交给一个 BPF 队列节点，并根据报文长度和配置速率计算允许发送时间。
5. `egress_pacer_dequeue` 返回已经到达发送时间的 skb。如果队首报文还不能发送，回调会把它放回去，并让 qdisc watchdog 在正确时间重试。
6. 用户态移除 qdisc 时，`egress_pacer_reset` 释放仍在队列中的 skb。加载器随后读取最终 BSS 计数器并打印 `SUMMARY`。

整个设计有意保持简单。一个加载器只管理一个 root qdisc、一个 FIFO 和一组全局统计。

## 完整源码

共享头文件定义了 BPF 程序与用户态共同使用的统计结构。

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

仓库中较早生成的头文件缺少部分 BPF qdisc 定义。下面这个本地兼容头文件补齐了所需声明，不会修改仓库全局集成的头文件。

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

内核态程序实现 qdisc 操作、报文队列、限速时钟和统计计数。

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

用户态加载器负责检查参数、注册 BPF qdisc、把它安装到一个接口，等待指定时间后再将其移除。

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

## 入队时如何把速率换算成时间

`egress_pacer_enqueue` 先读取 `qdisc_skb_cb(skb)->pkt_len`。队列上限以报文数计算，速率则使用 qdisc 记录的报文长度。队列已满时，程序直接进入丢弃路径。`bpf_obj_new` 分配失败也会走同一路径，因此两种情况都会累加 `policy_dropped`。

报文被接受后，`bpf_obj_new` 创建一个 `packet_node`，`bpf_kptr_xchg` 再把 skb 转移到节点的 `__kptr` 字段。节点同时保存报文长度和 `eligible_ns` 时间戳。BPF 链表节点与 skb 的所有权一起移动，后续 reset 才能可靠释放这两类对象。

限速间隔就是该报文在配置速率下的序列化时间：

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

接口空闲一段时间后，`next_departure_ns` 已经落后于当前时间，第一个报文便可以立即离开。后续报文根据各自长度继续推进时钟。这里实现的是聚合 FIFO pacer，不是 token bucket，也没有单独的突发预算。

这里用 spin lock 保护 list、`next_departure_ns`、qlen 与 backlog 的更新。节点成功插入后，程序增加 `enqueued`，并用 `max_qlen` 记录本次运行见到的队列峰值。

## 出队时如何避免忙等待

`egress_pacer_dequeue` 取出第一个节点，并把它的时间戳与 `bpf_ktime_get_ns()` 比较。时间已经到达时，另一次 `bpf_kptr_xchg` 把 skb 从 BPF 节点中移出。回调减少 qlen 和 backlog，释放空节点，更新 qdisc 字节统计，再累加 `dequeued` 与 `bytes_dequeued`。

如果报文还不能发送，回调会把节点放回队首，调用 `bpf_qdisc_watchdog_schedule(sch, expire, 0)`，然后返回 `NULL`。qdisc 核心会在 `eligible_ns` 到来时重试，BPF 程序不需要循环等待时间流逝。

## 为什么要单独记录 reset 清理丢包

移除 qdisc 时，队列中可能仍有报文。`egress_pacer_reset` 按当前 qlen 运行 `bpf_for`，依次移除节点，用 `bpf_kfree_skb` 释放 skb，再释放节点。这个阶段释放的报文累加到 `cleanup_dropped`，不会混入 `policy_dropped`。

两个字段回答的是不同问题。`policy_dropped` 表示 pacer 运行期间的准入失败，`cleanup_dropped` 表示带着 backlog 移除 qdisc 时丢弃的报文。reset 最后还会清零 `next_departure_ns`、qlen 和 backlog。

内核 BSS 中的 `pacer_stats` 包含下面六项统计：

| 字段 | 含义 |
| --- | --- |
| `enqueued` | 成功进入 FIFO 的报文数 |
| `dequeued` | 已返回给发送路径的报文数 |
| `policy_dropped` | 队列达到上限或节点分配失败时拒绝的报文数 |
| `cleanup_dropped` | qdisc reset 时排空的报文数 |
| `bytes_dequeued` | dequeue 返回的 qdisc 报文总字节数 |
| `max_qlen` | FIFO 的报文占用峰值 |

## 用户态如何管理 qdisc 生命周期

调用 `egress_pacer_bpf__load()` 之前，加载器会设置 `skel->rodata->rate_kbps` 与 `skel->rodata->queue_limit`。内核验证器在加载期间检查程序。挂载 skeleton 会注册 `struct_ops` 实现，随后 `bpf_tc_hook_create` 在指定 ifindex 的 `BPF_TC_QDISC`、`TC_H_ROOT` 位置创建 `bpf_pacer`。

独占创建返回 `-EEXIST` 时，加载器不会检查、堆叠、替换、保存或恢复冲突的 qdisc，只会输出拒绝信息。测试程序通过预先安装 `pfifo` 验证了这条路径。因此，手动运行时必须选择自己创建的测试接口。

工具打印 `READY` 后，以 100 ms 为间隔休眠，直到持续时间结束或信号处理函数设置 `exiting`。SIGINT 和 SIGTERM 共用这个处理函数。集成测试覆盖按时长退出与 SIGTERM，没有另外执行一遍 SIGINT。

清理流程先调用 `bpf_tc_hook_destroy`，再读取 `skel->bss->stats`。成功移除 qdisc 时，reset 会处理残留队列，因此 `SUMMARY` 包含清理阶段的丢包。如果移除失败，加载器会报告错误，打印当时可读到的 BSS 统计并返回失败；操作者仍需检查并恢复接口。最后，加载器销毁 skeleton，并注销 `struct_ops` link。

## 编译和运行

使用本课的 [`Makefile`](./Makefile) 编译 BPF object 与加载器，不需要 root：

```bash
cd src/53-egress-pacer
make clean
make -j2
```

第一次运行最好使用[集成测试程序](./tests/test_egress_pacer.py)。它会创建并删除一次性的 `epac_tx`/`epac_rx` veth 对，因此下面的命令需要 root：

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

完成一次干净的宿主机编译后，最终测试程序运行在复用的 `bpf-benchmark` KVM 客户机中。客户机使用干净的 `7.0.0-rc2+` 内核，源码 commit 为 `a03114efd0720dff230388f7e160e427e54ea31b`。实际采集到的输出如下：

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

这是一项功能性冒烟测试，不是吞吐量或限速精度基准测试。测试向速率 64 Kbit/s、队列上限 8 的 pacer 突发发送 40 个 1024 字节的 EtherType `0x88B5` 原始帧。在本次运行中，队列填满时有 31 次发送计入 `policy_dropped`。接收到的 9 个报文，其首尾时间戳相隔 1024 ms。这些数字只描述当前测试程序。

突发测试之前，测试程序会安装一个冲突的 `pfifo`，确认加载器不会将其替换。第二轮先制造 backlog，再发送 SIGTERM。测试要求 `cleanup_dropped` 非零，并验证 `enqueued = dequeued + cleanup_dropped`。

最后一轮发送 SIGKILL。在测试客户机上，这个不可捕获的信号留下了 `bpf_pacer`。测试程序随后使用 `tc` 显式删除 qdisc、验证接口恢复，并在 Python `finally` 块中删除 veth 对。

手动运行前，请先创建一个专用接口，并确认自己拥有它。先检查 root qdisc：

```bash
tc qdisc show dev veth-service
```

接下来让 pacer 运行 30 秒：

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

命令行用法如下：

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

加载器会在 qdisc 生效后打印 `READY`。成功移除 qdisc 后，`SUMMARY` 包含最终统计和 reset 阶段的清理丢包。移除失败时，程序会输出错误以及当时可读到的 BSS 统计。下面只展示成功路径的输出格式，省略号是占位符，不是实测值。

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

独占创建返回 `-EEXIST` 时，例如测试程序安装冲突 `pfifo` 的场景，加载器会退出并打印：

```text
refusing to replace the existing root qdisc on IFACE
```

## 运行要求

- Linux 6.16 或更新版本。[BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) 引入了所需内核支持。
- libbpf 1.6.0 或更新版本，用于 BPF qdisc TC hook。仓库在 `src/third_party` 中集成了 libbpf 与 bpftool。相关 [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) 和 [libbpf 1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0) 记录了这个 API 及其版本边界。
- 已测试的系统架构为 x86_64。
- 加载 BPF、创建和销毁 qdisc 需要 root 权限。
- 集成测试还需要 root、Python 3、原始报文套接字，以及 `iproute2` 提供的 `ip` 和 `tc`。
- 异常退出后的显式恢复需要 `tc` 命令。
- 内核需要启用 BTF 与 BPF JIT。
- 内核配置需要包含 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_NET_SCHED=y` 和 `CONFIG_NET_SCH_BPF=y`。
- 需要一个受控网络接口，veth 对已经足够。

## 适用边界与恢复方法

本课只实现一个聚合 FIFO，没有公平调度、每流隔离、每 cgroup 策略、类别、优先级、ECN、突发预算或拥塞控制集成。队列上限统计报文数，速率计算使用 `qdisc_skb_cb(skb)->pkt_len`。接口空闲后的第一个报文可以立即发出。

一次运行中的速率和队列上限保持固定。全局队列与 BSS 状态也意味着一个加载器进程只能管理一个 root qdisc 实例。独占创建返回 `-EEXIST` 时，加载器会停止；它不会检查、保留、堆叠或恢复冲突的 qdisc。

这个命令行工具只运行指定时长，不是守护进程、控制器、指标导出器或持久策略管理器。测试覆盖了按时长退出和 SIGTERM 清理。SIGINT 使用同一个信号处理函数，但没有单独测试。SIGKILL 或其他异常终止后不保证完成清理，宿主机崩溃与重启后的行为也没有测试。

这项 KVM 测试只验证功能，不覆盖真实网卡上的吞吐量、限速精度、驱动或硬件卸载、GSO/TSO，也不覆盖真实硬件时序。

程序异常退出后，先检查受控接口：

```bash
tc qdisc show dev IFACE
```

如果 `bpf_pacer` 仍然存在，可以将其移除：

```bash
sudo tc qdisc del dev IFACE root
```

删除 qdisc 会改变接口的流量调度。只应在自己控制的接口上执行这条命令。

## 总结

这个示例把 Linux 6.16 的 BPF qdisc 接口变成了一个有界、短时运行的出口 pacer。我们分析了 BPF object 如何持有 skb、报文序列化时间如何形成发送计划、watchdog 如何避免忙等待，以及 reset 如何区分策略丢包与清理丢包。相同结构可以承载更丰富的策略，但真实服务还需要明确设计公平性、并发状态、持久化和故障恢复。

> 如果你想继续深入学习 eBPF，可以查看我们的 [教程仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial)，或访问 [eunomia 教程网站](https://eunomia.dev/tutorials/)。

## 参考资料

- [Linux BPF qdisc 合入 commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog 后续 commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook 支持](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [上游 BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [上游 BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 发布说明](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
