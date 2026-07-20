# eBPF Tutorial: Building an Egress Pacer with BPF Qdisc

Imagine you need to verify how your application behaves under low-bandwidth conditions in a test environment. You create a veth pair to simulate a network link and want to limit egress to 64 Kbit/s while observing packet drops when the queue fills up. Traditional rate limiting requires complex tc configurations or user-space proxies, but Linux 6.16 introduced BPF qdisc, which lets you implement a complete queuing discipline directly in eBPF.

This tutorial shows how to use `struct_ops` to build a FIFO rate limiter. The program registers as a root qdisc, manages skb enqueue and dequeue, computes transmission time from packet length, uses the watchdog to schedule the next dequeue, and cleans up queued packets when the qdisc is removed. This is a complete qdisc lifecycle example, suitable for validating skb ownership, transmission timing, and resource cleanup on controlled interfaces like veth, TAP, or IFB.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## Why BPF Qdisc Is Needed

Traditional traffic shaping approaches have clear limitations.

tc provides rich qdisc options such as TBF (Token Bucket Filter) and HTB (Hierarchical Token Bucket), but these are predefined algorithms in the kernel. If you need a custom scheduling policy, such as prioritizing by application type or dynamically adjusting rates based on real-time metrics, you must either modify kernel code or use complex tc classifier combinations.

Ordinary TC BPF programs can inspect and process packets, but queueing and transmission timing remain under the original qdisc's control. [Lesson 20](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) demonstrates this pattern: BPF programs decide whether to pass or drop packets, but cannot control when packets are sent. If you want custom queueing policies, TC BPF is not enough.

User-space rate limiting approaches like tc-netem with external tools or DPDK can implement complex traffic shaping, but they introduce additional context switches and deployment complexity. In a test environment, you may just want to quickly validate an idea rather than set up a full user-space network stack.

Linux 6.16 introduced BPF implementations of `Qdisc_ops` callbacks through `struct_ops`. Programs implement `enqueue`, `dequeue`, `init`, `reset`, and `destroy`, and can dynamically register as a qdisc. This means you can use BPF programs to fully control packet queueing and transmission timing while retaining the performance advantages of the kernel network stack. The `egress_pacer` in this lesson is a FIFO rate limiter built exactly this way.

## How BPF Qdisc Works

Before diving into the code, let's understand the overall flow of a BPF qdisc. Unlike ordinary TC BPF programs, a qdisc BPF program registers as the root qdisc and completely takes over packet queueing and transmission.

The user-space program first sets the rate and queue limit, loads the BPF program and registers the `struct_ops` implementation, then attaches it to the `TC_H_ROOT` position on the target interface. From then on, all egress packets through that interface are handled by the BPF program.

When the kernel needs to send a packet, it calls the `enqueue` callback. The BPF program creates a node to hold the skb, computes the earliest transmission time based on packet length, then adds the node to the FIFO queue. If the queue is full or node allocation fails, the program drops the packet and updates statistics.

When the kernel tries to retrieve a packet for transmission, it calls the `dequeue` callback. The BPF program checks the transmission time of the head node. If the current time has reached or passed that time, the program retrieves the skb and returns it to the kernel; if the transmission time hasn't arrived yet, the program uses `bpf_qdisc_watchdog_schedule` to set a timer and returns NULL. When the timer expires, the kernel calls `dequeue` again.

When the user-space program removes the qdisc, the kernel calls the `reset` callback. The BPF program iterates through all unsent packets in the queue, releases their resources, and zeros out counters.

Throughout this lifecycle, the BPF program has complete ownership of the skb. From receiving the skb in `enqueue`, to returning it in `dequeue` or releasing it in `reset`, packets are held in BPF-managed data structures.

![egress_pacer data flow: from configuration, attachment, enqueue, BPF FIFO, dequeue to transmit path, including policy-drop branch, watchdog loop, and reset lifecycle](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/53-egress-pacer/egress-pacer-flow.png)

The solid lines in the diagram start from configuration and attachment, then trace an skb from enqueue into the BPF FIFO and out through dequeue to the transmit path. When the queue is full or node allocation returns null, packets take the policy-drop branch. An early dequeue pushes the node back to the front, schedules the watchdog, and returns NULL; when the watchdog fires, it re-enters dequeue. The dashed lines show the lifecycle path: removing the root qdisc triggers reset, which releases skbs in the queue and zeros qlen and backlog.

## Code Implementation

This tool consists of four files: a shared header defining the statistics structure, a compatibility header providing graph-object kfunc declarations, the BPF program implementing qdisc callbacks, and the user-space loader managing the lifecycle and printing results.

### Shared Header

`egress_pacer.h` defines the statistics structure shared between BPF and user space. These six fields categorize packet outcomes throughout their lifetime, residing in the BSS section as the result channel.

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

Packets that successfully enter and leave the FIFO are counted in `enqueued` and `dequeued` respectively. When the queue is full or node allocation fails, `policy_dropped` increases. Packets still in the queue during reset are counted in `cleanup_dropped`. `bytes_dequeued` accumulates the bytes actually returned to the transmit path, and `max_qlen` records the peak queue depth.

### Compatibility Header

This example requires graph-object kfuncs, so a local compatibility header provides the BPF qdisc declarations. These declarations exist only in this lesson's directory and are independent from the shared headers used across the repository.

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

This file provides the graph-object helpers needed to build the queue. `bpf_obj_new` creates a packet node, and `bpf_obj_drop` releases it when done. `bpf_list_push_back` and `bpf_list_pop_front` arrange these nodes into a FIFO. The `__contains` macro generates a BTF tag that tells the verifier which node type belongs inside the list head, enabling safe graph tracking.

### BPF Program

`egress_pacer.bpf.c` uses `SEC(".struct_ops")` to declare the `Qdisc_ops` implementation. The kernel registers these callbacks at load time, making the BPF program a complete qdisc.

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

The program structure centers on three core qdisc phases. The two `const volatile` variables `rate_kbps` and `queue_limit` reside in the `.rodata` section; user space writes the rate and queue limit after `open()` but before `load()`, and the verifier treats them as compile-time constants. The `packet_node` structure defines nodes in the queue, containing transmission time, packet length, skb pointer, and list node. The `__kptr` annotation tells the verifier this field owns a kernel pointer.

`egress_pacer_enqueue` is the enqueue callback. It first retrieves the packet length from `qdisc_skb_cb(skb)->pkt_len`, then checks if the queue has space. If the queue is full or node creation fails, it calls `bpf_qdisc_skb_drop` to drop the packet and increments `policy_dropped`. The actual ownership transfer happens via `bpf_kptr_xchg`: after success, the skb is placed in the node's `__kptr` field, and the node becomes responsible for it. The program then computes transmission time while holding `queue_lock`, adds the node to the FIFO tail, and updates qlen and backlog. The transmission interval is calculated as `packet_len * 8 * 1000000 / rate_kbps` in nanoseconds. After the queue has been idle for a while, `next_departure_ns` will be earlier than the current time, allowing the first arriving packet to leave immediately.

`egress_pacer_dequeue` is the dequeue callback. It retrieves the node from the front and compares `eligible_ns` with the current time. If the packet is ready to send, it uses `bpf_kptr_xchg` to retrieve the skb from the node, decrements qlen and backlog, releases the node, then calls `bpf_qdisc_bstats_update` to update qdisc statistics and returns the skb. If transmission time hasn't arrived, it pushes the node back to the front, calls `bpf_qdisc_watchdog_schedule` to set a timer, and returns NULL. The kernel will call dequeue again at the specified time.

`egress_pacer_reset` handles cleanup. When the qdisc is removed, there may still be unsent packets in the queue. The program uses `bpf_for` to retrieve nodes one by one, calls `bpf_kfree_skb` to release the skb, then destroys the node object. Cleared packets are counted in `cleanup_dropped`, separate from enqueue-stage `policy_dropped`. After draining the list, the program zeros `next_departure_ns`, qlen, and backlog together.

The `SEC(".struct_ops")` block at the end registers all callbacks as a `Qdisc_ops` structure. The `id` field specifies the qdisc name as `bpf_pacer`, which user space uses to create qdisc instances.

### User-Space Loader

`egress_pacer.c` parses command-line arguments, configures BPF constants, creates the qdisc, waits for the specified duration, then cleans up.

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

The loader follows a standard flow. After parsing command-line arguments, it uses `if_nametoindex` to verify the interface exists. After opening the skeleton, it writes the rate and queue limit to the `.rodata` section, then calls `load` to complete BPF program loading. After successful loading, it calls `attach` to register the `struct_ops` implementation, making `bpf_pacer` an available qdisc type.

The subsequent `bpf_tc_hook_create` creates a root qdisc named `bpf_pacer` at the `TC_H_ROOT` position on the target interface. This call has exclusive semantics: if the target interface already has a root qdisc, the kernel returns `-EEXIST` and the program stops immediately, preserving the existing configuration. This exclusive approach limits the tool's scope, making it suitable for use on dedicated test interfaces.

After successful installation, the program prints the `READY` line, then checks the runtime and `exiting` flag every 100 ms. SIGINT, SIGTERM, or timeout all exit the wait loop. The cleanup order ensures `SUMMARY` includes packets cleared during reset: first call `bpf_tc_hook_destroy` to trigger reset, then read `skel->bss->stats`, and finally destroy the skeleton to unregister the `struct_ops` link.

## Compilation and Execution

Build from source:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

For the first run, you can use the integration test directly. It creates a disposable `epac_tx`/`epac_rx` veth pair and deletes it after testing. Loading BPF and modifying qdisc require root:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

Here is a completed run. The environment was x86_64, with kernel `7.0.0-rc2+` built from commit `a03114efd0720dff230388f7e160e427e54ea31b`:

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

This output demonstrates functional correctness of the main paths: queue limits, rate limiting schedule, and counter consistency. The test sends 40 1024-byte raw EtherType `0x88B5` frames continuously into a 64 Kbit/s queue that can hold 8 packets. In this run, the receiver saw 9 packets with 1024 ms between first and last; another 31 sends went to `policy_dropped`. The exact numbers will vary depending on the system and timing.

The test also covers conflict detection, signal cleanup, and abnormal recovery. It pre-installs a conflicting `pfifo` to confirm the loader preserves existing configuration; creates a backlog then sends SIGTERM, checking that `cleanup_dropped` is greater than zero and verifying `enqueued = dequeued + cleanup_dropped`. The final SIGKILL is handled by the test program: it uses `tc` to delete the residual qdisc, confirms the interface recovers normally, and cleans up the veth pair in a Python `finally` block.

For manual runs, choose an interface you fully control and first check its current root qdisc:

```bash
tc qdisc show dev veth-service
```

After confirming the interface is safe to use, run the pacer for 30 seconds:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

Command-line arguments:

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]

Options:
  -i, --interface IFACE       target interface (required)
  -r, --rate-kbps KBPS        egress rate, 8-100000000 (default: 1024)
  -q, --queue-limit PACKETS   queue capacity, 1-65535 packets (default: 256)
  -d, --duration SEC          control duration, 1-86400 seconds (default: 10)
  -v, --verbose               print libbpf diagnostics
  -h, --help                  show help
```

Seeing `READY` means the qdisc is installed. After the run completes and removal succeeds, the program prints `SUMMARY`.

### Environment Requirements

This feature is available starting with Linux 6.16. The kernel must have BTF and BPF JIT enabled, with at least `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_NET_SCHED=y`, and `CONFIG_NET_SCH_BPF=y`.

BPF qdisc TC hook requires libbpf 1.6.0 or newer. The repository includes libbpf and bpftool in `src/third_party`. Root privileges are required at runtime. The integration test additionally requires Python 3, raw packet sockets, and `ip` and `tc` from `iproute2`. A controlled veth pair is sufficient; the tested architecture is x86_64.

| Requirement | Minimum Version / Config |
| --- | --- |
| Linux kernel | 6.16+ |
| `CONFIG_BPF` | y |
| `CONFIG_BPF_SYSCALL` | y |
| `CONFIG_BPF_JIT` | y |
| `CONFIG_DEBUG_INFO_BTF` | y |
| `CONFIG_NET_SCHED` | y |
| `CONFIG_NET_SCH_BPF` | y |
| libbpf | 1.6.0+ |
| Privileges | root |

## Summary

This tutorial demonstrated how to implement a complete BPF qdisc using `struct_ops`. `enqueue` takes ownership of the skb and schedules transmission time based on packet length, `dequeue` uses the watchdog to wake up at the right moment and return the skb, and `reset` releases packets still in the queue during removal. These three ownership and timing stages form a reusable qdisc pattern.

This scheduler implements a single aggregate FIFO, with queue limits counted by packet count and transmission intervals derived from qdisc packet length. Rate and queue limit are fixed at load time, making it suitable for validating functional correctness on controlled interfaces. A more complete scheduler could add fairness, dynamic policies, and persistent recovery on top of this foundation.

> To learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
