# eBPF Tutorial by Example: Build an Egress Pacer with a BPF Qdisc

Want to throttle a virtual link in your test environment? Say, squeeze a veth down to 64 Kbit/s and watch how many packets queue up before they start dropping. Ordinary TC BPF examples cannot do this. They inspect packets and return actions, but a separate qdisc still decides when packets actually leave.

Linux 6.16 hands that layer to BPF as well. You write a set of `struct_ops` callbacks and the kernel treats them as a real root qdisc. This tutorial builds `egress_pacer`, a small FIFO pacer that runs on a veth, TAP, or IFB. Give it a rate and a queue limit. It holds packets, releases them on schedule, and reports enqueue, dequeue, and drop statistics at the end.

This example uses one aggregate FIFO to demonstrate skb ownership, queue accounting, departure time, watchdog wakeups, and teardown cleanup. It is suitable for observing the full flow on controlled interfaces such as veth, TAP, or IFB. A fuller scheduler can build on this foundation with classes, fairness, ECN, and burst control.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## Ordinary TC BPF and Qdisc Ownership

An ordinary TC BPF program leaves queue ownership with the existing qdisc, so it can only inspect packets and decide whether to pass or drop them. [Lesson 20](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) shows this familiar path. `egress_pacer` implements `struct Qdisc_ops` through `struct_ops` and becomes the root qdisc, owning both the enqueue and dequeue stages. Once the kernel hands it an skb, this BPF program decides both queueing and release time.

Follow one packet and the design becomes easier to see. User space sets the rate and queue limit, loads `bpf_pacer`, and attaches it at `TC_H_ROOT`. On arrival, `enqueue` puts the skb into a BPF-managed node and computes the earliest time it may leave. When `dequeue` runs, it returns an eligible skb or sets the watchdog so the kernel comes back later. User space eventually removes the qdisc, and `reset` disposes of packets that are still waiting. Every piece of code below belongs to this path.

## Start the Pacer with Shared Data

The shared data contract comes before the callbacks. BPF manages the queue, while user space installs it and reports the result. Both sides first agree on the exact layout of the counters.

### Define the Statistics Once

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

These six fields cover the possible outcomes for a packet. `enqueued` and `dequeued` count successful entry and exit. A full queue or failed node allocation increases `policy_dropped`. A packet that is still waiting when the qdisc is removed increases `cleanup_dropped`. `bytes_dequeued` adds up the bytes returned to the transmit path, while `max_qlen` remembers the deepest point reached by the queue.

The counters live in BSS. After removing the qdisc, the loader reads them through `skel->bss->stats`. Including one header on both sides keeps the layout consistent.

### Supply the Qdisc Declarations Missing from Older Headers

This example needs graph-object kfuncs, so a local compatibility header supplies the BPF qdisc declarations. These declarations exist only in this lesson's directory and remain independent from the shared vendored headers.

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

This file provides only the graph-object helpers needed to build the queue. `bpf_obj_new` creates a packet node, and `bpf_obj_drop` releases that node when it is empty. `bpf_list_push_back` and `bpf_list_pop_front` arrange the nodes as a FIFO. The BTF tag produced by `__contains` tells the verifier which node type belongs inside the list head, enabling safe graph tracking.

Keeping the compatibility layer inside this lesson also separates it from the scheduler itself. Once the generated libbpf headers expose the same declarations, this file can be removed while the qdisc implementation stays unchanged.

### Implement the Complete Qdisc Lifecycle in BPF

Now we can read the complete kernel-side program. One file contains the qdisc callbacks, FIFO, pacing clock, and counter updates. The main path has only three stages: `enqueue` takes an skb, `dequeue` returns it at the right time, and `reset` handles anything that never left.

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

The full source is long, but ownership makes it manageable. We will follow the skb across each callback.

#### `enqueue`: Own the skb and Schedule Its Departure

During initialization, `init` copies the selected `queue_limit` into `sch->limit`. Every later call to `egress_pacer_enqueue` must give the incoming skb a definite outcome. The callback reads the qdisc-visible length from `qdisc_skb_cb(skb)->pkt_len`, checks for space, and creates a `packet_node` with `bpf_obj_new`. A full queue and a failed allocation both mean that the program cannot accept ownership, so they share one drop path and increment `policy_dropped`.

The actual ownership transfer happens through `bpf_kptr_xchg`. After it succeeds, the node's `__kptr` field holds the skb and the node is responsible for it. The node also stores the packet length and its `eligible_ns` timestamp. Under `queue_lock`, the program pushes that node to the FIFO tail and updates qlen, backlog, `enqueued`, and `max_qlen` in the same critical section. The list and its accounting therefore move together.

The delay is not a fixed interval. It comes from the time this packet would occupy the link at the selected rate:

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

After an idle period, `next_departure_ns` is behind the current time, so the next packet can leave at once. While the FIFO stays busy, every following packet advances the clock by its own length. The result is one aggregate FIFO schedule where each packet's departure interval depends on its own length.

#### `dequeue`: Hand Early Packets to the Watchdog

`egress_pacer_dequeue` only needs to examine the front node. It pops that node and compares `eligible_ns` with the current value from `bpf_ktime_get_ns()`. If the packet is ready, a second `bpf_kptr_xchg` returns the skb to the qdisc. The callback then reduces qlen and backlog, drops the empty node, updates the qdisc's byte counters, and increments `dequeued` and `bytes_dequeued`.

An early packet returns to the head. The callback schedules `bpf_qdisc_watchdog_schedule(sch, expire, 0)` and returns `NULL`. The qdisc core calls dequeue again around `eligible_ns`. The kernel watchdog handles the wait, so BPF code returns immediately.

#### `reset`: Finish the Ownership Story

`egress_pacer_reset` releases the skbs still held when the qdisc is removed. It uses `bpf_for` to pop as many nodes as the current qlen reports, releases each retained skb with `bpf_kfree_skb`, then drops the node object. Those packets count toward `cleanup_dropped`, separate from admission rejections in `policy_dropped`. Once the list is empty, reset clears the pacing clock, qlen, and backlog as well.

Each counter now has a clear update site and a concrete packet outcome:

| Field | Meaning |
| --- | --- |
| `enqueued` | Packets that entered the FIFO |
| `dequeued` | Packets returned for transmission |
| `policy_dropped` | Packets rejected at the queue limit or after allocation failed |
| `cleanup_dropped` | Packets drained during qdisc reset |
| `bytes_dequeued` | Total qdisc-packet bytes returned by dequeue |
| `max_qlen` | Peak packet occupancy of the FIFO |

### Install and Remove the Qdisc from User Space

The kernel-side file defines how the qdisc behaves. The user-space program below supplies its configuration, loads and registers it, installs it on one interface, and removes it when the run ends.

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

With the whole loader visible, we can follow the order from configuration to teardown.

#### Keep Every Operation on the Target Interface

After parsing arguments, the loader writes the rate and queue limit into `skel->rodata->rate_kbps` and `skel->rodata->queue_limit`. Loading freezes rodata, so configuration must happen before `egress_pacer_bpf__load()`. Once the verifier accepts the program, attaching the skeleton registers the `struct_ops` implementation. `bpf_tc_hook_create` then creates the `bpf_pacer` root qdisc at `BPF_TC_QDISC` and `TC_H_ROOT` for the target ifindex.

Creation is exclusive. If the interface already has a root qdisc, the kernel returns `-EEXIST` and the loader stops, preserving the existing configuration. This exclusive approach limits the tutorial code's scope, so the tool is best suited to an interface created for the experiment.

After installation, the loader prints `READY` and checks the duration and `exiting` flag every 100 ms. A normal timeout, SIGINT, and SIGTERM all reach the same cleanup label. Cleanup order ensures `SUMMARY` includes packets dropped during reset: the program calls `bpf_tc_hook_destroy` first to trigger reset, then reads `skel->bss->stats`, and finally destroys the skeleton to unregister the `struct_ops` link.

## Build, Run, and Watch the Queue

The lesson's [`Makefile`](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/53-egress-pacer/Makefile) builds the BPF object, skeleton, and user-space loader. This step does not need root:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

The first run can use the [integration fixture](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/53-egress-pacer/tests/test_egress_pacer.py) directly, which creates a disposable `epac_tx`/`epac_rx` veth pair and deletes it when the test ends. Loading BPF and changing a qdisc require root:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

Here is one completed run. It used x86_64 and a `7.0.0-rc2+` kernel built from commit `a03114efd0720dff230388f7e160e427e54ea31b`:

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

This output demonstrates functional correctness of the main paths: queue limits, pacing schedule, and counter consistency. The fixture sends 40 raw 1024-byte EtherType `0x88B5` frames into a 64 Kbit/s queue that can hold 8 packets. In this run, the receiver saw 9 packets over 1024 ms and another 31 send attempts reached `policy_dropped`. The exact numbers vary with timing and environment.

The fixture also covers conflict detection, signal cleanup, and abnormal recovery. It installs a conflicting `pfifo` and confirms that the loader preserves the existing configuration. It builds a backlog, sends SIGTERM, requires `cleanup_dropped` to be nonzero, and checks `enqueued = dequeued + cleanup_dropped`. The final case sends SIGKILL. The fixture handles cleanup itself: it removes the residual qdisc with `tc`, confirms recovery, and deletes the veth pair from a Python `finally` block.

Once the automatic test makes sense, you can inspect the behavior manually. Choose an interface you fully control and check its current root qdisc:

```bash
tc qdisc show dev veth-service
```

If that interface is safe to use, start the pacer for 30 seconds:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]
```

| Option | Range | Default |
| --- | --- | --- |
| `--interface` | Required | None |
| `--rate-kbps` | 8 to 100000000 | 1024 |
| `--queue-limit` | 1 to 65535 packets | 256 |
| `--duration` | 1 to 86400 seconds | 10 |
| `--verbose` | Flag | Off |

`READY` means installation succeeded. After the duration ends and removal succeeds, the loader prints `SUMMARY`. The ellipses below show the output format, not measured values:

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

If another root qdisc is present, the loader fails before changing it and explains the refusal:

```text
refusing to replace the existing root qdisc on IFACE
```

## Runtime Environment and Extension Points

The BPF qdisc support used here starts with Linux 6.16. The [BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) contains the core change. The kernel needs BTF and the BPF JIT enabled, with at least `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_NET_SCHED=y`, and `CONFIG_NET_SCH_BPF=y`.

The TC hook for a BPF qdisc also needs libbpf 1.6.0 or newer. This repository vendors libbpf and bpftool under `src/third_party`; the relevant [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) and [1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0) mark that boundary. Runtime operations require root. The fixture additionally needs Python 3, raw packet sockets, and the `ip` and `tc` tools from `iproute2`. One controlled veth pair is enough. The configuration tested here is x86_64.

This scheduler implements one aggregate FIFO. The queue limit counts packets, and the timing calculation uses `qdisc_skb_cb(skb)->pkt_len`. Rate and queue limit are fixed at load time, while the queue and counters use global BSS state.

This lesson is suitable for validating functional correctness on controlled interfaces. A fuller scheduler can add fairness, dynamic policy, and persistent recovery.

## What to Take Away

This lesson uses one aggregate FIFO to walk through the full BPF qdisc lifecycle. `enqueue` takes ownership of an skb and schedules its departure from the packet length. The watchdog wakes `dequeue` at the right time. `reset` releases skbs still held when the qdisc is removed. These ownership and timing patterns form the reusable core of a qdisc. A fuller scheduler can add fairness, dynamic policy, and persistent recovery.

> To keep learning eBPF by building complete examples, explore the [tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial).

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
