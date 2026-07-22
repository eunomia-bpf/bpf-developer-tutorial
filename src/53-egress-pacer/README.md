# eBPF Tutorial: Building an Egress Pacer with BPF Qdisc

## The Problem: Testing Under Bandwidth Constraints

Suppose you need to test how your application behaves when bandwidth is limited. You create a veth pair to simulate a network link and want to cap egress at 64 Kbit/s while observing what happens when the queue fills up and packets start dropping. Traditional approaches (complex tc configurations or user-space proxies) work but are heavyweight for a quick validation.

Linux 6.16 introduced a new option: BPF qdisc. Instead of configuring existing schedulers, you can implement a complete queuing discipline directly in eBPF. This tutorial builds a FIFO rate limiter that demonstrates the full qdisc lifecycle: registering as the root qdisc, managing packet ownership through enqueue and dequeue, computing transmission times, using the watchdog timer for scheduling, and cleaning up when removed.

This example is designed for controlled interfaces like veth, TAP, or IFB, environments where you have full control and can safely experiment with packet scheduling.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## Why BPF Qdisc Exists

To see what BPF qdisc changes, compare it with three common approaches.

**Built-in schedulers are fixed algorithms.** tc provides TBF (Token Bucket Filter), HTB (Hierarchical Token Bucket), and others, but these are predefined behaviors in the kernel. If you need something custom (prioritizing by application type, adjusting rates based on real-time metrics), you must either patch the kernel or chain multiple tc classifiers together.

**TC BPF programs cannot control timing.** Regular TC BPF programs can inspect packets and decide whether to pass or drop them, but the underlying qdisc still controls when packets actually transmit. [Lesson 20](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) shows this pattern: BPF decides pass/drop, but not "send this packet at time T."

**User-space solutions add overhead.** Tools like tc-netem with external helpers or DPDK can shape traffic, but they introduce context switches and deployment complexity. For testing, you often want something lightweight.

BPF qdisc addresses these gaps. Starting with Linux 6.16, you can implement `Qdisc_ops` callbacks (`enqueue`, `dequeue`, `init`, `reset`, `destroy`) in eBPF and register them as a qdisc type. Your BPF program fully controls packet queuing and timing while staying in kernel space. The `egress_pacer` in this tutorial is a FIFO rate limiter built this way.

## How BPF Qdisc Works

Unlike regular TC BPF programs that run within an existing qdisc, a BPF qdisc *is* the qdisc. When you attach it to an interface's root position, your BPF code handles every egress packet.

Here is the lifecycle:

1. **Setup**: User space sets the rate and queue limit, loads the BPF program, registers the `struct_ops` implementation, and attaches it to `TC_H_ROOT` on the target interface.

2. **Enqueue**: When the kernel needs to queue a packet for transmission, it calls your `enqueue` callback. You receive an `skb`, create a node to hold it, compute when it should transmit based on packet length and rate, and add the node to your queue. If the queue is full or allocation fails, you drop the packet.

3. **Dequeue**: When the kernel wants to transmit, it calls your `dequeue` callback. You check if the front packet's transmission time has arrived. If yes, return the `skb`; if not, schedule a watchdog timer for the correct time and return NULL. The kernel will call `dequeue` again when the timer fires.

4. **Reset**: When the qdisc is removed, the kernel calls `reset`. You iterate through any remaining packets, release their resources, and zero the counters.

Throughout this lifecycle, your BPF program owns the packets. From receiving an `skb` in `enqueue`, through holding it in your data structure, to returning it in `dequeue` or freeing it in `reset`, the BPF program is responsible.

![egress_pacer data flow: from configuration, attachment, enqueue, BPF FIFO, dequeue to transmit path, including policy-drop branch, watchdog loop, and reset lifecycle](https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/53-egress-pacer/egress-pacer-flow.png)

The solid lines trace a packet's normal path: configuration and attachment, then enqueue into the FIFO, then dequeue to the transmit path. When the queue is full or allocation fails, packets take the policy-drop branch. If dequeue is called before a packet's transmission time, the node is pushed back to the front, a watchdog is scheduled, and NULL is returned; the watchdog later re-enters dequeue. The dashed lines show the lifecycle path: removing the qdisc triggers reset, which frees queued packets and zeros qlen and backlog.

## Code Implementation

The implementation consists of four files: a shared header defining statistics, a compatibility header providing BPF graph-object declarations, the BPF program implementing qdisc callbacks, and a user-space loader that manages the lifecycle.

### Shared Header

`egress_pacer.h` defines statistics shared between BPF and user space. These six counters categorize every packet outcome:

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

- `enqueued` / `dequeued`: Packets that successfully entered and left the FIFO.
- `policy_dropped`: Packets dropped at enqueue because the queue was full or allocation failed.
- `cleanup_dropped`: Packets still in the queue when reset runs. These were queued but never transmitted.
- `bytes_dequeued`: Total bytes actually transmitted.
- `max_qlen`: Peak queue depth observed.

### Compatibility Header

BPF qdisc uses "graph-object" kfuncs, kernel functions for managing BPF-owned linked lists and objects. This local header provides the necessary declarations:

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

These helpers let BPF code manage kernel objects safely:

- `bpf_obj_new` allocates a new object of the given type.
- `bpf_obj_drop` frees it.
- `bpf_list_push_back` / `bpf_list_push_front` / `bpf_list_pop_front` implement a doubly-linked list.
- The `__contains` macro generates a BTF tag telling the verifier what node type the list head contains, enabling safe ownership tracking.

### BPF Program

`egress_pacer.bpf.c` implements the qdisc. The `SEC(".struct_ops")` declaration registers this as a `Qdisc_ops` implementation:

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

#### Key data structures

The `const volatile` variables `rate_kbps` and `queue_limit` live in `.rodata`. User space writes them after `open()` but before `load()`, and the verifier treats them as compile-time constants thereafter.

The `packet_node` structure holds each queued packet:
- `eligible_ns`: The earliest time this packet may transmit (in nanoseconds).
- `packet_len`: The packet's length for backlog accounting.
- `skb`: A `__kptr` field that owns the kernel socket buffer. The `__kptr` annotation tells the verifier this field holds an owned kernel pointer.
- `node`: A `bpf_list_node` for linking into the FIFO.

The `private(A)` macro places the lock, list head, and departure timestamp in a private data section with proper alignment.

#### The enqueue callback

`egress_pacer_enqueue` receives a packet from the kernel:

1. Get the packet length from `qdisc_skb_cb(skb)->pkt_len`.
2. If the queue is at capacity, drop the packet.
3. Allocate a `packet_node`. If allocation fails, drop.
4. Compute when this packet may transmit: `interval_ns = packet_len * 8 * 1000000 / rate_kbps` (bits divided by kilobits/sec gives nanoseconds).
5. Transfer ownership of the `skb` to the node using `bpf_kptr_xchg`. After this call, the node owns the `skb`.
6. Under the spin lock, set the packet's eligible time. If the queue was idle (`next_departure_ns` is in the past), this packet can leave immediately; otherwise it waits behind the previous departure.
7. Push the node onto the FIFO, update counters, unlock, and return success.

The `bpf_qdisc_skb_drop` call handles dropped packets: it adds the `skb` to the kernel's free list and updates qdisc statistics.

#### The dequeue callback

`egress_pacer_dequeue` is called when the kernel wants a packet to transmit:

1. Pop the front node from the FIFO.
2. If the queue is empty, return NULL.
3. Check if the current time has reached `eligible_ns`. If not, push the node back to the front, schedule a watchdog timer for `eligible_ns`, and return NULL. The kernel will call dequeue again when the timer fires.
4. If ready, extract the `skb` from the node using `bpf_kptr_xchg`, decrement counters, free the node, update statistics, and return the `skb`.

The watchdog mechanism (`bpf_qdisc_watchdog_schedule`) is how BPF qdisc implements transmission timing: you tell the kernel when to wake you, and it calls dequeue at that time.

#### The reset callback

`egress_pacer_reset` runs when the qdisc is removed. Any packets still in the queue must be freed:

1. Loop through all nodes using `bpf_for` (a BPF helper for bounded iteration).
2. Pop each node, extract its `skb`, and free it with `bpf_kfree_skb`.
3. Count freed packets in `cleanup_dropped`.
4. Zero the departure timestamp and qdisc counters.

#### Registration

The `SEC(".struct_ops")` block at the end registers the callbacks as a `Qdisc_ops` structure. The `id` field (`"bpf_pacer"`) is the name user space uses to instantiate this qdisc.

### User-Space Loader

`egress_pacer.c` handles command-line arguments, configures the BPF program, attaches the qdisc, waits for the specified duration, and cleans up:

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

The loader follows a standard libbpf pattern:

1. Parse arguments and verify the interface exists with `if_nametoindex`.
2. Open the skeleton and write rate/queue limit to `.rodata`.
3. Load the BPF program (this verifies and JIT-compiles it).
4. Attach the `struct_ops` implementation, making `bpf_pacer` available as a qdisc type.
5. Create the root qdisc on the target interface with `bpf_tc_hook_create`.

The `bpf_tc_hook_create` call has exclusive semantics: if the interface already has a root qdisc, the kernel returns `-EEXIST` and the program exits without changing anything. This safety measure means the tool is best suited for dedicated test interfaces where you control the configuration.

After successful attachment, the program prints `READY`, then polls every 100ms until duration expires or a signal arrives. Cleanup order matters: first `bpf_tc_hook_destroy` (which triggers reset and frees queued packets), then read final statistics, then destroy the skeleton.

## Compilation and Execution

Build from source:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

The easiest way to test is with the included integration test, which creates a temporary veth pair and cleans it up afterward. Root is required for loading BPF and modifying qdiscs:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

Here is output from a successful run on x86_64 with kernel `7.0.0-rc2+` (commit `a03114efd0720dff230388f7e160e427e54ea31b`):

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

What happened: the test sent 40 raw Ethernet frames (1024 bytes each, EtherType `0x88B5`) into a 64 Kbit/s queue limited to 8 packets. Nine packets made it through the queue, spaced over 1024ms, matching the expected rate. The other 31 sends hit the queue limit and went to `policy_dropped`. Exact numbers vary by system timing.

The test also exercises edge cases:
- Pre-installs a `pfifo` to confirm the loader refuses to replace existing qdiscs.
- Sends SIGTERM with packets queued, verifying `cleanup_dropped > 0` and that `enqueued = dequeued + cleanup_dropped`.
- Sends SIGKILL (which skips cleanup), then uses `tc` to manually remove the residual qdisc and confirm the interface recovers.

For manual testing, pick an interface you control and check its current qdisc:

```bash
tc qdisc show dev veth-service
```

If it shows the default `noqueue` or `pfifo_fast`, you can attach the pacer:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

Command-line options:

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]

Options:
  -i, --interface IFACE       target interface (required)
  -r, --rate-kbps KBPS        egress rate in Kbit/s, 8-100000000 (default: 1024)
  -q, --queue-limit PACKETS   queue capacity in packets, 1-65535 (default: 256)
  -d, --duration SEC          how long to run, 1-86400 seconds (default: 10)
  -v, --verbose               print libbpf debug output
  -h, --help                  show help
```

When you see `READY`, the qdisc is installed and pacing traffic. When the duration ends (or you press Ctrl+C), the program removes the qdisc and prints `SUMMARY`.

### Environment Requirements

BPF qdisc requires Linux 6.16 or later. Your kernel must have BTF and BPF JIT enabled:

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

The repository includes libbpf and bpftool in `src/third_party`. The integration test additionally requires Python 3, raw socket capability, and `ip`/`tc` from iproute2. A veth pair is sufficient for testing; verified on x86_64.

## Summary

This tutorial demonstrated BPF qdisc through a complete FIFO rate limiter:

- **enqueue** takes ownership of packets and schedules transmission times based on packet length and rate.
- **dequeue** uses the watchdog timer to wake at the right moment and returns packets to the kernel.
- **reset** frees any packets still queued when the qdisc is removed.

These three phases (receiving packets, timing their release, and cleaning up) form a reusable pattern for custom scheduling disciplines.

This particular scheduler implements a single aggregate FIFO with fixed rate and queue limit set at load time. It is intentionally simple, suited for validating correctness on controlled interfaces. A production scheduler could build on this foundation to add fairness, dynamic policies, or state persistence across restarts.

> To learn more about eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
