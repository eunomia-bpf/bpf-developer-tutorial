# eBPF Tutorial by Example: Build an Egress Pacer with a BPF Qdisc

Have you ever wanted to slow down traffic from one test interface and see exactly when each packet becomes ready to leave? Most TC BPF examples cannot show that part. They inspect an skb and return an action, but a separate queueing discipline still owns the packet queue and the send time.

Linux 6.16 lets BPF go one step further. A `struct_ops` program can implement the qdisc itself. In this tutorial, we will build `egress_pacer`, a small FIFO pacer for a disposable veth, TAP, or IFB interface. You give it a rate and a queue limit. It holds each skb until its departure time arrives, then reports how many packets were queued, sent, or dropped.

We keep the design intentionally small. There are no classes, fairness rules, ECN, or burst controls. That makes it easier to follow the parts a qdisc must get right: skb ownership, queue accounting, pacing time, watchdog wakeups, and cleanup. Treat it as a lab tool, not as a production scheduler for a physical NIC.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer>

## What Changes When BPF Becomes the Qdisc?

In an ordinary TC example, the BPF program sees a packet while another qdisc owns the queue. [Lesson 20](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) uses that familiar model. `egress_pacer` goes one layer deeper. Its `struct_ops` object implements `struct Qdisc_ops`, so the BPF program becomes the root qdisc and takes responsibility for every skb it accepts.

Follow one packet through the example. User space loads the BPF object with a rate and queue limit, registers `bpf_pacer`, and attaches it at `TC_H_ROOT`. The `enqueue` callback moves the skb into a BPF-owned node and assigns a departure time. The `dequeue` callback either returns the packet or asks the qdisc watchdog to wake up when the packet is ready. When user space removes the qdisc, `reset` releases anything still waiting.

## Building the Pacer

We will build the pacer one component at a time. The first component is the small statistics contract shared by BPF and user space.

### Sharing Statistics with User Space

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

The BPF program updates these six counters while packets move through the queue. `enqueued` and `dequeued` cover the normal path. `policy_dropped` counts packets rejected because the queue is full or a node cannot be allocated. `cleanup_dropped` counts packets still waiting when the qdisc is reset. The last two fields record the number of bytes sent and the largest queue depth seen during the run.

The loader reads the same structure from `skel->bss->stats` after it removes the qdisc. Keeping this definition in one header prevents the BPF program and the loader from disagreeing about the layout.

### Adding the Missing BPF Declarations

The repository's generated headers predate a few BPF qdisc definitions. This local compatibility header supplies those declarations without changing the vendored global headers.

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

This file does not implement pacing. It exposes the graph-object kfuncs used by the real qdisc: `bpf_obj_new` and `bpf_obj_drop` manage packet nodes, while `bpf_list_push_back` and `bpf_list_pop_front` manage the FIFO. The `__contains` BTF tag tells the verifier which node type belongs to the list head.

Keeping these declarations local matters because they are compatibility glue for this example, not a replacement for the repository's generated libbpf headers. Once those headers provide the same definitions, this file can disappear without changing the pacing algorithm.

### Implementing the Qdisc Callbacks

Now we can look at the kernel-mode program. It implements the qdisc operations, packet queue, pacing clock, and counters.

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

#### Taking Ownership of an skb

The `init` callback first copies `queue_limit` into `sch->limit`. From then on, `egress_pacer_enqueue` must either take ownership of each skb or reject it. It reads `qdisc_skb_cb(skb)->pkt_len`, checks the packet limit, and allocates a `packet_node` with `bpf_obj_new`. A full queue and an allocation failure use the same drop path, so both increase `policy_dropped`.

For an accepted packet, `bpf_kptr_xchg` moves the skb into the node's `__kptr` field. The node now owns the packet and stores its qdisc length and `eligible_ns` timestamp. While holding `queue_lock`, the program adds the node to the FIFO and updates qlen, backlog, `enqueued`, and `max_qlen` together.

The departure time comes from the serialization time of this packet at the requested rate:

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

If the queue was idle, `next_departure_ns` is already in the past, so the first packet can leave immediately. Every later packet advances the clock by its own length. This creates one aggregate FIFO schedule. It is not a token bucket and does not have a separate burst budget.

#### Waiting Without Busy Looping

`egress_pacer_dequeue` pops the first node and compares its `eligible_ns` with `bpf_ktime_get_ns()`. If the time has arrived, `bpf_kptr_xchg` moves the skb out of the node. The callback reduces qlen and backlog, frees the empty node, updates the qdisc byte statistics, and increases `dequeued` and `bytes_dequeued`.

If the packet is early, the callback puts the node back at the front and calls `bpf_qdisc_watchdog_schedule(sch, expire, 0)`. Returning `NULL` tells the qdisc core that nothing is ready. The core wakes the qdisc at `eligible_ns`, so the BPF program never spins while it waits.

#### Releasing Packets During Reset

Removal completes the ownership story. `egress_pacer_reset` uses `bpf_for` to drain the current qlen. It releases every retained skb with `bpf_kfree_skb` and drops each node object. These packets increase `cleanup_dropped`, while admission failures during normal enqueue increase `policy_dropped`. Reset also clears the pacing clock, qlen, and backlog.

Together, the BPF callbacks update the six counters we saw in the shared header:

| Field | Meaning |
| --- | --- |
| `enqueued` | Packets successfully added to the FIFO |
| `dequeued` | Packets returned for transmission |
| `policy_dropped` | Packets rejected at the queue limit or after node allocation failed |
| `cleanup_dropped` | Packets drained by qdisc reset |
| `bytes_dequeued` | Total qdisc packet bytes returned by dequeue |
| `max_qlen` | Peak packet occupancy of the FIFO |

### Loading and Removing the Qdisc

The user-space loader validates the command line, registers the BPF qdisc, installs it on one interface, waits for the requested duration, and removes it.

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

#### Keeping the Experiment on One Interface

Before `egress_pacer_bpf__load()`, the CLI writes the chosen rate and queue limit into `skel->rodata->rate_kbps` and `skel->rodata->queue_limit`. Loading invokes the verifier, attaching the skeleton registers the `struct_ops` implementation, and `bpf_tc_hook_create` creates `bpf_pacer` at `BPF_TC_QDISC` and `TC_H_ROOT` on the selected ifindex.

The create request is exclusive. If another root qdisc already exists and creation returns `-EEXIST`, the loader refuses to inspect, replace, stack, save, or restore it. This conservative behavior is why the example belongs on an interface created for the experiment.

After `READY`, the loader waits in 100 ms intervals until the duration expires or a signal handler sets `exiting`. Normal completion, SIGINT, and SIGTERM enter the same cleanup path. That path calls `bpf_tc_hook_destroy` before reading `skel->bss->stats`, so reset-time drops appear in `SUMMARY`. If removal fails, the loader prints the error and the counters available at that point, returns failure, and leaves the interface for explicit inspection. Destroying the skeleton then unregisters the `struct_ops` link.

## Compilation and execution

Build the BPF object and loader with the lesson's [`Makefile`](./Makefile). Compilation does not need root:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

The safest first run uses the [integration fixture](./tests/test_egress_pacer.py). It creates and removes a disposable `epac_tx`/`epac_rx` veth pair, so the runtime step needs root:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

The final binary was built cleanly on the host and run in the reused `bpf-benchmark` KVM guest. That guest used an x86_64 `7.0.0-rc2+` kernel built from commit `a03114efd0720dff230388f7e160e427e54ea31b`. The fixture produced:

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

This is a functional smoke test, not a throughput or pacing-precision benchmark. The fixture sends 40 raw 1024-byte EtherType `0x88B5` frames into a 64 Kbit/s pacer with an 8-packet queue. In this run, 9 packets arrived over 1024 ms and 31 attempts entered the `policy_dropped` path. Those values describe this fixture and this run.

The same fixture also covers the less pleasant paths. It installs a conflicting `pfifo` and checks that the loader leaves it alone. It creates a backlog before SIGTERM, requires a nonzero `cleanup_dropped`, and checks `enqueued = dequeued + cleanup_dropped`. Finally, it sends SIGKILL. The uncatchable signal left `bpf_pacer` installed on this guest, so the fixture removed it with `tc`, verified recovery, and deleted the veth pair from a Python `finally` block.

For a manual run, use only an interface you control. Inspect its root qdisc first:

```bash
tc qdisc show dev veth-service
```

Then start the pacer for 30 seconds:

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

The loader prints `READY` after installation and `SUMMARY` after successful removal. The ellipses below show the output shape rather than captured values:

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

An existing root qdisc makes exclusive creation fail with:

```text
refusing to replace the existing root qdisc on IFACE
```

## Requirements and limits

- Linux 6.16 or newer with BTF and BPF JIT enabled. The [BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) introduced the required support.
- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_NET_SCHED=y`, and `CONFIG_NET_SCH_BPF=y`.
- libbpf 1.6.0 or newer for the BPF qdisc TC hook. The repository vendors libbpf and bpftool under `src/third_party`. The [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) and [1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0) document the version boundary.
- Root privileges to load BPF and create or destroy a qdisc.
- For the fixture, Python 3, raw packet sockets, and the `ip` and `tc` tools from `iproute2`.
- A controlled interface. A veth pair is sufficient. The tested configuration is x86_64.

The scheduler has one aggregate FIFO. It provides no fairness, per-flow isolation, per-cgroup policy, classes, priorities, ECN, congestion-control integration, or token-bucket burst budget. The packet limit counts packets, while rate accounting uses `qdisc_skb_cb(skb)->pkt_len`. An idle queue lets its first packet leave immediately.

Rate and queue limit remain fixed for one invocation. Global queue and BSS state limit one loader process to one root qdisc instance. The duration-bounded CLI is not a daemon, controller, metrics exporter, or persistent policy manager.

The fixture tested duration-based exit and SIGTERM cleanup. SIGINT uses the same handler but did not receive a separate test. SIGKILL and other abnormal failures may leave the qdisc installed. Host crashes, reboots, GSO/TSO, driver or hardware offload, real-NIC pacing precision, throughput, and hardware timing were not tested.

After an abnormal exit, inspect the interface:

```bash
tc qdisc show dev IFACE
```

If `bpf_pacer` remains, remove it only from an interface you control:

```bash
sudo tc qdisc del dev IFACE root
```

Deleting a qdisc changes traffic scheduling, so never run this recovery command on an interface you do not control.

## Summary

This lesson used a small FIFO to expose the full BPF qdisc lifecycle. `enqueue` takes ownership of an skb and assigns its departure time, the watchdog wakes `dequeue` without a busy loop, and `reset` accounts for packets still queued during removal. Those mechanics are the reusable part. Fairness, concurrent state, dynamic policy, persistence, and stronger recovery would require a larger scheduler.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [libbpf 1.6.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.6.0)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
