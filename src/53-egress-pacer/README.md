# eBPF Tutorial by Example: Pace Egress Traffic with a BPF Qdisc

A lab service sends a sudden burst through a veth interface. The queue grows, latency jumps, and packets disappear without useful accounting. You want to slow that burst to a known rate, keep the queue bounded, and see whether packets left the interface or were dropped.

This tutorial builds `egress_pacer`, a small BPF qdisc for that job. It registers a FIFO qdisc with Linux 6.16 BPF `struct_ops`, assigns each packet an eligible departure time, and reports enqueue, dequeue, byte, and drop counters when the run ends. The loader also refuses to overwrite an existing root qdisc.

The example targets a controlled veth, TAP, or IFB interface. It is not a general-purpose scheduler for a production NIC. By the end, you will understand how a BPF qdisc owns an skb, how its watchdog avoids busy waiting, and how user space installs and removes the qdisc safely enough for a bounded lab run.

The complete lesson is available in the [`53-egress-pacer` source directory](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer).

## Why put the pacer in a qdisc?

Linux already sends outgoing packets through a queueing discipline, or qdisc. An ordinary TC classifier can inspect a packet and return an action, but a separate kernel qdisc still owns the queue. The [TC classifier tutorial](../20-tc/README.md) follows that model.

This example takes a different path. Its BPF `struct_ops` object implements `struct Qdisc_ops` and registers `bpf_pacer` as the root qdisc itself. The BPF program decides whether a packet enters the queue, when the head packet may leave, and what happens to queued skbs during reset.

That control comes with a lifecycle cost. Replacing a root qdisc can change live traffic, so the loader treats any existing root qdisc as a conflict. It runs for a fixed duration, removes the qdisc after normal completion or a handled SIGINT or SIGTERM, and leaves an explicit recovery command for abnormal termination. An uncatchable SIGKILL can leave the qdisc installed.

## Follow one packet through the tool

The kernel and user-space parts cooperate in this order:

1. The loader resolves a controlled interface, writes the rate and packet limit into BPF read-only data, and loads the object.
2. Attaching the `struct_ops` map registers `bpf_pacer`. The loader then creates it at `TC_H_ROOT` with the libbpf qdisc TC hook.
3. The qdisc `init` callback copies `queue_limit` into `sch->limit` before traffic arrives.
4. `egress_pacer_enqueue` either drops a packet at the limit or moves its skb into a BPF-owned queue node. It converts packet length and the configured rate into an eligible departure time.
5. `egress_pacer_dequeue` returns an eligible skb. If the head packet is early, the callback puts it back and asks the qdisc watchdog to retry at the right time.
6. When user space removes the qdisc, `egress_pacer_reset` drains any retained skbs. The loader then reads the final BSS counters and prints `SUMMARY`.

The design is deliberately small. One loader owns one root qdisc, one FIFO, and one global set of counters.

## Complete source code

The shared header defines the statistics contract used by BPF and user space.

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

The kernel-mode program implements the qdisc operations, packet queue, pacing clock, and counters.

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

## How enqueue turns a rate into time

`egress_pacer_enqueue` first reads `qdisc_skb_cb(skb)->pkt_len`. The queue limit is measured in packets, while the rate calculation uses this qdisc packet length. A full queue goes directly to the drop path. A failed `bpf_obj_new` allocation uses the same path, so both cases increment `policy_dropped`.

For an accepted packet, `bpf_obj_new` allocates a `packet_node`, and `bpf_kptr_xchg` transfers the skb into its `__kptr` field. The node now carries the packet length and an `eligible_ns` timestamp. BPF list ownership and skb ownership move together, which lets reset release both objects later.

The pacing interval is the packet's serialization time at the requested rate:

```text
interval_ns = packet_len * 8 * 1,000,000 / rate_kbps
eligible_ns = max(next_departure_ns, now)
next_departure_ns = eligible_ns + interval_ns
```

The first packet after an idle period sees an old `next_departure_ns`, so it may leave immediately. Every later packet advances the clock by its own serialized length. This is an aggregate FIFO pacer, not a token bucket. It has no separate burst budget.

The spin lock protects the list, `next_departure_ns`, qlen, and backlog updates. Successful insertion increments `enqueued`, and `max_qlen` records the largest queue seen during the run.

## How dequeue waits without spinning

`egress_pacer_dequeue` pops the first node and compares its timestamp with `bpf_ktime_get_ns()`. An eligible packet leaves the BPF node through another `bpf_kptr_xchg`. The callback reduces qlen and backlog, frees the empty node, updates the qdisc byte statistics, and increments `dequeued` and `bytes_dequeued`.

An early packet takes a different path. The callback pushes the node back to the front, calls `bpf_qdisc_watchdog_schedule(sch, expire, 0)`, and returns `NULL`. The qdisc core can retry when `eligible_ns` arrives, so the BPF program never loops while waiting for time to pass.

## Reset keeps cleanup drops separate

Removing a qdisc can happen while packets are still queued. `egress_pacer_reset` walks the current qlen with `bpf_for`, removes every node, releases each skb with `bpf_kfree_skb`, and drops the node object. Packets released here increment `cleanup_dropped`, not `policy_dropped`.

That distinction makes the final counters useful. `policy_dropped` describes admission failures while the pacer was running. `cleanup_dropped` describes packets discarded because the qdisc was removed with a backlog. Reset also clears `next_departure_ns`, qlen, and backlog.

The BSS `pacer_stats` fields have the following meanings:

| Field | Meaning |
| --- | --- |
| `enqueued` | Packets successfully added to the FIFO |
| `dequeued` | Packets returned for transmission |
| `policy_dropped` | Packets rejected at the queue limit or after node allocation failed |
| `cleanup_dropped` | Packets drained by qdisc reset |
| `bytes_dequeued` | Total qdisc packet bytes returned by dequeue |
| `max_qlen` | Peak packet occupancy of the FIFO |

## User space owns the qdisc lifecycle

The loader sets `skel->rodata->rate_kbps` and `skel->rodata->queue_limit` before the verifier loads the BPF object. Attaching the skeleton registers the `struct_ops` implementation. `bpf_tc_hook_create` then asks libbpf to create `bpf_pacer` at `BPF_TC_QDISC` and `TC_H_ROOT` on the selected ifindex.

An existing root qdisc makes that create call return `-EEXIST`. The loader prints a refusal instead of inspecting, stacking, replacing, saving, or restoring the existing qdisc. This conservative rule is why the example belongs on an interface you created for the test.

After printing `READY`, the loader sleeps in 100 ms intervals until the duration expires or a signal handler sets `exiting`. SIGINT and SIGTERM share that handler. The integration fixture exercises duration-based exit and SIGTERM, but it does not run a separate SIGINT case.

Cleanup calls `bpf_tc_hook_destroy` before reading `skel->bss->stats`. Destroying the qdisc invokes reset for any remaining queue. The loader prints `SUMMARY` only after those cleanup drops have been counted, then destroys the skeleton and unregisters the `struct_ops` link.

## Compilation and execution

Build the BPF object and loader without root:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

The safest first run is the integration fixture. It creates and deletes a disposable `epac_tx`/`epac_rx` veth pair, so this command requires root:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

The final test binary was run in the reused `bpf-benchmark` KVM guest with a clean `7.0.0-rc2+` kernel from source commit `a03114efd0720dff230388f7e160e427e54ea31b`. The captured output was:

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

The captured run is a functional smoke test, not a throughput or pacing-precision benchmark. The fixture bursts 40 raw 1024-byte EtherType `0x88B5` frames into a 64 Kbit/s pacer with an 8-packet queue. In this run, 31 attempts were counted as `policy_dropped` when the queue filled, while 9 packets were paced and received over 1024 ms. These numbers describe this fixture only.

Before that burst, the fixture installs a conflicting `pfifo` and confirms that the loader refuses to replace it. A second burst leaves packets queued before SIGTERM. That run requires a nonzero `cleanup_dropped` value and checks `enqueued = dequeued + cleanup_dropped`.

The last case sends SIGKILL. On the tested guest, the uncatchable signal left `bpf_pacer` installed. The fixture removes it explicitly with `tc`, verifies recovery, and deletes the veth pair in a Python `finally` block.

To use the loader manually, first create a dedicated interface that you control. Inspect its root qdisc before installation:

```bash
tc qdisc show dev veth-service
```

Then run the pacer for 30 seconds:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

The command accepts the following options:

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

When the qdisc is active, the loader prints `READY`. It prints the final counters in `SUMMARY` after removal. The following block shows only the output shape. Its ellipses are placeholders, not captured values.

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

If the interface already has a root qdisc, the loader exits with this diagnostic:

```text
refusing to replace the existing root qdisc on IFACE
```

## Requirements

- Linux 6.16 or newer. [The BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb) introduced the required kernel support.
- libbpf 1.6.0 or newer for the BPF qdisc TC hook. The repository vendors libbpf and bpftool under `src/third_party`, and the relevant [libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df) documents the API.
- An x86_64 system for the tested configuration.
- Root privileges to load BPF and create or destroy the qdisc.
- Root privileges, Python 3, raw packet sockets, and `iproute2` tools `ip` and `tc` for the integration fixture.
- The `tc` command for the explicit abnormal-exit recovery path.
- BTF and BPF JIT enabled.
- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_NET_SCHED=y`, and `CONFIG_NET_SCH_BPF=y`.
- A controlled network interface. A veth pair is sufficient.

## Limits and recovery

This lesson implements one aggregate FIFO. It has no fairness, per-flow isolation, per-cgroup policy, classes, priorities, ECN, burst budget, or congestion-control integration. The queue limit counts packets, and rate accounting uses `qdisc_skb_cb(skb)->pkt_len`. The first packet after an idle period may depart immediately.

Rate and queue limit stay fixed for one invocation. Global queue and BSS state also limit one loader process to one root qdisc instance. The loader refuses every existing root qdisc without inspecting, preserving, stacking, or restoring it.

The CLI is duration bounded. It is not a daemon, controller, metrics exporter, or persistent policy manager. Duration-based exit and SIGTERM cleanup were tested. SIGINT uses the same handler but was not tested separately. Cleanup is not guaranteed after SIGKILL or another abnormal process failure, and host-crash and reboot behavior were not tested.

The KVM fixture checks behavior only. It does not cover throughput, pacing precision on a real NIC, driver or hardware offload, GSO/TSO, or real hardware timing.

After an abnormal exit, inspect the controlled interface:

```bash
tc qdisc show dev IFACE
```

If `bpf_pacer` is still present, remove it with:

```bash
sudo tc qdisc del dev IFACE root
```

Deleting a qdisc changes traffic scheduling. Run this command only on an interface you control.

## Summary

This example turns the Linux 6.16 BPF qdisc interface into a bounded, short-lived egress pacer. You saw how BPF objects retain skbs, how serialization time becomes a departure schedule, how the watchdog waits without spinning, and how reset separates policy drops from cleanup drops. The same structure can support richer policies, but a real service would need explicit fairness, concurrency, persistence, and failure-recovery design.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)
