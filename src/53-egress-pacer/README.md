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

const volatile __u64 rate_kbps = 1024;
const volatile __u32 queue_limit = 256;

struct packet_node {
	__u64 eligible_ns;
	__u32 packet_len;
	struct sk_buff __kptr *skb;
	struct bpf_list_node node;
};

private(A) struct bpf_spin_lock queue_lock;
private(A) struct bpf_list_head packet_queue __contains(packet_node, node);
private(A) __u64 next_departure_ns;

SEC("struct_ops/egress_pacer_enqueue")
int BPF_PROG(egress_pacer_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct packet_node *packet;
	__u64 eligible_ns, interval_ns, now;
	__u32 packet_len = qdisc_packet_len(skb);

	if (sch->q.qlen >= sch->limit)
		goto drop;
	packet = bpf_obj_new(typeof(*packet));
	if (!packet)
		goto drop;

	now = bpf_ktime_get_ns();
	interval_ns = (__u64)packet_len * 8 * 1000000ULL / rate_kbps;
	packet->packet_len = packet_len;
	skb = bpf_kptr_xchg(&packet->skb, skb);

	bpf_spin_lock(&queue_lock);
	eligible_ns = next_departure_ns > now ? next_departure_ns : now;
	next_departure_ns = eligible_ns + interval_ns;
	packet->eligible_ns = eligible_ns;
	bpf_list_push_back(&packet_queue, &packet->node);
	sch->q.qlen++;
	sch->qstats.backlog += packet_len;
	bpf_spin_unlock(&queue_lock);
	return NET_XMIT_SUCCESS;

drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/egress_pacer_dequeue")
struct sk_buff *BPF_PROG(egress_pacer_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct packet_node *packet;
	struct sk_buff *skb = NULL;
	__u64 now = bpf_ktime_get_ns();

	bpf_spin_lock(&queue_lock);
	node = bpf_list_pop_front(&packet_queue);
	bpf_spin_unlock(&queue_lock);
	if (!node)
		return NULL;

	packet = container_of(node, struct packet_node, node);
	if (now < packet->eligible_ns) {
		bpf_spin_lock(&queue_lock);
		bpf_list_push_front(&packet_queue, &packet->node);
		bpf_spin_unlock(&queue_lock);
		bpf_qdisc_watchdog_schedule(sch, packet->eligible_ns, 0);
		return NULL;
	}

	skb = bpf_kptr_xchg(&packet->skb, skb);
	sch->q.qlen--;
	sch->qstats.backlog -= packet->packet_len;
	bpf_obj_drop(packet);
	return skb;
}

/* reset drains packet_queue and frees every remaining skb. */
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
#include <net/if.h>
#include <bpf/libbpf.h>
#include "egress_pacer.skel.h"

static struct {
	const char *interface;
	unsigned long long rate_kbps;
	unsigned int queue_limit;
	unsigned int duration;
} env = {
	.rate_kbps = 1024,
	.queue_limit = 256,
	.duration = 10,
};

/* Argument parsing, signal handling, and diagnostics are omitted here. */
static int parse_args(int argc, char **argv);
static int wait_for_duration(void);

int main(int argc, char **argv)
{
	struct egress_pacer_bpf *skel;
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.attach_point = BPF_TC_QDISC,
		.parent = TC_H_ROOT,
		.handle = TC_H_MAKE(1 << 16, 0),
		.qdisc = "bpf_pacer",
	};
	bool qdisc_created = false;

	parse_args(argc, argv);
	hook.ifindex = if_nametoindex(env.interface);

	skel = egress_pacer_bpf__open();
	skel->rodata->rate_kbps = env.rate_kbps;
	skel->rodata->queue_limit = env.queue_limit;
	egress_pacer_bpf__load(skel);
	egress_pacer_bpf__attach(skel);

	if (!bpf_tc_hook_create(&hook))
		qdisc_created = true;

	printf("READY interface=%s rate_kbps=%llu queue_limit=%u duration=%u\n",
	       env.interface, env.rate_kbps, env.queue_limit, env.duration);
	wait_for_duration();

	if (qdisc_created)
		bpf_tc_hook_destroy(&hook);
	printf("SUMMARY enqueued=%llu dequeued=%llu policy_dropped=%llu\n",
	       skel->bss->stats.enqueued,
	       skel->bss->stats.dequeued,
	       skel->bss->stats.policy_dropped);
	egress_pacer_bpf__destroy(skel);
}
```

The loader follows a standard libbpf pattern:

1. Parse arguments and verify the interface exists with `if_nametoindex`.
2. Open the skeleton and write rate/queue limit to `.rodata`.
3. Load the BPF program (this verifies and JIT-compiles it).
4. Attach the `struct_ops` implementation, making `bpf_pacer` available as a qdisc type.
5. Create the root qdisc on the target interface with `bpf_tc_hook_create`.

The `bpf_tc_hook_create` call has exclusive semantics: if the interface already has a root qdisc, the kernel returns `-EEXIST` and the program exits without changing anything. For a root-qdisc conflict on the requested interface, the loader prints `tc qdisc show dev IFACE` and the recovery command `sudo tc qdisc del dev IFACE root`. A `struct_ops` name conflict is global rather than interface-local, so the loader instead prints `tc qdisc show` for every interface and does not guess which interface to modify. It never runs a destructive command automatically; remove a root qdisc only after confirming that the displayed `bpf_pacer` entry is stale. This safety measure means the tool is best suited for dedicated interfaces where you control the configuration.

After successful attachment, the program prints `READY`, then polls every 100ms until duration expires or a signal arrives. Cleanup order matters: first `bpf_tc_hook_destroy` (which triggers reset and frees queued packets), then read final statistics, then destroy the skeleton.

## Compilation and Execution

Build from source:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

Pick an interface you control and inspect its current root qdisc before attaching the pacer:

```bash
tc qdisc show dev veth-service
```

If the interface is available for this experiment, start the pacer and let normal application traffic pass through it:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

The tool prints `READY` only after the qdisc is active. When the duration expires, its output has this shape:

```console
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=0 bytes_dequeued=... max_qlen=...
```

`enqueued` counts packets accepted by the qdisc, `dequeued` counts packets released to the device, and `policy_dropped` counts packets rejected when the queue was full. If the process is killed before normal cleanup and leaves `bpf_pacer` behind, the next run prints qdisc state across all interfaces. Find the interface whose line contains `bpf_pacer`, confirm that it is the stale instance, and then remove that actual root qdisc with `sudo tc qdisc del dev ACTUAL_IFACE root`.

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

The repository includes libbpf and bpftool in `src/third_party`. Use `tc` from iproute2 to inspect the target interface and recover a stale root qdisc if necessary.

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
