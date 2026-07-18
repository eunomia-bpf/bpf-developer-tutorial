# eBPF Tutorial by Example: Pace Egress Traffic with a BPF Qdisc

You have a lab, a test bench, or a service running behind a dedicated veth or TAP interface. Something sends a burst, the queue grows unbounded, latency spikes, and you have no visibility into the drop. You want a short-lived egress pacer that installs instantly, reports queue and byte counters, and removes itself on exit or signal.

This tutorial builds a single-purpose BPF qdisc that does exactly that. It uses the Linux 6.16 `struct_ops`-based BPF qdisc infrastructure to register a bounded FIFO, pace packets at an aggregate rate you choose, and expose enqueue/dequeue/drop statistics in user space.

This is not production-ready for a general-purpose NIC. It is intentionally designed for a controlled interface (veth, TAP, IFB) where you make an explicit lifecycle decision. The loader refuses to replace any existing root qdisc.

## Quick start

Build without root:

```bash
cd src/53-egress-pacer
make clean
make -j2
```

Run on a dedicated interface:

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

The tool prints a `READY` line when the qdisc is active, then a `SUMMARY` line with final counters when it exits:

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

Usage:

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]
```

| Option | Range | Default |
|--------|-------|---------|
| `--interface` | required | none |
| `--rate-kbps` | 8 to 100000000 | 1024 |
| `--queue-limit` | 1 to 65535 packets | 256 |
| `--duration` | 1 to 86400 seconds | 10 |
| `--verbose` | flag | off |

If the interface already has a root qdisc, the tool exits with:

```text
refusing to replace the existing root qdisc on IFACE
```

## Verified test output

The repository includes a deterministic integration fixture. This output was captured in a KVM guest running kernel `7.0.0-rc2+` after a clean host build:

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, and normal/signal cleanup succeeded
```

This is a functional smoke test, not benchmark-quality performance evidence. 40 raw 1024-byte EtherType `0x88B5` frames are sent in a burst through a 64 Kbit/s pacer with an 8-packet queue. 31 are dropped at the queue limit; 9 are paced and delivered. Do not generalize these numbers beyond this fixture.

Run the fixture yourself on a suitable disposable Linux 6.16+ system:

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

The fixture creates and deletes `epac_tx`/`epac_rx` veth interfaces, installs a conflicting `pfifo` first to prove refusal, then sends the burst. It asserts bounded drops, byte/packet accounting, pacing, normal cleanup, SIGTERM cleanup, and deletes the veth pair in a `finally` block.

## How it works

The tool has two parts: a BPF object that implements `struct Qdisc_ops`, and a user-space loader that manages the qdisc lifecycle.

### BPF qdisc: enqueue

When a packet arrives at the qdisc, the enqueue callback checks the queue length against `sch->limit`. If the queue is full, the packet is dropped and `policy_dropped` increments. Otherwise:

1. Allocate a `packet_node` with `bpf_obj_new`.
2. Transfer the skb into the node via `bpf_kptr_xchg`.
3. Compute the packet's eligible departure timestamp: `eligible_ns = max(next_departure_ns, now)`. Then advance `next_departure_ns` by the packet's serialization interval `(packet_len * 8 * 1,000,000 / rate_kbps)` nanoseconds.
4. Push the node onto a BPF linked list and update qlen/backlog.

From the BPF source (`egress_pacer.bpf.c`):

```c
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
```

The interval formula means the first packet after an idle period departs immediately (because `next_departure_ns` will be in the past, so `eligible_ns = now`). Subsequent packets are spaced by serialized packet length at the configured rate.

### BPF qdisc: dequeue

The dequeue callback pops the head of the list. If the current time is before the packet's `eligible_ns`, the packet goes back to the front of the list and the qdisc watchdog is scheduled:

```c
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
	if (!node)
		return NULL;

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
```

The watchdog (`bpf_qdisc_watchdog_schedule`) tells the kernel to call dequeue again at the eligible time. This is the pacing mechanism: the kernel does not poll; it sleeps until the next packet is due.

### BPF qdisc: reset

On qdisc removal, the `reset` callback drains all retained skbs, frees the `packet_node` objects, and zeroes qlen/backlog. Packets freed here are counted in `cleanup_dropped`, distinct from the policy drops during normal operation.

### User-space lifecycle

The loader (`egress_pacer.c`) follows this sequence:

1. Parse arguments and resolve the interface name to an ifindex.
2. Open the BPF skeleton and set `rodata->rate_kbps` and `rodata->queue_limit`.
3. Load the BPF object (verifier runs here).
4. Attach the struct_ops map, registering `bpf_pacer` as an available qdisc type.
5. Create the qdisc at the interface root via `bpf_tc_hook_create` with `BPF_TC_QDISC` and `TC_H_ROOT`. If the interface already has a root qdisc, the call returns `-EEXIST` and the tool prints the refusal and exits.
6. Print `READY`, then sleep in 100 ms increments until the duration expires or a signal arrives.
7. Destroy the qdisc via `bpf_tc_hook_destroy`, read final BSS counters, print `SUMMARY`, and destroy the skeleton.

Signal handlers set a flag that breaks the sleep loop. SIGINT and SIGTERM are tested cleanup paths.

### Statistics

The `pacer_stats` struct in BSS holds:

| Field | Meaning |
|-------|---------|
| `enqueued` | packets successfully queued |
| `dequeued` | packets transmitted |
| `policy_dropped` | packets dropped at the queue limit |
| `cleanup_dropped` | packets drained during reset |
| `bytes_dequeued` | total bytes of dequeued packets |
| `max_qlen` | peak queue occupancy |

The loader reads these from `skel->bss->stats` after destroying the qdisc.

## Requirements

- Linux kernel 6.16 or later. BPF qdisc support entered in [this commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb).
- libbpf 1.6.0 or later for BPF qdisc TC hook support ([libbpf commit](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)). This repository vendors bpftool v7.7.0 and libbpf v1.7.0.
- Architecture: x86_64 (tested).
- Root privileges for BPF load, qdisc creation, and raw test sockets.
- BTF and BPF JIT enabled.
- Kernel configs: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_NET_SCHED=y`, `CONFIG_NET_SCH_BPF=y`.
- A controlled network interface. A veth pair is sufficient.

## Limitations

- One aggregate FIFO. No fairness, per-flow isolation, per-cgroup policy, classes, priorities, ECN, burst budget, or congestion-control integration.
- Queue limit is in packets; rate accounting uses `qdisc_skb_cb(skb)->pkt_len`.
- The first packet after an idle period departs immediately.
- Rate and queue limit are fixed for one invocation.
- One root qdisc instance per loader process due to global queue and BSS state.
- Refuses every existing root qdisc without inspecting, preserving, stacking, or restoring it.
- Duration-bounded CLI. Not a daemon, controller, metrics exporter, or persistent policy manager.
- Normal exit, SIGINT, and SIGTERM are tested cleanup paths. SIGKILL, host crash, or abnormal process failure will not clean up the qdisc.
- KVM test validates behavior but is not a throughput or precision benchmark. It does not account for driver/hardware offload, GSO/TSO, or real NIC timing.

## Recovery

After an abnormal exit, verify with:

```bash
tc qdisc show dev IFACE
```

If `bpf_pacer` is still present on a controlled interface, remove it with:

```bash
sudo tc qdisc del dev IFACE root
```

This changes traffic scheduling on the interface. Only do this on an interface you control.

## References

- [Linux BPF qdisc merge commit](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog follow-up commit](https://github.com/torvalds/linux/commit/7a2dafd33c4506e4cb4e63a422530c1cd5a35481)
- [libbpf qdisc TC hook support](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [Upstream BPF FIFO qdisc selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [Upstream BPF qdisc test runner](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 release](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)

## More

This example is part of the eBPF Developer Tutorial. For more examples and the full tutorial, visit:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- <https://eunomia.dev/tutorials/>
