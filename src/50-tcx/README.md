# eBPF Tutorial by Example 50: Composable Traffic Control with TCX Links

Imagine you need to run two BPF programs on every inbound packet: one that collects statistics, and another that decides whether to accept the packet. With classic TC attachment, you would create a qdisc, assign each program a numeric priority, and hope no other application on the system picks the same priority numbers. If your stats-gathering application crashes, its filter stays attached, possibly interfering with the classifier. If a third-party CNI plugin runs `tc filter del` to clean up its own filters, it might accidentally remove yours too.

**TCX** (Traffic Control eXtension) solves these problems. Introduced by Daniel Borkmann and merged in Linux 6.6, TCX provides a link-based attachment model for the TC ingress and egress hooks. Programs gain automatic cleanup on file descriptor close, explicit ordering through `BPF_F_BEFORE` and `BPF_F_AFTER` flags, and immunity from accidental deletion by other processes, all without touching qdiscs or filter priorities.

In this tutorial, we build a minimal demonstration: two TCX ingress programs on the loopback interface, with controlled execution order and observable counters.

> Complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## Background: Why Classic TC Attachment Falls Short

### The Problem: Shared Namespace, No Ownership

Classic `tc` BPF attachment (`cls_bpf`) was designed when a single operator controlled the entire Traffic Control pipeline. To attach a BPF program, you create a `clsact` qdisc, then add filters with handles and priorities. This model breaks down when multiple independent applications need to coexist:

1. **No ownership model.** A filter is identified by its handle and priority, not by the process that created it. Any process with sufficient privilege can delete any filter; there is no protection against one application removing another's program.

2. **Priority collisions.** Two applications might independently choose priority 100. The second attachment silently replaces the first, with no error and no warning.

3. **Persistence after crash.** Classic filters survive until explicitly removed. If an application crashes without cleanup, its filter persists with potentially stale logic.

4. **Shared control plane.** Both the `tc` CLI and libbpf-based programs use netlink to manage filters. Your BPF application competes with every other tc user on the system for this shared namespace.

These problems became critical in projects like Cilium, where BPF datapaths must coexist with third-party CNI plugins, observability agents, and security tools, all attaching to the same interfaces.

### The Solution: Link-Based Attachment

TCX takes a fundamentally different approach. Instead of layering onto qdisc infrastructure, it provides a dedicated attachment point for BPF programs at the TC hooks. The design principles:

**BPF Link Semantics.** `bpf_program__attach_tcx()` creates a `BPF_LINK_TYPE_TCX` link. Like XDP and cgroup links, TCX links provide safe ownership: the link is tied to a file descriptor, auto-detaches when that fd closes, and cannot be removed by other applications.

**Explicit Ordering.** Rather than hoping two numeric priorities sort correctly, you specify order directly with `BPF_F_BEFORE` and `BPF_F_AFTER`. You can also use `BPF_F_REPLACE` to atomically swap a program. All operations accept an `expected_revision` field to prevent races during concurrent modifications.

**Chain Return Codes.** TCX defines return codes that make multi-program composition explicit:

| Return Code | Value | Behavior |
|-------------|-------|----------|
| `TCX_NEXT` | -1 | Continue to the next program in the chain |
| `TCX_PASS` | 0 | Accept the packet; terminate the chain |
| `TCX_DROP` | 2 | Drop the packet; terminate the chain |
| `TCX_REDIRECT` | 7 | Redirect the packet; terminate the chain |

Unknown return codes map to `TCX_NEXT` for forward compatibility.

**Coexistence with Classic TC.** TCX links can coexist with traditional `cls_bpf` filters on the same interface. The kernel runs TCX programs first, then falls through to classic `tcf_classify()` if any classic filters are present. This allows gradual migration from classic tc to TCX.

## The eBPF Program

Our BPF object contains two programs that demonstrate chained execution. Here is the complete kernel-side code:

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#ifndef TCX_PASS
#define TCX_PASS 0
#endif

char LICENSE[] SEC("license") = "GPL";

__u64 stats_hits;
__u64 classifier_hits;
__u32 last_len;
__u16 last_protocol;
__u32 last_ifindex;

SEC("tcx/ingress")
int tcx_stats(struct __sk_buff *skb)
{
	__sync_fetch_and_add(&stats_hits, 1);
	last_len = skb->len;
	last_protocol = bpf_ntohs(skb->protocol);
	last_ifindex = skb->ifindex;
	return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_classifier(struct __sk_buff *skb)
{
	__sync_fetch_and_add(&classifier_hits, 1);
	return TCX_PASS;
}
```

### Section Name: `SEC("tcx/ingress")`

The `SEC("tcx/ingress")` annotation tells libbpf this program attaches to the TCX ingress hook. Libbpf maps this section name to `BPF_PROG_TYPE_SCHED_CLS` with the TCX-specific attach type. The egress equivalent is `SEC("tcx/egress")`.

The older section names `SEC("tc")`, `SEC("classifier")`, and `SEC("action")` still work but are deprecated in favor of the `tcx/*` variants.

### The `__sk_buff` Context

Both programs receive a `struct __sk_buff *skb` parameter. This is the same socket buffer abstraction used by classic TC programs, XDP, and other networking BPF program types. It provides access to packet metadata:

- `skb->len`: packet length in bytes
- `skb->protocol`: EtherType in network byte order (hence `bpf_ntohs()`)
- `skb->ifindex`: the interface index where the packet arrived

For packet data access, you would use `bpf_skb_load_bytes()` or direct packet pointers, but this demo focuses on attachment mechanics rather than packet parsing.

### Global Variables as Counters

We use global variables (`stats_hits`, `classifier_hits`, etc.) rather than explicit BPF maps. The libbpf skeleton exposes these at `skel->bss->stats_hits`, simplifying user-space access. The hit counters use atomic additions because packets can arrive on multiple CPUs; the last-packet metadata remains a best-effort snapshot.

### Return Codes: `TCX_NEXT` vs `TCX_PASS`

The return code determines whether the chain continues:

- `tcx_stats` returns `TCX_NEXT`: "I have finished my work; pass the packet to the next program." Execution continues down the chain.
- `tcx_classifier` returns `TCX_PASS`: "Accept this packet." The chain terminates; no subsequent programs run.

Order matters. If `tcx_classifier` ran first, it would return `TCX_PASS` and `tcx_stats` would never execute. TCX makes you specify this order explicitly.

## User-Space Loader

The user-space code demonstrates the three key TCX operations: attaching programs, controlling their order, and querying the live chain state.

### Step 1: Attach the First Program

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier,
					 ifindex, NULL);
```

This attaches `tcx_classifier` to the TCX ingress hook on the specified interface. Passing `NULL` for options uses defaults: the program appends to the chain. The chain now contains one program.

### Step 2: Insert the Second Program Before the First

```c
LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats,
				    ifindex, &before_opts);
```

The `bpf_tcx_opts` structure specifies that `tcx_stats` should be inserted *before* `tcx_classifier`. The `.relative_fd` field identifies the reference point: the file descriptor of the already-attached classifier. After this call, the chain is: `tcx_stats` → `tcx_classifier`.

You could achieve the same ordering with `BPF_F_AFTER` and a different reference point. The key insight is that you express order directly, not through numeric priorities that might collide.

### Step 3: Query the Chain

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

After attachment, the loader queries the kernel for the live chain state. The result includes:

- **`revision`**: A monotonically increasing counter that increments on each chain modification. You can pass this as `expected_revision` when attaching to ensure the chain hasn't changed since you last observed it (useful for atomic multi-step updates).
- **`prog_ids[]`**: BPF program IDs in execution order.
- **`link_ids[]`**: Corresponding BPF link IDs.

This introspection capability is valuable for debugging multi-program pipelines and for tools that need to understand the current attachment state.

### Step 4: Stay Attached and Observe Traffic

After printing `READY` and the live chain, the loader stays attached. Generate traffic independently on the monitored interface, then press Ctrl-C (or use `--duration`) to stop. The loader detaches both links before reading a stable final snapshot:

```c
bpf_link__destroy(stats_link);
stats_link = NULL;
bpf_link__destroy(classifier_link);
classifier_link = NULL;

printf("COUNTERS stats_hits=%llu classifier_hits=%llu last_ifindex=%u "
       "last_protocol=0x%04x last_len=%u\n",
       (unsigned long long)skel->bss->stats_hits,
       (unsigned long long)skel->bss->classifier_hits,
       skel->bss->last_ifindex, skel->bss->last_protocol,
       skel->bss->last_len);
```

Matching hit counts show that `tcx_stats` ran first (recording metadata and returning `TCX_NEXT`) and `tcx_classifier` then ran and returned `TCX_PASS`. Keeping the process alive also demonstrates TCX ownership: closing the link file descriptors on exit automatically detaches the programs.

## Building and Running

### Requirements

- Linux 6.6 or later
- Kernel configuration: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_NET_XGRESS=y`
- Root privileges (for BPF and network interface access)
- Recent libbpf (1.2+ recommended)

### Build

```bash
cd bpf-developer-tutorial/src/50-tcx
make
```

### Run

```bash
sudo ./tcx_demo
```

The default monitors loopback until Ctrl-C. In another terminal, generate ordinary loopback traffic, for example `ping -c 1 127.0.0.1`. The monitor first prints readiness and chain order, then prints counters when it exits:

```text
READY interface=lo ifindex=1 duration=until-signal
TCX ingress chain revision: 2
  slot 0: prog_id=812 link_id=901
  slot 1: prog_id=811 link_id=900
^C
COUNTERS stats_hits=... classifier_hits=... last_ifindex=1 last_protocol=0x0800 last_len=...
```

**Reading the output:**

- **Revision 2**: The chain was modified twice: once when `tcx_classifier` attached (revision 1), and once when `tcx_stats` was inserted before it (revision 2).
- **Slot ordering**: Slot 0 is `tcx_stats` (the program we inserted with `BPF_F_BEFORE`); slot 1 is `tcx_classifier`.
- **Protocol 0x0800**: IPv4 traffic traversed the ingress chain.
- **Matching hit counts**: Both programs observed the same packets in the intended order.

### Options

- `-i, --interface IFACE`: Attach to a different interface (default: `lo`)
- `-d, --duration SEC`: Stop after a bounded interval; `0` waits for a signal (default: `0`)
- `-v, --verbose`: Enable libbpf debug output to see the underlying BPF syscall sequence

## Comparison with Lesson 20 (Classic TC)

[Lesson 20](../20-tc/README.md) teaches the classic TC path: creating a `clsact` qdisc, attaching a `SEC("tc")` program as a filter, and inspecting packets with `__sk_buff`. That lesson remains valuable because the **data-plane model** is identical: TCX programs use the same context structure and the same helpers for packet access.

TCX replaces the **control plane**:

| Aspect | Classic TC (Lesson 20) | TCX (Lesson 50) |
|--------|------------------------|-----------------|
| Attach mechanism | Netlink / `tc` CLI | `bpf_program__attach_tcx()` |
| Ownership | None; any process can delete any filter | BPF link tied to fd; auto-detaches on close |
| Ordering | Implicit numeric priorities | Explicit `BPF_F_BEFORE` / `BPF_F_AFTER` |
| Multi-program | Manual priority management | Built-in chain with revision tracking |
| Section name | `SEC("tc")` | `SEC("tcx/ingress")` / `SEC("tcx/egress")` |
| Kernel requirement | 4.1+ | 6.6+ |

For new libbpf-based networking tools, TCX is the recommended attachment method. Cilium has already migrated its dataplane from classic tc to TCX.

## Summary

TCX modernizes TC program attachment by replacing qdisc-based plumbing with BPF link semantics. In this tutorial, we attached two ingress programs, controlled their execution order with `BPF_F_BEFORE`, queried the live chain state, and verified correct execution by observing counters. TCX provides safe ownership, explicit ordering, revision-aware updates, and backward compatibility with classic TC, making it the foundation for composable, multi-program traffic control in modern eBPF applications.

For more eBPF tutorials, visit our repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or <https://eunomia.dev/tutorials/>.

## References

- [TCX kernel commit: fd-based tcx multi-prog infra with link support](https://lore.kernel.org/bpf/20230707172455.7634-3-daniel@iogearbox.net/)
- [BPF_PROG_TYPE_SCHED_CLS documentation](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
- [bpf_program__attach_tcx libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__attach_tcx/)
- [Cilium TCX & Netkit update (BPFConf 2024)](https://bpfconf.ebpf.io/bpfconf2024/bpfconf2024_material/tcx_netkit_update_and_global_sk_iter.pdf)
- [Generic multi-prog API, tcx links and meta device (BPFConf 2023)](http://oldvger.kernel.org/bpfconf2023_material/tcx_meta_netdev_borkmann.pdf)
- [Kernel BPF documentation](https://docs.kernel.org/bpf/)
