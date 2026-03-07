# eBPF Tutorial by Example 50: Composable Traffic Control with TCX Links

Ever tried attaching multiple BPF programs to the TC ingress path and got frustrated managing qdisc handles, filter priorities, and the `tc` CLI? Or needed one application's TC program to coexist safely with another's without accidentally overwriting it? Traditional `cls_bpf` attachment through `tc` works, but it inherits decades of queueing discipline plumbing that was never designed for the BPF-centric world. What if you could attach, order, and manage TC programs using the same link-based API that XDP and cgroup programs already enjoy?

This is what **TCX** (Traffic Control eXtension) solves. Introduced by Daniel Borkmann and merged in Linux 6.6, TCX provides a lightweight, fd-based multi-program attach infrastructure for the TC ingress and egress data path. Programs get BPF link semantics — safe ownership, auto-detachment on close, and explicit ordering through `BPF_F_BEFORE` / `BPF_F_AFTER` flags — without touching a single qdisc or filter priority.

In this tutorial, we'll attach two TCX ingress programs to the loopback interface, place one before the other, query the kernel's live chain state, and generate traffic to verify execution order.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## Introduction to TCX: Why Classic TC Attachment Needed a Rethink

### The Problem: Qdisc Plumbing and Unsafe Ownership

Classic `tc` BPF attachment (`cls_bpf`) was bolted onto the existing Traffic Control framework. To attach a BPF program, you first needed a `clsact` qdisc on the interface, then added a filter with a handle and priority. This worked fine for a single operator, but created real problems in cloud-native environments where multiple applications need to attach TC programs to the same interface:

1. **No ownership model**: A `tc filter del` from one application can accidentally remove another application's program. There's no protection against this because classic tc filters are identified by handle/priority, not by the process that created them.

2. **Priority conflicts**: Two applications might pick the same priority number. The second attachment silently replaces the first.

3. **Permanent attachment by default**: Classic tc filters persist until explicitly removed. If the application that attached a filter crashes without cleanup, the filter remains, potentially with stale program logic.

4. **CLI dependency**: Even with libbpf, the attachment model was tied to netlink — the same mechanism the `tc` CLI uses. This meant your BPF application was sharing a control plane with every other tc user on the system.

These issues became acute in projects like Cilium, where the BPF dataplane needs to coexist with third-party CNI plugins, observability agents, and security tools that all want to hook into TC.

### The Solution: Link-Based Multi-Program Management

TCX takes a fundamentally different approach. Instead of piggybacking on qdisc infrastructure, it provides a dedicated, qdisc-less extension point for BPF programs at the TC ingress and egress hooks. The key design principles:

**BPF Link Semantics**: `bpf_program__attach_tcx()` creates a `BPF_LINK_TYPE_TCX` link. Like XDP links and cgroup links, TCX links give you safe ownership — the link is pinned to the file descriptor, auto-detaches when the fd is closed, and cannot be accidentally overridden by another application.

**Explicit Ordering**: Instead of implicit priority numbers, you place programs relative to each other using `BPF_F_BEFORE` and `BPF_F_AFTER`. You can also use `BPF_F_REPLACE` to atomically swap a specific program. All operations support an `expected_revision` field that prevents race conditions during concurrent modifications.

**Chain Return Codes**: TCX defines simplified return codes that make multi-program composition explicit:

| Return Code | Value | Meaning |
|-------------|-------|---------|
| `TCX_NEXT` | -1 | Non-terminating; pass the packet to the next program in the chain |
| `TCX_PASS` | 0 | Accept the packet and terminate the chain |
| `TCX_DROP` | 2 | Drop the packet and terminate the chain |
| `TCX_REDIRECT` | 7 | Redirect the packet and terminate the chain |

Unknown return codes are mapped to `TCX_NEXT` for forward compatibility.

**Coexistence with Classic TC**: TCX links can coexist with traditional `cls_bpf` filters on the same interface. The kernel runs TCX programs first, then falls through to classic `tcf_classify()` if present. This allows gradual migration from classic tc to TCX without a disruptive cutover.

## Writing the eBPF Program

Our BPF object contains two programs that demonstrate chain composition. Here is the complete source:

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
	stats_hits++;
	last_len = skb->len;
	last_protocol = bpf_ntohs(skb->protocol);
	last_ifindex = skb->ifindex;
	return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_classifier(struct __sk_buff *skb)
{
	classifier_hits++;
	return TCX_PASS;
}
```

Let's walk through this step by step.

### Section Names: `SEC("tcx/ingress")`

The `SEC("tcx/ingress")` annotation tells libbpf that this program should be attached to the TCX ingress hook rather than the classic TC classifier. This is not just a naming convention — libbpf maps this section name to `BPF_PROG_TYPE_SCHED_CLS` with the appropriate attach type for TCX. The corresponding egress variant is `SEC("tcx/egress")`.

Note that `SEC("tc")`, `SEC("classifier")`, and `SEC("action")` are now considered deprecated by libbpf in favor of the `tcx/*` section names.

### Global Variables as Counters

Instead of using a BPF map for counters, we use global variables (`stats_hits`, `classifier_hits`, `last_len`, etc.). The libbpf skeleton exposes these through `skel->bss->stats_hits`, which makes the user-space code simpler. This is fine for a single-CPU demo; for production use, you would want per-CPU maps to avoid data races.

### Return Codes: `TCX_NEXT` vs `TCX_PASS`

This is the heart of TCX composition:

- `tcx_stats` returns `TCX_NEXT`, which means "I've done my work, now pass the packet to the next program in the chain." The chain continues executing.
- `tcx_classifier` returns `TCX_PASS`, which is a terminal verdict — the packet is accepted and no further programs in the chain run.

If we had placed `tcx_classifier` *before* `tcx_stats` in the chain, `tcx_stats` would never execute because `TCX_PASS` terminates the chain. Ordering matters, and TCX makes it explicit.

## User-Space Loader: Attaching and Querying the Chain

The user-space code demonstrates three key TCX operations: attaching programs, ordering them relative to each other, and querying the live chain.

### Step 1: Attach the First Program

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier,
					 ifindex, NULL);
```

This attaches `tcx_classifier` to the TCX ingress hook on the specified interface. Passing `NULL` for options means "use defaults" — the program gets appended to the chain. At this point, the chain has one program.

### Step 2: Insert the Second Program *Before* the First

```c
LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats,
				    ifindex, &before_opts);
```

The `bpf_tcx_opts` structure tells the kernel to insert `tcx_stats` *before* `tcx_classifier` in the chain. The `.relative_fd` field identifies the reference point — the fd of the already-attached classifier program. After this, the chain is: `tcx_stats` → `tcx_classifier`.

You could equivalently use `BPF_F_AFTER` with a different reference to achieve the same ordering. The important point is that you express the desired order directly, rather than hoping that two numeric priorities sort correctly.

### Step 3: Query the Chain

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

After attachment, the loader queries the kernel for the live chain state. The returned data includes:

- **`revision`**: A monotonically increasing counter that changes on every chain modification. This is the value you would pass as `expected_revision` if you wanted to perform atomic updates.
- **`prog_ids[]`**: The BPF program IDs in chain order.
- **`link_ids[]`**: The corresponding BPF link IDs.

This allows any observer to determine exactly which programs are attached and in what order, which is invaluable for debugging multi-program pipelines.

### Step 4: Generate Traffic and Read Counters

The loader sends a UDP packet to `127.0.0.1` (port 9, discard) to trigger the chain, waits briefly, then reads the global variables to verify both programs executed:

```c
printf("  tcx_stats hits      : %llu\n",
       (unsigned long long)skel->bss->stats_hits);
printf("  tcx_classifier hits : %llu\n",
       (unsigned long long)skel->bss->classifier_hits);
```

If both counters are 1, the chain worked as expected: `tcx_stats` ran first (recording metadata and returning `TCX_NEXT`), then `tcx_classifier` ran second (counting the packet and returning `TCX_PASS`).

## Compilation and Execution

This example requires Linux 6.6+ with TCX support and a recent libbpf.

```bash
cd bpf-developer-tutorial/src/50-tcx
make
sudo ./tcx_demo -i lo
```

Expected output:

```text
Attached TCX programs to lo (ifindex=1)
TCX ingress chain revision: 3
  slot 0: prog_id=812 link_id=901
  slot 1: prog_id=811 link_id=900

Counters:
  tcx_stats hits      : 1
  tcx_classifier hits : 1
  last ifindex        : 1
  last protocol       : 0x0800
  last length         : 46
```

The revision is 3 because the chain was modified twice: once when `tcx_classifier` was attached (revision went from 0 to 1), and once when `tcx_stats` was inserted before it (revision went to 2). The query itself increments the revision to 3.

If you want to inspect the attach behavior without traffic, add `-n`:

```bash
sudo ./tcx_demo -i lo -n
```

Use `-v` to enable libbpf debug output, which is helpful for seeing the low-level BPF syscall sequence.

## How This Differs from Lesson 20 (Classic TC)

[Lesson 20-tc](../20-tc/README.md) teaches the classic TC data path: creating a `clsact` qdisc, attaching a `SEC("tc")` program as a filter, and using `__sk_buff` for packet inspection. That lesson is still valuable because the **packet processing model** is identical — TCX programs receive the same `__sk_buff` context and use the same helpers for packet parsing.

What TCX replaces is the **control plane**:

| Aspect | Classic TC (Lesson 20) | TCX (Lesson 50) |
|--------|----------------------|-----------------|
| Attach mechanism | Netlink / `tc` CLI | `bpf_program__attach_tcx()` |
| Ownership | None; anyone can `tc filter del` | BPF link; auto-detaches on fd close |
| Ordering | Implicit priority numbers | Explicit `BPF_F_BEFORE` / `BPF_F_AFTER` |
| Multi-program | Manual priority management | Built-in chain with revision tracking |
| Section name | `SEC("tc")` | `SEC("tcx/ingress")` / `SEC("tcx/egress")` |
| Kernel requirement | Any modern kernel | Linux 6.6+ |

If you are building new libbpf-based networking tools, TCX is the recommended interface. Cilium has already migrated from classic tc to TCX for its dataplane.

## Summary

In this tutorial, we learned how TCX modernizes TC program attachment by replacing qdisc-based plumbing with BPF link semantics. We attached two ingress programs, controlled their execution order with `BPF_F_BEFORE`, queried the live chain with `bpf_prog_query_opts()`, and verified that both programs executed in the correct order. TCX provides safe ownership, explicit ordering, revision-aware updates, and coexistence with classic TC — making it the foundation for composable, multi-program traffic control in modern eBPF applications.

If you'd like to learn more about eBPF, visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

## References

- [TCX kernel commit: fd-based tcx multi-prog infra with link support](https://lore.kernel.org/bpf/20230707172455.7634-3-daniel@iogearbox.net/)
- [BPF_PROG_TYPE_SCHED_CLS documentation](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
- [bpf_program__attach_tcx libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__attach_tcx/)
- [Cilium TCX & Netkit update (BPFConf 2024)](https://bpfconf.ebpf.io/bpfconf2024/bpfconf2024_material/tcx_netkit_update_and_global_sk_iter.pdf)
- [Generic multi-prog API, tcx links and meta device (BPFConf 2023)](http://oldvger.kernel.org/bpfconf2023_material/tcx_meta_netdev_borkmann.pdf)
- <https://docs.kernel.org/bpf/>
