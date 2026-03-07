# eBPF Tutorial: TCX and Link-Based Traffic Control Chains

Classic `tc` BPF hooks are powerful, but they still inherit some old operational baggage: qdisc management through the `tc` CLI, filter priorities, and an awkward split between program attach and program ordering. **TCX** modernizes that model by turning TC attachments into first-class BPF links. You load a `tcx/ingress` or `tcx/egress` program, attach it with `bpf_program__attach_tcx()`, and manage the chain using link semantics instead of qdisc handles.

This tutorial adds a minimal but complete TCX example to complement the classic [lesson 20-tc](../20-tc/README.md). We'll attach two ingress programs to loopback, place one *before* the other with `BPF_F_BEFORE`, query the resulting chain revision, and generate traffic to prove that both programs ran in the expected order.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## Why TCX Exists

Traditional `tc` is tied to qdisc and filter plumbing. Even in direct-action mode, users still have to think in terms of handles, priorities, and `clsact`. TCX keeps the packet path and `__sk_buff` programming model, but replaces the old attach surface with a link-based API:

- `SEC("tcx/ingress")` and `SEC("tcx/egress")` declare the attach point in the ELF itself.
- `bpf_program__attach_tcx()` creates a `BPF_LINK_TYPE_TCX` link, which behaves like other modern BPF links.
- `struct bpf_tcx_opts` lets you insert a program relative to another program or link.
- `bpf_prog_query_opts()` exposes revision and chain order so you can reason about multi-program pipelines.

The important shift is conceptual: TCX is not just "another tc section name". It turns TC attachment into a composable BPF link workflow.

## The Example

Our BPF object contains two programs:

- `tcx_stats`: records metadata from the last packet and returns `TCX_NEXT`, allowing the chain to continue.
- `tcx_classifier`: counts packets and returns `TCX_PASS`, terminating the chain with a pass action.

The user-space loader attaches `tcx_classifier` first, then inserts `tcx_stats` *before* it:

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier, ifindex, NULL);

LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats, ifindex, &before_opts);
```

This is the key TCX pattern: attach one program, then place another relative to it without invoking the `tc` CLI or touching qdisc priority knobs.

After attaching, the loader queries the ingress chain:

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

The returned `revision`, `prog_ids`, and `link_ids` show the live chain as seen by the kernel.

## Build and Run

This example expects a kernel and libbpf with TCX support.

```bash
cd bpf-developer-tutorial/src/50-tcx
make
sudo ./tcx_demo -i lo
```

Running the loader requires a privileged environment with the usual TC/BPF capabilities, typically `root` or a process holding `CAP_BPF` and `CAP_NET_ADMIN`.

The program will attach both ingress programs to loopback and send a UDP packet to `127.0.0.1` automatically.

Example output:

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

If you want to inspect attach behavior without generating traffic, use `-n`:

```bash
sudo ./tcx_demo -i lo -n
```

## How This Differs from Lesson 20

[lesson 20-tc](../20-tc/README.md) is still useful because it teaches the original TC data path and direct-action programming style. TCX does **not** replace `__sk_buff`, return codes, or packet parsing patterns. What it replaces is the operational control plane:

- `20-tc` focuses on classic `tc` integration and qdisc-based attachment.
- `50-tcx` focuses on link-based attachment, chain ordering, and revision-aware management.

If you are building new libbpf-based tooling, TCX is the more representative interface to learn.

## References

- <https://docs.kernel.org/bpf/>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.h>
- <https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf>
