# eBPF Tutorial: BPF Token for Delegated Program Loading

Many eBPF tutorials assume one operator with full privilege. Real systems are messier: platform teams want to expose a controlled subset of BPF to tenants, service owners, or CI jobs without handing out broad `CAP_BPF`, `CAP_SYS_ADMIN`, or unrestricted access to every program type. **BPF token** is the kernel mechanism that makes this delegation model possible.

This tutorial focuses on the practical libbpf path. Instead of manually issuing `BPF_TOKEN_CREATE` and threading token FDs through every syscall, we'll use libbpf's `bpf_token_path` support to derive a token from a delegated bpffs mount, then load and attach a simple XDP program through that token-backed workflow.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_token>

## What a BPF Token Actually Does

A BPF token is an FD that carries a *delegated permission set* derived from a bpffs mount. That permission set is constrained along four axes:

- allowed BPF commands, such as `prog_load`, `map_create`, `btf_load`, or `link_create`;
- allowed map types;
- allowed program types;
- allowed attach types.

The important point is that the token is narrower than "all BPF privileges". It lets you define a precise slice of BPF functionality and pass only that slice to another loader.

For low-level userspace, the underlying kernel entry point is `bpf_token_create()`. For libbpf-based applications, the ergonomic path is `bpf_object_open_opts.bpf_token_path`, or the equivalent `LIBBPF_BPF_TOKEN_PATH` environment variable.

## The Minimal Demo

For an end-to-end delegated attach demo, this repository uses a tiny XDP program on loopback. It keeps the BPF side intentionally small and uses an explicit `BPF_MAP_TYPE_ARRAY`, which matches the delegated map policy cleanly:

```c
struct token_stats {
	__u64 packets;
	__u32 last_ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct token_stats);
} stats_map SEC(".maps");

SEC("xdp")
int handle_packet(struct xdp_md *ctx)
{
	__u32 key = 0;
	struct token_stats *stats = bpf_map_lookup_elem(&stats_map, &key);

	if (!stats)
		return 0;

	stats->packets++;
	stats->last_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}
```

The user-space loader accepts a delegated bpffs path and passes it to libbpf:

```c
struct bpf_object_open_opts open_opts = {};

open_opts.sz = sizeof(open_opts);
open_opts.bpf_token_path = env.token_path;

skel = token_trace_bpf__open_opts(&open_opts);
```

From that point on, libbpf will derive a token from the provided bpffs mount and use it automatically for map creation, BTF load, program load, and attach operations that accept a token-aware syscall path.

## Preparing a Delegated bpffs Mount

You need a bpffs instance that explicitly delegates the command, map, program, and attach types you want to allow. One subtle but important kernel rule is easy to miss: **BPF token creation must happen in the same non-`init_user_ns` user namespace as the bpffs instance**. So a host-namespace bpffs mount is useful for inspection, but it is not enough for an end-to-end token demo by itself.

This repository still includes a small helper script to show the mount syntax:

```bash
cd bpf-developer-tutorial/src/features/bpf_token
bash setup_token_bpffs.sh /tmp/bpf-token
```

The script mounts bpffs with the following delegation policy:

```text
delegate_cmds=prog_load:map_create:btf_load:link_create
delegate_maps=array
delegate_progs=xdp:socket_filter
delegate_attachs=any
```

The extra `socket_filter` allowance is not for the final XDP program itself. It is there because current libbpf still performs a trivial program-load probe before loading the real object, and that probe uses a generic program type. `delegate_attachs=any` is for the same reason: current token checks validate attach-type bits even for that probe path.

If you only want to inspect the delegated policy, the script plus `bpftool token list` is enough. If you want a working load-and-attach demo, use the wrapper below instead.

## Build and Run

Build the example:

```bash
cd bpf-developer-tutorial/src/features/bpf_token
make
```

For an end-to-end demo that really creates a token and attaches the XDP program, run:

```bash
sudo ./token_userns_demo
```

Example output:

```text
token path     : /proc/self/fd/5
interface      : lo (ifindex=1)
packets before : 0
packets after  : 1
delta          : 1
last ifindex   : 1
```

`token_userns_demo` does the awkward part for you:

- it creates a child process in a fresh user, mount, and network namespace;
- the privileged parent configures delegated bpffs options on the child's bpffs fs context;
- the child brings `lo` up, materializes a detached bpffs mount, passes `/proc/self/fd/<mnt_fd>` to `token_trace`, and `libbpf` derives the token from there.

If you already manage your own delegated bpffs instance inside the correct user namespace, you can still run the loader directly:

```bash
./token_trace -t /proc/self/fd/<mnt-fd> -i lo
```

## Why This Is Representative

This example is intentionally small, but the pattern scales:

- platform engineers create a constrained bpffs mount;
- libbpf applications derive a token from that mount;
- program loading and attaching happens through delegated capabilities instead of broad global privilege.

That makes BPF token more than a niche syscall. It is the kernel's answer to multi-tenant and delegated BPF operations.

## References

- <https://docs.kernel.org/bpf/>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/bpf.h>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.h>
