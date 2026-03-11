# eBPF Tutorial by Example: BPF Token for Delegated Privilege and Secure Program Loading

Ever needed to let a container or CI job load an eBPF program without giving it full `CAP_BPF` or `CAP_SYS_ADMIN`? Or wanted to expose XDP packet processing to a tenant workload while ensuring it can only create the specific map types and program types you've approved? Before BPF token, the answer was binary: either you had the capabilities to do *everything* in BPF, or you could do *nothing*. There was no middle ground.

This is what **BPF Token** solves. Introduced by Andrii Nakryiko and merged in Linux 6.9, BPF token is a delegation mechanism that lets a privileged process (like a container runtime or systemd) create a precisely scoped permission set for BPF operations, then hand it to an unprivileged process through a bpffs mount. The unprivileged process can load programs, create maps, and attach hooks, but only the types that were explicitly allowed. No broad capabilities required.

In this tutorial, we'll set up a delegated bpffs mount in a user namespace, derive a BPF token from it, and use libbpf to load and attach a minimal XDP program, all from a process that has zero BPF capabilities of its own.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_token>

## Introduction to BPF Token: Solving the Privilege Problem

### The Problem: All-or-Nothing BPF Capabilities

Traditional eBPF requires `CAP_BPF` for program loading and map creation, plus additional capabilities like `CAP_PERFMON` for tracing, `CAP_NET_ADMIN` for networking hooks, and `CAP_SYS_ADMIN` for certain advanced operations. These capabilities are inherently **system-wide**: you cannot namespace or sandbox `CAP_BPF`. As the kernel documentation explains, this is by design: BPF tracing helpers like `bpf_probe_read_kernel()` can access arbitrary kernel memory, which fundamentally cannot be scoped to a single namespace.

This creates a real problem in multi-tenant environments:

1. **Container isolation**: A Kubernetes pod that needs to run a simple XDP program must be given `CAP_BPF` + `CAP_NET_ADMIN`, which also grants it the ability to load *any* BPF program type and create *any* map type. There's no way to say "you can load XDP programs but not kprobes."

2. **CI/CD pipelines**: A build job that tests an eBPF-based observability tool needs root-equivalent capabilities to load programs, even though the test only exercises a specific, well-known program type.

3. **Third-party integrations**: A service mesh sidecar that attaches sockops programs needs capabilities that also grant it the ability to trace every process on the host.

The result is that organizations either give broad BPF capabilities (weakening their security posture) or prohibit BPF entirely in unprivileged contexts (limiting the technology's adoption).

### The Solution: Scoped Delegation Through bpffs

BPF token takes a different approach. Instead of trying to namespace capabilities (which is fundamentally unsafe for BPF), it introduces an explicit delegation model:

1. A **privileged process** (container runtime, init system, platform daemon) creates a bpffs instance with specific delegation options that define exactly which BPF operations are allowed.
2. The privileged process passes this bpffs mount to an **unprivileged process** (container, CI job, tenant workload).
3. The unprivileged process derives a **BPF token** from the bpffs mount. The token is a file descriptor that carries the delegated permission set.
4. When the unprivileged process makes `bpf()` syscalls (through libbpf or directly), it passes the token fd. The kernel checks permissions against the token instead of against the process's capabilities.

The token is scoped along four independent axes:

| Delegation Option | What It Controls | Example |
|-------------------|-----------------|---------|
| `delegate_cmds` | Which `bpf()` commands are allowed | `prog_load:map_create:btf_load:link_create` |
| `delegate_maps` | Which map types can be created | `array:hash:ringbuf` |
| `delegate_progs` | Which program types can be loaded | `xdp:socket_filter` |
| `delegate_attachs` | Which attach types are allowed | `xdp:cgroup_inet_ingress` or `any` |

Each axis is a bitmask. If a bit isn't set, the corresponding operation is denied even if the token is present. This gives platform engineers fine-grained control: you can allow a container to load XDP programs with array maps but deny it access to kprobes, perf events, or hash-of-maps.

### The User Namespace Constraint

One critical design decision: **a BPF token must be created inside the same user namespace as the bpffs instance, and that user namespace must not be `init_user_ns`**. This is intentional. It means:

- A host-namespace bpffs (the one at `/sys/fs/bpf`) does **not** produce usable tokens. Tokens only work when the bpffs is associated with a non-init user namespace.
- The privileged parent configures the bpffs before passing it to the child, but the child (in its own user namespace) is the one that creates and uses the token.
- This design prevents a process with an existing token from using it to escalate privileges outside its namespace boundary.

### How libbpf Makes It Transparent

For applications built with libbpf (which is most of them), token usage is nearly transparent. You have three options:

1. **Explicit path**: Set `bpf_object_open_opts.bpf_token_path` when opening the BPF object. libbpf will derive the token from the specified bpffs mount.
2. **Environment variable**: Set `LIBBPF_BPF_TOKEN_PATH` to point to the bpffs mount. libbpf picks it up automatically.
3. **Default path**: If the default `/sys/fs/bpf` is a delegated bpffs in the current user namespace, libbpf uses it implicitly.

Once the token is derived, libbpf passes it to every relevant syscall (`BPF_MAP_CREATE`, `BPF_BTF_LOAD`, `BPF_PROG_LOAD`, and `BPF_LINK_CREATE`) without any source-code changes in the BPF application.

## Writing the eBPF Program

The BPF side of this demo is intentionally minimal: a tiny XDP program on loopback. This keeps the focus on the token workflow. Here's the complete source:

```c
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

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
	struct token_stats *stats;
	__u32 key = 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return 0;

	stats->packets++;
	stats->last_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}
```

A few design choices to note:

**`BPF_MAP_TYPE_ARRAY`** was chosen because the delegation policy explicitly allows `array` maps. If we had used a hash map instead, loading would fail because the token doesn't grant `hash` map creation permission. This is the token model in action; even trivial program changes can be caught by the delegation policy.

**`SEC("xdp")`** matches the `delegate_progs=xdp` policy. If you changed this to `SEC("kprobe/...")`, the kernel would reject it at load time with an `EPERM` because kprobe isn't in the allowed program types.

**`XDP_PASS`** simply lets every packet through. The program's only purpose is to prove that a token-backed load and attach succeeded. In production, you'd replace this with real packet-processing logic.

## User-Space Loader: Token-Backed Loading

The `token_trace.c` loader is a standard libbpf skeleton program with one key addition: it passes a `bpf_token_path`:

```c
struct bpf_object_open_opts open_opts = {};

open_opts.sz = sizeof(open_opts);
open_opts.bpf_token_path = env.token_path;

skel = token_trace_bpf__open_opts(&open_opts);
```

From this point on, libbpf takes over. When it calls `bpf(BPF_MAP_CREATE)` to create `stats_map`, it includes the token fd. When it calls `bpf(BPF_PROG_LOAD)` for the XDP program, it includes the token fd. When it calls `bpf(BPF_LINK_CREATE)` to attach to the interface, it includes the token fd.

The rest of the loader is straightforward:

```c
err = token_trace_bpf__load(skel);    // token used for map_create + prog_load
link = bpf_program__attach_xdp(skel->progs.handle_packet, ifindex);  // token used for link_create
```

After attaching, the loader reads the map before and after generating a test packet to verify the program executed:

```c
err = bpf_map_lookup_elem(map_fd, &key, &before);
// ... generate UDP packet to 127.0.0.1 ...
err = bpf_map_lookup_elem(map_fd, &key, &after);
printf("delta          : %llu\n", after.packets - before.packets);
```

If the delta is 1, the XDP program was successfully loaded and attached using only delegated capabilities.

## The Namespace Orchestrator: `token_userns_demo`

Because BPF token requires a non-init user namespace, running a bare `token_trace -t /sys/fs/bpf` on the host won't work. The `token_userns_demo.c` wrapper automates the complex namespace choreography. Here's the full sequence:

### Step 1: Fork and Create Namespaces

```
parent (root, init_user_ns)          child (unprivileged, new userns)
         │                                        │
         │   fork()                               │
         ├────────────────────────────────────────>│
         │                                        │
         │                            unshare(CLONE_NEWUSER)
         │                            unshare(CLONE_NEWNS | CLONE_NEWNET)
```

The child creates a new user namespace (where it maps itself to uid/gid 0), a new mount namespace (so bpffs mounts are private), and a new network namespace (so `lo` is a fresh interface it can attach to).

### Step 2: Create bpffs and Configure Delegation

```
parent (root, init_user_ns)          child (new userns)
         │                                        │
         │                            fs_fd = fsopen("bpf", 0)
         │   <───── send fs_fd via SCM_RIGHTS ────│
         │                                        │
    fsconfig(fs_fd, "delegate_cmds", ...)         │  (waiting for ack)
    fsconfig(fs_fd, "delegate_maps", "array")     │
    fsconfig(fs_fd, "delegate_progs", "xdp:...")  │
    fsconfig(fs_fd, "delegate_attachs", "any")    │
    fsconfig(fs_fd, FSCONFIG_CMD_CREATE)          │
         │                                        │
         │   ───────── send ack ─────────────────>│
```

The child calls `fsopen("bpf", 0)` to create a bpffs filesystem context in its user namespace, then sends the file descriptor to the parent via a Unix socket (`SCM_RIGHTS`). The parent, running as root in the init namespace, configures the delegation policy with `fsconfig()`, then materializes the filesystem with `FSCONFIG_CMD_CREATE`.

This two-step dance is necessary because: (a) the bpffs must be created in the child's user namespace (for the token to be valid there), but (b) only the privileged parent can set delegation options (because those options grant BPF capabilities).

### Step 3: Mount and Load

```
child (new userns)
         │
    mnt_fd = fsmount(fs_fd, 0, 0)
    token_path = "/proc/self/fd/<mnt_fd>"
    set_loopback_up()
    exec("./token_trace", "-t", token_path, "-i", "lo")
```

The child materializes the bpffs as a detached mount (no mount point needed, since `/proc/self/fd/<mnt_fd>` gives a path), brings the loopback interface up in its network namespace, and `exec`s `token_trace` with the bpffs path. From `token_trace`'s perspective, it's just opening a BPF object with a token path. It doesn't know or care about the namespace setup.

## Preparing a bpffs Mount Manually

If you want to experiment with the mount syntax outside the demo wrapper, the repository includes a helper script:

```bash
cd bpf-developer-tutorial/src/features/bpf_token
bash setup_token_bpffs.sh /tmp/bpf-token
```

This mounts bpffs at `/tmp/bpf-token` with:

```text
delegate_cmds=prog_load:map_create:btf_load:link_create
delegate_maps=array
delegate_progs=xdp:socket_filter
delegate_attachs=any
```

**Why `socket_filter`?** libbpf performs a trivial program-load probe before loading the real BPF object. This probe uses a generic `BPF_PROG_TYPE_SOCKET_FILTER` program to detect kernel feature support. Without `socket_filter` in the delegation policy, the probe fails and libbpf refuses to proceed.

**Why `delegate_attachs=any`?** The same libbpf probe path also triggers attach-type validation in the kernel's token checking code. Using `any` avoids having to enumerate every possible attach type for probe compatibility.

Note that a host-namespace mount like this is useful for inspecting the delegation policy (e.g., with `bpftool token list`), but won't produce working tokens unless the `bpf(BPF_TOKEN_CREATE)` syscall comes from a matching non-init user namespace.

## Compilation and Execution

Build all binaries:

```bash
cd bpf-developer-tutorial/src/features/bpf_token
make
```

Run the end-to-end demo:

```bash
sudo ./token_userns_demo
```

Expected output:

```text
token path     : /proc/self/fd/5
interface      : lo (ifindex=1)
packets before : 0
packets after  : 1
delta          : 1
last ifindex   : 1
```

The `delta: 1` confirms that the XDP program was successfully loaded and attached using a BPF token, with no `CAP_BPF` or `CAP_SYS_ADMIN` in the child process.

Add `-v` for verbose libbpf output to see the token being created and used:

```bash
sudo ./token_userns_demo -v
```

If you already manage your own delegated bpffs in a user namespace, you can run the loader directly:

```bash
./token_trace -t /proc/self/fd/<mnt-fd> -i lo
```

## Real-World Applications

While this tutorial uses a minimal XDP program, the BPF token pattern scales to production scenarios:

- **Container runtimes** (LXD, Docker, Kubernetes): Mount a delegated bpffs into a container with only the program and map types the workload needs. LXD already supports this through its `security.delegate_bpf` option.

- **CI/CD testing**: Give build jobs the ability to load and test specific eBPF programs without granting them host-level capabilities. The delegation policy acts as an allowlist for BPF operations.

- **Multi-tenant BPF platforms**: A platform daemon creates per-tenant bpffs mounts with different delegation policies. One tenant might be allowed XDP + array maps, while another might get tracepoint + ringbuf access.

- **LSM integration**: Because BPF tokens integrate with Linux Security Modules, you can combine token delegation with SELinux or AppArmor policies for defense-in-depth. Each token gets its own security context that LSM hooks can inspect.

## Summary

In this tutorial, we learned how BPF token provides a delegation model for eBPF privilege that goes beyond the binary "all or nothing" of Linux capabilities. We walked through the complete flow: a privileged parent configures a bpffs instance with specific delegation options, an unprivileged child in a user namespace derives a token from that bpffs, and libbpf transparently uses the token for map creation, program loading, and attachment. The result is a minimal XDP program running in an unprivileged context, something that was impossible before Linux 6.9.

BPF token is not a niche feature. It represents the kernel's answer to a fundamental question in the eBPF ecosystem: how do you safely share BPF capabilities in a multi-tenant world without granting unconstrained access to the BPF subsystem?

If you'd like to learn more about eBPF, visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials.

## References

- [BPF Token concept documentation](https://docs.ebpf.io/linux/concepts/token/)
- [BPF token kernel patch series (Andrii Nakryiko)](https://lore.kernel.org/bpf/20240103222034.2582628-1-andrii@kernel.org/T/)
- [BPF token LWN article](https://lwn.net/Articles/959350/)
- [Finer-grained BPF tokens LWN discussion](https://lwn.net/Articles/947173/)
- [Privilege delegation using BPF Token (LXD documentation)](https://documentation.ubuntu.com/lxd/latest/explanation/bpf/)
- [bpf_token_create() libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_token_create/)
- <https://docs.kernel.org/bpf/>
