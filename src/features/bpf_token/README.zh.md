# eBPF 入门实践教程：BPF Token，安全的委托式权限与程序加载

你是否需要让容器或 CI 任务加载一个 eBPF 程序，但又不想给它完整的 `CAP_BPF` 或 `CAP_SYS_ADMIN`？或者你想把 XDP 数据包处理能力开放给租户工作负载，同时确保它只能创建你批准过的 map 类型和 program 类型？在 BPF token 出现之前，答案是二元的：要么你有能力在 BPF 中做*一切*，要么你*什么都做不了*。没有中间地带。

这就是 **BPF Token** 要解决的问题。BPF token 由 Andrii Nakryiko 开发，于 Linux 6.9 合入内核，它是一种委托机制，让特权进程（如容器运行时或 systemd）创建一组精确限定范围的 BPF 操作许可集合，然后通过 bpffs 挂载传递给非特权进程。非特权进程可以加载程序、创建 map、挂载 hook，但只能使用被显式允许的类型。不需要任何宽泛的 capability。

本教程将在 user namespace 中设置一个带委托策略的 bpffs 挂载，从中派生 BPF token，然后用 libbpf 加载并挂载一个最小的 XDP 程序。所有操作来自一个本身没有任何 BPF capability 的进程。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_token>

## 背景：解决 BPF 权限问题

### 问题：全有或全无的 BPF Capability

传统 eBPF 需要 `CAP_BPF` 来加载程序和创建 map，还需要 `CAP_PERFMON`（用于 tracing）、`CAP_NET_ADMIN`（用于网络 hook）、`CAP_SYS_ADMIN`（用于某些高级操作）等额外的 capability。这些 capability 本质上是**系统级**的，你无法对 `CAP_BPF` 做 namespace 隔离或沙箱化。内核文档解释了原因：BPF tracing helper（如 `bpf_probe_read_kernel()`）可以访问任意内核内存，这在根本上无法被限定到单个 namespace 中。

这在多租户环境中造成了实际问题：

1. **容器隔离**：一个只需要运行简单 XDP 程序的 Kubernetes Pod 必须被赋予 `CAP_BPF` + `CAP_NET_ADMIN`，但这也同时赋予了它加载*任意* BPF 程序类型和创建*任意* map 类型的能力。你没办法说"你可以加载 XDP 程序但不能加载 kprobe"。

2. **CI/CD 流水线**：一个测试 eBPF 可观测工具的构建任务需要 root 级别的 capability 来加载程序，即使测试只涉及一个特定的、已知的程序类型。

3. **第三方集成**：一个 service mesh sidecar 需要挂载 sockops 程序的 capability，但这些 capability 同时也赋予了它 trace 主机上每个进程的能力。

结果就是：组织要么给出宽泛的 BPF capability（削弱安全态势），要么在非特权环境中完全禁止 BPF（限制了该技术的采用）。

### 解决方案：通过 bpffs 进行精确委托

BPF token 采取了不同的思路。它没有尝试对 capability 做 namespace 化（对 BPF 来说这根本不安全），而是引入了显式的委托模型：

1. **特权进程**（容器运行时、init 系统、平台守护进程）创建一个带有特定委托选项的 bpffs 实例，精确定义允许哪些 BPF 操作。
2. 特权进程将这个 bpffs 挂载传递给**非特权进程**（容器、CI 任务、租户工作负载）。
3. 非特权进程从 bpffs 挂载中派生**BPF token**。token 是一个文件描述符，承载着委托的权限集合。
4. 当非特权进程发起 `bpf()` 系统调用时（通过 libbpf 或直接调用），传入 token fd。内核根据 token 而不是进程的 capability 来检查权限。

token 沿四个独立轴进行限定：

| 委托选项 | 控制内容 | 示例 |
|----------|---------|------|
| `delegate_cmds` | 允许哪些 `bpf()` 命令 | `prog_load:map_create:btf_load:link_create` |
| `delegate_maps` | 允许创建哪些 map 类型 | `array:hash:ringbuf` |
| `delegate_progs` | 允许加载哪些程序类型 | `xdp:socket_filter` |
| `delegate_attachs` | 允许哪些 attach 类型 | `xdp:cgroup_inet_ingress` 或 `any` |

每个轴是一个位掩码。如果某个位未设置，对应的操作即使有 token 也会被拒绝。这给了平台工程师细粒度的控制：你可以允许容器加载带 array map 的 XDP 程序，但拒绝它访问 kprobe、perf event 或 hash-of-maps。

### User Namespace 约束

一个关键的设计决定：**BPF token 必须在和 bpffs 实例相同的 user namespace 中创建，且该 user namespace 不能是 `init_user_ns`**。这是有意为之。这意味着：

- 主机 namespace 下的 bpffs（`/sys/fs/bpf`）**不能**产生可用的 token。token 只在 bpffs 关联到非 init 的 user namespace 时才能工作。
- 特权父进程在将 bpffs 传给子进程之前配置好委托策略，但子进程（在自己的 user namespace 中）才是创建和使用 token 的一方。
- 这个设计防止持有 token 的进程利用它在 namespace 边界之外提升权限。

### libbpf 如何让它变得透明

对于基于 libbpf 构建的应用（大多数 eBPF 应用都是），token 的使用几乎是透明的。你有三种选择：

1. **显式路径**：在打开 BPF 对象时设置 `bpf_object_open_opts.bpf_token_path`。libbpf 会从指定的 bpffs 挂载中派生 token。
2. **环境变量**：设置 `LIBBPF_BPF_TOKEN_PATH` 指向 bpffs 挂载。libbpf 自动识别。
3. **默认路径**：如果默认的 `/sys/fs/bpf` 是当前 user namespace 中的委托 bpffs，libbpf 隐式使用它。

一旦 token 被派生，libbpf 会在每个相关的 syscall（`BPF_MAP_CREATE`、`BPF_BTF_LOAD`、`BPF_PROG_LOAD` 和 `BPF_LINK_CREATE`）中传递它，不需要修改 BPF 应用的任何源代码。

## 编写 eBPF 程序

本教程的 BPF 侧故意保持最小，只有 loopback 上的一个 XDP 小程序。这样可以把注意力集中在 token 工作流上。以下是完整源码：

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

有几个设计选择值得注意：

**`BPF_MAP_TYPE_ARRAY`** 被选中是因为委托策略显式允许了 `array` map。如果我们改用 hash map，加载会失败，因为 token 不授予 `hash` map 的创建权限。这正是 token 模型在起作用：即使是微小的程序改动也会被委托策略捕获。

**`SEC("xdp")`** 匹配 `delegate_progs=xdp` 策略。如果你把它改成 `SEC("kprobe/...")`，内核会在加载时返回 `EPERM` 拒绝，因为 kprobe 不在允许的程序类型中。

**`XDP_PASS`** 简单地放行每个包。这个程序的唯一目的是证明基于 token 的加载和挂载成功了。在生产环境中，你会用真正的包处理逻辑来替换它。

## 用户态加载器：基于 Token 的加载

`token_trace.c` 加载器是一个标准的 libbpf skeleton 程序，唯一的关键区别是它传递了 `bpf_token_path`：

```c
struct bpf_object_open_opts open_opts = {};

open_opts.sz = sizeof(open_opts);
open_opts.bpf_token_path = env.token_path;

skel = token_trace_bpf__open_opts(&open_opts);
```

从这一刻开始，libbpf 接管了一切。当它调用 `bpf(BPF_MAP_CREATE)` 创建 `stats_map` 时，会附带 token fd。当它调用 `bpf(BPF_PROG_LOAD)` 加载 XDP 程序时，附带 token fd。当它调用 `bpf(BPF_LINK_CREATE)` 挂载到接口时，同样附带 token fd。

加载器的其余部分是标准流程：

```c
err = token_trace_bpf__load(skel);    // token 用于 map_create + prog_load
link = bpf_program__attach_xdp(skel->progs.handle_packet, ifindex);  // token 用于 link_create
```

挂载完成后，加载器在发送测试数据包前后分别读取 map 值来验证程序执行了：

```c
err = bpf_map_lookup_elem(map_fd, &key, &before);
// ... 向 127.0.0.1 发送 UDP 包 ...
err = bpf_map_lookup_elem(map_fd, &key, &after);
printf("delta          : %llu\n", after.packets - before.packets);
```

如果 delta 是 1，说明 XDP 程序已经用委托的 capability 成功加载和挂载了。

## Namespace 编排器：`token_userns_demo`

由于 BPF token 要求非 init 的 user namespace，在主机上直接运行 `token_trace -t /sys/fs/bpf` 是行不通的。`token_userns_demo.c` 封装器自动处理了复杂的 namespace 编排。以下是完整流程：

### 第一步：Fork 并创建 Namespace

```
父进程 (root, init_user_ns)          子进程 (非特权, 新 userns)
         │                                        │
         │   fork()                               │
         ├────────────────────────────────────────>│
         │                                        │
         │                            unshare(CLONE_NEWUSER)
         │                            unshare(CLONE_NEWNS | CLONE_NEWNET)
```

子进程创建新的 user namespace（在其中把自己映射为 uid/gid 0）、新的 mount namespace（使 bpffs 挂载是私有的）和新的 network namespace（使 `lo` 是一个全新的接口）。

### 第二步：创建 bpffs 并配置委托策略

```
父进程 (root, init_user_ns)          子进程 (新 userns)
         │                                        │
         │                            fs_fd = fsopen("bpf", 0)
         │   <───── 通过 SCM_RIGHTS 发送 fs_fd ──│
         │                                        │
    fsconfig(fs_fd, "delegate_cmds", ...)         │  (等待确认)
    fsconfig(fs_fd, "delegate_maps", "array")     │
    fsconfig(fs_fd, "delegate_progs", "xdp:...")  │
    fsconfig(fs_fd, "delegate_attachs", "any")    │
    fsconfig(fs_fd, FSCONFIG_CMD_CREATE)          │
         │                                        │
         │   ───────── 发送确认 ─────────────────>│
```

子进程调用 `fsopen("bpf", 0)` 在自己的 user namespace 中创建一个 bpffs 文件系统上下文，然后通过 Unix socket（`SCM_RIGHTS`）把文件描述符发给父进程。父进程以 root 身份运行在 init namespace 中，用 `fsconfig()` 配置委托策略，然后用 `FSCONFIG_CMD_CREATE` 实例化文件系统。

这个两步配合是必要的，因为：(a) bpffs 必须在子进程的 user namespace 中创建（token 才能在那里有效），但 (b) 只有特权父进程才能设置委托选项（因为这些选项授予 BPF capability）。

### 第三步：挂载并加载

```
子进程 (新 userns)
         │
    mnt_fd = fsmount(fs_fd, 0, 0)
    token_path = "/proc/self/fd/<mnt_fd>"
    set_loopback_up()
    exec("./token_trace", "-t", token_path, "-i", "lo")
```

子进程将 bpffs 实例化为一个分离的挂载（不需要挂载点，因为 `/proc/self/fd/<mnt_fd>` 提供了路径），在自己的 network namespace 中拉起 loopback 接口，然后 `exec` 执行 `token_trace` 并传入 bpffs 路径。从 `token_trace` 的角度看，它只是在用一个 token path 打开 BPF 对象，完全不知道也不关心 namespace 的设置过程。

## 手动准备 bpffs 挂载

如果你想在 demo 封装器之外试验 mount 语法，仓库里包含一个辅助脚本：

```bash
cd bpf-developer-tutorial/src/features/bpf_token
bash setup_token_bpffs.sh /tmp/bpf-token
```

它会在 `/tmp/bpf-token` 上用以下策略挂载 bpffs：

```text
delegate_cmds=prog_load:map_create:btf_load:link_create
delegate_maps=array
delegate_progs=xdp:socket_filter
delegate_attachs=any
```

**为什么要 `socket_filter`？** libbpf 在加载真正的 BPF 对象之前会做一次微小的 program-load probe 来检测内核特性支持。这个 probe 使用的是通用的 `BPF_PROG_TYPE_SOCKET_FILTER` 程序类型。如果委托策略中没有 `socket_filter`，probe 会失败，libbpf 拒绝继续。

**为什么要 `delegate_attachs=any`？** 同样的 libbpf probe 路径还会触发内核 token 检查代码中的 attach-type 验证。使用 `any` 避免了为 probe 兼容性而逐一列举每个可能的 attach type。

注意：这样的主机 namespace 挂载对于检查委托策略很有用（例如配合 `bpftool token list`），但除非 `bpf(BPF_TOKEN_CREATE)` syscall 来自匹配的非 init user namespace，否则不会产生可用的 token。

## 编译和运行

编译所有二进制文件：

```bash
cd bpf-developer-tutorial/src/features/bpf_token
make
```

运行端到端 demo：

```bash
sudo ./token_userns_demo
```

预期输出：

```text
token path     : /proc/self/fd/5
interface      : lo (ifindex=1)
packets before : 0
packets after  : 1
delta          : 1
last ifindex   : 1
```

`delta: 1` 确认 XDP 程序已使用 BPF token 成功加载和挂载，子进程中没有 `CAP_BPF` 或 `CAP_SYS_ADMIN`。

加 `-v` 可以看到 libbpf 的详细输出，显示 token 的创建和使用过程：

```bash
sudo ./token_userns_demo -v
```

如果你自己已经管理好了在 user namespace 中的委托 bpffs，可以直接运行加载器：

```bash
./token_trace -t /proc/self/fd/<mnt-fd> -i lo
```

## 实际应用场景

虽然本教程使用了一个最小的 XDP 程序，但 BPF token 模式可以扩展到生产场景：

- **容器运行时**（LXD、Docker、Kubernetes）：把带有特定 program 和 map 类型限制的委托 bpffs 挂载到容器中。LXD 已经通过 `security.delegate_bpf` 选项支持了这一点。

- **CI/CD 测试**：赋予构建任务加载和测试特定 eBPF 程序的能力，无需授予主机级 capability。委托策略充当 BPF 操作的白名单。

- **多租户 BPF 平台**：平台守护进程为每个租户创建不同委托策略的 bpffs 挂载。一个租户可能被允许使用 XDP + array map，另一个可能获得 tracepoint + ringbuf 访问权限。

- **LSM 集成**：由于 BPF token 和 Linux Security Module 集成，你可以将 token 委托和 SELinux 或 AppArmor 策略结合实现纵深防御。每个 token 获得自己的安全上下文，LSM hook 可以对其进行检查。

## 总结

本教程介绍了 BPF token 如何为 eBPF 权限提供一种超越 Linux capability "全有或全无"二元模型的委托机制。我们完整走过了整个流程：特权父进程用特定委托选项配置 bpffs 实例，user namespace 中的非特权子进程从该 bpffs 派生 token，libbpf 透明地使用 token 进行 map 创建、程序加载和挂载。最终结果是一个最小的 XDP 程序在非特权上下文中运行，这在 Linux 6.9 之前是不可能的。

BPF token 不是一个冷门功能。它代表了内核对 eBPF 生态系统中一个基本问题的回答：**在多租户环境中，如何安全地共享 BPF 能力，而不授予对 BPF 子系统的无约束访问？**

如果你想了解更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/> 获取更多示例和完整教程。

## 参考

- [BPF Token 概念文档](https://docs.ebpf.io/linux/concepts/token/)
- [BPF token 内核补丁系列（Andrii Nakryiko）](https://lore.kernel.org/bpf/20240103222034.2582628-1-andrii@kernel.org/T/)
- [BPF token LWN 文章](https://lwn.net/Articles/959350/)
- [更细粒度的 BPF token LWN 讨论](https://lwn.net/Articles/947173/)
- [使用 BPF Token 进行权限委托（LXD 文档）](https://documentation.ubuntu.com/lxd/latest/explanation/bpf/)
- [bpf_token_create() libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_token_create/)
- <https://docs.kernel.org/bpf/>
