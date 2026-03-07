# eBPF 教程：BPF Token 用于受控的委托加载

很多 eBPF 教程默认只有一个“全权限操作者”。真实系统不是这样：平台团队希望把一小部分 BPF 能力开放给租户、业务团队或者 CI 任务，但又不想直接给出宽泛的 `CAP_BPF`、`CAP_SYS_ADMIN`，更不想让对方随便加载任意 program type。**BPF token** 就是内核为这种“受控委托”场景提供的机制。

这篇教程只讲最实用的 libbpf 路径。不去手写整套 `BPF_TOKEN_CREATE` + raw syscall 流程，而是使用 libbpf 的 `bpf_token_path` 支持：从一个带 delegation policy 的 bpffs mount 派生 token，然后用这个 token 完成一个最小 XDP 程序的加载与挂载。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_token>

## BPF Token 到底解决什么问题

BPF token 本质上是一个 FD，它携带的是**从某个 bpffs mount 派生出来的委托权限集合**。这个权限集合不是“全部 BPF 能力”，而是按四个维度精确限制：

- 允许哪些 BPF command，例如 `prog_load`、`map_create`、`btf_load`、`link_create`；
- 允许哪些 map type；
- 允许哪些 program type；
- 允许哪些 attach type。

这就是它和“直接给 CAP_BPF”最大的区别：token 是一把被裁剪过的钥匙，而不是系统级总钥匙。

底层 API 是 `bpf_token_create()`；如果你用的是 libbpf，更自然的接入点是 `bpf_object_open_opts.bpf_token_path`，或者环境变量 `LIBBPF_BPF_TOKEN_PATH`。

## 这个最小示例做了什么

为了做成一条真正能端到端跑通的 delegated attach demo，这里选的是 loopback 上的最小 XDP 程序。BPF 侧保持得很小，而且显式使用了 `BPF_MAP_TYPE_ARRAY`，和 delegation policy 也更匹配：

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

用户态 loader 接收一个 delegated bpffs 路径，并把它传给 libbpf：

```c
struct bpf_object_open_opts open_opts = {};

open_opts.sz = sizeof(open_opts);
open_opts.bpf_token_path = env.token_path;

skel = token_trace_bpf__open_opts(&open_opts);
```

从这一刻开始，libbpf 会自动从这个 bpffs mount 派生 token，并在后续 map create、BTF load、prog load、attach 等支持 token 的 syscall 路径上自动使用它。

## 准备一个带委托策略的 bpffs 实例

要使用 BPF token，前提不是“系统里有 bpffs”，而是“系统里有一个**明确声明 delegation policy** 的 bpffs 实例”。这里有一个很容易踩坑的内核规则：**BPF token 必须在和 bpffs 实例相同的、且不是 `init_user_ns` 的 user namespace 里创建**。所以 host namespace 里的 bpffs mount 适合拿来观察 delegation policy，但它本身并不能直接完成一条端到端 token demo。

仓库里仍然放了一个最小辅助脚本，用来展示 mount 语法：

```bash
cd bpf-developer-tutorial/src/features/bpf_token
bash setup_token_bpffs.sh /tmp/bpf-token
```

这个脚本会用下面这组策略挂载 bpffs：

```text
delegate_cmds=prog_load:map_create:btf_load:link_create
delegate_maps=array
delegate_progs=xdp:socket_filter
delegate_attachs=any
```

这里额外放开 `socket_filter` 不是因为最终程序要用它，而是因为当前 libbpf 在真正加载对象前还会先做一次 trivial program-load probe，这一步会用到一个更通用的 program type。`delegate_attachs=any` 也是同样的原因：当前 token 校验在这条 probe 路径上也会检查 attach-type 位图。

如果你只是想看 delegation policy，本地挂出来再配合 `bpftool token list` 就够了；如果你想要一个真正能 load+attach 的 demo，建议直接用下面这个 wrapper。

## 编译和运行

先编译：

```bash
cd bpf-developer-tutorial/src/features/bpf_token
make
```

如果你要跑一条真正会创建 token 并挂上 XDP 程序的端到端 demo，直接执行：

```bash
sudo ./token_userns_demo
```

示例输出：

```text
token path     : /proc/self/fd/5
interface      : lo (ifindex=1)
packets before : 0
packets after  : 1
delta          : 1
last ifindex   : 1
```

`token_userns_demo` 帮你自动完成了最麻烦的那一段：

- 创建一个新的 user namespace、mount namespace 和 network namespace；
- 由特权父进程替子进程的 bpffs fs context 写入 delegation policy；
- 子进程拉起 `lo`，再把 detached bpffs mount 以 `/proc/self/fd/<mnt_fd>` 的形式交给 `token_trace`，让 `libbpf` 从这里派生 token。

如果你自己已经管理好了“位于正确 user namespace 里的 delegated bpffs 实例”，仍然可以直接运行底层 loader：

```bash
./token_trace -t /proc/self/fd/<mnt-fd> -i lo
```

## 为什么这个主题值得单独成章

这个示例虽然小，但它代表的是一整条真实的生产路径：

- 平台团队创建一个受控 bpffs mount；
- libbpf 应用从这个 mount 派生 token；
- 程序加载和挂载通过 token 完成，而不是依赖宽泛的全局权限。

所以 BPF token 不是一个冷门 syscall，它代表的是 **BPF 在多租户、受控委托、平台治理场景下的标准能力**。

## 参考

- <https://docs.kernel.org/bpf/>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/bpf.h>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.h>
