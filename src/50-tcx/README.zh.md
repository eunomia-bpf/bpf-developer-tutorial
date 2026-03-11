# eBPF 入门实践教程第五十篇：使用 TCX Link 实现可组合的流量控制

你是否试过在 TC ingress 路径上挂载多个 BPF 程序，却被 qdisc handle、filter priority 和 `tc` CLI 搞得焦头烂额？或者一个应用的 TC 程序被另一个应用不小心覆盖掉？传统的 `cls_bpf` 挂载方式确实能工作，但它继承了几十年的 queueing discipline 管道，而这套体系根本不是为 BPF 优先的世界设计的。如果你能用和 XDP、cgroup 相同的 link 模型来管理 TC 程序，会怎样？

这就是 **TCX**（Traffic Control eXtension）要解决的问题。TCX 由 Daniel Borkmann 开发，于 Linux 6.6 合入内核，它为 TC ingress 和 egress 数据路径提供了一套轻量级的、基于 fd 的多程序挂载基础设施。程序获得 BPF link 语义（安全的所有权、fd 关闭时自动卸载、通过 `BPF_F_BEFORE` / `BPF_F_AFTER` 显式排序），完全不需要碰任何 qdisc 或 filter priority。

本教程将在 loopback 接口上挂载两个 TCX ingress 程序，把一个插到另一个前面，查询内核的实时链状态，并发送流量来验证执行顺序。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## 背景：为什么经典 TC 挂载需要被重新思考

### 问题：qdisc 管道和不安全的所有权

经典的 `tc` BPF 挂载（`cls_bpf`）是嫁接在已有 Traffic Control 框架之上的。要挂载一个 BPF 程序，你首先需要在接口上创建一个 `clsact` qdisc，然后添加一个带有 handle 和 priority 的 filter。这在单一操作者的场景下没问题，但在云原生环境中，多个应用需要在同一个接口上挂载 TC 程序，就出了大问题：

1. **没有所有权模型**：一个应用的 `tc filter del` 可以意外删除另一个应用的程序。因为经典 tc filter 是通过 handle/priority 标识的，而不是通过创建它的进程。

2. **Priority 冲突**：两个应用可能选了相同的 priority 值。第二次挂载会默默覆盖第一次的。

3. **默认永久挂载**：经典 tc filter 会一直存在直到被显式删除。如果挂载 filter 的应用崩溃了且没有清理，filter 会一直留在那里，可能带着过时的程序逻辑。

4. **CLI 依赖**：即使用 libbpf，挂载模型也绑定在 netlink 上，和 `tc` CLI 使用的是同一套机制。这意味着你的 BPF 应用和系统上所有其他 tc 用户共享同一个控制面。

这些问题在 Cilium 等项目中变得尤为突出。BPF 数据面需要和第三方 CNI 插件、可观测性 agent 以及安全工具和平共处，而它们都想挂到 TC 上。

### 解决方案：基于 Link 的多程序管理

TCX 采取了完全不同的思路。它不是在 qdisc 基础设施上打补丁，而是在 TC ingress 和 egress 挂载点上提供了一个专用的、无 qdisc 的扩展入口。核心设计原则：

**BPF Link 语义**：`bpf_program__attach_tcx()` 创建 `BPF_LINK_TYPE_TCX` link。和 XDP link、cgroup link 一样，TCX link 赋予你安全的所有权：link 绑定到 fd 上，fd 关闭时自动卸载，不会被其他应用意外覆盖。

**显式排序**：不再依赖隐式的 priority 数字，而是通过 `BPF_F_BEFORE` 和 `BPF_F_AFTER` 将程序相对于彼此放置。还可以用 `BPF_F_REPLACE` 原子替换特定程序。所有操作都支持 `expected_revision` 字段来防止并发修改时的竞争条件。

**链返回码**：TCX 定义了简化的返回码，使多程序组合变得显式：

| 返回码 | 值 | 含义 |
|--------|-----|------|
| `TCX_NEXT` | -1 | 非终止；把数据包传给链中的下一个程序 |
| `TCX_PASS` | 0 | 接受数据包并终止链 |
| `TCX_DROP` | 2 | 丢弃数据包并终止链 |
| `TCX_REDIRECT` | 7 | 重定向数据包并终止链 |

未知的返回码会被映射为 `TCX_NEXT`，以保证前向兼容。

**和经典 TC 共存**：TCX link 可以和同一接口上的传统 `cls_bpf` filter 共存。内核先执行 TCX 程序，如果存在经典 filter，再降级到 `tcf_classify()`。这允许从经典 tc 到 TCX 的渐进迁移，不需要一次性切换。

## 编写 eBPF 程序

我们的 BPF 对象包含两个程序，用来演示链的组合。以下是完整源代码：

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

我们逐步分析。

### Section 名：`SEC("tcx/ingress")`

`SEC("tcx/ingress")` 注解告诉 libbpf 这个程序应该挂载到 TCX ingress 挂载点，而非经典的 TC classifier。这不仅仅是一个命名约定；libbpf 会把这个 section 名映射到 `BPF_PROG_TYPE_SCHED_CLS` 并设置 TCX 对应的 attach type。egress 的对应写法是 `SEC("tcx/egress")`。

注意，`SEC("tc")`、`SEC("classifier")` 和 `SEC("action")` 已经被 libbpf 视为废弃，推荐改用 `tcx/*` section 名。

### 全局变量作为计数器

我们用全局变量（`stats_hits`、`classifier_hits`、`last_len` 等）而不是 BPF map 作为计数器。libbpf skeleton 会通过 `skel->bss->stats_hits` 暴露这些变量，使用户态代码更简洁。这在单 CPU demo 中没有问题；生产环境中应使用 per-CPU map 来避免数据竞争。

### 返回码：`TCX_NEXT` vs `TCX_PASS`

这是 TCX 组合的核心：

- `tcx_stats` 返回 `TCX_NEXT`，意思是"我的工作做完了，把数据包传给链中的下一个程序"。链继续执行。
- `tcx_classifier` 返回 `TCX_PASS`，这是一个终止性判定：数据包被接受，链中后续的程序不会再执行。

如果我们把 `tcx_classifier` 放在 `tcx_stats` *前面*，`tcx_stats` 就永远不会执行，因为 `TCX_PASS` 会终止链。顺序很重要，而 TCX 让这件事变得显式。

## 用户态加载器：挂载和查询链

用户态代码演示了三个关键的 TCX 操作：挂载程序、相对排序、查询实时链。

### 第一步：挂载第一个程序

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier,
					 ifindex, NULL);
```

把 `tcx_classifier` 挂到指定接口的 TCX ingress 挂载点上。`NULL` 选项表示"使用默认值"，程序被追加到链的末尾。此时链中有一个程序。

### 第二步：把第二个程序插到第一个*前面*

```c
LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats,
				    ifindex, &before_opts);
```

`bpf_tcx_opts` 结构体告诉内核把 `tcx_stats` 插到 `tcx_classifier` *前面*。`.relative_fd` 字段标识参考点，即已挂载的 classifier 程序的 fd。操作完成后，链的顺序是：`tcx_stats` → `tcx_classifier`。

你也可以用 `BPF_F_AFTER` 配合不同的参考点来达到同样的排序效果。重点是你可以直接表达想要的顺序，而不需要期望两个数字 priority 碰巧排对。

### 第三步：查询链

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

挂载完成后，加载器查询内核中链的实时状态。返回的数据包括：

- **`revision`**：一个单调递增的计数器，每次链被修改时都会变化。如果你想执行原子更新，可以把这个值作为 `expected_revision` 传入。
- **`prog_ids[]`**：按链顺序排列的 BPF 程序 ID。
- **`link_ids[]`**：对应的 BPF link ID。

这让任何观察者都能精确判断哪些程序被挂载了、顺序是什么，这对调试多程序流水线非常有价值。

### 第四步：发送流量并读取计数器

加载器向 `127.0.0.1`（端口 9，discard 服务）发送一个 UDP 包来触发链，短暂等待后读取全局变量来验证两个程序都执行了：

```c
printf("  tcx_stats hits      : %llu\n",
       (unsigned long long)skel->bss->stats_hits);
printf("  tcx_classifier hits : %llu\n",
       (unsigned long long)skel->bss->classifier_hits);
```

如果两个计数器都是 1，链就按预期工作了：`tcx_stats` 先执行（记录元信息并返回 `TCX_NEXT`），然后 `tcx_classifier` 执行（计数并返回 `TCX_PASS`）。

## 编译和运行

本示例需要 Linux 6.6+ 且支持 TCX，以及较新版本的 libbpf。

```bash
cd bpf-developer-tutorial/src/50-tcx
make
sudo ./tcx_demo -i lo
```

预期输出：

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

revision 是 3，因为链被修改了两次：`tcx_classifier` 挂载时（revision 从 0 到 1），`tcx_stats` 插入到它前面时（revision 到 2）。查询本身使 revision 递增到 3。

如果只想看挂载行为而不发流量，加 `-n`：

```bash
sudo ./tcx_demo -i lo -n
```

加 `-v` 开启 libbpf 调试输出，可以看到底层 BPF syscall 的执行序列。

## 它和第 20 课（经典 TC）的区别

[第 20 课-tc](../20-tc/README.zh.md) 讲的是经典 TC 数据路径：创建 `clsact` qdisc，挂载 `SEC("tc")` 程序作为 filter，使用 `__sk_buff` 进行包检查。那一课仍然有价值，因为**数据包处理模型**是完全相同的：TCX 程序收到的是相同的 `__sk_buff` context，使用相同的 helper 来解析数据包。

TCX 替换的是**控制面**：

| 方面 | 经典 TC（第 20 课） | TCX（第 50 课） |
|------|---------------------|-----------------|
| 挂载方式 | Netlink / `tc` CLI | `bpf_program__attach_tcx()` |
| 所有权 | 无；任何人可以 `tc filter del` | BPF link；fd 关闭时自动卸载 |
| 排序 | 隐式 priority 数字 | 显式 `BPF_F_BEFORE` / `BPF_F_AFTER` |
| 多程序 | 手动 priority 管理 | 内建链 + revision 追踪 |
| Section 名 | `SEC("tc")` | `SEC("tcx/ingress")` / `SEC("tcx/egress")` |
| 内核要求 | 任意现代内核 | Linux 6.6+ |

如果你正在构建新的 libbpf 网络工具，TCX 是推荐的接口。Cilium 已经将其数据面从经典 tc 迁移到了 TCX。

## 总结

本教程介绍了 TCX 如何用 BPF link 语义取代基于 qdisc 的 TC 程序管理。我们挂载了两个 ingress 程序，用 `BPF_F_BEFORE` 控制了它们的执行顺序，用 `bpf_prog_query_opts()` 查询了实时链状态，并验证了两个程序按正确顺序执行。TCX 提供了安全的所有权、显式排序、revision 感知的更新以及和经典 TC 的共存能力，使其成为现代 eBPF 应用中可组合、多程序流量控制的基石。

如果你想了解更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/> 获取更多示例和完整教程。

## 参考

- [TCX 内核提交：fd-based tcx multi-prog infra with link support](https://lore.kernel.org/bpf/20230707172455.7634-3-daniel@iogearbox.net/)
- [BPF_PROG_TYPE_SCHED_CLS 文档](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
- [bpf_program__attach_tcx libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__attach_tcx/)
- [Cilium TCX & Netkit 更新（BPFConf 2024）](https://bpfconf.ebpf.io/bpfconf2024/bpfconf2024_material/tcx_netkit_update_and_global_sk_iter.pdf)
- [Generic multi-prog API, tcx links and meta device（BPFConf 2023）](http://oldvger.kernel.org/bpfconf2023_material/tcx_meta_netdev_borkmann.pdf)
- <https://docs.kernel.org/bpf/>
