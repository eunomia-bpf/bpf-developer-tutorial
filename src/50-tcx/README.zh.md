# eBPF 入门实践教程第五十篇：使用 TCX Link 实现可组合的流量控制

假设你需要在每个入站数据包上运行两个 BPF 程序：一个收集统计信息，另一个决定是否接受该数据包。使用经典 TC 挂载方式，你需要创建 qdisc，为每个程序分配一个数字优先级，然后祈祷系统上没有其他应用选择相同的优先级。如果你的统计收集应用崩溃了，它的 filter 会继续挂在那里，可能会干扰分类器。如果某个第三方 CNI 插件执行 `tc filter del` 清理自己的 filter，可能会顺带把你的也删掉。

**TCX**（Traffic Control eXtension）解决了这些问题。它由 Daniel Borkmann 开发，于 Linux 6.6 合入内核，为 TC ingress 和 egress 挂载点提供了基于 link 的挂载模型。程序获得了文件描述符关闭时自动清理的能力、通过 `BPF_F_BEFORE` 和 `BPF_F_AFTER` 标志的显式排序，以及不被其他进程意外删除的保护，所有这些都不需要接触 qdisc 或 filter 优先级。

本教程构建一个最小化的演示：在 loopback 接口上挂载两个 TCX ingress 程序，控制它们的执行顺序，并通过计数器观察执行情况。

> 完整源代码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## 背景：为什么经典 TC 挂载不够用

### 问题：共享命名空间，无所有权

经典的 `tc` BPF 挂载（`cls_bpf`）是在单一操作者控制整个 Traffic Control 流水线的时代设计的。要挂载一个 BPF 程序，你需要创建 `clsact` qdisc，然后添加带有 handle 和 priority 的 filter。当多个独立应用需要共存时，这种模型就崩溃了：

1. **没有所有权模型。** Filter 通过 handle 和 priority 标识，而不是创建它的进程。任何有足够权限的进程都能删除任何 filter，一个应用删除另一个应用的程序毫无保护可言。

2. **优先级冲突。** 两个应用可能独立地选择优先级 100。第二次挂载会悄无声息地替换第一次，没有错误，没有警告。

3. **崩溃后残留。** 经典 filter 会一直存在直到被显式删除。如果应用崩溃且没有清理，它的 filter 会带着可能过时的逻辑继续存在。

4. **共享控制面。** `tc` CLI 和基于 libbpf 的程序都使用 netlink 来管理 filter。你的 BPF 应用和系统上所有其他 tc 用户竞争这个共享命名空间。

这些问题在 Cilium 等项目中变得非常严重，BPF 数据面必须与第三方 CNI 插件、可观测性 agent 和安全工具共存，它们都在同一个接口上挂载。

### 解决方案：基于 Link 的挂载

TCX 采取了完全不同的思路。它不是在 qdisc 基础设施上叠加，而是在 TC 挂载点上提供了专用的 BPF 程序入口。核心设计原则：

**BPF Link 语义。** `bpf_program__attach_tcx()` 创建 `BPF_LINK_TYPE_TCX` link。与 XDP 和 cgroup link 一样，TCX link 提供安全的所有权：link 绑定到文件描述符，fd 关闭时自动卸载，不会被其他应用删除。

**显式排序。** 不再期望两个数字优先级碰巧排对，而是直接用 `BPF_F_BEFORE` 和 `BPF_F_AFTER` 指定顺序。还可以用 `BPF_F_REPLACE` 原子替换程序。所有操作都接受 `expected_revision` 字段来防止并发修改时的竞争。

**链返回码。** TCX 定义了让多程序组合变得显式的返回码：

| 返回码 | 值 | 行为 |
|--------|-----|------|
| `TCX_NEXT` | -1 | 继续执行链中的下一个程序 |
| `TCX_PASS` | 0 | 接受数据包；终止链 |
| `TCX_DROP` | 2 | 丢弃数据包；终止链 |
| `TCX_REDIRECT` | 7 | 重定向数据包；终止链 |

未知的返回码映射为 `TCX_NEXT` 以保证前向兼容。

**与经典 TC 共存。** TCX link 可以和同一接口上的传统 `cls_bpf` filter 共存。内核先执行 TCX 程序，如果存在经典 filter 再降级到 `tcf_classify()`。这允许从经典 tc 到 TCX 的渐进迁移。

## eBPF 程序

我们的 BPF 对象包含两个程序，用于演示链式执行。以下是完整的内核侧代码：

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

### Section 名：`SEC("tcx/ingress")`

`SEC("tcx/ingress")` 注解告诉 libbpf 这个程序挂载到 TCX ingress 挂载点。libbpf 将这个 section 名映射到 `BPF_PROG_TYPE_SCHED_CLS` 并设置 TCX 特定的 attach type。egress 对应的写法是 `SEC("tcx/egress")`。

旧的 section 名 `SEC("tc")`、`SEC("classifier")` 和 `SEC("action")` 仍然可用，但已被废弃，推荐使用 `tcx/*` 变体。

### `__sk_buff` 上下文

两个程序都接收 `struct __sk_buff *skb` 参数。这是经典 TC 程序、XDP 和其他网络 BPF 程序类型使用的同一个 socket buffer 抽象。它提供对数据包元数据的访问：

- `skb->len`：数据包长度（字节）
- `skb->protocol`：网络字节序的 EtherType（因此需要 `bpf_ntohs()`）
- `skb->ifindex`：数据包到达的接口索引

要访问数据包内容，可以使用 `bpf_skb_load_bytes()` 或直接数据包指针，但本演示聚焦于挂载机制而非数据包解析。

### 全局变量作为计数器

我们使用全局变量（`stats_hits`、`classifier_hits` 等）而非 BPF map。libbpf skeleton 在 `skel->bss->stats_hits` 暴露这些变量，简化了用户态访问。这种方式适用于单 CPU 演示；生产代码应使用 per-CPU 数组来避免并发更新竞争。

### 返回码：`TCX_NEXT` 与 `TCX_PASS`

返回码决定链是否继续：

- `tcx_stats` 返回 `TCX_NEXT`："我的工作做完了；把数据包传给下一个程序。"链继续执行。
- `tcx_classifier` 返回 `TCX_PASS`："接受这个数据包。"链终止；后续程序不再执行。

顺序很重要。如果 `tcx_classifier` 先执行，它会返回 `TCX_PASS`，`tcx_stats` 就永远不会执行。TCX 让你必须显式指定这个顺序。

## 用户态加载器

用户态代码演示了三个关键的 TCX 操作：挂载程序、控制顺序、查询实时链状态。

### 第一步：挂载第一个程序

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier,
					 ifindex, NULL);
```

这将 `tcx_classifier` 挂到指定接口的 TCX ingress 挂载点。`NULL` 选项表示使用默认值，程序追加到链末尾。此时链中有一个程序。

### 第二步：把第二个程序插到第一个前面

```c
LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats,
				    ifindex, &before_opts);
```

`bpf_tcx_opts` 结构体指定 `tcx_stats` 应该插入到 `tcx_classifier` *前面*。`.relative_fd` 字段标识参考点：已挂载的 classifier 的文件描述符。这个调用之后，链的顺序是：`tcx_stats` → `tcx_classifier`。

你可以用 `BPF_F_AFTER` 配合不同的参考点达到同样的排序效果。关键是你直接表达顺序，而不是通过可能冲突的数字优先级。

### 第三步：查询链

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

挂载完成后，加载器查询内核中链的实时状态。结果包括：

- **`revision`**：每次链被修改时递增的单调计数器。挂载时可以把这个值作为 `expected_revision` 传入，确保链在你上次观察之后没有变化，这对原子多步更新很有用。
- **`prog_ids[]`**：按执行顺序排列的 BPF 程序 ID。
- **`link_ids[]`**：对应的 BPF link ID。

这种内省能力对调试多程序流水线很有价值，也适用于需要了解当前挂载状态的工具。

### 第四步：发送流量并验证

加载器向 `127.0.0.1:9`（discard 服务）发送一个 UDP 包来触发链，短暂等待后读取全局变量：

```c
printf("  tcx_stats hits      : %llu\n",
       (unsigned long long)skel->bss->stats_hits);
printf("  tcx_classifier hits : %llu\n",
       (unsigned long long)skel->bss->classifier_hits);
```

如果两个计数器都显示 1，说明链按预期执行了：`tcx_stats` 先运行（记录元数据，返回 `TCX_NEXT`），然后 `tcx_classifier` 运行（计数，返回 `TCX_PASS`）。

## 编译和运行

### 环境要求

- Linux 6.6 或更高版本
- 内核配置：`CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_NET_XGRESS=y`
- root 权限（用于 BPF 和网络接口访问）
- 较新版本的 libbpf（推荐 1.2+）

### 编译

```bash
cd bpf-developer-tutorial/src/50-tcx
make
```

### 运行

```bash
sudo ./tcx_demo -i lo
```

预期输出：

```text
Attached TCX programs to lo (ifindex=1)
TCX ingress chain revision: 2
  slot 0: prog_id=812 link_id=901
  slot 1: prog_id=811 link_id=900

Counters:
  tcx_stats hits      : 1
  tcx_classifier hits : 1
  last ifindex        : 1
  last protocol       : 0x0800
  last length         : 46
```

**输出解读：**

- **Revision 2**：链被修改了两次，`tcx_classifier` 挂载时（revision 1），`tcx_stats` 插入到它前面时（revision 2）。
- **Slot 顺序**：Slot 0 是 `tcx_stats`（用 `BPF_F_BEFORE` 插入的程序）；slot 1 是 `tcx_classifier`。
- **Protocol 0x0800**：IPv4（生成的 UDP 包）。
- **Length 46**：20 字节的载荷 "tcx tutorial packet" 加上报头。

### 选项

- `-i IFACE`：挂载到不同的接口（默认：`lo`）
- `-n`：跳过流量生成（只查看挂载/查询行为）
- `-v`：启用 libbpf 调试输出，查看底层 BPF syscall 序列

## 与第 20 课（经典 TC）的对比

[第 20 课](../20-tc/README.zh.md)讲的是经典 TC 路径：创建 `clsact` qdisc，挂载 `SEC("tc")` 程序作为 filter，用 `__sk_buff` 检查数据包。那一课仍然有价值，因为**数据面模型**是相同的，TCX 程序使用相同的上下文结构和相同的 helper 来访问数据包。

TCX 替换的是**控制面**：

| 方面 | 经典 TC（第 20 课） | TCX（第 50 课） |
|------|---------------------|-----------------|
| 挂载方式 | Netlink / `tc` CLI | `bpf_program__attach_tcx()` |
| 所有权 | 无；任何进程都能删除任何 filter | BPF link 绑定到 fd；关闭时自动卸载 |
| 排序 | 隐式数字优先级 | 显式 `BPF_F_BEFORE` / `BPF_F_AFTER` |
| 多程序 | 手动优先级管理 | 内建链 + revision 追踪 |
| Section 名 | `SEC("tc")` | `SEC("tcx/ingress")` / `SEC("tcx/egress")` |
| 内核要求 | 4.1+ | 6.6+ |

对于新的基于 libbpf 的网络工具，TCX 是推荐的挂载方式。Cilium 已经将其数据面从经典 tc 迁移到了 TCX。

## 总结

TCX 用 BPF link 语义取代了基于 qdisc 的管道，使 TC 程序挂载现代化。本教程中，我们挂载了两个 ingress 程序，用 `BPF_F_BEFORE` 控制了它们的执行顺序，查询了实时链状态，并通过观察计数器验证了正确执行。TCX 提供了安全的所有权、显式排序、revision 感知的更新以及与经典 TC 的向后兼容，使其成为现代 eBPF 应用中可组合、多程序流量控制的基石。

更多 eBPF 教程请访问我们的仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或 <https://eunomia.dev/tutorials/>。

## 参考

- [TCX 内核提交：fd-based tcx multi-prog infra with link support](https://lore.kernel.org/bpf/20230707172455.7634-3-daniel@iogearbox.net/)
- [BPF_PROG_TYPE_SCHED_CLS 文档](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
- [bpf_program__attach_tcx libbpf API](https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_program__attach_tcx/)
- [Cilium TCX & Netkit 更新（BPFConf 2024）](https://bpfconf.ebpf.io/bpfconf2024/bpfconf2024_material/tcx_netkit_update_and_global_sk_iter.pdf)
- [Generic multi-prog API, tcx links and meta device（BPFConf 2023）](http://oldvger.kernel.org/bpfconf2023_material/tcx_meta_netdev_borkmann.pdf)
- [内核 BPF 文档](https://docs.kernel.org/bpf/)
