# eBPF 教程：TCX 与基于 Link 的流量控制链

经典 `tc` BPF 挂载点很强，但它依然带着旧时代的运维负担：要通过 `tc` CLI 管理 qdisc、filter priority，还要把“程序挂载”和“程序链排序”拆开理解。**TCX** 把这套模型现代化了。你写 `tcx/ingress` 或 `tcx/egress` 程序，用 `bpf_program__attach_tcx()` 挂载，然后通过 BPF link 语义管理链路，而不是继续和 qdisc handle 打交道。

这篇教程是对经典 [lesson 20-tc](../20-tc/README.zh.md) 的补充。我们会在 loopback 上挂两个 ingress 程序，用 `BPF_F_BEFORE` 把一个程序插到另一个前面，再查询链的 revision 和顺序，最后主动发一个 UDP 包验证两个程序都按预期执行。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/50-tcx>

## 为什么需要 TCX

传统 `tc` 和 qdisc / filter 体系绑得很紧。即使在 direct-action 模式下，用户依然要理解 handle、priority、`clsact` 这些概念。TCX 沿用了 `__sk_buff` 这一套数据路径，但把挂载接口换成了 link-based API：

- `SEC("tcx/ingress")` / `SEC("tcx/egress")` 直接在 ELF section 里声明挂载点。
- `bpf_program__attach_tcx()` 创建的是 `BPF_LINK_TYPE_TCX` link，和现代其他 BPF link 一样可管理。
- `struct bpf_tcx_opts` 支持“相对另一个 program / link 插入”。
- `bpf_prog_query_opts()` 可以直接拿到 revision 和链顺序，适合多程序流水线。

所以 TCX 不只是“换了一个 tc section 名字”，而是把 TC 的控制面真正纳入了 libbpf 的 link 模型。

## 这个示例做了什么

这个 BPF 对象里有两个程序：

- `tcx_stats`：记录最近一个数据包的长度、协议和 ifindex，然后返回 `TCX_NEXT`，让链继续执行。
- `tcx_classifier`：做最小分类计数，然后返回 `TCX_PASS`，表示该链最终放行。

用户态先挂 `tcx_classifier`，再把 `tcx_stats` 插到它前面：

```c
classifier_link = bpf_program__attach_tcx(skel->progs.tcx_classifier, ifindex, NULL);

LIBBPF_OPTS(bpf_tcx_opts, before_opts,
	.flags = BPF_F_BEFORE,
	.relative_fd = bpf_program__fd(skel->progs.tcx_classifier));

stats_link = bpf_program__attach_tcx(skel->progs.tcx_stats, ifindex, &before_opts);
```

这就是 TCX 最值得学的模式：不再借助 `tc filter add ... priority ...` 之类的命令，而是在 libbpf 里直接表达程序链顺序。

挂载后，程序再调用 `bpf_prog_query_opts()` 查询内核视角下的 ingress 链：

```c
LIBBPF_OPTS(bpf_prog_query_opts, query);

query.count = 8;
query.prog_ids = prog_ids;
query.link_ids = link_ids;

err = bpf_prog_query_opts(ifindex, BPF_TCX_INGRESS, &query);
```

返回的 `revision`、`prog_ids`、`link_ids` 就是当前 live chain 的真实状态。

## 编译和运行

这个示例需要内核和 libbpf 已支持 TCX。

```bash
cd bpf-developer-tutorial/src/50-tcx
make
sudo ./tcx_demo -i lo
```

运行这个 loader 仍然需要具备 TC/BPF 相关权限的环境，通常要用 `root`，或者至少持有 `CAP_BPF` 和 `CAP_NET_ADMIN`。

程序会把两个 ingress 程序挂到 loopback，并自动向 `127.0.0.1` 发送一个 UDP 包来触发链执行。

示例输出：

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

如果只想看 attach/query 过程，不自动发流量，可以加 `-n`：

```bash
sudo ./tcx_demo -i lo -n
```

## 它和 lesson 20 的区别

[lesson 20-tc](../20-tc/README.zh.md) 仍然有价值，因为它讲清楚了 TC 数据路径本身和 direct-action 的编程风格。TCX **并没有** 替换 `__sk_buff`、返回码或者包解析方法；它替换的是控制面：

- `20-tc` 讲的是 classic tc / qdisc attach。
- `50-tcx` 讲的是 link-based attach、program ordering 和 revision-aware 管理。

如果你现在要写新的 libbpf 工具，TCX 更值得单独学。

## 参考

- <https://docs.kernel.org/bpf/>
- <https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.h>
- <https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf>
