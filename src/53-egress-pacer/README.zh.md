# eBPF 实践教程：使用 BPF Qdisc 对出口流量进行限速

你有一个实验环境、测试台或通过专用 veth/TAP 接口运行的服务。某个组件突然发出流量突发，队列无限制地增长，延迟飙升，而你对丢包情况一无所知。你需要一个按指定时长运行的出口限速器，它能报告队列和字节统计，并在正常退出或处理 SIGINT、SIGTERM 时移除自身。不可捕获的信号仍需使用下文的恢复流程。

本教程构建的工具正是做这件事。它利用 Linux 6.16 的 `struct_ops` BPF qdisc 基础设施注册一个有界 FIFO，以你指定的总速率限制出口流量。这里的限速通过按报文序列化时间进行整形（pacing）实现，并将入队/出队/丢弃统计暴露给用户态。

这不是生产级工具，不适用于通用物理网卡。它的设计目标是受控接口（veth、TAP、IFB），由操作者做出明确的生命周期决定。加载器拒绝替换任何已存在的 root qdisc。

[查看本课的完整源码](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/53-egress-pacer)。

## 快速开始

无需 root 即可编译：

```bash
cd src/53-egress-pacer
make clean
make -j2
```

首次运行时，建议让集成测试自动创建并删除一次性 veth 对。此步骤需要 root 权限：

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

如果已经创建并控制一个专用接口，也可以手动运行加载器。请先通过 `tc qdisc show dev veth-service` 检查接口；如果内核报告已有 root qdisc，加载器会拒绝安装：

```bash
sudo ./egress_pacer --interface veth-service --rate-kbps 64000 --queue-limit 256 --duration 30
```

当 qdisc 激活后，工具输出 `READY`；退出时则输出 `SUMMARY` 统计。下面只展示输出格式，其中的省略号是占位符，并非实测值：

```text
READY interface=veth-service rate_kbps=64000 queue_limit=256 duration=30
SUMMARY enqueued=... dequeued=... policy_dropped=... cleanup_dropped=... bytes_dequeued=... max_qlen=...
```

完整用法：

```text
Usage: ./egress_pacer --interface IFACE [--rate-kbps KBPS] [--queue-limit PACKETS] [--duration SEC] [--verbose]
```

| 选项 | 取值范围 | 默认值 |
|------|----------|--------|
| `--interface` | 必选 | 无 |
| `--rate-kbps` | 8 到 100000000 | 1024 |
| `--queue-limit` | 1 到 65535 个报文 | 256 |
| `--duration` | 1 到 86400 秒 | 10 |
| `--verbose` | 开关 | 关闭 |

如果接口已有 root qdisc，工具会拒绝并输出：

```text
refusing to replace the existing root qdisc on IFACE
```

## 验证过的测试输出

仓库包含一个确定性集成测试。以下输出在 KVM 客户机（内核 `7.0.0-rc2+`）中于宿主机编译后采集：

```console
READY interface=epac_tx rate_kbps=64 queue_limit=8 duration=2
SUMMARY enqueued=9 dequeued=9 policy_dropped=31 cleanup_dropped=0 bytes_dequeued=9216 max_qlen=8
TEST-SUMMARY attempts=40 received=9 send_errors=31 span_ms=1024 observed_kbps=64.0
PASS: conflict refusal, bounded drops, pacing, accounting, normal/signal cleanup, and SIGKILL recovery succeeded
```

这是功能性冒烟测试，不是基准性能数据。测试向 64 Kbit/s、队列容量 8 的 pacer 突发 40 个 1024 字节的 EtherType `0x88B5` 原始帧。本次运行中，队列填满后有 31 个计入 `policy_dropped`，另有 9 个经过整形后交付。不要将这些数字推广到其他场景。

在一个可随意使用的 Linux 6.16+ 系统上自行运行：

```bash
sudo python3 tests/test_egress_pacer.py ./egress_pacer
```

该测试会创建并删除 `epac_tx`/`epac_rx` veth 对。它先安装一个 `pfifo` 以验证冲突拒绝行为，再发送突发流量。第一轮检查有界丢包、字节和报文计数、整形效果及正常退出清理。

第二轮在发送突发后保留队列积压，再发送 SIGTERM。测试要求 `cleanup_dropped` 非零，并验证 `enqueued = dequeued + cleanup_dropped`。最后一轮确认 SIGKILL 会在测试客户机上留下 `bpf_pacer`，随后通过 `tc` 显式删除 qdisc、验证恢复结果，并在 `finally` 块中删除 veth 对。

## 工作原理

本工具由两部分组成：实现 `struct Qdisc_ops` 的 BPF 对象，以及管理 qdisc 生命周期的用户态加载器。

与[普通 TC classifier/action 示例](../20-tc/README.zh.md)不同，后者由 classifier 在独立的内核 qdisc 上返回处理动作。本例的 struct_ops 程序会注册 `bpf_pacer`，并将它自身安装为 root qdisc。报文到达前，`init` 回调会把配置的 `queue_limit` 写入 `sch->limit`。

### BPF qdisc：入队

当报文到达 qdisc 时，入队回调检查队列长度是否超过 `sch->limit`。如果队列已满，报文被丢弃并累加 `policy_dropped`。`bpf_obj_new` 分配失败时也会进入同一丢弃和计数路径。否则：

1. 通过 `bpf_obj_new` 分配一个 `packet_node`。
2. 通过 `bpf_kptr_xchg` 将 skb 转移到节点中。
3. 计算报文的允许发送时间戳 `eligible_ns = max(next_departure_ns, now)`，再将 `next_departure_ns` 推进一个序列化间隔，即 `(packet_len * 8 * 1,000,000 / rate_kbps)` 纳秒。
4. 将节点推入 BPF 链表，更新 qlen 和 backlog。

以下代码摘自 BPF 源码（`egress_pacer.bpf.c`）：

```c
SEC("struct_ops/egress_pacer_enqueue")
int BPF_PROG(egress_pacer_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct packet_node *packet;
	__u64 eligible_ns, interval_ns, now;
	__u32 packet_len;

	packet_len = qdisc_packet_len(skb);
	if (sch->q.qlen >= sch->limit)
		goto drop;

	packet = bpf_obj_new(typeof(*packet));
	if (!packet)
		goto drop;

	now = bpf_ktime_get_ns();
	interval_ns = (__u64)packet_len * 8 * 1000000ULL / rate_kbps;
	if (!interval_ns)
		interval_ns = 1;
	packet->packet_len = packet_len;
	skb = bpf_kptr_xchg(&packet->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&queue_lock);
	eligible_ns = next_departure_ns > now ? next_departure_ns : now;
	next_departure_ns = eligible_ns + interval_ns;
	packet->eligible_ns = eligible_ns;
	bpf_list_push_back(&packet_queue, &packet->node);
	sch->q.qlen++;
	sch->qstats.backlog += packet_len;
	__sync_fetch_and_add(&stats.enqueued, 1);
	if (sch->q.qlen > stats.max_qlen)
		stats.max_qlen = sch->q.qlen;
	bpf_spin_unlock(&queue_lock);
	return NET_XMIT_SUCCESS;

drop:
	bpf_qdisc_skb_drop(skb, to_free);
	__sync_fetch_and_add(&stats.policy_dropped, 1);
	return NET_XMIT_DROP;
}
```

间隔公式意味着空闲后的第一个报文可以立即发出（因为 `next_departure_ns` 已经过去，`eligible_ns = now`）。后续报文按配置速率和序列化报文长度间隔发送。

### BPF qdisc：出队

出队回调弹出链表头部。如果当前时间早于报文的 `eligible_ns`，报文被放回链表头部，并调度 qdisc watchdog：

```c
SEC("struct_ops/egress_pacer_dequeue")
struct sk_buff *BPF_PROG(egress_pacer_dequeue, struct Qdisc *sch)
{
	struct bpf_list_node *node;
	struct packet_node *packet;
	struct sk_buff *skb = NULL;
	__u64 expire, now;
	__u32 packet_len;

	bpf_spin_lock(&queue_lock);
	node = bpf_list_pop_front(&packet_queue);
	bpf_spin_unlock(&queue_lock);
	if (!node)
		return NULL;

	packet = container_of(node, struct packet_node, node);
	now = bpf_ktime_get_ns();
	if (now < packet->eligible_ns) {
		expire = packet->eligible_ns;
		bpf_spin_lock(&queue_lock);
		bpf_list_push_front(&packet_queue, &packet->node);
		bpf_spin_unlock(&queue_lock);
		bpf_qdisc_watchdog_schedule(sch, expire, 0);
		return NULL;
	}

	packet_len = packet->packet_len;
	skb = bpf_kptr_xchg(&packet->skb, skb);
	bpf_spin_lock(&queue_lock);
	sch->q.qlen--;
	sch->qstats.backlog -= packet_len;
	bpf_spin_unlock(&queue_lock);
	bpf_obj_drop(packet);

	if (!skb)
		return NULL;

	bpf_qdisc_bstats_update(sch, skb);
	__sync_fetch_and_add(&stats.dequeued, 1);
	__sync_fetch_and_add(&stats.bytes_dequeued, packet_len);
	return skb;
}
```

内核通过 qdisc watchdog（`bpf_qdisc_watchdog_schedule`）在队首报文满足发送条件时重试 dequeue。BPF 程序因此无需忙轮询即可完成整形。

### BPF qdisc：reset

移除 qdisc 时，`reset` 回调排空所有残留的 skb，释放 `packet_node` 对象，将 qlen/backlog 归零。在此阶段释放的报文计入 `cleanup_dropped`，区别于正常运行期间的策略丢弃。

### 用户态生命周期

加载器（`egress_pacer.c`）按以下流程执行：

1. 解析参数，将接口名转换为 ifindex。
2. 打开 BPF skeleton，设置 `rodata->rate_kbps` 和 `rodata->queue_limit`。
3. 加载 BPF 对象（验证器在此运行）。
4. attach struct_ops map，将 `bpf_pacer` 注册为可用的 qdisc 类型。
5. 通过 `bpf_tc_hook_create`（带 `BPF_TC_QDISC` 和 `TC_H_ROOT`）在接口 root 创建 qdisc。若接口已有 root qdisc，返回 `-EEXIST`，工具输出拒绝信息并退出。
6. 打印 `READY`，以 100 ms 间隔休眠直到持续时间到期或信号到达。
7. 通过 `bpf_tc_hook_destroy` 销毁 qdisc，读取最终 BSS 计数器，打印 `SUMMARY`，销毁 skeleton。

程序为 SIGINT 和 SIGTERM 注册了同一个信号处理器。处理器设置标志位来中断休眠循环。集成测试覆盖按时长正常退出和 SIGTERM 清理，但没有单独执行 SIGINT 路径。

### 统计字段

内核 BSS 中的 `pacer_stats` 结构体包含：

| 字段 | 含义 |
|------|------|
| `enqueued` | 成功入队的报文数 |
| `dequeued` | 已发送的报文数 |
| `policy_dropped` | 队列满或节点分配失败时丢弃的报文数 |
| `cleanup_dropped` | reset 阶段排空的报文数 |
| `bytes_dequeued` | 已发送报文的总字节数 |
| `max_qlen` | 队列峰值占用 |

加载器在销毁 qdisc 后从 `skel->bss->stats` 读取这些字段。

## 运行要求

- Linux 内核 6.16 及以上。BPF qdisc 支持通过[此提交](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)合入。
- libbpf 1.6.0 及以上用于 BPF qdisc TC hook 支持（[libbpf 提交](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)）。仓库在 `src/third_party` 下集成 libbpf 和 bpftool。
- 架构：x86_64（已测试）。
- 工具需要 root 权限加载 BPF，以及创建或销毁 qdisc。
- 集成测试需要 root 权限、Python 3、原始报文套接字和 `iproute2`（`ip` 与 `tc`）。
- 显式恢复路径需要 `tc`。
- 需要开启 BTF 和 BPF JIT。
- 内核配置：`CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_NET_SCHED=y`、`CONFIG_NET_SCH_BPF=y`。
- 需要受控网络接口，veth 对即可满足。

## 限制

- 单一聚合 FIFO。没有公平调度、每流隔离、每 cgroup 策略、分类、优先级、ECN、突发预算或拥塞控制集成。
- 队列限制以报文数计量，速率计算使用 `qdisc_skb_cb(skb)->pkt_len`。
- 空闲后的第一个报文可以立即发出。
- 速率和队列限制在一次调用中固定不变。
- 由于全局队列和 BSS 状态，每个加载器进程只能运行一个 root qdisc 实例。
- 拒绝所有已存在的 root qdisc，不检查、不保留、不堆叠、不恢复。
- 有限时间的 CLI 工具，不是守护进程、控制器、指标导出器或持久策略管理器。
- 程序按时长正常退出和处理 SIGTERM 时的清理路径已经过测试。SIGINT 使用同一处理器，但没有单独执行。在测试客户机上，SIGKILL 会留下已安装的 qdisc。不可捕获的信号或进程异常终止后不保证完成清理，因此需要检查接口并执行下文的恢复命令。宿主机崩溃和重启行为未经过测试。
- KVM 测试验证行为正确性，不是吞吐量或精度基准测试，不考虑驱动/硬件卸载、GSO/TSO 或真实网卡时序。

## 恢复

异常退出后，验证 qdisc 状态：

```bash
tc qdisc show dev IFACE
```

如果 `bpf_pacer` 仍存在于受控接口上，移除它：

```bash
sudo tc qdisc del dev IFACE root
```

此操作会改变接口的流量调度。只在你控制的接口上执行。

## 参考资料

- [Linux BPF qdisc 合入提交](https://github.com/torvalds/linux/commit/c8240344956e3f0b4e8f1d40ec3435e47040cacb)
- [Qdisc watchdog 后续提交](https://github.com/torvalds/linux/commit/7a2dafda950b78611dc441c83d105dfdc7082681)
- [libbpf qdisc TC hook 支持](https://github.com/libbpf/libbpf/commit/f580871b429c550edf910a1b0d700510245351df)
- [上游 BPF FIFO qdisc 自测程序](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c)
- [上游 BPF qdisc 测试运行器](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/bpf_qdisc.c)
- [libbpf 1.7.0 发布](https://github.com/libbpf/libbpf/releases/tag/v1.7.0)

## 更多内容

现在，你可以在受控接口上安装短期有界 pacer，观察队列和丢包计数，拒绝不安全的 root qdisc 替换，并在异常退出后恢复接口。本示例是 eBPF 开发者教程的一部分。更多示例和完整教程请访问：

- <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- <https://eunomia.dev/tutorials/>
