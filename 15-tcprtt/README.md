## eBPF 入门实践教程：编写 eBPF 程序 Tcprtt 测量 TCP 连接的往返时间

### 背景
网络质量在互联网社会中是一个很重要的因素。导致网络质量差的因素有很多，可能是硬件因素导致，也可能是程序
写的不好导致。为了能更好地定位网络问题，`tcprtt` 工具被提出。它可以监测TCP链接的往返时间，从而分析
网络质量，帮助用户定位问题来源。

### 实现原理
`tcprtt` 在tcp链接建立的执行点下挂载了执行函数。
```c
SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;
	u32 srtt;

	if (targ_sport && targ_sport != inet->inet_sport)
		return 0;
	if (targ_dport && targ_dport != sk->__sk_common.skc_dport)
		return 0;
	if (targ_saddr && targ_saddr != inet->inet_saddr)
		return 0;
	if (targ_daddr && targ_daddr != sk->__sk_common.skc_daddr)
		return 0;

	if (targ_laddr_hist)
		key = inet->inet_saddr;
	else if (targ_raddr_hist)
		key = inet->sk.__sk_common.skc_daddr;
	else
		key = 0;
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	u32 srtt, saddr, daddr;
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;

	if (targ_sport) {
		u16 sport;
		bpf_probe_read_kernel(&sport, sizeof(sport), &inet->inet_sport);
		if (targ_sport != sport)
			return 0;
	}
	if (targ_dport) {
		u16 dport;
		bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
		if (targ_dport != dport)
			return 0;
	}
	bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
	if (targ_saddr && targ_saddr != saddr)
		return 0;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
	if (targ_daddr && targ_daddr != daddr)
		return 0;

	if (targ_laddr_hist)
		key = saddr;
	else if (targ_raddr_hist)
		key = daddr;
	else
		key = 0;
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;
	ts = (struct tcp_sock *)(sk);
	bpf_probe_read_kernel(&srtt, sizeof(srtt), &ts->srtt_us);
	srtt >>= 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

```
当有tcp链接建立时，该工具会自动根据当前系统的支持情况，选择合适的执行函数。
在执行函数中，`tcprtt`会收集tcp链接的各项基本底薪，包括地址，源端口，目标端口，耗时
等等，并将其更新到直方图的map中。运行结束后通过用户态代码，展现给用户。

### Eunomia中使用方式


### 总结

`tcprtt` 通过直方图的形式，可以轻松展现当前系统中网络抖动的情况，方便开发者快速定位系统网络问题