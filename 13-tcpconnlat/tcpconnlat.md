# eBPF 入门实践教程：编写 eBPF 程序 tcpconnlat 测量 tcp 连接延时

## 代码解释

### 背景

在互联网后端日常开发接口的时候中，不管你使用的是C、Java、PHP还是Golang，都避免不了需要调用mysql、redis等组件来获取数据，可能还需要执行一些rpc远程调用，或者再调用一些其它restful api。 在这些调用的底层，基本都是在使用TCP协议进行传输。这是因为在传输层协议中，TCP协议具备可靠的连接，错误重传，拥塞控制等优点，所以目前应用比UDP更广泛一些。但相对而言，tcp 连接也有一些缺点，例如建立连接的延时较长等。因此也会出现像 QUIC ，即 快速UDP网络连接 ( Quick UDP Internet Connections )这样的替代方案。

tcp 连接延时分析对于网络性能分析优化或者故障排查都能起到不少作用。

### tcpconnlat 的实现原理

tcpconnlat 这个工具跟踪执行活动TCP连接的内核函数 (例如，通过connect()系统调用），并显示本地测量的连接的延迟（时间），即从发送 SYN 到响应包的时间。

### tcp 连接原理

tcp 连接的整个过程如图所示：

![tcpconnlate](tcpconnlat1.png)

在这个连接过程中，我们来简单分析一下每一步的耗时：

1. 客户端发出SYNC包：客户端一般是通过connect系统调用来发出 SYN 的，这里牵涉到本机的系统调用和软中断的 CPU 耗时开销
2. SYN传到服务器：SYN从客户端网卡被发出，这是一次长途远距离的网络传输
3. 服务器处理SYN包：内核通过软中断来收包，然后放到半连接队列中，然后再发出SYN/ACK响应。主要是 CPU 耗时开销
4. SYC/ACK传到客户端：长途网络跋涉
5. 客户端处理 SYN/ACK：客户端内核收包并处理SYN后，经过几us的CPU处理，接着发出 ACK。同样是软中断处理开销
6. ACK传到服务器：长途网络跋涉
7. 服务端收到ACK：服务器端内核收到并处理ACK，然后把对应的连接从半连接队列中取出来，然后放到全连接队列中。一次软中断CPU开销
8. 服务器端用户进程唤醒：正在被accpet系统调用阻塞的用户进程被唤醒，然后从全连接队列中取出来已经建立好的连接。一次上下文切换的CPU开销

在客户端视角，在正常情况下一次TCP连接总的耗时也就就大约是一次网络RTT的耗时。但在某些情况下，可能会导致连接时的网络传输耗时上涨、CPU处理开销增加、甚至是连接失败。这种时候在发现延时过长之后，就可以结合其他信息进行分析。

### ebpf 实现原理

在 TCP 三次握手的时候，Linux 内核会维护两个队列，分别是：

- 半连接队列，也称 SYN 队列；
- 全连接队列，也称 accepet 队列；

服务端收到客户端发起的 SYN 请求后，内核会把该连接存储到半连接队列，并向客户端响应 SYN+ACK，接着客户端会返回 ACK，服务端收到第三次握手的 ACK 后，内核会把连接从半连接队列移除，然后创建新的完全的连接，并将其添加到 accept 队列，等待进程调用 accept 函数时把连接取出来。

我们的 ebpf 代码实现在 <https://github.com/yunwei37/Eunomia/blob/master/bpftools/tcpconnlat/tcpconnlat.bpf.c> 中：

它主要使用了 trace_tcp_rcv_state_process 和 kprobe/tcp_v4_connect 这样的跟踪点：

```c

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
 return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
 return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
 return handle_tcp_rcv_state_process(ctx, sk);
}
```

在 trace_connect 中，我们跟踪新的 tcp 连接，记录到达时间，并且把它加入 map 中：

```c
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, 4096);
 __type(key, struct sock *);
 __type(value, struct piddata);
} start SEC(".maps");

static int trace_connect(struct sock *sk)
{
 u32 tgid = bpf_get_current_pid_tgid() >> 32;
 struct piddata piddata = {};

 if (targ_tgid && targ_tgid != tgid)
  return 0;

 bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
 piddata.ts = bpf_ktime_get_ns();
 piddata.tgid = tgid;
 bpf_map_update_elem(&start, &sk, &piddata, 0);
 return 0;
}
```

在 handle_tcp_rcv_state_process 中，我们跟踪接收到的 tcp 数据包，从 map 从提取出对应的 connect 事件，并且计算延迟：

```c
static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
 struct piddata *piddatap;
 struct event event = {};
 s64 delta;
 u64 ts;

 if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
  return 0;

 piddatap = bpf_map_lookup_elem(&start, &sk);
 if (!piddatap)
  return 0;

 ts = bpf_ktime_get_ns();
 delta = (s64)(ts - piddatap->ts);
 if (delta < 0)
  goto cleanup;

 event.delta_us = delta / 1000U;
 if (targ_min_us && event.delta_us < targ_min_us)
  goto cleanup;
 __builtin_memcpy(&event.comm, piddatap->comm,
   sizeof(event.comm));
 event.ts_us = ts / 1000;
 event.tgid = piddatap->tgid;
 event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
 event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
 event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
 if (event.af == AF_INET) {
  event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
 } else {
  BPF_CORE_READ_INTO(&event.saddr_v6, sk,
    __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  BPF_CORE_READ_INTO(&event.daddr_v6, sk,
    __sk_common.skc_v6_daddr.in6_u.u6_addr32);
 }
 bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
   &event, sizeof(event));

cleanup:
 bpf_map_delete_elem(&start, &sk);
 return 0;
}
```

### Eunomia 测试 demo

使用命令行进行追踪：

```bash
$ sudo build/bin/Release/eunomia run tcpconnlat
[sudo] password for yunwei: 
[2022-08-07 02:13:39.601] [info] eunomia run in cmd...
[2022-08-07 02:13:40.534] [info] press 'Ctrl C' key to exit...
PID    COMM        IP  SRC              DEST             PORT  LAT(ms) CONATINER/OS
3477   openresty    4  172.19.0.7       172.19.0.5       2379  0.05    docker-apisix_apisix_1
3483   openresty    4  172.19.0.7       172.19.0.5       2379  0.08    docker-apisix_apisix_1
3477   openresty    4  172.19.0.7       172.19.0.5       2379  0.04    docker-apisix_apisix_1
3478   openresty    4  172.19.0.7       172.19.0.5       2379  0.05    docker-apisix_apisix_1
3478   openresty    4  172.19.0.7       172.19.0.5       2379  0.03    docker-apisix_apisix_1
3478   openresty    4  172.19.0.7       172.19.0.5       2379  0.03    docker-apisix_apisix_1
```

还可以使用 eunomia 作为 prometheus exporter，在运行上述命令之后，打开 prometheus 自带的可视化面板：

使用下述查询命令即可看到延时的统计图表：

```plain
  rate(eunomia_observed_tcpconnlat_v4_histogram_sum[5m])
/
  rate(eunomia_observed_tcpconnlat_v4_histogram_count[5m])
```

结果：

![result](tcpconnlat_p.png)

### 总结

通过上面的实验，我们可以看到，tcpconnlat 工具的实现原理是基于内核的TCP连接的跟踪，并且可以跟踪到 tcp 连接的延迟时间；除了命令行使用方式之外，还可以将其和容器、k8s 等元信息综合起来，通过 `prometheus` 和 `grafana` 等工具进行网络性能分析。

> `Eunomia` 是一个使用 C/C++ 开发的基于 eBPF的轻量级，高性能云原生监控工具，旨在帮助用户了解容器的各项行为、监控可疑的容器安全事件，力求提供覆盖容器全生命周期的轻量级开源监控解决方案。它使用 `Linux` `eBPF` 技术在运行时跟踪您的系统和应用程序，并分析收集的事件以检测可疑的行为模式。目前，它包含性能分析、容器集群网络可视化分析*、容器安全感知告警、一键部署、持久化存储监控等功能，提供了多样化的 ebpf 追踪点。其核心导出器/命令行工具最小仅需要约 4MB 大小的二进制程序，即可在支持的 Linux 内核上启动。

项目地址：<https://github.com/yunwei37/Eunomia>

### 参考资料

1. <http://kerneltravel.net/blog/2020/tcpconnlat/>
2. <https://network.51cto.com/article/640631.html>
