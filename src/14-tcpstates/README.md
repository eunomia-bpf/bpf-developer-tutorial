# eBPF入门实践教程十四：记录 TCP 连接状态与 TCP RTT

eBPF (扩展的伯克利数据包过滤器) 是一项强大的网络和性能分析工具，被广泛应用在 Linux 内核上。eBPF 使得开发者能够动态地加载、更新和运行用户定义的代码，而无需重启内核或更改内核源代码。

在我们的 eBPF 入门实践教程系列的这一篇，我们将介绍两个示例程序：`tcpstates` 和 `tcprtt`。`tcpstates` 用于记录 TCP 连接的状态变化，而 `tcprtt` 则用于记录 TCP 的往返时间 (RTT, Round-Trip Time)。

## `tcprtt` 与 `tcpstates`

网络质量在当前的互联网环境中至关重要。影响网络质量的因素有许多，包括硬件、网络环境、软件编程的质量等。为了帮助用户更好地定位网络问题，我们引入了 `tcprtt` 这个工具。`tcprtt` 可以监控 TCP 链接的往返时间，从而评估网络质量，帮助用户找出可能的问题所在。

当 TCP 链接建立时，`tcprtt` 会自动根据当前系统的状况，选择合适的执行函数。在执行函数中，`tcprtt` 会收集 TCP 链接的各项基本信息，如源地址、目标地址、源端口、目标端口、耗时等，并将这些信息更新到直方图型的 BPF map 中。运行结束后，`tcprtt` 会通过用户态代码，将收集的信息以图形化的方式展示给用户。

`tcpstates` 则是一个专门用来追踪和打印 TCP 连接状态变化的工具。它可以显示 TCP 连接在每个状态中的停留时长，单位为毫秒。例如，对于一个单独的 TCP 会话，`tcpstates` 可以打印出类似以下的输出：

```sh
SKADDR           C-PID C-COMM     LADDR           LPORT RADDR           RPORT OLDSTATE    -> NEWSTATE    MS
ffff9fd7e8192000 22384 curl       100.66.100.185  0     52.33.159.26    80    CLOSE       -> SYN_SENT    0.000
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    SYN_SENT    -> ESTABLISHED 1.373
ffff9fd7e8192000 22384 curl       100.66.100.185  63446 52.33.159.26    80    ESTABLISHED -> FIN_WAIT1   176.042
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT1   -> FIN_WAIT2   0.536
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT2   -> CLOSE       0.006
```

以上输出中，最多的时间被花在了 ESTABLISHED 状态，也就是连接已经建立并在传输数据的状态，这个状态到 FIN_WAIT1 状态（开始关闭连接的状态）的转变过程中耗费了 176.042 毫秒。

在我们接下来的教程中，我们会更深入地探讨这两个工具，解释它们的实现原理，希望这些内容对你在使用 eBPF 进行网络和性能分析方面的工作有所帮助。

## tcpstate

由于篇幅所限，这里我们主要讨论和分析对应的 eBPF 内核态代码实现。以下是 tcpstate 的 eBPF 代码：

```c
const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;
const volatile short target_family = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} sports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} dports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, __u64);
} timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    __u16 family = ctx->family;
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    __u64 *tsp, delta_us, ts;
    struct event event = {};

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (target_family && target_family != family)
        return 0;

    if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
        return 0;

    if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
        return 0;

    tsp = bpf_map_lookup_elem(&timestamps, &sk);
    ts = bpf_ktime_get_ns();
    if (!tsp)
        delta_us = 0;
    else
        delta_us = (ts - *tsp) / 1000;

    event.skaddr = (__u64)sk;
    event.ts_us = ts / 1000;
    event.delta_us = delta_us;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.oldstate = ctx->oldstate;
    event.newstate = ctx->newstate;
    event.family = family;
    event.sport = sport;
    event.dport = dport;
    bpf_get_current_comm(&event.task, sizeof(event.task));

    if (family == AF_INET) {
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    } else { /* family == AF_INET6 */
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&timestamps, &sk);
    else
        bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

    return 0;
}
```

`tcpstates`主要依赖于 eBPF 的 Tracepoints 来捕获 TCP 连接的状态变化，从而跟踪 TCP 连接在每个状态下的停留时间。

### 定义 BPF Maps

在`tcpstates`程序中，首先定义了几个 BPF Maps，它们是 eBPF 程序和用户态程序之间交互的主要方式。`sports`和`dports`分别用于存储源端口和目标端口，用于过滤 TCP 连接；`timestamps`用于存储每个 TCP 连接的时间戳，以计算每个状态的停留时间；`events`则是一个 perf_event 类型的 map，用于将事件数据发送到用户态。

### 追踪 TCP 连接状态变化

程序定义了一个名为`handle_set_state`的函数，该函数是一个 tracepoint 类型的程序，它将被挂载到`sock/inet_sock_set_state`这个内核 tracepoint 上。每当 TCP 连接状态发生变化时，这个 tracepoint 就会被触发，然后执行`handle_set_state`函数。

在`handle_set_state`函数中，首先通过一系列条件判断确定是否需要处理当前的 TCP 连接，然后从`timestamps`map 中获取当前连接的上一个时间戳，然后计算出停留在当前状态的时间。接着，程序将收集到的数据放入一个 event 结构体中，并通过`bpf_perf_event_output`函数将该 event 发送到用户态。

### 更新时间戳

最后，根据 TCP 连接的新状态，程序将进行不同的操作：如果新状态为 TCP_CLOSE，表示连接已关闭，程序将从`timestamps`map 中删除该连接的时间戳；否则，程序将更新该连接的时间戳。

用户态的部分主要是通过 libbpf 来加载 eBPF 程序，然后通过 perf_event 来接收内核中的事件数据：

```c
static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    char ts[32], saddr[26], daddr[26];
    struct event* e = data;
    struct tm* tm;
    int family;
    time_t t;

    if (emit_timestamp) {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%8s ", ts);
    }

    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));
    if (wide_output) {
        family = e->family == AF_INET ? 4 : 6;
        printf(
            "%-16llx %-7d %-16s %-2d %-26s %-5d %-26s %-5d %-11s -> %-11s "
            "%.3f\n",
            e->skaddr, e->pid, e->task, family, saddr, e->sport, daddr,
            e->dport, tcp_states[e->oldstate], tcp_states[e->newstate],
            (double)e->delta_us / 1000);
    } else {
        printf(
            "%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
            e->skaddr, e->pid, e->task, saddr, e->sport, daddr, e->dport,
            tcp_states[e->oldstate], tcp_states[e->newstate],
            (double)e->delta_us / 1000);
    }
}
```

`handle_event`就是这样一个回调函数，它会被 perf_event 调用，每当内核有新的事件到达时，它就会处理这些事件。

在`handle_event`函数中，我们首先通过`inet_ntop`函数将二进制的 IP 地址转换成人类可读的格式，然后根据是否需要输出宽格式，分别打印不同的信息。这些信息包括了事件的时间戳、源 IP 地址、源端口、目标 IP 地址、目标端口、旧状态、新状态以及在旧状态停留的时间。

这样，用户就可以清晰地看到 TCP 连接状态的变化，以及每个状态的停留时间，从而帮助他们诊断网络问题。

总结起来，用户态部分的处理主要涉及到了以下几个步骤：

1. 使用 libbpf 加载并运行 eBPF 程序。
2. 设置回调函数来接收内核发送的事件。
3. 处理接收到的事件，将其转换成人类可读的格式并打印。

以上就是`tcpstates`程序用户态部分的主要实现逻辑。通过这一章的学习，你应该已经对如何在用户态处理内核事件有了更深入的理解。在下一章中，我们将介绍更多关于如何使用 eBPF 进行网络监控的知识。

### tcprtt

在本章节中，我们将分析`tcprtt` eBPF 程序的内核态代码。`tcprtt`是一个用于测量 TCP 往返时间(Round Trip Time, RTT)的程序，它将 RTT 的信息统计到一个 histogram 中。

```c

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

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
```

首先，我们定义了一个 hash 类型的 eBPF map，名为`hists`，它用来存储 RTT 的统计信息。在这个 map 中，键是 64 位整数，值是一个`hist`结构，这个结构包含了一个数组，用来存储不同 RTT 区间的数量。

接着，我们定义了一个 eBPF 程序，名为`tcp_rcv`，这个程序会在每次内核中处理 TCP 收包的时候被调用。在这个程序中，我们首先根据过滤条件（源/目标 IP 地址和端口）对 TCP 连接进行过滤。如果满足条件，我们会根据设置的参数选择相应的 key（源 IP 或者目标 IP 或者 0），然后在`hists` map 中查找或者初始化对应的 histogram。

接下来，我们读取 TCP 连接的`srtt_us`字段，这个字段表示了平滑的 RTT 值，单位是微秒。然后我们将这个 RTT 值转换为对数形式，并将其作为 slot 存储到 histogram 中。

如果设置了`show_ext`参数，我们还会将 RTT 值和计数器累加到 histogram 的`latency`和`cnt`字段中。

通过以上的处理，我们可以对每个 TCP 连接的 RTT 进行统计和分析，从而更好地理解网络的性能状况。

总结起来，`tcprtt` eBPF 程序的主要逻辑包括以下几个步骤：

1. 根据过滤条件对 TCP 连接进行过滤。
2. 在`hists` map 中查找或者初始化对应的 histogram。
3. 读取 TCP 连接的`srtt_us`字段，并将其转换为对数形式，存储到 histogram 中。
4. 如果设置了`show_ext`参数，将 RTT 值和计数器累加到 histogram 的`latency`和`cnt`字段中。

tcprtt 挂载到了内核态的 tcp_rcv_established 函数上：

```c
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb);
```

这个函数是在内核中处理TCP接收数据的主要函数，主要在TCP连接处于`ESTABLISHED`状态时被调用。这个函数的处理逻辑包括一个快速路径和一个慢速路径。快速路径在以下几种情况下会被禁用：

- 我们宣布了一个零窗口 - 零窗口探测只能在慢速路径中正确处理。
- 收到了乱序的数据包。
- 期待接收紧急数据。
- 没有剩余的缓冲区空间。
- 接收到了意外的TCP标志/窗口值/头部长度（通过检查TCP头部与预设标志进行检测）。
- 数据在两个方向上都在传输。快速路径只支持纯发送者或纯接收者（这意味着序列号或确认值必须保持不变）。
- 接收到了意外的TCP选项。

当这些条件不满足时，它会进入一个标准的接收处理过程，这个过程遵循RFC793来处理所有情况。前三种情况可以通过正确的预设标志设置来保证，剩下的情况则需要内联检查。当一切都正常时，快速处理过程会在`tcp_data_queue`函数中被开启。

## 编译运行

对于 tcpstates，可以通过以下命令编译和运行 libbpf 应用：

```console
$ make
...
  BPF      .output/tcpstates.bpf.o
  GEN-SKEL .output/tcpstates.skel.h
  CC       .output/tcpstates.o
  BINARY   tcpstates
$ sudo ./tcpstates 
SKADDR           PID     COMM       LADDR           LPORT RADDR           RPORT OLDSTATE    -> NEWSTATE    MS
ffff9bf61bb62bc0 164978  node       192.168.88.15   0     52.178.17.2     443   CLOSE       -> SYN_SENT    0.000
ffff9bf61bb62bc0 0       swapper/0  192.168.88.15   41596 52.178.17.2     443   SYN_SENT    -> ESTABLISHED 225.794
ffff9bf61bb62bc0 0       swapper/0  192.168.88.15   41596 52.178.17.2     443   ESTABLISHED -> CLOSE_WAIT  901.454
ffff9bf61bb62bc0 164978  node       192.168.88.15   41596 52.178.17.2     443   CLOSE_WAIT  -> LAST_ACK    0.793
ffff9bf61bb62bc0 164978  node       192.168.88.15   41596 52.178.17.2     443   LAST_ACK    -> LAST_ACK    0.086
ffff9bf61bb62bc0 228759  kworker/u6 192.168.88.15   41596 52.178.17.2     443   LAST_ACK    -> CLOSE       0.193
ffff9bf6d8ee88c0 229832  redis-serv 0.0.0.0         6379  0.0.0.0         0     CLOSE       -> LISTEN      0.000
ffff9bf6d8ee88c0 229832  redis-serv 0.0.0.0         6379  0.0.0.0         0     LISTEN      -> CLOSE       1.763
ffff9bf7109d6900 88750   node       127.0.0.1       39755 127.0.0.1       50966 ESTABLISHED -> FIN_WAIT1   0.000
```

对于 tcprtt，我们可以使用 eunomia-bpf 编译运行这个例子：

Compile:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

或者

```console
$ ecc tcprtt.bpf.c tcprtt.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

运行：

```console
$ sudo ecli run package.json -h
A simple eBPF program


Usage: package.json [OPTIONS]

Options:
      --verbose                  Whether to show libbpf debug information
      --targ_laddr_hist          Set value of `bool` variable targ_laddr_hist
      --targ_raddr_hist          Set value of `bool` variable targ_raddr_hist
      --targ_show_ext            Set value of `bool` variable targ_show_ext
      --targ_sport <targ_sport>  Set value of `__u16` variable targ_sport
      --targ_dport <targ_dport>  Set value of `__u16` variable targ_dport
      --targ_saddr <targ_saddr>  Set value of `__u32` variable targ_saddr
      --targ_daddr <targ_daddr>  Set value of `__u32` variable targ_daddr
      --targ_ms                  Set value of `bool` variable targ_ms
  -h, --help                     Print help
  -V, --version                  Print version

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.

$ sudo ecli run package.json
key =  0
latency = 0
cnt = 0

     (unit)              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 4        |********************                    |
      1024 -> 2047       : 1        |*****                                   |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 8        |****************************************|

key =  0
latency = 0
cnt = 0

     (unit)              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 11       |***************************             |
      1024 -> 2047       : 1        |**                                      |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 16       |****************************************|
      8192 -> 16383      : 4        |**********                              |
```

完整源代码：

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/14-tcpstates>

参考资料：

- [tcpstates](https://github.com/iovisor/bcc/blob/master/tools/tcpstates_example.txt)
- [tcprtt](https://github.com/iovisor/bcc/blob/master/tools/tcprtt.py)
- [libbpf-tools/tcpstates](<https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpstates.bpf.c>)

## 总结

通过本篇 eBPF 入门实践教程，我们学习了如何使用tcpstates和tcprtt这两个 eBPF 示例程序，监控和分析 TCP 的连接状态和往返时间。我们了解了tcpstates和tcprtt的工作原理和实现方式，包括如何使用 BPF map 存储数据，如何在 eBPF 程序中获取和处理 TCP 连接信息，以及如何在用户态应用程序中解析和显示 eBPF 程序收集的数据。

如果您希望学习更多关于 eBPF 的知识和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。接下来的教程将进一步探讨 eBPF 的高级特性，我们会继续分享更多有关 eBPF 开发实践的内容。
