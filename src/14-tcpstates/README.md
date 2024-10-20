# eBPF Tutorial by Example 14: Recording TCP Connection Status and TCP RTT

eBPF (Extended Berkeley Packet Filter) is a powerful network and performance analysis tool widely used in the Linux kernel. eBPF allows developers to dynamically load, update, and run user-defined code without restarting the kernel or changing the kernel source code.

In this article of our eBPF Tutorial by Example series, we will introduce two sample programs: `tcpstates` and `tcprtt`. `tcpstates` is used to record the state changes of TCP connections, while `tcprtt` is used to record the Round-Trip Time (RTT) of TCP.

## `tcprtt` and `tcpstates`

Network quality is crucial in the current Internet environment. There are many factors that affect network quality, including hardware, network environment, and the quality of software programming. To help users better locate network issues, we introduce the tool `tcprtt`. `tcprtt` can monitor the Round-Trip Time of TCP connections, evaluate network quality, and help users identify potential problems.

When a TCP connection is established, `tcprtt` automatically selects the appropriate execution function based on the current system conditions. In the execution function, `tcprtt` collects various basic information of the TCP connection, such as source address, destination address, source port, destination port, and time elapsed, and updates this information to a histogram-like BPF map. After the execution is completed, `tcprtt` presents the collected information graphically to users through user-mode code.

`tcpstates` is a tool specifically designed to track and print changes in TCP connection status. It can display the duration of TCP connections in each state, measured in milliseconds. For example, for a single TCP session, `tcpstates` can print output similar to the following:

```sh
SKADDR           C-PID C-COMM     LADDR           LPORT RADDR           RPORT OLDSTATE    -> NEWSTATE    MS
ffff9fd7e8192000 22384 curl       100.66.100.185  0     52.33.159.26    80    CLOSE       -> SYN_SENT    0.000
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    SYN_SENT    -> ESTABLISHED 1.373
ffff9fd7e8192000 22384 curl       100.66.100.185  63446 52.33.159.26    80    ESTABLISHED -> FIN_WAIT1   176.042
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT1   -> FIN_WAIT2   0.536
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT2   -> CLOSE       0.006
```

In the above output, the most time is spent in the ESTABLISHED state, which indicates that the connection has been established and data transmission is in progress. The transition from this state to the FIN_WAIT1 state (the beginning of connection closure) took 176.042 milliseconds.

In our upcoming tutorials, we will delve deeper into these two tools, explaining their implementation principles, and hopefully, these contents will help you in your work with eBPF for network and performance analysis.

## tcpstate eBPF code

Due to space constraints, here we mainly discuss and analyze the corresponding eBPF kernel-mode code implementation. The following is the eBPF code for tcpstate:

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
    ...
```__type(key, __u16);
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

The `tcpstates` program relies on eBPF Tracepoints to capture the state changes of TCP connections, in order to track the time spent in each state of the TCP connection.

### Define BPF Maps

In the `tcpstates` program, several BPF Maps are defined, which are the primary way of interaction between the eBPF program and the user-space program. `sports` and `dports` are used to store the source and destination ports for filtering TCP connections; `timestamps` is used to store the timestamps for each TCP connection to calculate the time spent in each state; `events` is a map of type `perf_event`, used to send event data to the user-space.

### Trace TCP Connection State Changes

The program defines a function called `handle_set_state`, which is a program of type tracepoint and is mounted on the `sock/inet_sock_set_state` kernel tracepoint. Whenever the TCP connection state changes, this tracepoint is triggered and the `handle_set_state` function is executed.

In the `handle_set_state` function, it first determines whether the current TCP connection needs to be processed through a series of conditional judgments, then retrieves the previous timestamp of the current connection from the `timestamps` map, and calculates the time spent in the current state. Then, the program places the collected data in an event structure and sends the event to the user-space using the `bpf_perf_event_output` function.

### Update Timestamps

Finally, based on the new state of the TCP connection, the program performs different operations: if the new state is TCP_CLOSE, it means the connection has been closed and the program deletes the timestamp of that connection from the `timestamps` map; otherwise, the program updates the timestamp of the connection.

## User-Space Processing for tcpstate

The user-space part is mainly about loading the eBPF program using libbpf and receiving event data from the kernel using perf_event:

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
    ...
```

handle_event` is a callback function that is called by perf_event. It handles new events that arrive in the kernel.

In the `handle_event` function, we first use the `inet_ntop` function to convert the binary IP address to a human-readable format. Then, based on whether the wide format is needed or not, we print different information. This information includes the timestamp of the event, source IP address, source port, destination IP address, destination port, old state, new state, and the time spent in the old state.

This allows users to see the changes in TCP connection states and the duration of each state, helping them diagnose network issues.

In summary, the user-space part of the processing involves the following steps:

1. Use libbpf to load and run the eBPF program.
2. Set up a callback function to receive events sent by the kernel.
3. Process the received events, convert them into a human-readable format, and print them.

The above is the main implementation logic of the user-space part of the `tcpstates` program. Through this chapter, you should have gained a deeper understanding of how to handle kernel events in user space. In the next chapter, we will introduce more knowledge about using eBPF for network monitoring.

### tcprtt kernel eBPF code

In this section, we will analyze the kernel BPF code of the `tcprtt` eBPF program. `tcprtt` is a program used to measure TCP Round Trip Time (RTT) and stores the RTT information in a histogram.

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

The code above declares a map called `hists`, which is a hash map used to store the histogram data. The `hists` map has a maximum number of entries defined as `MAX_ENTRIES`.

The function `BPF_PROG(tcp_rcv, struct sock *sk)` is the entry point of the eBPF program for handling the `tcp_rcv_established` event. Within this function, the program retrieves various information from the network socket and checks if filtering conditions are met. Then, it performs operations on the histogram data structure. Finally, the program calculates the slot for the RTT value and updates the histogram accordingly.

This is the main code logic of the `tcprtt` eBPF program in kernel mode. The eBPF program measures the RTT of TCP connections and maintains a histogram to collect and analyze the RTT data.Instructions:

First, we define a hash type eBPF map called `hists`, which is used to store statistics information about RTT. In this map, the key is a 64-bit integer, and the value is a `hist` structure that contains an array to store the count of different RTT intervals.

Next, we define an eBPF program called `tcp_rcv` which will be called every time a TCP packet is received in the kernel. In this program, we first filter TCP connections based on filtering conditions (source/destination IP address and port). If the conditions are met, we select the corresponding key (source IP, destination IP, or 0) based on the set parameters, and then look up or initialize the corresponding histogram in the `hists` map.

Then, we read the `srtt_us` field of the TCP connection, which represents the smoothed RTT value in microseconds. We convert this RTT value to a logarithmic form and store it as a slot in the histogram.

If the `show_ext` parameter is set, we also increment the RTT value and the counter in the `latency` and `cnt` fields of the histogram.

With the above processing, we can analyze and track the RTT of each TCP connection to better understand the network performance.

In summary, the main logic of the `tcprtt` eBPF program includes the following steps:

1. Filter TCP connections based on filtering conditions.
2. Look up or initialize the corresponding histogram in the `hists` map.
3. Read the `srtt_us` field of the TCP connection, convert it to a logarithmic form, and store it in the histogram.
4. If the `show_ext` parameter is set, increment the RTT value and the counter in the `latency` and `cnt` fields of the histogram.

`tcprtt` is attached to the kernel's `tcp_rcv_established` function:

```c
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb);
```

This function is the main function in the kernel for processing received TCP data and is called when a TCP connection is in the `ESTABLISHED` state. The processing logic of this function includes a fast path and a slow path. The fast path is disabled in the following cases:

- We have advertised a zero window - zero window probing can only be handled correctly in the slow path.
- Out-of-order data packets received.
- Expecting to receive urgent data.
- No remaining buffer space.
- Received unexpected TCP flags/window values/header lengths (detected by checking TCP header against the expected flags).
- Data is being transmitted in both directions. The fast path only supports pure senders or pure receivers (meaning the sequence number or acknowledgement value must remain unchanged).
- Received unexpected TCP options.

When these conditions are not met, it enters a standard receive processing, which follows RFC 793 to handle all cases. The first three cases can be ensured by setting the correct expected flags, while the remaining cases require inline checks. When everything is normal, the fast processing path is invoked in the `tcp_data_queue` function.

## Compilation and Execution

For `tcpstates`, you can compile and run the libbpf application with the following command:

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
ffff9bf61bb62bc0 0       swapper/0  192.168.88.15   41596 52.178.17.2     443   SYN_SENT    -> ESTABLISHED 225.794".
"ffff9bf61bb62bc0 0       swapper/0  192.168.88.15   41596 52.178.17.2     443   ESTABLISHED -> CLOSE_WAIT  901.454
ffff9bf61bb62bc0 164978  node       192.168.88.15   41596 52.178.17.2     443   CLOSE_WAIT  -> LAST_ACK    0.793
ffff9bf61bb62bc0 164978  node       192.168.88.15   41596 52.178.17.2     443   LAST_ACK    -> LAST_ACK    0.086
ffff9bf61bb62bc0 228759  kworker/u6 192.168.88.15   41596 52.178.17.2     443   LAST_ACK    -> CLOSE       0.193
ffff9bf6d8ee88c0 229832  redis-serv 0.0.0.0         6379  0.0.0.0         0     CLOSE       -> LISTEN      0.000
ffff9bf6d8ee88c0 229832  redis-serv 0.0.0.0         6379  0.0.0.0         0     LISTEN      -> CLOSE       1.763
ffff9bf7109d6900 88750   node       127.0.0.1       39755 127.0.0.1       50966 ESTABLISHED -> FIN_WAIT1   0.000
```

For tcprtt, we can use eunomia-bpf to compile and run this example:

Compile:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or

```console
$ ecc tcprtt.bpf.c tcprtt.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

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

Built with eunomia-bpf framework.".
```See https://github.com/eunomia-bpf/eunomia-bpf for more information.

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
       256 -> 511        : 0        |                                        |512 -> 1023       : 11       |***************************             |
      1024 -> 2047       : 1        |**                                      |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 16       |****************************************|
      8192 -> 16383      : 4        |**********                              |
```

Complete source code:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/14-tcpstates>

References:

- [tcpstates](https://github.com/iovisor/bcc/blob/master/tools/tcpstates_example.txt)
- [tcprtt](https://github.com/iovisor/bcc/blob/master/tools/tcprtt.py)
- [libbpf-tools/tcpstates](<https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpstates.bpf.c>)

## Summary

In this eBPF introductory tutorial, we learned how to use the tcpstates and tcprtt eBPF example programs to monitor and analyze the connection states and round-trip time of TCP. We understood the working principles and implementation methods of tcpstates and tcprtt, including how to store data using BPF maps, how to retrieve and process TCP connection information in eBPF programs, and how to parse and display the data collected by eBPF programs in user-space applications.

If you would like to learn more about eBPF knowledge and practices, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete tutorials. The upcoming tutorials will further explore advanced features of eBPF, and we will continue to share more content about eBPF development practices.

> The original link of this article: <https://eunomia.dev/tutorials/14-tcpstates>
