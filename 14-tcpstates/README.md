# eBPF入门实践教程：使用 libbpf-bootstrap 开发程序统计 TCP 连接延时

```tcpstates``` 是一个追踪当前系统上的TCP套接字的TCP状态的程序，主要通过跟踪内核跟踪点 ```inet_sock_set_state``` 来实现。统计数据通过 ```perf_event```向用户态传输。

```c
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
```

在套接字改变状态处附加一个eBPF跟踪函数。

```c
 if (ctx->protocol != IPPROTO_TCP)
  return 0;

 if (target_family && target_family != family)
  return 0;

 if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
  return 0;

 if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
  return 0;
```

跟踪函数被调用后，先判断当前改变状态的套接字是否满足我们需要的过滤条件，如果不满足则不进行记录。

```c
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
```

使用状态改变相关填充event结构体。

- 此处使用了```libbpf``` 的 CO-RE 支持。

```c
 bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
```

将事件结构体发送至用户态程序。

```c
 if (ctx->newstate == TCP_CLOSE)
  bpf_map_delete_elem(&timestamps, &sk);
 else
  bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);
```

根据这个TCP链接的新状态，决定是更新下时间戳记录还是不再记录它的时间戳。

## 用户态程序

```c
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }
```

不停轮询内核程序所发过来的 ```perf event```。

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

static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}
```

收到事件后所调用对应的处理函数并进行输出打印。

## 编译运行

- ```git clone https://github.com/libbpf/libbpf-bootstrap libbpf-bootstrap-cloned```
- 将 [libbpf-bootstrap](libbpf-bootstrap)目录下的文件复制到 ```libbpf-bootstrap-cloned/examples/c```下
- 修改 ```libbpf-bootstrap-cloned/examples/c/Makefile``` ，在其 ```APPS``` 项后添加 ```tcpstates```
- 在 ```libbpf-bootstrap-cloned/examples/c``` 下运行 ```make tcpstates```
- ```sudo ./tcpstates```

## 效果

```plain
root@yutong-VirtualBox:~/libbpf-bootstrap/examples/c# ./tcpstates 
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

对于输出的详细解释，详见 [README.md](README.md)

## 总结

这里的代码修改自 <https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpstates.bpf.c>
