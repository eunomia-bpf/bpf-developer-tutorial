# eBPF sockops 示例

## 利用 eBPF 的 sockops 进行性能优化

网络连接本质上是 socket 之间的通讯，eBPF 提供了一个 [bpf_msg_redirect_hash](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) 函数，用来将应用发出的包直接转发到对端的 socket，可以极大地加速包在内核中的处理流程。

这里 sock_map 是记录 socket 规则的关键部分，即根据当前的数据包信息，从 sock_map 中挑选一个存在的 socket 连接来转发请求。所以需要先在 sockops 的 hook 处或者其它地方，将 socket 信息保存到 sock_map，并提供一个规则 (一般为四元组) 根据 key 查找到 socket。

Merbridge 项目就是这样实现了用 eBPF 代替 iptables 为 Istio 进行加速。在使用 Merbridge (eBPF) 优化之后，出入口流量会直接跳过很多内核模块，明显提高性能，如下图所示：

![merbridge](merbridge.png)

## 运行样例

此示例程序从发送者的套接字（出口）重定向流量至接收者的套接字（入口），**跳过 TCP/IP 内核网络栈**。在这个示例中，我们假定发送者和接收者都在**同一台**机器上运行。

### 编译 eBPF 程序

```shell
# Compile the bpf_sockops program
clang -O2 -g  -Wall -target bpf  -c bpf_sockops.c -o bpf_sockops.o
clang -O2 -g  -Wall -target bpf  -c bpf_redir.c -o bpf_redir.o
```

### 加载 eBPF 程序

```shell
sudo ./load.sh
```

您可以使用 [bpftool utility](https://github.com/torvalds/linux/blob/master/tools/bpf/bpftool/Documentation/bpftool-prog.rst) 检查这两个 eBPF 程序是否已经加载。

```console
$ sudo bpftool prog show
63: sock_ops  name bpf_sockmap  tag 275467be1d69253d  gpl
 loaded_at 2019-01-24T13:07:17+0200  uid 0
 xlated 1232B  jited 750B  memlock 4096B  map_ids 58
64: sk_msg  name bpf_redir  tag bc78074aa9dd96f4  gpl
 loaded_at 2019-01-24T13:07:17+0200  uid 0
 xlated 304B  jited 233B  memlock 4096B  map_ids 58
```

### 运行 [iperf3](https://iperf.fr/) 服务器

```shell
iperf3 -s -p 10000
```

### 运行 [iperf3](https://iperf.fr/) 客户端

```shell
iperf3 -c 127.0.0.1 -t 10 -l 64k -p 10000
```

### 收集追踪

```console
$ ./trace.sh
iperf3-9516  [001] .... 22500.634108: 0: <<< ipv4 op = 4, port 18583 --> 4135
iperf3-9516  [001] ..s1 22500.634137: 0: <<< ipv4 op = 5, port 4135 --> 18583
iperf3-9516  [001] .... 22500.634523: 0: <<< ipv4 op = 4, port 19095 --> 4135
iperf3-9516  [001] ..s1 22500.634536: 0: <<< ipv4 op = 5, port 4135 --> 19095
```

你应该可以看到 4 个用于套接字建立的事件。如果你没有看到任何事件，那么 eBPF 程序可能没有正确地附加上。

### 卸载 eBPF 程序

```shell
sudo ./unload.sh
```

## 参考资料

- <https://github.com/zachidan/ebpf-sockops>
- <https://github.com/merbridge/merbridge>
