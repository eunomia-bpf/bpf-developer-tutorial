# eBPF 入门实践教程：使用 eBPF 进行 tc 流量控制

## tc 程序示例

```c
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
```

这段代码定义了一个 eBPF 程序，它可以通过 Linux TC（Transmission Control）来捕获数据包并进行处理。在这个程序中，我们限定了只捕获 IPv4 协议的数据包，然后通过 bpf_printk 函数打印出数据包的总长度和 Time-To-Live（TTL）字段的值。

需要注意的是，我们在代码中使用了一些 BPF 库函数，例如 bpf_htons 和 bpf_ntohs 函数，它们用于进行网络字节序和主机字节序之间的转换。此外，我们还使用了一些注释来为 TC 提供附加点和选项信息。例如，在这段代码的开头，我们使用了以下注释：

```c
/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
```

这些注释告诉 TC 将 eBPF 程序附加到网络接口的 ingress 附加点，并指定了 handle 和 priority 选项的值。

总之，这段代码实现了一个简单的 eBPF 程序，用于捕获数据包并打印出它们的信息。

## 编译运行

```console
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

or compile with `ecc`:

```console
$ ecc tc.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

```shell
$ sudo ecli ./package.json
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.
......
```

The `tc` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

## 总结

TODO
