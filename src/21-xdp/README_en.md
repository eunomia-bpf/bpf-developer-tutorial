# eBPF Tutorial by Example 21: Programmable Packet Processing with XDP

## Background

XDP (eXpress Data Path) is an emerging scheme in the Linux kernel for programmable packet processing that bypasses the kernel. Compared to cBPF, XDP operates at a much lower level, residing within the network device driver's soft interrupt processing, even before the allocation of the `skb_buff` structure. Thus, eBPF programs mounted on XDP are suitable for many simple yet frequent packet processing operations (like defending against DoS attacks), achieving high performance (24Mpps/core).

## Overview of XDP

XDP isn't the first system supporting programmable packet processing. Before it, kernel-bypass solutions like DPDK (Data Plane Development Kit) could even achieve higher performance. The idea behind such solutions is to completely bypass the kernel and let user-level network applications take over network devices, eliminating the overhead of transitioning between user and kernel mode. However, this approach has inherent drawbacks:

+ Inability to integrate with mature network modules in the kernel, necessitating reimplementation in user space.
+ Breaking the kernel's security boundary, rendering many kernel-provided networking tools unusable.
+ When interacting with conventional sockets, packets must be reinjected into the kernel from user space.
+ Requires dedicating one or more separate CPUs for packet processing.

Additionally, using kernel modules and hook points in the kernel's network protocol stack is another approach. However, the former entails extensive kernel modifications with high error costs, while the latter, due to its position in the whole packet processing workflow, isn't as efficient.

In summary, XDP + eBPF presents a more robust approach for programmable packet processing. It balances the strengths and weaknesses of the aforementioned solutions, achieving high performance without altering the kernel's packet processing workflow too much. Moreover, the eBPF virtual machine isolates and constrains user-defined packet processing routines, enhancing security.

## Writing an eBPF Program

```C
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    bpf_printk("packet size is %d", pkt_sz);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
```

This is a kernel-side eBPF code written in C. It captures all packets passing through the target network device using XDP, calculates their size, and outputs it to `trace_pipe`.

It's worth noting the following annotations in the code:

```C
/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}
```

This functionality is provided by eunomia-bpf, which allows these annotations to inform the eunomia-bpf loader about the desired target network device number, mounting flags, and options for this XDP program.

These variables are based on the API provided by libbpf. Detailed information about the interface can be viewed [here](https://patchwork.kernel.org/project/netdevbpf/patch/20220120061422.2710637-2-andrii@kernel.org/#24705508).

The `SEC("xdp")` macro indicates the type of the BPF program, while `ctx` is the execution context of this BPF program for packet processing.

At the end of the program, we return `XDP_PASS`, signaling that our XDP program will deliver packets passing through the target network device to the kernel's network protocol stack as usual. For more on XDP actions, see [XDP actions](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/implementation/xdp_actions.html).

## Compilation and Execution

To compile using a container:

```console
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile with `ecc`:

```console
$ ecc xdp.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then, run with `ecli`:

```console
sudo ecli run package.json
```

To view the program's output:

```console
$ sudo cat /sys/kernel/tracing/trace_pipe
            node-1939    [000] d.s11  1601.190413: bpf_trace_printk: packet size is 177
            node-1939    [000] d.s11  1601.190479: bpf_trace_printk: packet size is 66
     ksoftirqd/1-19      [001] d.s.1  1601.237507: bpf_trace_printk: packet size is 66
            node-1939    [000] d.s11  1601.275860: bpf_trace_printk: packet size is 344
```

## Conclusion

This article introduces how to use XDP to process packets passing through a specific network device. With eunomia-bpf's annotation-based approach for passing parameters to libbpf, we can mount our custom XDP BPF program onto the target device with specified options. This allows packet processing even before they enter the kernel's network protocol stack, achieving high-performance programmable packet processing.

For those interested in further exploring eBPF, visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and a comprehensive guide.

## References

For more information, you can refer to:

+ <http://arthurchiao.art/blog/xdp-paper-acm-2018-zh/>
+ <http://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/>
+ <https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass>

> The original link of this article: <https://eunomia.dev/tutorials/21-xdp>
