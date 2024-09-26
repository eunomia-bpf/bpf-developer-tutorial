# eBPF Tutorial by Example 21: Programmable Packet Processing with XDP

In this tutorial, we will introduce XDP (eXpress Data Path) and walk through a small example to help you get started. Later on, we will explore more advanced XDP applications, such as load balancers, firewalls, and other real-world use cases. Please give us a start on [Github](https://github.com/eunomia-bpf/bpf-developer-tutorial) if you are interested in eBPF or XDP!

## What is XDP?

XDP is a high-performance, programmable data path in the Linux kernel, designed for packet processing at the network interface level. By attaching eBPF programs directly to network device drivers, XDP can intercept and handle packets before they reach the kernel’s networking stack. This allows for extremely low-latency and efficient packet processing, making it ideal for tasks like DDoS defense, load balancing, and traffic filtering. In fact, XDP can achieve throughput as high as **24 million packets per second (Mpps) per core**.

### Why XDP?

XDP operates at a lower level than traditional Linux networking components, like cBPF (Classic BPF), by running inside the soft interrupt context of the network device driver. It can handle packets before they are even processed by the kernel's standard networking stack, bypassing the creation of the `skb_buff` structure, which represents network packets in Linux. This early-stage processing provides significant performance gains for simple but frequent operations like dropping malicious packets or load balancing across servers.

Compared to other packet processing mechanisms, XDP strikes a balance between performance and usability, leveraging the security and reliability of the Linux kernel while providing flexibility through programmable eBPF.

## Overview of XDP vs. Other Approaches

Before XDP, several other solutions aimed to accelerate packet processing by bypassing the kernel entirely. One prominent example is **DPDK** (Data Plane Development Kit). DPDK allows user-space applications to take direct control of network devices, achieving very high performance. However, this approach comes with trade-offs:

1. **Lack of Kernel Integration**: DPDK and other kernel-bypass solutions cannot utilize existing kernel networking features, requiring developers to reimplement many protocols and functions in user space.

2. **Security Boundaries**: These bypass techniques break the kernel’s security model, making it harder to leverage security tools provided by the kernel.

3. **User-Kernel Transition Costs**: When user-space packet processing needs to interact with traditional kernel networking (like socket-based applications), packets must be reinjected into the kernel, adding overhead and complexity.

4. **Dedicated CPU Usage**: To handle high traffic, DPDK and similar solutions often require dedicating one or more CPU cores solely for packet processing, which limits the scalability and efficiency of general-purpose systems.

Another alternative to XDP is using **kernel modules** or **hooks** in the Linux networking stack. While this method integrates well with existing kernel features, it requires extensive kernel modifications and does not provide the same performance benefits, as it operates later in the packet processing pipeline.

### The XDP + eBPF Advantage

XDP combined with eBPF offers a middle ground between kernel-bypass solutions like DPDK and kernel-integrated solutions. Here’s why XDP + eBPF stands out:

- **High Performance**: By intercepting packets early at the NIC driver level, XDP achieves near-line rate performance for tasks like dropping, redirecting, or load balancing packets, all while keeping resource usage low.
  
- **Kernel Integration**: Unlike DPDK, XDP works within the Linux kernel, allowing seamless interaction with the existing kernel network stack and tools (such as `iptables`, `nftables`, or sockets). There’s no need to reimplement networking protocols in user space.

- **Security**: The eBPF virtual machine (VM) ensures that user-defined XDP programs are sandboxed and constrained, which means they cannot destabilize the kernel. The security model of eBPF prevents malicious or buggy code from harming the system, providing a safe environment for programmable packet processing.

- **No Dedicated CPUs Required**: XDP allows packet processing without dedicating entire CPU cores solely to network tasks. This improves the overall efficiency of the system, allowing for more flexible resource allocation.

In summary, XDP + eBPF delivers a robust solution for programmable packet processing that combines high performance with the flexibility and safety of kernel integration. It eliminates the drawbacks of full kernel-bypass solutions while retaining the benefits of kernel security and functionality.

## Projects and Use Cases with XDP

XDP is already being used in a number of high-profile projects that highlight its power and flexibility in real-world networking scenarios:

### 1. **Cilium**

- **Description**: Cilium is an open-source networking, security, and observability tool designed for cloud-native environments, especially Kubernetes. It leverages XDP to implement high-performance packet filtering and load balancing.
- **Use Case**: Cilium offloads packet filtering and security policies to XDP, enabling high-throughput and low-latency traffic management in containerized environments without sacrificing scalability.
- **Link**: [Cilium](https://cilium.io/)

### 2. **Katran**

- **Description**: Katran is a layer 4 load balancer developed by Facebook, optimized for high scalability and performance. It uses XDP to handle packet forwarding with minimal overhead.
- **Use Case**: Katran processes millions of packets per second to distribute traffic across backend servers efficiently, using XDP to achieve low-latency and high-performance load balancing in large-scale data centers.
- **Link**: [Katran GitHub](https://github.com/facebookincubator/katran)

### 3. **XDP DDoS Protection at Cloudflare**

- **Description**: Cloudflare has implemented XDP for real-time DDoS mitigation. By processing packets at the NIC level, Cloudflare can filter out attack traffic before it reaches the networking stack, minimizing the impact of DDoS attacks on their systems.
- **Use Case**: Cloudflare leverages XDP to drop malicious packets early in the pipeline, protecting their infrastructure from large-scale DDoS attacks while maintaining high availability for legitimate traffic.
- **Link**: [Cloudflare Blog on XDP](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)

These projects demonstrate the real-world capabilities of XDP for scalable and efficient packet processing across different domains, from security and load balancing to cloud-native networking.

### Why Use XDP Over Other Methods?

Compared to traditional methods like `iptables`, `nftables`, or `tc`, XDP offers several clear advantages:

- **Speed and Low Overhead**: Operating directly in the NIC driver, XDP bypasses much of the kernel’s overhead, enabling faster packet processing.
  
- **Customizability**: XDP allows developers to create custom packet-processing programs with eBPF, providing more flexibility and granularity than legacy tools like `iptables`.

- **Resource Efficiency**: XDP does not require dedicating entire CPU cores to packet processing, unlike user-space solutions like DPDK, making it a more efficient choice for high-performance networking.

## Writing your first XDP Program

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

- <http://arthurchiao.art/blog/xdp-paper-acm-2018-zh/>
- <http://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/>
- <https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass>

> The original link of this article: <https://eunomia.dev/tutorials/21-xdp>
