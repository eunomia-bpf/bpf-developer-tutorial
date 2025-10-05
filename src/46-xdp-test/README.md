# eBPF Tutorial by Example: Building a High-Performance XDP Packet Generator

Need to stress-test your network stack or measure XDP program performance? Traditional packet generators like `pktgen` require kernel modules or run in userspace with high overhead. There's a better way - XDP's BPF_PROG_RUN feature lets you inject packets directly into the kernel's fast path at millions of packets per second, all from userspace without loading network drivers.

In this tutorial, we'll build an XDP-based packet generator that leverages the kernel's BPF_PROG_RUN test infrastructure. We'll explore how XDP's `XDP_TX` action creates a packet reflection loop, understand the live frames mode that enables real packet injection, and measure the performance characteristics of XDP programs under load. By the end, you'll have a production-ready tool for network testing and XDP benchmarking.

## Understanding XDP Packet Generation

XDP (eXpress Data Path) provides the fastest programmable packet processing in Linux by hooking into network drivers before the kernel's networking stack allocates socket buffers. Normally, XDP programs process packets arriving from network interfaces. But what if you want to test an XDP program's performance without real network traffic? Or inject synthetic packets to stress-test your network infrastructure?

### The BPF_PROG_RUN Testing Interface

The kernel exposes `bpf_prog_test_run()` (BPF_PROG_RUN) as a testing mechanism for BPF programs. Originally designed for unit testing, this syscall lets userspace invoke a BPF program with synthetic input and capture its output. For XDP programs, you provide a packet buffer and an `xdp_md` context describing the packet metadata (interface index, RX queue). The kernel runs your XDP program and returns the action code (XDP_DROP, XDP_PASS, XDP_TX, etc.) along with any packet modifications.

Traditional BPF_PROG_RUN operates in "dry run" mode - packets are processed but never actually transmitted. The XDP program runs, modifies packet data, returns an action, but nothing hits the wire. This is perfect for testing packet parsing logic or measuring program execution time in isolation.

### Live Frames Mode: Real Packet Injection

In Linux 5.18+, the kernel introduced **live frames mode** via the `BPF_F_TEST_XDP_LIVE_FRAMES` flag. This fundamentally changes BPF_PROG_RUN behavior. When enabled, XDP_TX actions don't just return - they actually transmit packets on the wire through the specified network interface. This turns BPF_PROG_RUN into a powerful packet generator.

Here's how it works: Your userspace program constructs a packet (Ethernet frame with IP header, UDP payload, etc.) and passes it to `bpf_prog_test_run()` with live frames enabled. The XDP program receives this packet in its `xdp_md` context. If the program returns `XDP_TX`, the kernel transmits the packet through the network driver as if it arrived on the interface and was reflected back. The packet appears on the wire with full hardware offload support (checksumming, segmentation, etc.).

This enables several powerful use cases. **Network stack stress testing**: Flood your system with millions of packets per second to find breaking points in the network stack, driver, or application layer. **XDP program benchmarking**: Measure how many packets per second your XDP program can process under realistic load without external packet generators. **Protocol fuzzing**: Generate malformed packets or unusual protocol sequences to test robustness. **Synthetic traffic generation**: Create realistic traffic patterns for testing load balancers, firewalls, or intrusion detection systems.

### The XDP_TX Reflection Loop

The simplest XDP packet generator uses the `XDP_TX` action. This tells the kernel "transmit this packet back out the interface it arrived on." Our minimal XDP program is literally three lines:

```c
SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
    return XDP_TX;
}
```

That's it. No packet parsing, no header modification - just reflect everything. Combined with BPF_PROG_RUN in live frames mode, this creates a packet generation loop: userspace injects a packet, XDP reflects it to the wire, repeat at millions of packets per second.

Why is this so fast? The XDP program runs in the driver's receive path with direct access to DMA buffers. There's no socket buffer allocation, no protocol stack traversal, no context switching to userspace between packets. The kernel can batch packet processing across multiple frames, amortizing syscall overhead. On modern hardware, a single CPU core can generate 5-10 million packets per second.

## Building the Packet Generator

Let's examine how the complete packet generator works, from userspace control to kernel packet injection.

### Complete XDP Program: xdp-pktgen.bpf.c

```c
/* SPDX-License-Identifier: MIT */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return XDP_TX;
}
```

This is the entire XDP program. The `SEC("xdp")` attribute marks it as an XDP program for libbpf's program loader. The function receives an `xdp_md` context containing packet metadata - `data` and `data_end` pointers frame the packet buffer, `ingress_ifindex` identifies the receiving interface, and RX queue information is available for multi-queue NICs.

We immediately return `XDP_TX` without touching the packet. In live frames mode, this causes the kernel to transmit the packet. The packet data itself comes from userspace - we'll construct UDP or custom protocol packets and inject them via BPF_PROG_RUN.

The beauty of this minimal approach is that all packet construction happens in userspace where you have full control. Want to fuzz protocols? Generate packets in C with arbitrary header fields. Need realistic traffic patterns? Read pcap files and replay them through the XDP program. Testing specific edge cases? Craft packets byte-by-byte. The XDP program is just a vehicle for getting packets onto the wire at line rate.

### Userspace Control Program: xdp-pktgen.c

The userspace program handles packet construction, BPF program loading, and injection control. Let's walk through the key components.

#### Packet Construction and Configuration

```c
struct config {
	int ifindex;        // Which interface to inject packets on
	int xdp_flags;      // XDP attachment flags
	int repeat;         // How many times to inject each packet
	int batch_size;     // Batch size for BPF_PROG_RUN (0 = auto)
};

struct config cfg = {
	.ifindex = 6,              // Network interface (e.g., eth0)
	.repeat = 1 << 20,         // 1 million repeats per batch
	.batch_size = 0,           // Let kernel choose optimal batch
};
```

The configuration controls packet injection parameters. Interface index identifies which NIC to use - find it with `ip link show`. Repeat count determines how many times to inject each packet in a single BPF_PROG_RUN call. Higher counts amortize syscall overhead but increase latency before the next packet template. Batch size lets you inject multiple different packets in one syscall (advanced feature, 0 means single packet mode).

Packet construction supports two modes. By default, it generates a synthetic UDP/IPv4 packet:

```c
struct test_udp_packet_v4 pkt_udp = create_test_udp_packet_v4();
size = sizeof(pkt_udp);
memcpy(pkt_file_buffer, &pkt_udp, size);
```

This creates a minimal valid UDP packet - Ethernet frame with source/dest MACs, IPv4 header with addresses and checksums, UDP header with ports, and a small payload. The `create_test_udp_packet_v4()` helper (from test_udp_pkt.h) constructs a wire-format packet that network stacks will accept.

For custom packets, set the `PKTGEN_FILE` environment variable to a file containing raw packet bytes:

```c
if ((pkt_file = getenv("PKTGEN_FILE")) != NULL) {
    FILE* file = fopen(pkt_file, "r");
    size = fread(pkt_file_buffer, 1, 1024, file);
    fclose(file);
}
```

This lets you inject arbitrary packets - pcap extracts, fuzzing payloads, or protocol test vectors. Any binary data works as long as it forms a valid Ethernet frame.

#### BPF_PROG_RUN Invocation and Live Frames

The packet injection loop uses `bpf_prog_test_run_opts()` to repeatedly invoke the XDP program:

```c
struct xdp_md ctx_in = {
    .data_end = size,                 // Packet length
    .ingress_ifindex = cfg.ifindex    // Which interface
};

DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
    .data_in = pkt_file_buffer,       // Packet data
    .data_size_in = size,             // Packet length
    .ctx_in = &ctx_in,                // XDP metadata
    .ctx_size_in = sizeof(ctx_in),
    .repeat = cfg.repeat,             // Repeat count
    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,  // Enable live TX
    .batch_size = cfg.batch_size,
    .cpu = 0,                         // Pin to CPU 0
);
```

The critical flag is `BPF_F_TEST_XDP_LIVE_FRAMES`. Without it, the XDP program runs but packets stay in memory. With it, XDP_TX actions actually transmit packets through the driver. The kernel validates that the interface index is valid and the interface is up, ensuring packets hit the wire.

CPU pinning (`cpu = 0`) is important for performance measurement. By pinning the injection thread to CPU 0, you get consistent performance numbers and avoid cache bouncing across cores. For maximum throughput, you'd spawn multiple threads pinned to different CPUs, each injecting packets on separate interfaces or queues.

The injection loop continues until interrupted:

```c
do {
    err = bpf_prog_test_run_opts(run_prog_fd, &opts);
    if (err)
        return -errno;
    iterations += opts.repeat;
} while ((count == 0 || iterations < count) && !exiting);
```

Each `bpf_prog_test_run_opts()` call injects `repeat` packets (1 million by default). With a fast XDP program, this completes in milliseconds. The kernel batches packet processing, minimizing per-packet overhead. Total throughput depends on packet size, NIC capability, and CPU performance, but 5-10 Mpps per core is achievable.

#### Kernel Support Detection

Not all kernels support live frames mode. The program probes for support before starting injection:

```c
static int probe_kernel_support(int run_prog_fd)
{
    int err = run_prog(run_prog_fd, 1);  // Try injecting 1 packet
    if (err == -EOPNOTSUPP) {
        printf("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
    } else if (err == -EINVAL) {
        err = -EOPNOTSUPP;
        printf("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
    } else if (err) {
        printf("Error probing kernel support: %s\n", strerror(-err));
    } else {
        printf("Kernel supports live packet mode for XDP BPF_PROG_RUN.\n");
    }
    return err;
}
```

This attempts a single packet injection. If the kernel lacks support (Linux <5.18 or CONFIG_XDP_SOCKETS not enabled), it returns `-EINVAL`. Older libbpf versions without batch support return `-EOPNOTSUPP`. Success means you can proceed with full packet generation.

## Running the Packet Generator

Navigate to the tutorial directory and build the project:

```bash
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/46-xdp-test
make build
```

This compiles both the XDP program (`xdp-pktgen.bpf.o`) and userspace control program (`xdp-pktgen`). The build requires Clang for BPF compilation and libbpf for skeleton generation.

Before running, identify your network interface index. Use `ip link show` to list interfaces:

```bash
ip link show
```

You'll see output like:

```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
6: veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

Note the interface number (e.g., 6 for veth0). Update the config in xdp-pktgen.c if needed:

```c
struct config cfg = {
    .ifindex = 6,  // Change to your interface index
    ...
};
```

Run the packet generator with root privileges (required for BPF_PROG_RUN):

```bash
sudo ./xdp-pktgen
```

You'll see output like:

```
Kernel supports live packet mode for XDP BPF_PROG_RUN.
pkt size: 42
[Generating packets...]
```

The program runs until interrupted with Ctrl-C. Monitor packet transmission with:

```bash
# In another terminal, watch interface statistics
watch -n 1 'ip -s link show veth0'
```

You'll see TX packet counters increasing rapidly. On a modern CPU, expect 5-10 million packets per second per core for minimal-size packets.

### Custom Packet Injection

To inject custom packets, create a binary packet file and set the environment variable:

```bash
# Create a custom packet (e.g., using scapy or hping3 to generate the binary)
echo -n -e '\x00\x01\x02\x03\x04\x05...' > custom_packet.bin

# Inject it
sudo PKTGEN_FILE=custom_packet.bin ./xdp-pktgen
```

The generator reads up to 1024 bytes from the file and injects that packet repeatedly. This works for any protocol - IPv6, ICMP, custom L2 protocols, even malformed packets for fuzzing.

## Performance Characteristics and Tuning

XDP packet generation performance depends on several factors. Let's understand what limits throughput and how to maximize it.

**Packet size impact**: Smaller packets achieve higher packet rates but lower throughput in bytes per second. A 64-byte packet at 10 Mpps delivers 5 Gbps. A 1500-byte packet at 2 Mpps delivers 24 Gbps. The CPU processes packets at roughly constant packet-per-second rates, so larger packets achieve higher bandwidth.

**CPU frequency and microarchitecture**: Newer CPUs with higher frequencies and better IPC (instructions per cycle) achieve higher rates. Intel Xeon or AMD EPYC server CPUs can hit 10+ Mpps per core. Older or lower-power CPUs may only reach 2-5 Mpps.

**NIC capabilities**: The network driver must keep up with injection rates. High-end NICs (Intel X710, Mellanox ConnectX) support millions of packets per second. Consumer gigabit NICs often saturate at 1-2 Mpps due to driver limitations or hardware buffering.

**Memory bandwidth**: At high rates, packet data transfer to/from NIC DMA buffers can become a bottleneck. Ensure the system has sufficient memory bandwidth (use `perf stat` to monitor memory controller utilization).

**Interrupt and polling overhead**: Network drivers use interrupts or polling (NAPI) to process packets. Under extreme load, interrupt overhead can slow processing. Consider tuning interrupt coalescing or using busy-polling.

For maximum performance, pin the injection thread to a dedicated CPU core, disable CPU frequency scaling (set governor to performance), use huge pages for packet buffers to reduce TLB misses, and consider multi-queue NICs with RSS (Receive Side Scaling) - spawn threads per queue for parallel injection.

## Summary and Next Steps

XDP packet generators leverage the kernel's BPF_PROG_RUN infrastructure to inject packets at line rate from userspace. By combining a minimal XDP program that returns XDP_TX with live frames mode, you can transmit millions of packets per second without external hardware or kernel modules. This enables network stack stress testing, XDP program benchmarking, protocol fuzzing, and synthetic traffic generation.

Our implementation demonstrates the core concepts: a simple XDP reflection program, userspace packet construction with custom or default UDP packets, BPF_PROG_RUN invocation with live frames flag, and kernel support detection. The result is a flexible, high-performance packet generator suitable for testing network infrastructure, measuring XDP program performance, or generating realistic traffic patterns.

Beyond basic generation, you can extend this approach to create sophisticated testing tools. Add packet templates for different protocols (TCP SYN floods, ICMP echo, DNS queries). Implement traffic shaping (vary inter-packet delays). Support multiple interfaces simultaneously for throughput aggregation. Integrate with network monitoring to measure drop rates or latency. The XDP packet generator framework provides a foundation for advanced network testing capabilities.

> If you'd like to dive deeper into eBPF and XDP, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Tutorial Repository**: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/46-xdp-test>
- **Linux Kernel XDP Documentation**: `Documentation/networking/xdp.rst`
- **BPF_PROG_RUN Documentation**: `tools/testing/selftests/bpf/README.rst`
- **XDP Tutorial**: <https://github.com/xdp-project/xdp-tutorial>
- **libbpf Documentation**: <https://libbpf.readthedocs.io/>

Complete source code with build instructions and example packet templates is available in the tutorial repository. Contributions welcome!
