# eBPF Tutorial by Example: BPF Dynamic Pointers for Variable-Length Data

Ever written an eBPF packet parser and struggled with those verbose `data_end` bounds checks that the verifier still rejects? Or tried to send variable-length events through ring buffers only to find yourself locked into fixed-size structures? Traditional eBPF development forces you to prove memory safety statically at compile time, which becomes painful when dealing with runtime-determined sizes like packet lengths or user-configurable snapshot lengths.

This is what **BPF dynptrs** (dynamic pointers) solve. Introduced gradually from Linux v5.19, dynptrs provide a verifier-friendly way to work with variable-length data by shifting some bounds checking from compile-time static analysis to runtime validation. In this tutorial, we'll build a TC ingress program that uses **skb dynptrs** to parse TCP packets safely and **ringbuf dynptrs** to output variable-length events containing configurable payload snapshots.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/dynptr>

## Introduction to BPF Dynamic Pointers

### The Problem: When Static Verification Isn't Enough

The eBPF verifier's core mission is proving memory safety at load time. Every pointer dereference must be bounded, every array access must be within limits. This works beautifully for simple cases, but becomes a struggle when sizes are determined at runtime.

Consider parsing a packet where the IP header length comes from a 4-bit field, or reading user-configurable amounts of TCP payload. The classic approach requires extensive bounds checking with `data_end` comparisons, and even correctly written code sometimes fails verification because the verifier cannot trace all possible paths. When working with non-linear skb data (paged buffers), the situation gets worse since that data isn't directly accessible through `ctx->data` at all.

Variable-length output presents similar challenges. The traditional `bpf_ringbuf_reserve()` returns a raw pointer, but writing runtime-determined amounts of data to it makes the verifier uncomfortable because it cannot statically prove your writes stay within bounds.

### The Solution: Runtime-Checked Dynamic Pointers

Dynptrs introduce an opaque handle type that carries metadata about the underlying memory region including its bounds and type. You cannot dereference a dynptr directly since the verifier will reject such attempts. Instead, you must use helper functions or kfuncs that perform the appropriate safety checks.

The key insight is that **some of these checks happen at runtime rather than compile time**. Functions like `bpf_dynptr_read()` and `bpf_dynptr_write()` validate bounds when they execute and return errors on failure. Functions like `bpf_dynptr_slice()` return NULL when the requested region cannot be accessed safely. This lets you express logic that would be unprovable statically while maintaining safety guarantees.

For the verifier, dynptrs are tracked specially. They have lifecycle rules (some must be released), type constraints (skb dynptrs behave differently than local dynptrs), and the verifier ensures you follow these rules. The runtime checks are the verifier's way of delegating what it cannot prove statically.

## Dynptr API Overview

### Helpers vs Kfuncs

The dynptr ecosystem spans two categories of functions. **Helper functions** are part of the stable UAPI and generally maintain backward compatibility. **Kfuncs** (kernel functions) are internal kernel exports to BPF with no ABI stability guarantees, meaning they may change between kernel versions.

For dynptrs, the foundational read/write operations are helpers, while newer features like skb dynptrs and slicing are kfuncs. This means some dynptr functionality requires newer kernels and you should verify availability before relying on specific features.

### Creating Dynptrs

There are several ways to create dynptrs depending on your data source. The `bpf_dynptr_from_mem()` helper creates a dynptr from map values or global variables, useful for working with configuration data or scratch buffers. The `bpf_dynptr_from_skb()` kfunc creates a dynptr from a socket buffer, enabling safe access to packet data including non-linear (paged) regions. For XDP programs, `bpf_dynptr_from_xdp()` provides similar functionality.

Ring buffer operations use `bpf_ringbuf_reserve_dynptr()` to allocate variable-length records. Unlike regular `bpf_ringbuf_reserve()` which returns a pointer to a fixed-size region, the dynptr variant lets you specify the size at runtime. This is crucial for variable-length event structures.

### Reading and Writing

The `bpf_dynptr_read()` helper copies data from a dynptr into a destination buffer. It takes an offset and length, performing runtime bounds checking and returning an error if the read would exceed the dynptr's bounds. This is the safe way to extract data when you need it in a local buffer.

The `bpf_dynptr_write()` helper does the reverse, copying data into a dynptr. For skb dynptrs, writing may have additional semantics similar to `bpf_skb_store_bytes()`, and note that writes can invalidate previously obtained slices.

The `bpf_dynptr_data()` helper returns a direct pointer to data within the dynptr, with the verifier tracking the bounds statically. However, this does NOT work for skb or xdp dynptrs since their data may not be in a single contiguous region.

### Slicing for Packet Parsing

For skb and xdp dynptrs, `bpf_dynptr_slice()` is the primary way to access data. You provide an offset, a length, and optionally a local buffer. The function returns a pointer to the requested data, which may be either a direct pointer into the packet or your provided buffer (if the data needed to be copied from non-linear regions).

The critical rule is that **you must NULL-check the return value**. A NULL return means the requested region cannot be accessed, either because it exceeds packet bounds or for other internal reasons. Once you have a valid slice pointer, you can dereference it safely within the requested bounds.

There's also `bpf_dynptr_slice_rdwr()` for obtaining writable slices, with availability depending on the program type and whether the underlying data supports writes.

### Ring Buffer Lifecycle

The `bpf_ringbuf_reserve_dynptr()` function has special lifecycle rules enforced by the verifier. Once you call it, you **must** call either `bpf_ringbuf_submit_dynptr()` or `bpf_ringbuf_discard_dynptr()` on the dynptr, regardless of whether the reservation succeeded. This is not optional since the verifier tracks dynptr state and will reject programs that leak reserved dynptrs.

This differs from regular ringbuf usage where a NULL return from `bpf_ringbuf_reserve()` means nothing was allocated. With dynptrs, the reserve failure still requires explicit cleanup through discard. The verifier needs this guarantee to ensure proper resource management.

## Implementation: TC Ingress with Dynptr Parsing and Variable-Length Events

Our demonstration program attaches to TC ingress and accomplishes three things. First, it creates an skb dynptr from incoming packets using `bpf_dynptr_from_skb()`. Second, it parses Ethernet, IPv4, and TCP headers using `bpf_dynptr_slice()` for safe bounds-checked access. Third, it outputs variable-length events through a ringbuf dynptr, including a configurable snapshot of TCP payload.

### Complete BPF Program: dynptr_tc.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dynptr_tc.h"

/* kfunc declarations for dynptr operations (v6.4+) */
extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
                              void *buffer__opt, __u32 buffer__sz) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dynptr_cfg);
} cfg_map SEC(".maps");

SEC("tc")
int dynptr_tc_ingress(struct __sk_buff *ctx)
{
    const struct dynptr_cfg *cfg;
    struct bpf_dynptr skb_ptr;

    /* Temporary buffers for slice (data may be copied here) */
    struct ethhdr eth_buf;
    struct iphdr  ip_buf;
    struct tcphdr tcp_buf;

    const struct ethhdr *eth;
    const struct iphdr  *iph;
    const struct tcphdr *tcp;

    cfg = bpf_map_lookup_elem(&cfg_map, &(__u32){0});
    if (!cfg)
        return TC_ACT_OK;

    /* Create dynptr from skb */
    if (bpf_dynptr_from_skb(ctx, 0, &skb_ptr))
        return TC_ACT_OK;

    /* Parse Ethernet header using slice */
    eth = bpf_dynptr_slice(&skb_ptr, 0, &eth_buf, sizeof(eth_buf));
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IPv4 header */
    __u32 ip_off = sizeof(*eth);
    iph = bpf_dynptr_slice(&skb_ptr, ip_off, &ip_buf, sizeof(ip_buf));
    if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* Parse TCP header */
    __u32 tcp_off = ip_off + ((__u32)iph->ihl * 4);
    tcp = bpf_dynptr_slice(&skb_ptr, tcp_off, &tcp_buf, sizeof(tcp_buf));
    if (!tcp)
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u16 sport = bpf_ntohs(tcp->source);
    __u8 drop = (cfg->blocked_port && (sport == cfg->blocked_port || dport == cfg->blocked_port));

    /* Output variable-length event using ringbuf dynptr */
    if (cfg->enable_ringbuf) {
        __u32 snap_len = cfg->snap_len;
        __u8 payload[MAX_SNAPLEN] = {};

        __u32 payload_off = tcp_off + ((__u32)tcp->doff * 4);
        if (payload_off < ctx->len) {
            __u32 avail = ctx->len - payload_off;
            if (snap_len > avail) snap_len = avail;
            if (snap_len > MAX_SNAPLEN) snap_len = MAX_SNAPLEN;

            if (bpf_dynptr_read(payload, snap_len, &skb_ptr, payload_off, 0))
                snap_len = 0;
        } else {
            snap_len = 0;
        }

        struct event_hdr hdr = {
            .ts_ns = bpf_ktime_get_ns(),
            .ifindex = ctx->ifindex,
            .pkt_len = ctx->len,
            .saddr = iph->saddr,
            .daddr = iph->daddr,
            .sport = bpf_ntohs(tcp->source),
            .dport = dport,
            .drop = drop,
            .snap_len = snap_len,
        };

        /* Reserve variable-length ringbuf record */
        struct bpf_dynptr rb;
        __u32 total_sz = sizeof(hdr) + snap_len;

        long err = bpf_ringbuf_reserve_dynptr(&events, total_sz, 0, &rb);
        if (err) {
            /* Must discard even on failure */
            bpf_ringbuf_discard_dynptr(&rb, 0);
            return drop ? TC_ACT_SHOT : TC_ACT_OK;
        }

        bpf_dynptr_write(&rb, 0, &hdr, sizeof(hdr), 0);
        if (snap_len)
            bpf_dynptr_write(&rb, sizeof(hdr), payload, snap_len, 0);

        bpf_ringbuf_submit_dynptr(&rb, 0);
    }

    return drop ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

### Understanding the BPF Code

The program begins by declaring the kfuncs it needs. The `bpf_dynptr_from_skb()` function creates a dynptr from the socket buffer, and `bpf_dynptr_slice()` returns pointers to specific regions within it. The `__ksym` attribute tells the loader these are kernel symbols to be resolved at load time.

When parsing headers, notice how we provide local buffers (`eth_buf`, `ip_buf`, `tcp_buf`) to each slice call. The slice function may return a pointer directly into packet data if it's linearly accessible, or it may copy data into our buffer and return a pointer to the buffer. Either way, we get a valid pointer we can dereference, or NULL on failure.

The NULL check pattern is crucial. Each slice call can fail if the requested offset plus length exceeds packet bounds or if the data cannot be accessed for other reasons. Checking for NULL before using the returned pointer is mandatory.

For ringbuf output, we use `bpf_dynptr_read()` to copy TCP payload from the skb into a local buffer first. This demonstrates reading from an skb dynptr with runtime-determined length (bounded by configuration and available data). The read may fail if bounds are exceeded, in which case we set `snap_len` to zero.

The ringbuf dynptr reserve shows the variable-length allocation pattern. We compute the total size (header plus snapshot) and reserve that exact amount. After writing both the header and payload using `bpf_dynptr_write()`, we submit the record. Note the discard call on reserve failure to satisfy the verifier's lifecycle requirements.

### Complete User-Space Program: dynptr_tc.c

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dynptr_tc.skel.h"
#include "dynptr_tc.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo) { exiting = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_hdr *e = data;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    printf("if=%u %s:%u -> %s:%u len=%u drop=%u snap=%u",
           e->ifindex, saddr, e->sport, daddr, e->dport,
           e->pkt_len, e->drop, e->snap_len);

    if (e->snap_len && data_sz >= sizeof(*e) + e->snap_len) {
        printf(" payload=\"");
        for (int i = 0; i < e->snap_len; i++) {
            unsigned char c = e->payload[i];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        printf("\"");
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    struct dynptr_cfg cfg = { .blocked_port = 0, .snap_len = 64, .enable_ringbuf = 1 };

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) ifname = argv[++i];
        else if (!strcmp(argv[i], "-p") && i+1 < argc) cfg.blocked_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i+1 < argc) cfg.snap_len = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n")) cfg.enable_ringbuf = 0;
    }

    if (!ifname) {
        fprintf(stderr, "Usage: %s -i <ifname> [-p port] [-s len] [-n]\n", argv[0]);
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct dynptr_tc_bpf *skel = dynptr_tc_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "Failed to load BPF\n"); return 1; }

    /* Configure */
    bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &(__u32){0}, &cfg, BPF_ANY);

    /* Attach to TC ingress */
    struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = ifindex, .attach_point = BPF_TC_INGRESS };
    struct bpf_tc_opts opts = { .sz = sizeof(opts), .handle = 1, .priority = 1,
                                .prog_fd = bpf_program__fd(skel->progs.dynptr_tc_ingress) };

    bpf_tc_hook_create(&hook);
    if (bpf_tc_attach(&hook, &opts)) { fprintf(stderr, "TC attach failed\n"); goto cleanup; }

    struct ring_buffer *rb = cfg.enable_ringbuf ?
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL) : NULL;

    printf("Attached to %s. blocked_port=%u snap_len=%u\n", ifname, cfg.blocked_port, cfg.snap_len);

    while (!exiting) {
        if (rb) ring_buffer__poll(rb, 100);
        else usleep(100000);
    }

    ring_buffer__free(rb);
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
cleanup:
    dynptr_tc_bpf__destroy(skel);
    return 0;
}
```

### Understanding the User-Space Code

The userspace program loads the BPF skeleton, configures it through the array map, and attaches to TC ingress. The ring buffer callback `handle_event()` receives each variable-length event and prints it.

Notice how we access the variable-length payload. The `struct event_hdr` has a flexible array member `payload[]` at the end. When an event arrives, `data_sz` tells us the total size, and `e->snap_len` tells us specifically how much payload was included. We validate both before accessing the payload bytes.

The configuration map allows runtime control over blocking behavior and snapshot length without reloading the BPF program. This demonstrates the common pattern of using maps for user-to-kernel communication.

## Compilation and Execution

Navigate to the dynptr directory and build:

```bash
cd bpf-developer-tutorial/src/features/dynptr
make
```

This compiles the BPF program with the repository's standard toolchain, generating the skeleton header and linking against libbpf.

### Creating a Test Environment

To test properly, we need a network namespace so traffic actually traverses the veth pair rather than going through loopback. The included `test.sh` script handles this automatically, but here's the manual setup:

```bash
# Create network namespace
sudo ip netns add test_ns

# Create veth pair with one end in the namespace
sudo ip link add veth_host type veth peer name veth_ns
sudo ip link set veth_ns netns test_ns

# Configure host side
sudo ip addr add 10.200.0.1/24 dev veth_host
sudo ip link set veth_host up

# Configure namespace side
sudo ip netns exec test_ns ip addr add 10.200.0.2/24 dev veth_ns
sudo ip netns exec test_ns ip link set veth_ns up

# Start HTTP server inside the namespace
sudo ip netns exec test_ns python3 -m http.server 8080 --bind 10.200.0.2 &
```

### Running the Demo

Start the dynptr TC program attached to the host side of the veth:

```bash
sudo ./dynptr_tc -i veth_host -p 0 -s 32
```

In another terminal, make a request:

```bash
curl http://10.200.0.2:8080/
```

You should see output showing captured packets:

```
Attached to TC ingress of veth_host (ifindex=X). Ctrl-C to exit.
blocked_port=0 snap_len=32 ringbuf=1
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=221 drop=0 snap=32 payload="HTTP/1.0 200 OK..Server: SimpleH"
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=742 drop=0 snap=32 payload="<!DOCTYPE HTML>.<html lang="en">"
```

The output shows HTTP response packets from the server, with the payload field containing the beginning of the response data.

### Testing the Drop Policy

Test blocking by specifying port 8080:

```bash
sudo ./dynptr_tc -i veth_host -p 8080 -s 32
```

In another terminal:

```bash
curl --max-time 3 http://10.200.0.2:8080/
```

The curl should timeout since response packets are blocked. The dynptr_tc output shows `drop=1`:

```
if=X 10.200.0.2:8080 -> 10.200.0.1:XXXXX len=74 drop=1 snap=0
```

### Using the Test Script

For convenience, run the included test script which handles all setup automatically:

```bash
sudo ./test.sh
```

This creates the namespace, runs both capture and blocking tests, and cleans up afterward.

## When to Use Dynptrs

Dynptrs shine in several scenarios. **Variable-length events** are the classic use case since ringbuf dynptrs let you allocate exactly the size you need at runtime, avoiding wasted space from oversized fixed structures or complex multi-record schemes.

**Packet parsing** benefits from dynptrs when dealing with non-linear skbs or complex protocol stacks where traditional bounds checking becomes unwieldy. The slice API provides a cleaner abstraction that handles both linear and paged data uniformly.

**Crypto and verification** operations like `bpf_crypto_encrypt()`, `bpf_verify_pkcs7_signature()`, and `bpf_get_file_xattr()` all use dynptrs as buffer arguments, making dynptr familiarity essential for these advanced use cases.

**User ringbuf consumption** through `bpf_user_ringbuf_drain()` delivers samples as dynptrs, enabling safe handling of userspace-provided data in BPF programs.

For simple fixed-size operations where you know bounds at compile time, traditional approaches may be simpler. But as your BPF programs grow more sophisticated, dynptrs become increasingly valuable.

## Summary

BPF dynptrs provide a verifier-friendly mechanism for working with variable-length and runtime-bounded data. Rather than proving memory safety entirely through static analysis, dynptrs shift some verification to runtime checks, enabling patterns that would otherwise be impossible or extremely awkward to express.

Our example demonstrated the two primary dynptr patterns: using skb dynptrs with slices for clean packet parsing, and using ringbuf dynptrs for variable-length event output. The key takeaways are to always NULL-check slice returns, always submit or discard ringbuf dynptrs, and remember that skb dynptrs require kfuncs available from Linux v6.4.

As eBPF capabilities continue to expand, dynptrs form an increasingly important part of the toolkit. Whether you're building packet processors, security monitors, or performance tools, understanding dynptrs will help you write cleaner, more capable BPF programs.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Dynptr Concept Documentation:** <https://docs.ebpf.io/linux/concepts/dynptrs/>
- **bpf_ringbuf_reserve_dynptr Helper:** <https://docs.ebpf.io/linux/helper-function/bpf_ringbuf_reserve_dynptr/>
- **bpf_dynptr_from_skb Kfunc:** <https://docs.ebpf.io/linux/kfuncs/bpf_dynptr_from_skb/>
- **bpf_dynptr_slice Kfunc:** <https://docs.ebpf.io/linux/kfuncs/bpf_dynptr_slice/>
- **Kernel Kfuncs Documentation:** <https://docs.kernel.org/bpf/kfuncs.html>
- **Tutorial Repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial>

This example requires Linux kernel 6.4 or newer for the skb dynptr kfuncs. The ringbuf dynptr helpers are available from Linux 5.19. Complete source code is available in the tutorial repository.
