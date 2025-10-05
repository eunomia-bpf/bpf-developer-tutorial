# BPF Workqueues Tutorial

## What are BPF Workqueues?

BPF workqueues allow you to schedule **asynchronous work** from BPF programs. This enables:
- Deferred processing
- Non-blocking operations
- Background task execution
- Sleepable context for long-running operations

## The Problem

### Before bpf_wq: Limitations of bpf_timer

**bpf_timer** runs in **softirq context**, which has severe limitations:
- ❌ Cannot sleep
- ❌ Cannot use `kzalloc()` (memory allocation)
- ❌ Cannot wait for device I/O
- ❌ Cannot perform any blocking operations

### Real-World Use Case: HID Device Handling

**Problem**: HID (Human Interface Devices - keyboards, mice, tablets) devices need to:
1. **React to events asynchronously** - Transform input, inject new events
2. **Communicate with hardware** - Re-initialize devices after sleep/wake
3. **Perform device I/O** - Send commands, wait for responses

**These operations require sleepable context!**

## The Solution: bpf_wq

Developed by **Benjamin Tissoires** (Red Hat) in 2024 as part of HID-BPF work.

### Key Quote from Kernel Patches:
> "I need something similar to bpf_timers, but not in soft IRQ context...
> the bpf_timer functionality would prevent me to kzalloc and wait for the device"

### What bpf_wq Provides:
- ✅ **Sleepable context** - Can perform blocking operations
- ✅ **Memory allocation** - Can use `kzalloc()` safely
- ✅ **Device I/O** - Can wait for hardware responses
- ✅ **Asynchronous execution** - Deferred work without blocking main path

## Real-World Applications

### 1. HID Device Quirks and Fixes

**Problem**: Many HID devices have firmware bugs or quirks requiring workarounds.

**Before bpf_wq**: Write kernel drivers, recompile kernel
**With bpf_wq**: Load BPF program to fix device behavior dynamically

**Example Use Cases**:
- Transform single key press into macro sequence
- Fix devices that forget to send button release events
- Invert mouse coordinates for broken hardware
- Re-initialize device after wake from sleep

### 2. Network Packet Processing

**Problem**: Rate limiting requires tracking state and cleaning up old entries.

**Before**: Either block packet processing OR leak memory
**With bpf_wq**:
- Fast path: Check limits, drop packets (non-blocking)
- Slow path: Workqueue cleans up stale entries (async)

### 3. Security and Monitoring

**Problem**: Security decisions need to consult external services or databases.

**Before**: All decisions must be instant (no waiting)
**With bpf_wq**:
- Fast path: Apply known rules immediately
- Slow path: Query reputation databases, update policy

### 4. Resource Cleanup

**Problem**: Freeing resources (memory, connections) can be expensive.

**Before**: Block main path during cleanup
**With bpf_wq**: Defer cleanup to background workqueue

## Technical Architecture

### Comparison: bpf_timer vs bpf_wq

| Feature | bpf_timer | bpf_wq |
|---------|-----------|--------|
| **Context** | Softirq (interrupt) | Process (workqueue) |
| **Can sleep?** | ❌ No | ✅ Yes |
| **Memory allocation** | ❌ No | ✅ Yes |
| **Device I/O** | ❌ No | ✅ Yes |
| **Latency** | Very low (μs) | Higher (ms) |
| **Use case** | Time-critical | Sleepable operations |

### When to Use Each

**Use bpf_timer when:**
- You need microsecond-level precision
- Operations are fast and non-blocking
- You're just updating counters or state

**Use bpf_wq when:**
- You need to sleep or wait
- You need memory allocation
- You need device/network I/O
- Cleanup can happen later

## Code Example: Why Workqueue Matters

### ❌ Cannot Do with bpf_timer (softirq):
```c
// This FAILS in bpf_timer callback (softirq context)
static int timer_callback(void *map, int *key, void *value)
{
    // ERROR: Cannot allocate in softirq!
    struct data *d = kmalloc(sizeof(*d), GFP_KERNEL);

    // ERROR: Cannot sleep in softirq!
    send_device_command_and_wait(device);

    return 0;
}
```

### ✅ Works with bpf_wq (workqueue):
```c
// This WORKS in bpf_wq callback (process context)
static int wq_callback(void *map, int *key, void *value)
{
    // OK: Can allocate in process context
    struct data *d = kmalloc(sizeof(*d), GFP_KERNEL);

    // OK: Can sleep/wait in process context
    send_device_command_and_wait(device);

    // OK: Can do blocking I/O
    write_to_file(log_file, data);

    kfree(d);
    return 0;
}
```

## Historical Timeline

1. **2022**: Benjamin Tissoires starts HID-BPF work
2. **2023**: Realizes bpf_timer limitations for HID device I/O
3. **Early 2024**: Proposes bpf_wq as "bpf_timer in process context"
4. **April 2024**: bpf_wq merged into kernel (v6.10+)
5. **2024-Present**: Used for HID quirks, rate limiting, async cleanup

## Key Takeaway

**bpf_wq exists because real-world device handling and resource management need sleepable, blocking operations that bpf_timer cannot provide.**

It enables BPF programs to:
- Fix hardware quirks without kernel drivers
- Perform async cleanup without blocking
- Wait for I/O without hanging the system
- Do "slow work" without impacting "fast path"

**Bottom line**: bpf_wq brings true asynchronous, sleepable programming to BPF!

## How It Works

### 1. Workqueue Structure

Embed a `struct bpf_wq` in your map value:

```c
struct elem {
    int value;
    struct bpf_wq work;  // Embedded workqueue
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, struct elem);
} array SEC(".maps");
```

### 2. Initialize and Schedule

```c
SEC("fentry/do_unlinkat")
int test_workqueue(void *ctx)
{
    struct elem *val = bpf_map_lookup_elem(&array, &key);
    struct bpf_wq *wq = &val->work;

    // Initialize workqueue
    bpf_wq_init(wq, &array, 0);

    // Set callback function
    bpf_wq_set_callback(wq, callback_fn, 0);

    // Schedule async execution
    bpf_wq_start(wq, 0);

    return 0;
}
```

### 3. Callback Execution

```c
static int callback_fn(void *map, int *key, void *value)
{
    struct elem *val = value;

    // This runs asynchronously in workqueue context
    val->value = 42;

    return 0;
}
```

## Examples

### 1. Simple Workqueue Test (`wq_simple`)

Basic demonstration:
- Workqueue initialization on syscall entry
- Async callback execution
- Verification of both sync and async paths

```bash
$ sudo ./wq_simple
BPF workqueue program attached. Triggering unlink syscall...

Results:
  main_executed = 1 (expected: 1)
  wq_executed = 1 (expected: 1)

✓ Test PASSED!
```

### 2. Real-World: Rate Limiter with Async Cleanup (`rate_limiter`)

**Production-ready example** showing practical workqueue usage:

**Problem**:
- Track packet rates per source IP
- Drop packets exceeding 100 pps
- Clean up stale entries without blocking packet processing

**Solution with Workqueues**:
- **Fast path**: Check/update rate limits, drop if needed
- **Slow path (async)**: Workqueue removes entries older than 10 seconds
- **Zero blocking**: Cleanup runs in background

```bash
$ sudo ./rate_limiter eth0
=== BPF Rate Limiter with Workqueue Cleanup ===
Interface: eth0 (ifindex=2)
Rate limit: 100 packets/sec per IP
Cleanup: Async workqueue removes stale entries (>10s old)

Press Ctrl+C to stop...

Time       Total Pkts      Dropped         Active IPs      Cleanups
-----------------------------------------------------------------------
1234       45123          1234            150             12
1235       46789          1456            152             15
...
```

**Key Features**:
1. **In-kernel rate limiting** - No userspace involvement for packet decisions
2. **Per-IP tracking** - Hash map stores state for each source IP
3. **Async cleanup** - Workqueue prevents memory leaks without blocking packets
4. **Real-time stats** - Monitor performance and efficiency

## Use Cases

### 1. Rate Limiting
Schedule delayed actions to enforce rate limits:
```c
// Defer packet drop decision
bpf_wq_start(wq, 0);  // Execute in background
```

### 2. Batch Processing
Accumulate events and process in batches:
```c
// Collect events in map
// Workqueue processes batch periodically
```

### 3. Heavy Computations
Offload expensive operations:
```c
// Main path: fast, non-blocking
// Workqueue: slow processing (parsing, crypto)
```

### 4. Cleanup Tasks
Defer resource cleanup:
```c
// Free memory, close connections in background
```

## Building and Running

```bash
# Build
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/features/bpf_wq
make

# Run simple test
sudo ./wq_simple

# Run rate limiter (requires network interface)
sudo ./rate_limiter lo      # Use loopback for testing
sudo ./rate_limiter eth0    # Use real interface

# Generate test traffic
ping -f localhost           # Flood ping to trigger rate limiting
```

## Key APIs

| Function | Purpose |
|----------|---------|
| `bpf_wq_init(wq, map, flags)` | Initialize workqueue |
| `bpf_wq_set_callback(wq, fn, flags)` | Set callback function |
| `bpf_wq_start(wq, flags)` | Schedule async execution |

## Requirements

- Linux kernel 6.6+ (workqueue support)
- Root/sudo access
- libbpf, clang, bpftool

## Files

```
bpf_wq/
├── wq_simple.bpf.c       # BPF workqueue program
├── wq_simple.c           # Userspace loader
├── bpf_experimental.h    # Workqueue helper definitions
├── Makefile              # Build system
├── README.md             # This file
└── .gitignore            # Ignore build artifacts
```

## Advantages Over Alternatives

| Approach | Blocking | Context Switches | Complexity |
|----------|----------|-----------------|------------|
| **Synchronous** | Yes | No | Low |
| **Userspace notification** | No | Yes (many) | High |
| **BPF workqueue** | No | Minimal | Medium |

BPF workqueues provide the best balance of performance and flexibility for async operations!

## Summary

BPF workqueues enable **true asynchronous programming** in BPF:
- ✅ Non-blocking main path
- ✅ Deferred execution
- ✅ Sleepable context support
- ✅ Minimal overhead
- ✅ Type-safe callbacks

Perfect for scenarios where you need to do work later without blocking the fast path!
