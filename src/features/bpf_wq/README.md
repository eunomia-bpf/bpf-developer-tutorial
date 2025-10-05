# eBPF Tutorial: BPF Workqueues for Asynchronous Sleepable Tasks

Ever needed your eBPF program to sleep, allocate memory, or wait for device I/O? Traditional eBPF programs run in restricted contexts where blocking operations crash the system. But what if your HID device needs timing delays between injected key events, or your cleanup routine needs to sleep while freeing resources?

This is what **BPF Workqueues** enable. Created by Benjamin Tissoires at Red Hat in 2024 for HID-BPF device handling, workqueues let you schedule asynchronous work that runs in process context where sleeping and blocking operations are allowed. In this tutorial, we'll explore why workqueues were created, how they differ from timers, and build a complete example demonstrating async callback execution.

## Introduction to BPF Workqueues: Solving the Sleep Problem

### The Problem: When eBPF Can't Sleep

Before BPF workqueues existed, developers had `bpf_timer` for deferred execution. Timers work great for scheduling callbacks after a delay, perfect for updating counters or triggering periodic events. But there's a fundamental limitation that made timers unusable for certain critical use cases: **bpf_timer runs in softirq (software interrupt) context**.

Softirq context has strict rules enforced by the kernel. You cannot sleep or wait for I/O - any attempt to do so will cause kernel panics or deadlocks. You cannot allocate memory using `kzalloc()` with `GFP_KERNEL` flag because memory allocation might need to wait for pages. You cannot communicate with hardware devices that require waiting for responses. Essentially, you cannot perform any blocking operations that might cause the CPU to wait.

This limitation became a real problem for Benjamin Tissoires at Red Hat when he was developing HID-BPF in 2023. HID devices (keyboards, mice, tablets, game controllers) frequently need operations that timers simply can't handle. Imagine implementing keyboard macro functionality where pressing F1 types "hello" - you need 10ms delays between each keystroke for the system to properly process events. Or consider a device with buggy firmware that needs re-initialization after system wake - you must send commands and wait for hardware responses. Timer callbacks in softirq context can't do any of this.

As Benjamin Tissoires explained in his kernel patches: "I need something similar to bpf_timers, but not in soft IRQ context... the bpf_timer functionality would prevent me to kzalloc and wait for the device."

### The Solution: Process Context Execution

In early 2024, Benjamin proposed and developed **bpf_wq** - essentially "bpf_timer but in process context instead of softirq." The kernel community merged it into Linux v6.10+ in April 2024. The key insight is simple but powerful: by running callbacks in process context (through the kernel's workqueue infrastructure), BPF programs gain access to the full range of kernel operations.

Here's what changes with process context:

| Feature | bpf_timer (softirq) | bpf_wq (process) |
|---------|---------------------|------------------|
| **Can sleep?** | ❌ No - will crash | ✅ Yes - safe to sleep |
| **Memory allocation** | ❌ Limited flags only | ✅ Full `kzalloc()` support |
| **Device I/O** | ❌ Cannot wait | ✅ Can wait for responses |
| **Blocking operations** | ❌ Prohibited | ✅ Fully supported |
| **Latency** | Very low (microseconds) | Higher (milliseconds) |
| **Use case** | Time-critical fast path | Sleepable slow path |

Workqueues enable the classic "fast path + slow path" pattern. Your eBPF program handles performance-critical operations immediately in the fast path, then schedules expensive cleanup or I/O operations to run asynchronously in the slow path. The fast path stays responsive while the slow path gets the capabilities it needs.

### Real-World Applications

The applications span multiple domains. **HID device handling** was the original motivation - injecting keyboard macros with timing delays, fixing broken device firmware dynamically without kernel drivers, re-initializing devices after wake from sleep, transforming input events on the fly. All these require sleepable operations that only workqueues can provide.

**Network packet processing** benefits from async cleanup patterns. Your XDP program enforces rate limits and drops packets in the fast path (non-blocking), while a workqueue cleans up stale tracking entries in the background. This prevents memory leaks without impacting packet processing performance.

**Security monitoring** can apply fast rules immediately, then use workqueues to query reputation databases or external threat intelligence services. The fast path makes instant decisions while the slow path updates policies based on complex analysis.

**Resource cleanup** defers expensive operations. Instead of blocking the main code path while freeing memory, closing connections, or compacting data structures, you schedule a workqueue to handle cleanup in the background.

## Implementation: Simple Workqueue Test

Let's build a complete example that demonstrates the workqueue lifecycle. We'll create a program that triggers on the `unlink` syscall, schedules async work, and verifies that both the main path and workqueue callback execute correctly.

### Complete BPF Program: wq_simple.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Simple BPF workqueue example */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char LICENSE[] SEC("license") = "GPL";

/* Element with embedded workqueue */
struct elem {
	int value;
	struct bpf_wq work;
};

/* Array to store our element */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

/* Result variables */
__u32 wq_executed = 0;
__u32 main_executed = 0;

/* Workqueue callback - runs asynchronously in workqueue context */
static int wq_callback(void *map, int *key, void *value)
{
	struct elem *val = value;
	/* This runs later in workqueue context */
	wq_executed = 1;
	val->value = 42; /* Modify the value asynchronously */
	return 0;
}

/* Main program - schedules work */
SEC("fentry/do_unlinkat")
int test_workqueue(void *ctx)
{
	struct elem init = {.value = 0}, *val;
	struct bpf_wq *wq;
	int key = 0;

	main_executed = 1;

	/* Initialize element in map */
	bpf_map_update_elem(&array, &key, &init, 0);

	/* Get element from map */
	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return 0;

	/* Initialize workqueue */
	wq = &val->work;
	if (bpf_wq_init(wq, &array, 0) != 0)
		return 0;

	/* Set callback function */
	if (bpf_wq_set_callback(wq, wq_callback, 0))
		return 0;

	/* Schedule work to run asynchronously */
	if (bpf_wq_start(wq, 0))
		return 0;

	return 0;
}
```

### Understanding the BPF Code

The program demonstrates the complete workqueue workflow from initialization through async execution. We start by defining a structure that embeds a workqueue. The `struct elem` contains both application data (`value`) and the workqueue handle (`struct bpf_wq work`). This embedding pattern is critical - the workqueue infrastructure needs to know which map contains the workqueue structure, and embedding it in the map value establishes this relationship.

Our map is a simple array with one entry, chosen for simplicity in this example. In production code, you'd typically use hash maps to track multiple entities, each with its own embedded workqueue. The global variables `wq_executed` and `main_executed` serve as test instrumentation, letting userspace verify that both code paths ran.

The workqueue callback shows the signature that all workqueue callbacks must follow: `int callback(void *map, int *key, void *value)`. The kernel invokes this function asynchronously in process context, passing the map containing the workqueue, the key of the entry, and a pointer to the value. This signature gives the callback full context about which element triggered it and access to the element's data. Our callback sets `wq_executed = 1` to prove it ran, and modifies `val->value = 42` to demonstrate that async modifications persist in the map.

The main program attached to `fentry/do_unlinkat` triggers whenever the `unlink` syscall executes. This gives us an easy way to activate the program - userspace just needs to delete a file. We set `main_executed = 1` immediately to mark the synchronous path. Then we initialize an element and store it in the map using `bpf_map_update_elem()`. This is necessary because the workqueue must be embedded in a map entry.

The workqueue initialization follows a three-step sequence. First, `bpf_wq_init(wq, &array, 0)` initializes the workqueue handle, passing the map that contains it. The verifier uses this information to validate that the workqueue and its container are properly related. Second, `bpf_wq_set_callback(wq, wq_callback, 0)` registers our callback function. The verifier checks that the callback has the correct signature. Third, `bpf_wq_start(wq, 0)` schedules the workqueue to execute asynchronously. This call returns immediately - the main program continues executing while the kernel queues the work for later execution in process context.

The flags parameter in all three functions is reserved for future use and should be 0 in current kernels. The pattern allows future extensions without breaking API compatibility.

### Complete User-Space Program: wq_simple.c

```c
// SPDX-License-Identifier: GPL-2.0
/* Userspace test for BPF workqueue */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "wq_simple.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct wq_simple_bpf *skel;
	int err, fd;

	libbpf_set_print(libbpf_print_fn);

	/* Open and load BPF application */
	skel = wq_simple_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = wq_simple_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("BPF workqueue program attached. Triggering unlink syscall...\n");

	/* Create a temporary file to trigger do_unlinkat */
	fd = open("/tmp/wq_test_file", O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		close(fd);
		unlink("/tmp/wq_test_file");
	}

	/* Give workqueue time to execute */
	sleep(1);

	/* Check results */
	printf("\nResults:\n");
	printf("  main_executed = %u (expected: 1)\n", skel->bss->main_executed);
	printf("  wq_executed = %u (expected: 1)\n", skel->bss->wq_executed);

	if (skel->bss->main_executed == 1 && skel->bss->wq_executed == 1) {
		printf("\n✓ Test PASSED!\n");
	} else {
		printf("\n✗ Test FAILED!\n");
		err = 1;
	}

cleanup:
	wq_simple_bpf__destroy(skel);
	return err;
}
```

### Understanding the User-Space Code

The userspace program orchestrates the test and verifies results. We use the skeleton API from libbpf which embeds the compiled BPF bytecode in a C structure, making loading trivial. The `wq_simple_bpf__open_and_load()` call compiles (if needed), loads the BPF program into the kernel, and creates all maps in one operation.

After loading, `wq_simple_bpf__attach()` attaches the fentry program to `do_unlinkat`. From this point, any unlink syscall will trigger our BPF program. We deliberately trigger this by creating and immediately deleting a temporary file. The `open()` creates `/tmp/wq_test_file`, we close the fd, then `unlink()` deletes it. This deletion enters the kernel's `do_unlinkat` function, triggering our fentry probe.

Here's the critical timing aspect: workqueue execution is asynchronous. Our main BPF program schedules the work and returns immediately. The kernel queues the callback for later execution by a kernel worker thread. This is why we `sleep(1)` - giving the workqueue time to execute before we check results. In production code, you'd use more sophisticated synchronization, but for a simple test, sleep is sufficient.

After the sleep, we read global variables from the BPF program's `.bss` section. The skeleton provides convenient access through `skel->bss->main_executed` and `skel->bss->wq_executed`. If both are 1, we know the synchronous path (fentry) and async path (workqueue callback) both executed successfully.

## Understanding Workqueue APIs

The workqueue API consists of three essential functions that manage the lifecycle. **`bpf_wq_init(wq, map, flags)`** initializes a workqueue handle, establishing the relationship between the workqueue and its containing map. The map parameter is crucial - it tells the verifier which map contains the value with the embedded `bpf_wq` structure. The verifier uses this to ensure memory safety across async execution. Flags should be 0 in current kernels.

**`bpf_wq_set_callback(wq, callback_fn, flags)`** registers the function to execute asynchronously. The callback must have the signature `int callback(void *map, int *key, void *value)`. The verifier checks this signature at load time and will reject programs with mismatched signatures. This type safety prevents common async programming errors. Flags should be 0.

**`bpf_wq_start(wq, flags)`** schedules the workqueue to run. This returns immediately - your BPF program continues executing synchronously. The kernel queues the callback for execution by a worker thread in process context at some point in the future. The callback might run microseconds or milliseconds later depending on system load. Flags should be 0.

The callback signature deserves attention. Unlike `bpf_timer` callbacks which receive `(void *map, __u32 *key, void *value)`, workqueue callbacks receive `(void *map, int *key, void *value)`. Note the key type difference - `int *` vs `__u32 *`. This reflects the evolution of the API and must be matched exactly or the verifier rejects your program. The callback runs in process context, so it can safely perform operations that would crash in softirq context.

## When to Use Workqueues vs Timers

Choose **bpf_timer** when you need microsecond-precision timing, operations are fast and non-blocking, you're updating counters or simple state, or implementing periodic fast-path operations like statistics collection or packet pacing. Timers excel at time-critical tasks that must execute with minimal latency.

Choose **bpf_wq** when you need to sleep or wait, allocate memory with `kzalloc()`, perform device or network I/O, or defer cleanup operations that can happen later. Workqueues are perfect for the "fast path + slow path" pattern where critical operations happen immediately and expensive processing runs asynchronously. Examples include HID device I/O (keyboard macro injection with delays), async map cleanup (preventing memory leaks), security policy updates (querying external databases), and background processing (compression, encryption, aggregation).

The fundamental trade-off is latency vs capability. Timers have lower latency but restricted capabilities. Workqueues have higher latency but full process context capabilities including sleeping and blocking I/O.

## Compilation and Execution

Navigate to the bpf_wq directory and build:

```bash
cd bpf-developer-tutorial/src/features/bpf_wq
make
```

The Makefile compiles the BPF program with the experimental workqueue features enabled and generates a skeleton header.

Run the simple workqueue test:

```bash
sudo ./wq_simple
```

Expected output:

```
BPF workqueue program attached. Triggering unlink syscall...

Results:
  main_executed = 1 (expected: 1)
  wq_executed = 1 (expected: 1)

✓ Test PASSED!
```

The test verifies that both the synchronous fentry probe and the asynchronous workqueue callback executed successfully. If the workqueue callback didn't run, `wq_executed` would be 0 and the test would fail.

## Historical Timeline and Context

Understanding how workqueues came to exist helps appreciate their design. In 2022, Benjamin Tissoires started work on HID-BPF, aiming to let users fix broken HID devices without kernel drivers. By 2023, he realized `bpf_timer` limitations made HID device I/O impossible - you can't wait for hardware responses in softirq context. In early 2024, he proposed `bpf_wq` as "bpf_timer in process context," collaborating with the BPF community on the design. The kernel merged workqueues in April 2024 as part of Linux v6.10. Since then, they've been used for HID quirks, rate limiting, async cleanup, and other sleepable operations.

The key quote from Benjamin's patches captures the motivation perfectly: "I need something similar to bpf_timers, but not in soft IRQ context... the bpf_timer functionality would prevent me to kzalloc and wait for the device."

This real-world need drove the design. Workqueues exist because device handling and resource management require sleepable, blocking operations that timers fundamentally cannot provide.

## Summary and Next Steps

BPF workqueues solve a fundamental limitation of eBPF by enabling sleepable, blocking operations in process context. Created specifically to support HID device handling where timing delays and device I/O are essential, workqueues unlock powerful new capabilities for eBPF programs. They enable the "fast path + slow path" pattern where performance-critical operations execute immediately while expensive cleanup and I/O happen asynchronously without blocking.

Our simple example demonstrates the core workqueue lifecycle: embedding a `bpf_wq` in a map value, initializing and configuring it, scheduling async execution, and verifying the callback runs in process context. This same pattern scales to production use cases like network rate limiting with async cleanup, security monitoring with external service queries, and device handling with I/O operations.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Original Kernel Patches:** Benjamin Tissoires' HID-BPF and bpf_wq patches (2023-2024)
- **Linux Kernel Source:** `kernel/bpf/helpers.c` - workqueue implementation
- **Tutorial Repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/bpf_wq>

Example adapted from Linux kernel BPF selftests with educational enhancements. Requires Linux kernel 6.10+ for workqueue support. Complete source code available in the tutorial repository.
