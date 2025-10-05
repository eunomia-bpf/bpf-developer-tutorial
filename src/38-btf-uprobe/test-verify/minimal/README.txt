# minimal examples

- `uprobe/uretprobe`: trace userspace functions at start or and. No affect the control flow.
- `uprobe-override`: replace the userspace function with a eBPF function

You can use `bpf_override_return` to change the control flow and return value of the function.

```c
/*
 * bpf_override_return
 *
 *  Used for error injection, this helper uses kprobes to override
 *  the return value of the probed function, and to set it to *rc*.
 *  The first argument is the context *regs* on which the kprobe
 *  works.
 *
 *  This helper works by setting the PC (program counter)
 *  to an override function which is run in place of the original
 *  probed function. This means the probed function is not run at
 *  all. The replacement function just returns with the required
 *  value.
 *
 *  This helper has security implications, and thus is subject to
 *  restrictions. It is only available if the kernel was compiled
 *  with the **CONFIG_BPF_KPROBE_OVERRIDE** configuration
 *  option, and in this case it only works on functions tagged with
 *  **ALLOW_ERROR_INJECTION** in the kernel code.
 *
 *  Also, the helper is only available for the architectures having
 *  the CONFIG_FUNCTION_ERROR_INJECTION option. As of this writing,
 *  x86 architecture is the only one to support this feature.
 *
 * Returns
 *  0
 */
static long (*bpf_override_return)(struct pt_regs *regs, __u64 rc) = (void *) 58;
```

## uprobe trace

This code is a BPF (Berkeley Packet Filter) program written in C, often used for tracing and monitoring activities in the Linux kernel. BPF allows you to run custom programs within the kernel without modifying its source code. The code you provided creates a BPF program that uses a BPF map to count the number of times the `uprobe` function is called within a specified cgroup.

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} libc_uprobe_calls_total SEC(".maps");

SEC("uprobe/libc.so.6:uprobe")
int do_count(struct pt_regs *ctx)
{
    u64 cgroup_id = bpf_get_current_cgroup_id();

    increment_map(&libc_uprobe_calls_total, &cgroup_id, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

from <https://github.com/cloudflare/ebpf_exporter/blob/master/examples/uprobe.bpf.c>

Here's a breakdown of the code:

1. **Headers Inclusion**:
   - `<vmlinux.h>`: Provides access to kernel data structures and definitions.
   - `<bpf/bpf_helpers.h>`: Includes helper functions and macros for BPF programs.
   - `"bits.bpf.h"`: Custom header file (assumed to contain additional definitions).
   - `"maps.bpf.h"`: Custom header file (assumed to contain definitions related to BPF maps).

2. **Definition of BPF Map**:
   The code defines a BPF map named `libc_uprobe_calls_total` using the `struct` syntax. This map is of type `BPF_MAP_TYPE_HASH` (hash map) with a maximum of 1024 entries. The keys and values are of type `u64` (unsigned 64-bit integer).

3. **Map Definition Attributes**:
   The attributes specified within the map definition (`__uint`, `__type`) set properties of the map, such as its type, maximum number of entries, and types of keys and values.

4. **BPF Program**:
   - The program is associated with a `uprobe` on the `uprobe` function in the `libc.so.6` library.
   - The `do_count` function is executed when the `uprobe` function is called.
   - It retrieves the current cgroup ID using `bpf_get_current_cgroup_id()`.
   - Then, it increments the `libc_uprobe_calls_total` map with the cgroup ID as the key and increments the associated value by 1.

5. **License Information**:
   The `LICENSE[]` array contains the license information for the BPF program. In this case, the program is licensed under the GPL (GNU General Public License).

The purpose of this BPF program is to track and count the number of `uprobe` calls that occur within specific cgroups in the Linux kernel. It uses a BPF hash map to store and update the counts. This can be useful for monitoring memory allocation patterns and resource usage within different cgroups.

### how to run uprobe

server

```console
example/minimal# LD_PRELOAD=~/.bpftime/libbpftime-syscall-server.so ./uprobe
```

client

```console
example/minimal#  LD_PRELOAD=~/.bpftime/libbpftime-agent.so ./victim
```

## Syscall

### how to run syscall

server

```sh
LD_PRELOAD=~/.bpftime/libbpftime-syscall-server.so ./syscall
```

client

```sh
sudo ~/.bpftime/bpftime start -s ./victim
# or AGENT_SO=build/runtime/agent/libbpftime-agent.so LD_PRELOAD=build/attach/text_segment_transformer/libbpftime-agent-transformer.so ./victim
```
