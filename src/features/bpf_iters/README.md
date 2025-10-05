# BPF Iterators Tutorial

## What are BPF Iterators?

BPF iterators allow you to iterate over kernel data structures and export formatted data to userspace via `seq_file`. They're a modern replacement for traditional `/proc` files with **programmable, filterable, in-kernel data processing**.

## Real-World Example: Task Stack Iterator

### The Problem with Traditional Approach

**Traditional method** (using `/proc` or system tools):
```bash
# Show all process stack traces
cat /proc/*/stack
```

**Problems:**
1. ❌ **No filtering** - Must read ALL processes, parse in userspace
2. ❌ **Fixed format** - Cannot customize output
3. ❌ **High overhead** - Context switches, string formatting, massive output
4. ❌ **Post-processing** - All filtering/aggregation in userspace
5. ❌ **Inflexible** - Want different fields? Modify kernel!

### BPF Iterator Solution

**Our implementation** (`task_stack.bpf.c`):
```bash
# Show only systemd tasks with kernel stack traces
sudo ./task_stack systemd
```

**Benefits:**
1. ✅ **In-kernel filtering** - Only selected processes sent to userspace
2. ✅ **Custom format** - Choose exactly what fields to show
3. ✅ **Low overhead** - Filter before copying to userspace
4. ✅ **Programmable** - Add statistics, calculations, aggregations
5. ✅ **Dynamic** - Load different filters without kernel changes

### Performance Comparison

| Operation | Traditional `/proc` | BPF Iterator |
|-----------|-------------------|--------------|
| Read all stacks | Parse 1000+ files | Single read() call |
| Filter by name | Userspace loop | In-kernel filter |
| Data transfer | MB of text | KB of relevant data |
| CPU usage | High (parsing) | Low (pre-filtered) |
| Customization | Recompile kernel | Load new BPF program |

## Example Output

```
$ sudo ./task_stack systemd
Filtering for tasks matching: systemd

=== BPF Task Stack Iterator ===

=== Task: systemd (pid=1, tgid=1) ===
Stack depth: 6 frames
  [ 0] ep_poll+0x447/0x460
  [ 1] do_epoll_wait+0xc3/0xe0
  [ 2] __x64_sys_epoll_wait+0x6d/0x110
  [ 3] x64_sys_call+0x19b1/0x2310
  [ 4] do_syscall_64+0x7e/0x170
  [ 5] entry_SYSCALL_64_after_hwframe+0x76/0x7e

=== Summary: 2 task stacks shown ===
```

## How It Works

### 1. BPF Program (`task_stack.bpf.c`)

```c
SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;

    // In-kernel filtering by task name
    if (target_comm[0] != '\0' && !match_name(task->comm))
        return 0;  // Skip this task

    // Get kernel stack trace
    bpf_get_task_stack(task, entries, MAX_DEPTH * SIZE_OF_ULONG, 0);

    // Format and output to seq_file
    BPF_SEQ_PRINTF(seq, "Task: %s (pid=%u)\n", task->comm, task->pid);

    return 0;
}
```

### 2. Userspace Program (`task_stack.c`)

```c
// Attach iterator
link = bpf_program__attach_iter(skel->progs.dump_task_stack, NULL);

// Create iterator instance
iter_fd = bpf_iter_create(bpf_link__fd(link));

// Read output
while ((len = read(iter_fd, buf, sizeof(buf))) > 0) {
    printf("%s", buf);
}
```

## Available Iterator Types

The kernel provides many iterator types:

### System Iterators
- `iter/task` - Iterate all tasks/processes
- `iter/ksym` - Kernel symbols (like `/proc/kallsyms`)
- `iter/bpf_map` - All BPF maps in system
- `iter/bpf_link` - All BPF links

### Network Iterators
- `iter/tcp` - TCP sockets (replaces `/proc/net/tcp`)
- `iter/udp` - UDP sockets
- `iter/unix` - Unix domain sockets
- `iter/netlink` - Netlink sockets

### Map Iterators
- `iter/bpf_map_elem` - Iterate map elements
- `iter/sockmap` - Socket map entries

### Task/Process Iterators
- `iter/task_file` - Task file descriptors (like `/proc/PID/fd`)
- `iter/task_vma` - Task memory mappings (like `/proc/PID/maps`)

## Use Cases

### 1. Performance Monitoring
- Track high-latency network connections
- Monitor stuck processes (long-running syscalls)
- Identify memory-hungry tasks

### 2. Debugging
- Capture stack traces of specific processes
- Dump kernel state for analysis
- Trace system calls in real-time

### 3. Security
- Monitor process creation patterns
- Track network connection attempts
- Audit file access patterns

### 4. Custom `/proc` Replacements
- Create application-specific views
- Filter and aggregate kernel data
- Reduce userspace processing overhead

## Building and Running

```bash
# Build
cd /home/yunwei37/workspace/bpf-developer-tutorial/src/features/bpf_iters
make

# Run - show all tasks
sudo ./task_stack

# Run - filter by task name
sudo ./task_stack systemd
sudo ./task_stack bash
```

## Key Differences: Iterator Types

### Kernel Iterators (`SEC("iter/...")`)
- **Purpose**: Export kernel data to userspace
- **Output**: seq_file (readable via read())
- **Activation**: Attach, create instance, read FD
- **Example**: Task stacks, TCP sockets, kernel symbols

### Open-Coded Iterators (`bpf_for`, `bpf_iter_num`)
- **Purpose**: Loop constructs within BPF programs
- **Output**: Internal program variables
- **Activation**: Execute during program run
- **Example**: Sum numbers, count elements, iterate arrays

## Advantages Over Traditional Approaches

| Feature | Traditional `/proc` | BPF Iterators |
|---------|-------------------|---------------|
| **Filtering** | Userspace only | In-kernel |
| **Performance** | High overhead | Minimal overhead |
| **Customization** | Kernel rebuild | Load BPF program |
| **Format** | Fixed | Fully programmable |
| **Statistics** | Userspace calc | In-kernel aggregation |
| **Security** | No filtering | LSM hooks available |
| **Deployment** | Static | Dynamic (load anytime) |

## Summary

BPF iterators are **game-changing** for system observability:

1. **Performance**: Filter in kernel, only send relevant data
2. **Flexibility**: Load different programs for different views
3. **Power**: Access raw kernel structures with type safety (BTF)
4. **Safety**: Verified by BPF verifier, can't crash kernel
5. **Portability**: CO-RE ensures binary works across kernel versions

They enable creating **custom, high-performance system monitoring tools** without modifying the kernel!
