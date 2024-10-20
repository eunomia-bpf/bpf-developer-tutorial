# eBPF Practical Tutorial: Using eBPF to Trace Go Routine States

Go, the popular programming language created by Google, is known for its powerful concurrency model. One of the key features that makes Go stand out is the use of goroutines—lightweight, managed threads that make it easy to write concurrent programs. However, understanding and tracing the execution states of these goroutines in real time can be challenging, especially when debugging complex systems.

Enter eBPF (Extended Berkeley Packet Filter), a technology originally designed for network packet filtering, but which has since evolved into a powerful tool for tracing and monitoring system behavior. By leveraging eBPF, we can tap into the kernel and gather insights about the runtime behavior of Go programs, including the states of goroutines. This blog post explores how to use eBPF to trace the state transitions of goroutines in a Go program.

## Background: Goroutines and eBPF

### Goroutines

Goroutines are a core feature of Go, providing a simple and efficient way to handle concurrency. Unlike traditional threads, goroutines are managed by the Go runtime rather than the operating system, making them much more lightweight. Goroutines can switch states, such as:

- **RUNNABLE**: The goroutine is ready to run.
- **RUNNING**: The goroutine is currently executing.
- **WAITING**: The goroutine is waiting for some event (e.g., I/O, timers).
- **DEAD**: The goroutine has finished executing and is terminated.

Understanding these states and how goroutines transition between them is crucial for diagnosing performance issues and ensuring that your Go programs are running efficiently.

### eBPF

eBPF is a powerful technology that allows developers to run custom programs inside the Linux kernel without changing the kernel source code or loading kernel modules. Initially designed for packet filtering, eBPF has grown into a versatile tool used for performance monitoring, security, and debugging.

By writing eBPF programs, developers can trace various system events, including system calls, network events, and process execution. In this blog, we'll focus on how eBPF can be used to trace the state transitions of goroutines in a Go program.

## The eBPF Kernel Code

Let's dive into the eBPF kernel code that makes this tracing possible.

```c
#include <vmlinux.h>
#include "goroutine.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define GOID_OFFSET 0x98

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./go-server-http/main:runtime.casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
  int newval = ctx->cx;
  void *gp = ctx->ax;
  struct goroutine_execute_data *data;
  u64 goid;
  if (bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET) == 0) {
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (data) {
      u64 pid_tgid = bpf_get_current_pid_tgid();
      data->pid = pid_tgid;
      data->tgid = pid_tgid >> 32;
      data->goid = goid;
      data->state = newval;
      bpf_ringbuf_submit(data, 0);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

1. **Header Files**: The code begins by including necessary header files, such as `vmlinux.h`, which provides kernel definitions, and `bpf_helpers.h`, which offers helper functions for eBPF programs.
2. **GOID_OFFSET**: The offset of the `goid` field is hardcoded to `0x98`, which is specific to the Go version and the program being traced. This offset may vary between different Go versions or programs.
3. **Ring Buffer Map**: A BPF ring buffer map is defined to store the goroutine execution data. This buffer allows the kernel to pass information to user space efficiently.
4. **Uprobe**: The core of this eBPF program is an uprobes (user-level probe) attached to the `runtime.casgstatus` function in the Go program. This function is responsible for changing the state of a goroutine, making it an ideal place to intercept and trace state transitions.
5. **Reading Goroutine ID**: The `bpf_probe_read_user` function reads the goroutine ID (`goid`) from the user space memory, using the predefined offset.
6. **Submitting Data**: If the goroutine ID is successfully read, the data is stored in the ring buffer along with the process ID, thread group ID, and the new state of the goroutine. This data is then submitted to the user space for analysis.

## Running the Program

To run this tracing program, follow these steps:

1. **Compile the eBPF Code**: Compile the eBPF program using a compiler like `ecc` (eBPF Compiler Collection) and generate a package that can be loaded by an eBPF loader.

    ```bash
    ecc goroutine.bpf.c goroutine.h
    ```

2. **Run the eBPF Program**: Use an eBPF loader to run the compiled eBPF program.

    ```bash
    ecli-rs run package.json
    ```

3. **Output**: The program will output the state transitions of goroutines along with their `goid`, `pid`, and `tgid`. Here’s an example of the output:

    ```console
    TIME     STATE       GOID   PID    TGID   
    21:00:47 DEAD(6)     0      2542844 2542844
    21:00:47 RUNNABLE(1) 0      2542844 2542844
    21:00:47 RUNNING(2)  1      2542844 2542844
    21:00:47 WAITING(4)  2      2542847 2542844
    ```

You can find the complete code in <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/31-goroutine>

If you want to learn more about eBPF knowledge and practices, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> to get more examples and complete tutorials.

`Uprobe` in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode, compatible with kernel mode eBPF and can be faster for `uprobe`.

### Conclusion

Tracing goroutine states using eBPF provides deep insights into the execution of Go programs, especially in production environments where traditional debugging tools may fall short. By leveraging eBPF, developers can monitor and diagnose performance issues, ensuring their Go applications run efficiently.

Keep in mind that the offsets used in this eBPF program are specific to the Go version and the program being traced. As Go evolves, these offsets may change, requiring updates to the eBPF code.

In future explorations, we can extend this approach to trace other aspects of Go programs or even other languages, demonstrating the versatility and power of eBPF in modern software development.
