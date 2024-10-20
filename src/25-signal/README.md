# Using bpf_send_signal to Terminate Malicious Processes in eBPF

eBPF (Extended Berkeley Packet Filter) is a revolutionary technology in the Linux kernel that allows users to execute custom programs in kernel space without modifying the kernel source code or loading any kernel modules. This provides developers with great flexibility to observe, modify, and control the Linux system.

This article introduces how to use the `bpf_send_signal` feature of eBPF to intervene by sending signals to specified processes. For more tutorial documentation and complete source code, please refer to <https://github.com/eunomia-bpf/bpf-developer-tutorial>.

## Use Cases

**1. Performance Issues:**  

Optimizing the performance of applications is a core task for developers and system administrators in the modern software ecosystem. When applications, such as hhvm, run slowly or have abnormally high resource utilization, they can adversely affect the entire system. Therefore, pinpointing these performance bottlenecks and resolving them promptly is crucial.

**2. Anomaly Detection and Response:**  

Any system running in a production environment may face various anomalies, from simple resource leaks to complex malware attacks. In these situations, the system needs to detect these anomalies quickly and accurately and take appropriate countermeasures.

**3. Dynamic System Management:**  

With the rise of cloud computing and microservice architectures, dynamically adjusting resource configurations and application behaviors based on the current system state has become a key requirement. For example, auto-scaling based on traffic fluctuations or reducing CPU frequency when detecting system overheating.

### Limitations of Existing Solutions

To meet the needs of the above use cases, traditional technical methods are as follows:

- Install a bpf program that continuously monitors the system while polling a map.
- When an event triggers specific conditions defined in the bpf program, it writes related data to this map.
- Then, external analysis tools read data from this map and send signals to the target process based on the retrieved information.

Although this method is feasible in many scenarios, it has a major flaw: the time delay from when the event occurs to when the external tool responds can be relatively large. This delay can affect the speed of event response, making performance analysis results inaccurate or failing to respond promptly to malicious activity.

### Advantages of the New Solution

To overcome the limitations of traditional methods, the Linux kernel offers the `bpf_send_signal` and `bpf_send_signal_thread` helper functions.

The main advantages of these functions include:

**1. Real-time Response:**  

By sending signals directly from kernel space, avoiding extra overhead in user space, signals can be sent immediately after an event occurs, significantly reducing latency.

**2. Accuracy:**  

Thanks to reduced latency, we can now obtain a more accurate snapshot of the system state, especially important for performance analysis and anomaly detection.

**3. Flexibility:**  

These new helper functions provide developers with more flexibility. They can customize the signal sending logic according to different use cases and needs, allowing for more precise control and management of system behavior.

## Kernel Code Analysis

In modern operating systems, a common security strategy is to monitor and control interactions between processes. Especially in Linux systems, the `ptrace` system call is a powerful tool that allows one process to observe and control the execution of another process, modifying its registers and memory. This makes it the primary mechanism for debugging and tracing tools like `strace` and `gdb`. However, malicious use of `ptrace` can also pose security risks.

The goal of this program is to monitor `ptrace` calls in kernel mode. When specific conditions are met, it sends a `SIGKILL` signal to terminate the calling process. Additionally, for debugging or auditing purposes, the program logs this intervention and sends related information to user space.

## Code Analysis

### 1. Data Structure Definition (`signal.h`)

signal.h

```c
// Simple message structure to get events from eBPF Programs
// in the kernel to user space
#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};
```

This section defines a simple message structure used to pass events from eBPF programs in the kernel to user space. The structure includes the process ID, command name, and a boolean value indicating whether the signal was successfully sent.

### 2. eBPF Program (`signal.bpf.c`)

signal.bpf.c

```c
// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

SEC("tp/syscalls/sys_enter_ptrace")
int bpf_dos(struct trace_event_raw_sys_enter *ctx)
{
    long ret = 0;
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Send signal. 9 == SIGKILL
    ret = bpf_send_signal(9);

    // Log event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
```

- **License Declaration**

  The program's license is declared as "Dual BSD/GPL". This is to meet the Linux kernel's licensing requirements for eBPF programs.

- **Ringbuffer Map**

  This is a ring buffer type map that allows messages generated by the eBPF program in kernel space to be efficiently read by user space programs.

- **Target Parent Process ID**

  `target_ppid` is an optional parent process ID used to limit which processes are affected. If set to a non-zero value, only processes that match it will be targeted.

- **Main Function `bpf_dos`**

  - **Process Check**  
    The program first retrieves the current process's ID. If `target_ppid` is set, it also retrieves the current process's parent process ID and compares them. If they don't match, it returns immediately.

  - **Sending Signal**  
    It uses `bpf_send_signal(9)` to send a `SIGKILL` signal. This terminates the process calling `ptrace`.

  - **Logging the Event**  
    The event is logged using the ring buffer map. This includes whether the signal was successfully sent, the process ID, and the process's command name.

In summary, this eBPF program provides a method that allows system administrators or security teams to monitor and intervene `ptrace` calls at the kernel level, offering an additional layer against potential malicious activities or misoperations.

## Compilation and Execution

eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain combined with Wasm. Its purpose is to simplify the development, building, distribution, and execution of eBPF programs. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> to download and install the `ecc` compiler toolchain and `ecli` runtime. We use eunomia-bpf to compile and run this example.

Compilation:

```bash
./ecc signal.bpf.c signal.h
```

Usage:

```console
$ sudo ./ecli package.json
TIME     PID    COMM   SUCCESS
```

This program will send a `SIG_KILL` signal to any program attempting to use the `ptrace` system call, such as `strace`. Once the eBPF program starts running, you can test it by running the following command:

```bash
$ strace /bin/whoami
Killed
```

The original console will output:

```txt
INFO [bpf_loader_lib::skeleton] Running ebpf program...
TIME     PID    COMM   SUCCESS 
13:54:45  8857  strace true
```

The complete source code can be found at: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/25-signal>

## Conclusion

Through this example, we delved into how to combine eBPF programs with user-space programs to monitor and intervene in system calls. eBPF provides a mechanism for executing programs in kernel space. This technology is not limited to monitoring but can also be used for performance optimization, security defense, system diagnostics, and various other scenarios. For developers, it offers a powerful and flexible tool for performance tuning and troubleshooting in Linux systems.

Lastly, if you are interested in eBPF technology and wish to further understand and practice, you can visit our tutorial code repository <https://github.com/eunomia-bpf/bpf-developer-tutorial> and tutorial website <https://eunomia.dev/zh/tutorials/>.

## References

- <https://github.com/pathtofile/bad-bpf>
- <https://www.mail-archive.com/netdev@vger.kernel.org/msg296358.html>

> The original link of this article: <https://eunomia.dev/tutorials/25-signal>
