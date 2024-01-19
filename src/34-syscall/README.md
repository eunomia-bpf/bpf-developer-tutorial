# eBPF 开发实践：使用 eBPF 修改系统调用参数

eBPF（扩展的伯克利数据包过滤器）是 Linux 内核中的一个强大功能，可以在无需更改内核源代码或重启内核的情况下，运行、加载和更新用户定义的代码。这种功能让 eBPF 在网络和系统性能分析、数据包过滤、安全策略等方面有了广泛的应用。

本教程介绍了如何使用 eBPF 修改正在进行的系统调用参数。这种技术可以用作安全审计、系统监视、或甚至恶意行为。然而需要特别注意，篡改系统调用参数可能对系统的稳定性和安全性带来负面影响，因此必须谨慎使用。实现这个功能需要使用到 eBPF 的 `bpf_probe_write_user` 功能，它可以修改用户空间的内存，因此能用来修改系统调用参数，在内核读取用户空间内存之前，将其修改为我们想要的值。

本文的完整代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/34-syscall/> 找到。

## 修改 open 系统调用的文件名

此功能用于修改 `openat` 系统调用的参数，让它打开一个不同的文件。这个功能可能可以用于：

1. **文件访问审计**：在对法律合规性和数据安全性有严格要求的环境中，审计员可能需要记录所有对敏感文件的访问行为。通过修改 `openat` 系统调用参数，可以将所有尝试访问某个敏感文件的行为重定向到一个备份文件或者日志文件。
2. **安全沙盒**：在开发早期阶段，可能希望监控应用程序尝试打开的文件。通过更改 `openat` 调用，可以让应用在一个安全的沙盒环境中运行，所有文件操作都被重定向到一个隔离的文件系统路径。
3. **敏感数据保护**：对于存储有敏感信息的文件，例如配置文件中包含有数据库密码，一个基于 eBPF 的系统可以将这些调用重定向到一个加密的或暂存的位置，以增强数据安全性。

如果该技术被恶意软件利用，攻击者可以重定向文件操作，导致数据泄漏或者破坏数据完整性。例如，程序写入日志文件时，攻击者可能将数据重定向到控制的文件中，干扰审计跟踪。

内核态代码（部分，完整内容请参考 Github bpf-developer-tutorial）：

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    /* use kernel terminology here for tgid/pid: */
    if (target_pid && pid != target_pid) {
        return 0;
    }
    /* store arg info for later lookup */
    // since we can manually specify the attach process in userspace,
    // we don't need to check the process allowed here

    struct args_t args = {};
    args.fname = (const char *)ctx->args[1];
    args.flags = (int)ctx->args[2];
    if (rewrite) {
        bpf_probe_write_user((char*)ctx->args[1], "hijacked", 9);
    }
    bpf_map_update_elem(&start, &pid, &args, 0);
    return 0;
}
```

分析内核态代码：

- `bpf_get_current_pid_tgid()` 获取当前进程ID。
- 如果指定了 `target_pid` 并且不匹配当前进程ID，函数直接返回。
- 我们创建一个 `args_t` 结构来存储文件名和标志。
- 使用 `bpf_probe_write_user` 修改用户空间内存中的文件名为 "hijacked"。

eunomia-bpf 是一个开源的 eBPF 动态加载运行时和开发工具链，它的目的是简化 eBPF 程序的开发、构建、分发、运行。可以参考 <https://github.com/eunomia-bpf/eunomia-bpf> 或 <https://eunomia.dev/tutorials/1-helloworld/> 下载和安装 ecc 编译工具链和 ecli 运行时。我们使用 eunomia-bpf 编译运行这个例子。

编译：

```bash
./ecc open_modify.bpf.c open_modify.h
```

使用 make 构建一个简单的 victim 程序，用来测试：

```c
int main()
{
    char filename[100] = "my_test.txt";
    // print pid
    int pid = getpid();
    std::cout << "current pid: " << pid << std::endl;
    system("echo \"hello\" > my_test.txt");
    system("echo \"world\" >> hijacked");
    while (true) {
        std::cout << "Opening my_test.txt" << std::endl;

        int fd = open(filename, O_RDONLY);
        assert(fd != -1);

        std::cout << "test.txt opened, fd=" << fd << std::endl;
        usleep(1000 * 300);
        // print the file content
        char buf[100] = {0};
        int ret = read(fd, buf, 5);
        std::cout << "read " << ret << " bytes: " << buf << std::endl;
        std::cout << "Closing test.txt..." << std::endl;
        close(fd);
        std::cout << "test.txt closed" << std::endl;
    }
    return 0;
}
```

测试代码编译并运行:

```sh
$ ./victim
test.txt opened, fd=3
read 5 bytes: hello
Closing test.txt...
test.txt closed
```

可以使用以下命令指定应修改其 `openat` 系统调用参数的目标进程ID：

```bash
sudo ./ecli run package.json --rewrite --target_pid=$(pidof victim)
```

然后就会发现输出变成了 world，可以看到我们原先想要打开 "my_test.txt" 文件，但是实际上被劫持打开了 hijacked 文件：

```console
test.txt opened, fd=3
read 5 bytes: hello
Closing test.txt...
test.txt closed
Opening my_test.txt
test.txt opened, fd=3
read 5 bytes: world
Closing test.txt...
test.txt closed
Opening my_test.txt
test.txt opened, fd=3
read 5 bytes: world
```

包含测试用例的完整代码可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 找到。

## 修改 bash execve 的进程名称

这段功能用于当 `execve` 系统调用进行时修改执行程序名称。在一些审计或监控场景，这可能用于记录特定进程的行为或修改其行为。然而，此类篡改可能会造成混淆，使得用户或管理员难以确定系统实际执行的程序是什么。最严重的风险是，如果恶意用户能够控制 eBPF 程序，他们可以将合法的系统命令重定向到恶意软件，造成严重的安全威胁。

```c
SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // Check if we're a process of interest
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Read in program from first arg of execve
    char prog_name[TASK_COMM_LEN];
    char prog_name_orig[TASK_COMM_LEN];
    __builtin_memset(prog_name, '\x00', TASK_COMM_LEN);
    bpf_probe_read_user(&prog_name, TASK_COMM_LEN, (void*)ctx->args[0]);
    bpf_probe_read_user(&prog_name_orig, TASK_COMM_LEN, (void*)ctx->args[0]);
    prog_name[TASK_COMM_LEN-1] = '\x00';
    bpf_printk("[EXECVE_HIJACK] %s\n", prog_name);

    // Program can't be less than out two-char name
    if (prog_name[1] == '\x00') {
        bpf_printk("[EXECVE_HIJACK] program name too small\n");
        return 0;
    }

    // Attempt to overwrite with hijacked binary path
    prog_name[0] = '/';
    prog_name[1] = 'a';
    for (int i = 2; i < TASK_COMM_LEN ; i++) {
        prog_name[i] = '\x00';
    }
    long ret = bpf_probe_write_user((void*)ctx->args[0], &prog_name, 3);

    // Send an event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            e->comm[i] = prog_name_orig[i];
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
```

分析内核态代码：

- 执行 `bpf_get_current_pid_tgid` 获取当前进程ID和线程组ID。
- 如果设置了 `target_ppid`，代码会检查当前进程的父进程ID是否匹配。
- 读取第一个 `execve` 参数到 `prog_name`，这通常是将要执行的程序的路径。
- 通过 `bpf_probe_write_user` 重写这个参数，使得系统实际执行的是一个不同的程序。

这种做法的风险在于它可以被用于劫持软件的行为，导致系统运行恶意代码。同样也可以使用 ecc 和 ecli 编译运行：

```bash
./ecc exechijack.bpf.c exechijack.h
sudo ./ecli run package.json
```

## 总结

eBPF 提供了强大的能力来实现对正在运行的系统进行实时监控和干预。在合适的监管和安全策略配合下，这可以带来诸多好处，如安全增强、性能优化和运维便利。然而，这项技术的使用必须非常小心，因为错误的操作或滥用可能会对系统的正常运作造成破坏或者引发严重的安全事件。实践中，应确保只有授权用户和程序能够部署和管理 eBPF 程序，并且应当在隔离的测试环境中验证这些eBPF程序的行为，在充分理解其影响后才能将其应用到生产环境中。

您还可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/zh/tutorials/> 以获取更多示例和完整的教程。
