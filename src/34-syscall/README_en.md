# eBPF Development Practice: Modifying System Call Arguments with eBPF

eBPF (Extended Berkeley Packet Filter) is a powerful feature in the Linux kernel that allows user-defined code to be run, loaded, and updated without the need to modify kernel source code or reboot the kernel. This functionality has enabled a wide range of applications for eBPF, such as network and system performance analysis, packet filtering, and security policies.

In this tutorial, we will explore how to use eBPF to modify the arguments of a running system call. This technique can be used for security auditing, system monitoring, or even malicious behavior. However, it is important to note that modifying system call arguments can have negative implications for system stability and security, so caution must be exercised. To implement this functionality, we will use the `bpf_probe_write_user` feature of eBPF, which allows us to modify memory in the user space and therefore modify system call arguments before the kernel reads them from user space.

The complete code for this tutorial can be found in the <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/34-syscall/> repository on GitHub.

## Modifying the File Name of the `open` System Call

This functionality is used to modify the arguments of the `openat` system call to open a different file. This technique can be useful for:

1. **File Access Auditing**: In environments with strict legal and data security requirements, auditors may need to record access to sensitive files. By modifying the `openat` system call arguments, all attempts to access a specific sensitive file can be redirected to a backup file or a log file.
2. **Secure Sandbox**: In the early stages of development, it may be desirable to monitor the files accessed by an application. By changing the `openat` calls, the application can be run in a secure sandbox environment where all file operations are redirected to an isolated file system path.
3. **Sensitive Data Protection**: For files containing sensitive information, such as a configuration file that contains database passwords, a eBPF-based system can redirect those calls to an encrypted or temporary location to enhance data security.

If leveraged by malicious software, this technique can be used to redirect file operations resulting in data leaks or compromise data integrity. For example, when a program is writing to a log file, an attacker could redirect the data to a controlled file, disrupting the audit trail.

Kernel code (partial code, see complete code on Github bpf-developer-tutorial):

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

Analysis of the kernel code:

- `bpf_get_current_pid_tgid()` retrieves the current process ID.
- If `target_pid` is specified and does not match the current process ID, the function returns 0 and does not execute further.
- We create an `args_t` structure to store the file name and flags.
- We use `bpf_probe_write_user` to modify the file name in the user space memory to "hijacked".

The `eunomia-bpf` is an open-source eBPF dynamic loading runtime and development toolchain aimed at making eBPF program development, building, distribution, and execution easier. You can refer to <https://github.com/eunomia-bpf/eunomia-bpf> or <https://eunomia.dev/tutorials/1-helloworld/> for installing ecc compiler toolchain and ecli runtime. We will use `eunomia-bpf` to compile and run this example.

Compile the code:

```bash
./ecc open_modify.bpf.c open_modify.h
```

Build a simple victim program using make for testing:

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

Compile and run the test code:

```sh
$ ./victim
test.txt opened, fd=3
read 5 bytes: hello
Closing test.txt...
test.txt closed
```

Use the following command to specify the target process ID to modify the `openat` system call arguments:

```bash
sudo ./ecli run package.json --rewrite --target_pid=$(pidof victim)
```

You will see that the output changes to "world". Instead of opening the "my_test.txt" file, it opens the "hijacked" file:

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

The complete code with test cases can be found in the <https://github.com/eunomia-bpf/bpf-developer-tutorial> repository.

## Modifying the Process Name of bash `execve`

This functionality is used to modify the program name when the `execve` system call is made. In certain auditing or monitoring scenarios, this may be used to track the behavior of specific processes or modify their behavior. However, such modifications can lead to confusion and make it difficult for users or administrators to determine the actual program being executed by the system. The most serious risk is that if malicious users are able to control the eBPF program, they could redirect legitimate system commands to malicious software, resulting in a significant security threat.

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

Analysis of the kernel code:

- Execute `bpf_get_current_pid_tgid` to get the current process ID and thread group ID.
- If `target_ppid` is set, the code checks if the current process's parent process ID matches.
- Read the program name from the first argument of `execve`.
- Use `bpf_probe_write_user` to overwrite the argument with a hijacked binary path.

This approach poses a risk as it can be leveraged to hijack the behavior of software, resulting in the execution of malicious code on the system. Using ecc and ecli to compile and run:

```bash
./ecc exechijack.bpf.c exechijack.h
sudo ./ecli run package.json
```

## Conclusion

eBPF provides powerful capabilities for real-time monitoring and intervention in running systems. When used in conjunction with appropriate governance and security policies, this can bring many benefits such as enhanced security, performance optimization, and operational convenience. However, this technology must be used with great care as incorrect operations or misuse can result in system disruption or serious security incidents. In practice, it should be ensured that only authorized users and programs can deploy and manage eBPF programs, and their behavior should be validated in isolated test environments before they are applied in production.
