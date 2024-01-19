# eBPF Development Practice: Modifying System Call Parameters with eBPF

eBPF (extended Berkeley Packet Filter) is a powerful feature in the Linux kernel that allows running, loading, and updating user-defined code without the need to modify kernel source code or restart the kernel. This capability has enabled eBPF to be widely used in areas such as network and system performance analysis, packet filtering, and security policies.

This tutorial discusses how to use eBPF to modify ongoing system call parameters. This technique can be used for purposes such as security auditing, system monitoring, or even malicious behavior. However, it is important to note that tampering with system call parameters can have negative impacts on system stability and security, so it must be used with caution. To achieve this functionality, we will use the `bpf_probe_write_user` feature of eBPF, which allows us to modify memory in the user space, thus enabling us to modify system call parameters to the values we desire before the kernel reads the user space memory.

## Modifying the File Name for the open System Call

This functionality is used to modify the arguments of the `openat` system call to open a different file. This feature can be used for:

1. **File access auditing**: In environments with strict requirements for legal compliance and data security, auditors may need to record all access attempts to sensitive files. By modifying the `openat` system call parameters, all attempts to access a specific sensitive file can be redirected to a backup file or a log file.
2. **Security sandboxing**: During early stages of development, it may be desirable to monitor the files that an application attempts to open. By changing the `openat` call, the application can run in a secure sandbox environment where all file operations are redirected to an isolated file system path.
3. **Protection of sensitive data**: For files containing sensitive information, such as a configuration file that includes a database password, a eBPF-based system can redirect these calls to an encrypted or temporary location to enhance data security.

If this technique is leveraged by malicious software, attackers can redirect file operations, leading to data leakage or compromise of data integrity. For example, when a program writes to a log file, an attacker could redirect the data to a file under their control, disrupting the audit trail.

Kernel code:

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

Analysis of kernel code:

- `bpf_get_current_pid_tgid()` is used to get the current process ID (PID).
- If `target_pid` is specified and doesn't match the current PID, the function returns.
- We create an `args_t` structure to store the file name and flags.
- We use `bpf_probe_write_user` to modify the file name in the user space memory to "hijacked".

After compiling and running the code, you can use the following command to specify the target process ID whose `openat` system call parameters should be modified:

```bash
sudo ./ecli run package.json -- --rewrite --target_pid=$(pidof victim)
```

The complete code can be found in the tutorial code repository.

## Modifying the Process Name for bash execve

This functionality is used to modify the program name when the `execve` system call is being executed. In certain auditing or monitoring scenarios, this could be used to track the behavior of specific processes or modify their behavior. However, such tampering can lead to confusion, making it difficult for users or administrators to determine the actual program being executed by the system. The most serious risk is that if malicious users can control the eBPF program, they can redirect legitimate system commands to malicious software, posing a significant security threat.

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

Analysis of kernel code:

- Use `bpf_get_current_pid_tgid` to get the current process ID and thread group ID.
- If `target_ppid` is set, the code checks if the current process's parent process ID matches.
- Read the program name from the first argument of `execve`, which is typically the path to the program being executed.
- Overwrite this argument with a hijacked binary path using `bpf_probe_write_user`, so that the system actually executes a different program.

The risk of this approach is that it can be used to hijack the behavior of legitimate software, leading to the execution of malicious code by the system.

## Conclusion

eBPF provides powerful capabilities for real-time monitoring and intervention of running systems. With proper governance and security policies in place, this can bring many benefits such as enhanced security, performance optimization, and operational convenience. However, the use of this technology must be treated with utmost care, as misoperation or misuse can cause disruption to the normal operation of the system or trigger serious security incidents. In practice, it is essential to ensure that only authorized users and programs can deploy and manage eBPF programs, and to validate the behavior of these eBPF programs in isolated test environments before applying them to production environments.

You can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/tutorials/> for more examples and complete tutorials.