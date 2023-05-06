# eBPF 入门实践教程：编写 eBPF 程序 profile 进行性能分析

## 背景

`profile` 是一款用户追踪程序执行调用流程的工具，类似于perf中的 -g 指令。但是相较于perf而言，
`profile`的功能更为细化，它可以选择用户需要追踪的层面，比如在用户态层面进行追踪，或是在内核态进行追踪。

## 实现原理

`profile` 的实现依赖于linux中的perf_event。在注入ebpf程序前，`profile` 工具会先将 perf_event
注册好。

```c
static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                      struct bpf_link *links[])
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .freq = env.freq,
        .sample_freq = env.sample_freq,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    int i, fd;

    for (i = 0; i < nr_cpus; i++) {
        if (env.cpu != -1 && env.cpu != i)
            continue;

        fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        if (fd < 0) {
            /* Ignore CPU that is offline */
            if (errno == ENODEV)
                continue;
            fprintf(stderr, "failed to init perf sampling: %s\n",
                strerror(errno));
            return -1;
        }
        links[i] = bpf_program__attach_perf_event(prog, fd);
        if (!links[i]) {
            fprintf(stderr, "failed to attach perf event on cpu: "
                "%d\n", i);
            links[i] = NULL;
            close(fd);
            return -1;
        }
    }

    return 0;
}
```

其ebpf程序实现逻辑是对程序的堆栈进行定时采样，从而捕获程序的执行流程。

```c
SEC("perf_event")
int profile(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;
    int cp;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
```

通过这种方式，它可以根据用户指令，简单的决定追踪用户态层面的执行流程或是内核态层面的执行流程。

## 编译运行

```console
$ git clone https://github.com/libbpf/libbpf-bootstrap.git --recurse-submodules 
$ cd examples/c
$ make profile
$ sudo ./profile 
COMM: chronyd (pid=156) @ CPU 1
Kernel:
  0 [<ffffffff81ee9f56>] _raw_spin_lock_irqsave+0x16
  1 [<ffffffff811527b4>] remove_wait_queue+0x14
  2 [<ffffffff8132611d>] poll_freewait+0x3d
  3 [<ffffffff81326d3f>] do_select+0x7bf
  4 [<ffffffff81327af2>] core_sys_select+0x182
  5 [<ffffffff81327f3a>] __x64_sys_pselect6+0xea
  6 [<ffffffff81ed9e38>] do_syscall_64+0x38
  7 [<ffffffff82000099>] entry_SYSCALL_64_after_hwframe+0x61
Userspace:
  0 [<00007fab187bfe09>]
  1 [<000000000ee6ae98>]

COMM: profile (pid=9843) @ CPU 6
No Kernel Stack
Userspace:
  0 [<0000556deb068ac8>]
  1 [<0000556dec34cad0>]
```

### 总结

`profile` 实现了对程序执行流程的分析，在debug等操作中可以极大的帮助开发者提高效率。
