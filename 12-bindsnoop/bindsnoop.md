## eBPF 入门实践教程：编写 eBPF 程序 Bindsnoopn 监控 socket 端口绑定事件

### 背景

Bindsnoop 会跟踪操作 socket 端口绑定的内核函数，并且在可能会影响端口绑定的系统调用发生之前，打印
现有的 socket 选项。

### 实现原理

Bindsnoop 通过kprobe实现。其主要挂载点为 inet_bind 和 inet6_bind。inet_bind 为处理 IPV4 类型
socket 端口绑定系统调用的接口，inet6_bind 为处理IPV6类型 socket 端口绑定系统调用的接口。

```c
SEC("kprobe/inet_bind")
int BPF_KPROBE(ipv4_bind_entry, struct socket *socket)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_entry(ctx, socket);
}
SEC("kretprobe/inet_bind")

int BPF_KRETPROBE(ipv4_bind_exit)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_exit(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(ipv6_bind_entry, struct socket *socket)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(ipv6_bind_exit)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return probe_exit(ctx, 6);
}
```

当系统试图进行socket端口绑定操作时, kprobe挂载的处理函数会被触发。在进入绑定函数时，`probe_entry`会先被
调用，它会以 tid 为主键将 socket 信息存入 map 中。

```c
static int probe_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_map_update_elem(&sockets, &tid, &socket, BPF_ANY);
	return 0;
};
```
在执行完绑定函数后，`probe_exit`函数会被调用。该函数会读取tid对应的socket信息，将其和其他信息一起
写入 event 结构体并输出到用户态。

```c
struct bind_event {
	unsigned __int128 addr;
	__u64 ts_us;
	__u32 pid;
	__u32 bound_dev_if;
	int ret;
	__u16 port;
	__u16 proto;
	__u8 opts;
	__u8 ver;
	char task[TASK_COMM_LEN];
};
```

当用户停止该工具时，其用户态代码会读取存入的数据并按要求打印。

### Eunomia中使用方式

![result](../imgs/mountsnoop.jpg)
![result](../imgs/bindsnoop-prometheus.png)

### 总结

Bindsnoop 通过 kprobe 挂载点，实现了对 socket 端口的监视，增强了 Eunomia 的应用范围。