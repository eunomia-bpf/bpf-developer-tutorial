## eBPF 入门实践教程：编写 eBPF 程序监控打开文件路径并使用 Prometheus 可视化

### 背景

通过对 open 系统调用的监测，`opensnoop`可以展现系统内所有调用了 open 系统调用的进程信息。

### 使用 ecli 一键运行

```console
$ # 下载安装 ecli 二进制
$ wget https://aka.pw/bpf-ecli -O ./ecli && chmod +x ./ecli
$ # 使用 url 一键运行
$ ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/opensnoop/package.json

running and waiting for the ebpf events from perf event...
time ts pid uid ret flags comm fname
00:58:08 0 812 0 9 524288 vmtoolsd /etc/mtab
00:58:08 0 812 0 11 0 vmtoolsd /proc/devices
00:58:08 0 34351 0 24 524288 ecli /etc/localtime
00:58:08 0 812 0 9 0 vmtoolsd /sys/class/block/sda5/../device/../../../class
00:58:08 0 812 0 -2 0 vmtoolsd /sys/class/block/sda5/../device/../../../label
00:58:08 0 812 0 9 0 vmtoolsd /sys/class/block/sda1/../device/../../../class
00:58:08 0 812 0 -2 0 vmtoolsd /sys/class/block/sda1/../device/../../../label
00:58:08 0 812 0 9 0 vmtoolsd /run/systemd/resolve/resolv.conf
00:58:08 0 812 0 9 0 vmtoolsd /proc/net/route
00:58:08 0 812 0 9 0 vmtoolsd /proc/net/ipv6_route
```

### 实现

使用 eunomia-bpf 可以帮助你只需要编写内核态应用程序，不需要编写任何用户态辅助框架代码；需要编写的代码由两个部分组成：

- 头文件 opensnoop.h 里面定义需要导出的 C 语言结构体：
- 源文件 opensnoop.bpf.c 里面定义 BPF 代码：

头文件 opensnoop.h

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

// used for export event
struct event {
	/* user terminology for pid: */
	unsigned long long ts;
	int pid;
	int uid;
	int ret;
	int flags;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

#endif /* __OPENSNOOP_H */
```

`opensnoop` 的实现逻辑比较简单，它在 `sys_enter_open` 和 `sys_enter_openat` 这两个追踪点下
加了执行函数，当有 open 系统调用发生时，执行函数便会被触发。同样在，在对应的 `sys_exit_open` 和
`sys_exit_openat` 系统调用下，`opensnoop` 也加了执行函数。

源文件 opensnoop.bpf.c

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "opensnoop.h"

struct args_t {
	const char *fname;
	int flags;
};

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[0];
		args.flags = (int)ctx->args[1];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[1];
		args.flags = (int)ctx->args[2];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;
	int ret;
	u32 pid = bpf_get_current_pid_tgid();

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	/* event data */
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	event.flags = ap->flags;
	event.ret = ret;

	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
```

在 enter 环节，`opensnoop` 会记录调用者的 pid, comm 等基本信息，并存入 map 中。在 exit 环节，`opensnoop`
会根据 pid 读出之前存入的数据，再结合捕获的其他数据，输出到用户态处理函数中，展现给用户。

完整示例代码请参考：https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop

把头文件和源文件放在独立的目录里面，编译运行：

```bash
$ # 使用容器进行编译，生成一个 package.json 文件，里面是已经编译好的代码和一些辅助信息
$ docker run -it -v /path/to/opensnoop:/src yunwei37/ebpm:latest
$ # 运行 eBPF 程序（root shell）
$ sudo ecli run package.json
```

### Prometheus 可视化

编写 yaml 配置文件：

```yaml
programs:
  - name: opensnoop
    metrics:
      counters:
        - name: eunomia_file_open_counter
          description: test
          labels:
            - name: pid
            - name: comm
            - name: filename
              from: fname
    compiled_ebpf_filename: package.json
```

使用 eunomia-exporter 实现导出信息到 Prometheus：

- 通过 https://github.com/eunomia-bpf/eunomia-bpf/releases 下载 eunomia-exporter

```console
$ ls
config.yaml  eunomia-exporter package.json
$ sudo ./eunomia-exporter

Running ebpf program opensnoop takes 46 ms
Listening on http://127.0.0.1:8526
running and waiting for the ebpf events from perf event...
Receiving request at path /metrics
```

![result](../img/opensnoop_prometheus.png)

### 总结和参考资料

`opensnoop` 通过对 open 系统调用的追踪，使得用户可以较为方便地掌握目前系统中调用了 open 系统调用的进程信息。

参考资料：

- 源代码：https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop
- libbpf 参考代码：https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c
- eunomia-bpf 手册：https://eunomia-bpf.github.io/
