# eBPF 教程：精准隔离已建立的 TCP 连接

某个出站 IP 地址刚刚被加入威胁情报黑名单，防火墙已经更新规则阻止新连接。但当你用 `netstat` 检查时，发现服务器上已经存在一条到该地址的活跃 TCP 会话。你需要立即关闭这条连接，但不能杀掉进程，不能影响其他流量，也不能等待会话超时。

这个看似简单的需求，用传统工具却很难实现：

- **杀进程**会断开该进程的所有连接，而不只是有问题的那条。更糟糕的是，进程重启后可能立刻重连到同一目标。

- **防火墙规则**只能阻止新连接，对已经建立的会话无能为力。即使是 `iptables -m state --state ESTABLISHED` 也只能匹配已有连接用于后续报文过滤，无法主动拆除会话。

- **用户态工具**如 `ss --kill` 或 `tcpkill` 的工作方式是读取 `/proc/net/tcp`，然后注入 TCP RST 报文。这种方式存在竞态条件：在读取套接字列表和发送 RST 之间，套接字状态可能已经改变。RST 注入还需要猜测正确的序列号，对加密隧道或某些网络配置可能失效。

我们需要的是一种内核级机制，能够原子地识别并销毁特定套接字，不存在竞态窗口。这正是 Linux 6.5 引入 `bpf_sock_destroy` 内核函数（kfunc）所提供的能力。

本教程将构建一个命令行工具，使用 BPF 迭代器遍历内核的 TCP 套接字表。dry-run 列出所有匹配远端 IPv4 地址和端口的已建立连接；apply 模式还必须给出选中的本地 IPv4 地址和端口，因此只会销毁完整 4-tuple 对应的连接。你将学习 BPF 迭代器如何在持有锁的情况下安全遍历内核数据结构，以及 `bpf_sock_destroy` 这样的 kfunc 如何将内核操作暴露给 BPF 程序。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## 背景知识：BPF 迭代器与 Kfunc

在深入代码之前，我们先理解使这个工具成为可能的两个内核特性。

### BPF 迭代器

BPF 迭代器是一种特殊的 BPF 程序类型，内核会为某个数据结构中的每个元素重复调用它。与 tracepoint 或 kprobe 那种在特定事件发生时触发不同，迭代器让你可以按需主动扫描内核状态。

TCP 迭代器（`SEC("iter/tcp")`）会遍历触发它的进程所在网络命名空间中的所有 TCP 套接字。用户态程序通过从迭代器文件描述符读取来启动扫描，每次 `read()` 调用会促使内核为一批套接字调用你的 BPF 回调。当 `read()` 返回零（EOF）时，遍历完成。

由于内核控制着迭代过程，并在调用回调时持有适当的锁，因此读取套接字状态和对其操作之间不存在竞态条件。

### Kfunc

Kfunc（内核函数）是 BPF 程序直接调用特定内核函数的一种机制。与老式的 BPF helper 函数（有固定 ABI）不同，kfunc 是普通的内核函数，只是被显式标记为可从 BPF 调用。它们可以执行 helper 无法完成的操作，包括以复杂方式修改内核状态。

`bpf_sock_destroy` kfunc 在 Linux 6.5 引入（commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b`），允许运行在迭代器上下文中的 BPF 程序强制关闭套接字。内核会执行完整的协议特定拆除过程：从哈希表移除套接字、根据需要发送 FIN/RST、释放资源。这是同步操作：调用返回时，套接字已被销毁。

## 工具工作原理

`tcp_quarantine` 工具将这两个特性组合成一个实用的工作流程：

1. 用户态指定远端 IPv4 地址和端口。默认是 dry-run；apply 模式还要提供从 dry-run 输出复制的一组本地 IPv4 地址和端口。
2. BPF 程序加载时，这些参数被写入其只读数据段。
3. 用户态打开迭代器文件描述符并从中读取，触发内核为每个 TCP 套接字调用 BPF 回调。
4. 对于每个套接字，BPF 回调检查：这是 IPv4 套接字吗？处于 ESTABLISHED 状态吗？远端端点匹配吗？apply 模式下，本地端点也匹配吗？
5. 匹配的套接字会被打印并计数。只有 apply 扫描中四个端点字段全部相等时才调用 `bpf_sock_destroy`。
6. 遍历完成后，用户态从 BPF 程序的 BSS 段读取统计数据并报告结果。

最终匹配和销毁在同一个迭代器回调中针对同一个 socket 完成。dry-run 与 apply 是两次扫描，连接可能在两者之间消失；这时 apply 会安全地报告 `matched=0`。

## 代码详解

实现包含三个源文件：定义统计结构的共享头文件、执行实际迭代和销毁的 BPF 程序、以及协调一切的用户态加载器。

### 统计结构

`tcp_quarantine.h` 定义了 BPF 程序在迭代过程中更新、用户态之后读取的计数器：

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCP_QUARANTINE_H
#define __TCP_QUARANTINE_H

struct quarantine_stats {
	unsigned long long scanned;
	unsigned long long established;
	unsigned long long matched;
	unsigned long long destroyed;
	unsigned long long failed;
};

#endif /* __TCP_QUARANTINE_H */
```

五个计数器分别记录：检查的套接字总数、IPv4 且 ESTABLISHED 状态的数量、与当前选择器匹配的数量、成功销毁的数量（仅 apply 模式）、`bpf_sock_destroy` 调用失败的数量。

### BPF 迭代器程序

`tcp_quarantine.bpf.c` 是内核侧代码。`SEC("iter/tcp")` 注解告诉加载器这是一个 TCP 迭代器程序：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_quarantine.h"

#define AF_INET 2
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_addr;
const volatile __u16 target_port;
const volatile __u32 target_local_addr;
const volatile __u16 target_local_port;
const volatile bool apply;

struct quarantine_stats stats;

extern int bpf_sock_destroy(struct sock_common *sock) __ksym;

SEC("iter/tcp")
int quarantine_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;
	__u32 dst_addr, local_addr;
	__u32 dst_host, local_host;
	__u16 dst_port;
	__u16 local_port;
	__u16 family;
	__u8 state;
	int err;

	if (!sk)
		return 0;

	stats.scanned++;
	family = BPF_CORE_READ(sk, skc_family);
	state = BPF_CORE_READ(sk, skc_state);
	if (family != AF_INET || state != TCP_ESTABLISHED)
		return 0;

	stats.established++;
	dst_addr = BPF_CORE_READ(sk, skc_daddr);
	dst_port = BPF_CORE_READ(sk, skc_dport);
	if (dst_addr != target_addr || dst_port != bpf_htons(target_port))
		return 0;
	local_addr = BPF_CORE_READ(sk, skc_rcv_saddr);
	local_port = BPF_CORE_READ(sk, skc_num);
	if (apply && (local_addr != target_local_addr ||
		      local_port != target_local_port))
		return 0;

	stats.matched++;
	local_host = bpf_ntohl(local_addr);
	dst_host = bpf_ntohl(dst_addr);
	BPF_SEQ_PRINTF(seq,
		       "MATCH local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u\n",
		       local_host >> 24, (local_host >> 16) & 0xff,
		       (local_host >> 8) & 0xff, local_host & 0xff, local_port,
		       dst_host >> 24, (dst_host >> 16) & 0xff,
		       (dst_host >> 8) & 0xff, dst_host & 0xff, target_port);
	if (!apply)
		return 0;

	err = bpf_sock_destroy(sk);
	if (err)
		stats.failed++;
	else
		stats.destroyed++;

	return 0;
}
```

关键要素解读：

**配置变量**：五个 `const volatile` 变量在 BPF 程序的只读数据段（`.rodata`）中保存远端端点、可选本地端点和 apply 模式。用户态在打开 skeleton 之后、加载程序之前写入它们；当 `apply` 为 false 时，验证器可以消除本地匹配和销毁路径。

**Kfunc 声明**：`extern int bpf_sock_destroy(struct sock_common *sock) __ksym;` 这行将 `bpf_sock_destroy` 声明为外部内核符号。`__ksym` 注解告诉加载器在加载时通过查找内核函数来解析它。

**CO-RE 字段访问**：`BPF_CORE_READ(sk, skc_family)` 使用 BTF（BPF Type Format）信息读取套接字结构的 `skc_family` 字段。这是 CO-RE（Compile Once, Run Everywhere，一次编译到处运行）的一部分：编译后的 BPF 程序包含重定位记录，加载器会根据运行中内核的 BTF 数据进行修补。在一个内核版本上编译的程序可以在其他版本上运行，即使结构体字段偏移不同。

**字节序处理**：远端和本地地址与 `inet_pton` 产生的网络字节序一致。远端 `skc_dport` 是网络字节序，要与 `bpf_htons(target_port)` 比较；本地 `skc_num` 已经是主机字节序。

**逐级过滤**：回调先计数所有 socket（`scanned`），再筛选 IPv4 ESTABLISHED socket（`established`），最后匹配远端。dry-run 用 `MATCH local=... remote=...` 打印每个候选；apply 模式在增加 `matched` 或执行销毁前还会重新检查选中的本地端点。工具故意不提供销毁所有远端匹配项的选项。

### 用户态加载器

`tcp_quarantine.c` 处理参数解析、BPF 生命周期管理和结果报告：

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcp_quarantine.h"
#include "tcp_quarantine.skel.h"

static struct env {
	const char *remote_argument;
	const char *local_argument;
	bool apply;
	bool verbose;
} env;

struct endpoint {
	struct in_addr address;
	unsigned int port;
	char text[INET_ADDRSTRLEN + 7];
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [--apply LOCAL_IPV4:PORT] REMOTE_IPV4:PORT [--verbose]\n"
		"\n"
		"List established TCP clients to REMOTE_IPV4:PORT.\n"
		"The default is a dry run. Copy one listed local endpoint into\n"
		"--apply to destroy only that exact IPv4 4-tuple.\n"
		"\n"
		"Options:\n"
		"  -a, --apply IPv4:PORT   local endpoint selected from dry-run output\n"
		"  -v, --verbose           print libbpf diagnostics\n"
		"  -h, --help              show this help\n",
		program);
}

static int parse_port(const char *value, unsigned int *port)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end || parsed == 0 || parsed > 65535)
		return -EINVAL;
	*port = parsed;
	return 0;
}

static int parse_endpoint(const char *value, struct endpoint *endpoint)
{
	char address[INET_ADDRSTRLEN];
	const char *separator = strrchr(value, ':');
	size_t address_length;

	if (!separator || separator == value)
		return -EINVAL;
	address_length = separator - value;
	if (address_length >= sizeof(address))
		return -EINVAL;
	memcpy(address, value, address_length);
	address[address_length] = '\0';
	if (inet_pton(AF_INET, address, &endpoint->address) != 1 ||
	    parse_port(separator + 1, &endpoint->port))
		return -EINVAL;
	snprintf(endpoint->text, sizeof(endpoint->text), "%s:%u",
		 address, endpoint->port);
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "apply", required_argument, NULL, 'a' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "a:vh", options, NULL)) != -1) {
		switch (option) {
		case 'a':
			env.apply = true;
			env.local_argument = optarg;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			return -EINVAL;
		}
	}

	if (argc - optind != 1)
		return -EINVAL;
	env.remote_argument = argv[optind];
	return 0;
}

static int run_iterator(struct bpf_program *program)
{
	struct bpf_link *link;
	char buffer[4096];
	int iter_fd, length, err;

	link = bpf_program__attach_iter(program, NULL);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "failed to attach TCP iterator: %s\n", strerror(-err));
		return err;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		err = iter_fd;
		fprintf(stderr, "failed to create TCP iterator: %s\n", strerror(-err));
		goto cleanup;
	}

	while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0) {
		if (fwrite(buffer, 1, length, stdout) != (size_t)length) {
			err = -EIO;
			fprintf(stderr, "failed to print iterator output\n");
			break;
		}
	}
	if (length < 0) {
		err = -errno;
		fprintf(stderr, "failed while scanning TCP sockets: %s\n", strerror(errno));
	}
	close(iter_fd);

cleanup:
	bpf_link__destroy(link);
	return err;
}

int main(int argc, char **argv)
{
	struct tcp_quarantine_bpf *skel = NULL;
	struct endpoint remote = {};
	struct endpoint local = {};
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}
	if (parse_endpoint(env.remote_argument, &remote)) {
		fprintf(stderr, "invalid remote IPv4 endpoint: %s\n",
			env.remote_argument);
		return 1;
	}
	if (env.apply && parse_endpoint(env.local_argument, &local)) {
		fprintf(stderr, "invalid local IPv4 endpoint: %s\n",
			env.local_argument);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	skel = tcp_quarantine_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_addr = remote.address.s_addr;
	skel->rodata->target_port = remote.port;
	skel->rodata->target_local_addr = local.address.s_addr;
	skel->rodata->target_local_port = local.port;
	skel->rodata->apply = env.apply;

	err = tcp_quarantine_bpf__load(skel);
	if (err) {
		fprintf(stderr,
			"failed to load TCP quarantine program: %s\n"
			"This tool requires Linux 6.5+ with BTF, TCP BPF iterators, "
			"BPF JIT, and the bpf_sock_destroy kfunc.\n",
			strerror(-err));
		goto cleanup;
	}

	err = run_iterator(skel->progs.quarantine_tcp);
	if (err)
		goto cleanup;

	printf("SUMMARY mode=%s remote=%s%s%s scanned=%llu established=%llu "
	       "matched=%llu destroyed=%llu failed=%llu\n",
	       env.apply ? "apply" : "dry-run", remote.text,
	       env.apply ? " local=" : "", env.apply ? local.text : "",
	       skel->bss->stats.scanned, skel->bss->stats.established,
	       skel->bss->stats.matched, skel->bss->stats.destroyed,
	       skel->bss->stats.failed);
	if (skel->bss->stats.failed)
		err = -EIO;

cleanup:
	tcp_quarantine_bpf__destroy(skel);
	return err != 0;
}
```

核心工作流程：

1. **打开 skeleton**：`tcp_quarantine_bpf__open()` 解析嵌入的 BPF 对象但不加载。

2. **配置参数**：在 `load()` 前把解析后的远端端点、可选本地端点和 apply 标志写入 `skel->rodata->*`。

3. **加载程序**：`tcp_quarantine_bpf__load()` 将 BPF 程序加载到内核。验证器运行，BTF 重定位被应用，kfunc 被解析。

4. **运行迭代器**：`run_iterator()` 挂载程序，创建迭代器文件描述符，然后从中读取直到 EOF。读取循环驱动内核为每个 TCP 套接字调用我们的 BPF 回调。

5. **读取结果**：迭代完成后，我们从 `skel->bss->stats` 读取统计数据。BSS 段是自动内存映射的，所以这些读取只是访问共享内存。

迭代器回调用 `BPF_SEQ_PRINTF` 写出每个候选项，`read()` 循环把这些内容复制到 stdout，使 dry-run 可以直接用于下一步选择；汇总结果仍来自 BSS 统计。

## 网络命名空间边界

TCP BPF 迭代器扫描的是触发它的进程所在网络命名空间中的套接字。这是一个关键边界：工具只能看到和操作自己网络命名空间中的连接。

如果需要关闭容器或其他命名空间中的连接，先用 `nsenter` 进入该命名空间：

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  203.0.113.99:443
```

这里 `<target-pid>` 是目标网络命名空间中任意进程的 PID。`--net` 标志只改变网络命名空间而保持 mount 命名空间不变，所以工具二进制文件仍然可访问。

## 应用层看到的错误

当 `bpf_sock_destroy` 拆除套接字时，内核执行协议的关闭路径。应用看到的具体错误取决于连接的哪一端被销毁以及它下一步尝试什么操作：

- 上游 TCP selftest 预期客户端收到 `ECONNABORTED`，服务端收到 `ECONNRESET`。
- 写操作可能产生 `EPIPE` 并伴随 `SIGPIPE` 信号。
- 具体行为因内核版本和操作时机而异。

这些结果都可能表示连接已经被拆除；请结合你的应用行为和内核版本确认预期现象。

## 编译与运行

构建工具：

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

**Dry-run 模式**（默认）扫描匹配项但不销毁：

```bash
sudo ./tcp_quarantine 127.0.0.1:42063
```

从一行 `MATCH` 中复制本地端点交给 apply 模式；它只销毁这条完整 4-tuple：

```bash
sudo ./tcp_quarantine --apply 127.0.0.1:55490 127.0.0.1:42063
```

命令行参考：

```text
Usage: ./tcp_quarantine [--apply LOCAL_IPV4:PORT] REMOTE_IPV4:PORT [--verbose]

Options:
  -a, --apply IPv4:PORT   从 dry-run 输出选中的本地端点
  -v, --verbose           打印 libbpf 诊断信息
  -h, --help              显示帮助
```

### 示例会话

假设一个服务与同一个远端 listener 建立了两条连接。正常的 dry-run 会列出两个候选；把其中一个本地端点复制到 apply 命令后，只会选中这一条连接：

```console
MATCH local=127.0.0.1:55490 remote=127.0.0.1:42063
MATCH local=127.0.0.1:55494 remote=127.0.0.1:42063
SUMMARY mode=dry-run remote=127.0.0.1:42063 scanned=8 established=6 matched=2 destroyed=0 failed=0
MATCH local=127.0.0.1:55490 remote=127.0.0.1:42063
SUMMARY mode=apply remote=127.0.0.1:42063 local=127.0.0.1:55490 scanned=7 established=5 matched=1 destroyed=1 failed=0
```

socket 计数和端口每次都会变化。重要的是：dry-run 列出两个远端匹配且不改变它们；apply 对复制的 4-tuple 报告 `matched=1 destroyed=1`，另一条 socket 保持可用。

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.5+（`bpf_sock_destroy` 引入时） |
| BTF | 必需（`CONFIG_DEBUG_INFO_BTF=y`） |
| 内核配置 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_BPF_EVENTS=y`、`CONFIG_DEBUG_INFO_BTF=y`、`CONFIG_INET=y`、`CONFIG_PROC_FS=y` |
| BPF JIT | 必须启用。Kfunc 需要 JIT。使用 `CONFIG_BPF_JIT_ALWAYS_ON` 构建的内核无需运行时配置。 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | 需要 root |

如果加载失败，工具会打印内核错误和前置条件清单，帮助你诊断问题。

## 总结

本教程展示了如何使用 BPF 迭代器和 `bpf_sock_destroy` kfunc 精确终止一条选定的 TCP 连接。与杀进程、防火墙规则或用户态 RST 注入相比，这种方法：

- 原子操作，检查和动作之间不存在竞态窗口
- 不需要猜测 TCP 序列号
- 不影响同一进程上的其他连接
- 不受加密或特殊网络配置的影响

工具把完整 IPv4 4-tuple 作为最小安全销毁选择器。可能的扩展包括 IPv6、进程/cgroup 归属、多命名空间编排和威胁情报集成；宽泛的通配销毁故意不属于本教程。

> 如果你想深入了解 eBPF，请访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [bpf_sock_destroy 内核 commit](https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b)
- [上游 sock_destroy selftest（BPF 程序）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c)
- [上游 sock_destroy selftest（用户态测试）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c)
