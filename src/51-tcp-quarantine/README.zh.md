# eBPF 教程：精准隔离已建立的 TCP 连接

某个出站 IP 地址刚刚被加入威胁情报黑名单，防火墙已经更新规则阻止新连接。但当你用 `netstat` 检查时，发现服务器上已经存在一条到该地址的活跃 TCP 会话。你需要立即关闭这条连接，但不能杀掉进程，不能影响其他流量，也不能等待会话超时。

这个看似简单的需求，用传统工具却很难实现：

- **杀进程**会断开该进程的所有连接，而不只是有问题的那条。更糟糕的是，进程重启后可能立刻重连到同一目标。

- **防火墙规则**只能阻止新连接，对已经建立的会话无能为力。即使是 `iptables -m state --state ESTABLISHED` 也只能匹配已有连接用于后续报文过滤，无法主动拆除会话。

- **用户态工具**如 `ss --kill` 或 `tcpkill` 的工作方式是读取 `/proc/net/tcp`，然后注入 TCP RST 报文。这种方式存在竞态条件：在读取套接字列表和发送 RST 之间，套接字状态可能已经改变。RST 注入还需要猜测正确的序列号，对加密隧道或某些网络配置可能失效。

我们需要的是一种内核级机制，能够原子地识别并销毁特定套接字，不存在竞态窗口。这正是 Linux 6.5 引入 `bpf_sock_destroy` 内核函数（kfunc）所提供的能力。

本教程将构建一个命令行工具，使用 BPF 迭代器遍历内核的 TCP 套接字表，找出与指定 IPv4 地址和端口匹配的已建立连接，并按需销毁。你将学习 BPF 迭代器如何在持有锁的情况下安全遍历内核数据结构，以及 `bpf_sock_destroy` 这样的 kfunc 如何将内核操作暴露给 BPF 程序。

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

1. 用户态指定目标 IPv4 地址和端口，以及是真正销毁匹配项还是仅计数（dry-run 模式）。
2. BPF 程序加载时，这些参数被写入其只读数据段。
3. 用户态打开迭代器文件描述符并从中读取，触发内核为每个 TCP 套接字调用 BPF 回调。
4. 对于每个套接字，BPF 回调检查：这是 IPv4 套接字吗？处于 ESTABLISHED 状态吗？目标地址匹配吗？
5. 匹配的套接字被计数。在 apply 模式下，调用 `bpf_sock_destroy` 拆除它们。
6. 遍历完成后，用户态从 BPF 程序的 BSS 段读取统计数据并报告结果。

整个匹配和销毁过程都在内核中进行，检查和操作之间不存在套接字状态变化的窗口。

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

五个计数器分别记录：检查的套接字总数、IPv4 且 ESTABLISHED 状态的数量、与目标地址匹配的数量、成功销毁的数量（仅 apply 模式）、`bpf_sock_destroy` 调用失败的数量。

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
const volatile bool apply;

struct quarantine_stats stats;

extern int bpf_sock_destroy(struct sock_common *sock) __ksym;

SEC("iter/tcp")
int quarantine_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	__u32 dst_addr;
	__u16 dst_port;
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

	stats.matched++;
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

**配置变量**：三个 `const volatile` 变量（`target_addr`、`target_port`、`apply`）位于 BPF 程序的只读数据段（`.rodata`）。用户态在打开 skeleton 之后、加载程序之前写入它们。`const volatile` 模式告诉 BPF 验证器这些是编译期常量，同时仍允许用户态设置。这使验证器能够优化代码路径，例如当 `apply` 为 false 时，整个销毁分支可以被消除。

**Kfunc 声明**：`extern int bpf_sock_destroy(struct sock_common *sock) __ksym;` 这行将 `bpf_sock_destroy` 声明为外部内核符号。`__ksym` 注解告诉加载器在加载时通过查找内核函数来解析它。

**CO-RE 字段访问**：`BPF_CORE_READ(sk, skc_family)` 使用 BTF（BPF Type Format）信息读取套接字结构的 `skc_family` 字段。这是 CO-RE（Compile Once, Run Everywhere，一次编译到处运行）的一部分：编译后的 BPF 程序包含重定位记录，加载器会根据运行中内核的 BTF 数据进行修补。在一个内核版本上编译的程序可以在其他版本上运行，即使结构体字段偏移不同。

**字节序处理**：目标地址以网络字节序（大端）存储，与 `inet_pton` 产生的结果一致，所以直接比较。端口也以网络字节序存储，所以比较前用 `bpf_htons()` 把主机字节序的目标端口转换一下。

**三级过滤**：回调采用逐级收紧的过滤器。首先计数所有套接字（`scanned`），然后筛选出 IPv4 且 ESTABLISHED 状态的（`established`），最后筛选与目标地址精确匹配的（`matched`）。这种漏斗结构让你一眼就能看出工具是否在扫描正确的群体。

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
	const char *destination;
	unsigned int port;
	bool apply;
	bool verbose;
} env;

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
		"Usage: %s --destination IPv4 --port PORT [--apply] [--verbose]\n"
		"\n"
		"Find established TCP client connections to an exact destination.\n"
		"The default is a safe dry run; --apply destroys matching sockets.\n"
		"\n"
		"Options:\n"
		"  -d, --destination IPv4  exact remote IPv4 address\n"
		"  -p, --port PORT         exact remote TCP port (1-65535)\n"
		"  -a, --apply             destroy matching sockets\n"
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

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "destination", required_argument, NULL, 'd' },
		{ "port", required_argument, NULL, 'p' },
		{ "apply", no_argument, NULL, 'a' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "d:p:avh", options, NULL)) != -1) {
		switch (option) {
		case 'd':
			env.destination = optarg;
			break;
		case 'p':
			if (parse_port(optarg, &env.port)) {
				fprintf(stderr, "invalid TCP port: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'a':
			env.apply = true;
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

	if (!env.destination || !env.port || optind != argc)
		return -EINVAL;
	return 0;
}

static int run_iterator(struct bpf_program *program)
{
	struct bpf_link *link;
	char buffer[256];
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

	while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0)
		;
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
	struct in_addr destination;
	int err;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}
	if (inet_pton(AF_INET, env.destination, &destination) != 1) {
		fprintf(stderr, "invalid IPv4 destination: %s\n", env.destination);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	skel = tcp_quarantine_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_addr = destination.s_addr;
	skel->rodata->target_port = env.port;
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

	printf("mode=%s destination=%s:%u scanned=%llu established=%llu "
	       "matched=%llu destroyed=%llu failed=%llu\n",
	       env.apply ? "apply" : "dry-run", env.destination, env.port,
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

2. **配置参数**：我们写入 `skel->rodata->*` 来设置目标地址、端口和 apply 标志。这必须在 `load()` 之前完成。

3. **加载程序**：`tcp_quarantine_bpf__load()` 将 BPF 程序加载到内核。验证器运行，BTF 重定位被应用，kfunc 被解析。

4. **运行迭代器**：`run_iterator()` 挂载程序，创建迭代器文件描述符，然后从中读取直到 EOF。读取循环驱动内核为每个 TCP 套接字调用我们的 BPF 回调。

5. **读取结果**：迭代完成后，我们从 `skel->bss->stats` 读取统计数据。BSS 段是自动内存映射的，所以这些读取只是访问共享内存。

迭代器的 `read()` 循环丢弃缓冲区内容，因为这个工具不通过迭代器接口产生输出，它只是利用遍历来驱动 BPF 回调。其他迭代器程序可能会向迭代器写入数据（例如格式化的套接字信息），但我们的工具完全通过 BSS 统计数据进行通信。

## 网络命名空间边界

TCP BPF 迭代器扫描的是触发它的进程所在网络命名空间中的套接字。这是一个关键边界：工具只能看到和操作自己网络命名空间中的连接。

如果需要关闭容器或其他命名空间中的连接，先用 `nsenter` 进入该命名空间：

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

这里 `<target-pid>` 是目标网络命名空间中任意进程的 PID。`--net` 标志只改变网络命名空间而保持 mount 命名空间不变，所以工具二进制文件仍然可访问。

## 应用层看到的错误

当 `bpf_sock_destroy` 拆除套接字时，内核执行协议的关闭路径。应用看到的具体错误取决于连接的哪一端被销毁以及它下一步尝试什么操作：

- 上游 TCP selftest 预期客户端收到 `ECONNABORTED`，服务端收到 `ECONNRESET`。
- 写操作可能产生 `EPIPE` 并伴随 `SIGPIPE` 信号。
- 具体行为因内核版本和操作时机而异。

本教程附带的测试接受以上任何一种作为连接被拆除的有效指示。

## 编译与运行

构建工具：

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

**Dry-run 模式**（默认）扫描匹配项但不销毁：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063
```

**Apply 模式**销毁匹配的套接字：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063 --apply
```

命令行参考：

```text
Usage: ./tcp_quarantine --destination IPv4 --port PORT [--apply] [--verbose]

Options:
  -d, --destination IPv4  精确的远程 IPv4 地址
  -p, --port PORT         精确的远程 TCP 端口 (1-65535)
  -a, --apply             销毁匹配的套接字
  -v, --verbose           打印 libbpf 诊断信息
  -h, --help              显示帮助
```

### 示例会话

以下输出在运行内核 `7.0.0-rc2+` 的 x86_64 环境上采集。自动化测试创建两条回环 TCP 连接：一个目标（将被销毁）和一个控制（应该存活）。它在运行工具前验证两条连接上的流量都正常：

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

套接字计数和端口号每次运行都会变化。重要的是：恰好一个套接字匹配，dry-run 让它保持完好，apply 成功销毁了它，控制连接继续正常工作。

运行自动化测试：

```bash
sudo make test
```

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

本教程展示了如何使用 BPF 迭代器和 `bpf_sock_destroy` kfunc 精确终止特定 TCP 连接。与杀进程、防火墙规则或用户态 RST 注入相比，这种方法：

- 原子操作，检查和动作之间不存在竞态窗口
- 不需要猜测 TCP 序列号
- 不影响同一进程上的其他连接
- 不受加密或特殊网络配置的影响

工具目前实现的是单次遍历、精确匹配一个 IPv4 目标地址。可能的扩展包括 IPv6 支持、通配符匹配、持续监控模式、进程/cgroup 归属、多命名空间编排，以及与威胁情报源集成。

> 如果你想深入了解 eBPF，请访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [bpf_sock_destroy 内核 commit](https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b)
- [上游 sock_destroy selftest（BPF 程序）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c)
- [上游 sock_destroy selftest（用户态测试）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c)
