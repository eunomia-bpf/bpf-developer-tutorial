# eBPF 教程：精准隔离已建立的 TCP 连接

假设某个出站目标地址刚被添加到威胁情报黑名单，防火墙已更新规则阻止后续连接。然而 `netstat` 显示某台服务器上已经存在一条到该地址的活跃 TCP 会话——你需要精准关闭这条连接，同时保留进程和其他无关流量。

本教程展示如何使用 eBPF 迭代器和 `bpf_sock_destroy` kfunc 实现这一目标。工具遍历内核的 TCP 套接字表，找出精确匹配 IPv4 目标地址和端口的已建立连接，dry-run 模式统计匹配数量，`--apply` 模式销毁选中的套接字。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## 为什么需要内核级别的连接隔离

传统的连接终止方案都有明显的局限性。

**杀掉进程**是最直接的想法，但一个进程往往维护着多条连接，杀进程会中断所有业务流量，而且进程重启后可能立刻重建到同一目标的连接。

**防火墙规则**可以阻止新连接，但对已建立的连接无能为力。`iptables` 或 `nftables` 的 `-m state --state ESTABLISHED` 规则只能匹配状态，不能主动断开现有会话。

**用户态工具**如 `ss --kill` 或 `tcpkill` 依赖 `/proc/net/tcp` 遍历和注入 RST 报文，但这种方式有竞态问题：在你读取套接字列表和发送 RST 之间，套接字状态可能已经变化。而且注入 RST 需要正确的序列号，对加密连接或某些协议栈配置可能无效。

**内核态方案**才能真正解决这个问题。BPF 迭代器可以在持有适当锁的情况下遍历内核的套接字表，`bpf_sock_destroy` kfunc 直接调用内核的套接字销毁路径，整个过程是原子的，不存在竞态窗口。这就是 Linux 6.5 引入 `bpf_sock_destroy` 的意义：让 BPF 程序能够在迭代器上下文中强制关闭套接字，无需依赖用户态的 RST 注入。

## BPF 迭代器与 bpf_sock_destroy

BPF TCP 迭代器是一种特殊的 BPF 程序类型，它为加载进程所在网络命名空间内的每个 TCP 套接字驱动类型化回调。用户态程序通过读取迭代器文件描述符来触发遍历，内核在遍历过程中为每个套接字调用一次 BPF 回调。

`bpf_sock_destroy` kfunc 由 Linux 6.5 引入（commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b`），允许 BPF 程序在迭代器上下文中强制关闭套接字。内核执行协议特定的销毁路径，这是一个同步操作，调用返回时套接字已经被销毁。

`tcp_quarantine` 工具把这两个能力组合起来。用户指定目标 IPv4 地址和端口，BPF 程序遍历套接字表，筛选出 `ESTABLISHED` 状态且目标地址完全匹配的连接。dry-run 模式只统计匹配数量，apply 模式调用 `bpf_sock_destroy` 销毁匹配的套接字。整个过程在内核中完成，用户态只需要读取迭代器文件描述符来驱动遍历，最后从 BSS 段读取统计计数器。

## 代码实现

本工具由三个文件组成：共享头文件定义统计结构、BPF 程序遍历套接字表并执行销毁、用户空间加载器管理生命周期并打印结果。

### 共享头文件

`tcp_quarantine.h` 定义了 BPF 和用户空间共享的统计结构，位于 BSS 段作为结果通道传递五个计数器。

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

五个计数器分别记录：扫描的套接字总数、处于 `ESTABLISHED` 状态的 IPv4 套接字数、目标地址和端口完全匹配的数量、apply 模式下成功销毁的数量、以及 `bpf_sock_destroy` 返回非零的数量。

### BPF 程序

`tcp_quarantine.bpf.c` 使用 `SEC("iter/tcp")` 声明为 TCP 迭代器类型。当用户态读取迭代器文件描述符时，内核会为加载进程所在网络命名空间中的每个 TCP 套接字调用一次回调。

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

程序结构很直接。三个 `const volatile` 变量位于 `.rodata` 段，用户态在 `open()` 之后、`load()` 之前写入目标地址、端口和 apply 标志，验证器将它们视为编译期常量。`bpf_sock_destroy` 通过 `extern ... __ksym` 声明为强 kfunc 符号，内核在加载时解析该符号。

回调的处理逻辑分为三层过滤。首先对每个非空 `sk` 递增 `scanned` 计数器，然后选出 `AF_INET` 且状态为 `TCP_ESTABLISHED` 的套接字计入 `established`。`BPF_CORE_READ` 宏利用 BTF 信息读取 `sock_common` 结构体的字段，CO-RE 重定位保证同一编译产物可以在不同内核版本和字段布局上运行。

第二层过滤检查目标地址和端口。目标地址直接比较网络字节序的值（`inet_pton` 存储的结果已经是网络字节序），端口比较使用 `bpf_htons(target_port)` 因为 `skc_dport` 以网络字节序存储。

匹配的套接字递增 `matched`，dry-run 模式到此返回。apply 模式调用 `bpf_sock_destroy(sk)`，成功时递增 `destroyed`，返回非零时递增 `failed`。

### 用户空间加载器

`tcp_quarantine.c` 解析命令行参数、配置 BPF 常量、运行迭代器并打印结果。

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

加载器的流程比较标准。解析命令行后，用 `inet_pton` 验证 IPv4 地址并转换为网络字节序。打开 skeleton 后把三个参数写入 `.rodata` 段，然后调用 `load` 完成 BPF 程序加载。加载失败时的诊断同时给出内核 errno 和前置条件列表，方便用户排查问题。

`run_iterator` 函数是驱动遍历的核心。它先用 `bpf_program__attach_iter` 挂载 BPF 程序，然后用 `bpf_iter_create` 创建迭代器文件描述符。循环读取该 fd 直到 EOF，每次 `read` 驱动内核为若干 TCP 套接字调用 BPF 回调。读取缓冲区的内容在这个场景下不重要，它只是用于驱动遍历，真正的结果通过 BSS 段的计数器传递。迭代完成后，加载器从 `skel->bss->stats` 读取计数器并打印单行汇总。

## 网络命名空间

TCP BPF 迭代器扫描的是加载 BPF 程序的进程所在的网络命名空间。这是一个重要的边界：工具只能看到和操作自己网络命名空间中的连接。

要隔离容器或其他网络命名空间中的连接，先用 `nsenter` 进入目标命名空间：

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

`<target-pid>` 是目标网络命名空间中任意进程的 PID。`nsenter --net` 只改变网络命名空间，调用者的 mount 命名空间保持不变，因此二进制文件和当前工作目录仍可访问。

## bpf_sock_destroy 语义

`bpf_sock_destroy` 直接调用内核的套接字销毁路径，这与用户态注入 RST 报文有本质区别。内核执行协议特定的清理逻辑，套接字从哈希表中移除，相关资源被释放。

应用层看到的错误取决于被销毁的端点和下一个操作。上游 TCP selftest 预期客户端收到 `ECONNABORTED`，服务端收到 `ECONNRESET`。本教程的测试还接受发送端的 `EPIPE`，因为具体错误码可能因操作顺序和内核版本而异。

## 编译与运行

从源码构建：

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

Dry-run 模式报告匹配结果，匹配的连接保持已建立状态：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063
```

Apply 模式销毁匹配的套接字：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063 --apply
```

命令行参数：

```text
Usage: ./tcp_quarantine --destination IPv4 --port PORT [--apply] [--verbose]

Options:
  -d, --destination IPv4  精确的远程 IPv4 地址
  -p, --port PORT         精确的远程 TCP 端口 (1-65535)
  -a, --apply             销毁匹配的套接字
  -v, --verbose           打印 libbpf 诊断信息
  -h, --help              显示帮助
```

以下输出在运行内核 `7.0.0-rc2+` 的 x86_64 环境中采集。自动化测试创建两组回环 TCP 连接对：一个目标端口和一个无关的控制端口，先执行请求/响应往返，再运行工具验证行为：

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

套接字表计数和临时端口号随每次运行而变化，测试断言关注的是：匹配数为 1、dry-run 保留连接、apply 销毁目标、销毁失败数为 0、控制连接存活。

运行测试：

```bash
sudo make test
```

### 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.5+（`bpf_sock_destroy` 首次引入） |
| BTF | 必须启用 (`CONFIG_DEBUG_INFO_BTF=y`) |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT | 运行时必须启用。调用 kfunc 的程序使用 JIT 路径；`CONFIG_BPF_JIT_ALWAYS_ON` 内核无需 sysctl 设置。 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | root |

## 总结

本教程展示了如何使用 BPF 迭代器和 `bpf_sock_destroy` kfunc 实现精确的 TCP 连接隔离。相比杀进程、防火墙规则或用户态 RST 注入，这种内核态方案是原子的，不存在竞态窗口，也不依赖正确的序列号。

工具的设计是单次遍历、精确匹配一个 IPv4 目标元组。后续扩展可以添加 IPv6 支持、持续策略输入、进程/cgroup 归属、多命名空间编排、授权控制和审计记录。

> 如果你想深入了解 eBPF，请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [bpf_sock_destroy 内核 commit](https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b)
- [上游 sock_destroy selftest（BPF 程序）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c)
- [上游 sock_destroy selftest（用户态测试）](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c)
