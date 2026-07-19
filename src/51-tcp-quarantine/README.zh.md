# eBPF 教程：精准隔离已建立的 TCP 连接

假设某个出站目标地址刚被添加到威胁情报黑名单，防火墙已更新规则来阻止后续连接。然而 `netstat` 显示某台服务器上已经存在一条到该地址的活跃 TCP 会话，你需要精准关闭这条连接，同时保留进程和其他无关流量。

本教程构建 `tcp_quarantine`，一个单次执行的 eBPF 命令行工具，用于精确匹配指定的 IPv4 目标地址和端口，找到所有符合该元组的 `ESTABLISHED` TCP 连接并统计或销毁它们。默认模式是 dry-run，只报告匹配结果；`--apply` 模式调用内核的 `bpf_sock_destroy` kfunc 销毁每个匹配的套接字。BPF TCP 迭代器的扫描范围是加载它的进程所在的网络命名空间。

> 完整源码：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## 端到端流程

工具使用 BPF TCP 迭代器遍历内核的 TCP 套接字表。用户态程序首先用 `inet_pton` 验证 IPv4 地址并解析端口号，将这两个参数写入 skeleton 的只读数据段 `.rodata`，然后加载 BPF 程序。`inet_pton` 存储的 `destination.s_addr` 已经是网络字节序，主机字节序的端口和 apply 布尔值也一并写入。

BPF 程序使用 `SEC("iter/tcp")` 挂载为 TCP 迭代器。当用户态读取迭代器文件描述符时，内核会为加载进程所在网络命名空间中的每个 TCP 套接字调用一次回调。回调首先对每个非空 `sk` 递增 `scanned` 计数器，然后选出 `AF_INET` 且状态为 `TCP_ESTABLISHED` 的套接字计入 `established`。接着通过 `BPF_CORE_READ` 读取 `skc_daddr`、`skc_dport`、`skc_family` 和 `skc_state`，CO-RE 重定位保证同一编译产物可在不同内核布局上运行。目标地址直接比较网络字节序的值，端口比较使用 `bpf_htons(target_port)` 因为 `skc_dport` 以网络字节序存储。

匹配的套接字递增 `matched`，dry-run 模式到此返回。apply 模式调用 `bpf_sock_destroy(sk)`，成功时递增 `destroyed`，返回非零时递增 `failed`。`bpf_sock_destroy` 通过 `__ksym` 声明为强 kfunc 符号，内核在加载时解析该符号。

共享的 `quarantine_stats` 结构体位于 BSS 段，作为结果通道传递五个计数器。加载器用 `bpf_program__attach_iter` 挂载程序，`bpf_iter_create` 创建迭代器文件描述符，然后读到 EOF 驱动遍历；读取缓冲区仅用于驱动遍历，计数器通过 BSS 传递。加载器在退出时销毁迭代器 link 和 skeleton，加载或迭代失败、或 `bpf_sock_destroy` 有任何调用失败时返回非零退出码。`--verbose` 选项启用 libbpf 调试消息。

## 共享头文件

BPF 程序和用户态加载器都包含这个头文件，确保 BSS 段中 `quarantine_stats` 结构体的内存布局一致。

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

五个计数器分别记录扫描的套接字总数、处于 `ESTABLISHED` 状态的 IPv4 套接字数、目标地址和端口完全匹配的数量、apply 模式下成功销毁的数量、以及 `bpf_sock_destroy` 返回非零的数量。用户态在迭代完成后读取这些计数器并打印单行汇总。

## BPF 程序

以下是完整的 BPF 程序源码。

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

程序使用 `SEC("iter/tcp")` 声明为 TCP 迭代器类型。迭代器上下文 `bpf_iter__tcp` 由内核提供，其中 `sk_common` 字段在遍历套接字表时依次指向每个 TCP 套接字。三个 `const volatile` 变量位于 `.rodata` 段，通过只读全局数据直接传递小规模固定配置；用户态在 `open()` 之后、`load()` 之前写入目标地址、端口和 apply 标志，验证器将它们视为编译期常量。

`bpf_sock_destroy` 通过 `extern ... __ksym` 声明为强 kfunc 符号。强符号解析使 Linux 6.5+ 的 kfunc 可用性成为加载时前置条件，重定位在遍历开始前完成。加载诊断报告 errno 以及前置条件集合。`BPF_CORE_READ` 宏利用 BTF 信息读取 `sock_common` 结构体的字段，CO-RE 重定位保证同一编译产物可以在不同内核版本和字段布局上运行。端口比较使用 `bpf_htons(target_port)` 是因为 `skc_dport` 以网络字节序存储。

## 用户态加载器

以下是完整的用户态加载器源码。

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

加载器在 `main` 入口首先解析命令行参数，端口必须是 1 到 65535 之间的十进制数，地址用 `inet_pton` 验证并转换为网络字节序。打开 skeleton 后，三个参数写入 `.rodata` 段，然后调用 `load` 完成 BPF 程序加载。加载诊断同时给出内核 errno 以及 Linux 6.5+、BTF、TCP 迭代器、JIT 和 kfunc 的前置条件集合。

`run_iterator` 函数用 `bpf_program__attach_iter` 挂载 BPF 程序，用 `bpf_iter_create` 创建迭代器文件描述符。循环读取该 fd 直到 EOF，每次 `read` 驱动内核为若干 TCP 套接字调用 BPF 回调；读取缓冲区仅用于驱动遍历，计数器通过 BSS 传递。迭代完成后，加载器从 `skel->bss->stats` 读取计数器并打印单行汇总。如果有任何 `bpf_sock_destroy` 调用失败，程序返回非零退出码。

## 编译与执行

编译工具：

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

自动化测试的输出示例：

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

该命令执行 `python3 tests/test_tcp_quarantine.py ./tcp_quarantine`。测试创建两组回环 TCP 连接对：一个目标端口和一个无关的控制端口，先执行请求/响应往返，再运行工具验证行为。测试检查：无效目标 `not-an-ip` 返回非零并打印 `invalid IPv4 destination`；dry-run 输出包含 `mode=dry-run`、`matched=1`、`destroyed=0`，且两个连接仍能完成往返；apply 输出包含 `mode=apply`、`matched=1`、`destroyed=1`、`failed=0`；目标客户端 `send()` 或 `getsockopt(SO_ERROR)` 返回 `ECONNABORTED`、`ECONNRESET` 或 `EPIPE`；控制连接继续存活。

运行时行为已在 x86_64、Linux 7.0.0-rc2+ 上完成功能测试。

## 网络命名空间

TCP BPF 迭代器扫描的是加载 BPF 程序的进程所在的网络命名空间。要隔离容器或其他网络命名空间中的连接，先用 `nsenter` 进入目标命名空间：

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

`<target-pid>` 是目标网络命名空间中任意进程的 PID。`nsenter --net` 只改变网络命名空间，调用者的 mount 命名空间保持不变，因此二进制文件和当前工作目录仍可访问。功能验证发现：在调用者命名空间运行时 `matched=0`，进入隔离目标命名空间后 `matched=1`。

## 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.5+（`bpf_sock_destroy` 首次引入） |
| BTF | 必须启用 (`CONFIG_DEBUG_INFO_BTF=y`) |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT | 运行时必须启用。调用 kfunc 的程序使用 JIT 路径；`CONFIG_BPF_JIT_ALWAYS_ON` 内核无需 sysctl 设置，因为 JIT 已永久启用。 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | 已在 root 下测试 |
| 硬件 | 无特殊要求 |

加载诊断报告内核 errno 以及 Linux 6.5+、BTF、TCP BPF 迭代器、BPF JIT 和 kfunc 的前置条件集合。

## bpf_sock_destroy 语义

`bpf_sock_destroy` kfunc 由 Linux commit `4ddbcb886268af8d12a23e6640b39d1d9c652b1b` 引入，允许 BPF 程序在迭代器上下文中强制关闭套接字。内核执行协议特定的销毁路径，应用层看到的错误取决于被销毁的端点和下一个操作。上游 TCP selftest 预期客户端收到 `ECONNABORTED`、服务端收到 `ECONNRESET`；本教程的测试还接受发送端的 `EPIPE`。

## 扩展方向

本示例在调用者所选网络命名空间中执行单次遍历，处理所有匹配一个精确 IPv4 目标元组的已建立连接。后续扩展可添加 IPv6 支持、持续策略输入、进程/cgroup 归属、多命名空间编排、授权控制和审计记录。

## 总结

完成本教程后，你可以按目标元组精确终止所有匹配的 TCP 连接，同时保留进程和无关流量。dry-run 模式预览影响范围，apply 模式执行销毁。你理解了 BPF 迭代器如何遍历内核套接字表、kfunc 如何从 BPF 程序调用内核函数、以及 CO-RE 如何保证跨内核兼容性。更多 eBPF 教程和示例请参见 <https://github.com/eunomia-bpf/bpf-developer-tutorial>。

## 参考资料

- `bpf_sock_destroy` 内核 commit：<https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>
- 上游 sock_destroy selftest（BPF 程序）：<https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- 上游 sock_destroy selftest（用户态测试）：<https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>
