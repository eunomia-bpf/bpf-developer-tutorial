# eBPF 实践教程: 隔离已建立的 TCP 连接

你的威胁情报源刚刚把 `203.0.113.99` 标记为 C2 服务器。防火墙规则可以立即阻止新连接，但 `netstat` 显示三台生产节点已经和这个地址保持着活跃的 TCP 会话，数据仍在外泄。你需要立即切断这些连接，不重启服务，不杀死进程，也不影响无关流量。

本教程构建一个小型 eBPF 工具：扫描当前网络命名空间中的 TCP 套接字，找到目标远端 IPv4 地址和端口完全匹配的 `ESTABLISHED` 连接，用 `bpf_sock_destroy` 将其销毁。TCP BPF 迭代器只能看到加载它的进程所在网络命名空间中的套接字，而非主机上的全部套接字。默认模式是 dry-run，确认影响范围后再执行销毁。

> 完整源码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/51-tcp-quarantine>

## 快速演示

编译工具：

```bash
cd src/51-tcp-quarantine
make clean
make -j2
```

Dry-run 模式（安全，不会销毁任何连接）：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063
```

Apply 模式（销毁匹配的套接字）：

```bash
sudo ./tcp_quarantine --destination 127.0.0.1 --port 42063 --apply
```

测试环境的真实输出：

```console
mode=dry-run destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=0 failed=0
mode=apply destination=127.0.0.1:42063 scanned=6 established=4 matched=1 destroyed=1 failed=0
PASS: dry-run preserved both connections; apply destroyed only the target
```

请将目标 IP 和端口替换为你要隔离的实际地址。该工具执行一次扫描后退出，不会持续运行。

### 在其他网络命名空间中使用

TCP BPF 迭代器扫描的是加载 BPF 程序的进程所在的网络命名空间。要隔离容器或其他网络命名空间中的连接，先进入该命名空间：

```bash
sudo nsenter --net=/proc/<target-pid>/ns/net -- ./tcp_quarantine \
  --destination 203.0.113.99 --port 443 --apply
```

`<target-pid>` 是目标网络命名空间中任意进程的 PID。这里只进入网络命名空间，二进制文件和当前工作目录仍来自调用者的 mount 命名空间。该工具不会自动扫描其他网络命名空间。

## 工作原理：端到端流程

工具使用 BPF TCP iterator 遍历内核套接字表，流程如下：

1. **用户态解析目标参数。** 加载器用 `inet_pton` 验证 IPv4 地址，转换端口号，在加载 BPF 程序之前写入只读数据段。

2. **BPF 程序作为 TCP iterator 加载并挂载。** 内核对加载进程所在网络命名空间中的每个 TCP 套接字调用一次迭代器回调。

3. **迭代器过滤。** 对每个套接字递增 `scanned` 计数器，跳过非 `AF_INET` 或非 `TCP_ESTABLISHED` 的条目，然后比较 `skc_daddr` 和 `skc_dport` 是否与目标匹配。

4. **Dry-run 与 apply。** 如果 `apply` 为 false（默认），匹配的套接字只被计数。如果为 true，程序调用 `bpf_sock_destroy` 销毁它。

5. **用户态读取统计。** 迭代器消费完毕后，加载器从 BSS 段读取计数器并打印汇总行。

## BPF 程序

完整的 BPF 侧代码不到 60 行：

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

要点：

- **`const volatile` 用于参数传递。** 这些变量位于 `.rodata` 段，用户态在 `open()` 之后、`load()` 之前设置它们，验证器将其视为常量。这种方式比使用 map 更简洁。

- **`bpf_sock_destroy` 作为 kfunc 声明。** 通过 `__ksym` 标注为必需（强）符号，内核在加载时解析。如果内核中缺少该符号（版本过低或 kfunc 不可用），BPF 加载会在重定位阶段失败。

- **`BPF_CORE_READ` 保证可移植性。** CO-RE 重定位使同一编译产物能在不同 `sock_common` 布局的内核上运行，前提是有 BTF。

- **端口比较使用网络字节序。** `skc_dport` 以网络字节序存储，因此比较时使用 `bpf_htons(target_port)`。

## 用户态加载器

加载器负责参数解析、BPF 生命周期管理和迭代器执行。核心代码：

```c
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
```

加载完成后，挂载并消费迭代器：

```c
link = bpf_program__attach_iter(program, NULL);
iter_fd = bpf_iter_create(bpf_link__fd(link));
while ((length = read(iter_fd, buffer, sizeof(buffer))) > 0)
    ;
```

对迭代器 fd 读到 EOF 会驱动内核为每个 TCP 套接字调用 BPF 回调。读取缓冲区的内容在这里不使用，因为程序通过 BSS 计数器传递结果，而非 seq_file 输出。

## 共享头文件

```c
struct quarantine_stats {
    unsigned long long scanned;
    unsigned long long established;
    unsigned long long matched;
    unsigned long long destroyed;
    unsigned long long failed;
};
```

BPF 程序和用户态加载器都包含这个头文件，保证 BSS 布局一致。

## 运行自动化测试

Python 测试 (`tests/test_tcp_quarantine.py`) 验证四个场景：

1. 无效 IPv4 地址被拒绝。
2. Dry-run 发现并报告目标但不销毁。
3. Apply 模式销毁目标套接字（通过 `send()` 返回 `ECONNABORTED`、`ECONNRESET` 或 `EPIPE` 验证，与测试中的 `BROKEN_ERRORS` 一致）。
4. 不同端口的控制连接在两次执行中均存活。

```bash
sudo make test
```

该命令执行 `python3 tests/test_tcp_quarantine.py ./tcp_quarantine`，创建临时的回环连接，运行工具，并断言预期行为。

## 环境要求

| 要求 | 详情 |
|---|---|
| 内核版本 | Linux 6.5+（`bpf_sock_destroy` 首次出现的版本） |
| BTF | 必须启用 (`CONFIG_DEBUG_INFO_BTF=y`) |
| 内核配置 | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_INET=y`, `CONFIG_PROC_FS=y` |
| BPF JIT 运行时 | 必须在运行时启用（例如 `net.core.bpf_jit_enable=1`）。调用 kfunc 的程序无法回退到 BPF 解释器。如果内核编译时启用了 `CONFIG_BPF_JIT_ALWAYS_ON`，该 sysctl 可能不存在，因为 JIT 已永久启用。 |
| 架构 | 已在 x86_64 上测试 |
| 权限 | 已在 root 下测试。最小权限部署需要根据具体内核版本和环境确定所需的 capabilities 和 LSM 策略。 |

加载失败时，加载器会打印内核 errno 以及内核/BTF/迭代器/JIT/kfunc 的要求信息，帮助定位缺失的前置条件。

## 局限性

这是一个教学工具，不是生产级 agent。具体限制：

- **仅支持 IPv4。** 没有 IPv6 路径。
- **单次扫描。** 工具执行一次后退出，不会监控新建连接。
- **无进程归属信息。** 无法看到匹配套接字属于哪个进程。
- **网络命名空间范围，无 cgroup 筛选。** 扫描覆盖加载进程所在网络命名空间中的所有 TCP 套接字，但命名空间内部没有 cgroup 级别的过滤。管理多个命名空间的生产控制器需要分别进入每个目标命名空间运行，或显式编排。
- **无授权和审计日志。** 生产版本应通过策略审批控制销毁操作并记录审计轨迹。
- **不支持 UDP 或数据包检测。** 仅处理 TCP ESTABLISHED 套接字。

实际部署中应从威胁情报或策略系统获取目标，增加 RBAC 控制，并集成事件管理系统。

## bpf_sock_destroy 原理

`bpf_sock_destroy` kfunc 在 Linux 6.5 中引入，使 BPF 程序能在迭代器上下文中强制关闭套接字。最初的动机是让网络策略执行器能终止违反新规则的连接，而不需要用户态配合。

调用时，内核执行协议特定的销毁路径。应用层看到的具体错误取决于被销毁的是哪个端点以及下一次执行的操作。上游 TCP selftest 中，客户端预期收到 `ECONNABORTED`，服务端预期收到 `ECONNRESET`；本教程的测试还接受 `EPIPE` 作为发送端的结果。不要仅凭这些观察推断特定的 TCP 状态转换或报文行为。

引入此功能的内核 commit: <https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>

上游 BPF selftest 提供额外参考：
- BPF 程序: <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- 用户态测试: <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>

## 你现在能做什么

完成本教程后，你可以：

- 按目标地址精确终止特定 TCP 连接，无需杀死进程。
- 用 dry-run 安全预览影响范围后再执行操作。
- 理解 BPF iterator 如何遍历内核数据结构，以及 kfunc 如何扩展 BPF 能力。
- 在此模式基础上构建策略驱动的连接管控工具。

## 参考资料

- 教程仓库: <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- 教程网站: <https://eunomia.dev/tutorials/>
- `bpf_sock_destroy` 内核 commit: <https://github.com/torvalds/linux/commit/4ddbcb886268af8d12a23e6640b39d1d9c652b1b>
- 上游 sock_destroy selftest (BPF): <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/sock_destroy_prog.c>
- 上游 sock_destroy selftest (用户态): <https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/prog_tests/sock_destroy.c>
