# eBPF 实践教程：使用 uprobe 捕获多种库的 SSL/TLS 明文数据

随着TLS在现代网络环境中的广泛应用，跟踪微服务RPC消息已经变得愈加棘手。传统的流量嗅探技术常常受限于只能获取到加密后的数据，导致无法真正观察到通信的原始内容。这种限制为系统的调试和分析带来了不小的障碍。

但现在，我们有了新的解决方案。使用 eBPF 技术，通过其能力在用户空间进行探测，提供了一种方法重新获得明文数据，使得我们可以直观地查看加密前的通信内容。然而，每个应用可能使用不同的库，每个库都有多个版本，这种多样性给跟踪带来了复杂性。

在本教程中，我们将带您了解一种跨多种用户态 SSL/TLS 库的 eBPF 追踪技术，它不仅可以同时跟踪 GnuTLS 和 OpenSSL 等用户态库，而且相比以往，大大降低了对新版本库的维护工作。完整的源代码可以在这里查看：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff>。

## 背景知识

在深入本教程的主题之前，我们需要理解一些核心概念，这些概念将为我们后面的讨论提供基础。

### SSL 和 TLS

SSL (Secure Sockets Layer): 由 Netscape 在 1990 年代早期开发，为网络上的两台机器之间提供数据加密传输。然而，由于某些已知的安全问题，SSL的使用已被其后继者TLS所替代。

TLS (Transport Layer Security): 是 SSL 的继任者，旨在提供更强大和更安全的数据加密方式。TLS 工作通过一个握手过程，在这个过程中，客户端和服务器之间会选择一个加密算法和相应的密钥。一旦握手完成，数据传输开始，所有数据都使用选择的算法和密钥加密。

### TLS 的工作原理

Transport Layer Security (TLS) 是一个密码学协议，旨在为计算机网络上的通信提供安全性。它主要目标是通过密码学，例如证书的使用，为两个或更多通信的计算机应用程序提供安全性，包括隐私（机密性）、完整性和真实性。TLS 由两个子层组成：TLS 记录协议和TLS 握手协议。

#### 握手过程

当客户端与启用了TLS的服务器连接并请求建立安全连接时，握手过程开始。握手允许客户端和服务器通过不对称密码来建立连接的安全性参数，完整流程如下：

1. **初始握手**：客户端连接到启用了TLS的服务器，请求安全连接，并提供它支持的密码套件列表（加密算法和哈希函数）。
2. **选择密码套件**：从提供的列表中，服务器选择它也支持的密码套件和哈希函数，并通知客户端已做出的决定。
3. **提供数字证书**：通常，服务器接下来会提供形式为数字证书的身份验证。此证书包含服务器名称、信任的证书授权机构（为证书的真实性提供担保）以及服务器的公共加密密钥。
4. **验证证书**：客户端在继续之前确认证书的有效性。
5. **生成会话密钥**：为了生成用于安全连接的会话密钥，客户端有以下两种方法：
    - 使用服务器的公钥加密一个随机数（PreMasterSecret）并将结果发送到服务器（只有服务器才能使用其私钥解密）；双方然后使用该随机数生成一个独特的会话密钥，用于会话期间的数据加密和解密。
    - 使用 Diffie-Hellman 密钥交换（或其变体椭圆曲线DH）来安全地生成一个随机且独特的会话密钥，用于加密和解密，该密钥具有前向保密的额外属性：即使在未来公开了服务器的私钥，也不能用它来解密当前的会话，即使第三方拦截并记录了会话。

一旦上述步骤成功完成，握手过程便结束，加密的连接开始。此连接使用会话密钥进行加密和解密，直到连接关闭。如果上述任何步骤失败，则TLS握手失败，连接将不会建立。

#### OSI模型中的TLS

TLS 和 SSL 不完全适合 OSI 模型或 TCP/IP 模型的任何单一层次。TLS 在“某些可靠的传输协议（例如，TCP）之上运行”，这意味着它位于传输层之上。它为更高的层提供加密，这通常是表示层的功能。但是，使用TLS 的应用程序通常视其为传输层，即使使用TLS的应用程序必须积极控制启动 TLS 握手和交换的认证证书的处理。

### eBPF 和 uprobe

eBPF (Extended Berkeley Packet Filter): 是一种内核技术，允许用户在内核空间中运行预定义的程序，不需要修改内核源代码或重新加载模块。它创建了一个桥梁，使得用户空间和内核空间可以交互，从而为系统监控、性能分析和网络流量分析等任务提供了无前例的能力。

uprobes 是eBPF的一个重要特性，允许我们在用户空间应用程序中动态地插入探测点，特别适用于跟踪SSL/TLS库中的函数调用。Uprobe 在内核态 eBPF 运行时，也可能产生比较大的性能开销，这时候也可以考虑使用用户态 eBPF 运行时，例如  [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime 是一个基于 LLVM JIT/AOT 的用户态 eBPF 运行时，它可以在用户态运行 eBPF 程序，和内核态的 eBPF 兼容，避免了内核态和用户态之间的上下文切换，从而提高了 eBPF 程序的执行效率。对于 uprobe 而言，bpftime 的性能开销比 kernel 小一个数量级。

### 用户态库

SSL/TLS协议的实现主要依赖于用户态库。以下是一些常见的库：

- OpenSSL: 一个开源的、功能齐全的加密库，广泛应用于许多开源和商业项目中。
- BoringSSL: 是Google维护的OpenSSL的一个分支，重点是简化和优化，适用于Google的需求。
- GnuTLS: 是GNU项目的一部分，提供了SSL，TLS和DTLS协议的实现。与OpenSSL和BoringSSL相比，GnuTLS在API设计、模块结构和许可证上有所不同。

## OpenSSL API 分析

OpenSSL 是一个广泛应用的开源库，提供了 SSL 和 TLS 协议的完整实现，并广泛用于各种应用程序中以确保数据传输的安全性。其中，SSL_read() 和 SSL_write() 是两个核心的 API 函数，用于从 TLS/SSL 连接中读取和写入数据。本章节，我们将深入这两个函数，帮助你理解其工作机制。

### 1. SSL_read 函数

当我们想从一个已建立的 SSL 连接中读取数据时，可以使用 `SSL_read` 或 `SSL_read_ex` 函数。函数原型如下：

```c
int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int SSL_read(SSL *ssl, void *buf, int num);
```

`SSL_read` 和 `SSL_read_ex` 试图从指定的 `ssl` 中读取最多 `num` 字节的数据到缓冲区 `buf` 中。成功时，`SSL_read_ex` 会在 `*readbytes` 中存储实际读取到的字节数。

### 2. SSL_write 函数

当我们想往一个已建立的 SSL 连接中写入数据时，可以使用 `SSL_write` 或 `SSL_write_ex` 函数。

函数原型：

```c
int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_write(SSL *ssl, const void *buf, int num);
```

`SSL_write` 和 `SSL_write_ex` 会从缓冲区 `buf` 中将最多 `num` 字节的数据写入到指定的 `ssl` 连接中。成功时，`SSL_write_ex` 会在 `*written` 中存储实际写入的字节数。

## eBPF 内核态代码编写

在我们的例子中，我们使用 eBPF 来 hook ssl_read 和 ssl_write 函数，从而在数据读取或写入 SSL 连接时执行自定义操作。

### 数据结构

首先，我们定义了一个数据结构 probe_SSL_data_t 用于在内核态和用户态之间传输数据：

```c
#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
    __u64 timestamp_ns;  // 时间戳（纳秒）
    __u64 delta_ns;      // 函数执行时间
    __u32 pid;           // 进程 ID
    __u32 tid;           // 线程 ID
    __u32 uid;           // 用户 ID
    __u32 len;           // 读/写数据的长度
    int buf_filled;      // 缓冲区是否填充完整
    int rw;              // 读或写（0为读，1为写）
    char comm[TASK_COMM_LEN]; // 进程名
    __u8 buf[MAX_BUF_SIZE];  // 数据缓冲区
    int is_handshake;    // 是否是握手数据
};
```

### Hook 函数

我们的目标是 hook 到 `SSL_read` 和 `SSL_write` 函数。我们定义了一个函数 `SSL_exit` 来处理这两个函数的返回值。该函数会根据当前进程和线程的 ID，确定是否需要追踪并收集数据。

```c
static int SSL_exit(struct pt_regs *ctx, int rw) {
    int ret = 0;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    u64 *bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (bufp == 0)
        return 0;

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (!tsp)
        return 0;
    u64 delta_ns = ts - *tsp;

    int len = PT_REGS_RC(ctx);
    if (len <= 0)  // no data
        return 0;

    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = delta_ns;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = (u32)len;
    data->buf_filled = 0;
    data->rw = rw;
    data->is_handshake = false;
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (bufp != 0)
        ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    if (!ret)
        data->buf_filled = 1;
    else
        buf_copy_size = 0;

    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(buf_copy_size));
    return 0;
}
```

这里的 `rw` 参数标识是读还是写。0 代表读，1 代表写。

#### 数据收集流程

1. 获取当前进程和线程的 ID，以及当前用户的 ID。
2. 通过 `trace_allowed` 判断是否允许追踪该进程。
3. 获取起始时间，以计算函数的执行时间。
4. 尝试从 `bufs` 和 `start_ns` maps 中查找相关的数据。
5. 如果成功读取了数据，则创建或查找 `probe_SSL_data_t` 结构来填充数据。
6. 将数据从用户空间复制到缓冲区，并确保不超过预定的大小。
7. 最后，将数据发送到用户空间。

注意：我们使用了两个用户返回探针 `uretprobe` 来分别 hook `SSL_read` 和 `SSL_write` 的返回：

```c
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    return (SSL_exit(ctx, 0));  // 0 表示读操作
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    return (SSL_exit(ctx, 1));  // 1 表示写操作
}
```

### Hook到握手过程

在 SSL/TLS 中，握手（handshake）是一个特殊的过程，用于在客户端和服务器之间建立安全的连接。为了分析此过程，我们 hook 到了 `do_handshake` 函数，以跟踪握手的开始和结束。

#### 进入握手

我们使用 `uprobe` 为 `do_handshake` 设置一个 probe：

```c

SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_do_handshake_enter, void *ssl) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    u32 uid = bpf_get_current_uid_gid();

    if (!trace_allowed(uid, pid)) {
        return 0;
    }

    /* store arg info for later lookup */
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}
```

这段代码的主要功能如下：

1. 获取当前的 `pid`, `tid`, `ts` 和 `uid`。
2. 使用 `trace_allowed` 检查进程是否被允许追踪。
3. 将当前时间戳存储在 `start_ns` 映射中，用于稍后计算握手过程的持续时间。

#### 退出握手

同样，我们为 `do_handshake` 的返回设置了一个 `uretprobe`：

```c

SEC("uretprobe/do_handshake")
int BPF_URETPROBE(probe_SSL_do_handshake_exit) {
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();
    int ret = 0;

    /* use kernel terminology here for tgid/pid: */
    u32 tgid = pid_tgid >> 32;

    /* store arg info for later lookup */
    if (!trace_allowed(tgid, pid)) {
        return 0;
    }

    u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp == 0)
        return 0;

    ret = PT_REGS_RC(ctx);
    if (ret <= 0)  // handshake failed
        return 0;

    struct probe_SSL_data_t *data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = ts - *tsp;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = ret;
    data->buf_filled = 0;
    data->rw = 2;
    data->is_handshake = true;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_map_delete_elem(&start_ns, &tid);

    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data,
                            EVENT_SIZE(0));
    return 0;
}
```

此函数的逻辑如下：

1. 获取当前的 `pid`, `tid`, `ts` 和 `uid`。
2. 使用 `trace_allowed` 再次检查是否允许追踪。
3. 查找 `start_ns` 映射中的时间戳，用于计算握手的持续时间。
4. 使用 `PT_REGS_RC(ctx)` 获取 `do_handshake` 的返回值，判断握手是否成功。
5. 查找或初始化与当前线程关联的 `probe_SSL_data_t` 数据结构。
6. 更新数据结构的字段，包括时间戳、持续时间、进程信息等。
7. 通过 `bpf_perf_event_output` 将数据发送到用户态。

我们的 eBPF 代码不仅跟踪了 `ssl_read` 和 `ssl_write` 的数据传输，还特别关注了 SSL/TLS 的握手过程。这些信息对于深入了解和优化安全连接的性能至关重要。

通过这些 hook 函数，我们可以获得关于握手成功与否、握手所需的时间以及相关的进程信息的数据。这为我们提供了关于系统 SSL/TLS 行为的深入见解，可以帮助我们在需要时进行更深入的分析和优化。

## 用户态辅助代码分析与解读

在 eBPF 的生态系统中，用户态和内核态代码经常协同工作。内核态代码负责数据的采集，而用户态代码则负责设置、管理和处理这些数据。在本节中，我们将解读上述用户态代码如何配合 eBPF 追踪 SSL/TLS 交互。

### 1. 支持的库挂载

上述代码片段中，根据环境变量 `env` 的设定，程序可以选择针对三种常见的加密库（OpenSSL、GnuTLS 和 NSS）进行挂载。这意味着我们可以在同一个工具中对多种库的调用进行追踪。

为了实现这一功能，首先利用 `find_library_path` 函数确定库的路径。然后，根据库的类型，调用对应的 `attach_` 函数来将 eBPF 程序挂载到库函数上。

```c
    if (env.openssl) {
        char *openssl_path = find_library_path("libssl.so");
        printf("OpenSSL path: %s\n", openssl_path);
        attach_openssl(obj, openssl_path);
    }
    if (env.gnutls) {
        char *gnutls_path = find_library_path("libgnutls.so");
        printf("GnuTLS path: %s\n", gnutls_path);
        attach_gnutls(obj, gnutls_path);
    }
    if (env.nss) {
        char *nss_path = find_library_path("libnspr4.so");
        printf("NSS path: %s\n", nss_path);
        attach_nss(obj, nss_path);
    }
```

这里主要包含 OpenSSL、GnuTLS 和 NSS 三个库的挂载逻辑。NSS 是为组织设计的一套安全库，支持创建安全的客户端和服务器应用程序。它们最初是由 Netscape 开发的，现在由 Mozilla 维护。其他两个库前面已经介绍过了，这里不再赘述。

### 2. 详细挂载逻辑

具体的 attach 函数如下：

```c
#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)   \
    do {                                                                       \
      LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
                  .retprobe = is_retprobe);                                    \
      skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
          skel->progs.prog_name, env.pid, binary_path, 0, &uprobe_opts);       \
    } while (false)

int attach_openssl(struct sslsniff_bpf *skel, const char *lib) {
    ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_exit);
    ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_exit);

    if (env.latency && env.handshake) {
        ATTACH_UPROBE_CHECKED(skel, lib, SSL_do_handshake,
                            probe_SSL_do_handshake_enter);
        ATTACH_URETPROBE_CHECKED(skel, lib, SSL_do_handshake,
                                probe_SSL_do_handshake_exit);
    }

    return 0;
}

int attach_gnutls(struct sslsniff_bpf *skel, const char *lib) {
    ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_write_exit);
    ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_read_exit);

    return 0;
}

int attach_nss(struct sslsniff_bpf *skel, const char *lib) {
    ATTACH_UPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_write_exit);
    ATTACH_UPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_write_exit);
    ATTACH_UPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_read_exit);
    ATTACH_UPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_rw_enter);
    ATTACH_URETPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_read_exit);

    return 0;
}
```

我们进一步观察 `attach_` 函数，可以看到它们都使用了 `ATTACH_UPROBE_CHECKED` 和 `ATTACH_URETPROBE_CHECKED` 宏来实现具体的挂载逻辑。这两个宏分别用于设置 uprobe（函数入口）和 uretprobe（函数返回）。

考虑到不同的库有不同的 API 函数名称（例如，OpenSSL 使用 `SSL_write`，而 GnuTLS 使用 `gnutls_record_send`），所以我们需要为每个库写一个独立的 `attach_` 函数。

例如，在 `attach_openssl` 函数中，我们为 `SSL_write` 和 `SSL_read` 设置了 probe。如果用户还希望追踪握手的延迟 (`env.latency`) 和握手过程 (`env.handshake`)，那么我们还会为 `SSL_do_handshake` 设置 probe。

在eBPF生态系统中，perf_buffer是一个用于从内核态传输数据到用户态的高效机制。这对于内核态eBPF程序来说是十分有用的，因为它们不能直接与用户态进行交互。使用perf_buffer，我们可以在内核态eBPF程序中收集数据，然后在用户态异步地读取这些数据。我们使用 `perf_buffer__poll` 函数来读取内核态上报的数据，如下所示：

```c
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }
```

最后，在 print_event 函数中，我们将数据打印到标准输出：

```c
// Function to print the event from the perf buffer
void print_event(struct probe_SSL_data_t *event, const char *evt) {
    ...
    if (buf_size != 0) {
        if (env.hexdump) {
            // 2 characters for each byte + null terminator
            char hex_data[MAX_BUF_SIZE * 2 + 1] = {0};
            buf_to_hex((uint8_t *)buf, buf_size, hex_data);

            printf("\n%s\n", s_mark);
            for (size_t i = 0; i < strlen(hex_data); i += 32) {
                printf("%.32s\n", hex_data + i);
            }
            printf("%s\n\n", e_mark);
        } else {
            printf("\n%s\n%s\n%s\n\n", s_mark, buf, e_mark);
        }
    }
}
```

完整的源代码可以在这里查看：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff>

## 编译与运行

关于如何安装依赖，请参考：<https://eunomia.dev/tutorials/11-bootstrap/>

要开始使用 `sslsniff`，首先要进行编译：

```sh
make
```

完成后，请按照以下步骤操作：

### **启动 sslsniff**

在一个终端中，执行以下命令来启动 `sslsniff`：

```sh
sudo ./sslsniff
```

### **执行 CURL 命令**

在另一个终端中，执行：

```console
curl https://example.com
```

正常情况下，你会看到类似以下的输出：

```html
    <!doctype html>
    <html>
    <head>
        <title>Example Domain</title>
        ...
    <body>
    <div>
        ...
    </div>
    </body>
    </html>
```

### **sslsniff 输出**

当执行 `curl` 命令后，`sslsniff` 会显示以下内容：

```txt
    READ/RECV    0.132786160        curl             47458   1256
    ----- DATA -----
    <!doctype html>
    ...
    <div>
        <h1>Example Domain</h1>
        ...
    </div>
    </body>
    </html>

    ----- END DATA -----
```

**注意**：显示的 HTML 内容可能会因 `example.com` 页面的不同而有所不同。

### 显示延迟和握手过程

要查看延迟和握手过程，请执行以下命令：

```console
$ sudo ./sslsniff -l --handshake
OpenSSL path: /lib/x86_64-linux-gnu/libssl.so.3
GnuTLS path: /lib/x86_64-linux-gnu/libgnutls.so.30
NSS path: /lib/x86_64-linux-gnu/libnspr4.so
FUNC         TIME(s)            COMM             PID     LEN     LAT(ms)
HANDSHAKE    0.000000000        curl             6460    1      1.384  WRITE/SEND   0.000115400        curl             6460    24     0.014
```

### 16进制输出

要以16进制格式显示数据，请执行以下命令：

```console
$ sudo ./sslsniff --hexdump
WRITE/SEND   0.000000000        curl             16104   24
----- DATA -----
505249202a20485454502f322e300d0a
0d0a534d0d0a0d0a
----- END DATA -----

...
```

## 总结

eBPF 是一个非常强大的技术，它可以帮助我们深入了解系统的工作原理。本教程是一个简单的示例，展示了如何使用 eBPF 来监控 SSL/TLS 通信。如果您对 eBPF 技术感兴趣，并希望进一步了解和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 和教程网站 <https://eunomia.dev/zh/tutorials/。>

参考资料：

- <https://github.com/iovisor/bcc/pull/4706>
- <https://github.com/openssl/openssl>
- <https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html>
- <https://github.com/iovisor/bcc/blob/master/tools/sslsniff_example.txt>
- <https://en.wikipedia.org/wiki/Transport_Layer_Security>
