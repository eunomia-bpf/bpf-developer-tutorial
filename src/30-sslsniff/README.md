# eBPF 实践教程：使用 eBPF 用户态捕获多种库的 SSL/TLS 明文数据

随着TLS在现代网络环境中的广泛应用，跟踪微服务RPC消息已经变得愈加棘手。传统的流量嗅探技术常常受限于只能获取到加密后的数据，导致无法真正观察到通信的原始内容。这种限制为系统的调试和分析带来了不小的障碍。

但现在，我们有了新的解决方案。

eBPF技术，通过其能力在用户空间进行探测，提供了一种方法重新获得明文数据，使得我们可以直观地查看加密前的通信内容。然而，每个应用可能使用不同的库，每个库都有多个版本，这种多样性给跟踪带来了复杂性。

在本教程中，我们将带您了解一种跨多种条件的技术，它不仅可以同时跟踪 GnuTLS 和 OpenSSL 等用户态库，而且相比以往，大大降低了对新版本库的维护工作。

## 背景知识

在深入本教程的主题之前，我们需要理解一些核心概念，这些概念将为我们后面的讨论提供基础。

### SSL 和 TLS

SSL (Secure Sockets Layer): 由 Netscape 在 1990 年代早期开发，为网络上的两台机器之间提供数据加密传输。然而，由于某些已知的安全问题，SSL的使用已被其后继者TLS所替代。

TLS (Transport Layer Security): 是 SSL 的继任者，旨在提供更强大和更安全的数据加密方式。TLS 工作通过一个握手过程，在这个过程中，客户端和服务器之间会选择一个加密算法和相应的密钥。一旦握手完成，数据传输开始，所有数据都使用选择的算法和密钥加密。

### TLS 的工作原理

Transport Layer Security (TLS) 是一个密码学协议，旨在为计算机网络上的通信提供安全性。它主要目标是通过密码学，例如证书的使用，为两个或更多通信的计算机应用程序提供安全性，包括隐私（机密性）、完整性和真实性。TLS 由两个子层组成：TLS 记录协议和TLS 握手协议。

#### 握手过程

当客户端与启用了TLS的服务器连接并请求建立安全连接时，握手过程开始。握手允许客户端和服务器通过不对称密码来建立连接的安全性参数：

1. **初始握手**：客户端连接到启用了TLS的服务器，请求安全连接，并提供它支持的密码套件列表（加密算法和哈希函数）。
2. **选择密码套件**：从提供的列表中，服务器选择它也支持的密码套件和哈希函数，并通知客户端已做出的决定。
3. **提供数字证书**：通常，服务器接下来会提供形式为数字证书的身份验证。此证书包含服务器名称、信任的证书授权机构（为证书的真实性提供担保）以及服务器的公共加密密钥。
4. **验证证书**：客户端在继续之前确认证书的有效性。
5. **生成会话密钥**：为了生成用于安全连接的会话密钥，客户端有以下两种方法：
    - 使用服务器的公钥加密一个随机数（PreMasterSecret）并将结果发送到服务器（只有服务器才能使用其私钥解密）；双方然后使用该随机数生成一个独特的会话密钥，用于会话期间的数据加密和解密。
    - 使用Diffie-Hellman 密钥交换（或其变体椭圆曲线DH）来安全地生成一个随机且独特的会话密钥，用于加密和解密，该密钥具有前向保密的额外属性：即使在未来公开了服务器的私钥，也不能用它来解密当前的会话，即使第三方拦截并记录了会话。

一旦上述步骤成功完成，握手过程便结束，加密的连接开始。此连接使用会话密钥进行加密和解密，直到连接关闭。如果上述任何步骤失败，则TLS握手失败，连接将不会建立。

#### OSI模型中的TLS

TLS和SSL不完全适合OSI模型或TCP/IP模型的任何单一层次。TLS在“某些可靠的传输协议（例如，TCP）之上运行”，这意味着它位于传输层之上。它为更高的层提供加密，这通常是表示层的功能。但是，使用TLS的应用程序通常视其为传输层，即使使用TLS的应用程序必须积极控制启动TLS握手和交换的认证证书的处理。

### eBPF 和 uprobe

eBPF (Extended Berkeley Packet Filter): 是一种内核技术，允许用户在内核空间中运行预定义的程序，不需要修改内核源代码或重新加载模块。它创建了一个桥梁，使得用户空间和内核空间可以交互，从而为系统监控、性能分析和网络流量分析等任务提供了无前例的能力。

uprobes: 是eBPF的一个重要特性，允许我们在用户空间应用程序中动态地插入探测点，特别适用于跟踪SSL/TLS库中的函数调用。

### 用户态库

SSL/TLS协议的实现主要依赖于用户态库。以下是一些常见的库：

- OpenSSL: 一个开源的、功能齐全的加密库，广泛应用于许多开源和商业项目中。
- BoringSSL: 是Google维护的OpenSSL的一个分支，重点是简化和优化，适用于Google的需求。
- GnuTLS: 是GNU项目的一部分，提供了SSL，TLS和DTLS协议的实现。与OpenSSL和BoringSSL相比，GnuTLS在API设计、模块结构和许可证上有所不同。

## OpenSSL API 分析

OpenSSL 是一个广泛应用的开源库，提供了 SSL 和 TLS 协议的完整实现，并广泛用于各种应用程序中以确保数据传输的安全性。其中，SSL_read() 和 SSL_write() 是两个核心的 API 函数，用于从 TLS/SSL 连接中读取和写入数据。本章节，我们将深入这两个函数，帮助你理解其工作机制。

### 1. SSL_read 函数

当我们想从一个已建立的 SSL 连接中读取数据时，可以使用 `SSL_read` 或 `SSL_read_ex` 函数。

#### 函数原型

```c
int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int SSL_read(SSL *ssl, void *buf, int num);
```

`SSL_read` 和 `SSL_read_ex` 试图从指定的 `ssl` 中读取最多 `num` 字节的数据到缓冲区 `buf` 中。成功时，`SSL_read_ex` 会在 `*readbytes` 中存储实际读取到的字节数。

### 2. SSL_write 函数

当我们想往一个已建立的 SSL 连接中写入数据时，可以使用 `SSL_write` 或 `SSL_write_ex` 函数。

#### 函数原型

```c
int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_write(SSL *ssl, const void *buf, int num);
```

`SSL_write` 和 `SSL_write_ex` 会从缓冲区 `buf` 中将最多 `num` 字节的数据写入到指定的 `ssl` 连接中。成功时，`SSL_write_ex` 会在 `*written` 中存储实际写入的字节数。

## eBPF 内核态代码编写

首先是内核态和用户态共享的数据结构，内核态通过其往用户态发送数据：

```c
#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;
    int buf_filled;
    int rw;
    char comm[TASK_COMM_LEN];
    __u8 buf[MAX_BUF_SIZE];
    int is_handshake;
};
```

hook ssl_read 和 ssl_write:

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

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    return (SSL_exit(ctx, 0));
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    return (SSL_exit(ctx, 1));
}
```

hook handshake:

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

## 用户态辅助代码分析

用户态负责挂载 eBPF 程序，以及通过 perf event 接收内核态发送的数据信息：

支持三种库的挂载：

```
    if (env.openssl) {
        char *openssl_path = find_library_path("libssl.so");
        printf("OpenSSL path: %s\n", openssl_path);
        attach_openssl(obj, "/lib/x86_64-linux-gnu/libssl.so.3");
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

具体的 attach 函数：

```c
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

对于三种库，分别需要使用不同的挂载逻辑：

perf event

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

## 编译运行

In one terminal, initiate `sslsniff` by running:

```sh
sudo ./sslsniff
```

In a separate terminal, execute:

```console
$ curl https://example.com
<!doctype html>
<html>
<head>
    <title>Example Domain</title>
    .... { rest of curl data }
<body>
<div>
    .... { rest of curl data }
</div>
</body>
</html>
```

#### Output

Upon running the curl command, `sslsniff` is expected to display the following output:

```txt
READ/RECV    0.132786160        curl             47458   1256  
----- DATA -----
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

....
<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>

----- END DATA -----
```

*Note:* The displayed HTML content might vary based on the fetched page from `example.com`.

### show latency and handshake prosess

```
$ sudo ./sslsniff -l --handshake
OpenSSL path: /lib/x86_64-linux-gnu/libssl.so.3
GnuTLS path: /lib/x86_64-linux-gnu/libgnutls.so.30
NSS path: /lib/x86_64-linux-gnu/libnspr4.so
FUNC         TIME(s)            COMM             PID     LEN     LAT(ms)
HANDSHAKE    0.000000000        curl             6460    1      1.384  WRITE/SEND   0.000115400        curl             6460    24     0.014 
```

### hexdump

```
$ sudo ./sslsniff --hexdump
WRITE/SEND   0.000000000        curl             16104   24    
----- DATA -----
505249202a20485454502f322e300d0a
0d0a534d0d0a0d0a
----- END DATA -----

WRITE/SEND   0.000079802        curl             16104   27    
----- DATA -----
00001204000000000000030000006400
0402000000000200000000
----- END DATA -----
```

## 总结

如果您对 eBPF 技术感兴趣，并希望进一步了解和实践，可以访问我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 和教程网站 <https://eunomia.dev/zh/tutorials/。>

参考资料：

- <https://github.com/iovisor/bcc/pull/4706>
- <https://github.com/openssl/openssl>
- <https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html>
- <https://github.com/iovisor/bcc/blob/master/tools/sslsniff_example.txt>
- https://en.wikipedia.org/wiki/Transport_Layer_Security
