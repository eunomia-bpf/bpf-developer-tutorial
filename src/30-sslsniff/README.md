# eBPF Practical Tutorial: Capturing SSL/TLS Plain Text Data Using uprobe

With the widespread use of TLS in modern network environments, tracing microservices RPC messages has become increasingly challenging. Traditional traffic sniffing techniques often face limitations in accessing only encrypted data, preventing a genuine observation of the original communication content. This restriction poses significant obstacles to system debugging and analysis.

However, a new solution is now available. Through the use of eBPF technology and its capability to perform probing in user space, a method has emerged to regain plain text data, allowing us to intuitively view the pre-encrypted communication content. Nevertheless, each application might utilize different libraries, and each library comes in multiple versions, introducing complexity to the tracking process.

In this tutorial, we will guide you through an eBPF tracing technique that spans across various user-space SSL/TLS libraries. This technique not only allows simultaneous tracing of user-space libraries like GnuTLS and OpenSSL but also significantly reduces maintenance efforts for new library versions compared to previous methods. The complete code for this tutorial can be found in <完整的源代码可以在这里查看：<https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff>

## Background Knowledge

Before delving into the main topic of this tutorial, we need to grasp some core concepts that will serve as the foundation for our subsequent discussions.

### SSL and TLS

SSL (Secure Sockets Layer): Developed by Netscape in the early 1990s, SSL provides data encryption for communication between two machines on a network. However, due to known security vulnerabilities, SSL has been succeeded by its successor, TLS.

TLS (Transport Layer Security): TLS is the successor to SSL, aiming to provide stronger and more secure data encryption methods. TLS operates through a handshake process during which a client and a server select an encryption algorithm and corresponding keys. Once the handshake is complete, data transmission begins, with all data being encrypted using the chosen algorithm and keys.

### Operation Principles of TLS

Transport Layer Security (TLS) is a cryptographic protocol designed to provide security for communication over computer networks. Its primary goal is to provide security, including privacy (confidentiality), integrity, and authenticity, for two or more communicating computer applications over a network using cryptography, such as certificates. TLS consists of two sub-layers: the TLS Record Protocol and the TLS Handshake Protocol.

#### Handshake Process

When a client connects to a TLS-enabled server and requests a secure connection, the handshake process begins. The handshake allows the client and server to establish security parameters for the connection using asymmetric cryptography. The complete process is as follows:

1. **Initial Handshake**: The client connects to the TLS-enabled server, requests a secure connection, and provides a list of supported cipher suites (encryption algorithms and hash functions).
2. **Selecting Cipher Suite**: From the provided list, the server chooses a cipher suite and hash function it also supports and notifies the client of the decision.
3. **Providing Digital Certificate**: Usually, the server then provides identity authentication in the form of a digital certificate. This certificate includes the server's name, trusted certificate authorities (guaranteeing the certificate's authenticity), and the server's public encryption key.
4. **Certificate Verification**: The client verifies the certificate's validity before proceeding.
5. **Generating Session Key**: To create a session key for a secure connection, the client has two methods:
    - Encrypt a random number (PreMasterSecret) with the server's public key and send the result to the server (only the server can decrypt it with its private key); both parties then use this random number to generate a unique session key for encrypting and decrypting data during the session.
    - Use Diffie-Hellman key exchange (or its variant, Elliptic Curve DH) to securely generate a random and unique session key for encryption and decryption. This key has the additional property of forward secrecy: even if the server's private key is exposed in the future, it can't be used to decrypt the current session, even if a third party intercepts and records the session.

Once these steps are successfully completed, the handshake process concludes, and the encrypted connection begins. This connection uses the session key for encryption and decryption until the connection is closed. If any of the above steps fail, the TLS handshake fails, and the connection won't be established.

#### TLS in the OSI Model

TLS and SSL don't perfectly align with any single layer of the OSI model or the TCP/IP model. TLS "runs over some reliable transport protocol (such as TCP)," which means it sits above the transport layer. It provides encryption for higher layers, typically the presentation layer. However, applications using TLS often consider it the transport layer, even though applications using TLS must actively control the initiation of TLS handshakes and the handling of exchanged authentication certificates.

### eBPF and uprobes

eBPF (Extended Berkeley Packet Filter): It's a kernel technology that allows users to run predefined programs in the kernel space without modifying kernel source code or reloading modules. It creates a bridge that enables interaction between user space and kernel space, providing unprecedented capabilities for tasks like system monitoring, performance analysis, and network traffic analysis.

uprobes are a significant feature of eBPF, allowing dynamic insertion of probe points in user space applications, particularly useful for tracking function calls in SSL/TLS libraries. Uprobe in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime)。bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode and is compatible with kernel mode eBPF, avoiding context switching between kernel mode and user mode, thereby improving the execution efficiency of eBPF programs. bpftime can have a performance overhead that is one order of magnitude smaller than that of kernel mode eBPF.

### User-Space Libraries

The implementation of the SSL/TLS protocol heavily relies on user-space libraries. Here are some common ones:

- OpenSSL: An open-source, feature-rich cryptographic library widely used in many open-source and commercial projects.
- BoringSSL: A fork of OpenSSL maintained by Google, focusing on simplification and optimization for Google's needs.
- GnuTLS: Part of the GNU project, offering an implementation of SSL, TLS, and DTLS protocols. GnuTLS differs from OpenSSL and BoringSSL in API design, module structure, and licensing.

## OpenSSL API Analysis

OpenSSL is a widely used open-source library providing a complete implementation of the SSL and TLS protocols, ensuring data transmission security in various applications. Among its functions, SSL_read() and SSL_write() are two core API functions for reading from and writing to TLS/SSL connections. In this section, we'll delve into these functions to help you understand their mechanisms.

### 1. SSL_read Function

When we want to read data from an established SSL connection, we can use the `SSL_read` or `SSL_read_ex` function. The function prototype is as follows:

```c
int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int SSL_read(SSL *ssl, void *buf, int num);
```

`SSL_read` and `SSL_read_ex` attempt to read up to `num` bytes of data from the specified `ssl` into the buffer `buf`. Upon success, `SSL_read_ex` stores the actual number of read bytes in `*readbytes`.

### 2. Function SSL_write

When we want to write data into an established SSL connection, we can use the `SSL_write` or `SSL_write_ex` functions.

Function prototype:

```c
int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_write(SSL *ssl, const void *buf, int num);
```

`SSL_write` and `SSL_write_ex` will write up to `num` bytes of data from the buffer `buf` into the specified `ssl` connection. Upon success, `SSL_write_ex` will store the actual number of written bytes in `*written`.

## Writing eBPF Kernel Code

In our example, we use eBPF to hook the `ssl_read` and `ssl_write` functions to perform custom actions when data is read from or written to an SSL connection.

### Data Structures

Firstly, we define a data structure `probe_SSL_data_t` to transfer data between kernel and user space:

```c
#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
    __u64 timestamp_ns;  // Timestamp (nanoseconds)
    __u64 delta_ns;      // Function execution time
    __u32 pid;           // Process ID
    __u32 tid;           // Thread ID
    __u32 uid;           // User ID
    __u32 len;           // Length of read/write data
    int buf_filled;      // Whether buffer is filled completely
    int rw;              // Read or Write (0 for read, 1 for write)
    char comm[TASK_COMM_LEN]; // Process name
    __u8 buf[MAX_BUF_SIZE];  // Data buffer
    int is_handshake;    // Whether it's handshake data
};
```

### Hook Functions

Our goal is to hook into the `SSL_read` and `SSL_write` functions. We define a function `SSL_exit` to handle the return values of these two functions. This function determines whether to trace and collect data based on the current process and thread IDs.

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

The `rw` parameter here indicates whether it's a read or write operation. 0 represents read, and 1 represents write.

#### Data Collection Process

1. Obtain the ID of the current process and thread, along with the ID of the current user.
2. Use `trace_allowed` to determine if tracing is allowed for this process.
3. Get the start time to calculate the execution time of the function.
4. Attempt to retrieve relevant data from the `bufs` and `start_ns` maps.
5. If data retrieval is successful, create or locate a `probe_SSL_data_t` structure to populate the data.
6. Copy the data from user space to the buffer, ensuring it doesn't exceed the designated size.
7. Finally, send the data to user space.

Note: We use two user-level return probes `uretprobe` to respectively hook the returns of `SSL_read` and `SSL_write`:

```c
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit) {
    return (SSL_exit(ctx, 0));  // 0 indicates read operation
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit) {
    return (SSL_exit(ctx, 1));  // 1 indicates write operation
}
```

### Hooking into the Handshake Process

In SSL/TLS, the handshake is a special process used to establish a secure connection between a client and a server. To analyze this process, we hook into the `do_handshake` function to track the start and end of the handshake.

#### Entering the Handshake

We use a `uprobe` to set a probe for the `do_handshake` function:

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

The main functionality of this code is as follows:

1. Obtain the current `pid`, `tid`, `ts`, and `uid`.
2. Use `trace_allowed` to verify if the process is allowed to be traced.
3. Store the current timestamp in the `start_ns` map, which will be used to calculate the duration of the handshake process later.

#### Exiting the Handshake

Similarly, we've set a `uretprobe` for the return of `do_handshake`:

```c
SEC("uretprobe/do_handshake")
int BPF_URETPROBE(handle_do_handshake_exit) {
    // Code to execute upon exiting the do_handshake function.
    return 0;
}
```

In this context, the `uretprobe` will execute the provided code when the `do_handshake` function exits.

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

Logic of this Function:

1. Obtain the current `pid`, `tid`, `ts`, and `uid`.
2. Use `trace_allowed` to recheck if tracing is allowed.
3. Look up the timestamp in the `start_ns` map for calculating handshake duration.
4. Use `PT_REGS_RC(ctx)` to get the return value of `do_handshake` and determine if the handshake was successful.
5. Find or initialize the `probe_SSL_data_t` data structure associated with the current thread.
6. Update the data structure's fields, including timestamp, duration, process information, etc.
7. Use `bpf_perf_event_output` to send the data to user space.

Our eBPF code not only tracks data transmission for `ssl_read` and `ssl_write` but also focuses on the SSL/TLS handshake process. This information is crucial for a deeper understanding and optimization of the performance of secure connections.

Through these hook functions, we can obtain data regarding the success of the handshake, the time taken for the handshake, and related process information. This provides us with insights into the behavior of the system's SSL/TLS, enabling us to perform more in-depth analysis and optimization when necessary.

## User-Space Assisted Code Analysis and Interpretation

In the eBPF ecosystem, user-space and kernel-space code often work in collaboration. Kernel-space code is responsible for data collection, while user-space code manages, processes, and handles this data. In this section, we will explain how the above user-space code collaborates with eBPF to trace SSL/TLS interactions.

### 1. Supported Library Attachment

In the provided code snippet, based on the setting of the `env` environment variable, the program can choose to attach to three common encryption libraries (OpenSSL, GnuTLS, and NSS). This means that we can trace calls to multiple libraries within the same tool.

To achieve this functionality, the `find_library_path` function is first used to determine the library's path. Then, depending on the library type, the corresponding `attach_` function is called to attach the eBPF program to the library function.

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

This section primarily covers the attachment logic for the OpenSSL, GnuTLS, and NSS libraries. NSS is a set of security libraries designed for organizations, supporting the creation of secure client and server applications. Originally developed by Netscape, they are now maintained by Mozilla. The other two libraries have been introduced earlier and are not reiterated here.

### 2. Detailed Attachment Logic

The specific `attach` functions are as follows:

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

We further examine the `attach_` function and can see that they both use the `ATTACH_UPROBE_CHECKED` and `ATTACH_URETPROBE_CHECKED` macros to implement specific mounting logic. These two macros are used respectively for setting uprobe (function entry) and uretprobe (function return).

Considering that different libraries have different API function names (for example, OpenSSL uses `SSL_write`, while GnuTLS uses `gnutls_record_send`), we need to write a separate `attach_` function for each library.

For instance, in the `attach_openssl` function, we set up probes for both `SSL_write` and `SSL_read`. If users also want to track handshake latency (`env.latency`) and the handshake process (`env.handshake`), we set up a probe for `SSL_do_handshake`.

In the eBPF ecosystem, `perf_buffer` is an efficient mechanism used to transfer data from kernel space to user space. This is particularly useful for kernel-space eBPF programs as they can't directly interact with user space. With `perf_buffer`, we can collect data in kernel-space eBPF programs and then asynchronously read this data in user space. We use the `perf_buffer__poll` function to read data reported in kernel space, as shown below:

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

Finally, in the `print_event` function, we print the data to standard output:

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

You can find the complete source code here: [https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff)

## Compilation and Execution

To start using `sslsniff`, you need to first compile it:

```sh
make
```

Once done, follow these steps:

### **Start sslsniff**

In a terminal, execute the following command to start `sslsniff`:

```sh
sudo ./sslsniff
```

### **Execute CURL command**

In another terminal, execute:

```console
curl https://example.com
```

Under normal circumstances, you will see output similar to the following:

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

### **sslsniff Output**

After executing the `curl` command, `sslsniff` will display the following content:

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

**Note**: The displayed HTML content may vary depending on the specific content of the `example.com` page.

### Displaying Latency and Handshake Process

To view latency and handshake process, execute the following command:

```console
$ sudo ./sslsniff -l --handshake
OpenSSL path: /lib/x86_64-linux-gnu/libssl.so.3
GnuTLS path: /lib/x86_64-linux-gnu/libgnutls.so.30
NSS path: /lib/x86_64-linux-gnu/libnspr4.so
FUNC         TIME(s)            COMM             PID     LEN     LAT(ms)
HANDSHAKE    0.000000000        curl             6460    1      1.384  WRITE/SEND   0.000115400        curl             6460    24     0.014
```

### Hexadecimal Output

To display data in hexadecimal format, execute the following command:

```console
$ sudo ./sslsniff --hexdump
WRITE/SEND   0.000000000        curl             16104   24
----- DATA -----
505249202a20485454502f322e300d0a
0d0a534d0d0a0d0a
----- END DATA -----

...
```

## Summary

eBPF is a very powerful technology that can help us gain deeper insights into how a system works. This tutorial is a simple example demonstrating how to use eBPF to monitor SSL/TLS communication. If you're interested in eBPF technology and want to learn more and practice further, you can visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> and tutorial website at <https://eunomia.dev/zh/tutorials/>.

References:

- <https://github.com/iovisor/bcc/pull/4706>
- <https://github.com/openssl/openssl>
- <https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html>
- <https://github.com/iovisor/bcc/blob/master/tools/sslsniff_example.txt>
- <https://en.wikipedia.org/wiki/Transport_Layer_Security>

> The original link of this article: <https://eunomia.dev/tutorials/30-sslsniff>
