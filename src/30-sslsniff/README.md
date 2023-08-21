# eBPF 实践教程：使用 uprobe 捕获多种 SSL/TLS 库的加密明文

TLS 在当今环境中的应用正在快速增长，这给拦截微服务 RPC 消息的跟踪工具带来了挑战。普通流量嗅探收集的是加密数据，无法访问原始有效载荷。这阻碍了传统跟踪工具的使用，并在出现关键问题时使系统调试变得更加复杂。

为了解决这个问题，eBPF 工具会探测用户空间，以重新获取明文数据。虽然这些方法令人兴奋，但由于库的选择、每个库的可能版本和链接类型多种多样，扩展这种类型的仪器会遇到一系列新的困难。

我们介绍了为可靠地跟踪 TLS 应用程序而开发的技术，这些技术跨越了实际应用中的各种条件，可以同时跟踪 BoringSSL 和 OpenSSL，并且与之前的跟踪相比，减少了支持新版本库的维护工作。最后，我们指出了仍然存在的覆盖挑战和我们的未来计划。

#### Setup:

1. In one terminal, initiate `sslsniff` by running:
```sh
sudo ./sslsniff
```

2. In a separate terminal, execute:
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

#### Output:

Upon running the curl command, `sslsniff` is expected to display the following output:

```txt
READ/RECV    0.132786160        curl             47458   1256  
----- DATA -----
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

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

#### Test for latency and handshake

```
$ sudo ./sslsniff -l --handshake
OpenSSL path: /lib/x86_64-linux-gnu/libssl.so.3
GnuTLS path: /lib/x86_64-linux-gnu/libgnutls.so.30
NSS path: /lib/x86_64-linux-gnu/libnspr4.so
FUNC         TIME(s)            COMM             PID     LEN     LAT(ms)
HANDSHAKE    0.000000000        curl             6460    1      1.384  WRITE/SEND   0.000115400        curl             6460    24     0.014 
```

#### Test for hexdump

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
