# eBPF 实践教程：使用 eBPF 用户态捕获多种库的 SSL/TLS 明文数据

随着TLS在现代网络环境中的广泛应用，跟踪微服务RPC消息已经变得愈加棘手。传统的流量嗅探技术常常受限于只能获取到加密后的数据，导致无法真正观察到通信的原始内容。这种限制为系统的调试和分析带来了不小的障碍。

但现在，我们有了新的解决方案。

eBPF技术，通过其能力在用户空间进行探测，提供了一种方法重新获得明文数据，使得我们可以直观地查看加密前的通信内容。然而，每个应用可能使用不同的库，每个库都有多个版本，这种多样性给跟踪带来了复杂性。

在本教程中，我们将带您了解一种跨多种条件的技术，它不仅可以同时跟踪 GnuTLS 和 OpenSSL 等用户态库，而且相比以往，大大降低了对新版本库的维护工作。

## 背景知识

## OpenSSL 代码分析

## eBPF 内核态代码编写

## 用户态辅助代码分析

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

## 总结

