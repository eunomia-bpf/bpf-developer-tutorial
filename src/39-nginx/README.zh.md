# 使用 eBPF 跟踪 Nginx 请求

## 引言

Nginx 是世界上最流行的 Web 服务器和反向代理之一，以其高性能、稳定性和低资源消耗而闻名。它广泛用于提供静态内容、负载均衡以及作为动态应用的反向代理。为了保持其性能优势，监控和优化 Nginx 的运行尤为重要，尤其是在处理大量请求时。利用 eBPF（扩展的伯克利包过滤器），可以深入了解 Nginx 的性能表现，识别瓶颈并进行优化，而无需修改源代码或重启服务。

eBPF 是一项革命性技术，允许开发人员在 Linux 内核中运行自定义程序。最初设计用于网络数据包过滤，但 eBPF 现已发展为一个多功能工具，广泛应用于跟踪、监控和分析系统行为。通过利用 eBPF，您可以跟踪 Nginx 的关键函数，测量延迟，识别瓶颈，进而优化系统性能。

## 背景：Nginx 和 eBPF

### Nginx

Nginx 采用事件驱动架构，使其在资源占用极少的情况下能够高效处理成千上万的并发连接。这种高效性依赖于其请求处理、响应生成和事件处理等多个性能关键函数。了解这些函数在不同负载下的表现对于优化 Nginx 的使用至关重要。

### eBPF

eBPF 程序在 Linux 内核的安全沙盒环境中运行。这些程序可以附加到各种钩子上，如系统调用、跟踪点，甚至可以通过 uprobes（用户级探针）附加到用户空间的函数。这使得 eBPF 成为一个强大的系统可观测性工具，可以收集详细的性能数据并实时执行策略。

eBPF 的一个常见用例是跟踪函数执行时间，以测量延迟。这对于了解 Nginx 中特定函数的执行时间特别有用，有助于诊断性能问题、优化资源使用，并提高 Nginx 部署的整体效率。

### Uprobes

Uprobes 是一种用于跟踪用户空间应用程序函数的探针，它通过附加到特定用户空间函数的入口和出口点，可以捕获精确的时间信息。然而，需要注意的是，在内核模式 eBPF 运行时使用 uprobes 可能会带来一定的性能开销。为此，您可以考虑使用基于 LLVM JIT/AOT 的用户模式 eBPF 运行时 [bpftime](https://github.com/eunomia-bpf/bpftime)。这种运行时可以在用户空间中运行 eBPF 程序，与内核模式 eBPF 兼容，并有可能降低开销。

## Nginx 的性能关键函数

以下是 Nginx 中一些性能关键的函数，可以通过 eBPF 进行监控：

- **ngx_http_process_request**：负责处理传入的 HTTP 请求。监控此函数有助于跟踪请求处理的开始。
- **ngx_http_upstream_send_request**：当 Nginx 作为反向代理时，负责向上游服务器发送请求。
- **ngx_http_finalize_request**：完成 HTTP 请求的处理，包括发送响应。跟踪此函数可以衡量整个请求处理的时间。
- **ngx_event_process_posted**：处理事件循环中的队列事件。
- **ngx_handle_read_event**：负责处理来自套接字的读取事件，对监控网络 I/O 性能至关重要。
- **ngx_writev_chain**：负责将响应发送回客户端，通常与写事件循环结合使用。

## 使用 bpftrace 跟踪 Nginx 函数

为了监控这些函数，我们可以使用 `bpftrace`，一种 eBPF 的高级跟踪语言。以下是一个用于跟踪几个关键 Nginx 函数执行时间的脚本：

```bt
#!/usr/sbin/bpftrace

// 监控 HTTP 请求处理的开始
uprobe:/usr/sbin/nginx:ngx_http_process_request
{
    printf("HTTP 请求处理开始 (tid: %d)\n", tid);
    @start[tid] = nsecs;
}

// 监控 HTTP 请求的完成
uretprobe:/usr/sbin/nginx:ngx_http_finalize_request
/@start[tid]/
{
    $elapsed = nsecs - @start[tid];
    printf("HTTP 请求处理时间: %d ns (tid: %d)\n", $elapsed, tid);
    delete(@start[tid]);
}

// 监控向上游服务器发送请求的开始
uprobe:/usr/sbin/nginx:ngx_http_upstream_send_request
{
    printf("开始向上游服务器发送请求 (tid: %d)\n", tid);
    @upstream_start[tid] = nsecs;
}

// 监控上游请求发送完成
uretprobe:/usr/sbin/nginx:ngx_http_upstream_send_request
/@upstream_start[tid]/
{
    $elapsed = nsecs - @upstream_start[tid];
    printf("上游请求发送完成时间: %d ns (tid: %d)\n", $elapsed, tid);
    delete(@upstream_start[tid]);
}

// 监控事件处理的开始
uprobe:/usr/sbin/nginx:ngx_event_process_posted
{
    printf("事件处理开始 (tid: %d)\n", tid);
    @event_start[tid] = nsecs;
}

// 监控事件处理的完成
uretprobe:/usr/sbin/nginx:ngx_event_process_posted
/@event_start[tid]/
{
    $elapsed = nsecs - @event_start[tid];
    printf("事件处理时间: %d ns (tid: %d)\n", $elapsed, tid);
    delete(@event_start[tid]);
}
```

### 运行脚本

要运行上述脚本，先启动 Nginx，然后使用 `curl` 等工具生成 HTTP 请求：

```bt
# bpftrace /home/yunwei37/bpf-developer-tutorial/src/39-nginx/trace.bt
Attaching 4 probes...
事件处理开始 (tid: 1071)
事件处理时间: 166396 ns (tid: 1071)
事件处理开始 (tid: 1071)
事件处理时间: 87998 ns (tid: 1071)
HTTP 请求处理开始 (tid: 1071)
HTTP 请求处理时间: 1083969 ns (tid: 1071)
事件处理开始 (tid: 1071)
事件处理时间: 92597 ns (tid: 1071)
```

该脚本监控了几个 Nginx 函数的开始和结束时间，并打印了每个函数的执行时间。这些数据可以用来分析和优化 Nginx 服务器的性能。

## 测试 Nginx 的函数延迟

为了更详细地分析函数延迟，您可以使用 `funclatency` 工具，该工具可以测量 Nginx 函数的延迟分布。以下是如何测试 `ngx_http_process_request` 函数的延迟：

```console
# sudo ./funclatency /usr/sbin/nginx:ngx_http_process_request
tracing /usr/sbin/nginx:ngx_http_process_request...
tracing func ngx_http_process_request in /usr/sbin/nginx...
Tracing /usr/sbin/nginx:ngx_http_process_request.  Hit Ctrl-C to exit
^C
     nsec                : count    distribution
         0 -> 1          : 0        |                                        |
   524288 -> 1048575    : 16546    |****************************************|
   1048576 -> 2097151    : 2296     |*****                                   |
   2097152 -> 4194303    : 1264     |***                                     |
   4194304 -> 8388607    : 293      |                                        |
   8388608 -> 16777215   : 37       |                                        |
Exiting trace of /usr/sbin/nginx:ngx_http_process_request
```

### 结果总结

上述结果显示了 `ngx_http_process_request` 函数的延迟分布。大多数请求在 524,288 至 1,048,575 纳秒内处理完成，少部分请求处理时间更长。这些信息对于识别性能瓶颈和优化 Nginx 请求处理至关重要。

通过使用 `funclatency`，您可以：

- **识别性能瓶颈**：了解哪些函数执行时间最长，并将优化工作重点放在这些函数上。
- **监控系统性能**：定期监控函数延迟，确保在高负载下 Nginx 服务器的最佳性能。
- **优化 Nginx 配置**：利用延迟测量得出的洞察调整 Nginx 设置或修改应用程序，以提高整体性能。

您可以在 [bpf-developer-tutorial 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency) 中找到 `funclatency` 工具。

## 结论

通过 eBPF 跟踪 Nginx 请求可以为您的 Web 服务器提供宝贵的性能洞察，使您能够监控、分析和优化其操作。使用 `bpftrace` 和 `funclatency`

 等工具，您可以测量函数执行时间、识别瓶颈，并根据数据做出决策来改进 Nginx 部署。

如果您有兴趣了解更多关于 eBPF 的知识，包括更多高级示例和教程，请访问我们的 [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) 或查看我们的网站 [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/)。
