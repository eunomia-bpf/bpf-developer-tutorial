# Using eBPF to Trace Nginx Requests

Nginx is one of the most popular web servers and reverse proxies in the world, known for its high performance, stability, and low resource consumption. It is widely used for serving static content, load balancing, and acting as a reverse proxy for dynamic applications. To maintain its performance edge, it's crucial to monitor and optimize Nginx's operations, especially when handling a large number of requests. One powerful way to gain insights into Nginx's performance is by using eBPF (Extended Berkeley Packet Filter).

eBPF is a revolutionary technology that allows developers to run custom programs in the Linux kernel. Originally designed for network packet filtering, eBPF has evolved into a versatile tool for tracing, monitoring, and profiling system behavior in both kernel and user space. By leveraging eBPF, you can trace Nginx's critical functions, measure latency, and identify bottlenecks without modifying the source code or restarting the service.

## Background: Nginx and eBPF

### Nginx

Nginx operates on an event-driven architecture, making it highly efficient and capable of handling thousands of simultaneous connections with minimal resources. This efficiency is achieved through various performance-critical functions involved in request processing, response generation, and event handling. Understanding how these functions behave under different loads is key to optimizing Nginx for your specific use case.

### eBPF

eBPF programs run in a secure, sandboxed environment within the Linux kernel. These programs can attach to various hooks, such as system calls, tracepoints, and even user-space functions via uprobes (user-level probes). This capability allows you to collect detailed performance data and enforce policies in real time, making eBPF an invaluable tool for system observability.

One common use case of eBPF is tracing function execution to measure latency, which is particularly useful for understanding how long specific Nginx functions take to execute. This information can help in diagnosing performance issues, optimizing resource usage, and improving the overall efficiency of your Nginx deployment.

### Uprobes

Uprobes are a type of probe that can be used to trace functions in user-space applications, such as Nginx. They work by attaching to specific user-space function entry and exit points, allowing you to capture precise timing information. However, it’s important to note that using uprobes in the kernel mode eBPF runtime may cause some performance overhead. To mitigate this, you can consider using a user-mode eBPF runtime like [bpftime](https://github.com/eunomia-bpf/bpftime), which is based on LLVM JIT/AOT. This runtime can run eBPF programs in user space, offering compatibility with kernel mode eBPF while potentially reducing overhead.

## Performance-Critical Functions in Nginx

Here are some key Nginx functions that are performance-critical and can be monitored using eBPF:

- **ngx_http_process_request**: Processes incoming HTTP requests. Monitoring this function helps track the start of request handling.
- **ngx_http_upstream_send_request**: Handles sending requests to upstream servers when Nginx is acting as a reverse proxy.
- **ngx_http_finalize_request**: Finalizes HTTP request processing, including sending the response. Tracing this can measure total request handling time.
- **ngx_event_process_posted**: Processes queued events as part of the Nginx event loop.
- **ngx_handle_read_event**: Handles read events from sockets, crucial for monitoring network I/O performance.
- **ngx_writev_chain**: Sends responses back to the client, typically used in conjunction with the write event loop.

## Using bpftrace to Trace Nginx Functions

To monitor these functions, we can use `bpftrace`, a high-level tracing language for eBPF. Below is a script that traces the execution time of several critical Nginx functions:

```bt
#!/usr/sbin/bpftrace

// Monitor the start of HTTP request processing
uprobe:/usr/sbin/nginx:ngx_http_process_request
{
    printf("HTTP request processing started (tid: %d)\n", tid);
    @start[tid] = nsecs;
}

// Monitor when an HTTP request is finalized
uretprobe:/usr/sbin/nginx:ngx_http_finalize_request
/@start[tid]/
{
    $elapsed = nsecs - @start[tid];
    printf("HTTP request processed in %d ns (tid: %d)\n", $elapsed, tid);
    delete(@start[tid]);
}

// Monitor the start of sending a request to an upstream server
uprobe:/usr/sbin/nginx:ngx_http_upstream_send_request
{
    printf("Upstream request sending started (tid: %d)\n", tid);
    @upstream_start[tid] = nsecs;
}

// Monitor when the upstream request is sent
uretprobe:/usr/sbin/nginx:ngx_http_upstream_send_request
/@upstream_start[tid]/
{
    $elapsed = nsecs - @upstream_start[tid];
    printf("Upstream request sent in %d ns (tid: %d)\n", $elapsed, tid);
    delete(@upstream_start[tid]);
}

// Monitor the start of event processing
uprobe:/usr/sbin/nginx:ngx_event_process_posted
{
    printf("Event processing started (tid: %d)\n", tid);
    @event_start[tid] = nsecs;
}

// Monitor when event processing is completed
uretprobe:/usr/sbin/nginx:ngx_event_process_posted
/@event_start[tid]/
{
    $elapsed = nsecs - @event_start[tid];
    printf("Event processed in %d ns (tid: %d)\n", $elapsed, tid);
    delete(@event_start[tid]);
}
```

### Running the Program

To run the above script, start Nginx and use a tool like `curl` to generate HTTP requests:

```bt
# bpftrace /home/yunwei37/bpf-developer-tutorial/src/39-nginx/trace.bt
Attaching 4 probes...
Event processing started (tid: 1071)
Event processed in 166396 ns (tid: 1071)
Event processing started (tid: 1071)
Event processed in 87998 ns (tid: 1071)
HTTP request processing started (tid: 1071)
HTTP request processed in 1083969 ns (tid: 1071)
Event processing started (tid: 1071)
Event processed in 92597 ns (tid: 1071)
```

The script monitors the start and end times of various Nginx functions and prints the elapsed time for each. This data can be used to analyze and optimize the performance of your Nginx server.

## Testing Function Latency in Nginx

For a more detailed analysis of function latency, you can use the `funclatency` tool, which measures the latency distribution of Nginx functions. Here’s how to test the latency of the `ngx_http_process_request` function:

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

### Summary of Results

The results above show the distribution of latency for the `ngx_http_process_request` function. The majority of requests were processed within 524,288 to 1,048,575 nanoseconds, with a smaller percentage taking longer. This information can be crucial in identifying performance bottlenecks and optimizing request handling in Nginx.

By using `funclatency`, you can:

- **Identify Performance Bottlenecks**: Understand which functions are taking the most time to execute and focus your optimization efforts there.
- **Monitor System Performance**: Regularly monitor function latency to ensure your Nginx server is performing optimally, especially under heavy load.
- **Optimize Nginx Configuration**: Use the insights gained from latency measurements to tweak Nginx settings or modify your application to improve overall performance.

You can find the `funclatency` tool in the [bpf-developer-tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency).

## Conclusion

Tracing Nginx requests with eBPF provides valuable insights into the performance of your web server, allowing you to monitor, analyze, and optimize its operation. By using tools like `bpftrace` and `funclatency`, you can measure function execution times, identify bottlenecks, and make data-driven decisions to improve your Nginx deployment.

For those interested in learning more about eBPF, including more advanced examples and tutorials, please visit our [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or check out our [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/).
