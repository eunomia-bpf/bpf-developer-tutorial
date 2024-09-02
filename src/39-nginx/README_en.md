# Using eBPF to trace Nginx requests

> add simple background for nginx and eBPF

Performance-Critical Functions in Nginx

Nginx is a highly optimized event-driven server, and its performance-critical functions typically include those involved in request processing, response generation, and event handling. Some key functions that you might consider hooking into are:

ngx_http_process_request: This function is responsible for processing incoming HTTP requests. It’s a good place to monitor the start of request handling.

ngx_http_upstream_send_request: In scenarios where Nginx is acting as a reverse proxy, this function handles sending requests to upstream servers.

ngx_http_finalize_request: This function finalizes the processing of an HTTP request, including sending the response. Hooking into this can help measure request handling time.

ngx_event_process_posted: This function processes queued events, which is part of the Nginx event loop.

ngx_handle_read_event: Responsible for handling read events from sockets. This is crucial for monitoring network I/O performance.

ngx_writev_chain: This function handles sending responses back to the client, often in conjunction with the write event loop.

> add some background about uprobe
>

`Uprobe` in kernel mode eBPF runtime may also cause relatively large performance overhead. In this case, you can also consider using user mode eBPF runtime, such as [bpftime](https://github.com/eunomia-bpf/bpftime). bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. It can run eBPF programs in user mode, compatible with kernel mode eBPF and can be faster for `uprobe`.

## Using bpftrace to trace nginx functions

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

Run the program, start a nginx and using curl for a request:

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
Event processing started (tid: 1071)
Event processed in 86297 ns (tid: 1071)
Event processing started (tid: 1071)
Event processed in 100597 ns (tid: 1071)
Event processing started (tid: 1071)
Event processed in 93598 ns (tid: 1071)
```

## test function latency of nginx

using the funclatency tool, and test with `wrk http://localhost`:

```console
# sudo ./funclatency /usr/sbin/nginx:ngx_http_process_request
tracing /usr/sbin/nginx:ngx_http_process_request...
tracing func ngx_http_process_request in /usr/sbin/nginx...
Tracing /usr/sbin/nginx:ngx_http_process_request.  Hit Ctrl-C to exit
^C
     nsec                : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 0        |                                        |
     16384 -> 32767      : 0        |                                        |
     32768 -> 65535      : 0        |                                        |
     65536 -> 131071     : 0        |                                        |
    131072 -> 262143     : 0        |                                        |
    262144 -> 524287     : 0        |                                        |
    524288 -> 1048575    : 16546    |****************************************|
   1048576 -> 2097151    : 2296     |*****                                   |
   2097152 -> 4194303    : 1264     |***                                     |
   4194304 -> 8388607    : 293      |                                        |
   8388608 -> 16777215   : 37       |                                        |
Exiting trace of /usr/sbin/nginx:ngx_http_process_request
```

> summary the result, and mention what we can do with funclatency of nginx

You can find the funclatency tool in [https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/33-funclatency)

## conclusion

For those interested in learning more about eBPF, including more advanced examples and tutorials, please visit our [https://github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [https://eunomia.dev/tutorials/](https://eunomia.dev/tutorials/).
