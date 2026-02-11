# XDP Load Balancer - Curl Hanging Issue Fix

## Summary

This document describes the fix for the issue where `curl 10.0.0.10:8000` requests would hang indefinitely when testing the XDP load balancer.

## Problem Description

When running `curl 10.0.0.10:8000` to test the XDP load balancer, the request would hang and never complete. This occurred even though:
- The network topology was correctly set up
- The XDP program was successfully loaded and attached
- Packets were being forwarded to the backend servers

## Root Cause

The issue was caused by a mismatch between the HTTP Host header and the backend server's IP address:

1. **Client sends request**: When `curl 10.0.0.10:8000` makes a request, it includes an HTTP Host header set to `Host: 10.0.0.10:8000`

2. **XDP forwards at Layer 3/4**: The XDP load balancer operates at the IP/TCP layer (Layer 3/4) and modifies:
   - Source IP: Changed to load balancer's IP (10.0.0.10)
   - Destination IP: Changed to backend's IP (10.0.0.2 or 10.0.0.3)
   - MAC addresses: Updated accordingly
   - IP and TCP checksums: Recalculated

3. **HTTP headers remain unchanged**: The XDP program does NOT modify HTTP headers (this would require parsing and modifying the packet payload, which is complex and inefficient at the XDP level)

4. **Backend server rejects request**: The backend HTTP server receives a packet with:
   - IP destination: 10.0.0.2 (correct)
   - HTTP Host header: 10.0.0.10:8000 (mismatched!)
   
   If the HTTP server validates the Host header and expects it to match its own IP address, it may reject or drop the request, causing curl to hang.

## Solution

The fix ensures that backend HTTP servers accept requests with any Host header. Two approaches are provided:

### Option 1: Use the provided simple_http_server.py (Recommended)

A custom Python HTTP server (`simple_http_server.py`) that:
- Binds to `0.0.0.0` to accept connections from any interface
- Does not validate the Host header
- Logs the Host header for debugging purposes

Usage:
```bash
sudo ip netns exec h2 python3 simple_http_server.py &
sudo ip netns exec h3 python3 simple_http_server.py &
```

### Option 2: Use Python's built-in http.server with --bind 0.0.0.0

Python's built-in `http.server` with explicit binding to `0.0.0.0` also works:

```bash
sudo ip netns exec h2 python3 -m http.server --bind 0.0.0.0 &
sudo ip netns exec h3 python3 -m http.server --bind 0.0.0.0 &
```

## Files Modified/Created

1. **simple_http_server.py** - Custom HTTP server that accepts any Host header
2. **test_http_server.sh** - Automated test to verify the fix works
3. **README.md** - Updated with:
   - Correct server startup commands
   - Explanation of the Host header issue
   - Troubleshooting section for curl hanging
4. **README.zh.md** - Chinese version of the documentation updates

## Testing

Run the automated test to verify both server options work correctly:

```bash
cd /home/runner/work/bpf-developer-tutorial/bpf-developer-tutorial/src/42-xdp-loadbalancer
./test_http_server.sh
```

The test verifies that both server options correctly handle HTTP requests with mismatched Host headers.

## Technical Details

### Why XDP Can't Modify HTTP Headers

XDP programs operate at the earliest point in the network stack, directly in the NIC driver. While this provides extremely high performance, it also means:

- Limited packet inspection: XDP can access raw packet data but parsing complex protocols like HTTP is inefficient
- Packet size adjustments are constrained: While helpers like `bpf_xdp_adjust_head`/`bpf_xdp_adjust_tail` can change the accessible data region, safely modifying HTTP headers (often requiring length changes and revalidation) is complex and error-prone in high-performance XDP_TX paths
- Performance impact: Parsing and modifying HTTP headers would significantly slow down packet processing

For these reasons, the XDP load balancer operates at Layer 3/4 (IP/TCP) only, and the backend servers must be configured to handle the Host header mismatch.

### Why This Works

When the backend HTTP server is bound to `0.0.0.0`:
- It accepts connections on all network interfaces
- Python's http.server (both custom and built-in) processes requests based on the URL path, not the Host header
- The Host header is preserved in the request but doesn't affect request processing

This is a common pattern for servers behind load balancers and reverse proxies.

## References

- XDP Tutorial: https://github.com/xdp-project/xdp-tutorial
- XDP Packet Debugging: https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it/
- eBPF Developer Tutorial: https://github.com/eunomia-bpf/bpf-developer-tutorial
