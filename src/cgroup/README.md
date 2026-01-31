# eBPF Tutorial: cgroup-based Policy Control

This tutorial demonstrates how to use cgroup eBPF programs to implement per-cgroup policy controls for networking, device access, and sysctl operations.

## What is cgroup eBPF?

**cgroup eBPF** allows you to attach eBPF programs to cgroups (control groups) to enforce policies based on process/container membership. Unlike XDP/tc which work on network interfaces, cgroup eBPF works at the process level:

- Policies only affect processes in the target cgroup
- Perfect for container/multi-tenant/sandbox isolation
- Covers: network access control, socket options, sysctl access, device access

When a cgroup eBPF program denies an operation, userspace typically sees `EPERM` (Operation not permitted).

## cgroup eBPF Hook Points

### 1. `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` - Socket Address Hooks

Triggered on socket address syscalls (bind/connect/sendmsg/recvmsg):

| Hook | Section Name | Description |
|------|--------------|-------------|
| IPv4 bind | `cgroup/bind4` | Filter bind() calls |
| IPv6 bind | `cgroup/bind6` | Filter bind() calls |
| IPv4 connect | `cgroup/connect4` | Filter connect() calls |
| IPv6 connect | `cgroup/connect6` | Filter connect() calls |
| UDP sendmsg | `cgroup/sendmsg4`, `cgroup/sendmsg6` | Filter UDP sends |
| UDP recvmsg | `cgroup/recvmsg4`, `cgroup/recvmsg6` | Filter UDP receives |
| Unix connect | `cgroup/connect_unix` | Filter Unix socket connect |

**Context**: `struct bpf_sock_addr` - contains `user_ip4`, `user_port` (network byte order)

**Return semantics**: `return 1` = allow, `return 0` = deny (EPERM)

### 2. `BPF_PROG_TYPE_CGROUP_DEVICE` - Device Access Control

| Hook | Section Name | Description |
|------|--------------|-------------|
| Device access | `cgroup/dev` | Filter device open/read/write/mknod |

**Context**: `struct bpf_cgroup_dev_ctx` - contains `major`, `minor`, `access_type`

**Return semantics**: `return 0` = deny (EPERM), non-zero = allow

### 3. `BPF_PROG_TYPE_CGROUP_SYSCTL` - Sysctl Access Control

| Hook | Section Name | Description |
|------|--------------|-------------|
| Sysctl access | `cgroup/sysctl` | Filter /proc/sys reads/writes |

**Context**: `struct bpf_sysctl` - use `bpf_sysctl_get_name()` to get sysctl name

**Return semantics**: `return 0` = reject (EPERM), `return 1` = proceed

### 4. Other cgroup Hooks

- `cgroup_skb/ingress`, `cgroup_skb/egress` - Packet-level filtering
- `cgroup/getsockopt`, `cgroup/setsockopt` - Socket option filtering
- `cgroup/sock_create`, `cgroup/sock_release` - Socket lifecycle
- `sockops` - TCP-level optimization (attached via `BPF_CGROUP_SOCK_OPS`)

## This Tutorial: cgroup Policy Guard

We implement a single eBPF object with three programs:

1. **Network (TCP)**: Block `connect()` to a specified destination port
2. **Device**: Block access to a specified `major:minor` device
3. **Sysctl**: Block reading a specified sysctl (read-only, safer for testing)

Events are sent to userspace via ringbuf for observability.

## Building

```bash
cd src/49-cgroup
make
```

## Running

### Terminal A: Start the loader

```bash
# Block: TCP port 9090, /dev/null (1:3), reading kernel/hostname
sudo ./cgroup_guard \
  --cgroup /sys/fs/cgroup/ebpf_demo \
  --block-port 9090 \
  --deny-device 1:3 \
  --deny-sysctl kernel/hostname
```

You should see:
```
Attached to cgroup: /sys/fs/cgroup/ebpf_demo
Config: block_port=9090, deny_device=1:3, deny_sysctl_read=kernel/hostname
Press Ctrl-C to stop.
```

### Terminal B: Start test servers (outside cgroup)

```bash
# Start two HTTP servers
python3 -m http.server 8080 --bind 127.0.0.1 &
python3 -m http.server 9090 --bind 127.0.0.1 &
```

### Terminal C: Test from within the cgroup

```bash
sudo bash -c '
echo $$ > /sys/fs/cgroup/ebpf_demo/cgroup.procs

echo "== TCP test =="
curl -s http://127.0.0.1:8080 >/dev/null && echo "8080 OK"
curl -s http://127.0.0.1:9090 >/dev/null && echo "9090 OK (unexpected)" || echo "9090 BLOCKED (expected)"

echo
echo "== Device test =="
cat /dev/null && echo "/dev/null OK (unexpected)" || echo "/dev/null BLOCKED (expected)"

echo
echo "== Sysctl test =="
cat /proc/sys/kernel/hostname && echo "sysctl read OK (unexpected)" || echo "sysctl read BLOCKED (expected)"
'
```

Expected output:
- `8080 OK` - Port 8080 is allowed
- `9090 BLOCKED (expected)` - Port 9090 is blocked
- `/dev/null BLOCKED (expected)` - Device 1:3 is blocked
- `sysctl read BLOCKED (expected)` - Reading kernel/hostname is blocked

### Terminal A output (events)

```
[DENY connect4] pid=12345 comm=curl daddr=127.0.0.1 dport=9090 proto=6
[DENY device]   pid=12346 comm=cat major=1 minor=3 access_type=0x...
[DENY sysctl]   pid=12347 comm=cat write=0 name=kernel/hostname
```

## Verifying with bpftool

```bash
sudo bpftool cgroup tree /sys/fs/cgroup/ebpf_demo
```

## Key Implementation Details

### 1. Network byte order for sock_addr

```c
// user_port is network byte order, must convert
__u16 dport = bpf_ntohs((__u16)ctx->user_port);
```

### 2. Return value semantics

```c
// For sock_addr (connect4/bind4/etc):
return 1;  // allow
return 0;  // deny -> EPERM

// For device:
return 0;  // deny -> EPERM
return 1;  // allow

// For sysctl:
return 0;  // reject -> EPERM
return 1;  // proceed
```

### 3. Configuration via .rodata

```c
// BPF side - const volatile for CO-RE
const volatile __u16 blocked_tcp_dport = 0;

// Userspace - set before load
skel->rodata->blocked_tcp_dport = (__u16)port;
```

## Files

- `cgroup_guard.h` - Shared data structures
- `cgroup_guard.bpf.c` - eBPF programs (connect4, device, sysctl hooks)
- `cgroup_guard.c` - Userspace loader
- `Makefile` - Build system

## References

- [Kernel docs: libbpf program types](https://docs.kernel.org/bpf/libbpf/program_types.html)
- [eBPF docs: CGROUP_SOCK_ADDR](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/)
- [eBPF docs: CGROUP_DEVICE](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_DEVICE/)
