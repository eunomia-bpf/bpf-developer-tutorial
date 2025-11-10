# BPF struct_ops Example with Custom Kernel Module

This example demonstrates BPF struct_ops functionality using a custom kernel module that defines struct_ops operations triggered via a proc file write.

## Overview

struct_ops allows BPF programs to implement kernel subsystem operations dynamically. This example includes:

1. **Kernel Module** (`module/hello.c`) - Defines `bpf_testmod_ops` struct_ops with three callbacks
2. **BPF Program** (`struct_ops.bpf.c`) - Implements the struct_ops callbacks in BPF
3. **User-space Loader** (`struct_ops.c`) - Loads the BPF program and triggers callbacks via `/proc/bpf_testmod_trigger`

## Building and Running

### 1. Build the kernel module:
```bash
cd module
make
cd ..
```

### 2. Load the kernel module:
```bash
sudo insmod module/hello.ko
```

### 3. Build the BPF program:
```bash
make
```

### 4. Run the example:
```bash
sudo ./struct_ops
```

### 5. Check kernel logs:
```bash
sudo dmesg -w
```

You should see output like:
```
bpf_testmod loaded with struct_ops support
bpf_testmod_ops registered
Calling struct_ops callbacks:
BPF test_1 called!
test_1() returned: 42
BPF test_2 called: 10 + 20 = 30
test_2(10, 20) returned: 30
BPF test_3 called with buffer length 21
First char: H
test_3() called with buffer
```

### 6. Clean up:
```bash
sudo rmmod hello
make clean
```

## How It Works

1. The kernel module registers a custom struct_ops type `bpf_testmod_ops`
2. It creates `/proc/bpf_testmod_trigger` - writing to this file triggers the callbacks
3. The BPF program implements the three callbacks: `test_1`, `test_2`, and `test_3`
4. The user-space program loads the BPF program and periodically writes to the proc file
5. Each write triggers all registered callbacks, demonstrating BPF struct_ops in action

## Troubleshooting

- If you get "Failed to attach struct_ops", make sure the kernel module is loaded
- Check `dmesg` for any error messages from the kernel module or BPF verifier
- Ensure your kernel has CONFIG_BPF_SYSCALL=y and supports struct_ops