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
# First, stop the BPF program gracefully (Ctrl-C if running in foreground)
# This ensures the BPF link is properly destroyed

# Then unload the kernel module
sudo rmmod hello

# If you get "Module hello is in use", there may still be a BPF struct_ops attached
# This can happen if the userspace process was killed (-9) instead of stopped gracefully
# Solutions:
#   1. Wait ~30 seconds for kernel to garbage collect the BPF link
#   2. Force unload: sudo rmmod -f hello (may be unstable)
#   3. Reboot the system

# Clean build artifacts
make clean
```

**Note on Module Unloading:**
The kernel module maintains a reference count while BPF struct_ops programs are attached. When you stop the userspace loader program gracefully (Ctrl-C), it calls `bpf_link__destroy()` which properly detaches the struct_ops and decrements the module reference count. If the process is killed abruptly (kill -9), the kernel should eventually garbage collect the BPF link, but this may take some time.

## How It Works

1. The kernel module registers a custom struct_ops type `bpf_testmod_ops`
2. It creates `/proc/bpf_testmod_trigger` - writing to this file triggers the callbacks
3. The BPF program implements the three callbacks: `test_1`, `test_2`, and `test_3`
4. The user-space program loads the BPF program and periodically writes to the proc file
5. Each write triggers all registered callbacks, demonstrating BPF struct_ops in action

## Troubleshooting

### Common Issues

- If you get "Failed to attach struct_ops", make sure the kernel module is loaded
- Check `dmesg` for any error messages from the kernel module or BPF verifier
- Ensure your kernel has CONFIG_BPF_SYSCALL=y and supports struct_ops

## Detailed Troubleshooting Guide

This section documents the complete process of resolving BTF and struct_ops issues encountered during development.

### Issue 1: Missing BTF in Kernel Module

**Problem:**
```
libbpf: failed to find BTF info for struct_ops/bpf_testmod_ops
```

**Root Cause:**
The kernel module was not compiled with BTF (BPF Type Format) information, which is required for struct_ops to work. BTF provides type information that BPF programs need to interact with kernel structures.

**Solution:**

#### Step 1: Extract vmlinux with BTF
The kernel build system needs the `vmlinux` ELF binary (not just headers) to generate BTF for modules.

```bash
# Extract vmlinux from compressed kernel image
sudo /usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux \
    /boot/vmlinuz-$(uname -r) > /tmp/vmlinux

# Copy to kernel build directory
sudo cp /tmp/vmlinux /usr/src/linux-headers-$(uname -r)/vmlinux

# Verify it's an ELF binary
file /tmp/vmlinux
# Output: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked
```

#### Step 2: Upgrade pahole (if needed)
The BTF generation requires `pahole` (from dwarves package) version 1.16+. Older versions don't support the `--btf_features` flag.

Check your version:
```bash
pahole --version
```

If version is < 1.25, compile from source:

```bash
# Install dependencies
sudo apt-get install -y libelf-dev cmake zlib1g-dev

# Downgrade elfutils packages to matching versions
sudo apt-get install -y --allow-downgrades \
    libelf1t64=0.190-1.1ubuntu0.1 \
    libdw1t64=0.190-1.1ubuntu0.1 \
    libdw-dev=0.190-1.1ubuntu0.1 \
    libelf-dev=0.190-1.1ubuntu0.1

# Clone and build pahole
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git /tmp/pahole
cd /tmp/pahole
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install

# Verify new version
pahole --version  # Should show v1.30 or higher
```

#### Step 3: Rebuild the module with BTF
The module Makefile already has BTF enabled with `-g -O2` flags. Simply rebuild:

```bash
cd module
make clean
make
```

Verify BTF was generated:
```bash
readelf -S hello.ko | grep BTF
# Should show:
#   [60] .BTF              PROGBITS         ...
#   [61] .BTF.base         PROGBITS         ...
```

### Issue 2: Kernel Panic on Module Load

**Problem:**
Loading the module causes a kernel panic or NULL pointer dereference.

**Root Cause:**
The `bpf_struct_ops` structure was missing required callback functions that the kernel tries to access during registration:
- `.verifier_ops` - BPF verifier operations (NULL pointer dereference)
- `.init` - BTF initialization callback
- `.init_member` - Member initialization callback

**Error Pattern in dmesg:**
```
BUG: kernel NULL pointer dereference
Call Trace:
  register_bpf_struct_ops
  ...
```

**Solution:**
Add the required callbacks to the module (`module/hello.c`):

```c
/* BTF initialization callback */
static int bpf_testmod_ops_init(struct btf *btf)
{
    /* Initialize BTF if needed */
    return 0;
}

/* Verifier access control */
static bool bpf_testmod_ops_is_valid_access(int off, int size,
                                            enum bpf_access_type type,
                                            const struct bpf_prog *prog,
                                            struct bpf_insn_access_aux *info)
{
    /* Allow all accesses for this example */
    return true;
}

/* Verifier operations structure */
static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
    .is_valid_access = bpf_testmod_ops_is_valid_access,
};

/* Member initialization callback */
static int bpf_testmod_ops_init_member(const struct btf_type *t,
                                       const struct btf_member *member,
                                       void *kdata, const void *udata)
{
    /* No special member initialization needed */
    return 0;
}

/* Updated struct_ops definition with ALL required callbacks */
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
    .verifier_ops = &bpf_testmod_verifier_ops,  // REQUIRED
    .init = bpf_testmod_ops_init,              // REQUIRED
    .init_member = bpf_testmod_ops_init_member, // REQUIRED
    .reg = bpf_testmod_ops_reg,
    .unreg = bpf_testmod_ops_unreg,
    .cfi_stubs = &__bpf_ops_bpf_testmod_ops,
    .name = "bpf_testmod_ops",
    .owner = THIS_MODULE,
};
```

**Why This Matters:**
The kernel's `register_bpf_struct_ops()` function expects these callbacks to be present. When it tries to call them and finds NULL pointers, it causes a kernel panic. These callbacks are essential for:
- **verifier_ops**: Validates BPF program access to struct_ops members
- **init**: Initializes BTF type information for the struct_ops
- **init_member**: Handles special initialization for data members

After adding these callbacks, rebuild and reload:
```bash
cd module
make clean
make
sudo insmod hello.ko
dmesg | tail
# Should see: "bpf_testmod loaded with struct_ops support"
```

### Issue 3: BPF Program Load Failure - Invalid Helper

**Problem:**
```
libbpf: prog 'bpf_testmod_test_1': BPF program load failed: Invalid argument
program of this type cannot use helper bpf_trace_printk#6
```

**Root Cause:**
struct_ops BPF programs have restricted helper function access. `bpf_trace_printk` (bpf_printk) is not allowed in struct_ops context because these programs run in a different context than tracing programs.

**Solution:**
Remove all `bpf_printk()` calls from struct_ops BPF programs:

```c
// BEFORE (fails to load):
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
    bpf_printk("BPF test_1 called!\n");  // NOT ALLOWED
    return 42;
}

// AFTER (works):
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
    /* Return a special value to indicate BPF implementation */
    return 42;
}
```

**Alternative Debugging Approaches:**
1. Use BPF maps to export counters/statistics to userspace
2. Use the kernel module's `printk()` to log struct_ops invocations
3. Use `bpftool prog tracelog` to see what programs are being called

### Verification Checklist

After resolving all issues, verify everything works:

```bash
# 1. Check module BTF
readelf -S module/hello.ko | grep BTF

# 2. Load module successfully
sudo insmod module/hello.ko
dmesg | tail -5
# Should see: "bpf_testmod loaded with struct_ops support"

# 3. Verify proc file created
ls -l /proc/bpf_testmod_trigger
# Should exist with write permissions

# 4. Build and load BPF program
make
sudo ./struct_ops
# Should see: "Successfully loaded and attached BPF struct_ops!"

# 5. Verify callbacks are being invoked
sudo dmesg | tail -20
# Should see periodic output:
#   Calling struct_ops callbacks:
#   test_1() returned: 42
#   test_2(10, 20) returned: 30
#   test_3() called with buffer

# 6. Clean up
sudo rmmod hello
```

### Key Takeaways

1. **BTF is mandatory** for struct_ops - ensure `vmlinux` is available and `pahole` is recent enough
2. **All required callbacks must be present** in the `bpf_struct_ops` structure (verifier_ops, init, init_member)
3. **Helper restrictions apply** - struct_ops programs cannot use tracing helpers like `bpf_printk`
4. **Test incrementally** - load module first, then BPF program, to isolate issues

## Kernel Source Code Analysis

### Root Cause of Kernel Panic (Confirmed from Kernel 6.18-rc4 Source)

The kernel panic was caused by **missing NULL pointer checks** in the kernel's struct_ops registration code. Analysis of the Linux kernel source code (version 6.18-rc4) reveals three critical locations where callback pointers are dereferenced without validation:

#### 1. Missing NULL check for `st_ops->init` callback
**Location**: `kernel/bpf/bpf_struct_ops.c:381`

```c
if (st_ops->init(btf)) {          // ← NULL pointer dereference if init is NULL
    pr_warn("Error in init bpf_struct_ops %s\n",
        st_ops->name);
    err = -EINVAL;
    goto errout;
}
```

The code calls `st_ops->init(btf)` directly in the `bpf_struct_ops_desc_init()` function without checking if the callback exists. If a module registers struct_ops with `init = NULL`, this causes an immediate kernel panic.

#### 2. Missing NULL check for `st_ops->init_member` callback
**Location**: `kernel/bpf/bpf_struct_ops.c:753`

```c
err = st_ops->init_member(t, member, kdata, udata);  // ← NULL pointer dereference
if (err < 0)
    goto reset_unlock;

/* The ->init_member() has handled this member */
if (err > 0)
    continue;
```

During map update operations, the kernel calls `st_ops->init_member()` for each struct member without verifying the callback pointer is non-NULL.

#### 3. Missing NULL check for `st_ops->verifier_ops`
**Location**: `kernel/bpf/verifier.c:23486`

```c
env->ops = st_ops->verifier_ops;  // ← Assigns potentially NULL pointer
```

The BPF verifier assigns `verifier_ops` directly and later dereferences it through `env->ops->*` calls. If `verifier_ops` is NULL, subsequent verifier operations will cause a kernel panic.

### Why These Callbacks Are Mandatory

The kernel code **assumes** these callbacks exist and does not provide fallback behavior:

1. **`init`**: Called during struct_ops registration to initialize BTF type information. No default implementation exists.
2. **`init_member`**: Called for each struct member during map updates to handle special initialization. Return value of 0 means "not handled", >0 means "handled", <0 is error.
3. **`verifier_ops`**: Provides verification operations (e.g., `is_valid_access`) that control BPF program access to struct_ops context.

### Is This Fixed in Current Kernel?

**No.** As of Linux kernel 6.18-rc4 (checked 2025-11-10), these NULL pointer dereferences still exist. The kernel code has not added defensive NULL checks for these callbacks.

This means:
- ✅ **Our fix is correct** - providing all three callbacks prevents the kernel panic
- ❌ **Kernel could be more defensive** - ideally it should validate callbacks before dereferencing
- ⚠️ **All struct_ops modules MUST provide these callbacks** - this is an undocumented requirement

### Recommendation for Kernel Upstream

The kernel should add validation before dereferencing these pointers:

```c
// Suggested fix for kernel/bpf/bpf_struct_ops.c:381
if (st_ops->init && st_ops->init(btf)) {
    pr_warn("Error in init bpf_struct_ops %s\n", st_ops->name);
    err = -EINVAL;
    goto errout;
}

// Suggested fix for kernel/bpf/bpf_struct_ops.c:753
if (st_ops->init_member) {
    err = st_ops->init_member(t, member, kdata, udata);
    if (err < 0)
        goto reset_unlock;
    if (err > 0)
        continue;
}

// Suggested fix for registration
if (!st_ops->verifier_ops) {
    pr_warn("struct_ops %s missing verifier_ops\n", st_ops->name);
    return -EINVAL;
}
```

However, until such changes are merged, **all struct_ops implementations must provide these callbacks** to avoid kernel panics.

---

## Additional Resources

- **Kernel Test Module**: `/home/yunwei37/linux/tools/testing/selftests/bpf/test_kmods/bpf_testmod.c` - Official kernel reference implementation
- **BPF Documentation**: https://www.kernel.org/doc/html/latest/bpf/

## Contributing

If you encounter similar issues or have improvements, please document them and contribute back to the tutorial.
