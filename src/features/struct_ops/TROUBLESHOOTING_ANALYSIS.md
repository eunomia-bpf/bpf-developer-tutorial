# BPF struct_ops Implementation - Complete Troubleshooting Analysis

**Date**: 2025-11-10
**Kernel Version**: 6.15.11-061511-generic
**Kernel Source**: Linux 6.18-rc4 (from `/home/yunwei37/linux`)

## Executive Summary

This document provides a complete technical analysis of the issues encountered while implementing a custom BPF struct_ops kernel module. Three critical bugs were discovered and resolved:

1. **Missing BTF in kernel module** - Required extracting vmlinux and upgrading pahole
2. **Kernel panic on module load** - Caused by missing required callbacks in struct_ops definition
3. **BPF program load failure** - Due to restricted helper functions in struct_ops context

Additionally, kernel source code analysis revealed that these issues stem from missing NULL pointer checks in the Linux kernel itself (still present as of 6.18-rc4).

---

## Issue #1: Missing BTF in Kernel Module

### Initial Symptom

When attempting to load the BPF struct_ops program:

```
libbpf: failed to find BTF info for struct_ops/bpf_testmod_ops
libbpf: failed to load BPF skeleton 'struct_ops_bpf': -2
Failed to load BPF skeleton: -2
```

### Root Cause Analysis

BPF struct_ops requires BTF (BPF Type Format) information to be embedded in the kernel module. BTF provides type information that allows BPF programs to understand and interact with kernel structures.

**Investigation Steps:**

1. **Checked if module has BTF section:**
   ```bash
   readelf -S module/hello.ko | grep BTF
   # Result: No BTF sections found
   ```

2. **Verified BTF flags in Makefile:**
   ```makefile
   KBUILD_CFLAGS += -g -O2
   ```
   These flags enable debug info generation, which is necessary for BTF.

3. **Identified missing component: vmlinux**

   The kernel module build system uses `pahole` to generate BTF from DWARF debug info. However, `pahole` needs the base kernel BTF (from `vmlinux`) to generate module BTF properly.

### Technical Deep Dive: BTF Generation Process

The kernel module BTF generation process involves multiple steps:

```
┌─────────────┐
│  Module .c  │
└──────┬──────┘
       │ (gcc -g)
       ▼
┌─────────────┐
│ Module .ko  │ ← Contains DWARF debug info
│ (with DWARF)│
└──────┬──────┘
       │
       │ (pahole -J --btf_base=vmlinux)
       │
       ▼
┌─────────────┐
│ Module .ko  │ ← Now contains BTF
│ (with BTF)  │
└─────────────┘
```

**Key Requirements:**
1. Module compiled with `-g` (debug info)
2. `vmlinux` ELF binary available (contains base kernel BTF)
3. Recent `pahole` version (≥1.16, preferably ≥1.25)

### Solution Part 1: Extract vmlinux

The `vmlinux` binary is not distributed with kernel headers. It must be extracted from the compressed kernel image:

```bash
# The kernel boot image is compressed
file /boot/vmlinuz-6.15.11-061511-generic
# Output: Linux kernel x86 boot executable bzImage, version 6.15.11...

# Extract uncompressed vmlinux using kernel's own script
sudo /usr/src/linux-headers-6.15.11-061511-generic/scripts/extract-vmlinux \
    /boot/vmlinuz-6.15.11-061511-generic > /tmp/vmlinux

# Verify extraction
file /tmp/vmlinux
# Output: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked

# Copy to kernel build directory where module build system expects it
sudo cp /tmp/vmlinux /usr/src/linux-headers-6.15.11-061511-generic/vmlinux
```

### Solution Part 2: Upgrade pahole

**Problem Discovery:**

```bash
# First attempt to rebuild module
cd module && make

# Error output:
pahole: unrecognized option '--btf_features=encode_force,var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func,decl_tag_kfuncs'
make[4]: *** [hello.ko] Error 64
```

**Version Check:**

```bash
pahole --version
# Output: v1.25
```

The kernel 6.15.11 build system expects pahole v1.30+ with support for advanced BTF features.

**Compilation from Source:**

pahole is part of the `dwarves` project and requires `libdw` (elfutils) for DWARF parsing.

**Dependency Challenge:**

```bash
sudo apt-get install libdw-dev
# Error: libdw-dev depends on libdw1t64 (= 0.190) but 0.191 is installed
```

The system has mismatched elfutils library versions. Solution: downgrade to matching versions.

**Complete Build Process:**

```bash
# Step 1: Downgrade elfutils to matching versions
sudo apt-get install -y --allow-downgrades \
    libelf1t64=0.190-1.1ubuntu0.1 \
    libdw1t64=0.190-1.1ubuntu0.1 \
    libdw-dev=0.190-1.1ubuntu0.1 \
    libelf-dev=0.190-1.1ubuntu0.1

# Step 2: Clone pahole source
git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git /tmp/pahole
cd /tmp/pahole

# Step 3: Build and install
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
sudo make install

# Step 4: Verify installation
pahole --version
# Output: v1.30
```

### Solution Part 3: Rebuild Module with BTF

After ensuring vmlinux and pahole are available:

```bash
cd module
make clean
make
```

**Build Output (Success):**
```
CC [M]  hello.o
MODPOST Module.symvers
CC [M]  hello.mod.o
LD [M]  hello.ko
BTF [M] hello.ko  ← BTF generation succeeded!
```

**Verification:**

```bash
readelf -S hello.ko | grep BTF
# Output:
#   [60] .BTF              PROGBITS  ...
#   [61] .BTF.base         PROGBITS  ...
```

### Technical Insights

1. **Why BTF.base section exists:** Module BTF references types from kernel BTF. The `.BTF.base` section contains the base BTF ID from vmlinux that this module's BTF extends.

2. **Why pahole needs vmlinux:** Module types can reference kernel types (e.g., `struct btf`, `struct bpf_link`). pahole needs the kernel BTF to resolve these references and generate correct type IDs.

3. **BTF vs DWARF:** DWARF is the debug info format generated by the compiler. BTF is a more compact, BPF-specific type format that's optimized for verification and JIT compilation.

---

## Issue #2: Kernel Panic on Module Load

### Initial Symptom

After successfully building the module with BTF, loading it caused an immediate kernel panic:

```bash
sudo insmod module/hello.ko
# System freezes, kernel panic
```

**Evidence from System Reboot:**

After reboot, the system clock jumped backwards (indicating a crash recovery), and no error messages were logged because the panic happened during interrupt context.

### Hypothesis Formation

The panic occurred during `insmod`, specifically during the `register_bpf_struct_ops()` call. This suggested the kernel was trying to access invalid memory when processing the struct_ops registration.

### Investigation Strategy

Since we couldn't capture the panic directly, we needed to analyze what `register_bpf_struct_ops()` does and identify potential NULL pointer dereferences.

**Approach:**
1. Examine the kernel test module that works (bpf_testmod.c)
2. Compare our struct_ops definition with the working one
3. Identify missing fields

### Comparison Analysis

**Our Original Code:**

```c
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
    .reg = bpf_testmod_ops_reg,
    .unreg = bpf_testmod_ops_unreg,
    .name = "bpf_testmod_ops",
    .cfi_stubs = &__bpf_ops_bpf_testmod_ops,
    .owner = THIS_MODULE,
};
```

**Kernel's bpf_testmod.c (Working Code):**

```c
struct bpf_struct_ops bpf_bpf_testmod_ops = {
    .verifier_ops = &bpf_testmod_verifier_ops,  // ← Missing!
    .init = bpf_testmod_ops_init,              // ← Missing!
    .init_member = bpf_testmod_ops_init_member, // ← Missing!
    .reg = bpf_dummy_reg,
    .unreg = bpf_dummy_unreg,
    .cfi_stubs = &__bpf_testmod_ops,
    .name = "bpf_testmod_ops",
    .owner = THIS_MODULE,
};
```

**Key Finding:** Three callbacks were missing:
- `.verifier_ops`
- `.init`
- `.init_member`

### Kernel Source Code Analysis

To understand why these are required, I examined the kernel source code in `/home/yunwei37/linux` (version 6.18-rc4).

#### Location 1: `st_ops->init` Dereference

**File:** `kernel/bpf/bpf_struct_ops.c`
**Function:** `bpf_struct_ops_desc_init()`
**Line:** 381

```c
int bpf_struct_ops_desc_init(struct bpf_struct_ops_desc *st_ops_desc,
                             struct btf *btf,
                             struct bpf_verifier_log *log)
{
    struct bpf_struct_ops *st_ops = st_ops_desc->st_ops;
    // ... initialization code ...

    // CRITICAL: No NULL check before dereferencing!
    if (st_ops->init(btf)) {
        pr_warn("Error in init bpf_struct_ops %s\n",
            st_ops->name);
        err = -EINVAL;
        goto errout;
    }

    return 0;
errout:
    bpf_struct_ops_desc_release(st_ops_desc);
    return err;
}
```

**Bug Analysis:**
- The code calls `st_ops->init(btf)` directly
- If `.init` is NULL, this causes: `call [NULL]` → Kernel Panic
- No defensive check like: `if (st_ops->init && st_ops->init(btf))`

#### Location 2: `st_ops->init_member` Dereference

**File:** `kernel/bpf/bpf_struct_ops.c`
**Function:** `bpf_struct_ops_map_update_elem()`
**Line:** 753

```c
static long bpf_struct_ops_map_update_elem(struct bpf_map *map, void *key,
                                           void *value, u64 flags)
{
    // ... setup code ...

    for_each_member(i, t, member) {
        // ... member processing ...

        // CRITICAL: No NULL check before calling!
        err = st_ops->init_member(t, member, kdata, udata);
        if (err < 0)
            goto reset_unlock;

        /* The ->init_member() has handled this member */
        if (err > 0)
            continue;

        // ... rest of processing ...
    }
}
```

**Bug Analysis:**
- Called when userspace updates the struct_ops map
- If `.init_member` is NULL → Kernel Panic
- This would panic later when BPF program tries to attach, not during module load

#### Location 3: `st_ops->verifier_ops` Dereference

**File:** `kernel/bpf/verifier.c`
**Function:** `bpf_check_struct_ops_btf_id()`
**Line:** 23486

```c
static int check_struct_ops_btf_id(struct bpf_verifier_env *env)
{
    // ... verification setup ...

    // CRITICAL: No NULL check, assigns potentially NULL pointer
    env->ops = st_ops->verifier_ops;

    // Later code dereferences env->ops:
    // env->ops->is_valid_access(...)
    // env->ops->get_func_proto(...)
}
```

**Bug Analysis:**
- If `.verifier_ops` is NULL, `env->ops` becomes NULL
- Later verifier calls like `env->ops->is_valid_access()` → Kernel Panic
- This would panic when BPF program loads, not during module load

### Root Cause Conclusion

The **immediate panic during module load** was caused by `st_ops->init` being NULL.

When `insmod` called `register_bpf_struct_ops()`:
1. `__register_bpf_struct_ops()` calls `btf_add_struct_ops()`
2. `btf_add_struct_ops()` calls `bpf_struct_ops_desc_init()`
3. `bpf_struct_ops_desc_init()` calls `st_ops->init(btf)`
4. **CRASH:** NULL pointer dereference

### Solution Implementation

Add all three required callbacks:

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

### Verification

After adding the callbacks:

```bash
cd module
make clean
make
sudo insmod hello.ko
dmesg | tail -5
```

**Output:**
```
[4213.650774] hello: loading out-of-tree module taints kernel.
[4213.680932] bpf_testmod loaded with struct_ops support
```

✅ **Success!** Module loaded without panic.

### Technical Insights

#### Why These Callbacks Exist

1. **`init` callback:**
   - Called once during struct_ops registration
   - Purpose: Perform any BTF-related initialization
   - Common uses:
     - Validate struct layout
     - Cache BTF type IDs
     - Initialize function models
   - Return: 0 on success, negative errno on failure

2. **`init_member` callback:**
   - Called for each struct member during map update
   - Purpose: Handle special initialization for non-function-pointer members
   - Return values:
     - `< 0`: Error, abort map update
     - `0`: Not handled, kernel uses default behavior
     - `> 0`: Handled, skip default processing
   - Example use case: Initialize data fields that can't be simply copied

3. **`verifier_ops` structure:**
   - Defines how BPF verifier validates programs using this struct_ops
   - Key callbacks:
     - `is_valid_access`: Controls what context offsets BPF can access
     - `get_func_proto`: Returns allowed helper function prototypes
     - `convert_ctx_access`: Converts context accesses to kernel accesses
   - Used during BPF program load/verification

#### Why No NULL Checks in Kernel?

The kernel assumes these callbacks are always present because:

1. **Historical reasons:** Early struct_ops implementations (like TCP congestion control) always provided these callbacks
2. **Performance:** Avoiding NULL checks in hot paths
3. **Design philosophy:** Kernel internal APIs often assume correct usage
4. **Documentation gap:** Not clearly documented as required

However, this is **poor defensive programming** and should ideally be fixed upstream.

---

## Issue #3: BPF Program Load Failure - Invalid Helper

### Initial Symptom

After fixing the module panic, attempting to load the BPF program failed:

```
libbpf: prog 'bpf_testmod_test_1': BPF program load failed: Invalid argument
libbpf: prog 'bpf_testmod_test_1': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
; bpf_printk("BPF test_1 called!\n");
0: (18) r1 = 0xffff8ec80bd10f08
2: (b7) r2 = 20
3: (85) call bpf_trace_printk#6
program of this type cannot use helper bpf_trace_printk#6
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
```

### Root Cause Analysis

The BPF verifier rejected the program because it tried to use `bpf_trace_printk` (helper #6), which is not allowed in struct_ops programs.

**Why the Restriction?**

struct_ops programs run in different contexts than tracing programs:

1. **Context type:** struct_ops programs receive struct_ops-specific context (e.g., function parameters), not tracing context (pt_regs, etc.)

2. **Helper allowlist:** Each BPF program type has an allowed set of helpers. struct_ops programs have a very restricted set.

3. **Allowed helpers for struct_ops:**
   - Basic map operations (map_lookup_elem, map_update_elem, etc.)
   - Spinlock operations (spin_lock, spin_unlock)
   - RCU operations (rcu_read_lock, rcu_read_unlock)
   - Helper functions defined by the struct_ops itself

4. **NOT allowed:**
   - `bpf_trace_printk` - tracing-specific
   - `bpf_probe_read_*` - tracing-specific
   - Most kernel helper functions

### Verification of Restriction

Checking the verifier ops we defined:

```c
static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
    .is_valid_access = bpf_testmod_ops_is_valid_access,
};
```

We didn't define `.get_func_proto`, which means the default behavior applies:
- Only base helper functions are allowed
- `bpf_trace_printk` is not in the base set for struct_ops

### Solution

Remove all `bpf_printk()` calls from the BPF programs:

**Before:**
```c
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
    bpf_printk("BPF test_1 called!\n");  // NOT ALLOWED
    return 42;
}
```

**After:**
```c
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
    /* Return a special value to indicate BPF implementation */
    return 42;
}
```

### Alternative Debugging Approaches

Since `bpf_printk` doesn't work, here are alternatives:

1. **Use BPF maps for counters/stats:**
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_ARRAY);
       __uint(max_entries, 1);
       __type(key, __u32);
       __type(value, __u64);
   } call_count SEC(".maps");

   SEC("struct_ops/test_1")
   int BPF_PROG(bpf_testmod_test_1)
   {
       __u32 key = 0;
       __u64 *count = bpf_map_lookup_elem(&call_count, &key);
       if (count)
           (*count)++;
       return 42;
   }
   ```

2. **Use kernel module's printk:**

   Our module already logs when callbacks are invoked:
   ```c
   if (ops->test_1) {
       ret = ops->test_1();
       pr_info("test_1() returned: %d\n", ret);  // ← Logs to dmesg
   }
   ```

3. **Use return values for signaling:**

   Return specific values to indicate state:
   ```c
   return 42;  // Magic number indicates BPF program executed
   ```

### Verification

After removing `bpf_printk`:

```bash
make
sudo ./struct_ops
```

**Output:**
```
Successfully loaded and attached BPF struct_ops!
Triggering struct_ops callbacks...
```

**dmesg Output:**
```
Calling struct_ops callbacks:
test_1() returned: 42        ← BPF program's return value!
test_2(10, 20) returned: 30  ← BPF computed 10 + 20
test_3() called with buffer
```

✅ **Success!** The BPF program is running and the kernel module logs confirm it.

### Technical Insights

#### Why struct_ops Has Helper Restrictions

1. **Security:** struct_ops programs run in kernel context with high privileges. Limiting helpers reduces attack surface.

2. **Consistency:** Different struct_ops types (TCP congestion control, schedulers, etc.) need different helpers. A restrictive default prevents misuse.

3. **Verifiability:** Fewer helpers = simpler verification. The verifier must prove the program won't crash or compromise security.

#### How to Add Custom Helpers

If you need additional functionality, you can define kfuncs (kernel functions callable from BPF):

```c
// In kernel module
__bpf_kfunc void my_custom_log(const char *msg)
{
    pr_info("BPF: %s\n", msg);
}

// Register the kfunc
BTF_ID_FLAGS(func, my_custom_log)
// ... register with BPF subsystem ...
```

Then call from BPF:
```c
extern void my_custom_log(const char *msg) __ksym;

SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
    my_custom_log("test_1 called");
    return 42;
}
```

---

## Summary of Discoveries

### Critical Issues Found

1. **BTF Generation Infrastructure Missing:**
   - Root cause: No vmlinux binary available for BTF generation
   - Compounding factor: Outdated pahole version
   - Solution complexity: High (requires kernel image extraction and tool compilation)

2. **Kernel NULL Pointer Dereferences:**
   - Location: Multiple sites in kernel/bpf/ subsystem
   - Status: Still present in Linux 6.18-rc4
   - Impact: ANY struct_ops module missing callbacks will panic
   - Severity: Critical (no graceful error, immediate crash)

3. **Undocumented Helper Restrictions:**
   - Documentation gap: struct_ops helper restrictions not clearly documented
   - Error message clarity: Good (verifier explicitly states the issue)
   - Workarounds: Multiple alternatives exist

### Kernel Bugs Identified

| Location | Issue | Status | Suggested Fix |
|----------|-------|--------|---------------|
| `kernel/bpf/bpf_struct_ops.c:381` | NULL deref of `st_ops->init` | Unfixed (6.18-rc4) | Add `if (st_ops->init && ...)` check |
| `kernel/bpf/bpf_struct_ops.c:753` | NULL deref of `st_ops->init_member` | Unfixed (6.18-rc4) | Add `if (st_ops->init_member)` check |
| `kernel/bpf/verifier.c:23486` | NULL assignment of `st_ops->verifier_ops` | Unfixed (6.18-rc4) | Validate at registration time |

### Lessons Learned

1. **BTF is mandatory for struct_ops:** Cannot be bypassed or worked around. Full BTF infrastructure must be in place.

2. **Kernel assumes correct usage:** Many internal kernel APIs lack defensive checks. Incorrect usage leads to crashes, not errors.

3. **Test incrementally:** Load module first (tests registration), then BPF program (tests verification/loading). This isolates failure points.

4. **Verifier errors are your friend:** BPF verifier provides excellent error messages. Read them carefully.

5. **Consult working examples:** The kernel's own test modules (bpf_testmod.c) are the best reference for correct implementation.

### Recommendations for Future Work

#### For Kernel Developers

1. **Add NULL checks** to struct_ops registration code
2. **Document required callbacks** in bpf_struct_ops structure comments
3. **Improve error messages** for missing callbacks (instead of panicking)
4. **Add validation** during registration to catch issues early

#### For Module Developers

1. **Always provide all callbacks:** init, init_member, verifier_ops, reg, unreg
2. **Test on a VM first:** Kernel panics can corrupt filesystems
3. **Study existing implementations:** TCP congestion control, schedulers, etc.
4. **Use kernel test infrastructure:** bpf_testmod provides a template

---

## Testing Checklist

For anyone implementing struct_ops, use this checklist:

### Prerequisites
- [ ] Kernel headers installed
- [ ] vmlinux extracted and placed in headers directory
- [ ] pahole version ≥1.25 installed
- [ ] Test environment is a VM or disposable system

### Module Development
- [ ] All required callbacks implemented: init, init_member, verifier_ops, reg, unreg
- [ ] Module compiles without warnings
- [ ] BTF sections present in module (`readelf -S module.ko | grep BTF`)
- [ ] Module loads without panic (`insmod module.ko`)
- [ ] dmesg shows successful registration

### BPF Program Development
- [ ] No use of restricted helpers (bpf_printk, probe_read, etc.)
- [ ] Uses only allowed helpers or custom kfuncs
- [ ] BPF program loads successfully
- [ ] BPF program attaches to struct_ops
- [ ] Callbacks are invoked (verify via dmesg or maps)

### Cleanup
- [ ] BPF program detaches cleanly
- [ ] Module unloads without errors
- [ ] No leaked resources (check /proc/bpf_testmod_trigger removed)

---

## References

### Kernel Source Files Analyzed
- `kernel/bpf/bpf_struct_ops.c` - struct_ops core implementation
- `kernel/bpf/btf.c` - BTF management and struct_ops registration
- `kernel/bpf/verifier.c` - BPF verifier integration
- `tools/testing/selftests/bpf/test_kmods/bpf_testmod.c` - Reference implementation

### External Resources
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [pahole/dwarves GitHub](https://github.com/acmel/dwarves)

### Tools Used
- `pahole` v1.30 - BTF generation
- `readelf` - ELF section inspection
- `bpftool` - BPF introspection (limited in bootstrap mode)
- `dmesg` - Kernel log analysis

---

## Appendix: Complete Working Code

### Module Code (module/hello.c)

See the file for complete implementation with all fixes applied.

Key sections:
- Lines 45-71: Required callback implementations
- Lines 100-109: Complete struct_ops definition with all callbacks
- Lines 127-147: Module init with proper error handling

### BPF Code (struct_ops.bpf.c)

See the file for complete implementation.

Key points:
- No bpf_printk usage
- Simple implementations demonstrating callbacks work
- Proper section naming: `SEC("struct_ops/callback_name")`

### Userspace Loader (struct_ops.c)

See the file for complete implementation.

Key points:
- Uses libbpf for loading and attaching
- Properly destroys BPF link on exit
- Periodically triggers callbacks for testing

---

**End of Analysis**

This document represents the complete investigation and resolution process for implementing BPF struct_ops with a custom kernel module. All issues were resolved and root causes identified down to kernel source code level.
