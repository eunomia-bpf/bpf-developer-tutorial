# extern eBPF with kfuncs in kernel modules

what 's kfuncs?

BPF Kernel Functions or more commonly known as kfuncs are functions in the Linux kernel which are exposed for use by BPF programs. Unlike normal BPF helpers, kfuncs do not have a stable interface and can change from one kernel release to another. Hence, BPF programs need to be updated in response to changes in the kernel. See 3. kfunc lifecycle expectations for more information.

There are two ways to expose a kernel function to BPF programs, either make an existing function in the kernel visible, or add a new wrapper for BPF. In both cases, care must be taken that BPF program can only call such function in a valid context. To enforce this, visibility of a kfunc can be per program type.

If you are not creating a BPF wrapper for existing kernel function, skip ahead to 2.3 Using an existing kernel function.

This timeline analyzes the evolution of eBPF helper functions and their relationship with kernel functions over time. The analysis highlights trends in the adoption of new helper functions and their impact on kernel functionality.

![cumulative_helper_kfunc_timeline](https://raw.githubusercontent.com/eunomia-bpf/code-survey/main/imgs/cumulative_helper_kfunc_timeline.png)

Key Takeaways:

Helper functions are stable, and almost no new helpers are being added.
Kfuncs are growing very rapidly, showing the community's interest in expanding kernel interaction via kfuncs.
Since 2023, all new use cases now tend to use kfuncs to influence kernel behavior, signaling a shift towards deeper kernel integrations.

how to use kfuncs?

Add new kfunc with kernel module: extern eBPF what ever you like

## write kernel module

hello.c

```c
#include <linux/init.h>    // Macros for module initialization
#include <linux/module.h>  // Core header for loading modules
#include <linux/kernel.h>  // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d);

/* Define a kfunc function */
__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d)
{
    return a + b + c + d;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_kfunc_call_test)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

// Register the kfunc ID set
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

// Function executed when the module is loaded
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    // Register the BTF kfunc ID set
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret) {
        pr_err("bpf_kfunc_example: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: Module loaded successfully\n");
    return 0;  // Return 0 if successful
}

// Function executed when the module is removed
static void __exit hello_exit(void)
{
    // Unregister the BTF kfunc ID set
    // unregister_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_kfunc_example_set);
    printk(KERN_INFO "Goodbye, world!\n");
}

// Macros to define the module’s init and exit points
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");               // License type (GPL)
MODULE_AUTHOR("Your Name");          // Module author
MODULE_DESCRIPTION("A simple module"); // Module description
MODULE_VERSION("1.0");               // Module version

```

makefile:

```makefile
obj-m += hello.o  # hello.o is the target

# Enable BTF generation
KBUILD_CFLAGS += -g -O2

all:
    # Compile the module with BTF information
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```

Note the code is testing on 6.11. on earlier version, it might need some work around, see  `compact.h`.

### 4. Compile the Module

Run the following command in the directory where your `hello.c` and `Makefile` are located:

```bash
make
```

This will generate a file called `hello.ko`, which is the compiled kernel module.

### 5. Load the Module

To insert the module into the kernel, use `insmod`:

```bash
sudo insmod hello.ko
```

### 6. Check the Logs

To see the output from the `printk` statements, use the `dmesg` command:

```bash
dmesg | tail
```

You should see something like:

```txt
[ 1234.5678] Hello, world!
```

### 7. Remove the Module

To unload the module, use `rmmod`:

```bash
sudo rmmod hello
```

Again, check the logs using `dmesg`:

```bash
sudo dmesg | tail
```

You should see:

```txt
[ 1234.9876] Goodbye, world!
```

## error

If exists:

```txt
Skipping BTF generation for /root/bpf-developer-tutorial/src/43-kfuncs/module/hello.ko due to unavailability of vmlinux
```

fix

```sh
sudo apt install dwarves
cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
```

## write eBPF use kfuncs

let's see how to use your new kfunc.

code:

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

extern u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int handle_kprobe(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 result = bpf_kfunc_call_test(1, 2, 3, 4);
    bpf_printk("BPF triggered do_unlinkat from PID %d. Result: %lld\n", pid, result);
    return 0;
}

```

run:

```c
# ./kfunc 
BPF program loaded and attached successfully. Press Ctrl-C to exit.
            node-9523    [004] ...21  7520.587718: bpf_trace_printk: BPF triggered do_unlinkat from PID 9523. Result: 10

        cpptools-11242   [003] ...21  7859.613060: bpf_trace_printk: BPF triggered do_unlinkat from PID 11235. Result: 10

^C^C        cpptools-11242   [002] ...21  7865.831074: bpf_trace_printk: BPF triggered do_unlinkat from PID 11235. Result: 10
```

## reference

- <https://docs.kernel.org/bpf/kfuncs.html>
- <https://docs.ebpf.io/linux/kfuncs/>
