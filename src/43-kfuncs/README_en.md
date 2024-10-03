# Extending eBPF Beyond Its Limits: Custom kfuncs in Kernel Modules

Have you ever felt constrained by eBPF's capabilities? Maybe you've run into situations where the existing eBPF features just aren't enough to accomplish your goals. Perhaps you need deeper interactions with the kernel, or you're facing performance issues that the standard eBPF runtime can't solve. If you've ever wished for more flexibility and power in your eBPF programs, this tutorial is for you.

## Introduction: Breaking Free from eBPF Runtime Limitations with kfuncs

**eBPF (extended Berkeley Packet Filter)** has revolutionized Linux system programming by allowing developers to run sandboxed programs inside the kernel. It's a game-changer for networking, security, and observability, enabling powerful functionalities without the need to modify kernel source code or load traditional kernel modules.

But as amazing as eBPF is, it isn't without its limitations:

- **Functionality Gaps:** Sometimes, the existing features of the eBPF runtime don't provide the specific capabilities you need.
- **Complex Requirements:** Certain tasks demand more intricate kernel interactions that eBPF can't handle out of the box.
- **Performance Issues:** In some cases, the overhead of the eBPF runtime introduces latency or isn't efficient enough for high-performance requirements.

These challenges stem from the limitations of the **entire eBPF runtime**, not just its helper functions. So how do you overcome these hurdles without altering the kernel itself?

Enter **kfuncs (BPF Kernel Functions)**. By defining your own kfuncs within kernel modules, you can extend eBPF's capabilities beyond its default limitations. This approach lets you:

- **Enhance Functionality:** Introduce new operations that aren't available in the standard eBPF runtime.
- **Customize Behavior:** Tailor kernel interactions to fit your specific needs.
- **Boost Performance:** Optimize critical paths by executing custom code directly in the kernel context.

Best of all, you achieve this without modifying the core kernel, keeping your system stable and your code safe.

In this tutorial, we'll show you how to define custom kfuncs to fill any gaps in eBPF's capabilities. We'll walk through creating a kernel module that introduces new kfuncs and demonstrate how to use them in your eBPF programs. Whether you're looking to overcome performance bottlenecks or need features the eBPF runtime doesn't offer, custom kfuncs can unlock new possibilities for your projects.

## Understanding kfuncs: Extending eBPF Beyond Helpers

### What Are kfuncs?

**BPF Kernel Functions (kfuncs)** are specialized functions within the Linux kernel that are exposed for use by eBPF programs. Unlike standard eBPF helpers, kfuncs do not have a stable interface and can vary between kernel releases. This variability means that BPF programs utilizing kfuncs need to be updated in tandem with kernel updates to maintain compatibility and stability.

### Why Use kfuncs?

1. **Extended Functionality:** kfuncs enable operations that standard eBPF helpers cannot perform.
2. **Customization:** Define logic tailored to specific use cases, enhancing the flexibility of eBPF programs.
3. **Safety and Stability:** By encapsulating kfuncs within kernel modules, you avoid direct modifications to the core kernel, preserving system integrity.

### How kfuncs Fit into eBPF

kfuncs serve as bridges between eBPF programs and deeper kernel functionalities. They allow eBPF programs to perform more intricate operations by either exposing existing kernel functions or introducing new wrappers specifically designed for eBPF interactions. This integration facilitates deeper kernel interactions while ensuring that eBPF programs remain safe and maintainable.

It's important to note that the Linux kernel already includes a plethora of kfuncs. These built-in kfuncs cover a wide range of functionalities, allowing most developers to accomplish their tasks without the need to define new ones. However, in cases where the existing kfuncs do not meet specific requirements, defining custom kfuncs becomes necessary. This tutorial demonstrates how to define new kfuncs to fill any gaps, ensuring that your eBPF programs can leverage the exact functionality you need. eBPF can also be extended to userspace. In the userspace eBPF runtime [bpftime](https://github.com/eunomia-bpf/bpftime), we are also implementing ufuncs, which are similar to kfuncs but extending userspace applications.

## Overview of kfuncs and Their Evolution

To appreciate the significance of kfuncs, it's essential to understand their evolution in relation to eBPF helper functions.

![Cumulative Helper and kfunc Timeline](https://raw.githubusercontent.com/eunomia-bpf/code-survey/main/imgs/cumulative_helper_kfunc_timeline.png)

**Key Takeaways:**

- **Stability of Helper Functions:** eBPF helper functions have remained largely stable, with minimal new additions.
- **Rapid Growth of kfuncs:** There's been a significant increase in the adoption and creation of kfuncs, indicating the community's interest in expanding kernel interactions via kfuncs.
- **Shift Towards Deeper Kernel Integrations:** Since 2023, new use cases predominantly leverage kfuncs to influence kernel behavior, signaling a trend towards more profound kernel integrations through eBPF.

This trend underscores the community's drive to push the boundaries of what eBPF can achieve by integrating more deeply with the kernel through kfuncs.

## Defining Your Own kfunc: A Step-by-Step Guide

To harness the power of kfuncs, you'll need to define them within a kernel module. This process ensures that your custom functions are safely exposed to eBPF programs without altering the core kernel.

### Writing the Kernel Module

Let's start by creating a simple kernel module that defines a kfunc. This kfunc will perform a basic arithmetic operation, serving as a foundation for understanding the mechanics.

#### **File: `hello.c`**

```c
#include <linux/init.h>    // Macros for module initialization
#include <linux/module.h>  // Core header for loading modules
#include <linux/kernel.h>  // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

// Declare the kfunc
__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d);

/* Define the kfunc functions */
__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d)
{
    return a + b + c + d;
}

__bpf_kfunc_end_defs();

// Define the BTF kfunc ID set
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_kfunc_call_test)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

// Register the kfunc ID set
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

// Module initialization
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
    return 0;  // Success
}

// Module cleanup
static void __exit hello_exit(void)
{
    // Unregister the BTF kfunc ID set (optional based on kernel version)
    // unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "Goodbye, world!\n");
}

// Define module entry and exit points
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // License type
MODULE_AUTHOR("Your Name");            // Module author
MODULE_DESCRIPTION("A simple module"); // Module description
MODULE_VERSION("1.0");                 // Module version
```

**Explanation of the Code:**

- **Declaring the kfunc:** The `__bpf_kfunc` macro declares a function that eBPF programs can invoke. Here, `bpf_kfunc_call_test` takes four parameters (`a`, `b`, `c`, `d`) and returns their sum.
  
- **BTF Definitions:** The `__bpf_kfunc_start_defs` and `__bpf_kfunc_end_defs` macros demarcate the beginning and end of kfunc definitions. The `BTF_KFUNCS_START` and related macros assist in registering the kfuncs with the BPF Type Format (BTF).
  
- **Module Initialization:** The `hello_init` function registers the kfunc ID set, making `bpf_kfunc_call_test` available to eBPF programs of type `BPF_PROG_TYPE_KPROBE`.
  
- **Module Cleanup:** The `hello_exit` function ensures that the kfunc ID set is unregistered upon module removal, maintaining system cleanliness.

#### **File: `Makefile`**

```makefile
obj-m += hello.o  # hello.o is the target

# Enable BTF generation
KBUILD_CFLAGS += -g -O2

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

**Explanation of the Makefile:**

- **Target Definition:** `obj-m += hello.o` specifies that `hello.o` is the module to be built.
  
- **BTF Generation Flags:** `KBUILD_CFLAGS += -g -O2` enables debug information and optimization, facilitating BTF generation.
  
- **Build Commands:**
  - **`all`:** Compiles the kernel module by invoking the kernel build system.
  - **`clean`:** Cleans up the build artifacts.

**Note:** The provided code has been tested on Linux kernel version **6.11**. If you're using an earlier version, you might need to implement workarounds, such as referencing `compact.h`.

### Compiling the Kernel Module

With the kernel module source and Makefile in place, follow these steps to compile the module:

1. **Navigate to the Module Directory:**

   ```bash
   cd /path/to/bpf-developer-tutorial/src/43-kfuncs/module/
   ```

2. **Compile the Module:**

   ```bash
   make
   ```

   This command will generate a file named `hello.ko`, which is the compiled kernel module.

### Loading the Kernel Module

To insert the compiled module into the kernel, use the `insmod` command:

```bash
sudo insmod hello.ko
```

### Verifying Module Loading

After loading the module, verify its successful insertion by checking the kernel logs:

```bash
dmesg | tail
```

**Expected Output:**

```txt
[ 1234.5678] Hello, world!
[ 1234.5679] bpf_kfunc_example: Module loaded successfully
```

### Removing the Kernel Module

When you no longer need the module, unload it using the `rmmod` command:

```bash
sudo rmmod hello
```

**Verify Removal:**

```bash
dmesg | tail
```

**Expected Output:**

```txt
[ 1234.9876] Goodbye, world!
```

## Handling Compilation Errors

During the compilation process, you might encounter the following error:

```txt
Skipping BTF generation for /root/bpf-developer-tutorial/src/43-kfuncs/module/hello.ko due to unavailability of vmlinux
```

**Solution:**

1. **Install the `dwarves` Package:**

   The `dwarves` package provides tools necessary for BTF generation.

   ```sh
   sudo apt install dwarves
   ```

2. **Copy the `vmlinux` File:**

   Ensure that the `vmlinux` file, which contains BTF information, is available in the build directory.

   ```sh
   sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/
   ```

   This command copies the `vmlinux` file to the appropriate build directory, enabling successful BTF generation.

The complete code for this tutorial can be found in the link <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/43-kfuncs> on GitHub. This is tested on Linux kernel version 6.11, and some modifications may be required for lower versions, referring to `compact.h`.

## Utilizing Your Custom kfunc in an eBPF Program

With the kernel module defining your custom kfunc in place, the next step is to create an eBPF program that leverages this function. This interaction showcases the enhanced capabilities introduced by kfuncs.

### Writing the eBPF Program

Create an eBPF program that attaches to the `do_unlinkat` kernel function and uses the custom `bpf_kfunc_call_test` kfunc.

#### **File: `kfunc.c`**

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef int pid_t;

// Declare the external kfunc
extern u64 bpf_kfunc_call_test(u32 a, u64 b, u32 c, u64 d) __ksym;

// License information
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Attach to the do_unlinkat kernel function
SEC("kprobe/do_unlinkat")
int handle_kprobe(void *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 result = bpf_kfunc_call_test(1, 2, 3, 4);
    bpf_printk("BPF triggered do_unlinkat from PID %d. Result: %lld\n", pid, result);
    return 0;
}
```

**Explanation of the eBPF Code:**

- **External kfunc Declaration:** The `extern` keyword declares the `bpf_kfunc_call_test` function, making it accessible within the eBPF program.
  
- **Kprobe Attachment:** The `SEC("kprobe/do_unlinkat")` macro attaches the eBPF program to the `do_unlinkat` kernel function. Every time `do_unlinkat` is invoked, the `handle_kprobe` function executes.
  
- **Using the kfunc:** Within `handle_kprobe`, the eBPF program calls `bpf_kfunc_call_test` with four arguments (`1, 2, 3, 4`). The result, which should be the sum of these numbers, is then printed using `bpf_printk`, displaying both the PID and the result.

### Compiling the eBPF Program

To compile the eBPF program, ensure you have the necessary tools installed, such as `clang` and `llvm`. Here's how you can compile the program:

1. **Navigate to the eBPF Program Directory:**

   ```bash
   cd /path/to/bpf-developer-tutorial/src/43-kfuncs/
   ```

2. **Compile the eBPF Program:**

   ```bash
   make
   ```

### Running the eBPF Program

Assuming you have a user-space application or a tool to load and attach the eBPF program, you can execute it to observe the interaction between the eBPF program and the custom kfunc.

**Sample Output:**

```bash
$ sudo ./kfunc
BPF program loaded and attached successfully. Press Ctrl-C to exit.
            node-9523    [004] ...21  7520.587718: bpf_trace_printk: BPF triggered do_unlinkat from PID 9523. Result: 10

        cpptools-11242   [003] ...21  7859.613060: bpf_trace_printk: BPF triggered do_unlinkat from PID 11235. Result: 10

^C
cpptools-11242   [002] ...21  7865.831074: bpf_trace_printk: BPF triggered do_unlinkat from PID 11235. Result: 10
```

**Explanation of the Output:**

Each time the `do_unlinkat` function is invoked in the kernel, the eBPF program prints a message indicating the PID of the process and the result of the kfunc call. In this example, the sum `1 + 2 + 3 + 4` results in `10`, which is reflected in the output.

## Summary and Conclusion

In this tutorial, we've delved deep into extending eBPF's capabilities by defining and utilizing custom kernel functions (kfuncs). Here's a recap of what we've covered:

- **Understanding kfuncs:** Grasped the concept of kfuncs and their role in enhancing eBPF beyond standard helper functions.
- **Defining kfuncs:** Created a kernel module that defines a custom kfunc, ensuring it can be safely exposed to eBPF programs without altering the core kernel.
- **Writing eBPF Programs with kfuncs:** Developed an eBPF program that leverages the custom kfunc to perform specific operations, demonstrating the enhanced functionality.
- **Compilation and Execution:** Provided a step-by-step guide to compile, load, and run both the kernel module and the eBPF program, ensuring you can replicate the setup on your own system.
- **Error Handling:** Addressed potential compilation issues and offered solutions to ensure a smooth development experience.

**Key Takeaways:**

- **Overcoming Helper Limitations:** kfuncs bridge the gaps left by standard eBPF helpers, offering extended functionality tailored to specific needs.
- **Maintaining System Stability:** By encapsulating kfuncs within kernel modules, you ensure that system stability is maintained without making invasive changes to the kernel.
- **Community-Driven Evolution:** The rapid growth and adoption of kfuncs highlight the eBPF community's commitment to pushing the boundaries of what's possible with kernel-level programming.
- **Leveraging Existing kfuncs:** Before defining new kfuncs, explore the existing ones provided by the kernel. They cover a wide range of functionalities, reducing the need to create custom functions unless absolutely necessary.

**Ready to elevate your eBPF skills even further?** [Visit our tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial) and [explore more tutorials on our website](https://eunomia.dev/tutorials/). Dive into a wealth of examples, deepen your understanding, and contribute to the dynamic world of eBPF!

Happy eBPF-ing!

## References

- [BPF Kernel Functions Documentation](https://docs.kernel.org/bpf/kfuncs.html)
- [eBPF kfuncs Guide](https://docs.ebpf.io/linux/kfuncs/)

## Additional Resources

If you'd like to learn more about eBPF knowledge and practices, you can visit our open source tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or website <https://eunomia.dev/tutorials/> for more examples and complete code.

## Conclusion

By following this detailed tutorial, you've equipped yourself with the knowledge to extend eBPF's capabilities using custom kfuncs. Whether you're aiming to perform advanced kernel interactions, overcome helper limitations, or enhance your observability tools, kfuncs provide the flexibility and power you need. Continue experimenting, stay curious, and contribute to the ever-evolving landscape of eBPF!
