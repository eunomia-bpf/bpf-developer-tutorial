# Extending eBPF Beyond Its Limits: Custom kfuncs in Kernel Modules

Have you ever felt constrained by eBPF's capabilities? Maybe you've run into situations where the existing eBPF features just aren't enough to accomplish your goals. Perhaps you need deeper interactions with the kernel, or you're facing performance issues that the standard eBPF runtime can't solve. If you've ever wished for more flexibility and power in your eBPF programs, this tutorial is for you.

## Introduction: Adding a `strstr` kfunc to Break Free from eBPF Runtime Limitations

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

**In this tutorial, we'll specifically add a `strstr` kfunc.** While implementing a string search directly in eBPF is challenging due to verifier restrictions, defining it as a kfunc allows us to bypass these limitations and perform more complex operations safely and efficiently.

Best of all, you achieve this without modifying the core kernel, keeping your system stable and your code safe.

In this tutorial, we'll show you how to define custom kfuncs to fill any gaps in eBPF's capabilities. We'll walk through creating a kernel module that introduces new kfuncs and demonstrate how to use them in your eBPF programs. Whether you're looking to overcome performance bottlenecks or need features the eBPF runtime doesn't offer, custom kfuncs can unlock new possibilities for your projects.

## Understanding kfunc: Extending eBPF Beyond Helpers

### What Are kfuncs?

**BPF Kernel Functions (kfuncs)** are specialized functions within the Linux kernel that are exposed for use by eBPF programs. Unlike standard eBPF helpers, kfuncs do not have a stable interface and can vary between kernel releases. This variability means that BPF programs utilizing kfuncs need to be updated in tandem with kernel updates to maintain compatibility and stability.

### Why Use kfuncs?

1. **Extended Functionality:** kfuncs enable operations that standard eBPF helpers cannot perform.
2. **Customization:** Define logic tailored to specific use cases, enhancing the flexibility of eBPF programs.
3. **Safety and Stability:** By encapsulating kfuncs within kernel modules, you avoid direct modifications to the core kernel, preserving system integrity.

### How kfuncs Fit into eBPF

kfuncs serve as bridges between eBPF programs and deeper kernel functionalities. They allow eBPF programs to perform more intricate operations by either exposing existing kernel functions or introducing new wrappers specifically designed for eBPF interactions. This integration facilitates deeper kernel interactions while ensuring that eBPF programs remain safe and maintainable.

It's important to note that the Linux kernel already includes a plethora of kfuncs. These built-in kfuncs cover a wide range of functionalities, allowing most developers to accomplish their tasks without the need to define new ones. However, in cases where the existing kfuncs do not meet specific requirements, defining custom kfuncs becomes necessary. This tutorial demonstrates how to define new kfuncs to fill any gaps, ensuring that your eBPF programs can leverage the exact functionality you need. eBPF can also be extended to userspace. In the userspace eBPF runtime [bpftime](https://github.com/eunomia-bpf/bpftime), we are also implementing ufuncs, which are similar to kfuncs but extend userspace applications.

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

Let's start by creating a simple kernel module that defines a `strstr` kfunc. This kfunc will perform a substring search operation, serving as a foundation for understanding the mechanics.

#### **File: `hello.c`**

```c
#include <linux/init.h>       // Macros for module initialization
#include <linux/module.h>     // Core header for loading modules
#include <linux/kernel.h>     // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

/* Declare the kfunc prototype */
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);

/* Begin kfunc definitions */
__bpf_kfunc_start_defs();

/* Define the bpf_strstr kfunc */
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz)
{
    // Edge case: if substr is empty, return 0 (assuming empty string is found at the start)
    if (substr__sz == 0)
    {
        return 0;
    }
    // Edge case: if the substring is longer than the main string, it's impossible to find
    if (substr__sz > str__sz)
    {
        return -1; // Return -1 to indicate not found
    }
    // Iterate through the main string, considering the size limit
    for (size_t i = 0; i <= str__sz - substr__sz; i++)
    {
        size_t j = 0;
        // Compare the substring with the current position in the string
        while (j < substr__sz && str[i + j] == substr[j])
        {
            j++;
        }
        // If the entire substring was found
        if (j == substr__sz)
        {
            return i; // Return the index of the first match
        }
    }
    // Return -1 if the substring is not found
    return -1;
}

/* End kfunc definitions */
__bpf_kfunc_end_defs();

/* Define the BTF kfuncs ID set */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* Register the kfunc ID set */
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* Function executed when the module is loaded */
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    /* Register the BTF kfunc ID set for BPF_PROG_TYPE_KPROBE */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpf_kfunc_example: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: Module loaded successfully\n");
    return 0; // Return 0 if successful
}

/* Function executed when the module is removed */
static void __exit hello_exit(void)
{
    /* Unregister the BTF kfunc ID set */
    unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "Goodbye, world!\n");
}

/* Macros to define the module’s init and exit points */
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // License type (GPL)
MODULE_AUTHOR("Your Name");            // Module author
MODULE_DESCRIPTION("A simple module"); // Module description
MODULE_VERSION("1.0");                 // Module version
```

**Explanation of the Code:**

- **Declaring the kfunc:** The `__bpf_kfunc` macro declares a function that eBPF programs can invoke. Here, `bpf_strstr` performs a substring search within a given string.
  
- **BTF Definitions:** The `__bpf_kfunc_start_defs` and `__bpf_kfunc_end_defs` macros demarcate the beginning and end of kfunc definitions. The `BTF_KFUNCS_START` and related macros assist in registering the kfuncs with the BPF Type Format (BTF).
  
- **Module Initialization:** The `hello_init` function registers the kfunc ID set, making `bpf_strstr` available to eBPF programs of type `BPF_PROG_TYPE_KPROBE`.
  
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

The complete code for this tutorial can be found in the [bpf-developer-tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/43-kfuncs) on GitHub. This is tested on Linux kernel version 6.11, and some modifications may be required for lower versions, referring to `compact.h`.

## Utilizing Your Custom kfunc in an eBPF Program

With the kernel module defining your custom `strstr` kfunc in place, the next step is to create an eBPF program that leverages this function. This interaction showcases the enhanced capabilities introduced by kfuncs.

### Writing the eBPF Program

Create an eBPF program that attaches to the `do_unlinkat` kernel function and uses the custom `bpf_strstr` kfunc.

#### **File: `kfunc.c`**

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef long long s64;

/* Declare the external kfunc */
extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int handle_kprobe(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char str[] = "Hello, world!";
    char substr[] = "wor";
    int result = bpf_strstr(str, sizeof(str) - 1, substr, sizeof(substr) - 1);
    if (result != -1)
    {
        bpf_printk("'%s' found in '%s' at index %d\n", substr, str, result);
    }
    bpf_printk("Hello, world! (pid: %d) bpf_strstr %d\n", pid, result);
    return 0;
}
```

**Explanation of the eBPF Code:**

- **External kfunc Declaration:** The `extern` keyword declares the `bpf_strstr` function, making it accessible within the eBPF program.

- **Kprobe Attachment:** The `SEC("kprobe/do_unlinkat")` macro attaches the eBPF program to the `do_unlinkat` kernel function. Every time `do_unlinkat` is invoked, the `handle_kprobe` function executes.

- **Using the kfunc:** Within `handle_kprobe`, the eBPF program calls `bpf_strstr` with four arguments:
  - `str`: The main string to search within.
  - `str__sz`: The size of the main string.
  - `substr`: The substring to search for.
  - `substr__sz`: The size of the substring.

  The result, which is the index of the first occurrence of `substr` in `str` or `-1` if not found, is then printed using `bpf_printk`, displaying both the PID and the result.

**Important Note:** Implementing a `strstr`-like function directly in eBPF is challenging due to verifier restrictions that limit loops and complex memory accesses. By implementing `strstr` as a kfunc, we bypass these limitations, allowing for more complex and efficient string operations within eBPF programs.

### Compiling the eBPF Program

To compile the eBPF program, ensure you have the necessary tools installed, such as `clang` and `llvm`. Here's how you can compile the program:

1. **Navigate to the eBPF Program Directory:**

   ```bash
   cd /path/to/bpf-developer-tutorial/src/43-kfuncs/
   ```

2. **Create a `Makefile` for the eBPF Program:**

   ```makefile
   # File: Makefile

   CLANG ?= clang
   LLVM_STRIP ?= llvm-strip
   BPF_TARGET := bpf

   CFLAGS := -O2 -g -target $(BPF_TARGET) -Wall -Werror -I/usr/include

   all: kfunc.o

   kfunc.o: kfunc.c
       $(CLANG) $(CFLAGS) -c $< -o $@

   clean:
       rm -f kfunc.o
   ```

3. **Compile the eBPF Program:**

   ```bash
   make
   ```

   This command will generate a file named `kfunc.o`, which is the compiled eBPF object file.

### Running the eBPF Program

Assuming you have a user-space application or a tool to load and attach the eBPF program, you can execute it to observe the interaction between the eBPF program and the custom kfunc.

**Sample Output:**

```bash
# sudo ./kfunc
BPF program loaded and attached successfully. Press Ctrl-C to exit.
```

Then, when the `do_unlinkat` function is invoked (e.g., when a file is unlinked), you can check the kernel logs:

```bash
dmesg | tail
```

**Expected Output:**

```txt
[ 1234.5678] 'wor' found in 'Hello, world!' at index 7
[ 1234.5679] Hello, world! (pid: 2075) bpf_strstr 7
```

**Explanation of the Output:**

Each time the `do_unlinkat` function is invoked in the kernel, the eBPF program prints a message indicating the PID of the process and the result of the kfunc call. In this example, the substring `"wor"` is found at index `7` in the string `"Hello, world!"`.

## Summary and Conclusion

In this tutorial, we've delved deep into extending eBPF's capabilities by defining and utilizing custom kernel functions (kfuncs). Here's a recap of what we've covered:

- **Understanding kfuncs:** Grasped the concept of kfuncs and their role in enhancing eBPF beyond standard helper functions.
- **Defining kfuncs:** Created a kernel module that defines a custom `strstr` kfunc, ensuring it can be safely exposed to eBPF programs without altering the core kernel.
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

If you'd like to learn more about eBPF knowledge and practices, you can visit our open-source tutorial code repository at [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) or our website [eunomia.dev/tutorials](https://eunomia.dev/tutorials/) for more examples and complete code.
