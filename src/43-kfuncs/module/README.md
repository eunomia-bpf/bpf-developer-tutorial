# write a basic kernel module

## hello world

Writing a Linux kernel module involves creating code that can be loaded into and unloaded from the kernel dynamically, without rebooting the system. Here’s a simple step-by-step guide to help you write a basic kernel module:

### 1. Set Up Your Environment

Make sure you have the Linux kernel headers installed and a suitable development environment ready. For Ubuntu or Debian, install them with:

```bash
sudo apt-get install linux-headers-$(uname -r) build-essential
```

### 2. Write the Kernel Module Code

Here’s an example of a very basic Linux kernel module:

```c
// hello.c: A simple Linux kernel module
#include <linux/init.h>    // Macros for module initialization
#include <linux/module.h>  // Core header for loading modules
#include <linux/kernel.h>  // Kernel logging macros

// Function executed when the module is loaded
static int __init hello_init(void)
{
    printk(KERN_INFO "Hello, world!\n");
    return 0;  // Return 0 if successful
}

// Function executed when the module is removed
static void __exit hello_exit(void)
{
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

### 3. Create a Makefile

To compile the kernel module, you’ll need a `Makefile`. Here's a simple one:

```makefile
obj-m += hello.o  # hello.o is the target

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

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

### 8. Clean Up

To clean up the build files, run:

```bash
make clean
```

### Notes

- **License**: The `MODULE_LICENSE("GPL")` ensures the module is GPL-compliant, which allows it to use symbols (functions) exported by the kernel.
- **Debugging**: Use `printk` for logging within the module. It behaves similarly to `printf` but is designed for kernel space.
- **Module Parameters**: You can add parameters to modules using `module_param()` to pass arguments when the module is loaded.

### Next Steps

Once you are familiar with this basic example, you can explore:

- Writing more advanced modules that interact with hardware or the filesystem.
- Using kernel-specific APIs like work queues, kthreads, or handling interrupts.
- Diving into eBPF or loadable kernel module techniques for debugging and tracing kernel events.
