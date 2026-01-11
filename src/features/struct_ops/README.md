# eBPF Tutorial: Extending Kernel Subsystems with BPF struct_ops

Have you ever wanted to implement a kernel feature, like a new network protocol or a custom security policy, but were put off by the complexity of writing and maintaining a full kernel module? What if you could define the operational logic of a kernel subsystem directly in eBPF, allowing for dynamic updates, safe execution, and programmable control, all without recompiling the kernel or risking system stability?

This is the power of **BPF struct_ops**. This advanced eBPF feature allows BPF programs to implement the callbacks for a kernel structure of operations, effectively allowing you to "plug in" BPF code to act as a kernel subsystem. It's a step beyond simple tracing or filtering; it's about implementing core kernel logic in BPF. For instance, we also use it to implement GPU scheduling and memory offloading extensions with eBPF in GPU drivers (see [LPC 2024 talk](https://lpc.events/event/19/contributions/2168/) and the [gpu_ext project](https://github.com/eunomia-bpf/gpu_ext)).

In this tutorial, we will explore how to use `struct_ops` to dynamically implement a kernel subsystem's functionality. We won't be using the common TCP congestion control example. Instead, we'll take a more fundamental approach that mirrors the extensibility seen with kfuncs. We will create a custom kernel module that defines a new, simple subsystem with a set of operations. This module will act as a placeholder, creating new attachment points for our BPF programs. Then, we will write a BPF program to implement the logic for these operations. This demonstrates a powerful pattern: using a minimal kernel module to expose a `struct_ops` interface, and then using BPF to provide the full, complex implementation.

> The complete source code for this tutorial can be found here: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/features/struct_ops>

## Introduction to BPF struct_ops: Programmable Kernel Subsystems

### The Challenge: Extending Kernel Behavior Safely and Dynamically

Traditionally, adding new functionality to the Linux kernel, such as a new file system, a network protocol, or a scheduler algorithm, requires writing a kernel module. While powerful, kernel modules come with significant challenges:
- **Complexity:** Kernel development has a steep learning curve and requires a deep understanding of kernel internals.
- **Safety:** A bug in a kernel module can easily crash the entire system. There are no sandboxing guarantees.
- **Maintenance:** Kernel modules must be maintained and recompiled for different kernel versions, creating a tight coupling with the kernel's internal APIs.

eBPF has traditionally addressed these issues for tracing, networking, and security by providing a safe, sandboxed environment. However, most eBPF programs are attached to existing hooks (like tracepoints, kprobes, or XDP) and react to events. They don't typically *implement* the core logic of a kernel subsystem.

### The Solution: Implementing Kernel Operations with BPF

BPF `struct_ops` bridges this gap. It allows a BPF program to implement the functions within a `struct_ops`—a common pattern in the kernel where a structure holds function pointers for a set of operations. Instead of these pointers pointing to functions compiled into the kernel or a module, they can point to BPF programs.

This is a paradigm shift. It's no longer just about observing or filtering; it's about *implementing*. Imagine a kernel subsystem that defines a set of operations like `open`, `read`, `write`. With `struct_ops`, you can write BPF programs that serve as the implementation for these very functions.

This approach is similar in spirit to how **kfuncs** allow developers to extend the capabilities of BPF. With kfuncs, we can add custom helper functions to the BPF runtime by defining them in a kernel module. With `struct_ops`, we take this a step further: we define a whole new *set of attach points* for BPF programs, effectively creating a custom, BPF-programmable subsystem within the kernel.

The benefits are immense:
- **Dynamic Implementation**: You can load, update, and unload the BPF programs implementing the subsystem logic on the fly, without restarting the kernel or the application.
- **Safety**: The BPF verifier ensures that the BPF programs are safe to run, preventing common pitfalls like infinite loops, out-of-bounds memory access, and system crashes.
- **Flexibility**: The logic is in the BPF program, which can be developed and updated independently of the kernel module that defines the `struct_ops` interface.
- **Programmability**: Userspace applications can interact with and control the BPF programs, allowing for dynamic configuration and control of the kernel subsystem's behavior.

In this tutorial, we will walk through a practical example of this pattern. We'll start with a kernel module that defines a new `struct_ops` type, and then we'll write a BPF program to implement its functions.

## The Kernel Module: Defining the Subsystem Interface

The first step is to create a kernel module that defines our new BPF-programmable subsystem. This module doesn't need to contain much logic itself. Its primary role is to define a `struct_ops` type and register it with the kernel, creating a new attachment point for BPF programs. It also provides a mechanism to trigger the operations, which in our case will be a simple proc file.

This approach is powerful because it separates the interface definition (in the kernel module) from the implementation (in the BPF program). The kernel module is stable and minimal, while the complex, dynamic logic resides in the BPF program, which can be updated at any time.

### Complete Kernel Module: `module/hello.c`

Here is the complete source code for our kernel module. It defines a `struct_ops` named `bpf_testmod_ops` with three distinct operations that our BPF program will later implement.

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/bpf_verifier.h>

/* Define our custom struct_ops operations */
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	int (*test_3)(const char *buf, int len);
};

/* Global instance that BPF programs will implement */
static struct bpf_testmod_ops __rcu *testmod_ops;

/* Proc file to trigger the struct_ops */
static struct proc_dir_entry *trigger_file;

/* CFI stub functions - required for struct_ops */
static int bpf_testmod_ops__test_1(void)
{
	return 0;
}

static int bpf_testmod_ops__test_2(int a, int b)
{
	return 0;
}

static int bpf_testmod_ops__test_3(const char *buf, int len)
{
	return 0;
}

/* CFI stubs structure */
static struct bpf_testmod_ops __bpf_ops_bpf_testmod_ops = {
	.test_1 = bpf_testmod_ops__test_1,
	.test_2 = bpf_testmod_ops__test_2,
	.test_3 = bpf_testmod_ops__test_3,
};

/* BTF and verifier callbacks */
static int bpf_testmod_ops_init(struct btf *btf)
{
	/* Initialize BTF if needed */
	return 0;
}

static bool bpf_testmod_ops_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	/* Allow all accesses for now */
	return true;
}

/* Allow specific BPF helpers to be used in struct_ops programs */
static const struct bpf_func_proto *
bpf_testmod_ops_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	/* Use base func proto which includes trace_printk and other basic helpers */
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
	.get_func_proto = bpf_testmod_ops_get_func_proto,
};

static int bpf_testmod_ops_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	/* No special member initialization needed */
	return 0;
}

/* Registration function */
static int bpf_testmod_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops *ops = kdata;
	
	/* Only one instance at a time */
	if (cmpxchg(&testmod_ops, NULL, ops) != NULL)
		return -EEXIST;

	pr_info("bpf_testmod_ops registered\n");
	return 0;
}

/* Unregistration function */
static void bpf_testmod_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops *ops = kdata;

	if (cmpxchg(&testmod_ops, ops, NULL) != ops) {
		pr_warn("bpf_testmod_ops: unexpected unreg\n");
		return;
	}

	pr_info("bpf_testmod_ops unregistered\n");
}

/* Struct ops definition */
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	.cfi_stubs = &__bpf_ops_bpf_testmod_ops,
	.name = "bpf_testmod_ops",
	.owner = THIS_MODULE,
};

/* Proc file write handler to trigger struct_ops */
static ssize_t trigger_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct bpf_testmod_ops *ops;
	char kbuf[64];
	int ret = 0;
	
	if (count >= sizeof(kbuf))
		count = sizeof(kbuf) - 1;
	
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	
	kbuf[count] = '\0';
	
	rcu_read_lock();
	ops = rcu_dereference(testmod_ops);
	if (ops) {
		pr_info("Calling struct_ops callbacks:\n");
		
		if (ops->test_1) {
			ret = ops->test_1();
			pr_info("test_1() returned: %d\n", ret);
		}
		
		if (ops->test_2) {
			ret = ops->test_2(10, 20);
			pr_info("test_2(10, 20) returned: %d\n", ret);
		}
		
		if (ops->test_3) {
			ops->test_3(kbuf, count);
			pr_info("test_3() called with buffer\n");
		}
	} else {
		pr_info("No struct_ops registered\n");
	}
	rcu_read_unlock();
	
	return count;
}

static const struct proc_ops trigger_proc_ops = {
	.proc_write = trigger_write,
};

static int __init testmod_init(void)
{
	int ret;

	/* Register the struct_ops */
	ret = register_bpf_struct_ops(&bpf_testmod_ops_struct_ops, bpf_testmod_ops);
	if (ret) {
		pr_err("Failed to register struct_ops: %d\n", ret);
		return ret;
	}

	/* Create proc file for triggering */
	trigger_file = proc_create("bpf_testmod_trigger", 0222, NULL, &trigger_proc_ops);
	if (!trigger_file) {
		/* Note: No unregister function available in this kernel version */
		return -ENOMEM;
	}

	pr_info("bpf_testmod loaded with struct_ops support\n");
	return 0;
}

static void __exit testmod_exit(void)
{
	proc_remove(trigger_file);
	/* Note: struct_ops unregister happens automatically on module unload */
	pr_info("bpf_testmod unloaded\n");
}

module_init(testmod_init);
module_exit(testmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eBPF Example");
MODULE_DESCRIPTION("BPF struct_ops test module");
MODULE_VERSION("1.0");
```

### Understanding the Kernel Module Code

This module may seem complex, but its structure is logical and serves a clear purpose: to safely expose a new programmable interface to the BPF subsystem. Let's break it down.

First, we define the structure of our new operations. This is a simple C struct containing function pointers. This `struct bpf_testmod_ops` is the interface that our BPF program will implement. Each function pointer defines a "slot" that a BPF program can fill.

```c
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	int (*test_3)(const char *buf, int len);
};
```

Next, we have the core `bpf_struct_ops` definition. This is a special kernel structure that describes our new `struct_ops` type to the BPF system. It's the glue that connects our custom `bpf_testmod_ops` to the BPF infrastructure.

```c
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	.cfi_stubs = &__bpf_ops_bpf_testmod_ops,
	.name = "bpf_testmod_ops",
	.owner = THIS_MODULE,
};
```

This structure is filled with callbacks that the kernel will use to manage our `struct_ops`:
- `.reg` and `.unreg`: These are registration and unregistration callbacks. The kernel invokes `.reg` when a BPF program tries to attach an implementation for `bpf_testmod_ops`. Our implementation uses `cmpxchg` to ensure only one BPF program can be attached at a time. `.unreg` is called when the BPF program is detached.
- `.verifier_ops`: This points to a structure of callbacks for the BPF verifier. It allows us to customize how the verifier treats BPF programs attached to this `struct_ops`. For example, we can control which helper functions are allowed. In our case, we use `bpf_base_func_proto` to allow a basic set of helpers, including `bpf_printk`, which is useful for debugging.
- `.init` and `.init_member`: These are for BTF (BPF Type Format) initialization. They are required for the kernel to understand the types and layout of our `struct_ops`.
- `.name` and `.owner`: These identify our `struct_ops` and tie it to our module, ensuring proper reference counting so the module isn't unloaded while a BPF program is still attached.

The module's `testmod_init` function is where the magic starts. It calls `register_bpf_struct_ops`, passing our definition. This makes the kernel aware of the new `bpf_testmod_ops` type, and from this point on, BPF programs can target it.

Finally, to make this demonstrable, the module creates a file in the proc filesystem: `/proc/bpf_testmod_trigger`. When a userspace program writes to this file, the `trigger_write` function is called. This function checks if a BPF program has registered an implementation for `testmod_ops`. If so, it calls the function pointers (`test_1`, `test_2`, `test_3`), which will execute the code in our BPF program. This provides a simple way to invoke the BPF-implemented operations from userspace. The use of RCU (`rcu_read_lock`, `rcu_dereference`) ensures that we can safely access the `testmod_ops` pointer even if it's being updated concurrently.

## The BPF Program: Implementing the Operations

With the kernel module in place defining the *what* (the `bpf_testmod_ops` interface), we can now write a BPF program to define the *how* (the actual implementation of those operations). This BPF program will contain the logic that executes when the `test_1`, `test_2`, and `test_3` functions are called from the kernel.

### Complete BPF Program: `struct_ops.bpf.c`

This program provides the concrete implementations for the function pointers in `bpf_testmod_ops`.

```c
/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "module/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/* Implement the struct_ops callbacks */
SEC("struct_ops/test_1")
int BPF_PROG(bpf_testmod_test_1)
{
	bpf_printk("BPF test_1 called!\n");
	return 42;
}

SEC("struct_ops/test_2")
int BPF_PROG(bpf_testmod_test_2, int a, int b)
{
	int result = a + b;
	bpf_printk("BPF test_2 called: %d + %d = %d\n", a, b, result);
	return result;
}

SEC("struct_ops/test_3")
int BPF_PROG(bpf_testmod_test_3, const char *buf, int len)
{
	char read_buf[64] = {0};
	int read_len = len < sizeof(read_buf) ? len : sizeof(read_buf) - 1;

	bpf_printk("BPF test_3 called with buffer length %d\n", len);

	/* Safely read from kernel buffer using bpf_probe_read_kernel */
	if (buf && read_len > 0) {
		long ret = bpf_probe_read_kernel(read_buf, read_len, buf);
		if (ret == 0) {
			/* Successfully read buffer - print first few characters */
			bpf_printk("Buffer content: '%c%c%c%c'\n",
				   read_buf[0], read_buf[1], read_buf[2], read_buf[3]);
			bpf_printk("Full buffer: %s\n", read_buf);
		} else {
			bpf_printk("Failed to read buffer, ret=%ld\n", ret);
		}
	}

	return len;
}

/* Define the struct_ops map */
SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)bpf_testmod_test_1,
	.test_2 = (void *)bpf_testmod_test_2,
	.test_3 = (void *)bpf_testmod_test_3,
};
```

### Understanding the BPF Code

The BPF code is remarkably straightforward, which is a testament to the power of the `struct_ops` abstraction.

Each function in the BPF program corresponds to one of the operations defined in the kernel module's `bpf_testmod_ops` struct. The magic lies in the `SEC` annotations:
- `SEC("struct_ops/test_1")`: This tells the BPF loader that the `bpf_testmod_test_1` program is an implementation for a `struct_ops` operation. The name after the slash isn't strictly enforced to match the function name, but it's a good convention. The key part is the `struct_ops` prefix.

The implementations themselves are simple:
- `bpf_testmod_test_1`: This function takes no arguments, prints a message to the kernel trace log using `bpf_printk`, and returns the integer `42`.
- `bpf_testmod_test_2`: This function takes two integers, `a` and `b`, calculates their sum, prints the operation and result, and returns the sum.
- `bpf_testmod_test_3`: This function demonstrates handling data from userspace. It receives a character buffer and its length. It uses `bpf_probe_read_kernel` to safely copy the data from the buffer passed by the kernel module into a local buffer on the BPF stack. This is a crucial safety measure, as BPF programs cannot directly access arbitrary kernel memory pointers. After reading, it prints the content.

The final piece is the `struct_ops` map itself:

```c
SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)bpf_testmod_test_1,
	.test_2 = (void *)bpf_testmod_test_2,
	.test_3 = (void *)bpf_testmod_test_3,
};
```

This is the most critical part for linking everything together.
- `SEC(".struct_ops")`: This special section identifies the following data structure as a `struct_ops` map.
- `struct bpf_testmod_ops testmod_ops`: We declare a variable named `testmod_ops` of the type `struct bpf_testmod_ops`. The **name of this variable is important**. It must match the `name` field in the `bpf_struct_ops` definition within the kernel module (`.name = "bpf_testmod_ops"`). This is how `libbpf` knows which kernel `struct_ops` this BPF program intends to implement.
- The structure is initialized by assigning the BPF programs (`bpf_testmod_test_1`, etc.) to the corresponding function pointers. This maps our BPF functions to the "slots" in the `struct_ops` interface.

When the userspace loader attaches this `struct_ops`, `libbpf` and the kernel work together to find the `bpf_testmod_ops` registered by our kernel module and link these BPF programs as its implementation.

## The Userspace Loader: Attaching and Triggering

The final component is the userspace program. Its job is to load the BPF program, attach it to the `struct_ops` defined by the kernel module, and then trigger the operations to demonstrate that everything is working.

### Complete Userspace Program: `struct_ops.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "struct_ops.skel.h"

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

static int trigger_struct_ops(const char *message) {
    int fd, ret;
    
    fd = open("/proc/bpf_testmod_trigger", O_WRONLY);
    if (fd < 0) {
        perror("open /proc/bpf_testmod_trigger");
        return -1;
    }
    
    ret = write(fd, message, strlen(message));
    if (ret < 0) {
        perror("write");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    struct struct_ops_bpf *skel;
    struct bpf_link *link;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Open BPF application */
    skel = struct_ops_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load BPF programs */
    err = struct_ops_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Register struct_ops */
    link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
    if (!link) {
        fprintf(stderr, "Failed to attach struct_ops\n");
        err = -1;
        goto cleanup;
    }

    printf("Successfully loaded and attached BPF struct_ops!\n");
    printf("Triggering struct_ops callbacks...\n");
    
    /* Trigger the struct_ops by writing to proc file */
    if (trigger_struct_ops("Hello from userspace!") < 0) {
        printf("Failed to trigger struct_ops - is the kernel module loaded?\n");
        printf("Load it with: sudo insmod module/hello.ko\n");
    } else {
        printf("Triggered struct_ops successfully! Check dmesg for output.\n");
    }
    
    printf("\nPress Ctrl-C to exit...\n");

    /* Main loop - trigger periodically */
    while (!exiting) {
        sleep(2);
        if (!exiting && trigger_struct_ops("Periodic trigger") == 0) {
            printf("Triggered struct_ops again...\n");
        }
    }

    printf("\nDetaching struct_ops...\n");
    bpf_link__destroy(link);

cleanup:
    struct_ops_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

### Understanding the Userspace Code

The userspace code orchestrates the entire process.
1.  **Signal Handling**: It sets up a signal handler for `SIGINT` and `SIGTERM` to allow for a graceful exit. This is crucial for `struct_ops` because we need to ensure the BPF program is detached properly.

2.  **Open and Load**: It uses the standard `libbpf` skeleton API to open and load the BPF application (`struct_ops_bpf__open()` and `struct_ops_bpf__load()`). This loads the BPF programs and the `struct_ops` map into the kernel.

3.  **Attach `struct_ops`**: The key step is the attachment:
    ```c
    link = bpf_map__attach_struct_ops(skel->maps.testmod_ops);
    ```
    This `libbpf` function does the heavy lifting. It takes the `struct_ops` map from our BPF skeleton (`skel->maps.testmod_ops`) and asks the kernel to link it to the corresponding `struct_ops` definition (which it finds by the name "bpf_testmod_ops"). If successful, the kernel's `reg` callback in our module is executed, and the function pointers in the kernel are now pointing to our BPF programs. The function returns a `bpf_link`, which represents the active attachment.

4.  **Triggering**: The `trigger_struct_ops` function simply opens the `/proc/bpf_testmod_trigger` file and writes a message to it. This action invokes the `trigger_write` handler in our kernel module, which in turn calls the BPF-implemented operations.

5.  **Cleanup**: When the user presses Ctrl-C, the `exiting` flag is set, the loop terminates, and `bpf_link__destroy(link)` is called. This is the counterpart to the attach step. It detaches the BPF programs, causing the kernel to call the `unreg` callback in our module. This cleans up the link and decrements the module's reference count, allowing it to be unloaded cleanly. If this step is skipped (e.g., by killing the process with `-9`), the module will remain "in use" until the kernel's garbage collection cleans up the link, which can take time.

## Compilation and Execution

Now that we have all three components—the kernel module, the BPF program, and the userspace loader—let's compile and run the example to see `struct_ops` in action.

### 1. Build the Kernel Module

First, navigate to the `module` directory and compile the kernel module. This requires having the kernel headers installed for your current kernel version.

```bash
cd module
make
cd ..
```

This will produce a `hello.ko` file, which is our compiled kernel module.

### 2. Load the Kernel Module

Load the module into the kernel using `insmod`. This will register our `bpf_testmod_ops` struct_ops type and create the `/proc/bpf_testmod_trigger` file.

```bash
sudo insmod module/hello.ko
```

You can verify that the module loaded successfully by checking the kernel log:

```bash
dmesg | tail -n 1
```

You should see a message like: `bpf_testmod loaded with struct_ops support`.

### 3. Build and Run the eBPF Application

Next, compile and run the userspace loader, which will also compile the BPF program.

```bash
make
sudo ./struct_ops
```

Upon running, the userspace application will:
1.  Load the BPF programs.
2.  Attach the BPF implementation to the `bpf_testmod_ops` struct_ops.
3.  Write to `/proc/bpf_testmod_trigger` to invoke the BPF functions.

You should see output in your terminal like this:

```
Successfully loaded and attached BPF struct_ops!
Triggering struct_ops callbacks...
Triggered struct_ops successfully! Check dmesg for output.

Press Ctrl-C to exit...
Triggered struct_ops again...
```

### 4. Check the Kernel Log for BPF Output

While the userspace program is running, open another terminal and watch the kernel log to see the output from our BPF programs.

```bash
sudo dmesg -w
```

Every time the proc file is written to, you will see messages printed by the BPF programs via `bpf_printk`:

```
[ ... ] bpf_testmod_ops registered
[ ... ] Calling struct_ops callbacks:
[ ... ] BPF test_1 called!
[ ... ] test_1() returned: 42
[ ... ] BPF test_2 called: 10 + 20 = 30
[ ... ] test_2(10, 20) returned: 30
[ ... ] BPF test_3 called with buffer length 21
[ ... ] Buffer content: 'Hell'
[ ... ] Full buffer: Hello from userspace!
[ ... ] test_3() called with buffer
```

This output confirms that the calls from the kernel module are being correctly dispatched to our BPF programs.

### 5. Clean Up

When you are finished, press `Ctrl-C` in the terminal running `./struct_ops`. The program will gracefully detach the BPF link. Then, you can unload the kernel module.

```bash
sudo rmmod hello
```

Finally, clean up the build artifacts:

```bash
make clean
cd module
make clean
```

**Note on Unloading the Module**: Gracefully stopping the userspace program is important. It ensures `bpf_link__destroy()` is called, which allows the kernel module's reference count to be decremented. If the userspace process is killed abruptly (e.g., with `kill -9`), the kernel module may remain "in use," and `rmmod` will fail until the BPF link is garbage collected by the kernel, which can take some time.

## Troubleshooting Common Issues

When working with advanced features like `struct_ops`, which involve kernel modules, BTF, and the BPF verifier, you may encounter some tricky issues. This section covers common problems and their solutions, based on the development process of this example.

### Issue 1: Failed to find BTF for `struct_ops`

**Symptom:** The userspace loader fails with an error like:

```
libbpf: failed to find BTF info for struct_ops/bpf_testmod_ops
Failed to attach struct_ops
```

**Root Cause:** This error means the kernel module (`hello.ko`) was compiled without the necessary BTF (BPF Type Format) information. The BPF system relies on BTF to understand the structure and types defined in the module, which is essential for linking the BPF program to the `struct_ops`.

**Solution:**

1.  **Ensure `vmlinux` with BTF is available:** The kernel build system needs access to the `vmlinux` file corresponding to your running kernel to generate BTF for external modules. This file is often not available by default. You may need to copy it from `/sys/kernel/btf/vmlinux` or build it from your kernel source. A common location for the build system to look is `/lib/modules/$(uname -r)/build/vmlinux`.

2.  **Ensure `pahole` is up-to-date:** BTF generation depends on the `pahole` tool (part of the `dwarves` package). Older versions of `pahole` may lack the features needed for modern BTF generation. Ensure you have `pahole` v1.16 or newer. If your distribution's version is too old, you may need to compile it from source.

3.  **Rebuild the module:** After ensuring the dependencies are met, rebuild the kernel module. The `Makefile` for this example already includes the `-g` flag, which instructs the compiler to generate debug information that `pahole` uses to create BTF.

You can verify that BTF information is present in your module with `readelf`:

```bash
readelf -S module/hello.ko | grep .BTF
```

You should see sections named `.BTF` and `.BTF.ext`, indicating that BTF data has been embedded.

### Issue 2: Kernel Panic on Module Load

**Symptom:** The system crashes (kernel panic) immediately after you run `sudo insmod hello.ko`. The `dmesg` log might show a `NULL pointer dereference` inside `register_bpf_struct_ops`.

**Root Cause:** The kernel's `struct_ops` registration logic expects certain callback pointers in the `bpf_struct_ops` structure to be non-NULL. In older kernel versions or certain configurations, if callbacks like `.verifier_ops`, `.init`, or `.init_member` are missing, the kernel may dereference a NULL pointer, causing a panic. The kernel's code doesn't always perform defensive NULL checks.

**Solution:** Always provide all required callbacks in your `bpf_struct_ops` definition, even if they are just empty functions.

```c
// In module/hello.c
static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
    .is_valid_access = bpf_testmod_ops_is_valid_access,
    .get_func_proto = bpf_testmod_ops_get_func_proto,
};

static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,  // REQUIRED
	.init = bpf_testmod_ops_init,              // REQUIRED
	.init_member = bpf_testmod_ops_init_member, // REQUIRED
	.reg = bpf_testmod_ops_reg,
	.unreg = bpf_testmod_ops_unreg,
	/* ... */
};
```

By explicitly defining these callbacks, you prevent the kernel from attempting to call a NULL function pointer.

### Issue 3: BPF Program Fails to Load with "Invalid Argument"

**Symptom:** The userspace loader fails with an error indicating that a BPF helper function is not allowed.

```
libbpf: prog 'bpf_testmod_test_1': BPF program load failed: Invalid argument
program of this type cannot use helper bpf_trace_printk#6
```

**Root Cause:** BPF programs of type `struct_ops` run in a different kernel context than tracing programs (like kprobes or tracepoints). As a result, they are subject to a different, often more restrictive, set of allowed helper functions. The `bpf_trace_printk` helper (which `bpf_printk` is a macro for) is a tracing helper and is not allowed by default in `struct_ops` programs.

**Solution:** While you can't use `bpf_printk` by default, you can explicitly allow it for your `struct_ops` type. This is done in the kernel module by implementing the `.get_func_proto` callback in your `bpf_verifier_ops`.

```c
// In module/hello.c
static const struct bpf_func_proto *
bpf_testmod_ops_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	/* Use base func proto which includes trace_printk and other basic helpers */
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
	.get_func_proto = bpf_testmod_ops_get_func_proto, // Add this line
};
```

The `bpf_base_func_proto` function provides access to a set of common, basic helpers, including `bpf_trace_printk`. By adding this to our verifier operations, we tell the BPF verifier that programs attached to `bpf_testmod_ops` are permitted to use these helpers. This makes debugging with `bpf_printk` possible.

## Summary

In this tutorial, we explored the powerful capabilities of BPF `struct_ops` by moving beyond common examples. We demonstrated a robust pattern for extending the kernel: creating a minimal kernel module to define a new, BPF-programmable subsystem interface, and then providing the full, complex implementation in a safe, updatable BPF program. This approach combines the extensibility of kernel modules with the safety and flexibility of eBPF.

We saw how the kernel module registers a `struct_ops` type, how the BPF program implements the required functions, and how a userspace loader attaches this implementation and triggers its execution. This architecture opens the door to implementing a wide range of kernel-level features in BPF, from custom network protocols and security policies to new filesystem behaviors, all while maintaining system stability and avoiding the need to recompile the kernel.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- **Kernel Source for `struct_ops`**: The implementation can be found in `kernel/bpf/bpf_struct_ops.c` in the Linux source tree.
- **Kernel Test Module for `struct_ops`**: The official kernel self-test module provides a reference implementation: `tools/testing/selftests/bpf/test_kmods/bpf_testmod.c`.
- **BPF Documentation**: The official BPF documentation in the kernel source: [https://www.kernel.org/doc/html/latest/bpf/](https://www.kernel.org/doc/html/latest/bpf/)
