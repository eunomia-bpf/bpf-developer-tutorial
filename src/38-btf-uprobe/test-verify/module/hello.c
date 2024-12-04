#include <linux/init.h>   // Macros for module initialization
#include <linux/module.h> // Core header for loading modules
#include <linux/kernel.h> // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

__bpf_kfunc struct data *my_alloc_data(void);
__bpf_kfunc void my_free_data(struct data *d);

/* Define a kfunc function */
__bpf_kfunc_start_defs();

/*Auto generated code start*/
/*This type definition can be get from the BTF information of the userspace program*/
struct deep_memory_block
{
    int a;
    char b[10];
};

struct inner_memory_block
{
    int a;
    char b[10];
    struct deep_memory_block *deep;
};

struct data
{
    int a;
    int b;
    int c;
    int d;
    // represent a pointer to a memory block
    struct inner_memory_block *inner;
};

__bpf_kfunc struct data *my_alloc_data(void)
{
    // here we only use it for verification
    return NULL;
}

__bpf_kfunc void my_free_data(struct data *d)
{
    // here we only use it for verification
    return;
}
/*Auto generated code end*/

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, my_alloc_data, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, my_free_data, KF_RELEASE)
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
    if (ret)
    {
        pr_err("bpf_kfunc_example: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: Module loaded successfully\n");
    return 0; // Return 0 if successful
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

MODULE_LICENSE("GPL");                 // License type (GPL)
MODULE_AUTHOR("Your Name");            // Module author
MODULE_DESCRIPTION("A simple module"); // Module description
MODULE_VERSION("1.0");                 // Module version
