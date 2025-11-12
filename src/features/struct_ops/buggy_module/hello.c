#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/* Define our custom struct_ops operations */
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	void (*test_3)(const char *buf, int len);
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

static void bpf_testmod_ops__test_3(const char *buf, int len)
{
}

/* CFI stubs structure */
static struct bpf_testmod_ops __bpf_ops_bpf_testmod_ops = {
	.test_1 = bpf_testmod_ops__test_1,
	.test_2 = bpf_testmod_ops__test_2,
	.test_3 = bpf_testmod_ops__test_3,
};

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

/* BUGGY Struct ops definition - MISSING REQUIRED CALLBACKS!
 * This will cause kernel NULL pointer dereferences in:
 * 1. kernel/bpf/bpf_struct_ops.c:457  - st_ops->init(btf)
 * 2. kernel/bpf/bpf_struct_ops.c:753  - st_ops->init_member()
 * 3. kernel/bpf/verifier.c:24011      - env->ops = st_ops->verifier_ops
 *
 * WARNING: Loading this module WILL cause a kernel panic!
 */
static struct bpf_struct_ops bpf_testmod_ops_struct_ops = {
	/* MISSING: .verifier_ops = &bpf_testmod_verifier_ops,  ← NULL pointer dereference! */
	/* MISSING: .init = bpf_testmod_ops_init,              ← NULL pointer dereference! */
	/* MISSING: .init_member = bpf_testmod_ops_init_member, ← NULL pointer dereference! */
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

	/* Register the struct_ops - THIS WILL CAUSE KERNEL PANIC! */
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
MODULE_DESCRIPTION("BPF struct_ops BUGGY test module - DO NOT LOAD!");
MODULE_VERSION("0.1-buggy");
