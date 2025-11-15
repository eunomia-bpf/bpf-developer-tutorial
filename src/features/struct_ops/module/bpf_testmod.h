#ifndef _BPF_TESTMOD_H
#define _BPF_TESTMOD_H

/* Shared struct_ops definition between kernel module and BPF program */
struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	int (*test_3)(const char *buf, int len);
};

#endif /* _BPF_TESTMOD_H */