/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TC_FLOW_INDEX_EXPERIMENTAL_H
#define __TC_FLOW_INDEX_EXPERIMENTAL_H

#include <bpf/bpf_core_read.h>

#define __contains(name, node) \
	__attribute__((btf_decl_tag("contains:" #name ":" #node)))

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
#define bpf_obj_new(type) \
	((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))

extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

extern void *bpf_refcount_acquire_impl(void *kptr, void *meta) __ksym;
#define bpf_refcount_acquire(kptr) \
	bpf_refcount_acquire_impl(kptr, NULL)

extern int bpf_rbtree_add_impl(struct bpf_rb_root *root,
			       struct bpf_rb_node *node,
			       bool (*less)(struct bpf_rb_node *,
					    const struct bpf_rb_node *),
			       void *meta, __u64 off) __ksym;
#define bpf_rbtree_add(root, node, less) \
	bpf_rbtree_add_impl(root, node, less, NULL, 0)

extern struct bpf_rb_node *
bpf_rbtree_remove(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_first(struct bpf_rb_root *root) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_root(struct bpf_rb_root *root) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_left(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *
bpf_rbtree_right(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;

#endif /* __TC_FLOW_INDEX_EXPERIMENTAL_H */
