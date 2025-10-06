/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HID_BPF_DEFS_H
#define __HID_BPF_DEFS_H

/* HID BPF context structure */
struct hid_bpf_ctx {
	struct hid_device *hid;
	__u32 allocated_size;
	union {
		__s32 retval;
		__s32 size;
	};
};

/* HID BPF operations structure */
struct hid_bpf_ops {
	int hid_id;
	__u32 flags;
	int (*hid_device_event)(struct hid_bpf_ctx *ctx, enum hid_report_type report_type);
	int (*hid_rdesc_fixup)(struct hid_bpf_ctx *ctx);
	int (*hid_hw_request)(struct hid_bpf_ctx *ctx, unsigned char reportnum,
			      enum hid_report_type rtype, enum hid_class_request reqtype,
			      __u64 source);
	int (*hid_hw_output_report)(struct hid_bpf_ctx *ctx, __u64 source);
};

#endif /* __HID_BPF_DEFS_H */
