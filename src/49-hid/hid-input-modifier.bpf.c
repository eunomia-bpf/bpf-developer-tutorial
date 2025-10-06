// SPDX-License-Identifier: GPL-2.0
/* HID-BPF example: Modify input data from virtual HID device
 *
 * This program doubles the X and Y movement of a mouse.
 * Works with the virtual HID device created by the userspace program.
 */

#include "vmlinux.h"
#include "hid_bpf_defs.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

SEC("struct_ops/hid_device_event")
int BPF_PROG(hid_double_movement, struct hid_bpf_ctx *hctx, enum hid_report_type type)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, 9);
	__s8 x, y;

	if (!data)
		return 0;

	/* Mouse HID report format (simplified):
	 * Byte 0: Report ID
	 * Byte 1: Buttons
	 * Byte 2: X movement (signed byte)
	 * Byte 3: Y movement (signed byte)
	 */

	x = (__s8)data[2];
	y = (__s8)data[3];

	/* Double the movement */
	x *= 2;
	y *= 2;

	data[2] = (__u8)x;
	data[3] = (__u8)y;

	bpf_printk("Modified: X=%d Y=%d -> X=%d Y=%d",
		   (__s8)data[2]/2, (__s8)data[3]/2,
		   (__s8)data[2], (__s8)data[3]);

	return 0;
}

SEC(".struct_ops.link")
struct hid_bpf_ops input_modifier = {
	.hid_device_event = (void *)hid_double_movement,
};

char _license[] SEC("license") = "GPL";
