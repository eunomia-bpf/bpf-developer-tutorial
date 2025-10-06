# eBPF Tutorial: Fixing Broken HID Devices Without Kernel Patches

Ever plugged in a new mouse or drawing tablet only to find it doesn't work quite right on Linux? Maybe the Y-axis is inverted, buttons are mapped wrong, or the device just feels broken. Traditionally, fixing these quirks meant writing a kernel driver, waiting weeks for review, and hoping your distro ships the fix sometime next year. By then, you've probably bought a different device.

This tutorial shows you a better way. We'll use HID-BPF to create a virtual mouse device and modify its input on the fly using eBPF. In minutes, not months, you'll see how to fix device quirks without touching the kernel. This is the same technology now shipping with 14+ device fixes in the mainline Linux kernel.

> The complete source code: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/49-hid>

## The HID Device Problem

HID (Human Interface Device) is a standard protocol for input devices like mice, keyboards, game controllers, and drawing tablets. The protocol is well-defined, but hardware vendors often implement it incorrectly or add quirks that don't follow the spec. When this happens on Linux, users suffer.

Let's say you buy a drawing tablet with an inverted Y-axis. When you move the stylus up, the cursor goes down. Or you get a mouse where buttons 4 and 5 report themselves as buttons 6 and 7, breaking your browser's back/forward navigation. These bugs are incredibly frustrating because the hardware works perfectly on other operating systems, but Linux sees the raw incorrect data.

The traditional fix requires writing a kernel driver or patching an existing one. You'd need to understand kernel development, submit patches to LKML, get them reviewed, wait for the next kernel release, and then wait again for your distribution to ship that kernel. For a user with broken hardware, this could take six months or more. Most users just return the device or dual-boot to another OS.

## Enter HID-BPF

HID-BPF changes everything by letting you fix devices in userspace with eBPF programs loaded into the kernel. The programs hook into the HID subsystem using BPF struct_ops, intercepting HID reports before applications see them. You can modify the report data, fix descriptor issues, or even block certain operations entirely.

This approach gives you the safety of kernel code (the BPF verifier ensures no crashes) with the flexibility of userspace development. Write your fix, load it, test it immediately. If it works, package it and ship to users the same day. The Linux kernel already includes HID-BPF fixes for 14 different devices, including:

- Microsoft Xbox Elite 2 controller
- Huion drawing tablets (Kamvas Pro 19, Inspiroy 2-S)
- XPPen tablets (Artist24, ArtistPro16Gen2, DecoMini4)
- Wacom ArtPen
- Thrustmaster TCA Yoke Boeing
- IOGEAR Kaliber MMOmentum mouse
- Various other mice and gaming peripherals

Each fix is typically 100-300 lines of BPF code instead of a full kernel driver. The ecosystem has grown rapidly, with the udev-hid-bpf project providing scaffolding to make writing these fixes even easier.

## Why Virtual Devices for Learning?

This tutorial uses a virtual HID device created through uhid (userspace HID). You might wonder why we don't just attach to your real mouse. Virtual devices are perfect for learning because they give you:

- **Complete control**: We send exactly the events we want, when we want
- **Repeatability**: Same test events produce same results every time
- **Safety**: Can't accidentally break your real input devices
- **No hardware required**: Works on any Linux system with kernel 6.3+

The virtual mouse we create reports movement events just like a real USB mouse. Our BPF program intercepts these events and modifies them before the input subsystem sees them. In our example, we'll double all movement, but the same technique applies to fixing inverted axes, remapping buttons, or any other transformation.

## Implementation: The Virtual HID Device

Let's look at the complete implementation, starting with the userspace code that creates our virtual mouse. This uses the uhid interface, which allows userspace programs to create kernel HID devices.

### Creating the Virtual Mouse

```c
// SPDX-License-Identifier: GPL-2.0
/* Create virtual HID mouse and modify its input with BPF */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/uhid.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "hid-input-modifier.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

/* Simple mouse report descriptor */
static unsigned char rdesc[] = {
	0x05, 0x01,	/* USAGE_PAGE (Generic Desktop) */
	0x09, 0x02,	/* USAGE (Mouse) */
	0xa1, 0x01,	/* COLLECTION (Application) */
	0x09, 0x01,	/*   USAGE (Pointer) */
	0xa1, 0x00,	/*   COLLECTION (Physical) */
	0x05, 0x09,	/*     USAGE_PAGE (Button) */
	0x19, 0x01,	/*     USAGE_MINIMUM (Button 1) */
	0x29, 0x03,	/*     USAGE_MAXIMUM (Button 3) */
	0x15, 0x00,	/*     LOGICAL_MINIMUM (0) */
	0x25, 0x01,	/*     LOGICAL_MAXIMUM (1) */
	0x95, 0x03,	/*     REPORT_COUNT (3) */
	0x75, 0x01,	/*     REPORT_SIZE (1) */
	0x81, 0x02,	/*     INPUT (Data,Var,Abs) */
	0x95, 0x01,	/*     REPORT_COUNT (1) */
	0x75, 0x05,	/*     REPORT_SIZE (5) */
	0x81, 0x03,	/*     INPUT (Cnst,Var,Abs) */
	0x05, 0x01,	/*     USAGE_PAGE (Generic Desktop) */
	0x09, 0x30,	/*     USAGE (X) */
	0x09, 0x31,	/*     USAGE (Y) */
	0x15, 0x81,	/*     LOGICAL_MINIMUM (-127) */
	0x25, 0x7f,	/*     LOGICAL_MAXIMUM (127) */
	0x75, 0x08,	/*     REPORT_SIZE (8) */
	0x95, 0x02,	/*     REPORT_COUNT (2) */
	0x81, 0x06,	/*     INPUT (Data,Var,Rel) */
	0xc0,		/*   END_COLLECTION */
	0xc0		/* END_COLLECTION */
};
```

This report descriptor defines a standard USB mouse with three buttons and relative X/Y movement. The descriptor uses HID descriptor language to tell the kernel what data the device will send. Each report will contain three bytes: button states in byte 0, X movement in byte 1, and Y movement in byte 2.

The uhid interface requires us to write this descriptor when creating the device:

```c
static int create_uhid_device(void)
{
	struct uhid_event ev;
	int fd;

	fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open /dev/uhid: %m\n");
		return -errno;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char*)ev.u.create.name, "BPF Virtual Mouse");
	ev.u.create.rd_data = rdesc;
	ev.u.create.rd_size = sizeof(rdesc);
	ev.u.create.bus = BUS_USB;
	ev.u.create.vendor = 0x15d9;
	ev.u.create.product = 0x0a37;
	ev.u.create.version = 0;
	ev.u.create.country = 0;

	if (uhid_write(fd, &ev)) {
		close(fd);
		return -1;
	}

	printf("Created virtual HID device\n");
	return fd;
}
```

When this succeeds, the kernel creates a new HID device that appears in `/sys/bus/hid/devices/` just like a real USB mouse. We can then attach our BPF program to intercept its events.

### Sending Synthetic Mouse Events

With the virtual device created, we can inject mouse movement events:

```c
static int send_mouse_event(int fd, __s8 x, __s8 y)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = 3;
	ev.u.input.data[0] = 0;	/* Buttons */
	ev.u.input.data[1] = x;	/* X movement */
	ev.u.input.data[2] = y;	/* Y movement */

	return uhid_write(fd, &ev);
}
```

Each event sends three bytes matching our report descriptor. Byte 0 contains button states (all zeros means no buttons pressed), byte 1 is X movement as a signed 8-bit value, and byte 2 is Y movement. The kernel processes this exactly like it would process events from a real USB mouse.

## The BPF Program: Intercepting HID Events

Now for the interesting part: the BPF program that modifies mouse input. This runs in the kernel, attached to the HID device via struct_ops.

```c
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
```

The program hooks into `hid_device_event`, which the kernel calls for every HID input report. The `hctx` parameter provides context about the device and report. We call `hid_bpf_get_data()` to get a pointer to the actual report data, which we can read and modify.

The report data follows the format defined by our descriptor. For our simple mouse, byte 2 contains X movement and byte 3 contains Y movement, both as signed 8-bit integers. We read these values, double them, and write them back. The kernel will then pass the modified report to the input subsystem, where applications see the doubled movement.

The `bpf_printk()` call logs our modifications to the kernel trace buffer. This is invaluable for debugging, letting you see exactly how the BPF program transforms each event.

### Understanding struct_ops

The `SEC(".struct_ops.link")` section creates a struct_ops map that connects our BPF program to the HID subsystem. Struct_ops is a BPF feature that lets you implement kernel interfaces in BPF code. For HID, this means providing callbacks that the kernel invokes during HID processing.

The `hid_bpf_ops` structure defines which callbacks we're implementing. We only need `hid_device_event` to intercept reports, but HID-BPF also supports:

- `hid_rdesc_fixup`: Modify the report descriptor itself
- `hid_hw_request`: Intercept requests to the device
- `hid_hw_output_report`: Intercept output reports

The userspace code loads this BPF program and attaches it by setting the `hid_id` field to our virtual device's ID, then calling `bpf_map__attach_struct_ops()`.

## Putting It All Together

The main function orchestrates everything:

```c
int main(int argc, char **argv)
{
	struct hid_input_modifier_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int err, hid_id;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Create virtual HID device */
	uhid_fd = create_uhid_device();
	if (uhid_fd < 0)
		return 1;

	/* Find the HID device ID */
	hid_id = find_hid_device();
	if (hid_id < 0) {
		fprintf(stderr, "Cannot find virtual HID device\n");
		destroy_uhid_device(uhid_fd);
		return 1;
	}

	/* Open and load BPF program */
	skel = hid_input_modifier_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		destroy_uhid_device(uhid_fd);
		return 1;
	}

	skel->struct_ops.input_modifier->hid_id = hid_id;

	err = hid_input_modifier_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Attach BPF program */
	link = bpf_map__attach_struct_ops(skel->maps.input_modifier);
	if (!link) {
		fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	printf("BPF program attached successfully!\n");
	printf("The BPF program will DOUBLE all mouse movements\n\n");
	printf("Sending test mouse events:\n");

	/* Send some test events */
	for (int i = 0; i < 5 && !exiting; i++) {
		__s8 x = 10, y = 20;
		printf("Sending: X=%d, Y=%d (BPF will double to X=%d, Y=%d)\n",
		       x, y, x*2, y*2);
		send_mouse_event(uhid_fd, x, y);
		sleep(1);
	}

	printf("\nPress Ctrl-C to exit...\n");
	while (!exiting)
		sleep(1);

cleanup:
	bpf_link__destroy(link);
	hid_input_modifier_bpf__destroy(skel);
	destroy_uhid_device(uhid_fd);
	return err < 0 ? -err : 0;
}
```

The flow is straightforward: create virtual device, find its ID, load BPF program with that ID, attach the program, send test events. The BPF program runs in the kernel, intercepting and modifying each event before it reaches the input layer.

## Understanding HID Report Format

To modify HID data effectively, you need to understand the report format. Our simple mouse uses this structure:

```
Byte 0: Report ID (always 0 for our single report type)
Byte 1: Button states
        bit 0: Left button
        bit 1: Right button
        bit 2: Middle button
        bits 3-7: Unused
Byte 2: X movement (signed 8-bit, -127 to +127)
Byte 3: Y movement (signed 8-bit, -127 to +127)
```

Real devices often have more complex reports with multiple report IDs, more buttons, wheel data, and additional axes. You'd determine the format by examining the device's report descriptor, which you can read from sysfs or by looking at existing kernel drivers for similar devices.

## Compilation and Execution

Building the example is simple. Navigate to the tutorial directory and run make:

```bash
cd src/49-hid
make
```

This compiles both the BPF program and userspace loader, producing the `hid-input-modifier` executable. Run it with sudo since HID-BPF requires CAP_BPF and CAP_SYS_ADMIN capabilities:

```bash
sudo ./hid-input-modifier
```

You'll see output like:

```
Created virtual HID device
Found HID device ID: 8
BPF program attached successfully!
The BPF program will DOUBLE all mouse movements

Sending test mouse events:
Sending: X=10, Y=20 (BPF will double to X=20, Y=40)
Sending: X=10, Y=20 (BPF will double to X=20, Y=40)
Sending: X=10, Y=20 (BPF will double to X=20, Y=40)
Sending: X=10, Y=20 (BPF will double to X=20, Y=40)
Sending: X=10, Y=20 (BPF will double to X=20, Y=40)

Press Ctrl-C to exit...
```

In another terminal, you can view the BPF trace output to see the modifications in action:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

This shows the `bpf_printk()` messages from the BPF program, confirming that events are being intercepted and modified.

## Experimenting with Modifications

The beauty of this approach is how easy it is to experiment. Want to reverse mouse direction instead of doubling it? Just change the BPF code:

```c
/* Reverse direction */
x = -x;
y = -y;
```

Or maybe swap the axes so horizontal becomes vertical:

```c
/* Swap axes */
__s8 temp = x;
x = y;
y = temp;
```

You could implement dead zone filtering for aging joysticks:

```c
/* Ignore small movements */
if (x > -5 && x < 5) x = 0;
if (y > -5 && y < 5) y = 0;
```

Or fix the common inverted Y-axis problem on drawing tablets:

```c
/* Invert Y axis only */
y = -y;
```

After any change, just run `make` and execute again. No kernel rebuild, no module signing, no waiting. This is the power of HID-BPF.


## Summary

HID-BPF transforms how we handle quirky input devices on Linux. Instead of kernel patches that take months to reach users, we can write small BPF programs that fix devices immediately. The programs run safely in the kernel thanks to the BPF verifier, and they can be packaged and distributed like any other software.

This tutorial showed you the fundamentals by creating a virtual mouse and modifying its input. You saw how uhid lets userspace create HID devices, how BPF struct_ops connects programs to the HID subsystem, and how simple transformations can fix common device problems. The same techniques apply to real hardware, whether you're fixing an inverted tablet axis or implementing custom game controller mappings.

The Linux kernel already ships with 14 HID-BPF device fixes, and that number grows with each release. Projects like udev-hid-bpf are making it even easier to write and distribute fixes. If you have a broken HID device, you now have the tools to fix it yourself, in hours instead of months.

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## References

- [Linux HID-BPF Documentation](https://docs.kernel.org/hid/hid-bpf.html)
- [udev-hid-bpf Project](https://gitlab.freedesktop.org/libevdev/udev-hid-bpf)
- [Kernel HID-BPF Device Fixes](https://github.com/torvalds/linux/tree/master/drivers/hid/bpf/progs)
- [UHID Kernel Documentation](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [HID Usage Tables](https://www.usb.org/document-library/device-class-definition-hid-111)
- [Who-T Blog: udev-hid-bpf Quickstart](https://who-t.blogspot.com/2024/04/udev-hid-bpf-quickstart-tooling-to-fix.html)
