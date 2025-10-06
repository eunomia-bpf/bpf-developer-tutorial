// SPDX-License-Identifier: GPL-2.0
/* Create virtual HID mouse and modify its input with BPF
 *
 * This program:
 * 1. Creates a virtual HID mouse using uhid
 * 2. Attaches a BPF program that doubles movement
 * 3. Sends synthetic mouse events
 * 4. Shows the BPF modification in action
 */

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

static int uhid_fd = -1;

static int uhid_write(int fd, const struct uhid_event *ev)
{
	ssize_t ret;
	ret = write(fd, ev, sizeof(*ev));
	if (ret < 0) {
		fprintf(stderr, "Cannot write to uhid: %m\n");
		return -errno;
	} else if (ret != sizeof(*ev)) {
		fprintf(stderr, "Wrong size written to uhid: %zd != %zu\n",
			ret, sizeof(*ev));
		return -EFAULT;
	}
	return 0;
}

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

static int destroy_uhid_device(int fd)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	uhid_write(fd, &ev);
	close(fd);
	printf("Destroyed virtual HID device\n");
	return 0;
}

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

/* Find our virtual HID device */
static int find_hid_device(void)
{
	char path[256];
	FILE *fp;
	int i;

	/* Wait a bit for device to appear */
	sleep(1);

	for (i = 0; i < 100; i++) {
		snprintf(path, sizeof(path), "/sys/bus/hid/devices/0003:15D9:0A37.%04X/uevent", i);
		fp = fopen(path, "r");
		if (fp) {
			fclose(fp);
			printf("Found HID device ID: %d\n", i);
			return i;
		}
	}

	return -1;
}

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
	printf("View trace with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

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
