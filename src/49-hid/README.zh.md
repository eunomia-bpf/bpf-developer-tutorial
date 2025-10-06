# eBPF 教程：无需内核补丁修复故障的 HID 设备

你是否遇到过这样的情况：插入新鼠标或绘图板后发现在 Linux 上无法正常工作?也许 Y 轴反了,按钮映射错了,或者设备感觉完全坏了。传统的解决方法需要编写内核驱动,等待数周的审查,然后希望你的发行版能在明年某个时候提供这个修复。到那时,你可能已经买了另一个设备。

本教程将向你展示更好的方法。我们将使用 HID-BPF 创建虚拟鼠标设备,并使用 eBPF 动态修改其输入。在几分钟内,而不是几个月,你就能看到如何在不修改内核的情况下修复设备问题。这项技术已经在主线 Linux 内核中提供了 14+ 个设备修复。

> 完整源代码: <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/49-hid>

## HID 设备问题

HID(人机接口设备)是鼠标、键盘、游戏控制器和绘图板等输入设备的标准协议。该协议定义明确,但硬件供应商经常实现不正确或添加不符合规范的特性。当这种情况发生在 Linux 上时,用户就会遭殃。

假设你买了一个 Y 轴反转的绘图板。当你向上移动触控笔时,光标向下移动。或者你买了一个鼠标,其中按钮 4 和 5 报告为按钮 6 和 7,破坏了浏览器的后退/前进导航。这些错误非常令人沮丧,因为硬件在其他操作系统上完美运行,但 Linux 看到的是原始的错误数据。

传统的修复方法需要编写内核驱动或修补现有驱动。你需要了解内核开发,向 LKML 提交补丁,让它们被审查,等待下一个内核版本,然后再等待你的发行版发布该内核。对于硬件有问题的用户来说,这可能需要六个月或更长时间。大多数用户只是退回设备或双启动到另一个操作系统。

## HID-BPF 登场

HID-BPF 通过让你使用加载到内核的 eBPF 程序在用户空间修复设备来改变一切。这些程序使用 BPF struct_ops 挂钩到 HID 子系统,在应用程序看到 HID 报告之前拦截它们。你可以修改报告数据、修复描述符问题,甚至完全阻止某些操作。

这种方法为你提供了内核代码的安全性(BPF 验证器确保不会崩溃)和用户空间开发的灵活性。编写修复、加载它、立即测试。如果有效,打包并在同一天发布给用户。Linux 内核已经包含了针对 14 种不同设备的 HID-BPF 修复,包括:

- Microsoft Xbox Elite 2 控制器
- Huion 绘图板(Kamvas Pro 19, Inspiroy 2-S)
- XPPen 数位板(Artist24, ArtistPro16Gen2, DecoMini4)
- Wacom ArtPen
- Thrustmaster TCA Yoke Boeing
- IOGEAR Kaliber MMOmentum 鼠标
- 各种其他鼠标和游戏外设

每个修复通常是 100-300 行 BPF 代码,而不是完整的内核驱动。随着 udev-hid-bpf 项目提供了脚手架,使编写这些修复变得更加容易,生态系统迅速发展。

## 为什么使用虚拟设备进行学习?

本教程使用通过 uhid(用户空间 HID)创建的虚拟 HID 设备。你可能想知道为什么我们不直接附加到你的真实鼠标。虚拟设备非常适合学习,因为它们为你提供:

- **完全控制**: 我们精确地发送我们想要的事件,何时发送
- **可重复性**: 相同的测试事件每次都产生相同的结果
- **安全性**: 不会意外破坏你的真实输入设备
- **无需硬件**: 在任何具有内核 6.3+ 的 Linux 系统上都可以工作

我们创建的虚拟鼠标报告移动事件就像真实的 USB 鼠标一样。我们的 BPF 程序在输入子系统看到这些事件之前拦截并修改它们。在我们的例子中,我们将所有移动加倍,但同样的技术适用于修复反转的轴、重新映射按钮或任何其他转换。

## 实现:虚拟 HID 设备

让我们看看完整的实现,从创建虚拟鼠标的用户空间代码开始。这使用 uhid 接口,允许用户空间程序创建内核 HID 设备。

### 创建虚拟鼠标

```c
// SPDX-License-Identifier: GPL-2.0
/* 创建虚拟 HID 鼠标并使用 BPF 修改其输入 */

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

/* 简单的鼠标报告描述符 */
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

此报告描述符定义了具有三个按钮和相对 X/Y 移动的标准 USB 鼠标。描述符使用 HID 描述符语言告诉内核设备将发送什么数据。每个报告将包含三个字节:字节 0 中的按钮状态、字节 1 中的 X 移动和字节 2 中的 Y 移动。

uhid 接口要求我们在创建设备时写入此描述符:

```c
static int create_uhid_device(void)
{
	struct uhid_event ev;
	int fd;

	fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "无法打开 /dev/uhid: %m\n");
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

	printf("已创建虚拟 HID 设备\n");
	return fd;
}
```

成功后,内核会创建一个新的 HID 设备,就像真实的 USB 鼠标一样出现在 `/sys/bus/hid/devices/` 中。然后我们可以附加 BPF 程序来拦截其事件。

### 发送合成鼠标事件

创建虚拟设备后,我们可以注入鼠标移动事件:

```c
static int send_mouse_event(int fd, __s8 x, __s8 y)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = 3;
	ev.u.input.data[0] = 0;	/* 按钮 */
	ev.u.input.data[1] = x;	/* X 移动 */
	ev.u.input.data[2] = y;	/* Y 移动 */

	return uhid_write(fd, &ev);
}
```

每个事件发送三个字节,与我们的报告描述符匹配。字节 0 包含按钮状态(全零表示未按下任何按钮),字节 1 是作为有符号 8 位值的 X 移动,字节 2 是 Y 移动。内核处理此事件的方式与处理来自真实 USB 鼠标的事件完全相同。

## BPF 程序:拦截 HID 事件

现在是有趣的部分:修改鼠标输入的 BPF 程序。这在内核中运行,通过 struct_ops 附加到 HID 设备。

```c
// SPDX-License-Identifier: GPL-2.0
/* HID-BPF 示例:修改来自虚拟 HID 设备的输入数据
 *
 * 此程序将鼠标的 X 和 Y 移动加倍。
 * 与用户空间程序创建的虚拟 HID 设备一起使用。
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

	/* 鼠标 HID 报告格式(简化):
	 * 字节 0: 报告 ID
	 * 字节 1: 按钮
	 * 字节 2: X 移动(有符号字节)
	 * 字节 3: Y 移动(有符号字节)
	 */

	x = (__s8)data[2];
	y = (__s8)data[3];

	/* 移动加倍 */
	x *= 2;
	y *= 2;

	data[2] = (__u8)x;
	data[3] = (__u8)y;

	bpf_printk("已修改: X=%d Y=%d -> X=%d Y=%d",
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

程序挂钩到 `hid_device_event`,内核为每个 HID 输入报告调用它。`hctx` 参数提供有关设备和报告的上下文。我们调用 `hid_bpf_get_data()` 来获取指向实际报告数据的指针,我们可以读取和修改它。

报告数据遵循我们的描述符定义的格式。对于我们的简单鼠标,字节 2 包含 X 移动,字节 3 包含 Y 移动,均为有符号 8 位整数。我们读取这些值,将它们加倍,然后写回。然后内核将修改后的报告传递给输入子系统,应用程序看到加倍的移动。

`bpf_printk()` 调用将我们的修改记录到内核跟踪缓冲区。这对调试非常宝贵,让你准确地看到 BPF 程序如何转换每个事件。

### 理解 struct_ops

`SEC(".struct_ops.link")` 部分创建一个 struct_ops 映射,将我们的 BPF 程序连接到 HID 子系统。Struct_ops 是一个 BPF 功能,允许你在 BPF 代码中实现内核接口。对于 HID,这意味着提供内核在 HID 处理期间调用的回调。

`hid_bpf_ops` 结构定义了我们正在实现的回调。我们只需要 `hid_device_event` 来拦截报告,但 HID-BPF 还支持:

- `hid_rdesc_fixup`: 修改报告描述符本身
- `hid_hw_request`: 拦截对设备的请求
- `hid_hw_output_report`: 拦截输出报告

用户空间代码加载此 BPF 程序并通过将 `hid_id` 字段设置为我们的虚拟设备的 ID 来附加它,然后调用 `bpf_map__attach_struct_ops()`。

## 综合应用

主函数协调一切:

```c
int main(int argc, char **argv)
{
	struct hid_input_modifier_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int err, hid_id;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 创建虚拟 HID 设备 */
	uhid_fd = create_uhid_device();
	if (uhid_fd < 0)
		return 1;

	/* 查找 HID 设备 ID */
	hid_id = find_hid_device();
	if (hid_id < 0) {
		fprintf(stderr, "无法找到虚拟 HID 设备\n");
		destroy_uhid_device(uhid_fd);
		return 1;
	}

	/* 打开并加载 BPF 程序 */
	skel = hid_input_modifier_bpf__open();
	if (!skel) {
		fprintf(stderr, "无法打开 BPF skeleton\n");
		destroy_uhid_device(uhid_fd);
		return 1;
	}

	skel->struct_ops.input_modifier->hid_id = hid_id;

	err = hid_input_modifier_bpf__load(skel);
	if (err) {
		fprintf(stderr, "无法加载 BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* 附加 BPF 程序 */
	link = bpf_map__attach_struct_ops(skel->maps.input_modifier);
	if (!link) {
		fprintf(stderr, "无法附加 BPF 程序: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	printf("BPF 程序附加成功!\n");
	printf("BPF 程序将使所有鼠标移动加倍\n\n");
	printf("发送测试鼠标事件:\n");

	/* 发送一些测试事件 */
	for (int i = 0; i < 5 && !exiting; i++) {
		__s8 x = 10, y = 20;
		printf("发送: X=%d, Y=%d (BPF 将加倍为 X=%d, Y=%d)\n",
		       x, y, x*2, y*2);
		send_mouse_event(uhid_fd, x, y);
		sleep(1);
	}

	printf("\n按 Ctrl-C 退出...\n");
	while (!exiting)
		sleep(1);

cleanup:
	bpf_link__destroy(link);
	hid_input_modifier_bpf__destroy(skel);
	destroy_uhid_device(uhid_fd);
	return err < 0 ? -err : 0;
}
```

流程很简单:创建虚拟设备、查找其 ID、使用该 ID 加载 BPF 程序、附加程序、发送测试事件。BPF 程序在内核中运行,在每个事件到达输入层之前拦截并修改它。

## 理解 HID 报告格式

要有效地修改 HID 数据,你需要理解报告格式。我们的简单鼠标使用此结构:

```
字节 0: 报告 ID(对于我们的单一报告类型始终为 0)
字节 1: 按钮状态
        位 0: 左键
        位 1: 右键
        位 2: 中键
        位 3-7: 未使用
字节 2: X 移动(有符号 8 位,-127 到 +127)
字节 3: Y 移动(有符号 8 位,-127 到 +127)
```

真实设备通常具有更复杂的报告,具有多个报告 ID、更多按钮、滚轮数据和其他轴。你可以通过检查设备的报告描述符来确定格式,可以从 sysfs 读取或查看类似设备的现有内核驱动。

## 编译和执行

构建示例很简单。导航到教程目录并运行 make:

```bash
cd src/49-hid
make
```

这会编译 BPF 程序和用户空间加载器,生成 `hid-input-modifier` 可执行文件。使用 sudo 运行它,因为 HID-BPF 需要 CAP_BPF 和 CAP_SYS_ADMIN 权限:

```bash
sudo ./hid-input-modifier
```

你会看到类似这样的输出:

```
已创建虚拟 HID 设备
找到 HID 设备 ID: 8
BPF 程序附加成功!
BPF 程序将使所有鼠标移动加倍

发送测试鼠标事件:
发送: X=10, Y=20 (BPF 将加倍为 X=20, Y=40)
发送: X=10, Y=20 (BPF 将加倍为 X=20, Y=40)
发送: X=10, Y=20 (BPF 将加倍为 X=20, Y=40)
发送: X=10, Y=20 (BPF 将加倍为 X=20, Y=40)
发送: X=10, Y=20 (BPF 将加倍为 X=20, Y=40)

按 Ctrl-C 退出...
```

在另一个终端中,你可以查看 BPF 跟踪输出以查看正在进行的修改:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

这显示了来自 BPF 程序的 `bpf_printk()` 消息,确认事件正在被拦截和修改。

## 实验修改

这种方法的美妙之处在于实验是多么容易。想要反转鼠标方向而不是加倍它?只需更改 BPF 代码:

```c
/* 反转方向 */
x = -x;
y = -y;
```

或者交换轴,使水平变为垂直:

```c
/* 交换轴 */
__s8 temp = x;
x = y;
y = temp;
```

你可以为老化的操纵杆实现死区过滤:

```c
/* 忽略小移动 */
if (x > -5 && x < 5) x = 0;
if (y > -5 && y < 5) y = 0;
```

或修复绘图板上常见的 Y 轴反转问题:

```c
/* 仅反转 Y 轴 */
y = -y;
```

任何更改后,只需运行 `make` 并再次执行。无需重建内核、无需模块签名、无需等待。这就是 HID-BPF 的力量。

## 总结

HID-BPF 改变了我们在 Linux 上处理古怪输入设备的方式。我们可以编写小型 BPF 程序立即修复设备,而不是需要数月才能到达用户的内核补丁。由于 BPF 验证器,程序在内核中安全运行,并且可以像任何其他软件一样打包和分发。

本教程通过创建虚拟鼠标并修改其输入向你展示了基础知识。你看到了 uhid 如何让用户空间创建 HID 设备,BPF struct_ops 如何将程序连接到 HID 子系统,以及简单的转换如何修复常见的设备问题。相同的技术适用于真实硬件,无论你是修复反转的平板轴还是实现自定义游戏控制器映射。

Linux 内核已经提供了 14 个 HID-BPF 设备修复,并且每个版本都在增加。像 udev-hid-bpf 这样的项目使编写和分发修复变得更加容易。如果你有一个损坏的 HID 设备,你现在有工具可以自己修复它,只需几个小时而不是几个月。

> 如果你想深入了解 eBPF,请查看我们的教程代码仓库 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 或访问我们的网站 <https://eunomia.dev/tutorials/>。

## 参考资料

- [Linux HID-BPF 文档](https://docs.kernel.org/hid/hid-bpf.html)
- [udev-hid-bpf 项目](https://gitlab.freedesktop.org/libevdev/udev-hid-bpf)
- [内核 HID-BPF 设备修复](https://github.com/torvalds/linux/tree/master/drivers/hid/bpf/progs)
- [UHID 内核文档](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [HID 使用表](https://www.usb.org/document-library/device-class-definition-hid-111)
- [Who-T 博客: udev-hid-bpf 快速入门](https://who-t.blogspot.com/2024/04/udev-hid-bpf-quickstart-tooling-to-fix.html)
