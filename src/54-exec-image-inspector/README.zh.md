# eBPF 实例教程：在 `exec` 后检查可执行镜像

应用启动器收到的命令不一定等于内核最终安装的可执行镜像。Shell 脚本会启动解释器，包装程序可能选择另一个二进制文件，运行时也可能通过多层进程准备隐藏最终镜像。排查问题时，如果需要确认实际执行了什么，原始命令字符串并不足够。

本课实现 `exec_image_inspector`。这个小型命令运行器在 `bprm_committed_creds` LSM hook 上观察一个子进程，报告内核安装的可执行文件路径，并解析 ELF class、字节序、类型和机器架构。它还展示如何用 BPF task work 把可能触发缺页的文件读取移出不可睡眠的 hook。

完整实现位于 [`exec_image_inspector.bpf.c`](./exec_image_inspector.bpf.c)、[`exec_image_inspector.c`](./exec_image_inspector.c) 和 [`tests/test_exec_image_inspector.py`](./tests/test_exec_image_inspector.py)。

## 构建并运行已验证场景

宿主机只负责编译，不加载 BPF。先在仓库根目录初始化第三方 submodule 并构建本课：

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

集成测试只能在 Linux 6.19 或更新版本的一次性测试虚拟机中运行。虚拟机可以访问仓库目录后，执行：

```bash
cd src/54-exec-image-inspector
sudo make test
```

不要把 `make test` 或直接运行 `exec_image_inspector` 当作宿主机验证。这两个命令都会加载并挂载 BPF LSM 程序。
仓库 CI 只编译本课，运行时证据由 KVM 测试提供。

仓库测试复用了 `bpf-benchmark` 的 KVM 虚拟机和干净的 `7.0.0-rc2+` 内核，得到如下输出：

```text
guest_kernel=7.0.0-rc2+
guest_identity=uid=0(root) gid=0(root) groups=0(root)
TEST-MISSING matched=0 events=0 command_exit=127
TEST-TIMEOUT matched=1 callbacks=1 events=1 command_exit=137
READY target_tgid=1264 probe_offset=4214784 timeout_ms=3000 command=/tmp/exec-image-inspector-qo0ucl88/exec_fixture_image
EXEC pid=1264 tgid=1264 comm=exec_fixture_im path=/tmp/exec-image-inspector-qo0ucl88/exec_fixture_image is_elf=1 class=ELF64 endian=LSB type=ET_DYN(3) machine=EM_X86_64(62) header_error=0 path_error=0 latency_us=48
PROBE offset=4214784 direct_error=-14 deferred_error=0 bytes=454950524f424521
exec fixture completed
SUMMARY matched=1 scheduled=1 schedule_errors=0 callbacks=1 header_errors=0 path_errors=0 direct_probes=1 direct_probe_errors=1 deferred_probes=1 deferred_probe_errors=0 dropped=0 events=1 command_exit=0
PASS: missing-command, timeout cleanup, ELF decode, and deferred file read succeeded
```

进程号（PID）、临时路径和回调延迟会随运行变化。探测偏移取决于 fixture 构建后的大小，重新构建后可能改变。这些字段只证明功能正确，不是性能测量结果。

本次复用的 KVM 内核来自源码 commit `a03114efd0720dff230388f7e160e427e54ea31b`。内核镜像 SHA-256 为 `760150dd317a5c05e58d35928bd70c399f41838f3be3ac643f3f3a3af4340b88`，config SHA-256 为 `82f63944a9ddd0bc3b0a60c3e6ebbe3e9900f2eefad7d3872793bb98b3cc68fe`。

输出中的 `EXEC` 行给出了最终可执行镜像及其 ELF header。随后的 `PROBE` 行展示了两种文件读取上下文的差异。测试 fixture 在 `exec` 前把追加的 marker 变成冷页。在 LSM 程序中直接读取该位置会返回 `-EFAULT`（`-14`），task-work 回调则成功读取 `454950524f424521`，也就是 `EIPROBE!` 的十六进制编码。

输出中位于 `READY` 之前的两行覆盖了失败行为。不存在的命令以状态码 127 退出，不会到达已提交 exec 的 hook。另一个命令先产生 exec 事件，随后超过测试设置的 200 ms 时限，父进程发送 `SIGKILL` 并回收它，最终状态码为 137。

在满足要求的测试虚拟机中，可以省略 fixture 专用的探测偏移，检查其他命令：

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

工具只观察 `--` 后面的这个命令，不是全系统 daemon。
普通运行不设置 `--probe-offset` 时，只输出 `READY`、`EXEC` 和 `SUMMARY`，不会出现 `PROBE` 行。

### 命令行选项

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms` 接受 100 至 60000 ms，默认值为 5000 ms。超过时限后，加载器会终止并回收命令。
- `--probe-offset` 在指定文件偏移比较 8-byte 直接读取与延迟读取。普通镜像检查不需要这个选项。自动化 fixture 会计算有效的 marker 偏移并创建冷页条件。
- `--verbose` 在排查加载或挂载问题时输出 libbpf 诊断信息。
- `--` 结束 inspector 自身的选项，后面的所有参数都属于被观察命令。

## 端到端流程

用户态加载器和 BPF 程序通过以下步骤协作，避免漏掉生命周期很短的命令：

1. 用户态先 fork 命令，但让子进程在调用 `execvp` 前阻塞于 pipe。
2. 加载器把子进程 TGID 写入 BPF 只读数据，加载 skeleton，挂载 LSM 程序并创建 ring buffer reader。
3. 用户态释放 pipe。子进程调用 `execvp`，新可执行文件的凭据提交后，`lsm/bprm_committed_creds` 匹配这个 TGID。
4. 该 hook 记录可选的直接读取结果，再为当前 task 调用 `bpf_task_work_schedule_signal()`。
5. 回调在 task work 中取得该 task 已安装的可执行文件，解析路径，通过 dynptr 读取文件，解析 ELF header，并向 ring buffer 发送一个事件。
6. 用户态格式化事件，等待命令退出，执行超时限制，最后销毁 ring buffer 和 BPF skeleton。

这次 pipe 握手保证加载器在挂载 BPF 程序前就知道目标 TGID。先加载再通过单独协议启动命令也能避免竞态，但会引入额外控制接口。阻塞子进程让本课保持自包含，同时不会漏掉目标的 exec。

## 从 exec hook 调度文件读取

这个 LSM 程序只处理用户态指定的子进程。每次工具调用只观察一个命令，因此 map 中只需要一个 `exec_work` 值。

```c
SEC("lsm/bprm_committed_creds")
void BPF_PROG(schedule_exec_inspection, struct linux_binprm *bprm)
{
	struct task_struct *task;
	struct exec_work *work;
	__u64 pid_tgid;
	__u32 key = 0, tgid;
	int err;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	if (target_tgid && tgid != target_tgid)
		return;

	__sync_fetch_and_add(&stats.matched, 1);
	work = bpf_map_lookup_elem(&pending, &key);
	if (!work) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}

	work->scheduled_ns = bpf_ktime_get_ns();
	work->direct_probe_error = probe_file_without_sleep(bprm->file);
	task = bpf_get_current_task_btf();
	err = bpf_task_work_schedule_signal(task, &work->work, &pending,
					    inspect_executable);
	if (err) {
		__sync_fetch_and_add(&stats.schedule_errors, 1);
		return;
	}
	__sync_fetch_and_add(&stats.scheduled, 1);
}
```

直接探测用于明确展示执行上下文的边界。不可睡眠的 BPF 程序创建 file-backed dynptr 后，不能为缺失的文件页触发 page fault。集成测试会主动驱逐 marker 所在的页，使这次读取返回 `-EFAULT`。如果数据已经缓存，直接读取也可能成功，因此不能认为每个可执行文件或偏移都会返回 `-EFAULT`。这项可复现比较由 `sudo make test` 完成。[`create_probe_image()`](./tests/test_exec_image_inspector.py) 会追加 marker、计算偏移、刷新文件并请求驱逐 page cache，随后把该偏移传给 CLI。

调用 `bpf_task_work_schedule_signal()` 可以为当前 task 关联 BPF 回调。回调复用 map value 中嵌入的 task-work 存储。内核会持有所需引用直至回调结束，所以 hook 不会把裸 `struct file *` 传过延迟执行边界。

## 在回调中读取已安装镜像

这个 task-work 回调运行在可睡眠上下文中。它重新取得当前 task 的可执行文件，创建 file-backed dynptr，并在所有路径上释放这两项资源。

```c
task = bpf_get_current_task_btf();
file = bpf_get_task_exe_file(task);
if (!file) {
	event.header_error = -ENOENT;
	__sync_fetch_and_add(&stats.header_errors, 1);
	if (probe_offset) {
		event.deferred_probe_error = -ENOENT;
		__sync_fetch_and_add(&stats.deferred_probes, 1);
		__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
	}
	goto emit;
}

err = bpf_path_d_path(&file->f_path, event.path, sizeof(event.path));
if (err < 0) {
	event.path_error = err;
	__sync_fetch_and_add(&stats.path_errors, 1);
}

err = bpf_dynptr_from_file(file, 0, &dynptr);
if (err) {
	bpf_dynptr_file_discard(&dynptr);
	event.header_error = err;
	__sync_fetch_and_add(&stats.header_errors, 1);
	if (probe_offset) {
		event.deferred_probe_error = err;
		__sync_fetch_and_add(&stats.deferred_probes, 1);
		__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
	}
	goto put_file;
}

err = bpf_dynptr_read(header, sizeof(header), &dynptr, 0, 0);
if (err) {
	event.header_error = err;
	__sync_fetch_and_add(&stats.header_errors, 1);
}

if (probe_offset) {
	__sync_fetch_and_add(&stats.deferred_probes, 1);
	err = bpf_dynptr_read(event.probe_bytes, sizeof(event.probe_bytes),
			      &dynptr, probe_offset, 0);
	event.deferred_probe_error = err;
	if (err)
		__sync_fetch_and_add(&stats.deferred_probe_errors, 1);
}
bpf_dynptr_file_discard(&dynptr);

if (!event.header_error && header[0] == 0x7f && header[1] == 'E' &&
    header[2] == 'L' && header[3] == 'F') {
	event.is_elf = 1;
	event.elf_class = header[EI_CLASS];
	event.elf_data = header[EI_DATA];
	event.elf_type = read_elf_u16(header, 16, event.elf_data);
	event.elf_machine = read_elf_u16(header, 18, event.elf_data);
}

put_file:
bpf_put_file(file);
emit:
if (bpf_ringbuf_output(&events, &event, sizeof(event), 0))
	__sync_fetch_and_add(&stats.dropped, 1);
```

通过 `bpf_get_task_exe_file()` 取得的 `struct file` 对象带有引用，必须与 `bpf_put_file()` 配对释放。文件 dynptr 也拥有内部状态，因此即使创建失败，也要调用 `bpf_dynptr_file_discard()`。回调只读取 64-byte ELF header 和可选的 8-byte 测试 marker，不会扫描整个文件。

成功读取 header 后，程序先检查四个 ELF magic byte，再解析 `EI_CLASS`、`EI_DATA`、`e_type` 和 `e_machine`。用户态把常见数值格式化为 `ELF64`、`ET_DYN` 和 `EM_X86_64` 等名称，同时保留原始数值，便于检查未知类型。

## 限制命令运行时间并完成清理

父进程只在 BPF 设置完成后才释放目标命令：

```c
error = start_blocked_child(&child);
if (error)
	return 1;

error = setup_inspector(&child, &events, &skel, &ring_buffer);
if (error)
	goto cleanup;

command_exit = wait_for_command(ring_buffer, &child, &events);
if (command_exit < 0)
	goto cleanup;
result = report_result(skel, &events, command_exit);

cleanup:
stop_child(&child);
ring_buffer__free(ring_buffer);
exec_image_inspector_bpf__destroy(skel);
```

如果 BPF 设置失败，清理逻辑会关闭尚未释放的 pipe，并在目标执行前回收子进程。已经释放的命令如果超过 `--timeout-ms`，`stop_child()` 会发送 `SIGKILL` 并等待它退出。正常结束和所有错误路径都会释放 ring buffer，并销毁 skeleton，由此卸载 LSM link。

工具保留命令本身的退出状态。收到事件不会掩盖命令失败，命令失败也不会被错误地报告成检查成功。工具不会创建 bpffs pin 或持久 link，因此进程退出已经完成全部清理。

## 运行要求

| 要求 | 值 | 原因 |
| --- | --- | --- |
| Linux 内核 | 6.19 或更新版本 | BPF task work 在 6.18 引入，file-backed dynptr 在 6.19 引入 |
| 内核配置 | `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`、`CONFIG_BPF_JIT=y`、`CONFIG_BPF_LSM=y`、`CONFIG_SECURITY=y`、`CONFIG_DEBUG_INFO_BTF=y` | 加载带 BTF 的 BPF LSM 程序 |
| 活动 LSM 列表 | `/sys/kernel/security/lsm` 中包含 `bpf` | 只有 `CONFIG_BPF_LSM=y` 并不保证启动时启用 BPF LSM |
| 权限 | root | 加载并挂载 BPF LSM 程序 |
| 已测试架构 | x86_64 | 确定性 ELF 断言当前按 x86-64 编写 |
| 已测试工具链 | bpftool v7.7.0 与 libbpf v1.7.0 | 构建本课使用的 BPF object 和 skeleton |
| 硬件 | 无特殊要求 | Fixture 不依赖加速器或特殊设备 |

仓库生成的 `vmlinux.h` 和 UAPI header 早于这些 kfunc。[`bpf_experimental.h`](./bpf_experimental.h) 因此把所需声明限制在本课目录，待仓库更新 vendored header 后再移除。

在虚拟机中执行 `cat /sys/kernel/security/lsm` 可以检查 active list。如果其中没有 `bpf`，需要把它追加到虚拟机现有的逗号分隔 `lsm=` kernel command-line 值中。例如，把 `lsm=<existing-list>` 改为 `lsm=<existing-list>,bpf`，不要删除虚拟机的其他 LSM，否则 attach 会失败。这个启动配置修改也应限制在一次性测试虚拟机内。

## 范围与限制

- 工具只观察加载器创建的一个子进程，不会监控系统中的所有 exec。
- 它报告可执行镜像和少量 ELF header 信息，不验证签名，不判断恶意软件，也不执行 allowlist 策略。
- 对于脚本，已安装的可执行镜像可能是解释器，而不是脚本路径。输出回答 task 安装了哪个镜像，不包含启动链消费的每个输入文件。
- 冷页 fixture 用于证明延迟文件读取的必要性，不能据此认为所有直接文件读取都会失败。
- 单个 map slot 适用于单子进程 CLI。并发服务需要 per-task 状态、准入上限，以及 task 未执行回调时的恢复策略。
- KVM 运行只做功能测试。输出中的回调延迟不能作为 benchmark 或开销估算。
- 运行行为只在 x86_64 上验证。其他架构需要对应的 fixture 断言和 KVM 覆盖。

## 参考资料

- [BPF task-work 基础实现](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [`bpf_task_work_schedule_signal()` kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr 基础实现](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfunc 与 helper](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [可睡眠 file-dynptr 调度](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc 文档](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)

现在可以区分启动请求和内核最终安装的可执行镜像，也可以复用一条有边界的路径，把可能触发 page fault 的文件检查移动到 task work。本课故意保持单进程、小读取范围，后续可以在不把示例变成 daemon 的前提下扩展其他元数据或策略输入。

继续阅读 [bpf-developer-tutorial 仓库](https://github.com/eunomia-bpf/bpf-developer-tutorial) 和 [eunomia 教程索引](https://eunomia.dev/tutorials/)。
