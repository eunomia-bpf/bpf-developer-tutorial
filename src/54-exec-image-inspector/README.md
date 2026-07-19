# eBPF Tutorial by Example: Inspect the Executable Image After `exec`

An application launcher may receive one command but install a different executable image. A shell script starts an interpreter, a wrapper selects another binary, and a runtime may hide the final image behind several layers of process setup. When an incident depends on what actually ran, the original command string is not enough.

This lesson builds `exec_image_inspector`, a small command runner that observes one child at the `bprm_committed_creds` LSM hook. It reports the installed executable path and decodes the ELF class, byte order, type, and machine. It also demonstrates how BPF task work moves a potentially faulting file read out of the non-sleepable hook.

The complete implementation is in [`exec_image_inspector.bpf.c`](./exec_image_inspector.bpf.c), [`exec_image_inspector.c`](./exec_image_inspector.c), and [`tests/test_exec_image_inspector.py`](./tests/test_exec_image_inspector.py).

## Build and run the verified scenario

Build the tool on the host without loading BPF. From the repository root, initialize the third-party submodules and compile the lesson:

```bash
git submodule update --init --recursive
make -C src/54-exec-image-inspector clean
make -C src/54-exec-image-inspector -j2
```

Run the integration test only inside a disposable Linux 6.19 or newer guest. When the repository directory is available in that guest, run:

```bash
cd src/54-exec-image-inspector
sudo make test
```

Do not use `make test` or run `exec_image_inspector` as host validation. Both commands load and attach the BPF LSM program.
Repository CI compiles this lesson only. The KVM test supplies the runtime proof.

The repository test was run in the reused `bpf-benchmark` KVM guest with a clean `7.0.0-rc2+` kernel. It produced the following output:

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

PID, temporary path, and callback latency vary between runs. The probe offset depends on the built fixture's size and may change after a rebuild. These fields are functional evidence, not performance measurements.

The reused KVM kernel came from source commit `a03114efd0720dff230388f7e160e427e54ea31b`. Its image SHA-256 was `760150dd317a5c05e58d35928bd70c399f41838f3be3ac643f3f3a3af4340b88`, and its config SHA-256 was `82f63944a9ddd0bc3b0a60c3e6ebbe3e9900f2eefad7d3872793bb98b3cc68fe`.

The `EXEC` line identifies the final executable image and its ELF header. The `PROBE` line is the important file-I/O comparison. The fixture made an appended marker cold before `exec`. Reading that location directly from the LSM program returned `-EFAULT` (`-14`), while the task-work callback read `454950524f424521`, the hex encoding of `EIPROBE!`.

The two lines before `READY` cover negative behavior. A missing command exits with status 127 and never reaches the committed-exec hook. A sleeping command produces its exec event, exceeds the 200 ms test deadline, and is reaped after `SIGKILL` with status 137.

To inspect another command in a suitable test guest, omit the fixture-only probe offset:

```bash
sudo ./exec_image_inspector --timeout-ms 3000 -- /bin/true
```

The tool observes exactly the command after `--`. It is not a system-wide daemon.
Without `--probe-offset`, an ordinary run prints `READY`, `EXEC`, and `SUMMARY`, but no `PROBE` line.

### Command-line options

```text
exec_image_inspector [--probe-offset BYTES] [--timeout-ms MS] [--verbose] -- COMMAND [ARG...]
```

- `--timeout-ms` accepts 100 through 60000 ms and defaults to 5000 ms. The loader kills and reaps the command when this deadline expires.
- `--probe-offset` compares a direct and deferred eight-byte read at one file offset. Ordinary image inspection does not need it. The automated fixture calculates a valid marker offset and creates the cold-page condition.
- `--verbose` prints libbpf diagnostics when load or attach behavior needs investigation.
- `--` ends inspector options. Every following argument belongs to the observed command.

## End-to-end flow

The loader and BPF program cooperate so the hook cannot miss a short-lived command.

1. User space forks the command, but the child blocks on a pipe before `execvp`.
2. The loader writes the child TGID into BPF read-only data, loads the skeleton, attaches the LSM program, and creates the ring-buffer reader.
3. User space releases the pipe. The child calls `execvp`, and `lsm/bprm_committed_creds` matches that TGID after the new executable credentials have been committed.
4. The hook records an optional direct-read result and schedules `bpf_task_work_schedule_signal()` for the current task.
5. The callback obtains the task's installed executable file, resolves its path, reads the file through a dynptr, decodes the ELF header, and sends one event through the ring buffer.
6. User space formats the event, waits for the command, enforces the deadline, and destroys the ring buffer and BPF skeleton.

The pipe handshake is important. Loading first and launching later would also avoid a race, but then the loader would need a separate command protocol. The blocked child keeps this tutorial self-contained while guaranteeing that its TGID is known before attachment.

## Schedule file reads from the exec hook

The LSM program filters on the one child selected by user space. Its map contains one `exec_work` value because one invocation observes one command.

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

The direct probe exists to make the context boundary visible. A file-backed dynptr created in this non-sleepable program cannot fault missing file pages into memory. The integration fixture deliberately evicts its marker pages so this attempt returns `-EFAULT`. Cached data may succeed, so `-EFAULT` is not a universal result for every executable or offset. The reproducible comparison belongs to `sudo make test`. [`create_probe_image()`](./tests/test_exec_image_inspector.py) appends the marker, calculates the offset, flushes the file, and requests page-cache eviction before passing that offset to the CLI.

`bpf_task_work_schedule_signal()` associates a BPF callback with the current task. The callback uses the same task-work storage embedded in the map value. The kernel holds the required references until the callback finishes, so the hook does not pass a raw `struct file *` across the deferred boundary.

## Read the installed image in the callback

The task-work callback runs in a sleepable context. It reacquires the current task's executable file, creates a file-backed dynptr, and always releases both resources.

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

`bpf_get_task_exe_file()` returns a referenced file, which must be paired with `bpf_put_file()`. The file dynptr also owns internal state, so every creation path is paired with `bpf_dynptr_file_discard()`, including creation failure. The callback reads only the 64-byte ELF header plus the optional eight-byte test marker. It does not scan the full file.

After a successful header read, the program checks the four ELF magic bytes. It then decodes `EI_CLASS`, `EI_DATA`, `e_type`, and `e_machine`. The user-space formatter maps common numeric values to names such as `ELF64`, `ET_DYN`, and `EM_X86_64`, while retaining each original number in the output.

## Bound command runtime and clean up

The parent does not release the command until BPF setup is complete:

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

If BPF setup fails, cleanup closes the unreleased pipe and reaps the child without executing the target. If a released command exceeds `--timeout-ms`, `stop_child()` sends `SIGKILL` and waits for it. Normal completion and every error path free the ring buffer and destroy the skeleton, which detaches the LSM link.

The process exit status remains visible. A successful event does not hide a failed command, and a command failure does not become an inspection success. The tool creates no bpffs pin or persistent link, so process teardown is the complete cleanup procedure.

## Runtime requirements

| Requirement | Value | Why it is needed |
| --- | --- | --- |
| Linux kernel | 6.19 or newer | BPF task work arrived in 6.18, while file-backed dynptr support arrived in 6.19 |
| Kernel configuration | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y`, `CONFIG_DEBUG_INFO_BTF=y` | Loads a BTF-enabled BPF LSM program |
| Active LSM list | `bpf` appears in `/sys/kernel/security/lsm` | `CONFIG_BPF_LSM=y` alone does not make BPF LSM active at boot |
| Privilege | root | Loads and attaches the BPF LSM program |
| Tested architecture | x86_64 | The deterministic ELF assertions currently expect x86-64 |
| Tested tooling | bpftool v7.7.0 with libbpf v1.7.0 | Builds the object and generated skeleton used by this lesson |
| Hardware | none | The fixture needs no accelerator or special device |

The repository's generated `vmlinux.h` and UAPI headers predate these kfuncs. [`bpf_experimental.h`](./bpf_experimental.h) therefore keeps the required declarations local to this lesson until those vendored headers are regenerated.

Check the active list inside the guest with `cat /sys/kernel/security/lsm`. If `bpf` is absent, add it to the guest's existing comma-separated `lsm=` kernel command-line value. For example, change `lsm=<existing-list>` to `lsm=<existing-list>,bpf` without removing the guest's other LSMs. Otherwise the attach step fails. Keep this boot change inside the disposable guest.

## Scope and limitations

- This tool observes one child created by its own loader. It does not monitor every exec on the system.
- It reports an executable image and a compact ELF header. It does not verify signatures, classify malware, or enforce an allowlist.
- For a script, the installed executable image may be the interpreter rather than the script path. The output answers what image the task installed, not every input file consumed by the launch chain.
- The cold-page fixture demonstrates why deferred file I/O matters. It does not prove that every direct file read fails.
- The single map slot is correct for the one-child CLI. A concurrent service would need per-task state, admission limits, and a recovery policy for tasks that never execute the callback.
- The KVM run is a functional test. Its callback latency is not a benchmark or an overhead estimate.
- Runtime behavior was exercised on x86_64. Other architectures need their own fixture assertions and KVM coverage.

## References

- [BPF task-work plumbing](https://github.com/torvalds/linux/commit/5c8fd7e2b5b0a527cf88740da122166695382a78)
- [`bpf_task_work_schedule_signal()` kfunc](https://github.com/torvalds/linux/commit/38aa7003e369802f81a078f6673d10d97013f04f)
- [File-backed dynptr plumbing](https://github.com/torvalds/linux/commit/8d8771dc03e48300e80b43744dd3c320ccaf746a)
- [File dynptr kfuncs and helpers](https://github.com/torvalds/linux/commit/e3e36edb1b8f0e6975c68acd2e1202ec0397fd75)
- [Sleepable file-dynptr dispatch](https://github.com/torvalds/linux/commit/2c52e8943a437af6093d8b0f0920f1764f0e5f64)
- [Kernel kfunc documentation](https://github.com/torvalds/linux/blob/v7.1/Documentation/bpf/kfuncs.rst)
- [File-reader BPF selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/file_reader.c)
- [BPF task-work selftest](https://github.com/torvalds/linux/blob/v7.1/tools/testing/selftests/bpf/progs/task_work.c)

You can now distinguish a launch request from the executable image the kernel installed, and you have a bounded pattern for moving faultable file inspection into task work. The complete lesson remains intentionally small so the same flow can be adapted to richer metadata or policy inputs without turning this example into a daemon.

Continue with the [bpf-developer-tutorial repository](https://github.com/eunomia-bpf/bpf-developer-tutorial) and the [eunomia tutorial index](https://eunomia.dev/tutorials/).
