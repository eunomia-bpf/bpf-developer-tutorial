---
name: test-bpf-tutorial-kvm
description: Build and smoke-test bpf-developer-tutorial lessons without loading BPF programs into the host kernel. Use when creating, changing, reviewing, or debugging an eBPF tutorial and the runtime test should reuse the already-built x86 kernel under bpf-benchmark through virtme-ng/KVM. Also use for checking whether a tutorial needs a newer kernel feature. Do not use this workflow for performance benchmarking or for rebuilding the benchmark kernel.
---

# Test BPF Tutorials in KVM

Compile tutorial code on the host, but run every command that loads, attaches, or exercises BPF inside a short-lived KVM guest using the kernel artifact already built by `bpf-benchmark`.

## Safety boundary

- Never load or attach a tutorial BPF program on the host. This includes `bpftool prog load`, loaders, `make run`, XDP/TC attachment, sched_ext registration, and LSM/cgroup attachment.
- Do not rebuild or modify `bpf-benchmark`, its kernel tree, its Git state, caches, results, or conversation/agent-history data.
- Do not silently fall back to the host kernel or to TCG. Stop if `/dev/kvm`, `vng`, or the expected benchmark kernel is unavailable.
- Treat the tutorial directory as read-only in the guest by default. Use `--rwdir` only for a path that must return guest-generated files to the host.
- Use bounded commands. The wrapper applies a host-side timeout; add a shorter guest-side `timeout` to long-running loaders when useful.
- Report a KVM run as a functional smoke test, not as benchmark-quality evidence.
- Keep this infrastructure private in public prose. A tutorial or PR description may state the architecture, kernel version and commit, configuration, commands, and captured output, but must not name `bpf-benchmark`, local paths, VM instances, mount routes, caches, or agent-state locations.

## Default locations

Resolve the tutorial checkout and skill from the current Git worktree:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="$TUTORIAL_ROOT/.agents/skills/test-bpf-tutorial-kvm/scripts/run-in-kvm.sh"
```

The helper reads `BPF_BENCHMARK_ROOT`, defaulting to a `bpf-benchmark` checkout next to the tutorial repository. Its `--cwd` defaults to the caller's current directory.

The reused kernel is:

```text
$BPF_BENCHMARK_ROOT/vendor/build/x86/linux/arch/x86/boot/bzImage
```

## Workflow

### 1. Validate the repositories and instructions

Read every applicable `AGENTS.md` or equivalent repository instruction before acting.

Require a real tutorial checkout before implementation or testing. A valid checkout has lesson sources and a working Git worktree, not only a `.git` fragment. If it is incomplete, stop and explain that the checkout must be restored; do not clone over it or delete the remnant without explicit authorization.

The top-level `bpf-benchmark` Git repository does not need to be healthy for artifact reuse. The wrapper validates the kernel image, build config, kernel source worktree, KVM device, and toolchain independently.

Run the preflight:

```bash
"$RUNNER" --check
```

### 2. Inspect before building

Read the lesson README, Makefile, source, and existing test commands. Identify separately:

1. a compile-only host command;
2. the userspace loader or runtime command;
3. the event or workload that proves the program works;
4. any required network, cgroup, tracefs, debugfs, or kernel-config feature.

Use `make -n` or inspect recipes before choosing a target. A target that invokes a loader is a guest command, even if it also compiles.

### 3. Build on the host

Run only compile and static-generation steps on the host. Prefer the lesson's documented build target. Preserve generated `.bpf.o`, skeletons, and userspace binaries in the lesson directory so the guest sees the exact host-built artifacts.

Do not use `sudo` for the build. Do not run a post-build loader on the host.

### 4. Run inside the benchmark-kernel guest

Pass the runtime command after `--`. Arguments are preserved without host re-evaluation.

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="$TUTORIAL_ROOT/.agents/skills/test-bpf-tutorial-kvm/scripts/run-in-kvm.sh"
LESSON="$TUTORIAL_ROOT/src/<lesson>"

"$RUNNER" --cwd "$LESSON" -- ./loader --help
```

The wrapper boots the built benchmark `bzImage` with KVM, verifies the guest release, runs as guest root, mounts bpffs/debugfs/tracefs/cgroup2, prints provenance, and powers off when the command exits. It defaults to 2 vCPUs, 4G RAM, no network, and 120 seconds.

Use `--network user` only when the test needs an external/userspace-backed interface. Use `--network loop` for a guest-local loop network. Prefer `BPF_PROG_TEST_RUN` or deterministic guest-local traffic when either is sufficient.

Read [the tutorial test patterns](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/.agents/skills/test-bpf-tutorial-kvm/references/tutorial-patterns.md) for tracer, network, writable-output, and failure-diagnosis patterns.

### 5. Verify the behavior, not only the exit code

Capture enough evidence to connect an input event to the expected BPF output: attach confirmation, a deterministic trigger in the same guest, expected map/event output, and clean detach or process exit. Negative tests should verify the expected verifier or attach failure.

For a new lesson, test at least:

- host compile from a clean lesson build state when safe;
- KVM preflight;
- one successful guest runtime path;
- one relevant error or cleanup path;
- documentation commands exactly as written.

Do not clean unrelated files or repository-wide caches to create a clean build state.

### 6. Report provenance and limitations

Include the guest `uname -r`, benchmark kernel source commit, kernel image SHA-256, lesson commit or dirty state, host build command, guest command, and the observed result. The wrapper prints kernel provenance automatically.

If the tutorial requires a feature absent from the built config or kernel, report the missing symbol/helper/attach type and stop. Propose a benchmark-kernel rebuild or upgrade separately; do not perform it as a fallback.

## Wrapper interface

```text
run-in-kvm.sh --check
run-in-kvm.sh [--cwd PATH] [--cpus N] [--memory SIZE]
              [--timeout SECONDS] [--network none|user|loop]
              [--rwdir PATH]... [--append KERNEL_ARGS]...
              [--dry-run] [--verbose] -- COMMAND [ARG...]
```

Use `--dry-run` to inspect the generated `vng`/QEMU launch without booting. `--rwdir` is an explicit trust decision because guest root can change that host path.
