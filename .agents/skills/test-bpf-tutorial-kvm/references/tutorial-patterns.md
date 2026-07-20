# BPF tutorial KVM test patterns

Resolve the wrapper from the tutorial worktree:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="$TUTORIAL_ROOT/.agents/skills/test-bpf-tutorial-kvm/scripts/run-in-kvm.sh"
```

All paths below are host paths exposed at the same location in the virtme-ng guest.

## One-shot loader or self-test

```bash
"$RUNNER" --cwd "$LESSON" -- ./loader --self-test
```

Prefer a self-test that loads the BPF object, exercises a deterministic input, checks the map or return value, and detaches before exiting.

## Long-running tracer plus a trigger

The loader, trigger, signal, and output assertion must all occur inside the same guest:

```bash
"$RUNNER" --cwd "$LESSON" --timeout 90 -- bash -lc '
set -euo pipefail
out=$(mktemp)
./tracer >"$out" 2>&1 &
pid=$!
trap '\''kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true'\'' EXIT
sleep 1
true                         # replace with the deterministic traced event
sleep 1
kill -INT "$pid"
wait "$pid" || test $? -eq 130
trap - EXIT
grep -F "expected event" "$out"
'
```

Keep the host timeout longer than the guest-side lifecycle. Avoid an unbounded `timeout ./tracer` assertion because exit 124 proves only that it was killed.

## XDP or TC

For a userspace-backed interface and outbound guest traffic:

```bash
"$RUNNER" --cwd "$LESSON" --network user -- bash -lc '
set -euo pipefail
ip -brief link
./loader --interface eth0 &
pid=$!
trap '\''kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true'\'' EXIT
ping -c 1 -W 2 10.0.2.2
# Assert counters or emitted events here.
'
```

Use `--network loop` for guest-local network testing. Prefer `BPF_PROG_TEST_RUN` when the lesson is about program behavior rather than attachment mechanics.

## sched_ext, LSM, and cgroup programs

- Verify the exact config symbol in the printed kernel config before booting, for example `CONFIG_SCHED_CLASS_EXT=y` or `CONFIG_BPF_LSM=y`.
- Keep sched_ext registration bounded and assert that the scheduler exits or unregisters cleanly.
- Create test cgroups only inside the guest's cgroup2 mount.
- Test LSM enforcement on guest-local temporary files or processes, never on host resources mounted read-write.

## Returning generated output

The tutorial directory is read-only by default. Create a dedicated output directory and expose only it when a test must retain logs or generated files:

```bash
mkdir -p "$LESSON/test-output"
"$RUNNER" --cwd "$LESSON" --rwdir "$LESSON/test-output" -- \
    ./loader --output "$LESSON/test-output/smoke.json"
```

Guest root can modify any `--rwdir` path. Never expose a repository root, `.git`, credentials, task histories, or agent traces just for convenience.

## Interpreting failures

- **Preflight fails:** repair KVM/tool/artifact availability; do not fall back to the host kernel.
- **Guest kernel mismatch:** the image and build metadata are inconsistent; rebuild or repair the benchmark artifact separately.
- **`bpftool` asks for `linux-tools-<guest-version>`:** the Ubuntu `/usr/sbin/bpftool` wrapper was selected. On this machine, use the real binary at `/usr/local/sbin/bpftool` after confirming it with `--version`.
- **Unknown helper, attach type, or kfunc:** compare lesson requirements with the built kernel release/config/BTF. Report a kernel gap rather than changing the host test boundary.
- **Permission error inside guest:** confirm the command is running as guest root and that bpffs/debugfs/tracefs/cgroup2 mounted. Do not add host `sudo`.
- **Read-only filesystem:** write under `/tmp`, or explicitly expose a narrow output directory with `--rwdir`.
- **Timeout 124:** inspect loader cleanup and the trigger. A timeout is not a passing tracer test.
- **Verifier rejection:** preserve the complete verifier log and distinguish an intentional negative test from a compatibility regression.
