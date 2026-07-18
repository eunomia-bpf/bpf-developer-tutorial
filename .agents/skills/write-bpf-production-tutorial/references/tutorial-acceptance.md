# Tutorial acceptance and placement

## Acceptance gate

A numbered lesson must ship a small tool that a developer could plausibly run while operating or debugging a real system. Require all of the following:

- A concrete actor and problem, such as an SRE diagnosing queueing, a security agent quarantining a live connection, or an accelerator operator finding leaked shared buffers.
- A user-space CLI with useful output, filters, and actionable errors.
- A deterministic workload or fixture that recreates the scenario.
- An assertion connecting the workload to BPF output or behavior.
- A relevant negative path, unsupported-feature probe, or policy miss.
- Automatic cleanup of links, qdiscs, cgroups, maps, sockets, and test processes.
- A documented minimum kernel and required config or hardware.
- Host compile coverage and guest runtime evidence.

An upstream selftest may guide correctness, but do not copy its test harness as the lesson's product story.

## Placement

- Use `src/<number>-<name>/` for an end-to-end tracing, networking, security, scheduling, or operations tool.
- Use `src/features/<name>/` only when the reusable kernel primitive itself is the teaching goal and no honest production tool can be kept small.
- Use `src/xpu/<name>/` when the workload is specifically about GPU, NPU, DMA-BUF, accelerator drivers, or accelerator profiling. Do not use xpu merely because the host has a GPU.
- Keep cross-cutting deployment mechanisms such as program signing under `src/features/` unless the lesson implements a complete operational policy loader.

## Scenario guidance

- `fsession`: build function-latency/SLO diagnosis, not a cookie unit test.
- BPF qdisc: build a two-class latency-sensitive packet scheduler with queue/drop counters, not a bare `Qdisc_ops` registration test.
- Socket destroy: build a live connection quarantine CLI with an allowlisted control case.
- File dynptr plus task work: build deferred executable/header inspection with a direct-read failure demonstration.
- DMA-BUF iterator: build an accelerator/shared-buffer inventory and leak check under `src/xpu/`; avoid claiming per-process ownership without fd correlation.
- XDP multi-buffer: build a fragmented/jumbo-packet L4 parser with a truncated-packet failure case.
- Signed programs: build a signed policy deployment workflow with an untrusted/tampered rejection path.
- BPF crypto: defer unless the example has a defensible operational use and clear key-lifecycle boundaries.

## PR boundary

Keep each scenario in its own branch and PR. Generate README/SUMMARY/compatibility changes on that branch only. Rebase the next branch on current upstream `main`, not on another unmerged tutorial branch.
