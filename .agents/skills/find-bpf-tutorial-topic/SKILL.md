---
name: find-bpf-tutorial-topic
description: Audit bpf-developer-tutorial coverage, research current Linux BPF work and real open-source eBPF projects, maintain the repository tutorial candidate registry, and rank the next lesson by reader value, eBPF leverage, reproducibility, distinctness, teaching clarity, ecosystem evidence, maturity, and maintenance cost. Use when deciding what eBPF tutorial to write next, checking whether an idea is already covered, comparing feature-driven and scenario-driven topics, refreshing the topic roadmap, or asking which candidate has the highest value.
---

# Find the Next BPF Tutorial Topic

Choose one lesson-sized problem with lasting teaching value. Treat kernel changes as capability evidence and open-source projects as evidence that the problem matters.

## Resolve the repository

Work from a complete Git checkout and derive absolute paths:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
CANDIDATES="$REPO_ROOT/TUTORIAL_IDEAS.md"
```

Read `CANDIDATES` before researching. Preserve its history: keep existing candidates and change their status to `covered`, `superseded`, `deferred`, or `rejected` with a reason instead of deleting them.

## Audit existing coverage

Inspect the current worktree, open tutorial branches or PRs when available, and every first-level directory under `src`. Include numbered lessons, unnumbered lessons such as `cgroup`, and grouped material such as `features` and `xpu`; exclude vendored source such as `third_party` from the coverage decision. Read enough implementation and prose to distinguish a shared helper from a genuinely covered mechanism.

Use `rg` to search candidate hook names, helpers, program types, protocols, and scenarios across README and source files. Record the closest existing lesson for every candidate. A new scenario can reuse an existing primitive when it teaches a different diagnostic or control pattern; a renamed example of the same flow is duplicate coverage.

Pay special attention to unmerged lessons in the current worktree so the roadmap does not recommend work already under review.

## Research capabilities and real use cases

Use current primary sources. Search more broadly than Linux:

1. Linux BPF merge commits, documentation, selftests, libbpf, and bpftool releases establish semantics, version requirements, and reference behavior.
2. Active observability and profiling projects reveal recurring operational questions. Include OpenTelemetry OBI and profiler, Parca, Pyroscope, Coroot, Odigos, and comparable projects.
3. Networking projects reveal reusable datapath patterns. Include Cilium, Hubble, Kmesh, Katran, sched_ext, and comparable projects.
4. Security projects reveal concrete detection and enforcement scenarios. Include Tetragon, Falco, Tracee, and comparable projects.
5. Packaging and lifecycle projects reveal deployment gaps. Include Inspektor Gadget and bpfman.
6. AI, accelerator, storage, and runtime projects reveal newer workloads. Include agtap, eCapture, io_uring tools, OpenTelemetry profiler GPU work, GPU/NCCL projects, and comparable projects.

Prefer official repositories, release notes, documentation, selftests, and papers from the project authors. Use popularity only as supporting context. Recent releases, repeated implementations across independent projects, and concrete tests are stronger evidence.

Convert each project feature into a small independent lesson. Teach the mechanism and the question it answers rather than writing an installation guide for the source project.

## Define the runnable lesson before scoring

For every serious candidate, write five short fields:

- the concrete question a reader can reproduce;
- the event, packet, request, task, or workload followed end to end;
- the BPF hook, map, helper, kfunc, or program type that makes the answer possible;
- the deterministic fixture and observable success output;
- the closest existing lesson and the new knowledge this candidate adds.

Defer an idea when these fields remain vague. A helper name alone is not a tutorial topic.

## Score value

Score from evidence, then subtract costs. Keep the breakdown in working notes and place the final score in `TUTORIAL_IDEAS.md`.

| Dimension | Maximum | Question |
|---|---:|---|
| Reader problem | 25 | Does it answer a recurring, consequential question? |
| eBPF leverage | 20 | Does eBPF provide visibility or control that ordinary tools cannot provide as cleanly? |
| Coverage gap | 15 | Does it add a distinct mechanism or scenario to this repository? |
| Reproducibility | 15 | Can one bounded local or KVM fixture prove the result? |
| Teaching clarity | 10 | Can the lesson follow one understandable path and show decisive output? |
| Ecosystem evidence | 10 | Do maintained projects or upstream tests validate the use case? |
| Maturity | 5 | Are the required kernel and userspace interfaces stable enough to maintain? |

Subtract up to 20 points for unstable private interfaces, broad multi-service scope, unusual hardware, cloud or Kubernetes requirements, fragile protocol parsing, and high version-specific maintenance.

Newness breaks close ties; it does not replace reader value. Favor a stable lesson that solves a real problem over a new helper without a compelling use case.

## Apply the admission gates

A candidate can become `ready` only when:

- it has a concrete reproducible problem and expected output;
- eBPF is central to the solution;
- the repository does not already teach the same flow;
- the example can fit one coherent tutorial;
- primary sources establish the technical claims;
- required kernel, architecture, privilege, and hardware conditions are known;
- the likely maintenance burden is proportionate to its value.

Classify a small addition to an existing lesson as `maintenance` rather than creating a new numbered tutorial. Classify an immature upstream feature as `watch` until it reaches a suitable stable kernel or userspace release.

## Maintain the candidate registry

Update `CANDIDATES` with:

- the audit date;
- candidate status and score;
- the smallest useful lesson scope;
- the closest existing coverage;
- primary project or upstream sources;
- the reason for any status change.

Add newly found candidates. Retain covered and rejected entries as an append-only decision record. Update scores when repository coverage, upstream maturity, available test infrastructure, or ecosystem evidence changes.

## Recommend one next lesson

Return the top three and select one winner. Explain the winner through its problem, reusable mechanism, deterministic demonstration, repository gap, and maintenance cost. State why the most fashionable alternative ranked lower when that tradeoff is material.

Separate these conclusions when useful:

- highest overall tutorial value;
- strongest new-kernel-feature lesson;
- most timely or attention-grabbing scenario;
- best topic that can run in the current KVM environment.

Do not implement the winner unless the user also asks to write it.
