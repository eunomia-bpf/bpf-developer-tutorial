---
name: write-bpf-production-tutorial
description: Design, write, or rewrite one or more practical bilingual bpf-developer-tutorial lessons with pinned Claude Opus 4.5, then verify the public workflow, complete source, and prose against the implementation. Use when creating README.md and README.zh.md, checking whether a tutorial tool has a realistic CLI and lifecycle, testing the example, or preparing tutorial changes for review.
---

# Write a BPF Tutorial

Use `$bpf-tutorial-writing-style` for the finished prose. Keep this workflow small: prepare reliable source material, let one pinned writer complete both languages, then check what it actually wrote.

## 1. Prepare the lesson

Read these inputs before writing:

- `scripts/guideline_advance.md` for tutorials 40+, `scripts/guideline_basic.md` for tutorials 0-39;
- both README files from `src/47-cuda-events`, `src/48-energy`, and `src/49-hid` as style references;
- the lesson's implementation, headers, Makefile, fixtures, and tests;
- the current README pair when revising an existing lesson;
- primary upstream sources for versions and feature semantics.

Collect the facts the reader needs: the problem, useful alternatives, the kernel/user-space flow, feature versions, requirements, intended public commands, real output, concurrency or admission behavior, cleanup, limits, and references. Keep every claim grounded in the code, tests, captured output, or a primary source. Preserve an existing draft before a from-scratch rewrite.

Write down the narrowest useful description supported by the normal execution path before drafting. Use it to align the title, opening, CLI, output, and test. For stateful security examples, include the correlation key, admission checks, state lifetime, enforcement point, and the negative cases exercised by the test.

Make the example a small useful tool. Its normal mode works on a reader-selected process, cgroup, interface, or other real target. A deterministic demo or integration test may create its own workload. Keep the CLI compact and keep infrastructure details out of public text.

Build and run the example when the environment supports it. Use `$test-bpf-tutorial-kvm` for kernel features that need the repository's KVM environment. Runtime details support the tutorial; local workspace paths, VM names, shared repositories, caches, prompts, and agent traces stay private.

## 2. Pass the practical-design gate

Validate the tool as an operator before writing prose. Keep its public workflow separate from the deterministic fixture:

- State the operational question, the exact command a reader would run, the independent workload or target, the useful output, and how the tool stops.
- Classify the lifecycle. A scan or atomic control action may be one-shot; a tracer or monitor must attach before the workload and remain active until a signal, duration, or real completion condition.
- Do not turn a blocked toy child or `/bin/true` fixture into the public CLI merely because it removes a test race. Launch-scoped tracing is valid only when it is the intended real workflow.
- Emit and test an explicit readiness signal before starting an independent workload. Do not use a fixed sleep as proof that setup or attachment completed.
- Check target scope and filters, concurrent state, admission bounds, drop and failure counters, exit status, normal cleanup, signal cleanup, and destructive-action safety in proportion to the lesson.
- For asynchronous work, stop admission first, wait for completed work rather than merely entered callbacks, drain output, report stable health, and only then destroy resources.
- Execute the documented command as written. The test must prove the real lifecycle plus one relevant failure or cleanup path, not only that the BPF program loaded.
- Describe the current public workflow directly. Do not narrate removed flags, old child-command modes, or other migration history unless backward compatibility is itself the lesson.
- Keep repository tests out of the reader-facing tutorial path. Use them as private validation evidence, but teach the normal command, independent workload, useful tool output, and shutdown sequence.
- Show only output emitted by the documented tool in public examples. Never include harness lines such as `TEST-*` or `PASS`, fixture setup, test assertions, or local test-infrastructure provenance.

If the implementation only demonstrates a helper but is awkward or misleading as a tool, revise the implementation and test before asking the writer to explain it. Do not let polished prose overclaim an impractical design.

## 3. Shape the lesson

Follow `scripts/guideline_advance.md`, then organize the article around the example rather than a fixed heading template. A complete lesson normally has:

- a direct title and a short introduction that says what the tool answers;
- enough eBPF, kernel-subsystem, and feature background to make the mechanism understandable, including the feature's kernel version when relevant;
- the complete kernel and user-space flow before detailed code;
- every core source file in a normal Markdown fence, followed by focused explanation;
- the normal public command, target, lifecycle, useful output, and shutdown path;
- copyable build and run commands, real output, requirements, a compact ending, and primary references.

Use headings that fit the topic. Keep compilation after the code discussion. Explain alternatives, limits, diagrams, and extra concepts only when they materially improve the lesson.

## 4. Let Opus write

Claude Opus writes all reader-facing tutorial prose. Use the exact model ID `claude-opus-4-5-20251101`. Stop if that model is unavailable instead of substituting another model.

Use one non-interactive invocation for the complete requested set. A single lesson means one English and Chinese pair; a batch means every requested pair is finished in the same invocation before Opus returns. The prompt stays short and names only:

- every target README pair;
- `scripts/guideline_advance.md` or `scripts/guideline_basic.md`;
- `$bpf-tutorial-writing-style`;
- `src/47-cuda-events`, `src/48-energy`, and `src/49-hid` as style references;
- the request to read the implementation, rewrite each paragraph in place, and finish both files before returning without questions.

Do not paste a second checklist, paragraph plan, fact inventory, or review rubric into the prompt. Add a technical fact only when it is unavailable in the repository.

Run Claude from the repository root with the pinned model and permission to read the repository and write only the target README files. Opus does not commit or push.

## 5. Check the result

Inspect both files and the diff instead of trusting the model's final message. Confirm that:

- both languages are complete and tell the same technical story;
- the documented command, target, lifecycle, signals, concurrency bounds, cleanup, and health output match the practical design gate;
- the opening reads like a tutorial rather than an abstract or feature list;
- every mechanism promised by the title and introduction appears in the executable path, and a feature-driven lesson both uses and explains the named API;
- the title and opening describe the narrowest useful behavior proven by the normal mode and test, without expanding a focused allowlist, profiler, index, capture tool, or monitor into a broader product category;
- the relevant eBPF and kernel background appears before details that depend on it;
- the high-level mechanism is explained before code sections;
- compilation/execution is AFTER code analysis;
- every core source file, including the user-space loader, appears once in a complete ordinary Markdown fence;
- code, commands, output, versions, requirements, cleanup, and limits agree with the repository;
- sample output comes from the normal public workflow and contains no test-harness or migration/deprecation narration;
- the opening source link points only to the lesson directory;
- every published link uses a stable absolute `https://` URL; GitHub, kernel.org, and authoritative documentation sites are valid, while relative links are prohibited;
- no local infrastructure, prompt, model, agent, or trace detail appears in public text.

Check every core header, kernel/BPF source, and user-space loader with the bundled `sync-source-blocks.py`. Then run `git diff --check`, the lesson build, its tests, the exact documented public command, and the relevant runtime test. Treat a functional run as a functional run rather than a benchmark.

Read the finished pair once as an intermediate eBPF developer. Remove template-like detours, repeated setup, unexplained jargon, and details that belong only to the test harness. If a concrete problem remains, give Opus a short defect list in the same session and let it revise the affected paragraphs before returning. Keep prompts, responses, partial drafts, and failed runs; never delete real conversation or agent history.

Stop after the reviewed local result unless the user asks to commit, push, or update a PR.
