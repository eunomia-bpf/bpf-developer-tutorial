---
name: write-bpf-production-tutorial
description: Write or rewrite one or more bilingual bpf-developer-tutorial lessons with pinned Claude Opus 4.5, then verify the result against the implementation. Use when creating README.md and README.zh.md, preserving full source, testing the example, or preparing tutorial changes for review.
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

Collect the facts the reader needs: the problem, the kernel/user-space flow, feature versions, requirements, commands, real output, cleanup, scope, and references. Add alternatives when they help the reader choose or understand the mechanism. Keep every claim grounded in the code, tests, captured output, or a primary source. Preserve an existing draft before a from-scratch rewrite.

Make the example a small useful tool. Its normal mode works on a reader-selected process, cgroup, interface, or other real target. A deterministic demo or integration test may create its own workload. Keep the CLI compact and keep infrastructure details out of public text.

Build and run the example when the environment supports it. Use `$test-bpf-tutorial-kvm` for kernel features that need the repository's KVM environment. Runtime details support the tutorial; local workspace paths, VM names, shared repositories, caches, prompts, and agent traces stay private.

## 2. Shape the lesson

Follow `scripts/guideline_advance.md`, then organize the article around the example rather than a fixed heading template. A complete lesson normally has:

- a direct title and a short introduction that says what the tool answers;
- enough eBPF, kernel-subsystem, and feature background to make the mechanism understandable, including the feature's kernel version when relevant;
- the complete kernel and user-space flow before detailed code;
- every core source file in a normal Markdown fence, followed by focused explanation;
- copyable build and run commands, real output, requirements, a compact ending, and primary references.

Use headings that fit the topic. Keep compilation after the code discussion. Explain alternatives, limits, diagrams, and extra concepts only when they materially improve the lesson.

## 3. Let Opus write

Claude Opus writes all reader-facing tutorial prose. Use the exact model ID `claude-opus-4-5-20251101`. Stop if that model is unavailable instead of substituting another model.

Use one non-interactive invocation for the complete requested set. A single lesson means one English and Chinese pair; a batch means every requested pair is finished in the same invocation before Opus returns. The prompt stays short and names only:

- every target README pair;
- `scripts/guideline_advance.md` or `scripts/guideline_basic.md`;
- `$bpf-tutorial-writing-style`;
- `src/47-cuda-events`, `src/48-energy`, and `src/49-hid` as style references;
- the request to read the implementation, rewrite each paragraph in place, and finish both files before returning without questions.

Do not paste a second checklist, paragraph plan, fact inventory, or review rubric into the prompt. Add a technical fact only when it is unavailable in the repository.

Run Claude from the repository root with the pinned model and permission to read the repository and write only the target README files. Opus does not commit or push.

## 4. Check the result

Inspect both files and the diff instead of trusting the model's final message. Confirm that:

- both languages are complete and tell the same technical story;
- the opening reads like a tutorial rather than an abstract or feature list;
- the relevant eBPF and kernel background appears before details that depend on it;
- the high-level mechanism is explained before code sections;
- compilation/execution is AFTER code analysis;
- every core source file appears once in a complete ordinary Markdown fence;
- code, commands, output, versions, requirements, cleanup, and limits agree with the repository;
- the opening source link points only to the lesson directory;
- every published link uses a stable absolute `https://` URL; GitHub, kernel.org, and authoritative documentation sites are valid, while relative links are prohibited;
- no local infrastructure, prompt, model, agent, or trace detail appears in public text.

Check source blocks with the bundled `sync-source-blocks.py`, then run `git diff --check`, the lesson build, its tests, and the relevant runtime test. Treat a functional run as a functional run rather than a benchmark.

Read the finished pair once as an intermediate eBPF developer. Remove template-like detours, repeated setup, unexplained jargon, and details that belong only to the test harness. If a concrete problem remains, give Opus a short defect list in the same session and let it revise the affected paragraphs before returning. Keep prompts, responses, partial drafts, and failed runs; never delete real conversation or agent history.

Stop after the reviewed local result unless the user asks to commit, push, or update a PR.
