---
name: write-bpf-production-tutorial
description: Write or rewrite one bilingual bpf-developer-tutorial lesson with pinned Claude Opus 4.5, then verify the result against the implementation. Use when creating README.md and README.zh.md, preserving full source, testing the example, or preparing tutorial changes for review.
---

# Write a BPF Tutorial

Use `$bpf-tutorial-writing-style` for the finished prose. Keep this workflow small: prepare reliable source material, let one pinned writer complete both languages, then check what it actually wrote.

## 1. Prepare the lesson

Read these inputs before writing:

- `scripts/guideline_advance.md`;
- both README files from `src/47-cuda-events` and `src/49-hid`;
- the lesson's implementation, headers, Makefile, fixtures, and tests;
- the current README pair when revising an existing lesson;
- primary upstream sources for versions and feature semantics.

Collect the facts the reader needs: the problem, kernel/user-space flow, feature versions, requirements, commands, real output, cleanup, limits, and references. Keep every claim grounded in the code, tests, captured output, or a primary source. Preserve an existing draft before a from-scratch rewrite.

Build and run the example when the environment supports it. Use `$test-bpf-tutorial-kvm` for kernel features that need the repository's KVM environment. Runtime details support the tutorial; local workspace paths, VM names, shared repositories, caches, prompts, and agent traces stay private.

## 2. Let Opus write

Claude Opus writes all reader-facing tutorial prose. Use the exact model ID `claude-opus-4-5-20251101`. Stop if that model is unavailable instead of substituting another model.

Use one non-interactive invocation for the complete English and Chinese pair. The prompt stays short and names only:

- the two target README files;
- `scripts/guideline_advance.md`;
- `$bpf-tutorial-writing-style`;
- `src/47-cuda-events` and `src/49-hid` as style references;
- the request to read the implementation and write both files completely before returning.

Do not paste a second checklist, paragraph plan, fact inventory, or review rubric into the prompt. Add a technical fact only when it is unavailable in the repository.

Run Claude from the repository root with the pinned model and permission to read the repository and write the two README files. Opus does not commit or push.

## 3. Check the result

Inspect both files and the diff instead of trusting the model's final message. Confirm that:

- both languages are complete and tell the same technical story;
- the opening reads like a tutorial rather than an abstract or feature list;
- every core source file appears once in a complete ordinary Markdown fence;
- code, commands, output, versions, requirements, cleanup, and limits agree with the repository;
- the opening source link points only to the lesson directory;
- every published link is an absolute `https://github.com/...` URL;
- no local infrastructure, prompt, model, agent, or trace detail appears in public text.

Check source blocks with the bundled `sync-source-blocks.py`, then run `git diff --check`, the lesson build, its tests, and the relevant runtime test. Treat a functional run as a functional run rather than a benchmark.

Read the finished pair once as an intermediate eBPF developer. If a concrete problem remains, give Opus a short defect list in the same session and let it revise the whole pair before returning. Keep prompts, responses, partial drafts, and failed runs; never delete real conversation or agent history.

Stop after the reviewed local result unless the user asks to commit, push, or update a PR.
