---
name: write-bpf-production-tutorial
description: Design, write, or rewrite one practical bilingual bpf-developer-tutorial lesson with pinned Claude Opus 4.5, then verify the public workflow and prose against the implementation. Use when creating README.md and README.zh.md, checking whether a tutorial tool has a realistic CLI and lifecycle, preserving complete kernel source, testing the example, or preparing tutorial changes for review.
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

Collect the facts the reader needs: the problem, why traditional approaches fail, the kernel/user-space flow, feature versions, requirements, intended public commands, real output, concurrency or admission behavior, cleanup, limits, and references. Keep every claim grounded in the code, tests, captured output, or a primary source. Preserve an existing draft before a from-scratch rewrite.

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

## 3. Structure requirements

For advanced tutorials (40+), follow this exact section order as defined in `$bpf-tutorial-writing-style`:

1. **Title + Introduction**: Concrete problem scenario, link to source
2. **Background / Why This Approach**: Explain traditional approaches and their limitations, then what eBPF enables
3. **High-Level Mechanism**: How the feature works before showing code
4. **Code Implementation**: Complete kernel/BPF source and core headers, plus a complete user-space loader when concise or focused user-space excerpts when long, then paragraph explanations
5. **Additional Concepts** (if needed)
6. **Compilation and Execution**: AFTER code analysis, not before
7. **Summary + Call to Action**
8. **References**

The "Background / Why" section is critical. It must explain:
- What traditional approaches exist
- Why each doesn't work well
- What the eBPF approach enables

## 4. Let Opus write

Claude Opus writes all reader-facing tutorial prose. Use the exact model ID `claude-opus-4-5-20251101`. Stop if that model is unavailable instead of substituting another model.

Use one non-interactive invocation for the complete English and Chinese pair. The prompt stays short and names only:

- the two target README files;
- `scripts/guideline_advance.md` or `scripts/guideline_basic.md`;
- `$bpf-tutorial-writing-style`;
- `src/47-cuda-events`, `src/48-energy`, and `src/49-hid` as style references;
- the request to read the implementation and write both files completely before returning.

Do not paste a second checklist, paragraph plan, fact inventory, or review rubric into the prompt. Add a technical fact only when it is unavailable in the repository.

Run Claude from the repository root with the pinned model and permission to read the repository and write the two README files. Opus does not commit or push.

## 5. Check the result

Inspect both files and the diff instead of trusting the model's final message. Confirm that:

- both languages are complete and tell the same technical story;
- the documented command, target, lifecycle, signals, concurrency bounds, cleanup, and health output match the practical design gate;
- the opening reads like a tutorial rather than an abstract or feature list;
- there is a "Why" section explaining traditional approaches and their limitations;
- the high-level mechanism is explained BEFORE code sections;
- compilation/execution is AFTER code analysis;
- every kernel/BPF source and core header appears once in a complete ordinary Markdown fence; a concise user-space loader should also be complete, while a long loader may use focused excerpts that cover the normal public control flow;
- code, commands, output, versions, requirements, cleanup, and limits agree with the repository;
- sample output comes from the normal public workflow and contains no test-harness or migration/deprecation narration;
- the opening source link points only to the lesson directory;
- every published link is an absolute `https://github.com/...` URL;
- no local infrastructure, prompt, model, agent, or trace detail appears in public text.

Check the required complete-source inventory with the bundled `sync-source-blocks.py`: always include kernel/BPF sources and core headers, and include user-space files only when the README presents them as complete. Then run `git diff --check`, the lesson build, its tests, the exact documented public command, and the relevant runtime test. Treat a functional run as a functional run rather than a benchmark.

Read the finished pair once as an intermediate eBPF developer. If a concrete problem remains, give Opus a short defect list in the same session and let it revise the whole pair before returning. Keep prompts, responses, partial drafts, and failed runs; never delete real conversation or agent history.

Stop after the reviewed local result unless the user asks to commit, push, or update a PR.
