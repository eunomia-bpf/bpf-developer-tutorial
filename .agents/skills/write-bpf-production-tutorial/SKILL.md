---
name: write-bpf-production-tutorial
description: Create or revise a tested bilingual bpf-developer-tutorial lesson from the implementation and real runtime evidence. Use for tutorial scope, README drafting, exact source inclusion, host builds, benchmark-kernel KVM tests, self-review, and PR preparation. Pair with bpf-tutorial-writing-style for prose decisions. External models are optional, never a required gate.
---

# Write a BPF Tutorial

Keep the workflow small. The normal path has one author, one reader-focused self-review, and the relevant build and runtime checks. Do not create task ledgers, reviewer databases, mandatory model rounds, or extra process files for an ordinary lesson.

Invoke `$bpf-tutorial-writing-style` before writing or reviewing README prose.

## 1. Understand the lesson

Read the implementation, tests, Makefile, captured output, and primary upstream references. Read these bilingual precedents in full:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events> for end-to-end depth;
- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/49-hid> for an approachable teaching voice;
- at most one closer completed lesson when it contributes a subsystem-specific pattern.

Write down only two private working sentences: who the reader is, and what they should be able to explain or run at the end. Do not add this planning material to the repository.

Choose an honest scope. A lesson may teach a small operational tool or a focused kernel feature. Do not call a lab demo production-ready, and do not invent a production story that the CLI, output, and tests cannot support.

## 2. Verify the implementation

Build on the host. Use `$test-bpf-tutorial-kvm` for load, attach, and runtime behavior when the host kernel cannot run the feature safely. Exercise the normal path, one meaningful failure or boundary path, and cleanup. Record the commands, guest kernel version and commit, and real output needed by the README.

Do not turn the README into a validation transcript. Runtime provenance supports the tutorial, but the reader-facing mechanism remains the story.

## 3. Draft the English lesson

Follow the project-provided advanced tutorial guidelines through `$bpf-tutorial-writing-style`. Start with one concrete situation, explain the whole kernel/user-space path, include the complete core source exactly as implemented, then walk through the important mechanisms.

Follow the selected precedent's component rhythm. Introduce one component, present its complete source inline, and explain its important logic before moving to the next component. Do not hide source in `<details>` or collect every file into one uninterrupted source dump. The source must remain searchable, copyable, and byte-exact.

Explain advanced eBPF behavior, not ordinary C syntax. Keep build, run, expected output, requirements, cleanup, limitations, summary, and primary references. State once what the evidence proves and once where the example stops.

Use canonical GitHub absolute URLs for every Markdown link, including links to the current lesson's source, `Makefile`, and tests. Never publish a `./` or `../` target or a link to another host. If no stable GitHub URL exists, omit the link. This repository rule overrides link examples in older lessons and the advanced guideline's website call to action.

Do not publish local infrastructure details. Keep workspace paths, shared lab repository names, VM names, host-to-guest copy steps, cache locations, and agent trace paths out of the README and PR description. Public reproducibility text may state the architecture, kernel version and commit, required configuration, commands, and captured output.

## 4. Write Chinese from the same facts

Write `README.zh.md` from the implementation and the paragraph's purpose, not by translating English sentence by sentence. Keep the same section progression, code, commands, output, claims, limitations, and references. Allow natural Chinese sentence and paragraph boundaries.

## 5. Run one reader review

Read both files from top to bottom as an intermediate eBPF developer. Fix the text when:

- the opening reads like an abstract, specification, PR description, or test report;
- a large code wall arrives before the reader has a useful mental model;
- setup, conflicts, signals, KVM provenance, or limitations repeat;
- a section catalogs facts without explaining cause and effect;
- the scenario promises a tool more capable than the implementation;
- Chinese follows English word order or switches languages unnecessarily;
- the reader reaches the end remembering only a feature name or validation transcript.

For a rewrite, compare the finished pair with the entry version once. Confirm that code, commands, captured output, versions, requirements, failure behavior, cleanup, limitations, and primary references did not disappear or change. Every removed passage should be repetition, stale framing, or material that moved to a better place. Word counts, heading counts, and repeated-term counts can expose bloat, but they are diagnostics rather than targets.

This is the normal review gate. A different model is optional when the user asks for one or when the author is stuck on a concrete passage. Use at most one model for one focused pass, inspect its diff, and keep Codex or the human author as final editor. Model identity is never evidence of quality.

Never delete, truncate, overwrite, or clean real conversation history, agent traces, prompts, partial runs, or failed runs. This preservation rule applies whether or not an external model is used.

## 6. Validate and publish

Check every complete-source block in the English and Chinese pair:

```bash
python3 .agents/skills/write-bpf-production-tutorial/scripts/sync-source-blocks.py \
  --repo "$(git rev-parse --show-toplevel)" \
  --readme src/<lesson>/README.md \
  --readme src/<lesson>/README.zh.md \
  --expected-source src/<lesson>/<tool>.bpf.c \
  --expected-source src/<lesson>/<tool>.c \
  --check
```

Repeat `--expected-source` for each complete shared header. Use ordinary Markdown fenced code blocks without HTML markers. Copy complete source from the real file, then run the checker; it is deliberately read-only.

Run `git diff --check`, the lesson build, the relevant host tests, the KVM runtime test, and repository documentation checks. Inspect the final diff for unintended files. Commit and push the repository-local Skills and tutorial changes only after these checks pass. Do not merge unless the user asks.
