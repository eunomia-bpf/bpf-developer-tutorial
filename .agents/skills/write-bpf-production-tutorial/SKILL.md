---
name: write-bpf-production-tutorial
description: Run the repository-local workflow for proposing, implementing, verifying, documenting, reviewing, and preparing PRs for bilingual bpf-developer-tutorial lessons. Use for scope selection, host builds, benchmark-kernel KVM tests, reproducible evidence, author/reviewer provenance, and CI closure. Pair it with bpf-tutorial-writing-style for prose and bilingual style decisions.
---

# Write BPF Production Tutorials

Build a useful tool around a kernel capability. Do not publish a wrapper around an upstream selftest or a feature-only API tour.

This Skill owns the writing process, not writing style. Invoke `$bpf-tutorial-writing-style` before drafting, rewriting, translating, or reviewing README prose. Never substitute a global Skill for the repository-local style Skill.

## Separate authorship from acceptance

- Let Codex, a human, or another capable model author and revise the lesson. Treat model identity as provenance, not proof of quality.
- Require a read-only review by a different model family after every completed writing or substantial editing pass.
- Give the reviewer the finished English and Chinese files, implementation, tests, real output, primary sources, and the repository rulebooks. Do not give it the author's diagnosis or a list of expected defects.
- Resolve every valid **Must fix** finding. Record a concrete disposition for every **Should fix** and **Consider** finding, then run an external re-review of the final diff.
- Do not call the prose finished while any valid Must-fix remains. If no different model family is available, report `cross-model review unavailable`.
- Use `scripts/run-external-review.sh` for Grok 4.5 or OpenCode GLM 5.2 reviews. Choose one reviewer for a normal pass and at most two when the first review finds factual uncertainty or substantial bilingual problems. Do not run every available model by default. The wrapper is read-only and preserves the complete prompt, trace, and manifest under `~/.local/state/bpf-tutorial-reviews/runs/`.
- Keep `scripts/run-claude-writer.sh` only as an optional, trace-verified `claude-opus-4-6[1m]` authoring channel. It requires a clean checkout, authors inside a bubblewrap-protected isolated worktree, verifies the exact two-file diff, preserves a prompt, trace, manifest, and patch, then applies that patch to the real checkout.
- Never delete, truncate, rewrite, or clean any writer or reviewer trace directory. Preserve failed and partial runs too.

## Establish the tutorial contract

Before coding, write one sentence naming:

1. the production failure or operational need;
2. the user-visible command and result;
3. the kernel capability that makes it possible;
4. the positive and negative paths that prove it works.

Reject proposals whose only result is “the program loaded,” “the helper returned success,” or “the upstream selftest passed.”

Read [references/tutorial-acceptance.md](references/tutorial-acceptance.md) before selecting scope or placement. Read [references/repository-precedents.md](references/repository-precedents.md) and the required precedent lessons in full before drafting. Read [references/drafting-process.md](references/drafting-process.md) before creating the task file. Read [references/review-checklist.md](references/review-checklist.md) before external review. Read every reference required by `$bpf-tutorial-writing-style` before drafting and again before final review.

## Implement and verify

1. Read the repository contract, nearby lesson code, Makefiles, documentation generators, and CI workflows.
2. Keep one production scenario per PR. Start from the remote default branch for every PR.
3. Follow existing libbpf and CO-RE patterns. Add a deterministic workload, observable result, cleanup, and a relevant failure path.
4. Build on the host without loading BPF there.
5. Use `$test-bpf-tutorial-kvm` for every load, attach, and runtime test. Record guest kernel provenance and real output.
6. Add a compile CI step. Add a runtime feature probe or an explicit skip when ordinary CI lacks the required kernel.
7. Run documentation generators and link/unit tests.

## Draft from evidence

First write a precedent brief that confirms the required `47-cuda-events` and `49-hid` bilingual pairs were read in full, then names one additional lesson with the closest subsystem or operational shape when useful. State which teaching patterns to reuse, which legacy weaknesses to avoid, and why the new lesson has a distinct operational job. Do not draft until this brief exists.

Create a task file outside the lesson with:

- the exact README paths the author may edit;
- the production scenario and intended audience;
- the final code paths and CLI;
- verified build and guest commands;
- real captured output with private paths and identities removed;
- minimum kernel, libbpf, config, privilege, and hardware requirements;
- primary upstream references;
- the precedent brief and exact sibling README paths;
- a source-fidelity ledger covering every fact, command, code file, captured-output block, requirement, failure path, cleanup behavior, limitation, and reference that must survive a rewrite;
- facts or claims the author must not add.

Draft or revise both README files from that evidence and the repository-local style Skill. Present the complete core BPF and user-space source before the detailed walkthrough as required by the advanced tutorial guidelines. The optional exact-Claude authoring path is:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
"$TUTORIAL_ROOT/.agents/skills/write-bpf-production-tutorial/scripts/run-claude-writer.sh" \
  --repo "$TUTORIAL_ROOT" \
  --task /absolute/path/to/writer-task.md \
  --readme "$TUTORIAL_ROOT/src/<lesson>/README.md" \
  --readme "$TUTORIAL_ROOT/src/<lesson>/README.zh.md"
```

The wrapper must finish with a verified exact-model trace. When another author writes the files, record the author identity in the PR evidence instead.

## Run independent prose review

Run a different model family read-only over the final files, implementation evidence, the two required style precedents, and any additional precedent named in the brief. The wrapper embeds both repository-local Skills and their rulebooks. Pass repository-relative paths with repeated `--file` arguments:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
"$TUTORIAL_ROOT/.agents/skills/write-bpf-production-tutorial/scripts/run-external-review.sh" \
  --reviewer grok \
  --scope tutorial \
  --repo "$TUTORIAL_ROOT" \
  --task /absolute/path/to/review-task.md \
  --file src/<lesson>/README.md \
  --file src/<lesson>/README.zh.md \
  --file src/<lesson>/<tool>.bpf.c \
  --file src/<lesson>/<tool>.c \
  --file src/<lesson>/tests/<test>.py \
  --file src/47-cuda-events/README.md \
  --file src/47-cuda-events/README.zh.md \
  --file src/49-hid/README.md \
  --file src/49-hid/README.zh.md
```

Use `--reviewer glm` for the fixed OpenCode model `zai-coding-plan/glm-5.2`. Apply valid findings with targeted edits, diff-check both languages, rerun documented commands, and invoke an external reviewer again. The gate passes only when the final trace reports no valid Must-fix item.

## Prepare the PR

- Include only one lesson and the minimal generated index/compatibility changes.
- Explain the production problem before the kernel feature in the PR body.
- Report the host build, KVM positive test, negative/cleanup test, guest kernel provenance, documentation tests, author identity, review manifests, and finding dispositions.
- Account for every item in the source-fidelity ledger and state that complete core source appears unchanged in both languages.
- Follow the repository's review, Copilot, and monitored CI gates. Do not merge unless the user asks.
