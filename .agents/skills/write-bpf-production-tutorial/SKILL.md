---
name: write-bpf-production-tutorial
description: Create or revise bilingual bpf-developer-tutorial lessons as small, production-realistic eBPF tools with host builds, benchmark-kernel KVM tests, reproducible evidence, and mandatory independent cross-model prose review. Use when proposing, implementing, documenting, reviewing, or preparing a PR for a new eBPF tutorial, especially when deciding between numbered lessons, features, networking, security, or xpu/gpu placement.
---

# Write BPF Production Tutorials

Build a useful tool around a kernel capability. Do not publish a wrapper around an upstream selftest or a feature-only API tour.

## Separate authorship from acceptance

- Let Codex, a human, or another capable model author and revise the lesson. Treat model identity as provenance, not proof of quality.
- Require a read-only review by a different model family after every completed writing or substantial editing pass.
- Give the reviewer the finished English and Chinese files, implementation, tests, real output, primary sources, and the repository rulebooks. Do not give it the author's diagnosis or a list of expected defects.
- Resolve every valid **Must fix** finding. Record a concrete disposition for every **Should fix** and **Consider** finding, then run an external re-review of the final diff.
- Do not call the prose finished while any valid Must-fix remains. If no different model family is available, report `cross-model review unavailable`.
- Use `scripts/run-external-review.sh` for Grok 4.5 or OpenCode GLM 5.2 reviews. Choose one reviewer for a normal pass and at most two when the first review finds factual uncertainty or substantial bilingual problems. Do not run every available model by default. The wrapper is read-only and preserves the complete prompt, trace, and manifest under `~/.local/state/bpf-tutorial-reviews/runs/`.
- Keep `scripts/run-claude-writer.sh` only as an optional, trace-verified `claude-opus-4-6[1m]` authoring channel.
- Never delete, truncate, rewrite, or clean any writer or reviewer trace directory. Preserve failed and partial runs too.

## Establish the tutorial contract

Before coding, write one sentence naming:

1. the production failure or operational need;
2. the user-visible command and result;
3. the kernel capability that makes it possible;
4. the positive and negative paths that prove it works.

Reject proposals whose only result is “the program loaded,” “the helper returned success,” or “the upstream selftest passed.”

Read [references/tutorial-acceptance.md](references/tutorial-acceptance.md) before selecting scope or placement. Read [references/repository-precedents.md](references/repository-precedents.md) and the selected precedent lessons in full before drafting. Read [references/writing-guide.md](references/writing-guide.md) before drafting. Read [references/review-checklist.md](references/review-checklist.md) before external review.

## Implement and verify

1. Read the repository contract, nearby lesson code, Makefiles, documentation generators, and CI workflows.
2. Keep one production scenario per PR. Start from the remote default branch for every PR.
3. Follow existing libbpf and CO-RE patterns. Add a deterministic workload, observable result, cleanup, and a relevant failure path.
4. Build on the host without loading BPF there.
5. Use `$test-bpf-tutorial-kvm` for every load, attach, and runtime test. Record guest kernel provenance and real output.
6. Add a compile CI step. Add a runtime feature probe or an explicit skip when ordinary CI lacks the required kernel.
7. Run documentation generators and link/unit tests.

## Draft from evidence

First write a precedent brief that names two or three existing bilingual lessons read in full, including one with the same operational shape. Use `src/47-cuda-events/README.md` and `README.zh.md` as a default precedent for a production tracer or accelerator tool. State which structural patterns to reuse, which legacy weaknesses to avoid, and why the new lesson has a distinct operational job. Do not draft until this brief exists.

Create a task file outside the lesson with:

- the exact README paths the author may edit;
- the production scenario and intended audience;
- the final code paths and CLI;
- verified build and guest commands;
- real captured output with private paths and identities removed;
- minimum kernel, libbpf, config, privilege, and hardware requirements;
- primary upstream references;
- the precedent brief and exact sibling README paths;
- facts or claims the author must not add.

Draft or revise both README files from that evidence. The optional exact-Claude authoring path is:

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

Run a different model family read-only over the final files, implementation evidence, and the precedent READMEs named in the brief. Pass repository-relative paths with repeated `--file` arguments:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
"$TUTORIAL_ROOT/.agents/skills/write-bpf-production-tutorial/scripts/run-external-review.sh" \
  --reviewer grok \
  --repo "$TUTORIAL_ROOT" \
  --task /absolute/path/to/review-task.md \
  --file src/<lesson>/README.md \
  --file src/<lesson>/README.zh.md \
  --file src/<lesson>/<tool>.bpf.c \
  --file src/<lesson>/<tool>.c \
  --file src/<lesson>/tests/<test>.py \
  --file src/47-cuda-events/README.md \
  --file src/47-cuda-events/README.zh.md
```

Use `--reviewer glm` for the fixed OpenCode model `zai-coding-plan/glm-5.2`. Apply valid findings with targeted edits, diff-check both languages, rerun documented commands, and invoke an external reviewer again. The gate passes only when the final trace reports no valid Must-fix item.

## Prepare the PR

- Include only one lesson and the minimal generated index/compatibility changes.
- Explain the production problem before the kernel feature in the PR body.
- Report the host build, KVM positive test, negative/cleanup test, guest kernel provenance, documentation tests, author identity, review manifests, and finding dispositions.
- Follow the repository's review, Copilot, and monitored CI gates. Do not merge unless the user asks.
