---
name: write-bpf-production-tutorial
description: Create or revise bilingual bpf-developer-tutorial lessons as small, production-realistic eBPF tools with host builds, benchmark-kernel KVM tests, reproducible evidence, and prose authored only by the exact Claude model claude-opus-4-6[1m]. Use when proposing, implementing, documenting, reviewing, or preparing a PR for a new eBPF tutorial, especially when deciding between numbered lessons, features, networking, security, or xpu/gpu placement.
---

# Write BPF Production Tutorials

Build a useful tool around a kernel capability. Do not publish a wrapper around an upstream selftest or a feature-only API tour.

## Enforce the author boundary

- Let the implementation agent design, code, test, and collect technical evidence.
- Require Claude Code with the exact model string `claude-opus-4-6[1m]` to author or revise `README.md` and `README.zh.md`.
- Invoke Claude only through `scripts/run-claude-writer.sh`. Do not expose a model override and do not configure a fallback model.
- Do not write tutorial prose with Codex or another model. Send factual corrections back through the same wrapper instead of rewriting paragraphs manually.
- Permit other models to review code or prose, but never to author replacement tutorial text.
- Preserve every wrapper trace and manifest under `~/.local/state/bpf-tutorial-writer/runs/`. Never delete, truncate, rewrite, or clean that directory.

## Establish the tutorial contract

Before coding, write one sentence naming:

1. the production failure or operational need;
2. the user-visible command and result;
3. the kernel capability that makes it possible;
4. the positive and negative paths that prove it works.

Reject proposals whose only result is “the program loaded,” “the helper returned success,” or “the upstream selftest passed.”

Read [references/tutorial-acceptance.md](references/tutorial-acceptance.md) before selecting scope or placement. Read [references/writing-guide.md](references/writing-guide.md) before invoking the writer.

## Implement and verify

1. Read the repository contract, nearby lesson code, Makefiles, documentation generators, and CI workflows.
2. Keep one production scenario per PR. Start from the remote default branch for every PR.
3. Follow existing libbpf and CO-RE patterns. Add a deterministic workload, observable result, cleanup, and a relevant failure path.
4. Build on the host without loading BPF there.
5. Use `$test-bpf-tutorial-kvm` for every load, attach, and runtime test. Record guest kernel provenance and real output.
6. Add a compile CI step. Add a runtime feature probe or an explicit skip when ordinary CI lacks the required kernel.
7. Run documentation generators and link/unit tests.

## Delegate the prose

Create a task file outside the lesson with:

- the exact README paths Claude may edit;
- the production scenario and intended audience;
- the final code paths and CLI;
- verified build and guest commands;
- real captured output with private paths and identities removed;
- minimum kernel, libbpf, config, privilege, and hardware requirements;
- primary upstream references;
- facts or claims Claude must not add.

Then run:

```bash
TUTORIAL_ROOT="$(git rev-parse --show-toplevel)"
"$TUTORIAL_ROOT/.agents/skills/write-bpf-production-tutorial/scripts/run-claude-writer.sh" \
  --repo "$TUTORIAL_ROOT" \
  --task /absolute/path/to/writer-task.md \
  --readme "$TUTORIAL_ROOT/src/<lesson>/README.md" \
  --readme "$TUTORIAL_ROOT/src/<lesson>/README.zh.md"
```

The wrapper must finish with a verified exact-model trace. Inspect both READMEs for matching structure and technical meaning, then rerun build and documentation commands exactly as written.

## Prepare the PR

- Include only one lesson and the minimal generated index/compatibility changes.
- Explain the production problem before the kernel feature in the PR body.
- Report the host build, KVM positive test, negative/cleanup test, guest kernel provenance, documentation tests, and model-trace manifest.
- Follow the repository's review, Copilot, and monitored CI gates. Do not merge unless the user asks.
