---
name: write-bpf-production-tutorial
description: Create or revise a tested bilingual bpf-developer-tutorial lesson from the implementation and real runtime evidence. Use for tutorial scope, pinned Claude Opus 4.5 authorship, README drafting, technical flow diagrams, exact source inclusion, host builds, KVM tests, supervised completion, and PR preparation. Pair with bpf-tutorial-writing-style for prose decisions.
---

# Write a BPF Tutorial

Keep the workflow small. Claude Opus 4.5 writes all tutorial prose. Codex supervises source fidelity, actual completion, bilingual consistency, validation, and publication. Do not add other writers, reviewer panels, task ledgers, reviewer databases, or extra process files.

Invoke `$bpf-tutorial-writing-style` before writing or reviewing README prose.

## Pinned writer

Use the exact model ID `claude-opus-4-5-20251101` through Claude Code. Never use `opus`, `latest`, a default model, a fallback model, or another provider for tutorial prose. If this exact model is unavailable, stop and report the block instead of substituting another writer.

Use exactly one non-interactive Claude invocation for one lesson. Require Opus to edit the existing README files in place, one specific sentence or paragraph at a time and in document order. Each Edit operation must have a narrow target. It must not generate a replacement article and overwrite the file as a whole. It must preserve the existing code-block positions while revising the prose around each block, first completing natural Chinese and then matching English from the same facts.

The initial prompt must contain the complete task, source-fidelity rules, style rules, and final audit checklist. Opus must not ask Codex or the user a question, pause for confirmation, return a partial progress report, or stop after one language or one section. It may return only after both README files have been rewritten from beginning to end and it has run its own baseline comparison and formatting checks. Do not split the main rewrite into planned paragraph batches, switch models, or let Codex fill in prose afterward.

A typical non-interactive invocation is:

```bash
claude -p \
  --model claude-opus-4-5-20251101 \
  --effort high \
  --permission-mode acceptEdits \
  --allowedTools 'Read,Edit,Grep,Glob,Bash(git show *),Bash(git diff *),Bash(git status *)' \
  --output-format json
```

Give Opus access only to the lesson, its implementation and tests, the selected precedents, these repository-local Skills, and read-only baseline inspection through `git show` and `git diff`. Tell it to edit only the English and Chinese README pair and never commit, push, or publish.

## 1. Prepare the fact pack and technical draft

Codex prepares the complete input before invoking Opus. Read the entry README pair, implementation, tests, Makefile, captured output, and primary upstream references. Read these bilingual precedents in full:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/47-cuda-events> for end-to-end depth;
- <https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/49-hid> for an approachable teaching voice;
- at most one closer completed lesson when it contributes a subsystem-specific pattern.

Build a private fact pack that accounts for every mechanism, number, version, requirement, failure path, cleanup behavior, limitation, output field, and reference that the final lesson must retain. Include useful verified background from source code and primary upstream material. More context is helpful only when it is source-grounded; do not pad the pack with plausible but unverified history, adoption, performance, or production claims.

Prepare a complete technical draft before Opus writes. For an existing lesson, the entry README pair is the initial draft: repair factual gaps and add verified missing context without polishing the voice. For a new lesson, write a direct, comprehensive bilingual technical draft from the fact pack. Completeness and traceability matter more than style at this stage. Keep the fact pack private and do not add planning files to the repository.

Write down two private working sentences as part of the fact pack: who the reader is, and what they should be able to explain or run at the end.

Prepare an opening background ladder from primary sources. Identify the lesson once as part of the **eBPF Tutorial by Example** series, explain the small amount of general eBPF context needed for this example, then name the enabling feature, the first Linux release that contains it, and the capability that release added. End the ladder by connecting that capability directly to the program the reader will build. When the example combines features introduced in different releases, account for each version boundary and explain why the combination matters.

Keep this background specific to the lesson. Useful context includes where the verified BPF program runs, how user space loads or attaches it, which hook, iterator, map, kfunc, `struct_ops`, dynptr, or callback carries the work, and how data returns to user space. Support version and capability claims with a primary kernel commit, documentation page, or selftest already included in the fact pack.

Choose an honest scope. A lesson may teach a small operational tool or a focused kernel feature. Do not call a lab demo production-ready, and do not invent a production story that the CLI, output, and tests cannot support.

Decide once whether a technical diagram materially improves the lesson. A diagram earns its place when the reader must track at least three dependent state changes, a branch or retry loop, ownership across kernel and user space, or one source that affects several downstream components. A short linear filter or one-step attachment usually reads better as prose.

Codex prepares technical diagrams from the verified fact pack before the Opus prose pass. Prefer a reviewable text source such as Graphviz DOT or Mermaid, or a directly maintained SVG, and commit that source beside the rendered PNG. Keep one language-neutral diagram when code identifiers carry the meaning; use paired Chinese and English assets only when prose labels are essential. Technical flowcharts come from code and tests rather than generative illustration.

Render the asset deterministically and record a reproducible command in the fact pack. Use a descriptive image name, readable text at normal README width, restrained color, and a clear branch or ownership direction. Published Markdown uses descriptive alt text and a canonical absolute GitHub image target such as `https://github.com/eunomia-bpf/bpf-developer-tutorial/raw/main/src/<lesson>/<diagram>.png`. Give Opus the finished asset and source so it can introduce the diagram, connect it to the running example, and explain the important branch immediately afterward.

## 2. Verify the implementation

Build on the host. Use `$test-bpf-tutorial-kvm` for load, attach, and runtime behavior when the host kernel cannot run the feature safely. Exercise the normal path, one meaningful failure or boundary path, and cleanup. Record the commands, guest kernel version and commit, and real output needed by the README.

Do not turn the README into a validation transcript. Runtime provenance supports the tutorial, but the reader-facing mechanism remains the story.

## 3. Give the complete pack to Opus

Give pinned Opus the entry pair, the complete technical draft, the fact pack, implementation and evidence, and the project-provided advanced tutorial guidelines through `$bpf-tutorial-writing-style`. The initial prompt must explicitly separate authoritative lesson facts from voice-only examples. Opus may reorganize and rewrite the supplied facts, but it must not introduce technical content from a style sample or precedent unless that content already appears in the fact pack.

The lesson must start from one short, truthful scene that the implementation can reproduce, then follow one packet, event, task, device interaction, or failure through the whole kernel/user-space path. Use the scene to raise the technical question before naming every mechanism, requirement, counter, and limitation. Never invent a customer, outage, production deployment, performance result, or tool capability to make the opening sound important.

Immediately after the scene, use one or two compact paragraphs for the opening background ladder. The reader should learn that this is one lesson in the **eBPF Tutorial by Example** series, which eBPF execution and attachment model matters here, when the enabling feature entered Linux, what new operation it made possible, and why this example depends on it. Keep detailed commit IDs and compatibility tables in the later requirements or references sections.

Include the complete core source exactly as implemented, then walk through the important mechanisms. Tell Opus explicitly to use repeated local edits in document order and to continue without returning until the last paragraph of the second language is complete. Replacing the complete README in one write is a workflow failure even when the final prose looks acceptable.

Follow the selected precedent's component rhythm. Introduce one component, present its complete source inline, and explain its important logic before moving to the next component. Do not hide source in `<details>` or collect every file into one uninterrupted source dump. The source must remain searchable, copyable, and byte-exact.

Explain advanced eBPF behavior, not ordinary C syntax. Keep build, run, expected output, requirements, summary, and primary references. Explain cleanup as part of the normal mechanism instead of turning it into a warning section. Compress failure conditions, limitations, and safety boundaries into one short paragraph of at most two sentences near the end.

Use one opening complete-source callout whose only target is the lesson directory at `https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/<lesson>`. The directory is the single entry point for implementation files, the `Makefile`, fixtures, and tests; introduce individual filenames as code labels beside their complete blocks instead of turning the opening into a file-link catalog.

Use canonical GitHub absolute URLs for every other Markdown link. Never publish a `./` or `../` target or a link to another host. If no stable GitHub URL exists, omit the link. This repository rule overrides link examples in older lessons and the advanced guideline's website call to action.

Do not publish local infrastructure details. Keep workspace paths, shared lab repository names, VM names, host-to-guest copy steps, cache locations, and agent trace paths out of the README and PR description. Public reproducibility text may state the architecture, kernel version and commit, required configuration, commands, and captured output.

Opus must write Chinese as Chinese, using the voice sample and rules in `$bpf-tutorial-writing-style`, then write natural English with the same promise, structure, source, commands, evidence, and limits. It must not translate sentence by sentence. It must finish both files in the same lesson session.

## 4. Supervise actual completion

Do not accept Opus's final message as evidence that the work is complete. Inspect the files and diff. Confirm that both README files changed, every requested prose paragraph was actually rewritten, every source file still appears exactly once, and code, commands, captured output, versions, requirements, failure behavior, cleanup, limitations, and references remain intact.

For a full rewrite, compare prose outside fenced blocks with the entry version. Unchanged titles, tables, commands, output, and reference entries may be intentional. Unchanged explanatory paragraphs are evidence that the rewrite is incomplete unless the user explicitly exempted them. Inspect diff hunk distribution as well: changes concentrated only at the opening or ending do not satisfy a paragraph-by-paragraph rewrite.

When the lesson contains a diagram, inspect the rendered image as well as its source. Confirm that every node and edge follows the implementation, both languages introduce the same figure and draw the same conclusion, the PNG remains legible at README width, and the absolute GitHub image target points to the committed asset.

Codex performs this postcondition check after the one complete rewrite. If it finds a concrete defect, reject Opus's self-report and send one exact defect list back to the same pinned-model session. Opus must fix every listed issue without asking questions and rerun the final checks. This supervised correction is not permission to draft the lesson in batches: the first invocation must still attempt the entire Chinese and English pair before returning.

Codex may point out omissions, contradictions, awkward passages, broken links, or failed checks, but Opus must make every reader-facing prose revision. After the supervised Opus correction, Codex may apply a deterministic non-prose correction such as canonicalizing a verified link target, normalizing line endings, or restoring a source block byte-for-byte from its real file. It must not use this exception to rewrite wording, repair missing explanation, or introduce facts.

Preserve the model response, failed run, partial diff, prompt, and session history. Never delete, truncate, overwrite, or clean real conversation history, agent traces, prompts, partial runs, or failed runs.

## 5. Run one reader review

Read both files from top to bottom as an intermediate eBPF developer. Fix the text when:

- the opening reads like an abstract, specification, PR description, or test report;
- a large code wall arrives before the reader has a useful mental model;
- setup, conflicts, signals, KVM provenance, or limitations interrupt the main mechanism;
- a section catalogs facts without explaining cause and effect;
- the scenario promises a tool more capable than the implementation;
- Chinese follows English word order or switches languages unnecessarily;
- the reader reaches the end remembering only a feature name or validation transcript.

For a rewrite, compare the finished pair with the entry version once. Confirm that code, commands, captured output, versions, requirements, cleanup, the compact final boundary, and primary references remain accurate. Failure and limitation details may be condensed into the required two-sentence ending instead of surviving as a catalog. Every other removed passage should be repetition, stale framing, or material that moved to a better place. Word counts, heading counts, and repeated-term counts can expose bloat, but they are diagnostics rather than targets.

This is the normal review gate. Keep the pinned Opus session as the only prose editor. Codex reports concrete defects and reruns deterministic checks; Opus revises the affected paragraphs. The exact model identity is required by the workflow, but it is not evidence of quality. Only the finished artifact and passing checks are evidence.

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

Run `git diff --check`, the lesson build, the relevant host tests, the KVM runtime test, and repository documentation checks. Re-render every diagram from its committed text or vector source and confirm that the generated PNG matches the committed asset. Inspect the final diff for unintended files. Commit and push the repository-local Skills and tutorial changes only after these checks pass. Do not merge unless the user asks.
