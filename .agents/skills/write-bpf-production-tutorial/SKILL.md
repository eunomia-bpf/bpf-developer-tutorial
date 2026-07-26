---
name: write-bpf-production-tutorial
description: Write or rewrite bilingual bpf-developer-tutorial lessons by assigning each tutorial's English and Chinese README pair to its own pinned Claude Opus 4.5 process. Use when creating or revising README.md and README.zh.md while requiring Claude to edit one tutorial paragraph by paragraph from the reader's perspective, allowing Codex to make local word and punctuation edits only and forbidding an additional prose review or rewrite request.
---

# Write a BPF Tutorial

Keep one writer for the complete reader-facing text. One Claude Opus process performs one free, paragraph-by-paragraph pass over one tutorial's English and Chinese README pair. Codex coordinates the invocation and performs integrity and technical-fidelity checks without becoming a second prose writer or reviewer.

## 1. Give Opus the complete task once

Use the exact model ID `claude-opus-4-5-20251101`. Stop when that model is unavailable instead of substituting another model.

Run one non-interactive invocation from the repository root for one tutorial directory. Name that tutorial's English and Chinese README pair, its implementation, headers, Makefile, tests, the applicable `scripts/guideline_advance.md` or `scripts/guideline_basic.md`, and existing tutorials as general references. Ask Claude to read those sources, keep technical claims grounded in them, revise every paragraph freely from the reader's perspective, improve readability, adjust content or structure wherever useful, finish both files before returning, and ask no questions.

Start a separate Claude process for every additional tutorial. Never batch README pairs from different tutorial directories into one process.

Keep the prompt to that request. Do not add a paragraph plan, fact inventory, style checklist, defect list, review rubric, acceptance criteria, or instructions for a later revision. Give Claude permission to read the repository and write only the target README files. Claude does not commit or push.

## 2. Preserve single-writer ownership

Treat Claude as the sole author of sentences, headings, paragraph order, explanations, and translations. After Claude returns, Codex must make a local word-choice and punctuation pass. Keep those edits within the existing sentence meaning and paragraph structure. Codex must not add or remove information, rewrite sentences, reorder paragraphs, change headings, shorten or expand explanations, or alter translations substantively.

Reader-facing prose must not use em dashes, doubled Chinese em dashes, or en dashes as sentence punctuation. After every Claude writing pass, run `rg -n '[—–]'` on the target README pair and inspect every match outside source code. Replace prose matches with commas, semicolons, colons, parentheses, or separate sentences. Hyphens that belong to code identifiers, command options, URLs, or established technical names remain unchanged.

Use exactly one Claude writing pass per tutorial. Do not ask Claude to review its result, respond to a defect list, polish selected paragraphs, or rewrite the tutorial again. Do not invoke another model, subagent, or independent reviewer for the prose. When the result needs another writing pass, report that fact to the user and wait for an explicit request.

## 3. Check integrity and technical fidelity

Check that the intended files exist, remain nonempty, stay within the requested file scope, contain no merge markers, and expose no local paths, usernames, secrets, prompts, or private infrastructure. The mandatory dash scan in the previous section is part of Codex's punctuation pass. Do not count lines or code fences as a quality proxy. Do not require the README to contain a byte-exact copy of every source file, and do not treat an omitted complete user-space loader as a failure.

Verify every included source excerpt, command, output sample, version, requirement, and behavior claim against the implementation, tests, captured evidence, or a primary source. Use `sync-source-blocks.py` for blocks intended to reproduce complete repository files when the script supports the lesson, but do not compare focused excerpts against a required inventory of every source file. Run non-rewriting repository documentation validation. When technical commands, runtime behavior, requirements, or output claims changed, run the smallest relevant build or test, or identify exact current validation evidence for the unchanged implementation.

These are content-fidelity checks, not a second prose-writing pass. Codex may make the smallest factual correction needed to match the implementation or evidence, but must not ask another model, subagent, or independent reviewer to rewrite or polish content-only changes. Preserve prompts, responses, drafts, and failed runs; never delete real conversation or agent history.

Stop with the local result unless the user explicitly asks to commit, push, or update a PR.
