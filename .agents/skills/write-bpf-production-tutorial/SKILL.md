---
name: write-bpf-production-tutorial
description: Write or rewrite bilingual bpf-developer-tutorial lessons by assigning each tutorial's English and Chinese README pair to its own pinned Claude Opus 4.5 process. Use when creating or revising README.md and README.zh.md while requiring Claude to edit one tutorial paragraph by paragraph from the reader's perspective, allowing Codex to make local word and punctuation edits only and forbidding an additional prose review or rewrite request.
---

# Write a BPF Tutorial

Keep one writer for the complete reader-facing text. One Claude Opus process performs one free, paragraph-by-paragraph pass over one tutorial's English and Chinese README pair. Codex coordinates the invocation and performs mechanical checks without becoming a second writer or reviewer.

## 1. Give Opus the complete task once

Use the exact model ID `claude-opus-4-5-20251101`. Stop when that model is unavailable instead of substituting another model.

Run one non-interactive invocation from the repository root for one tutorial directory. Name that tutorial's English and Chinese README pair, the applicable `scripts/guideline_advance.md` or `scripts/guideline_basic.md`, and existing tutorials as general references. Ask Claude to revise every paragraph freely from the reader's perspective, improve readability, adjust content or structure wherever useful, finish both files before returning, and ask no questions.

Start a separate Claude process for every additional tutorial. Never batch README pairs from different tutorial directories into one process.

Keep the prompt to that request. Do not add a paragraph plan, fact inventory, style checklist, defect list, review rubric, acceptance criteria, or instructions for a later revision. Give Claude permission to read the repository and write only the target README files. Claude does not commit or push.

## 2. Preserve single-writer ownership

Treat Claude as the sole author of sentences, headings, paragraph order, explanations, and translations. After Claude returns, Codex may make local word-choice and punctuation edits. Keep those edits within the existing sentence meaning and paragraph structure. Codex must not add or remove information, rewrite sentences, reorder paragraphs, change headings, shorten or expand explanations, or alter translations substantively.

Use exactly one Claude writing pass per tutorial. Do not ask Claude to review its result, respond to a defect list, polish selected paragraphs, or rewrite the tutorial again. Do not invoke another model, subagent, or independent reviewer for the prose. When the result needs another writing pass, report that fact to the user and wait for an explicit request.

## 3. Perform mechanical checks only

Check only that the intended files exist, remain nonempty, stay within the requested file scope, contain no merge markers, and expose no local paths, usernames, secrets, prompts, or private infrastructure. Do not count lines or code fences as a quality proxy. Never run `sync-source-blocks.py` or compare README code fences against a complete repository source inventory as writing acceptance. Do not require the README to contain a byte-exact copy of every source file, and do not treat an omitted complete user-space loader as a failure. These checks establish basic file integrity; they are not a prose, style, structure, factual, or technical review.

Run repository formatting or documentation validation only when it does not rewrite the text. Report mechanical failures without repairing words or asking Claude to revise them. Preserve prompts, responses, drafts, and failed runs; never delete real conversation or agent history.

Stop with the local result unless the user explicitly asks to commit, push, or update a PR.
