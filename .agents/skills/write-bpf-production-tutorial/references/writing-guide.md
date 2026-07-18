# BPF tutorial writing guide

Write for developers who want to reproduce a small, useful eBPF tool. Use direct English and natural Chinese. Prefer short, connected sentences over academic prose, release-note inventories, or marketing claims.

Before prose, write a private architecture brief with one thesis, the reader's operational goal, the unique angle relative to nearby lessons, non-goals, a running scenario, and the role of each section. Also write the precedent brief required by `repository-precedents.md`. Build a progression from the operational problem through the mechanism and measured evidence to a practical boundary. Do not mirror an upstream selftest or kernel merge note.

## Required narrative

1. Open with a production incident or operational task the reader recognizes. Explain the consequence and the signal the tool will expose or control.
2. Show the command and verified result early. Do not begin with a generic definition of eBPF.
3. Explain the end-to-end flow from workload to hook, maps or kfuncs, user-space processing, and final output.
4. Present complete source when it stays readable. Otherwise use copyable 15–40 line excerpts and link to the complete lesson.
5. Explain only the kernel mechanisms needed to understand the tool. State minimum kernel/libbpf versions, configs, privileges, limitations, and cleanup.
6. Provide exact build and run commands. Use only output captured from a real run. Never invent benchmark numbers, events, PIDs, paths, or errors.
7. Include the positive path and one meaningful miss, failure, or unsupported path.
8. Close with what the operator can now learn or control, plus the repository and tutorial-site links.

## Style rules

- Use a specific title such as `# eBPF Tutorial by Example: Quarantine an Established TCP Connection`.
- Build a progressive explanation around one running example instead of listing features.
- Match the repository's established depth: explain the workload, BPF hook and state, event/control path, user-space behavior, CLI, verified run, failure path, cleanup, limits, and primary references. Omit any section the actual tool does not need.
- Borrow organization and voice from the selected precedents, never their scenario-specific facts, output, claims, or defects. The current rulebook overrides a weaker pattern in an older lesson.
- Use active voice and define technical terms through the example.
- Give each paragraph one job. Inspect English paragraphs above 110 words, Chinese paragraphs above 320 characters, and any run of three dense paragraphs.
- Avoid throat clearing, repeated summaries, vague claims, paper-like language, em dashes, semicolons joining independent clauses, and stacked one-line paragraphs.
- Use a colon only for a real list, code block, or table. Rewrite claim-colon-evidence and noun-phrase-colon openings as sentences.
- Keep subjects near their verbs, use concrete actors, and replace spec-sheet paragraphs with an argument that explains why each mechanism or number matters.
- Do not describe a demo as production-ready. State scope and missing hardening plainly.
- Preserve exact code, command, version, and output facts supplied in the task file.
- Link kernel claims to primary sources such as kernel commits, documentation, or selftests.

## Bilingual rules

- Keep English and Chinese headings, examples, commands, limitations, and claims aligned.
- Compose Chinese from the source facts and paragraph role rather than translating English sentence by sentence. Sentence and paragraph boundaries should differ when natural Chinese requires it.
- Keep product names, code, commands, file names, functions, and genuine terms of art in English. Translate ordinary concept nouns consistently, with a first-use English gloss only when useful.
- Do not start Chinese prose sentences with an English common noun. Use full-width Chinese punctuation and spaces between CJK text and Latin letters or digits.
- Keep code and verified console output identical.
- Do not use Chinese em dashes (`——`) or spaced English em dashes (` — `).

## Required ending links

Include direct links to:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- <https://eunomia.dev/tutorials/>

Do not add frontmatter unless nearby lessons use it.
