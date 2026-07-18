# BPF tutorial writing guide

Write for developers who want to reproduce a small, useful eBPF tool. Use oral, direct English and natural Chinese. Prefer short, connected sentences over academic prose or marketing claims.

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
- Use active voice and define technical terms through the example.
- Avoid throat clearing, repeated summaries, vague claims, paper-like language, em dashes, and stacked one-line paragraphs.
- Do not describe a demo as production-ready. State scope and missing hardening plainly.
- Preserve exact code, command, version, and output facts supplied in the task file.
- Link kernel claims to primary sources such as kernel commits, documentation, or selftests.

## Bilingual rules

- Keep English and Chinese headings, examples, commands, limitations, and claims aligned.
- Translate naturally rather than sentence by sentence.
- Keep code and verified console output identical.
- Do not use Chinese em dashes (`——`) or spaced English em dashes (` — `).

## Required ending links

Include direct links to:

- <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- <https://eunomia.dev/tutorials/>

Do not add frontmatter unless nearby lessons use it.
