---
name: bpf-tutorial-writing-style
description: Repository-local writing-style and bilingual review checklist for advanced bpf-developer-tutorial lessons. Use when drafting, rewriting, translating, or reviewing tutorial README.md and README.zh.md files, especially when matching the voice and code-first structure of lessons 47-cuda-events and 49-hid without losing technical facts, code, commands, evidence, caveats, or references.
---

# BPF Tutorial Writing Style

Apply this Skill as the single source of truth for tutorial prose and presentation. It contains style rules only. Use `$write-bpf-production-tutorial` for implementation, evidence, model review, KVM, PR, and CI workflow.

## Read the rulebooks

Read all three references before drafting or reviewing an advanced lesson:

1. [Advanced tutorial guidelines](references/advanced-tutorial-guidelines.md) preserves the complete project-provided requirements.
2. [Repository house style](references/repository-house-style.md) defines how new lessons should match `47-cuda-events` and `49-hid` while avoiding their legacy defects.
3. [Prose and bilingual checklist](references/prose-and-bilingual-checklist.md) carries the applicable eunomia.dev prose discipline into this repository.

Use existing tutorials as living examples, not as a fixed template. Always read the `47-cuda-events` and `49-hid` English/Chinese pairs. The agent may select up to three additional completed tutorial pairs when their subsystem, attachment type, tool shape, or target reader adds a useful pattern. Read every selected file in full and record why it was chosen. Never infer house style from headings alone.

Treat verified implementation facts, real runtime evidence, and the user's current requirements as authoritative. Never change code, commands, output, versions, claims, qualifiers, failure behavior, or limitations to make prose smoother. When an older precedent conflicts with verified facts or the current rulebooks, preserve the facts and use only the precedent's useful teaching style.

## Apply the final gate

Treat every unmarked rule in the three references as blocking unless the rule explicitly calls itself diagnostic or advisory. A **Must fix** label highlights a common hard failure; it is not the only kind of blocking rule. Report each failure with the file, heading, smallest useful excerpt, reason, and a targeted correction. Never rewrite a whole section during review when a paragraph-level fix is enough.

Paragraph length ranges are diagnostics, not quotas. A rule marked **Must fix** blocks acceptance. Preserve English and Chinese macro structure, facts, code, commands, output, examples, limitations, and references, but compose each language naturally rather than translating line by line.

The workflow Skill synchronizes every complete-source block. Mark each block with a repository-relative source path:

````markdown
<!-- BEGIN FULL SOURCE: src/<lesson>/<tool>.bpf.c -->
```c
placeholder replaced by the script
```
<!-- END FULL SOURCE -->
````

Never hand-edit content between these markers. `$write-bpf-production-tutorial` owns the expected-source inventory, synchronization commands, verification order, and acceptance workflow.
