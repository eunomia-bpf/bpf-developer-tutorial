---
name: bpf-tutorial-writing-style
description: Repository-local prose and bilingual checklist for drafting, rewriting, or reviewing advanced bpf-developer-tutorial README.md and README.zh.md files. Use to match the readable voice of 49-hid and the useful depth of 47-cuda-events while preserving implementation facts, complete source, commands, evidence, caveats, and references.
---

# BPF Tutorial Writing Style

Use this Skill for writing quality only. Use `$write-bpf-production-tutorial` for build, KVM, exact-source checks, and PR steps.

Read all three references before drafting or reviewing:

1. [Advanced tutorial guidelines](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/.agents/skills/bpf-tutorial-writing-style/references/advanced-tutorial-guidelines.md) contains the complete project-provided requirements and must remain intact.
2. [Repository house style](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/.agents/skills/bpf-tutorial-writing-style/references/repository-house-style.md) explains how to learn from existing tutorials without copying their defects.
3. [Prose and bilingual checklist](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/.agents/skills/bpf-tutorial-writing-style/references/prose-and-bilingual-checklist.md) carries the relevant eunomia.dev writing discipline into this repository.

Also read the English and Chinese versions of `47-cuda-events` and `49-hid` in full. Existing lessons are examples of rhythm, depth, and teaching order, not templates. Verified code, real output, primary sources, and the user's requirements remain authoritative.

## Write for a reader

Start with a problem the reader can picture. Give the reader a small mental model before the full source. Keep one example, packet, event, or failure as the thread through the article.

Use oral English, familiar words, and connected sentences. Write natural Chinese independently from the same facts. Prefer causal explanation over inventories. A paragraph should tell the reader what happens, why it happens, and what that enables.

Do not write like a paper, specification, PR description, release note, test log, or compliance report. Build and KVM evidence belongs in compilation and execution, where it should support a claim instead of becoming the article's main plot.

## Keep the source readable

Include complete core source exactly as implemented. Teach one component at a time: introduce its role, present its source inline, and immediately explain the important logic before moving on. Do not hide source in `<details>` and do not separate a long source dump from all of its explanation.

Do not simplify code, insert ellipses, or rewrite comments. Present complete source in ordinary Markdown fenced code blocks without HTML synchronization markers, then verify it against the real file.

Use canonical GitHub absolute URLs for every Markdown link, even when the target belongs to the current lesson. Never use `./`, `../`, or another host. If no stable GitHub URL exists, leave the text unlinked. This rule overrides link patterns in older lessons and the website call to action in the advanced guidelines.

Keep local infrastructure private. Do not name workspace paths, shared lab repositories, VM instances, copy routes, caches, or agent trace locations in a tutorial or PR description. Retain only public reproducibility facts such as architecture, kernel version and commit, configuration, commands, and captured output.

## Keep scope honest

Describe what the implementation actually provides. A bounded lab command is a bounded lab command. Do not inflate it into a daemon, controller, production scheduler, security product, or operational platform.

State requirements, one meaningful failure path, cleanup behavior, and limitations. Say each important boundary once, at the point where the reader needs it. Move low-level kernel provenance into a compact requirements or reproducibility note.

## Final reader check

Read the finished lesson in order once. The reader should be able to answer:

- What concrete problem does this lesson solve?
- How does one packet or event move through kernel and user space?
- Which eBPF mechanism makes that possible?
- Which code deserves close attention?
- How do I build, run, and recognize success?
- What does the captured output prove?
- Where does the example stop?

Revise if the reader instead encounters a code wall, repeated disclaimers, a validation transcript, dense spec-sheet paragraphs, literal Chinese translation, or a scenario larger than the tool. This reader check is a judgment pass, not a reason to add reviewers or models.
