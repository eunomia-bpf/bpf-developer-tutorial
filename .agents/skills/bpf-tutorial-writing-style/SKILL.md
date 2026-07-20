---
name: bpf-tutorial-writing-style
description: Style checklist for English and Chinese bpf-developer-tutorial README files. Use while drafting or reviewing a tutorial so it reads like the established series, preserves technical detail, and presents complete source clearly.
---

# BPF Tutorial Writing Style

Read the complete [advanced tutorial guideline](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/.agents/skills/bpf-tutorial-writing-style/references/advanced-tutorial-guidelines.md), then read the English and Chinese versions of `47-cuda-events` and `49-hid`. Learn their teaching rhythm and level of detail without copying their topic or wording.

## Tell one useful story

- Open with a concrete situation that the example can reproduce and the question it answers.
- Identify the lesson once as part of the **eBPF Tutorial by Example** series.
- Near the first mention of eBPF, use one natural sentence to say what eBPF is and why it fits this problem. Assume the reader already knows the basics.
- Introduce the relevant kernel subsystem and new feature when the running example needs them. State when the feature entered Linux and what it enabled, while detailed commit IDs fit better in requirements or references.
- Follow one packet, event, task, or device interaction through kernel space and user space. Explain what happens, why it happens, and what the next step enables.
- Present the whole flow before detailed code. A small diagram helps when the reader must track a branch, wait, retry, ownership transfer, or at least three dependent states.

## Sound like a tutorial

- Use familiar words, direct verbs, and connected paragraphs. Attraction comes from the problem and mechanism rather than promotional language.
- Prefer positive descriptions of what the example does. Put remaining limits and safety boundaries in one short paragraph near the end.
- Use prose for the main explanation and lists for genuinely parallel items.
- Keep each paragraph focused on one job. Connect facts through cause, sequence, or contrast instead of listing them like a specification.
- Write Chinese naturally from the same facts instead of translating English sentence by sentence. Use restrained punctuation and spaces between Chinese text and Latin letters or numbers.
- Keep technical names, code identifiers, commands, numbers, output, versions, and references exact.

Use this Chinese paragraph only as a voice reference for connected rhythm, restrained symbols, and technical density:

> libbpf 是一个 C/C++ 的 eBPF 用户态加载和控制库，随着内核一起分发，几乎已经成为 eBPF 用户态事实上的 API 标准，libbpf 也支持 CO-RE(Compile Once – Run Everywhere) 的解决方案，即预编译的 bpf 代码可以在不同内核版本上正常工作，而无需为每个特定内核重新编译。我们希望尽可能的保持与 libbpf 的用户态 API 以及行为一致，尽可能减少应用迁移到 Wasm （如果需要的话）的成本。

The paragraph supplies tone only. Its libbpf, CO-RE, API, compatibility, and Wasm claims belong in a lesson only when independent sources require them.

## Teach from complete source

- Introduce one component, show its complete source in an ordinary Markdown fence, then explain the important logic before moving to the next component.
- Keep source byte-exact. Preserve comments and commands; use focused excerpts only after the complete block.
- Use neither `<details>` nor HTML synchronization markers.
- Link to the complete lesson once through its GitHub directory. Avoid an opening catalog of individual files.
- Every Markdown link uses an absolute `https://github.com/...` target. Omit a link when no stable GitHub target exists.
- Public prose contains no local path, shared test repository, VM name, copy route, cache, prompt, model, agent, or trace detail.

## Finish the lesson

- Show copyable build and run commands, representative real output, and what that output proves.
- State kernel, configuration, privilege, architecture, and hardware requirements that affect the example.
- Explain cleanup as part of the normal lifecycle.
- End with a compact scope boundary, summary, repository invitation, and primary references.
- Keep the English and Chinese files aligned on structure, facts, source, commands, output, limits, and references while allowing each language to sound natural.

The final read should answer: what problem is solved, how one event moves through the system, which eBPF mechanism makes it possible, which code matters, how to run it, what success looks like, and where the example stops.
