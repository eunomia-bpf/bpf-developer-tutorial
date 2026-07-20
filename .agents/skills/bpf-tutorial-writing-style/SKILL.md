---
name: bpf-tutorial-writing-style
description: Style checklist for English and Chinese bpf-developer-tutorial README files. Use while drafting or reviewing a tutorial so it reads like the established series, preserves technical detail, and presents complete source clearly.
---

# BPF Tutorial Writing Style

Read the complete guidelines first:
- [Advanced tutorial guideline](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/scripts/guideline_advance.md) for tutorials 40+
- [Basic tutorial guideline](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/scripts/guideline_basic.md) for tutorials 0-39

Then read the English and Chinese versions of `47-cuda-events`, `48-energy`, and `49-hid` as style references. Learn their teaching rhythm and level of detail without copying their topic or wording.

## Document Structure (strictly follow guideline)

For advanced tutorials (40+), follow this exact section order:

1. **Title**: `# eBPF 教程：[Topic Description]` or `# eBPF Tutorial by Example: [Topic Description]`

2. **Introduction**: Brief intro with a concrete problem scenario. Highlight significance and what readers will learn. Link to complete source once here.

3. **Background / Why This Approach**: 
   - Explain WHY this approach is needed
   - List traditional/alternative approaches and their limitations (e.g., killing process, firewall rules, user-space tools)
   - Explain what eBPF/the new kernel feature enables that traditional approaches cannot
   - State when the feature entered Linux (kernel version + commit if relevant)

4. **High-Level Mechanism**:
   - Explain HOW the eBPF feature/tool works at a high level BEFORE showing code
   - Describe the overall flow: what happens in kernel, what happens in user space, how they interact
   - Use diagrams for complex flows with branches, waits, ownership transfers, or 3+ dependent states

5. **Code Implementation**:
   - First introduce the overall processing logic
   - Show complete source code for each component (header, BPF program, user-space loader)
   - After each complete code block, explain the key parts with paragraph style (not bullet lists)
   - Focus on logic and advanced features, not basic syntax

6. **Additional Concepts** (if needed): Deeper explanation of specific features, edge cases, or semantics

7. **Compilation and Execution** (AFTER code, not before):
   - Build commands
   - Run commands with examples
   - Expected output with explanation
   - Environment requirements table (kernel version, config, privileges, architecture)

8. **Summary**: Key points, scope boundaries, future extensions

9. **Call to Action**: Repository and website invitation (as blockquote)

10. **References**: Links to kernel commits, upstream selftests, documentation

## Tell one useful story

- Open with a concrete situation that the example can reproduce and the question it answers.
- Near the first mention of eBPF, use one natural sentence to say what eBPF is and why it fits this problem.
- Introduce the relevant kernel subsystem and new feature when the running example needs them. State when the feature entered Linux and what it enabled.
- Follow one packet, event, task, or device interaction through kernel space and user space. Explain what happens, why it happens, and what the next step enables.
- Present the whole flow before detailed code. A small diagram helps when the reader must track a branch, wait, retry, ownership transfer, or at least three dependent states.

## Explain the "Why" thoroughly

This is critical. The Background section must explain:
- What problem you're solving
- What traditional approaches exist (killing process, firewall rules, user-space tools like `ss --kill`, sampling, etc.)
- Why each traditional approach doesn't work well (race conditions, incomplete coverage, performance overhead, etc.)
- What the eBPF approach enables that wasn't possible before

Example pattern for the "Why" section:
> **杀掉进程**是最直接的想法，但一个进程往往维护着多条连接，杀进程会中断所有业务流量。
> **防火墙规则**可以阻止新连接，但对已建立的连接无能为力。
> **用户态工具**如 `ss --kill` 依赖 `/proc/net/tcp` 遍历和注入 RST 报文，但这种方式有竞态问题。
> **内核态方案**才能真正解决这个问题。BPF 迭代器可以在持有适当锁的情况下遍历内核的套接字表...

## Sound like a tutorial

- Use familiar words, direct verbs, and connected paragraphs. Attraction comes from the problem and mechanism rather than promotional language.
- Prefer positive descriptions of what the example does. Put remaining limits and safety boundaries in one short paragraph near the end.
- Use prose for the main explanation and lists for genuinely parallel items.
- Keep each paragraph focused on one job. Connect facts through cause, sequence, or contrast instead of listing them like a specification.
- Write Chinese naturally from the same facts instead of translating English sentence by sentence. Use restrained punctuation and spaces between Chinese text and Latin letters or numbers.
- Keep technical names, code identifiers, commands, numbers, output, versions, and references exact.

Use this Chinese paragraph only as a voice reference for connected rhythm, restrained symbols, and technical density:

> libbpf 是一个 C/C++ 的 eBPF 用户态加载和控制库，随着内核一起分发，几乎已经成为 eBPF 用户态事实上的 API 标准，libbpf 也支持 CO-RE(Compile Once – Run Everywhere) 的解决方案，即预编译的 bpf 代码可以在不同内核版本上正常工作，而无需为每个特定内核重新编译。

## Teach from complete source

- Introduce one component, show its complete source in an ordinary Markdown fence, then explain the important logic before moving to the next component.
- Keep source byte-exact. Preserve comments and commands; use focused excerpts only after the complete block.
- Use neither `<details>` nor HTML synchronization markers.
- Link to the complete lesson once through its GitHub directory. Avoid an opening catalog of individual files.
- Every Markdown link uses an absolute `https://github.com/...` target. Omit a link when no stable GitHub target exists.
- Public prose contains no local path, shared test repository, VM name, copy route, cache, prompt, model, agent, or trace detail.

## Finish the lesson

- Show copyable build and run commands, representative real output, and what that output proves.
- State kernel, configuration, privilege, architecture, and hardware requirements that affect the example (use a table).
- End with a compact scope boundary, summary, repository invitation, and primary references.
- Keep the English and Chinese files aligned on structure, facts, source, commands, output, limits, and references while allowing each language to sound natural.

The final read should answer: what problem is solved, how one event moves through the system, which eBPF mechanism makes it possible, which code matters, how to run it, what success looks like, and where the example stops.
