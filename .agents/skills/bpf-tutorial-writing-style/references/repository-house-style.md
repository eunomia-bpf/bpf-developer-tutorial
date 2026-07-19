# Repository house style

New advanced lessons must feel like they belong beside `src/47-cuda-events/` and `src/49-hid/`. Read both English/Chinese README pairs in full before drafting. Use `47-cuda-events` as the depth baseline for an end-to-end tool and `49-hid` as the voice and code-first teaching baseline.

## Match the useful patterns

- Start with a concrete situation the reader can picture. Address the reader directly when it sounds natural, then name the tool and what the reader will learn.
- Give enough subsystem background to make the advanced mechanism understandable. Assume basic eBPF knowledge, so skip generic definitions of maps, CO-RE, or the verifier unless the lesson depends on a non-obvious property.
- Introduce the whole kernel/user-space path before walking through individual functions. Keep returning to the same example so the lesson reads as one story.
- Present the complete kernel-mode eBPF source and complete user-space source exactly as implemented before the detailed walkthrough. Include a shared header when understanding the event or control contract depends on it. Link test fixtures and build files instead of reproducing them unless they are part of the teaching mechanism.
- After the complete source, explain the important BPF structure, helpers, maps, callbacks or hooks, kernel event interaction, user-space load/attach path, output processing, error handling, and cleanup. Explain basic C syntax only when it hides an eBPF-specific constraint.
- Put compilation and execution after the concept and implementation walkthrough. Show exact commands, real output, prerequisites, and what the output means.
- End with a compact summary and one invitation to the repository and tutorial website. Keep primary references in a dedicated final section.

## Preserve modern correctness

Use the precedents for voice and teaching order, not as permission to copy their weaknesses. New lessons must:

- use only captured output and identify fields that vary across runs;
- source version, performance, deployment, adoption, and upstream-history claims;
- state minimum kernel, config, privilege, architecture, and hardware requirements;
- explain at least one meaningful failure or boundary path and all relevant cleanup behavior;
- distinguish a functional KVM run from a benchmark;
- avoid unsupported claims such as “production-ready,” “safe,” “negligible,” or “complete visibility”;
- use consistent Markdown, full-width Chinese punctuation, and spaces between CJK text and Latin letters or digits.

## Keep the teaching narrative

Prefer paragraphs over inventories. Use lists for CLI options, requirements, byte layouts, or genuinely parallel items. Do not turn the mechanism into an acceptance report with headings such as “Verified output,” “Test evidence,” or “Statistics” unless the result itself is the topic. Runtime proof should appear naturally in the compilation and execution section, followed by an explanation of what it proves.

Keep exact operational details, but move low-level provenance such as commit and image hashes into the runtime-requirements or reproducibility discussion. Lead with what the tool does, not how its PR was validated.

The English and Chinese versions must share the same title promise, section progression, complete code, commands, output, facts, caveats, summary, and references. Natural Chinese takes priority over sentence-for-sentence symmetry.
