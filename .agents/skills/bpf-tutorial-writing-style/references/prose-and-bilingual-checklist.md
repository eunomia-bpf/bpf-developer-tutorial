# Prose and bilingual checklist

This checklist carries the relevant eunomia.dev writing discipline into advanced eBPF tutorials. It is self-contained and does not depend on a global or external Skill.

## Fidelity is the first gate

- **Must fix:** Any code, command, captured output, number, version, requirement, limitation, negative result, cleanup behavior, reference, or scope-bearing qualifier from the supplied material is missing or changed.
- Preserve technical names and project names. Do not replace them with vague pronouns across paragraphs.
- Treat numbers as claims. State what was measured, under which conditions, and what the result does or does not prove.
- Avoid absolute words such as “always,” “never,” “cannot,” and “impossible” unless the implementation or a primary source proves the boundary.
- Do not invent output, benchmark numbers, PIDs, paths, errors, production uses, or performance conclusions.
- Reorganize for teaching, but do not simplify away technical information. During a rewrite, compare the final text against the entry version from the end backwards and account for every removed paragraph.

## Voice and argument

- Use oral, direct English with familiar words and short connected sentences. Write as an experienced developer explaining a working tool, not as a paper, merge report, release note, or test log.
- Open with the real problem or a concrete scenario. Avoid “In this tutorial, we will explore,” generic eBPF history, product promotion, and an abstract-style contribution list.
- Let each section answer the question raised by the previous one. A useful progression is problem, background, whole-system flow, complete code, focused walkthrough, deeper concept, compilation and execution, limits, summary, and references.
- Give each paragraph one primary job. If a paragraph establishes context, explains a mechanism, reports evidence, and states a limitation at once, split it.
- Prefer active voice and concrete actors. Name the hook, BPF program, map, callback, loader, fixture, command, or kernel rather than using “it,” “this,” “the approach,” or “the result.”
- Replace spec-sheet prose with causal explanation. If three neighboring sentences can be reordered without changing the paragraph, connect each fact to what it enables or why it matters.
- Avoid fancy or promotional words, clickbait, exclamation marks, vague superlatives, hollow calls to action, and self-praise. Attraction should come from a concrete problem and a mechanism the reader can reuse.
- Do not overuse lists. Use prose for the implementation story and lists only when parallel items become easier to scan.

## Paragraph and sentence checks

- English paragraphs usually work best at 40–90 words. Inspect every paragraph above 110 words. Three consecutive paragraphs above 90 words are **Must fix**.
- Chinese paragraphs usually work best at 120–260 Chinese characters. Inspect every paragraph above 320 characters. Three consecutive paragraphs above 260 characters are **Must fix**.
- The ranges are diagnostic tripwires, not quotas. Short transitions and longer indivisible mechanism explanations are allowed.
- Keep a sentence's subject near its verb. Split long modifiers, dangling introductions, and sentences that make the reader hold several clauses before reaching the action.
- Avoid weak openings such as “It is,” “There is,” and “This is” when a concrete subject is available.
- Do not stack three or more short note-like sentences. Connect cause, mechanism, and consequence.
- Cut filler such as “in order to,” “utilize,” “it is important to note that,” “due to the fact that,” “in terms of,” and “with respect to.” Prefer direct verbs.
- Do not use spaced English em dashes (` — `) or Chinese em dashes (`——`) in prose.
- Do not join independent clauses with semicolons. Use two sentences or a conjunction.
- Use colons only to introduce a list, code block, or table. Rewrite claim-colon-evidence and Chinese noun-phrase-colon openings as sentences.

## Code and evidence presentation

- Present full core source exactly as it exists before excerpting it again for explanation. Never silently shorten functions, replace blocks with ellipses, translate comments, or “clean up” commands.
- Introduce each complete file with its role in the kernel/user-space flow. After the file, select only the parts that need deeper explanation.
- Explain what advanced developers need to know: program type, attach point, context restrictions, helper or kfunc semantics, map ownership, state lifetime, concurrency, verifier constraints, event/control path, error handling, and cleanup.
- Keep build and run commands copyable. Explain prerequisites before the command and interpret real output after it.
- Label volatile fields and distinguish demonstrations, functional tests, and benchmarks.

## Natural Chinese

- Compose Chinese from the facts and paragraph role, not from English sentence order. The two languages may use different sentence and paragraph boundaries.
- Translate ordinary concept nouns consistently. Keep proper nouns, product names, code, commands, file names, function names, and genuine terms of art in English.
- Do not begin a Chinese prose sentence with an English common noun. Avoid English clause splicing and glossary-style prose where every other concept stays in English.
- Use full-width Chinese punctuation. Put a half-width space between CJK text and Latin letters or digits, such as “64 个事件” and “eBPF 程序.”
- Write table headings in Chinese. Translate ordinary prose inside comments only when the code block is illustrative; when the block claims to be complete source, preserve it byte-for-byte in both languages.
- Read every Chinese paragraph aloud. Rewrite literal translations, English word order, and stiff phrases that a developer would not use in conversation.

## Bilingual consistency

- Keep the same macro structure, examples, complete code payload, commands, output, claims, numbers, caveats, limitations, summary, and references in both files.
- Corresponding headings should promise the same content, but they do not need literal translations.
- A near-perfect line-for-line prose translation is a review smell. Confirm that each language reads naturally even when that changes sentence or paragraph boundaries.
- When one version changes a fact, example, figure, command, code block, output, or limitation, update the other in the same pass.

## Final reader check

After reading in order, an intermediate or advanced eBPF developer should be able to explain the real problem, the kernel/user-space flow, why the advanced capability is needed, how the core code works, how to build and run it, what the captured output proves, and where the example stops. If the reader remembers only a feature name or a validation transcript, revise the narrative.
