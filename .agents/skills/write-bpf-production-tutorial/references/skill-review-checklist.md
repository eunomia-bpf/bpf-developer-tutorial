# Independent repository-local Skill review checklist

Use this checklist only for `--scope skill`. Review the supplied immutable snapshot without editing files or running commands. The author and reviewer must belong to different model families. The snapshot must include both repository-local writing Skill entrypoints, every changed Skill reference or script, every changed CI hook, and any neighboring Skill or workflow needed to verify an interface claim. Fail the process as incomplete when a changed public surface or required dependency is absent.

Classify every finding as **Must fix**, **Should fix**, or **Consider**. For each finding, name the file and line or heading, quote the smallest useful fragment, explain the problem, and propose a concrete correction. Do not turn a Skill review into a tutorial prose review.

Give explicit verdicts for:

1. whether workflow ownership and writing-style ownership are separated cleanly, with correct trigger descriptions and cross-Skill routing;
2. whether the complete project-provided advanced tutorial guidelines are preserved and every optional author or reviewer receives the full applicable rulebook;
3. whether agents must read the required completed tutorial pairs and may select other finished tutorials as useful precedents rather than following a closed allowlist;
4. whether source synchronization enforces containment, complete inventory, exact accepted payloads, bilingual pairing, idempotence, and safe check/write behavior;
5. whether writer and reviewer wrappers preserve prompts, snapshots, traces, manifests, patches, failed runs, partial runs, and real agent behavior without deleting or rewriting prior records;
6. whether author isolation, path/tool restrictions, model proof, read-only review, prompt-injection boundaries, interruption handling, and final gate status match the documented contract;
7. whether unit tests and CI cover the important contracts without requiring BPF runtime on the host;
8. whether every added public surface is authorized or strictly necessary, and whether the two-Skill design is simpler than a combined or duplicated workflow;
9. whether the final Skill can guide a fresh agent from evidence through bilingual drafting, KVM verification, independent review, PR preparation, and CI closure without relying on a global Skill.

The tutorial-specific precedent snapshot requirement and nine lesson verdicts in `review-checklist.md` do not apply to `--scope skill`. A Skill review checks that those tutorial rules are encoded correctly; it does not pretend that the Skill itself is a runnable lesson.

Finish with a count by severity and exactly one final gate result:

- `GATE: PASS` when no valid Must-fix item remains.
- `GATE: FAIL` when one or more Must-fix items remain.

Model identity documents review independence. It is not evidence that the workflow is correct.
