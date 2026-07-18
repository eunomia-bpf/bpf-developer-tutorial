# Independent tutorial review checklist

Review the supplied snapshot without editing files or running commands. The author and reviewer must belong to different model families. The snapshot must include the precedent lessons named by the author; fail the process as incomplete if they are absent.

Classify every finding as **Must fix**, **Should fix**, or **Consider**. For each finding, name the file and line or heading, quote the smallest useful fragment, explain the problem, and propose a concrete correction. Do not rewrite entire sections.

Give explicit verdicts for:

1. production realism and whether the lesson is a useful small tool rather than a feature tour or upstream selftest wrapper;
2. factual faithfulness to the implementation, KVM evidence, minimum versions, configs, privileges, limitations, and cleanup behavior;
3. architecture, including the thesis, running scenario, section progression, and ending;
4. reproducibility of every build, run, failure, and cleanup command;
5. paragraph density, note-like prose, vague claims, invented output, and unsupported production claims;
6. overlap with nearby lessons and whether the new lesson has a distinct operational job;
7. English and Chinese agreement on headings, commands, examples, numbers, claims, and caveats;
8. natural Chinese composition, terminology consistency, punctuation, and avoidance of line-locked translation.

For the precedent verdict, distinguish legitimate repository continuity from copying. Confirm that the new lesson matches the selected examples' useful depth and end-to-end explanation while rejecting legacy weaknesses such as generic introductions, late commands, invented volatile output, unsupported benchmark claims, exhaustive feature inventories, or bilingual structure drift.

Finish with a count by severity and exactly one final gate result:

- `GATE: PASS` when no valid Must-fix item remains.
- `GATE: FAIL` when one or more Must-fix items remain.

Model identity documents review independence. It is not evidence that the prose is correct.
