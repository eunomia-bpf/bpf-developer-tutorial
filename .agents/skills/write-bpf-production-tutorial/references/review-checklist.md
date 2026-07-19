# Independent tutorial review checklist

Review the supplied snapshot without editing files or running commands. The author and reviewer must belong to different model families. The snapshot must include both required precedent pairs, any additional precedent named by the author, the process rulebooks, and the complete `$bpf-tutorial-writing-style` rulebooks. Fail the process as incomplete if any are absent.

Classify every finding as **Must fix**, **Should fix**, or **Consider**. For each finding, name the file and line or heading, quote the smallest useful fragment, explain the problem, and propose a concrete correction. Do not rewrite entire sections.

Give explicit verdicts for:

1. production realism and whether the lesson is a useful small tool rather than a feature tour or upstream selftest wrapper;
2. factual faithfulness to the implementation, KVM evidence, minimum versions, configs, privileges, limitations, and cleanup behavior;
3. architecture, including the thesis, running scenario, section progression, and ending;
4. reproducibility of every build, run, failure, and cleanup command;
5. source-fidelity ledger coverage, including whether any fact, code, command, output, requirement, limitation, failure path, cleanup behavior, qualifier, or reference disappeared during rewriting;
6. exact inclusion of the complete core kernel-mode, user-space, and required shared-header source before the detailed walkthrough;
7. compliance with every repository-local writing-style checklist item, including oral English, repository voice, narrative flow, paragraph density, natural Chinese, punctuation, and avoidance of line-locked translation;
8. overlap with nearby lessons and whether the new lesson has a distinct operational job;
9. English and Chinese agreement on headings, code, commands, examples, output, numbers, claims, caveats, summary, and references.

For the precedent verdict, distinguish legitimate repository continuity from copying. Confirm that the new lesson matches `47-cuda-events` in useful depth and `49-hid` in approachable code-first teaching order while rejecting their legacy weaknesses. A validation-report structure that leads with CI, KVM provenance, or test statistics instead of the reader's problem is a style failure even when every fact is correct.

Finish with a count by severity and exactly one final gate result:

- `GATE: PASS` when no valid Must-fix item remains.
- `GATE: FAIL` when one or more Must-fix items remain.

Model identity documents review independence. It is not evidence that the prose is correct.
