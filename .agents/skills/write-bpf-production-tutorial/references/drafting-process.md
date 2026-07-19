# Tutorial drafting process

Use this process after the tool and its runtime evidence are complete. `$bpf-tutorial-writing-style` owns all prose, structure, and bilingual rules.

## Prepare immutable inputs

Create a task file outside the lesson. Record the exact README paths the author may edit, intended reader, operational scenario, non-goals, code paths, CLI, verified host and guest commands, captured output, kernel provenance, requirements, primary sources, and forbidden claims.

Add a source-fidelity ledger. Inventory every supplied fact, number, command, code file, output block, volatile field, version, config, privilege, failure path, cleanup behavior, limitation, and reference. A rewrite may move these items, but it may not remove or alter them.

Add a code inventory that identifies the complete core files to reproduce in the tutorial. Include the kernel-mode eBPF source, user-space source, and any shared header needed to understand their contract. Keep tests, generated skeletons, vendored code, and build boilerplate as links unless the teaching mechanism depends on them.

## Establish the teaching path

Write one sentence for the tutorial's promise and one sentence for its reader. Map each planned section to a distinct reader question. Confirm that the path covers the problem, relevant background, whole-system flow, complete code, focused kernel explanation, brief user-space explanation, deeper concepts, compilation and execution, real output, requirements, failure and cleanup behavior, limitations, summary, and references.

Do not draft until the precedent brief confirms that both `47-cuda-events` and `49-hid` English/Chinese pairs were read in full. Add the nearest subsystem lesson when it contributes a pattern that those two do not cover.

## Draft and compare

Draft English and Chinese from the same evidence ledger. Keep code, commands, and captured output identical. Compose prose independently in each language under `$bpf-tutorial-writing-style`.

After the rewrite, compare each README with its entry version from the end backwards. Mark every removed paragraph as moved, rephrased with all facts intact, or intentionally excluded for a reason already authorized by the task. Restore any unaccounted technical content.

Run `$bpf-tutorial-writing-style/scripts/sync-source-blocks.py --check` to verify that every complete-source block matches its repository file exactly. Then run the repository documentation generators, link checks, tests, and external review workflow.
