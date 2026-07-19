# Repository house style

New advanced lessons should feel at home beside `src/47-cuda-events/` and `src/49-hid/`. Read both English/Chinese README pairs in full. Use `47-cuda-events` as a depth reference for an end-to-end tool and `49-hid` as the stronger reference for voice, pacing, and teaching through a concrete device problem.

These lessons are precedents, not perfect templates. Do not copy their unsupported claims, stale version language, inconsistent punctuation, or unnecessary feature catalogs. Verified implementation facts and current project rules win whenever a precedent differs.

Read at most one additional completed bilingual lesson when it offers a closer subsystem pattern. For networking, good candidates include `20-tc`, `41-xdp-tcpdump`, `42-xdp-loadbalancer`, and `50-tcx`. Choose by teaching need, not by directory number.

## Build one continuous story

Open with a concrete situation the reader can picture. Name the small tool or example and the useful result, but do not preview every version, counter, failure case, and test in the opening.

Give enough background to explain why the hook or kernel subsystem matters. Then introduce the whole kernel/user-space path before individual functions. Keep returning to the same packet, event, device, or failure so adjacent sections feel causally connected.

Present complete core source exactly as required by the advanced tutorial guidelines, but organize it by component. Introduce one file, show it inline, explain its important behavior, and only then move to the next file. Never hide source in `<details>` and never make readers cross several complete files before reaching the explanation.

After the source, explain the BPF structure, attach point, state and ownership, relevant helpers or kfuncs, kernel interaction, user-space lifecycle, error handling, and cleanup. Spend words on advanced constraints and surprising behavior. Do not explain ordinary C syntax.

Compilation and execution should show copyable commands, representative real output, and what that output means. Put detailed KVM provenance, commit IDs, and compatibility data in a compact requirements or reproducibility paragraph. Do not narrate the PR's validation history.

End with an honest boundary, a short summary, the required invitation, and primary references.

## Lessons from the 53-egress-pacer rewrite

The first `53-egress-pacer` draft was technically accurate but still failed as a tutorial. It:

- packed the scenario, kernel version, algorithm, counters, conflict behavior, and test result into the opening;
- gave the reader only a few setup paragraphs before several hundred lines of source;
- repeated the same conflict, signal, cleanup, KVM, or safety caveat in the introduction, implementation, run section, and limitations;
- read like an artifact report because validation details received more emphasis than the mechanism;
- called a fixed-duration lab demo a production or operational tool without matching CLI capabilities;
- wrote Chinese by following English sentence order.

The rewrite kept all four complete source files, commands, output, versions, failure paths, and limits. It replaced the invented production story with an honest lab scope and followed one skb through ownership and timing. Reader review then exposed a structural problem: collecting the files before their explanations made the tutorial read like a design document. The corrected method places each complete file beside its component explanation, as tutorials 47 and 49 do.

Reuse the corrected method, not exact section counts. Shrink overloaded openings, give the reader one useful mental model, and alternate complete component source with nearby explanation. Keep each technical fact, but place it once where the reader is ready for it.

## Preserve modern correctness

- Use captured output and identify fields that vary across runs.
- Source version, performance, deployment, adoption, and upstream-history claims.
- State the minimum kernel, config, privilege, architecture, and hardware requirements.
- Explain at least one meaningful failure or boundary path and relevant cleanup.
- Distinguish a functional KVM run from a benchmark.
- Avoid unsupported claims such as “production-ready,” “safe,” “negligible,” or “complete visibility.”
- Keep Markdown consistent. Use full-width Chinese punctuation and spaces between CJK text and Latin letters or digits.

English and Chinese must share the same promise, section progression, source, commands, output, facts, caveats, summary, and references. Natural expression matters more than sentence-for-sentence symmetry.
