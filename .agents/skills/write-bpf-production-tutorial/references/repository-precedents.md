# Repository tutorial precedents

Read both required English/Chinese README pairs in full before drafting:

- `src/47-cuda-events/README.md` and `src/47-cuda-events/README.zh.md`
- `src/49-hid/README.md` and `src/49-hid/README.zh.md`

Select one additional lesson with the same operational shape or eBPF attachment when it adds a useful domain pattern. Record every exact path in a precedent brief.

## Required advanced-tool precedents

Use `47-cuda-events` as the end-to-end depth baseline. Reuse its useful scope:

- identify a real workload and the operator-visible events;
- connect the BPF hooks, shared event structure, ring buffer, user-space formatter, CLI, and fixture end to end;
- include build and run commands, representative output, limitations, extension points, and primary references;
- keep the complete source easy to find while explaining only the important excerpts.

Use `49-hid` as the approachable, code-first teaching baseline. Reuse its useful scope:

- open with a concrete problem that gives the advanced feature a reason to exist;
- explain enough subsystem background before implementation;
- present complete source before walking through the important mechanisms;
- explain kernel-mode code in depth and user-space orchestration more briefly;
- put compilation, execution, expected output, experiments, summary, and references after the implementation story.

Do not inherit either lesson's legacy weaknesses. New lessons must avoid generic eBPF history, excessive marketing language, stale or unsupported counts, invented output, unqualified volatile IDs and addresses, unsourced benchmark claims, inconsistent Chinese punctuation, exhaustive feature inventories, and missing requirements or cleanup. The repository-local style Skill defines the current house style when the precedents differ.

## Domain selection

- For networking, also read the closest of `src/20-tc/`, `src/41-xdp-tcpdump/`, `src/42-xdp-loadbalancer/`, or `src/50-tcx/`.
- For security and process lifecycle, also read the closest of `src/7-execsnoop/`, `src/19-lsm-connect/`, `src/26-sudo/`, or `src/34-syscall/`.
- For latency and operations, also read the closest of `src/9-runqlat/`, `src/17-biopattern/`, `src/33-funclatency/`, or `src/48-energy/`.
- For GPU, NPU, or DMA-BUF work, read `src/47-cuda-events/` plus the closest lesson under `src/xpu/`.
- For a reusable kernel primitive, read the closest pair under `src/features/` and one numbered lesson that uses a similar end-to-end flow.

## Required precedent brief

Before prose, record:

1. confirmation that both required README pairs and any additional pair were read in full;
2. two to four structural patterns to reuse;
3. old weaknesses or irrelevant sections to avoid;
4. the new lesson's distinct operational question;
5. the complete core source files that will appear before the walkthrough;
6. why the chosen depth fits this tool rather than copying a fixed template.

Give this brief to both the author and external reviewer. Repository continuity is a requirement, but an older lesson never overrides verified code, runtime evidence, or the current writing rules.
