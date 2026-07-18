# Repository tutorial precedents

Read two or three existing English/Chinese README pairs in full before drafting. Select one lesson with the same operational shape and one with the same eBPF attachment or subsystem. Record the exact paths in a precedent brief.

## Default production-tool precedent

Use `src/47-cuda-events/README.md` and `src/47-cuda-events/README.zh.md` as a default precedent for tracers and accelerator-facing tools. Reuse its useful scope:

- identify a real workload and the operator-visible events;
- connect the BPF hooks, shared event structure, ring buffer, user-space formatter, CLI, and fixture end to end;
- include build and run commands, representative output, limitations, extension points, and primary references;
- keep the complete source easy to find while explaining only the important excerpts.

Do not inherit its legacy weaknesses. New lessons must show commands and verified evidence early, avoid generic eBPF or subsystem introductions, use only captured output, qualify volatile IDs and addresses, source every benchmark claim, keep English and Chinese macro structure aligned, and state requirements, negative behavior, and cleanup explicitly.

## Domain selection

- For networking, also read the closest of `src/20-tc/`, `src/41-xdp-tcpdump/`, `src/42-xdp-loadbalancer/`, or `src/50-tcx/`.
- For security and process lifecycle, also read the closest of `src/7-execsnoop/`, `src/19-lsm-connect/`, `src/26-sudo/`, or `src/34-syscall/`.
- For latency and operations, also read the closest of `src/9-runqlat/`, `src/17-biopattern/`, `src/33-funclatency/`, or `src/48-energy/`.
- For GPU, NPU, or DMA-BUF work, read `src/47-cuda-events/` plus the closest lesson under `src/xpu/`.
- For a reusable kernel primitive, read the closest pair under `src/features/` and one numbered lesson that uses a similar end-to-end flow.

## Required precedent brief

Before prose, record:

1. the exact README pairs read in full;
2. two to four structural patterns to reuse;
3. old weaknesses or irrelevant sections to avoid;
4. the new lesson's distinct operational question;
5. why the chosen depth fits this tool rather than copying a fixed template.

Give this brief to both the author and external reviewer. Repository continuity is a requirement, but an older lesson never overrides verified code, runtime evidence, or the current writing rules.
