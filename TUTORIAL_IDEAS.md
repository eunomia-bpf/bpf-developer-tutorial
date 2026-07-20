# eBPF Tutorial Candidate Registry

This file records possible additions to bpf-developer-tutorial and the reasoning behind their priority. It is an append-only decision record: when an idea is completed, deferred, superseded, or rejected, keep the row and record the new status and reason.

Last full audit: 2026-07-20

## What counts as a high-value tutorial

The strongest lesson starts from a real question, uses eBPF in an essential way, follows one event or request through a clear mechanism, and ends with output that can be reproduced locally or in KVM. Kernel novelty helps when it enables that lesson. Novelty by itself has less value than a broadly useful and maintainable example.

Scores use seven positive dimensions: reader problem (25), eBPF leverage (20), coverage gap (15), reproducibility (15), teaching clarity (10), ecosystem evidence (10), and maturity (5). Up to 20 points are deducted for unstable interfaces, excessive scope, special hardware, external infrastructure, or unusually fragile maintenance.

Status meanings:

- `ready`: sufficiently scoped and supported to start implementation
- `research`: promising, with one or more design questions to resolve
- `watch`: upstream interface or ecosystem is still moving
- `maintenance`: better added to an existing lesson
- `covered`: already present locally or in an active tutorial change
- `deferred`: valuable after another prerequisite or test environment exists
- `rejected`: insufficient value or excessive overlap, with the reason retained

## Current recommendation

The highest overall value is a **container-aware service dependency map**. A fixture can place a frontend, API, and datastore process in separate cgroup v2 subtrees, generate successful and failed connections, then let eBPF turn kernel socket events into named service edges. The result answers a common question, demonstrates the reusable boundary between kernel identity and user-space enrichment, produces an intuitive graph, and runs without Kubernetes or special hardware. Tutorials 13 and 14 already trace TCP connections and state, while the unnumbered `src/cgroup` lesson already introduces cgroup network policy. The new lesson remains distinct because it correlates both sides of a connection with workload identity and constructs topology instead of filtering one operation or printing individual socket events.

The strongest feature-centered lesson is **Signed BPF program verification**. It has a compact success path, two decisive failure paths, clear operational value, and stable Linux 6.18 support.

The most timely scenario is an **LLM and MCP call timeline**. It ranks below the first two because TLS/runtime coverage, stream reassembly, protocol parsing, and sensitive payload handling increase scope and maintenance.

The leading score breakdown makes this tradeoff explicit:

| Candidate | Reader problem | eBPF leverage | Coverage gap | Reproducibility | Teaching clarity | Ecosystem evidence | Maturity | Cost | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Container-aware service dependency map | 25 | 19 | 12 | 15 | 9 | 10 | 5 | -5 | 90 |
| Signed BPF program verification | 23 | 20 | 15 | 15 | 10 | 8 | 5 | -8 | 88 |
| io_uring request latency and async-punt diagnosis | 24 | 19 | 15 | 14 | 9 | 9 | 5 | -8 | 87 |

### Ready definition for the first lesson

The service-dependency lesson should answer one question: **which local workload called which service, how long did connection setup take, and which edge failed?**

The fixture creates `frontend`, `api`, and `database` cgroup v2 subtrees and starts one small process in each. A successful request follows `frontend → api → database`; a second request targets a closed port. Kernel-side programs correlate connect completion, accepted sockets or TCP state, addresses, latency, and cgroup identity. User space resolves cgroup IDs to stable fixture names, aggregates edges, and prints a table plus Graphviz DOT output. A passing run must show both successful edges and one failed `frontend → api` attempt without requiring Kubernetes, containers, or an external network.

This lesson teaches one reusable architecture: BPF captures stable kernel facts, while user space enriches volatile workload metadata and constructs the graph. It can mention production projects as motivation while keeping the implementation independent and small.

## Ranked candidates

| Score | Status | Candidate | Smallest useful lesson | Distinct repository value | Primary inspiration |
|---:|---|---|---|---|---|
| 90 | ready | Container-aware service dependency map | Trace `connect`, accept/state, and cgroup identity for three local services; emit named edges, latency, and failures | Combines concepts nearest to tutorials 13, 14, and `src/cgroup`, then adds two-sided workload identity and topology | [Coroot node agent](https://github.com/coroot/coroot-node-agent), [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget), [Hubble](https://github.com/cilium/hubble) |
| 88 | ready | Signed BPF program verification | Create a key and certificate, trust it through the kernel keyring, load a signed program, then show unknown-key and tampered-object failures | Adds BPF deployment integrity and supply-chain verification | [Linux 6.18 BPF merge](https://github.com/torvalds/linux/commit/ae28ed4578e6d5a481e39c5a9827f27048661fdd), [bpftool](https://github.com/libbpf/bpftool) |
| 87 | ready | io_uring request latency and async-punt diagnosis | Correlate submit, io-wq execution, and completion; report latency by opcode, batching, and punt ratio | Observes the io_uring lifecycle rather than block-device access alone | [uringscope](https://github.com/rch0wdhury/uringscope), [liburing](https://github.com/axboe/liburing) |
| 85 | research | OOM pre-kill profile and cgroup attribution | Trigger a bounded cgroup OOM, identify the victim and memory limit, and preserve a useful pre-kill profile | Complements allocation leak tracking with evidence from the failure moment | [OOMProf](https://github.com/parca-dev/oomprof), [Coroot node agent](https://github.com/coroot/coroot-node-agent) |
| 83 | research | AI-agent runtime activity audit | Run a fixture in one cgroup and correlate its process tree, file writes, network connections, and tool subprocesses into a timeline | Applies stable tracing hooks to a new security and provenance scenario | [AgentSight](https://github.com/agent-sight/agentsight), [Tetragon](https://github.com/cilium/tetragon), [Tracee](https://github.com/aquasecurity/tracee), [Falco](https://github.com/falcosecurity/falco) |
| 82 | ready | `sk_lookup` transparent local service router | Route a virtual TCP or UDP address to one of two existing sockets with `bpf_sk_assign()` and demonstrate failover | Introduces a program type and socket-selection point absent from current examples | [Linux sk_lookup selftest](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/sk_lookup.c) |
| 81 | research | LLM and MCP call timeline | Trace one local OpenAI-compatible streaming request and one MCP stdio tool call; report model, tool, TTFT, and total latency | Turns TLS and I/O tracing into an end-to-end agent scenario | [agtap](https://github.com/zhebrak/agtap), [OpenTelemetry eBPF Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation) |
| 80 | research | Container-aware runtime policy | Attach a BPF LSM policy to selected workload identity and audit or deny one file or network action | Moves beyond a host-wide LSM example into workload identity and policy | [Tetragon](https://github.com/cilium/tetragon), [Tracee](https://github.com/aquasecurity/tracee), [Falco](https://github.com/falcosecurity/falco) |
| 79 | ready | Sidecarless service traffic split | Use cgroup socket hooks to translate one service address to two local backends and expose the chosen backend in a map | Teaches socket-level service routing rather than the existing sockhash fast path | [Cilium](https://github.com/cilium/cilium), [Kmesh](https://github.com/kmesh-net/kmesh) |
| 78 | ready | DNS-aware egress policy with BPF netfilter or cgroup hooks | Permit one resolver or domain-derived address set, count policy decisions, and show one accepted and one rejected query | Adds a concrete egress-control scenario and a new attachment choice | [Cilium](https://github.com/cilium/cilium), [Linux BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) |
| 77 | research | OCI-packaged eBPF Gadget with workload enrichment | Package one small tracer as an OCI artifact, run it on a local container, and enrich kernel IDs with container names | Teaches portable distribution and enrichment instead of only local loading | [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget), [bpfman](https://github.com/bpfman/bpfman) |
| 76 | ready | XDP multi-buffer parsing with `bpf_xdp_pull_data()` | Place an L4 header across fragments, show the initial boundary, pull data, reacquire pointers, and parse it | Adds non-linear packet handling to the XDP series | [Linux XDP pull-data selftest](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_xdp_pull_data.c) |
| 75 | research | Zero-code trace export to OpenTelemetry | Trace a small HTTP client/server pair without SDK changes and emit one OTLP span with process and network attributes | Connects BPF events to an open telemetry model | [OpenTelemetry eBPF Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation), [Odigos](https://github.com/odigos-io/odigos) |
| 74 | research | Cgroup block-I/O noisy-neighbor attribution | Run two cgroups against one virtual disk and attribute queue and completion latency to the issuing workload | Adds workload attribution and contention diagnosis to block-I/O tracing | [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget), [Coroot node agent](https://github.com/coroot/coroot-node-agent) |
| 73 | ready | `uprobe_multi` with attach cookies | Attach one BPF program to allocator or database-client functions and dispatch by per-symbol cookie | Replaces repetitive individual uprobes with one scalable attachment pattern | [libbpf](https://github.com/libbpf/libbpf), [Linux BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) |
| 72 | research | TLS key capture and HTTP/2 or HTTP/3 decoding | Capture session material for a local TLS or QUIC fixture, combine it with packets, and decode in Wireshark-compatible form | Advances beyond printing OpenSSL plaintext buffers | [eCapture](https://github.com/gojue/ecapture), [ngtcp2](https://github.com/ngtcp2/ngtcp2) |
| 70 | research | gRPC trace-context propagation with `sk_msg` | Inject or propagate one trace header across a local HTTP/2 gRPC call and verify both spans share context | A genuine advanced sequel to sockmap and OpenTelemetry lessons | [OpenTelemetry eBPF Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation) |
| 69 | research | AF_XDP multi-buffer and RX metadata | Redirect frames to AF_XDP, preserve selected metadata, and reconstruct a fragmented packet in user space | Adds the XDP/user-space zero-copy boundary and metadata contract | [Linux AF_XDP selftests](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/xskxceiver.c) |
| 68 | deferred | Netkit container datapath | Connect two namespaces with netkit, attach primary and peer programs, and show link-based policy ordering | Adds a modern container device model, after a stable local test fixture is prepared | [Cilium](https://github.com/cilium/cilium), [Linux BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) |
| 67 | deferred | Cross-language continuous profiling | Collect one mixed native and managed-runtime stack and symbolize it through build identity | Goes beyond stack sampling into unwinding and symbolization architecture | [OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler), [Parca](https://github.com/parca-dev/parca), [Pyroscope](https://github.com/grafana/pyroscope) |
| 67 | research | BPF-controlled io_uring loop with `io_uring_bpf_ops` | Let a BPF struct_ops callback inspect completions and submit one follow-up operation without returning to the ordinary userspace loop | Demonstrates a new Linux 7.1 control surface | [Linux io_uring BPF source](https://github.com/torvalds/linux/blob/master/io_uring/bpf-ops.c), [Linux io_uring BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) |
| 65 | deferred | GPU causal stall diagnosis | Correlate CUDA synchronization latency with CPU scheduling and block-I/O events in one controlled workload | Extends CUDA event tracing from isolated calls to a causal chain | [OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) |
| 64 | research | BPF object reference counting and rbtree traversal | Maintain ordered objects with explicit ownership, lookup, acquire, and release paths | Extends graph-object coverage beyond the qdisc list example | [Linux rbtree selftest](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/rbtree_search.c) |
| 63 | deferred | NCCL collective straggler timeline | Correlate collective duration, rank, CPU preemption, and retransmits across a two-rank fixture | Adds distributed GPU communication behavior | [OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler), [NCCL](https://github.com/NVIDIA/nccl) |
| 58 | maintenance | Ring-buffer overwrite mode | Add a bounded producer/slow-consumer demonstration to the existing ring-buffer material | The mechanism is too small for a separate numbered lesson | [Linux BPF selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) |

## Upstream watchlist

These topics remain candidates, while their interfaces and examples are still moving. Re-score them after Linux 7.2 becomes stable and the corresponding libbpf support has a released reference implementation.

| Status | Topic | Promotion condition | Source |
|---|---|---|---|
| watch | `tracing_multi` | A stable attach API and a scenario clearer than several individual tracing links | [Linux 7.2 BPF merge](https://github.com/torvalds/linux/commit/9c87e61e3c5797277407ba5eae4eac8a52be3fa3) |
| watch | BPF rhashtable map | Stable userspace creation support and a lesson where resize/concurrency matters | [Linux 7.2 BPF merge](https://github.com/torvalds/linux/commit/9c87e61e3c5797277407ba5eae4eac8a52be3fa3) |
| watch | Sleepable tracepoint programs | A deterministic event that requires sleeping work directly at the tracepoint | [Linux 7.2 BPF merge](https://github.com/torvalds/linux/commit/9c87e61e3c5797277407ba5eae4eac8a52be3fa3) |
| watch | libarena with ASAN-style diagnostics | Released tooling and a compact memory-error fixture | [Linux 7.2 BPF merge](https://github.com/torvalds/linux/commit/9c87e61e3c5797277407ba5eae4eac8a52be3fa3) |

## Covered by current lessons or active changes

Keep these entries to prevent repeated proposals.

| Status | Topic | Existing coverage |
|---|---|---|
| covered | Basic kprobe, fentry, uprobe, tracepoint, process, CPU, and syscall tracing | Tutorials 1–18 and 31–38 |
| covered | TC, XDP, XDP capture, XDP load balancing, sockops/sk_msg, and TCX fundamentals | Tutorials 20–21, 29, 41–42, and 50 |
| covered | HTTP, OpenSSL plaintext, Nginx, and MySQL tracing | Tutorials 23, 30, 39, and 40 |
| covered | Basic sched_ext schedulers | Tutorials 44 and 45 |
| covered | Cgroup socket, device, and sysctl policy fundamentals | Unnumbered `src/cgroup` lesson |
| covered | CUDA API events, energy, HID-BPF, arena, iterators, tokens, workqueues, dynptr, and struct_ops | Tutorials 47–49 plus `src/features` |
| covered | TCP iterator quarantine | Active tutorial 51 |
| covered | `fsession` latency tracing | Active tutorial 52 |
| covered | BPF qdisc with graph objects and list ownership | Active tutorial 53 |
| covered | BPF task work and file-backed dynptr inspection after exec | Active tutorial 54 |

## Decision history

- 2026-07-20: Created the registry after auditing the local tutorials and surveying Linux BPF work plus OpenTelemetry OBI and profiler, Coroot, Cilium, Hubble, Kmesh, AgentSight, Tetragon, Falco, Tracee, Inspektor Gadget, bpfman, OOMProf, uringscope, agtap, eCapture, Parca, Pyroscope, and Odigos.
- 2026-07-20: Selected the container-aware service dependency map as the highest overall value. It combines a common question, stable hooks, a clear visual result, broad reuse, and deterministic KVM execution.
- 2026-07-20: Kept LLM/MCP tracing as the most timely candidate while scoring its protocol and runtime maintenance cost explicitly.
- 2026-07-20: Removed Ingero as a primary source after its GitHub repository returned 404 during link validation; retained the GPU candidates with currently auditable OpenTelemetry profiler and NCCL sources.
