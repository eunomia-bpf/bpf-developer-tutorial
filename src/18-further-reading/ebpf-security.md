# The Secure Path Forward for eBPF runtime: Challenges and Innovations

Yusheng Zheng

Extended Berkeley Packet Filter (eBPF) represents a significant evolution in the way we interact with and extend the capabilities of modern operating systems. As a powerful technology that enables the Linux kernel to run sandboxed programs in response to events, eBPF has become a cornerstone for system observability, networking, and security features.

However, as with any system that interfaces closely with the kernel, the security of eBPF itself is paramount. In this blog, we delve into the often-overlooked aspect of eBPF security, exploring how the mechanisms intended to safeguard eBPF can themselves be fortified. We'll dissect the role of the eBPF verifier, scrutinize the current access control model, and investigate potential improvements from ongoing research. Moreover, we'll navigate through the complexities of securing eBPF, addressing open questions and the challenges they pose to system architects and developers alike.

## Table of Contents
<!-- TOC -->

- [The Secure Path Forward for eBPF runtime: Challenges and Innovations](#the-secure-path-forward-for-ebpf-runtime-challenges-and-innovations)
  - [Table of Contents](#table-of-contents)
  - [How eBPF Ensures Security with Verifier](#how-ebpf-ensures-security-with-verifier)
    - [What the eBPF Verifier Is and What It Does](#what-the-ebpf-verifier-is-and-what-it-does)
    - [How the eBPF Verifier Works](#how-the-ebpf-verifier-works)
    - [Challenges](#challenges)
    - [Other works to improve verifier](#other-works-to-improve-verifier)
  - [Limitations in eBPF Access Control](#limitations-in-ebpf-access-control)
    - [CAP\_BPF](#cap_bpf)
    - [bpf namespace](#bpf-namespace)
    - [Unprivileged eBPF](#unprivileged-ebpf)
      - [Trusted Unprivileged BPF](#trusted-unprivileged-bpf)
  - [Other possible solutions](#other-possible-solutions)
    - [MOAT: Towards Safe BPF Kernel Extension (Isolation)](#moat-towards-safe-bpf-kernel-extension-isolation)
    - [Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing](#unleashing-unprivileged-ebpf-potential-with-dynamic-sandboxing)
    - [Kernel extension verification is untenable](#kernel-extension-verification-is-untenable)
    - [Wasm-bpf: WebAssembly eBPF library, toolchain and runtime](#wasm-bpf-webassembly-ebpf-library-toolchain-and-runtime)
    - [`bpftime`: Userspace eBPF runtime for uprobe \& syscall hook \& plugin](#bpftime-userspace-ebpf-runtime-for-uprobe--syscall-hook--plugin)
  - [Conclusion](#conclusion)

<!-- /TOC -->
<!-- /TOC -->

## How eBPF Ensures Security with Verifier

The security framework of eBPF is largely predicated on the robustness of its verifier. This component acts as the gatekeeper, ensuring that only safe and compliant programs are allowed to run within the kernel space.

### What the eBPF Verifier Is and What It Does

At its core, the eBPF verifier is a static code analyzer. Its primary function is to vet the BPF program instructions before they are executed. It scrutinizes a copy of the program within the kernel, operating with the following objectives:

- `Ensuring Program Termination`

  The verifier uses depth-first search (DFS) algorithms to traverse the program's control flow graph, which it ensures is a Directed Acyclic Graph (DAG). This is crucial for guaranteeing that the program cannot enter into an infinite loop, thereby ensuring its termination. It meticulously checks for any unbounded loops and malformed or out-of-bounds jumps that could disrupt the normal operation of the kernel or lead to a system hang.

- `Ensuring Memory Safety`

  Memory safety is paramount in kernel operations. The verifier checks for potential out-of-bounds memory accesses that could lead to data corruption or security breaches. It also safeguards against use-after-free bugs and object leaks, which are common vulnerabilities that can be exploited. In addition to these, it takes into account hardware vulnerabilities like Spectre, enforcing mitigations to prevent such side-channel attacks.

- `Ensuring Type Safety`

  Type safety is another critical aspect that the verifier ensures. By preventing type confusion bugs, it helps maintain the integrity of data within the kernel. The eBPF verifier utilizes BPF Type Format (BTF), which allows it to accurately understand and check the kernel's complex data structures, ensuring that the program's operations on these structures are valid and safe.

- `Preventing Hardware Exceptions`

  Hardware exceptions, such as division by zero, can cause abrupt program terminations and kernel panics. To prevent this, the verifier includes checks for divisions by unknown scalars, ensuring that instructions are rewritten or handled in a manner consistent with aarch64 specifications, which dictate safe handling of such exceptions.

Through these mechanisms, the eBPF verifier plays a critical role in maintaining the security and stability of the kernel, making it an indispensable component of the eBPF infrastructure. It not only reinforces the system's defenses but also upholds the integrity of operations that eBPF programs intend to perform, making it a quintessential part of the eBPF ecosystem.

### How the eBPF Verifier Works

The eBPF verifier is essentially a sophisticated simulation engine that exhaustively tests every possible execution path of a given eBPF program. This simulation is not a mere theoretical exercise but a stringent enforcement of security and safety policies in kernel operations.

- **Follows control flow graph**
  The verifier begins its analysis by constructing and following the control flow graph (CFG) of the eBPF program. It carefully computes the set of possible states for each instruction, considering the BPF register set and stack. Safety checks are then performed depending on the current instruction context.
  
  One of the critical aspects of this process is register spill/fill tracking for the program's private BPF stack. This ensures that operations involving the stack do not lead to overflows or underflows, which could corrupt data or provide an attack vector.

- **Back-edges in control flow graph**
  To effectively manage loops within the eBPF program, the verifier identifies back-edges in the CFG. Bounded loops are handled by simulating all iterations up to a predefined limit, thus guaranteeing that loops will not lead to indefinite execution.

- **Dealing with potentially large number of states**
  The verifier must manage the complexity that comes with the large number of potential states in a program's execution paths. It employs path pruning logic to compare the current state with prior states, assessing whether the current path is "equivalent" to prior paths and has a safe exit. This reduces the overall number of states that need to be considered.

- **Function-by-function verification for state reduction**
  To streamline the verification process, the verifier conducts a function-by-function analysis. This modular approach allows for a reduction in the number of states that need to be analyzed at any given time, thereby improving the efficiency of the verification.

- **On-demand scalar precision (back-)tracking for state reduction**
  The verifier uses on-demand scalar precision tracking to reduce the state space further. By back-tracking scalar values when necessary, the verifier can more accurately predict the program's behavior, optimizing its analysis process.

- **Terminates with rejection upon surpassing “complexity” threshold**
  To maintain practical performance, the verifier has a "complexity" threshold. If a program's analysis surpasses this threshold, the verifier will terminate the process and reject the program. This ensures that only programs that are within the manageable complexity are allowed to execute, balancing security with system performance.

### Challenges

Despite its thoroughness, the eBPF verifier faces significant challenges:

- **Attractive target for exploitation when exposed to non-root users**
  As the verifier becomes more complex, it becomes an increasingly attractive target for exploitation. The programmability of eBPF, while powerful, also means that if an attacker were to bypass the verifier and gain execution within the OS kernel, the consequences could be severe.

- **Reasoning about verifier correctness is non-trivial**
  Ensuring the verifier's correctness, especially concerning Spectre mitigations, is not a straightforward task. While there is some formal verification in place, it is only partial. Areas such as the Just-In-Time (JIT) compilers and abstract interpretation models are particularly challenging.

- **Occasions where valid programs get rejected**
  There is sometimes a disconnect between the optimizations performed by LLVM (the compiler infrastructure used to prepare eBPF programs) and the verifier's ability to understand these optimizations, leading to valid programs being erroneously rejected.

- **"Stable ABI" for BPF program types**
  A "stable ABI" is vital so that BPF programs running in production do not break upon an OS kernel upgrade. However, maintaining this stability while also evolving the verifier and the BPF ecosystem presents its own set of challenges.

- **Performance vs. security considerations**
  Finally, the eternal trade-off between performance and security is pronounced in the verification of complex eBPF programs. While the verifier must be efficient to be practical, it also must not compromise on security, as the performance of the programs it is verifying is crucial for modern computing systems.

The eBPF verifier stands as a testament to the ingenuity in modern computing security, navigating the treacherous waters between maximum programmability and maintaining a fortress-like defense at the kernel level.

### Other works to improve verifier

- Specification and verification in the field: Applying formal methods to BPF just-in-time compilers in the Linux kernel: <https://www.usenix.org/conference/osdi20/presentation/nelson>
- "Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers”, Vishwanathan et al. <https://arxiv.org/abs/2105.05398>
- “Eliminating bugs in BPF JITs using automated formal verification”, Nelson et al. <https://arxiv.org/abs/2105.05398>
- “A proof-carrying approach to building correct and flexible BPF verifiers”, Nelson et al. <https://linuxplumbersconf.org/event/7/contributions/685/>
- “Automatically optimizing BPF programs using program synthesis”, Xu et al. <https://linuxplumbersconf.org/event/11/contributions/944/>
- “Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions”, Gershuni et al. <https://linuxplumbersconf.org/event/11/contributions/951/>
- “An Analysis of Speculative Type Confusion Vulnerabilities in the Wild”, Kirzner et al. <https://www.usenix.org/conference/usenixsecurity21/presentation/kirzner>

Together, these works signify a robust and multi-faceted research initiative aimed at bolstering the foundations of eBPF verification, ensuring that it remains a secure and performant tool for extending the capabilities of the Linux kernel.

Other reference for you to learn more about eBPF verifier:

- BPF and Spectre: Mitigating transient execution attacks: <https://popl22.sigplan.org/details/prisc-2022-papers/11/BPF-and-Spectre-Mitigating-transient-execution-attacks>

## Limitations in eBPF Access Control

After leading Linux distributions, such as Ubuntu and SUSE, have disallowed unprivileged usage of eBPF Socket Filter and CGroup programs, the current eBPF access control model only supports a single permission level. This level necessitates the CAP_SYS_ADMIN capability for all features. However, CAP_SYS_ADMIN carries inherent risks, particularly to containers, due to its extensive privileges.

Addressing this, Linux 5.6 introduces a more granular permission system by breaking down eBPF capabilities. Instead of relying solely on CAP_SYS_ADMIN, a new capability, CAP_BPF, is introduced for invoking the bpf syscall. Additionally, installing specific types of eBPF programs demands further capabilities, such as CAP_PERFMON for performance monitoring or CAP_NET_ADMIN for network administration tasks. This structure aims to mitigate certain types of attacks—like altering process memory or eBPF maps—that still require CAP_SYS_ADMIN.

Nevertheless, these segregated capabilities are not bulletproof against all eBPF-based attacks, such as Denial of Service (DoS) and information theft. Attackers may exploit these to craft eBPF-based malware specifically targeting containers. The emergence of eBPF in cloud-native applications exacerbates this threat, as users could inadvertently deploy containers that contain untrusted eBPF programs.

Compounding the issue, the risks associated with eBPF in containerized environments are not entirely understood. Some container services might unintentionally grant eBPF permissions, for reasons such as enabling filesystem mounting functionality. The existing permission model is inadequate in preventing misuse of these potentially harmful eBPF features within containers.

### CAP_BPF

Traditionally, almost all BPF actions required CAP_SYS_ADMIN privileges, which also grant broad system access. Over time, there has been a push to separate BPF permissions from these root privileges. As a result, capabilities like CAP_PERFMON and CAP_BPF were introduced to allow more granular control over BPF operations, such as reading kernel memory and loading tracing or networking programs, without needing full system admin rights.

However, CAP_BPF's scope is also ambiguous, leading to a perception problem. Unlike CAP_SYS_MODULE, which is well-defined and used for loading kernel modules, CAP_BPF lacks namespace constraints, meaning it can access all kernel memory rather than being container-specific. This broad access is problematic because verifier bugs in BPF programs can crash the kernel, considered a security vulnerability, leading to an excessive number of CVEs (Common Vulnerabilities and Exposures) being filed, even for bugs that are already fixed. This response to verifier bugs creates undue alarm and urgency to patch older kernel versions that may not have been updated.

Additionally, some security startups have been criticized for exploiting the fears around BPF's capabilities to market their products, paradoxically using BPF itself to safeguard against the issues they highlight. This has led to a contradictory narrative where BPF is both demonized and promoted as a solution.

### bpf namespace

The current security model requires the CAP_SYS_ADMIN capability for iterating BPF object IDs and converting these IDs to file descriptors (FDs). This is to prevent non-privileged users from accessing BPF programs owned by others, but it also restricts them from inspecting their own BPF objects, posing a challenge in container environments.

Users can run BPF programs with CAP_BPF and other specific capabilities, yet they lack a generic method to inspect these programs, as tools like bpftool need CAP_SYS_ADMIN. The existing workaround without CAP_SYS_ADMIN is deemed inconvenient, involving SCM_RIGHTS and Unix domain sockets for sharing BPF object FDs between processes.

To address these limitations, Yafang Shao proposes introducing a BPF namespace. This would allow users to create BPF maps, programs, and links within a specific namespace, isolating these objects from users in different namespaces. However, objects within a BPF namespace would still be visible to the parent namespace, enabling system administrators to maintain oversight.

The BPF namespace is conceptually similar to the PID namespace and is intended to be intuitive. The initial implementation focuses on BPF maps, programs, and links, with plans to extend this to other BPF objects like BTF and bpffs in the future. This could potentially enable container users to trace only the processes within their container without accessing data from other containers, enhancing security and usability in containerized environments.

reference:

- BPF and security: <https://lwn.net/Articles/946389/>
- Cross Container Attacks: The Bewildered eBPF on Clouds <https://www.usenix.org/system/files/usenixsecurity23-he.pdf>
- bpf: Introduce BPF namespace: <https://lwn.net/Articles/927354/>
- ebpf-running-in-linux-namespaces: <https://stackoverflow.com/questions/48815633/ebpf-running-in-linux-namespaces>

### Unprivileged eBPF

The concept of unprivileged eBPF refers to the ability for non-root users to load eBPF programs into the kernel. This feature is controversial due to security implications and, as such, is currently turned off by default across all major Linux distributions. The concern stems from hardware vulnerabilities like Spectre to kernel bugs and exploits, which can be exploited by malicious eBPF programs to leak sensitive data or attack the system.

To combat this, mitigations have been put in place for various versions of these vulnerabilities, like v1, v2, and v4. However, these mitigations come at a cost, often significantly reducing the flexibility and performance of eBPF programs. This trade-off makes the feature unattractive and impractical for many users and use cases.

#### Trusted Unprivileged BPF

In light of these challenges, a middle ground known as "trusted unprivileged BPF" is being explored. This approach would involve an allowlist system, where specific eBPF programs that have been thoroughly vetted and deemed trustworthy could be loaded by unprivileged users. This vetting process would ensure that only secure, production-ready programs bypass the privilege requirement, maintaining a balance between security and functionality. It's a step toward enabling more widespread use of eBPF without compromising the system's integrity.

- Permissive LSM hooks: Rejected upstream given LSMs enforce further restrictions

    New Linux Security Module (LSM) hooks specifically for the BPF subsystem, with the intent of offering more granular control over BPF maps and BTF data objects. These are fundamental to the operation of modern BPF applications.

    The primary addition includes two LSM hooks: bpf_map_create_security and bpf_btf_load_security, which provide the ability to override the default permission checks that rely on capabilities like CAP_BPF and CAP_NET_ADMIN. This new mechanism allows for finer control, enabling policies to enforce restrictions or bypass checks for trusted applications, shifting the decision-making to custom LSM policy implementations.

    This approach allows for a safer default by not requiring applications to have BPF-related capabilities, which are typically required to interact with the kernel's BPF subsystem. Instead, applications can run without such privileges, with only vetted and trusted cases being granted permission to operate as if they had elevated capabilities.

- BPF token concept to delegate subset of BPF via token fd from trusted privileged daemon

    the BPF token, a new mechanism allowing privileged daemons to delegate a subset of BPF functionality to trusted unprivileged applications. This concept enables containerized BPF applications to operate safely within user namespaces—a feature previously unattainable due to security restrictions with CAP_BPF capabilities. The BPF token is created and managed via kernel APIs, and it can be pinned within the BPF filesystem for controlled access. The latest version of the patch ensures that a BPF token is confined to its creation instance in the BPF filesystem to prevent misuse. This addition to the BPF subsystem facilitates more secure and flexible unprivileged BPF operations.

- BPF signing as gatekeeper: application vs BPF program (no one-size-fits-all)

    Song Liu has proposed a patch for unprivileged access to BPF functionality through a new device, `/dev/bpf`. This device controls access via two new ioctl commands that allow users with write permissions to the device to invoke `sys_bpf()`. These commands toggle the ability of the current task to call `sys_bpf()`, with the permission state being stored in the `task_struct`. This permission is also inheritable by new threads created by the task. A new helper function, `bpf_capable()`, is introduced to check if a task has obtained permission through `/dev/bpf`. The patch includes updates to documentation and header files.

- RPC to privileged BPF daemon: Limitations depending on use cases/environment

    The RPC approach (eg. bpfd) is similar to the BPF token concept, but it uses a privileged daemon to manage the BPF programs. This daemon is responsible for loading and unloading BPF programs, as well as managing the BPF maps. The daemon is also responsible for verifying the BPF programs before loading them. This approach is more flexible than the BPF token concept, as it allows for more fine-grained control over the BPF programs. However, it is also more complex, bring more maintenance challenges and possibilities for single points of failure.

reference

- Permissive LSM hooks: <https://lore.kernel.org/bpf/20230412043300.360803-1-andrii@kernel.org/>
- BPF token concept: <https://lore.kernel.org/bpf/20230629051832.897119-1-andrii@kernel.org/>
- BPF signing using fsverity and LSM gatekeeper: <https://www.youtube.com/watch?v=9p4qviq60z8>
- Sign the BPF bytecode: <https://lpc.events/event/16/contributions/1357/attachments/1045/1999/BPF%20Signatures.pdf>
- bpfd: <https://bpfd.dev/>

## Other possible solutions

Here are also some research or discussions about how to improve the security of eBPF. Existing works can be roughly divided into three categories: virtualization, Software Fault Isolation (SFI), and formal methods. Use a sandbox like WebAssembly to deploy eBPF programs or run eBPF programs in userspace is also a possible solution.

### MOAT: Towards Safe BPF Kernel Extension (Isolation)

The Linux kernel makes considerable use of
Berkeley Packet Filter (BPF) to allow user-written BPF applications
to execute in the kernel space. BPF employs a verifier to
statically check the security of user-supplied BPF code. Recent
attacks show that BPF programs can evade security checks and
gain unauthorized access to kernel memory, indicating that the
verification process is not flawless. In this paper, we present
MOAT, a system that isolates potentially malicious BPF programs
using Intel Memory Protection Keys (MPK). Enforcing BPF
program isolation with MPK is not straightforward; MOAT is
carefully designed to alleviate technical obstacles, such as limited
hardware keys and supporting a wide variety of kernel BPF
helper functions. We have implemented MOAT in a prototype
kernel module, and our evaluation shows that MOAT delivers
low-cost isolation of BPF programs under various real-world
usage scenarios, such as the isolation of a packet-forwarding
BPF program for the memcached database with an average
throughput loss of 6%.

<https://arxiv.org/abs/2301.13421>

> If we must resort to hardware protection mechanisms, is language safety or verification still necessary to protect the kernel and extensions from one another?

### Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing

For safety reasons, unprivileged users today have only limited ways to customize the kernel through the extended Berkeley Packet Filter (eBPF). This is unfortunate, especially since the eBPF framework itself has seen an increase in scope over the years. We propose SandBPF, a software-based kernel isolation technique that dynamically sandboxes eBPF programs to allow unprivileged users to safely extend the kernel, unleashing eBPF's full potential. Our early proof-of-concept shows that SandBPF can effectively prevent exploits missed by eBPF's native safety mechanism (i.e., static verification) while incurring 0%-10% overhead on web server benchmarks.

<https://arxiv.org/abs/2308.01983>

> It may be conflict with the original design of eBPF, since it's not designed to use sandbox to ensure safety. Why not using webassembly in kernel if you want SFI?

### Kernel extension verification is untenable

The emergence of verified eBPF bytecode is ushering in a
new era of safe kernel extensions. In this paper, we argue
that eBPF’s verifier—the source of its safety guarantees—has
become a liability. In addition to the well-known bugs and
vulnerabilities stemming from the complexity and ad hoc
nature of the in-kernel verifier, we highlight a concerning
trend in which escape hatches to unsafe kernel functions
(in the form of helper functions) are being introduced to
bypass verifier-imposed limitations on expressiveness, unfortunately also bypassing its safety guarantees. We propose
safe kernel extension frameworks using a balance of not
just static but also lightweight runtime techniques. We describe a design centered around kernel extensions in safe
Rust that will eliminate the need of the in-kernel verifier,
improve expressiveness, allow for reduced escape hatches,
and ultimately improve the safety of kernel extensions

<https://sigops.org/s/conferences/hotos/2023/papers/jia.pdf>

> It may limits the kernel to load only eBPF programs that are signed by trusted third parties, as the kernel itself can no longer independently verify them. The rust toolchains also has vulnerabilities.

### Wasm-bpf: WebAssembly eBPF library, toolchain and runtime

Wasm-bpf is a WebAssembly eBPF library, toolchain and runtime allows the construction of eBPF programs into Wasm with little to no changes to the code, and run them cross platforms with Wasm sandbox.

It provides a configurable environment with limited eBPF WASI behavior, enhancing security and control. This allows for fine-grained permissions, restricting access to kernel resources and providing a more secure environment. For instance, eBPF programs can be restricted to specific types of useage, such as network monitoring, it can also configure what kind of eBPF programs can be loaded in kernel, what kind of attach event it can access without the need for modify kernel eBPF permission models.

- Kubecon talk: <https://sched.co/1R2uf>
- Repo: <https://github.com/eunomia-bpf/wasm-bpf>

> It will require additional effort to port the application to WebAssembly. Additionally, Wasm interface of kernel eBPF also need more effort of maintain, as the BPF daemon does.

### `bpftime`: Userspace eBPF runtime for uprobe & syscall hook & plugin

An userspace eBPF runtime that allows existing eBPF applications to operate in unprivileged userspace using the same libraries and toolchains. It offers Uprobe and Syscall tracepoints for eBPF, with significant performance improvements over kernel uprobe and without requiring manual code instrumentation or process restarts. The runtime facilitates interprocess eBPF maps in userspace shared memory, and is also compatible with kernel eBPF maps, allowing for seamless operation with the kernel's eBPF infrastructure. It includes a high-performance LLVM JIT for various architectures, alongside a lightweight JIT for x86 and an interpreter.

- <https://arxiv.org/abs/2311.07923>
- Linux Plumbers: <https://lpc.events/event/17/contributions/1639/>
- Repo: <https://github.com/eunomia-bpf/bpftime>

> It may only limited to certain eBPF program types and usecases, not a general approach for kernel eBPF.

## Conclusion

As we have traversed the multifaceted domain of eBPF security, it's clear that while eBPF’s verifier provides a robust first line of defense, there are inherent limitations within the current access control model that require attention. We have considered potential solutions from the realms of virtualization, software fault isolation, and formal methods to WebAssembly or userspace eBPF runtime, each offering unique approaches to fortify eBPF against vulnerabilities.

However, as with any complex system, new questions and challenges continue to surface. The gaps identified between the theoretical security models and their practical implementation invite continued research and experimentation. The future of eBPF security is not only promising but also demands a collective effort to ensure the technology can be adopted with confidence in its capacity to safeguard systems.

> We are [github.com/eunomia-bpf](https://github.com/eunomia-bpf), build open source projects to make eBPF easier to use, and exploring new technologies, toolchains and runtimes related to eBPF.
> For those interested in eBPF technology, check out our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> and our tutorials at <https://eunomia.dev/tutorials/> for practical understanding and practice.
