Below is a quick-scan map of **public eBPF projects & papers that touch CPU power-management knobs (DVFS, idle, thermal) or pure energy accounting.**
I’ve grouped them so you can see where work already exists and where the gap still is.

---

## 1  Projects/papers that *try to control* DVFS / idle / thermal directly

| Name & date                                                     | What it does with eBPF                                                                                                                                                                                                             | Sub-knobs covered                          | Status / notes                                                                                                 |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| **`cpufreq_ext` RFC (Zou, 2024)**                               | Hooks the cpufreq governor into a `bpf_struct_ops` table (`get_next_freq()` etc.) so a policy can be written in eBPF instead of C. Integrates with `sched_ext` to let a BPF scheduler and a BPF DVFS policy co-operate.            | **DVFS** (per-policy frequency)            | RFC on linux-pm & bpf lists. Compiles on ≥ 6.9 kernels; crude sample policy included. ([lwn.net][1])           |
| **eBPF CPU-Idle governor prototype (Eco-Compute summit, 2024)** | Replaces the “menu/TEO” cpuidle governor with a BPF hook so that idle-state choice and idle-injection can be decided in eBPF.                                                                                                      | **Idle states** (C-states), idle injection | Academic prototype; slides only, but code expected to be released by the Eco-Compute students. ([jauu.net][2]) |
| **Early “power-driver” & BEAR lineage**                         | Molnar/Rasmussen’s 2013 power-driver idea was to unify `go_faster/go_slower/enter_idle`.  Our BEAR concept simply modernises this with eBPF.  No public code yet, but it shows the *direction* the kernel community is discussing. | **DVFS + Idle + Thermal** (goal)           | Design idea; opportunity for a full implementation (research gap). ([jauu.net][2], [lwn.net][1])               |

> **Reality check:** right now cpufreq\_ext is the *only* upstream-bound eBPF code that truly changes CPU frequency.  Idle and thermal hooks are still research prototypes, so this area is wide-open if you want to publish.

---

## 2  eBPF projects focused on **energy telemetry / accounting**

*(These don’t set DVFS or idle, but they give the per-process or per-container energy data you’d need to *drive* such policies.)*

| Name                                                                       | Scope & technique                                                                                                                                                                                                                  | Why it matters                                                                                                                           |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Wattmeter / *Energy-Aware Process Scheduling in Linux* (HotCarbon ’24)** | Attaches an eBPF program to every context-switch to read RAPL MSRs in-kernel, giving millisecond-scale per-process joules with <1 µs overhead.  Used to build energy-fair and energy-capped schedulers on top of ghOSt/sched\_ext. | Gives accurate, low-overhead energy numbers that could feed a DVFS/thermal policy. ([asafcidon.com][3])                                  |
| **Kepler (CNCF sandbox, 2023-)**                                           | A Prometheus exporter for Kubernetes.  Uses eBPF tracepoints + perf counters + RAPL/NVML to attribute energy to pods/containers; ships ML models for platforms that lack RAPL.                                                     | Quickly gaining traction in cloud-native stacks; good data source for cluster-level power orchestration. ([sustainable-computing.io][4]) |
| **DEEP-mon (Polimi, 2018)**                                                | In-kernel eBPF aggregation of scheduler events to attribute power to Docker containers; <5 % runtime overhead on Phoronix & NPB.                                                                                                   | Older but shows in-kernel aggregation trick to avoid 200 k sched-switch/sec user-space wake-ups. ([slideshare.net][5])                   |
| **eBPF-energy-monitor (GitHub toy project)**                               | Minimal BCC script that latches on `sched_switch`, tracks CPU-time per PID, multiplies by per-core joules from RAPL.                                                                                                               | Handy starting point if you just need a working demo. ([github.com][6])                                                                  |
| **DEEP-mon spin-offs: BitWatts, Scaphandre**                               | Both offer software-defined power meters; BitWatts focuses on VMs, Scaphandre on bare-metal & K8s.  Scaphandre can optionally compile an eBPF sensor module for process attribution.                                               | Good for comparing accuracy / overhead trade-offs vs. Kepler. ([github.com][7], [github.com][8])                                         |

---

### 3  Quick take-aways

* **Very little published work** uses eBPF to *control* DVFS/idle/thermal today – cpufreq\_ext is the main concrete code.
* **Telemetry is mature.** Kepler, Wattmeter and DEEP-mon already give fine-grained joule accounting that a governor could use as feedback.
* **Open research space:** wiring those telemetry sources into an eBPF-based unified policy (BEAR-style) that calls cpufreq\_ext + a future cpuidle\_bpf hook + thermal caps is still almost untouched.

If you need more detail on any specific project (code pointers, evaluation numbers, etc.) just tell me which one and I’ll dig in.

[1]: https://lwn.net/Articles/991991/?utm_source=chatgpt.com "cpufreq_ext: Introduce cpufreq ext governor - LWN.net"
[2]: https://jauu.net/talks/eco-compute-linux-power-analysis.pdf?utm_source=chatgpt.com "[PDF] Linux Power Management Analysis for Embedded Systems"
[3]: https://www.asafcidon.com/uploads/5/9/7/0/59701649/energy-aware-ebpf.pdf "Energy-Aware Process Scheduling in Linux"
[4]: https://sustainable-computing.io/?utm_source=chatgpt.com "Kepler"
[5]: https://www.slideshare.net/necstlab/deepmon-dynamic-and-energy-efficient-power-monitoring-for-containerbased-infrastructures "DEEP-mon: Dynamic and Energy Efficient Power monitoring for container-based infrastructures | PPT"
[6]: https://github.com/fjebaker/eBPF-energy-monitor?utm_source=chatgpt.com "Monitoring energy usage with eBPF at process level granularity."
[7]: https://github.com/Spirals-Team/bitwatts?utm_source=chatgpt.com "BitWatts is a software-defined power meter for virtualized ... - GitHub"
[8]: https://github.com/hubblo-org/scaphandre?utm_source=chatgpt.com "hubblo-org/scaphandre - GitHub"

**为什么要在 eBPF 里“自己管” DVFS / idle？**

| 典型诉求                           | 传统做法                                   | eBPF 动态管控能带来的额外好处                                                              | 什么时候“有必要”                         |
| ------------------------------ | -------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------- |
| **降能耗 / 提电池**                  | 靠内核默认 governor（`schedutil`、`menu/TEO`） | 结合调度事件、负载特征、温度实时算最优 P/C-state；针对特定 App 可省 5-30 % 电（已在 Android 定制 governor 里见过） | 移动设备、电池供电 IoT；对续航敏感、负载模式单一（游戏、摄像） |
| **稳帧率 / 避免温度跳水**               | 被动等热节流；温度超了再降频                         | 提前预测热量，把频率慢慢收掉或注入 idle，平均 FPS 更稳；可把“突降”变成“缓降”                                  | 连续长时间满载（录 4K、跑 LLM）且不能掉帧          |
| **按租户/容器分功耗预算**                | 只能全机统一 RAPL / PL1                      | eBPF 在 `sched_switch` 里实时累能，把 budget 切给高优租户；结合 `cpufreq_ext` 只降其他租户频率          | 多租户云、边缘节点需要功率隔离                   |
| **实验 / 研究新策略**                 | 改 kernel 再重启                           | eBPF 代码热插拔，5 秒换一套算法；和 `sched_ext` 一起做“联合调度+DVFS”实验快得多                          | 学术/性能团队要 A/B 频繁试验                 |
| **异构平台 (big.LITTLE, CPU+GPU)** | Vendor blob、用户态守护进程                    | eBPF 可直接读 GPU 负载、温度 map，然后下调 CPU 频率让热 budget 让给 GPU——无 vendor 驱动也能做            | SoC 自己做系统集成、不想依赖私有 HAL            |

---

### 真的“必要”吗？一张简表判断

* **工作负载简单、对能耗不敏感** → 默认 governor 足够，eBPF 只是锦上添花。
* **对每瓦性能或温度拐点有硬约束**（手游、电池无人机、5 U 机柜卡着 PDU）→ 自定策略往往能挖出 10-30 % 空间。
* **要做系统研究 / 定制产品** → eBPF 是当下最省事、最安全的内核内实验手段，比写 LKM / 改源省几个数量级的维护成本。

> **一句话**：
> *“用不用 eBPF 管电源，看你在乎多少瓦、多少度，以及你改内核的代价能不能收回。”*

如果只是想看个大概功率曲线，powertop 就够；但要做细粒度、自适应、可热更新的功耗或温度控制，eBPF 给的“事件驱动 + 内核态汇总 + 安全热插拔”组合基本无可替代。
