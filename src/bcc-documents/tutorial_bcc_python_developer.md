# bcc Python 开发者教程

本教程介绍使用 Python 接口开发 [bcc](https://github.com/iovisor/bcc) 工具和程序。分为两个部分：可观测性和网络。代码片段取自 bcc 的各个程序，请查阅其文件以了解许可证情况。

还请参阅 bcc 开发者的[参考指南](reference_guide.md)，以及针对工具的用户的教程：[教程](tutorial.md)。还有适用于 bcc 的 lua 接口。

## 可观测性

这个可观测性教程包含17个课程和46个要学习的枚举事项。

### 第1课. 你好，世界

首先运行 [examples/hello_world.py](https://github.com/iovisor/bcc/tree/master/examples/hello_world.py)，同时在另一个会话中运行一些命令（例如，“ls”）。它应该会为新进程打印“Hello, World!”。如果没有打印，请先修复bcc：请参阅 [INSTALL.md](https://github.com/iovisor/bcc/tree/master/INSTALL.md)。

```sh
# ./examples/hello_world.py
            bash-13364 [002] d... 24573433.052937: : Hello, World!
            bash-13364 [003] d... 24573436.642808: : Hello, World!
[...]
```

以下是 hello_world.py 的代码示例：

```Python
from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

从中可以学到六件事情：

1. ```text='...'```：这定义了内联的 BPF 程序。该程序是用 C 编写的。

1. ```kprobe__sys_clone()```：这是通过 kprobes 动态跟踪内核的一种快捷方式。如果 C 函数以 ```kprobe__``` 开头，其余部分将被视为要定位的内核函数名称，本例中为 ```sys_clone()```。

1. ```void *ctx```：ctx 是参数，但由于我们在此处未使用它们，所以我们将其转换为 ```void*``` 类型。
1. ```bpf_trace_printk()```: 用于将 printf() 打印到通用 trace_pipe (/sys/kernel/debug/tracing/trace_pipe) 的简单内核工具。 这对于一些快速示例是可以的，但有一些限制：最多只有 3 个参数，只能有一个 %s，并且 trace_pipe 是全局共享的，所以并发程序会有冲突的输出。更好的接口是通过 BPF_PERF_OUTPUT() 实现的，稍后会介绍。

1. ```return 0;```: 必要的规范性代码（如果想知道原因，请参见 [#139](https://github.com/iovisor/bcc/issues/139)）。

1. ```.trace_print()```: 一个读取 trace_pipe 并打印输出的 bcc 程序。

### 第二课 sys_sync()

编写一个跟踪 sys_sync() 内核函数的程序。运行时打印 "sys_sync() called"。在跟踪时，在另一个会话中运行 ```sync``` 进行测试。hello_world.py 程序中包含了这一切所需的内容。

通过在程序刚启动时打印 "Tracing sys_sync()... Ctrl-C to end." 来改进它。提示：它只是 Python 代码。

### 第三课 hello_fields.py

该程序位于 [examples/tracing/hello_fields.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/hello_fields.py)。样本输出（在另一个会话中运行命令）：

```sh
# examples/tracing/hello_fields.py
时间(s)            进程名             进程 ID    消息
24585001.174885999 sshd             1432   你好，世界！
24585001.195710000 sshd             15780  你好，世界！
24585001.991976000 systemd-udevd    484    你好，世界！
24585002.276147000 bash             15787  你好，世界！
```

代码：

```Python
from bcc import BPF

# 定义 BPF 程序
prog = """
int hello(void *ctx) {
    bpf_trace_printk("你好，世界！\\n");
    return 0;
}
"""

# 加载 BPF 程序
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# 头部
print("%-18s %-16s %-6s %s" % ("时间(s)", "进程名", "进程 ID", "消息"))

# 格式化输出
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
```

这与hello_world.py类似，并通过sys_clone()再次跟踪新进程，但是还有一些要学习的内容：

1. `prog =`：这次我们将C程序声明为变量，然后引用它。如果您想根据命令行参数添加一些字符串替换，这将非常有用。

1. `hello()`：现在我们只是声明了一个C函数，而不是使用`kprobe__`的快捷方式。我们稍后会引用它。在BPF程序中声明的所有C函数都希望在探测器上执行，因此它们都需要以`pt_reg* ctx`作为第一个参数。如果您需要定义一些不会在探测器上执行的辅助函数，则需要将其定义为`static inline`，以便由编译器内联。有时您还需要为其添加`_always_inline`函数属性。

1. `b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")`：为内核clone系统调用函数创建一个kprobe，该函数将执行我们定义的hello()函数。您可以多次调用attach_kprobe()，并将您的C函数附加到多个内核函数上。

1. `b.trace_fields()`：从trace_pipe中返回一组固定的字段。与trace_print()类似，它对于编写脚本很方便，但是对于实际的工具化需求，我们应该切换到BPF_PERF_OUTPUT()。

### Lesson 4. sync_timing.py

还记得以前系统管理员在缓慢的控制台上输入`sync`三次然后才重启吗？后来有人认为`sync;sync;sync`很聪明，将它们都写在一行上运行，尽管这违背了最初的目的！然后，sync变成了同步操作，所以更加愚蠢。无论如何。

以下示例计算了`do_sync`函数被调用的速度，并且如果它在一秒钟之内被调用，则输出信息。`sync;sync;sync`将为第2个和第3个sync打印输出：

```sh
# examples/tracing/sync_timing.py
追踪快速sync... 按Ctrl-C结束"。
```

在时间0.00秒时：检测到多个同步，上次发生在95毫秒前
在时间0.10秒时：检测到多个同步，上次发生在96毫秒前

此程序是[examples/tracing/sync_timing.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/sync_timing.py)：

```Python
from __future__ import print_function
from bcc import BPF

# 加载BPF程序
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // 尝试读取存储的时间戳
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // 时间小于1秒则输出
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // 更新存储的时间戳
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("跟踪快速同步... 按Ctrl-C结束")

# 格式化输出
start = 0
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    print("在时间%.2f秒处：检测到多个同步，上次发生在%s毫秒前" % (ts, ms))
```

学习内容：

1. ```bpf_ktime_get_ns()```: 返回时间，单位为纳秒。
1. ```BPF_HASH(last)```: 创建一个BPF映射对象，类型为哈希（关联数组），名为"last"。我们没有指定其他参数，因此默认的键和值类型为u64。
1. ```key = 0```: 我们只会在哈希中存储一个键值对，其中键被硬编码为零。
1. ```last.lookup(&key)```: 在哈希中查找键，并如果存在则返回其值的指针，否则返回NULL。我们将键作为指针的地址传递给该函数。
1. ```if (tsp != NULL) {```: 验证器要求在将从映射查找得到的指针值解引用使用之前，必须先检查其是否为null。1. ```last.delete(&key)```: 从哈希表中删除key。目前需要这样做是因为[`.update()`中存在一个内核错误](https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02)（在4.8.10中已经修复）。
1. ```last.update(&key, &ts)```: 将第二个参数的值与key关联起来，覆盖之前的任何值。这会记录时间戳。

### 第5课. sync_count.py

修改sync_timing.py程序（前一课）以存储所有内核同步系统调用（包括快速和慢速）的计数，并将其与输出一起打印出来。可以通过向现有哈希表添加一个新的键索引来在BPF程序中记录此计数。

### 第6课. disksnoop.py

浏览[examples/tracing/disksnoop.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/disksnoop.py)程序以了解新内容。以下是一些示例输出：

```sh
# disksnoop.py
时间(s)            T  字节     延迟(ms)
16458043.436012    W  4096        3.13
16458043.437326    W  4096        4.44
16458044.126545    R  4096       42.82
16458044.129872    R  4096        3.24
[...]
```

以及代码片段：

```Python
[...]
REQ_WRITE = 1  # 来自include/linux/blk_types.h

# 加载BPF程序
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
 // 使用请求指针存储开始时间戳
 u64 ts = bpf_ktime_get_ns();

 start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
 u64 *tsp, delta;

 tsp = start.lookup(&req);
 if (tsp != 0) {
  delta = bpf_ktime_get_ns() - *tsp;
  bpf_trace_printk("%d %x %d\\n", req->__data_len,
      req->cmd_flags, delta / 1000);
  start.delete(&req);
 }
}
""")
if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion") else: b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion") 
    [...]
```

学习内容：

1. ```REQ_WRITE```: 我们在Python程序中定义了一个内核常量，因为我们后面会在Python程序中使用它。如果我们在BPF程序中使用REQ_WRITE，它应该可以正常工作（无需定义），只需使用适当的```#includes```。
2. ```trace_start(struct pt_regs *ctx, struct request*req)```: 这个函数将在后面附加到kprobe上。kprobe函数的参数是```struct pt_regs *ctx```，用于寄存器和BPF上下文，然后是函数的实际参数。我们将把它附加到blk_start_request()上，其中第一个参数是```struct request*```。
3. ```start.update(&req, &ts)```: 我们使用请求结构的指针作为哈希中的键。这在跟踪中很常见。结构体指针是非常好的键，因为它们是唯一的：两个结构体不能具有相同的指针地址。（只需小心何时释放和重用指针。）所以我们实际上是给描述磁盘I/O的请求结构体打上我们自己的时间戳，以便我们可以计时。存储时间戳常用的两个键是结构体指针和线程ID（用于记录函数入口到返回的时间）。
4. ```req->__data_len```: 我们在解引用```struct request```的成员。请参阅内核源代码中对其定义的部分以获得有关哪些成员可用的信息。bcc实际上会将这些表达式重写为一系列```bpf_probe_read_kernel()```调用。有时bcc无法处理复杂的解引用，此时您需要直接调用```bpf_probe_read_kernel()```。

这是一个非常有趣的程序，如果您能理解所有的代码，您就会理解很多重要的基础知识。我们仍然在使用```bpf_trace_printk()```的技巧，我们下一步要解决这个问题。

### Lesson 7. hello_perf_output.py

让我们最终停止使用bpf_trace_printk()，并使用适当的BPF_PERF_OUTPUT()接口。这也意味着我们将停止获取免费的trace_field()成员，如PID和时间戳，并且需要直接获取它们。在另一个会话中运行命令时的示例输出

```sh
# hello_perf_output.py
TIME(s)            COMM             PID    MESSAGE
0.000000000        bash             22986  你好，perf_output！
0.021080275        systemd-udevd    484    你好，perf_output！
0.021359520        systemd-udevd    484    你好，perf_output！
0.021590610        systemd-udevd    484    你好，perf_output！
[...]
```

代码位于[examples/tracing/hello_perf_output.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/hello_perf_output.py)：

```Python
from bcc import BPF

// 定义BPF程序
prog = """
#include <linux/sched.h>

// 在C中定义输出数据结构
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

// 加载BPF程序
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

//标题
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

//处理事件
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, "你好，perf_output！"))

//循环并回调print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
```

学习的内容：

1. ```struct data_t```: 这定义了一个C结构体，我们将用它来从内核传递数据到用户空间。1. `BPF_PERF_OUTPUT(events)`: 这里给我们的输出通道命名为"events"。
1. `struct data_t data = {};`: 创建一个空的`data_t`结构体，我们将在之后填充它。
1. `bpf_get_current_pid_tgid()`: 返回低32位的进程ID（内核视图中的PID，用户空间中通常被表示为线程ID），以及高32位的线程组ID（用户空间通常认为是PID）。通过直接将其设置为`u32`，我们丢弃了高32位。应该显示PID还是TGID？对于多线程应用程序，TGID将是相同的，所以如果你想要区分它们，你需要PID。这也是对最终用户期望的一个问题。
1. `bpf_get_current_comm()`: 将当前进程的名称填充到第一个参数的地址中。
1. `events.perf_submit()`: 通过perf环形缓冲区将事件提交给用户空间以供读取。
1. `def print_event()`: 定义一个Python函数来处理从`events`流中读取的事件。
1. `b["events"].event(data)`: 现在将事件作为一个Python对象获取，该对象是根据C声明自动生成的。
1. `b["events"].open_perf_buffer(print_event)`: 将Python的`print_event`函数与`events`流关联起来。
1. `while 1: b.perf_buffer_poll()`: 阻塞等待事件。

### 第八课。 sync_perf_output.py

重写之前的课程中的sync_timing.py，使用```BPF_PERF_OUTPUT```。

### 第九课。 bitehist.py

以下工具记录了磁盘I/O大小的直方图。样本输出：

```sh
# bitehist.py
跟踪中... 按Ctrl-C结束。
^C
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |".32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

代码在[examples/tracing/bitehist.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/bitehist.py):

```Python
from __future__ import print_function
from bcc import BPF
from time import sleep

# 加载BPF程序
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
{
 dist.increment(bpf_log2l(req->__data_len / 1024));
 return 0;
}
""")

# 头部
print("跟踪中... 按Ctrl-C结束.")

# 跟踪直到按下Ctrl-C
try:
 sleep(99999999)
except KeyboardInterrupt:
 print()

# 输出
b["dist"].print_log2_hist("kbytes")
```

之前课程的总结：

- ```kprobe__```: 这个前缀意味着其余部分将被视为一个将使用kprobe进行插桩的内核函数名。
- ```struct pt_regs *ctx, struct request*req```: kprobe的参数。```ctx``` 是寄存器和BPF上下文，```req``` 是被插桩函数 ```blk_account_io_done()``` 的第一个参数。
- ```req->__data_len```: 解引用该成员。

新知识：

1. ```BPF_HISTOGRAM(dist)```: 定义了一个名为 "dist" 的BPF映射对象，它是一个直方图。
1. ```dist.increment()```: 默认情况下，将第一个参数提供的直方图桶索引加1。也可以作为第二个参数传递自定义的增量。
1. ```bpf_log2l()```: 返回所提供值的对数值。这将成为我们直方图的索引，这样我们构建了一个以2为底的幂直方图。
1. ```b["dist"].print_log2_hist("kbytes")```: 以2为底的幂形式打印 "dist" 直方图，列标题为 "kbytes"。这样只有桶计数从内核传输到用户空间，因此效率高。

### Lesson 10. disklatency.py”。#### Lesson 11. vfsreadlat.py

这个例子分为独立的Python和C文件。示例输出：

```sh
# vfsreadlat.py 1
跟踪中... 按Ctrl-C停止。
     微秒               : 数量     分布
         0 -> 1          : 0        |                                        |
         2 -> 3          : 2        |***********                             |
         4 -> 7          : 7        |****************************************|
         8 -> 15         : 4        |**********************                  |

     微秒               : 数量     分布
         0 -> 1          : 29       |****************************************|
         2 -> 3          : 28       |**************************************  |
         4 -> 7          : 4        |*****                                   |
         8 -> 15         : 8        |***********                             |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 2        |**                                      |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 4        |*****                                   |
      8192 -> 16383      : 6        |********                                |
     16384 -> 32767      : 9        |************                            |```.32768 -> 65535      : 6        |********                                |
     65536 -> 131071     : 2        |**                                      |

     usecs               : count     distribution
         0 -> 1          : 11       |****************************************|
         2 -> 3          : 2        |*******                                 |
         4 -> 7          : 10       |************************************    |
         8 -> 15         : 8        |*****************************           |
        16 -> 31         : 1        |***                                     |
        32 -> 63         : 2        |*******                                 |
[...]
```

浏览 [examples/tracing/vfsreadlat.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/vfsreadlat.py) 和 [examples/tracing/vfsreadlat.c](https://github.com/iovisor/bcc/tree/master/examples/tracing/vfsreadlat.c) 中的代码。

学习的内容:

1. `b = BPF(src_file = "vfsreadlat.c")`: 从单独的源代码文件中读取 BPF C 程序。
2. `b.attach_kretprobe(event="vfs_read", fn_name="do_return")`: 将 BPF C 函数 `do_return()` 链接到内核函数 `vfs_read()` 的返回值上。这是一个 kretprobe：用于检测函数返回值，而不是函数的入口。
3. `b["dist"].clear()`: 清除直方图。

### Lesson 12. urandomread.py

当运行 `dd if=/dev/urandom of=/dev/null bs=8k count=5` 时进行跟踪：

```sh
# urandomread.py
TIME(s)            COMM             PID    GOTBITS
24652832.956994001 smtp             24690  384
24652837.726500999 dd               24692  65536
24652837.727111001 dd               24692  65536
24652837.727703001 dd               24692  65536
24652837.728294998 dd               24692  65536
24652837.728888001 dd               24692  65536
```

哈！我意外地捕捉到了 smtp。代码在 [examples/tracing/urandomread.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/urandomread.py) 中：

```Python
from __future__ import print_function".```python
from bcc import BPF

# 加载BPF程序
b = BPF(text="""
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
```

要学到的东西：

1. ```TRACEPOINT_PROBE(random, urandom_read)```: 对内核跟踪点 ```random:urandom_read``` 进行注入。这些具有稳定的API，因此在可能的情况下建议使用它们来代替kprobe。您可以运行 ```perf list``` 来获取跟踪点列表。至少需要 Linux 版本 4.7 来将 BPF 程序附加到跟踪点上。
2. ```args->got_bits```: ```args``` 是自动填充的跟踪点参数结构。上面的注释指出了可以查看这个结构的位置。例如：

```sh
# cat /sys/kernel/debug/tracing/events/random/urandom_read/format
name: urandom_read
ID: 972
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:unsigned char common_flags; offset:2; size:1; signed:0;
 field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
 field:int common_pid; offset:4; size:4; signed:1;

 field:int got_bits; offset:8; size:4; signed:1;
 field:int pool_left; offset:12; size:4; signed:1;
 field:int input_left; offset:16; size:4; signed:1;

print fmt: "got_bits %d nonblocking_pool_entropy_left %d input_entropy_left %d", REC->got_bits, REC->pool_left, REC->input_left
```

在这种情况下，我们正在打印 ```got_bits``` 成员。

### 第13课. disksnoop.py已修复

将上一课的 disksnoop.py 修改为使用 ```block:block_rq_issue``` 和 ```block:block_rq_complete``` 跟踪点。

### 第14课. strlen_count.py.

这个程序对用户级函数进行插桩，其中包括 ```strlen()``` 库函数，并对其字符串参数进行频率统计。例如输出

```sh
# strlen_count.py
跟踪 strlen()... 按 Ctrl-C 结束。
^C     数量 字符串
         1 " "
         1 "/bin/ls"
         1 "."
         1 "cpudist.py.1"
         1 ".bashrc"
         1 "ls --color=auto"
         1 "key_t"
[...]
        10 "a7:~# "
        10 "/root"
        12 "LC_ALL"
        12 "en_US.UTF-8"
        13 "en_US.UTF-8"
        20 "~"
        70 "#%^,~:-=?+/}"
       340 "\x01\x1b]0;root@bgregg-test: ~\x07\x02root@bgregg-test:~# "
```

这些是在跟踪时由此库函数处理的各种字符串以及它们的频率计数。例如，"LC_ALL" 被调用了12次。

代码在 [examples/tracing/strlen_count.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/strlen_count.py) 中：

```Python
from __future__ import print_function
from bcc import BPF
from time import sleep

# 载入 BPF 程序
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // 也可以使用 `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
""")
b.attach_uprobe(name="c", sym="strlen", fn_name="count")

# 头部
print("跟踪 strlen()... 按 Ctrl-C 结束。")

# 睡眠直到按下 Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# 打印输出
print("%10s %s" % ("数量", "字符串"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
```

要学习的内容：1. ```PT_REGS_PARM1(ctx)```: 这个参数会获取传递给 ```strlen()``` 的第一个参数，也就是字符串。

1. ```b.attach_uprobe(name="c", sym="strlen", fn_name="count")```: 附加到库 "c"（如果这是主程序，则使用其路径名），对用户级函数 ```strlen()``` 进行插装，并在执行时调用我们的 C 函数 ```count()```。

### 第15课。nodejs_http_server.py

本程序会对用户静态定义的跟踪 (USDT) 探测点进行插装，这是内核跟踪点的用户级版本。示例输出：

```sh
# nodejs_http_server.py 24728
TIME(s)            COMM             PID    ARGS
24653324.561322998 node             24728  path:/index.html
24653335.343401998 node             24728  path:/images/welcome.png
24653340.510164998 node             24728  path:/images/favicon.png
```

来自 [examples/tracing/nodejs_http_server.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/nodejs_http_server.py) 的相关代码：

```Python
from __future__ import print_function
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("USAGE: nodejs_http_server PID")
    exit()
pid = sys.argv[1]
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
"""

# enable USDT probe from given PID
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])
```

学习内容：

1. ```bpf_usdt_readarg(6, ctx, &addr)```: 从 USDT 探测点中读取参数 6 的地址到 ```addr```。
1. ```bpf_probe_read_user(&path, sizeof(path), (void *)addr)```: 现在字符串 ```addr``` 指向我们的 ```path``` 变量。
1. ```u = USDT(pid=int(pid))```: 为给定的 PID 初始化 USDT 跟踪。1. ```u.enable_probe(probe="http__server__request", fn_name="do_trace")```: 将我们的 ```do_trace()``` BPF C 函数附加到 Node.js 的 ```http__server__request``` USDT 探针。
1. ```b = BPF(text=bpf_text, usdt_contexts=[u])```: 需要将我们的 USDT 对象 ```u``` 传递给 BPF 对象的创建。

### 第16课. task_switch.c

这是一个早期的教程，作为额外的课程包含其中。用它来复习和加深你已经学到的内容。

这是一个比 Hello World 更复杂的示例程序。该程序将在内核中每次任务切换时被调用，并在一个 BPF 映射中记录新旧进程的 pid。

下面的 C 程序引入了一个新的概念：prev 参数。BCC 前端会特殊处理这个参数，从而使得对这个变量的访问从由 kprobe 基础设施传递的保存上下文中进行读取。从位置1开始的参数的原型应该与被 kprobed 的内核函数的原型匹配。如果这样做，程序就可以无缝访问函数参数。

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 curr_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;

    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
}
```

用户空间组件加载上面显示的文件，并将其附加到 `finish_task_switch` 内核函数上。
BPF 对象的 `[]` 运算符允许访问程序中的每个 BPF_HASH，允许对内核中的值进行通行访问。可以像使用任何其他 python dict 对象一样使用该对象：读取、更新和删除操作都是允许的。

```python
from bcc import BPF
from time import sleep

b = BPF(src_file="task_switch.c")".```markdown
```Chinese
b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

# 生成多个调度事件
for i in range(0, 100): sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))
```

这些程序可以在文件 [examples/tracing/task_switch.c](https://github.com/iovisor/bcc/tree/master/examples/tracing/task_switch.c) 和 [examples/tracing/task_switch.py](https://github.com/iovisor/bcc/tree/master/examples/tracing/task_switch.py) 中找到。

### 第17课. 进一步研究

要进行进一步研究，请参阅 Sasha Goldshtein 的 [linux-tracing-workshop](https://github.com/goldshtn/linux-tracing-workshop)，其中包含了额外的实验。bcc/tools 中还有许多工具可供研究。

如果您希望为 bcc 贡献工具，请阅读 [CONTRIBUTING-SCRIPTS.md](https://github.com/iovisor/bcc/tree/master/CONTRIBUTING-SCRIPTS.md)。在主要的 [README.md](https://github.com/iovisor/bcc/tree/master/README.md) 的底部，您还会找到与我们联系的方法。祝您好运，祝您成功追踪！

## 网络

TODO
