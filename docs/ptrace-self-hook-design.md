# Android 自进程反向 ptrace Hook 设计

状态: 常驻 full-ptrace、路径策略、虚拟文件、受保护 FD、ptrace Level 1、proc status
Level-2 read view、nested ptrace phase-1 resident bridge、M4 capability probe 和正式 selective
常驻 dispatcher/TSYNC 安装事务均已实现，详见 [implementation-status.md](implementation-status.md)  
目标平台: Android arm64, 非 root；设计兼容 Linux 5.1.x，当前实测 Linux 6.1.99，保留 Linux 5.10.110 历史回归记录  
目标关系: tracer 子进程反向 attach 主 App 进程  
参考实现: PRoot 的 ptrace 事件模型、seccomp 加速、寄存器和路径翻译思想

> 本文把用户所说的“内核 5.1”解释为 Linux 5.1.x, 不是 Android 5.1。若实际是 Linux 5.10.x, 后续可重新评估 seccomp user notification、pidfd 和 openat2 后端。

## 1. 结论

这个方案在标准 AOSP 的普通 App 域中可行, 但必须把 attach 能力视为运行时能力, 不能仅凭内核版本或 Android 版本判定。

第一条实现主线确定为:

1. 主 App 内的 native library 创建 tracer 子进程。
2. 主进程主动设置 `PR_SET_DUMPABLE=1`, 并把 tracer PID 写入 `PR_SET_PTRACER`。
3. tracer 对主进程全部 TID 执行 `PTRACE_SEIZE + PTRACE_INTERRUPT`。
4. 先使用完全可回滚的 `PTRACE_SYSCALL` 验证观测和改参。
5. 稳定后由主进程使用 `SECCOMP_FILTER_FLAG_TSYNC` 安装 selective `SECCOMP_RET_TRACE` 过滤器。
6. tracer 在 `PTRACE_EVENT_SECCOMP` 处理 syscall 入口, 仅在需要结果或输出修补时切换到 `PTRACE_SYSCALL` 等待出口。
7. 路径重写字符串放入预分配共享 scratch arena, 再修改 arm64 syscall 参数寄存器。

预期可实现:

- 观测主 App 及其线程直接发出的 syscall, 包括绕过 libc 的 `svc #0`。
- 对选定路径 syscall 做参数级重定向。
- 修改指定 syscall 的参数、返回值或将其替换为无副作用 syscall。
- 跟踪新线程、fork/vfork 子进程和 exec 事件。
- 对 App 自身常见的 ptrace、dumpable 和 `/proc` 检查做有限虚拟化。

不能承诺:

- 完全隐藏内核中的 ptrace 关系和所有时序特征。
- 与 LLDB/gdbserver/另一个真实 ptracer 同时工作。
- 通过路径字符串替换实现完整 mount namespace、overlayfs 或无竞态安全沙箱。
- 绕过目标路径上的 Android DAC/SELinux 权限。重定向后的 syscall 仍以 App 自身凭据执行。
- 追溯 attach 之前已经发生的 syscall、已经打开的 FD 或已经建立的 mmap。

## 2. 可行性矩阵

| 条件 | 判断 | 设计处理 |
|---|---|---|
| Linux 5.1 `PTRACE_SEIZE` | 支持 | 主路径使用 `SEIZE`, `ATTACH` 只作兼容探针 |
| arm64 寄存器读写 | 支持 | `GETREGSET/SETREGSET + NT_PRSTATUS` |
| 修改 arm64 syscall number | 支持 | 使用 `NT_ARM_SYSTEM_CALL`, 不能只改 `x8` |
| `PTRACE_O_TRACESECCOMP` | 当前设备已验证 | 牺牲 tracee 连续取得两次真实 event 和 class data |
| seccomp `TSYNC` | 当前设备已验证 | 牺牲进程覆盖 leader + worker；正式 runtime 在 App stop-the-world 后覆盖全部已有线程 |
| `PTRACE_GET_SYSCALL_INFO` | 5.1 不支持，5.10 已验证 | 当前设备校验 SECCOMP/EXIT info；5.1 使用 regset 和每 TID 状态机 |
| seccomp user notification | 能力不足 | 5.1 缺少后来的 `CONTINUE` 和 `ADDFD`, 不作为路径重定向主线 |
| AOSP App SELinux | 通常允许 | AOSP 有 `allow untrusted_app_all self:process ptrace` |
| OEM SELinux/其他 LSM | 不确定 | 启动能力探针记录精确 errno 和环境信息 |
| Yama scope 0/无 Yama | 可行 | 同 UID + dumpable 即可 |
| Yama scope 1 | 有条件可行 | 主进程设置 `PR_SET_PTRACER(tracer_pid)` |
| Yama scope 2/3 | 普通 App 不可行 | 作为硬性 no-go 返回 |
| 已有 ptracer | 不可并存 | `TracerPid != 0` 时不启动正式 hook |
| raw fork 后长期运行 | 工程风险较高 | child 只能使用 raw syscall 和预分配内存 |
| 独立 PIE tracer | 推荐生产形态 | fork/posix_spawn 后立即 exec, 保持真实父子关系 |
| `android:process=":tracer"` | 最稳的 App 集成形态 | 同 UID, 但 Linux PPID 是 zygote, 不是严格子进程 |
| `isolatedProcess=true` | 不适用 | UID/SELinux 域不同 |
| app zygote | 不适用 | AOSP 对 `app_zygote` 有 ptrace neverallow |

历史参考设备为 Android 10/API 29、arm64、Linux 5.10.110；当前 USB 验收设备为 Android 15/API 35、
arm64、Linux 6.1.99、SELinux Enforcing。二者都不能替代 Linux 5.1 目标机验收。

2026-07-14 的 M4 capability probe 在该设备单轮 `PASS`：App 原有
`Seccomp=2`、`Seccomp_filters=1`，probe 前后 App 自身的 `NoNewPrivs`、seccomp mode
和 filter count 均不变。所有自定义 filter 只安装在 fork 出的牺牲进程。该 OEM 内核在
成功叠加 filter 后仍把牺牲 tracee、TSYNC leader 和 worker 的 `Seccomp_filters` 固定报告
为 1，因此安装成功以真实 TRACE event 和两个线程的命中行为为主要证据。

## 3. 与 PRoot 的关系

PRoot 的启动模型是:

```text
parent tracer
    fork
      -> child tracee: PTRACE_TRACEME -> SIGSTOP -> seccomp -> exec
```

本项目要求的是反向关系:

```text
main App tracee
    fork/spawn
      -> child tracer: wait GO -> PTRACE_SEIZE(parent all tids)
```

因此不能直接复用 PRoot 的启动代码。可借鉴的是 attach 成功后的设计:

- 每 TID 独立状态和 `waitpid(-1, ..., __WALL)` 事件循环。
- `TRACESYSGOOD` 区分 syscall stop。
- `TRACECLONE/FORK/VFORK/EXEC/EXIT` 管理进程树。
- `SECCOMP_RET_TRACE | data` 只通知需要处理的 syscall。
- arm64 `NT_PRSTATUS` 和 `NT_ARM_SYSTEM_CALL` 的寄存器处理。
- `process_vm_readv/writev` 优先、ptrace PEEK/POKE 后备的远程内存访问。
- guest path 规范化、dirfd/cwd 解析、binding 替换、输出反向翻译。

必须重写或简化的部分:

- 反向 attach 和 stop-the-world 握手。
- 对 attach 时已存在的 ART 线程、cwd 和 FD 做快照。
- 多线程进程安装 seccomp 时使用 `TSYNC`。
- fork 后 child 不使用 PRoot 的 talloc、stdio、普通 malloc、Android log 或 JNI。
- 不搬 PRoot 的 ELF loader、fake-id、完整 nested ptrace 和完整 rootfs 模型；当前 resident
  nested 只实现本设计第 15.3 节的受限 phase-1。
- PRoot 为 GPL-2.0-or-later。项目应 clean-room 实现; 若直接复制源码, 需要单独处理许可证策略。

关键本地参考:

- `proot-master/src/tracee/event.c`: 启动、wait 事件循环、seccomp/clone 事件。
- `proot-master/src/tracee/reg.c`: arm64 寄存器映射和 syscall number 写入。
- `proot-master/src/tracee/mem.c`: 远程内存和 tracee 栈 scratch。
- `proot-master/src/syscall/seccomp.c`: BPF syscall 选择和事件 data。
- `proot-master/src/syscall/enter.c`: 路径类 syscall 分派。
- `proot-master/src/path/path.c`: cwd/dirfd、规范化和正反向翻译。

## 4. 推荐总体架构

```text
┌──────────────────────────── Main App / tracee ────────────────────────────┐
│ :hookself AAR / libhookself.so                                            │
│                                                                          │
│ HookselfFramework -> Rule Registry -> HookselfRuntime                    │
│       │                                  │             ▲                  │
│       │                         shared mmap / memfd     │ facade event/log │
│       │                                  │             │ forwarding       │
│       ├──────────── control socket ──────┼─────────────┼─────────┐        │
│       │                                  │             │         │        │
│ BootstrapThread     seccomp TSYNC    Scratch Arena  Event Ring   │        │
│                                                                          │
│ :app demo/JNI/UI 是可选消费层，不属于 framework ABI                        │
└───────┼────────────────────┼───────────────────────────┼─────────┼────────┘
        │                    │                           │         │
        │ fork/spawn         │                           │ ptrace  │
        ▼                    ▼                           │         │
┌──────────────────────── Child tracer ──────────────────┴─────────┘
│ raw bootstrap -> attach manager -> wait/event loop                    │
│ arm64 regs -> remote memory -> syscall dispatcher -> path engine      │
│ fd/process/thread state -> proc/ptrace virtualization -> ring writer  │
└───────────────────────────────────────────────────────────────────────┘
```

职责边界:

- `:hookself` library 拥有 facade、runtime、tracer core 与 public headers，并通过
  AAR/Prefab 发布；`:app` 只提供 demo/JNI 和 instrumentation 宿主。
- `HookselfFramework` 管理规则 handle、整体启停和 runtime 转发；底层 `HookselfRuntime`
  仍保留为进阶 ABI。
- 主进程 bootstrap 只负责资源预建、创建 tracer、权限握手和安装 TSYNC filter。
- tracer 是唯一允许调用 ptrace、waitpid、修改寄存器和决定信号重投递的组件。
- Java/UI 只异步读取事件, 不参与 syscall 的同步决策。
- 路径/syscall 规则在 start 前编译成固定布局快照。full-ptrace 只允许 stop 后修改规则，
  下一次 start 重建 runtime；selective 首次成功 start 后冻结规则 registry。dynamic virtual
  snapshot publication 是独立的运行期能力。
- tracer 不能同步调用主进程 Binder 服务, 也不能获取主进程可能在停止时持有的锁。

## 5. Tracer 后端选择

### 5.1 `ForkRawBackend`, 第一版指定后端

优点:

- 严格满足“Linux 子进程 attach 父 App 进程”。
- 只依赖已注入的 `.so`, 不要求修改 Manifest。
- fork 前创建的共享匿名映射在父子中地址一致。

约束:

- ART App 已经是多线程进程。fork 后 child 只保留调用线程, 却继承其他线程持有的 libc、malloc、linker、JNI、日志锁。
- child 不得调用 JNI、Binder、`__android_log_*`、iostream、普通 allocator、动态加载或任何未知锁路径。
- 使用固定容量 POD 表、预分配 mmap、raw syscall、`ptrace`、`waitpid`、`getdents64`、`read/write`、`clock_gettime`。
- child 退出使用 `_exit`/raw exit_group, 永不返回 Java。

因此第一版 raw child 适合能力探针和最小事件循环。它能否作为长期生产后端, 由 24 小时稳定性测试决定。

### 5.2 `SpawnExecBackend`, 推荐的严格父子生产后端

主进程预先准备独立 arm64 PIE tracer, 使用 `posix_spawn` 或 fork 后立即 exec。tracer 通过继承的控制 FD 和 memfd 取得配置。

优点是 exec 后拥有干净的 bionic/allocator 状态, 同时保持 Linux PPID 为主 App。难点是 Android 对可执行文件的打包、提取、execute_no_trans 和目标 App 集成方式, 必须在目标 ROM 上验证。

### 5.3 `ServiceBackend`, 可修改 App 时的稳定后端

使用 `android:process=":tracer"` 的非 isolated Service。它由 zygote 正常创建, 生命周期和运行时最稳定。主进程收到 tracer PID 后仍执行 dumpable/PR_SET_PTRACER 握手。

它是“同 App 子进程”的 Android 语义, 但不是主进程 fork 出来的 Linux 子进程。核心 ptrace、seccomp、路径和伪装模块保持一致, 只替换 bootstrap transport。

## 6. 启动事务

启动必须分成可回滚阶段和不可回滚阶段。

### 6.1 主进程预备

在专用 native bootstrap 线程中完成, 不在 ELF constructor 或 linker 锁持有期间 fork:

1. 读取 PID/TID、UID/GID、ABI、kernel release、SELinux context。
2. 读取 `TracerPid`、`Threads`、`Seccomp`、`Seccomp_filters`、`NoNewPrivs`。
3. 保存 `PR_GET_DUMPABLE` 原值和 Yama `ptrace_scope`。
4. 创建双向 `SOCK_SEQPACKET` 或两根 pipe。
5. 创建共享 control page、event ring 和 scratch arena。
6. 把配置规则序列化成定长、只读快照。
7. 创建 tracer 子进程。
8. 父进程取得 child PID 后调用 `PR_SET_DUMPABLE=1`。
9. 调用 `PR_SET_PTRACER(child_pid)`; `EINVAL` 可表示内核无 Yama, 其他错误进入报告。
10. 父进程发送带 nonce、PID、start-time、主 bootstrap TID 和共享布局的 `GO`。

### 6.2 tracer 身份和生命周期验证

child 收到 GO 前不 attach:

1. 设置 `PR_SET_PDEATHSIG=SIGKILL`。
2. 设置后再次读取 PPID, 防止父进程已在竞争窗口退出。
3. 校验父 PID 的 `/proc/<pid>/stat` start-time 和随机 nonce, 防 PID 重用。
4. 关闭无关 FD, 禁止进入 JNI/ART。
5. 初始化固定容量 task/process/fd 表。

### 6.3 全线程 seize 屏障

1. 用 raw `getdents64` 枚举 `/proc/<pid>/task`。
2. 对每个 TID 调用 `PTRACE_SEIZE(tid, options)`。
3. options 从第一次 seize 就包含 `TRACESYSGOOD` 和 `TRACECLONE`。
4. 对全部成功 seize 的 TID 调用 `PTRACE_INTERRUPT`。
5. `waitpid(-1, ..., __WALL)` 收齐 `PTRACE_EVENT_STOP`。
6. 再次枚举 task, 补 attach 新 TID。
7. 连续两轮集合稳定且所有存活 TID 已停止, 才建立 stop-the-world 屏障。
8. `ESRCH` 只表示线程退出竞态; 任一仍存活 TID attach 失败则标记 partial, 禁止正式重定向。

初始 ptrace options:

```text
PTRACE_O_TRACESYSGOOD
PTRACE_O_TRACECLONE
PTRACE_O_TRACEFORK
PTRACE_O_TRACEVFORK
PTRACE_O_TRACEVFORKDONE
PTRACE_O_TRACEEXEC
PTRACE_O_TRACEEXIT
PTRACE_O_TRACESECCOMP
```

能力探针阶段不加 `PTRACE_O_EXITKILL`；正式 selective runtime 在 attach 时即启用
`TRACESECCOMP + EXITKILL`。

当前 M4 probe 使用 `PTRACE_TRACEME` 牺牲 tracee 验证这组 options，而不是给常驻
runtime 提前安装不可回滚 filter。tracee 叠加只选择 `gettid` 的 filter，连续两次命中均
取得 `PTRACE_EVENT_SECCOMP`；`PTRACE_GETEVENTMSG` 返回预期 class id，当前 5.10 设备的
`PTRACE_GET_SYSCALL_INFO` 同时返回匹配的 `SECCOMP` info。第一个 event 以
`PTRACE_CONT` 恢复，第二个以 `PTRACE_SYSCALL` 恢复并取得匹配的 EXIT stop/info；detach
以后再次命中返回 `-ENOSYS`。这同时验证了 CONT fast path、按需等待出口和 tracer 消失
三条内核语义。

### 6.4 attach 后快照

所有线程停止期间采集:

- 每个 TID 的 `NT_PRSTATUS` 和 ABI。
- `/proc/<tgid>/cwd`、`root`、`fd/*`。
- 每个 FD 的目标、CLOEXEC 和已知 guest/host path。
- 线程组、父子关系和已有 clone/fork 状态。
- `process_vm_readv/writev` 与 PEEK/POKE 能力。

已有 FD 不会被追溯重定向。快照只用于相对路径、cwd 和后续状态一致性。

### 6.5 正式 filter 提交

这是不可回滚边界:

1. parent 在 fork tracer 前编译排序去重的 filter plan，并把 hash/rule count/instruction
   count 写入 shared ABI v12。
2. tracer 停止全部 TID，复核 task 集合稳定，只以 `PTRACE_CONT` 恢复本次
   `hookself_start()` 调用 TID。
3. 调用 TID 从 status pipe 读到 `INSTALL_READY`，校验事务序列后设置
   `PR_SET_NO_NEW_PRIVS=1`。
4. 调用 TID 执行 `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)`；
   返回 0 才算全部线程安装成功，正 TID或负 errno 都是失败。
5. 调用 TID以 release store 发布结果，然后执行固定 arm64 `BRK #0x4853`；成功安装后
   到 BRK 之间没有握手 syscall。
6. tracer 验证 SIGTRAP、BRK 指令、plan hash、TSYNC 结果和最终 TID 集合，必要时推进
   PC，再发布 `COMMITTED + RUNNING_SELECTIVE`。
7. 成功后所有 task 以 `PTRACE_CONT` 恢复；失败且 NNP/filter 均未提交时可 detach，
   NNP 或 filter 已产生不可回滚副作用时 fail-closed。

绝不能在 fork/spawn tracer 之前安装 `RET_TRACE` filter, 否则 tracer 会继承过滤器而自己没有 tracer, 命中 syscall 将得到 `ENOSYS`。

## 7. 生命周期状态机

public runtime 状态:

```text
IDLE
  -> CONFIGURED
  -> STARTING
       -> RUNNING_FULL_PTRACE
       -> INSTALLING_FILTER -> RUNNING_SELECTIVE
  -> STOPPING -> STOPPED
  -> FATAL

STOPPED -> STARTING -> RUNNING_SELECTIVE
```

`PREPARING/CHILD_READY/ATTACHING/STOPPED_SNAPSHOT` 是启动事务内部阶段，不属于 public
runtime state。installer 首次 `PTRACE_CONT` 前可确定回滚；之后必须结合 owner response、
NNP 前值和 filter commit 位判断，任何不明确状态都 fail-closed。`RUNNING_SELECTIVE` 之后
不执行 detach；stop 会 quiesce 在途 mutation 后切到常驻 pass-through，start 可重新启用策略。

每 TID 状态:

| 状态 | 含义 | 合法恢复动作 |
|---|---|---|
| `DISCOVERED` | 已发现, 尚未 seize | `PTRACE_SEIZE` |
| `INTERRUPTING` | 已 seize, 等初始停止 | 等待 event stop |
| `STOPPED_BOOT` | 启动屏障内 | CONT/SYSCALL/DETACH |
| `RUNNING_CONT` | selective 正常运行 | 等 seccomp/signal/event |
| `RUNNING_SYSCALL` | 正在等待指定 syscall 出口 | 等 `SIGTRAP|0x80` |
| `SECCOMP_ENTRY` | syscall 入口事务 | 观测、改参、跳过或请求出口 |
| `SIGNAL_STOP` | 真实 signal-delivery stop | 精确 reinject 一次 |
| `GROUP_STOP` | SIGSTOP/TSTP/TTIN/TTOU | `PTRACE_LISTEN` |
| `FORK_EVENT` | 等 child initial stop 配对 | 建立 child state |
| `EXEC_REINIT` | 地址空间被替换 | 清事务并重建 ABI/scratch |
| `EXITING` | exit event/死亡 | 回收状态 |

每个 syscall transaction 保存:

```text
syscall_nr
original_regs
original_args[6]
entry_action
guest_path[2]
host_path[2]
scratch_frame
needs_exit
pending_signal
rule_generation
restart_state
```

当前实现使用 task table v8；每个 task 保存 `Unknown/Cont/Syscall` resume mode，active
syscall 记录 seccomp-origin、日志 bypass 和 nested dispatch operation。task 还保存 nested
tracee hold、held wait、exec 重建标志与 `PTRACE_GETEVENTMSG` 缓存。日志 bypass 用于在 App
侧同步 sink/Logcat 输出期间保持该 TID 的 entry/exit 相位，同时跳过策略和事件生成。

不能用一个全局 entry/exit toggle。信号、clone、seccomp event 和不同 TID 会交错。

## 8. wait/ptrace 事件循环

唯一事件线程执行:

```text
waitpid(-1, &status, __WALL)
  -> 找到或创建 TidState
  -> 分类完整 wait status, 包含高位 ptrace event
  -> 读取 siginfo/eventmsg/regs
  -> 执行 handler
  -> 写回 regs
  -> 选择 CONT/SYSCALL/LISTEN/DETACH 和 reinject signal
```

必须区分:

- `SIGTRAP|0x80`: `TRACESYSGOOD` syscall stop。
- `SIGTRAP|(PTRACE_EVENT_SECCOMP<<8)`: selective syscall 入口。
- `PTRACE_EVENT_STOP`: SEIZE/INTERRUPT 或 group-stop。
- `TRACECLONE/FORK/VFORK`: 新 task event。
- `TRACEEXEC`: 地址空间替换和 TID 迁移。
- `TRACEEXIT`: 退出前状态。
- 裸 `SIGTRAP`: App 自己的 trap 或其他真实 signal, 不能无条件吞掉。

signal 规则:

- 内部 INTERRUPT stop 不向 App 注入信号。
- 真实 signal-delivery stop 精确 reinject 一次。
- group-stop 使用 `PTRACE_LISTEN` 保留 job-control 语义。
- syscall restart 的 `ERESTART*` 状态不能提前释放 scratch。
- fatal signal 的 crash/tombstone 策略需要单独测试, 因为真实 ptracer 会阻止 crash_dump 再 attach。

## 9. arm64 寄存器层

固定映射:

| 用途 | arm64 寄存器 |
|---|---|
| syscall number | `x8` |
| 参数 1..6 | `x0..x5` |
| 返回值 | `x0` |
| stack pointer | `sp` |
| instruction pointer | `pc` |

GPR 结构使用兼容 POD:

```c
uint64_t regs[31];
uint64_t sp;
uint64_t pc;
uint64_t pstate;
```

操作规则:

- `PTRACE_GETREGSET + NT_PRSTATUS` 读 GPR。
- `PTRACE_SETREGSET + NT_PRSTATUS` 写参数、结果、SP、PC。
- syscall number 真正变化时额外使用 `PTRACE_SETREGSET + NT_ARM_SYSTEM_CALL`。
- x0 在入口是 arg1, 在出口是 result, 所以必须保存完整入口快照。
- 返回值按 Linux `[-4095, -1]` 解释 errno。
- Android tagged pointer 只在确认是数据地址时按运行时能力去 tag, 原始寄存器值仍保留。不能统一掩码 PC/PAC 值。

跳过 syscall 的首版策略:

1. 把 syscall number 替换为 BPF 明确放行、无内存副作用的 surrogate, 例如 `getpid`。
2. 使用 `PTRACE_SYSCALL` 等待 surrogate 出口。
3. 在出口把 x0 改成期望结果。

在目标内核验证 `NT_ARM_SYSTEM_CALL=-1` 的 skip 语义后, 才可增加更快路径。

## 10. 两种 syscall 模式

### 10.1 `FULL_PTRACE`

所有线程以 `PTRACE_SYSCALL` 运行, 通过 `SIGTRAP|0x80` 处理入口和出口。

用途:

- M0/M1 能力与正确性验证。
- seccomp 不可用时的兼容模式。
- 需要可 detach/fail-open 的开发模式。

代价是每个 syscall 都产生入口和出口 stop, Android Binder/futex 高频场景开销很大。

### 10.2 `SELECTIVE_SECCOMP`

BPF 默认 `ALLOW`, 只对关心的 syscall 返回:

```text
SECCOMP_RET_TRACE | class_id
```

tracer 通过 `PTRACE_GETEVENTMSG` 取得低 16 位 class, 快速路由:

- `OBSERVE_ENTRY`
- `PATH_ONE`
- `PATH_TWO`
- `NEEDS_EXIT`
- `FD_STATE`
- `PROC_SPOOF`
- `PTRACE_SPOOF`

入口处理完成后:

- 只需入口观测/改参: `PTRACE_CONT`。
- 需要返回值、输出 buffer、FD 或 syscall emulation: `PTRACE_SYSCALL`, 下一 syscall stop 按出口处理。

Linux 5.1 属于 4.8 之后的 seccomp/ptrace 顺序, 但仍应在牺牲 tracee 中确认厂商内核没有异常回移。

当前 5.10.110 设备已经通过上述牺牲 tracee 检查。另一个独立牺牲进程先创建 leader 与
worker，再用 `SECCOMP_FILTER_FLAG_TSYNC` 叠加只选择 `getppid` 的 filter；安装返回 0，
两个线程在没有 tracer 时均得到 `-ENOSYS`，证明 TSYNC 覆盖安装时已有的两个线程。
App 调用进程没有执行 `PR_SET_NO_NEW_PRIVS` 或安装 filter，probe 前后状态一致。

filter 只安装在主进程，tracer 必须在此之前创建。用户可以显式选择
`read/write/futex/ppoll/rt_sigprocmask/gettid` 等 syscall；框架不从 plan 中静默删除这些
规则。runtime API 使用 shared ABI v12 的 64 个并发 TID bypass 槽：63 个普通调用槽加
1 个 destroy 保留槽；同线程嵌套调用复用根槽。入口的专用 arm64 `gettid` claim stub 由
tracer 按 PC 识别。dispatcher 仍先执行 protected FD 完整性策略，再跳过 API owner 的
用户 mutation、路径策略和日志，因此 App 自己从其他调用点发起的同号 syscall 仍按规则处理。

published control 使用 pin + closing writer 协议保护 shared mapping。full stop/start 失败需要
回收 control 时，由 runtime 级 `CALL/DESTROY` retire owner 仲裁唯一执行者；retire owner 持有
publisher barrier，等待既有 pin 和 unpinned call 越过安全点，完成最外层 active-call 退场后
才释放 resident lease。首次 publication 同样阻止新 unpinned guard 并等待既有 guard 结束。
嵌套回调若需要首次 publication 直接返回 `HOOKSELF_E_BUSY`，不会等待外层自身。

## 11. 首批 seccomp syscall 集

当前 formal plan:

| 来源 | syscall 集 |
|---|---|
| public syscall rules | 配置中全部显式 syscall，包含 `PASS` 规则 |
| protected FD | `dup3`, `fcntl`, `ioctl`, `close`, `close_range` |
| path/virtual file | `openat`, `openat2`, `newfstatat`, `statx`, `faccessat`, `faccessat2`, `readlinkat`, `unlinkat`, `mkdirat`, `mknodat`, `utimensat`, `fchmodat`, `fchownat`, `renameat`, `renameat2`, `linkat`, `symlinkat` |
| ptrace/proc view | `ptrace`, `prctl`, `read`, `pread64`, `readv` |

条件性 syscall:

- `openat2` 从上游 Linux 5.6 出现。
- `faccessat2` 从 5.8 出现。
- `close_range` 从 5.9 出现。

路径功能启用时，`openat2/faccessat2` 的编号直接进入 BPF 超集；未实现该 syscall 的内核
不会执行它，比较指令本身无副作用。`close_range` 始终作为 protected FD 依赖进入 plan，
并分别探测 syscall 本身和纯 `CLOSE_RANGE_CLOEXEC` flag，不能从前者推断后者；能力结果由
internal shared ABI v12 记录，dispatcher 再决定具体行为。cwd 和进程树 syscall 只有在
用户显式配置时才进入 selective plan；clone/exec 生命周期主要由 ptrace event 跟踪。

## 12. 远程内存和 scratch

读取优先级:

1. `process_vm_readv`, 必须验证 exact byte count。
2. `PTRACE_PEEKDATA`, 正确处理末尾非 word 字节和 errno。
3. 路径按页读取, 遇 NUL 停止, 上限 `PATH_MAX`。

写入优先级:

1. 共享 scratch arena。
2. `process_vm_writev`。
3. `PTRACE_POKEDATA` read-modify-write。
4. tracee 栈临时 scratch, 仅作为 exec 后降级路径。

共享 arena 设计:

- raw fork 后端可使用 `MAP_SHARED|MAP_ANONYMOUS`, 父子地址一致。
- spawn/exec 或 Service 后端使用 memfd/ASharedMemory; 主进程和 tracer 映射地址可不同。
- tracer 写自己映射的 `slot + offset`, 但写入 tracee 寄存器的是主进程 base + offset。
- 固定每 TID 多个 frame, 支持双路径 syscall 和有限嵌套。
- frame 带 owner tid、generation、长度和 canary。
- ring/arena 满时路径操作采用明确策略: 默认透传并记录错误, 不阻塞 tracer。

不原地覆盖 App 原始字符串, 即使新字符串更短也不这样做, 避免只读页、并发共享和调用者后续观察问题。

exec 成功后旧 scratch mapping 消失, 但 seccomp filter 仍保留。必须进入 `EXEC_REINIT`, 使用栈 scratch 或远程重建映射, 否则不能恢复该进程。

## 13. 路径重定向模型

首版只实现确定性的 prefix binding:

```text
guest_prefix -> host_prefix
```

规则字段:

```text
guest prefix
host prefix
read/write/execute permissions
passthrough/redirect/deny action
follow-final policy
priority and generation
```

匹配要求:

- 最长前缀优先。
- 必须按路径组件边界匹配, `/a/b` 不能匹配 `/a/bad`。
- 保留根路径、尾斜杠、空路径和 `AT_EMPTY_PATH` 语义。
- 配置时拒绝含 NUL、超长或互相递归的映射。

入口处理流水线:

```text
读取原始 pathname
  -> 判断 absolute / AT_FDCWD / dirfd
  -> 取得 guest base cwd 或 fd path
  -> lexical normalize
  -> 按 syscall 语义解析 symlink
  -> 最长 binding 替换
  -> 写 scratch
  -> 修改对应 arg register
```

不能简单调用 tracer 自己的 `realpath()`:

- 创建目标的最终组件可能还不存在。
- `O_NOFOLLOW` 和 `AT_SYMLINK_NOFOLLOW` 的最终组件不能被提前跟随。
- guest 绝对 symlink 应从 guest root 重新解析。
- `rename/link/symlink` 的两个参数语义不同。

建议实现三种 resolver 操作:

- `RESOLVE_EXISTING_FOLLOW_FINAL`
- `RESOLVE_EXISTING_NOFOLLOW_FINAL`
- `RESOLVE_PARENT_KEEP_LEAF`

symlink 最大跟随 40 次, 循环返回 `ELOOP`。路径读取失败时尽量保留内核原始 `EFAULT/ENAMETOOLONG` 行为, 不制造不同错误码。

### 13.1 syscall 参数语义

| syscall | dirfd | path 参数 | 关键语义 |
|---|---|---|---|
| `openat` | x0 | x1 | O_NOFOLLOW/O_CREAT/O_EXCL 决定 final 处理 |
| `newfstatat/statx` | x0 | x1 | AT_SYMLINK_NOFOLLOW/AT_EMPTY_PATH |
| `faccessat` | x0 | x1 | Linux 5.1 flags 能力有限 |
| `readlinkat` | x0 | x1 | 输入不跟随 final, 输出需反翻译 |
| `unlinkat` | x0 | x1 | 保留 final, AT_REMOVEDIR |
| `mkdirat` | x0 | x1 | 只解析 parent |
| `renameat2` | x0/x2 | x1/x3 | old/new 分别处理, new 通常保留 leaf |
| `linkat` | x0/x2 | x1/x3 | old 受 AT_SYMLINK_FOLLOW, new 保留 leaf |
| `symlinkat` | x1 | x2 | x0 是 symlink 内容, 不能一律翻译 |
| `chdir` | 无 | x0 | 成功出口更新 guest cwd |
| `fchdir` | x0 | 无 | 成功出口从 fd 状态更新 cwd |
| `getcwd` | 无 | 输出 x0 | 出口把 host cwd 反翻译为 guest cwd |

`openat2` 若存在且带 `RESOLVE_BENEATH/IN_ROOT`, 将 path 改成绝对 host path 会改变语义。首版对这些 flags 透传并报告 unsupported; 完整实现需要为映射根预开 O_PATH dirfd, 同时重写 dirfd 和相对 path。

### 13.2 FD 和进程状态

每个线程属于一个 `ProcessState`。进程状态包含:

- guest cwd/root。
- FD table。
- binding generation。
- scratch mapping。
- seccomp/ABI 状态。

clone 时根据 `CLONE_FS`, `CLONE_FILES`, `CLONE_VM`, `CLONE_THREAD` 共享或复制对应状态。fork 复制, exec 清除 CLOEXEC FD 并重建地址空间状态。

dirfd 初期可读取 `/proc/<tgid>/fd/<fd>` 并反向映射。完整 FD table 还要处理:

- open/openat 成功返回值。
- close、dup/dup3、fcntl duplication。
- fork/exec 和 CLOEXEC。
- SCM_RIGHTS/Binder 获得的未知 FD。
- FD number 重用。

目录内容合并、whiteout、跨 binding rename 和完整 overlay 语义不属于首版。

### 13.3 protected FD 与 `close_range`

当前实现采用不改变 FD number 的安全切片：

- `close_range` syscall 不存在时不做框架级结果替换，调用继续进入内核并得到
  `-ENOSYS`。
- syscall 存在且范围不与 protected FD 相交时，调用透传内核。
- 范围相交且 flags 恰为 `CLOSE_RANGE_CLOEXEC` 时仍透传内核；它只设置 CLOEXEC，
  不立即关闭或重排 FD。单独的能力位说明内核是否接受该 flag，具体成功或错误结果
  仍由内核产生。
- 范围相交且 flags 为 0，或包含 `CLOSE_RANGE_UNSHARE` 时返回 `-EBUSY`，避免关闭
  protected backing FD，或让调用线程切换到框架尚未跟踪的独立 FD table。
- 初次 protected-FD 检查使用原始 syscall number/参数。用户 syscall rule 完成 number 或
  argument mutation 后，再从生效寄存器读取 syscall number/参数并执行一次 protected-FD
  检查；因此 `REPLACE_NUMBER`/`REPLACE_ARGUMENT` 不能把原本无关的调用改成针对 protected
  FD 的 `close`、`dup3`、`fcntl/ioctl` 或 `close_range`。syscall-info 和 Linux 5.1 regset
  fallback 共享该顺序。

完整实现需要把非 protected 子区间分段 replay，并为 `CLOSE_RANGE_UNSHARE` 建立新的
per-files table 状态；这两项仍属于后续里程碑。

### 13.4 selective destroy freeze

selective filter 已提交后不能卸载，destroy 也不能先关闭 shared/protected FD 再让其他线程
继续运行。当前 teardown 协议为：

1. `hookself_destroy()` 先取得 pass-through ack，确认用户 policy 已停用且全部任务已恢复。
2. destroy owner 屏蔽当前线程可屏蔽信号，发布 `kTeardownFreeze(owner_tid)`；tracer 再次
   quiesce 全任务、核验 task coverage，只以 `PTRACE_CONT` 恢复 owner，并发布 frozen ack。
3. owner 每次只发布一个 `teardown_bypass_tid + teardown_bypass_fd + active` capability，执行
   对应 raw `close`；成功后在其他任务仍冻结时立即从 protected registry 删除该 FD。
4. provider backing、source、controller 与 shared FD 全部关闭且 registry count 为 0 后，owner
   发布 release。tracer 验证 capability 已清空，恢复其余任务，再清除 frozen/release。
5. parent 清除 teardown owner、解映射 shared session、删除 runtime；任一 coverage、close、
   release 或状态校验失败都 fail-closed，不暴露部分释放的控制面。

冻结其他 TID 和逐 FD 删除共同关闭了 FD number reuse 窗口；仅做 owner-TID-wide bypass 或在
最后一次性清 registry 都不足以保证并发 open/close 的完整性。

## 14. syscall 观测

固定尺寸事件建议包含:

```text
sequence
monotonic timestamp
tgid / tid
syscall number and class
entry / exit
original args[6]
result / errno
action: pass, observe, redirect, deny, emulate
guest path[2] / host path[2]
rule id / generation
internal error flags
```

规则:

- tracer 写共享 lock-free SPSC ring，App 侧 reader mutex 串行化显式消费者。
- ring 满时 drop 并增加计数, 绝不阻塞 tracee。
- 字符串使用固定上限或单独 blob ring, 禁止 child malloc。
- 日志级别在共享 control page 发布。public ABI v6 提供 `hookself_syscall_name()`、
  `hookself_event_log_level()`、`hookself_format_event()`、`hookself_set_log_sink()` 和
  `hookself_drain_logs()`。
- `hookself_drain_logs()` 明确消费 event ring：自定义 sink 或默认 Logcat sink 都只在
  调用它的 App 线程执行。框架不启动隐藏 reader，也不在 fork 后 tracer 调用日志库。
  整次 drain 持有 parent reader mutex，sink 回调中的 `HookselfEvent*` 和格式化文本指针
  仅在该次同步回调期间有效。
- 每个 runtime 强制单一消费模式：首次有效 `hookself_read_events()` 选择 `RAW_EVENTS`，
  首次启用日志的 `hookself_drain_logs()` 选择 `LOG_DRAIN`。RAW 模式下 drain 返回
  `HOOKSELF_E_INVALID_STATE`；LOG 模式下 raw read 返回 0，事件流不会被两个 API 分割。
- `hookself_set_log_sink()` 与 drain 使用同一 reader mutex。sink 回调内重入 set/drain
  返回 `HOOKSELF_E_BUSY`；只有替换 sink 返回 `HOOKSELF_OK` 后，调用方才能释放旧
  `user_data`。传入 null sink 会恢复默认 Logcat sink 并清除已保存的 `user_data`。
- internal shared ABI v12 在 drain 期间发布当前 App TID 为日志 bypass owner，task table
  v6 在 active syscall 上保存 bypass 标志。sink 回调或 Logcat 触发的 syscall 仍更新
  entry/exit 相位；protected FD 和内部 FD claim/complete 属于不可跳过的完整性协议，
  其后才跳过用户规则、ptrace/proc view、路径重定向和 event ring 写入，阻止 TRACE 日志
  形成反馈循环。
- parent 维护 runtime 注册表、active-call 计数和 closing 状态。destroy 在 registry->runtime
  固定锁序下先摘表，外部 destroy 等待 active-call 归零；sink 回调内 destroy 由最外层
  call guard 延迟到 drain 清理结束后执行，避免 callback/drain 与 unmap/delete 竞态。facade
  重入 destroy 通过 hidden abort bridge 让 raw drain 在当前 callback 后终止，再等待 facade
  runtime lease 退出，不提前释放 raw runtime。
- public API 依赖锁、条件变量与 allocator，不是 async-signal-safe API，signal handler 只应
  通知普通 App 线程。sink 回调内 set/drain 返回 `HOOKSELF_E_BUSY`；需要首次发布 bypass
  control 的嵌套 start 也返回 `HOOKSELF_E_BUSY`。deferred destroy 保持 unpinned publication
  barrier 直到 Finalize 完成，避免下一代 tracer 接管旧 runtime 的 close/unmap/delete。
- formatter 的完整长度与有限缓冲输出分离；路径转义超过日志容量时输出明确的 truncation
  key，不在 `\\xNN` 或 quoted value 中间硬截断。
- full-ptrace 可观察全部 syscall; selective 模式只保证 BPF 选择集合。
- vDSO 调用不会进入 syscall, 不在观测范围内。

## 15. ptrace 和 `/proc` 伪装

这里的“伪装”定义为让主 App 自己的常见检查得到一致的虚拟结果, 不是让内核关系真正消失。

### 15.1 Level 1, 首版

当前实现契约：

- Level 1 基础视图仅作用于根 App TGID；fork/vfork 后代继续使用真实内核语义。第 15.3 节的
  root App 直接子进程 leader `TRACEME -> exec` phase-1 是唯一 resident 例外，不构成
  per-TGID 的通用后代视图。
- 对未进入第 15.3 节 phase-1 的 task，每个 TID 第一次 `ptrace(PTRACE_TRACEME)` 返回 0，
  同 TID 后续调用返回 `-EPERM`；Level 1 本身不创建通用 nested tracer、wait 或 signal 关系。
- 使用 syscall number `-1` 压制真实调用，在 syscall-exit 写入逻辑结果；stop 时这些
  mutation 必须先推进到 exit，不能回滚后执行原始 TRACEME。
- `PR_GET_DUMPABLE` 返回根 TGID 共享的逻辑值；`PR_SET_DUMPABLE` 只接受完整
  64 位参数 0/1，运行期真实值保持 tracer attach 所需状态。
- `PR_SET_PTRACER` 接受 0、全宽 `PR_SET_PTRACER_ANY` 和存在的正 PID；正 PID
  保存 starttime，最终提交时复核 PID 身份。
- 两阶段 stop commit 先只释放 API 调用 TID；它应用最终逻辑 dumpable/ptracer 后，
  tracer 才释放其余 TID。
- 配置的 `PROC_STATUS` virtual provider 将唯一 `TracerPid:` 改为 0；它提供 sealed
  snapshot，适合要求严格一致性或任意碎片读取的调用方。已打开真实 proc status FD
  的输出级修补属于 Level 2。
- 内建策略先于用户 syscall rule，并使用保留 rule ID 与
  `HOOKSELF_EVENT_F_PTRACE_VIEW` 发出成对 ENTRY/EXIT 事件。

### 15.2 Level 2（proc status read view 已实现）

- 对根 App TGID 的真实 `/proc/<pid-or-tid>/status` FD，在 `read`、`pread64`、
  `readv` 出口聚合本次返回数据；只有数据内包含完整 `TracerPid:` 行时才把数字
  等宽写成零，并在写回后重新读取验证。
- 通过 `/proc/<reader-tid>/fd/<fd>` 在 syscall-entry 识别 FD，并校验 status 内容的
  `Tgid` 属于根 App；非 proc FD 不进入该视图。
- 输出修补事件使用 public ABI v6 的 `HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW`、
  `HOOKSELF_EVENT_F_PROC_STATUS_VIEW` 和 `HookselfStats.proc_status_patches`；tracer
  共享控制页版本为 internal shared ABI v12。
- 任意碎片读取或严格一致性使用 sealed `PROC_STATUS` virtual provider；真实 FD
  read view 不推算跨 syscall 的绝对 `TracerPid` offset。
- 当前单次返回聚合上限为 4096 字节。等宽零可能表现为 `00000`，不是 proc 原生的
  单字符 `0`。
- 内核写入真实 buffer 到 syscall-exit patch 之间存在跨线程观察窗口；`readv` 在出口
  一次性取得 iovec 描述符快照，后续聚合、回写和验证复用该快照，但取得快照时仍可能
  与用户线程并发修改 iovec 发生竞态。
- 后续补齐 status/maps/smaps 的持久 FD 身份跟踪。
- 后续修补 `/proc` getdents64 结果中的 tracer PID。
- 后续对 `kill(tracerPid, 0)`、`tgkill` 等存在性探测保持一致。
- 后续对 `PR_GET_NO_NEW_PRIVS` 和必要的 seccomp 状态查询维护逻辑视图。

### 15.3 Level 3 nested ptrace phase-1（resident 已接入，范围受限）

`HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE` 的 resident 路径只实现根 App 与其**直接创建的
子进程 leader** 之间的 `TRACEME -> exec` 链路。它在 full-ptrace、
`ENABLE_PTRACE_VIEW + TRACE_DESCENDANTS + FAIL_CLOSED` 下运行；配置 selective seccomp 时
在校验阶段拒绝，不做降级。

#### 15.3.1 支持的调用顺序

1. 根 App 的一个 task 创建直接子进程；只有该子进程的 leader（`tid == tgid`）是 phase-1
   候选。非 leader、孙代或其他后代不进入该路径。
2. 候选 leader 调用 `PTRACE_TRACEME`。resident dispatcher 压制真实 syscall，并建立仅限这个
   直接父子关系的逻辑 relation。
3. 子进程第一次 `exec` 时，outer tracer 为框架自身处理得到物理 exec stop；对逻辑父进程，
   resident bridge 将其映射为普通 `SIGTRAP` signal-delivery stop。`wait4` 或 `waitid` 消费该
   stop；尚无事件时 `waitid(..., WNOHANG)` 保持无事件语义。匹配的物理 tracee stop 与阻塞
   wait 的 surrogate syscall-exit 均保持，直到逻辑动作完成。
4. 父进程只能在该 hold 上调用 `PTRACE_SETOPTIONS(0)` 或
   `PTRACE_SETOPTIONS(PTRACE_O_TRACEEXEC)`，然后使用 `PTRACE_CONT`。其他 option 位没有
   resident 支持。
5. 选择 `PTRACE_O_TRACEEXEC` 后，子进程后续 `exec` 以 `PTRACE_EVENT_EXEC` 形式交给
   `wait4`/`waitid`；`PTRACE_GETEVENTMSG` 读取该 stop 对应的缓存 message。未选择
   `TRACEEXEC` 时，后续 exec 继续映射为 `SIGTRAP` stop。
6. 父进程在 held stop 上调用 `PTRACE_CONT` 或 `PTRACE_DETACH`。前者恢复 child；后者仅删除
   逻辑 relation 并恢复 child，framework 自己仍保留真实 ptrace 关系。child 随后的退出由真实
   父进程的 wait ownership 回收。

bridge 在 syscall entry 用 harmless surrogate 取得 exit stop，在 exit 写回逻辑结果；physical
tracee hold 与 held wait 使用 task-table 的独立标志和 generation 校验。stop/destroy 时，held wait
以 `-EINTR` 结束、held tracee 被恢复，避免把逻辑 hold 留在已解除的 resident session 中。

#### 15.3.2 能力报告与边界

public capability version 2 将 `runtime_features` 和 `engine_features` 分开报告。phase-1 在
`runtime_features` 中只增加 `HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC`；这不表示完整
logical engine 已成为 resident。`DESCENDANT_TGID_STATE`、`ATTACH_SEIZE`、`RESUME_CONTROL`、
`WAIT_EMULATION`、`SIGNAL_STATE`、`MEMORY_ACCESS`、`REGSET` 和 `SYSCALL_INFO` 即使存在于
`engine_features`，调用方也不能将其视为 resident nested 契约。

本阶段不支持 `PTRACE_ATTACH`、`PTRACE_SEIZE`、`PTRACE_INTERRUPT`、`PTRACE_SYSCALL`、
`PTRACE_SINGLESTEP`、`PTRACE_LISTEN`、通用 signal/siginfo、PEEK/POKE、GET/SETREGSET、
`GET_SYSCALL_INFO`，也不支持 `TRACEFORK`、`TRACEVFORK`、`TRACEEXIT` 等其他
`PTRACE_SETOPTIONS` event 位。完整后代 TGID 视图、通用 nested wait/relation 状态机及其 backend
操作仍是后续工作。

USB `3B241FDJH000S4`（Android 15、Linux 6.1.99、SELinux Enforcing）已完成专用
`nestedPtraceResidentOnly` instrumentation 连续 `3/3`：每轮 39 项检查均通过，覆盖
`wait4` held wait/first `SIGTRAP`、`SETOPTIONS(TRACEEXEC)`、第二次 exec 的
`GETEVENTMSG + CONT`，以及 `waitid(WNOHANG)`、`DETACH`、exit/reap 与 runtime teardown。
Linux 5.1 设备结果仍待补充。

已知限制:

- 一个线程只能有一个真实 ptracer。
- 外部 LLDB、gdbserver 和 crash_dump 无法同时 attach。
- tracer PID、调度延迟、stop 行为和某些 proc/cgroup 视图仍可能暴露。
- 完全透明伪装在非 root 用户态方案中不成立。

## 16. seccomp 后的故障策略

自定义 seccomp filter 不可卸载。没有 tracer 时, `SECCOMP_RET_TRACE` 命中的 syscall 会得到 `ENOSYS`。因此:

该返回行为已由 M4 probe 的 ptrace detach 后 `gettid`，以及无 tracer TSYNC leader/worker
的 `getppid` 在当前设备实测为 `-ENOSYS`。正式 runtime 因此始终保留 tracer：active 模式
执行完整策略，stop 后的常驻模式保留 class/nr 校验与 internal/protected FD 完整性协议，
其余用户策略快速透传；destroy 在 owner-only freeze 中逐项清空 protected registry，随后
最小 pass-through tracer 继续存活到进程退出。

- installer 首次恢复前，或 owner 已明确回复且证明本次未改变 NNP、filter 未提交：detach
  全部 TID，恢复信号和 dumpable。
- NNP 从 0 成功变为 1 后，即使后续 TSYNC/filter 安装失败，也属于不可回滚状态并
  fail-closed；缺少 owner response、意外 stop 或 commit 位不一致同样 fail-closed。
- filter 安装后: 不提供普通 disable/detach API, 只能把规则切为快速透传。
- tracer 崩溃后不能从已过滤主进程可靠 fork 一个新 tracer, 因为新 child 也继承 filter。

正式模式提供两种明确选择:

1. `FAIL_CLOSED`, 推荐: 正式提交前启用 `PTRACE_O_EXITKILL`; tracer 异常时 App 被终止, 由 Android 正常重启。
2. `FULL_PTRACE_FAIL_OPEN`: 永不安装自定义 seccomp, 性能较差; tracer 死亡时内核解除 ptrace 后 App 更可能继续运行。

所谓热备 tracer 需要在 filter 安装前由未过滤环境创建并设计 ptrace 所有权交接, 实现和竞态成本高, 不进入前五个里程碑。

内部发现以下状态时, selective 模式应终止并重启 tracee, 不能盲目 detach:

- 寄存器写回失败。
- syscall entry/exit 状态不一致。
- 存活 TID 脱离跟踪。
- scratch transaction 无法恢复。
- clone/exec 事件丢失或 task 表溢出。

## 17. 当前代码布局

```text
hookself/                         Android Library / AAR
  build.gradle
  src/main/cpp/
    CMakeLists.txt
    hookself.exports.map
    hookself/
      include/hookself/
        framework.h               统一 facade ABI
        public_api.h              底层 runtime ABI
      framework.cpp               facade 编排单元
      api/
        config_api.cpp
        framework/                registry/lifecycle/rules/forwarding 片段
        runtime/                  runtime API 职责片段
      runtime_api.cpp             runtime API 编排单元
      logging.cpp
      arch/                       arm64 register 适配
      platform/                   raw syscall、procfs、bootstrap assembly
      tracer/                     task/wait/path/remote-syscall 状态
        path_state.cpp            path state 编排单元
        path_state/               storage/task-fd/mount 职责片段
      internal/                   resident、shared ABI、event、virtual file
        resident_session.cpp      resident 编排单元
        resident_session/         lifecycle/dispatch/path/selective 等片段
    test_support/                 Debug-only probe/JNI 支持

app/                              demo / instrumentation 宿主
  src/main/cpp/
    CMakeLists.txt                通过 Prefab 查找 hookself::hookself
    demo/
    jni/
```

library CMake 将无 public export 的 tracer 实现编译为 `hookself_tracer_core` static target，再链接
到 `libhookself.so`。release 使用 hidden visibility 与 version script 收敛动态导出；
`HOOKSELF_BUILD_TEST_SUPPORT` 只在 Debug 构建加入 self-test、probe 和测试 JNI。

child 路径不使用 STL。可以用 C++ 编译, 但核心结构必须是固定容量 POD, 错误以整数和固定
buffer 传回。

推荐的 facade API：

```c
void hookself_framework_default_config(HookselfConfig *config);
void hookself_framework_default_redirect_options(
        HookselfRedirectOptions *options);
int32_t hookself_framework_create(
        const HookselfConfig *config, HookselfFramework **framework);

int32_t hookself_framework_register_syscall_rule(
        HookselfFramework *framework, const HookselfSyscallRule *rule,
        int32_t enabled, HookselfRuleHandle *handle);
int32_t hookself_framework_register_path_rule(
        HookselfFramework *framework, const HookselfPathRule *rule,
        int32_t enabled, HookselfRuleHandle *handle);
int32_t hookself_framework_register_redirect(
        HookselfFramework *framework, const char *guest_prefix,
        const char *host_prefix, const HookselfRedirectOptions *options,
        int32_t enabled, HookselfRuleHandle *handle);
int32_t hookself_framework_find_rule(
        const HookselfFramework *framework, HookselfRuleKind kind,
        uint32_t rule_id, HookselfRuleHandle *handle);
int32_t hookself_framework_set_rule_enabled(
        HookselfFramework *framework, HookselfRuleHandle handle,
        int32_t enabled);
int32_t hookself_framework_is_rule_enabled(
        const HookselfFramework *framework, HookselfRuleHandle handle,
        int32_t *enabled);
int32_t hookself_framework_unregister_rule(
        HookselfFramework *framework, HookselfRuleHandle handle);

int32_t hookself_framework_start(HookselfFramework *framework);
int32_t hookself_framework_stop(HookselfFramework *framework);
void hookself_framework_destroy(HookselfFramework *framework);
```

facade 同时转发 state/stats、event read、log sink/drain 和 virtual-file publish/refresh。
`public_api.h` 继续提供 `hookself_create(config, &runtime)`、`hookself_start(runtime)`、
`hookself_stop(runtime)` 与 `hookself_destroy(runtime)`，供需要直接拥有静态 runtime 的调用方使用。

raw/facade stop 在 full-ptrace 模式完成 detach；在 selective 模式完成 quiesce 后进入
pass-through tracer，后续 start 可重新启用策略。selective destroy 不卸载 filter，也不释放
进程级 resident lease。full-ptrace stop 则在最外层 call 退出时通过 retire-owner 仲裁和
publisher barrier 回收 control/lease，使另一 full runtime 可在旧调用完全退场后启动。facade
在 full-ptrace stop 后接受规则 mutation，并丢弃 stopped runtime 以便下一次 start 重建；
selective 首次成功 start 后冻结规则 registry。

## 18. 分阶段实现与验收

### M0: 反向 attach 能力探针

实现:

- fork raw tracer child。
- dumpable/PR_SET_PTRACER/GO 握手。
- seize/interrupt 主线程和所有 TID。
- GETREGSET、已知共享内存读写、完整 detach。
- 生成结构化报告, 不安装 seccomp。

验收:

- 1000 次启动/attach/detach 无冻结。
- 报告包含每一步 errno、SELinux context、Yama、TracerPid、dumpable、seccomp 状态。
- 任一 TID partial attach 不判 PASS。
- detach 后 UI、Binder、线程创建和前后台切换正常。

### M1: 全量只读 syscall 观测

实现:

- `PTRACE_SYSCALL + TRACESYSGOOD`。
- 每 TID entry/exit 状态。
- 观测 raw `getpid/gettid/openat`。
- clone 和 signal 最小处理。

验收:

- syscall number、参数、返回值与测试程序一致。
- 64 线程 clone storm 无遗漏。
- SIGSTOP/CONT、EINTR、应用 SIGTRAP 不被错误吞掉。
- 可以无损停止并 detach。

### M2: 单规则路径重定向, 仍用 full ptrace

实现:

- shared scratch arena。
- 最长前缀规则。
- `openat` 绝对路径与 AT_FDCWD 相对路径。
- open 成功/失败出口观测。

验收:

- 使用 libc open 和直接 `svc #0` 都重定向。
- 新路径比原路径长、原字符串只读、并发访问均正确。
- PASS/REDIRECT/DENY 行为和 errno 稳定。

### M3: 路径语义和进程状态

实现:

- newfstatat/statx/faccessat/readlinkat。
- mkdirat/unlinkat/renameat2/linkat/symlinkat。
- cwd、dirfd、FD table、双路径和 symlink resolver。
- getcwd/readlink 输出反翻译。

验收:

- 覆盖 `ENOENT`, `EFAULT`, `ENAMETOOLONG`, `ELOOP`, `AT_EMPTY_PATH`。
- 创建目标不提前解析 leaf。
- O_NOFOLLOW/AT_SYMLINK_NOFOLLOW 语义不变。
- 并发 rename、FD 重用和 syscall restart 不破坏 transaction。

### M4: selective seccomp 加速（capability 与正式 runtime 已实现）

已实现的 capability probe:

- 可复用 arm64 cBPF builder：arch 检查、最多 192 条 syscall/class-id 规则、默认
  `ALLOW`、匹配项 `RET_TRACE | class_id`，以及 raw seccomp installer/TSYNC 失败 TID
  处理。
- 在 ptrace 牺牲 tracee 上验证两次 TRACESECCOMP event、`GETEVENTMSG` class data、
  `PTRACE_GET_SYSCALL_INFO_SECCOMP/EXIT` 和 Linux 5.1 regset fallback。
- 第一次 event 用 `PTRACE_CONT`，第二次用 `PTRACE_SYSCALL` 等待出口；detach 后命中
  filter 得到 `-ENOSYS`。
- 在独立双线程牺牲进程中验证 TSYNC 同时覆盖 leader/worker，两个线程无 tracer 命中
  均得到 `-ENOSYS`。
- probe 前后核对 App 自身 NNP/seccomp/filter 状态；App 不承担不可回滚副作用。
- TSYNC worker 使用 arm64 raw clone trampoline、全 signal mask 和双 guard-page stack；
  安装前两个线程都验证真实 `getppid` baseline。强制 fallback 子例在支持 syscall-info 的
  5.10 设备上也实际执行 arm64 regset 入口/出口路径。
- 三层牺牲进程均验证 `PDEATHSIG=SIGKILL`；tracee 用 starttime + 原子 PID + start gate
  发布身份。supervisor-hang/TSYNC-hang 故障注入验证有界 kill/reap 和 shared mapping
  生命周期，不把不可回滚状态留在 App。

正式 selective runtime 已实现:

- builder 已接入 stop-the-world + bootstrap TID + BRK 提交事务。
- syscall policy/path/provider/ptrace view 编译为稳定 plan/hash；dispatcher 对 class 和 nr
  二次校验，entry-only 使用 `CONT`，需要完成事务时只等待一次 exit。
- task table v8 保存 per-TID resume mode；clone/fork/vfork/exec/exit 路径继承 selective
  状态，signal/group-stop 保持原 resume mode。
- 正式模式固定 `FAIL_CLOSED + PTRACE_O_EXITKILL`；stop/start 使用常驻 pass-through/active
  切换，不执行危险 detach。
- shared ABI v12 提供 63 个普通 runtime API bypass 槽和 1 个 destroy 保留槽；63+1 stress
  在普通槽全部占用时验证 destroy 仍能登记、等待 active call、完成 freeze 和删除 runtime。
- selective destroy 已实现 pass-through -> owner-only teardown freeze -> exact FD close/remove ->
  release/resume -> unmap；dispatcher 在用户 mutation 后按生效 syscall/参数二次执行 protected
  FD 检查。

验收:

- 当前 5.10.110 真机 capability 加固版 fresh-data、20 轮和 100 轮均通过；正式 runtime
  也完成 fresh、`20/20` 和 `100/100`；最新版 fresh 为 1.871 秒，最新 100 轮为 3.013 秒。正式
  100 轮包含 101 次 active start/stop，gettid/getpid/getppid ENTRY/EXIT 分别为
  `101/101`、`101/0`、`101/101`，`events_read/emitted` `708/708`、observed 303、
  `tracked_tasks` 27，control/pass-through/unexpected `0/0/0`，dropped/internal/fatal `0/0/0`。
- 最新 post-destroy 验收使用 2.5 秒全局 deadline 重扫 `/proc/self/task`，容忍扫描期间退出的
  瞬态 TID；全部存活 task 必须具有同一个正值 resident `TracerPid` 且状态非 `T/t/Z`，连续
  两轮全局稳定后才通过。
- 同版 full-ptrace/M4 综合回归最新 fresh 为 4.47 秒、`20/20` 为 39.531 秒；历史
  `100/100` 为 186.319 秒，`singleton_pass=1`。
- 与 M1/M3 结果一致。
- TSYNC 失败时没有部分 hook 状态。
- kill tracer 后行为严格符合故障策略。
- 对比 full ptrace 的吞吐、P50/P95/P99 延迟和功耗。

### M5: 完整线程树和 exec

实现:

- clone/fork/vfork 状态共享或复制。
- seccomp 继承后的全部后代跟踪。
- exec TID 迁移、ABI 重识别、CLOEXEC 和 scratch 重建。

验收:

- fork 后规则一致。
- vfork 不死锁。
- exec 成功/失败均不遗留旧 transaction。
- 子进程不因无人跟踪的 RET_TRACE 获得 ENOSYS。

### M6: ptrace Level 1 与 proc status Level-2 read view（已实现）

实现:

- PTRACE_TRACEME 返回虚拟化。
- dumpable 逻辑值。
- 所有常见 status 路径的 TracerPid 一致修补。
- 已打开真实 status FD 的 `read`/`pread64`/`readv` 完整行输出修补。

验收:

- raw syscall 直调已覆盖；libc `prctl` wrapper 和更多 status 别名仍需单独补测。
- 根 TGID status provider、逻辑 dumpable/TRACEME 和 stop commit 已通过设备回归。
- 每 TID proc status provider 和真实 status FD read view 已覆盖；proc 目录枚举和其他
  proc 文件仍进入后续 Level 2。nested ptrace phase-1 resident bridge 已在 USB 专用
  instrumentation 连续 `3/3` 通过；完整 nested logical engine 仍不是 resident 功能。

### M7: 生产硬化

实现:

- SpawnExecBackend 或 ServiceBackend。
- 24 小时压力、OOM、App freezer、随机 signal/kill、前后台和 ANR 测试。
- 固定容量表的溢出和故障注入；63+1 bypass slot 正常销毁已覆盖，仍需补 TaskTable headroom、
  worker/join watchdog、teardown freeze timeout 和部分恢复失败注入。

验收:

- 无永久 ptrace-stop、无僵尸 tracer、无 JNI/allocator fork 死锁。
- 规则更新不会阻塞事件循环。
- 每个 fatal path 都能得到确定的退出或回滚结果。

## 19. M0 能力报告格式

建议返回 JSON/Java model 对应字段:

```text
environment:
  api, kernel, abi, uid, gid, selinux, yama_scope
target:
  pid, bootstrap_tid, thread_count, tracer_pid, tracer_pid_before
prctl:
  original_dumpable, set_dumpable_errno, set_ptracer_errno
ptrace:
  seize, interrupt, event_stop, getregset, setregset, traceclone
memory:
  process_vm_readv, process_vm_writev, peekdata, pokedata
syscall:
  entry_seen, exit_seen, nr, result
coverage:
  discovered_tids, attached_tids, escaped_tids
rollback:
  detached_tids, restored_dumpable, app_responsive
verdict:
  PASS_FULL, PASS_ATTACH_ONLY, PARTIAL, BLOCKED, INTERNAL_ERROR
```

`EPERM` 分类至少结合:

- `TracerPid != 0`: 已有 tracer。
- dumpable 未变成 1: dumpable/进程状态问题。
- Yama 2/3: 能力不足。
- 条件均正常: OEM SELinux、LSM、seccomp 或厂商内核策略, 需要抓取 avc/kernel log 辅助判断。

## 20. Go/No-Go 门槛

进入 M1 前:

- 目标 Linux 5.1 真机 `PASS_FULL`。
- 所有稳定存活 TID 均可 seize。
- arm64 GETREGSET 正确。
- detach 后 App 无冻结。

进入路径改写前:

- signal、clone 和 entry/exit 状态机压力通过。
- 共享 scratch 与远程内存两条路径都通过。
- 明确第一批 redirect rule 和期望错误策略。

进入 selective seccomp 前:

- PTRACE_O_TRACESECCOMP 在牺牲进程产生真实 event：当前 5.10.110 设备已通过，Linux 5.1
  目标机仍需验收。
- TSYNC 在目标多线程 App 成功：双线程牺牲进程和 28 个现存 task 的正式 App
  stop-the-world 提交均已在当前设备验证。
- 已选择 `FAIL_CLOSED` 或继续 full ptrace。
- 已覆盖 App 可能创建的 fork/exec 后代。

进入伪装前:

- 明确“只兼容 PTRACE_TRACEME”还是需要 nested ptrace。
- 明确要覆盖的 `/proc` 路径和一致性要求。
- 接受外部 debugger/crash_dump 共存限制。

## 21. 默认决策

在没有额外输入时, 后续实现按以下默认值推进:

- 仅支持 arm64-v8a。
- “内核 5.1”按 Linux 5.1.x 处理, 同时在报告中显示完整 release。
- 第一版使用 strict `ForkRawBackend`。
- M0/M1 不安装 seccomp, 保证可回滚。
- 第一条路径规则只覆盖测试目录, 不修改系统或共享存储真实内容。
- 首批观测 syscall 为 `getpid`, `gettid`, `openat`。
- 第一条改写 syscall 为 `openat`。
- 正式 selective 模式采用 `FAIL_CLOSED + PTRACE_O_EXITKILL`。
- ptrace 伪装首版只做 PTRACE_TRACEME、dumpable 和 status/TracerPid 一致性。

## 22. 已知根本限制

- ptrace 是按线程、排他且可被观察的机制。
- seccomp filter 只能叠加, 不能卸载或放宽。
- fork/exec 后代继承 filter, 必须持续跟踪。
- 内核内部打开、io_uring 后台操作、Binder 内部 FD 传递不一定呈现为普通路径 syscall。
- tracee 参数在用户内存中, 读取和最终内核使用之间存在 TOCTOU。
- 路径重定向不改变 mount namespace 和 SELinux label。
- App 已运行后 attach, 只能从快照时刻开始维护逻辑视图。
- 完整 nested ptrace 和完整 proc 虚拟化接近一个独立子项目。

## 23. 当前实施起点

M0-M4、常驻 full-ptrace、正式 selective runtime、M6 既有切片与 nested phase-1 resident bridge
均已进入回归。shared ABI v12 的 63+1 runtime bypass、retire-owner/publisher barrier、
post-mutation protected-FD 复检和 selective owner-only teardown freeze 已进入当前回归；nested
phase-1 已在 USB 专用 instrumentation 连续 `3/3` 通过。

工程封装与 API 分层已经落地：

- `:hookself` 独立 Android Library 通过 AAR/Prefab 发布 `libhookself.so`、`framework.h` 和
  `public_api.h`；`:app` 已收敛为 demo/JNI 与 instrumentation 宿主。
- `HookselfFramework` 已统一 syscall/path/redirect 注册、opaque handle 查询/启停/注销、整体
  start/stop，以及 event/log/virtual-file forwarding。底层 `HookselfRuntime` API 继续保留为进阶层。
- facade config 使用深拷贝和 lazy runtime；full-ptrace stop 后的规则变更触发下一次 start 重建，
  selective 首次成功 start 后冻结规则 registry。dynamic snapshot 已提交后的后处理错误也会同步
  facade cache，重建不回退旧内容。
- `framework.cpp`、`runtime_api.cpp`、`resident_session.cpp` 和 `path_state.cpp` 已拆成按职责组织的
  编排单元与子目录；self-test、probe 和测试 JNI 由 Debug-only build option 隔离。

下一阶段集中补齐路径/FD 语义基础和扩大故障矩阵：

1. 为 redirect 打开的目录 FD 建立 guest-origin/path 身份表，作为 dirfd、cwd、getcwd 和
   host-to-guest 反译的统一基础。
2. 完整解析 openat2 `open_how/resolve`、`AT_EMPTY_PATH`、follow-final、symlink 与双路径
   syscall 语义；补 exec 后 scratch/provider/FD 状态重建。
3. 扩展 proc `getdents64`、maps/smaps 和 SELinux/xattr 输出视图，避免只覆盖单文件读取。
4. 给正式 selective 增加 tracer kill、提交边界和 class/phase desync 故障注入，并覆盖
   filter 继承后的新线程、fork/vfork 和 non-leader exec 压力。
5. 对比 full-ptrace 与 selective 的吞吐、P50/P95/P99 延迟和功耗。
6. 在 Linux 5.1 目标机和量产 SELinux Enforcing ROM 执行同一份 capability、正式启动与
   故障 Go/No-Go 验证。

## 24. 查证资料

- [AOSP 当前普通 App 同域 ptrace 规则](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/untrusted_app_all.te#102)
- [AOSP App ptrace neverallow 边界](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/app.te#561)
- [AOSP app_zygote ptrace 禁止规则](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/app_zygote.te#172)
- [Linux 5.1 Yama 文档](https://www.kernel.org/doc/html/v5.1/admin-guide/LSM/Yama.html)
- [Linux ptrace 接口和 stop 语义](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Linux 5.1 seccomp filter 文档](https://www.kernel.org/doc/html/v5.1/userspace-api/seccomp_filter.html)
- [多线程进程 fork 后的调用限制](https://man7.org/linux/man-pages/man2/fork.2.html)
