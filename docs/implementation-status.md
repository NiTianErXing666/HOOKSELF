# hookself 实现与验证状态

更新日期：2026-07-15

> 注：5.10.110 的性能和 instrumentation 数字保留为迁移前历史记录；当前 public ABI v6、
> internal shared ABI v12 与 regular virtual backing 的验收结果见下方 USB 回归。Linux 5.1
> 目标仍未完成实机验收。

## 当前验证设备

- USB ADB `3B241FDJH000S4`：Android 15 / API 35 / arm64-v8a，Linux
  `6.1.99-android14-11-gd7dac4b14270-ab12946699`。
- 该 Android 15 设备在 App 启动前已有 seccomp filter：`Seccomp=2`、
  `Seccomp_filters=1`；SELinux 为 Enforcing，测试进程 context 为
  `u:r:untrusted_app:s0:...`，`yama_scope=unavailable`，M0/M1 反向 attach 均通过。
- 网络 ADB `192.168.1.129:5555`：Android 10 / API 29 / arm64-v8a，Linux 5.10.110；
  已有回归记录见“USB v6/v12 回归”和“迁移前 5.10 历史记录”。
- Linux 5.1 目标仍没有新的实机验收结果。

## 当前架构

- 工程拆分为 `:hookself` Android Library 与 `:app` demo/instrumentation 宿主。
  `:hookself` 通过 AAR/Prefab 发布 `libhookself.so`、`hookself/framework.h` 和
  `hookself/public_api.h`；`:app` 仅构建 `libhookself_demo.so` 并通过
  `hookself::hookself` 链接公共库。
- native 实现按 `api`、`arch`、`platform`、`tracer`、`internal` 和 `test_support` 分层。
  `framework.cpp`、`resident_session.cpp`、`runtime_api.cpp` 与 `path_state.cpp` 只保留编排和
  共同 include，具体职责拆入 `api/framework`、`api/runtime`、`internal/resident_session` 与
  `tracer/path_state`。facade 单个职责片段不超过 330 行。
- `HOOKSELF_BUILD_TEST_SUPPORT` 只在 library Debug 构建开启。native self-test、probe、测试
  JNI 和 Java `NativeTestBridge` 不进入 release 业务路径。
- public ABI v6，internal shared ABI v12，task table v8。public v6 新增调用方提供的
  `virtual_backing_dir`；shared v12 提供 64 个并发 runtime API bypass TID 槽，其中 63 个供
  普通调用、1 个专供 destroy，另含 selective teardown freeze/release 与 exact-FD capability；
  task table v8 保存每 TID `CONT/SYSCALL` resume mode、seccomp-origin active syscall 标志，以及
  nested phase-1 的 tracee hold、held wait、exec 重建和 `PTRACE_GETEVENTMSG` 缓存状态。
- `libhookself.so` runtime 使用 raw `clone(SIGCHLD)` 创建 tracer 子进程，tracer 关闭无关
  继承 FD。
- parent 保存 dumpable，设置 tracer 访问条件；child 对主进程全部 TID 执行
  `PTRACE_SEIZE + PTRACE_INTERRUPT`。
- tracer 使用固定容量 task table、共享规则双缓冲、事件 ring 和 tracee scratch；
  fork 后不依赖 allocator、JNI 或 Android log。
- syscall 主循环优先使用 `PTRACE_GET_SYSCALL_INFO`，并保留基于每 TID phase 的
  Linux 5.1 fallback。
- M4 capability probe 继续只在 fork 出的牺牲进程安装测试 filter；正式 runtime 已支持
  在 stop-the-world 后由 `hookself_start()` 调用线程执行 `NO_NEW_PRIVS + TSYNC`，进入
  常驻 selective 模式。

## 已实现能力

### Library 封装与统一 Framework

- `HookselfFramework` 是推荐的业务门面，拥有可编辑规则 registry 与延迟创建的
  `HookselfRuntime`。create 深拷贝 config、path/syscall 规则、virtual-file descriptor 和
  initial content，调用方不需要维持原始缓冲区生命周期。
- syscall/path 规则通过 opaque `HookselfRuleHandle` 管理，支持注册、按 kind + public rule ID
  查找、查询 enabled、启停和注销。`hookself_framework_register_redirect()` 提供不需要手工
  构造 `HookselfPathRule` 的 prefix redirect 快捷入口。
- facade 统一转发 state/stats、raw events、log sink/drain 和 virtual-file publish/refresh；
  start/stop 幂等，未创建 runtime 时 facade state 为 `CONFIGURED`。
- 首次成功 start 前规则表可编辑。full-ptrace 运行期间拒绝 mutation，stop 后成功变更会销毁
  stopped runtime，并在下一次 start 按新规则重建；selective 首次成功 start 后永久冻结规则表，
  disabled syscall 以 `PASS` 进入初始 plan。
- facade live-object registry、active-call 计数和 generation-aware runtime lease 协调并发调用、
  stop 后重建和 destroy。生命周期事务及 sink 更新串行化；destroy 先阻止新调用，再等待在途
  facade call/runtime lease 退出。sink 回调内重入 destroy 会中止当前 raw drain，避免再次使用
  已由回调释放的 `user_data`。
- facade 镜像 dynamic virtual-file snapshot。即使具名路径已提交但 stable-FD/handshake 后处理返回
  `HOOKSELF_E_INTERNAL`，内部 commit 状态也会同步到 facade，stop 后规则变更和 runtime 重建不会
  回退到旧内容。

### 常驻生命周期

- 覆盖启动时已有 TID，并跟踪运行期 clone/fork/vfork/exec/exit。
- 处理 child-first clone stop、非 leader exec TID 迁移、成功 execve exit 合成、
  signal-delivery stop 和 group-stop。
- 启动、运行、停止和 fatal 都校验 PID starttime，防止 PID 复用。
- stop 先 quiesce，再把所有寄存器/参数/结果 mutation 推进到 syscall-exit。
- full-ptrace 使用两阶段 stop commit：只先 detach stop 调用 TID，其余 TID 保持停止；调用线程提交
  最终逻辑 dumpable/ptracer 后，tracer 才 detach 其余任务。
- full-ptrace stop 在最后一个外层 call guard 退出时以 runtime 级 retire-owner 仲裁回收全局
  bypass control 和 resident lease。retire 期间 publisher barrier 阻止下一代 control 发布；与
  destroy 竞争时只有 CALL 或 DESTROY 一方负责 retire，避免 pin 互等和跨代 cleanup。
- selective stop 先切换 pass-through 并成功恢复全部 TID，之后才以 release 顺序发布
  ack、`STOPPED` 和状态字节；任何部分恢复失败都不会向调用方报告成功。
- mutation 回滚失败进入 fail-closed，不把未知寄存器状态恢复给 App。

### Syscall 观测与策略

- `OBSERVE`、`DENY`、`REPLACE_NUMBER`、`REPLACE_RESULT`、
  `REPLACE_ARGUMENT`。
- 规则支持 phase、参数 mask/value、rule ID 和参数/结果事件。
- 内建策略优先级：internal runtime/protected FD > ptrace view > 用户 syscall rule >
  path policy。
- public API 入口在任何锁或控制 syscall 前登记调用 TID；专用 arm64 `gettid` claim stub
  由 tracer 按 syscall PC 精确识别。protected FD 策略仍先执行，随后才跳过该 TID 的用户
  mutation、路径策略与事件输出，避免框架控制流被自身规则递归修改。
- 用户 syscall rule 改写 syscall number 或 FD 参数后，dispatcher 会按生效寄存器再次执行
  protected-FD 检查；规则不能先把无关调用 mutation 成 `close/dup/fcntl/close_range` 再绕过
  protected registry。syscall-info 与 Linux 5.1 regset fallback 使用同一二次检查。
- 用户 syscall rule ID `0xffff0000..0xffffffff` 保留给框架内建策略。

### M4 selective seccomp 能力探针

- 可复用 arm64 builder 生成 `AUDIT_ARCH_AARCH64` 检查、按 syscall number 返回
  `SECCOMP_RET_TRACE | class_id`、其余 `ALLOW` 的固定容量 cBPF；拒绝负数、重复 syscall、
  非法 arch action 和非法安装 flags。raw installer 支持并校验 `TSYNC`，同时保留内核
  返回失败 TID 的报告路径。
- ptrace 子探针在牺牲 tracee 上叠加单 syscall filter，并启用
  `PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD`。连续两个 `gettid` 均产生
  `PTRACE_EVENT_SECCOMP`；每次通过 `PTRACE_GETEVENTMSG` 校验 class id，并在支持时通过
  `PTRACE_GET_SYSCALL_INFO_SECCOMP` 校验 syscall number/data，Linux 5.1 路径使用 arm64
  regset fallback。
- 第一个 TRACE event 由 `PTRACE_CONT` 继续，第二个由 `PTRACE_SYSCALL` 继续并校验
  syscall-exit stop、返回值和 `PTRACE_SYSCALL_INFO_EXIT`；probe 随后 detach，命中
  `RET_TRACE` 的调用在没有 tracer 时得到 `-ENOSYS`。
- 独立 TSYNC 子探针创建 leader + worker 两个线程，再以
  `SECCOMP_FILTER_FLAG_TSYNC` 安装 `getppid -> RET_TRACE` filter。两个线程在没有 tracer
  时均得到 `-ENOSYS`，验证 filter 已覆盖安装时存在的两个线程。worker 由 arm64 raw
  clone trampoline 启动，不进入 libc clone/TLS 路径；异步 signal 在 clone 前屏蔽，64 KiB
  worker stack 两端均有 guard page。安装前 leader/worker 还必须同时得到真实 `getppid`，
  避免把 OEM 既有策略误判为 TSYNC 成功。
- 整个 probe 的 `PR_SET_NO_NEW_PRIVS` 和 filter 安装都发生在牺牲子进程；报告前后核对
  App 调用线程的 `NoNewPrivs`、`Seccomp` 和 `Seccomp_filters`，防止不可回滚状态泄漏到
  主 App。
- supervisor、tracee、TSYNC child 均设置并回读 `PDEATHSIG=SIGKILL`，再复核父 PID。
  tracee 以 `/proc/<pid>/stat` starttime、release/acquire PID 发布和 start gate 建立身份；
  顶层超时时先有界终止/reap supervisor，再按 PID + starttime 等待原 tracee 身份消失。
  shared mapping 或 worker stack 仅在所有直接 child 已确认 reap 后释放。
- 测试入口支持强制关闭 `PTRACE_GET_SYSCALL_INFO`，真实执行 arm64 regset fallback；另有
  supervisor-hang 与 TSYNC-hang 两个 250 ms 故障注入，验证 SIGKILL、reap、App 状态保持
  和后续完整回归。

### 正式 selective seccomp 常驻 runtime

- `BuildSelectiveSeccompPlan()` 在任何不可回滚动作前，将用户 syscall、protected FD、
  路径策略、virtual file 和 ptrace/proc view 依赖编译为排序去重的 cBPF plan。上限为
  192 条，覆盖 public API 最坏 128 条用户规则与 27 条内建依赖；统一 class id 后仍以
  syscall number 二次校验，plan 使用稳定 schema/hash。
- child tracer 对所有现存 TID 完成 `SEIZE + INTERRUPT` 后保持 stop-the-world，只以
  `PTRACE_CONT` 放行本次 `hookself_start()` 调用 TID。调用线程设置 `NO_NEW_PRIVS`，执行
  `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)`，发布结果后执行固定 arm64 `BRK`，提交后不再
  依赖可能被新 filter 捕获的握手 syscall。
- tracer 校验事务序列、plan hash、BRK 指令、TSYNC 结果和最终 TID 覆盖，再发布
  `RUNNING_SELECTIVE`。提交后异常路径依靠 `PTRACE_O_EXITKILL` fail-closed；提交前且未
  改变 NNP 的失败仍可走原 full-ptrace detach 回滚。
- tracer 本地记录 installer 是否已被首次 `PTRACE_CONT` 放行；放行前的协议、状态管道和
  resume 错误可确定回滚，放行后的非预期 stop 一律视为 NNP/filter 结果不明确。只有收到
  owner response、状态为 `ABORTED_PRECOMMIT`、filter 未提交且本次未改变 NNP 时才 detach。
- `PTRACE_EVENT_SECCOMP` 是唯一 selective syscall 入口。tracer 同时校验
  `PTRACE_GETEVENTMSG`、`PTRACE_GET_SYSCALL_INFO_SECCOMP` 与 plan；Linux 5.1 路径使用
  arm64 regset fallback。纯 ENTRY 观测或候选未命中时直接回到 `PTRACE_CONT`；需要结果、
  mutation 恢复、路径 scratch、protected/internal FD、ptrace/proc view 的调用只追加一次
  `PTRACE_SYSCALL` exit stop，完成后恢复 `CONT`。
- resume mode 按 TID 保存；signal、group-stop、clone/fork/vfork、exec/exit 插入事件不会
  把其他 TID 的入口/出口相位串在一起。新后代初始为 `CONT` 并继承 filter；exec 恢复
  保留一次合成 exit，终止性 EXIT event 丢弃不会返回的 active transaction。
- selective filter 在 Linux 中不可卸载。`hookself_stop()` 因此先 quiesce 完成在途
  mutation，再切换为常驻 pass-through tracer；该模式仍执行 internal/protected FD 完整性
  协议，其他用户策略透传。`hookself_start()` 可重新启用策略而不重复安装 filter。
  `hookself_destroy()` 在 pass-through 后释放 App 侧对象，最小 tracer 随 App 进程存活，
  避免命中 `RET_TRACE` 时退化为 `-ENOSYS`。
- selective destroy 必须先得到 pass-through ack；超时、控制失败或状态不一致时保留共享
  控制面并 fail-closed，不会关闭 FD 后继续解映射 active policy。确认 pass-through 后，tracer
  处理 `kTeardownFreeze`：quiesce 并核验全部任务，只恢复 destroy owner，发布 frozen ack。
  owner 屏蔽可屏蔽信号，每次只为一个精确的 owner TID + FD close 发布 capability；close 成功后
  立即从 protected registry 删除该 FD。registry 归零后 owner 发布 release，tracer 恢复其余
  任务并清除 freeze/release，parent 最后清 capability、解映射和删除 runtime。
- selective 与 `HOOKSELF_CONFIG_OBSERVE_ALL` 语义冲突并在配置验证阶段拒绝；全量 syscall
  流继续使用 full-ptrace。

### 结构化日志

- `hookself_syscall_name()` 覆盖常见 arm64 syscall 名称；未知编号稳定返回 `unknown`。
- `hookself_event_log_level()` 将 internal error、signal、lifecycle/process、path 和 syscall
  映射到 ERROR..TRACE；`hookself_format_event()` 输出带 tgid/tid、编号/名称、phase、
  action、result/error、rule、flags、参数和转义路径的单行文本。路径转义超出容量时改为
  输出结构化 truncation 标记，不切断 `\\xNN` 或引号。
- `hookself_set_log_sink()` 注册同步自定义 sink；未注册时 `hookself_drain_logs()` 使用
  Android Logcat。回调只在调用 drain 的 App 线程执行，fork 后 tracer 不调用 JNI、
  allocator 或 Android log。
- 日志 drain 是显式事件消费者，没有隐藏后台线程。每个 runtime 只能选择
  `RAW_EVENTS`（`hookself_read_events()`）或 `LOG_DRAIN`（`hookself_drain_logs()`）一种
  消费模式，首次有效消费调用即锁定模式，避免同一事件流被两个 API 任意分割。
- `hookself_drain_logs()` 整次调用持有 parent reader mutex。sink 回调中的 `event` 和
  `message` 指针仅在本次同步回调期间有效；回调内重入 set sink 或 drain 返回
  `HOOKSELF_E_BUSY`。替换 sink 返回 `HOOKSELF_OK` 后，调用方才可释放旧 `user_data`。
- public API 使用 mutex、条件变量和 allocator，不具备 async-signal-safe 语义，不从 signal
  handler 调用。同步 sink 回调内的 destroy 继续延迟到最外层 drain 退场；需要首次发布
  runtime bypass control 的嵌套 start 直接返回 `HOOKSELF_E_BUSY`，不会等待外层自身。
- drain 期间将当前 App TID 发布为日志 bypass owner；sink/Logcat 产生的 syscall 仍维持
  entry/exit 相位，并始终执行 protected FD 与内部 FD 发布协议，只跳过用户规则、
  ptrace/proc view、路径策略和事件写入，防止 TRACE 日志反馈循环。
- runtime 使用全局注册表和 active-call 计数协调销毁。destroy 先摘表再等待在途调用；
  sink 回调内 destroy 延迟到 drain 清除 bypass/reader lock 后唯一完成，避免 shared mapping、
  sink `user_data` 或 mutex 的并发释放。

### 路径重定向

- 固定容量最长 prefix 规则和组件边界匹配。
- 支持绝对路径和 `AT_FDCWD`/dirfd 相对路径解析。
- chroot 状态同时保存 guest/host root；绝对路径、host-to-guest 反向映射和 `getcwd` 均按
  逻辑 root 处理。`getcwd` 在物理 cwd 因缓冲区不足返回 `-ERANGE`、但虚拟 cwd 可写入时，会在
  syscall exit 合成虚拟路径和返回长度。
- `openat2(RESOLVE_IN_ROOT)` 以调用 dirfd 作为词法根解析绝对和相对路径；重复 `..` 被夹断在
  dirfd 根内，不会误上溯到进程 cwd 或 chroot root。
- 分派 openat/openat2、newfstatat、statx、faccessat、readlinkat、unlinkat、
  mkdirat、mknodat、fchmodat、renameat/renameat2、linkat、symlinkat、execveat、
  chdir 等常见路径参数。
- 支持双路径 syscall 的独立 scratch slot、guest/translated path 事件和 deny。
- 修改寄存器后立即回读验证；syscall-exit 恢复用户参数视图。

### 虚拟文件与受保护 FD

- `virtual_backing_dir` 是调用方预先创建的规范绝对 App 私有根目录；每个 runtime 只拥有其
  下的一个私有子目录，框架不会创建、重命名或删除该根目录。
- 静态、动态 snapshot 和 `PROC_STATUS`、`PROC_MAPS`、`SELINUX_CONTEXT` provider 都使用
  runtime 私有子目录中的具名 regular backing。创建、临时 snapshot、提交和销毁均校验
  FD object identity；FD number 被复用时不会关闭或覆盖新对象。
- `DYNAMIC_SNAPSHOT` 先写入临时文件，再以 `renameat()` 提交具名路径，并用 `dup3()` 同步
  protected stable FD。USB 回归验证已打开 FD 读取旧 snapshot、新 open 读取新 snapshot，
  static/dynamic/provider 内容与 FD-reuse 保护均通过。路径提交后 stable-FD 同步若失败，
  API 返回内部错误但路径仍是新 snapshot，调用方必须重新打开并校验，不能假定路径回滚。
- provider source FD 在启动前打开；运行期 refresh 使用内部 syscall bypass。
- status provider 将唯一 `TracerPid:` 改为 0；maps 按真实地址区间过滤 runtime、
  scratch 和当前模块 `PT_LOAD`；SELinux provider 支持真实源或配置内容。
- protected FD registry 拦截 close、外部 dup3 覆盖和 CLOEXEC 清除。启动时在独立子进程
  分别探测 `close_range` syscall、`CLOSE_RANGE_CLOEXEC` 与 `CLOSE_RANGE_UNSHARE`，并把
  capability mask 写入 shared control。能力缺失或未知 flag 透传内核；有效请求命中
  protected FD 时，dispatcher 抑制原调用并分段 replay 非 protected 区间。
- `CLOSE_RANGE_UNSHARE` 先以 `[UINT32_MAX, UINT32_MAX]` sentinel 分离 FD table，随后
  无 `UNSHARE` 地 replay 实际子区间。每段成功后才更新 FD identity 状态；某段失败时停止后续
  replay，保留内核已经产生的部分副作用。USB 已验证 ordinary/protected `CLOEXEC`、flags 为 0、
  分段 close 和分段 `UNSHARE` 的成功语义。
- 用户 mutation 完成后按生效 syscall number 和寄存器参数再次检查 protected FD；selective
  teardown 则在冻结其他任务后逐 FD close 并立即删除 registry entry，避免 FD number 复用窗口。

### Ptrace Level-1 运行视图与 nested phase-1 resident bridge

- Level-1 仅作用于根 App TGID；TRACE_DESCENDANTS 后代默认透传真实内核语义，下面的
  nested phase-1 直接子进程 leader 是受限例外。
- 每个 TID 第一次 `PTRACE_TRACEME` 返回 0，后续返回 `-EPERM`。
- `PR_GET_DUMPABLE` 返回 TGID 共享逻辑值；`PR_SET_DUMPABLE` 仅接受完整 64 位参数
  0/1，其他值返回 `-EINVAL`。
- `PR_SET_PTRACER` 支持 0、全宽 `PR_SET_PTRACER_ANY` 和存在的正 PID；正 PID 同时
  记录 starttime，停止提交前防复用校验。
- unrelated ptrace/prctl 继续进入用户规则或真实内核。
- 所有内建 view 操作发出成对 ENTRY/EXIT syscall 事件，并统计
  `ptrace_view_operations`。
- nested resident phase-1 仅接受根 App 直接创建的子进程 leader：子进程 leader 的
  `PTRACE_TRACEME` 成功后，第一次 `exec` 通过 `wait4`/`waitid` 呈现为 `SIGTRAP` stop；
  该 stop 被物理 hold，直到根 App 继续其逻辑 ptrace 请求。
- 在第一次 stop 上，`PTRACE_SETOPTIONS` 仅接受 `0` 或 `PTRACE_O_TRACEEXEC`；
  `PTRACE_CONT` 恢复子进程。设置 `TRACEEXEC` 后的后续 `exec` 呈现为
  `PTRACE_EVENT_EXEC`，`PTRACE_GETEVENTMSG` 读取该 stop 缓存的 event message，随后
  `PTRACE_CONT` 或 `PTRACE_DETACH` 释放 hold。逻辑 detach 不会释放框架自身的真实 ptrace。
- phase-1 对该链路持有 `wait4`/`waitid` 的 surrogate exit，并在匹配 stop 发布后唤醒；
  支持 `waitid(..., WNOHANG)` 的无事件返回。子进程在恢复或 detach 后的终止仍由其真实父进程
  wait ownership 回收。
- public capability API version 2 分开报告 `runtime_features` 与 `engine_features`。
  resident 的 nested 发布位只有 `HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC`；后代
  TGID 状态、ATTACH/SEIZE、通用 resume、完整 wait/signal/siginfo、memory、regset 和
  syscall-info 等 logical-engine 位没有因此成为 resident 能力。
- phase-1 只在 full-ptrace 中运行；public 校验拒绝它与 selective seccomp 的组合。它不支持
  非 leader、孙代或其他后代、已有 relation、`PTRACE_ATTACH`/`PTRACE_SEIZE`、
  `PTRACE_SYSCALL`、`PTRACE_SINGLESTEP`、`PTRACE_LISTEN`，以及 `TRACEFORK`、
  `TRACEVFORK`、`TRACEEXIT` 等其他 `PTRACE_SETOPTIONS` 位。

### Proc Status Level-2 输出视图

- 对根 App TGID 打开的真实 `/proc/<pid-or-tid>/status` FD，在 `read`、`pread64`
  和 `readv` 的 syscall-exit 聚合本次返回数据并修补 `TracerPid:`。
- 每次通过 `/proc/<reader-tid>/fd/<fd>` 识别真实 FD，并校验 status 内的 `Tgid`
  属于根 App；普通 memfd 等非 proc FD 不进入该策略。
- 仅当一次 syscall 返回的数据中包含完整 `TracerPid:` 行时修补；内建策略使用
  `HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW` 发出带
  `HOOKSELF_EVENT_F_PROC_STATUS_VIEW` 的成对 ENTRY/EXIT 事件，并累计
  `proc_status_patches`。
- 需要严格一致性或支持任意碎片读取时，应把路径重定向到 sealed `PROC_STATUS`
  virtual provider；provider 在数据交给 App 前已经生成净化后的稳定 snapshot。

## 当前验证结果

### USB v6/v12 回归（2026-07-15）

- `:app:assembleDebug`、`:app:assembleDebugAndroidTest`、`:app:assembleRelease`、
  `:hookself:assembleRelease` 和 `:app:lintDebug` 通过；lint 为 0 errors、3 个已知环境/平台警告
  （target/compile SDK 更新提示与 arm64-only ChromeOS 提示）。
- Release AAR 为 1,231,422 字节，metadata 为 `minCompileSdk=24`、extension 0；包含 arm64-v8a
  Prefab 库、`framework.h`、`public_api.h` 与 `c++_shared`。stripped `libhookself.so` 为
  345,968 字节，动态导出仅 38 个 `hookself_*`（其中 20 个 facade），测试符号/字符串为 0。
- 单轮 instrumentation 的 `frameworkOnly`、`procVirtualResidentOnly`、`residentOnly` 和
  `repeatAll` 均通过。`frameworkOnly` 的 framework API self-test 为 `PASS`、failures 为 0、
  `chroot_path_result=0`；facade 覆盖 32 轮 entry/destroy、关闭后拒绝新登记、sink 内重入 destroy、
  initial-rule deep copy/find、规则 no-op/校验，以及 post-commit publish 错误后的 stop/mutation/rebuild
  内容保持。
  `repeatAll` 覆盖 M0/M1、redirect、M4、proc view、regular backing 和 resident 生命周期。
- `procVirtualResidentOnly`：create/start/stop 均为 0，`maps_hidden`、`smaps_hidden`、
  `proc_dir_hidden`、xattr get/list match 均为 1，fatal code/errno 均为 0。
- `residentOnly`：start/stop 为 0，状态 `RUNNING_FULL_PTRACE(3) -> STOPPED(7)`；
  clone/fork/exec（`execve_exit=1`）、ptrace Level-1、proc status read view、路径重定向和
  virtual file 均通过，fatal code/errno 为 0。redirect 回归包含
  `openat2(RESOLVE_IN_ROOT, "/../../relative")` 的 dirfd 根夹断，以及物理 cwd 较长时
  短缓冲 `getcwd` 的虚拟结果回写。
- regular backing：`virtual_static_match`、`virtual_old_snapshot_match`、
  `virtual_new_snapshot_match`、`virtual_fd_reuse_pass` 均为 1，`virtual_publish_result=0`。
- `close_range`：base、ordinary/protected `CLOEXEC` 和 protected flags=0 均返回 0；
  ordinary/protected `F_GETFD` 报告 CLOEXEC，分段 close 与分段 `UNSHARE` 回归均通过。
- nested phase-1 的专用 USB instrumentation `nestedPtraceResidentOnly` 连续 `3/3` 通过。
  它覆盖 direct-child leader 的 `TRACEME -> first exec SIGTRAP -> SETOPTIONS(TRACEEXEC) ->`
  `later exec event/GETEVENTMSG -> CONT`，以及 `waitid(WNOHANG)`、`DETACH`、child exit/reap
  和 runtime stop/destroy；每轮 39 项检查均为 0 failures、fatal code/errno 均为 0。
- 最新 5.10/API 29 回归：`192.168.1.129:5555` 上 `AndroidJUnitRunner` 全量 `7/7` 通过。
  `procVirtualResidentOnly` 连续 `10/10`、`nestedPtraceResidentOnly` 连续 `10/10` 通过；
  nested smoke 使用最大 public event ring，避免 `NEW_TASK` 同步事件被普通 syscall 事件挤出。
  xattr smoke 在 caller 提供且已验证存在的 `virtual_backing_dir` 下创建临时文件，并报告 open
  结果/errno，不再依赖可延迟创建的 app `files` 目录。该 API 29 进程的 `close_range` 基线为
  `-ENOSYS`，因此 instrumentation 只在 syscall 可用时校验 CLOEXEC 后续 FD 状态。
  `selectiveRuntime` 固定为 `ProbeStressTest` 最后一个方法，因为 TSYNC filter 会保留在同一
  instrumentation target process 内，阻止后续 full-ptrace 场景重新启动。
- 模块化 facade 最新定向回归：Linux 6.1/API 35 与 Linux 5.10.110/API 29 的
  `frameworkOnly` 均通过；5.10 的 `demoLoggingFlow` 通过。6.1 最新 `repeatAll` 为 7.169 秒，
  清进程后独立 `selectiveRuntime` 为 1.298 秒，均为 `OK (1 test)`。

### 迁移前 5.10 历史记录

- Gradle/CMake：`:app:assembleDebug`、`:app:assembleDebugAndroidTest` 和
  `:app:lintDebug` 通过。
- 正式 selective runtime 在 `192.168.1.129:5555` 完成 fresh 单轮、`20/20` 和
  `100/100` 独立 instrumentation；最新版 fresh 单轮为 1.871 秒，最新 100 轮为 3.013 秒。
  最终 100 轮包含一次不可逆 TSYNC 安装、101 次 start、101 次 stop、101 个 active
  round 和 100 个 pass-through round；`RUNNING_SELECTIVE/STOPPED` 状态检查均为 101 次。
- selective 最终轮精确得到 gettid ENTRY/EXIT `101/101`、getpid ENTRY-only `101/0`、
  getppid DENY ENTRY/EXIT `101/101`；`events_read/emitted` 为 `708/708`、observed 为 303、
  `tracked_tasks` 为 27，control/pass-through/unexpected rule event 为 `0/0/0`，
  dropped/internal/fatal 为 `0/0/0`。
  最终 selective destroy 同时执行 63 个普通 bypass slot holder + 1 个保留 destroy slot 的
  teardown stress；instrumentation 结束后 App/tracer 进程、stopped/zombie、crash dropbox、
  fatal/ANR 检索均为空。
  最新 post-destroy 断言在 2.5 秒全局 deadline 内反复重扫 `/proc/self/task`，容忍扫描期间
  已退出的瞬态 TID，同时要求全部存活 task 使用同一个正值 resident `TracerPid`、状态均非
  `T/t/Z`，并连续两轮稳定后才判定通过。
- 本次接入正式 selective 后，旧 full-ptrace/M4 综合回归重新完成 fresh repeatAll
  （4.47 秒）、`20/20`（最新 39.531 秒）和历史 `100/100`（186.319 秒），
  `singleton_pass=1`。该轮对应迁移前 shared/task-table layout，不验证当前 v12/v6。当前 fresh/20 轮结束后
  `ps` 与 Activity 状态均无 hookself 残留，`data_app_crash`/`data_app_anr` 无 hookself 条目，
  logcat 无本 App fatal。
- M4 capability probe 在清空 App 数据后的真机综合回归中通过；加固版完整 20 轮
  instrumentation 为 `20/20`，38.991 秒；最终完整 100 轮为 `100/100`，182.429 秒。
  正常单次 probe 约 109-134 ms，第 100 轮为 119 ms。
  两次 TRACE event、两次 class-id/SECCOMP syscall-info 校验、一次 syscall-exit info
  校验、CONT/SYSCALL 恢复顺序、detach 后 `-ENOSYS` 以及双线程 TSYNC 后两个
  `-ENOSYS` 均符合预期；强制 regset fallback、supervisor/TSYNC 超时清理也通过，
  无 unexpected stop 和牺牲进程残留。
- 第 100 轮 M4 的 `fatal_errno=0`、TRACE/class-id 次数 `2/2`、SECCOMP/EXIT info
  `2/1`、三个 cleanup errno 均为 0；supervisor/tracee/TSYNC 三个 PID 随后均已消失。
  整轮测试后 crash dropbox 为空，logcat 无 App fatal/ANR，App/tracer/stopped/zombie 残留为空。
- M4 probe 前后 App 自身的 `NoNewPrivs`、`Seccomp=2` 和 `Seccomp_filters=1` 保持不变。
  该 OEM 内核在牺牲 tracee 及 TSYNC 两个线程成功叠加 filter 后，`/proc/*/status` 的
  `Seccomp_filters` 仍固定报告 1；因此 probe 以真实 TRACE event/TSYNC 行为作为安装证据，
  filter count 仅接受“不变或 +1”，不把该字段作为唯一判据。
- 历史 resident/lifecycle/provider/FD 回归：100/100 通过。
- 本轮 Proc Status Level-2 单轮完整回归通过；`pread64`、dup 后 `read`、跨 iovec
  `readv`、非 leader `thread-self/status` 和普通 memfd 负例均通过。
- 清空 App 数据后的 fresh-install 单轮通过；Java resident 自测入口会先创建
  `getFilesDir()`，不再依赖历史 App 数据目录。
- 本轮 close-range 基线 20 轮完整 instrumentation：`20/20`，33.403 秒，无 crash
  buffer 记录。
- close-range 版本最终 100 轮完整 instrumentation：`100/100`，163.037 秒；最终轮
  `proc_status_events=8`、`proc_status_patches=4`、event pair error/dropped/fatal 均为 0。
  设备的 base `close_range` 返回 0，纯 CLOEXEC 对普通和 protected FD 均返回
  `-EINVAL`，flags 0 与 protected FD 相交返回 `-EBUSY`，且无 crash/ANR、
  hookself/tracer 进程残留。
- 迁移前 public v5 最终加固版本完成 fresh-data、`20/20` 和完整 `100/100` instrumentation；
  100 轮测试用时 164.351 秒（命令总耗时 165.29 秒）。`completed iteration 100/100`
  存在，crash buffer、ANR/fatal 检索及 hookself/tracer 进程残留均为空，
  `:app:lintDebug` 通过。
- 日志自测覆盖 sink 内动态 snapshot 发布、protected/internal FD claim/complete、无反馈
  observed 计数、回调重入 BUSY、final drain 的 `HOOKSELF_STATE_STOPPED`、超长路径安全
  truncation、回调内延迟 destroy，以及阻塞 sink 与第二线程 destroy 的等待/摘表顺序。
- framework API 自测的共享 memfd 销毁检查使用 `fstat` 对象身份，不再把多线程环境中的
  FD 数字复用误判为资源未关闭。
- 每轮 ptrace-view event 与 operation 保持严格 2:1；最终轮为 50/25，
  event pair error 0、dropped 0、fatal 0。
- 已覆盖启动前 worker、启动后 worker、每 TID TRACEME、TGID dumpable 共享、
  descendant 隔离和 stop 并发。
- stop 并发 worker 在 detach/commit 周期内未观察到错误 dumpable；停止后应用逻辑值
  0，再由自测恢复入口值 1。

运行综合回归：

```powershell
.\gradlew.bat :app:assembleDebug :app:assembleDebugAndroidTest `
  :app:assembleRelease :hookself:assembleRelease :app:lintDebug --no-daemon
adb -s 3B241FDJH000S4 install -r -t app\build\outputs\apk\debug\app-debug.apk
adb -s 3B241FDJH000S4 install --no-streaming -r -t `
  app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk
adb -s 3B241FDJH000S4 shell am instrument -w -r `
  -e class com.io.hookself.ProbeStressTest#repeatAll `
  -e iterations 1 `
  com.io.hookself.test/androidx.test.runner.AndroidJUnitRunner
```

运行正式 selective 常驻回归（应与 full-ptrace 综合回归分开执行）：

```powershell
adb -s 3B241FDJH000S4 shell pm clear com.io.hookself
adb -s 3B241FDJH000S4 shell am instrument -w -r `
  -e class com.io.hookself.ProbeStressTest#selectiveRuntime `
  -e iterations 1 `
  com.io.hookself.test/androidx.test.runner.AndroidJUnitRunner
```

## 当前边界

- Linux 5.1 fallback 已实现但尚未在真实 5.1 设备验收；当前 USB 结果来自 Linux 6.1，
  网络 ADB `192.168.1.129:5555` 是 Linux 5.10.110，不是 Linux 5.1 目标。
- regular backing 的 create/publish/destroy、snapshot 新旧 FD 语义和 FD-reuse 防护已在
  USB 上通过；断电、文件系统故障和异常杀进程矩阵仍需单独压力验收。
- nested phase-1 resident 只覆盖根 App 直接子进程 leader 的
  `TRACEME -> first exec SIGTRAP -> SETOPTIONS(0/TRACEEXEC) -> later exec event/
  GETEVENTMSG -> CONT/DETACH`。该链路已在 USB `3B241FDJH000S4`（Android 15、Linux 6.1.99、
  SELinux Enforcing）连续 `3/3` 通过；Linux 5.1 仍待实机验收。后代 TGID 独立视图、
  ATTACH/SEIZE、通用 resume/wait、signal/siginfo、memory/regset/syscall-info 和其他
  `PTRACE_SETOPTIONS` event 位仍只属于 logical engine，不由 `runtime_features` 发布。
- proc Level-2 已覆盖真实 status FD 的 `read`/`pread64`/`readv` 完整行输出修补；
  status/maps/smaps 的持久 FD 身份表、proc `getdents64` 过滤及其他 proc 视图仍待补齐。
- 单次 proc status 输出修补容量上限为 4096 字节；为保持返回长度和后续 offset
  不变，`TracerPid` 数字按原宽度写成零（例如 `00000`），不是原生单字符 `0`。
- 内核把真实字节写入用户 buffer 后，到 tracer 在 syscall-exit 完成写回前，其他线程
  仍可能观察到短暂的真实内容窗口。
- `readv` 在 syscall-exit 一次性取得 iovec 描述符快照，聚合、回写和验证复用同一快照；
  取得快照时仍可能与用户线程并发修改 iovec 发生竞态。严格或碎片化读取使用 sealed
  provider。
- `close_range` 的 capability-gated 分段 replay 与 `UNSHARE` 后独立 FD table 跟踪已覆盖。
  其固有边界是：后续 replay segment 失败时，先前成功 segment 的内核副作用会保留；该行为
  与 `close_range(2)` 允许的部分副作用一致。
- openat2/renameat2 的完整 flag、symlink、mount/namespace 和输出路径反向翻译语义仍需补齐。
- 正式 selective 已接入启动提交、class/nr dispatcher、按需 entry-to-exit、后代继承和
  `EXITKILL`。由于 filter 不可卸载，selective destroy 后本进程不能再创建第二个 resident
  runtime；原 tracer 保持 pass-through 直至 App 进程退出。需要完整 detach/重复创建独立
  runtime 的场景继续使用 full-ptrace。
- selective 当前只接受配置时编译的 syscall 选择集合；运行期可刷新 virtual snapshot，
  但新增原 plan 之外的 syscall 规则需要在下次新进程启动时安装新 filter。
- facade 将上述约束落实为明确的 registry 生命周期：full-ptrace 只在 stop 后接受规则变更并
  重建 runtime；selective 首次成功 start 后，注册、注销和 enabled mutation 均返回
  `HOOKSELF_E_INVALID_STATE`。整体 stop/start 仍可在同一 selective runtime 上切换
  pass-through 与已提交策略。
- Linux 5.1 没有 `pidfd_open`；probe 的 direct-child cleanup 使用 wait4 ownership 预检、
  有界 SIGKILL/reap，仍保留预检与 signal 两个 syscall 之间极小的 PID-reuse TOCTOU。
  Linux 5.10+ 正式 runtime 应优先持有 pidfd 关闭该窗口。
- 外部 LLDB/gdbserver/crash_dump 仍不能与框架同时持有同一 TID。
- 日志 sink 为显式 drain 模型；调用方需要安排自己的轮询线程或事件循环，并在 runtime
  第一次消费事件前选定 `RAW_EVENTS` 或 `LOG_DRAIN`。

PRoot 仅用于行为语义参考。本项目的 attach、task、寄存器事务、路径规则和虚拟文件
均为 clean-room 实现，没有复制其 GPL-2.0-or-later 控制流或代码。
