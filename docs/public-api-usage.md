# HookSelf 公共 API 使用指南

当前 public ABI 为 v6。推荐业务代码包含 `<hookself/framework.h>` 并使用
`HookselfFramework`；它统一管理规则注册表、延迟创建的 `HookselfRuntime`、整体启停以及
日志/事件/虚拟文件转发。`<hookself/public_api.h>` 中的底层 runtime API 继续保留，适合需要
一次性静态配置或自行管理 runtime 生命周期的调用方。

## AAR/Prefab 集成

本仓库中的 `:hookself` Android Library 发布 syscall/path 用的 `libhookself.so`、独立的
`libhookself_inline.so` 和 `libhookself_elf.so`，Prefab target 分别为
`hookself::hookself`、`hookself::hookself_inline` 与 `hookself::hookself_elf`。本指南后续内容
使用第一个；函数入口替换见 [ARM64 Inline Hook 设计与使用](inline-hook-design.md)，内存符号解析与
PLT/GOT hook 见 [ARM64 ELF/GOT Hook 设计与使用](elf-got-hook-design.md)。消费模块启用 Prefab，
并与库统一使用 NDK `28.2.13676358` 和 `c++_shared`：

```groovy
android {
    ndkVersion '28.2.13676358'
    buildFeatures { prefab true }
    defaultConfig {
        externalNativeBuild {
            cmake { arguments '-DANDROID_STL=c++_shared' }
        }
    }
}

dependencies {
    implementation project(':hookself')
    // 独立消费时也可使用：implementation files('libs/hookself-release.aar')
}
```

```cmake
find_package(hookself REQUIRED CONFIG)
target_link_libraries(your_native_target PRIVATE hookself::hookself)
```

当前 AAR 只提供 `arm64-v8a`，最低 Android API 为 24。

## 推荐入口：Framework 门面

### 注册 syscall hook 与路径重定向

`hookself_framework_create()` 会深拷贝 config、初始 path/syscall 规则、virtual file descriptor
及其初始内容。create 返回后，调用方可以释放原始数组和内容缓冲区。底层 runtime 在第一次
成功 start 时才创建。

```cpp
#include <asm/unistd.h>
#include <hookself/framework.h>

int32_t CreateHooks(HookselfFramework** output,
                    HookselfRuleHandle* openat_handle,
                    HookselfRuleHandle* redirect_handle) {
    if (output == nullptr || openat_handle == nullptr ||
        redirect_handle == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *output = nullptr;
    *openat_handle = HOOKSELF_INVALID_RULE_HANDLE;
    *redirect_handle = HOOKSELF_INVALID_RULE_HANDLE;

    HookselfConfig config{};
    hookself_framework_default_config(&config);
    config.flags |= HOOKSELF_CONFIG_TRACE_DESCENDANTS;
    config.log_level = HOOKSELF_LOG_TRACE;

    HookselfFramework* framework = nullptr;
    int32_t result = hookself_framework_create(&config, &framework);
    if (result != HOOKSELF_OK) {
        return result;
    }

    HookselfSyscallRule openat{};
    openat.struct_size = sizeof(openat);
    openat.rule_id = 1;
    openat.syscall_number = __NR_openat;
    openat.action = HOOKSELF_SYSCALL_OBSERVE;
    openat.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    result = hookself_framework_register_syscall_rule(
            framework, &openat, 1, openat_handle);
    if (result != HOOKSELF_OK) {
        hookself_framework_destroy(framework);
        return result;
    }

    HookselfRedirectOptions redirect_options{};
    hookself_framework_default_redirect_options(&redirect_options);
    redirect_options.priority = 100;
    result = hookself_framework_register_redirect(
            framework,
            "/virtual/root",
            "/data/user/0/PACKAGE/files/root",
            &redirect_options,
            1,
            redirect_handle);
    if (result != HOOKSELF_OK) {
        hookself_framework_destroy(framework);
        return result;
    }

    *output = framework;
    return HOOKSELF_OK;
}
```

传 null `HookselfRedirectOptions` 等价于默认配置：自动分配 public path rule ID、匹配全部 path
operation、无额外 flags。helper 会自动为 facade 注册的 redirect 开启
`HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT`，但不会改变调用方选择的 failure mode。

`HookselfRuleHandle` 是 facade 内使用的不透明句柄，不等同于 public `rule_id`；
`HOOKSELF_INVALID_RULE_HANDLE`（0）永远不是有效句柄。对于 create config 中已有的规则，或只
保存了 public rule ID 的调用方，可以重新取得 handle：

```cpp
HookselfRuleHandle handle = HOOKSELF_INVALID_RULE_HANDLE;
const int32_t result = hookself_framework_find_rule(
        framework, HOOKSELF_RULE_KIND_SYSCALL, 1, &handle);
```

path 与 syscall 拥有独立的 rule ID namespace，查询时必须传入对应的
`HOOKSELF_RULE_KIND_PATH` 或 `HOOKSELF_RULE_KIND_SYSCALL`。

### 整体启停与单条规则管理

```cpp
HookselfFramework* framework = nullptr;
HookselfRuleHandle openat_handle = HOOKSELF_INVALID_RULE_HANDLE;
HookselfRuleHandle redirect_handle = HOOKSELF_INVALID_RULE_HANDLE;

if (CreateHooks(&framework, &openat_handle, &redirect_handle) == HOOKSELF_OK) {
    if (hookself_framework_start(framework) == HOOKSELF_OK) {
        // Run the observed workload here.
        hookself_framework_stop(framework);
    }

    // full-ptrace 在 stop 后允许变更。下一次 start 会按新规则重建 runtime。
    hookself_framework_set_rule_enabled(framework, openat_handle, 0);
    hookself_framework_unregister_rule(framework, redirect_handle);

    hookself_framework_destroy(framework);
}
```

`hookself_framework_start()` 在已运行时幂等，`hookself_framework_stop()` 在未启动或已停止时
幂等。规则注册、注销和 enabled 状态修改遵循以下边界：

- 第一次成功 start 前，或一次失败的 start 后，规则表可继续编辑。
- full-ptrace 运行期间规则表保持稳定；stop 后的成功变更会丢弃 stopped runtime，下一次
  start 自动重建。
- selective runtime 首次成功 start 后永久冻结规则表，首次 start 前必须确定完整 syscall
  集合及 enabled 状态；disabled 规则仍以 `PASS` 保留在初始 plan。stop/start 只整体停用和
  恢复已提交的策略集合，冻结后也不能把 disabled 规则改为 enabled。
- 不允许的变更返回 `HOOKSELF_E_INVALID_STATE`；与 start/stop 正在交错的变更可返回
  `HOOKSELF_E_BUSY`。

`hookself_framework_is_rule_enabled()` 查询规则状态；`hookself_framework_unregister_rule()`
注销后，旧 handle 不再有效。destroy 由一个调用方发起；请求 destroy 后不再开始新的 facade
调用。

`HOOKSELF_CONFIG_OBSERVE_ALL` 记录所有进入内核的 syscall；只注册指定规则时，事件量更可控。
vDSO 调用不产生 syscall stop。

### 状态与运行期转发

- `hookself_framework_get_state()` 在首次 start 前返回 `HOOKSELF_STATE_CONFIGURED`，runtime
  创建后转发真实生命周期状态。
- `hookself_framework_get_stats()` 在首次 start 前返回 state 为 `CONFIGURED` 的零统计；调用方
  仍需先设置 `HookselfStats::struct_size`。
- `hookself_framework_read_events()`、`hookself_framework_set_log_sink()` 和
  `hookself_framework_drain_logs()` 复用底层 runtime 的单消费者事件模型。sink 可以在 start 前
  保存，runtime 创建时自动安装。
- `hookself_framework_publish_virtual_file()` 与
  `hookself_framework_refresh_virtual_file()` 转发运行期 virtual-file 更新；首次 start 前没有
  runtime，返回 `HOOKSELF_E_INVALID_STATE`。facade 会镜像已经提交的 dynamic snapshot，供
  full-ptrace stop 后的透明 runtime 重建使用。

## 底层 Runtime 进阶

底层 API 使用一次性 config 创建 `HookselfRuntime`。它不提供 facade 的 handle registry，规则
集合直接来自 create 时的 config：

```cpp
#include <asm/unistd.h>
#include <hookself/public_api.h>

HookselfSyscallRule rules[2]{};
rules[0].struct_size = sizeof(rules[0]);
rules[0].rule_id = 1;
rules[0].syscall_number = __NR_openat;
rules[0].action = HOOKSELF_SYSCALL_OBSERVE;
rules[0].phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;

rules[1].struct_size = sizeof(rules[1]);
rules[1].rule_id = 2;
rules[1].syscall_number = __NR_ptrace;
rules[1].action = HOOKSELF_SYSCALL_OBSERVE;
rules[1].phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;

HookselfConfig config{};
hookself_default_config(&config);
config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
config.flags |= HOOKSELF_CONFIG_TRACE_DESCENDANTS;
config.log_level = HOOKSELF_LOG_TRACE;
config.syscall_rules = rules;
config.syscall_rule_count = 2;

HookselfRuntime* runtime = nullptr;
if (hookself_create(&config, &runtime) == HOOKSELF_OK) {
    if (hookself_start(runtime) == HOOKSELF_OK) {
        // Run the observed workload here.
        hookself_stop(runtime);
    }
    hookself_destroy(runtime);
}
```

## Ptrace 视图能力与 nested phase-1 配置

调用方应通过能力查询区分已经接入 resident 的运行能力和仅在逻辑引擎中实现的能力。当前
ptrace capability 版本为 2；nested phase-1 只检查其单独发布的 resident feature：

```cpp
HookselfPtraceCapabilities ptrace_caps{};
ptrace_caps.struct_size = sizeof(ptrace_caps);
if (hookself_get_ptrace_capabilities(&ptrace_caps) != HOOKSELF_OK) {
    HandleHookselfError(HOOKSELF_E_UNSUPPORTED);
}

const uint64_t nested_phase1_required =
        HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC;

if (ptrace_caps.version >= HOOKSELF_PTRACE_CAPABILITIES_VERSION &&
    (ptrace_caps.runtime_features & nested_phase1_required) ==
            nested_phase1_required) {
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                    HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;
}
```

`runtime_features` 是当前 public resident 路径可使用的能力；`engine_features` 是已经编译并通过
native self-test 的逻辑状态机能力。只有出现在 `runtime_features` 的位才可由 App 配置使用。
当前 resident runtime 提供 Level-1 的 TRACEME、dumpable/ptracer、proc status 视图，以及 nested
phase-1 的 `HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC`。后者是唯一 resident 发布的 nested
feature；它不表示 `DESCENDANT_TGID_STATE`、`ATTACH_SEIZE`、`RESUME_CONTROL`、`WAIT_EMULATION`、
`SIGNAL_STATE`、`MEMORY_ACCESS`、`REGSET` 或 `SYSCALL_INFO` 已全部接入 resident。那些位即使出现于
`engine_features`，也不应被调用方当作 resident nested 能力使用。

启用 nested 配置必须同时设置 `HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW`、
`HOOKSELF_CONFIG_TRACE_DESCENDANTS` 和 `HOOKSELF_FAILURE_FAIL_CLOSED`，并使用 full-ptrace
runtime。public 校验拒绝 nested 与 `HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP` 的组合；phase-1
不在 selective runtime 运行。

phase-1 只覆盖根 App 作为逻辑 tracer 时，其**直接创建的子进程 leader** 的下列顺序：

1. 子进程 leader 调用 `PTRACE_TRACEME`，并在该直接父子关系上得到逻辑成功结果。
2. 子进程的第一次 `exec` 被呈现为 `SIGTRAP` signal-delivery stop；根 App 使用该链路的
   `wait4` 或 `waitid` 取得 stop。
3. stop 持有期间，根 App 可调用 `PTRACE_SETOPTIONS`，参数仅可为 `0` 或
   `PTRACE_O_TRACEEXEC`；随后使用 `PTRACE_CONT` 恢复子进程。
4. 设置 `PTRACE_O_TRACEEXEC` 后的后续 `exec` 被呈现为 `PTRACE_EVENT_EXEC`；根 App 可在该
   stop 上调用 `PTRACE_GETEVENTMSG`，然后调用 `PTRACE_CONT` 或 `PTRACE_DETACH`。

`PTRACE_DETACH` 只结束该逻辑关系，框架仍持有为自身 syscall 观测所需的真实 ptrace 关系。
phase-1 不覆盖非 leader、孙代或其他后代、已有逻辑 relation、`PTRACE_ATTACH`/`PTRACE_SEIZE`、
`PTRACE_SYSCALL`、`PTRACE_SINGLESTEP`、`PTRACE_LISTEN`、完整 signal/siginfo、内存访问、regset，
也不支持 `TRACEFORK`、`TRACEVFORK`、`TRACEEXIT` 等其他 `PTRACE_SETOPTIONS` 位。

## 调用上下文与并发边界

public API 会使用 mutex、条件变量和 allocator，不是 async-signal-safe API。signal handler
只记录原子标志或写入调用方自己的 async-signal-safe 通知 FD，由普通 App 线程随后调用
hookself；不要直接从 signal handler 调用本节 API。

facade 会串行化 start/stop、规则表 mutation 和 sink 更新；交错操作在当前生命周期事务完成前
可返回 `HOOKSELF_E_BUSY`。事件、日志和 virtual-file 转发调用会持有对应 runtime lease，避免
stop 后重建 runtime 时把旧调用转发到新一代对象。destroy 从 facade live registry 摘除对象，
阻止新调用登记并等待在途调用退出；每个 facade 只使用一个 destroy 发起者，请求销毁后调用方
不再开始新调用。

internal shared ABI v12 为当前 published runtime 提供 64 个 TID bypass 槽：63 个普通外层
调用槽和 1 个 destroy 保留槽。相同线程的嵌套调用复用已有槽；普通槽用尽时新调用返回
`HOOKSELF_E_BUSY`，保留槽保证 destroy 仍能登记并等待在途调用。full-ptrace stop 通过
retire-owner 仲裁和 publisher barrier 回收 control/lease，完成后另一 runtime 才能 start；
selective filter 不可卸载，因此 selective stop 保留同一 pass-through tracer 和进程级 lease。

`hookself_start()` / `hookself_framework_start()` 不在同步回调内等待外层自身释放 publication
barrier。回调内的嵌套 start 若需要首次发布 control，会返回 `HOOKSELF_E_BUSY`；在回调返回后
由普通调用栈重试。
一个 runtime 已发布 control 时，对另一 runtime 发起的普通调用同样返回
`HOOKSELF_E_BUSY`，避免把不同 shared mapping 混入同一 bypass generation。

## 日志 sink

facade 转发 sink 与 drain，独立文本格式化继续使用 public v6 的无状态 formatter：

```cpp
int32_t hookself_format_event(const HookselfEvent* event, char* message,
                              size_t capacity, size_t* required_size);
int32_t hookself_framework_drain_logs(
        HookselfFramework* framework, size_t max_events,
        size_t* consumed_events, size_t* emitted_logs);
```

底层对应函数为 `hookself_set_log_sink()` 和 `hookself_drain_logs()`，消费规则与 facade 转发
版本相同。

```cpp
static void OnHookselfLog(int32_t level, const HookselfEvent* event,
                          const char* message, void* user_data) {
    // The pointers are valid only for this synchronous callback.
    WriteApplicationLog(level, message, user_data);
}

const int32_t sink_result =
        hookself_framework_set_log_sink(
                framework, OnHookselfLog, app_context);
if (sink_result != HOOKSELF_OK) {
    HandleHookselfError(sink_result);
}

// Call from an App-owned polling thread or event loop.
while (running) {
    size_t consumed = 0;
    size_t emitted = 0;
    const int32_t result =
            hookself_framework_drain_logs(
                    framework, 128, &consumed, &emitted);
    if (result != HOOKSELF_OK) {
        HandleHookselfError(result);
        break;
    }
    if (consumed == 0) {
        SleepBriefly();
    }
}
```

未设置 sink 时，facade/raw drain 都写入 tag 为 `Hookself` 的 Logcat。日志级别按
`ERROR <= WARN <= INFO <= DEBUG <= TRACE` 过滤。drain 会消费事件，包括因级别被过滤而
未输出的事件；`consumed` 是已从 ring 取出的事件数，`emitted` 是通过自定义 sink 或
Logcat 实际输出的日志数。

每个 runtime 只能使用一种事件消费模式。第一次有效调用 `hookself_read_events()` 或
`hookself_framework_read_events()`（即使当时 ring 为空）会选择 `RAW_EVENTS`；第一次在非
`HOOKSELF_LOG_OFF` 配置下调用 raw/facade drain 会选择 `LOG_DRAIN`。RAW 模式下 drain 返回
`HOOKSELF_E_INVALID_STATE`，LOG 模式下 raw read 返回 0，因此二者不能作为两个广播
订阅者使用。

sink 是同步回调。`event` 和 `message` 指针只在当前回调期间有效，需要跨回调保存时由
调用方复制。drain 整次调用持有 reader mutex，因此回调内重入 raw/facade set sink 或 drain
会返回 `HOOKSELF_E_BUSY`。替换 sink 时，只有 set sink 返回 `HOOKSELF_OK` 后，旧回调才不再
执行，调用方才可释放旧 `user_data`；返回错误时旧 sink 和 `user_data` 仍保持注册。传入 null
sink 会恢复默认 Logcat sink 并清除保存的 `user_data`。

drain 执行自定义 sink 或 Logcat 时，会临时 bypass 当前 drain TID 的用户 syscall rule、
ptrace/proc 逻辑视图、路径策略与事件写入。这些 syscall 仍正常进入内核并维持 tracer 的
entry/exit 相位；protected FD 防护和内部 `dup3` 发布协议始终执行，因此 sink 内调用 raw
`hookself_publish_virtual_file()` 或 facade `hookself_framework_publish_virtual_file()` 仍能
原子发布 snapshot，也不会形成 TRACE 反馈循环。

每个 public runtime 调用都在全局注册表中登记 active-call。`hookself_destroy()` 先摘除
runtime，阻止其他线程开始新调用，再等待已登记调用退出。sink 回调内请求 destroy 时，
销毁延迟到当前 drain 清除 bypass 并释放 reader mutex 后执行，该次 drain 返回
`HOOKSELF_E_INVALID_STATE`；请求 destroy 后调用方不再使用该 runtime，并保证每个 runtime
只有一个 destroy 发起者。与 destroy 竞争但尚未登记的调用只返回
`HOOKSELF_E_INVALID_STATE`，不访问已释放对象。

facade 的 destroy 遵守同一调用方约束，并额外等待已登记的 facade 调用和 runtime lease；
回调内的重入 destroy 会请求 raw drain 在本次回调后返回 `HOOKSELF_E_INVALID_STATE`，并延迟到
最外层 facade 调用退出后完成销毁，因此同一批次不会再次调用已释放的 sink `user_data`。

selective destroy 会先把常驻 tracer 切到 pass-through，再短暂冻结其他 App TID，只恢复
destroy owner。owner 对每个 protected FD 发布精确的 TID + FD close capability，close
成功后立即从 registry 删除；全部 FD 释放后通知 tracer 恢复其余 TID，随后才解映射和删除
runtime。该冻结属于 destroy 的内部事务；调用方只需遵守单 destroy 发起者和 destroy 后不再
使用 runtime 的约束。freeze、coverage、exact close 或 release 任一步失败都会走既定
fail-closed 路径，不返回一个部分销毁的 selective runtime。

只需要文本格式化而不消费 runtime ring 时：

```cpp
char message[HOOKSELF_LOG_MESSAGE_CAPACITY];
size_t required = 0;
const int32_t result =
        hookself_format_event(&event, message, sizeof(message), &required);
if (result != HOOKSELF_OK) {
    HandleHookselfError(result);
}
```

`required` 是完整文本所需字节数，不含末尾 NUL；`required` 大于等于容量时，输出已截断
且保持 NUL 终止。若完整路径转义超过缓冲区，formatter 输出不含半截转义序列的结构化
摘要，并加入 `path_truncated=true` / `translated_path_truncated=true`。也可传
`message=nullptr, capacity=0` 只查询长度。路径中的引号、反斜杠、换行和非打印字节会转义。

## 路径规则与虚拟文件

单纯的 prefix redirect 优先使用前文的 `hookself_framework_register_redirect()`。需要
`DENY/PASS`、精确 operation/flags，或要与 virtual file 一次性组合时，也可以在 config 中
提供完整 `HookselfPathRule`；它可通过 `hookself_framework_register_path_rule()` 动态注册，也可
随 config 传给 facade create 或底层 runtime create：

```cpp
HookselfPathRule redirect{};
redirect.struct_size = sizeof(redirect);
redirect.rule_id = 10;
redirect.priority = 100;
redirect.action = HOOKSELF_PATH_REDIRECT;
redirect.operation_mask = HOOKSELF_PATH_OP_ALL;
snprintf(redirect.guest_prefix, sizeof(redirect.guest_prefix),
         "/virtual/root");
snprintf(redirect.host_prefix, sizeof(redirect.host_prefix),
         "/data/user/0/PACKAGE/files/root");

HookselfVirtualFile status{};
status.struct_size = sizeof(status);
status.file_id = 20;
status.provider = HOOKSELF_VFILE_PROC_STATUS;
status.mode = 0444;
snprintf(status.guest_path, sizeof(status.guest_path), "/proc/self/status");

config.flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
                HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW;
config.path_rules = &redirect;
config.path_rule_count = 1;
config.virtual_files = &status;
config.virtual_file_count = 1;
snprintf(config.virtual_backing_dir, sizeof(config.virtual_backing_dir),
         "/data/user/0/PACKAGE/files/hookself-vfiles");
```

facade create 后可用 path `rule_id` 查询初始规则的 handle：

```cpp
HookselfRuleHandle redirect_handle = HOOKSELF_INVALID_RULE_HANDLE;
hookself_framework_find_rule(
        framework, HOOKSELF_RULE_KIND_PATH, 10, &redirect_handle);
```

只要 `virtual_file_count` 非零，`virtual_backing_dir` 就必须是调用方预先创建的、规范绝对的
App 私有目录。框架只在该目录下创建和清理唯一的 runtime 子目录，不创建、重命名或删除
调用方提供的根目录；路径过长或不规范会在 facade/raw create 时被拒绝。

每个 virtual file 在 runtime 私有子目录内使用具名 regular backing。对
`DYNAMIC_SNAPSHOT`，`hookself_publish_virtual_file()` 先准备临时 snapshot，再以
`renameat()` 提交路径，并同步受保护的 stable FD。USB 回归已验证：已打开 FD 继续读取旧
snapshot，新 open 读取新 snapshot；static/dynamic 内容、provider refresh 和 FD-number
复用保护均通过。create、prepare、commit 与 destroy 都校验 FD object identity，避免复用的
FD 被关闭或覆盖。

路径提交成功后，stable-FD 同步若失败，`hookself_publish_virtual_file()` 返回
`HOOKSELF_E_INTERNAL`，但具名路径已经指向新 snapshot；调用方在这种错误后应重新打开并
校验内容，不能假设路径已回滚到旧 snapshot。facade 会根据内部 commit 状态同步这类已提交
snapshot；之后 stop、规则变更和 runtime 重建仍使用新内容，同时保留原错误返回值。

`PROC_STATUS`、`PROC_MAPS` 和 SELinux provider 通过
`hookself_refresh_virtual_file()` 请求刷新，并使用相同的 runtime backing 生命周期。
使用 facade 时分别调用 `hookself_framework_publish_virtual_file()` 和
`hookself_framework_refresh_virtual_file()`；它们在 runtime 尚未创建时返回
`HOOKSELF_E_INVALID_STATE`。

protected FD 防护同时检查原始调用和用户规则 mutation 后的生效 syscall/参数。例如把普通
syscall 通过 `REPLACE_NUMBER` 改成 `close`，或通过 `REPLACE_ARGUMENT` 把目标改成 protected
FD，都会在执行前被二次检查；调用方不应依赖 mutation 绕过 provider/shared control FD 的
完整性策略。

启动时框架会在独立子进程分别探测 `close_range` syscall、`CLOSE_RANGE_CLOEXEC` 和
`CLOSE_RANGE_UNSHARE`。未获得对应能力或携带未知 flag 的调用保持内核原始行为。有效调用的
范围若命中 protected FD，dispatcher 会抑制原调用，并只 replay 非 protected 子区间；
`CLOSE_RANGE_UNSHARE` 先用 `[UINT32_MAX, UINT32_MAX]` sentinel 分离 FD table，再无
`UNSHARE` 地 replay 其余区间。每段成功后才提交 FD identity 状态；后续段失败时停止 replay，
保留内核已经产生的部分副作用。USB 已验证普通/受保护 `CLOEXEC`、flags 为 0 的保护范围、
分段 close 和分段 `UNSHARE` 都返回预期结果，不再以 `-EBUSY` 代替有效请求。
