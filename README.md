# HookSelf

HookSelf 是面向 Android arm64 App 自进程的 native hook 工程。`libhookself.so` 通过子进程
tracer 管理 full-ptrace 或 selective-seccomp runtime，并提供统一的 syscall 规则、启停、路径
重定向、事件、日志和虚拟文件接口；独立的 `libhookself_inline.so` 提供 ARM64 函数入口替换、
original trampoline 和按 handle/target 移除接口；`libhookself_elf.so` 提供已加载 ELF 的
内存动态符号解析，以及按 consumer module + imported symbol 安装和恢复 PLT/GOT hook。

当前支持范围：

- Android `arm64-v8a`
- `minSdk 24`
- NDK `28.2.13676358`
- C++ runtime `c++_shared`
- AAR consumer `minCompileSdk 24`
- syscall/path public ABI v6
- inline-hook public ABI v1
- ELF/GOT-hook public ABI v1

## 项目结构

```text
hookself/                         Android Library，产出 AAR/Prefab
  src/main/cpp/
    CMakeLists.txt
    hookself.exports.map
    hookself_inline.exports.map
    hookself_elf.exports.map
    elf_hook/
      include/hookself/
        elf_hook.h                 内存 ELF 与 PLT/GOT hook C ABI
      internal/                    module、hash、relocation 与权限事务
      elf_hook.cpp                 安装/恢复与 generation 注册表
    inline_hook/
      include/hookself/
        inline_hook.h              ARM64 inline-hook C ABI
      internal/                    编码、重定位与近地址内存
      inline_hook.cpp              安装事务与注册表
    hookself/
      include/hookself/
        framework.h               推荐的统一门面
        public_api.h              底层 runtime ABI
      framework.cpp               facade 编排入口
      runtime_api.cpp             raw runtime 编排入口
      api/framework/              facade 职责片段
      api/runtime/                raw runtime 职责片段
      logging.cpp
      arch/
      platform/
      tracer/
      internal/
    test_support/                 仅 Debug 测试支持

app/                              demo 与 instrumentation 宿主
  src/main/cpp/
    CMakeLists.txt
    demo/
    jni/
```

`:hookself` AAR 同时发布 `libhookself.so`、`libhookself_inline.so`、`libhookself_elf.so` 和
三个 Prefab module。`:app` 的 Release 只构建 `libhookself_demo.so`；Debug 额外构建 native
fixture 做黑盒回归。业务工程不需要复制 demo/JNI 层。三个 HookSelf 动态库互不依赖，消费方
可以只链接需要的模块。

## 接入

同一 Gradle 工程内可直接依赖 library module：

```groovy
dependencies {
    implementation project(':hookself')
}

android {
    ndkVersion '28.2.13676358'
    buildFeatures {
        prefab true
    }
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments '-DANDROID_STL=c++_shared'
            }
        }
    }
}
```

消费已构建 AAR 时，将依赖替换为实际制品位置，例如：

```groovy
dependencies {
    implementation files('libs/hookself-release.aar')
}
```

CMake 侧通过 Prefab 查找并链接：

```cmake
find_package(hookself REQUIRED CONFIG)

target_link_libraries(your_native_target PRIVATE
        hookself::hookself)
```

只使用 ARM64 inline hook 时链接独立 target：

```cmake
target_link_libraries(your_native_target PRIVATE
        hookself::hookself_inline)
```

只使用内存 ELF 解析或 PLT/GOT hook 时链接：

```cmake
target_link_libraries(your_native_target PRIVATE
        hookself::hookself_elf)
```

消费方 native 模块应使用相同 NDK 和 `c++_shared`，并只为 `arm64-v8a` 打包 HookSelf。

## 公共接口

推荐包含 `<hookself/framework.h>` 并使用 `HookselfFramework`：

1. `hookself_framework_default_config()` 初始化配置。
2. `hookself_framework_create()` 创建门面；配置、规则和虚拟文件初始内容会被深拷贝。
3. 注册 syscall/path 规则，或用 `hookself_framework_register_redirect()` 注册路径重定向。
4. `hookself_framework_start()` / `hookself_framework_stop()` 整体启停策略。
5. 使用规则 handle 查询、启停或注销单条规则。
6. `hookself_framework_destroy()` 释放门面及其 runtime。

完整示例、规则变更边界和底层 `HookselfRuntime` 进阶接口见
[公共 API 使用指南](docs/public-api-usage.md)。

### ARM64 inline hook

包含 `<hookself/inline_hook.h>`，使用完整 handle API：

```cpp
using TargetFn = int (*)(int);
static void* original_target = nullptr;

static int ReplacementTarget(int value) {
    auto original = reinterpret_cast<TargetFn>(
            __atomic_load_n(&original_target, __ATOMIC_ACQUIRE));
    return original(value) + 1;
}

HookselfInlineOptions options{};
hookself_inline_default_options(&options);

HookselfInlineHandle handle = HOOKSELF_INLINE_INVALID_HANDLE;
int32_t result = hookself_inline_install(
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(ReplacementTarget),
        &options, &original_target, &handle);

// target DSO 仍保持加载时，original trampoline 在 remove 后仍可调用。
result = hookself_inline_remove(handle);
```

简化调用为 `hookself_inline_hook(target, replacement, &original)`，随后用
`hookself_inline_unhook(target)` 移除。库在 ARM64 入口只原子替换一条 4 字节 `B`，支持
BTI/PAC 入口和常见 PC-relative 指令重定位；无法安全重定位时会在修改 target 前返回 typed
error。原理、全部 API、并发/内存语义和错误表见
[ARM64 Inline Hook 设计与使用](docs/inline-hook-design.md)。

编码、边界和 UB 窄测试可在已连接的 ARM64 设备上重复执行：

```powershell
.\scripts\run-inline-encoding-tests.ps1 -Serial 3B241FDJH000S4
```

inline hook、syscall 观测、路径重定向、ptrace 视图和 proc 虚拟视图是独立能力。安装一个
inline hook 不会创建 syscall runtime；开启路径重定向或日志观测也不会自动安装函数入口 hook，
更不会隐式启用 ptrace view。

### 内存 ELF 解析与 PLT/GOT hook

包含 `<hookself/elf_hook.h>`。`module_name` 是需要改写 GOT 的 caller/consumer DSO，不是导出
函数的 provider：

```cpp
using ReadConfig = int (*)(const char*);
static void* original_read_config = nullptr;
static HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;

static int ReplacementReadConfig(const char* path) {
    auto original = reinterpret_cast<ReadConfig>(
            __atomic_load_n(&original_read_config, __ATOMIC_ACQUIRE));
    return original(path);
}

HookselfElfOptions options{};
hookself_elf_default_options(&options);
int32_t result = hookself_elf_install(
        "libclient.so", "read_config",
        reinterpret_cast<void*>(ReplacementReadConfig),
        &options, &original_read_config, &handle);

result = hookself_elf_remove(handle);
```

`hookself_elf_resolve_symbol()` 从已加载 module 的 `PT_DYNAMIC` 查询 GNU/SysV hash 与
`.dynsym`。hook v1 只处理 ARM64 `DT_JMPREL` 中的 `R_AARCH64_JUMP_SLOT`，使用 64 位 CAS，
临时打开并完整恢复 RELRO 页权限；它不自动接管后续 `dlopen()`，也不隐式启动另外两个
HookSelf 模块。`RECOVERY_REQUIRED` 会同时返回有效 handle，`hookself_elf_find()` 也能找回
该恢复态 handle，调用方应继续 `remove()`/`unhook()` 直到清理完成。多线程 `fork()` 的 child
在 `exec()` 前只使用 `hookself_elf_get_info()` 等不进入 Android loader 的查询；HookSelf 会重置
自己的 registry/patch 锁，但不替换 Bionic 私有 loader mutex。模块匹配、生命周期、错误恢复、
全部 API 和 GitHub 参考审计见
[ARM64 ELF/GOT Hook 设计与使用](docs/elf-got-hook-design.md)。

## 配置总览

配置项必须在 `hookself_framework_create()` 之前确定。Framework 会深拷贝配置、初始规则、
virtual file descriptor 和初始内容；create 以后可以管理 path/syscall 规则，但不能再修改
`HookselfConfig::flags` 或增加 virtual file descriptor。

推荐始终从 facade 默认配置开始：

```cpp
HookselfConfig config{};
hookself_framework_default_config(&config);
```

facade 默认使用 `HOOKSELF_BACKEND_FORK_RAW`、`HOOKSELF_FAILURE_FAIL_CLOSED`、
`HOOKSELF_LOG_INFO`，启用路径、参数和返回值采集，事件容量为 256。底层
`hookself_default_config()` 的 failure mode 是 `HOOKSELF_FAILURE_FULL_PTRACE_FAIL_OPEN`；直接使用
底层 API 时，路径修改、虚拟文件、ptrace/proc 视图、selective runtime 和 syscall mutation
都应显式改为 `HOOKSELF_FAILURE_FAIL_CLOSED`。当前 resident backend 只实现
`HOOKSELF_BACKEND_FORK_RAW`。

### Config fields

| 字段 | 用途 |
|---|---|
| `struct_size` / `abi_version` | 由 default config 初始化，用于结构和 ABI 校验 |
| `backend` | 选择 tracer backend；当前使用 `HOOKSELF_BACKEND_FORK_RAW` |
| `failure_mode` | `FULL_PTRACE_FAIL_OPEN` 只允许 PASS/OBSERVE；`FAIL_CLOSED` 允许改变执行语义并用于所有 view |
| `log_level` | `OFF/ERROR/WARN/INFO/DEBUG/TRACE`，决定 drain 时输出哪些事件 |
| `flags` | 组合下表中的功能开关 |
| `event_capacity` | 事件 ring 容量，范围 1 到 1024 |
| `path_rules` / `path_rule_count` | create 时导入的初始 path 规则，最多 64 条 |
| `syscall_rules` / `syscall_rule_count` | create 时导入的初始 syscall 规则，最多 128 条 |
| `virtual_files` / `virtual_file_count` | create 时导入的 exact-path virtual file，最多 64 个 |
| `virtual_backing_dir` | virtual file 使用的调用方预创建 App 私有根目录 |
| `reserved` | 保持为零，预留后续 ABI 扩展 |

### Config flags

下表依赖列和“常用组合”为便于阅读会省略 `HOOKSELF_CONFIG_` 前缀；`FAIL_CLOSED` 指
`HOOKSELF_FAILURE_FAIL_CLOSED`。

| 配置 | 开启的功能 | 依赖与限制 |
|---|---|---|
| `HOOKSELF_CONFIG_OBSERVE_ALL` | 观测全部真实 syscall stop | 事件量和开销较大；与 selective seccomp 互斥 |
| `HOOKSELF_CONFIG_CAPTURE_PATHS` | 在事件中采集 guest/translated path | facade 默认开启；只影响事件内容 |
| `HOOKSELF_CONFIG_CAPTURE_ARGUMENTS` | 在事件中采集 6 个 syscall 参数 | facade 默认开启；只影响事件内容 |
| `HOOKSELF_CONFIG_CAPTURE_RESULTS` | 在事件中采集返回值和 errno | facade 默认开启；只影响事件内容 |
| `HOOKSELF_CONFIG_TRACE_DESCENDANTS` | 跟踪 fork/vfork 创建的后代进程 | 新线程始终跟踪；ptrace view 对普通后代仍透传真实语义，nested phase-1 是受限例外 |
| `HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT` | 启用用户 path PASS/REDIRECT/DENY policy | 要求 `FAIL_CLOSED`；facade 注册非 PASS path rule 时会自动加入该 flag |
| `HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES` | 启用精确 guest path 的只读虚拟文件 | 要求 `FAIL_CLOSED`；非空 virtual file 数组还要求有效 `virtual_backing_dir` |
| `HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW` | 启用根目标进程的 TRACEME、dumpable/ptracer 和 proc status 视图 | 要求 `FAIL_CLOSED`；不是通用反调试识别器 |
| `HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP` | 只让计划内 syscall 进入 tracer | 要求 `FAIL_CLOSED + TRACE_DESCENDANTS`；与 `OBSERVE_ALL`、`ENABLE_NESTED_PTRACE` 互斥 |
| `HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW` | 启用当前已实现的 `/proc` FD、目录和 maps/smaps 虚拟视图调度 | 要求 `FAIL_CLOSED`；属于部分 `/proc` 覆盖，通常与 proc virtual-file provider 配套 |
| `HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE` | 启用 direct-child leader 的受限 `TRACEME -> exec` 逻辑链路 | 要求 `FAIL_CLOSED + ENABLE_PTRACE_VIEW + TRACE_DESCENDANTS`，且只支持 full-ptrace |

`event_capacity` 的有效范围是 1 到 `HOOKSELF_MAX_EVENT_CAPACITY`。容量不足时事件会被丢弃，
可通过 `HookselfStats::dropped_events` 查询。配置完成后可先调用
`hookself_validate_config()`，也可以直接让 `hookself_framework_create()` 返回校验错误。

### 常用组合

| 目标 | 配置/接口 |
|---|---|
| 只观测指定 syscall | 注册 `HOOKSELF_SYSCALL_OBSERVE` 规则；不需要 `OBSERVE_ALL` |
| 观测全部 syscall | `HOOKSELF_CONFIG_OBSERVE_ALL`，并主动调用日志 drain 或读取 raw events |
| 重定向普通文件或目录 | `hookself_framework_register_redirect()`；facade 自动开启 path policy |
| 严格匹配一个 guest 文件路径 | `ENABLE_VIRTUAL_FILES` + 一个 `HookselfVirtualFile` descriptor |
| 处理根目标的 ptrace/prctl 检查 | `ENABLE_PTRACE_VIEW` |
| 提供稳定 `/proc/self/status` | `ENABLE_PTRACE_VIEW + ENABLE_VIRTUAL_FILES` + `PROC_STATUS` provider |
| 提供 maps/proc 组合视图 | `ENABLE_PROC_VIRTUAL_VIEW + ENABLE_VIRTUAL_FILES` + `PROC_MAPS` provider |
| selective runtime | `TRACE_DESCENDANTS + ENABLE_SELECTIVE_SECCOMP`，并显式注册 syscall 集合 |
| direct-child nested phase-1 | `ENABLE_PTRACE_VIEW + TRACE_DESCENDANTS + ENABLE_NESTED_PTRACE` |

表中的 path redirect、syscall observe、ptrace view 和 proc virtual view 是独立功能；开启其中一个
不会隐式开启其余功能。

## 功能使用

### 1. 观测指定 syscall

`HOOKSELF_SYSCALL_OBSERVE` 只记录事件，不修改参数、syscall number 或返回结果。下面只观测
`openat` 的 entry/exit：

```cpp
#include <asm/unistd.h>
#include <hookself/framework.h>

HookselfConfig config{};
hookself_framework_default_config(&config);
config.log_level = HOOKSELF_LOG_TRACE;

HookselfFramework* framework = nullptr;
int32_t result = hookself_framework_create(&config, &framework);

HookselfSyscallRule openat{};
openat.struct_size = sizeof(openat);
openat.rule_id = 1;
openat.syscall_number = __NR_openat;
openat.action = HOOKSELF_SYSCALL_OBSERVE;
openat.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;

HookselfRuleHandle openat_handle = HOOKSELF_INVALID_RULE_HANDLE;
if (result == HOOKSELF_OK) {
    result = hookself_framework_register_syscall_rule(
            framework, &openat, 1, &openat_handle);
}
if (result == HOOKSELF_OK) {
    result = hookself_framework_start(framework);
}
```

`argument_match_mask == 0` 表示不按参数过滤。需要按参数过滤时，设置 `argument_index`、
`argument_match_mask` 和 `argument_match_value`；匹配公式为
`(argument & mask) == (value & mask)`。

### 2. 观测全部 syscall 并打印日志

```cpp
HookselfConfig config{};
hookself_framework_default_config(&config);
config.flags |= HOOKSELF_CONFIG_OBSERVE_ALL;
config.log_level = HOOKSELF_LOG_TRACE;
config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;
```

设置 log level 不会创建后台日志线程。业务线程或自己的轮询线程需要主动 drain：

```cpp
static void OnHookselfLog(int32_t level, const HookselfEvent* event,
                          const char* message, void* user_data) {
    WriteApplicationLog(level, message, user_data);
}

hookself_framework_set_log_sink(framework, OnHookselfLog, app_context);

size_t consumed = 0;
size_t emitted = 0;
hookself_framework_drain_logs(
        framework, 128, &consumed, &emitted);
```

没有注册 sink 时，`hookself_framework_drain_logs()` 输出到 Logcat 的 `Hookself` tag。一个 runtime
只能选择 `hookself_framework_read_events()` 原始事件或 `hookself_framework_drain_logs()` 日志
drain 其中一种消费模式，首次有效消费会固定模式。sink 是同步回调，`event` 和 `message` 只在
当前回调内有效；需要保存时由调用方复制。

### 3. Syscall 策略动作

| action | 生效阶段 | 用途 |
|---|---|---|
| `HOOKSELF_SYSCALL_PASS` | entry/exit | 显式透传，不修改结果 |
| `HOOKSELF_SYSCALL_OBSERVE` | 按 `phase_mask` | 只产生观测事件 |
| `HOOKSELF_SYSCALL_DENY` | 必须包含 entry | 抑制原调用并以 `deny_errno` 返回失败 |
| `HOOKSELF_SYSCALL_REPLACE_RESULT` | 必须包含 exit | 原调用返回后以 `replacement_value` 替换结果 |
| `HOOKSELF_SYSCALL_REPLACE_NUMBER` | 必须包含 entry | 以 `replacement_syscall_number` 执行另一个 syscall |
| `HOOKSELF_SYSCALL_REPLACE_ARGUMENT` | 必须包含 entry | 将 `argument_index` 指定的参数替换为 `replacement_value` |

例如拒绝 `getppid`：

```cpp
#include <cerrno>

HookselfSyscallRule deny{};
deny.struct_size = sizeof(deny);
deny.rule_id = 2;
deny.syscall_number = __NR_getppid;
deny.action = HOOKSELF_SYSCALL_DENY;
deny.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
deny.deny_errno = EPERM;

HookselfRuleHandle deny_handle = HOOKSELF_INVALID_RULE_HANDLE;
hookself_framework_register_syscall_rule(
        framework, &deny, 1, &deny_handle);
```

所有 mutation 动作要求 `HOOKSELF_FAILURE_FAIL_CLOSED`；facade 默认配置已经满足。内建 runtime
和 protected-FD 策略优先于 ptrace view，ptrace view 优先于用户 syscall rule，用户 syscall
rule 又优先于 path policy。

syscall rule 没有 priority 字段。resident 按发布到 rule bank 的顺序扫描重叠规则：首个匹配的
`PASS` 会立即透传并停止后续 mutation 查找，首个匹配的 mutation 生效，观测事件也只使用首个
匹配 `OBSERVE` 的 rule ID。存在相同 syscall/phase/参数条件时，应主动安排为互斥条件，避免依赖
rule ID 大小决定顺序。

### 4. 重定向目录或单个普通文件

推荐使用 facade helper。它会自动开启 path policy：

```cpp
HookselfRedirectOptions options{};
hookself_framework_default_redirect_options(&options);
options.priority = 100;
options.operation_mask = HOOKSELF_PATH_OP_ALL;

HookselfRuleHandle redirect_handle = HOOKSELF_INVALID_RULE_HANDLE;
int32_t result = hookself_framework_register_redirect(
        framework,
        "/data/user/0/PACKAGE/files/config.json",
        "/data/user/0/PACKAGE/files/redirect/config.json",
        &options,
        1,
        &redirect_handle);
```

把完整文件路径作为 guest/host prefix，可完成常规的单文件到单文件映射。当前 redirect API 是
组件边界 prefix 规则，不是 exact-only 规则：上例不匹配 `config.json.bak`，但语义上仍会匹配
`config.json/...`。普通文件不能作为目录打开，因此通常不产生实际差异；需要严格 exact guest
path 时使用下一节的 virtual file。

路径匹配先选最长组件前缀；长度相同时选择更高 priority；长度和 priority 都相同时，rule bank
中后扫描的规则获胜，因此建议为重叠规则设置不同 priority。`operation_mask` 可以组合
`LOOKUP/READ/WRITE/CREATE/DELETE/RENAME/METADATA/EXECUTE`。完整 `HookselfPathRule` 还支持：

| path action/flag | 用途 |
|---|---|
| `HOOKSELF_PATH_PASS` | 对命中路径显式透传，可覆盖更宽的规则 |
| `HOOKSELF_PATH_REDIRECT` | 将 guest prefix 替换为 host prefix |
| `HOOKSELF_PATH_DENY` | 以 `deny_errno` 拒绝命中操作 |
| `HOOKSELF_PATH_VIRTUAL_FILE` | ABI 预留的用户 path action；当前 resident start 返回 `HOOKSELF_E_NOT_IMPLEMENTED`，请直接配置 `HookselfVirtualFile` |
| `HOOKSELF_PATH_RULE_READ_ONLY` | 写入、创建、删除、重命名和元数据修改返回 `EROFS` |
| `HOOKSELF_PATH_RULE_REVERSE_VISIBLE` | 允许 host path 在 `getcwd`、proc maps 等视图中反向显示为 guest path |
| `HOOKSELF_PATH_RULE_FOLLOW_FINAL` | ABI 当前接受该位；resident 暂无独立于 syscall 自身语义的额外处理 |

只开启路径重定向只影响路径型 syscall。它不会自动开启 `ptrace()`、`prctl()` 或
`/proc/.../status` 的内建 ptrace view。

### 5. 精确路径虚拟文件

virtual file 的 `guest_path` 使用完整路径精确匹配，不需要额外注册 redirect rule。描述符必须
在 framework create 前放入 config，且 backing 根目录必须由调用方提前创建为规范绝对的 App
私有目录：

```cpp
#include <cstdio>

static constexpr char kInitialConfig[] = "{\"enabled\":true}\n";

HookselfVirtualFile file{};
file.struct_size = sizeof(file);
file.file_id = 100;
file.provider = HOOKSELF_VFILE_DYNAMIC_SNAPSHOT;
file.mode = 0444;
file.initial_content = reinterpret_cast<const uint8_t*>(kInitialConfig);
file.initial_content_size = sizeof(kInitialConfig) - 1;
std::snprintf(file.guest_path, sizeof(file.guest_path),
              "/data/user/0/PACKAGE/files/config.json");

HookselfConfig config{};
hookself_framework_default_config(&config);
config.flags |= HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES;
config.virtual_files = &file;
config.virtual_file_count = 1;
std::snprintf(config.virtual_backing_dir,
              sizeof(config.virtual_backing_dir),
              "/data/user/0/PACKAGE/files/hookself-vfiles");
```

start 成功后，动态 snapshot 可原子发布：

```cpp
static constexpr char kUpdatedConfig[] = "{\"enabled\":false}\n";
hookself_framework_publish_virtual_file(
        framework, 100,
        reinterpret_cast<const uint8_t*>(kUpdatedConfig),
        sizeof(kUpdatedConfig) - 1);
```

| provider | 用途 | 运行期更新 |
|---|---|---|
| `HOOKSELF_VFILE_STATIC` | 固定只读内容 | 无 |
| `HOOKSELF_VFILE_DYNAMIC_SNAPSHOT` | 可替换的只读 snapshot | `hookself_framework_publish_virtual_file()` |
| `HOOKSELF_VFILE_PROC_STATUS` | 根据真实 status 生成稳定视图并修补 `TracerPid` | `hookself_framework_refresh_virtual_file()` |
| `HOOKSELF_VFILE_PROC_MAPS` | 根据真实 maps 生成视图 | `hookself_framework_refresh_virtual_file()` |
| `HOOKSELF_VFILE_SELINUX_CONTEXT` | 提供 exact guest path 内容，并模拟 `security.selinux` xattr | `hookself_framework_refresh_virtual_file()` |

每个 `file_id` 和 `guest_path` 必须唯一，mode 不能包含写权限位；只有 `PROC_MAPS` 接受非零
virtual-file flags。publish 只适用于 `DYNAMIC_SNAPSHOT`，refresh 只适用于 provider-backed
文件，并且 facade 的 publish/refresh 都需要首次 start 已成功创建 runtime。

`PROC_MAPS` 可设置 `HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS`，过滤 runtime、scratch 和当前模块
`PT_LOAD` 对应的真实地址区间。virtual file 均为只读，最大内容大小为
`HOOKSELF_MAX_VIRTUAL_FILE_SIZE`。`PROC_STATUS`、`PROC_MAPS` 和 `SELINUX_CONTEXT` 的 exact-path
backing 只用于根目标 TGID；非根 TGID 不使用该 derived backing snapshot，但仍可能受独立启用
的 proc dispatcher 或 xattr policy 影响。`SELINUX_CONTEXT` 还会为已解析的绝对路径模拟
`security.selinux` get/list xattr；该 xattr 规则只要求
`ENABLE_VIRTUAL_FILES`，不要求 `ENABLE_PROC_VIRTUAL_VIEW`。`STATIC` 和 `DYNAMIC_SNAPSHOT`
不受 derived provider 的根 TGID 限制。

### 6. Ptrace 与 `/proc` 视图

只观测 syscall、只打印日志或只重定向普通文件，都不会自动启用 ptrace view。需要在 create
之前显式设置：

```cpp
HookselfConfig config{};
hookself_framework_default_config(&config);
config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW;
```

当前 resident 对根目标 TGID 自动处理：

- 每个 TID 第一次 `PTRACE_TRACEME` 逻辑返回 0，后续返回 `EPERM`。
- `PR_GET_DUMPABLE`、`PR_SET_DUMPABLE` 和 `PR_SET_PTRACER` 使用逻辑进程状态。
- 对真实 `/proc/<pid-or-tid>/status` FD 的 `read`、`pread64`、`readv`，当一次返回包含完整
  `TracerPid:` 行时将数字按原宽度修补为零。

需要严格 status snapshot、任意碎片读取和 maps 视图时，组合 virtual provider：

```cpp
HookselfVirtualFile proc_files[2]{};

proc_files[0].struct_size = sizeof(proc_files[0]);
proc_files[0].file_id = 200;
proc_files[0].provider = HOOKSELF_VFILE_PROC_STATUS;
proc_files[0].mode = 0444;
std::snprintf(proc_files[0].guest_path,
              sizeof(proc_files[0].guest_path), "/proc/self/status");

proc_files[1].struct_size = sizeof(proc_files[1]);
proc_files[1].file_id = 201;
proc_files[1].provider = HOOKSELF_VFILE_PROC_MAPS;
proc_files[1].mode = 0444;
proc_files[1].flags = HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS;
std::snprintf(proc_files[1].guest_path,
              sizeof(proc_files[1].guest_path), "/proc/self/maps");

config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW |
                HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES;
config.virtual_files = proc_files;
config.virtual_file_count = 2;
std::snprintf(config.virtual_backing_dir,
              sizeof(config.virtual_backing_dir),
              "/data/user/0/PACKAGE/files/hookself-vfiles");
```

`ENABLE_PROC_VIRTUAL_VIEW` 仍是部分 `/proc` 覆盖；对每个需要稳定内容的文件应配置对应的
exact-path provider。这些视图只覆盖当前列出的 syscall/proc 路径。Java/JDWP API、时序、
信号、线程名、FD/进程
扫描、自定义检测和未配置的文件/module 视图不会因为开启日志、redirect 或 ptrace view 自动
改变。框架启动前已经执行并缓存的检查也不会被追溯修改。

### 7. 跟踪后代与 nested ptrace phase-1

只需要跟踪新线程/后代的 syscall 时：

```cpp
config.flags |= HOOKSELF_CONFIG_TRACE_DESCENDANTS;
```

后代默认透传真实 ptrace/prctl 语义。需要 direct-child leader 的受限
`PTRACE_TRACEME -> exec-stop -> wait/CONT/DETACH` 链路时，应先查询 resident capability，再开启：

```cpp
HookselfPtraceCapabilities caps{};
caps.struct_size = sizeof(caps);
if (hookself_get_ptrace_capabilities(&caps) == HOOKSELF_OK &&
    caps.version >= HOOKSELF_PTRACE_CAPABILITIES_VERSION &&
    (caps.runtime_features &
     HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC) != 0) {
    config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                    HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;
}
```

nested phase-1 只覆盖根 App 直接创建的子进程 leader，不覆盖非 leader、孙代、通用
`PTRACE_ATTACH/PTRACE_SEIZE`、完整 wait/signal、内存/regset/syscall-info，也不能与 selective
seccomp 同时启用。

### 8. Selective seccomp runtime

只追踪已注册 syscall 和内建策略依赖时：

```cpp
HookselfConfig config{};
hookself_framework_default_config(&config);
config.flags |= HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP;
```

selective 模式必须在第一次 start 前注册完整 syscall 集合，不能设置 `OBSERVE_ALL`。第一次成功
start 后规则表永久冻结；stop 只切换为 pass-through，start 恢复已提交的策略。Linux seccomp
filter 不能卸载，因此 destroy 后最小 tracer 会保持 pass-through，直到目标进程退出。

### 9. 规则、状态和统计管理

| API | 用途 |
|---|---|
| `hookself_framework_default_config()` | 初始化 facade 推荐的 fail-closed 配置 |
| `hookself_framework_default_redirect_options()` | 初始化自动 rule ID、全部 path operation 的 redirect options |
| `hookself_framework_create()` | 深拷贝配置并创建 facade，runtime 延迟到首次 start 创建 |
| `hookself_framework_destroy()` | 释放 facade、runtime 和内部深拷贝；每个实例只由一个调用方发起 destroy |
| `hookself_framework_register_syscall_rule()` | 注册 syscall 规则并返回 handle |
| `hookself_framework_register_path_rule()` | 注册完整 path rule |
| `hookself_framework_register_redirect()` | 便捷注册 guest-to-host redirect |
| `hookself_framework_find_rule()` | 按 path/syscall namespace 和 public `rule_id` 查找 handle |
| `hookself_framework_set_rule_enabled()` | 开启或关闭单条规则 |
| `hookself_framework_is_rule_enabled()` | 查询单条规则状态 |
| `hookself_framework_unregister_rule()` | 注销规则；旧 handle 立即失效 |
| `hookself_framework_start()` / `hookself_framework_stop()` | 整体启停策略 |
| `hookself_framework_get_state()` | 查询 runtime 生命周期状态 |
| `hookself_framework_get_stats()` | 查询事件、观测、redirect、ptrace view、错误和任务统计 |
| `hookself_framework_read_events()` | 读取原始结构化事件 |
| `hookself_framework_set_log_sink()` / `hookself_framework_drain_logs()` | 设置同步 sink 并消费格式化日志 |
| `hookself_framework_publish_virtual_file()` | 发布 dynamic snapshot |
| `hookself_framework_refresh_virtual_file()` | 刷新 provider-backed virtual file |

`HookselfRuleHandle` 是 facade 内部句柄，不等于 public `rule_id`；path 与 syscall 的 rule ID
namespace 彼此独立。初始配置中的规则可以按 kind 和 ID 重新取得 handle：

```cpp
HookselfRuleHandle handle = HOOKSELF_INVALID_RULE_HANDLE;
hookself_framework_find_rule(
        framework, HOOKSELF_RULE_KIND_SYSCALL, 1, &handle);

int32_t enabled = 0;
hookself_framework_is_rule_enabled(framework, handle, &enabled);

hookself_framework_stop(framework);
hookself_framework_set_rule_enabled(framework, handle, 0);
hookself_framework_start(framework);

HookselfStats stats{};
stats.struct_size = sizeof(stats);
hookself_framework_get_stats(framework, &stats);
```

full-ptrace 运行期间规则表保持稳定；先 stop，再启停、注册或注销单条规则，下一次 start 会按
新规则重建 runtime。selective runtime 第一次成功 start 后不再接受规则变更。

## 构建

```powershell
.\gradlew.bat :hookself:assembleRelease --no-daemon
```

Release AAR 输出到：

```text
hookself/build/outputs/aar/hookself-release.aar
```

构建 demo、Debug 测试宿主和 instrumentation：

```powershell
.\gradlew.bat :app:assembleDebug :app:assembleDebugAndroidTest `
  :app:assembleRelease :hookself:assembleRelease --no-daemon
```

`HOOKSELF_BUILD_TEST_SUPPORT` 只在 `:hookself` Debug 构建启用；release 不编译 native
self-test、probe 和测试 JNI bridge。

Release AAR 的 `libhookself.so` 只导出既有 `hookself_*` public API，其中包含 20 个统一 facade
入口；独立 `libhookself_inline.so` 只导出 11 个 `hookself_inline_*` ABI v1 入口，独立
`libhookself_elf.so` 只导出 13 个 `hookself_elf_*` ABI v1 入口。三个 Prefab module 的公共头与
源码一致；Debug-only self-test、fault injection、inline/ELF fixtures 和 JNI bridge 不进入
Release。

## 生命周期边界

- full-ptrace runtime 运行时规则表保持稳定。先 stop，再变更规则；下一次 start 会按新规则重建。
- selective runtime 首次成功 start 后永久冻结规则表。stop 会切换到 pass-through，后续 start
  重新启用首次提交的策略集合。
- selective filter 不能从当前进程卸载。destroy 后最小 tracer 保持 pass-through，直到 App
  进程退出。
- 外部 debugger/crash_dump 不能与框架同时持有同一 TID。
- 日志 drain 与 raw event read 是互斥的事件消费模式，首次有效消费会固定该 runtime 的模式。

## 文档

- [公共 API 使用指南](docs/public-api-usage.md)
- [ARM64 Inline Hook 设计与使用](docs/inline-hook-design.md)
- [实现与验证状态](docs/implementation-status.md)
- [自进程反向 ptrace Hook 设计](docs/ptrace-self-hook-design.md)
