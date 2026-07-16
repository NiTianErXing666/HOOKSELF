# HookSelf ARM64 Inline Hook

`libhookself_inline.so` 是 HookSelf AAR 中独立发布的 ARM64 函数入口替换库。它采用与 Dobby
相近的 C API 使用方式，但实现、注册表、近地址分配、指令重定位和提交事务均为本项目独立实现，
运行时也不依赖 `libhookself.so`。

它只负责 inline hook。syscall 观测、路径重定向、ptrace 视图和 `/proc` 虚拟视图仍由
`libhookself.so` 提供；开启其中任意一项都不会隐式开启其他功能。

## 产物与接入


`:hookself` AAR 同时发布三个独立 Prefab module：

| 功能 | 动态库 | Prefab target | 公共头 |
|---|---|---|---|
| syscall/path framework | `libhookself.so` | `hookself::hookself` | `<hookself/framework.h>` |
| ARM64 inline hook | `libhookself_inline.so` | `hookself::hookself_inline` | `<hookself/inline_hook.h>` |
| ELF symbol + PLT/GOT hook | `libhookself_elf.so` | `hookself::hookself_elf` | `<hookself/elf_hook.h>` |

消费方启用 Prefab 后按需链接：

```cmake
find_package(hookself REQUIRED CONFIG)

target_link_libraries(your_native_target PRIVATE
        hookself::hookself_inline)
```

若同一模块还使用 syscall/path framework，再同时链接 `hookself::hookself`。当前 inline ABI 为
`HOOKSELF_INLINE_ABI_VERSION == 1`，仅发布 `arm64-v8a`，最低 Android API 为 24。

## 基本用法

```cpp
#include <hookself/inline_hook.h>

using ReadValue = int (*)(const char* path);
static void* g_original_read_value = nullptr;

static int ReplacementReadValue(const char* path) {
    // 可在这里调用原实现；target DSO 保持加载时，remove 后仍可调用。
    auto original = reinterpret_cast<ReadValue>(
            __atomic_load_n(&g_original_read_value, __ATOMIC_ACQUIRE));
    return original(path) + 1;
}

HookselfInlineHandle g_handle = HOOKSELF_INLINE_INVALID_HANDLE;

int32_t InstallReadValueHook(ReadValue target) {
    HookselfInlineOptions options{};
    hookself_inline_default_options(&options);

    return hookself_inline_install(
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(ReplacementReadValue),
            &options, &g_original_read_value, &g_handle);
}

int32_t RemoveReadValueHook() {
    return hookself_inline_remove(g_handle);
}
```

也可以使用接近 Dobby 的简化入口：

```cpp
void* original = nullptr;
int32_t result = hookself_inline_hook(target, replacement, &original);
// 简化入口不返回 handle，按 target 移除。
result = hookself_inline_unhook(target);
```

调用约束：

- `target` 必须是 4 字节对齐的 ARM64 函数入口，且位于当前进程可读、可执行的 private
  mapping；本 ABI 不把任意函数中间指令地址作为透明 hook 点。
- `replacement` 必须是 4 字节对齐、保持映射的 ARM64 可执行函数入口。
- 安装和移除期间，调用方必须保证目标 DSO/JIT mapping 不被并发卸载或重建。
- hook 活动期间不得卸载 target、replacement 或 `libhookself_inline.so` 所在 DSO。remove 后，
  target mapping 仍需保留到所有在途 original 调用结束，且只要旧 original 还可能再次调用就必须
  继续保留；replacement mapping 至少保留到其在途调用结束。动态加载场景应持有相应
  `dlopen()` handle，并在 quiesce 后再 `dlclose()`。
- replacement 的函数签名、调用约定和返回类型必须与 target 一致。
- replacement 需要调用原函数且安装期间其他线程仍可执行 target 时，把共享 `void*` 直接作为
  `original` 输出，并像上例一样 acquire-load；库会在入口 patch 生效前 release-store 该地址。
- 不从 signal handler 调用安装、查询或移除 API。

## 公开 API

| API | 作用 |
|---|---|
| `hookself_inline_get_abi_version()` | 返回 inline ABI 版本 |
| `hookself_inline_default_options()` | 初始化 options；保留字段必须为零 |
| `hookself_inline_validate_options()` | 独立校验 options |
| `hookself_inline_get_capabilities()` | 查询架构能力、patch 大小、分支范围和最大活动 hook 数 |
| `hookself_inline_install()` | 安装并返回 original trampoline 与 handle |
| `hookself_inline_hook()` | Dobby 风格简化安装 |
| `hookself_inline_remove()` | 按 handle 移除 |
| `hookself_inline_unhook()` | 按 target 移除 |
| `hookself_inline_find()` | 查询 target 当前的活动 handle |
| `hookself_inline_get_info()` | 查询地址、状态、patch 位置及重定位 flags |
| `hookself_inline_result_string()` | 把 typed result 转为稳定名称 |

`HookselfInlineInfo::state` 在安装后为 `ACTIVE`，成功移除后为 `REMOVED`。removed entry 的槽位
可以被后续安装复用；复用后旧 handle 返回 `HOOKSELF_INLINE_E_NOT_FOUND`。

## ARM64 跳转模型

普通入口只覆盖一条指令：

```text
target                              retained code page
+------------------+               +------------------------------+
| B replacement    |-------------->| near bridge (需要时)         |
| target + 4       |               | BTI C + relocated instruction|
| original body... |<--------------| B target+4                   |
+------------------+               +------------------------------+
```

提交到 target 的始终是一条对齐的 4 字节 `B`，使用 32 位原子 store，不会出现 12/16 字节
入口 patch 被其他线程观察为半写状态。replacement 在分支范围内时 target 可直接跳转；超出范围时，
先跳到 target 附近的 RX bridge，再由 bridge 进入 replacement。

original trampoline 会重定位被覆盖指令并跳回未覆盖的函数体。当前重定位覆盖：

- `B`、`BL`
- `B.cond`
- `CBZ`、`CBNZ`
- `TBZ`、`TBNZ`
- `ADR`、`ADRP`
- literal `LDR W/X/S/D/Q`、`LDRSW`、`PRFM`
- 覆盖窗口内、落在已知指令边界的分支目标

能够保持原编码时优先重新编码 PC-relative immediate；超出原指令范围时使用等价展开或 literal
pool。无法保持语义的指令返回 `HOOKSELF_INLINE_E_RELOCATION` 或
`HOOKSELF_INLINE_E_RANGE`，提交前不会修改 target。

`BLR`、`BLRAA`、`BLRAB`、`BLRAAZ` 和 `BLRABZ` 会把与原 PC 相关的返回地址写入 X30；ABI v1
在它们位于待覆盖入口时保守返回 `HOOKSELF_INLINE_E_RELOCATION`，不直接复制成不同 LR 语义。
`SVC/HVC/SMC/BRK/HLT/DCPS*` 等 exception-generation 指令也会暴露异常发生 PC，复制到
trampoline 会改变 seccomp、ptrace 或 signal 可见地址，因此同样在 prepare 阶段拒绝。

## BTI 与 PAC

- 入口第一条为 BTI 时保留 BTI，在 `target + 4` 提交 branch，保证间接调用仍从原 BTI landing
  pad 进入。
- 入口第一条为 `PACIASP`/`PACIBSP` 时保留 PAC，在 `target + 4` 提交 branch；replacement
  bridge 先执行配对的 `AUTIASP`/`AUTIBSP`，再进入 replacement。
- original trampoline 以 `BTI C` 开头；不支持 BTI 的处理器会把该编码当作 hint。
- `HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI`、`PATCH_AFTER_PAC`、`USES_X17` 和
  `RELOCATION_EXPANDED` 可用于确认实际安装路径。

## 内存与并发语义

- near allocator 读取 `/proc/self/maps`，优先使用 `MAP_FIXED_NOREPLACE`，旧内核回退为安全的
  mmap hint/retry；不会使用 `MAP_FIXED` 覆盖已有 mapping，也不会扫描代码段中的零字节洞。
- 每次安装准备独立代码页。页面先以 RW 生成，cache maintenance 完成后永久切换为 RX；不会在
  已执行页面中继续追加代码。
- target 提交时短暂把原页面权限增加 WRITE 并保留 EXEC，同时从 `/proc/self/smaps` 保留 ARM64
  `PROT_BTI`/`PROT_MTE` 页面属性；compare-exchange 和 I-cache 同步后恢复完整原权限。若系统
  策略拒绝该权限变化，返回 `HOOKSELF_INLINE_E_PROTECTION` 并保持或恢复原指令。
- registry 串行化 install/remove/find/info，最多同时保存 256 个活动 hook。执行 target 或
  original 不获取 registry lock。
- 并发执行与 install/remove 交错时，一次调用只会走完整的旧入口或新入口；API 不承诺所有 CPU
  在返回瞬间都已经开始走同一业务路径。
- remove 不等待 replacement 返回。trampoline 代码页保留到进程结束，因此旧 original 指针
  不会因库回收 trampoline 自身而悬空；original 仍会跳回 target 的未覆盖函数体，在途
  replacement 也仍执行 replacement DSO，调用方必须遵守前述 mapping 生命周期。
- 保留策略以稳定性为优先，反复安装/移除会持续消耗每次安装的一页虚拟地址与物理页；长期高频
  切换应复用一个已安装 hook，并在 replacement 内使用原子开关选择行为。

框架在 install commit 前复核目标原指令。若目标已被其他组件修改，返回
`HOOKSELF_INLINE_E_CONFLICT`，不会覆盖未知 patch。

## 错误处理

所有 public API 返回 `HookselfInlineResult`。常用结果：

| 结果 | 含义 |
|---|---|
| `HOOKSELF_INLINE_OK` | 操作完成 |
| `E_INVALID_ARGUMENT` | null、未对齐、结构大小或保留字段错误 |
| `E_ABI_MISMATCH` | options ABI 与库不一致 |
| `E_ALREADY_INSTALLED` | target 已存在活动 hook |
| `E_NOT_FOUND` | handle/target 不存在或已经移除 |
| `E_NO_MEMORY` | 分支范围内没有可用代码页 |
| `E_RANGE` | 所需 direct branch 无法编码 |
| `E_RELOCATION` | 被覆盖指令无法按当前规则安全重定位 |
| `E_PROTECTION` | mapping 或权限切换不满足要求 |
| `E_CONFLICT` | commit 时目标指令已变化 |
| `E_BUSY` | 活动 hook 已达到 registry 容量 |

安装失败返回时，handle 和 `original` 保持调用前的值，registry 不发布 entry。这允许调用方把
正在使用的全局 original 直接作为重试输出，而不会被重复安装错误清空。若新的 original 地址曾在
commit 前被并发调用方观察到，失败路径仍保留对应 RX 页面，避免产生悬空函数指针。

## 扩展边界

ABI v1 的 options、capabilities 和 info 均保留零字段，后续可以在不暴露内部 C++ 类型的前提下
扩展 allocator policy、额外架构或诊断能力。新增指令重定位必须遵循同一事务边界：先完整解码与
生成，再固化代码页，最后原子提交；任何 prepare 失败都不得改变 target 或 registry。

当前 trampoline 以 RX 匿名页发布并在间接入口写入 `BTI C`，但匿名页本身尚未增加
`PROT_BTI` guarded 属性；这不改变正常调用语义，属于后续 CFI 加固项。动态代码也尚未注册
unwind metadata，异步采样、signal 或崩溃恰好停在 relocated prologue 内时，回溯可能在该帧
中断。当前实机矩阵为 Android 15、4 KiB page；16 KiB page、`PROT_MTE`、FEAT_GCS、far guarded
replacement，以及 syscall/proc runtime 正在运行时交错 install/remove 仍需专门压力矩阵。
