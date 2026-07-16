# HookSelf ARM64 ELF/GOT Hook

`libhookself_elf.so` 是 HookSelf AAR 中独立发布的内存 ELF 符号解析与 ARM64 PLT/GOT hook
库。公共头为 `<hookself/elf_hook.h>`，Prefab target 为 `hookself::hookself_elf`，ABI 为
`HOOKSELF_ELF_ABI_VERSION == 1`。它不依赖 `libhookself.so` 或
`libhookself_inline.so`，消费方可以单独链接。

该库修改的是 **caller/consumer DSO 的 GOT slot**。例如 `libclient.so` 调用
`libprovider.so` 导出的 `read_config()` 时，`module_name` 应传 `libclient.so`，不是
`libprovider.so`。内存符号解析则选择定义该符号的 module。

## 产物与接入

| 功能 | 动态库 | Prefab target | 公共头 |
|---|---|---|---|
| syscall/path framework | `libhookself.so` | `hookself::hookself` | `<hookself/framework.h>` |
| ARM64 inline hook | `libhookself_inline.so` | `hookself::hookself_inline` | `<hookself/inline_hook.h>` |
| ELF symbol + PLT/GOT hook | `libhookself_elf.so` | `hookself::hookself_elf` | `<hookself/elf_hook.h>` |

```cmake
find_package(hookself REQUIRED CONFIG)

target_link_libraries(your_native_target PRIVATE
        hookself::hookself_elf)
```

当前只发布 `arm64-v8a`，最低 Android API 为 24。syscall、inline 与 ELF/GOT 三个模块没有
隐式联动；安装 GOT hook 不会启动 syscall tracer，也不会安装 inline hook。

## 内存符号解析

```cpp
#include <hookself/elf_hook.h>

HookselfElfModuleInfo module{};
module.struct_size = sizeof(module);
int32_t result = hookself_elf_get_module_info(
        "libprovider.so", &module);

HookselfElfSymbolInfo symbol{};
symbol.struct_size = sizeof(symbol);
if (result == HOOKSELF_ELF_OK) {
    result = hookself_elf_resolve_symbol(
            "libprovider.so", "read_config", &symbol);
}

using ReadConfig = int (*)(const char*);
auto read_config = reinterpret_cast<ReadConfig>(symbol.address);
```

解析过程只读取当前进程已经加载 module 的 `PT_DYNAMIC`、`.dynsym`、`.dynstr`、GNU hash
或 SysV hash，不读取磁盘 section header，也不会调用 `dlopen()`。返回的是所选 module 中
**已定义**的动态符号：

- GNU hash 使用 bloom filter、bucket 和 chain；`bloom_shift`、symbol count 和 chain 结尾均有
  边界校验。
- SysV hash 使用 bucket/chain，并用 `DT_HASH::nchain` 约束 dynsym 数量。
- 所有 dynamic 指针、表大小、字符串终止符和符号范围都必须落在可读 `PT_LOAD` 内，并满足
  `Elf64_Dyn/Sym/Rela/Addr` 的自然对齐。
- `SHN_ABS` 返回绝对值；普通定义返回 `load_bias + st_value`。
- TLS、GNU IFUNC resolver 与 `SHN_COMMON` 返回 `UNSUPPORTED_SYMBOL`。
- v1 按 dynstr 基础名称查找，不执行全局 `dlsym` 解析，也不选择 ELF symbol version。

`module_path` 可能截断到固定 ABI 容量；分别检查
`HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED` 或
`HOOKSELF_ELF_SYMBOL_F_PATH_TRUNCATED`。

## 安装与移除 PLT/GOT Hook

```cpp
#include <hookself/elf_hook.h>

using ReadConfig = int (*)(const char*);
static void* g_original_read_config = nullptr;
static HookselfElfHandle g_read_config_hook =
        HOOKSELF_ELF_INVALID_HANDLE;

static int ReplacementReadConfig(const char* path) {
    auto original = reinterpret_cast<ReadConfig>(
            __atomic_load_n(&g_original_read_config, __ATOMIC_ACQUIRE));
    return original(path);
}

int32_t InstallReadConfigHook() {
    HookselfElfOptions options{};
    hookself_elf_default_options(&options);
    return hookself_elf_install(
            "libclient.so",                 // caller / consumer DSO
            "read_config",                  // imported dynsym name
            reinterpret_cast<void*>(ReplacementReadConfig),
            &options,
            &g_original_read_config,
            &g_read_config_hook);
}

int32_t RemoveReadConfigHook() {
    return hookself_elf_remove(g_read_config_hook);
}
```

简化入口与 Dobby 风格一致：

```cpp
int32_t result = hookself_elf_hook(
        "libclient.so", "read_config",
        reinterpret_cast<void*>(ReplacementReadConfig),
        &g_original_read_config);

result = hookself_elf_unhook("libclient.so", "read_config");
```

v1 只扫描 ARM64 `DT_JMPREL` 中的 `Elf64_Rela`，并只接受
`R_AARCH64_JUMP_SLOT`。同一 consumer 内同名的所有 JUMP_SLOT 会作为一个事务提交；如果它们
当前指向不同 original，则返回 `CONFLICT`，避免给 replacement 一个不可靠的单一 original。

## 模块选择

- `module_name == nullptr` 或空字符串选择 `dl_iterate_phdr()` 的首个主程序条目。Android
  bionic 可能给该条目返回 realpath，因此实现不依赖 `dlpi_name` 为空。
- 不含 `/` 时按 basename 精确匹配；出现多个同名 module 时返回 `MODULE_AMBIGUOUS`。
- 含 `/` 时与 `dlpi_name` 做逐字节完整匹配，不做 `realpath()`、路径规范化或 `DT_SONAME`
  匹配；相同 loader path 出现多个实例时同样返回 `MODULE_AMBIGUOUS`。
- API 只处理调用时已经加载的 module，不自动把规则应用到后续 `dlopen()`。

需要处理多个 namespace、同路径多实例或后续加载时，v1 调用方应在自己的加载生命周期中使用
明确路径并逐次安装。未来的 module-by-address、枚举、版本选择和 `dlopen` 订阅将使用新增 API，
不会改变 v1 单 module handle 的含义。

## 提交事务与 RELRO

安装流程如下：

1. 在 `dl_iterate_phdr()` loader 临界区内重新确认 module identity。
2. 解析 `DT_JMPREL/DT_PLTRELSZ/DT_PLTREL`，校验每个 slot 位于可读、原始可写的
   `PT_LOAD`。
3. 从 `/proc/self/maps` 与 `/proc/self/smaps` 读取 slot 当前权限，保留 `PROT_MTE/BTI`
   等架构标志；拒绝 executable 或 shared GOT mapping。
4. 先以 release store 发布 `original`，再为相关页临时添加写权限。
5. 对 8 字节对齐 slot 使用 acquire/release CAS；任一值冲突时逆序回滚。
6. 完整恢复每页原权限。full RELRO 页不会在 API 返回后保持可写。
7. 所有 slot 和权限提交成功后才发布 generation handle。

registry 使用 `INSTALLING/ACTIVE/RECOVERY_REQUIRED/REMOVING/REMOVED/ORPHANED` 状态。代码不在持有 registry
锁时进入 `dl_iterate_phdr()`，避免 DSO 构造/析构阶段的 bionic loader mutex 与 registry
形成 ABBA 锁反转。mutation lease 在 loader callback 内取得，并延续到 `dl_iterate_phdr()`
返回、loader mutex 已释放之后；install/remove 的状态发布和 module-unloaded 后的 `ORPHANED`
转换都受同一 fork gate 保护。事务期间临时屏蔽调用线程的异步信号，避免信号 handler 重入
`fork()` 后等待当前线程自己的 mutation。

正常失败会恢复 `original` 输出并保持 handle 原值。若内核在 slot 已可能可见后持续拒绝权限
恢复，API 返回 `HOOKSELF_ELF_E_RECOVERY_REQUIRED`，同时返回有效 `original` 和 handle，info
状态为 `HOOKSELF_ELF_STATE_RECOVERY_REQUIRED`。此时调用方必须调用 `remove(handle)` 或
`unhook(module, symbol)`；注册表保留原始页权限和 slot 方向，后续恢复不会丢失入口。简化
`hook()` 遇到该结果时使用 `unhook(module, symbol)` 清理。`find(module, symbol)` 同时查询
`ACTIVE` 与 `RECOVERY_REQUIRED`，因此恢复 handle 不会因调用方只保存 module/symbol 而失联。

## 生命周期与并发约束

- 调用方应持有 consumer/provider/replacement 对应的 `dlopen()` handle。安装、查询 slot 和移除
  期间不得并发 `dlclose()`、raw `munmap()` 或同地址重载。
- replacement 的签名、ABI 和返回类型必须与 imported function 相同；replacement 与 GOT 中的
  original 都必须位于 executable mapping。execute-only/XOM mapping 是有效目标，因为 GOT hook
  不读取函数指令。
- replacement 需要 original 时，应像示例一样从安装 API 的共享输出做 acquire load。库保证
  replacement 可见前已 release store original。
- slot 的 64 位切换是原子的；多个 slot 之间不是单条 CPU 指令。事务失败会回滚，但并发调用可能
  在事务期间分别观察提交前或提交后的完整函数指针。
- remove 成功只表示 GOT 已恢复。调用方仍需等待所有在途 replacement 调用结束，之后才能卸载
  replacement、provider、consumer 或 `libhookself_elf.so`。
- `ORPHANED` 表示按 handle 移除时原 module 已不在 loader 列表中；同一 DSO 卸载后又恰好在相同
  地址重载无法仅凭内存身份完全区分，因此持有 loader reference 是正式契约。
- API 使用锁、`dl_iterate_phdr()`、procfs 和 `mprotect`，不具备 async-signal-safe 语义。
- 库注册 `pthread_atfork()` 以阻止 fork 复制半提交 registry，并在 child 重置自身 spin lock。
  多线程 fork 的 child 在 `exec()` 前不得调用会进入 loader 的 module/resolve/install/remove/find
  API；若另一线程正持有 Bionic loader mutex，该私有 mutex 会以原 owner 状态被 child 继承。
  loader-free 的 `get_info()` 可用于检查稳定 handle，然后应 `_exit()` 或 `exec()`。

## v1 边界

以下能力没有混入当前函数型 JUMP_SLOT 契约：

- `R_AARCH64_GLOB_DAT/ABS64`：可能对应 object/data，不能复用“replacement 必须 executable”和
  单一 function original 语义；后续使用独立 generic relocation API。
- APS2 (`DT_ANDROID_RELA/SZ`) 使用 APS2 + SLEB128 压缩 `.rela.dyn`；RELR
  (`DT_RELR/RELRSZ/RELRENT`) 是只表达 RELATIVE、没有 symbol index 的独立位图/地址编码。
  二者都不会承载命名 JUMP_SLOT，因此不影响当前普通 `DT_JMPREL + Elf64_Rela` 扫描；APS2
  只在未来扩展 GLOB_DAT/ABS64 时相关，RELR 只在完整 relocation inventory 中相关。
- 后续 `dlopen` 自动订阅、symbol version selector、IFUNC 执行、磁盘 `.symtab`/debugdata、
  任意 module address selector。

这些限制均在写 GOT 前返回 typed error，不会降级为未校验的指针扫描。

## GitHub 参考审计

实现独立编写，构建未纳入这些项目的源码、头文件或二进制。2026-07-16 审计的固定快照：

| 项目 | 快照 | 许可证 | 重点文件与结论 |
|---|---|---|---|
| [xHook](https://github.com/iqiyi/xHook) | `391d0c4103626bf39d54a1d9c7a10965c82ff8d2` | 主体 MIT；`tree.h` BSD-2、`queue.h` BSD-3；文档 CC BY 4.0 | `xh_elf.c` 展示 dynamic/PLT relocation 扫描；未采用 maps+signal fault guard、普通指针写及缺少完整回滚的做法 |
| [ByteHook](https://github.com/bytedance/bhook) | `a8bd254f6e53022b65136f40d10ae3763b6ef8ad` | 主体 MIT；`third_party/bsd/queue.h` 与 `third_party/lss` BSD-3 | `bh_elf.c`、`bh_elf_relocator.c`、`bh_dl_iterate.c`、`bh_dl_monitor.c` 展示 module cache、原子 GOT 写和加载生命周期；未采用私有 linker 符号、自动 CFI hook 及写后不恢复权限的做法 |
| [xDL](https://github.com/hexhacking/xDL) | `1e0b6254165a2ddcbd32f77a371700c69155acf8` | MIT | `xdl.c` 展示 GNU/SysV dynsym 查询和 IFUNC 分支；采用 hash 原理，但重新实现了 PT_LOAD 边界、对齐、字符串、SHN_ABS 和 module identity 校验 |

在 API 24+ 的范围内，HookSelf 只以公开 `dl_iterate_phdr()` 为模块枚举基线，不解析 Android
linker 私有结构，不监控或替换 `dlopen/dlclose`。这减少了 Android 版本耦合，也让当前库保持
独立、可测试和可扩展。

上表是设计来源审计，不构成源码依赖或许可证替代。若以后引入任何参考项目代码，应同步保留其
copyright 与 license notice；项目公开发布前还需要为 HookSelf 自身确定根级许可证。

## 验证

Debug instrumentation 使用五个真实 DSO：纯 GNU hash provider、纯 SysV hash provider、同时
含两种 hash 且启用 full RELRO/BIND_NOW 的 consumer，以及在 `dlclose` 析构中回调 ELF API 的
loader-lock fixture 和可独立卸载的 consumer。当前 Android 15 ARM64 专项覆盖：

- GNU/SysV 已定义 function 与 object 符号解析；main、basename 和完整 loader path 选择。
- 真实 `R_AARCH64_JUMP_SLOT` 安装、original、find/info、重复安装、remove/unhook。
- 外部 slot 冲突、失败输出、RELRO 恢复、execute-only replacement 和不可执行 GOT 页检查。
- install/remove 两个方向的确定性权限恢复故障；恢复态可由 info/find 查询并完成清理。
- consumer 卸载后的 `MODULE_UNLOADED -> ORPHANED` handle 转换。
- 64 轮并发 install/remove 与数百万次并发调用，无 torn pointer。
- loader 析构回调内 fork、另一线程确定阻塞于 loader mutex，parent/child 均无 registry 锁反转；
  另有并发 mutation/fork 稳定 handle 快照。
- syscall/path 与 inline 库在同一进程加载，三个库保持独立 public ABI。
