#include <jni.h>

#include <dlfcn.h>
#include <elf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "hookself/elf_hook.h"

namespace {

using FixtureFn = uint64_t (*)(uint64_t);

extern "C" {
uint64_t hs_elf_consumer_call_gnu(uint64_t value);
uint64_t hs_elf_consumer_call_sysv(uint64_t value);
uintptr_t hs_elf_consumer_gnu_address(void);
uintptr_t hs_elf_consumer_sysv_address(void);
uintptr_t hs_elf_consumer_gnu_data_address(void);
}

constexpr char kConsumerModule[] = "libhookself_elf_fixture_consumer.so";
constexpr char kGnuModule[] = "libhookself_elf_fixture_gnu.so";
constexpr char kSysvModule[] = "libhookself_elf_fixture_sysv.so";
constexpr char kUnloadableModule[] =
        "libhookself_elf_fixture_unloadable.so";
constexpr char kGnuSymbol[] = "hs_elf_fixture_gnu_target";
constexpr char kSysvSymbol[] = "hs_elf_fixture_sysv_target";
constexpr char kGnuDataSymbol[] = "hs_elf_fixture_gnu_data";
constexpr uint64_t kReplacementDelta = UINT64_C(1000);

std::atomic<void*> g_gnu_original{nullptr};
std::atomic<void*> g_sysv_original{nullptr};
std::atomic<bool> g_lifecycle_entered{false};
std::atomic<bool> g_lifecycle_allow_api{false};
std::atomic<int32_t> g_lifecycle_api_result{HOOKSELF_ELF_E_INTERNAL};
std::atomic<int32_t> g_lifecycle_fork_result{HOOKSELF_ELF_E_INTERNAL};
std::atomic<HookselfElfHandle> g_lifecycle_snapshot_handle{
        HOOKSELF_ELF_INVALID_HANDLE};

void LifecycleDestructorCallback() {
    g_lifecycle_entered.store(true, std::memory_order_release);
    while (!g_lifecycle_allow_api.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    const pid_t child = fork();
    if (child == 0) {
        HookselfElfInfo info{};
        info.struct_size = sizeof(info);
        const HookselfElfHandle expected =
                g_lifecycle_snapshot_handle.load(std::memory_order_acquire);
        const bool valid = expected != HOOKSELF_ELF_INVALID_HANDLE &&
                hookself_elf_get_info(expected, &info) == HOOKSELF_ELF_OK &&
                info.handle == expected &&
                info.state == HOOKSELF_ELF_STATE_REMOVED;
        _exit(valid ? 0 : 72);
    }
    int status = 0;
    pid_t waited = -1;
    if (child > 0) {
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
    }
    g_lifecycle_fork_result.store(
            waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0
                    ? HOOKSELF_ELF_OK
                    : HOOKSELF_ELF_E_INTERNAL,
            std::memory_order_release);
    HookselfElfModuleInfo info{};
    info.struct_size = sizeof(info);
    g_lifecycle_api_result.store(
            hookself_elf_get_module_info(kConsumerModule, &info),
            std::memory_order_release);
}

bool WaitForFlag(const std::atomic<bool>& flag,
                 std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::yield();
    }
    return true;
}

bool WaitForFutexWait(pid_t tid, const std::atomic<bool>& finished,
                      std::chrono::milliseconds timeout) {
    if (tid <= 0) {
        return false;
    }
    std::ostringstream path;
    path << "/proc/self/task/" << tid << "/wchan";
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::ifstream input(path.str());
        std::string wait_channel;
        if (std::getline(input, wait_channel) &&
            wait_channel.find("futex") != std::string::npos) {
            return true;
        }
        std::this_thread::yield();
    }
    return false;
}

struct TestStats {
    uint32_t checks = 0U;
    uint32_t failures = 0U;
    uint32_t gnu_resolves = 0U;
    uint32_t sysv_resolves = 0U;
    uint32_t hook_cycles = 0U;
    uint32_t relro_restores = 0U;
    uint32_t conflict_checks = 0U;
    uint32_t lock_order_checks = 0U;
    uint32_t loader_forks = 0U;
    uint32_t parallel_transactions = 0U;
    uint32_t fork_snapshots = 0U;
    uint32_t xom_replacements = 0U;
    uint32_t recovery_transactions = 0U;
    uint32_t orphaned_modules = 0U;
    uint64_t concurrent_calls = 0U;
    std::string first_failure;

    void Check(bool condition, const std::string& message) {
        ++checks;
        if (condition) {
            return;
        }
        ++failures;
        if (first_failure.empty()) {
            first_failure = message;
        }
    }
};

struct Mapping {
    bool found = false;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool private_mapping = false;

    int Protection() const {
        return (readable ? PROT_READ : 0) |
                (writable ? PROT_WRITE : 0) |
                (executable ? PROT_EXEC : 0);
    }
};

Mapping FindMapping(uintptr_t address) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long long start = 0U;
        unsigned long long end = 0U;
        char permissions[5] = {};
        if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end,
                        permissions) != 3 ||
            address < static_cast<uintptr_t>(start) ||
            address >= static_cast<uintptr_t>(end)) {
            continue;
        }
        return {
                true,
                permissions[0] == 'r',
                permissions[1] == 'w',
                permissions[2] == 'x',
                permissions[3] == 'p'};
    }
    return {};
}

bool StoreSlot(uintptr_t slot, uintptr_t value) {
    const Mapping mapping = FindMapping(slot);
    const long page_size_value = getpagesize();
    if (!mapping.found || !mapping.readable || mapping.executable ||
        !mapping.private_mapping || page_size_value <= 0 ||
        (slot & (alignof(uintptr_t) - 1U)) != 0U) {
        return false;
    }
    const size_t page_size = static_cast<size_t>(page_size_value);
    const uintptr_t page = slot & ~(static_cast<uintptr_t>(page_size) - 1U);
    if (mprotect(reinterpret_cast<void*>(page), page_size,
                 mapping.Protection() | PROT_WRITE) != 0) {
        return false;
    }
    __atomic_store_n(reinterpret_cast<uintptr_t*>(slot), value,
                     __ATOMIC_RELEASE);
    return mprotect(reinterpret_cast<void*>(page), page_size,
                    mapping.Protection()) == 0;
}

uint64_t GnuReplacement(uint64_t value) {
    const auto original = reinterpret_cast<FixtureFn>(
            g_gnu_original.load(std::memory_order_acquire));
    return original == nullptr
            ? UINT64_MAX : original(value) + kReplacementDelta;
}

uint64_t SysvReplacement(uint64_t value) {
    const auto original = reinterpret_cast<FixtureFn>(
            g_sysv_original.load(std::memory_order_acquire));
    return original == nullptr
            ? UINT64_MAX : original(value) + kReplacementDelta;
}

uint64_t ConflictingReplacement(uint64_t value) {
    return value + UINT64_C(0x7000);
}

void* FunctionPointer(FixtureFn function) {
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(function));
}

std::string ResultMessage(const char* operation, int32_t result) {
    std::ostringstream stream;
    stream << operation << '=' << hookself_elf_result_string(result)
           << '(' << result << ')';
    return stream.str();
}

bool InstallRestoreFailureFilter() {
    sock_filter instructions[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                     static_cast<uint32_t>(
                             offsetof(struct seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 4),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                     static_cast<uint32_t>(
                             offsetof(struct seccomp_data, args) +
                             2U * sizeof(uint64_t))),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
            BPF_STMT(BPF_RET | BPF_K,
                     SECCOMP_RET_ERRNO |
                             (EACCES & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{
            static_cast<unsigned short>(
                    sizeof(instructions) / sizeof(instructions[0])),
            instructions};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
            syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
}

void CheckRelro(TestStats* stats, uintptr_t slot, const char* operation) {
    const Mapping mapping = FindMapping(slot);
    stats->Check(mapping.found, std::string(operation) + ": slot not mapped");
    stats->Check(mapping.readable,
                 std::string(operation) + ": slot is not readable");
    stats->Check(!mapping.writable,
                 std::string(operation) + ": RELRO page stayed writable");
    stats->Check(!mapping.executable,
                 std::string(operation) + ": GOT page is executable");
    if (mapping.found && mapping.readable && !mapping.writable &&
        !mapping.executable) {
        ++stats->relro_restores;
    }
}

void TestApiContract(TestStats* stats) {
    stats->Check(hookself_elf_get_abi_version() ==
                         HOOKSELF_ELF_ABI_VERSION,
                 "ABI version mismatch");

    HookselfElfOptions options{};
    hookself_elf_default_options(&options);
    stats->Check(options.struct_size == sizeof(options),
                 "default option size mismatch");
    stats->Check(options.abi_version == HOOKSELF_ELF_ABI_VERSION,
                 "default option ABI mismatch");
    stats->Check(hookself_elf_validate_options(&options) == HOOKSELF_ELF_OK,
                 "default options rejected");
    HookselfElfOptions invalid = options;
    invalid.abi_version += 1U;
    stats->Check(hookself_elf_validate_options(&invalid) ==
                         HOOKSELF_ELF_E_ABI_MISMATCH,
                 "option ABI mismatch was not rejected");
    invalid = options;
    invalid.reserved[0] = 1U;
    stats->Check(hookself_elf_validate_options(&invalid) ==
                         HOOKSELF_ELF_E_INVALID_ARGUMENT,
                 "reserved option was not rejected");

    HookselfElfCapabilities capabilities{};
    capabilities.struct_size = sizeof(capabilities);
    const int32_t result = hookself_elf_get_capabilities(&capabilities);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("capabilities", result));
    const uint64_t required =
            HOOKSELF_ELF_FEATURE_MEMORY_DYNSYM |
            HOOKSELF_ELF_FEATURE_GNU_HASH |
            HOOKSELF_ELF_FEATURE_SYSV_HASH |
            HOOKSELF_ELF_FEATURE_ARM64_JUMP_SLOT |
            HOOKSELF_ELF_FEATURE_ATOMIC_POINTER_CAS |
            HOOKSELF_ELF_FEATURE_RELRO_RESTORE |
            HOOKSELF_ELF_FEATURE_THREAD_SAFE_REGISTRY |
            HOOKSELF_ELF_FEATURE_RECOVERABLE_TRANSACTION;
    stats->Check((capabilities.features & required) == required,
                 "required capability bits missing");
    stats->Check(capabilities.pointer_size == sizeof(void*),
                 "pointer size capability mismatch");
    stats->Check(capabilities.max_active_hooks == 128U,
                 "active hook capacity mismatch");
    stats->Check(capabilities.max_slots_per_hook >= 1U,
                 "slot capacity is zero");
    stats->Check(std::string(hookself_elf_result_string(
                         HOOKSELF_ELF_E_CONFLICT)) == "CONFLICT",
                 "result string mismatch");
}

void TestModuleAndSymbolLookup(TestStats* stats) {
    HookselfElfModuleInfo main_module{};
    main_module.struct_size = sizeof(main_module);
    int32_t result = hookself_elf_get_module_info(nullptr, &main_module);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("main module", result));
    stats->Check((main_module.flags &
                  HOOKSELF_ELF_MODULE_F_MAIN_EXECUTABLE) != 0U,
                 "main executable flag missing");
    HookselfElfModuleInfo empty_main{};
    empty_main.struct_size = sizeof(empty_main);
    const int32_t empty_result = hookself_elf_get_module_info(
            "", &empty_main);
    stats->Check(empty_result == HOOKSELF_ELF_OK,
                 ResultMessage("empty main module", empty_result));
    stats->Check(empty_main.load_bias == main_module.load_bias,
                 "null and empty main module selection differ");
    if (main_module.path[0] != '\0' &&
        (main_module.flags & HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED) == 0U) {
        HookselfElfModuleInfo exact_main{};
        exact_main.struct_size = sizeof(exact_main);
        const int32_t exact_main_result = hookself_elf_get_module_info(
                main_module.path, &exact_main);
        stats->Check(exact_main_result == HOOKSELF_ELF_OK,
                     ResultMessage("exact main module", exact_main_result));
        stats->Check(exact_main.load_bias == main_module.load_bias,
                     "main module path selected another loader entry");
    }

    HookselfElfModuleInfo consumer{};
    consumer.struct_size = sizeof(consumer);
    result = hookself_elf_get_module_info(kConsumerModule, &consumer);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("consumer module", result));
    stats->Check(consumer.load_start < consumer.load_end,
                 "consumer load range is empty");
    stats->Check((consumer.flags & HOOKSELF_ELF_MODULE_F_GNU_HASH) != 0U,
                 "consumer GNU hash flag missing");
    stats->Check((consumer.flags & HOOKSELF_ELF_MODULE_F_SYSV_HASH) != 0U,
                 "consumer SysV hash flag missing");
    stats->Check((consumer.flags & HOOKSELF_ELF_MODULE_F_GNU_RELRO) != 0U,
                 "consumer RELRO flag missing");

    if (result == HOOKSELF_ELF_OK &&
        (consumer.flags & HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED) == 0U) {
        HookselfElfModuleInfo exact{};
        exact.struct_size = sizeof(exact);
        const int32_t exact_result = hookself_elf_get_module_info(
                consumer.path, &exact);
        stats->Check(exact_result == HOOKSELF_ELF_OK,
                     ResultMessage("exact module", exact_result));
        stats->Check(exact.load_bias == consumer.load_bias,
                     "exact path selected another module");
    }

    HookselfElfModuleInfo missing{};
    missing.struct_size = sizeof(missing);
    missing.load_bias = UINTPTR_C(0x1234);
    result = hookself_elf_get_module_info("libhookself_missing.so", &missing);
    stats->Check(result == HOOKSELF_ELF_E_MODULE_NOT_FOUND,
                 "missing module returned wrong result");
    stats->Check(missing.load_bias == UINTPTR_C(0x1234),
                 "failed module lookup modified output");

    HookselfElfSymbolInfo gnu{};
    gnu.struct_size = sizeof(gnu);
    result = hookself_elf_resolve_symbol(kGnuModule, kGnuSymbol, &gnu);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("GNU symbol", result));
    stats->Check(gnu.address == hs_elf_consumer_gnu_address(),
                 "GNU symbol address mismatch");
    stats->Check((gnu.flags & HOOKSELF_ELF_SYMBOL_F_GNU_HASH) != 0U,
                 "GNU lookup flag missing");
    stats->Check(gnu.type == STT_FUNC, "GNU symbol type mismatch");
    if (result == HOOKSELF_ELF_OK) {
        ++stats->gnu_resolves;
    }

    HookselfElfSymbolInfo data{};
    data.struct_size = sizeof(data);
    result = hookself_elf_resolve_symbol(
            kGnuModule, kGnuDataSymbol, &data);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("GNU data", result));
    stats->Check(data.address == hs_elf_consumer_gnu_data_address(),
                 "GNU data symbol address mismatch");
    stats->Check(data.type == STT_OBJECT, "GNU data symbol type mismatch");

    HookselfElfSymbolInfo sysv{};
    sysv.struct_size = sizeof(sysv);
    result = hookself_elf_resolve_symbol(kSysvModule, kSysvSymbol, &sysv);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("SysV symbol", result));
    stats->Check(sysv.address == hs_elf_consumer_sysv_address(),
                 "SysV symbol address mismatch");
    stats->Check((sysv.flags & HOOKSELF_ELF_SYMBOL_F_SYSV_HASH) != 0U,
                 "SysV lookup flag missing");
    if (result == HOOKSELF_ELF_OK) {
        ++stats->sysv_resolves;
    }

    HookselfElfSymbolInfo no_symbol{};
    no_symbol.struct_size = sizeof(no_symbol);
    result = hookself_elf_resolve_symbol(
            kGnuModule, "hs_elf_fixture_missing", &no_symbol);
    stats->Check(result == HOOKSELF_ELF_E_SYMBOL_NOT_FOUND,
                 "missing symbol returned wrong result");
}

void TestHandleLifecycle(TestStats* stats) {
    stats->Check(hs_elf_consumer_call_gnu(5U) == 16U,
                 "GNU baseline mismatch");
    HookselfElfHandle absent = UINT64_C(7);
    int32_t result = hookself_elf_find(kConsumerModule, kGnuSymbol, &absent);
    stats->Check(result == HOOKSELF_ELF_E_NOT_FOUND,
                 "find before install returned wrong result");
    stats->Check(absent == HOOKSELF_ELF_INVALID_HANDLE,
                 "failed find did not clear handle");

    void* original = g_gnu_original.load(std::memory_order_acquire);
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    result = hookself_elf_install(
            kConsumerModule, kGnuSymbol,
            FunctionPointer(GnuReplacement), nullptr, &original, &handle);
    if (result == HOOKSELF_ELF_OK) {
        g_gnu_original.store(original, std::memory_order_release);
    }
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("install", result));
    stats->Check(handle != HOOKSELF_ELF_INVALID_HANDLE,
                 "install returned invalid handle");
    stats->Check(reinterpret_cast<uintptr_t>(original) ==
                         hs_elf_consumer_gnu_address(),
                 "install original mismatch");
    stats->Check(hs_elf_consumer_call_gnu(5U) == 1016U,
                 "replacement call mismatch");

    HookselfElfInfo info{};
    info.struct_size = sizeof(info);
    result = hookself_elf_get_info(handle, &info);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("get info", result));
    stats->Check(info.state == HOOKSELF_ELF_STATE_ACTIVE,
                 "active info state mismatch");
    stats->Check(info.slot_count >= 1U, "hook has no slots");
    stats->Check((info.flags & HOOKSELF_ELF_INFO_F_JUMP_SLOT) != 0U,
                 "JUMP_SLOT info flag missing");
    stats->Check((info.flags & HOOKSELF_ELF_INFO_F_GNU_RELRO) != 0U,
                 "RELRO info flag missing");
    CheckRelro(stats, info.first_slot, "installed");

    HookselfElfHandle duplicate_handle = UINT64_C(0x55);
    void* duplicate_original = reinterpret_cast<void*>(UINTPTR_C(0x1234));
    result = hookself_elf_install(
            kConsumerModule, kGnuSymbol,
            FunctionPointer(GnuReplacement), nullptr,
            &duplicate_original, &duplicate_handle);
    stats->Check(result == HOOKSELF_ELF_E_ALREADY_INSTALLED,
                 "duplicate install returned wrong result");
    stats->Check(duplicate_handle == UINT64_C(0x55),
                 "duplicate install modified handle");
    stats->Check(duplicate_original ==
                         reinterpret_cast<void*>(UINTPTR_C(0x1234)),
                 "duplicate install modified original");

    HookselfElfHandle found = HOOKSELF_ELF_INVALID_HANDLE;
    result = hookself_elf_find(kConsumerModule, kGnuSymbol, &found);
    stats->Check(result == HOOKSELF_ELF_OK && found == handle,
                 "find did not return installed handle");

    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("remove", result));
    stats->Check(hs_elf_consumer_call_gnu(5U) == 16U,
                 "remove did not restore target");
    info = {};
    info.struct_size = sizeof(info);
    result = hookself_elf_get_info(handle, &info);
    stats->Check(result == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_REMOVED,
                 "removed info state mismatch");
    if (result == HOOKSELF_ELF_OK &&
        info.state == HOOKSELF_ELF_STATE_REMOVED) {
        g_lifecycle_snapshot_handle.store(handle, std::memory_order_release);
    }
    CheckRelro(stats, info.first_slot, "removed");
    stats->Check(hookself_elf_remove(handle) == HOOKSELF_ELF_E_NOT_FOUND,
                 "second remove returned wrong result");
    ++stats->hook_cycles;
}

void TestConvenienceAndFailureOutputs(TestStats* stats) {
    void* original = g_sysv_original.load(std::memory_order_acquire);
    int32_t result = hookself_elf_hook(
            kConsumerModule, kSysvSymbol,
            FunctionPointer(SysvReplacement), &original);
    if (result == HOOKSELF_ELF_OK) {
        g_sysv_original.store(original, std::memory_order_release);
    }
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("convenience hook", result));
    stats->Check(hs_elf_consumer_call_sysv(5U) == 1022U,
                 "convenience replacement mismatch");
    result = hookself_elf_unhook(kConsumerModule, kSysvSymbol);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("convenience unhook", result));
    stats->Check(hs_elf_consumer_call_sysv(5U) == 22U,
                 "convenience unhook did not restore target");
    ++stats->hook_cycles;

    HookselfElfHandle sentinel_handle = UINT64_C(0x8899);
    void* sentinel_original = reinterpret_cast<void*>(UINTPTR_C(0x7788));
    result = hookself_elf_install(
            kConsumerModule, "hs_elf_fixture_missing",
            FunctionPointer(GnuReplacement), nullptr,
            &sentinel_original, &sentinel_handle);
    stats->Check(result == HOOKSELF_ELF_E_RELOCATION_NOT_FOUND,
                 "missing relocation returned wrong result");
    stats->Check(sentinel_handle == UINT64_C(0x8899),
                 "failed install modified handle");
    stats->Check(sentinel_original ==
                         reinterpret_cast<void*>(UINTPTR_C(0x7788)),
                 "failed install modified original");
}

void TestConflictDetection(TestStats* stats) {
    void* original = g_gnu_original.load(std::memory_order_acquire);
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    int32_t result = hookself_elf_install(
            kConsumerModule, kGnuSymbol,
            FunctionPointer(GnuReplacement), nullptr, &original, &handle);
    if (result == HOOKSELF_ELF_OK) {
        g_gnu_original.store(original, std::memory_order_release);
    }
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("conflict install", result));
    HookselfElfInfo info{};
    info.struct_size = sizeof(info);
    result = hookself_elf_get_info(handle, &info);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("conflict info", result));
    const bool wrote_conflict = StoreSlot(
            info.first_slot,
            reinterpret_cast<uintptr_t>(FunctionPointer(
                    ConflictingReplacement)));
    stats->Check(wrote_conflict, "failed to create external slot conflict");
    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_E_CONFLICT,
                 "external slot change was not detected");
    info = {};
    info.struct_size = sizeof(info);
    stats->Check(hookself_elf_get_info(handle, &info) == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_ACTIVE,
                 "conflicted hook did not remain active");
    const bool restored_replacement = StoreSlot(
            info.first_slot,
            reinterpret_cast<uintptr_t>(FunctionPointer(GnuReplacement)));
    stats->Check(restored_replacement,
                 "failed to restore replacement after conflict");
    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("conflict cleanup", result));
    stats->Check(hs_elf_consumer_call_gnu(7U) == 18U,
                 "conflict cleanup did not restore target");
    CheckRelro(stats, info.first_slot, "conflict cleanup");
    ++stats->conflict_checks;
    ++stats->hook_cycles;
}

void TestExecuteOnlyReplacement(TestStats* stats) {
    const long page_size_value = getpagesize();
    stats->Check(page_size_value > 0, "invalid page size for XOM fixture");
    if (page_size_value <= 0) {
        return;
    }
    const size_t page_size = static_cast<size_t>(page_size_value);
    void* const page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    stats->Check(page != MAP_FAILED, "XOM fixture mmap failed");
    if (page == MAP_FAILED) {
        return;
    }

    auto* const code = static_cast<uint32_t*>(page);
    code[0] = UINT32_C(0xd503245f);  // BTI C
    code[1] = UINT32_C(0x91007400);  // ADD X0, X0, #29
    code[2] = UINT32_C(0xd65f03c0);  // RET
    __builtin___clear_cache(reinterpret_cast<char*>(page),
                            reinterpret_cast<char*>(page) + 12U);
    const bool protected_xom =
            mprotect(page, page_size, PROT_EXEC) == 0;
    stats->Check(protected_xom, "XOM fixture mprotect failed");
    if (!protected_xom) {
        (void)munmap(page, page_size);
        return;
    }
    const Mapping executable = FindMapping(reinterpret_cast<uintptr_t>(page));
    const bool is_xom = executable.found && executable.executable &&
            !executable.readable && !executable.writable;
    stats->Check(executable.found, "XOM fixture mapping disappeared");
    stats->Check(executable.executable, "XOM fixture is not executable");
    stats->Check(!executable.readable, "XOM fixture remained readable");
    stats->Check(!executable.writable, "XOM fixture remained writable");

    void* original = nullptr;
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    int32_t result = hookself_elf_install(
            kConsumerModule, kGnuSymbol, page, nullptr, &original, &handle);
    bool can_unmap = handle == HOOKSELF_ELF_INVALID_HANDLE;
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("XOM install", result));
    HookselfElfInfo info{};
    info.struct_size = sizeof(info);
    if (result == HOOKSELF_ELF_OK) {
        stats->Check(reinterpret_cast<uintptr_t>(original) ==
                             hs_elf_consumer_gnu_address(),
                     "XOM install original mismatch");
        stats->Check(hs_elf_consumer_call_gnu(7U) == 36U,
                     "XOM replacement call mismatch");
        result = hookself_elf_get_info(handle, &info);
        stats->Check(result == HOOKSELF_ELF_OK,
                     ResultMessage("XOM info", result));
        stats->Check(info.replacement == reinterpret_cast<uintptr_t>(page),
                     "XOM info replacement mismatch");
        int32_t remove_result = hookself_elf_remove(handle);
        if (remove_result == HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
            remove_result = hookself_elf_remove(handle);
        }
        can_unmap = remove_result == HOOKSELF_ELF_OK;
        stats->Check(can_unmap,
                     ResultMessage("XOM remove", remove_result));
        stats->Check(hs_elf_consumer_call_gnu(7U) == 18U,
                     "XOM remove did not restore target");
        if (can_unmap) {
            CheckRelro(stats, info.first_slot, "XOM remove");
            ++stats->hook_cycles;
            if (is_xom) {
                ++stats->xom_replacements;
            }
        }
    } else if (handle != HOOKSELF_ELF_INVALID_HANDLE) {
        int32_t cleanup = hookself_elf_remove(handle);
        if (cleanup == HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
            cleanup = hookself_elf_remove(handle);
        }
        can_unmap = cleanup == HOOKSELF_ELF_OK;
        stats->Check(can_unmap,
                     ResultMessage("XOM failed-install cleanup", cleanup));
    }
    if (can_unmap) {
        stats->Check(munmap(page, page_size) == 0,
                     "XOM fixture munmap failed");
    } else {
        stats->Check(false,
                     "XOM page retained because the hook is still reachable");
    }
}

void TestOrphanedModule(TestStats* stats) {
    void* const module = dlopen(kUnloadableModule, RTLD_NOW | RTLD_LOCAL);
    stats->Check(module != nullptr, "unloadable fixture dlopen failed");
    if (module == nullptr) {
        return;
    }
    auto call = reinterpret_cast<FixtureFn>(
            dlsym(module, "hs_elf_unloadable_call"));
    stats->Check(call != nullptr, "unloadable fixture dlsym failed");
    if (call == nullptr) {
        (void)dlclose(module);
        return;
    }
    stats->Check(call(4U) == 15U, "unloadable fixture baseline mismatch");

    void* original = g_gnu_original.load(std::memory_order_acquire);
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    int32_t result = hookself_elf_install(
            kUnloadableModule, kGnuSymbol,
            FunctionPointer(GnuReplacement), nullptr, &original, &handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("unloadable install", result));
    if (result != HOOKSELF_ELF_OK) {
        (void)dlclose(module);
        return;
    }
    g_gnu_original.store(original, std::memory_order_release);
    stats->Check(call(4U) == 15U + kReplacementDelta,
                 "unloadable replacement mismatch");

    HookselfElfInfo info{};
    info.struct_size = sizeof(info);
    stats->Check(hookself_elf_get_info(handle, &info) == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_ACTIVE,
                 "unloadable active info mismatch");
    const int close_result = dlclose(module);
    stats->Check(close_result == 0, "unloadable fixture dlclose failed");
    if (close_result != 0) {
        (void)hookself_elf_remove(handle);
        return;
    }

    HookselfElfModuleInfo unloaded{};
    unloaded.struct_size = sizeof(unloaded);
    stats->Check(hookself_elf_get_module_info(
                         kUnloadableModule, &unloaded) ==
                         HOOKSELF_ELF_E_MODULE_NOT_FOUND,
                 "unloadable fixture remained in the loader list");
    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_E_MODULE_UNLOADED,
                 ResultMessage("orphan remove", result));
    info = {};
    info.struct_size = sizeof(info);
    const bool orphaned =
            hookself_elf_get_info(handle, &info) == HOOKSELF_ELF_OK &&
            info.state == HOOKSELF_ELF_STATE_ORPHANED;
    stats->Check(orphaned, "unloaded handle was not marked orphaned");
    stats->Check(hookself_elf_remove(handle) == HOOKSELF_ELF_E_NOT_FOUND,
                 "orphaned handle remained removable");
    if (orphaned) {
        ++stats->orphaned_modules;
    }
}

void TestRecoveryTransactions(TestStats* stats) {
    bool filter_installed = false;
    int32_t install_result = HOOKSELF_ELF_E_INTERNAL;
    void* original = nullptr;
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    std::thread install_worker([&] {
        filter_installed = InstallRestoreFailureFilter();
        if (filter_installed) {
            install_result = hookself_elf_install(
                    kConsumerModule, kGnuSymbol,
                    FunctionPointer(GnuReplacement), nullptr,
                    &original, &handle);
        }
    });
    install_worker.join();
    stats->Check(filter_installed,
                 "install recovery seccomp filter failed");
    if (!filter_installed) {
        return;
    }
    stats->Check(install_result == HOOKSELF_ELF_E_RECOVERY_REQUIRED,
                 ResultMessage("injected install recovery", install_result));
    stats->Check(handle != HOOKSELF_ELF_INVALID_HANDLE,
                 "install recovery did not return a handle");
    stats->Check(reinterpret_cast<uintptr_t>(original) ==
                         hs_elf_consumer_gnu_address(),
                 "install recovery original mismatch");
    if (original != nullptr) {
        g_gnu_original.store(original, std::memory_order_release);
    }
    if (install_result != HOOKSELF_ELF_E_RECOVERY_REQUIRED ||
        handle == HOOKSELF_ELF_INVALID_HANDLE) {
        if (handle != HOOKSELF_ELF_INVALID_HANDLE) {
            (void)hookself_elf_remove(handle);
        }
        return;
    }

    HookselfElfInfo info{};
    info.struct_size = sizeof(info);
    int32_t result = hookself_elf_get_info(handle, &info);
    stats->Check(result == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_RECOVERY_REQUIRED,
                 "install recovery info state mismatch");
    HookselfElfHandle found = HOOKSELF_ELF_INVALID_HANDLE;
    result = hookself_elf_find(kConsumerModule, kGnuSymbol, &found);
    stats->Check(result == HOOKSELF_ELF_OK && found == handle,
                 "find did not return install recovery handle");
    stats->Check(FindMapping(info.first_slot).writable,
                 "install recovery did not retain writable recovery page");
    stats->Check(hs_elf_consumer_call_gnu(7U) == 18U,
                 "install recovery did not roll back the slot");
    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("install recovery cleanup", result));
    if (result != HOOKSELF_ELF_OK) {
        return;
    }
    info = {};
    info.struct_size = sizeof(info);
    stats->Check(hookself_elf_get_info(handle, &info) == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_REMOVED,
                 "install recovery cleanup state mismatch");
    stats->Check(hs_elf_consumer_call_gnu(7U) == 18U,
                 "install recovery cleanup changed target");
    CheckRelro(stats, info.first_slot, "install recovery cleanup");
    ++stats->recovery_transactions;

    original = g_gnu_original.load(std::memory_order_acquire);
    handle = HOOKSELF_ELF_INVALID_HANDLE;
    result = hookself_elf_install(
            kConsumerModule, kGnuSymbol,
            FunctionPointer(GnuReplacement), nullptr, &original, &handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("remove recovery install", result));
    if (result != HOOKSELF_ELF_OK) {
        return;
    }
    g_gnu_original.store(original, std::memory_order_release);

    filter_installed = false;
    int32_t remove_result = HOOKSELF_ELF_E_INTERNAL;
    std::thread remove_worker([&] {
        filter_installed = InstallRestoreFailureFilter();
        if (filter_installed) {
            remove_result = hookself_elf_remove(handle);
        }
    });
    remove_worker.join();
    stats->Check(filter_installed,
                 "remove recovery seccomp filter failed");
    stats->Check(remove_result == HOOKSELF_ELF_E_RECOVERY_REQUIRED,
                 ResultMessage("injected remove recovery", remove_result));
    if (!filter_installed ||
        remove_result != HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
        (void)hookself_elf_remove(handle);
        return;
    }

    info = {};
    info.struct_size = sizeof(info);
    result = hookself_elf_get_info(handle, &info);
    stats->Check(result == HOOKSELF_ELF_OK &&
                         info.state == HOOKSELF_ELF_STATE_RECOVERY_REQUIRED,
                 "remove recovery info state mismatch");
    found = HOOKSELF_ELF_INVALID_HANDLE;
    result = hookself_elf_find(kConsumerModule, kGnuSymbol, &found);
    stats->Check(result == HOOKSELF_ELF_OK && found == handle,
                 "find did not return remove recovery handle");
    stats->Check(FindMapping(info.first_slot).writable,
                 "remove recovery did not retain writable recovery page");
    stats->Check(hs_elf_consumer_call_gnu(7U) == 1018U,
                 "remove recovery did not restore replacement");
    result = hookself_elf_remove(handle);
    stats->Check(result == HOOKSELF_ELF_OK,
                 ResultMessage("remove recovery cleanup", result));
    if (result != HOOKSELF_ELF_OK) {
        return;
    }
    info = {};
    info.struct_size = sizeof(info);
    const bool removed_info =
            hookself_elf_get_info(handle, &info) == HOOKSELF_ELF_OK &&
            info.state == HOOKSELF_ELF_STATE_REMOVED;
    stats->Check(removed_info,
                 "remove recovery cleanup state mismatch");
    if (removed_info) {
        g_lifecycle_snapshot_handle.store(handle, std::memory_order_release);
    }
    stats->Check(hs_elf_consumer_call_gnu(7U) == 18U,
                 "remove recovery cleanup did not restore target");
    CheckRelro(stats, info.first_slot, "remove recovery cleanup");
    ++stats->recovery_transactions;
    ++stats->hook_cycles;
}

void TestLoaderLockOrdering(TestStats* stats) {
    using ArmFn = void (*)(void (*)(void));
    void* const lifecycle = dlopen(
            "libhookself_elf_fixture_lifecycle.so", RTLD_NOW | RTLD_LOCAL);
    stats->Check(lifecycle != nullptr, "lifecycle fixture dlopen failed");
    if (lifecycle == nullptr) {
        return;
    }
    auto arm = reinterpret_cast<ArmFn>(dlsym(
            lifecycle, "hs_elf_lifecycle_arm"));
    stats->Check(arm != nullptr, "lifecycle fixture dlsym failed");
    if (arm == nullptr) {
        (void)dlclose(lifecycle);
        return;
    }

    g_lifecycle_entered.store(false, std::memory_order_release);
    g_lifecycle_allow_api.store(false, std::memory_order_release);
    g_lifecycle_api_result.store(HOOKSELF_ELF_E_INTERNAL,
                                 std::memory_order_release);
    g_lifecycle_fork_result.store(HOOKSELF_ELF_E_INTERNAL,
                                  std::memory_order_release);
    arm(LifecycleDestructorCallback);

    std::atomic<int> close_result{-1};
    std::thread closer([&] {
        close_result.store(dlclose(lifecycle), std::memory_order_release);
    });
    const bool destructor_entered = WaitForFlag(
            g_lifecycle_entered, std::chrono::milliseconds(2000));
    stats->Check(destructor_entered,
                 "lifecycle destructor did not run under dlclose");

    std::atomic<bool> installer_started{false};
    std::atomic<bool> installer_finished{false};
    std::atomic<pid_t> installer_tid{-1};
    int32_t install_result = HOOKSELF_ELF_E_INTERNAL;
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    void* original = g_gnu_original.load(std::memory_order_acquire);
    std::thread installer([&] {
        installer_tid.store(static_cast<pid_t>(syscall(__NR_gettid)),
                            std::memory_order_relaxed);
        installer_started.store(true, std::memory_order_release);
        install_result = hookself_elf_install(
                kConsumerModule, kGnuSymbol,
                FunctionPointer(GnuReplacement), nullptr,
                &original, &handle);
        installer_finished.store(true, std::memory_order_release);
    });
    stats->Check(WaitForFlag(installer_started,
                             std::chrono::milliseconds(2000)),
                 "loader-order installer did not start");
    stats->Check(WaitForFutexWait(
                         installer_tid.load(std::memory_order_relaxed),
                         installer_finished, std::chrono::milliseconds(2000)),
                 "loader-order installer did not block on the loader lock");
    g_lifecycle_allow_api.store(true, std::memory_order_release);
    closer.join();
    installer.join();

    stats->Check(close_result.load(std::memory_order_acquire) == 0,
                 "lifecycle fixture dlclose failed");
    stats->Check(g_lifecycle_api_result.load(std::memory_order_acquire) ==
                         HOOKSELF_ELF_OK,
                 "ELF API failed inside loader destructor callback");
    const bool loader_fork_ok =
            g_lifecycle_fork_result.load(std::memory_order_acquire) ==
                    HOOKSELF_ELF_OK;
    stats->Check(loader_fork_ok,
                 "loader callback fork inherited an unstable registry");
    if (loader_fork_ok) {
        ++stats->loader_forks;
    }
    stats->Check(install_result == HOOKSELF_ELF_OK,
                 ResultMessage("loader-order install", install_result));
    if (install_result == HOOKSELF_ELF_OK) {
        g_gnu_original.store(original, std::memory_order_release);
        const int32_t remove = hookself_elf_remove(handle);
        stats->Check(remove == HOOKSELF_ELF_OK,
                     ResultMessage("loader-order remove", remove));
        if (remove == HOOKSELF_ELF_OK) {
            ++stats->hook_cycles;
        }
    }
    ++stats->lock_order_checks;
}

void TestParallelTransactions(TestStats* stats) {
    constexpr uint32_t kRounds = 16U;
    for (uint32_t round = 0U; round < kRounds; ++round) {
        std::atomic<uint32_t> ready{0U};
        std::atomic<bool> start{false};
        int32_t gnu_result = HOOKSELF_ELF_E_INTERNAL;
        int32_t sysv_result = HOOKSELF_ELF_E_INTERNAL;
        HookselfElfHandle gnu_handle = HOOKSELF_ELF_INVALID_HANDLE;
        HookselfElfHandle sysv_handle = HOOKSELF_ELF_INVALID_HANDLE;
        void* gnu_original = g_gnu_original.load(std::memory_order_acquire);
        void* sysv_original = g_sysv_original.load(std::memory_order_acquire);

        std::thread gnu_installer([&] {
            ready.fetch_add(1U, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            gnu_result = hookself_elf_install(
                    kConsumerModule, kGnuSymbol,
                    FunctionPointer(GnuReplacement), nullptr,
                    &gnu_original, &gnu_handle);
        });
        std::thread sysv_installer([&] {
            ready.fetch_add(1U, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            sysv_result = hookself_elf_install(
                    kConsumerModule, kSysvSymbol,
                    FunctionPointer(SysvReplacement), nullptr,
                    &sysv_original, &sysv_handle);
        });
        while (ready.load(std::memory_order_acquire) != 2U) {
            std::this_thread::yield();
        }
        start.store(true, std::memory_order_release);
        gnu_installer.join();
        sysv_installer.join();
        stats->Check(gnu_result == HOOKSELF_ELF_OK,
                     ResultMessage("parallel GNU install", gnu_result));
        stats->Check(sysv_result == HOOKSELF_ELF_OK,
                     ResultMessage("parallel SysV install", sysv_result));
        if (gnu_result != HOOKSELF_ELF_OK ||
            sysv_result != HOOKSELF_ELF_OK) {
            if (gnu_result == HOOKSELF_ELF_OK) {
                (void)hookself_elf_remove(gnu_handle);
            }
            if (sysv_result == HOOKSELF_ELF_OK) {
                (void)hookself_elf_remove(sysv_handle);
            }
            break;
        }
        g_gnu_original.store(gnu_original, std::memory_order_release);
        g_sysv_original.store(sysv_original, std::memory_order_release);

        int32_t gnu_remove = HOOKSELF_ELF_E_INTERNAL;
        int32_t sysv_remove = HOOKSELF_ELF_E_INTERNAL;
        std::thread gnu_remover([&] {
            gnu_remove = hookself_elf_remove(gnu_handle);
        });
        std::thread sysv_remover([&] {
            sysv_remove = hookself_elf_remove(sysv_handle);
        });
        gnu_remover.join();
        sysv_remover.join();
        stats->Check(gnu_remove == HOOKSELF_ELF_OK,
                     ResultMessage("parallel GNU remove", gnu_remove));
        stats->Check(sysv_remove == HOOKSELF_ELF_OK,
                     ResultMessage("parallel SysV remove", sysv_remove));
        if (gnu_remove != HOOKSELF_ELF_OK ||
            sysv_remove != HOOKSELF_ELF_OK) {
            break;
        }
        ++stats->parallel_transactions;
        stats->hook_cycles += 2U;
    }
    stats->Check(hs_elf_consumer_call_gnu(3U) == 14U,
                 "parallel GNU cleanup mismatch");
    stats->Check(hs_elf_consumer_call_sysv(3U) == 20U,
                 "parallel SysV cleanup mismatch");
}

void TestForkSnapshots(TestStats* stats) {
    constexpr uint32_t kForks = 8U;
    void* stable_original = g_sysv_original.load(std::memory_order_acquire);
    HookselfElfHandle stable_handle = HOOKSELF_ELF_INVALID_HANDLE;
    const int32_t stable_install = hookself_elf_install(
            kConsumerModule, kSysvSymbol,
            FunctionPointer(SysvReplacement), nullptr,
            &stable_original, &stable_handle);
    stats->Check(stable_install == HOOKSELF_ELF_OK,
                 ResultMessage("fork stable install", stable_install));
    if (stable_install != HOOKSELF_ELF_OK) {
        return;
    }
    g_sysv_original.store(stable_original, std::memory_order_release);

    std::atomic<bool> running{true};
    std::atomic<uint32_t> mutation_cycles{0U};
    std::atomic<uint32_t> mutation_failures{0U};
    std::thread mutator([&] {
        while (running.load(std::memory_order_acquire)) {
            void* original = g_gnu_original.load(std::memory_order_acquire);
            HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
            const int32_t install = hookself_elf_install(
                    kConsumerModule, kGnuSymbol,
                    FunctionPointer(GnuReplacement), nullptr,
                    &original, &handle);
            if (install == HOOKSELF_ELF_E_BUSY) {
                continue;
            }
            if (install != HOOKSELF_ELF_OK) {
                mutation_failures.fetch_add(1U, std::memory_order_relaxed);
                continue;
            }
            g_gnu_original.store(original, std::memory_order_release);
            int32_t remove = HOOKSELF_ELF_E_BUSY;
            while (remove == HOOKSELF_ELF_E_BUSY) {
                remove = hookself_elf_remove(handle);
                if (remove == HOOKSELF_ELF_E_BUSY) {
                    std::this_thread::yield();
                }
            }
            if (remove != HOOKSELF_ELF_OK) {
                mutation_failures.fetch_add(1U, std::memory_order_relaxed);
                break;
            }
            mutation_cycles.fetch_add(1U, std::memory_order_release);
        }
    });
    const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(2);
    while (mutation_cycles.load(std::memory_order_acquire) == 0U &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    stats->Check(mutation_cycles.load(std::memory_order_acquire) > 0U,
                 "fork mutator did not complete a cycle");

    std::atomic<uint32_t> fork_successes{0U};
    std::atomic<uint32_t> fork_failures{0U};
    const auto run_forks = [&] {
        for (uint32_t iteration = 0U; iteration < kForks / 2U;
             ++iteration) {
            const pid_t child = fork();
            if (child == 0) {
                HookselfElfInfo info{};
                info.struct_size = sizeof(info);
                const int32_t get_info =
                        hookself_elf_get_info(stable_handle, &info);
                const uint64_t gnu_value = hs_elf_consumer_call_gnu(6U);
                const uint64_t sysv_value = hs_elf_consumer_call_sysv(6U);
                const bool valid = get_info == HOOKSELF_ELF_OK &&
                        info.state == HOOKSELF_ELF_STATE_ACTIVE &&
                        info.handle == stable_handle &&
                        sysv_value == 23U + kReplacementDelta &&
                        (gnu_value == 17U ||
                         gnu_value == 17U + kReplacementDelta);
                _exit(valid ? 0 : 71);
            }
            if (child <= 0) {
                fork_failures.fetch_add(1U, std::memory_order_relaxed);
                continue;
            }
            int status = 0;
            const pid_t waited = waitpid(child, &status, 0);
            if (waited == child && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0) {
                fork_successes.fetch_add(1U, std::memory_order_relaxed);
            } else {
                fork_failures.fetch_add(1U, std::memory_order_relaxed);
            }
        }
    };
    std::thread forker_a(run_forks);
    std::thread forker_b(run_forks);
    forker_a.join();
    forker_b.join();
    stats->fork_snapshots = fork_successes.load(std::memory_order_relaxed);
    stats->Check(fork_failures.load(std::memory_order_relaxed) == 0U,
                 "fork child inherited a transient ELF hook state");
    stats->Check(stats->fork_snapshots == kForks,
                 "concurrent fork snapshot count mismatch");
    running.store(false, std::memory_order_release);
    mutator.join();
    stats->Check(mutation_failures.load(std::memory_order_relaxed) == 0U,
                 "fork mutator operation failed");
    stats->Check(hs_elf_consumer_call_gnu(4U) == 15U,
                 "fork mutator cleanup mismatch");
    const int32_t stable_remove = hookself_elf_remove(stable_handle);
    stats->Check(stable_remove == HOOKSELF_ELF_OK,
                 ResultMessage("fork stable remove", stable_remove));
    stats->Check(hs_elf_consumer_call_sysv(4U) == 21U,
                 "fork stable cleanup mismatch");
    if (stable_remove == HOOKSELF_ELF_OK) {
        ++stats->hook_cycles;
    }
}

void TestConcurrentSwitching(TestStats* stats) {
    constexpr uint32_t kCycles = 64U;
    constexpr size_t kWorkers = 4U;
    std::atomic<bool> running{true};
    std::atomic<uint64_t> calls{0U};
    std::atomic<uint64_t> bad_results{0U};
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);
    for (size_t worker = 0U; worker < kWorkers; ++worker) {
        workers.emplace_back([&] {
            uint64_t argument = 1U;
            while (running.load(std::memory_order_acquire)) {
                const uint64_t value = hs_elf_consumer_call_gnu(argument);
                if (value != argument + 11U &&
                    value != argument + 11U + kReplacementDelta) {
                    bad_results.fetch_add(1U, std::memory_order_relaxed);
                }
                calls.fetch_add(1U, std::memory_order_relaxed);
                argument = argument == 127U ? 1U : argument + 1U;
            }
        });
    }

    uint32_t completed = 0U;
    for (uint32_t cycle = 0U; cycle < kCycles; ++cycle) {
        void* original = g_gnu_original.load(std::memory_order_acquire);
        HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
        const int32_t install = hookself_elf_install(
                kConsumerModule, kGnuSymbol,
                FunctionPointer(GnuReplacement), nullptr, &original, &handle);
        if (install != HOOKSELF_ELF_OK) {
            stats->Check(false, ResultMessage("concurrent install", install));
            break;
        }
        g_gnu_original.store(original, std::memory_order_release);
        for (uint32_t spin = 0U; spin < 4U; ++spin) {
            std::this_thread::yield();
        }
        const int32_t remove = hookself_elf_remove(handle);
        if (remove != HOOKSELF_ELF_OK) {
            stats->Check(false, ResultMessage("concurrent remove", remove));
            (void)hookself_elf_unhook(kConsumerModule, kGnuSymbol);
            break;
        }
        ++completed;
    }
    running.store(false, std::memory_order_release);
    for (std::thread& worker : workers) {
        worker.join();
    }
    stats->concurrent_calls = calls.load(std::memory_order_relaxed);
    stats->Check(completed == kCycles, "concurrent cycle count mismatch");
    stats->Check(stats->concurrent_calls > 0U,
                 "concurrent workers made no calls");
    stats->Check(bad_results.load(std::memory_order_relaxed) == 0U,
                 "concurrent call observed a torn slot value");
    stats->Check(hs_elf_consumer_call_gnu(9U) == 20U,
                 "concurrent cleanup did not restore target");
    stats->hook_cycles += completed;
}

std::string EscapeJson(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (char character : value) {
        if (character == '\\' || character == '"') {
            escaped.push_back('\\');
        }
        if (character == '\n' || character == '\r') {
            escaped.push_back(' ');
        } else {
            escaped.push_back(character);
        }
    }
    return escaped;
}

std::string RunElfHookSelfTest() {
    TestStats stats{};
    TestApiContract(&stats);
    TestModuleAndSymbolLookup(&stats);
    TestHandleLifecycle(&stats);
    TestConvenienceAndFailureOutputs(&stats);
    TestConflictDetection(&stats);
    TestExecuteOnlyReplacement(&stats);
    TestOrphanedModule(&stats);
    TestRecoveryTransactions(&stats);
    TestLoaderLockOrdering(&stats);
    TestParallelTransactions(&stats);
    TestForkSnapshots(&stats);
    TestConcurrentSwitching(&stats);

    std::ostringstream report;
    report << "HOOKSELF_ELF_RESULT {\"verdict\":\""
           << (stats.failures == 0U ? "PASS" : "FAILED")
           << "\",\"version\":1,\"checks\":" << stats.checks
           << ",\"failures\":" << stats.failures
           << ",\"gnu_resolves\":" << stats.gnu_resolves
           << ",\"sysv_resolves\":" << stats.sysv_resolves
           << ",\"hook_cycles\":" << stats.hook_cycles
           << ",\"relro_restores\":" << stats.relro_restores
           << ",\"conflict_checks\":" << stats.conflict_checks
           << ",\"lock_order_checks\":" << stats.lock_order_checks
           << ",\"loader_forks\":" << stats.loader_forks
           << ",\"parallel_transactions\":"
           << stats.parallel_transactions
           << ",\"fork_snapshots\":" << stats.fork_snapshots
           << ",\"xom_replacements\":" << stats.xom_replacements
           << ",\"recovery_transactions\":"
           << stats.recovery_transactions
           << ",\"orphaned_modules\":" << stats.orphaned_modules
           << ",\"concurrent_calls\":" << stats.concurrent_calls
           << ",\"first_failure\":\""
           << EscapeJson(stats.first_failure) << "\"}";
    return report.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runElfHookSelfTest(
        JNIEnv* env, jclass) {
    try {
        const std::string report = RunElfHookSelfTest();
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_ELF_RESULT {\"verdict\":\"INTERNAL_ERROR\","
                "\"version\":1,\"checks\":0,\"failures\":1,"
                "\"gnu_resolves\":0,\"sysv_resolves\":0,"
                "\"hook_cycles\":0,\"relro_restores\":0,"
                "\"conflict_checks\":0,\"lock_order_checks\":0,"
                "\"loader_forks\":0,"
                "\"parallel_transactions\":0,"
                "\"fork_snapshots\":0,"
                "\"xom_replacements\":0,"
                "\"recovery_transactions\":0,"
                "\"orphaned_modules\":0,"
                "\"concurrent_calls\":0,"
                "\"first_failure\":\"native exception\"}");
    }
}
