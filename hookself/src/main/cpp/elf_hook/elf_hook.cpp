#include "hookself/elf_hook.h"

#include <atomic>
#include <pthread.h>
#include <signal.h>
#include <string.h>

#include "elf_hook/internal/elf_image.h"
#include "elf_hook/internal/memory.h"

namespace hookself::elf_hook::internal {
namespace {

#if defined(__LP64__)
static_assert(sizeof(HookselfElfOptions) == 32U);
static_assert(sizeof(HookselfElfCapabilities) == 56U);
static_assert(sizeof(HookselfElfModuleInfo) == 592U);
static_assert(sizeof(HookselfElfSymbolInfo) == 600U);
static_assert(sizeof(HookselfElfInfo) == 856U);
static_assert(offsetof(HookselfElfModuleInfo, path) == 48U);
static_assert(offsetof(HookselfElfSymbolInfo, module_path) == 56U);
static_assert(offsetof(HookselfElfInfo, module_path) == 56U);
static_assert(offsetof(HookselfElfInfo, symbol_name) == 568U);
#endif

enum class EntryState : uint32_t {
    kFree = 0,
    kInstalling = 1,
    kActive = 2,
    kRecovery = 3,
    kRemoving = 4,
    kRemoved = 5,
    kOrphaned = 6,
};

struct HookEntry {
    HookselfElfHandle handle;
    uint64_t generation;
    EntryState state;
    ModuleIdentity identity;
    uintptr_t replacement;
    uintptr_t original;
    uintptr_t slots[kMaxSlotsPerHook];
    uint32_t slot_count;
    uint32_t info_flags;
    bool recovery_required;
    bool recovery_from_install;
    PointerPatchOutcome recovery;
    char symbol[HOOKSELF_ELF_SYMBOL_CAPACITY];
};

class RegistryLock {
public:
    void Lock() noexcept {
        while (flag_.test_and_set(std::memory_order_acquire)) {
#if defined(__aarch64__)
            __asm__ volatile("yield" : : : "memory");
#endif
        }
    }

    void Unlock() noexcept {
        flag_.clear(std::memory_order_release);
    }

    void ResetAfterFork() noexcept {
        flag_.clear(std::memory_order_seq_cst);
    }

private:
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

class ScopedRegistryLock {
public:
    explicit ScopedRegistryLock(RegistryLock* lock) noexcept : lock_(lock) {
        lock_->Lock();
    }
    ~ScopedRegistryLock() { lock_->Unlock(); }

    ScopedRegistryLock(const ScopedRegistryLock&) = delete;
    ScopedRegistryLock& operator=(const ScopedRegistryLock&) = delete;

private:
    RegistryLock* lock_;
};

RegistryLock g_registry_lock;
RegistryLock g_patch_lock;
HookEntry g_entries[kMaxActiveHooks]{};
uint64_t g_generation = 1U;
std::atomic<uint32_t> g_fork_prepares{0U};
std::atomic<uint32_t> g_active_mutations{0U};

class MutationGuard {
public:
    MutationGuard() noexcept
        : active_(false), signal_mask_saved_(false), previous_signal_mask_{} {}

    bool TryAcquire() noexcept {
        if (active_) {
            return true;
        }
        sigset_t blocked_signals{};
        if (sigfillset(&blocked_signals) != 0 ||
            pthread_sigmask(SIG_SETMASK, &blocked_signals,
                            &previous_signal_mask_) != 0) {
            return false;
        }
        signal_mask_saved_ = true;
        if (g_fork_prepares.load(std::memory_order_seq_cst) != 0U) {
            return false;
        }
        g_active_mutations.fetch_add(1U, std::memory_order_seq_cst);
        if (g_fork_prepares.load(std::memory_order_seq_cst) != 0U) {
            g_active_mutations.fetch_sub(1U, std::memory_order_seq_cst);
            return false;
        }
        active_ = true;
        return true;
    }

    ~MutationGuard() {
        if (active_) {
            g_active_mutations.fetch_sub(1U, std::memory_order_seq_cst);
        }
        RestoreSignalMask();
    }

    MutationGuard(const MutationGuard&) = delete;
    MutationGuard& operator=(const MutationGuard&) = delete;

private:
    void RestoreSignalMask() noexcept {
        if (signal_mask_saved_) {
            signal_mask_saved_ = false;
            (void)pthread_sigmask(SIG_SETMASK, &previous_signal_mask_, nullptr);
        }
    }

    bool active_;
    bool signal_mask_saved_;
    sigset_t previous_signal_mask_;
};

uint64_t NextGeneration() noexcept {
    ++g_generation;
    if (g_generation == 0U) {
        ++g_generation;
    }
    return g_generation;
}

HookselfElfHandle MakeHandle(uint32_t index, uint64_t generation) noexcept {
    return (generation << 16U) | static_cast<uint64_t>(index + 1U);
}

uint32_t HandleIndex(HookselfElfHandle handle) noexcept {
    const uint32_t encoded = static_cast<uint32_t>(handle & UINT64_C(0xffff));
    return encoded == 0U ? kMaxActiveHooks : encoded - 1U;
}

bool SameModule(const ModuleIdentity& left,
                const ModuleIdentity& right) noexcept {
    return left.load_bias == right.load_bias &&
            left.program_headers == right.program_headers &&
            left.program_header_count == right.program_header_count &&
            left.path_length == right.path_length &&
            left.path_hash == right.path_hash;
}

bool SameSymbol(const HookEntry& entry, const char* symbol,
                size_t length) noexcept {
    return length < sizeof(entry.symbol) && entry.symbol[length] == '\0' &&
            memcmp(entry.symbol, symbol, length) == 0;
}

HookEntry* FindDiscoverableLocked(const ModuleIdentity& identity,
                                  const char* symbol,
                                  size_t symbol_length) noexcept {
    for (HookEntry& entry : g_entries) {
        if ((entry.state == EntryState::kActive ||
             entry.state == EntryState::kRecovery) &&
            SameModule(entry.identity, identity) &&
            SameSymbol(entry, symbol, symbol_length)) {
            return &entry;
        }
    }
    return nullptr;
}

HookEntry* FindMatchingLocked(const ModuleIdentity& identity,
                              const char* symbol,
                              size_t symbol_length) noexcept {
    for (HookEntry& entry : g_entries) {
        if (entry.state != EntryState::kFree &&
            entry.state != EntryState::kRemoved &&
            entry.state != EntryState::kOrphaned &&
            SameModule(entry.identity, identity) &&
            SameSymbol(entry, symbol, symbol_length)) {
            return &entry;
        }
    }
    return nullptr;
}

HookEntry* FindHandleLocked(HookselfElfHandle handle) noexcept {
    const uint32_t index = HandleIndex(handle);
    if (index >= kMaxActiveHooks || g_entries[index].handle != handle ||
        g_entries[index].state == EntryState::kFree) {
        return nullptr;
    }
    return &g_entries[index];
}

HookEntry* FindReusableLocked(uint32_t* index) noexcept {
    for (uint32_t candidate = 0U; candidate < kMaxActiveHooks; ++candidate) {
        if (g_entries[candidate].state == EntryState::kFree ||
            g_entries[candidate].state == EntryState::kRemoved ||
            g_entries[candidate].state == EntryState::kOrphaned) {
            if (index != nullptr) {
                *index = candidate;
            }
            return &g_entries[candidate];
        }
    }
    return nullptr;
}

void ReserveEntry(HookEntry* entry, uint32_t index,
                  const ModuleIdentity& identity, const char* symbol,
                  size_t symbol_length) noexcept {
    const uint64_t generation = NextGeneration();
    *entry = {};
    entry->generation = generation;
    entry->handle = MakeHandle(index, generation);
    entry->state = EntryState::kInstalling;
    entry->identity = identity;
    memcpy(entry->symbol, symbol, symbol_length);
    entry->symbol[symbol_length] = '\0';
}

bool ValidHookSymbol(const char* symbol, size_t* length) noexcept {
    return ValidInputName(symbol, length) && *length != 0U &&
            *length < HOOKSELF_ELF_SYMBOL_CAPACITY;
}

int32_t ParseModuleDynamic(const ModuleView& module,
                           DynamicView* dynamic) noexcept {
#if !defined(__aarch64__)
    (void)module;
    (void)dynamic;
    return HOOKSELF_ELF_E_UNSUPPORTED_ARCH;
#else
    return ParseDynamic(module, dynamic);
#endif
}

struct ModuleInfoContext {
    HookselfElfModuleInfo info;
};

int32_t ReadModuleInfo(const ModuleView& module, void* opaque) noexcept {
    auto* const context = static_cast<ModuleInfoContext*>(opaque);
    DynamicView dynamic{};
    const int32_t result = ParseModuleDynamic(module, &dynamic);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    HookselfElfModuleInfo info{};
    info.struct_size = sizeof(info);
    info.flags = dynamic.module_flags;
    info.load_bias = module.identity.load_bias;
    info.load_start = module.load_start;
    info.load_end = module.load_end;
    info.program_headers = module.identity.program_headers;
    info.program_header_count = module.identity.program_header_count;
    memcpy(info.path, module.identity.path, sizeof(info.path));
    context->info = info;
    return HOOKSELF_ELF_OK;
}

struct ResolveContext {
    const char* symbol_name;
    HookselfElfSymbolInfo info;
};

int32_t ResolveModuleSymbol(const ModuleView& module, void* opaque) noexcept {
    auto* const context = static_cast<ResolveContext*>(opaque);
    DynamicView dynamic{};
    int32_t result = ParseModuleDynamic(module, &dynamic);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    SymbolRecord record{};
    result = ResolveSymbol(module, dynamic, context->symbol_name, &record);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    HookselfElfSymbolInfo info{};
    info.struct_size = sizeof(info);
    info.flags = record.flags;
    info.address = record.address;
    info.size = record.size;
    info.module_load_bias = module.identity.load_bias;
    info.symbol_index = record.index;
    info.binding = record.binding;
    info.type = record.type;
    info.visibility = record.visibility;
    info.section_index = record.section_index;
    if ((module.identity.flags &
         HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED) != 0U) {
        info.flags |= HOOKSELF_ELF_SYMBOL_F_PATH_TRUNCATED;
    }
    memcpy(info.module_path, module.identity.path, sizeof(info.module_path));
    context->info = info;
    return HOOKSELF_ELF_OK;
}

void PublishEntry(HookEntry* entry, uintptr_t replacement,
                  const PreparedJumpSlotHook& prepared,
                  const PointerPatchOutcome& outcome,
                  HookselfElfHandle* handle) noexcept;

struct InstallContext {
    const char* symbol_name;
    size_t symbol_length;
    uintptr_t replacement;
    void** original_output;
    void* previous_original;
    PreparedJumpSlotHook prepared;
    PointerPatchOutcome outcome;
    HookselfElfHandle published;
    MutationGuard mutation;
};

int32_t InstallInModule(const ModuleView& module, void* opaque) noexcept {
    auto* const context = static_cast<InstallContext*>(opaque);
    DynamicView dynamic{};
    int32_t result = ParseModuleDynamic(module, &dynamic);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    result = CollectJumpSlots(module, dynamic, context->symbol_name,
                              &context->prepared);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    if (!context->mutation.TryAcquire()) {
        return HOOKSELF_ELF_E_BUSY;
    }
    uint32_t entry_index = 0U;
    HookEntry* entry = nullptr;
    {
        ScopedRegistryLock lock(&g_registry_lock);
        HookEntry* const matching = FindMatchingLocked(
                module.identity, context->symbol_name,
                context->symbol_length);
        if (matching != nullptr) {
            return matching->state == EntryState::kActive
                    ? HOOKSELF_ELF_E_ALREADY_INSTALLED
                    : HOOKSELF_ELF_E_BUSY;
        }
        entry = FindReusableLocked(&entry_index);
        if (entry == nullptr) {
            return HOOKSELF_ELF_E_BUSY;
        }
        ReserveEntry(entry, entry_index, module.identity,
                     context->symbol_name, context->symbol_length);
    }

    {
        ScopedRegistryLock patch_lock(&g_patch_lock);
        result = InspectPointerSlots(context->prepared.slots,
                                     context->prepared.slot_count,
                                     &context->prepared.original);
        if (result == HOOKSELF_ELF_OK &&
            context->prepared.original == context->replacement) {
            result = HOOKSELF_ELF_E_CONFLICT;
        }
        if (result == HOOKSELF_ELF_OK) {
            PointerPatch patches[kMaxSlotsPerHook]{};
            for (uint32_t index = 0U;
                 index < context->prepared.slot_count; ++index) {
                patches[index] = {
                        context->prepared.slots[index],
                        context->prepared.original,
                        context->replacement};
            }
            if (context->original_output != nullptr) {
                __atomic_store_n(
                        context->original_output,
                        reinterpret_cast<void*>(
                                context->prepared.original),
                        __ATOMIC_RELEASE);
            }
            result = CommitPointerPatches(
                    patches, context->prepared.slot_count,
                    &context->outcome);
            if (result != HOOKSELF_ELF_OK &&
                result != HOOKSELF_ELF_E_RECOVERY_REQUIRED &&
                context->original_output != nullptr) {
                __atomic_store_n(context->original_output,
                                 context->previous_original,
                                 __ATOMIC_RELEASE);
            }
        }
    }

    {
        ScopedRegistryLock lock(&g_registry_lock);
        if (entry->state != EntryState::kInstalling) {
            return HOOKSELF_ELF_E_INTERNAL;
        }
        if (result == HOOKSELF_ELF_OK ||
            result == HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
            PublishEntry(entry, context->replacement, context->prepared,
                         context->outcome, &context->published);
        } else {
            entry->state = EntryState::kFree;
        }
    }
    return result;
}

void PublishEntry(HookEntry* entry, uintptr_t replacement,
                  const PreparedJumpSlotHook& prepared,
                  const PointerPatchOutcome& outcome,
                  HookselfElfHandle* handle) noexcept {
    const HookselfElfHandle reserved_handle = entry->handle;
    entry->state = outcome.recovery_required
            ? EntryState::kRecovery : EntryState::kActive;
    entry->replacement = replacement;
    entry->original = prepared.original;
    entry->slot_count = prepared.slot_count;
    entry->info_flags = prepared.flags;
    entry->recovery_required = outcome.recovery_required;
    entry->recovery_from_install = outcome.recovery_required;
    entry->recovery = outcome;
    memcpy(entry->slots, prepared.slots,
           prepared.slot_count * sizeof(prepared.slots[0]));
    *handle = reserved_handle;
}

struct RemoveContext {
    bool by_handle;
    HookselfElfHandle handle;
    const char* symbol_name;
    size_t symbol_length;
    HookEntry* entry;
    bool started_in_recovery;
    bool recovery_from_install;
    PointerPatchOutcome outcome;
    MutationGuard mutation;
};

int32_t ApplyRemoval(const ModuleView& module,
                     RemoveContext* context) noexcept {
    HookEntry& entry = *context->entry;
    DynamicView dynamic{};
    int32_t result = ParseModuleDynamic(module, &dynamic);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    PreparedJumpSlotHook current{};
    result = CollectJumpSlots(module, dynamic, entry.symbol, &current);
    if (result != HOOKSELF_ELF_OK || current.slot_count != entry.slot_count) {
        return result == HOOKSELF_ELF_OK
                ? HOOKSELF_ELF_E_CONFLICT : result;
    }
    for (uint32_t index = 0U; index < entry.slot_count; ++index) {
        bool found = false;
        for (uint32_t candidate = 0U; candidate < current.slot_count;
             ++candidate) {
            if (entry.slots[index] == current.slots[candidate]) {
                found = true;
                break;
            }
        }
        if (!found) {
            return HOOKSELF_ELF_E_CONFLICT;
        }
    }
    ScopedRegistryLock patch_lock(&g_patch_lock);
    if (context->started_in_recovery) {
        PointerPatch recovery_patches[kMaxSlotsPerHook]{};
        for (uint32_t index = 0U; index < entry.slot_count; ++index) {
            recovery_patches[index] = context->recovery_from_install
                    ? PointerPatch{entry.slots[index], entry.original,
                                   entry.replacement}
                    : PointerPatch{entry.slots[index], entry.replacement,
                                   entry.original};
        }
        result = RecoverPointerPatches(
                recovery_patches, entry.slot_count, entry.recovery);
        if (result != HOOKSELF_ELF_OK ||
            context->recovery_from_install) {
            return result;
        }
    }
    PointerPatch patches[kMaxSlotsPerHook]{};
    for (uint32_t index = 0U; index < entry.slot_count; ++index) {
        patches[index] = {
                entry.slots[index], entry.replacement, entry.original};
    }
    return CommitPointerPatches(
            patches, entry.slot_count, &context->outcome);
}

int32_t CheckRemovableLocked(HookEntry* entry) noexcept {
    if (entry == nullptr || entry->state == EntryState::kRemoved ||
        entry->state == EntryState::kOrphaned ||
        entry->state == EntryState::kFree) {
        return HOOKSELF_ELF_E_NOT_FOUND;
    }
    if (entry->state == EntryState::kInstalling ||
        entry->state == EntryState::kRemoving) {
        return HOOKSELF_ELF_E_BUSY;
    }
    return HOOKSELF_ELF_OK;
}

int32_t BeginRemoveLocked(HookEntry* entry) noexcept {
    const int32_t result = CheckRemovableLocked(entry);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    entry->state = EntryState::kRemoving;
    return HOOKSELF_ELF_OK;
}

int32_t RemoveFromModule(const ModuleView& module, void* opaque) noexcept {
    auto* const context = static_cast<RemoveContext*>(opaque);
    if (!context->mutation.TryAcquire()) {
        return HOOKSELF_ELF_E_BUSY;
    }
    int32_t result = HOOKSELF_ELF_OK;
    {
        ScopedRegistryLock lock(&g_registry_lock);
        context->entry = context->by_handle
                ? FindHandleLocked(context->handle)
                : FindMatchingLocked(module.identity, context->symbol_name,
                                     context->symbol_length);
        if (context->entry != nullptr &&
            !SameModule(context->entry->identity, module.identity)) {
            context->entry = nullptr;
        }
        result = BeginRemoveLocked(context->entry);
        if (result == HOOKSELF_ELF_OK) {
            context->started_in_recovery =
                    context->entry->recovery_required;
            context->recovery_from_install =
                    context->entry->recovery_from_install;
        }
    }
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }

    result = ApplyRemoval(module, context);
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = context->entry;
    if (entry == nullptr || entry->state != EntryState::kRemoving) {
        return HOOKSELF_ELF_E_INTERNAL;
    }
    if (result == HOOKSELF_ELF_OK) {
        entry->recovery_required = false;
        entry->state = EntryState::kRemoved;
    } else if (result == HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
        if (!context->outcome.recovery_required) {
            entry->state = EntryState::kRecovery;
        } else {
            entry->recovery_required = true;
            entry->recovery_from_install = false;
            entry->recovery = context->outcome;
            entry->state = EntryState::kRecovery;
        }
    } else {
        entry->state = context->started_in_recovery
                ? EntryState::kRecovery : EntryState::kActive;
    }
    return result;
}

void AtForkPrepare() {
    g_fork_prepares.fetch_add(1U, std::memory_order_seq_cst);
    while (g_active_mutations.load(std::memory_order_seq_cst) != 0U) {
#if defined(__aarch64__)
        __asm__ volatile("yield" : : : "memory");
#endif
    }
}

void AtForkParent() {
    g_fork_prepares.fetch_sub(1U, std::memory_order_seq_cst);
}

void AtForkChild() {
    g_registry_lock.ResetAfterFork();
    g_patch_lock.ResetAfterFork();
    g_active_mutations.store(0U, std::memory_order_seq_cst);
    g_fork_prepares.store(0U, std::memory_order_seq_cst);
}

int32_t MarkHandleOrphaned(HookselfElfHandle handle) noexcept {
    MutationGuard mutation;
    if (!mutation.TryAcquire()) {
        return HOOKSELF_ELF_E_BUSY;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindHandleLocked(handle);
    if (entry != nullptr &&
        (entry->state == EntryState::kActive ||
         entry->state == EntryState::kRecovery)) {
        entry->state = EntryState::kOrphaned;
    }
    return HOOKSELF_ELF_E_MODULE_UNLOADED;
}

int32_t MarkSymbolOrphaned(const ModuleIdentity& identity,
                           const char* symbol_name,
                           size_t symbol_length) noexcept {
    MutationGuard mutation;
    if (!mutation.TryAcquire()) {
        return HOOKSELF_ELF_E_BUSY;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindMatchingLocked(
            identity, symbol_name, symbol_length);
    if (entry != nullptr &&
        (entry->state == EntryState::kActive ||
         entry->state == EntryState::kRecovery)) {
        entry->state = EntryState::kOrphaned;
    }
    return HOOKSELF_ELF_E_MODULE_UNLOADED;
}

__attribute__((constructor)) void RegisterAtFork() {
    (void)pthread_atfork(AtForkPrepare, AtForkParent, AtForkChild);
}

}  // namespace
}  // namespace hookself::elf_hook::internal

extern "C" HOOKSELF_ELF_API uint32_t hookself_elf_get_abi_version(void) {
    return HOOKSELF_ELF_ABI_VERSION;
}

extern "C" HOOKSELF_ELF_API void hookself_elf_default_options(
        HookselfElfOptions* options) {
    if (options == nullptr) {
        return;
    }
    *options = {};
    options->struct_size = sizeof(*options);
    options->abi_version = HOOKSELF_ELF_ABI_VERSION;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_validate_options(
        const HookselfElfOptions* options) {
    if (options == nullptr || options->struct_size != sizeof(*options)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    if (options->abi_version != HOOKSELF_ELF_ABI_VERSION) {
        return HOOKSELF_ELF_E_ABI_MISMATCH;
    }
    if (options->flags != 0U) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    for (uint32_t value : options->reserved) {
        if (value != 0U) {
            return HOOKSELF_ELF_E_INVALID_ARGUMENT;
        }
    }
    return HOOKSELF_ELF_OK;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_get_capabilities(
        HookselfElfCapabilities* capabilities) {
    using namespace hookself::elf_hook::internal;
    if (capabilities == nullptr ||
        capabilities->struct_size != sizeof(*capabilities)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
#if defined(__aarch64__)
    *capabilities = {};
    capabilities->struct_size = sizeof(*capabilities);
    capabilities->abi_version = HOOKSELF_ELF_ABI_VERSION;
    capabilities->features =
            HOOKSELF_ELF_FEATURE_LOADED_MODULE_LOOKUP |
            HOOKSELF_ELF_FEATURE_MEMORY_DYNSYM |
            HOOKSELF_ELF_FEATURE_GNU_HASH |
            HOOKSELF_ELF_FEATURE_SYSV_HASH |
            HOOKSELF_ELF_FEATURE_ARM64_JUMP_SLOT |
            HOOKSELF_ELF_FEATURE_ATOMIC_POINTER_CAS |
            HOOKSELF_ELF_FEATURE_RELRO_RESTORE |
            HOOKSELF_ELF_FEATURE_THREAD_SAFE_REGISTRY |
            HOOKSELF_ELF_FEATURE_RECOVERABLE_TRANSACTION;
    capabilities->pointer_size = sizeof(uintptr_t);
    capabilities->max_active_hooks = kMaxActiveHooks;
    capabilities->max_slots_per_hook = kMaxSlotsPerHook;
    capabilities->path_capacity = HOOKSELF_ELF_PATH_CAPACITY;
    capabilities->symbol_capacity = HOOKSELF_ELF_SYMBOL_CAPACITY;
    return HOOKSELF_ELF_OK;
#else
    return HOOKSELF_ELF_E_UNSUPPORTED_ARCH;
#endif
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_get_module_info(
        const char* module_name, HookselfElfModuleInfo* info) {
    using namespace hookself::elf_hook::internal;
    if (info == nullptr || info->struct_size != sizeof(*info)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    ModuleIdentity identity{};
    int32_t result = FindUniqueModule(module_name, &identity);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    ModuleInfoContext context{};
    result = VisitModule(identity, ReadModuleInfo, &context);
    if (result == HOOKSELF_ELF_OK) {
        *info = context.info;
    }
    return result;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_resolve_symbol(
        const char* module_name, const char* symbol_name,
        HookselfElfSymbolInfo* info) {
    using namespace hookself::elf_hook::internal;
    size_t symbol_length = 0U;
    if (info == nullptr || info->struct_size != sizeof(*info) ||
        !ValidInputName(symbol_name, &symbol_length) || symbol_length == 0U) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    ModuleIdentity identity{};
    int32_t result = FindUniqueModule(module_name, &identity);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    ResolveContext context{symbol_name, {}};
    result = VisitModule(identity, ResolveModuleSymbol, &context);
    if (result == HOOKSELF_ELF_OK) {
        *info = context.info;
    }
    return result;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_install(
        const char* module_name, const char* symbol_name, void* replacement,
        const HookselfElfOptions* options, void** original,
        HookselfElfHandle* handle) {
    using namespace hookself::elf_hook::internal;
    if (replacement == nullptr || handle == nullptr) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    if (!IsExecutableAddress(reinterpret_cast<uintptr_t>(replacement))) {
        return HOOKSELF_ELF_E_PROTECTION;
    }
    size_t symbol_length = 0U;
    if (!ValidHookSymbol(symbol_name, &symbol_length)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    HookselfElfOptions defaults{};
    if (options == nullptr) {
        hookself_elf_default_options(&defaults);
        options = &defaults;
    }
    const int32_t options_result = hookself_elf_validate_options(options);
    if (options_result != HOOKSELF_ELF_OK) {
        return options_result;
    }

    ModuleIdentity identity{};
    int32_t result = FindUniqueModule(module_name, &identity);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    void* previous_original = nullptr;
    if (original != nullptr) {
        previous_original = __atomic_load_n(original, __ATOMIC_ACQUIRE);
    }
    InstallContext context{
            symbol_name, symbol_length,
            reinterpret_cast<uintptr_t>(replacement), original,
            previous_original, {}, {}, HOOKSELF_ELF_INVALID_HANDLE, {}};
    result = VisitModule(identity, InstallInModule, &context);
    if (result == HOOKSELF_ELF_OK ||
        result == HOOKSELF_ELF_E_RECOVERY_REQUIRED) {
        *handle = context.published;
    }
    return result;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_hook(
        const char* module_name, const char* symbol_name, void* replacement,
        void** original) {
    HookselfElfHandle handle = HOOKSELF_ELF_INVALID_HANDLE;
    return hookself_elf_install(module_name, symbol_name, replacement, nullptr,
                                original, &handle);
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_remove(
        HookselfElfHandle handle) {
    using namespace hookself::elf_hook::internal;
    if (handle == HOOKSELF_ELF_INVALID_HANDLE) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    ModuleIdentity identity{};
    int32_t result = HOOKSELF_ELF_OK;
    {
        ScopedRegistryLock lock(&g_registry_lock);
        HookEntry* const entry = FindHandleLocked(handle);
        result = CheckRemovableLocked(entry);
        if (result == HOOKSELF_ELF_OK) {
            identity = entry->identity;
        }
    }
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    RemoveContext context{
            true, handle, nullptr, 0U, nullptr, false, false, {}, {}};
    result = VisitModule(identity, RemoveFromModule, &context);
    if (result == HOOKSELF_ELF_E_MODULE_UNLOADED) {
        result = MarkHandleOrphaned(handle);
    }
    return result;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_unhook(
        const char* module_name, const char* symbol_name) {
    using namespace hookself::elf_hook::internal;
    size_t symbol_length = 0U;
    if (!ValidHookSymbol(symbol_name, &symbol_length)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    ModuleIdentity identity{};
    int32_t result = FindUniqueModule(module_name, &identity);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    RemoveContext context{
            false, HOOKSELF_ELF_INVALID_HANDLE,
            symbol_name, symbol_length, nullptr, false, false, {}, {}};
    result = VisitModule(identity, RemoveFromModule, &context);
    if (result == HOOKSELF_ELF_E_MODULE_UNLOADED) {
        result = MarkSymbolOrphaned(identity, symbol_name, symbol_length);
    }
    return result;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_find(
        const char* module_name, const char* symbol_name,
        HookselfElfHandle* handle) {
    using namespace hookself::elf_hook::internal;
    size_t symbol_length = 0U;
    if (handle == nullptr || !ValidHookSymbol(symbol_name, &symbol_length)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    *handle = HOOKSELF_ELF_INVALID_HANDLE;
    ModuleIdentity identity{};
    const int32_t result = FindUniqueModule(module_name, &identity);
    if (result != HOOKSELF_ELF_OK) {
        return result;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry =
            FindDiscoverableLocked(identity, symbol_name, symbol_length);
    if (entry == nullptr) {
        return HOOKSELF_ELF_E_NOT_FOUND;
    }
    *handle = entry->handle;
    return HOOKSELF_ELF_OK;
}

extern "C" HOOKSELF_ELF_API int32_t hookself_elf_get_info(
        HookselfElfHandle handle, HookselfElfInfo* info) {
    using namespace hookself::elf_hook::internal;
    if (handle == HOOKSELF_ELF_INVALID_HANDLE || info == nullptr ||
        info->struct_size != sizeof(*info)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindHandleLocked(handle);
    if (entry == nullptr) {
        return HOOKSELF_ELF_E_NOT_FOUND;
    }
    if (entry->state == EntryState::kInstalling) {
        return HOOKSELF_ELF_E_BUSY;
    }
    *info = {};
    info->struct_size = sizeof(*info);
    switch (entry->state) {
        case EntryState::kActive:
            info->state = HOOKSELF_ELF_STATE_ACTIVE;
            break;
        case EntryState::kRemoving:
            info->state = entry->recovery_required
                    ? HOOKSELF_ELF_STATE_RECOVERY_REQUIRED
                    : HOOKSELF_ELF_STATE_ACTIVE;
            break;
        case EntryState::kRemoved:
            info->state = HOOKSELF_ELF_STATE_REMOVED;
            break;
        case EntryState::kOrphaned:
            info->state = HOOKSELF_ELF_STATE_ORPHANED;
            break;
        case EntryState::kRecovery:
            info->state = HOOKSELF_ELF_STATE_RECOVERY_REQUIRED;
            break;
        case EntryState::kFree:
        case EntryState::kInstalling:
            return HOOKSELF_ELF_E_NOT_FOUND;
    }
    info->handle = entry->handle;
    info->module_load_bias = entry->identity.load_bias;
    info->replacement = entry->replacement;
    info->original = entry->original;
    info->first_slot = entry->slots[0];
    info->slot_count = entry->slot_count;
    info->flags = entry->info_flags;
    memcpy(info->module_path, entry->identity.path,
           sizeof(info->module_path));
    memcpy(info->symbol_name, entry->symbol, sizeof(info->symbol_name));
    return HOOKSELF_ELF_OK;
}

extern "C" HOOKSELF_ELF_API const char* hookself_elf_result_string(
        int32_t result) {
    switch (result) {
        case HOOKSELF_ELF_OK: return "OK";
        case HOOKSELF_ELF_E_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case HOOKSELF_ELF_E_ABI_MISMATCH: return "ABI_MISMATCH";
        case HOOKSELF_ELF_E_UNSUPPORTED_ARCH: return "UNSUPPORTED_ARCH";
        case HOOKSELF_ELF_E_MODULE_NOT_FOUND: return "MODULE_NOT_FOUND";
        case HOOKSELF_ELF_E_MODULE_AMBIGUOUS: return "MODULE_AMBIGUOUS";
        case HOOKSELF_ELF_E_MALFORMED_ELF: return "MALFORMED_ELF";
        case HOOKSELF_ELF_E_UNSUPPORTED_ELF: return "UNSUPPORTED_ELF";
        case HOOKSELF_ELF_E_SYMBOL_NOT_FOUND: return "SYMBOL_NOT_FOUND";
        case HOOKSELF_ELF_E_RELOCATION_NOT_FOUND:
            return "RELOCATION_NOT_FOUND";
        case HOOKSELF_ELF_E_ALREADY_INSTALLED: return "ALREADY_INSTALLED";
        case HOOKSELF_ELF_E_NOT_FOUND: return "NOT_FOUND";
        case HOOKSELF_ELF_E_TOO_MANY_SLOTS: return "TOO_MANY_SLOTS";
        case HOOKSELF_ELF_E_PROTECTION: return "PROTECTION";
        case HOOKSELF_ELF_E_CONFLICT: return "CONFLICT";
        case HOOKSELF_ELF_E_BUSY: return "BUSY";
        case HOOKSELF_ELF_E_MODULE_UNLOADED: return "MODULE_UNLOADED";
        case HOOKSELF_ELF_E_UNSUPPORTED_SYMBOL: return "UNSUPPORTED_SYMBOL";
        case HOOKSELF_ELF_E_INTERNAL: return "INTERNAL";
        case HOOKSELF_ELF_E_RECOVERY_REQUIRED:
            return "RECOVERY_REQUIRED";
        default: return "UNKNOWN";
    }
}
