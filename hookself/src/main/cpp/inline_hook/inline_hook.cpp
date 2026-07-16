#include "hookself/inline_hook.h"

#include <atomic>
#include <pthread.h>
#include <sys/mman.h>

#include "inline_hook/internal/arm64_encoding.h"
#include "inline_hook/internal/arm64_relocator.h"
#include "inline_hook/internal/memory.h"

namespace hookself::inline_hook::internal {
namespace {

using arm64::AddressMap;
using arm64::CodeWriter;
using arm64::RelocationRequest;
using arm64::RelocationResult;
using arm64::RelocationStatus;

constexpr uint32_t kMaxHooks = 256U;
constexpr uint64_t kNearAllocationRange = UINT64_C(120) * 1024U * 1024U;
constexpr size_t kBridgeCapacity = 64U;
constexpr size_t kOriginalOffset = 64U;
constexpr size_t kOriginalCapacity = 192U;

enum class EntryState : uint32_t {
    kFree = 0,
    kActive = 1,
    kRemoved = 2,
};

struct HookEntry {
    uint64_t handle;
    uint64_t generation;
    EntryState state;
    uintptr_t target;
    uintptr_t replacement;
    uintptr_t original;
    uintptr_t patch_address;
    uintptr_t bridge_address;
    uintptr_t code_page;
    uint32_t original_instruction;
    uint32_t patch_instruction;
    uint32_t relocated_size;
    uint32_t info_flags;
};

struct PreparedHook {
    uintptr_t target;
    uintptr_t replacement;
    uintptr_t original;
    uintptr_t patch_address;
    uintptr_t bridge_address;
    uintptr_t code_page;
    uint32_t original_instruction;
    uint32_t patch_instruction;
    uint32_t relocated_size;
    uint32_t info_flags;
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
HookEntry g_entries[kMaxHooks]{};
uint64_t g_generation = 1U;

uint64_t NextGeneration() noexcept {
    ++g_generation;
    if (g_generation == 0U) {
        ++g_generation;
    }
    return g_generation;
}

uint64_t MakeHandle(uint32_t index, uint64_t generation) noexcept {
    return (generation << 16U) | static_cast<uint64_t>(index + 1U);
}

uint32_t HandleIndex(HookselfInlineHandle handle) noexcept {
    const uint32_t encoded = static_cast<uint32_t>(handle & 0xffffU);
    return encoded == 0U ? kMaxHooks : encoded - 1U;
}

HookEntry* FindActiveTargetLocked(uintptr_t target) noexcept {
    for (HookEntry& entry : g_entries) {
        if (entry.state == EntryState::kActive && entry.target == target) {
            return &entry;
        }
    }
    return nullptr;
}

HookEntry* FindHandleLocked(HookselfInlineHandle handle) noexcept {
    const uint32_t index = HandleIndex(handle);
    if (index >= kMaxHooks || g_entries[index].handle != handle ||
        g_entries[index].state == EntryState::kFree) {
        return nullptr;
    }
    return &g_entries[index];
}

HookEntry* FindReusableEntryLocked(uint32_t* index) noexcept {
    for (uint32_t candidate = 0; candidate < kMaxHooks; ++candidate) {
        if (g_entries[candidate].state != EntryState::kActive) {
            if (index != nullptr) {
                *index = candidate;
            }
            return &g_entries[candidate];
        }
    }
    return nullptr;
}

int32_t RelocationError(RelocationStatus status) noexcept {
    switch (status) {
        case RelocationStatus::kOk:
            return HOOKSELF_INLINE_OK;
        case RelocationStatus::kInvalidArgument:
            return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
        case RelocationStatus::kNoSpace:
            return HOOKSELF_INLINE_E_INTERNAL;
        case RelocationStatus::kRange:
            return HOOKSELF_INLINE_E_RANGE;
        case RelocationStatus::kUnsupported:
            return HOOKSELF_INLINE_E_RELOCATION;
    }
    return HOOKSELF_INLINE_E_INTERNAL;
}

bool EmitFarBranch(CodeWriter* writer, uintptr_t destination,
                   bool* uses_x17) noexcept {
    if (writer == nullptr) {
        return false;
    }
    const size_t load_offset = writer->size();
    if (!writer->Emit32(0U) || !writer->Emit32(arm64::kBrX17) ||
        !writer->Align8()) {
        return false;
    }
    const uintptr_t literal_address = writer->address();
    if (!writer->Emit64(destination)) {
        return false;
    }
    uint32_t load = 0;
    if (!arm64::EncodeLdrLiteralX(
                17U, writer->address_at(load_offset), literal_address,
                &load) ||
        !writer->Patch32(load_offset, load)) {
        return false;
    }
    if (uses_x17 != nullptr) {
        *uses_x17 = true;
    }
    return true;
}

int32_t BuildBridge(uint8_t* page, uintptr_t page_address,
                    uintptr_t replacement, uint32_t authenticate,
                    uintptr_t* bridge_address, uint32_t* flags,
                    size_t* used_size) noexcept {
    if (page == nullptr || bridge_address == nullptr || flags == nullptr ||
        used_size == nullptr) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    CodeWriter writer(page, kBridgeCapacity, page_address);
    if (authenticate != 0U && !writer.Emit32(authenticate)) {
        return HOOKSELF_INLINE_E_INTERNAL;
    }
    uint32_t branch = 0;
    bool uses_x17 = false;
    if (arm64::EncodeBranch(writer.address(), replacement, false, &branch)) {
        if (!writer.Emit32(branch)) {
            return HOOKSELF_INLINE_E_INTERNAL;
        }
    } else if (!EmitFarBranch(&writer, replacement, &uses_x17)) {
        return HOOKSELF_INLINE_E_INTERNAL;
    }
    *bridge_address = page_address;
    *flags |= HOOKSELF_INLINE_INFO_F_NEAR_BRIDGE;
    if (uses_x17) {
        *flags |= HOOKSELF_INLINE_INFO_F_USES_X17;
    }
    *used_size = writer.size();
    return HOOKSELF_INLINE_OK;
}

int32_t BuildOriginalTrampoline(
        uint8_t* page, uintptr_t page_address, uintptr_t target,
        uintptr_t patch_address, uint32_t first_instruction,
        uint32_t patched_instruction, uint32_t copied_instruction_count,
        uintptr_t* original, uint32_t* relocated_size,
        uint32_t* flags, size_t* used_size) noexcept {
    if (page == nullptr || original == nullptr || relocated_size == nullptr ||
        flags == nullptr || used_size == nullptr ||
        copied_instruction_count == 0U || copied_instruction_count > 2U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    uint8_t* const output = page + kOriginalOffset;
    const uintptr_t output_address = page_address + kOriginalOffset;
    CodeWriter prefix(output, kOriginalCapacity, output_address);
    if (!prefix.Emit32(arm64::kBtiC)) {
        return HOOKSELF_INLINE_E_INTERNAL;
    }

    AddressMap maps[2]{};
    size_t map_count = 0;
    maps[map_count++] = {target, prefix.address()};
    if (copied_instruction_count == 2U) {
        if (!prefix.Emit32(first_instruction)) {
            return HOOKSELF_INLINE_E_INTERNAL;
        }
        maps[map_count++] = {patch_address, prefix.address()};
    }

    RelocationRequest request{};
    request.instruction = patched_instruction;
    request.source_pc = patch_address;
    request.continuation = target + copied_instruction_count * 4U;
    request.overwritten_start = patch_address;
    request.overwritten_size = sizeof(uint32_t);
    request.internal_maps = maps;
    request.internal_map_count = map_count;
    request.output = output + prefix.size();
    request.output_capacity = kOriginalCapacity - prefix.size();
    request.output_address = prefix.address();
    RelocationResult relocation{};
    const RelocationStatus relocation_status =
            arm64::RelocateOneAndContinue(request, &relocation);
    if (relocation_status != RelocationStatus::kOk) {
        return RelocationError(relocation_status);
    }
    *original = output_address;
    *relocated_size = static_cast<uint32_t>(
            prefix.size() + relocation.code_size);
    if (relocation.expanded != 0U) {
        *flags |= HOOKSELF_INLINE_INFO_F_RELOCATION_EXPANDED;
    }
    if (relocation.uses_x17 != 0U) {
        *flags |= HOOKSELF_INLINE_INFO_F_USES_X17;
    }
    *flags |= HOOKSELF_INLINE_INFO_F_TRAMPOLINE_RETAINED;
    *used_size = kOriginalOffset + prefix.size() + relocation.total_size;
    return HOOKSELF_INLINE_OK;
}

int32_t PrepareHook(uintptr_t target, uintptr_t replacement,
                    PreparedHook* prepared) noexcept {
#if !defined(__aarch64__)
    (void)target;
    (void)replacement;
    (void)prepared;
    return HOOKSELF_INLINE_E_UNSUPPORTED_ARCH;
#else
    if (prepared == nullptr) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    *prepared = {};
    prepared->target = target;
    prepared->replacement = replacement;

    MemoryRegion replacement_region{};
    if (!FindMemoryRegion(replacement, 4U, &replacement_region) ||
        (replacement_region.protection & PROT_EXEC) == 0) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }

    uint32_t first_instruction = 0;
    int32_t result = ReadExecutableInstruction(target, &first_instruction);
    if (result != HOOKSELF_INLINE_OK) {
        return result;
    }
    uintptr_t patch_address = target;
    uint32_t patched_instruction = first_instruction;
    uint32_t copied_instruction_count = 1U;
    uint32_t authenticate = 0U;
    if (arm64::IsBti(first_instruction)) {
        patch_address += 4U;
        copied_instruction_count = 2U;
        prepared->info_flags |= HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI;
        result = ReadExecutableInstruction(patch_address,
                                           &patched_instruction);
        if (result != HOOKSELF_INLINE_OK) {
            return result;
        }
    } else if (arm64::IsPacEntry(first_instruction, &authenticate)) {
        patch_address += 4U;
        copied_instruction_count = 2U;
        prepared->info_flags |= HOOKSELF_INLINE_INFO_F_PATCH_AFTER_PAC;
        result = ReadExecutableInstruction(patch_address,
                                           &patched_instruction);
        if (result != HOOKSELF_INLINE_OK) {
            return result;
        }
    }

    void* const code_page = AllocateNearCodePage(
            patch_address, kNearAllocationRange);
    if (code_page == nullptr) {
        return HOOKSELF_INLINE_E_NO_MEMORY;
    }
    prepared->code_page = reinterpret_cast<uintptr_t>(code_page);
    prepared->patch_address = patch_address;
    prepared->original_instruction = patched_instruction;

    size_t original_end = 0;
    result = BuildOriginalTrampoline(
            static_cast<uint8_t*>(code_page), prepared->code_page,
            target, patch_address, first_instruction, patched_instruction,
            copied_instruction_count, &prepared->original,
            &prepared->relocated_size, &prepared->info_flags,
            &original_end);
    if (result != HOOKSELF_INLINE_OK) {
        ReleaseUnpublishedPage(code_page);
        prepared->code_page = 0;
        return result;
    }

    uint32_t patch = 0;
    size_t bridge_end = 0;
    if (authenticate == 0U && arm64::EncodeBranch(
            patch_address, replacement, false, &patch)) {
        prepared->bridge_address = 0;
    } else {
        result = BuildBridge(
                static_cast<uint8_t*>(code_page), prepared->code_page,
                replacement, authenticate, &prepared->bridge_address,
                &prepared->info_flags, &bridge_end);
        if (result != HOOKSELF_INLINE_OK ||
            !arm64::EncodeBranch(patch_address,
                                 prepared->bridge_address, false, &patch)) {
            ReleaseUnpublishedPage(code_page);
            prepared->code_page = 0;
            return result != HOOKSELF_INLINE_OK
                    ? result : HOOKSELF_INLINE_E_RANGE;
        }
    }
    prepared->patch_instruction = patch;

    const size_t used_size = original_end > bridge_end
            ? original_end : bridge_end;
    result = FinalizeCodePage(code_page, used_size);
    if (result != HOOKSELF_INLINE_OK) {
        ReleaseUnpublishedPage(code_page);
        prepared->code_page = 0;
        return result;
    }
    return HOOKSELF_INLINE_OK;
#endif
}

void PublishEntry(HookEntry* entry, uint32_t index,
                  const PreparedHook& prepared,
                  HookselfInlineHandle* handle) noexcept {
    const uint64_t generation = NextGeneration();
    *entry = {};
    entry->generation = generation;
    entry->handle = MakeHandle(index, generation);
    entry->state = EntryState::kActive;
    entry->target = prepared.target;
    entry->replacement = prepared.replacement;
    entry->original = prepared.original;
    entry->patch_address = prepared.patch_address;
    entry->bridge_address = prepared.bridge_address;
    entry->code_page = prepared.code_page;
    entry->original_instruction = prepared.original_instruction;
    entry->patch_instruction = prepared.patch_instruction;
    entry->relocated_size = prepared.relocated_size;
    entry->info_flags = prepared.info_flags;
    *handle = entry->handle;
}

int32_t RemoveEntryLocked(HookEntry* entry) noexcept {
    if (entry == nullptr || entry->state != EntryState::kActive) {
        return HOOKSELF_INLINE_E_NOT_FOUND;
    }
    const int32_t result = PatchExecutableInstruction(
            entry->patch_address, entry->patch_instruction,
            entry->original_instruction);
    if (result == HOOKSELF_INLINE_OK) {
        entry->state = EntryState::kRemoved;
    }
    return result;
}

void AtForkPrepare() {
    g_registry_lock.Lock();
}

void AtForkRelease() {
    g_registry_lock.Unlock();
}

__attribute__((constructor)) void RegisterAtFork() {
    (void)pthread_atfork(AtForkPrepare, AtForkRelease, AtForkRelease);
}

}  // namespace
}  // namespace hookself::inline_hook::internal

extern "C" HOOKSELF_INLINE_API uint32_t
hookself_inline_get_abi_version(void) {
    return HOOKSELF_INLINE_ABI_VERSION;
}

extern "C" HOOKSELF_INLINE_API void hookself_inline_default_options(
        HookselfInlineOptions* options) {
    if (options == nullptr) {
        return;
    }
    *options = {};
    options->struct_size = sizeof(*options);
    options->abi_version = HOOKSELF_INLINE_ABI_VERSION;
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_validate_options(
        const HookselfInlineOptions* options) {
    if (options == nullptr || options->struct_size != sizeof(*options)) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    if (options->abi_version != HOOKSELF_INLINE_ABI_VERSION) {
        return HOOKSELF_INLINE_E_ABI_MISMATCH;
    }
    if (options->flags != 0U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    for (uint32_t value : options->reserved) {
        if (value != 0U) {
            return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
        }
    }
    return HOOKSELF_INLINE_OK;
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_get_capabilities(
        HookselfInlineCapabilities* capabilities) {
    if (capabilities == nullptr ||
        capabilities->struct_size != sizeof(*capabilities)) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    *capabilities = {};
    capabilities->struct_size = sizeof(*capabilities);
    capabilities->abi_version = HOOKSELF_INLINE_ABI_VERSION;
#if defined(__aarch64__)
    capabilities->features =
            HOOKSELF_INLINE_FEATURE_ATOMIC_ARM64_BRANCH |
            HOOKSELF_INLINE_FEATURE_NEAR_BRIDGE |
            HOOKSELF_INLINE_FEATURE_ORIGINAL_TRAMPOLINE |
            HOOKSELF_INLINE_FEATURE_PC_RELATIVE_RELOCATION |
            HOOKSELF_INLINE_FEATURE_BTI_ENTRY |
            HOOKSELF_INLINE_FEATURE_PAC_ENTRY |
            HOOKSELF_INLINE_FEATURE_RETAINED_TRAMPOLINE |
            HOOKSELF_INLINE_FEATURE_THREAD_SAFE_REGISTRY;
    capabilities->instruction_size = 4U;
    capabilities->patch_size = 4U;
    capabilities->near_branch_range =
            hookself::inline_hook::arm64::kBranchRange;
    capabilities->max_active_hooks =
            hookself::inline_hook::internal::kMaxHooks;
    return HOOKSELF_INLINE_OK;
#else
    return HOOKSELF_INLINE_E_UNSUPPORTED_ARCH;
#endif
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_install(
        void* target, void* replacement, const HookselfInlineOptions* options,
        void** original, HookselfInlineHandle* handle) {
    using namespace hookself::inline_hook::internal;
    if (handle == nullptr) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    if (target == nullptr || replacement == nullptr || target == replacement ||
        (reinterpret_cast<uintptr_t>(target) & 3U) != 0U ||
        (reinterpret_cast<uintptr_t>(replacement) & 3U) != 0U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    HookselfInlineOptions defaults{};
    if (options == nullptr) {
        hookself_inline_default_options(&defaults);
        options = &defaults;
    }
    const int32_t options_result = hookself_inline_validate_options(options);
    if (options_result != HOOKSELF_INLINE_OK) {
        return options_result;
    }

    ScopedRegistryLock lock(&g_registry_lock);
    const uintptr_t target_address = reinterpret_cast<uintptr_t>(target);
    if (FindActiveTargetLocked(target_address) != nullptr) {
        return HOOKSELF_INLINE_E_ALREADY_INSTALLED;
    }
    uint32_t index = 0;
    HookEntry* const entry = FindReusableEntryLocked(&index);
    if (entry == nullptr) {
        return HOOKSELF_INLINE_E_BUSY;
    }

    PreparedHook prepared{};
    int32_t result = PrepareHook(
            target_address, reinterpret_cast<uintptr_t>(replacement),
            &prepared);
    if (result != HOOKSELF_INLINE_OK) {
        return result;
    }
    void* previous_original = nullptr;
    if (original != nullptr) {
        previous_original = __atomic_load_n(original, __ATOMIC_ACQUIRE);
        __atomic_store_n(original, reinterpret_cast<void*>(prepared.original),
                         __ATOMIC_RELEASE);
    }
    result = PatchExecutableInstruction(
            prepared.patch_address, prepared.original_instruction,
            prepared.patch_instruction);
    if (result != HOOKSELF_INLINE_OK) {
        if (original != nullptr) {
            __atomic_store_n(original, previous_original, __ATOMIC_RELEASE);
        } else {
            ReleaseUnpublishedPage(
                    reinterpret_cast<void*>(prepared.code_page));
        }
        return result;
    }
    PublishEntry(entry, index, prepared, handle);
    return HOOKSELF_INLINE_OK;
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_hook(
        void* target, void* replacement, void** original) {
    HookselfInlineHandle handle = HOOKSELF_INLINE_INVALID_HANDLE;
    return hookself_inline_install(target, replacement, nullptr, original,
                                   &handle);
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_remove(
        HookselfInlineHandle handle) {
    using namespace hookself::inline_hook::internal;
    if (handle == HOOKSELF_INLINE_INVALID_HANDLE) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindHandleLocked(handle);
    return RemoveEntryLocked(entry);
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_unhook(void* target) {
    using namespace hookself::inline_hook::internal;
    if (target == nullptr ||
        (reinterpret_cast<uintptr_t>(target) & 3U) != 0U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindActiveTargetLocked(
            reinterpret_cast<uintptr_t>(target));
    return RemoveEntryLocked(entry);
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_find(
        const void* target, HookselfInlineHandle* handle) {
    using namespace hookself::inline_hook::internal;
    if (target == nullptr || handle == nullptr) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    *handle = HOOKSELF_INLINE_INVALID_HANDLE;
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindActiveTargetLocked(
            reinterpret_cast<uintptr_t>(target));
    if (entry == nullptr) {
        return HOOKSELF_INLINE_E_NOT_FOUND;
    }
    *handle = entry->handle;
    return HOOKSELF_INLINE_OK;
}

extern "C" HOOKSELF_INLINE_API int32_t hookself_inline_get_info(
        HookselfInlineHandle handle, HookselfInlineInfo* info) {
    using namespace hookself::inline_hook::internal;
    if (handle == HOOKSELF_INLINE_INVALID_HANDLE || info == nullptr ||
        info->struct_size != sizeof(*info)) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    ScopedRegistryLock lock(&g_registry_lock);
    HookEntry* const entry = FindHandleLocked(handle);
    if (entry == nullptr) {
        return HOOKSELF_INLINE_E_NOT_FOUND;
    }
    *info = {};
    info->struct_size = sizeof(*info);
    info->state = entry->state == EntryState::kActive
            ? HOOKSELF_INLINE_STATE_ACTIVE
            : HOOKSELF_INLINE_STATE_REMOVED;
    info->handle = entry->handle;
    info->target = entry->target;
    info->replacement = entry->replacement;
    info->original = entry->original;
    info->patch_address = entry->patch_address;
    info->bridge_address = entry->bridge_address;
    info->patch_size = 4U;
    info->relocated_size = entry->relocated_size;
    info->flags = entry->info_flags;
    return HOOKSELF_INLINE_OK;
}

extern "C" HOOKSELF_INLINE_API const char* hookself_inline_result_string(
        int32_t result) {
    switch (result) {
        case HOOKSELF_INLINE_OK: return "OK";
        case HOOKSELF_INLINE_E_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case HOOKSELF_INLINE_E_ABI_MISMATCH: return "ABI_MISMATCH";
        case HOOKSELF_INLINE_E_UNSUPPORTED_ARCH: return "UNSUPPORTED_ARCH";
        case HOOKSELF_INLINE_E_ALREADY_INSTALLED: return "ALREADY_INSTALLED";
        case HOOKSELF_INLINE_E_NOT_FOUND: return "NOT_FOUND";
        case HOOKSELF_INLINE_E_NO_MEMORY: return "NO_MEMORY";
        case HOOKSELF_INLINE_E_RANGE: return "RANGE";
        case HOOKSELF_INLINE_E_RELOCATION: return "RELOCATION";
        case HOOKSELF_INLINE_E_PROTECTION: return "PROTECTION";
        case HOOKSELF_INLINE_E_CONFLICT: return "CONFLICT";
        case HOOKSELF_INLINE_E_BUSY: return "BUSY";
        case HOOKSELF_INLINE_E_INTERNAL: return "INTERNAL";
        default: return "UNKNOWN";
    }
}
