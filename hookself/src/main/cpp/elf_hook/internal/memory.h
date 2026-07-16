#ifndef HOOKSELF_ELF_MEMORY_H
#define HOOKSELF_ELF_MEMORY_H

#include <stddef.h>
#include <stdint.h>

namespace hookself::elf_hook::internal {

struct PointerPatch {
    uintptr_t address;
    uintptr_t expected;
    uintptr_t desired;
};

struct PointerPageProtection {
    uintptr_t address;
    int protection;
};

struct PointerPatchOutcome {
    bool recovery_required;
    bool desired_visible;
    uint32_t page_count;
    PointerPageProtection pages[32];
};

bool IsExecutableAddress(uintptr_t address) noexcept;
int32_t InspectPointerSlots(const uintptr_t* slots, size_t count,
                            uintptr_t* common_value) noexcept;
int32_t CommitPointerPatches(const PointerPatch* patches, size_t count,
                             PointerPatchOutcome* outcome) noexcept;
int32_t RecoverPointerPatches(const PointerPatch* patches, size_t count,
                              const PointerPatchOutcome& outcome) noexcept;

}  // namespace hookself::elf_hook::internal

#endif
