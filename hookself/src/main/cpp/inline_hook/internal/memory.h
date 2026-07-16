#ifndef HOOKSELF_INLINE_MEMORY_H
#define HOOKSELF_INLINE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

namespace hookself::inline_hook::internal {

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    int protection;
    bool private_mapping;
};

size_t PageSize() noexcept;
bool FindMemoryRegion(uintptr_t address, size_t size,
                      MemoryRegion* region) noexcept;

void* AllocateNearCodePage(uintptr_t reference,
                           uint64_t range) noexcept;
int32_t FinalizeCodePage(void* page, size_t used_size) noexcept;
void ReleaseUnpublishedPage(void* page) noexcept;

int32_t ReadExecutableInstruction(uintptr_t address,
                                  uint32_t* instruction) noexcept;
int32_t PatchExecutableInstruction(uintptr_t address, uint32_t expected,
                                   uint32_t replacement) noexcept;

void FlushInstructionCache(uintptr_t start, size_t size) noexcept;

}  // namespace hookself::inline_hook::internal

#endif
