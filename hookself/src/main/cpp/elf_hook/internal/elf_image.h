#ifndef HOOKSELF_ELF_IMAGE_H
#define HOOKSELF_ELF_IMAGE_H

#include <elf.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

#include "hookself/elf_hook.h"

namespace hookself::elf_hook::internal {

constexpr uint32_t kMaxActiveHooks = 128U;
constexpr uint32_t kMaxSlotsPerHook = 32U;
constexpr size_t kMaxProgramHeaders = 256U;
constexpr size_t kMaxLoadSegments = 32U;
constexpr size_t kMaxInputName = 4096U;

struct ModuleIdentity {
    uintptr_t load_bias;
    uintptr_t program_headers;
    uint32_t program_header_count;
    uint32_t path_length;
    uint64_t path_hash;
    uint32_t flags;
    char path[HOOKSELF_ELF_PATH_CAPACITY];
};

struct LoadSegment {
    uintptr_t start;
    uintptr_t end;
    uint32_t flags;
};

struct SysvHashView {
    const uint32_t* buckets;
    const uint32_t* chains;
    uint32_t bucket_count;
    uint32_t chain_count;
};

struct GnuHashView {
    const Elf64_Addr* bloom;
    const uint32_t* buckets;
    const uint32_t* chains;
    uint32_t bucket_count;
    uint32_t symbol_offset;
    uint32_t bloom_count;
    uint32_t bloom_shift;
    uint32_t symbol_count;
};

struct DynamicView {
    const Elf64_Sym* symbols;
    const char* strings;
    size_t string_size;
    uint32_t symbol_count;
    SysvHashView sysv_hash;
    GnuHashView gnu_hash;
    const Elf64_Rela* plt_relocations;
    size_t plt_relocation_count;
    uint32_t module_flags;
};

struct ModuleView {
    ModuleIdentity identity;
    LoadSegment segments[kMaxLoadSegments];
    size_t segment_count;
    uintptr_t load_start;
    uintptr_t load_end;
    uintptr_t dynamic_address;
    size_t dynamic_size;
    uintptr_t relro_start;
    uintptr_t relro_end;

    bool Contains(uintptr_t address, size_t size,
                  uint32_t required_flags = 0U) const noexcept;
    bool ResolveAddress(uint64_t value, size_t size, uint32_t required_flags,
                        uintptr_t* address) const noexcept;
    bool IsRelro(uintptr_t address, size_t size) const noexcept;
};

struct SymbolRecord {
    uintptr_t address;
    uint64_t size;
    uint32_t index;
    uint32_t binding;
    uint32_t type;
    uint32_t visibility;
    uint32_t section_index;
    uint32_t flags;
};

struct PreparedJumpSlotHook {
    uintptr_t slots[kMaxSlotsPerHook];
    uint32_t slot_count;
    uintptr_t original;
    uint32_t flags;
};

using ModuleVisitor = int32_t (*)(const ModuleView& module, void* context);

int32_t FindUniqueModule(const char* module_name,
                         ModuleIdentity* identity) noexcept;
int32_t VisitModule(const ModuleIdentity& identity, ModuleVisitor visitor,
                    void* context) noexcept;
int32_t ParseDynamic(const ModuleView& module,
                     DynamicView* dynamic) noexcept;
int32_t ResolveSymbol(const ModuleView& module, const DynamicView& dynamic,
                      const char* symbol_name,
                      SymbolRecord* symbol) noexcept;
int32_t CollectJumpSlots(const ModuleView& module,
                         const DynamicView& dynamic,
                         const char* symbol_name,
                         PreparedJumpSlotHook* prepared) noexcept;

bool ValidInputName(const char* value, size_t* length) noexcept;
void CopyPublicString(char* destination, size_t capacity, const char* source,
                      size_t source_length, bool* truncated) noexcept;

}  // namespace hookself::elf_hook::internal

#endif
