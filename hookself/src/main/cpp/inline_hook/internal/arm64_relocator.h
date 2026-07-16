#ifndef HOOKSELF_INLINE_ARM64_RELOCATOR_H
#define HOOKSELF_INLINE_ARM64_RELOCATOR_H

#include <stddef.h>
#include <stdint.h>

namespace hookself::inline_hook::arm64 {

enum class RelocationStatus {
    kOk,
    kInvalidArgument,
    kNoSpace,
    kRange,
    kUnsupported,
};

struct AddressMap {
    uintptr_t source;
    uintptr_t destination;
};

struct RelocationRequest {
    uint32_t instruction;
    uintptr_t source_pc;
    uintptr_t continuation;
    uintptr_t overwritten_start;
    size_t overwritten_size;
    const AddressMap* internal_maps;
    size_t internal_map_count;
    uint8_t* output;
    size_t output_capacity;
    uintptr_t output_address;
};

struct RelocationResult {
    size_t code_size;
    size_t total_size;
    uint32_t expanded;
    uint32_t uses_x17;
};

RelocationStatus RelocateOneAndContinue(
        const RelocationRequest& request,
        RelocationResult* result) noexcept;

}  // namespace hookself::inline_hook::arm64

#endif
