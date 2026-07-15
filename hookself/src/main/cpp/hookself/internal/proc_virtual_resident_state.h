#pragma once

#include <cstddef>
#include <cstdint>

#include "hookself/public_api.h"
#include "proc_virtual_dispatch.h"

namespace hookself::internal {

constexpr size_t kProcVirtualResidentBufferCapacity = 4U * 1024U * 1024U;
constexpr uint32_t kProcVirtualResidentCursorCapacity = 1024U;
constexpr uint32_t kProcVirtualResidentHiddenRangeCapacity = 96U;
constexpr uint32_t kProcVirtualResidentReverseRuleCapacity =
        HOOKSELF_MAX_PATH_RULES;
constexpr uint32_t kProcVirtualResidentXattrRuleCapacity = 4U;
constexpr size_t kProcVirtualResidentXattrValueCapacity =
        HOOKSELF_PATH_CAPACITY;

struct ProcVirtualFdCursor {
    uint32_t occupied;
    uint32_t owner_slot;
    int32_t fd;
    uint32_t path_length;
    uint64_t last_used_sequence;
    uint64_t raw_position;
    uint64_t logical_position;
    char identity_path[kProcVirtualDispatchPathCapacity];
};

struct ProcVirtualResidentState {
    ProcVirtualPendingTable pending;
    uint64_t cursor_sequence;
    uint32_t hidden_range_count;
    uint32_t reverse_rule_count;
    uint32_t xattr_rule_count;
    uint32_t reserved;
    ProcVirtualAddressRange hidden_ranges[
            kProcVirtualResidentHiddenRangeCapacity];
    ProcReversePathRule reverse_rules[
            kProcVirtualResidentReverseRuleCapacity];
    ProcVirtualXattrRule xattr_rules[
            kProcVirtualResidentXattrRuleCapacity];
    uint8_t xattr_values[kProcVirtualResidentXattrRuleCapacity]
                        [kProcVirtualResidentXattrValueCapacity];
    ProcVirtualFdCursor cursors[kProcVirtualResidentCursorCapacity];
    uint8_t snapshot_buffer[kProcVirtualResidentBufferCapacity];
    uint8_t rewrite_buffer[kProcVirtualResidentBufferCapacity];
};

static_assert(__is_standard_layout(ProcVirtualFdCursor) &&
              __is_trivially_copyable(ProcVirtualFdCursor));
static_assert(__is_standard_layout(ProcVirtualResidentState) &&
              __is_trivially_copyable(ProcVirtualResidentState));

void InitProcVirtualResidentState(ProcVirtualResidentState* state) noexcept;

int AppendProcVirtualHiddenRange(ProcVirtualResidentState* state,
                                 uintptr_t start, size_t size) noexcept;

// owner_slot identifies a shared FD table. raw_start/raw_end describe the
// backing file-description movement performed by the just-completed syscall.
// A discontinuity resets the logical cursor, covering lseek and FD reuse.
int BeginProcVirtualSequentialRead(ProcVirtualResidentState* state,
                                   uint32_t owner_slot, int32_t fd,
                                   const char* identity_path,
                                   size_t identity_path_length,
                                   uint64_t raw_start, uint64_t raw_end,
                                   uint64_t* logical_offset) noexcept;

int AdvanceProcVirtualSequentialRead(ProcVirtualResidentState* state,
                                     uint32_t owner_slot, int32_t fd,
                                     const char* identity_path,
                                     size_t identity_path_length,
                                     size_t visible_size) noexcept;

bool ValidateProcVirtualResidentState(
        const ProcVirtualResidentState* state) noexcept;

}  // namespace hookself::internal
