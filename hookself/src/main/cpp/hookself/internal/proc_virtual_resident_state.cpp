#include "proc_virtual_resident_state.h"

#include <errno.h>
#include <string.h>

namespace hookself::internal {
namespace {

bool SamePath(const ProcVirtualFdCursor& cursor, const char* path,
              size_t path_length) noexcept {
    return cursor.path_length == path_length &&
           (path_length == 0 ||
            memcmp(cursor.identity_path, path, path_length) == 0);
}

ProcVirtualFdCursor* FindCursor(ProcVirtualResidentState* state,
                                uint32_t owner_slot, int32_t fd,
                                const char* path,
                                size_t path_length) noexcept {
    for (uint32_t slot = 0; slot < kProcVirtualResidentCursorCapacity;
         ++slot) {
        ProcVirtualFdCursor& cursor = state->cursors[slot];
        if (cursor.occupied != 0 && cursor.owner_slot == owner_slot &&
            cursor.fd == fd && SamePath(cursor, path, path_length)) {
            return &cursor;
        }
    }
    return nullptr;
}

const ProcVirtualFdCursor* FindSharedDescriptionCursor(
        const ProcVirtualResidentState* state, uint32_t owner_slot,
        int32_t excluded_fd, const char* path, size_t path_length,
        uint64_t raw_position) noexcept {
    const ProcVirtualFdCursor* newest = nullptr;
    for (uint32_t slot = 0; slot < kProcVirtualResidentCursorCapacity;
         ++slot) {
        const ProcVirtualFdCursor& cursor = state->cursors[slot];
        if (cursor.occupied == 0 || cursor.owner_slot != owner_slot ||
            cursor.fd == excluded_fd || cursor.raw_position != raw_position ||
            !SamePath(cursor, path, path_length)) {
            continue;
        }
        if (newest == nullptr ||
            cursor.last_used_sequence > newest->last_used_sequence) {
            newest = &cursor;
        }
    }
    return newest;
}

ProcVirtualFdCursor* AllocateCursor(ProcVirtualResidentState* state) noexcept {
    ProcVirtualFdCursor* oldest = &state->cursors[0];
    for (uint32_t slot = 0; slot < kProcVirtualResidentCursorCapacity;
         ++slot) {
        ProcVirtualFdCursor& cursor = state->cursors[slot];
        if (cursor.occupied == 0) {
            return &cursor;
        }
        if (cursor.last_used_sequence < oldest->last_used_sequence) {
            oldest = &cursor;
        }
    }
    return oldest;
}

uint64_t NextSequence(ProcVirtualResidentState* state) noexcept {
    ++state->cursor_sequence;
    if (state->cursor_sequence == 0) {
        state->cursor_sequence = 1;
        for (uint32_t slot = 0; slot < kProcVirtualResidentCursorCapacity;
             ++slot) {
            if (state->cursors[slot].occupied != 0) {
                state->cursors[slot].last_used_sequence = 1;
            }
        }
    }
    return state->cursor_sequence;
}

void InitializeCursor(ProcVirtualFdCursor* cursor, uint32_t owner_slot,
                      int32_t fd, const char* path, size_t path_length,
                      uint64_t raw_start, uint64_t raw_end,
                      uint64_t sequence) noexcept {
    memset(cursor, 0, sizeof(*cursor));
    cursor->occupied = 1;
    cursor->owner_slot = owner_slot;
    cursor->fd = fd;
    cursor->path_length = static_cast<uint32_t>(path_length);
    cursor->last_used_sequence = sequence;
    cursor->raw_position = raw_end;
    cursor->logical_position = raw_start;
    if (path_length != 0) {
        memcpy(cursor->identity_path, path, path_length);
    }
    cursor->identity_path[path_length] = '\0';
}

}  // namespace

void InitProcVirtualResidentState(ProcVirtualResidentState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    memset(state, 0, sizeof(*state));
    InitProcVirtualPendingTable(&state->pending);
}

int AppendProcVirtualHiddenRange(ProcVirtualResidentState* state,
                                 uintptr_t start, size_t size) noexcept {
    if (state == nullptr || size == 0 || start > UINTPTR_MAX - size) {
        return EINVAL;
    }
    for (uint32_t index = 0; index < state->hidden_range_count; ++index) {
        const ProcVirtualAddressRange& existing = state->hidden_ranges[index];
        if (existing.start == start && existing.size == size) {
            return 0;
        }
    }
    if (state->hidden_range_count >=
        kProcVirtualResidentHiddenRangeCapacity) {
        return ENOSPC;
    }
    state->hidden_ranges[state->hidden_range_count++] = {start, size};
    return 0;
}

int BeginProcVirtualSequentialRead(ProcVirtualResidentState* state,
                                   uint32_t owner_slot, int32_t fd,
                                   const char* identity_path,
                                   size_t identity_path_length,
                                   uint64_t raw_start, uint64_t raw_end,
                                   uint64_t* logical_offset) noexcept {
    if (state == nullptr || fd < 0 || logical_offset == nullptr ||
        raw_start > raw_end ||
        identity_path_length >= kProcVirtualDispatchPathCapacity ||
        (identity_path_length != 0 && identity_path == nullptr)) {
        return EINVAL;
    }
    ProcVirtualFdCursor* cursor = FindCursor(
            state, owner_slot, fd, identity_path, identity_path_length);
    const uint64_t sequence = NextSequence(state);
    if (cursor == nullptr) {
        const ProcVirtualFdCursor* shared = FindSharedDescriptionCursor(
                state, owner_slot, fd, identity_path, identity_path_length,
                raw_start);
        const bool inherit_shared = shared != nullptr;
        const uint64_t shared_logical =
                inherit_shared ? shared->logical_position : 0U;
        cursor = AllocateCursor(state);
        InitializeCursor(cursor, owner_slot, fd, identity_path,
                         identity_path_length, raw_start, raw_end, sequence);
        if (inherit_shared) {
            cursor->logical_position = shared_logical;
        }
    } else {
        cursor->last_used_sequence = sequence;
        if (cursor->raw_position != raw_start) {
            const ProcVirtualFdCursor* shared =
                    FindSharedDescriptionCursor(
                            state, owner_slot, fd, identity_path,
                            identity_path_length, raw_start);
            cursor->logical_position = shared == nullptr
                                               ? raw_start
                                               : shared->logical_position;
        }
        cursor->raw_position = raw_end;
    }
    *logical_offset = cursor->logical_position;
    return 0;
}

int AdvanceProcVirtualSequentialRead(ProcVirtualResidentState* state,
                                     uint32_t owner_slot, int32_t fd,
                                     const char* identity_path,
                                     size_t identity_path_length,
                                     size_t visible_size) noexcept {
    if (state == nullptr || fd < 0 ||
        identity_path_length >= kProcVirtualDispatchPathCapacity ||
        (identity_path_length != 0 && identity_path == nullptr)) {
        return EINVAL;
    }
    ProcVirtualFdCursor* cursor = FindCursor(
            state, owner_slot, fd, identity_path, identity_path_length);
    if (cursor == nullptr) {
        return ENOENT;
    }
    if (visible_size > UINT64_MAX - cursor->logical_position) {
        return EOVERFLOW;
    }
    cursor->logical_position += visible_size;
    cursor->last_used_sequence = NextSequence(state);
    return 0;
}

bool ValidateProcVirtualResidentState(
        const ProcVirtualResidentState* state) noexcept {
    if (state == nullptr ||
        !ValidateProcVirtualPendingTable(&state->pending) ||
        state->hidden_range_count > kProcVirtualResidentHiddenRangeCapacity ||
        state->reverse_rule_count > kProcVirtualResidentReverseRuleCapacity ||
        state->xattr_rule_count > kProcVirtualResidentXattrRuleCapacity) {
        return false;
    }
    for (uint32_t slot = 0; slot < kProcVirtualResidentCursorCapacity;
         ++slot) {
        const ProcVirtualFdCursor& cursor = state->cursors[slot];
        if (cursor.occupied == 0) {
            const auto* bytes = reinterpret_cast<const uint8_t*>(&cursor);
            for (size_t index = 0; index < sizeof(cursor); ++index) {
                if (bytes[index] != 0) {
                    return false;
                }
            }
            continue;
        }
        if (cursor.occupied != 1 || cursor.fd < 0 ||
            cursor.path_length >= kProcVirtualDispatchPathCapacity ||
            cursor.identity_path[cursor.path_length] != '\0' ||
            cursor.last_used_sequence == 0) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kProcVirtualResidentCursorCapacity; ++other) {
            const ProcVirtualFdCursor& candidate = state->cursors[other];
            if (candidate.occupied != 0 &&
                candidate.owner_slot == cursor.owner_slot &&
                candidate.fd == cursor.fd &&
                SamePath(candidate, cursor.identity_path,
                         cursor.path_length)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace hookself::internal
