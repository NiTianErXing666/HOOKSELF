#include "close_range_replay.h"

#include <errno.h>
#include <limits.h>

namespace hookself::tracer {
namespace {

void ZeroBytes(void* memory, size_t size) noexcept {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
}

bool FdInRange(int32_t fd, uint32_t first, uint32_t last) noexcept {
    return fd >= 0 && static_cast<uint32_t>(fd) >= first &&
           static_cast<uint32_t>(fd) <= last;
}

void InsertSortedUnique(int32_t fd, CloseRangeReplayCursor* cursor) noexcept {
    uint32_t insert = 0;
    while (insert < cursor->protected_count &&
           cursor->protected_fds[insert] < fd) {
        ++insert;
    }
    if (insert < cursor->protected_count &&
        cursor->protected_fds[insert] == fd) {
        return;
    }
    for (uint32_t index = cursor->protected_count; index > insert; --index) {
        cursor->protected_fds[index] = cursor->protected_fds[index - 1U];
    }
    cursor->protected_fds[insert] = fd;
    ++cursor->protected_count;
}

void MarkComplete(CloseRangeReplayCursor* cursor) noexcept {
    cursor->active = 0;
    cursor->complete = 1;
    cursor->next_first = 0;
    cursor->protected_index = cursor->protected_count;
    cursor->unshare_pending = 0;
}

}  // namespace

int PrepareCloseRangeReplay(
        uint32_t first, uint32_t last, uint32_t flags,
        const int32_t* protected_fds, size_t protected_fd_count,
        CloseRangeReplayCursor* cursor,
        CloseRangeReplayDisposition* disposition) noexcept {
    if (cursor == nullptr || disposition == nullptr || first > last ||
        (flags & ~kCloseRangeReplayKnownFlags) != 0 ||
        (protected_fd_count != 0 && protected_fds == nullptr)) {
        return EINVAL;
    }
    if (protected_fd_count > kCloseRangeReplayProtectedCapacity) {
        return EOVERFLOW;
    }

    ZeroBytes(cursor, sizeof(*cursor));
    cursor->magic = kCloseRangeReplayMagic;
    cursor->version = kCloseRangeReplayVersion;
    cursor->original_first = first;
    cursor->original_last = last;
    cursor->original_flags = flags;
    cursor->next_first = first;
    cursor->unshare_pending =
            (flags & kCloseRangeReplayUnshare) != 0 ? 1U : 0U;
    *disposition = CloseRangeReplayDisposition::kPassthrough;

    for (size_t index = 0; index < protected_fd_count; ++index) {
        const int32_t fd = protected_fds[index];
        if (!FdInRange(fd, first, last)) {
            continue;
        }
        if (cursor->protected_count ==
            kCloseRangeReplayProtectedCapacity) {
            ZeroBytes(cursor, sizeof(*cursor));
            return EOVERFLOW;
        }
        InsertSortedUnique(fd, cursor);
    }

    if (cursor->protected_count == 0) {
        cursor->complete = 1;
        cursor->unshare_pending = 0;
        return 0;
    }

    cursor->active = 1;
    cursor->complete = 0;
    *disposition = CloseRangeReplayDisposition::kReplay;
    return 0;
}

bool IsCloseRangeReplayCursorValid(
        const CloseRangeReplayCursor* cursor) noexcept {
    if (cursor == nullptr || cursor->magic != kCloseRangeReplayMagic ||
        cursor->version != kCloseRangeReplayVersion ||
        cursor->active > 1U || cursor->complete > 1U ||
        cursor->unshare_pending > 1U ||
        cursor->protected_count == 0 ||
        cursor->protected_count > kCloseRangeReplayProtectedCapacity ||
        cursor->protected_index > cursor->protected_count ||
        cursor->segment_count > cursor->protected_count + 2U ||
        cursor->original_first > cursor->original_last ||
        (cursor->original_flags & ~kCloseRangeReplayKnownFlags) != 0 ||
        cursor->active + cursor->complete != 1U) {
        return false;
    }
    for (uint32_t index = 0; index < cursor->protected_count; ++index) {
        const int32_t fd = cursor->protected_fds[index];
        if (!FdInRange(fd, cursor->original_first, cursor->original_last) ||
            (index != 0 && cursor->protected_fds[index - 1U] >= fd)) {
            return false;
        }
    }
    if (cursor->complete != 0) {
        return cursor->active == 0 &&
               cursor->protected_index == cursor->protected_count &&
               cursor->unshare_pending == 0;
    }
    if (cursor->protected_index >= cursor->protected_count ||
        cursor->next_first < cursor->original_first ||
        cursor->next_first > cursor->original_last) {
        return false;
    }
    for (uint32_t index = 0; index < cursor->protected_index; ++index) {
        if (static_cast<uint32_t>(cursor->protected_fds[index]) >=
            cursor->next_first) {
            return false;
        }
    }
    if (static_cast<uint32_t>(
                cursor->protected_fds[cursor->protected_index]) <
        cursor->next_first) {
        return false;
    }

    const uint32_t expected_initial_unshare =
            (cursor->original_flags & kCloseRangeReplayUnshare) != 0
                    ? 1U
                    : 0U;
    if (cursor->segment_count == 0) {
        return cursor->protected_index == 0 &&
               cursor->next_first == cursor->original_first &&
               cursor->unshare_pending == expected_initial_unshare;
    }
    if (expected_initial_unshare != 0U && cursor->segment_count == 1U) {
        return cursor->unshare_pending == 0U &&
               cursor->protected_index == 0U &&
               cursor->next_first == cursor->original_first;
    }
    return cursor->unshare_pending == 0 &&
           static_cast<uint32_t>(
                   cursor->protected_fds[cursor->protected_index]) ==
                   cursor->next_first;
}

int NextCloseRangeReplaySegment(
        CloseRangeReplayCursor* cursor,
        CloseRangeReplaySegment* segment,
        bool* has_segment) noexcept {
    if (segment == nullptr || has_segment == nullptr ||
        !IsCloseRangeReplayCursorValid(cursor)) {
        return EINVAL;
    }
    ZeroBytes(segment, sizeof(*segment));
    *has_segment = false;
    if (cursor->complete != 0) {
        return 0;
    }

    if (cursor->unshare_pending != 0U) {
        segment->first = UINT32_MAX;
        segment->last = UINT32_MAX;
        segment->flags =
                (cursor->original_flags & kCloseRangeReplayCloexec) |
                kCloseRangeReplayUnshare;
        segment->sequence = ++cursor->segment_count;
        cursor->unshare_pending = 0U;
        *has_segment = true;
        return 0;
    }

    for (;;) {
        while (cursor->protected_index < cursor->protected_count &&
               static_cast<uint32_t>(
                       cursor->protected_fds[cursor->protected_index]) <
                       cursor->next_first) {
            ++cursor->protected_index;
        }

        if (cursor->protected_index < cursor->protected_count) {
            const uint32_t protected_fd = static_cast<uint32_t>(
                    cursor->protected_fds[cursor->protected_index]);
            if (cursor->next_first < protected_fd) {
                segment->first = cursor->next_first;
                segment->last = protected_fd - 1U;
                segment->flags =
                        cursor->original_flags & kCloseRangeReplayCloexec;
                segment->sequence = ++cursor->segment_count;
                cursor->next_first = protected_fd;
                *has_segment = true;
                return 0;
            }

            ++cursor->protected_index;
            if (protected_fd == UINT32_MAX ||
                protected_fd == cursor->original_last) {
                break;
            }
            cursor->next_first = protected_fd + 1U;
            continue;
        }

        if (cursor->next_first <= cursor->original_last) {
            segment->first = cursor->next_first;
            segment->last = cursor->original_last;
            segment->flags =
                    cursor->original_flags & kCloseRangeReplayCloexec;
            segment->sequence = ++cursor->segment_count;
            // Marking complete here avoids a next_first overflow when last is
            // UINT32_MAX. The emitted segment is still valid for the caller.
            cursor->active = 0;
            cursor->complete = 1;
            cursor->protected_index = cursor->protected_count;
            *has_segment = true;
            return 0;
        }
        break;
    }

    MarkComplete(cursor);
    return 0;
}

}  // namespace hookself::tracer
