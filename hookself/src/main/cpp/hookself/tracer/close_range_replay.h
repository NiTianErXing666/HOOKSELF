#pragma once

#include <stddef.h>
#include <stdint.h>

namespace hookself::tracer {

// Linux UAPI values. These are kept local so the planner also builds against
// NDK releases which predate close_range(2).
constexpr uint32_t kCloseRangeReplayUnshare = 1U << 1;
constexpr uint32_t kCloseRangeReplayCloexec = 1U << 2;
constexpr uint32_t kCloseRangeReplayKnownFlags =
        kCloseRangeReplayUnshare | kCloseRangeReplayCloexec;

// The runtime registry currently holds at most 160 descriptors. The planner
// deliberately has headroom and remains independent from the shared ABI.
constexpr uint32_t kCloseRangeReplayProtectedCapacity = 256U;
constexpr uint32_t kCloseRangeReplayMagic = 0x48534352U;  // HSCR
constexpr uint32_t kCloseRangeReplayVersion = 2U;

enum class CloseRangeReplayDisposition : uint32_t {
    kInvalid = 0,
    // Execute the original syscall unchanged when no protected descriptor is
    // intersected.
    kPassthrough = 1,
    // Replace the original range with one or more segments from Next().
    kReplay = 2,
};

struct CloseRangeReplaySegment {
    uint32_t first;
    uint32_t last;
    uint32_t flags;
    uint32_t sequence;
};

// Cursor state is self-contained so changes to the live protected-FD registry
// cannot alter an in-flight replay. protected_fds is sorted and unique.
struct CloseRangeReplayCursor {
    uint32_t magic;
    uint32_t version;
    uint32_t active;
    uint32_t complete;
    uint32_t original_first;
    uint32_t original_last;
    uint32_t original_flags;
    uint32_t next_first;
    uint32_t protected_count;
    uint32_t protected_index;
    uint32_t segment_count;
    uint32_t unshare_pending;
    int32_t protected_fds[kCloseRangeReplayProtectedCapacity];
};

static_assert(__is_standard_layout(CloseRangeReplaySegment) &&
              __is_trivially_copyable(CloseRangeReplaySegment));
static_assert(__is_standard_layout(CloseRangeReplayCursor) &&
              __is_trivially_copyable(CloseRangeReplayCursor));

// Normalizes an unsorted registry, discarding negative descriptors, entries
// outside [first, last], and duplicates. Both close and CLOEXEC requests are
// segmented around protected descriptors so their physical CLOEXEC state can
// remain clear across a traced exec.
int PrepareCloseRangeReplay(
        uint32_t first, uint32_t last, uint32_t flags,
        const int32_t* protected_fds, size_t protected_fd_count,
        CloseRangeReplayCursor* cursor,
        CloseRangeReplayDisposition* disposition) noexcept;

bool IsCloseRangeReplayCursorValid(
        const CloseRangeReplayCursor* cursor) noexcept;

// Emits the next replay syscall. An UNSHARE request first emits
// [UINT32_MAX, UINT32_MAX] with CLOSE_RANGE_UNSHARE, then emits every actual
// non-protected interval without UNSHARE. Linux cannot allocate an FD at that
// number, so the sentinel separates the complete files table before a low
// first interval can make the kernel truncate higher protected descriptors.
//
// has_segment=false means replay is complete and the original visible result
// is zero. Callers abort replay immediately if an emitted syscall returns an
// error; already completed segments intentionally remain applied, matching
// close_range's documented allowance for partial side effects on failure.
int NextCloseRangeReplaySegment(
        CloseRangeReplayCursor* cursor,
        CloseRangeReplaySegment* segment,
        bool* has_segment) noexcept;

}  // namespace hookself::tracer
