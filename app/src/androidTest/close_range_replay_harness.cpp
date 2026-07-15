#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "hookself/tracer/close_range_replay.h"

namespace {

using hookself::tracer::CloseRangeReplayCursor;
using hookself::tracer::CloseRangeReplayDisposition;
using hookself::tracer::CloseRangeReplaySegment;
using hookself::tracer::IsCloseRangeReplayCursorValid;
using hookself::tracer::NextCloseRangeReplaySegment;
using hookself::tracer::PrepareCloseRangeReplay;
using hookself::tracer::kCloseRangeReplayCloexec;
using hookself::tracer::kCloseRangeReplayProtectedCapacity;
using hookself::tracer::kCloseRangeReplayUnshare;

uint32_t g_checks = 0;
uint32_t g_case_first = 0;
uint32_t g_case_last = 0;
uint32_t g_case_flags = 0;
uint32_t g_case_mask = 0;

bool Check(bool result, const char* expression, int line) {
    ++g_checks;
    if (result) {
        return true;
    }
    fprintf(stderr,
            "FAIL line=%d expression=%s first=%u last=%u flags=%u "
            "mask=%u checks=%u\n",
            line, expression, g_case_first, g_case_last, g_case_flags,
            g_case_mask, g_checks);
    return false;
}

#define CHECK(expression)                                      \
    do {                                                       \
        if (!Check((expression), #expression, __LINE__)) {     \
            return false;                                      \
        }                                                      \
    } while (0)

bool IsZeroSegment(const CloseRangeReplaySegment& segment) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&segment);
    for (size_t index = 0; index < sizeof(segment); ++index) {
        if (bytes[index] != 0U) {
            return false;
        }
    }
    return true;
}

bool RunExhaustiveCase(uint32_t first, uint32_t last, uint32_t flags,
                       uint32_t mask) {
    constexpr uint32_t kUniverse = 6U;
    g_case_first = first;
    g_case_last = last;
    g_case_flags = flags;
    g_case_mask = mask;

    std::vector<int32_t> input;
    input.push_back(-1);
    input.push_back(99);
    for (uint32_t fd = kUniverse; fd != 0; --fd) {
        const uint32_t value = fd - 1U;
        if ((mask & (1U << value)) != 0) {
            input.push_back(static_cast<int32_t>(value));
            input.push_back(static_cast<int32_t>(value));
        }
    }

    uint32_t expected_protected = 0;
    for (uint32_t fd = first; fd <= last; ++fd) {
        if ((mask & (1U << fd)) != 0) {
            ++expected_protected;
        }
    }

    CloseRangeReplayCursor cursor{};
    CloseRangeReplayDisposition disposition =
            CloseRangeReplayDisposition::kInvalid;
    CHECK(PrepareCloseRangeReplay(first, last, flags, input.data(),
                                  input.size(), &cursor, &disposition) == 0);
    if (expected_protected == 0) {
        CHECK(disposition == CloseRangeReplayDisposition::kPassthrough);
        CHECK(cursor.active == 0U && cursor.complete == 1U);
        CHECK(cursor.protected_count == 0U);
        return true;
    }

    CHECK(disposition == CloseRangeReplayDisposition::kReplay);
    CHECK(cursor.protected_count == expected_protected);
    CHECK(IsCloseRangeReplayCursorValid(&cursor));
    std::vector<uint32_t> coverage(kUniverse, 0U);
    uint32_t emitted = 0;
    uint32_t unshare_segments = 0;
    bool had_real_segment = false;
    uint32_t previous_last = 0;

    for (;;) {
        CHECK(IsCloseRangeReplayCursorValid(&cursor));
        CloseRangeReplaySegment segment{
                0xaaaaaaaaU, 0xbbbbbbbbU, 0xccccccccU, 0xddddddddU};
        bool has_segment = true;
        CHECK(NextCloseRangeReplaySegment(
                      &cursor, &segment, &has_segment) == 0);
        CHECK(IsCloseRangeReplayCursorValid(&cursor));
        if (!has_segment) {
            CHECK(IsZeroSegment(segment));
            break;
        }

        ++emitted;
        CHECK(segment.sequence == emitted);
        CHECK(segment.first <= segment.last);
        CHECK((segment.flags & kCloseRangeReplayCloexec) ==
              (flags & kCloseRangeReplayCloexec));
        const bool has_unshare =
                (segment.flags & kCloseRangeReplayUnshare) != 0;
        CHECK(has_unshare ==
              (emitted == 1U &&
               (flags & kCloseRangeReplayUnshare) != 0));
        unshare_segments += has_unshare ? 1U : 0U;

        const bool synthetic = segment.first == UINT32_MAX &&
                               segment.last == UINT32_MAX;
        if (synthetic) {
            CHECK(!had_real_segment);
            CHECK((flags & kCloseRangeReplayUnshare) != 0);
            continue;
        }
        CHECK(segment.first >= first && segment.last <= last);
        if (had_real_segment) {
            CHECK(segment.first > previous_last);
        }
        had_real_segment = true;
        previous_last = segment.last;
        for (uint32_t fd = segment.first; fd <= segment.last; ++fd) {
            CHECK(fd < kUniverse);
            CHECK((mask & (1U << fd)) == 0);
            ++coverage[fd];
        }
        CHECK(emitted <= expected_protected + 2U);
    }

    CHECK(cursor.active == 0U && cursor.complete == 1U);
    CHECK(cursor.protected_index == cursor.protected_count);
    CHECK(cursor.unshare_pending == 0U);
    CHECK(cursor.segment_count == emitted);
    CHECK(unshare_segments ==
          ((flags & kCloseRangeReplayUnshare) != 0 ? 1U : 0U));
    for (uint32_t fd = first; fd <= last; ++fd) {
        const uint32_t expected = (mask & (1U << fd)) != 0 ? 0U : 1U;
        CHECK(coverage[fd] == expected);
    }

    CloseRangeReplaySegment repeated{1U, 2U, 3U, 4U};
    bool repeated_segment = true;
    CHECK(NextCloseRangeReplaySegment(
                  &cursor, &repeated, &repeated_segment) == 0);
    CHECK(!repeated_segment && IsZeroSegment(repeated));
    CHECK(cursor.segment_count == emitted);
    return true;
}

bool TestExhaustiveSmallRanges() {
    constexpr uint32_t kFlags[] = {
            0U,
            kCloseRangeReplayUnshare,
            kCloseRangeReplayCloexec,
            kCloseRangeReplayUnshare | kCloseRangeReplayCloexec,
    };
    for (uint32_t first = 0; first < 6U; ++first) {
        for (uint32_t last = first; last < 6U; ++last) {
            for (uint32_t flags : kFlags) {
                for (uint32_t mask = 0; mask < (1U << 6U); ++mask) {
                    if (!RunExhaustiveCase(first, last, flags, mask)) {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

bool ExpectSegment(CloseRangeReplayCursor* cursor, uint32_t first,
                   uint32_t last, uint32_t flags, uint32_t sequence) {
    CloseRangeReplaySegment segment{};
    bool has_segment = false;
    CHECK(NextCloseRangeReplaySegment(
                  cursor, &segment, &has_segment) == 0);
    CHECK(has_segment);
    CHECK(segment.first == first && segment.last == last);
    CHECK(segment.flags == flags && segment.sequence == sequence);
    CHECK(IsCloseRangeReplayCursorValid(cursor));
    return true;
}

bool ExpectComplete(CloseRangeReplayCursor* cursor) {
    CloseRangeReplaySegment segment{};
    bool has_segment = true;
    CHECK(NextCloseRangeReplaySegment(
                  cursor, &segment, &has_segment) == 0);
    CHECK(!has_segment && IsZeroSegment(segment));
    CHECK(cursor->complete == 1U && cursor->active == 0U);
    CHECK(IsCloseRangeReplayCursorValid(cursor));
    return true;
}

bool TestBoundariesAndCapacity() {
    g_case_first = 0;
    g_case_last = UINT32_MAX;
    g_case_flags = kCloseRangeReplayUnshare | kCloseRangeReplayCloexec;
    g_case_mask = 0;
    const int32_t endpoints[] = {INT32_MAX, 0, INT32_MAX, -1};
    CloseRangeReplayCursor cursor{};
    CloseRangeReplayDisposition disposition =
            CloseRangeReplayDisposition::kInvalid;
    CHECK(PrepareCloseRangeReplay(
                  0, UINT32_MAX, g_case_flags, endpoints,
                  sizeof(endpoints) / sizeof(endpoints[0]), &cursor,
                  &disposition) == 0);
    CHECK(disposition == CloseRangeReplayDisposition::kReplay);
    CHECK(ExpectSegment(&cursor, UINT32_MAX, UINT32_MAX,
                        g_case_flags, 1U));
    CHECK(ExpectSegment(&cursor, 1U,
                        static_cast<uint32_t>(INT32_MAX) - 1U,
                        kCloseRangeReplayCloexec, 2U));
    CHECK(ExpectSegment(&cursor,
                        static_cast<uint32_t>(INT32_MAX) + 1U,
                        UINT32_MAX, kCloseRangeReplayCloexec, 3U));
    CHECK(ExpectComplete(&cursor));

    g_case_first = static_cast<uint32_t>(INT32_MAX);
    g_case_last = static_cast<uint32_t>(INT32_MAX);
    g_case_flags = kCloseRangeReplayUnshare;
    const int32_t maximum = INT32_MAX;
    CHECK(PrepareCloseRangeReplay(
                  g_case_first, g_case_last, g_case_flags, &maximum, 1,
                  &cursor, &disposition) == 0);
    CHECK(ExpectSegment(&cursor, UINT32_MAX, UINT32_MAX,
                        kCloseRangeReplayUnshare, 1U));
    CHECK(ExpectComplete(&cursor));

    g_case_first = static_cast<uint32_t>(INT32_MAX);
    g_case_last = UINT32_MAX;
    g_case_flags = 0;
    CHECK(PrepareCloseRangeReplay(
                  g_case_first, g_case_last, 0, &maximum, 1, &cursor,
                  &disposition) == 0);
    CHECK(ExpectSegment(&cursor,
                        static_cast<uint32_t>(INT32_MAX) + 1U,
                        UINT32_MAX, 0, 1U));
    CHECK(ExpectComplete(&cursor));

    g_case_first = UINT32_MAX;
    g_case_last = UINT32_MAX;
    CHECK(PrepareCloseRangeReplay(
                  UINT32_MAX, UINT32_MAX, 0, &maximum, 1, &cursor,
                  &disposition) == 0);
    CHECK(disposition == CloseRangeReplayDisposition::kPassthrough);
    CHECK(cursor.protected_count == 0U && cursor.complete == 1U);

    std::vector<int32_t> capacity(kCloseRangeReplayProtectedCapacity);
    for (uint32_t index = 0; index < kCloseRangeReplayProtectedCapacity;
         ++index) {
        capacity[index] = static_cast<int32_t>(
                kCloseRangeReplayProtectedCapacity - index - 1U);
    }
    g_case_first = 0;
    g_case_last = kCloseRangeReplayProtectedCapacity - 1U;
    g_case_flags = kCloseRangeReplayUnshare;
    CHECK(PrepareCloseRangeReplay(
                  g_case_first, g_case_last, g_case_flags,
                  capacity.data(), capacity.size(), &cursor,
                  &disposition) == 0);
    CHECK(cursor.protected_count ==
          kCloseRangeReplayProtectedCapacity);
    CHECK(ExpectSegment(&cursor, UINT32_MAX, UINT32_MAX,
                        kCloseRangeReplayUnshare, 1U));
    CHECK(ExpectComplete(&cursor));
    capacity.push_back(0);
    CHECK(PrepareCloseRangeReplay(
                  g_case_first, g_case_last, 0, capacity.data(),
                  capacity.size(), &cursor, &disposition) == EOVERFLOW);
    return true;
}

bool Rejects(const CloseRangeReplayCursor& cursor) {
    CHECK(!IsCloseRangeReplayCursorValid(&cursor));
    CloseRangeReplayCursor mutable_cursor = cursor;
    CloseRangeReplaySegment segment{1U, 2U, 3U, 4U};
    bool has_segment = true;
    CHECK(NextCloseRangeReplaySegment(
                  &mutable_cursor, &segment, &has_segment) == EINVAL);
    return true;
}

bool TestValidatorCorruption() {
    g_case_first = 1;
    g_case_last = 8;
    g_case_flags = kCloseRangeReplayUnshare;
    g_case_mask = 0;
    const int32_t protected_fds[] = {5, 2};
    CloseRangeReplayCursor initial{};
    CloseRangeReplayDisposition disposition =
            CloseRangeReplayDisposition::kInvalid;
    CHECK(PrepareCloseRangeReplay(
                  1, 8, g_case_flags, protected_fds, 2, &initial,
                  &disposition) == 0);
    CHECK(IsCloseRangeReplayCursorValid(&initial));

#define REJECT_MUTATION(statement)                 \
    do {                                           \
        CloseRangeReplayCursor damaged = initial;  \
        statement;                                 \
        CHECK(Rejects(damaged));                   \
    } while (0)

    REJECT_MUTATION(damaged.magic ^= 1U);
    REJECT_MUTATION(damaged.version += 1U);
    REJECT_MUTATION(damaged.active = 2U);
    REJECT_MUTATION(damaged.complete = 2U);
    REJECT_MUTATION(damaged.unshare_pending = 2U);
    REJECT_MUTATION(damaged.active = 1U; damaged.complete = 1U);
    REJECT_MUTATION(damaged.active = 0U; damaged.complete = 0U);
    REJECT_MUTATION(damaged.protected_count = 0U);
    REJECT_MUTATION(damaged.protected_count =
                            kCloseRangeReplayProtectedCapacity + 1U);
    REJECT_MUTATION(damaged.protected_index = 3U);
    REJECT_MUTATION(damaged.segment_count = 4U);
    REJECT_MUTATION(damaged.original_first = 9U);
    REJECT_MUTATION(damaged.original_flags |= 0x80000000U);
    REJECT_MUTATION(damaged.protected_fds[0] = -1);
    REJECT_MUTATION(damaged.protected_fds[0] = 5;
                    damaged.protected_fds[1] = 2);
    REJECT_MUTATION(damaged.protected_fds[1] = 2);
    REJECT_MUTATION(damaged.next_first = 0U);
    REJECT_MUTATION(damaged.next_first = 2U);
    REJECT_MUTATION(damaged.protected_index = 1U);
    REJECT_MUTATION(damaged.unshare_pending = 0U);

    CloseRangeReplayCursor advanced = initial;
    CHECK(ExpectSegment(&advanced, UINT32_MAX, UINT32_MAX,
                        kCloseRangeReplayUnshare, 1U));
    initial = advanced;
    REJECT_MUTATION(damaged.next_first = 0U);
    REJECT_MUTATION(damaged.next_first = 2U);
    REJECT_MUTATION(damaged.unshare_pending = 1U);
    REJECT_MUTATION(damaged.protected_index = 1U);

    CHECK(ExpectSegment(&advanced, 1U, 1U, 0U, 2U));
    initial = advanced;
    REJECT_MUTATION(damaged.next_first = 1U);
    REJECT_MUTATION(damaged.next_first = 3U);
    REJECT_MUTATION(damaged.unshare_pending = 1U);
    REJECT_MUTATION(damaged.protected_index = 1U);

    CHECK(ExpectSegment(&advanced, 3U, 4U, 0U, 3U));
    CHECK(ExpectSegment(&advanced, 6U, 8U, 0U, 4U));
    CHECK(advanced.complete == 1U);
    initial = advanced;
    REJECT_MUTATION(damaged.protected_index =
                            damaged.protected_count - 1U);
    REJECT_MUTATION(damaged.unshare_pending = 1U);
    REJECT_MUTATION(damaged.active = 2U);
    REJECT_MUTATION(damaged.segment_count =
                            damaged.protected_count + 3U);
#undef REJECT_MUTATION
    return true;
}

bool TestInvalidArguments() {
    g_case_first = 10;
    g_case_last = 1;
    g_case_flags = 0;
    g_case_mask = 0;
    const int32_t fd = 3;
    CloseRangeReplayCursor cursor{};
    CloseRangeReplayDisposition disposition =
            CloseRangeReplayDisposition::kInvalid;
    CHECK(PrepareCloseRangeReplay(
                  10, 1, 0, &fd, 1, &cursor, &disposition) == EINVAL);
    CHECK(PrepareCloseRangeReplay(
                  1, 10, 1U, &fd, 1, &cursor, &disposition) == EINVAL);
    CHECK(PrepareCloseRangeReplay(
                  1, 10, 0, nullptr, 1, &cursor, &disposition) == EINVAL);
    CHECK(PrepareCloseRangeReplay(
                  1, 10, 0, &fd, 1, nullptr, &disposition) == EINVAL);
    CHECK(PrepareCloseRangeReplay(
                  1, 10, 0, &fd, 1, &cursor, nullptr) == EINVAL);
    CHECK(!IsCloseRangeReplayCursorValid(nullptr));
    CHECK(PrepareCloseRangeReplay(
                  1, 10, 0, &fd, 1, &cursor, &disposition) == 0);
    CloseRangeReplaySegment segment{};
    bool has_segment = false;
    CHECK(NextCloseRangeReplaySegment(
                  &cursor, nullptr, &has_segment) == EINVAL);
    CHECK(NextCloseRangeReplaySegment(
                  &cursor, &segment, nullptr) == EINVAL);
    return true;
}

}  // namespace

int main() {
    if (!TestInvalidArguments() || !TestExhaustiveSmallRanges() ||
        !TestBoundariesAndCapacity() || !TestValidatorCorruption()) {
        return 1;
    }
    printf("close_range_replay_harness: PASS checks=%u\n", g_checks);
    return 0;
}
