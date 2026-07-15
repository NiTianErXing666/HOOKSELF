#include "framework_selftest.h"

#include <android/log.h>
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "event_ring.h"
#include "framework_facade_selftest.h"
#include "framework_facade_runtime_selftest.h"
#include "hookself/public_api.h"
#include "proc_status_view.h"
#include "proc_virtual_selftest.h"
#include "resident_session.h"
#include "selective_seccomp_filter.h"
#include "selective_seccomp_plan.h"
#include "shared_abi.h"
#include "tracer/close_range_replay.h"
#include "tracer/mount_syscall_state.h"
#include "tracer/task_table.h"
#include "tracer/wait_decoder.h"
#include "virtual_file_provider.h"
#include "virtual_file_store.h"

namespace hookself::internal {
namespace {

void Check(FrameworkSelfTestReport* report, bool condition, int32_t failure) {
    ++report->checks;
    if (!condition) {
        ++report->failures;
        if (report->first_failure == 0) {
            report->first_failure = failure;
        }
    }
}

void CopyString(char* destination, size_t capacity, const char* source) {
    size_t i = 0;
    while (i + 1 < capacity && source[i] != '\0') {
        destination[i] = source[i];
        ++i;
    }
    destination[i] = '\0';
}

bool TextEquals(const char* left, const char* right) {
    if (left == nullptr || right == nullptr) {
        return false;
    }
    size_t i = 0;
    while (left[i] != '\0' && right[i] != '\0') {
        if (left[i] != right[i]) {
            return false;
        }
        ++i;
    }
    return left[i] == right[i];
}

bool TextContains(const char* text, const char* expected) {
    if (text == nullptr || expected == nullptr) {
        return false;
    }
    size_t expected_size = 0;
    while (expected[expected_size] != '\0') {
        ++expected_size;
    }
    if (expected_size == 0) {
        return true;
    }
    for (size_t start = 0; text[start] != '\0'; ++start) {
        size_t offset = 0;
        while (offset < expected_size && text[start + offset] != '\0' &&
               text[start + offset] == expected[offset]) {
            ++offset;
        }
        if (offset == expected_size) {
            return true;
        }
    }
    return false;
}

struct LogCapture {
    HookselfRuntime* runtime;
    uint32_t calls;
    uint32_t lifecycle_calls;
    uint32_t formatted_lifecycle_calls;
    uint32_t stopped_calls;
    uint32_t formatted_stopped_calls;
    uint32_t probe_enabled;
    uint32_t probe_done;
    uint32_t publish_enabled;
    uint32_t publish_done;
    uint32_t reentrant_done;
    int32_t last_level;
    int32_t reentrant_set_result;
    int32_t reentrant_drain_result;
    int32_t probe_publish_result;
    int64_t probe_open_result;
    char last_message[HOOKSELF_LOG_MESSAGE_CAPACITY];
};

void CaptureLog(int32_t level, const HookselfEvent* event,
                const char* message, void* user_data) {
    auto* capture = static_cast<LogCapture*>(user_data);
    if (capture == nullptr || event == nullptr || message == nullptr) {
        return;
    }
    ++capture->calls;
    if (event->kind == HOOKSELF_EVENT_LIFECYCLE) {
        ++capture->lifecycle_calls;
        const bool formatted = TextContains(message, "kind=LIFECYCLE");
        if (formatted) {
            ++capture->formatted_lifecycle_calls;
        }
        if (event->action == HOOKSELF_STATE_STOPPED) {
            ++capture->stopped_calls;
            if (formatted && TextContains(message, "action=STOPPED(")) {
                ++capture->formatted_stopped_calls;
            }
        }
    }
    capture->last_level = level;
    CopyString(capture->last_message, sizeof(capture->last_message), message);
    if (capture->runtime != nullptr && capture->reentrant_done == 0) {
        capture->reentrant_done = 1;
        capture->reentrant_set_result = hookself_set_log_sink(
                capture->runtime, nullptr, nullptr);
        size_t consumed = 0;
        size_t emitted = 0;
        capture->reentrant_drain_result = hookself_drain_logs(
                capture->runtime, 1, &consumed, &emitted);
    }
    if (capture->runtime != nullptr && capture->publish_enabled != 0 &&
        capture->publish_done == 0 &&
        event->kind == HOOKSELF_EVENT_LIFECYCLE) {
        capture->publish_done = 1;
        const uint8_t content[] = {'l', 'o', 'g', '-', 's', 'i', 'n', 'k'};
        capture->probe_publish_result = hookself_publish_virtual_file(
                capture->runtime, 13, content, sizeof(content));
    }
    if (capture->probe_enabled != 0 && capture->probe_done == 0 &&
        event->kind == HOOKSELF_EVENT_LIFECYCLE) {
        capture->probe_done = 1;
        const long descriptor = syscall(
                __NR_openat, AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC, 0);
        capture->probe_open_result =
                descriptor >= 0 ? descriptor : -errno;
        if (descriptor >= 0) {
            (void)syscall(__NR_close, descriptor);
        }
    }
}

struct DestroyLogCapture {
    HookselfRuntime* runtime;
    uint32_t calls;
    uint32_t destroy_returned;
};

void DestroyFromLog(int32_t level, const HookselfEvent* event,
                    const char* message, void* user_data) {
    (void)level;
    (void)event;
    (void)message;
    auto* capture = static_cast<DestroyLogCapture*>(user_data);
    if (capture == nullptr || capture->runtime == nullptr ||
        capture->calls != 0) {
        return;
    }
    ++capture->calls;
    HookselfRuntime* const runtime = capture->runtime;
    hookself_destroy(runtime);
    capture->destroy_returned = 1;
}

struct ConcurrentDestroyCapture {
    HookselfRuntime* runtime;
    uint32_t callback_calls;
    uint32_t callback_entered;
    uint32_t release_callback;
    uint32_t drain_returned;
    uint32_t destroy_started;
    uint32_t destroy_returned;
    int32_t drain_result;
    size_t consumed;
    size_t emitted;
    size_t max_events;
};

void BlockingLog(int32_t level, const HookselfEvent* event,
                 const char* message, void* user_data) {
    (void)level;
    (void)event;
    (void)message;
    auto* capture = static_cast<ConcurrentDestroyCapture*>(user_data);
    if (capture == nullptr) {
        return;
    }
    __atomic_fetch_add(&capture->callback_calls, 1U, __ATOMIC_RELAXED);
    __atomic_store_n(&capture->callback_entered, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&capture->release_callback,
                           __ATOMIC_ACQUIRE) == 0) {
        usleep(1000);
    }
}

void* DrainLogsThread(void* argument) {
    auto* capture = static_cast<ConcurrentDestroyCapture*>(argument);
    capture->drain_result = hookself_drain_logs(
            capture->runtime, capture->max_events,
            &capture->consumed, &capture->emitted);
    __atomic_store_n(&capture->drain_returned, 1U, __ATOMIC_RELEASE);
    return nullptr;
}

void* DestroyRuntimeThread(void* argument) {
    auto* capture = static_cast<ConcurrentDestroyCapture*>(argument);
    __atomic_store_n(&capture->destroy_started, 1U, __ATOMIC_RELEASE);
    hookself_destroy(capture->runtime);
    __atomic_store_n(&capture->destroy_returned, 1U, __ATOMIC_RELEASE);
    return nullptr;
}

bool WaitForAtomicValue(const uint32_t* value, uint32_t expected,
                        uint32_t timeout_ms) {
    for (uint32_t elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected) {
            return true;
        }
        usleep(1000);
    }
    return __atomic_load_n(value, __ATOMIC_ACQUIRE) == expected;
}

bool WaitForRuntimeRejected(HookselfRuntime* runtime, uint32_t timeout_ms) {
    for (uint32_t elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        int32_t state = HOOKSELF_STATE_IDLE;
        if (hookself_get_state(runtime, &state) ==
            HOOKSELF_E_INVALID_STATE) {
            return true;
        }
        usleep(1000);
    }
    int32_t state = HOOKSELF_STATE_IDLE;
    return hookself_get_state(runtime, &state) == HOOKSELF_E_INVALID_STATE;
}

bool RangeInside(uint64_t offset, uint64_t size, uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

bool DescriptorArrayInside(const SharedRuleBankHeader* bank, uint32_t offset,
                           size_t element_size, uint32_t capacity) {
    return bank != nullptr &&
           RangeInside(offset, element_size * static_cast<uint64_t>(capacity),
                       bank->bank_size);
}

bool ReferenceInsideArena(const SharedRuleBankHeader* bank,
                          const SharedStringRef& reference) {
    return bank != nullptr && reference.offset >= bank->arena_offset &&
           RangeInside(reference.offset, reference.length, bank->bank_size) &&
           reference.offset + reference.length <=
                   static_cast<uint64_t>(bank->arena_offset) + bank->arena_used;
}

bool ReferenceEqualsString(const SharedRuleBankHeader* bank,
                           const SharedStringRef& reference, const char* expected) {
    if (!ReferenceInsideArena(bank, reference)) {
        return false;
    }
    size_t expected_length = 0;
    while (expected[expected_length] != '\0') {
        ++expected_length;
    }
    if (reference.length != expected_length + 1) {
        return false;
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(bank) + reference.offset;
    for (size_t i = 0; i <= expected_length; ++i) {
        if (bytes[i] != static_cast<uint8_t>(expected[i])) {
            return false;
        }
    }
    return true;
}

uint64_t Fnv1a64ForTest(const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool FindMappingPermissions(const void* address, char permissions[5]) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == nullptr) {
        return false;
    }
    const uintptr_t target = reinterpret_cast<uintptr_t>(address);
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char parsed[5] = {};
        if (sscanf(line, "%llx-%llx %4s", &start, &end, parsed) == 3 &&
            target >= start && target < end) {
            for (size_t i = 0; i < sizeof(parsed); ++i) {
                permissions[i] = parsed[i];
            }
            found = true;
            break;
        }
    }
    fclose(maps);
    return found;
}

bool FirstPageIsUnmapped(void* address, size_t page_size) {
    unsigned char resident = 0;
    errno = 0;
    return mincore(address, page_size, &resident) == -1 && errno == ENOMEM;
}

bool BytesAreZero(const void* object, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(object);
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0U) {
            return false;
        }
    }
    return true;
}

bool NextCloseRangeSegment(
        tracer::CloseRangeReplayCursor* cursor, uint32_t first,
        uint32_t last, uint32_t flags, uint32_t sequence) {
    tracer::CloseRangeReplaySegment segment{};
    bool has_segment = false;
    return tracer::NextCloseRangeReplaySegment(
                   cursor, &segment, &has_segment) == 0 &&
           has_segment && segment.first == first && segment.last == last &&
           segment.flags == flags && segment.sequence == sequence;
}

bool CloseRangeReplayComplete(tracer::CloseRangeReplayCursor* cursor) {
    tracer::CloseRangeReplaySegment segment{};
    bool has_segment = true;
    return tracer::NextCloseRangeReplaySegment(
                   cursor, &segment, &has_segment) == 0 &&
           !has_segment && cursor->complete != 0 && cursor->active == 0;
}

}  // namespace

FrameworkSelfTestReport RunFrameworkSelfTest(
        const char* virtual_backing_dir) {
    FrameworkSelfTestReport report{};
    const char* const backing_root =
            virtual_backing_dir == nullptr ? "" : virtual_backing_dir;

    Check(&report, RunProtectedFdIdentitySelfTest() == 0, 6601);
    Check(&report, RunCloseRangeCapabilityPolicySelfTest() == 0, 6602);
    report.chroot_path_result = RunChrootPathResolutionSelfTest(
            &report.chroot_path_first_failure);
    Check(&report, report.chroot_path_result == 0,
          report.chroot_path_first_failure != 0
                  ? report.chroot_path_first_failure
                  : 6603);

    const FrameworkFacadeSelfTestReport facade =
            RunFrameworkFacadeSelfTest();
    report.checks += facade.checks;
    report.failures += facade.failures;
    if (facade.failures != 0U && report.first_failure == 0) {
        report.first_failure = facade.first_failure;
    }

    const ProcVirtualSelfTestReport proc_virtual =
            RunProcVirtualSelfTest();
    report.checks += proc_virtual.checks;
    report.failures += proc_virtual.failures;
    if (proc_virtual.failures != 0 && report.first_failure == 0) {
        report.first_failure = proc_virtual.first_failure;
    }

    {
        constexpr uint8_t kExecPersistentContent[] = {'e', 'x', 'e', 'c'};
        VirtualBackingSession backing_session{};
        InitializeVirtualBackingSession(&backing_session);
        const int backing_session_error = CreateVirtualBackingSession(
                backing_root, 0x6810000000000001ULL, &backing_session);
        VirtualFileBacking backing{};
        InitializeVirtualFileBacking(&backing);
        const int backing_error = backing_session_error == 0
                ? CreateVirtualFileBacking(
                          kExecPersistentContent, sizeof(kExecPersistentContent),
                          HOOKSELF_VFILE_STATIC, 0444, 0x6810U,
                          &backing_session, &backing)
                : backing_session_error;
        Check(&report,
              backing_error == 0 && backing.stable_fd >= 0 &&
                      backing.stable_identity_valid != 0 &&
                      backing.stable_file_type == S_IFREG &&
                      backing.backing_path[0] == '/' &&
                      (fcntl(backing.stable_fd, F_GETFD) & FD_CLOEXEC) == 0,
              6810);
        const int first_open = backing_error == 0
                ? open(backing.backing_path, O_RDONLY | O_CLOEXEC)
                : -1;
        const int second_open = backing_error == 0
                ? open(backing.backing_path, O_RDONLY | O_CLOEXEC)
                : -1;
        char first_byte = '\0';
        char second_byte = '\0';
        const bool independent_reopens =
                first_open >= 0 && second_open >= 0 &&
                read(first_open, &first_byte, 1) == 1 &&
                read(second_open, &second_byte, 1) == 1 &&
                first_byte == 'e' && second_byte == 'e';
        Check(&report, independent_reopens, 6814);
        if (first_open >= 0) {
            (void)syscall(__NR_close, first_open);
        }
        if (second_open >= 0) {
            (void)syscall(__NR_close, second_open);
        }
        DestroyVirtualFileBacking(&backing);

        VirtualFileBacking stale_backing{};
        InitializeVirtualFileBacking(&stale_backing);
        const int stale_backing_error = backing_session_error == 0
                ? CreateVirtualFileBacking(
                          kExecPersistentContent, sizeof(kExecPersistentContent),
                          HOOKSELF_VFILE_STATIC, 0444, 0x6812U,
                          &backing_session, &stale_backing)
                : backing_session_error;
        const int stale_fd = stale_backing.stable_fd;
        const long stale_close_result = stale_fd >= 0
                ? syscall(__NR_close, stale_fd)
                : -1;
        const long replacement_source = syscall(
                __NR_memfd_create, "hookself-stale-replacement", 0);
        long replacement_result = replacement_source;
        if (replacement_source >= 0 && replacement_source != stale_fd) {
            replacement_result = dup3(static_cast<int>(replacement_source),
                                      stale_fd, O_CLOEXEC);
        }
        const bool replacement_ready = stale_backing_error == 0 &&
                stale_close_result == 0 && replacement_source >= 0 &&
                replacement_result == stale_fd;
        DestroyVirtualFileBacking(&stale_backing);
        const bool replacement_survived = replacement_ready &&
                fcntl(stale_fd, F_GETFD) >= 0 && stale_backing.stable_fd < 0;
        Check(&report, replacement_survived, 6812);
        if (replacement_result == stale_fd && stale_fd >= 0) {
            (void)syscall(__NR_close, stale_fd);
        }
        if (replacement_source >= 0 && replacement_source != stale_fd) {
            (void)syscall(__NR_close, replacement_source);
        }

        constexpr uint8_t kCommitContent[] = {'n', 'e', 'w'};
        VirtualFileBacking stale_commit_backing{};
        InitializeVirtualFileBacking(&stale_commit_backing);
        const int stale_commit_create_error = backing_session_error == 0
                ? CreateVirtualFileBacking(
                          kExecPersistentContent, sizeof(kExecPersistentContent),
                          HOOKSELF_VFILE_STATIC, 0444, 0x6813U,
                          &backing_session, &stale_commit_backing)
                : backing_session_error;
        const int stale_commit_fd = stale_commit_backing.stable_fd;
        int stale_commit_snapshot_fd = -1;
        const int stale_commit_prepare_result =
                stale_commit_create_error == 0
                        ? PrepareVirtualFileSnapshot(
                                  &stale_commit_backing, kCommitContent,
                                  sizeof(kCommitContent),
                                  &stale_commit_snapshot_fd)
                        : EINVAL;
        const long stale_commit_close_result =
                stale_commit_prepare_result == 0 && stale_commit_fd >= 0
                        ? syscall(__NR_close, stale_commit_fd)
                        : -1;
        const long stale_commit_replacement_source = syscall(
                __NR_memfd_create, "hookself-stale-commit-replacement", 0);
        long stale_commit_replacement_result = stale_commit_replacement_source;
        if (stale_commit_replacement_source >= 0 &&
            stale_commit_replacement_source != stale_commit_fd) {
            stale_commit_replacement_result = dup3(
                    static_cast<int>(stale_commit_replacement_source),
                    stale_commit_fd, O_CLOEXEC);
        }
        const bool stale_commit_ready = stale_commit_create_error == 0 &&
                stale_commit_prepare_result == 0 &&
                stale_commit_close_result == 0 &&
                stale_commit_replacement_source >= 0 &&
                stale_commit_replacement_result == stale_commit_fd;
        const int stale_commit_result = stale_commit_ready
                ? CommitVirtualFileSnapshot(&stale_commit_backing,
                                            stale_commit_snapshot_fd)
                : EINVAL;
        int rejected_snapshot_fd = 77;
        const int rejected_prepare_result = stale_commit_ready
                ? PrepareVirtualFileSnapshot(&stale_commit_backing,
                                             kCommitContent,
                                             sizeof(kCommitContent),
                                             &rejected_snapshot_fd)
                : EINVAL;
        const bool stale_commit_replacement_survived = stale_commit_ready &&
                stale_commit_result == ESTALE &&
                rejected_prepare_result == ESTALE &&
                rejected_snapshot_fd == -1 &&
                fcntl(stale_commit_fd, F_GETFD) >= 0;
        Check(&report, stale_commit_replacement_survived, 6813);
        if (stale_commit_snapshot_fd >= 0) {
            (void)syscall(__NR_close, stale_commit_snapshot_fd);
        }
        DestroyVirtualFileBacking(&stale_commit_backing);
        if (stale_commit_replacement_result == stale_commit_fd &&
            stale_commit_fd >= 0) {
            (void)syscall(__NR_close, stale_commit_fd);
        }
        if (stale_commit_replacement_source >= 0 &&
            stale_commit_replacement_source != stale_commit_fd) {
            (void)syscall(__NR_close, stale_commit_replacement_source);
        }

        int provider_fd = -1;
        const int provider_error = OpenVirtualFileProviderSource(
                HOOKSELF_VFILE_PROC_STATUS, getpid(), &provider_fd);
        Check(&report,
              provider_error == 0 && provider_fd >= 0 &&
                      (fcntl(provider_fd, F_GETFD) & FD_CLOEXEC) == 0,
              6811);
        if (provider_fd >= 0) {
            close(provider_fd);
        }
        DestroyVirtualBackingSession(&backing_session);
    }

    {
        tracer::CloseRangeReplayCursor cursor{};
        tracer::CloseRangeReplayDisposition disposition =
                tracer::CloseRangeReplayDisposition::kInvalid;
        const int32_t protected_fds[] = {9, 3, -1, 9, 7, 40};
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      1, 12, 0, protected_fds,
                      sizeof(protected_fds) / sizeof(protected_fds[0]),
                      &cursor, &disposition) == 0 &&
                      disposition ==
                              tracer::CloseRangeReplayDisposition::kReplay &&
                      tracer::IsCloseRangeReplayCursorValid(&cursor) &&
                      cursor.protected_count == 3,
              6801);
        Check(&report,
              NextCloseRangeSegment(&cursor, 1, 2, 0, 1) &&
                      NextCloseRangeSegment(&cursor, 4, 6, 0, 2) &&
                      NextCloseRangeSegment(&cursor, 8, 8, 0, 3) &&
                      NextCloseRangeSegment(&cursor, 10, 12, 0, 4) &&
                      CloseRangeReplayComplete(&cursor),
              6802);

        const int32_t outside[] = {2, 20};
        disposition = tracer::CloseRangeReplayDisposition::kInvalid;
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      3, 10, 0, outside,
                      sizeof(outside) / sizeof(outside[0]), &cursor,
                      &disposition) == 0 &&
                      disposition == tracer::CloseRangeReplayDisposition::
                                             kPassthrough &&
                      cursor.complete != 0 && cursor.active == 0,
              6803);

        const int32_t cloexec_protected[] = {5};
        disposition = tracer::CloseRangeReplayDisposition::kInvalid;
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      1, 10,
                       tracer::kCloseRangeReplayUnshare |
                               tracer::kCloseRangeReplayCloexec,
                       cloexec_protected, 1, &cursor, &disposition) == 0 &&
                       disposition ==
                               tracer::CloseRangeReplayDisposition::kReplay &&
                       NextCloseRangeSegment(
                               &cursor, UINT32_MAX, UINT32_MAX,
                               tracer::kCloseRangeReplayUnshare |
                                       tracer::kCloseRangeReplayCloexec,
                               1) &&
                       NextCloseRangeSegment(
                               &cursor, 1, 4,
                               tracer::kCloseRangeReplayCloexec, 2) &&
                       NextCloseRangeSegment(
                               &cursor, 6, 10,
                               tracer::kCloseRangeReplayCloexec, 3) &&
                       CloseRangeReplayComplete(&cursor),
               6804);

        disposition = tracer::CloseRangeReplayDisposition::kInvalid;
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      5, 5, tracer::kCloseRangeReplayUnshare,
                      cloexec_protected, 1, &cursor, &disposition) == 0 &&
                      disposition ==
                              tracer::CloseRangeReplayDisposition::kReplay &&
                      NextCloseRangeSegment(
                              &cursor, UINT32_MAX, UINT32_MAX,
                              tracer::kCloseRangeReplayUnshare, 1) &&
                      CloseRangeReplayComplete(&cursor),
              6805);

        const int32_t split_protected[] = {8, 4};
        disposition = tracer::CloseRangeReplayDisposition::kInvalid;
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      1, 10, tracer::kCloseRangeReplayUnshare,
                      split_protected, 2, &cursor, &disposition) == 0 &&
                      NextCloseRangeSegment(
                              &cursor, UINT32_MAX, UINT32_MAX,
                              tracer::kCloseRangeReplayUnshare, 1) &&
                      NextCloseRangeSegment(&cursor, 1, 3, 0, 2) &&
                      NextCloseRangeSegment(&cursor, 5, 7, 0, 3) &&
                      NextCloseRangeSegment(&cursor, 9, 10, 0, 4) &&
                      CloseRangeReplayComplete(&cursor),
              6806);

        const int32_t maximum_fd[] = {INT32_MAX};
        disposition = tracer::CloseRangeReplayDisposition::kInvalid;
        Check(&report,
              tracer::PrepareCloseRangeReplay(
                      0, UINT32_MAX, 0, maximum_fd, 1, &cursor,
                      &disposition) == 0 &&
                      NextCloseRangeSegment(
                              &cursor, 0,
                              static_cast<uint32_t>(INT32_MAX) - 1U, 0, 1) &&
                      NextCloseRangeSegment(
                              &cursor,
                              static_cast<uint32_t>(INT32_MAX) + 1U,
                              UINT32_MAX, 0, 2) &&
                      CloseRangeReplayComplete(&cursor),
              6807);
    }

    tracer::WaitDecodeOptions decode_options{};
    decode_options.ptrace_options = tracer::kPtraceOptionTraceSysgood;
    const int32_t seccomp_status = static_cast<int32_t>(
            (tracer::kPtraceEventSeccomp << 16U) |
            (static_cast<uint32_t>(SIGTRAP) << 8U) | 0x7fU);
    const tracer::StopEvent seccomp_event =
            tracer::DecodeWaitStatus(seccomp_status, decode_options);
    Check(&report,
          seccomp_event.kind == tracer::StopEventKind::kSeccompStop &&
                  seccomp_event.ptrace_event ==
                          tracer::kPtraceEventSeccomp &&
                  seccomp_event.signal == SIGTRAP &&
                  seccomp_event.tracesysgood == 1,
          69);
    const int32_t syscall_status =
            ((SIGTRAP | 0x80) << 8) | 0x7f;
    const tracer::StopEvent syscall_event =
            tracer::DecodeWaitStatus(syscall_status, decode_options);
    Check(&report,
          syscall_event.kind == tracer::StopEventKind::kSyscallStop &&
                  syscall_event.ptrace_event == 0U,
          70);
    const int32_t ordinary_event_status = static_cast<int32_t>(
            (6U << 16U) | (static_cast<uint32_t>(SIGTRAP) << 8U) | 0x7fU);
    const tracer::StopEvent ordinary_event =
            tracer::DecodeWaitStatus(ordinary_event_status, decode_options);
    Check(&report,
          ordinary_event.kind == tracer::StopEventKind::kPtraceEvent &&
                  ordinary_event.ptrace_event == 6U,
          71);

    void* task_memory = mmap(nullptr, sizeof(tracer::TaskTable),
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Check(&report, task_memory != MAP_FAILED, 72);
    if (task_memory != MAP_FAILED) {
        auto* task_table = static_cast<tracer::TaskTable*>(task_memory);
        tracer::Init(task_table);
        tracer::TaskRecord* task = nullptr;
        const tracer::TaskInsertResult insert_result =
                tracer::Insert(task_table, 101, 101, &task);
        Check(&report,
              task_table->version == tracer::kTaskTableVersion &&
                      tracer::Validate(task_table) &&
                      insert_result == tracer::TaskInsertResult::kInserted &&
                      task != nullptr &&
                      task->resume_mode == tracer::TaskResumeMode::kUnknown,
              73);
        if (task != nullptr) {
            const uint32_t slot = task->slot;
            task->resume_mode = tracer::TaskResumeMode::kSyscall;
            task->active_syscall.flags =
                    tracer::kActiveSyscallValid |
                    tracer::kActiveSyscallFromSeccomp;
            Check(&report, tracer::Validate(task_table), 74);
            tracer::ClearActiveSyscall(task);
            Check(&report,
                  task->resume_mode == tracer::TaskResumeMode::kSyscall &&
                          task->active_syscall.flags ==
                                  tracer::kActiveSyscallNone &&
                          task->active_syscall.syscall_number == -1 &&
                          task->active_syscall.scratch_slot ==
                                  tracer::kInvalidTaskSlot,
                  75);
            task->resume_mode = static_cast<tracer::TaskResumeMode>(3U);
            Check(&report, !tracer::Validate(task_table), 76);
            task->resume_mode = tracer::TaskResumeMode::kCont;
            Check(&report,
                  tracer::EraseAt(task_table, slot) &&
                          tracer::Validate(task_table) &&
                          task_table->tasks[slot].resume_mode ==
                                  tracer::TaskResumeMode::kUnknown,
                  77);
        }
        task_table->version = 3U;
        Check(&report, !tracer::IsInitialized(task_table), 78);
        (void)munmap(task_memory, sizeof(tracer::TaskTable));
    }

    {
        HookselfConfig plan_config{};
        hookself_default_config(&plan_config);
        SelectiveSeccompPlan plan{};
        uint16_t found_class = 0;
        const int32_t expected_protected[] = {
                __NR_dup, __NR_dup3, __NR_fcntl, __NR_ioctl,
                tracer::kMountStateUmount2,
                tracer::kMountStateMount,
                tracer::kMountStatePivotRoot,
                tracer::kMountStateChroot,
                __NR_close, __NR_unshare, __NR_clone, __NR_execve,
                __NR_execveat, tracer::kMountStateOpenTree,
                tracer::kMountStateMoveMount, __NR_clone3, 436,
                tracer::kMountStateMountSetattr};
        bool protected_rules_match =
                BuildSelectiveSeccompPlan(&plan_config, &plan) == 0 &&
                plan.schema_version == kSelectiveSeccompPlanSchemaVersion &&
                plan.class_id == kSelectiveSeccompUnifiedClassId &&
                plan.rule_count == 18U && plan.syscall_set_hash != 0U &&
                plan.filter.rule_count == plan.rule_count;
        for (size_t index = 0;
             protected_rules_match && index < plan.rule_count; ++index) {
            protected_rules_match =
                    plan.rules[index].syscall_number ==
                            expected_protected[index] &&
                    plan.rules[index].class_id == plan.class_id;
        }
        Check(&report,
              protected_rules_match &&
                      FindSelectiveSeccompClass(
                              &plan, __NR_close, &found_class) &&
                      found_class == kSelectiveSeccompUnifiedClassId &&
                      !FindSelectiveSeccompClass(
                              &plan, __NR_write, &found_class) &&
                      found_class == 0U,
              6501);

        HookselfSyscallRule ordered_rules[3]{};
        const int32_t ordered_numbers[] = {
                __NR_gettid, __NR_openat, __NR_getpid};
        for (size_t index = 0; index < 3U; ++index) {
            ordered_rules[index].struct_size = sizeof(HookselfSyscallRule);
            ordered_rules[index].rule_id = static_cast<uint32_t>(index + 1U);
            ordered_rules[index].syscall_number = ordered_numbers[index];
            ordered_rules[index].action =
                    index == 2U ? HOOKSELF_SYSCALL_PASS
                                : HOOKSELF_SYSCALL_OBSERVE;
            ordered_rules[index].phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
        }
        plan_config.syscall_rules = ordered_rules;
        plan_config.syscall_rule_count = 3U;
        plan_config.flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                             HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW;
        SelectiveSeccompPlan ordered_plan{};
        const int ordered_result =
                BuildSelectiveSeccompPlan(&plan_config, &ordered_plan);

        HookselfSyscallRule reordered_rules[] = {
                ordered_rules[2], ordered_rules[1], ordered_rules[0]};
        plan_config.syscall_rules = reordered_rules;
        SelectiveSeccompPlan reordered_plan{};
        const int reordered_result =
                BuildSelectiveSeccompPlan(&plan_config, &reordered_plan);
        bool deterministic =
                ordered_result == 0 && reordered_result == 0 &&
                ordered_plan.rule_count == 45U &&
                ordered_plan.rule_count == reordered_plan.rule_count &&
                ordered_plan.syscall_set_hash ==
                        reordered_plan.syscall_set_hash;
        for (size_t index = 0;
             deterministic && index < ordered_plan.rule_count; ++index) {
            deterministic =
                    ordered_plan.rules[index].syscall_number ==
                            reordered_plan.rules[index].syscall_number &&
                    ordered_plan.rules[index].class_id ==
                            reordered_plan.rules[index].class_id &&
                    (index == 0U ||
                     ordered_plan.rules[index - 1U].syscall_number <
                             ordered_plan.rules[index].syscall_number);
        }
        Check(&report,
              deterministic &&
                      FindSelectiveSeccompClass(
                              &ordered_plan, __NR_getpid, &found_class) &&
                      found_class == kSelectiveSeccompUnifiedClassId,
              6502);

        HookselfConfig nested_plan_config{};
        hookself_default_config(&nested_plan_config);
        nested_plan_config.flags |=
                HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;
        SelectiveSeccompPlan nested_plan{};
        Check(&report,
              BuildSelectiveSeccompPlan(
                      &nested_plan_config, &nested_plan) == 0 &&
                      FindSelectiveSeccompClass(
                              &nested_plan, __NR_ptrace, &found_class) &&
                      found_class == kSelectiveSeccompUnifiedClassId &&
                      FindSelectiveSeccompClass(
                              &nested_plan, __NR_wait4, &found_class) &&
                      found_class == kSelectiveSeccompUnifiedClassId &&
                      FindSelectiveSeccompClass(
                              &nested_plan, __NR_waitid, &found_class) &&
                      found_class == kSelectiveSeccompUnifiedClassId,
              6505);

        plan_config.flags |= HOOKSELF_CONFIG_OBSERVE_ALL;
        SelectiveSeccompPlan rejected_plan = ordered_plan;
        Check(&report,
              BuildSelectiveSeccompPlan(
                      &plan_config, &rejected_plan) == EOPNOTSUPP &&
                      BytesAreZero(&rejected_plan, sizeof(rejected_plan)),
              6503);

        HookselfSyscallRule maximum_rules[HOOKSELF_MAX_SYSCALL_RULES]{};
        hookself_default_config(&plan_config);
        plan_config.flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                             HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW;
        plan_config.syscall_rules = maximum_rules;
        plan_config.syscall_rule_count = HOOKSELF_MAX_SYSCALL_RULES;
        for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
            maximum_rules[index].struct_size = sizeof(HookselfSyscallRule);
            maximum_rules[index].rule_id = index + 1U;
            maximum_rules[index].syscall_number =
                    static_cast<int32_t>(500U + index);
            maximum_rules[index].action = HOOKSELF_SYSCALL_PASS;
            maximum_rules[index].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
        }
        SelectiveSeccompPlan maximum_plan{};
        bool maximum_union =
                BuildSelectiveSeccompPlan(&plan_config, &maximum_plan) == 0 &&
                maximum_plan.rule_count == 171U &&
                maximum_plan.filter.rule_count == 171U &&
                maximum_plan.filter.instruction_count == 347U;
        for (size_t index = 0;
             maximum_union && index < maximum_plan.rule_count; ++index) {
            maximum_union =
                    maximum_plan.rules[index].class_id ==
                            kSelectiveSeccompUnifiedClassId &&
                    (index == 0U ||
                     maximum_plan.rules[index - 1U].syscall_number <
                             maximum_plan.rules[index].syscall_number);
        }
        Check(&report, maximum_union, 6504);

        SelectiveSeccompRule builder_limit_rules[
                kMaxSelectiveSeccompRules]{};
        for (size_t index = 0; index < kMaxSelectiveSeccompRules; ++index) {
            builder_limit_rules[index].syscall_number =
                    static_cast<int32_t>(index);
            builder_limit_rules[index].class_id =
                    kSelectiveSeccompUnifiedClassId;
        }
        SelectiveSeccompFilter builder_limit_filter{};
        Check(&report,
              BuildSelectiveSeccompFilter(
                      builder_limit_rules, kMaxSelectiveSeccompRules,
                      SelectiveSeccompArchMismatchAction::kKillProcess,
                      &builder_limit_filter) == 0 &&
                      builder_limit_filter.rule_count ==
                              kMaxSelectiveSeccompRules &&
                      builder_limit_filter.instruction_count == 389U,
              6505);
    }

    const SelectiveSeccompRule seccomp_rule{
            static_cast<int32_t>(__NR_gettid), 0xffffU};
    SelectiveSeccompFilter seccomp_filter{};
    Check(&report,
          BuildSelectiveSeccompFilter(
                  &seccomp_rule, 1,
                  SelectiveSeccompArchMismatchAction::kKillProcess,
                  &seccomp_filter) == 0 &&
                  seccomp_filter.rule_count == 1U &&
                  seccomp_filter.instruction_count == 7U &&
                  seccomp_filter.instructions[5].k ==
                          (SECCOMP_RET_TRACE | 0xffffU) &&
                  seccomp_filter.instructions[6].k == SECCOMP_RET_ALLOW,
          65);
    const SelectiveSeccompRule duplicate_rules[] = {
            {static_cast<int32_t>(__NR_gettid), 1U},
            {static_cast<int32_t>(__NR_gettid), 2U},
    };
    SelectiveSeccompFilter rejected_filter = seccomp_filter;
    Check(&report,
          BuildSelectiveSeccompFilter(
                  duplicate_rules, 2,
                  SelectiveSeccompArchMismatchAction::kAllow,
                  &rejected_filter) == EEXIST &&
                  BytesAreZero(&rejected_filter, sizeof(rejected_filter)),
          66);
    const SelectiveSeccompRule negative_rule{-1, 0U};
    rejected_filter = seccomp_filter;
    Check(&report,
          BuildSelectiveSeccompFilter(
                  &negative_rule, 1,
                  SelectiveSeccompArchMismatchAction::kAllow,
                  &rejected_filter) == EINVAL &&
                  BytesAreZero(&rejected_filter, sizeof(rejected_filter)),
          67);
    int32_t failed_tid = -1;
    Check(&report,
          InstallSelectiveSeccompFilter(
                  &seccomp_filter, 1U << 31, &failed_tid) == EINVAL &&
                  failed_tid == 0,
          68);

    HookselfConfig config{};
    hookself_default_config(&config);
    Check(&report, config.struct_size == sizeof(config), 1);
    Check(&report, config.abi_version == HOOKSELF_ABI_VERSION, 2);
    Check(&report, hookself_validate_config(&config) == HOOKSELF_OK, 3);
    HookselfConfig missing_syscall_rules = config;
    missing_syscall_rules.syscall_rule_count = 1U;
    missing_syscall_rules.syscall_rules = nullptr;
    Check(&report,
          hookself_validate_config(&missing_syscall_rules) ==
                  HOOKSELF_E_CAPACITY,
          7106);

    HookselfPtraceCapabilities ptrace_capabilities{};
    ptrace_capabilities.struct_size = sizeof(ptrace_capabilities);
    constexpr uint64_t kExpectedRuntimePtraceFeatures =
            HOOKSELF_PTRACE_FEATURE_TRACEME_VIEW |
            HOOKSELF_PTRACE_FEATURE_DUMPABLE_PTRACER_VIEW |
            HOOKSELF_PTRACE_FEATURE_PROC_STATUS_VIEW |
            HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC;
    constexpr uint64_t kExpectedNestedEngineFeatures =
            HOOKSELF_PTRACE_FEATURE_DESCENDANT_TGID_STATE |
            HOOKSELF_PTRACE_FEATURE_ATTACH_SEIZE |
            HOOKSELF_PTRACE_FEATURE_RESUME_CONTROL |
            HOOKSELF_PTRACE_FEATURE_WAIT_EMULATION |
            HOOKSELF_PTRACE_FEATURE_SIGNAL_STATE |
            HOOKSELF_PTRACE_FEATURE_MEMORY_ACCESS |
            HOOKSELF_PTRACE_FEATURE_REGSET |
            HOOKSELF_PTRACE_FEATURE_SYSCALL_INFO;
    Check(&report,
          hookself_get_ptrace_capabilities(&ptrace_capabilities) ==
                          HOOKSELF_OK &&
                  ptrace_capabilities.version ==
                          HOOKSELF_PTRACE_CAPABILITIES_VERSION &&
                  ptrace_capabilities.runtime_features ==
                          kExpectedRuntimePtraceFeatures &&
                  (ptrace_capabilities.engine_features &
                   kExpectedNestedEngineFeatures) ==
                          kExpectedNestedEngineFeatures &&
                  ptrace_capabilities.max_tasks == 512U &&
                  ptrace_capabilities.max_relations == 512U &&
                  ptrace_capabilities.max_pending_waits == 512U &&
                  ptrace_capabilities.per_tracee_event_capacity == 4U,
          7101);
    HookselfPtraceCapabilities invalid_capabilities{};
    invalid_capabilities.struct_size =
            sizeof(invalid_capabilities) - 1U;
    Check(&report,
          hookself_get_ptrace_capabilities(nullptr) ==
                          HOOKSELF_E_INVALID_ARGUMENT &&
                  hookself_get_ptrace_capabilities(
                          &invalid_capabilities) ==
                          HOOKSELF_E_INVALID_ARGUMENT,
          7102);

    HookselfConfig nested_config = config;
    nested_config.flags |= HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;
    Check(&report,
          hookself_validate_config(&nested_config) ==
                  HOOKSELF_E_INVALID_ARGUMENT,
          7103);
    nested_config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    nested_config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                           HOOKSELF_CONFIG_TRACE_DESCENDANTS;
    Check(&report,
          hookself_validate_config(&nested_config) == HOOKSELF_OK,
          7104);
    nested_config.flags |= HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP;
    Check(&report,
          hookself_validate_config(&nested_config) ==
                  HOOKSELF_E_INVALID_ARGUMENT,
          7105);

    HookselfPathRule path_rule{};
    path_rule.struct_size = sizeof(path_rule);
    path_rule.rule_id = 11;
    path_rule.priority = 10;
    path_rule.action = HOOKSELF_PATH_REDIRECT;
    path_rule.operation_mask = HOOKSELF_PATH_OP_ALL;
    CopyString(path_rule.guest_prefix, sizeof(path_rule.guest_prefix), "/virtual");
    CopyString(path_rule.host_prefix, sizeof(path_rule.host_prefix), "/data/local/tmp/host");
    config.path_rules = &path_rule;
    config.path_rule_count = 1;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT;

    HookselfSyscallRule syscall_rule{};
    syscall_rule.struct_size = sizeof(syscall_rule);
    syscall_rule.rule_id = 12;
    syscall_rule.syscall_number = __NR_openat;
    syscall_rule.action = HOOKSELF_SYSCALL_OBSERVE;
    syscall_rule.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    config.syscall_rules = &syscall_rule;
    config.syscall_rule_count = 1;

    uint8_t virtual_content[] = {'v', 'i', 'r', 't', 'u', 'a', 'l', '\n'};
    HookselfVirtualFile virtual_file{};
    virtual_file.struct_size = sizeof(virtual_file);
    virtual_file.file_id = 13;
    virtual_file.provider = HOOKSELF_VFILE_DYNAMIC_SNAPSHOT;
    virtual_file.mode = 0444;
    virtual_file.initial_content = virtual_content;
    virtual_file.initial_content_size = sizeof(virtual_content);
    CopyString(virtual_file.guest_path, sizeof(virtual_file.guest_path),
               "/proc/self/hookself-test");
    config.virtual_files = &virtual_file;
    config.virtual_file_count = 1;
    CopyString(config.virtual_backing_dir,
               sizeof(config.virtual_backing_dir), backing_root);
    config.flags |= HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES;
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    Check(&report, hookself_validate_config(&config) == HOOKSELF_OK, 4);

    HookselfConfig invalid = config;
    invalid.abi_version = HOOKSELF_ABI_VERSION + 1;
    Check(&report, hookself_validate_config(&invalid) == HOOKSELF_E_ABI_MISMATCH, 5);
    invalid = config;
    invalid.flags |= HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP;
    Check(&report, hookself_validate_config(&invalid) == HOOKSELF_E_INVALID_ARGUMENT, 6);
    HookselfSyscallRule builtin_id_rule = syscall_rule;
    builtin_id_rule.rule_id = HOOKSELF_BUILTIN_RULE_ID_MIN;
    invalid = config;
    invalid.syscall_rules = &builtin_id_rule;
    Check(&report,
          hookself_validate_config(&invalid) == HOOKSELF_E_INVALID_ARGUMENT,
          48);

    uint8_t status_sample[] =
            "Name:\thookself\nTgid:\t123\nPid:\t124\nTracerPid:\t4567\n";
    ProcStatusMetadata status_metadata{};
    Check(&report,
          ParseProcStatusMetadata(
                  status_sample, sizeof(status_sample) - 1U, 123,
                  &status_metadata) == 0 &&
                  status_metadata.tgid == 123 &&
                  status_metadata.pid == 124 &&
                  status_metadata.tracer_value_length == 4,
          49);
    Check(&report,
          RewriteTracerPidValue(
                  status_sample, sizeof(status_sample) - 1U) == 4 &&
                  TracerPidValueIsZero(
                          status_sample, sizeof(status_sample) - 1U,
                          status_metadata),
          50);
    Check(&report,
          ParseProcStatusMetadata(
                  status_sample, sizeof(status_sample) - 1U, 999,
                  &status_metadata) == EPROTO,
          51);

    HookselfEvent formatted_event{};
    formatted_event.struct_size = sizeof(formatted_event);
    formatted_event.kind = HOOKSELF_EVENT_SYSCALL;
    formatted_event.sequence = 42;
    formatted_event.monotonic_time_ns = 123456;
    formatted_event.tgid = 100;
    formatted_event.tid = 101;
    formatted_event.syscall_number = __NR_openat;
    formatted_event.phase = HOOKSELF_SYSCALL_PHASE_ENTRY;
    formatted_event.action = HOOKSELF_SYSCALL_OBSERVE;
    formatted_event.arguments[0] = static_cast<uint64_t>(AT_FDCWD);
    formatted_event.arguments[1] = 0x1234;
    CopyString(formatted_event.path, sizeof(formatted_event.path),
               "/proc/self/status\nquoted\"");
    char formatted_message[HOOKSELF_LOG_MESSAGE_CAPACITY]{};
    size_t formatted_size = 0;
    const int32_t formatted_result = hookself_format_event(
            &formatted_event, formatted_message, sizeof(formatted_message),
            &formatted_size);
    Check(&report,
          TextEquals(hookself_syscall_name(__NR_openat), "openat") &&
                  TextEquals(hookself_syscall_name(-1), "unknown"),
          54);
    Check(&report,
          hookself_event_log_level(&formatted_event) == HOOKSELF_LOG_TRACE &&
                  formatted_result == HOOKSELF_OK &&
                  formatted_size != 0 &&
                  TextContains(formatted_message, "level=TRACE") &&
                  TextContains(formatted_message, "syscall=openat(") &&
                  TextContains(formatted_message, "phase=ENTRY") &&
                  TextContains(formatted_message,
                               "path=\"/proc/self/status\\nquoted\\\"\""),
          55);
    char tiny_message[16]{};
    size_t tiny_size = 0;
    Check(&report,
          hookself_format_event(
                  &formatted_event, tiny_message, sizeof(tiny_message),
                  &tiny_size) == HOOKSELF_OK &&
                  tiny_size == formatted_size &&
                  tiny_message[sizeof(tiny_message) - 1U] == '\0',
          56);
    HookselfEvent boundary_event = formatted_event;
    for (size_t i = 0; i < sizeof(boundary_event.path); ++i) {
        boundary_event.path[i] = '\x01';
        boundary_event.translated_path[i] = '\x02';
    }
    char boundary_message[HOOKSELF_LOG_MESSAGE_CAPACITY]{};
    size_t boundary_size = 0;
    Check(&report,
          hookself_format_event(
                  &boundary_event, boundary_message,
                  sizeof(boundary_message), &boundary_size) == HOOKSELF_OK &&
                  boundary_size >= sizeof(boundary_message) &&
                  TextContains(boundary_message, "path_truncated=true") &&
                  TextContains(boundary_message,
                               "translated_path_truncated=true") &&
                  !TextContains(boundary_message, " path=\"") &&
                  !TextContains(boundary_message, " translated=\""),
          63);

    SharedSessionMapping shared{};
    const int32_t shared_virtual_fds[] = {-1};
    const char* const shared_virtual_paths[] = {
            "/hookself/framework-shared-backing"};
    const int32_t self_pid = static_cast<int32_t>(getpid());
    const int32_t self_tid = static_cast<int32_t>(syscall(__NR_gettid));
    constexpr uint64_t kTestStartTime = 0x1122334455667788ULL;
    constexpr uint64_t kTestNonce = 0x8877665544332211ULL;
    Check(&report,
          CreateSharedSession(config, self_pid, self_tid, kTestStartTime, kTestNonce,
                              &shared, shared_virtual_fds,
                              shared_virtual_paths) == HOOKSELF_OK,
          21);
    if (shared.fd >= 0) {
        SharedHeader* header = GetSharedHeader(shared);
        SharedControlPage* control = GetSharedControl(shared);
        SharedRuleBankHeader* bank0 = GetSharedRuleBank(shared, 0);
        SharedRuleBankHeader* bank1 = GetSharedRuleBank(shared, 1);
        Check(&report,
              ValidateSharedSession(shared) &&
                      (fcntl(shared.fd, F_GETFD) & FD_CLOEXEC) == 0,
              22);
        Check(&report,
              header != nullptr && header->magic == kSharedMagic &&
                      header->abi_version == kSharedAbiVersion &&
                      header->header_size == sizeof(SharedHeader) &&
                      header->arch == kSharedArchArm64 && header->target_pid == self_pid &&
                      header->bootstrap_tid == self_tid &&
                      header->target_start_time == kTestStartTime &&
                      header->nonce == kTestNonce,
              23);
        Check(&report,
              header != nullptr && header->page_size != 0 &&
                      (header->page_size & (header->page_size - 1U)) == 0 &&
                      shared.prefix_size % header->page_size == 0 &&
                      shared.scratch_size % header->page_size == 0 &&
                      shared.total_size == shared.prefix_size + shared.scratch_size &&
                      header->total_size == shared.total_size,
              24);
        Check(&report,
              header != nullptr && RangeInside(header->control.offset,
                                               header->control.size,
                                               shared.prefix_size) &&
                      RangeInside(header->event_ring.offset, header->event_ring.size,
                                  shared.prefix_size) &&
                      RangeInside(header->rule_banks[0].offset,
                                  header->rule_banks[0].size, shared.prefix_size) &&
                      RangeInside(header->rule_banks[1].offset,
                                  header->rule_banks[1].size, shared.prefix_size) &&
                      header->scratch.offset == shared.prefix_size &&
                      header->scratch.size == shared.scratch_size,
              25);
        Check(&report,
              header != nullptr && header->control.offset >= header->page_size &&
                      header->control.offset + header->control.size <=
                              header->event_ring.offset &&
                      header->event_ring.offset + header->event_ring.size <=
                              header->rule_banks[0].offset &&
                      header->rule_banks[0].offset + header->rule_banks[0].size <=
                              header->rule_banks[1].offset &&
                      header->rule_banks[1].offset + header->rule_banks[1].size <=
                              shared.prefix_size,
              26);
        Check(&report,
              control != nullptr && control->tracer_state == HOOKSELF_STATE_CONFIGURED &&
                      control->active_rule_bank == 0 &&
                      control->published_generation == 1,
              27);
        Check(&report,
              bank0 != nullptr && bank0->generation == 1 &&
                      bank0->bank_size == SharedRuleBankBytes() &&
                      bank0->path_rule_count == 1 && bank0->syscall_rule_count == 1 &&
                      bank0->virtual_file_count == 1 && bank0->arena_used != 0 &&
                      bank0->checksum ==
                              Fnv1a64ForTest(
                                      reinterpret_cast<const uint8_t*>(bank0) +
                                              sizeof(SharedRuleBankHeader),
                                      bank0->bank_size - sizeof(SharedRuleBankHeader)),
              28);
        Check(&report,
              bank0 != nullptr &&
                      DescriptorArrayInside(bank0, bank0->path_rules_offset,
                                            sizeof(SharedPathRuleDesc),
                                            HOOKSELF_MAX_PATH_RULES) &&
                      DescriptorArrayInside(bank0, bank0->syscall_rules_offset,
                                            sizeof(SharedSyscallRuleDesc),
                                            HOOKSELF_MAX_SYSCALL_RULES) &&
                      DescriptorArrayInside(bank0, bank0->virtual_files_offset,
                                            sizeof(SharedVirtualFileDesc),
                                            HOOKSELF_MAX_VIRTUAL_FILES) &&
                      bank0->arena_offset <= bank0->bank_size &&
                      bank0->arena_capacity == bank0->bank_size - bank0->arena_offset &&
                      bank0->arena_used <= bank0->arena_capacity,
              29);
        if (bank0 != nullptr) {
            const auto* bank_bytes = reinterpret_cast<const uint8_t*>(bank0);
            const auto* shared_path = reinterpret_cast<const SharedPathRuleDesc*>(
                    bank_bytes + bank0->path_rules_offset);
            const auto* shared_syscall = reinterpret_cast<const SharedSyscallRuleDesc*>(
                    bank_bytes + bank0->syscall_rules_offset);
            const auto* shared_file = reinterpret_cast<const SharedVirtualFileDesc*>(
                    bank_bytes + bank0->virtual_files_offset);
            Check(&report,
                  shared_path[0].rule_id == path_rule.rule_id &&
                          shared_path[0].priority == path_rule.priority &&
                          shared_path[0].action == path_rule.action &&
                          shared_path[0].operation_mask == path_rule.operation_mask &&
                          ReferenceEqualsString(bank0, shared_path[0].guest_prefix,
                                                "/virtual") &&
                          ReferenceEqualsString(bank0, shared_path[0].host_prefix,
                                                "/data/local/tmp/host"),
                  30);
            Check(&report,
                  shared_syscall[0].rule_id == syscall_rule.rule_id &&
                          shared_syscall[0].syscall_number == syscall_rule.syscall_number &&
                          shared_syscall[0].action == syscall_rule.action &&
                          shared_syscall[0].phase_mask == syscall_rule.phase_mask,
                  31);
            Check(&report,
                  shared_file[0].file_id == virtual_file.file_id &&
                          shared_file[0].provider == virtual_file.provider &&
                          shared_file[0].mode == virtual_file.mode &&
                          shared_file[0].target_fd == -1 &&
                          ReferenceEqualsString(bank0, shared_file[0].guest_path,
                                                "/proc/self/hookself-test") &&
                          ReferenceEqualsString(bank0, shared_file[0].backing_path,
                                                "/hookself/framework-shared-backing"),
                  32);
        }
        Check(&report,
              bank1 != nullptr && bank1->generation == 0 && bank1->checksum == 0 &&
                      bank1->bank_size == SharedRuleBankBytes() &&
                      bank1->path_rule_count == 0 && bank1->syscall_rule_count == 0 &&
                      bank1->virtual_file_count == 0 && bank1->arena_used == 0,
              33);

        SharedRegion saved_event_region{};
        if (header != nullptr) {
            saved_event_region = header->event_ring;
            header->event_ring.offset = shared.prefix_size;
            header->event_ring.size = 1;
        }
        Check(&report,
              header != nullptr && !ValidateSharedSession(shared) &&
                      GetSharedEventRing(shared) == nullptr,
              34);
        if (header != nullptr) {
            header->event_ring = saved_event_region;
        }
        Check(&report, ValidateSharedSession(shared), 35);

        Check(&report,
              header != nullptr && shared.tracee_scratch_mapping != nullptr &&
                      header->tracee_scratch_address ==
                              reinterpret_cast<uintptr_t>(
                                      shared.tracee_scratch_mapping) &&
                      shared.scratch_size == SharedScratchBytes() &&
                      shared.scratch_size >=
                              sizeof(SharedScratchFrame) * kMaxTrackedTasks,
              36);
        char scratch_permissions[5] = {};
        const bool scratch_mapping_found =
                FindMappingPermissions(shared.tracee_scratch_mapping,
                                       scratch_permissions);
        Check(&report, scratch_mapping_found, 37);
        Check(&report,
              scratch_mapping_found && scratch_permissions[0] == 'r' &&
                      scratch_permissions[1] == '-' && scratch_permissions[2] == '-' &&
                      scratch_permissions[3] == 's',
              38);

        void* writable_scratch =
                header == nullptr
                        ? MAP_FAILED
                        : mmap(nullptr, shared.scratch_size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, shared.fd,
                               static_cast<off_t>(header->scratch.offset));
        Check(&report,
              writable_scratch != MAP_FAILED &&
                      writable_scratch != shared.tracee_scratch_mapping,
              39);
        if (writable_scratch != MAP_FAILED) {
            auto* writable_frames =
                    static_cast<SharedScratchFrame*>(writable_scratch);
            const auto* tracee_frames = static_cast<const volatile SharedScratchFrame*>(
                    shared.tracee_scratch_mapping);
            writable_frames[0].guard_before = kScratchGuardBefore;
            writable_frames[0].owner_tid = self_tid;
            writable_frames[0].generation = 7;
            writable_frames[0].path_lengths[0] = 1;
            writable_frames[0].paths[0][0] = 'S';
            writable_frames[0].paths[0][1] = '\0';
            writable_frames[0].guard_after = kScratchGuardAfter;
            writable_frames[kMaxTrackedTasks - 1].guard_after = kScratchGuardAfter;
            Check(&report,
                  tracee_frames[0].guard_before == kScratchGuardBefore &&
                          tracee_frames[0].owner_tid == self_tid &&
                          tracee_frames[0].generation == 7 &&
                          tracee_frames[0].path_lengths[0] == 1 &&
                          tracee_frames[0].paths[0][0] == 'S' &&
                          tracee_frames[0].guard_after == kScratchGuardAfter &&
                          tracee_frames[kMaxTrackedTasks - 1].guard_after ==
                                  kScratchGuardAfter,
                  40);
        }

        EventRingHeader* shared_ring = GetSharedEventRing(shared);
        Check(&report,
              header != nullptr && shared_ring != nullptr &&
                      reinterpret_cast<uint8_t*>(shared_ring) ==
                              static_cast<uint8_t*>(shared.prefix_mapping) +
                                      header->event_ring.offset &&
                      header->event_ring.size >= EventRingBytes(config.event_capacity) &&
                      shared_ring->magic == kEventRingMagic &&
                      shared_ring->version == kEventRingVersion &&
                      shared_ring->capacity == config.event_capacity &&
                      shared_ring->event_size == sizeof(HookselfEvent),
              41);
        if (shared_ring != nullptr) {
            HookselfEvent shared_event{};
            shared_event.kind = HOOKSELF_EVENT_SYSCALL;
            shared_event.syscall_number = __NR_openat;
            shared_event.rule_id = syscall_rule.rule_id;
            CopyString(shared_event.path, sizeof(shared_event.path), "/shared-ring");
            HookselfEvent shared_output{};
            Check(&report,
                  PushEvent(shared_ring, shared_event) &&
                          ReadEvents(shared_ring, &shared_output, 1) == 1 &&
                          shared_output.sequence == 1 &&
                          shared_output.syscall_number == __NR_openat &&
                          shared_output.rule_id == syscall_rule.rule_id &&
                          shared_output.path[1] == 's',
                  42);
        }
        const uint8_t published_content[] = {'g', 'e', 'n', '2'};
        virtual_file.initial_content = published_content;
        virtual_file.initial_content_size = sizeof(published_content);
        Check(&report,
              PublishSharedConfig(config, &shared, shared_virtual_fds,
                                  shared_virtual_paths) == HOOKSELF_OK,
              48);
        SharedRuleBankHeader* published_bank = GetSharedRuleBank(shared, 1);
        Check(&report,
              control != nullptr && control->active_rule_bank == 1 &&
                      control->published_generation == 2 &&
                      published_bank != nullptr && published_bank->generation == 2 &&
                      published_bank->virtual_file_count == 1,
              49);
        if (published_bank != nullptr) {
            const auto* bytes = reinterpret_cast<const uint8_t*>(published_bank);
            const auto* files = reinterpret_cast<const SharedVirtualFileDesc*>(
                    bytes + published_bank->virtual_files_offset);
            Check(&report,
                  files[0].file_id == virtual_file.file_id &&
                          files[0].target_fd == -1 &&
                          ReferenceEqualsString(
                                  published_bank, files[0].guest_path,
                                  "/proc/self/hookself-test") &&
                          ReferenceEqualsString(
                                  published_bank, files[0].backing_path,
                                  "/hookself/framework-shared-backing"),
                  50);
        }
        Check(&report, ValidateSharedSession(shared), 51);
        virtual_file.initial_content = virtual_content;
        virtual_file.initial_content_size = sizeof(virtual_content);
        Check(&report,
              PublishSharedConfig(config, &shared, shared_virtual_fds,
                                  shared_virtual_paths) == HOOKSELF_OK &&
                      control != nullptr && control->active_rule_bank == 0 &&
                      control->published_generation == 3 &&
                      ValidateSharedSession(shared),
              52);
        if (writable_scratch != MAP_FAILED) {
            Check(&report, munmap(writable_scratch, shared.scratch_size) == 0, 43);
        }

        const int old_fd = shared.fd;
        struct stat old_fd_stat {};
        const bool old_fd_identity_valid =
                fstat(old_fd, &old_fd_stat) == 0;
        void* const old_prefix_mapping = shared.prefix_mapping;
        void* const old_scratch_mapping = shared.tracee_scratch_mapping;
        const size_t page_size = header == nullptr ? 4096 : header->page_size;
        DestroySharedSession(&shared);
        Check(&report,
              shared.fd == -1 && shared.prefix_mapping == nullptr &&
                      shared.prefix_size == 0 &&
                      shared.tracee_scratch_mapping == nullptr &&
                      shared.scratch_size == 0 && shared.total_size == 0,
              44);
        struct stat current_fd_stat {};
        errno = 0;
        const int current_fd_result = fstat(old_fd, &current_fd_stat);
        const bool original_fd_released =
                current_fd_result == -1 && errno == EBADF;
        const bool fd_number_reused =
                current_fd_result == 0 &&
                (current_fd_stat.st_dev != old_fd_stat.st_dev ||
                 current_fd_stat.st_ino != old_fd_stat.st_ino);
        Check(&report,
              old_fd_identity_valid &&
                      (original_fd_released || fd_number_reused),
              45);
        Check(&report, FirstPageIsUnmapped(old_prefix_mapping, page_size), 46);
        Check(&report, FirstPageIsUnmapped(old_scratch_mapping, page_size), 47);
    }

    HookselfRuntime* runtime = nullptr;
    Check(&report, hookself_create(&config, &runtime) == HOOKSELF_OK && runtime != nullptr, 7);
    if (runtime != nullptr) {
        LogCapture log_capture{};
        log_capture.runtime = runtime;
        log_capture.probe_enabled = 1;
        log_capture.publish_enabled = 1;
        log_capture.probe_open_result = INT64_MIN;
        log_capture.probe_publish_result = HOOKSELF_E_INTERNAL;
        log_capture.reentrant_set_result = HOOKSELF_E_INTERNAL;
        log_capture.reentrant_drain_result = HOOKSELF_E_INTERNAL;
        Check(&report,
              hookself_set_log_sink(runtime, CaptureLog, &log_capture) ==
                      HOOKSELF_OK,
              57);
        virtual_content[0] = 'X';
        int32_t state = -1;
        Check(&report, hookself_get_state(runtime, &state) == HOOKSELF_OK &&
                       state == HOOKSELF_STATE_CONFIGURED, 8);
        HookselfStats stats{};
        stats.struct_size = sizeof(stats);
        Check(&report, hookself_get_stats(runtime, &stats) == HOOKSELF_OK &&
                       stats.state == HOOKSELF_STATE_CONFIGURED, 9);
        Check(&report, hookself_read_events(runtime, nullptr, 0) == 0, 10);
        const uint8_t update[] = {'u', 'p', 'd', 'a', 't', 'e', 'd'};
        Check(&report, hookself_publish_virtual_file(runtime, 13, update, sizeof(update)) ==
                       HOOKSELF_OK, 11);
        const int32_t start_result = hookself_start(runtime);
        HookselfStats pre_log_stats{};
        pre_log_stats.struct_size = sizeof(pre_log_stats);
        (void)hookself_get_stats(runtime, &pre_log_stats);
        size_t active_consumed_logs = 0;
        size_t active_emitted_logs = 0;
        const int32_t active_drain_result =
                start_result == HOOKSELF_OK
                        ? hookself_drain_logs(
                                  runtime, 64, &active_consumed_logs,
                                  &active_emitted_logs)
                        : HOOKSELF_E_INVALID_STATE;
        HookselfStats post_log_stats{};
        post_log_stats.struct_size = sizeof(post_log_stats);
        (void)hookself_get_stats(runtime, &post_log_stats);
        size_t quiet_consumed_logs = 0;
        size_t quiet_emitted_logs = 0;
        const int32_t quiet_drain_result =
                start_result == HOOKSELF_OK
                        ? hookself_drain_logs(
                                  runtime, 64, &quiet_consumed_logs,
                                  &quiet_emitted_logs)
                        : HOOKSELF_E_INVALID_STATE;
        Check(&report,
              active_drain_result == HOOKSELF_OK &&
                      active_consumed_logs > 0 && active_emitted_logs > 0 &&
                      log_capture.probe_done != 0 &&
                      log_capture.probe_open_result >= 0 &&
                      log_capture.publish_done != 0 &&
                      log_capture.probe_publish_result == HOOKSELF_OK &&
                      log_capture.reentrant_set_result == HOOKSELF_E_BUSY &&
                      log_capture.reentrant_drain_result == HOOKSELF_E_BUSY &&
                      post_log_stats.observed_syscalls ==
                              pre_log_stats.observed_syscalls &&
                      post_log_stats.internal_fd_operations ==
                              pre_log_stats.internal_fd_operations + 1U &&
                      quiet_drain_result == HOOKSELF_OK &&
                      quiet_consumed_logs == 0 && quiet_emitted_logs == 0,
              60);
        const int32_t stop_result = start_result == HOOKSELF_OK
                                            ? hookself_stop(runtime)
                                            : HOOKSELF_E_INVALID_STATE;
        Check(&report, start_result == HOOKSELF_OK, 12);
        HookselfStats stop_stats{};
        stop_stats.struct_size = sizeof(stop_stats);
        (void)hookself_get_stats(runtime, &stop_stats);
        const int32_t stop_failure_id =
                530000 + stop_stats.fatal_code * 1000 +
                (stop_stats.fatal_errno < 0
                         ? -stop_stats.fatal_errno
                         : stop_stats.fatal_errno);
        Check(&report, stop_result == HOOKSELF_OK,
              stop_result == HOOKSELF_OK ? 53 : stop_failure_id);
        const uint32_t calls_before_final_drain = log_capture.calls;
        const uint32_t lifecycle_before_final_drain =
                log_capture.lifecycle_calls;
        const uint32_t formatted_lifecycle_before_final_drain =
                log_capture.formatted_lifecycle_calls;
        const uint32_t stopped_before_final_drain =
                log_capture.stopped_calls;
        const uint32_t formatted_stopped_before_final_drain =
                log_capture.formatted_stopped_calls;
        size_t drained_logs = 0;
        size_t emitted_logs = 0;
        const int32_t drain_result = hookself_drain_logs(
                runtime, static_cast<size_t>(config.event_capacity) + 1U,
                &drained_logs, &emitted_logs);
        Check(&report,
              drain_result == HOOKSELF_OK && drained_logs > 0 &&
                      drained_logs <= config.event_capacity &&
                      emitted_logs > 0 &&
                      log_capture.calls ==
                              calls_before_final_drain + emitted_logs &&
                      log_capture.lifecycle_calls >
                              lifecycle_before_final_drain &&
                      log_capture.formatted_lifecycle_calls >
                              formatted_lifecycle_before_final_drain &&
                      log_capture.stopped_calls >
                              stopped_before_final_drain &&
                      log_capture.formatted_stopped_calls >
                              formatted_stopped_before_final_drain &&
                      log_capture.last_level >= HOOKSELF_LOG_ERROR &&
                      log_capture.last_level <= HOOKSELF_LOG_INFO &&
                      TextContains(log_capture.last_message, "level="),
              58);
        Check(&report,
              hookself_set_log_sink(runtime, nullptr, nullptr) == HOOKSELF_OK &&
                      hookself_drain_logs(
                              runtime, 0, &drained_logs, &emitted_logs) ==
                              HOOKSELF_E_INVALID_ARGUMENT,
              59);
        hookself_destroy(runtime);
    }

    HookselfConfig raw_consumer_config{};
    hookself_default_config(&raw_consumer_config);
    HookselfRuntime* raw_consumer_runtime = nullptr;
    const int32_t raw_consumer_create = hookself_create(
            &raw_consumer_config, &raw_consumer_runtime);
    HookselfEvent unused_event{};
    const size_t empty_raw_read =
            raw_consumer_runtime == nullptr
                    ? 1U
                    : hookself_read_events(
                              raw_consumer_runtime, &unused_event, 1);
    size_t conflict_consumed = 0;
    size_t conflict_emitted = 0;
    const int32_t conflict_result =
            raw_consumer_runtime == nullptr
                    ? HOOKSELF_E_INTERNAL
                    : hookself_drain_logs(
                              raw_consumer_runtime, 1, &conflict_consumed,
                              &conflict_emitted);
    Check(&report,
          raw_consumer_create == HOOKSELF_OK &&
                  raw_consumer_runtime != nullptr && empty_raw_read == 0 &&
                  conflict_result == HOOKSELF_E_INVALID_STATE &&
                  conflict_consumed == 0 && conflict_emitted == 0,
          61);
    hookself_destroy(raw_consumer_runtime);

    HookselfConfig destroy_config{};
    hookself_default_config(&destroy_config);
    HookselfRuntime* destroy_runtime = nullptr;
    const int32_t destroy_create = hookself_create(
            &destroy_config, &destroy_runtime);
    DestroyLogCapture destroy_capture{destroy_runtime, 0, 0};
    const int32_t destroy_sink =
            destroy_runtime == nullptr
                    ? HOOKSELF_E_INTERNAL
                    : hookself_set_log_sink(
                              destroy_runtime, DestroyFromLog,
                              &destroy_capture);
    const int32_t destroy_start =
            destroy_sink == HOOKSELF_OK
                    ? hookself_start(destroy_runtime)
                    : HOOKSELF_E_INVALID_STATE;
    const int32_t destroy_stop =
            destroy_start == HOOKSELF_OK
                    ? hookself_stop(destroy_runtime)
                    : HOOKSELF_E_INVALID_STATE;
    size_t destroy_consumed = 0;
    size_t destroy_emitted = 0;
    const int32_t destroy_drain =
            destroy_stop == HOOKSELF_OK
                    ? hookself_drain_logs(
                              destroy_runtime,
                              static_cast<size_t>(destroy_config.event_capacity) +
                                      1U,
                              &destroy_consumed, &destroy_emitted)
                    : HOOKSELF_E_INVALID_STATE;
    if (destroy_capture.destroy_returned != 0) {
        destroy_runtime = nullptr;
    }
    Check(&report,
          destroy_create == HOOKSELF_OK && destroy_sink == HOOKSELF_OK &&
                  destroy_start == HOOKSELF_OK &&
                  destroy_stop == HOOKSELF_OK &&
                  destroy_drain == HOOKSELF_E_INVALID_STATE &&
                  destroy_capture.calls == 1 &&
                  destroy_capture.destroy_returned == 1 &&
                  destroy_consumed == 1 && destroy_emitted == 1,
          62);
    hookself_destroy(destroy_runtime);

    HookselfConfig concurrent_config{};
    hookself_default_config(&concurrent_config);
    HookselfRuntime* concurrent_runtime = nullptr;
    const int32_t concurrent_create = hookself_create(
            &concurrent_config, &concurrent_runtime);
    ConcurrentDestroyCapture concurrent_capture{};
    concurrent_capture.runtime = concurrent_runtime;
    concurrent_capture.drain_result = HOOKSELF_E_INTERNAL;
    concurrent_capture.max_events =
            static_cast<size_t>(concurrent_config.event_capacity) + 1U;
    const int32_t concurrent_sink =
            concurrent_runtime == nullptr
                    ? HOOKSELF_E_INTERNAL
                    : hookself_set_log_sink(
                              concurrent_runtime, BlockingLog,
                              &concurrent_capture);
    const int32_t concurrent_start =
            concurrent_sink == HOOKSELF_OK
                    ? hookself_start(concurrent_runtime)
                    : HOOKSELF_E_INVALID_STATE;
    const int32_t concurrent_stop =
            concurrent_start == HOOKSELF_OK
                    ? hookself_stop(concurrent_runtime)
                    : HOOKSELF_E_INVALID_STATE;
    pthread_t drain_thread{};
    pthread_t destroy_thread{};
    const int drain_thread_result =
            concurrent_stop == HOOKSELF_OK
                    ? pthread_create(
                              &drain_thread, nullptr, DrainLogsThread,
                              &concurrent_capture)
                    : EINVAL;
    const bool callback_entered =
            drain_thread_result == 0 &&
            WaitForAtomicValue(
                    &concurrent_capture.callback_entered, 1U, 5000);
    const int destroy_thread_result =
            callback_entered
                    ? pthread_create(
                              &destroy_thread, nullptr, DestroyRuntimeThread,
                              &concurrent_capture)
                    : EINVAL;
    const bool destroy_started =
            destroy_thread_result == 0 &&
            WaitForAtomicValue(
                    &concurrent_capture.destroy_started, 1U, 5000);
    const bool runtime_rejected =
            destroy_started &&
            WaitForRuntimeRejected(concurrent_runtime, 5000);
    const bool destroy_waited =
            runtime_rejected &&
            __atomic_load_n(&concurrent_capture.destroy_returned,
                            __ATOMIC_ACQUIRE) == 0;
    __atomic_store_n(&concurrent_capture.release_callback, 1U,
                     __ATOMIC_RELEASE);
    const int drain_join_result =
            drain_thread_result == 0
                    ? pthread_join(drain_thread, nullptr)
                    : EINVAL;
    const int destroy_join_result =
            destroy_thread_result == 0
                    ? pthread_join(destroy_thread, nullptr)
                    : EINVAL;
    const bool concurrent_destroy_completed =
            destroy_thread_result == 0 && destroy_join_result == 0 &&
            __atomic_load_n(&concurrent_capture.destroy_returned,
                            __ATOMIC_ACQUIRE) != 0;
    if (destroy_thread_result != 0) {
        hookself_destroy(concurrent_runtime);
    }
    Check(&report,
          concurrent_create == HOOKSELF_OK &&
                  concurrent_sink == HOOKSELF_OK &&
                  concurrent_start == HOOKSELF_OK &&
                  concurrent_stop == HOOKSELF_OK &&
                  drain_thread_result == 0 && callback_entered &&
                  destroy_thread_result == 0 && runtime_rejected &&
                  destroy_waited &&
                  drain_join_result == 0 &&
                  concurrent_destroy_completed &&
                  concurrent_capture.drain_returned != 0 &&
                  concurrent_capture.drain_result ==
                          HOOKSELF_E_INVALID_STATE &&
                  concurrent_capture.callback_calls == 1 &&
                  concurrent_capture.consumed == 1 &&
                  concurrent_capture.emitted == 1,
          64);

    Check(&report, RunFrameworkFacadeRuntimeSelfTest(backing_root), 6491);

    const size_t ring_size = EventRingBytes(2);
    void* memory = mmap(nullptr, ring_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Check(&report, memory != MAP_FAILED, 13);
    if (memory != MAP_FAILED) {
        auto* ring = static_cast<EventRingHeader*>(memory);
        Check(&report, InitializeEventRing(memory, ring_size, 2), 14);
        HookselfEvent first{};
        first.kind = HOOKSELF_EVENT_SYSCALL;
        first.syscall_number = __NR_openat;
        first.arguments[0] = 100;
        CopyString(first.path, sizeof(first.path), "/first");
        HookselfEvent second = first;
        second.arguments[0] = 200;
        CopyString(second.path, sizeof(second.path), "/second");
        HookselfEvent third = first;
        third.arguments[0] = 300;
        CopyString(third.path, sizeof(third.path), "/third");
        Check(&report, PushEvent(ring, first), 15);
        Check(&report, PushEvent(ring, second), 16);
        Check(&report, !PushEvent(ring, third) && EventRingDropped(ring) == 1, 17);
        HookselfEvent output[2]{};
        Check(&report, ReadEvents(ring, output, 1) == 1 && output[0].sequence == 1 &&
                       output[0].arguments[0] == 100 && output[0].path[1] == 'f', 18);
        Check(&report, PushEvent(ring, third), 19);
        Check(&report, ReadEvents(ring, output, 2) == 2 && output[0].sequence == 2 &&
                       output[0].arguments[0] == 200 && output[1].sequence == 3 &&
                       output[1].arguments[0] == 300, 20);
        munmap(memory, ring_size);
    }

    return report;
}

}  // namespace hookself::internal
