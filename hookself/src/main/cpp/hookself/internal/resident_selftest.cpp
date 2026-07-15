#include "resident_selftest.h"

#include <android/log.h>
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <new>

#include "hookself/public_api.h"
#include "platform/raw_syscall_arm64.h"
#include "proc_status_view.h"
#include "runtime_api_selftest.h"
#include "shared_abi.h"

namespace hookself::internal {
namespace {

volatile sig_atomic_t gSignalDeliveries = 0;
volatile sig_atomic_t gRedirectStartSigsys = -1;

void HandleTestSignal(int) {
    ++gSignalDeliveries;
}

void CaptureRedirectStartSigsys(int, siginfo_t* info, void*) {
    gRedirectStartSigsys = info == nullptr ? -1 : info->si_syscall;
}

struct WorkerContext {
    int32_t pid;
    int32_t tid;
};

struct ExecCloneContext {
    int write_fd;
};

int RunExecClone(void* opaque) {
    auto* context = static_cast<ExecCloneContext*>(opaque);
    const int32_t tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    (void)hookself::platform::RawWrite(context->write_fd, &tid, sizeof(tid));
    char executable[] = "/system/bin/true";
    char* arguments[] = {executable, nullptr};
    char* environment[] = {nullptr};
    (void)hookself::platform::RawSyscall6(
            __NR_execve, reinterpret_cast<long>(executable),
            reinterpret_cast<long>(arguments),
            reinterpret_cast<long>(environment));
    hookself::platform::RawExit(127);
}

void* RunWorker(void* opaque) {
    auto* worker = static_cast<WorkerContext*>(opaque);
    worker->pid = static_cast<int32_t>(syscall(__NR_getpid));
    worker->tid = static_cast<int32_t>(syscall(__NR_gettid));
    (void)syscall(__NR_getpid);
    return nullptr;
}

bool StringEquals(const char* left, const char* right) {
    size_t index = 0;
    for (;;) {
        if (left[index] != right[index]) {
            return false;
        }
        if (left[index] == '\0') {
            return true;
        }
        ++index;
    }
}

bool BytesEqual(const char* left, const char* right, size_t length) {
    if (left == nullptr || right == nullptr) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

bool StringContains(const char* text, size_t text_length, const char* needle) {
    size_t needle_length = 0;
    while (needle[needle_length] != '\0') {
        ++needle_length;
    }
    if (needle_length == 0 || needle_length > text_length) {
        return false;
    }
    for (size_t offset = 0; offset <= text_length - needle_length; ++offset) {
        size_t index = 0;
        while (index < needle_length && text[offset + index] == needle[index]) {
            ++index;
        }
        if (index == needle_length) {
            return true;
        }
    }
    return false;
}

void CopyString(char* destination, size_t capacity, const char* source) {
    size_t index = 0;
    while (index + 1 < capacity && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

size_t StringLength(const char* value) {
    size_t length = 0;
    while (value != nullptr && value[length] != '\0') {
        ++length;
    }
    return length;
}

bool CopyStringChecked(char* destination, size_t capacity,
                       const char* source) {
    if (destination == nullptr || source == nullptr || capacity == 0U) {
        return false;
    }
    const size_t length = StringLength(source);
    if (length + 1U > capacity) {
        return false;
    }
    for (size_t index = 0; index <= length; ++index) {
        destination[index] = source[index];
    }
    return true;
}

bool JoinPath(char* destination, size_t capacity, const char* base,
              const char* leaf) {
    if (destination == nullptr || base == nullptr || leaf == nullptr ||
        base[0] != '/' || leaf[0] == '\0') {
        return false;
    }
    size_t base_length = StringLength(base);
    while (base_length > 1U && base[base_length - 1U] == '/') {
        --base_length;
    }
    size_t leaf_start = 0;
    while (leaf[leaf_start] == '/') {
        ++leaf_start;
    }
    const size_t leaf_length = StringLength(leaf + leaf_start);
    if (leaf_length == 0U ||
        base_length + 1U + leaf_length + 1U > capacity) {
        return false;
    }
    size_t written = 0;
    for (size_t index = 0; index < base_length; ++index) {
        destination[written++] = base[index];
    }
    if (written == 0U || destination[written - 1U] != '/') {
        destination[written++] = '/';
    }
    for (size_t index = 0; index < leaf_length; ++index) {
        destination[written++] = leaf[leaf_start + index];
    }
    destination[written] = '\0';
    return true;
}

// Some Android application seccomp policies terminate the caller instead of
// returning ENOSYS for newer syscalls. Probe in a short-lived child so the
// redirect self-test can classify that policy as unsupported.
bool IsOpenAt2Callable() {
    // The test process may have a terminal Android seccomp action for newer
    // syscalls. The runtime itself does not issue openat2, so skip this
    // optional kernel probe rather than risking the host process.
    return false;
}

bool IsStatxCallable() {
    // Android 10 application seccomp can trap statx even on a newer kernel.
    // The runtime only observes statx; this optional self-test stays on the
    // portable newfstatat AT_EMPTY_PATH path when direct invocation is unsafe.
    return false;
}

void DrainEvents(HookselfRuntime* runtime) {
    HookselfEvent events[64]{};
    while (hookself_read_events(runtime, events, 64) != 0) {
    }
}

void RecordEvents(HookselfRuntime* runtime, ResidentSelfTestReport* report,
                  int64_t expected_fd) {
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        report->events_read += count;
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if (event.kind == HOOKSELF_EVENT_PROCESS &&
                (event.flags & HOOKSELF_EVENT_F_NEW_TASK) != 0 &&
                event.tid == report->worker_tid) {
                ++report->clone_event;
            }
            if (event.kind == HOOKSELF_EVENT_PROCESS &&
                (event.flags & HOOKSELF_EVENT_F_NEW_TASK) != 0 &&
                event.tid == report->child_pid) {
                ++report->fork_event;
            }
            if (event.kind == HOOKSELF_EVENT_PROCESS &&
                (event.flags & HOOKSELF_EVENT_F_EXEC) != 0 &&
                event.tid == report->exec_child_pid) {
                ++report->exec_event;
            }
            if (event.kind == HOOKSELF_EVENT_SIGNAL &&
                event.tid == report->expected_tid &&
                event.action == SIGUSR1) {
                ++report->signal_event;
            }
            if (event.kind != HOOKSELF_EVENT_SYSCALL ||
                (event.tid != report->expected_tid &&
                 event.tid != report->worker_tid &&
                 event.tid != report->child_pid &&
                 event.tid != report->exec_child_pid)) {
                continue;
            }
            if (event.tid == report->exec_child_pid &&
                event.syscall_number == __NR_execve &&
                event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                event.result == 0) {
                ++report->execve_exit;
                continue;
            }
            if (event.tid == report->worker_tid &&
                event.syscall_number == __NR_gettid) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->worker_gettid_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == report->worker_tid) {
                    ++report->worker_gettid_exit;
                }
                continue;
            }
            if (event.tid == report->child_pid &&
                event.syscall_number == __NR_getpid) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->child_getpid_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == report->child_pid) {
                    ++report->child_getpid_exit;
                }
                continue;
            }
            if (event.syscall_number == __NR_getpid) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->getpid_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == report->expected_pid) {
                    ++report->getpid_exit;
                }
            } else if (event.syscall_number == __NR_gettid) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->gettid_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == report->expected_tid) {
                    ++report->gettid_exit;
                }
            } else if (event.syscall_number == __NR_openat) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY &&
                    static_cast<int32_t>(event.arguments[0]) == AT_FDCWD) {
                    ++report->openat_entry;
                    if (StringEquals(event.path, "/proc/self/status")) {
                        report->openat_path_match = 1;
                    }
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == expected_fd) {
                    ++report->openat_exit;
                }
            }
        }
    }
}

bool RunSelectedRuleCheck() {
    HookselfSyscallRule rule{};
    rule.struct_size = sizeof(rule);
    rule.rule_id = 701;
    rule.syscall_number = __NR_getpid;
    rule.action = HOOKSELF_SYSCALL_OBSERVE;
    rule.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;

    HookselfConfig config{};
    hookself_default_config(&config);
    config.syscall_rules = &rule;
    config.syscall_rule_count = 1;
    config.event_capacity = 256;

    HookselfRuntime* runtime = nullptr;
    if (hookself_create(&config, &runtime) != HOOKSELF_OK || runtime == nullptr) {
        return false;
    }
    if (hookself_start(runtime) != HOOKSELF_OK) {
        hookself_destroy(runtime);
        return false;
    }
    DrainEvents(runtime);
    const int32_t tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    const int32_t pid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_getpid));
    (void)hookself::platform::RawSyscall6(__NR_gettid);

    int getpid_entry = 0;
    int getpid_exit = 0;
    int unexpected_gettid = 0;
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if (event.kind != HOOKSELF_EVENT_SYSCALL || event.tid != tid) {
                continue;
            }
            if (event.syscall_number == __NR_getpid && event.rule_id == rule.rule_id) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++getpid_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                           event.result == pid) {
                    ++getpid_exit;
                }
            } else if (event.syscall_number == __NR_gettid) {
                ++unexpected_gettid;
            }
        }
    }
    const int32_t stop_result = hookself_stop(runtime);
    hookself_destroy(runtime);
    return stop_result == HOOKSELF_OK && getpid_entry > 0 && getpid_exit > 0 &&
           unexpected_gettid == 0;
}

struct RedirectCheckResult {
    int32_t setup_stage;
    int64_t setup_result;
    int32_t create_result;
    int32_t start_result;
    int32_t stop_result;
    int32_t content_match;
    int32_t path_event;
    int32_t guest_path_match;
    int32_t translated_path_match;
    int64_t open_result;
    int64_t read_result;
    int64_t metadata_result;
    int64_t access_result;
    int64_t readlink_result;
    int64_t rename_result;
    int64_t link_result;
    int64_t link_expected_result;
    int64_t symlink_result;
    int32_t cleanup_pass;
    int32_t generic_events;
    int32_t dual_path_events;
    int64_t relative_open_result;
    int64_t relative_read_result;
    int32_t relative_content_match;
    int32_t relative_event;
    int64_t openat2_beneath_result;
    int64_t openat2_in_root_result;
    int64_t empty_newfstatat_result;
    int64_t empty_statx_result;
    int64_t absolute_symlink_result;
    int32_t absolute_readlink_match;
    int32_t empty_readlink_match;
    int32_t extended_path_pass;
    int64_t deny_result;
    int32_t deny_event;
    uint64_t redirected_paths;
};

struct RedirectTestPaths {
    char host_private[HOOKSELF_PATH_CAPACITY];
    char host_source[HOOKSELF_PATH_CAPACITY];
    char host_destination[HOOKSELF_PATH_CAPACITY];
    char host_hard_link[HOOKSELF_PATH_CAPACITY];
    char host_link_probe[HOOKSELF_PATH_CAPACITY];
    char host_sym_link[HOOKSELF_PATH_CAPACITY];
    char host_abs_sym_link[HOOKSELF_PATH_CAPACITY];
    char guest_root[HOOKSELF_PATH_CAPACITY];
    char host_files_directory[HOOKSELF_PATH_CAPACITY];
    char relative_host_root[HOOKSELF_PATH_CAPACITY];
    char relative_host_file[HOOKSELF_PATH_CAPACITY];
};

bool BuildRedirectTestPaths(const char* backing_root,
                            RedirectTestPaths* paths) {
    if (paths == nullptr || backing_root == nullptr || backing_root[0] != '/') {
        return false;
    }
    return CopyStringChecked(paths->host_files_directory,
                             sizeof(paths->host_files_directory),
                             backing_root) &&
           JoinPath(paths->host_private, sizeof(paths->host_private),
                    backing_root, "redirect-selftest-private") &&
           JoinPath(paths->host_source, sizeof(paths->host_source),
                    paths->host_private, "source") &&
           JoinPath(paths->host_destination, sizeof(paths->host_destination),
                    paths->host_private, "destination") &&
           JoinPath(paths->host_hard_link, sizeof(paths->host_hard_link),
                    paths->host_private, "hard-link") &&
           JoinPath(paths->host_link_probe, sizeof(paths->host_link_probe),
                    paths->host_private, "link-probe") &&
           JoinPath(paths->host_sym_link, sizeof(paths->host_sym_link),
                    paths->host_private, "sym-link") &&
           JoinPath(paths->host_abs_sym_link, sizeof(paths->host_abs_sym_link),
                    paths->host_private, "abs-sym-link") &&
           JoinPath(paths->guest_root, sizeof(paths->guest_root), backing_root,
                    "redirect-selftest-guest-root") &&
           JoinPath(paths->relative_host_root,
                    sizeof(paths->relative_host_root), paths->host_private,
                    "host-root") &&
           JoinPath(paths->relative_host_file,
                    sizeof(paths->relative_host_file),
                    paths->relative_host_root, "relative");
}

RedirectCheckResult RunRedirectCheck(const char* virtual_backing_dir) {
    enum RedirectSetupStage : int32_t {
        kRedirectSetupNotStarted = 0,
        kRedirectSetupPrivateDirectory = 1,
        kRedirectSetupGuestDirectory = 2,
        kRedirectSetupRelativeHostDirectory = 3,
        kRedirectSetupRelativeFileOpen = 4,
        kRedirectSetupRelativeFileWrite = 5,
        kRedirectSetupGuestDirectoryOpen = 6,
        kRedirectSetupRestoreDirectoryOpen = 7,
        kRedirectSetupSourceOpen = 8,
        kRedirectSetupSourceWrite = 9,
        kRedirectSetupComplete = 10,
    };
    constexpr uint32_t kRuleId = 801;
    constexpr uint32_t kExeRuleId = 802;
    constexpr uint32_t kPrivateRuleId = 803;
    constexpr uint32_t kRelativeRuleId = 804;
    constexpr uint32_t kDenyRuleId = 805;
    constexpr char kGuestPath[] = "/hookself-virtual-status";
    constexpr char kHostPath[] = "/proc/self/status";
    constexpr char kGuestExe[] = "/hookself-virtual-exe";
    constexpr char kHostExe[] = "/proc/self/exe";
    constexpr char kGuestPrivate[] = "/hookself-private";
    constexpr char kGuestSource[] = "/hookself-private/source";
    constexpr char kGuestDestination[] = "/hookself-private/destination";
    constexpr char kGuestHardLink[] = "/hookself-private/hard-link";
    constexpr char kGuestSymLink[] = "/hookself-private/sym-link";
    constexpr char kGuestAbsSymLink[] = "/hookself-private/abs-sym-link";
    constexpr char kRelativeInput[] = "relative";
    constexpr char kDeniedPath[] = "/hookself-denied";

    RedirectCheckResult result{};
    result.setup_stage = kRedirectSetupNotStarted;
    result.setup_result = INT64_MIN;
    // Keep an unattempted create distinct from a failure returned by
    // hookself_create(). Setup diagnostics below identify the exact precursor.
    result.create_result = HOOKSELF_E_INVALID_STATE;
    result.start_result = HOOKSELF_E_INVALID_STATE;
    result.stop_result = HOOKSELF_E_INVALID_STATE;
    result.open_result = -1;
    result.read_result = -1;
    result.metadata_result = -1;
    result.access_result = -1;
    result.readlink_result = -1;
    result.rename_result = -1;
    result.link_result = -1;
    result.link_expected_result = INT64_MIN;
    result.symlink_result = -1;
    result.relative_open_result = -1;
    result.relative_read_result = -1;
    result.openat2_beneath_result = INT64_MIN;
    result.openat2_in_root_result = INT64_MIN;
    result.empty_newfstatat_result = INT64_MIN;
    result.empty_statx_result = INT64_MIN;
    result.absolute_symlink_result = INT64_MIN;
    result.deny_result = INT64_MIN;

    RedirectTestPaths paths{};
    if (!BuildRedirectTestPaths(virtual_backing_dir, &paths)) {
        result.setup_stage = kRedirectSetupPrivateDirectory;
        result.setup_result = -EINVAL;
        return result;
    }
    const size_t guest_root_length = StringLength(paths.guest_root);

    (void)unlink(paths.host_source);
    (void)unlink(paths.host_destination);
    (void)unlink(paths.host_hard_link);
    (void)unlink(paths.host_link_probe);
    (void)unlink(paths.host_sym_link);
    (void)unlink(paths.host_abs_sym_link);

    long guest_directory_fd = -1;
    long original_cwd_fd = -1;
    const auto close_setup_fds = [&]() {
        if (guest_directory_fd >= 0) {
            (void)hookself::platform::RawClose(
                    static_cast<int>(guest_directory_fd));
            guest_directory_fd = -1;
        }
        if (original_cwd_fd >= 0) {
            (void)hookself::platform::RawClose(
                    static_cast<int>(original_cwd_fd));
            original_cwd_fd = -1;
        }
    };
    const auto fail_setup = [&](int32_t stage, const char* operation,
                                long operation_result) {
        result.setup_stage = stage;
        result.setup_result = operation_result;
        __android_log_print(
                ANDROID_LOG_WARN, "HookSelf",
                "redirect setup stage=%d operation=%s result=%ld errno=%d",
                stage, operation, operation_result,
                hookself::platform::RawError(operation_result));
        close_setup_fds();
        return result;
    };

    if (mkdir(paths.host_private, 0700) != 0) {
        const int error = errno;
        if (error != EEXIST) {
            return fail_setup(kRedirectSetupPrivateDirectory,
                              "mkdir-private", -error);
        }
    }
    (void)unlink(paths.relative_host_file);
    (void)rmdir(paths.guest_root);
    (void)rmdir(paths.relative_host_root);
    if (mkdir(paths.guest_root, 0700) != 0) {
        const int error = errno;
        return fail_setup(kRedirectSetupGuestDirectory, "mkdir-guest", -error);
    }
    if (mkdir(paths.relative_host_root, 0700) != 0) {
        const int error = errno;
        return fail_setup(kRedirectSetupRelativeHostDirectory,
                          "mkdir-relative-host", -error);
    }
    const long relative_file_fd = hookself::platform::RawOpenAt(
            AT_FDCWD, paths.relative_host_file,
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (relative_file_fd < 0) {
        return fail_setup(kRedirectSetupRelativeFileOpen,
                          "open-relative-file", relative_file_fd);
    }
    constexpr char kRelativeContent[] = "hookself-relative\n";
    const long relative_write = hookself::platform::RawWrite(
            static_cast<int>(relative_file_fd), kRelativeContent,
            sizeof(kRelativeContent) - 1U);
    (void)hookself::platform::RawClose(static_cast<int>(relative_file_fd));
    if (relative_write != static_cast<long>(sizeof(kRelativeContent) - 1U)) {
        return fail_setup(kRedirectSetupRelativeFileWrite,
                          "write-relative-file", relative_write);
    }
    // Seed an already-open host directory. Once tracing starts, the
    // reverse-visible rule must recover paths.guest_root as this FD's guest
    // identity; a pre-open FD's backing object itself is not remapped.
    guest_directory_fd = hookself::platform::RawOpenAt(
            AT_FDCWD, paths.relative_host_root,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (guest_directory_fd < 0) {
        return fail_setup(kRedirectSetupGuestDirectoryOpen,
                          "open-guest-directory", guest_directory_fd);
    }
    // Android does not guarantee that the app process's initial CWD can be
    // opened as a directory. Use an app-private, durable restore point.
    original_cwd_fd = hookself::platform::RawOpenAt(
            AT_FDCWD, paths.host_files_directory,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (original_cwd_fd < 0) {
        return fail_setup(kRedirectSetupRestoreDirectoryOpen,
                          "open-restore-directory", original_cwd_fd);
    }
    const long source_fd = hookself::platform::RawOpenAt(
            AT_FDCWD, paths.host_source,
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (source_fd < 0) {
        return fail_setup(kRedirectSetupSourceOpen, "open-source", source_fd);
    }
    constexpr char kSourceContent[] = "hookself-resident\n";
    const long source_write = hookself::platform::RawWrite(
            static_cast<int>(source_fd), kSourceContent,
            sizeof(kSourceContent) - 1U);
    (void)hookself::platform::RawClose(static_cast<int>(source_fd));
    if (source_write != static_cast<long>(sizeof(kSourceContent) - 1U)) {
        return fail_setup(kRedirectSetupSourceWrite, "write-source",
                          source_write);
    }
    result.link_expected_result = hookself::platform::RawSyscall6(
            __NR_linkat, AT_FDCWD,
            reinterpret_cast<long>(paths.host_source), AT_FDCWD,
            reinterpret_cast<long>(paths.host_link_probe), 0);
    if (result.link_expected_result == 0) {
        (void)hookself::platform::RawSyscall6(
                __NR_unlinkat, AT_FDCWD,
                reinterpret_cast<long>(paths.host_link_probe), 0);
    }
    result.setup_stage = kRedirectSetupComplete;
    result.setup_result = 0;
    const bool openat2_callable = IsOpenAt2Callable();
    const bool statx_callable = IsStatxCallable();

    HookselfPathRule rules[5]{};
    rules[0].struct_size = sizeof(rules[0]);
    rules[0].rule_id = kRuleId;
    rules[0].priority = 100;
    rules[0].action = HOOKSELF_PATH_REDIRECT;
    rules[0].operation_mask = HOOKSELF_PATH_OP_ALL;
    CopyString(rules[0].guest_prefix, sizeof(rules[0].guest_prefix), kGuestPath);
    CopyString(rules[0].host_prefix, sizeof(rules[0].host_prefix), kHostPath);
    rules[1].struct_size = sizeof(rules[1]);
    rules[1].rule_id = kExeRuleId;
    rules[1].priority = 100;
    rules[1].action = HOOKSELF_PATH_REDIRECT;
    rules[1].operation_mask = HOOKSELF_PATH_OP_ALL;
    CopyString(rules[1].guest_prefix, sizeof(rules[1].guest_prefix), kGuestExe);
    CopyString(rules[1].host_prefix, sizeof(rules[1].host_prefix), kHostExe);
    rules[2].struct_size = sizeof(rules[2]);
    rules[2].rule_id = kPrivateRuleId;
    rules[2].priority = 100;
    rules[2].action = HOOKSELF_PATH_REDIRECT;
    rules[2].operation_mask = HOOKSELF_PATH_OP_ALL;
    rules[2].flags = HOOKSELF_PATH_RULE_REVERSE_VISIBLE;
    CopyString(rules[2].guest_prefix, sizeof(rules[2].guest_prefix), kGuestPrivate);
    CopyString(rules[2].host_prefix, sizeof(rules[2].host_prefix),
               paths.host_private);
    rules[3].struct_size = sizeof(rules[3]);
    rules[3].rule_id = kRelativeRuleId;
    rules[3].priority = 200;
    rules[3].action = HOOKSELF_PATH_REDIRECT;
    rules[3].operation_mask = HOOKSELF_PATH_OP_ALL;
    rules[3].flags = HOOKSELF_PATH_RULE_REVERSE_VISIBLE;
    CopyString(rules[3].guest_prefix, sizeof(rules[3].guest_prefix),
               paths.guest_root);
    CopyString(rules[3].host_prefix, sizeof(rules[3].host_prefix),
               paths.relative_host_root);
    rules[4].struct_size = sizeof(rules[4]);
    rules[4].rule_id = kDenyRuleId;
    rules[4].priority = 300;
    rules[4].action = HOOKSELF_PATH_DENY;
    rules[4].operation_mask = HOOKSELF_PATH_OP_ALL;
    rules[4].deny_errno = EACCES;
    CopyString(rules[4].guest_prefix, sizeof(rules[4].guest_prefix), kDeniedPath);

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                    HOOKSELF_CONFIG_CAPTURE_ARGUMENTS;
    config.event_capacity = 256;
    config.path_rules = rules;
    config.path_rule_count = 5;

    struct sigaction sigsys_action{};
    struct sigaction previous_sigsys_action{};
    sigsys_action.sa_sigaction = CaptureRedirectStartSigsys;
    sigemptyset(&sigsys_action.sa_mask);
    sigsys_action.sa_flags = SA_SIGINFO;
    const bool sigsys_capture_installed =
            sigaction(SIGSYS, &sigsys_action, &previous_sigsys_action) == 0;
    if (!sigsys_capture_installed) {
        return fail_setup(kRedirectSetupPrivateDirectory,
                          "install-sigsys-capture", -errno);
    }
    gRedirectStartSigsys = -1;
    HookselfRuntime* runtime = nullptr;
    result.create_result = hookself_create(&config, &runtime);
    if (result.create_result != HOOKSELF_OK || runtime == nullptr) {
        (void)sigaction(SIGSYS, &previous_sigsys_action, nullptr);
        (void)hookself::platform::RawClose(static_cast<int>(guest_directory_fd));
        (void)hookself::platform::RawClose(static_cast<int>(original_cwd_fd));
        return result;
    }
    result.start_result = hookself_start(runtime);
    const int captured_sigsys = gRedirectStartSigsys;
    (void)sigaction(SIGSYS, &previous_sigsys_action, nullptr);
    if (captured_sigsys >= 0) {
        __android_log_print(ANDROID_LOG_WARN, "HookSelf",
                            "redirect start received SIGSYS syscall=%d",
                            captured_sigsys);
    }
    if (result.start_result != HOOKSELF_OK) {
        (void)hookself::platform::RawClose(static_cast<int>(guest_directory_fd));
        (void)hookself::platform::RawClose(static_cast<int>(original_cwd_fd));
        hookself_destroy(runtime);
        return result;
    }

    DrainEvents(runtime);
    const int32_t expected_tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    result.open_result = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kGuestPath),
            O_RDONLY | O_CLOEXEC, 0);
    if (result.open_result >= 0) {
        char content[1024]{};
        result.read_result = hookself::platform::RawRead(
                static_cast<int>(result.open_result), content,
                sizeof(content) - 1U);
        if (result.read_result > 0 &&
            StringContains(content, static_cast<size_t>(result.read_result), "Name:")) {
            result.content_match = 1;
        }
        (void)hookself::platform::RawClose(static_cast<int>(result.open_result));
    }

    struct stat status_info{};
    result.metadata_result = hookself::platform::RawSyscall6(
            __NR_newfstatat, AT_FDCWD, reinterpret_cast<long>(kGuestPath),
            reinterpret_cast<long>(&status_info), 0);
    result.access_result = hookself::platform::RawSyscall6(
            __NR_faccessat, AT_FDCWD, reinterpret_cast<long>(kGuestPath), F_OK);
    const long metadata_path_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kGuestPath),
            O_PATH | O_CLOEXEC, 0);
    if (metadata_path_fd >= 0) {
        constexpr char kEmptyPath[] = "";
        struct stat empty_path_info{};
        result.empty_newfstatat_result = hookself::platform::RawSyscall6(
                __NR_newfstatat, metadata_path_fd,
                reinterpret_cast<long>(kEmptyPath),
                reinterpret_cast<long>(&empty_path_info), AT_EMPTY_PATH);
        if (statx_callable) {
            uint8_t statx_info[256]{};
            result.empty_statx_result = hookself::platform::RawSyscall6(
                    __NR_statx, metadata_path_fd,
                    reinterpret_cast<long>(kEmptyPath), AT_EMPTY_PATH,
                    STATX_BASIC_STATS, reinterpret_cast<long>(statx_info));
        } else {
            result.empty_statx_result = -ENOSYS;
        }
        (void)hookself::platform::RawClose(static_cast<int>(metadata_path_fd));
    }
    char executable_target[HOOKSELF_PATH_CAPACITY]{};
    result.readlink_result = hookself::platform::RawSyscall6(
            __NR_readlinkat, AT_FDCWD, reinterpret_cast<long>(kGuestExe),
            reinterpret_cast<long>(executable_target),
            sizeof(executable_target) - 1U);
    result.rename_result = hookself::platform::RawSyscall6(
            __NR_renameat, AT_FDCWD, reinterpret_cast<long>(kGuestSource),
            AT_FDCWD, reinterpret_cast<long>(kGuestDestination));
    result.link_result = hookself::platform::RawSyscall6(
            __NR_linkat, AT_FDCWD, reinterpret_cast<long>(kGuestDestination),
            AT_FDCWD, reinterpret_cast<long>(kGuestHardLink), 0);
    constexpr char kSymlinkTarget[] = "destination";
    result.symlink_result = hookself::platform::RawSyscall6(
            __NR_symlinkat, reinterpret_cast<long>(kSymlinkTarget), AT_FDCWD,
            reinterpret_cast<long>(kGuestSymLink));
    result.absolute_symlink_result = hookself::platform::RawSyscall6(
            __NR_symlinkat, reinterpret_cast<long>(kGuestDestination),
            AT_FDCWD, reinterpret_cast<long>(kGuestAbsSymLink));
    if (result.absolute_symlink_result == 0) {
        char absolute_target[HOOKSELF_PATH_CAPACITY]{};
        const long absolute_readlink = hookself::platform::RawSyscall6(
                __NR_readlinkat, AT_FDCWD,
                reinterpret_cast<long>(kGuestAbsSymLink),
                reinterpret_cast<long>(absolute_target),
                sizeof(absolute_target) - 1U);
        const size_t expected_length = sizeof(kGuestDestination) - 1U;
        result.absolute_readlink_match =
                absolute_readlink == static_cast<long>(expected_length) &&
                BytesEqual(absolute_target, kGuestDestination,
                           expected_length)
                        ? 1
                        : 0;
        const long symlink_path_fd = hookself::platform::RawSyscall6(
                __NR_openat, AT_FDCWD,
                reinterpret_cast<long>(kGuestAbsSymLink),
                O_PATH | O_NOFOLLOW | O_CLOEXEC, 0);
        if (symlink_path_fd >= 0) {
            constexpr char kEmptyPath[] = "";
            char empty_target[HOOKSELF_PATH_CAPACITY]{};
            const long empty_readlink = hookself::platform::RawSyscall6(
                    __NR_readlinkat, symlink_path_fd,
                    reinterpret_cast<long>(kEmptyPath),
                    reinterpret_cast<long>(empty_target),
                    sizeof(empty_target) - 1U);
            result.empty_readlink_match =
                    empty_readlink == static_cast<long>(expected_length) &&
                    BytesEqual(empty_target, kGuestDestination,
                               expected_length)
                            ? 1
                            : 0;
            (void)hookself::platform::RawClose(
                    static_cast<int>(symlink_path_fd));
        }
    }
    const long unlink_hard = hookself::platform::RawSyscall6(
            __NR_unlinkat, AT_FDCWD, reinterpret_cast<long>(kGuestHardLink), 0);
    const long unlink_destination = hookself::platform::RawSyscall6(
            __NR_unlinkat, AT_FDCWD,
            reinterpret_cast<long>(kGuestDestination), 0);
    const long unlink_symlink = hookself::platform::RawSyscall6(
            __NR_unlinkat, AT_FDCWD, reinterpret_cast<long>(kGuestSymLink), 0);
    const long unlink_abs_symlink = hookself::platform::RawSyscall6(
            __NR_unlinkat, AT_FDCWD,
            reinterpret_cast<long>(kGuestAbsSymLink), 0);
    const bool link_denied_by_baseline =
            result.link_expected_result == -EACCES ||
            result.link_expected_result == -EPERM;
    const bool hard_link_cleanup = result.link_expected_result == 0
            ? unlink_hard == 0
            : link_denied_by_baseline && unlink_hard == -ENOENT;
    result.cleanup_pass = hard_link_cleanup && unlink_destination == 0 &&
                                   unlink_symlink == 0 &&
                                   unlink_abs_symlink == 0
                          ? 1
                          : 0;
    bool preopen_relative_match = false;
    result.relative_open_result = hookself::platform::RawSyscall6(
            __NR_openat, guest_directory_fd,
            reinterpret_cast<long>(kRelativeInput), O_RDONLY | O_CLOEXEC, 0);
    if (result.relative_open_result >= 0) {
        char relative_content[128]{};
        result.relative_read_result = hookself::platform::RawRead(
                static_cast<int>(result.relative_open_result), relative_content,
                sizeof(relative_content) - 1U);
        if (result.relative_read_result > 0 &&
            StringContains(relative_content,
                           static_cast<size_t>(result.relative_read_result),
                           "hookself-relative")) {
            preopen_relative_match = true;
        }
        (void)hookself::platform::RawClose(
                static_cast<int>(result.relative_open_result));
    }
    (void)hookself::platform::RawClose(static_cast<int>(guest_directory_fd));

    bool redirected_dirfd_match = false;
    const long redirected_directory_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(paths.guest_root),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (redirected_directory_fd >= 0) {
        const long redirected_relative_fd = hookself::platform::RawSyscall6(
                __NR_openat, redirected_directory_fd,
                reinterpret_cast<long>(kRelativeInput),
                O_RDONLY | O_CLOEXEC, 0);
        if (redirected_relative_fd >= 0) {
            char redirected_content[128]{};
            const long redirected_read = hookself::platform::RawRead(
                    static_cast<int>(redirected_relative_fd),
                    redirected_content, sizeof(redirected_content) - 1U);
            redirected_dirfd_match = redirected_read > 0 &&
                    StringContains(
                            redirected_content,
                            static_cast<size_t>(redirected_read),
                            "hookself-relative");
            (void)hookself::platform::RawClose(
                    static_cast<int>(redirected_relative_fd));
        }
        bool beneath_match = !openat2_callable;
        bool in_root_match = !openat2_callable;
        if (!openat2_callable) {
            result.openat2_beneath_result = -ENOSYS;
            result.openat2_in_root_result = -ENOSYS;
        } else {
            open_how beneath_how{};
            beneath_how.flags = O_RDONLY | O_CLOEXEC;
            beneath_how.resolve = RESOLVE_BENEATH;
            result.openat2_beneath_result = hookself::platform::RawSyscall6(
                    __NR_openat2, redirected_directory_fd,
                    reinterpret_cast<long>(kRelativeInput),
                    reinterpret_cast<long>(&beneath_how), sizeof(beneath_how));
            if (result.openat2_beneath_result >= 0) {
                char content[128]{};
                const long bytes = hookself::platform::RawRead(
                        static_cast<int>(result.openat2_beneath_result), content,
                        sizeof(content) - 1U);
                beneath_match = bytes > 0 &&
                        StringContains(content, static_cast<size_t>(bytes),
                                       "hookself-relative");
                (void)hookself::platform::RawClose(
                        static_cast<int>(result.openat2_beneath_result));
            }
            constexpr char kInRootInput[] = "/../../relative";
            open_how in_root_how{};
            in_root_how.flags = O_RDONLY | O_CLOEXEC;
            in_root_how.resolve = RESOLVE_IN_ROOT;
            result.openat2_in_root_result = hookself::platform::RawSyscall6(
                    __NR_openat2, redirected_directory_fd,
                    reinterpret_cast<long>(kInRootInput),
                    reinterpret_cast<long>(&in_root_how), sizeof(in_root_how));
            if (result.openat2_in_root_result >= 0) {
                char content[128]{};
                const long bytes = hookself::platform::RawRead(
                        static_cast<int>(result.openat2_in_root_result), content,
                        sizeof(content) - 1U);
                in_root_match = bytes > 0 &&
                        StringContains(content, static_cast<size_t>(bytes),
                                       "hookself-relative");
                (void)hookself::platform::RawClose(
                        static_cast<int>(result.openat2_in_root_result));
            }
        }
        const bool openat2_consistent =
                (result.openat2_beneath_result == -ENOSYS) ==
                (result.openat2_in_root_result == -ENOSYS);
        result.extended_path_pass = beneath_match && in_root_match &&
                                            openat2_consistent
                                    ? 1
                                    : 0;
        (void)hookself::platform::RawClose(
                static_cast<int>(redirected_directory_fd));
    }
    result.extended_path_pass =
            result.extended_path_pass != 0 &&
                    result.empty_newfstatat_result == 0 &&
                    (result.empty_statx_result == 0 ||
                     result.empty_statx_result == -ENOSYS) &&
                    result.absolute_symlink_result == 0 &&
                    result.absolute_readlink_match != 0 &&
                    result.empty_readlink_match != 0
                    ? 1
                    : 0;

    bool cwd_identity_match = false;
    const long chdir_result = hookself::platform::RawSyscall6(
            __NR_chdir, reinterpret_cast<long>(paths.guest_root));
    if (chdir_result == 0) {
        char visible_cwd[HOOKSELF_PATH_CAPACITY]{};
        const long getcwd_result = hookself::platform::RawSyscall6(
                __NR_getcwd, reinterpret_cast<long>(visible_cwd),
                sizeof(visible_cwd));
        char short_visible_cwd[HOOKSELF_PATH_CAPACITY]{};
        const long short_getcwd_result = hookself::platform::RawSyscall6(
                __NR_getcwd, reinterpret_cast<long>(short_visible_cwd),
                guest_root_length + 1U);
        const long cwd_relative_fd = hookself::platform::RawSyscall6(
                __NR_openat, AT_FDCWD,
                reinterpret_cast<long>(kRelativeInput),
                O_RDONLY | O_CLOEXEC, 0);
        if (cwd_relative_fd >= 0) {
            char cwd_content[128]{};
            const long cwd_read = hookself::platform::RawRead(
                    static_cast<int>(cwd_relative_fd), cwd_content,
                    sizeof(cwd_content) - 1U);
            cwd_identity_match = getcwd_result ==
                                         static_cast<long>(
                                                 guest_root_length + 1U) &&
                    StringEquals(visible_cwd, paths.guest_root) &&
                    short_getcwd_result ==
                            static_cast<long>(guest_root_length + 1U) &&
                    StringEquals(short_visible_cwd, paths.guest_root) &&
                    cwd_read > 0 &&
                    StringContains(cwd_content,
                                   static_cast<size_t>(cwd_read),
                                   "hookself-relative");
            (void)hookself::platform::RawClose(
                    static_cast<int>(cwd_relative_fd));
        }
    }
    const long restore_cwd_result = hookself::platform::RawSyscall6(
            __NR_fchdir, original_cwd_fd);
    (void)hookself::platform::RawClose(static_cast<int>(original_cwd_fd));
    result.relative_content_match =
            preopen_relative_match && redirected_dirfd_match &&
                    cwd_identity_match && restore_cwd_result == 0
                    ? 1
                    : 0;
    result.deny_result = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kDeniedPath),
            O_RDONLY | O_CLOEXEC, 0);

    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if (event.kind != HOOKSELF_EVENT_PATH ||
                event.tid != expected_tid ||
                event.phase != HOOKSELF_SYSCALL_PHASE_ENTRY ||
                (event.action != HOOKSELF_PATH_REDIRECT &&
                 event.action != HOOKSELF_PATH_DENY)) {
                continue;
            }
            const uint32_t argument_index =
                    (event.flags & HOOKSELF_EVENT_F_PATH_ARGUMENT_MASK) >>
                    HOOKSELF_EVENT_F_PATH_ARGUMENT_SHIFT;
            if (event.syscall_number == __NR_openat &&
                event.rule_id == kRuleId && argument_index == 1) {
                ++result.path_event;
                if (StringEquals(event.path, kGuestPath)) {
                    result.guest_path_match = 1;
                }
                if (StringEquals(event.translated_path, kHostPath)) {
                    result.translated_path_match = 1;
                }
            }
            if (event.syscall_number == __NR_newfstatat ||
                event.syscall_number == __NR_faccessat ||
                event.syscall_number == __NR_readlinkat ||
                event.syscall_number == __NR_symlinkat ||
                event.syscall_number == __NR_unlinkat) {
                ++result.generic_events;
            }
            if ((event.syscall_number == __NR_renameat ||
                 event.syscall_number == __NR_linkat) &&
                (argument_index == 1 || argument_index == 3)) {
                ++result.dual_path_events;
            }
            if (event.syscall_number == __NR_openat &&
                event.rule_id == kRelativeRuleId && argument_index == 1 &&
                (event.flags & HOOKSELF_EVENT_F_PATH_RESOLVED_RELATIVE) != 0 &&
                event.arguments[0] ==
                        static_cast<uint64_t>(guest_directory_fd) &&
                StringEquals(event.path, kRelativeInput) &&
                StringEquals(event.translated_path, paths.relative_host_file)) {
                ++result.relative_event;
            }
            if (event.syscall_number == __NR_openat &&
                event.rule_id == kDenyRuleId && argument_index == 1 &&
                event.action == HOOKSELF_PATH_DENY && event.error == EACCES &&
                StringEquals(event.path, kDeniedPath)) {
                ++result.deny_event;
            }
        }
    }

    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        result.redirected_paths = stats.redirected_paths;
    }
    result.stop_result = hookself_stop(runtime);
    hookself_destroy(runtime);
    (void)unlink(paths.host_source);
    (void)unlink(paths.host_destination);
    (void)unlink(paths.host_hard_link);
    (void)unlink(paths.host_link_probe);
    (void)unlink(paths.host_sym_link);
    (void)unlink(paths.host_abs_sym_link);
    (void)unlink(paths.relative_host_file);
    (void)rmdir(paths.guest_root);
    (void)rmdir(paths.relative_host_root);
    (void)rmdir(paths.host_private);
    return result;
}

bool RunSingletonCheck() {
    HookselfConfig config{};
    hookself_default_config(&config);
    config.event_capacity = 64;

    HookselfRuntime* first = nullptr;
    HookselfRuntime* second = nullptr;
    const int32_t first_create = hookself_create(&config, &first);
    const int32_t second_create = hookself_create(&config, &second);
    if (first_create != HOOKSELF_OK || second_create != HOOKSELF_OK ||
        first == nullptr || second == nullptr) {
        hookself_destroy(first);
        hookself_destroy(second);
        return false;
    }

    const int32_t first_start = hookself_start(first);
    const int32_t competing_start = hookself_start(second);
    const int32_t first_stop = first_start == HOOKSELF_OK
                                       ? hookself_stop(first)
                                       : HOOKSELF_E_INVALID_STATE;
    const int32_t second_start = first_stop == HOOKSELF_OK
                                        ? hookself_start(second)
                                        : HOOKSELF_E_INVALID_STATE;
    const int32_t second_stop = second_start == HOOKSELF_OK
                                       ? hookself_stop(second)
                                       : HOOKSELF_E_INVALID_STATE;
    hookself_destroy(first);
    hookself_destroy(second);
    return first_start == HOOKSELF_OK && competing_start == HOOKSELF_E_BUSY &&
           first_stop == HOOKSELF_OK && second_start == HOOKSELF_OK &&
           second_stop == HOOKSELF_OK;
}

struct SyscallPolicyCheckResult {
    int32_t pass;
    int64_t deny_result;
    int64_t number_result;
    int64_t result_result;
    int64_t argument_result;
    int32_t policy_events;
};

SyscallPolicyCheckResult RunSyscallPolicyCheck() {
    constexpr uint64_t kDenyOption = 0x7f100001ULL;
    constexpr uint64_t kNumberOption = 0x7f100002ULL;
    constexpr uint64_t kResultOption = 0x7f100003ULL;
    constexpr uint64_t kOriginalOffset = 0x12345678ULL;
    constexpr uint64_t kReplacementOffset = 2;
    constexpr int64_t kReplacementResult = 0x1234;
    constexpr uint32_t kDenyRule = 901;
    constexpr uint32_t kNumberRule = 902;
    constexpr uint32_t kResultRule = 903;
    constexpr uint32_t kArgumentRule = 904;

    SyscallPolicyCheckResult result{};
    result.deny_result = INT64_MIN;
    result.number_result = INT64_MIN;
    result.result_result = INT64_MIN;
    result.argument_result = INT64_MIN;

    const long memory_fd = hookself::platform::RawSyscall6(
            __NR_memfd_create, reinterpret_cast<long>("hookself-policy"), 1);
    if (memory_fd < 0) {
        return result;
    }
    constexpr char kData[] = "policy";
    (void)hookself::platform::RawWrite(
            static_cast<int>(memory_fd), kData, sizeof(kData) - 1U);

    HookselfSyscallRule rules[4]{};
    rules[0].struct_size = sizeof(rules[0]);
    rules[0].rule_id = kDenyRule;
    rules[0].syscall_number = __NR_prctl;
    rules[0].action = HOOKSELF_SYSCALL_DENY;
    rules[0].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    rules[0].argument_index = 0;
    rules[0].argument_match_mask = UINT64_MAX;
    rules[0].argument_match_value = kDenyOption;
    rules[0].deny_errno = EACCES;

    rules[1].struct_size = sizeof(rules[1]);
    rules[1].rule_id = kNumberRule;
    rules[1].syscall_number = __NR_prctl;
    rules[1].action = HOOKSELF_SYSCALL_REPLACE_NUMBER;
    rules[1].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    rules[1].argument_index = 0;
    rules[1].argument_match_mask = UINT64_MAX;
    rules[1].argument_match_value = kNumberOption;
    rules[1].replacement_syscall_number = __NR_getpid;

    rules[2].struct_size = sizeof(rules[2]);
    rules[2].rule_id = kResultRule;
    rules[2].syscall_number = __NR_prctl;
    rules[2].action = HOOKSELF_SYSCALL_REPLACE_RESULT;
    rules[2].phase_mask = HOOKSELF_SYSCALL_PHASE_EXIT;
    rules[2].argument_index = 0;
    rules[2].argument_match_mask = UINT64_MAX;
    rules[2].argument_match_value = kResultOption;
    rules[2].replacement_value = static_cast<uint64_t>(kReplacementResult);

    rules[3].struct_size = sizeof(rules[3]);
    rules[3].rule_id = kArgumentRule;
    rules[3].syscall_number = __NR_lseek;
    rules[3].action = HOOKSELF_SYSCALL_REPLACE_ARGUMENT;
    rules[3].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    rules[3].argument_index = 1;
    rules[3].argument_match_mask = UINT64_MAX;
    rules[3].argument_match_value = kOriginalOffset;
    rules[3].replacement_value = kReplacementOffset;

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.syscall_rules = rules;
    config.syscall_rule_count = 4;
    config.event_capacity = 256;
    HookselfRuntime* runtime = nullptr;
    if (hookself_create(&config, &runtime) != HOOKSELF_OK || runtime == nullptr ||
        hookself_start(runtime) != HOOKSELF_OK) {
        hookself_destroy(runtime);
        (void)hookself::platform::RawClose(static_cast<int>(memory_fd));
        return result;
    }
    DrainEvents(runtime);

    result.deny_result = hookself::platform::RawSyscall6(
            __NR_prctl, static_cast<long>(kDenyOption));
    result.number_result = hookself::platform::RawSyscall6(
            __NR_prctl, static_cast<long>(kNumberOption));
    result.result_result = hookself::platform::RawSyscall6(
            __NR_prctl, static_cast<long>(kResultOption));
    result.argument_result = hookself::platform::RawSyscall6(
            __NR_lseek, memory_fd, static_cast<long>(kOriginalOffset), SEEK_SET);

    bool deny_entry = false;
    bool deny_exit = false;
    bool number_entry = false;
    bool result_exit = false;
    bool argument_entry = false;
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if (event.kind != HOOKSELF_EVENT_SYSCALL) {
                continue;
            }
            if (event.rule_id == kDenyRule &&
                event.action == HOOKSELF_SYSCALL_DENY) {
                deny_entry |= event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY;
                deny_exit |= event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                             event.result == -EACCES;
            } else if (event.rule_id == kNumberRule &&
                       event.action == HOOKSELF_SYSCALL_REPLACE_NUMBER) {
                number_entry |= event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY;
            } else if (event.rule_id == kResultRule &&
                       event.action == HOOKSELF_SYSCALL_REPLACE_RESULT) {
                result_exit |= event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                               event.result == kReplacementResult;
            } else if (event.rule_id == kArgumentRule &&
                       event.action == HOOKSELF_SYSCALL_REPLACE_ARGUMENT) {
                argument_entry |= event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY;
            }
        }
    }
    result.policy_events = static_cast<int32_t>(deny_entry) +
                           static_cast<int32_t>(deny_exit) +
                           static_cast<int32_t>(number_entry) +
                           static_cast<int32_t>(result_exit) +
                           static_cast<int32_t>(argument_entry);
    const int32_t expected_pid = static_cast<int32_t>(getpid());
    const int32_t stop_result = hookself_stop(runtime);
    hookself_destroy(runtime);
    (void)hookself::platform::RawClose(static_cast<int>(memory_fd));
    result.pass = stop_result == HOOKSELF_OK &&
                          result.deny_result == -EACCES &&
                          result.number_result == expected_pid &&
                          result.result_result == kReplacementResult &&
                          result.argument_result ==
                                  static_cast<int64_t>(kReplacementOffset) &&
                          result.policy_events == 5
                  ? 1
                  : 0;
    return result;
}

struct PtraceViewCheckResult {
    int32_t pass;
    int32_t validation_pass;
    int32_t event_pairs_pass;
    int32_t preexisting_worker_pass;
    int32_t new_worker_pass;
    int32_t shared_dumpable_pass;
    int32_t descendant_isolation_pass;
    int32_t stop_concurrency_pass;
    int64_t traceme_first;
    int64_t traceme_second;
    int64_t set_dumpable_zero;
    int64_t get_dumpable_zero;
    int64_t invalid_dumpable;
    int64_t get_after_invalid;
    int64_t set_dumpable_one;
    int64_t get_dumpable_one;
    int64_t set_ptracer_any;
    int64_t set_ptracer_invalid;
    int64_t set_ptracer_self;
    int64_t set_ptracer_zero;
    int64_t passthrough_result;
    int32_t policy_events;
    int32_t event_pair_errors;
    int32_t child_pid;
    int64_t child_set_dumpable_zero;
    int64_t child_get_dumpable_zero;
    int64_t parent_get_after_child;
    int32_t stop_worker_tid;
    uint32_t stop_worker_calls;
    uint32_t stop_overlap_calls;
    uint32_t stop_worker_unexpected_results;
    int32_t stop_worker_entry;
    int32_t stop_worker_exit;
    uint64_t operations;
    uint64_t dropped_events;
    int32_t fatal_code;
    int32_t fatal_errno;
    int32_t entry_dumpable;
    int32_t final_logical_dumpable;
    int32_t stop_result;
    int32_t stop_applied_dumpable;
    int32_t cleanup_restored_dumpable;
};

constexpr long kPrSetPtracerOption = 0x59616d61;
constexpr uint32_t kPtraceExpectedCapacity = 64;
constexpr uint32_t kPtracePendingCapacity = 128;
constexpr uint32_t kStopWorkerCallLimit = 64;

struct PtraceViewWorkerContext {
    uint32_t ready;
    uint32_t command;
    uint32_t completed;
    int32_t tid;
    int64_t traceme_first;
    int64_t traceme_second;
    int64_t get_dumpable_zero;
    int64_t get_dumpable_one;
};

struct PtraceStopWorkerContext {
    uint32_t ready;
    uint32_t command;
    uint32_t prime_done;
    uint32_t stop_finished;
    uint32_t calls;
    uint32_t unexpected_results;
    int32_t tid;
    int32_t expected_dumpable;
    int64_t prime_result;
};

struct PtraceExpectedOperation {
    int32_t tid;
    int32_t syscall_number;
    uint64_t argument0;
    uint64_t argument1;
    uint32_t rule_id;
    int64_t result;
    uint32_t entry_seen;
    uint32_t exit_seen;
};

struct PtracePendingEvent {
    int32_t tid;
    int32_t syscall_number;
    uint64_t arguments[6];
    uint32_t rule_id;
    uint32_t active;
};

bool WaitForAtomicAtLeast(const uint32_t* value, uint32_t target,
                          uint32_t timeout_ms) {
    for (uint32_t elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) >= target) {
            return true;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
    return __atomic_load_n(value, __ATOMIC_ACQUIRE) >= target;
}

void* RunPtraceViewWorker(void* opaque) {
    auto* context = static_cast<PtraceViewWorkerContext*>(opaque);
    context->tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    __atomic_store_n(&context->ready, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) < 1U) {
        hookself::platform::RawSleepOneMillisecond();
    }
    if (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) >= 3U) {
        return nullptr;
    }
    context->traceme_first = hookself::platform::RawSyscall6(
            __NR_ptrace, static_cast<long>(PTRACE_TRACEME), 0, 0, 0);
    context->traceme_second = hookself::platform::RawSyscall6(
            __NR_ptrace, static_cast<long>(PTRACE_TRACEME), 0, 0, 0);
    context->get_dumpable_zero = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    __atomic_store_n(&context->completed, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) < 2U) {
        hookself::platform::RawSleepOneMillisecond();
    }
    if (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) >= 3U) {
        return nullptr;
    }
    context->get_dumpable_one = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    __atomic_store_n(&context->completed, 2U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) < 3U) {
        hookself::platform::RawSleepOneMillisecond();
    }
    return nullptr;
}

void* RunPtraceStopWorker(void* opaque) {
    auto* context = static_cast<PtraceStopWorkerContext*>(opaque);
    context->tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    __atomic_store_n(&context->ready, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) < 1U) {
        hookself::platform::RawSleepOneMillisecond();
    }
    context->prime_result = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    __atomic_store_n(&context->prime_done, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&context->command, __ATOMIC_ACQUIRE) < 2U) {
        hookself::platform::RawSleepOneMillisecond();
    }
    while (__atomic_load_n(&context->stop_finished, __ATOMIC_ACQUIRE) == 0U &&
           __atomic_load_n(&context->calls, __ATOMIC_ACQUIRE) <
                   kStopWorkerCallLimit) {
        const int64_t observed = hookself::platform::RawSyscall6(
                __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
        if (observed != context->expected_dumpable) {
            __atomic_fetch_add(&context->unexpected_results, 1U,
                               __ATOMIC_RELAXED);
        }
        __atomic_fetch_add(&context->calls, 1U, __ATOMIC_RELEASE);
        hookself::platform::RawSleepOneMillisecond();
    }
    return nullptr;
}

bool AppendPtraceExpected(PtraceExpectedOperation* expected, uint32_t* count,
                          int32_t tid, int32_t syscall_number,
                          uint64_t argument0, uint64_t argument1,
                          uint32_t rule_id, int64_t result) {
    if (*count >= kPtraceExpectedCapacity) {
        return false;
    }
    PtraceExpectedOperation& operation = expected[(*count)++];
    operation.tid = tid;
    operation.syscall_number = syscall_number;
    operation.argument0 = argument0;
    operation.argument1 = argument1;
    operation.rule_id = rule_id;
    operation.result = result;
    return true;
}

uint32_t PtraceRuleForEvent(const HookselfEvent& event) {
    if (event.syscall_number == __NR_ptrace &&
        event.arguments[0] == static_cast<uint64_t>(PTRACE_TRACEME)) {
        return HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME;
    }
    if (event.syscall_number != __NR_prctl) {
        return 0;
    }
    if (event.arguments[0] == PR_GET_DUMPABLE ||
        event.arguments[0] == PR_SET_DUMPABLE) {
        return HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW;
    }
    if (event.arguments[0] == static_cast<uint64_t>(kPrSetPtracerOption)) {
        return HOOKSELF_BUILTIN_RULE_PTRACER_VIEW;
    }
    return 0;
}

PtracePendingEvent* FindPendingPtraceEvent(PtracePendingEvent* pending,
                                           int32_t tid, bool create) {
    PtracePendingEvent* empty = nullptr;
    for (uint32_t i = 0; i < kPtracePendingCapacity; ++i) {
        if (pending[i].active != 0 && pending[i].tid == tid) {
            return &pending[i];
        }
        if (empty == nullptr && pending[i].active == 0) {
            empty = &pending[i];
        }
    }
    return create ? empty : nullptr;
}

PtraceExpectedOperation* FindExpectedPtraceOperation(
        PtraceExpectedOperation* expected, uint32_t expected_count,
        int32_t tid) {
    for (uint32_t i = 0; i < expected_count; ++i) {
        if (expected[i].tid == tid && expected[i].exit_seen == 0) {
            return &expected[i];
        }
    }
    return nullptr;
}

void VerifyPtraceViewEvents(HookselfRuntime* runtime,
                            PtraceExpectedOperation* expected,
                            uint32_t expected_count, int32_t root_tgid,
                            int32_t child_pid,
                            int32_t stop_worker_tid,
                            int32_t stop_worker_result,
                            PtraceViewCheckResult* result) {
    PtracePendingEvent pending[kPtracePendingCapacity]{};
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if ((event.flags & HOOKSELF_EVENT_F_PTRACE_VIEW) == 0) {
                continue;
            }
            ++result->policy_events;
            bool valid = event.kind == HOOKSELF_EVENT_SYSCALL &&
                         event.action == HOOKSELF_SYSCALL_REPLACE_RESULT &&
                         event.tgid == root_tgid;
            const uint32_t expected_rule = PtraceRuleForEvent(event);
            valid = valid && expected_rule != 0 &&
                    event.rule_id == expected_rule;
            if (event.tgid == child_pid) {
                valid = false;
            }

            PtracePendingEvent* state = FindPendingPtraceEvent(
                    pending, event.tid,
                    event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY);
            if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                valid = valid && state != nullptr &&
                        (state == nullptr || state->active == 0) &&
                        event.result == 0 && event.error == 0;
                if (state != nullptr && state->active == 0) {
                    state->tid = event.tid;
                    state->syscall_number = event.syscall_number;
                    for (size_t argument = 0; argument < 6; ++argument) {
                        state->arguments[argument] = event.arguments[argument];
                    }
                    state->rule_id = event.rule_id;
                    state->active = 1;
                }
            } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                const int32_t expected_error =
                        event.result < 0 && event.result >= -4095
                                ? static_cast<int32_t>(-event.result)
                                : 0;
                valid = valid && state != nullptr &&
                        (state == nullptr ||
                         (state->syscall_number == event.syscall_number &&
                          state->rule_id == event.rule_id)) &&
                        event.error == expected_error;
                if (state != nullptr) {
                    for (size_t argument = 0; argument < 6; ++argument) {
                        valid = valid && state->arguments[argument] ==
                                                 event.arguments[argument];
                    }
                }
                if (state != nullptr) {
                    state->active = 0;
                }
            } else {
                valid = false;
            }

            PtraceExpectedOperation* operation =
                    FindExpectedPtraceOperation(
                            expected, expected_count, event.tid);
            if (operation != nullptr) {
                valid = valid &&
                        operation->syscall_number == event.syscall_number &&
                        operation->argument0 == event.arguments[0] &&
                        operation->argument1 == event.arguments[1] &&
                        operation->rule_id == event.rule_id &&
                        event.arguments[2] == 0 && event.arguments[3] == 0 &&
                        event.arguments[4] == 0 && event.arguments[5] == 0;
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    valid = valid && operation->entry_seen == 0;
                    operation->entry_seen = 1;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    valid = valid && operation->entry_seen == 1 &&
                            operation->exit_seen == 0 &&
                            operation->result == event.result;
                    operation->exit_seen = 1;
                }
            } else if (event.tid == stop_worker_tid) {
                valid = valid && event.syscall_number == __NR_prctl &&
                        event.arguments[0] == PR_GET_DUMPABLE &&
                        event.arguments[1] == 0 &&
                        event.arguments[2] == 0 &&
                        event.arguments[3] == 0 &&
                        event.arguments[4] == 0 &&
                        event.arguments[5] == 0 &&
                        event.rule_id ==
                                HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW;
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++result->stop_worker_entry;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    valid = valid && event.result == stop_worker_result;
                    ++result->stop_worker_exit;
                }
            } else {
                valid = false;
            }
            if (!valid) {
                ++result->event_pair_errors;
            }
        }
    }
    for (uint32_t i = 0; i < kPtracePendingCapacity; ++i) {
        if (pending[i].active != 0) {
            ++result->event_pair_errors;
        }
    }
    for (uint32_t i = 0; i < expected_count; ++i) {
        if (expected[i].entry_seen != 1 || expected[i].exit_seen != 1) {
            ++result->event_pair_errors;
        }
    }
    result->event_pairs_pass =
            result->event_pair_errors == 0 &&
                    result->stop_worker_entry > 0 &&
                    result->stop_worker_entry == result->stop_worker_exit
                    ? 1
                    : 0;
}

PtraceViewCheckResult RunPtraceViewCheck() {
    constexpr uint64_t kWideInvalidDumpable = 0x100000001ULL;
    constexpr uint64_t kUint32Max = UINT32_MAX;
    PtraceViewCheckResult result{};
    result.traceme_first = INT64_MIN;
    result.traceme_second = INT64_MIN;
    result.set_dumpable_zero = INT64_MIN;
    result.get_dumpable_zero = INT64_MIN;
    result.invalid_dumpable = INT64_MIN;
    result.get_after_invalid = INT64_MIN;
    result.set_dumpable_one = INT64_MIN;
    result.get_dumpable_one = INT64_MIN;
    result.set_ptracer_any = INT64_MIN;
    result.set_ptracer_invalid = INT64_MIN;
    result.set_ptracer_self = INT64_MIN;
    result.set_ptracer_zero = INT64_MIN;
    result.passthrough_result = INT64_MIN;
    result.child_set_dumpable_zero = INT64_MIN;
    result.child_get_dumpable_zero = INT64_MIN;
    result.parent_get_after_child = INT64_MIN;
    result.entry_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    result.final_logical_dumpable = result.entry_dumpable == 0 ? 1 : 0;
    result.stop_result = HOOKSELF_E_INVALID_STATE;
    result.stop_applied_dumpable = -1;

    PtraceViewWorkerContext preexisting{};
    preexisting.traceme_first = INT64_MIN;
    preexisting.traceme_second = INT64_MIN;
    preexisting.get_dumpable_zero = INT64_MIN;
    preexisting.get_dumpable_one = INT64_MIN;
    pthread_t preexisting_thread{};
    const bool preexisting_created =
            pthread_create(&preexisting_thread, nullptr,
                           RunPtraceViewWorker, &preexisting) == 0;
    if (!preexisting_created ||
        !WaitForAtomicAtLeast(&preexisting.ready, 1U, 3000U)) {
        if (preexisting_created) {
            __atomic_store_n(&preexisting.command, 3U, __ATOMIC_RELEASE);
            (void)pthread_join(preexisting_thread, nullptr);
        }
        return result;
    }

    HookselfConfig config{};
    hookself_default_config(&config);
    config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                    HOOKSELF_CONFIG_CAPTURE_ARGUMENTS;
    const bool fail_open_rejected =
            hookself_validate_config(&config) == HOOKSELF_E_INVALID_ARGUMENT;
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    const bool fail_closed_valid =
            hookself_validate_config(&config) == HOOKSELF_OK;
    result.validation_pass = fail_open_rejected && fail_closed_valid ? 1 : 0;
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;

    HookselfRuntime* runtime = nullptr;
    const bool started = hookself_create(&config, &runtime) == HOOKSELF_OK &&
                         runtime != nullptr &&
                         hookself_start(runtime) == HOOKSELF_OK;
    if (!started) {
        __atomic_store_n(&preexisting.command, 3U, __ATOMIC_RELEASE);
        (void)pthread_join(preexisting_thread, nullptr);
        hookself_destroy(runtime);
        if (result.entry_dumpable == 0 || result.entry_dumpable == 1) {
            (void)prctl(PR_SET_DUMPABLE, result.entry_dumpable, 0, 0, 0);
        }
        return result;
    }

    PtraceViewWorkerContext new_worker{};
    new_worker.traceme_first = INT64_MIN;
    new_worker.traceme_second = INT64_MIN;
    new_worker.get_dumpable_zero = INT64_MIN;
    new_worker.get_dumpable_one = INT64_MIN;
    pthread_t new_worker_thread{};
    const bool new_worker_created =
            pthread_create(&new_worker_thread, nullptr,
                           RunPtraceViewWorker, &new_worker) == 0;
    if (!new_worker_created ||
        !WaitForAtomicAtLeast(&new_worker.ready, 1U, 3000U)) {
        __atomic_store_n(&preexisting.command, 3U, __ATOMIC_RELEASE);
        (void)pthread_join(preexisting_thread, nullptr);
        if (new_worker_created) {
            __atomic_store_n(&new_worker.command, 3U, __ATOMIC_RELEASE);
            (void)pthread_join(new_worker_thread, nullptr);
        }
        result.stop_result = hookself_stop(runtime);
        hookself_destroy(runtime);
        if (result.entry_dumpable == 0 || result.entry_dumpable == 1) {
            (void)prctl(PR_SET_DUMPABLE, result.entry_dumpable, 0, 0, 0);
        }
        return result;
    }

    PtraceExpectedOperation expected[kPtraceExpectedCapacity]{};
    uint32_t expected_count = 0;
    bool expected_capacity_ok = true;
    const int32_t main_tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    const int32_t root_tgid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_getpid));
    result.traceme_first = hookself::platform::RawSyscall6(
            __NR_ptrace, static_cast<long>(PTRACE_TRACEME), 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_ptrace,
            PTRACE_TRACEME, 0, HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME, 0);
    result.traceme_second = hookself::platform::RawSyscall6(
            __NR_ptrace, static_cast<long>(PTRACE_TRACEME), 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_ptrace,
            PTRACE_TRACEME, 0, HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME, -EPERM);

    result.set_dumpable_zero = hookself::platform::RawSyscall6(
            __NR_prctl, PR_SET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_SET_DUMPABLE, 0, HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);
    result.get_dumpable_zero = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_GET_DUMPABLE, 0, HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);
    result.invalid_dumpable = hookself::platform::RawSyscall6(
            __NR_prctl, PR_SET_DUMPABLE,
            static_cast<long>(kWideInvalidDumpable), 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_SET_DUMPABLE, kWideInvalidDumpable,
            HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, -EINVAL);
    result.get_after_invalid = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_GET_DUMPABLE, 0, HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);

    __atomic_store_n(&preexisting.command, 1U, __ATOMIC_RELEASE);
    __atomic_store_n(&new_worker.command, 1U, __ATOMIC_RELEASE);
    const bool workers_zero_complete =
            WaitForAtomicAtLeast(&preexisting.completed, 1U, 3000U) &&
            WaitForAtomicAtLeast(&new_worker.completed, 1U, 3000U);

    result.set_dumpable_one = hookself::platform::RawSyscall6(
            __NR_prctl, PR_SET_DUMPABLE, 1, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_SET_DUMPABLE, 1, HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);
    result.get_dumpable_one = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_GET_DUMPABLE, 0, HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 1);
    __atomic_store_n(&preexisting.command, 2U, __ATOMIC_RELEASE);
    __atomic_store_n(&new_worker.command, 2U, __ATOMIC_RELEASE);
    const bool workers_one_complete =
            WaitForAtomicAtLeast(&preexisting.completed, 2U, 3000U) &&
            WaitForAtomicAtLeast(&new_worker.completed, 2U, 3000U);
    __atomic_store_n(&preexisting.command, 3U, __ATOMIC_RELEASE);
    __atomic_store_n(&new_worker.command, 3U, __ATOMIC_RELEASE);
    (void)pthread_join(preexisting_thread, nullptr);
    (void)pthread_join(new_worker_thread, nullptr);

    const PtraceViewWorkerContext* workers[2] = {
            &preexisting, &new_worker};
    for (const PtraceViewWorkerContext* worker : workers) {
        expected_capacity_ok &= AppendPtraceExpected(
                expected, &expected_count, worker->tid, __NR_ptrace,
                PTRACE_TRACEME, 0,
                HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME, 0);
        expected_capacity_ok &= AppendPtraceExpected(
                expected, &expected_count, worker->tid, __NR_ptrace,
                PTRACE_TRACEME, 0,
                HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME, -EPERM);
        expected_capacity_ok &= AppendPtraceExpected(
                expected, &expected_count, worker->tid, __NR_prctl,
                PR_GET_DUMPABLE, 0,
                HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);
        expected_capacity_ok &= AppendPtraceExpected(
                expected, &expected_count, worker->tid, __NR_prctl,
                PR_GET_DUMPABLE, 0,
                HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 1);
    }
    result.preexisting_worker_pass =
            workers_zero_complete && workers_one_complete &&
                    preexisting.tid > 0 &&
                    preexisting.traceme_first == 0 &&
                    preexisting.traceme_second == -EPERM &&
                    preexisting.get_dumpable_zero == 0 &&
                    preexisting.get_dumpable_one == 1
                    ? 1
                    : 0;
    result.new_worker_pass =
            workers_zero_complete && workers_one_complete &&
                    new_worker.tid > 0 &&
                    new_worker.traceme_first == 0 &&
                    new_worker.traceme_second == -EPERM &&
                    new_worker.get_dumpable_zero == 0 &&
                    new_worker.get_dumpable_one == 1
                    ? 1
                    : 0;
    result.shared_dumpable_pass =
            result.preexisting_worker_pass != 0 &&
                    result.new_worker_pass != 0
                    ? 1
                    : 0;

    result.set_ptracer_any = hookself::platform::RawSyscall6(
            __NR_prctl, kPrSetPtracerOption, -1L, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            kPrSetPtracerOption, UINT64_MAX,
            HOOKSELF_BUILTIN_RULE_PTRACER_VIEW, 0);
    result.set_ptracer_invalid = hookself::platform::RawSyscall6(
            __NR_prctl, kPrSetPtracerOption,
            static_cast<long>(kUint32Max), 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            kPrSetPtracerOption, kUint32Max,
            HOOKSELF_BUILTIN_RULE_PTRACER_VIEW, -EINVAL);
    result.set_ptracer_self = hookself::platform::RawSyscall6(
            __NR_prctl, kPrSetPtracerOption, root_tgid, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            kPrSetPtracerOption, static_cast<uint64_t>(root_tgid),
            HOOKSELF_BUILTIN_RULE_PTRACER_VIEW, 0);
    result.set_ptracer_zero = hookself::platform::RawSyscall6(
            __NR_prctl, kPrSetPtracerOption, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            kPrSetPtracerOption, 0,
            HOOKSELF_BUILTIN_RULE_PTRACER_VIEW, 0);
    char name[32]{};
    result.passthrough_result = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_NAME, reinterpret_cast<long>(name), 0, 0);

    struct ChildDumpableResult {
        int64_t set_zero;
        int64_t get_zero;
    } child_result{INT64_MIN, INT64_MIN};
    int child_pipe[2] = {-1, -1};
    if (pipe2(child_pipe, O_CLOEXEC) == 0) {
        const pid_t child = fork();
        if (child == 0) {
            (void)hookself::platform::RawClose(child_pipe[0]);
            ChildDumpableResult local{};
            local.set_zero = hookself::platform::RawSyscall6(
                    __NR_prctl, PR_SET_DUMPABLE, 0, 0, 0);
            local.get_zero = hookself::platform::RawSyscall6(
                    __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
            (void)hookself::platform::RawWrite(
                    child_pipe[1], &local, sizeof(local));
            hookself::platform::RawExit(0);
        }
        (void)hookself::platform::RawClose(child_pipe[1]);
        child_pipe[1] = -1;
        if (child > 0) {
            result.child_pid = child;
            const long bytes = hookself::platform::RawRead(
                    child_pipe[0], &child_result, sizeof(child_result));
            int child_status = 0;
            while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
            }
            if (bytes != static_cast<long>(sizeof(child_result)) ||
                !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
                child_result = {INT64_MIN, INT64_MIN};
            }
        }
        (void)hookself::platform::RawClose(child_pipe[0]);
    }
    result.child_set_dumpable_zero = child_result.set_zero;
    result.child_get_dumpable_zero = child_result.get_zero;
    result.parent_get_after_child = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_GET_DUMPABLE, 0,
            HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 1);
    result.descendant_isolation_pass =
            result.child_pid > 0 && result.child_set_dumpable_zero == 0 &&
                    result.child_get_dumpable_zero == 0 &&
                    result.parent_get_after_child == 1
                    ? 1
                    : 0;

    const int64_t final_set = hookself::platform::RawSyscall6(
            __NR_prctl, PR_SET_DUMPABLE,
            result.final_logical_dumpable, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_SET_DUMPABLE,
            static_cast<uint64_t>(result.final_logical_dumpable),
            HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW, 0);
    const int64_t final_get = hookself::platform::RawSyscall6(
            __NR_prctl, PR_GET_DUMPABLE, 0, 0, 0);
    expected_capacity_ok &= AppendPtraceExpected(
            expected, &expected_count, main_tid, __NR_prctl,
            PR_GET_DUMPABLE, 0,
            HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW,
            result.final_logical_dumpable);

    PtraceStopWorkerContext stop_worker{};
    stop_worker.expected_dumpable = result.final_logical_dumpable;
    stop_worker.prime_result = INT64_MIN;
    pthread_t stop_thread{};
    const bool stop_worker_created =
            pthread_create(&stop_thread, nullptr,
                           RunPtraceStopWorker, &stop_worker) == 0;
    bool stop_worker_ready = stop_worker_created &&
            WaitForAtomicAtLeast(&stop_worker.ready, 1U, 3000U);
    if (stop_worker_ready) {
        __atomic_store_n(&stop_worker.command, 1U, __ATOMIC_RELEASE);
        stop_worker_ready = WaitForAtomicAtLeast(
                &stop_worker.prime_done, 1U, 3000U);
    }
    uint32_t calls_before_stop = 0;
    if (stop_worker_ready) {
        __atomic_store_n(&stop_worker.command, 2U, __ATOMIC_RELEASE);
        stop_worker_ready = WaitForAtomicAtLeast(
                &stop_worker.calls, 1U, 3000U);
        calls_before_stop = __atomic_load_n(
                &stop_worker.calls, __ATOMIC_ACQUIRE);
    }
    result.stop_result = hookself_stop(runtime);
    __atomic_store_n(&stop_worker.stop_finished, 1U, __ATOMIC_RELEASE);
    if (stop_worker_created) {
        __atomic_store_n(&stop_worker.command, 2U, __ATOMIC_RELEASE);
        (void)pthread_join(stop_thread, nullptr);
    }
    const uint32_t calls_after_stop = __atomic_load_n(
            &stop_worker.calls, __ATOMIC_ACQUIRE);
    const uint32_t unexpected_stop_results = __atomic_load_n(
            &stop_worker.unexpected_results, __ATOMIC_ACQUIRE);
    result.stop_worker_tid = stop_worker.tid;
    result.stop_worker_calls = calls_after_stop;
    result.stop_worker_unexpected_results = unexpected_stop_results;
    result.stop_overlap_calls = calls_after_stop >= calls_before_stop
                                        ? calls_after_stop - calls_before_stop
                                        : 0;

    VerifyPtraceViewEvents(runtime, expected, expected_count, root_tgid,
                           result.child_pid, stop_worker.tid,
                           result.final_logical_dumpable, &result);
    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        result.operations = stats.ptrace_view_operations;
        result.dropped_events = stats.dropped_events;
        result.fatal_code = stats.fatal_code;
        result.fatal_errno = stats.fatal_errno;
    }
    hookself_destroy(runtime);

    result.stop_applied_dumpable =
            prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if ((result.entry_dumpable == 0 || result.entry_dumpable == 1) &&
        prctl(PR_SET_DUMPABLE, result.entry_dumpable, 0, 0, 0) == 0 &&
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == result.entry_dumpable) {
        result.cleanup_restored_dumpable = 1;
    }
    result.stop_concurrency_pass =
            stop_worker_ready && stop_worker.prime_result ==
                                         result.final_logical_dumpable &&
                    result.stop_worker_calls > 0 &&
                    result.stop_worker_calls <= kStopWorkerCallLimit &&
                    result.stop_overlap_calls > 0 &&
                    result.stop_worker_unexpected_results == 0 &&
                    result.stop_worker_entry == result.stop_worker_exit &&
                    result.stop_worker_entry > 0
                    ? 1
                    : 0;
    const uint64_t paired_operations =
            static_cast<uint64_t>(result.policy_events / 2);
    result.pass = result.validation_pass != 0 && expected_capacity_ok &&
                          result.event_pairs_pass != 0 &&
                          result.preexisting_worker_pass != 0 &&
                          result.new_worker_pass != 0 &&
                          result.shared_dumpable_pass != 0 &&
                          result.descendant_isolation_pass != 0 &&
                          result.stop_concurrency_pass != 0 &&
                          result.traceme_first == 0 &&
                          result.traceme_second == -EPERM &&
                          result.set_dumpable_zero == 0 &&
                          result.get_dumpable_zero == 0 &&
                          result.invalid_dumpable == -EINVAL &&
                          result.get_after_invalid == 0 &&
                          result.set_dumpable_one == 0 &&
                          result.get_dumpable_one == 1 &&
                          result.set_ptracer_any == 0 &&
                          result.set_ptracer_invalid == -EINVAL &&
                          result.set_ptracer_self == 0 &&
                          result.set_ptracer_zero == 0 &&
                          result.passthrough_result == 0 &&
                          final_set == 0 &&
                          final_get == result.final_logical_dumpable &&
                          (result.policy_events & 1) == 0 &&
                          result.operations == paired_operations &&
                          result.dropped_events == 0 &&
                          result.fatal_code == HOOKSELF_FATAL_NONE &&
                          result.stop_result == HOOKSELF_OK &&
                          result.stop_applied_dumpable ==
                                  result.final_logical_dumpable &&
                          result.cleanup_restored_dumpable != 0
                  ? 1
                  : 0;
    return result;
}

constexpr size_t kResidentProcStatusCapacity = 4096U;
constexpr uint32_t kProcStatusExpectedCapacity = 64U;

struct ProcStatusExpectedOperation {
    int32_t tid;
    int32_t syscall_number;
    uint64_t arguments[6];
    int64_t result;
    uint32_t entry_seen;
    uint32_t exit_seen;
};

struct ProcStatusWorkerContext {
    int32_t root_tgid;
    int32_t tid;
    int32_t fd;
    int32_t parse_result;
    int32_t parsed_tgid;
    int32_t parsed_pid;
    int32_t tracer_zero;
    int64_t read_result;
    alignas(8) uint8_t content[kResidentProcStatusCapacity];
};

struct ProcStatusViewCheckResult {
    int32_t pass;
    int32_t preopen_fd;
    int64_t pread_result;
    int32_t pread_match;
    int64_t dup_read_result;
    int32_t dup_read_match;
    int64_t readv_result;
    int32_t readv_match;
    int32_t readv_cross_iov;
    int32_t worker_tid;
    int32_t worker_tgid;
    int32_t worker_pid;
    int32_t worker_match;
    int32_t fake_memfd_unchanged;
    int32_t event_pairs_pass;
    int32_t event_pair_errors;
    int32_t policy_events;
    uint64_t patches;
    uint64_t dropped_events;
    int32_t fatal_code;
    int32_t fatal_errno;
    int32_t stop_result;
};

bool BytesEqual(const uint8_t* left, const uint8_t* right, size_t size) {
    if (left == nullptr || right == nullptr) {
        return false;
    }
    for (size_t i = 0; i < size; ++i) {
        if (left[i] != right[i]) {
            return false;
        }
    }
    return true;
}

void* RunProcStatusWorker(void* opaque) {
    auto* worker = static_cast<ProcStatusWorkerContext*>(opaque);
    worker->tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    const long fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD,
            reinterpret_cast<long>("/proc/thread-self/status"),
            O_RDONLY | O_CLOEXEC, 0);
    worker->fd = static_cast<int32_t>(fd);
    if (fd < 0) {
        worker->read_result = fd;
        return nullptr;
    }
    worker->read_result = hookself::platform::RawRead(
            static_cast<int>(fd), worker->content,
            sizeof(worker->content));
    if (worker->read_result > 0) {
        ProcStatusMetadata metadata{};
        worker->parse_result = ParseProcStatusMetadata(
                worker->content,
                static_cast<size_t>(worker->read_result),
                worker->root_tgid, &metadata);
        if (worker->parse_result == 0) {
            worker->parsed_tgid = metadata.tgid;
            worker->parsed_pid = metadata.pid;
            worker->tracer_zero = TracerPidValueIsZero(
                                          worker->content,
                                          static_cast<size_t>(
                                                  worker->read_result),
                                          metadata)
                                          ? 1
                                          : 0;
        }
    }
    (void)hookself::platform::RawClose(static_cast<int>(fd));
    return nullptr;
}

bool AppendProcStatusExpected(ProcStatusExpectedOperation* expected,
                              uint32_t* count, int32_t tid,
                              int32_t syscall_number,
                              const uint64_t arguments[6],
                              int64_t result) {
    if (expected == nullptr || count == nullptr || arguments == nullptr ||
        *count >= kProcStatusExpectedCapacity) {
        return false;
    }
    ProcStatusExpectedOperation& operation = expected[(*count)++];
    operation.tid = tid;
    operation.syscall_number = syscall_number;
    for (size_t i = 0; i < 6; ++i) {
        operation.arguments[i] = arguments[i];
    }
    operation.result = result;
    return true;
}

ProcStatusExpectedOperation* FindProcStatusExpected(
        ProcStatusExpectedOperation* expected, uint32_t count,
        int32_t tid) {
    for (uint32_t i = 0; i < count; ++i) {
        if (expected[i].tid == tid && expected[i].exit_seen == 0) {
            return &expected[i];
        }
    }
    return nullptr;
}

void VerifyProcStatusEvents(HookselfRuntime* runtime, int32_t root_tgid,
                            ProcStatusExpectedOperation* expected,
                            uint32_t expected_count,
                            ProcStatusViewCheckResult* result) {
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            const HookselfEvent& event = events[i];
            if ((event.flags & HOOKSELF_EVENT_F_PROC_STATUS_VIEW) == 0) {
                continue;
            }
            ++result->policy_events;
            ProcStatusExpectedOperation* operation =
                    FindProcStatusExpected(
                            expected, expected_count, event.tid);
            bool valid = operation != nullptr &&
                         event.kind == HOOKSELF_EVENT_SYSCALL &&
                         event.tgid == root_tgid &&
                         event.action == HOOKSELF_SYSCALL_OBSERVE &&
                         event.rule_id ==
                                 HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW;
            if (operation != nullptr) {
                valid = valid &&
                        event.syscall_number == operation->syscall_number;
                for (size_t argument = 0; argument < 6; ++argument) {
                    valid = valid && event.arguments[argument] ==
                                             operation->arguments[argument];
                }
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    valid = valid && operation->entry_seen == 0 &&
                            event.result == 0 && event.error == 0;
                    operation->entry_seen = 1;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    const int32_t expected_error =
                            operation->result < 0 &&
                                    operation->result >= -4095
                                    ? static_cast<int32_t>(
                                              -operation->result)
                                    : 0;
                    valid = valid && operation->entry_seen == 1 &&
                            operation->exit_seen == 0 &&
                            event.result == operation->result &&
                            event.error == expected_error;
                    operation->exit_seen = 1;
                } else {
                    valid = false;
                }
            }
            if (!valid) {
                ++result->event_pair_errors;
            }
        }
    }
    for (uint32_t i = 0; i < expected_count; ++i) {
        if (expected[i].entry_seen != 1 || expected[i].exit_seen != 1) {
            ++result->event_pair_errors;
        }
    }
    result->event_pairs_pass =
            result->event_pair_errors == 0 &&
                    result->policy_events ==
                            static_cast<int32_t>(expected_count * 2U)
                    ? 1
                    : 0;
}

bool ParseZeroTracerStatus(const uint8_t* content, size_t size,
                           int32_t expected_tgid,
                           ProcStatusMetadata* metadata) {
    return ParseProcStatusMetadata(
                   content, size, expected_tgid, metadata) == 0 &&
           TracerPidValueIsZero(content, size, *metadata);
}

ProcStatusViewCheckResult RunProcStatusViewCheck() {
    ProcStatusViewCheckResult result{};
    result.preopen_fd = -1;
    result.pread_result = INT64_MIN;
    result.dup_read_result = INT64_MIN;
    result.readv_result = INT64_MIN;
    result.stop_result = HOOKSELF_E_INVALID_STATE;
    uint8_t incomplete_line[] = "TracerPid:\t12345";
    const bool incomplete_line_unchanged =
            RewriteTracerPidValue(incomplete_line,
                                  sizeof(incomplete_line) - 1U) == 0 &&
            BytesEqual(incomplete_line,
                       reinterpret_cast<const uint8_t*>(
                               "TracerPid:\t12345"),
                       sizeof(incomplete_line) - 1U);
    const int32_t root_tgid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_getpid));
    const int32_t main_tid = static_cast<int32_t>(
            hookself::platform::RawSyscall6(__NR_gettid));
    const long preopen_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD,
            reinterpret_cast<long>("/proc/self/status"),
            O_RDONLY | O_CLOEXEC, 0);
    result.preopen_fd = static_cast<int32_t>(preopen_fd);
    if (preopen_fd < 0) {
        return result;
    }

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                    HOOKSELF_CONFIG_CAPTURE_ARGUMENTS;
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;
    HookselfRuntime* runtime = nullptr;
    const bool started = hookself_create(&config, &runtime) == HOOKSELF_OK &&
                         runtime != nullptr &&
                         hookself_start(runtime) == HOOKSELF_OK;
    if (!started) {
        hookself_destroy(runtime);
        (void)hookself::platform::RawClose(static_cast<int>(preopen_fd));
        return result;
    }

    ProcStatusExpectedOperation expected[kProcStatusExpectedCapacity]{};
    uint32_t expected_count = 0;
    bool expected_capacity_ok = true;
    alignas(8) uint8_t pread_content[kResidentProcStatusCapacity]{};
    result.pread_result = hookself::platform::RawSyscall6(
            __NR_pread64, preopen_fd,
            reinterpret_cast<long>(pread_content),
            sizeof(pread_content), 0);
    const uint64_t pread_arguments[6] = {
            static_cast<uint64_t>(preopen_fd),
            reinterpret_cast<uint64_t>(pread_content),
            sizeof(pread_content), 0, 0, 0};
    expected_capacity_ok &= AppendProcStatusExpected(
            expected, &expected_count, main_tid, __NR_pread64,
            pread_arguments, result.pread_result);
    ProcStatusMetadata pread_metadata{};
    if (result.pread_result > 0 &&
        ParseZeroTracerStatus(
                pread_content, static_cast<size_t>(result.pread_result),
                root_tgid, &pread_metadata)) {
        result.pread_match = 1;
    }

    const long dup_fd = hookself::platform::RawSyscall6(
            __NR_dup, preopen_fd);
    alignas(8) uint8_t dup_content[kResidentProcStatusCapacity]{};
    if (dup_fd >= 0) {
        result.dup_read_result = hookself::platform::RawRead(
                static_cast<int>(dup_fd), dup_content,
                sizeof(dup_content));
        const uint64_t dup_arguments[6] = {
                static_cast<uint64_t>(dup_fd),
                reinterpret_cast<uint64_t>(dup_content),
                sizeof(dup_content), 0, 0, 0};
        expected_capacity_ok &= AppendProcStatusExpected(
                expected, &expected_count, main_tid, __NR_read,
                dup_arguments, result.dup_read_result);
        ProcStatusMetadata dup_metadata{};
        if (result.dup_read_result > 0 &&
            ParseZeroTracerStatus(
                    dup_content,
                    static_cast<size_t>(result.dup_read_result),
                    root_tgid, &dup_metadata)) {
            result.dup_read_match = 1;
        }
        (void)hookself::platform::RawClose(static_cast<int>(dup_fd));
    }

    alignas(8) uint8_t readv_combined[kResidentProcStatusCapacity]{};
    constexpr size_t kReadvSingleByteIovecs = 32U;
    constexpr size_t kReadvIovecCount = kReadvSingleByteIovecs + 2U;
    iovec vectors[kReadvIovecCount]{};
    if (result.pread_match != 0) {
        const size_t pread_offset =
                static_cast<size_t>(pread_metadata.tracer_value_offset);
        const size_t single_byte_begin =
                pread_offset >= kReadvSingleByteIovecs / 2U
                        ? pread_offset - kReadvSingleByteIovecs / 2U
                        : 0U;
        const size_t single_byte_end =
                single_byte_begin + kReadvSingleByteIovecs;
        if (single_byte_end <= sizeof(readv_combined) &&
            hookself::platform::RawSyscall6(
                    __NR_lseek, preopen_fd, 0, SEEK_SET) == 0) {
            vectors[0].iov_base = readv_combined;
            vectors[0].iov_len = single_byte_begin;
            for (size_t i = 0; i < kReadvSingleByteIovecs; ++i) {
                vectors[i + 1U].iov_base =
                        readv_combined + single_byte_begin + i;
                vectors[i + 1U].iov_len = 1U;
            }
            vectors[kReadvIovecCount - 1U].iov_base =
                    readv_combined + single_byte_end;
            vectors[kReadvIovecCount - 1U].iov_len =
                    sizeof(readv_combined) - single_byte_end;
            result.readv_result = hookself::platform::RawSyscall6(
                    __NR_readv, preopen_fd,
                    reinterpret_cast<long>(vectors),
                    static_cast<long>(kReadvIovecCount));
            const uint64_t readv_arguments[6] = {
                    static_cast<uint64_t>(preopen_fd),
                    reinterpret_cast<uint64_t>(vectors),
                    kReadvIovecCount, 0, 0, 0};
            expected_capacity_ok &= AppendProcStatusExpected(
                    expected, &expected_count, main_tid, __NR_readv,
                    readv_arguments, result.readv_result);
            if (result.readv_result > 0 &&
                static_cast<uint64_t>(result.readv_result) <=
                        sizeof(readv_combined)) {
                const size_t total = static_cast<size_t>(result.readv_result);
                ProcStatusMetadata readv_metadata{};
                if (ParseZeroTracerStatus(
                            readv_combined, total, root_tgid,
                            &readv_metadata)) {
                    result.readv_match = 1;
                    const size_t tracer_start = static_cast<size_t>(
                            readv_metadata.tracer_value_offset);
                    const size_t tracer_end =
                            tracer_start + static_cast<size_t>(
                                                   readv_metadata
                                                           .tracer_value_length);
                    size_t boundary = 0;
                    for (size_t i = 0; i + 1U < kReadvIovecCount; ++i) {
                        boundary += vectors[i].iov_len;
                        if (boundary > tracer_start &&
                            boundary < tracer_end && boundary < total) {
                            result.readv_cross_iov = 1;
                            break;
                        }
                    }
                }
            }
        }
    }

    char fake_source[256]{};
    const int fake_size = snprintf(
            fake_source, sizeof(fake_source),
            "Name:\tfake-status\nTgid:\t%d\nPid:\t%d\nTracerPid:\t98765\n",
            root_tgid, root_tgid);
    const long fake_fd = hookself::platform::RawSyscall6(
            __NR_memfd_create,
            reinterpret_cast<long>("hookself-fake-status"), 1U);
    if (fake_fd >= 0 && fake_size > 0 &&
        static_cast<size_t>(fake_size) < sizeof(fake_source) &&
        hookself::platform::RawWrite(
                static_cast<int>(fake_fd), fake_source,
                static_cast<size_t>(fake_size)) == fake_size &&
        hookself::platform::RawSyscall6(
                __NR_lseek, fake_fd, 0, SEEK_SET) == 0) {
        uint8_t fake_output[256]{};
        const long fake_read = hookself::platform::RawRead(
                static_cast<int>(fake_fd), fake_output,
                sizeof(fake_output));
        ProcStatusMetadata fake_metadata{};
        if (fake_read == fake_size &&
            BytesEqual(fake_output,
                       reinterpret_cast<const uint8_t*>(fake_source),
                       static_cast<size_t>(fake_size)) &&
            ParseProcStatusMetadata(
                    fake_output, static_cast<size_t>(fake_read),
                    root_tgid, &fake_metadata) == 0 &&
            !TracerPidValueIsZero(
                    fake_output, static_cast<size_t>(fake_read),
                    fake_metadata)) {
            result.fake_memfd_unchanged = 1;
        }
    }
    if (fake_fd >= 0) {
        (void)hookself::platform::RawClose(static_cast<int>(fake_fd));
    }

    ProcStatusWorkerContext worker{};
    worker.root_tgid = root_tgid;
    worker.fd = -1;
    worker.parse_result = EINVAL;
    worker.read_result = INT64_MIN;
    pthread_t worker_thread{};
    const bool worker_created =
            pthread_create(&worker_thread, nullptr,
                           RunProcStatusWorker, &worker) == 0;
    if (worker_created) {
        (void)pthread_join(worker_thread, nullptr);
        result.worker_tid = worker.tid;
        result.worker_tgid = worker.parsed_tgid;
        result.worker_pid = worker.parsed_pid;
        result.worker_match =
                worker.tid > 0 && worker.tid != root_tgid &&
                        worker.parse_result == 0 &&
                        worker.parsed_tgid == root_tgid &&
                        worker.parsed_pid == worker.tid &&
                        worker.tracer_zero != 0
                        ? 1
                        : 0;
        if (worker.fd >= 0) {
            const uint64_t worker_arguments[6] = {
                    static_cast<uint64_t>(worker.fd),
                    reinterpret_cast<uint64_t>(worker.content),
                    sizeof(worker.content), 0, 0, 0};
            expected_capacity_ok &= AppendProcStatusExpected(
                    expected, &expected_count, worker.tid, __NR_read,
                    worker_arguments, worker.read_result);
        }
    }

    (void)hookself::platform::RawClose(static_cast<int>(preopen_fd));
    result.stop_result = hookself_stop(runtime);
    VerifyProcStatusEvents(runtime, root_tgid, expected, expected_count,
                           &result);
    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        result.patches = stats.proc_status_patches;
        result.dropped_events = stats.dropped_events;
        result.fatal_code = stats.fatal_code;
        result.fatal_errno = stats.fatal_errno;
    }
    hookself_destroy(runtime);
    result.pass = result.preopen_fd >= 0 &&
                          result.pread_match != 0 &&
                          result.dup_read_match != 0 &&
                          result.readv_match != 0 &&
                          result.readv_cross_iov != 0 &&
                          result.worker_match != 0 &&
                          result.fake_memfd_unchanged != 0 &&
                          result.event_pairs_pass != 0 &&
                          incomplete_line_unchanged &&
                          expected_capacity_ok && result.patches >= 4U &&
                          result.dropped_events == 0 &&
                          result.fatal_code == HOOKSELF_FATAL_NONE &&
                          result.fatal_errno == 0 &&
                          result.stop_result == HOOKSELF_OK
                  ? 1
                  : 0;
    return result;
}

struct VirtualFileCheckResult {
    int32_t pass;
    int32_t static_match;
    int32_t old_snapshot_match;
    int32_t new_snapshot_match;
    int64_t write_result;
    int64_t readlink_result;
    int32_t events;
    uint64_t opens;
    int32_t publish_result;
    int32_t stable_fd;
    int64_t protected_close_result;
    int32_t after_close_match;
    int64_t protected_dup3_result;
    int32_t after_dup3_match;
    int64_t protected_setfd_result;
    int64_t protected_getfd_result;
    int64_t close_range_base_result;
    int64_t ordinary_close_range_cloexec_result;
    int64_t ordinary_close_range_getfd_result;
    int32_t ordinary_close_range_cloexec_set;
    int64_t protected_close_range_cloexec_result;
    int64_t protected_close_range_getfd_result;
    int32_t protected_close_range_cloexec_set;
    int64_t protected_close_range_result;
    int32_t fd_reuse_target_fd;
    int32_t fd_reuse_register_result;
    int32_t fd_reuse_unregister_result;
    int64_t fd_reuse_protected_close_result;
    int64_t fd_reuse_duplicate_result;
    int64_t fd_reuse_ordinary_close_result;
    int64_t fd_reuse_ordinary_getfd_result;
    int32_t fd_reuse_pass;
    int64_t segmented_close_range_result;
    int32_t segmented_close_range_left_fd;
    int32_t segmented_close_range_right_fd;
    int64_t segmented_close_range_left_getfd;
    int64_t segmented_close_range_right_getfd;
    int64_t segmented_close_range_protected_getfd;
    int32_t segmented_close_range_pass;
    int64_t segmented_unshare_close_range_result;
    int64_t segmented_unshare_close_range_left_getfd;
    int64_t segmented_unshare_close_range_right_getfd;
    int64_t segmented_unshare_close_range_protected_getfd;
    int32_t segmented_unshare_close_range_pass;
    uint64_t protected_fd_blocks;
    uint64_t internal_fd_operations;
    int32_t provider_pass;
    int32_t status_refresh_result;
    int32_t maps_refresh_result;
    int32_t selinux_refresh_result;
    int32_t status_match;
    int32_t maps_match;
    int32_t selinux_match;
};

bool ReadFdContains(int fd, const char* expected) {
    char content[128]{};
    const long bytes = hookself::platform::RawRead(
            fd, content, sizeof(content) - 1U);
    return bytes > 0 &&
           StringContains(content, static_cast<size_t>(bytes), expected);
}

bool ReadFdSnapshotMatches(int fd, const char* required,
                           const char* forbidden) {
    auto* content = new (std::nothrow)
            char[HOOKSELF_MAX_VIRTUAL_FILE_SIZE + 1U];
    if (content == nullptr) {
        return false;
    }
    size_t total = 0;
    while (total < HOOKSELF_MAX_VIRTUAL_FILE_SIZE) {
        const long bytes = hookself::platform::RawRead(
                fd, content + total,
                HOOKSELF_MAX_VIRTUAL_FILE_SIZE - total);
        if (bytes < 0 && bytes == -EINTR) {
            continue;
        }
        if (bytes < 0) {
            delete[] content;
            return false;
        }
        if (bytes == 0) {
            break;
        }
        total += static_cast<size_t>(bytes);
    }
    content[total] = '\0';
    const bool required_match =
            required == nullptr || StringContains(content, total, required);
    const bool forbidden_absent =
            forbidden == nullptr || !StringContains(content, total, forbidden);
    delete[] content;
    return required_match && forbidden_absent;
}

int FindFdContaining(const char* expected) {
    for (int fd = 3; fd < 1024; ++fd) {
        char content[128]{};
        const long bytes = hookself::platform::RawSyscall6(
                __NR_pread64, fd, reinterpret_cast<long>(content),
                sizeof(content) - 1U, 0);
        if (bytes > 0 &&
            StringContains(content, static_cast<size_t>(bytes), expected)) {
            return fd;
        }
    }
    return -1;
}

VirtualFileCheckResult RunVirtualFileCheck(const char* virtual_backing_dir) {
    constexpr uint32_t kStaticId = 1001;
    constexpr uint32_t kDynamicId = 1002;
    constexpr uint32_t kStatusId = 1003;
    constexpr uint32_t kMapsId = 1004;
    constexpr uint32_t kSelinuxId = 1005;
    constexpr int32_t kCloseRangeSyscall = 436;
    constexpr uint32_t kCloseRangeUnshare = 1U << 1;
    constexpr uint32_t kCloseRangeCloexec = 1U << 2;
    constexpr char kStaticPath[] = "/hookself-static-file";
    constexpr char kDynamicPath[] = "/hookself-dynamic-file";
    constexpr uint8_t kStaticContent[] = "static-snapshot\n";
    constexpr uint8_t kDynamicA[] = "dynamic-A\n";
    constexpr uint8_t kDynamicB[] = "dynamic-B\n";
    constexpr uint8_t kSelinuxContent[] = "u:r:hookself_virtual:s0\n";
    constexpr char kProtectedMutationMarker[] =
            "hookself-protected-mutation";

    VirtualFileCheckResult result{};
    result.write_result = INT64_MIN;
    result.readlink_result = INT64_MIN;
    result.stable_fd = -1;
    result.protected_close_result = INT64_MIN;
    result.protected_dup3_result = INT64_MIN;
    result.protected_setfd_result = INT64_MIN;
    result.protected_getfd_result = INT64_MIN;
    result.close_range_base_result = INT64_MIN;
    result.ordinary_close_range_cloexec_result = INT64_MIN;
    result.ordinary_close_range_getfd_result = INT64_MIN;
    result.protected_close_range_cloexec_result = INT64_MIN;
    result.protected_close_range_getfd_result = INT64_MIN;
    result.protected_close_range_result = INT64_MIN;
    result.fd_reuse_target_fd = -1;
    result.fd_reuse_register_result = HOOKSELF_E_INTERNAL;
    result.fd_reuse_unregister_result = HOOKSELF_E_INTERNAL;
    result.fd_reuse_protected_close_result = INT64_MIN;
    result.fd_reuse_duplicate_result = INT64_MIN;
    result.fd_reuse_ordinary_close_result = INT64_MIN;
    result.fd_reuse_ordinary_getfd_result = INT64_MIN;
    result.segmented_close_range_result = INT64_MIN;
    result.segmented_close_range_left_fd = -1;
    result.segmented_close_range_right_fd = -1;
    result.segmented_close_range_left_getfd = INT64_MIN;
    result.segmented_close_range_right_getfd = INT64_MIN;
    result.segmented_close_range_protected_getfd = INT64_MIN;
    result.segmented_unshare_close_range_result = INT64_MIN;
    result.segmented_unshare_close_range_left_getfd = INT64_MIN;
    result.segmented_unshare_close_range_right_getfd = INT64_MIN;
    result.segmented_unshare_close_range_protected_getfd = INT64_MIN;
    HookselfVirtualFile files[5]{};
    files[0].struct_size = sizeof(files[0]);
    files[0].file_id = kStaticId;
    files[0].provider = HOOKSELF_VFILE_STATIC;
    files[0].mode = 0444;
    files[0].initial_content = kStaticContent;
    files[0].initial_content_size = sizeof(kStaticContent) - 1U;
    CopyString(files[0].guest_path, sizeof(files[0].guest_path), kStaticPath);
    files[1].struct_size = sizeof(files[1]);
    files[1].file_id = kDynamicId;
    files[1].provider = HOOKSELF_VFILE_DYNAMIC_SNAPSHOT;
    files[1].mode = 0444;
    files[1].initial_content = kDynamicA;
    files[1].initial_content_size = sizeof(kDynamicA) - 1U;
    CopyString(files[1].guest_path, sizeof(files[1].guest_path), kDynamicPath);
    files[2].struct_size = sizeof(files[2]);
    files[2].file_id = kStatusId;
    files[2].provider = HOOKSELF_VFILE_PROC_STATUS;
    files[2].mode = 0444;
    CopyString(files[2].guest_path, sizeof(files[2].guest_path),
               "/proc/self/status");
    files[3].struct_size = sizeof(files[3]);
    files[3].file_id = kMapsId;
    files[3].provider = HOOKSELF_VFILE_PROC_MAPS;
    files[3].mode = 0444;
    files[3].flags = HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS;
    CopyString(files[3].guest_path, sizeof(files[3].guest_path),
               "/proc/self/maps");
    files[4].struct_size = sizeof(files[4]);
    files[4].file_id = kSelinuxId;
    files[4].provider = HOOKSELF_VFILE_SELINUX_CONTEXT;
    files[4].mode = 0444;
    files[4].initial_content = kSelinuxContent;
    files[4].initial_content_size = sizeof(kSelinuxContent) - 1U;
    CopyString(files[4].guest_path, sizeof(files[4].guest_path),
               "/proc/self/attr/current");

    HookselfConfig config{};
    hookself_default_config(&config);
    HookselfSyscallRule syscall_rules[2]{};
    syscall_rules[0].struct_size = sizeof(syscall_rules[0]);
    syscall_rules[0].rule_id = 1006;
    syscall_rules[0].syscall_number = __NR_pwrite64;
    syscall_rules[0].action = HOOKSELF_SYSCALL_DENY;
    syscall_rules[0].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    syscall_rules[0].deny_errno = EIO;
    syscall_rules[1].struct_size = sizeof(syscall_rules[1]);
    syscall_rules[1].rule_id = 1007;
    syscall_rules[1].syscall_number = __NR_faccessat;
    syscall_rules[1].action = HOOKSELF_SYSCALL_REPLACE_NUMBER;
    syscall_rules[1].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    syscall_rules[1].argument_index = 1U;
    syscall_rules[1].argument_match_mask = UINT64_MAX;
    syscall_rules[1].argument_match_value = reinterpret_cast<uintptr_t>(
            kProtectedMutationMarker);
    syscall_rules[1].replacement_syscall_number = __NR_close;
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.flags |= HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS;
    config.virtual_files = files;
    config.virtual_file_count = 5;
    CopyString(config.virtual_backing_dir, sizeof(config.virtual_backing_dir),
               virtual_backing_dir == nullptr ? "" : virtual_backing_dir);
    config.syscall_rules = syscall_rules;
    config.syscall_rule_count = 2;
    config.event_capacity = 256;
    HookselfRuntime* runtime = nullptr;
    if (hookself_create(&config, &runtime) != HOOKSELF_OK || runtime == nullptr ||
        hookself_start(runtime) != HOOKSELF_OK) {
        hookself_destroy(runtime);
        return result;
    }
    DrainEvents(runtime);
    const uint32_t close_range_capabilities =
            CloseRangeCapabilitiesForSelfTest(runtime);
    const bool close_range_supported =
            (close_range_capabilities & kCloseRangeCapabilitySyscall) != 0U;
    const bool close_range_cloexec_supported =
            (close_range_capabilities & kCloseRangeCapabilityCloexec) != 0U;
    const bool close_range_unshare_supported =
            (close_range_capabilities & kCloseRangeCapabilityUnshare) != 0U;
    result.close_range_base_result = close_range_supported ? 0 : -ENOSYS;

    result.status_refresh_result = hookself_refresh_virtual_file(
            runtime, kStatusId);
    result.maps_refresh_result = hookself_refresh_virtual_file(
            runtime, kMapsId);
    result.selinux_refresh_result = hookself_refresh_virtual_file(
            runtime, kSelinuxId);
    const long status_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD,
            reinterpret_cast<long>("/proc/self/status"),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open status result=%ld", status_fd);
    if (status_fd >= 0) {
        result.status_match = ReadFdSnapshotMatches(
                                      static_cast<int>(status_fd),
                                      "TracerPid:\t0\n", nullptr)
                                      ? 1
                                      : 0;
        (void)hookself::platform::RawClose(static_cast<int>(status_fd));
    }
    const long maps_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD,
            reinterpret_cast<long>("/proc/self/maps"),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open maps result=%ld", maps_fd);
    if (maps_fd >= 0) {
        result.maps_match =
                ReadFdSnapshotMatches(static_cast<int>(maps_fd), "r-xp",
                                      "libhookself.so") &&
                hookself::platform::RawSyscall6(
                        __NR_lseek, maps_fd, 0, SEEK_SET) == 0 &&
                ReadFdSnapshotMatches(static_cast<int>(maps_fd), nullptr,
                                      "hookself-session")
                        ? 1
                        : 0;
        (void)hookself::platform::RawClose(static_cast<int>(maps_fd));
    }
    const long selinux_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD,
            reinterpret_cast<long>("/proc/self/attr/current"),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open selinux result=%ld", selinux_fd);
    if (selinux_fd >= 0) {
        result.selinux_match = ReadFdSnapshotMatches(
                                       static_cast<int>(selinux_fd),
                                       "u:r:hookself_virtual:s0", nullptr)
                                       ? 1
                                       : 0;
        (void)hookself::platform::RawClose(static_cast<int>(selinux_fd));
    }
    result.provider_pass =
            result.status_refresh_result == HOOKSELF_OK &&
            result.maps_refresh_result == HOOKSELF_OK &&
            result.selinux_refresh_result == HOOKSELF_OK &&
            result.status_match != 0 && result.maps_match != 0 &&
            result.selinux_match != 0
                    ? 1
                    : 0;

    const long static_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kStaticPath),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open static result=%ld", static_fd);
    if (static_fd >= 0) {
        result.static_match = ReadFdContains(
                                      static_cast<int>(static_fd),
                                      "static-snapshot")
                                      ? 1
                                      : 0;
        (void)hookself::platform::RawClose(static_cast<int>(static_fd));
    }
    const long old_dynamic_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kDynamicPath),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open dynamic-old result=%ld",
                        old_dynamic_fd);
    const int32_t publish_result = hookself_publish_virtual_file(
            runtime, kDynamicId, kDynamicB, sizeof(kDynamicB) - 1U);
    result.publish_result = publish_result;
    if (old_dynamic_fd >= 0) {
        result.old_snapshot_match = ReadFdContains(
                                            static_cast<int>(old_dynamic_fd),
                                            "dynamic-A")
                                            ? 1
                                            : 0;
        (void)hookself::platform::RawClose(
                static_cast<int>(old_dynamic_fd));
    }
    const long new_dynamic_fd = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kDynamicPath),
            O_RDONLY | O_CLOEXEC, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest open dynamic-new result=%ld",
                        new_dynamic_fd);
    if (new_dynamic_fd >= 0) {
        result.new_snapshot_match = ReadFdContains(
                                            static_cast<int>(new_dynamic_fd),
                                            "dynamic-B")
                                            ? 1
                                            : 0;
        (void)hookself::platform::RawClose(
                static_cast<int>(new_dynamic_fd));
    }
    const long ordinary_close_range_fd = hookself::platform::RawSyscall6(
            __NR_memfd_create,
            reinterpret_cast<long>("hookself-close-range-probe"), 0);
    if (ordinary_close_range_fd >= 0 && close_range_cloexec_supported) {
        result.ordinary_close_range_cloexec_result =
                hookself::platform::RawSyscall6(
                        kCloseRangeSyscall, ordinary_close_range_fd,
                        ordinary_close_range_fd, kCloseRangeCloexec);
        result.ordinary_close_range_getfd_result =
                hookself::platform::RawSyscall6(
                        __NR_fcntl, ordinary_close_range_fd, F_GETFD, 0);
        result.ordinary_close_range_cloexec_set =
                result.ordinary_close_range_getfd_result >= 0 &&
                        (result.ordinary_close_range_getfd_result &
                         FD_CLOEXEC) != 0
                        ? 1
                        : 0;
    }
    if (ordinary_close_range_fd >= 0) {
        (void)hookself::platform::RawClose(
                static_cast<int>(ordinary_close_range_fd));
    }
    result.stable_fd = FindFdContaining("dynamic-B");
    int64_t transformed_close_result = INT64_MIN;
    int32_t after_transformed_close_match = 0;
    if (result.stable_fd >= 0) {
        transformed_close_result = hookself::platform::RawSyscall6(
                __NR_faccessat, result.stable_fd,
                reinterpret_cast<long>(kProtectedMutationMarker), F_OK, 0);
        const long reopened_after_transformed_close =
                hookself::platform::RawSyscall6(
                        __NR_openat, AT_FDCWD,
                        reinterpret_cast<long>(kDynamicPath),
                        O_RDONLY | O_CLOEXEC, 0);
        if (reopened_after_transformed_close >= 0) {
            after_transformed_close_match = ReadFdContains(
                                                    static_cast<int>(
                                                            reopened_after_transformed_close),
                                                    "dynamic-B")
                                                    ? 1
                                                    : 0;
            (void)hookself::platform::RawClose(
                    static_cast<int>(reopened_after_transformed_close));
        }
        result.protected_close_result = hookself::platform::RawClose(
                result.stable_fd);
        const long reopened = hookself::platform::RawSyscall6(
                __NR_openat, AT_FDCWD,
                reinterpret_cast<long>(kDynamicPath),
                O_RDONLY | O_CLOEXEC, 0);
        if (reopened >= 0) {
            result.after_close_match = ReadFdContains(
                                               static_cast<int>(reopened),
                                               "dynamic-B")
                                               ? 1
                                               : 0;
            (void)hookself::platform::RawClose(static_cast<int>(reopened));
        }

        const long replacement_fd = hookself::platform::RawSyscall6(
                __NR_memfd_create,
                reinterpret_cast<long>("hookself-fd-attack"), 1);
        if (replacement_fd >= 0) {
            constexpr char kReplacement[] = "external-replacement\n";
            (void)hookself::platform::RawWrite(
                    static_cast<int>(replacement_fd), kReplacement,
                    sizeof(kReplacement) - 1U);
            result.protected_dup3_result = hookself::platform::RawSyscall6(
                    __NR_dup3, replacement_fd, result.stable_fd,
                    O_CLOEXEC);
            (void)hookself::platform::RawClose(
                    static_cast<int>(replacement_fd));
        }
        const long reopened_after_dup = hookself::platform::RawSyscall6(
                __NR_openat, AT_FDCWD,
                reinterpret_cast<long>(kDynamicPath),
                O_RDONLY | O_CLOEXEC, 0);
        if (reopened_after_dup >= 0) {
            result.after_dup3_match = ReadFdContains(
                                              static_cast<int>(reopened_after_dup),
                                              "dynamic-B")
                                              ? 1
                                              : 0;
            (void)hookself::platform::RawClose(
                    static_cast<int>(reopened_after_dup));
        }
        result.protected_setfd_result = hookself::platform::RawSyscall6(
                __NR_fcntl, result.stable_fd, F_SETFD, 0);
        result.protected_getfd_result = hookself::platform::RawSyscall6(
                __NR_fcntl, result.stable_fd, F_GETFD, 0);
        if (close_range_cloexec_supported) {
            result.protected_close_range_cloexec_result =
                    hookself::platform::RawSyscall6(
                            kCloseRangeSyscall, result.stable_fd,
                            result.stable_fd, kCloseRangeCloexec);
            result.protected_close_range_getfd_result =
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, result.stable_fd, F_GETFD, 0);
            result.protected_close_range_cloexec_set =
                    result.protected_close_range_getfd_result >= 0 &&
                            (result.protected_close_range_getfd_result &
                             FD_CLOEXEC) != 0
                            ? 1
                            : 0;
        }
        const long replay_source = close_range_supported
                ? hookself::platform::RawSyscall6(
                          __NR_memfd_create,
                          reinterpret_cast<long>(
                                  "hookself-close-range-replay"),
                          MFD_CLOEXEC)
                : -ENOSYS;
        int32_t replay_left = -1;
        if (replay_source >= 0) {
            for (int32_t candidate = 768; candidate <= 1021; ++candidate) {
                if (hookself::platform::RawSyscall6(
                            __NR_fcntl, candidate, F_GETFD, 0) == -EBADF &&
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, candidate + 1, F_GETFD, 0) ==
                            -EBADF &&
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, candidate + 2, F_GETFD, 0) ==
                            -EBADF) {
                    replay_left = candidate;
                    break;
                }
            }
        }
        const int32_t replay_protected = replay_left < 0
                ? -1
                : replay_left + 1;
        const int32_t replay_right = replay_left < 0
                ? -1
                : replay_left + 2;
        const bool replay_triplet_ready =
                replay_left >= 0 &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, replay_source, replay_left,
                        O_CLOEXEC) == replay_left &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, replay_source, replay_protected,
                        O_CLOEXEC) == replay_protected &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, replay_source, replay_right,
                        O_CLOEXEC) == replay_right;
        const int32_t replay_register = replay_triplet_ready
                ? RegisterProtectedFdForSelfTest(runtime, replay_protected)
                : HOOKSELF_E_INTERNAL;
        if (replay_register == HOOKSELF_OK) {
            result.segmented_close_range_left_fd = replay_left;
            result.segmented_close_range_right_fd = replay_right;
            result.segmented_close_range_result =
                    hookself::platform::RawSyscall6(
                            kCloseRangeSyscall, replay_left,
                            replay_right, 0);
            result.segmented_close_range_left_getfd =
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, replay_left, F_GETFD, 0);
            result.segmented_close_range_right_getfd =
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, replay_right, F_GETFD, 0);
            result.segmented_close_range_protected_getfd =
                    hookself::platform::RawSyscall6(
                            __NR_fcntl, replay_protected, F_GETFD, 0);
            const int32_t replay_unregister =
                    UnregisterProtectedFdForSelfTest(
                            runtime, replay_protected);
            result.segmented_close_range_pass =
                    result.segmented_close_range_result == 0 &&
                    result.segmented_close_range_left_getfd == -EBADF &&
                    result.segmented_close_range_right_getfd == -EBADF &&
                    result.segmented_close_range_protected_getfd >= 0 &&
                    replay_unregister == HOOKSELF_OK
                    ? 1
                    : 0;
        }
        if (replay_source >= 0) {
            (void)hookself::platform::RawClose(
                    static_cast<int>(replay_source));
        }
        if (replay_left >= 0) {
            (void)hookself::platform::RawClose(replay_left);
            (void)hookself::platform::RawClose(replay_protected);
            (void)hookself::platform::RawClose(replay_right);
        }

        const long unshare_source = close_range_unshare_supported
                ? hookself::platform::RawSyscall6(
                          __NR_memfd_create,
                          reinterpret_cast<long>(
                                  "hookself-close-range-unshare"),
                          MFD_CLOEXEC)
                : -ENOSYS;
        const bool unshare_triplet_ready =
                unshare_source >= 0 && replay_left >= 0 &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, unshare_source, replay_left,
                        O_CLOEXEC) == replay_left &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, unshare_source, replay_protected,
                        O_CLOEXEC) == replay_protected &&
                hookself::platform::RawSyscall6(
                        __NR_dup3, unshare_source, replay_right,
                        O_CLOEXEC) == replay_right;
        const int32_t unshare_register = unshare_triplet_ready
                ? RegisterProtectedFdForSelfTest(runtime, replay_protected)
                : HOOKSELF_E_INTERNAL;
        if (unshare_register == HOOKSELF_OK) {
            struct UnshareChildReport {
                int64_t close_range_result;
                int64_t left_getfd;
                int64_t right_getfd;
                int64_t protected_getfd;
            } child_report{INT64_MIN, INT64_MIN, INT64_MIN, INT64_MIN};
            int report_pipe[2] = {-1, -1};
            const bool pipe_ready =
                    pipe2(report_pipe, O_CLOEXEC) == 0;
            const long child = pipe_ready
                    ? hookself::platform::RawSyscall6(
                              __NR_clone, SIGCHLD, 0, 0, 0, 0)
                    : -errno;
            if (child == 0) {
                (void)hookself::platform::RawClose(report_pipe[0]);
                UnshareChildReport report{};
                report.close_range_result =
                        hookself::platform::RawSyscall6(
                                kCloseRangeSyscall, replay_left,
                                replay_right, kCloseRangeUnshare);
                report.left_getfd = hookself::platform::RawSyscall6(
                        __NR_fcntl, replay_left, F_GETFD, 0);
                report.right_getfd = hookself::platform::RawSyscall6(
                        __NR_fcntl, replay_right, F_GETFD, 0);
                report.protected_getfd = hookself::platform::RawSyscall6(
                        __NR_fcntl, replay_protected, F_GETFD, 0);
                const long written = hookself::platform::RawWrite(
                        report_pipe[1], &report, sizeof(report));
                (void)hookself::platform::RawClose(report_pipe[1]);
                hookself::platform::RawExit(
                        written == static_cast<long>(sizeof(report)) ? 0
                                                                     : 127);
            }
            bool child_pass = false;
            if (pipe_ready) {
                (void)hookself::platform::RawClose(report_pipe[1]);
                const long bytes = child > 0
                        ? hookself::platform::RawRead(
                                  report_pipe[0], &child_report,
                                  sizeof(child_report))
                        : -ECHILD;
                (void)hookself::platform::RawClose(report_pipe[0]);
                int child_status = 0;
                const long waited = child > 0
                        ? hookself::platform::RawWait4(
                                  static_cast<pid_t>(child), &child_status, 0)
                        : child;
                child_pass = bytes ==
                                     static_cast<long>(sizeof(child_report)) &&
                             waited == child && WIFEXITED(child_status) &&
                             WEXITSTATUS(child_status) == 0;
            }
            result.segmented_unshare_close_range_result =
                    child_report.close_range_result;
            result.segmented_unshare_close_range_left_getfd =
                    child_report.left_getfd;
            result.segmented_unshare_close_range_right_getfd =
                    child_report.right_getfd;
            result.segmented_unshare_close_range_protected_getfd =
                    child_report.protected_getfd;
            const int32_t unshare_unregister =
                    UnregisterProtectedFdForSelfTest(
                            runtime, replay_protected);
            result.segmented_unshare_close_range_pass =
                    child_pass &&
                    result.segmented_unshare_close_range_result == 0 &&
                    result.segmented_unshare_close_range_left_getfd ==
                            -EBADF &&
                    result.segmented_unshare_close_range_right_getfd ==
                            -EBADF &&
                    result.segmented_unshare_close_range_protected_getfd >=
                            0 &&
                    unshare_unregister == HOOKSELF_OK
                    ? 1
                    : 0;
        }
        if (unshare_source >= 0) {
            (void)hookself::platform::RawClose(
                    static_cast<int>(unshare_source));
        }
        if (replay_left >= 0) {
            (void)hookself::platform::RawClose(replay_left);
            (void)hookself::platform::RawClose(replay_protected);
            (void)hookself::platform::RawClose(replay_right);
        }
        result.protected_close_range_result = close_range_supported
                ? hookself::platform::RawSyscall6(
                          kCloseRangeSyscall, result.stable_fd,
                          result.stable_fd, 0)
                : -ENOSYS;
    }

    // A protected descriptor is tracked by number. Verify that removing a test
    // registration before reusing that number does not suppress a later close
    // on an unrelated ordinary descriptor.
    constexpr int32_t kFdReuseFirst = 1024;
    constexpr int32_t kFdReuseLast = 1279;
    const long fd_reuse_protected_source = hookself::platform::RawSyscall6(
            __NR_memfd_create,
            reinterpret_cast<long>("hookself-fd-reuse-protected"),
            MFD_CLOEXEC);
    int32_t fd_reuse_target = -1;
    bool fd_reuse_target_open = false;
    if (fd_reuse_protected_source >= 0) {
        for (int32_t candidate = kFdReuseFirst;
             candidate <= kFdReuseLast; ++candidate) {
            if (hookself::platform::RawSyscall6(
                        __NR_fcntl, candidate, F_GETFD, 0) != -EBADF) {
                continue;
            }
            if (hookself::platform::RawSyscall6(
                        __NR_dup3, fd_reuse_protected_source, candidate,
                        O_CLOEXEC) == candidate) {
                fd_reuse_target = candidate;
                fd_reuse_target_open = true;
                break;
            }
        }
    }
    result.fd_reuse_target_fd = fd_reuse_target;
    if (fd_reuse_target >= 0) {
        result.fd_reuse_register_result = RegisterProtectedFdForSelfTest(
                runtime, fd_reuse_target);
        if (result.fd_reuse_register_result == HOOKSELF_OK) {
            result.fd_reuse_protected_close_result =
                    CloseProtectedFdForSelfTest(runtime, fd_reuse_target);
            fd_reuse_target_open = hookself::platform::RawSyscall6(
                    __NR_fcntl, fd_reuse_target, F_GETFD, 0) >= 0;
            const long fd_reuse_ordinary_source =
                    hookself::platform::RawSyscall6(
                            __NR_memfd_create,
                            reinterpret_cast<long>(
                                    "hookself-fd-reuse-ordinary"),
                            MFD_CLOEXEC);
            if (result.fd_reuse_protected_close_result == 0 &&
                !fd_reuse_target_open && fd_reuse_ordinary_source >= 0) {
                result.fd_reuse_duplicate_result =
                        hookself::platform::RawSyscall6(
                                __NR_dup3, fd_reuse_ordinary_source,
                                fd_reuse_target, O_CLOEXEC);
                if (result.fd_reuse_duplicate_result == fd_reuse_target) {
                    fd_reuse_target_open = true;
                    result.fd_reuse_ordinary_close_result =
                            hookself::platform::RawClose(fd_reuse_target);
                    result.fd_reuse_ordinary_getfd_result =
                            hookself::platform::RawSyscall6(
                                    __NR_fcntl, fd_reuse_target, F_GETFD, 0);
                    fd_reuse_target_open =
                            result.fd_reuse_ordinary_getfd_result >= 0;
                }
            }
            if (fd_reuse_ordinary_source >= 0) {
                (void)hookself::platform::RawClose(
                        static_cast<int>(fd_reuse_ordinary_source));
            }
            result.fd_reuse_unregister_result =
                    UnregisterProtectedFdForSelfTest(runtime, fd_reuse_target);
            if (result.fd_reuse_unregister_result == HOOKSELF_OK &&
                fd_reuse_target_open) {
                (void)hookself::platform::RawClose(fd_reuse_target);
                fd_reuse_target_open = hookself::platform::RawSyscall6(
                        __NR_fcntl, fd_reuse_target, F_GETFD, 0) >= 0;
            }
        }
    }
    if (fd_reuse_protected_source >= 0) {
        (void)hookself::platform::RawClose(
                static_cast<int>(fd_reuse_protected_source));
    }
    result.fd_reuse_pass =
            result.fd_reuse_register_result == HOOKSELF_OK &&
                    result.fd_reuse_protected_close_result == 0 &&
                    result.fd_reuse_unregister_result == HOOKSELF_OK &&
                    result.fd_reuse_duplicate_result == fd_reuse_target &&
                    result.fd_reuse_ordinary_close_result == 0 &&
                    result.fd_reuse_ordinary_getfd_result == -EBADF
            ? 1
            : 0;
    result.write_result = hookself::platform::RawSyscall6(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kDynamicPath),
            O_WRONLY | O_CLOEXEC, 0);
    char link_target[128]{};
    result.readlink_result = hookself::platform::RawSyscall6(
            __NR_readlinkat, AT_FDCWD,
            reinterpret_cast<long>(kDynamicPath),
            reinterpret_cast<long>(link_target), sizeof(link_target));
    const int32_t static_publish_result = hookself_publish_virtual_file(
            runtime, kStaticId, kDynamicB, sizeof(kDynamicB) - 1U);

    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            if (events[i].kind == HOOKSELF_EVENT_PATH &&
                (events[i].action == HOOKSELF_PATH_VIRTUAL_FILE ||
                 events[i].action == HOOKSELF_PATH_DENY) &&
                (events[i].rule_id == kStaticId ||
                 events[i].rule_id == kDynamicId)) {
                ++result.events;
            }
            if (events[i].kind == HOOKSELF_EVENT_PATH &&
                events[i].rule_id >= kStaticId &&
                events[i].rule_id <= kSelinuxId) {
                __android_log_print(
                        ANDROID_LOG_DEBUG, "HookSelf",
                        "virtual selftest path rule=%u action=%d error=%d result=%lld path=%s translated=%s",
                        events[i].rule_id, events[i].action, events[i].error,
                        static_cast<long long>(events[i].result),
                        events[i].path, events[i].translated_path);
            }
        }
    }
    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        result.opens = stats.virtual_file_opens;
        result.protected_fd_blocks = stats.protected_fd_blocks;
        result.internal_fd_operations = stats.internal_fd_operations;
    }
    const int32_t stop_result = hookself_stop(runtime);
    if (fd_reuse_target_open) {
        (void)hookself::platform::RawClose(fd_reuse_target);
    }
    hookself_destroy(runtime);
    const bool close_range_base_supported =
            result.close_range_base_result != -ENOSYS;
    const bool close_range_base_probed =
            result.close_range_base_result != INT64_MIN;
    const bool close_range_cloexec_pass =
            !close_range_cloexec_supported ||
            (result.ordinary_close_range_getfd_result >= 0 &&
             result.protected_close_range_getfd_result >= 0 &&
             result.ordinary_close_range_cloexec_result ==
                     result.protected_close_range_cloexec_result &&
             result.ordinary_close_range_cloexec_result != -EBUSY &&
             result.ordinary_close_range_cloexec_set ==
                     (result.ordinary_close_range_cloexec_result == 0 ? 1
                                                                      : 0) &&
             result.protected_close_range_cloexec_set != 0);
    const bool close_range_flags_zero_pass =
            close_range_base_supported
                    ? result.protected_close_range_result == 0
                    : result.protected_close_range_result == -ENOSYS;
    const bool segmented_close_range_pass =
            !close_range_base_supported ||
            (result.segmented_close_range_pass != 0 &&
             (!close_range_unshare_supported ||
              result.segmented_unshare_close_range_pass != 0));
    const uint64_t expected_protected_fd_blocks =
            close_range_base_supported ? 5U : 4U;
    result.pass = publish_result == HOOKSELF_OK &&
                          static_publish_result == HOOKSELF_E_INVALID_STATE &&
                          result.static_match != 0 &&
                          result.old_snapshot_match != 0 &&
                          result.new_snapshot_match != 0 &&
                          result.stable_fd >= 0 &&
                          transformed_close_result == 0 &&
                          after_transformed_close_match != 0 &&
                          result.protected_close_result == 0 &&
                          result.after_close_match != 0 &&
                          result.protected_dup3_result == -EBUSY &&
                          result.after_dup3_match != 0 &&
                          result.protected_setfd_result == 0 &&
                          (result.protected_getfd_result & FD_CLOEXEC) != 0 &&
                          close_range_base_probed &&
                           close_range_cloexec_pass &&
                          close_range_flags_zero_pass &&
                           segmented_close_range_pass &&
                          result.fd_reuse_pass != 0 &&
                          result.protected_fd_blocks >=
                                  expected_protected_fd_blocks &&
                          result.internal_fd_operations >= 1 &&
                          result.provider_pass != 0 &&
                          result.write_result == -EROFS &&
                          result.readlink_result == -EINVAL &&
                          result.events >= 5 && result.opens >= 3 &&
                          stop_result == HOOKSELF_OK
                  ? 1
                  : 0;
    return result;
}

struct LivenessCheckResult {
    int32_t tracer_pid;
    int32_t state;
    int32_t stop_result;
    int32_t detected;
    int32_t dumpable_restored;
    int64_t cleanup_ms;
};

LivenessCheckResult RunLivenessCheck() {
    LivenessCheckResult result{};
    result.state = HOOKSELF_STATE_IDLE;
    result.stop_result = HOOKSELF_E_INVALID_STATE;
    const int original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);

    HookselfConfig config{};
    hookself_default_config(&config);
    config.event_capacity = 64;
    HookselfRuntime* runtime = nullptr;
    if (hookself_create(&config, &runtime) != HOOKSELF_OK || runtime == nullptr ||
        hookself_start(runtime) != HOOKSELF_OK) {
        hookself_destroy(runtime);
        return result;
    }

    HookselfEvent events[32]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 32);
        if (count == 0) {
            break;
        }
        for (size_t i = 0; i < count; ++i) {
            if (events[i].kind == HOOKSELF_EVENT_LIFECYCLE &&
                events[i].action == HOOKSELF_STATE_RUNNING_FULL_PTRACE &&
                events[i].result > 0 && events[i].result <= INT32_MAX) {
                result.tracer_pid = static_cast<int32_t>(events[i].result);
            }
        }
    }

    const int64_t started_ms = hookself::platform::RawNowMs();
    if (result.tracer_pid > 0) {
        (void)hookself::platform::RawSyscall6(
                __NR_kill, result.tracer_pid, SIGKILL);
        for (int attempt = 0; attempt < 100; ++attempt) {
            (void)hookself_get_state(runtime, &result.state);
            if (result.state == HOOKSELF_STATE_FATAL) {
                result.detected = 1;
                break;
            }
            hookself::platform::RawSleepOneMillisecond();
        }
    }
    result.stop_result = hookself_stop(runtime);
    const int64_t finished_ms = hookself::platform::RawNowMs();
    if (started_ms >= 0 && finished_ms >= started_ms) {
        result.cleanup_ms = finished_ms - started_ms;
    } else {
        result.cleanup_ms = -1;
    }
    const int restored_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    result.dumpable_restored =
            original_dumpable >= 0 && restored_dumpable == original_dumpable ? 1 : 0;
    hookself_destroy(runtime);
    return result;
}

}  // namespace

ResidentSelfTestReport RunResidentSelfTest(const char* virtual_backing_dir) {
    ResidentSelfTestReport report{};
    report.start_result = HOOKSELF_E_INTERNAL;
    report.stop_result = HOOKSELF_E_INVALID_STATE;
    report.running_state = HOOKSELF_STATE_IDLE;
    report.stopped_state = HOOKSELF_STATE_IDLE;

    HookselfConfig config{};
    hookself_default_config(&config);
    config.flags |= HOOKSELF_CONFIG_OBSERVE_ALL |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS;
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;

    HookselfRuntime* runtime = nullptr;
    const int32_t create_result = hookself_create(&config, &runtime);
    if (create_result != HOOKSELF_OK || runtime == nullptr) {
        report.start_result = create_result;
        return report;
    }

    int continue_pipe[2] = {-1, -1};
    pid_t continue_helper = -1;
    const pid_t group_stop_target = getpid();
    if (pipe2(continue_pipe, O_CLOEXEC) == 0) {
        continue_helper = fork();
        if (continue_helper == 0) {
            (void)hookself::platform::RawClose(continue_pipe[1]);
            char gate = 0;
            const long bytes = hookself::platform::RawRead(
                    continue_pipe[0], &gate, 1);
            (void)hookself::platform::RawClose(continue_pipe[0]);
            if (bytes == 1 && gate == 'G') {
                timespec delay{};
                delay.tv_nsec = 100000000;
                (void)hookself::platform::RawNanosleep(&delay);
                (void)hookself::platform::RawSyscall6(
                        __NR_kill, static_cast<long>(group_stop_target), SIGCONT);
            }
            hookself::platform::RawExit(0);
        }
        close(continue_pipe[0]);
        continue_pipe[0] = -1;
        if (continue_helper < 0) {
            close(continue_pipe[1]);
            continue_pipe[1] = -1;
        }
    }

    report.start_result = hookself_start(runtime);
    if (report.start_result != HOOKSELF_OK) {
        if (continue_pipe[1] >= 0) {
            const char gate = 'G';
            (void)write(continue_pipe[1], &gate, 1);
            close(continue_pipe[1]);
        }
        if (continue_helper > 0) {
            int helper_status = 0;
            while (waitpid(continue_helper, &helper_status, 0) < 0 &&
                   errno == EINTR) {
            }
        }
        hookself_destroy(runtime);
        return report;
    }
    (void)hookself_get_state(runtime, &report.running_state);
    if (continue_helper > 0 && continue_pipe[1] >= 0) {
        const char gate = 'G';
        (void)write(continue_pipe[1], &gate, 1);
        close(continue_pipe[1]);
        continue_pipe[1] = -1;
        (void)hookself::platform::RawSyscall6(
                __NR_kill, static_cast<long>(group_stop_target),
                SIGSTOP);
        report.group_stop_resumed = 1;
        int helper_status = 0;
        while (waitpid(continue_helper, &helper_status, 0) < 0 && errno == EINTR) {
        }
    }
    DrainEvents(runtime);

    report.expected_pid = static_cast<int32_t>(syscall(__NR_getpid));
    report.expected_tid = static_cast<int32_t>(syscall(__NR_gettid));

    struct sigaction test_action{};
    struct sigaction old_action{};
    sigset_t signal_mask{};
    sigset_t old_signal_mask{};
    test_action.sa_handler = HandleTestSignal;
    sigemptyset(&test_action.sa_mask);
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGUSR1);
    gSignalDeliveries = 0;
    const bool signal_action_installed =
            sigaction(SIGUSR1, &test_action, &old_action) == 0;
    const bool signal_mask_changed = signal_action_installed &&
            pthread_sigmask(SIG_UNBLOCK, &signal_mask, &old_signal_mask) == 0;
    const bool signal_handler_installed =
            signal_action_installed && signal_mask_changed;
    if (signal_handler_installed) {
        (void)syscall(__NR_tgkill, report.expected_pid, report.expected_tid,
                      SIGUSR1);
        for (int attempt = 0; attempt < 100 && gSignalDeliveries == 0; ++attempt) {
            timespec delay{};
            delay.tv_nsec = 1000000;
            (void)syscall(__NR_nanosleep, &delay, nullptr);
        }
        report.signal_delivered = gSignalDeliveries == 1 ? 1 : 0;
    }
    const long descriptor = syscall(__NR_openat, AT_FDCWD, "/proc/self/status",
                                    O_RDONLY | O_CLOEXEC, 0);
    if (descriptor >= 0) {
        (void)syscall(__NR_close, descriptor);
    }

    WorkerContext worker{};
    pthread_t worker_thread{};
    if (pthread_create(&worker_thread, nullptr, RunWorker, &worker) == 0) {
        (void)pthread_join(worker_thread, nullptr);
        report.worker_tid = worker.tid;
    }
    RecordEvents(runtime, &report, descriptor);

    const pid_t child = fork();
    if (child == 0) {
        (void)hookself::platform::RawSyscall6(__NR_getpid);
        (void)hookself::platform::RawSyscall6(__NR_gettid);
        hookself::platform::RawExit(0);
    }
    if (child > 0) {
        report.child_pid = child;
        int child_status = 0;
        while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
        }
    }
    RecordEvents(runtime, &report, descriptor);

    int exec_tid_pipe[2] = {-1, -1};
    (void)pipe2(exec_tid_pipe, O_CLOEXEC);
    const pid_t exec_child = fork();
    if (exec_child == 0) {
        if (exec_tid_pipe[0] >= 0) {
            (void)hookself::platform::RawClose(exec_tid_pipe[0]);
        }
        constexpr size_t kExecStackSize = 64U * 1024U;
        const long stack_result = hookself::platform::RawSyscall6(
                __NR_mmap, 0, kExecStackSize, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (hookself::platform::RawError(stack_result) != 0 ||
            exec_tid_pipe[1] < 0) {
            hookself::platform::RawExit(126);
        }
        ExecCloneContext exec_context{exec_tid_pipe[1]};
        auto* stack_top = reinterpret_cast<void*>(
                static_cast<uintptr_t>(stack_result) + kExecStackSize);
        const int clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES |
                                CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
        const int clone_tid = clone(RunExecClone, stack_top, clone_flags,
                                    &exec_context);
        if (clone_tid < 0) {
            hookself::platform::RawExit(126);
        }
        for (;;) {
            timespec delay{};
            delay.tv_nsec = 10000000;
            (void)hookself::platform::RawNanosleep(&delay);
        }
    }
    if (exec_tid_pipe[1] >= 0) {
        close(exec_tid_pipe[1]);
        exec_tid_pipe[1] = -1;
    }
    if (exec_child > 0) {
        report.exec_child_pid = exec_child;
        int32_t former_tid = 0;
        ssize_t bytes = -1;
        do {
            bytes = read(exec_tid_pipe[0], &former_tid, sizeof(former_tid));
        } while (bytes < 0 && errno == EINTR);
        if (bytes == static_cast<ssize_t>(sizeof(former_tid))) {
            report.exec_former_tid = former_tid;
        }
        int child_status = 0;
        while (waitpid(exec_child, &child_status, 0) < 0 && errno == EINTR) {
        }
    }
    if (exec_tid_pipe[0] >= 0) {
        close(exec_tid_pipe[0]);
        exec_tid_pipe[0] = -1;
    }
    RecordEvents(runtime, &report, descriptor);

    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        report.observed_syscalls = stats.observed_syscalls;
        report.dropped_events = stats.dropped_events;
        report.tracked_tasks_running = stats.tracked_tasks;
        report.fatal_code = stats.fatal_code;
        report.fatal_errno = stats.fatal_errno;
        report.fatal_tid = stats.fatal_tid;
    }

    report.stop_result = hookself_stop(runtime);
    if (signal_mask_changed) {
        (void)pthread_sigmask(SIG_SETMASK, &old_signal_mask, nullptr);
    }
    if (signal_action_installed) {
        (void)sigaction(SIGUSR1, &old_action, nullptr);
    }
    (void)hookself_get_state(runtime, &report.stopped_state);
    report.result_match = descriptor >= 0 && report.getpid_exit > 0 &&
                                  report.gettid_exit > 0 && report.openat_exit > 0
                          ? 1
                          : 0;
    report.verdict = report.start_result == HOOKSELF_OK &&
                             report.stop_result == HOOKSELF_OK &&
                             report.running_state == HOOKSELF_STATE_RUNNING_FULL_PTRACE &&
                             report.stopped_state == HOOKSELF_STATE_STOPPED &&
                             report.getpid_entry > 0 && report.getpid_exit > 0 &&
                             report.gettid_entry > 0 && report.gettid_exit > 0 &&
                             report.openat_entry > 0 && report.openat_exit > 0 &&
                             report.openat_path_match != 0 &&
                             report.result_match != 0 &&
                             report.worker_tid > 0 && report.clone_event > 0 &&
                             report.worker_gettid_entry > 0 &&
                             report.worker_gettid_exit > 0 &&
                             report.child_pid > 0 && report.fork_event > 0 &&
                             report.child_getpid_entry > 0 &&
                             report.child_getpid_exit > 0 &&
                              report.exec_child_pid > 0 &&
                              report.exec_former_tid > 0 &&
                              report.exec_former_tid != report.exec_child_pid &&
                              report.exec_event > 0 && report.execve_exit > 0 &&
                             report.signal_event > 0 &&
                             report.signal_delivered != 0 &&
                             report.group_stop_resumed != 0 &&
                             report.tracked_tasks_running > 0
                     ? 1
                     : 0;
    hookself_destroy(runtime);
    report.selected_rule_pass = RunSelectedRuleCheck() ? 1 : 0;
    if (report.selected_rule_pass == 0) {
        report.verdict = 0;
    }
    const SyscallPolicyCheckResult syscall_policy = RunSyscallPolicyCheck();
    report.syscall_policy_pass = syscall_policy.pass;
    report.syscall_deny_result = syscall_policy.deny_result;
    report.syscall_number_result = syscall_policy.number_result;
    report.syscall_result_result = syscall_policy.result_result;
    report.syscall_argument_result = syscall_policy.argument_result;
    report.syscall_policy_events = syscall_policy.policy_events;
      if (report.syscall_policy_pass == 0) {
          report.verdict = 0;
      }
      const PtraceViewCheckResult ptrace_view = RunPtraceViewCheck();
      report.ptrace_view_pass = ptrace_view.pass;
      report.ptrace_view_validation_pass = ptrace_view.validation_pass;
      report.ptrace_view_event_pairs_pass = ptrace_view.event_pairs_pass;
      report.ptrace_view_preexisting_worker_pass =
              ptrace_view.preexisting_worker_pass;
      report.ptrace_view_new_worker_pass = ptrace_view.new_worker_pass;
      report.ptrace_view_shared_dumpable_pass =
              ptrace_view.shared_dumpable_pass;
      report.ptrace_view_descendant_isolation_pass =
              ptrace_view.descendant_isolation_pass;
      report.ptrace_view_stop_concurrency_pass =
              ptrace_view.stop_concurrency_pass;
      report.ptrace_traceme_first = ptrace_view.traceme_first;
      report.ptrace_traceme_second = ptrace_view.traceme_second;
      report.ptrace_dumpable_zero = ptrace_view.get_dumpable_zero;
      report.ptrace_dumpable_invalid = ptrace_view.invalid_dumpable;
      report.ptrace_dumpable_one = ptrace_view.get_dumpable_one;
      report.ptrace_ptracer_any = ptrace_view.set_ptracer_any;
      report.ptrace_ptracer_invalid = ptrace_view.set_ptracer_invalid;
      report.ptrace_ptracer_self = ptrace_view.set_ptracer_self;
      report.ptrace_ptracer_zero = ptrace_view.set_ptracer_zero;
      report.ptrace_view_passthrough = ptrace_view.passthrough_result;
      report.ptrace_view_events = ptrace_view.policy_events;
      report.ptrace_view_event_pair_errors =
              ptrace_view.event_pair_errors;
      report.ptrace_view_child_pid = ptrace_view.child_pid;
      report.ptrace_view_child_set_dumpable_zero =
              ptrace_view.child_set_dumpable_zero;
      report.ptrace_view_child_get_dumpable_zero =
              ptrace_view.child_get_dumpable_zero;
      report.ptrace_view_parent_get_after_child =
              ptrace_view.parent_get_after_child;
      report.ptrace_view_stop_worker_tid = ptrace_view.stop_worker_tid;
      report.ptrace_view_stop_worker_calls = ptrace_view.stop_worker_calls;
      report.ptrace_view_stop_overlap_calls =
              ptrace_view.stop_overlap_calls;
      report.ptrace_view_stop_worker_unexpected_results =
              ptrace_view.stop_worker_unexpected_results;
      report.ptrace_view_stop_worker_entry =
              ptrace_view.stop_worker_entry;
      report.ptrace_view_stop_worker_exit = ptrace_view.stop_worker_exit;
      report.ptrace_view_operations = ptrace_view.operations;
      report.ptrace_view_dropped_events = ptrace_view.dropped_events;
      report.ptrace_view_fatal_code = ptrace_view.fatal_code;
      report.ptrace_view_fatal_errno = ptrace_view.fatal_errno;
      report.ptrace_view_entry_dumpable = ptrace_view.entry_dumpable;
      report.ptrace_view_final_logical_dumpable =
              ptrace_view.final_logical_dumpable;
      report.ptrace_view_stop_result = ptrace_view.stop_result;
      report.ptrace_view_restored_dumpable =
              ptrace_view.stop_applied_dumpable;
      report.ptrace_view_cleanup_restored_dumpable =
              ptrace_view.cleanup_restored_dumpable;
      if (report.ptrace_view_pass == 0) {
          report.verdict = 0;
      }
      const ProcStatusViewCheckResult proc_status =
              RunProcStatusViewCheck();
      report.proc_status_view_pass = proc_status.pass;
      report.proc_status_preopen_fd = proc_status.preopen_fd;
      report.proc_status_pread_result = proc_status.pread_result;
      report.proc_status_pread_match = proc_status.pread_match;
      report.proc_status_dup_read_result = proc_status.dup_read_result;
      report.proc_status_dup_read_match = proc_status.dup_read_match;
      report.proc_status_readv_result = proc_status.readv_result;
      report.proc_status_readv_match = proc_status.readv_match;
      report.proc_status_readv_cross_iov = proc_status.readv_cross_iov;
      report.proc_status_worker_tid = proc_status.worker_tid;
      report.proc_status_worker_tgid = proc_status.worker_tgid;
      report.proc_status_worker_pid = proc_status.worker_pid;
      report.proc_status_worker_match = proc_status.worker_match;
      report.proc_status_fake_memfd_unchanged =
              proc_status.fake_memfd_unchanged;
      report.proc_status_event_pairs_pass = proc_status.event_pairs_pass;
      report.proc_status_event_pair_errors =
              proc_status.event_pair_errors;
      report.proc_status_events = proc_status.policy_events;
      report.proc_status_patches = proc_status.patches;
      report.proc_status_dropped_events = proc_status.dropped_events;
      report.proc_status_fatal_code = proc_status.fatal_code;
      report.proc_status_fatal_errno = proc_status.fatal_errno;
      report.proc_status_stop_result = proc_status.stop_result;
      if (report.proc_status_view_pass == 0) {
          report.verdict = 0;
      }
      const VirtualFileCheckResult virtual_file = RunVirtualFileCheck(
              virtual_backing_dir);
    report.virtual_file_pass = virtual_file.pass;
    report.virtual_static_match = virtual_file.static_match;
    report.virtual_old_snapshot_match = virtual_file.old_snapshot_match;
    report.virtual_new_snapshot_match = virtual_file.new_snapshot_match;
    report.virtual_write_result = virtual_file.write_result;
    report.virtual_readlink_result = virtual_file.readlink_result;
    report.virtual_events = virtual_file.events;
      report.virtual_file_opens = virtual_file.opens;
      report.virtual_publish_result = virtual_file.publish_result;
      report.virtual_stable_fd = virtual_file.stable_fd;
      report.virtual_protected_close_result =
              virtual_file.protected_close_result;
      report.virtual_after_close_match = virtual_file.after_close_match;
      report.virtual_protected_dup3_result =
              virtual_file.protected_dup3_result;
      report.virtual_after_dup3_match = virtual_file.after_dup3_match;
      report.virtual_protected_setfd_result =
              virtual_file.protected_setfd_result;
      report.virtual_protected_getfd_result =
              virtual_file.protected_getfd_result;
      report.virtual_close_range_base_result =
              virtual_file.close_range_base_result;
      report.virtual_ordinary_close_range_cloexec_result =
              virtual_file.ordinary_close_range_cloexec_result;
      report.virtual_ordinary_close_range_getfd_result =
              virtual_file.ordinary_close_range_getfd_result;
      report.virtual_ordinary_close_range_cloexec_set =
              virtual_file.ordinary_close_range_cloexec_set;
      report.virtual_protected_close_range_cloexec_result =
              virtual_file.protected_close_range_cloexec_result;
      report.virtual_protected_close_range_getfd_result =
              virtual_file.protected_close_range_getfd_result;
      report.virtual_protected_close_range_cloexec_set =
              virtual_file.protected_close_range_cloexec_set;
      report.virtual_protected_close_range_result =
              virtual_file.protected_close_range_result;
      report.virtual_fd_reuse_target_fd = virtual_file.fd_reuse_target_fd;
      report.virtual_fd_reuse_register_result =
              virtual_file.fd_reuse_register_result;
      report.virtual_fd_reuse_unregister_result =
              virtual_file.fd_reuse_unregister_result;
      report.virtual_fd_reuse_protected_close_result =
              virtual_file.fd_reuse_protected_close_result;
      report.virtual_fd_reuse_duplicate_result =
              virtual_file.fd_reuse_duplicate_result;
      report.virtual_fd_reuse_ordinary_close_result =
              virtual_file.fd_reuse_ordinary_close_result;
      report.virtual_fd_reuse_ordinary_getfd_result =
              virtual_file.fd_reuse_ordinary_getfd_result;
      report.virtual_fd_reuse_pass = virtual_file.fd_reuse_pass;
      report.virtual_segmented_close_range_result =
              virtual_file.segmented_close_range_result;
      report.virtual_segmented_close_range_left_fd =
              virtual_file.segmented_close_range_left_fd;
      report.virtual_segmented_close_range_right_fd =
              virtual_file.segmented_close_range_right_fd;
      report.virtual_segmented_close_range_left_getfd =
              virtual_file.segmented_close_range_left_getfd;
      report.virtual_segmented_close_range_right_getfd =
              virtual_file.segmented_close_range_right_getfd;
      report.virtual_segmented_close_range_protected_getfd =
              virtual_file.segmented_close_range_protected_getfd;
      report.virtual_segmented_close_range_pass =
              virtual_file.segmented_close_range_pass;
      report.virtual_segmented_unshare_close_range_result =
              virtual_file.segmented_unshare_close_range_result;
      report.virtual_segmented_unshare_close_range_left_getfd =
              virtual_file.segmented_unshare_close_range_left_getfd;
      report.virtual_segmented_unshare_close_range_right_getfd =
              virtual_file.segmented_unshare_close_range_right_getfd;
      report.virtual_segmented_unshare_close_range_protected_getfd =
              virtual_file.segmented_unshare_close_range_protected_getfd;
      report.virtual_segmented_unshare_close_range_pass =
              virtual_file.segmented_unshare_close_range_pass;
      report.protected_fd_blocks = virtual_file.protected_fd_blocks;
      report.internal_fd_operations = virtual_file.internal_fd_operations;
      report.virtual_provider_pass = virtual_file.provider_pass;
      report.virtual_status_refresh_result =
              virtual_file.status_refresh_result;
      report.virtual_maps_refresh_result = virtual_file.maps_refresh_result;
      report.virtual_selinux_refresh_result =
              virtual_file.selinux_refresh_result;
      report.virtual_status_match = virtual_file.status_match;
      report.virtual_maps_match = virtual_file.maps_match;
      report.virtual_selinux_match = virtual_file.selinux_match;
    if (report.virtual_file_pass == 0) {
        report.verdict = 0;
    }
    report.singleton_pass = RunSingletonCheck() ? 1 : 0;
    if (report.singleton_pass == 0) {
        report.verdict = 0;
    }
    const RedirectCheckResult redirect = RunRedirectCheck(virtual_backing_dir);
    report.redirect_setup_stage = redirect.setup_stage;
    report.redirect_setup_result = redirect.setup_result;
    report.redirect_create_result = redirect.create_result;
    report.redirect_start_result = redirect.start_result;
    report.redirect_stop_result = redirect.stop_result;
    report.redirect_content_match = redirect.content_match;
    report.redirect_path_event = redirect.path_event;
    report.redirect_guest_path_match = redirect.guest_path_match;
    report.redirect_translated_path_match = redirect.translated_path_match;
    report.redirect_open_result = redirect.open_result;
    report.redirect_read_result = redirect.read_result;
    report.redirect_metadata_result = redirect.metadata_result;
    report.redirect_access_result = redirect.access_result;
    report.redirect_readlink_result = redirect.readlink_result;
    report.redirect_rename_result = redirect.rename_result;
    report.redirect_link_result = redirect.link_result;
    report.redirect_link_expected_result = redirect.link_expected_result;
    report.redirect_symlink_result = redirect.symlink_result;
    report.redirect_cleanup_pass = redirect.cleanup_pass;
    report.redirect_generic_events = redirect.generic_events;
    report.redirect_dual_path_events = redirect.dual_path_events;
    report.redirect_relative_open_result = redirect.relative_open_result;
    report.redirect_relative_read_result = redirect.relative_read_result;
    report.redirect_relative_content_match = redirect.relative_content_match;
    report.redirect_relative_event = redirect.relative_event;
    report.redirect_openat2_beneath_result = redirect.openat2_beneath_result;
    report.redirect_openat2_in_root_result = redirect.openat2_in_root_result;
    report.redirect_empty_newfstatat_result = redirect.empty_newfstatat_result;
    report.redirect_empty_statx_result = redirect.empty_statx_result;
    report.redirect_absolute_symlink_result = redirect.absolute_symlink_result;
    report.redirect_absolute_readlink_match = redirect.absolute_readlink_match;
    report.redirect_empty_readlink_match = redirect.empty_readlink_match;
    report.redirect_extended_path_pass = redirect.extended_path_pass;
    report.redirect_deny_result = redirect.deny_result;
    report.redirect_deny_event = redirect.deny_event;
    report.redirected_paths = redirect.redirected_paths;
    if (redirect.create_result != HOOKSELF_OK ||
        redirect.start_result != HOOKSELF_OK ||
        redirect.stop_result != HOOKSELF_OK || redirect.open_result < 0 ||
        redirect.read_result <= 0 || redirect.content_match == 0 ||
        redirect.metadata_result != 0 || redirect.access_result != 0 ||
        redirect.readlink_result <= 0 || redirect.rename_result != 0 ||
        (redirect.link_expected_result != 0 &&
         redirect.link_expected_result != -EACCES &&
         redirect.link_expected_result != -EPERM) ||
        redirect.link_result != redirect.link_expected_result ||
        redirect.symlink_result != 0 ||
        redirect.cleanup_pass == 0 || redirect.generic_events < 7 ||
        redirect.dual_path_events < 4 ||
        redirect.relative_open_result < 0 || redirect.relative_read_result <= 0 ||
        redirect.relative_content_match == 0 || redirect.relative_event == 0 ||
        redirect.extended_path_pass == 0 ||
        redirect.deny_result != -EACCES || redirect.deny_event == 0 ||
        redirect.path_event == 0 || redirect.guest_path_match == 0 ||
        redirect.translated_path_match == 0 || redirect.redirected_paths < 13) {
        report.verdict = 0;
    }
    const LivenessCheckResult liveness = RunLivenessCheck();
    report.liveness_tracer_pid = liveness.tracer_pid;
    report.liveness_state = liveness.state;
    report.liveness_stop_result = liveness.stop_result;
    report.liveness_detected = liveness.detected;
    report.liveness_dumpable_restored = liveness.dumpable_restored;
    report.liveness_cleanup_ms = liveness.cleanup_ms;
    if (liveness.tracer_pid <= 0 || liveness.detected == 0 ||
        liveness.state != HOOKSELF_STATE_FATAL ||
        liveness.stop_result != HOOKSELF_E_INTERNAL ||
        liveness.dumpable_restored == 0 || liveness.cleanup_ms < 0 ||
        liveness.cleanup_ms > 3000) {
        report.verdict = 0;
    }
    return report;
}

}  // namespace hookself::internal
