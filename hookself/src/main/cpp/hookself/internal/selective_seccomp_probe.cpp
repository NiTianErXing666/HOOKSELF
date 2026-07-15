#include "internal/selective_seccomp_probe.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>

#include "internal/selective_seccomp_filter.h"
#include "platform/procfs.h"
#include "platform/raw_clone_thread_arm64.h"
#include "platform/raw_syscall_arm64.h"

namespace hookself::internal {
namespace {

constexpr uint32_t kProbeVersion = 1;
constexpr uint16_t kPtraceClassId = 0x4d34;
constexpr uint16_t kTsyncClassId = 0x5453;
constexpr int64_t kSubprocessTimeoutMs = 5000;
constexpr int64_t kInjectedHangTimeoutMs = 250;
constexpr size_t kWorkerStackSize = 64U * 1024U;
constexpr uint64_t kCloneFlags =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
        CLONE_THREAD | CLONE_SYSVSEM;
constexpr unsigned long kPtraceOptions =
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP;

struct Arm64Regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static_assert(sizeof(Arm64Regs) == 272U);
static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr));

struct SeccompStatus {
    int32_t mode;
    int32_t filters;
    int32_t filter_count_supported;
};

struct ProbeShared {
    SelectiveSeccompProbeReport report;
    uint32_t tracee_start_gate;
    uint32_t worker_ready;
    uint32_t worker_release;
    uint32_t worker_exited;
};

std::atomic_flag g_probe_running = ATOMIC_FLAG_INIT;

class ProbeGuard {
public:
    explicit ProbeGuard(bool acquired) noexcept : acquired_(acquired) {}
    ~ProbeGuard() {
        if (acquired_) {
            g_probe_running.clear(std::memory_order_release);
        }
    }

    ProbeGuard(const ProbeGuard&) = delete;
    ProbeGuard& operator=(const ProbeGuard&) = delete;

private:
    bool acquired_;
};

long RawPrctl(long option, long arg2 = 0) noexcept {
    return platform::RawSyscall6(__NR_prctl, option, arg2);
}

int ConfigureParentDeathSignal(int32_t* configured_signal) noexcept {
    if (configured_signal == nullptr) {
        return EINVAL;
    }
    *configured_signal = 0;
    const int set_error = platform::RawError(
            RawPrctl(PR_SET_PDEATHSIG, SIGKILL));
    if (set_error != 0) {
        return set_error;
    }
    int signal_number = 0;
    const int get_error = platform::RawError(
            RawPrctl(PR_GET_PDEATHSIG,
                     reinterpret_cast<long>(&signal_number)));
    *configured_signal = signal_number;
    if (get_error != 0) {
        return get_error;
    }
    return signal_number == SIGKILL ? 0 : EPROTO;
}

long RawKill(pid_t pid, int signal_number) noexcept {
    return platform::RawSyscall6(__NR_kill, pid, signal_number);
}

pid_t RawGetPid() noexcept {
    return static_cast<pid_t>(platform::RawSyscall6(__NR_getpid));
}

pid_t RawGetTid() noexcept {
    return static_cast<pid_t>(platform::RawSyscall6(__NR_gettid));
}

int DecodeExitStatus(int status) noexcept {
    if (platform::IsExitedStatus(status)) {
        return (status >> 8) & 0xff;
    }
    if (platform::IsSignaledStatus(status)) {
        return 128 + (status & 0x7f);
    }
    return -1;
}

int WaitForPidUntil(pid_t pid, int options, int64_t deadline_ms,
                    int* status) noexcept {
    for (;;) {
        const long result = platform::RawWait4(
                pid, status, options | WNOHANG);
        if (result == pid) {
            return 0;
        }
        const int error = platform::RawError(result);
        if (error != 0 && error != EINTR) {
            return error;
        }
        int64_t now_ms = 0;
        const int clock_error = platform::MonotonicNowMilliseconds(&now_ms);
        if (clock_error != 0) {
            return clock_error;
        }
        if (now_ms >= deadline_ms) {
            return ETIMEDOUT;
        }
        const int sleep_error = platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
}

int WaitForPid(pid_t pid, int options, int* status,
               int64_t timeout_ms = kSubprocessTimeoutMs) noexcept {
    int64_t now_ms = 0;
    const int clock_error = platform::MonotonicNowMilliseconds(&now_ms);
    if (clock_error != 0) {
        return clock_error;
    }
    return WaitForPidUntil(pid, options, now_ms + timeout_ms,
                           status);
}

int KillAndReap(pid_t pid, int options = 0, int* final_status = nullptr) noexcept {
    if (pid <= 0) {
        return EINVAL;
    }
    int64_t precheck_now_ms = 0;
    const int precheck_clock_error =
            platform::MonotonicNowMilliseconds(&precheck_now_ms);
    if (precheck_clock_error != 0) {
        return precheck_clock_error;
    }
    const int64_t precheck_deadline_ms =
            precheck_now_ms + kSubprocessTimeoutMs;
    int status = 0;
    for (;;) {
        const long probe_result = platform::RawWait4(
                pid, &status, options | WNOHANG);
        if (probe_result == pid) {
            if (platform::IsExitedStatus(status) ||
                platform::IsSignaledStatus(status)) {
                if (final_status != nullptr) {
                    *final_status = status;
                }
                return 0;
            }
            break;
        }
        const int probe_error = platform::RawError(probe_result);
        if (probe_error == EINTR) {
            if (platform::MonotonicNowMilliseconds(&precheck_now_ms) != 0) {
                return EIO;
            }
            if (precheck_now_ms >= precheck_deadline_ms) {
                return ETIMEDOUT;
            }
            continue;
        }
        if (probe_error == ECHILD) {
            return 0;
        }
        if (probe_error != 0) {
            return probe_error;
        }
        break;
    }

    const int kill_error = platform::RawError(RawKill(pid, SIGKILL));
    if (kill_error != 0 && kill_error != ESRCH) {
        return kill_error;
    }
    const int wait_error = WaitForPid(pid, options, &status);
    if (wait_error == ECHILD) {
        return 0;
    }
    if (wait_error != 0) {
        return wait_error;
    }
    if (final_status != nullptr) {
        *final_status = status;
    }
    return 0;
}

int WaitForProcessIdentityGone(pid_t pid, uint64_t start_time) noexcept {
    if (pid <= 0 || start_time == 0U) {
        return EINVAL;
    }
    int64_t now_ms = 0;
    const int clock_error = platform::MonotonicNowMilliseconds(&now_ms);
    if (clock_error != 0) {
        return clock_error;
    }
    const int64_t deadline_ms = now_ms + kSubprocessTimeoutMs;
    for (;;) {
        uint64_t current_start_time = 0;
        const int identity_error = platform::ReadProcessStartTime(
                pid, &current_start_time);
        if (identity_error == ENOENT || identity_error == ESRCH) {
            return 0;
        }
        if (identity_error != 0) {
            return identity_error;
        }
        if (current_start_time != start_time) {
            return 0;
        }
        if (platform::MonotonicNowMilliseconds(&now_ms) != 0) {
            return EIO;
        }
        if (now_ms >= deadline_ms) {
            return ETIMEDOUT;
        }
        const int sleep_error = platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
}

bool AppendText(char* output, size_t capacity, size_t* length,
                const char* text) noexcept {
    while (*text != '\0') {
        if (*length + 1U >= capacity) {
            return false;
        }
        output[(*length)++] = *text++;
    }
    output[*length] = '\0';
    return true;
}

bool AppendPositiveDecimal(char* output, size_t capacity, size_t* length,
                           pid_t value) noexcept {
    if (value <= 0) {
        return false;
    }
    char reversed[16]{};
    size_t count = 0;
    uint32_t current = static_cast<uint32_t>(value);
    do {
        reversed[count++] = static_cast<char>('0' + current % 10U);
        current /= 10U;
    } while (current != 0U && count < sizeof(reversed));
    if (*length + count >= capacity) {
        return false;
    }
    while (count != 0U) {
        output[(*length)++] = reversed[--count];
    }
    output[*length] = '\0';
    return true;
}

bool ParseStatusValue(const char* buffer, size_t size, const char* key,
                      int32_t* output) noexcept {
    const size_t key_size = std::strlen(key);
    for (size_t offset = 0; offset + key_size <= size;) {
        const size_t line_start = offset;
        while (offset < size && buffer[offset] != '\n') {
            ++offset;
        }
        const size_t line_size = offset - line_start;
        if (line_size >= key_size &&
            std::memcmp(buffer + line_start, key, key_size) == 0) {
            size_t cursor = line_start + key_size;
            while (cursor < line_start + line_size &&
                   (buffer[cursor] == ' ' || buffer[cursor] == '\t')) {
                ++cursor;
            }
            if (cursor == line_start + line_size ||
                buffer[cursor] < '0' || buffer[cursor] > '9') {
                return false;
            }
            int64_t value = 0;
            while (cursor < line_start + line_size &&
                   buffer[cursor] >= '0' && buffer[cursor] <= '9') {
                value = value * 10 + (buffer[cursor++] - '0');
                if (value > INT32_MAX) {
                    return false;
                }
            }
            *output = static_cast<int32_t>(value);
            return true;
        }
        if (offset < size) {
            ++offset;
        }
    }
    return false;
}

int ReadSeccompStatus(pid_t tid, SeccompStatus* output) noexcept {
    if (output == nullptr) {
        return EINVAL;
    }
    output->mode = -1;
    output->filters = -1;
    output->filter_count_supported = 0;

    char path[96]{};
    size_t length = 0;
    if (tid <= 0) {
        if (!AppendText(path, sizeof(path), &length, "/proc/self/status")) {
            return ENAMETOOLONG;
        }
    } else {
        if (!AppendText(path, sizeof(path), &length, "/proc/self/task/") ||
            !AppendPositiveDecimal(path, sizeof(path), &length, tid) ||
            !AppendText(path, sizeof(path), &length, "/status")) {
            return ENAMETOOLONG;
        }
    }

    const long fd_result = platform::RawOpenAt(
            AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    const int open_error = platform::RawError(fd_result);
    if (open_error != 0) {
        return open_error;
    }
    const int fd = static_cast<int>(fd_result);
    char buffer[8192]{};
    size_t used = 0;
    int read_error = 0;
    while (used + 1U < sizeof(buffer)) {
        const long read_result = platform::RawRead(
                fd, buffer + used, sizeof(buffer) - used - 1U);
        read_error = platform::RawError(read_result);
        if (read_error == EINTR) {
            continue;
        }
        if (read_error != 0 || read_result == 0) {
            break;
        }
        used += static_cast<size_t>(read_result);
    }
    const int close_error = platform::RawError(platform::RawClose(fd));
    if (read_error != 0) {
        return read_error;
    }
    if (close_error != 0) {
        return close_error;
    }
    if (!ParseStatusValue(buffer, used, "Seccomp:", &output->mode)) {
        return ENODATA;
    }
    output->filter_count_supported =
            ParseStatusValue(buffer, used, "Seccomp_filters:",
                             &output->filters)
                    ? 1
                    : 0;
    return 0;
}

int ReadArm64Registers(pid_t tid, Arm64Regs* registers) noexcept {
    iovec vector{registers, sizeof(*registers)};
    const long result = platform::RawPtrace(
            PTRACE_GETREGSET, tid, 1,
            reinterpret_cast<uintptr_t>(&vector));
    const int error = platform::RawError(result);
    if (error != 0) {
        return error;
    }
    return vector.iov_len == sizeof(*registers) ? 0 : EIO;
}

void InitializeReport(SelectiveSeccompProbeReport* report) noexcept {
    std::memset(report, 0, sizeof(*report));
    report->version = kProbeVersion;
    report->caller_no_new_privs_before = -1;
    report->caller_no_new_privs_after = -1;
    report->caller_seccomp_mode_before = -1;
    report->caller_seccomp_mode_after = -1;
    report->caller_filter_count_before = -1;
    report->caller_filter_count_after = -1;
    report->tracee_no_new_privs_before = -1;
    report->tracee_seccomp_mode_before = -1;
    report->tracee_seccomp_mode_after = -1;
    report->tracee_filter_count_before = -1;
    report->tracee_filter_count_after = -1;
    report->syscall_info_supported = -1;
    report->first_gettid_result = INT64_MIN;
    report->second_gettid_result = INT64_MIN;
    report->post_detach_gettid_result = INT64_MIN;
    report->observed_exit_result = INT64_MIN;
    report->tracee_exit_status = -1;
    report->supervisor_exit_status = -1;
    report->tsync_exit_status = -1;
    report->tsync_no_new_privs_before = -1;
    report->tsync_leader_mode_before = -1;
    report->tsync_worker_mode_before = -1;
    report->tsync_leader_mode_after = -1;
    report->tsync_worker_mode_after = -1;
    report->tsync_leader_filters_before = -1;
    report->tsync_worker_filters_before = -1;
    report->tsync_leader_filters_after = -1;
    report->tsync_worker_filters_after = -1;
    report->tsync_main_baseline_result = INT64_MIN;
    report->tsync_worker_baseline_result = INT64_MIN;
    report->tsync_main_no_tracer_result = INT64_MIN;
    report->tsync_worker_no_tracer_result = INT64_MIN;
}

void TraceeMain(ProbeShared* shared, pid_t expected_parent) noexcept {
    SelectiveSeccompProbeReport& report = shared->report;
    const pid_t self_pid = RawGetPid();
    report.tracee_pdeathsig_errno = ConfigureParentDeathSignal(
            &report.tracee_pdeathsig_value);
    if (report.tracee_pdeathsig_errno != 0) {
        report.fatal_errno = report.tracee_pdeathsig_errno;
        platform::RawExit(99);
    }
    if (platform::RawSyscall6(__NR_getppid) != expected_parent) {
        platform::RawExit(100);
    }
    while (__atomic_load_n(&shared->tracee_start_gate,
                           __ATOMIC_ACQUIRE) == 0U) {
        (void)platform::RawSyscall6(__NR_sched_yield);
    }

    const long traceme_result = platform::RawPtrace(PTRACE_TRACEME, 0);
    report.traceme_errno = platform::RawError(traceme_result);
    if (report.traceme_errno != 0) {
        platform::RawExit(101);
    }
    (void)platform::RawSyscall6(
            __NR_tgkill, self_pid, self_pid, SIGSTOP);

    const long no_new_privs = RawPrctl(PR_GET_NO_NEW_PRIVS);
    report.tracee_no_new_privs_before_errno =
            platform::RawError(no_new_privs);
    report.tracee_no_new_privs_before =
            report.tracee_no_new_privs_before_errno == 0
                    ? static_cast<int32_t>(no_new_privs)
                    : -1;
    SeccompStatus before{};
    report.tracee_status_before_errno = ReadSeccompStatus(0, &before);
    report.tracee_seccomp_mode_before = before.mode;
    report.tracee_filter_count_before = before.filters;

    const long nnp_result = RawPrctl(PR_SET_NO_NEW_PRIVS, 1);
    report.tracee_no_new_privs_errno = platform::RawError(nnp_result);
    SelectiveSeccompFilter filter{};
    const SelectiveSeccompRule rule{
            static_cast<int32_t>(__NR_gettid), kPtraceClassId};
    report.tracee_filter_build_errno = BuildSelectiveSeccompFilter(
            &rule, 1, SelectiveSeccompArchMismatchAction::kAllow, &filter);
    if (report.tracee_no_new_privs_errno == 0 &&
        report.tracee_filter_build_errno == 0) {
        report.tracee_filter_install_errno = InstallSelectiveSeccompFilter(
                &filter, 0, &report.tracee_filter_failed_tid);
    } else {
        report.tracee_filter_install_errno = EINVAL;
    }

    SeccompStatus after{};
    report.tracee_status_after_errno = ReadSeccompStatus(0, &after);
    report.tracee_seccomp_mode_after = after.mode;
    report.tracee_filter_count_after = after.filters;
    report.tracee_filter_count_supported =
            before.filter_count_supported != 0 &&
                    after.filter_count_supported != 0
                    ? 1
                    : 0;
    if (report.tracee_filter_install_errno != 0) {
        platform::RawExit(102);
    }

    report.first_gettid_result = platform::RawSyscall6(__NR_gettid);
    report.second_gettid_result = platform::RawSyscall6(__NR_gettid);
    (void)platform::RawSyscall6(
            __NR_tgkill, self_pid, self_pid, SIGSTOP);
    report.post_detach_gettid_result = platform::RawSyscall6(__NR_gettid);
    platform::RawExit(0);
}

bool ObserveSeccompEvent(SelectiveSeccompProbeReport* report, pid_t tracee,
                         int status, bool force_fallback) noexcept {
    if (!platform::IsStoppedStatus(status) ||
        platform::StopSignal(status) != SIGTRAP ||
        platform::PtraceEvent(status) != PTRACE_EVENT_SECCOMP) {
        ++report->unexpected_stop_count;
        return false;
    }
    ++report->seccomp_event_count;

    unsigned long message = 0;
    const long message_result = platform::RawPtrace(
            PTRACE_GETEVENTMSG, tracee, 0,
            reinterpret_cast<uintptr_t>(&message));
    if (platform::RawError(message_result) == 0 &&
        message == kPtraceClassId) {
        ++report->event_data_match_count;
    }

    ptrace_syscall_info info{};
    const long info_result =
            force_fallback
                    ? -ENOSYS
                    : platform::RawPtrace(
                              PTRACE_GET_SYSCALL_INFO, tracee, sizeof(info),
                              reinterpret_cast<uintptr_t>(&info));
    if (!force_fallback && platform::RawError(info_result) == 0) {
        report->syscall_info_supported = 1;
        if (info.op == PTRACE_SYSCALL_INFO_SECCOMP &&
            info.seccomp.nr == __NR_gettid &&
            info.seccomp.ret_data == kPtraceClassId) {
            ++report->seccomp_info_match_count;
        }
    } else {
        if (report->syscall_info_supported < 0) {
            report->syscall_info_supported = 0;
        }
        Arm64Regs registers{};
        if (ReadArm64Registers(tracee, &registers) == 0 &&
            registers.regs[8] == __NR_gettid) {
            ++report->seccomp_fallback_match_count;
        }
    }
    return true;
}

bool ObserveSyscallExit(SelectiveSeccompProbeReport* report, pid_t tracee,
                        int status, bool force_fallback) noexcept {
    if (!platform::IsStoppedStatus(status) ||
        platform::StopSignal(status) != (SIGTRAP | 0x80) ||
        platform::PtraceEvent(status) != 0U) {
        ++report->unexpected_stop_count;
        return false;
    }
    report->syscall_exit_stop_seen = 1;

    ptrace_syscall_info info{};
    const long info_result =
            force_fallback
                    ? -ENOSYS
                    : platform::RawPtrace(
                              PTRACE_GET_SYSCALL_INFO, tracee, sizeof(info),
                              reinterpret_cast<uintptr_t>(&info));
    if (!force_fallback && platform::RawError(info_result) == 0) {
        report->syscall_info_supported = 1;
        if (info.op == PTRACE_SYSCALL_INFO_EXIT &&
            info.exit.rval == tracee && info.exit.is_error == 0U) {
            report->syscall_exit_info_match = 1;
            report->observed_exit_result = info.exit.rval;
        }
    } else {
        if (report->syscall_info_supported < 0) {
            report->syscall_info_supported = 0;
        }
        Arm64Regs registers{};
        if (ReadArm64Registers(tracee, &registers) == 0 &&
            static_cast<int64_t>(registers.regs[0]) == tracee) {
            report->syscall_exit_fallback_match = 1;
            report->observed_exit_result = tracee;
        }
    }
    return true;
}

bool RunPtraceSupervisor(ProbeShared* shared, pid_t expected_parent) noexcept {
    SelectiveSeccompProbeReport& report = shared->report;
    const pid_t self_pid = RawGetPid();
    const bool force_fallback =
            (report.probe_flags &
             kSelectiveSeccompProbeForceRegisterFallback) != 0U;
    report.supervisor_pdeathsig_errno = ConfigureParentDeathSignal(
            &report.supervisor_pdeathsig_value);
    if (report.supervisor_pdeathsig_errno != 0) {
        report.fatal_errno = report.supervisor_pdeathsig_errno;
        return false;
    }
    report.supervisor_parent_check =
            platform::RawSyscall6(__NR_getppid) == expected_parent ? 1 : 0;
    if (report.supervisor_parent_check == 0) {
        report.fatal_errno = ECHILD;
        return false;
    }
    const pid_t tracee = fork();
    if (tracee < 0) {
        report.fatal_errno = errno;
        return false;
    }
    if (tracee == 0) {
        TraceeMain(shared, self_pid);
    }
    report.tracee_identity_errno = platform::ReadProcessStartTime(
            tracee, &report.tracee_start_time);
    if (report.tracee_identity_errno != 0 ||
        report.tracee_start_time == 0U) {
        report.fatal_errno = report.tracee_identity_errno != 0
                                     ? report.tracee_identity_errno
                                     : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }
    __atomic_store_n(&report.tracee_pid, static_cast<int32_t>(tracee),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&shared->tracee_start_gate, 1U, __ATOMIC_RELEASE);
    if ((report.probe_flags &
         kSelectiveSeccompProbeInjectSupervisorHang) != 0U) {
        for (;;) {
            (void)platform::RawSyscall6(__NR_sched_yield);
        }
    }

    int status = 0;
    int wait_error = WaitForPid(tracee, platform::kWaitWall, &status);
    if (wait_error != 0 || !platform::IsStoppedStatus(status) ||
        platform::StopSignal(status) != SIGSTOP) {
        report.fatal_errno = wait_error != 0 ? wait_error : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }
    report.initial_stop_seen = 1;

    const long options_result = platform::RawPtrace(
            PTRACE_SETOPTIONS, tracee, 0, kPtraceOptions);
    report.setoptions_errno = platform::RawError(options_result);
    if (report.setoptions_errno != 0) {
        report.fatal_errno = report.setoptions_errno;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }

    report.cont_resume_errno = platform::RawError(
            platform::RawPtrace(PTRACE_CONT, tracee, 0, 0));
    wait_error = report.cont_resume_errno == 0
                         ? WaitForPid(tracee, platform::kWaitWall, &status)
                         : report.cont_resume_errno;
    if (wait_error != 0 ||
        !ObserveSeccompEvent(&report, tracee, status, force_fallback)) {
        report.fatal_errno = wait_error != 0 ? wait_error : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }

    report.cont_resume_errno = platform::RawError(
            platform::RawPtrace(PTRACE_CONT, tracee, 0, 0));
    wait_error = report.cont_resume_errno == 0
                         ? WaitForPid(tracee, platform::kWaitWall, &status)
                         : report.cont_resume_errno;
    if (wait_error != 0 ||
        !ObserveSeccompEvent(&report, tracee, status, force_fallback)) {
        report.fatal_errno = wait_error != 0 ? wait_error : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }

    report.syscall_resume_errno = platform::RawError(
            platform::RawPtrace(PTRACE_SYSCALL, tracee, 0, 0));
    wait_error = report.syscall_resume_errno == 0
                         ? WaitForPid(tracee, platform::kWaitWall, &status)
                         : report.syscall_resume_errno;
    if (wait_error != 0 ||
        !ObserveSyscallExit(&report, tracee, status, force_fallback)) {
        report.fatal_errno = wait_error != 0 ? wait_error : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }

    report.final_resume_errno = platform::RawError(
            platform::RawPtrace(PTRACE_CONT, tracee, 0, 0));
    wait_error = report.final_resume_errno == 0
                         ? WaitForPid(tracee, platform::kWaitWall, &status)
                         : report.final_resume_errno;
    if (wait_error != 0 || !platform::IsStoppedStatus(status) ||
        platform::StopSignal(status) != SIGSTOP ||
        platform::PtraceEvent(status) != 0U) {
        report.fatal_errno = wait_error != 0 ? wait_error : EPROTO;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }
    report.detach_stop_seen = 1;
    report.detach_errno = platform::RawError(
            platform::RawPtrace(PTRACE_DETACH, tracee, 0, 0));
    wait_error = report.detach_errno == 0
                         ? WaitForPid(tracee, platform::kWaitWall, &status)
                         : report.detach_errno;
    if (wait_error != 0) {
        report.fatal_errno = wait_error;
        report.tracee_cleanup_errno =
                KillAndReap(tracee, platform::kWaitWall);
        return false;
    }
    report.tracee_exit_status = DecodeExitStatus(status);
    return report.tracee_exit_status == 0;
}

__attribute__((no_stack_protector)) int TsyncWorkerMain(void* opaque) noexcept {
    auto* shared = static_cast<ProbeShared*>(opaque);
    SelectiveSeccompProbeReport& report = shared->report;
    report.tsync_worker_baseline_result =
            platform::RawSyscall6(__NR_getppid);
    __atomic_store_n(&shared->worker_ready, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&shared->worker_release, __ATOMIC_ACQUIRE) == 0U) {
        (void)platform::RawSyscall6(__NR_sched_yield);
    }
    report.tsync_worker_no_tracer_result =
            platform::RawSyscall6(__NR_getppid);
    report.tsync_worker_exited = 1;
    __atomic_store_n(&shared->worker_exited, 1U, __ATOMIC_RELEASE);
    return 0;
}

bool WaitForAtomicValue(const uint32_t* address, uint32_t expected,
                        int64_t timeout_ms) noexcept {
    int64_t now_ms = 0;
    if (platform::MonotonicNowMilliseconds(&now_ms) != 0) {
        return false;
    }
    const int64_t deadline_ms = now_ms + timeout_ms;
    while (__atomic_load_n(address, __ATOMIC_ACQUIRE) != expected) {
        if (platform::MonotonicNowMilliseconds(&now_ms) != 0 ||
            now_ms >= deadline_ms) {
            return false;
        }
        const int sleep_error = platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return false;
        }
    }
    return true;
}

bool RunTsyncChild(ProbeShared* shared, void* worker_stack_top,
                   pid_t expected_parent) noexcept {
    SelectiveSeccompProbeReport& report = shared->report;
    report.tsync_pdeathsig_errno = ConfigureParentDeathSignal(
            &report.tsync_pdeathsig_value);
    if (report.tsync_pdeathsig_errno != 0) {
        report.fatal_errno = report.tsync_pdeathsig_errno;
        return false;
    }
    report.tsync_parent_check =
            platform::RawSyscall6(__NR_getppid) == expected_parent ? 1 : 0;
    if (report.tsync_parent_check == 0) {
        report.fatal_errno = ECHILD;
        return false;
    }

    const uint64_t signal_mask = UINT64_MAX;
    report.tsync_signal_mask_errno = platform::RawError(
            platform::RawSyscall6(
                    __NR_rt_sigprocmask, SIG_BLOCK,
                    reinterpret_cast<long>(&signal_mask), 0,
                    sizeof(signal_mask)));
    if (report.tsync_signal_mask_errno != 0) {
        return false;
    }

    const long clone_result = platform::HookselfRawCloneThread(
            TsyncWorkerMain, shared, worker_stack_top, kCloneFlags);
    report.tsync_clone_errno = platform::RawError(clone_result);
    if (report.tsync_clone_errno != 0 || clone_result <= 0 ||
        clone_result > INT32_MAX) {
        if (report.tsync_clone_errno == 0) {
            report.tsync_clone_errno = EIO;
        }
        return false;
    }
    const int worker_tid = static_cast<int>(clone_result);
    report.tsync_worker_tid = worker_tid;
    report.tsync_worker_ready =
            WaitForAtomicValue(&shared->worker_ready, 1U,
                               kSubprocessTimeoutMs)
                    ? 1
                    : 0;
    if (report.tsync_worker_ready == 0) {
        return false;
    }
    if ((report.probe_flags & kSelectiveSeccompProbeInjectTsyncHang) != 0U) {
        for (;;) {
            (void)platform::RawSyscall6(__NR_sched_yield);
        }
    }
    report.tsync_main_baseline_result =
            platform::RawSyscall6(__NR_getppid);

    SeccompStatus leader_before{};
    SeccompStatus worker_before{};
    report.tsync_leader_status_before_errno =
            ReadSeccompStatus(0, &leader_before);
    report.tsync_worker_status_before_errno =
            ReadSeccompStatus(report.tsync_worker_tid, &worker_before);
    report.tsync_leader_mode_before = leader_before.mode;
    report.tsync_worker_mode_before = worker_before.mode;
    report.tsync_leader_filters_before = leader_before.filters;
    report.tsync_worker_filters_before = worker_before.filters;

    const long no_new_privs = RawPrctl(PR_GET_NO_NEW_PRIVS);
    report.tsync_no_new_privs_before_errno =
            platform::RawError(no_new_privs);
    report.tsync_no_new_privs_before =
            report.tsync_no_new_privs_before_errno == 0
                    ? static_cast<int32_t>(no_new_privs)
                    : -1;
    report.tsync_no_new_privs_errno = platform::RawError(
            RawPrctl(PR_SET_NO_NEW_PRIVS, 1));

    SelectiveSeccompFilter filter{};
    const SelectiveSeccompRule rule{
            static_cast<int32_t>(__NR_getppid), kTsyncClassId};
    report.tsync_filter_build_errno = BuildSelectiveSeccompFilter(
            &rule, 1, SelectiveSeccompArchMismatchAction::kAllow, &filter);
    if (report.tsync_no_new_privs_errno == 0 &&
        report.tsync_filter_build_errno == 0) {
        report.tsync_filter_install_errno = InstallSelectiveSeccompFilter(
                &filter, SECCOMP_FILTER_FLAG_TSYNC,
                &report.tsync_filter_failed_tid);
    } else {
        report.tsync_filter_install_errno = EINVAL;
    }
    if (report.tsync_filter_install_errno != 0) {
        __atomic_store_n(&shared->worker_release, 1U, __ATOMIC_RELEASE);
        (void)WaitForAtomicValue(&shared->worker_exited, 1U, 1000);
        return false;
    }

    SeccompStatus leader_after{};
    SeccompStatus worker_after{};
    report.tsync_leader_status_after_errno =
            ReadSeccompStatus(0, &leader_after);
    report.tsync_worker_status_after_errno =
            ReadSeccompStatus(report.tsync_worker_tid, &worker_after);
    report.tsync_leader_mode_after = leader_after.mode;
    report.tsync_worker_mode_after = worker_after.mode;
    report.tsync_leader_filters_after = leader_after.filters;
    report.tsync_worker_filters_after = worker_after.filters;
    report.tsync_filter_count_supported =
            leader_before.filter_count_supported != 0 &&
                    worker_before.filter_count_supported != 0 &&
                    leader_after.filter_count_supported != 0 &&
                    worker_after.filter_count_supported != 0
                    ? 1
                    : 0;

    report.tsync_main_no_tracer_result =
            platform::RawSyscall6(__NR_getppid);
    __atomic_store_n(&shared->worker_release, 1U, __ATOMIC_RELEASE);
    report.tsync_worker_exited =
            WaitForAtomicValue(&shared->worker_exited, 1U,
                               kSubprocessTimeoutMs)
                    ? 1
                    : 0;
    return report.tsync_worker_exited != 0;
}

bool PtraceProbePassed(const SelectiveSeccompProbeReport& report) noexcept {
    const bool info_pass =
            report.syscall_info_supported == 1
                    ? report.seccomp_info_match_count == 2 &&
                              report.syscall_exit_info_match == 1
                    : report.seccomp_fallback_match_count == 2 &&
                              report.syscall_exit_fallback_match == 1;
    const bool filter_count_pass =
            report.tracee_filter_count_supported != 0
                    ? report.tracee_filter_count_before >= 1 &&
                              (report.tracee_filter_count_after ==
                                       report.tracee_filter_count_before ||
                               report.tracee_filter_count_after ==
                                       report.tracee_filter_count_before + 1)
                    : report.tracee_filter_count_before == -1 &&
                              report.tracee_filter_count_after == -1;
    return report.supervisor_timeout == 0 &&
           report.supervisor_exit_status == 0 &&
           report.supervisor_cleanup_errno == 0 &&
           report.supervisor_parent_check == 1 &&
           report.supervisor_pdeathsig_errno == 0 &&
           report.supervisor_pdeathsig_value == SIGKILL &&
           report.tracee_cleanup_errno == 0 &&
           report.tracee_identity_errno == 0 &&
           report.tracee_start_time != 0U &&
           report.tracee_pdeathsig_errno == 0 &&
           report.tracee_pdeathsig_value == SIGKILL &&
           report.traceme_errno == 0 && report.initial_stop_seen == 1 &&
           report.setoptions_errno == 0 &&
           report.tracee_status_before_errno == 0 &&
           report.tracee_status_after_errno == 0 &&
           report.tracee_no_new_privs_before_errno == 0 &&
           (report.tracee_no_new_privs_before == 0 ||
            report.tracee_no_new_privs_before == 1) &&
           report.tracee_no_new_privs_errno == 0 &&
           report.tracee_filter_build_errno == 0 &&
           report.tracee_filter_install_errno == 0 &&
           report.tracee_filter_failed_tid == 0 &&
           report.tracee_seccomp_mode_before == SECCOMP_MODE_FILTER &&
           report.tracee_seccomp_mode_after == SECCOMP_MODE_FILTER &&
           filter_count_pass &&
           report.seccomp_event_count == 2 &&
           report.event_data_match_count == 2 && info_pass &&
           report.cont_resume_errno == 0 &&
           report.syscall_resume_errno == 0 &&
           report.syscall_exit_stop_seen == 1 &&
           report.final_resume_errno == 0 &&
           report.detach_stop_seen == 1 && report.detach_errno == 0 &&
           report.unexpected_stop_count == 0 &&
           report.first_gettid_result == report.tracee_pid &&
           report.second_gettid_result == report.tracee_pid &&
           report.post_detach_gettid_result == -ENOSYS &&
           report.observed_exit_result == report.tracee_pid &&
           report.tracee_exit_status == 0;
}

bool TsyncProbePassed(const SelectiveSeccompProbeReport& report) noexcept {
    const bool filter_count_pass =
            report.tsync_filter_count_supported != 0
                    ? report.tsync_leader_filters_before >= 1 &&
                              report.tsync_leader_filters_before ==
                                      report.tsync_worker_filters_before &&
                              report.tsync_leader_filters_after ==
                                      report.tsync_worker_filters_after &&
                              (report.tsync_leader_filters_after ==
                                       report.tsync_leader_filters_before ||
                               report.tsync_leader_filters_after ==
                                       report.tsync_leader_filters_before + 1)
                    : report.tsync_leader_filters_before == -1 &&
                              report.tsync_worker_filters_before == -1 &&
                              report.tsync_leader_filters_after == -1 &&
                              report.tsync_worker_filters_after == -1;
    return report.tsync_timeout == 0 && report.tsync_exit_status == 0 &&
           report.tsync_cleanup_errno == 0 &&
           report.tsync_parent_check == 1 &&
           report.tsync_pdeathsig_errno == 0 &&
           report.tsync_pdeathsig_value == SIGKILL &&
           report.tsync_signal_mask_errno == 0 &&
           report.tsync_clone_errno == 0 && report.tsync_worker_tid > 0 &&
           report.tsync_worker_ready == 1 &&
           report.tsync_no_new_privs_before_errno == 0 &&
           (report.tsync_no_new_privs_before == 0 ||
            report.tsync_no_new_privs_before == 1) &&
           report.tsync_no_new_privs_errno == 0 &&
           report.tsync_leader_status_before_errno == 0 &&
           report.tsync_worker_status_before_errno == 0 &&
           report.tsync_leader_status_after_errno == 0 &&
           report.tsync_worker_status_after_errno == 0 &&
           report.tsync_leader_mode_before == SECCOMP_MODE_FILTER &&
           report.tsync_worker_mode_before == SECCOMP_MODE_FILTER &&
           report.tsync_leader_mode_after == SECCOMP_MODE_FILTER &&
           report.tsync_worker_mode_after == SECCOMP_MODE_FILTER &&
           filter_count_pass &&
           report.tsync_filter_build_errno == 0 &&
           report.tsync_filter_install_errno == 0 &&
           report.tsync_filter_failed_tid == 0 &&
           report.tsync_main_baseline_result == report.caller_pid &&
           report.tsync_worker_baseline_result == report.caller_pid &&
           report.tsync_main_no_tracer_result == -ENOSYS &&
           report.tsync_worker_no_tracer_result == -ENOSYS &&
           report.tsync_worker_exited == 1;
}

}  // namespace

SelectiveSeccompProbeReport RunSelectiveSeccompCapabilityProbe(uint32_t flags) {
    SelectiveSeccompProbeReport busy_report{};
    InitializeReport(&busy_report);
    busy_report.probe_flags = flags;
    constexpr uint32_t kAllowedFlags =
            kSelectiveSeccompProbeForceRegisterFallback |
            kSelectiveSeccompProbeInjectSupervisorHang |
            kSelectiveSeccompProbeInjectTsyncHang;
    if ((flags & ~kAllowedFlags) != 0U ||
        ((flags & kSelectiveSeccompProbeInjectSupervisorHang) != 0U &&
         (flags & kSelectiveSeccompProbeInjectTsyncHang) != 0U)) {
        busy_report.fatal_errno = EINVAL;
        return busy_report;
    }
    const bool acquired =
            !g_probe_running.test_and_set(std::memory_order_acquire);
    ProbeGuard guard(acquired);
    if (!acquired) {
        busy_report.fatal_errno = EBUSY;
        return busy_report;
    }

    int64_t start_ms = 0;
    (void)platform::MonotonicNowMilliseconds(&start_ms);
    void* mapping = mmap(nullptr, sizeof(ProbeShared),
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        busy_report.fatal_errno = errno;
        return busy_report;
    }
    auto* shared = static_cast<ProbeShared*>(mapping);
    std::memset(shared, 0, sizeof(*shared));
    InitializeReport(&shared->report);
    shared->report.probe_flags = flags;
    shared->report.caller_pid = RawGetPid();

    const long caller_nnp_before = RawPrctl(PR_GET_NO_NEW_PRIVS);
    shared->report.caller_no_new_privs_before_errno =
            platform::RawError(caller_nnp_before);
    shared->report.caller_no_new_privs_before =
            shared->report.caller_no_new_privs_before_errno == 0
                    ? static_cast<int32_t>(caller_nnp_before)
                    : -1;
    SeccompStatus caller_status_before{};
    shared->report.caller_status_before_errno =
            ReadSeccompStatus(RawGetTid(), &caller_status_before);
    shared->report.caller_seccomp_mode_before = caller_status_before.mode;
    shared->report.caller_filter_count_before = caller_status_before.filters;

    const pid_t supervisor = fork();
    if (supervisor < 0) {
        shared->report.fatal_errno = errno;
    } else if (supervisor == 0) {
        const bool passed = RunPtraceSupervisor(
                shared, shared->report.caller_pid);
        platform::RawExit(passed ? 0 : 1);
    } else {
        shared->report.supervisor_pid = supervisor;
        int status = 0;
        const int64_t supervisor_timeout_ms =
                (flags & kSelectiveSeccompProbeInjectSupervisorHang) != 0U
                        ? kInjectedHangTimeoutMs
                        : kSubprocessTimeoutMs;
        const int wait_error = WaitForPid(
                supervisor, 0, &status, supervisor_timeout_ms);
        if (wait_error != 0) {
            if (wait_error == ETIMEDOUT) {
                shared->report.supervisor_timeout = 1;
            }
            if (shared->report.fatal_errno == 0) {
                shared->report.fatal_errno = wait_error;
            }
            const pid_t tracee_pid = static_cast<pid_t>(__atomic_load_n(
                    &shared->report.tracee_pid, __ATOMIC_ACQUIRE));
            const uint64_t tracee_start_time =
                    shared->report.tracee_start_time;
            const int tracee_identity_error =
                    shared->report.tracee_identity_errno;
            shared->report.supervisor_cleanup_errno =
                    KillAndReap(supervisor, 0, &status);
            if (tracee_pid > 0) {
                shared->report.tracee_cleanup_errno =
                        tracee_identity_error == 0 &&
                                        tracee_start_time != 0U
                                ? WaitForProcessIdentityGone(
                                          tracee_pid, tracee_start_time)
                                : (tracee_identity_error != 0
                                           ? tracee_identity_error
                                           : EPROTO);
            }
        }
        shared->report.supervisor_exit_status = DecodeExitStatus(status);
    }

    if (shared->report.supervisor_cleanup_errno != 0 ||
        shared->report.tracee_cleanup_errno != 0) {
        SelectiveSeccompProbeReport cleanup_failure{};
        InitializeReport(&cleanup_failure);
        cleanup_failure.probe_flags = flags;
        cleanup_failure.fatal_errno =
                shared->report.supervisor_cleanup_errno != 0
                        ? shared->report.supervisor_cleanup_errno
                        : shared->report.tracee_cleanup_errno;
        cleanup_failure.caller_pid = shared->report.caller_pid;
        cleanup_failure.supervisor_pid = supervisor;
        cleanup_failure.tracee_pid = __atomic_load_n(
                &shared->report.tracee_pid, __ATOMIC_ACQUIRE);
        cleanup_failure.supervisor_cleanup_errno =
                shared->report.supervisor_cleanup_errno;
        cleanup_failure.tracee_cleanup_errno =
                shared->report.tracee_cleanup_errno;
        // Keep the mapping alive because an unreaped task may still reference it.
        return cleanup_failure;
    }

    const bool previous_children_stable =
            shared->report.supervisor_cleanup_errno == 0 &&
            shared->report.tracee_cleanup_errno == 0;
    const long page_size_result =
            previous_children_stable ? sysconf(_SC_PAGESIZE) : -1;
    const bool valid_page_size =
            page_size_result > 0 &&
            kWorkerStackSize % static_cast<size_t>(page_size_result) == 0U &&
            static_cast<size_t>(page_size_result) <=
                    (SIZE_MAX - kWorkerStackSize) / 2U;
    const size_t page_size = valid_page_size
                                     ? static_cast<size_t>(page_size_result)
                                     : 0U;
    const size_t stack_mapping_size =
            valid_page_size ? kWorkerStackSize + 2U * page_size : 0U;
    void* worker_stack_mapping =
            valid_page_size
                    ? mmap(nullptr, stack_mapping_size, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                    : MAP_FAILED;
    void* worker_stack =
            worker_stack_mapping == MAP_FAILED
                    ? MAP_FAILED
                    : static_cast<char*>(worker_stack_mapping) + page_size;
    if (!valid_page_size || worker_stack_mapping == MAP_FAILED ||
        mprotect(worker_stack, kWorkerStackSize,
                 PROT_READ | PROT_WRITE) != 0) {
        if (shared->report.fatal_errno == 0) {
            shared->report.fatal_errno =
                    !valid_page_size ? EINVAL : errno;
        }
    } else {
        const pid_t tsync_child = fork();
        if (tsync_child < 0) {
            if (shared->report.fatal_errno == 0) {
                shared->report.fatal_errno = errno;
            }
        } else if (tsync_child == 0) {
            void* stack_top =
                    static_cast<char*>(worker_stack) + kWorkerStackSize;
            const bool passed = RunTsyncChild(
                    shared, stack_top, shared->report.caller_pid);
            platform::RawExit(passed ? 0 : 1);
        } else {
            shared->report.tsync_pid = tsync_child;
            int status = 0;
            const int64_t tsync_timeout_ms =
                    (flags & kSelectiveSeccompProbeInjectTsyncHang) != 0U
                            ? kInjectedHangTimeoutMs
                            : kSubprocessTimeoutMs;
            const int wait_error = WaitForPid(
                    tsync_child, 0, &status, tsync_timeout_ms);
            if (wait_error != 0) {
                if (wait_error == ETIMEDOUT) {
                    shared->report.tsync_timeout = 1;
                }
                if (shared->report.fatal_errno == 0) {
                    shared->report.fatal_errno = wait_error;
                }
                shared->report.tsync_cleanup_errno =
                        KillAndReap(tsync_child, 0, &status);
            }
            shared->report.tsync_exit_status = DecodeExitStatus(status);
        }
    }
    if (shared->report.tsync_cleanup_errno != 0) {
        SelectiveSeccompProbeReport cleanup_failure{};
        InitializeReport(&cleanup_failure);
        cleanup_failure.probe_flags = flags;
        cleanup_failure.fatal_errno = shared->report.tsync_cleanup_errno;
        cleanup_failure.caller_pid = shared->report.caller_pid;
        cleanup_failure.tsync_pid = shared->report.tsync_pid;
        cleanup_failure.tsync_cleanup_errno =
                shared->report.tsync_cleanup_errno;
        // Keep both mappings alive because an unreaped thread group may use them.
        return cleanup_failure;
    }
    if (worker_stack_mapping != MAP_FAILED) {
        (void)munmap(worker_stack_mapping, stack_mapping_size);
    }

    const long caller_nnp_after = RawPrctl(PR_GET_NO_NEW_PRIVS);
    shared->report.caller_no_new_privs_after_errno =
            platform::RawError(caller_nnp_after);
    shared->report.caller_no_new_privs_after =
            shared->report.caller_no_new_privs_after_errno == 0
                    ? static_cast<int32_t>(caller_nnp_after)
                    : -1;
    SeccompStatus caller_status_after{};
    shared->report.caller_status_after_errno =
            ReadSeccompStatus(RawGetTid(), &caller_status_after);
    shared->report.caller_seccomp_mode_after = caller_status_after.mode;
    shared->report.caller_filter_count_after = caller_status_after.filters;
    shared->report.caller_filter_count_supported =
            caller_status_before.filter_count_supported != 0 &&
                    caller_status_after.filter_count_supported != 0
                    ? 1
                    : 0;
    const bool caller_filter_count_preserved =
            shared->report.caller_filter_count_supported != 0
                    ? shared->report.caller_filter_count_before ==
                              shared->report.caller_filter_count_after
                    : shared->report.caller_filter_count_before == -1 &&
                              shared->report.caller_filter_count_after == -1;
    const bool caller_state_preserved =
            shared->report.caller_status_before_errno == 0 &&
            shared->report.caller_status_after_errno == 0 &&
            shared->report.caller_no_new_privs_before_errno == 0 &&
            shared->report.caller_no_new_privs_after_errno == 0 &&
            (shared->report.caller_no_new_privs_before == 0 ||
             shared->report.caller_no_new_privs_before == 1) &&
            shared->report.caller_no_new_privs_before ==
                    shared->report.caller_no_new_privs_after &&
            shared->report.caller_seccomp_mode_before ==
                    shared->report.caller_seccomp_mode_after &&
            caller_filter_count_preserved;
    shared->report.verdict =
            shared->report.fatal_errno == 0 && caller_state_preserved &&
                            PtraceProbePassed(shared->report) &&
                            TsyncProbePassed(shared->report)
                    ? 1
                    : 0;
    int64_t finish_ms = 0;
    if (platform::MonotonicNowMilliseconds(&finish_ms) == 0 &&
        finish_ms >= start_ms) {
        shared->report.duration_ms = finish_ms - start_ms;
    }
    const SelectiveSeccompProbeReport result = shared->report;
    (void)munmap(mapping, sizeof(ProbeShared));
    return result;
}

std::string FormatSelectiveSeccompProbeReport(
        const SelectiveSeccompProbeReport& report) {
    std::ostringstream output;
    output << "HOOKSELF_M4_PROBE_RESULT {\"verdict\":\""
           << (report.verdict != 0 ? "PASS" : "FAILED")
           << "\",\"version\":" << report.version
           << ",\"probe_flags\":" << report.probe_flags
           << ",\"fatal_errno\":" << report.fatal_errno
           << ",\"duration_ms\":" << report.duration_ms
           << ",\"caller_status_before_errno\":"
           << report.caller_status_before_errno
           << ",\"caller_status_after_errno\":"
           << report.caller_status_after_errno
           << ",\"caller_no_new_privs_before_errno\":"
           << report.caller_no_new_privs_before_errno
           << ",\"caller_no_new_privs_after_errno\":"
           << report.caller_no_new_privs_after_errno
           << ",\"caller_no_new_privs_before\":"
           << report.caller_no_new_privs_before
           << ",\"caller_no_new_privs_after\":"
           << report.caller_no_new_privs_after
           << ",\"caller_seccomp_mode_before\":"
           << report.caller_seccomp_mode_before
           << ",\"caller_seccomp_mode_after\":"
           << report.caller_seccomp_mode_after
           << ",\"caller_filter_count_before\":"
           << report.caller_filter_count_before
           << ",\"caller_filter_count_after\":"
           << report.caller_filter_count_after
           << ",\"caller_filter_count_supported\":"
           << report.caller_filter_count_supported
           << ",\"caller_pid\":" << report.caller_pid
           << ",\"supervisor_pid\":" << report.supervisor_pid
           << ",\"tracee_pid\":" << report.tracee_pid
           << ",\"supervisor_timeout\":" << report.supervisor_timeout
           << ",\"supervisor_exit_status\":" << report.supervisor_exit_status
           << ",\"supervisor_cleanup_errno\":"
           << report.supervisor_cleanup_errno
           << ",\"supervisor_parent_check\":"
           << report.supervisor_parent_check
           << ",\"supervisor_pdeathsig_errno\":"
           << report.supervisor_pdeathsig_errno
           << ",\"supervisor_pdeathsig_value\":"
           << report.supervisor_pdeathsig_value
           << ",\"tracee_cleanup_errno\":"
           << report.tracee_cleanup_errno
           << ",\"tracee_identity_errno\":"
           << report.tracee_identity_errno
           << ",\"tracee_start_time\":" << report.tracee_start_time
           << ",\"tracee_pdeathsig_errno\":"
           << report.tracee_pdeathsig_errno
           << ",\"tracee_pdeathsig_value\":"
           << report.tracee_pdeathsig_value
           << ",\"traceme_errno\":" << report.traceme_errno
           << ",\"initial_stop_seen\":" << report.initial_stop_seen
           << ",\"setoptions_errno\":" << report.setoptions_errno
           << ",\"tracee_no_new_privs_before_errno\":"
           << report.tracee_no_new_privs_before_errno
           << ",\"tracee_no_new_privs_before\":"
           << report.tracee_no_new_privs_before
           << ",\"tracee_no_new_privs_errno\":"
           << report.tracee_no_new_privs_errno
           << ",\"tracee_status_before_errno\":"
           << report.tracee_status_before_errno
           << ",\"tracee_status_after_errno\":"
           << report.tracee_status_after_errno
           << ",\"tracee_seccomp_mode_before\":"
           << report.tracee_seccomp_mode_before
           << ",\"tracee_seccomp_mode_after\":"
           << report.tracee_seccomp_mode_after
           << ",\"tracee_filter_count_before\":"
           << report.tracee_filter_count_before
           << ",\"tracee_filter_count_after\":"
           << report.tracee_filter_count_after
           << ",\"tracee_filter_count_supported\":"
           << report.tracee_filter_count_supported
           << ",\"tracee_filter_build_errno\":"
           << report.tracee_filter_build_errno
           << ",\"tracee_filter_install_errno\":"
           << report.tracee_filter_install_errno
           << ",\"tracee_filter_failed_tid\":"
           << report.tracee_filter_failed_tid
           << ",\"seccomp_event_count\":" << report.seccomp_event_count
           << ",\"event_data_match_count\":"
           << report.event_data_match_count
           << ",\"syscall_info_supported\":"
           << report.syscall_info_supported
           << ",\"seccomp_info_match_count\":"
           << report.seccomp_info_match_count
           << ",\"seccomp_fallback_match_count\":"
           << report.seccomp_fallback_match_count
           << ",\"cont_resume_errno\":" << report.cont_resume_errno
           << ",\"syscall_resume_errno\":" << report.syscall_resume_errno
           << ",\"syscall_exit_stop_seen\":"
           << report.syscall_exit_stop_seen
           << ",\"syscall_exit_info_match\":"
           << report.syscall_exit_info_match
           << ",\"syscall_exit_fallback_match\":"
           << report.syscall_exit_fallback_match
           << ",\"final_resume_errno\":" << report.final_resume_errno
           << ",\"detach_stop_seen\":" << report.detach_stop_seen
           << ",\"detach_errno\":" << report.detach_errno
           << ",\"unexpected_stop_count\":"
           << report.unexpected_stop_count
           << ",\"first_gettid_result\":" << report.first_gettid_result
           << ",\"second_gettid_result\":" << report.second_gettid_result
           << ",\"post_detach_gettid_result\":"
           << report.post_detach_gettid_result
           << ",\"observed_exit_result\":" << report.observed_exit_result
           << ",\"tracee_exit_status\":" << report.tracee_exit_status
           << ",\"tsync_pid\":" << report.tsync_pid
           << ",\"tsync_timeout\":" << report.tsync_timeout
           << ",\"tsync_exit_status\":" << report.tsync_exit_status
           << ",\"tsync_cleanup_errno\":"
           << report.tsync_cleanup_errno
           << ",\"tsync_parent_check\":" << report.tsync_parent_check
           << ",\"tsync_pdeathsig_errno\":"
           << report.tsync_pdeathsig_errno
           << ",\"tsync_pdeathsig_value\":"
           << report.tsync_pdeathsig_value
           << ",\"tsync_signal_mask_errno\":"
           << report.tsync_signal_mask_errno
           << ",\"tsync_clone_errno\":" << report.tsync_clone_errno
           << ",\"tsync_worker_tid\":" << report.tsync_worker_tid
           << ",\"tsync_worker_ready\":" << report.tsync_worker_ready
           << ",\"tsync_no_new_privs_before_errno\":"
           << report.tsync_no_new_privs_before_errno
           << ",\"tsync_no_new_privs_before\":"
           << report.tsync_no_new_privs_before
           << ",\"tsync_no_new_privs_errno\":"
           << report.tsync_no_new_privs_errno
           << ",\"tsync_leader_status_before_errno\":"
           << report.tsync_leader_status_before_errno
           << ",\"tsync_worker_status_before_errno\":"
           << report.tsync_worker_status_before_errno
           << ",\"tsync_leader_status_after_errno\":"
           << report.tsync_leader_status_after_errno
           << ",\"tsync_worker_status_after_errno\":"
           << report.tsync_worker_status_after_errno
           << ",\"tsync_leader_mode_before\":"
           << report.tsync_leader_mode_before
           << ",\"tsync_worker_mode_before\":"
           << report.tsync_worker_mode_before
           << ",\"tsync_leader_mode_after\":"
           << report.tsync_leader_mode_after
           << ",\"tsync_worker_mode_after\":"
           << report.tsync_worker_mode_after
           << ",\"tsync_leader_filters_before\":"
           << report.tsync_leader_filters_before
           << ",\"tsync_worker_filters_before\":"
           << report.tsync_worker_filters_before
           << ",\"tsync_leader_filters_after\":"
           << report.tsync_leader_filters_after
           << ",\"tsync_worker_filters_after\":"
           << report.tsync_worker_filters_after
           << ",\"tsync_filter_count_supported\":"
           << report.tsync_filter_count_supported
           << ",\"tsync_filter_build_errno\":"
           << report.tsync_filter_build_errno
           << ",\"tsync_filter_install_errno\":"
           << report.tsync_filter_install_errno
           << ",\"tsync_filter_failed_tid\":"
           << report.tsync_filter_failed_tid
           << ",\"tsync_main_baseline_result\":"
           << report.tsync_main_baseline_result
           << ",\"tsync_worker_baseline_result\":"
           << report.tsync_worker_baseline_result
           << ",\"tsync_main_no_tracer_result\":"
           << report.tsync_main_no_tracer_result
           << ",\"tsync_worker_no_tracer_result\":"
           << report.tsync_worker_no_tracer_result
           << ",\"tsync_worker_exited\":" << report.tsync_worker_exited
           << '}';
    return output.str();
}

}  // namespace hookself::internal
