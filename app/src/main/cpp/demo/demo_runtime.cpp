#include "demo_runtime.h"

#include <android/log.h>
#include <asm/unistd.h>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <fcntl.h>
#include <linux/stat.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "hookself/framework.h"

// 反调试检测模块 (app/src/main/cpp/demo/anti_debug.cpp)
unsigned ad_detect_all(std::string* report);

namespace hookself::demo {
namespace {

constexpr char kDemoLogTag[] = "HookselfDemo";
constexpr char kStatusPath[] = "/proc/self/status";
constexpr size_t kStatusBufferCapacity = 4096U;
constexpr size_t kDrainBatchSize = 256U;
constexpr uint32_t kDrainMaxRounds = 8U;

constexpr uint32_t kOpenAtRuleId = 0x44454d01U;
constexpr uint32_t kNewFstatAtRuleId = 0x44454d02U;
constexpr uint32_t kStatxRuleId = 0x44454d03U;
constexpr uint32_t kPtraceRuleId = 0x44454d04U;

pthread_mutex_t gDemoMutex = PTHREAD_MUTEX_INITIALIZER;
HookselfFramework* gDemoFramework = nullptr;

class ScopedDemoLock {
public:
    ScopedDemoLock() noexcept : error_(pthread_mutex_lock(&gDemoMutex)) {}
    ~ScopedDemoLock() {
        if (error_ == 0) {
            (void)pthread_mutex_unlock(&gDemoMutex);
        }
    }

    bool ok() const noexcept { return error_ == 0; }
    int error() const noexcept { return error_; }

    ScopedDemoLock(const ScopedDemoLock&) = delete;
    ScopedDemoLock& operator=(const ScopedDemoLock&) = delete;

private:
    int error_;
};

struct DrainReport {
    int32_t result = HOOKSELF_OK;
    size_t consumed = 0;
    size_t emitted = 0;
};

struct StatusSnapshot {
    long open_result = -EBADF;
    long read_result = -EBADF;
    long close_result = -EBADF;
    int32_t parse_error = EINVAL;
    int32_t tracer_pid = -1;
};

struct PtraceWorkerResult {
    long tid = -1;
    long ptrace_result = -ENOSYS;
    StatusSnapshot status{};
};

long RawCall(long number, long first = 0, long second = 0, long third = 0,
             long fourth = 0, long fifth = 0, long sixth = 0) noexcept {
    errno = 0;
    const long result = syscall(number, first, second, third, fourth, fifth,
                                sixth);
    return result == -1 ? -errno : result;
}

int RawError(long result) noexcept {
    return result < 0 && result >= -4095 ? static_cast<int>(-result) : 0;
}

std::string LogReport(std::string report) {
    (void)__android_log_write(ANDROID_LOG_INFO, kDemoLogTag, report.c_str());
    return report;
}

int32_t CurrentStateLocked() noexcept {
    if (gDemoFramework == nullptr) {
        return HOOKSELF_STATE_IDLE;
    }
    int32_t state = HOOKSELF_STATE_FATAL;
    return hookself_framework_get_state(gDemoFramework, &state) == HOOKSELF_OK
                   ? state
                   : HOOKSELF_STATE_FATAL;
}

bool IsAttachedLocked() noexcept {
    const int32_t state = CurrentStateLocked();
    return state == HOOKSELF_STATE_RUNNING_FULL_PTRACE ||
           state == HOOKSELF_STATE_RUNNING_SELECTIVE;
}

void InitializeObserveRule(HookselfSyscallRule* rule, uint32_t rule_id,
                           int32_t syscall_number) noexcept {
    *rule = {};
    rule->struct_size = sizeof(*rule);
    rule->rule_id = rule_id;
    rule->syscall_number = syscall_number;
    rule->action = HOOKSELF_SYSCALL_OBSERVE;
    rule->phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
}

// syscall 号 => 可读名（arm64 asm-generic 编号，只列观测相关的，其余按 sys#N 输出）
const char* SyscallName(int32_t number) noexcept {
    switch (number) {
        case 291: return "statx";
        case 56:  return "openat";
        case 57:  return "close";
        case 63:  return "read";
        case 79:  return "newfstatat";
        case 93:  return "exit";
        case 94:  return "exit_group";
        case 117: return "ptrace";
        case 129: return "kill";
        case 167: return "prctl";
        case 172: return "getpid";
        case 178: return "gettid";
        case 220: return "clone";
        case 221: return "execve";
        default:  return nullptr;
    }
}

// 每条观测事件同步打到 logcat tag=HookselfEvents，标出虚拟视图命中标记
void DemoEventSink(int32_t level, const HookselfEvent* event,
                   const char* message, void* /*user_data*/) noexcept {
    if (event == nullptr) {
        if (message != nullptr) {
            (void)__android_log_print(static_cast<int>(level), "HookselfEvents",
                                      "MSG %s", message);
        }
        return;
    }
    if (event->kind != HOOKSELF_EVENT_SYSCALL) {
        return;
    }
    const char* name = SyscallName(event->syscall_number);
    char sys[24];
    if (name == nullptr) {
        (void)snprintf(sys, sizeof(sys), "sys%d", event->syscall_number);
        name = sys;
    }
    uint32_t view_flags = event->flags & (HOOKSELF_EVENT_F_PTRACE_VIEW |
                                          HOOKSELF_EVENT_F_PROC_STATUS_VIEW |
                                          HOOKSELF_EVENT_F_PROC_STAT_VIEW |
                                          HOOKSELF_EVENT_F_PROC_WCHAN_VIEW);
    (void)__android_log_print(static_cast<int>(level), "HookselfEvents",
                              "seq=%llu tid=%d sys=%s phase=%s ret=%ld err=%d "
                              "path='%s' flags=0x%x%s%s%s%s",
                              (unsigned long long)event->sequence, event->tid,
                              name,
                              (event->phase & HOOKSELF_SYSCALL_PHASE_ENTRY)
                                      ? ((event->phase & HOOKSELF_SYSCALL_PHASE_EXIT)
                                                 ? "BOTH" : "ENTRY") : "EXIT",
                              (long)event->result, event->error,
                              event->path, event->flags,
                              (view_flags & HOOKSELF_EVENT_F_PTRACE_VIEW)
                                      ? " [VPTRACE]" : "",
                              (view_flags & HOOKSELF_EVENT_F_PROC_STATUS_VIEW)
                                      ? " [VSTATUS]" : "",
                              (view_flags & HOOKSELF_EVENT_F_PROC_STAT_VIEW)
                                      ? " [VSTAT]" : "",
                              (view_flags & HOOKSELF_EVENT_F_PROC_WCHAN_VIEW)
                                      ? " [VWCHAN]" : "");
}

DrainReport DrainLogsLocked() noexcept {
    DrainReport report{};
    if (gDemoFramework == nullptr) {
        report.result = HOOKSELF_E_INVALID_STATE;
        return report;
    }
    for (uint32_t round = 0; round < kDrainMaxRounds; ++round) {
        size_t consumed = 0;
        size_t emitted = 0;
        report.result = hookself_framework_drain_logs(
                gDemoFramework, kDrainBatchSize, &consumed, &emitted);
        report.consumed += consumed;
        report.emitted += emitted;
        if (report.result != HOOKSELF_OK || consumed < kDrainBatchSize) {
            break;
        }
    }
    return report;
}

int32_t ParseTracerPid(const uint8_t* data, size_t size,
                       int32_t expected_tgid, int32_t* tracer_pid) noexcept {
    if (data == nullptr || tracer_pid == nullptr || expected_tgid <= 0) {
        return EINVAL;
    }
    *tracer_pid = -1;

    int32_t parsed_tgid = -1;
    uint32_t tgid_count = 0;
    uint32_t tracer_count = 0;
    for (size_t line_start = 0; line_start < size;) {
        size_t line_end = line_start;
        while (line_end < size && data[line_end] != '\n') {
            ++line_end;
        }
        const char* name = nullptr;
        size_t name_size = 0;
        int32_t* output = nullptr;
        uint32_t* count = nullptr;
        if (line_end - line_start >= 5 &&
            __builtin_memcmp(data + line_start, "Tgid:", 5) == 0) {
            name = "Tgid:";
            name_size = 5;
            output = &parsed_tgid;
            count = &tgid_count;
        } else if (line_end - line_start >= 10 &&
                   __builtin_memcmp(data + line_start, "TracerPid:", 10) == 0) {
            name = "TracerPid:";
            name_size = 10;
            output = tracer_pid;
            count = &tracer_count;
        }
        if (name != nullptr) {
            (void)name;
            ++*count;
            size_t cursor = line_start + name_size;
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t')) {
                ++cursor;
            }
            uint64_t value = 0;
            const size_t digits_start = cursor;
            while (cursor < line_end && data[cursor] >= '0' &&
                   data[cursor] <= '9') {
                const uint8_t digit = data[cursor++] - '0';
                if (value > (static_cast<uint64_t>(INT32_MAX) - digit) / 10U) {
                    return EOVERFLOW;
                }
                value = value * 10U + digit;
            }
            if (cursor == digits_start || cursor != line_end) {
                return EPROTO;
            }
            *output = static_cast<int32_t>(value);
        }
        line_start = line_end < size ? line_end + 1U : size;
    }
    return tgid_count == 1 && tracer_count == 1 &&
                   parsed_tgid == expected_tgid
           ? 0
           : EPROTO;
}

StatusSnapshot ReadProcStatus() noexcept {
    StatusSnapshot snapshot{};
    alignas(8) uint8_t buffer[kStatusBufferCapacity]{};
    snapshot.open_result = RawCall(
            __NR_openat, AT_FDCWD, reinterpret_cast<long>(kStatusPath),
            O_RDONLY | O_CLOEXEC, 0);
    if (RawError(snapshot.open_result) != 0) {
        return snapshot;
    }
    const int fd = static_cast<int>(snapshot.open_result);
    snapshot.read_result = RawCall(
            __NR_read, fd, reinterpret_cast<long>(buffer), sizeof(buffer));
    if (snapshot.read_result > 0) {
        const long pid = RawCall(__NR_getpid);
        if (pid > 0 && pid <= INT32_MAX) {
            snapshot.parse_error = ParseTracerPid(
                    buffer, static_cast<size_t>(snapshot.read_result),
                    static_cast<int32_t>(pid), &snapshot.tracer_pid);
        }
    }
    snapshot.close_result = RawCall(__NR_close, fd);
    return snapshot;
}

void* RunPtraceWorker(void* opaque) noexcept {
    auto* result = static_cast<PtraceWorkerResult*>(opaque);
    result->tid = RawCall(__NR_gettid);
    result->ptrace_result = RawCall(
            __NR_ptrace, static_cast<long>(PTRACE_TRACEME), 0, 0, 0);
    result->status = ReadProcStatus();
    return nullptr;
}

std::string NotAttachedReport(const char* marker) {
    return LogReport(std::string(marker) +
                     " {\"verdict\":\"ATTACH_REQUIRED\"}");
}

}  // namespace

bool IsAttached() noexcept {
    ScopedDemoLock lock;
    return lock.ok() && IsAttachedLocked();
}

std::string AttachSelf() {
    ScopedDemoLock lock;
    if (!lock.ok()) {
        return LogReport(
                "HOOKSELF_DEMO_ATTACH {\"verdict\":\"FAILED\",\"lock_error\":" +
                std::to_string(lock.error()) + "}");
    }

    if (IsAttachedLocked()) {
        const DrainReport drain = DrainLogsLocked();
        return LogReport(
                "HOOKSELF_DEMO_ATTACH {\"verdict\":\"PASS\",\"already_attached\":1,"
                "\"state\":" + std::to_string(CurrentStateLocked()) +
                ",\"drain_result\":" + std::to_string(drain.result) +
                ",\"logs_consumed\":" + std::to_string(drain.consumed) +
                ",\"logs_emitted\":" + std::to_string(drain.emitted) + "}");
    }
    if (gDemoFramework != nullptr) {
        hookself_framework_destroy(gDemoFramework);
        gDemoFramework = nullptr;
    }

    HookselfSyscallRule rules[4]{};
    InitializeObserveRule(&rules[0], kOpenAtRuleId, __NR_openat);
    InitializeObserveRule(&rules[1], kNewFstatAtRuleId, __NR_newfstatat);
    InitializeObserveRule(&rules[2], kStatxRuleId, __NR_statx);
    InitializeObserveRule(&rules[3], kPtraceRuleId, __NR_ptrace);

    HookselfConfig config{};
    hookself_framework_default_config(&config);
    config.log_level = HOOKSELF_LOG_TRACE;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                    HOOKSELF_CONFIG_TRACE_DESCENDANTS;
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;

    const int32_t validate_result = hookself_validate_config(&config);
    HookselfFramework* framework = nullptr;
    const int32_t create_result = validate_result == HOOKSELF_OK
                                          ? hookself_framework_create(
                                                    &config, &framework)
                                          : HOOKSELF_E_INVALID_STATE;
    if (create_result == HOOKSELF_OK && framework != nullptr) {
        // sink 在 start 前安装，事件经由 drain_logs 同步回调
        (void)hookself_framework_set_log_sink(framework, &DemoEventSink, nullptr);
    }
    int32_t register_result = create_result;
    for (const HookselfSyscallRule& rule : rules) {
        if (register_result != HOOKSELF_OK) {
            break;
        }
        HookselfRuleHandle handle = HOOKSELF_INVALID_RULE_HANDLE;
        register_result = hookself_framework_register_syscall_rule(
                framework, &rule, 1, &handle);
        if (register_result == HOOKSELF_OK &&
            handle == HOOKSELF_INVALID_RULE_HANDLE) {
            register_result = HOOKSELF_E_INTERNAL;
        }
    }
    const int32_t start_result = register_result == HOOKSELF_OK &&
                                                 framework != nullptr
                                         ? hookself_framework_start(framework)
                                         : HOOKSELF_E_INVALID_STATE;
    int32_t state = HOOKSELF_STATE_FATAL;
    const int32_t state_result = start_result == HOOKSELF_OK
                                         ? hookself_framework_get_state(
                                                   framework, &state)
                                         : HOOKSELF_E_INVALID_STATE;
    if (start_result != HOOKSELF_OK || state_result != HOOKSELF_OK ||
        state != HOOKSELF_STATE_RUNNING_FULL_PTRACE) {
        hookself_framework_destroy(framework);
        return LogReport(
                "HOOKSELF_DEMO_ATTACH {\"verdict\":\"FAILED\",\"already_attached\":0,"
                "\"validate_result\":" + std::to_string(validate_result) +
                ",\"create_result\":" + std::to_string(create_result) +
                ",\"register_result\":" + std::to_string(register_result) +
                ",\"start_result\":" + std::to_string(start_result) +
                ",\"state_result\":" + std::to_string(state_result) +
                ",\"state\":" + std::to_string(state) + "}");
    }

    gDemoFramework = framework;
    const DrainReport drain = DrainLogsLocked();
    return LogReport(
            "HOOKSELF_DEMO_ATTACH {\"verdict\":\"PASS\",\"already_attached\":0,"
            "\"validate_result\":" + std::to_string(validate_result) +
            ",\"create_result\":" + std::to_string(create_result) +
            ",\"register_result\":" + std::to_string(register_result) +
            ",\"start_result\":" + std::to_string(start_result) +
            ",\"state\":" + std::to_string(state) +
            ",\"drain_result\":" + std::to_string(drain.result) +
            ",\"logs_consumed\":" + std::to_string(drain.consumed) +
            ",\"logs_emitted\":" + std::to_string(drain.emitted) + "}");
}

std::string OpenStatProcStatus() {
    ScopedDemoLock lock;
    if (!lock.ok() || !IsAttachedLocked()) {
        return NotAttachedReport("HOOKSELF_DEMO_OPEN_STAT");
    }

    const StatusSnapshot status = ReadProcStatus();
    struct stat stat_buffer {};
    const long stat_result = RawCall(
            __NR_newfstatat, AT_FDCWD, reinterpret_cast<long>(kStatusPath),
            reinterpret_cast<long>(&stat_buffer), 0);
    struct statx statx_buffer {};
    const long statx_result = RawCall(
            __NR_statx, AT_FDCWD, reinterpret_cast<long>(kStatusPath), 0,
            STATX_BASIC_STATS, reinterpret_cast<long>(&statx_buffer));
    const DrainReport drain = DrainLogsLocked();

    const int open_error = RawError(status.open_result);
    const int read_error = RawError(status.read_result);
    const int close_error = RawError(status.close_result);
    const int stat_error = RawError(stat_result);
    const int statx_error = RawError(statx_result);
    const bool hook_observed = status.parse_error == 0 && status.tracer_pid == 0;
    const bool passed = open_error == 0 && read_error == 0 && close_error == 0 &&
                        stat_error == 0 && hook_observed;
    return LogReport(
            std::string("HOOKSELF_DEMO_OPEN_STAT {\"verdict\":\"") +
            (passed ? "PASS" : "FAILED") +
            "\",\"open_result\":" + std::to_string(status.open_result) +
            ",\"open_errno\":" + std::to_string(open_error) +
            ",\"read_result\":" + std::to_string(status.read_result) +
            ",\"read_errno\":" + std::to_string(read_error) +
            ",\"close_errno\":" + std::to_string(close_error) +
            ",\"newfstatat_result\":" + std::to_string(stat_result) +
            ",\"newfstatat_errno\":" + std::to_string(stat_error) +
            ",\"stat_mode\":" + std::to_string(stat_buffer.st_mode) +
            ",\"stat_size\":" + std::to_string(stat_buffer.st_size) +
            ",\"statx_result\":" + std::to_string(statx_result) +
            ",\"statx_errno\":" + std::to_string(statx_error) +
            ",\"statx_mask\":" + std::to_string(statx_buffer.stx_mask) +
            ",\"status_parse_errno\":" + std::to_string(status.parse_error) +
            ",\"tracer_pid\":" + std::to_string(status.tracer_pid) +
            ",\"hook_effect_observed\":" + std::to_string(hook_observed ? 1 : 0) +
            ",\"drain_result\":" + std::to_string(drain.result) +
            ",\"logs_consumed\":" + std::to_string(drain.consumed) +
            ",\"logs_emitted\":" + std::to_string(drain.emitted) + "}");
}

std::string RunPtraceDetection() {
    ScopedDemoLock lock;
    if (!lock.ok() || !IsAttachedLocked()) {
        return NotAttachedReport("HOOKSELF_DEMO_PTRACE");
    }

    PtraceWorkerResult worker{};
    pthread_t thread{};
    const int create_error = pthread_create(
            &thread, nullptr, RunPtraceWorker, &worker);
    const int join_error = create_error == 0
                                   ? pthread_join(thread, nullptr)
                                   : 0;
    const DrainReport drain = DrainLogsLocked();

    const int ptrace_error = RawError(worker.ptrace_result);
    const int open_error = RawError(worker.status.open_result);
    const int read_error = RawError(worker.status.read_result);
    const bool hook_observed = create_error == 0 && join_error == 0 &&
                               worker.ptrace_result == 0 &&
                               worker.status.parse_error == 0 &&
                               worker.status.tracer_pid == 0;
    return LogReport(
            std::string("HOOKSELF_DEMO_PTRACE {\"verdict\":\"") +
            (hook_observed ? "PASS" : "FAILED") +
            "\",\"thread_create_errno\":" + std::to_string(create_error) +
            ",\"thread_join_errno\":" + std::to_string(join_error) +
            ",\"worker_tid\":" + std::to_string(worker.tid) +
            ",\"ptrace_traceme_result\":" +
            std::to_string(worker.ptrace_result) +
            ",\"ptrace_traceme_errno\":" + std::to_string(ptrace_error) +
            ",\"status_open_errno\":" + std::to_string(open_error) +
            ",\"status_read_errno\":" + std::to_string(read_error) +
            ",\"status_parse_errno\":" +
            std::to_string(worker.status.parse_error) +
            ",\"tracer_pid\":" + std::to_string(worker.status.tracer_pid) +
            ",\"hook_effect_observed\":" + std::to_string(hook_observed ? 1 : 0) +
            ",\"drain_result\":" + std::to_string(drain.result) +
            ",\"logs_consumed\":" + std::to_string(drain.consumed) +
            ",\"logs_emitted\":" + std::to_string(drain.emitted) + "}");
}

std::string RunAntiDebug() {
    std::string report;
    const unsigned bits = ad_detect_all(&report);
    (void)__android_log_write(ANDROID_LOG_INFO, "AntiDebug", report.c_str());
    // 检测产生的 openat/read/clone/execve 事件全在 ring 里，drain 后经 sink 打到 logcat
    const DrainReport drain = DrainLogsLocked();
    return report + "HOOKSELF_DEMO_ANTIDEBUG {\"bits\":" +
           std::to_string(bits) + ",\"drain_result\":" +
           std::to_string(drain.result) + ",\"logs_consumed\":" +
           std::to_string(drain.consumed) + ",\"logs_emitted\":" +
           std::to_string(drain.emitted) + "}\n";
}

#if defined(HOOKSELF_DEMO_BUILD_TEST_SUPPORT)
std::string DetachSelf() {
    ScopedDemoLock lock;
    if (!lock.ok()) {
        return LogReport(
                "HOOKSELF_DEMO_DETACH {\"verdict\":\"FAILED\",\"lock_error\":" +
                std::to_string(lock.error()) + "}");
    }
    if (gDemoFramework == nullptr) {
        return LogReport(
                "HOOKSELF_DEMO_DETACH {\"verdict\":\"PASS\",\"already_detached\":1}");
    }

    const int32_t state_before = CurrentStateLocked();
    const int32_t stop_result = hookself_framework_stop(gDemoFramework);
    const DrainReport drain = DrainLogsLocked();
    hookself_framework_destroy(gDemoFramework);
    gDemoFramework = nullptr;
    return LogReport(
            std::string("HOOKSELF_DEMO_DETACH {\"verdict\":\"") +
            (stop_result == HOOKSELF_OK ? "PASS" : "FAILED") +
            "\",\"already_detached\":0,\"state_before\":" +
            std::to_string(state_before) +
            ",\"stop_result\":" + std::to_string(stop_result) +
            ",\"drain_result\":" + std::to_string(drain.result) +
            ",\"logs_consumed\":" + std::to_string(drain.consumed) +
            ",\"logs_emitted\":" + std::to_string(drain.emitted) + "}");
}
#endif

}  // namespace hookself::demo
