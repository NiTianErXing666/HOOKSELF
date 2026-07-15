#include "nested_ptrace_resident_selftest.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "hookself/public_api.h"
#include "platform/raw_syscall_arm64.h"

namespace hookself::internal {
namespace {

constexpr int64_t kRegistrationTimeoutMs = 3000;
constexpr int64_t kGateTimeoutMs = 1500;
constexpr int64_t kWaitTimeoutMs = 5000;

struct ScenarioPipes {
    int traceme_gate[2];
    int phase[2];
    int exec_gate[2];
};

struct ChildPhase {
    int64_t traceme_result;
    int32_t stage;
    int32_t reserved;
};

struct WaitReleaseContext {
    HookselfRuntime* runtime;
    int32_t parent_tid;
    int32_t syscall_number;
    int exec_gate_fd;
    volatile uint32_t started;
    volatile uint32_t wait_entry_seen;
    int32_t release_result;
    int32_t worker_error;
};

struct Phase1ScenarioResult {
    int32_t child_pid;
    int32_t new_task_event;
    int64_t traceme_result;
    int64_t nohang_result;
    int32_t nohang_zero;
    int32_t wait_entry_event;
    int32_t release_result;
    int64_t initial_wait_result;
    int32_t initial_wait_status;
    int32_t initial_signal_stop;
    int32_t initial_siginfo_match;
    int64_t setoptions_result;
    int64_t first_cont_result;
    int64_t exec_wait_result;
    int32_t exec_wait_status;
    int32_t exec_stop;
    int32_t exec_siginfo_match;
    int64_t geteventmsg_result;
    uint64_t event_message;
    int32_t event_message_match;
    int64_t resume_result;
    int64_t exit_result;
    int32_t exit_status;
    int32_t cleanup_result;
};

void Check(NestedPtraceResidentSelfTestReport* report, bool condition,
           int32_t failure) noexcept {
    ++report->checks;
    if (!condition) {
        ++report->failures;
        if (report->first_failure == 0) {
            report->first_failure = failure;
        }
    }
}

void InitializePipes(ScenarioPipes* pipes) noexcept {
    for (size_t index = 0; index < 2; ++index) {
        pipes->traceme_gate[index] = -1;
        pipes->phase[index] = -1;
        pipes->exec_gate[index] = -1;
    }
}

void CloseFd(int* fd) noexcept {
    if (fd != nullptr && *fd >= 0) {
        (void)hookself::platform::RawClose(*fd);
        *fd = -1;
    }
}

void CloseAllPipes(ScenarioPipes* pipes) noexcept {
    if (pipes == nullptr) {
        return;
    }
    for (size_t index = 0; index < 2; ++index) {
        CloseFd(&pipes->traceme_gate[index]);
        CloseFd(&pipes->phase[index]);
        CloseFd(&pipes->exec_gate[index]);
    }
}

int CreatePipe(int output[2]) noexcept {
    output[0] = -1;
    output[1] = -1;
    const long result = hookself::platform::RawSyscall6(
            __NR_pipe2, reinterpret_cast<long>(output),
            O_CLOEXEC | O_NONBLOCK);
    return hookself::platform::RawError(result);
}

int CreateScenarioPipes(ScenarioPipes* pipes) noexcept {
    if (pipes == nullptr) {
        return EINVAL;
    }
    InitializePipes(pipes);
    int error = CreatePipe(pipes->traceme_gate);
    if (error == 0) {
        error = CreatePipe(pipes->phase);
    }
    if (error == 0) {
        error = CreatePipe(pipes->exec_gate);
    }
    if (error != 0) {
        CloseAllPipes(pipes);
    }
    return error;
}

int DeadlineFromNow(int64_t timeout_ms, int64_t* deadline_ms) noexcept {
    if (deadline_ms == nullptr || timeout_ms < 0) {
        return EINVAL;
    }
    int64_t now_ms = 0;
    const int clock_error = hookself::platform::MonotonicNowMilliseconds(&now_ms);
    if (clock_error != 0) {
        return clock_error;
    }
    if (now_ms > INT64_MAX - timeout_ms) {
        return EOVERFLOW;
    }
    *deadline_ms = now_ms + timeout_ms;
    return 0;
}

bool DeadlineReached(int64_t deadline_ms) noexcept {
    int64_t now_ms = 0;
    return hookself::platform::MonotonicNowMilliseconds(&now_ms) != 0 ||
           now_ms >= deadline_ms;
}

int ReadExactUntil(int fd, void* output, size_t size,
                   int64_t timeout_ms) noexcept {
    if (fd < 0 || (size != 0U && output == nullptr)) {
        return EINVAL;
    }
    int64_t deadline_ms = 0;
    const int deadline_error = DeadlineFromNow(timeout_ms, &deadline_ms);
    if (deadline_error != 0) {
        return deadline_error;
    }
    auto* bytes = static_cast<uint8_t*>(output);
    size_t offset = 0;
    while (offset < size) {
        const long result = hookself::platform::RawRead(
                fd, bytes + offset, size - offset);
        if (result > 0) {
            offset += static_cast<size_t>(result);
            continue;
        }
        if (result == 0) {
            return EPIPE;
        }
        const int error = hookself::platform::RawError(result);
        if (error != EINTR && error != EAGAIN && error != EWOULDBLOCK) {
            return error == 0 ? EIO : error;
        }
        if (DeadlineReached(deadline_ms)) {
            return ETIMEDOUT;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
    return 0;
}

int WriteExactUntil(int fd, const void* input, size_t size,
                    int64_t timeout_ms) noexcept {
    if (fd < 0 || (size != 0U && input == nullptr)) {
        return EINVAL;
    }
    int64_t deadline_ms = 0;
    const int deadline_error = DeadlineFromNow(timeout_ms, &deadline_ms);
    if (deadline_error != 0) {
        return deadline_error;
    }
    const auto* bytes = static_cast<const uint8_t*>(input);
    size_t offset = 0;
    while (offset < size) {
        const long result = hookself::platform::RawWrite(
                fd, bytes + offset, size - offset);
        if (result > 0) {
            offset += static_cast<size_t>(result);
            continue;
        }
        const int error = hookself::platform::RawError(result);
        if (error != EINTR && error != EAGAIN && error != EWOULDBLOCK) {
            return error == 0 ? EIO : error;
        }
        if (DeadlineReached(deadline_ms)) {
            return ETIMEDOUT;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
    return 0;
}

void DrainEvents(HookselfRuntime* runtime) noexcept {
    HookselfEvent events[16]{};
    while (hookself_read_events(runtime, events, 16) != 0U) {
    }
}

int WaitForNewTaskEvent(HookselfRuntime* runtime, pid_t child) noexcept {
    if (runtime == nullptr || child <= 0) {
        return EINVAL;
    }
    int64_t deadline_ms = 0;
    const int deadline_error = DeadlineFromNow(
            kRegistrationTimeoutMs, &deadline_ms);
    if (deadline_error != 0) {
        return deadline_error;
    }
    for (;;) {
        HookselfEvent events[16]{};
        const size_t count = hookself_read_events(runtime, events, 16);
        for (size_t index = 0; index < count; ++index) {
            const HookselfEvent& event = events[index];
            if (event.kind == HOOKSELF_EVENT_PROCESS &&
                event.tid == child &&
                (event.flags & HOOKSELF_EVENT_F_NEW_TASK) != 0U) {
                return 0;
            }
        }
        if (DeadlineReached(deadline_ms)) {
            return ETIMEDOUT;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
}

bool NestedWaitEntry(const HookselfEvent& event, int32_t parent_tid,
                     int32_t syscall_number) noexcept {
    return event.kind == HOOKSELF_EVENT_SYSCALL &&
           event.tid == parent_tid &&
           event.syscall_number == syscall_number &&
           event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY &&
           event.rule_id == HOOKSELF_BUILTIN_RULE_NESTED_PTRACE &&
           (event.flags & HOOKSELF_EVENT_F_NESTED_PTRACE) != 0U;
}

void* RunWaitReleaseWorker(void* opaque) {
    auto* context = static_cast<WaitReleaseContext*>(opaque);
    if (context == nullptr || context->runtime == nullptr ||
        context->exec_gate_fd < 0) {
        return nullptr;
    }
    __atomic_store_n(&context->started, 1U, __ATOMIC_RELEASE);
    int64_t deadline_ms = 0;
    context->worker_error = DeadlineFromNow(kGateTimeoutMs, &deadline_ms);
    if (context->worker_error != 0) {
        return nullptr;
    }
    for (;;) {
        HookselfEvent events[16]{};
        const size_t count = hookself_read_events(context->runtime, events, 16);
        for (size_t index = 0; index < count; ++index) {
            if (NestedWaitEntry(events[index], context->parent_tid,
                                context->syscall_number)) {
                __atomic_store_n(&context->wait_entry_seen, 1U,
                                 __ATOMIC_RELEASE);
                const uint8_t release = 1U;
                context->release_result = WriteExactUntil(
                        context->exec_gate_fd, &release, sizeof(release),
                        kGateTimeoutMs);
                return nullptr;
            }
        }
        if (DeadlineReached(deadline_ms)) {
            context->worker_error = ETIMEDOUT;
            const uint8_t release = 1U;
            context->release_result = WriteExactUntil(
                    context->exec_gate_fd, &release, sizeof(release),
                    kGateTimeoutMs);
            return nullptr;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            context->worker_error = sleep_error;
            return nullptr;
        }
    }
}

int WaitForWorkerStart(const WaitReleaseContext& context) noexcept {
    int64_t deadline_ms = 0;
    const int deadline_error = DeadlineFromNow(kGateTimeoutMs, &deadline_ms);
    if (deadline_error != 0) {
        return deadline_error;
    }
    while (__atomic_load_n(&context.started, __ATOMIC_ACQUIRE) == 0U) {
        if (DeadlineReached(deadline_ms)) {
            return ETIMEDOUT;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
    return 0;
}

bool BytesAreZero(const void* input, size_t size) noexcept {
    const auto* bytes = static_cast<const uint8_t*>(input);
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0U) {
            return false;
        }
    }
    return true;
}

bool IsExecStopStatus(int status) noexcept {
    return hookself::platform::IsStoppedStatus(status) &&
           hookself::platform::StopSignal(status) == SIGTRAP &&
           hookself::platform::PtraceEvent(status) == PTRACE_EVENT_EXEC;
}

bool IsTrapSignalDeliveryStop(int status) noexcept {
    return hookself::platform::IsStoppedStatus(status) &&
           hookself::platform::StopSignal(status) == SIGTRAP &&
           hookself::platform::PtraceEvent(status) == 0U;
}

bool IsCleanExitStatus(int status) noexcept {
    return hookself::platform::IsExitedStatus(status) &&
           WEXITSTATUS(status) == 0;
}

bool EventMessageMatchesLeader(pid_t child, uint64_t message) noexcept {
    // Kernels use zero for a leader exec and the former leader TID for a
    // de-threading exec. Android devices observed in the field use both
    // encodings for direct-child leader execs.
    return message == 0U || message == static_cast<uint64_t>(child);
}

int WaitForTerminal(pid_t child, int64_t timeout_ms,
                    int64_t* result_out, int32_t* status_out,
                    bool resume_unexpected_stops) noexcept {
    if (child <= 0 || result_out == nullptr || status_out == nullptr) {
        return EINVAL;
    }
    *result_out = INT64_MIN;
    *status_out = 0;
    int64_t deadline_ms = 0;
    const int deadline_error = DeadlineFromNow(timeout_ms, &deadline_ms);
    if (deadline_error != 0) {
        return deadline_error;
    }
    for (;;) {
        int status = 0;
        const long result = hookself::platform::RawWait4(
                child, &status, WNOHANG);
        if (result == child) {
            *result_out = result;
            *status_out = status;
            if (hookself::platform::IsExitedStatus(status) ||
                hookself::platform::IsSignaledStatus(status)) {
                return 0;
            }
            if (resume_unexpected_stops &&
                hookself::platform::IsStoppedStatus(status)) {
                (void)hookself::platform::RawPtrace(PTRACE_CONT, child, 0, 0);
            }
        } else {
            const int error = hookself::platform::RawError(result);
            if (error == ECHILD) {
                return 0;
            }
            if (error != 0 && error != EINTR) {
                return error;
            }
        }
        if (DeadlineReached(deadline_ms)) {
            return ETIMEDOUT;
        }
        const int sleep_error = hookself::platform::SleepForNanoseconds(1000000);
        if (sleep_error != 0 && sleep_error != EINTR) {
            return sleep_error;
        }
    }
}

int KillAndReap(pid_t child, int64_t* result_out,
                int32_t* status_out) noexcept {
    if (child <= 0) {
        return 0;
    }
    const long detach_result = hookself::platform::RawPtrace(
            PTRACE_DETACH, child, 0, 0);
    const int detach_error = hookself::platform::RawError(detach_result);
    (void)detach_error;
    const long kill_result = hookself::platform::RawSyscall6(
            __NR_kill, child, SIGKILL);
    const int kill_error = hookself::platform::RawError(kill_result);
    if (kill_error != 0 && kill_error != ESRCH) {
        return kill_error;
    }
    return WaitForTerminal(child, kWaitTimeoutMs, result_out, status_out, true);
}

[[noreturn]] void RunTraceeChild(ScenarioPipes pipes,
                                 pid_t expected_parent) noexcept {
    CloseFd(&pipes.traceme_gate[1]);
    CloseFd(&pipes.phase[0]);
    CloseFd(&pipes.exec_gate[1]);

    const long parent_result = hookself::platform::RawSyscall6(__NR_getppid);
    if (hookself::platform::RawError(parent_result) != 0 ||
        parent_result != expected_parent) {
        hookself::platform::RawExit(101);
    }

    uint8_t gate = 0;
    if (ReadExactUntil(pipes.traceme_gate[0], &gate, sizeof(gate),
                       kWaitTimeoutMs) != 0) {
        hookself::platform::RawExit(102);
    }
    const long traceme_result = hookself::platform::RawPtrace(
            PTRACE_TRACEME, 0, 0, 0);
    const ChildPhase phase {traceme_result, 1, 0};
    if (WriteExactUntil(pipes.phase[1], &phase, sizeof(phase),
                        kWaitTimeoutMs) != 0 ||
        traceme_result != 0) {
        hookself::platform::RawExit(103);
    }

    if (ReadExactUntil(pipes.exec_gate[0], &gate, sizeof(gate),
                       kWaitTimeoutMs) != 0) {
        hookself::platform::RawExit(104);
    }
    // The first exec is delivered as the legacy SIGTRAP stop. After the
    // parent enables TRACEEXEC and resumes it, sh performs the second exec,
    // which must be surfaced as PTRACE_EVENT_EXEC by the phase-1 bridge.
    char executable[] = "/system/bin/sh";
    char option[] = "-c";
    char command[] = "exec /system/bin/true";
    char* arguments[] = {executable, option, command, nullptr};
    char* environment[] = {nullptr};
    (void)hookself::platform::RawSyscall6(
            __NR_execve, reinterpret_cast<long>(executable),
            reinterpret_cast<long>(arguments),
            reinterpret_cast<long>(environment));
    hookself::platform::RawExit(127);
}

void InitializeScenario(Phase1ScenarioResult* result) noexcept {
    *result = {};
    result->child_pid = -1;
    result->traceme_result = INT64_MIN;
    result->nohang_result = INT64_MIN;
    result->initial_wait_result = INT64_MIN;
    result->setoptions_result = INT64_MIN;
    result->first_cont_result = INT64_MIN;
    result->exec_wait_result = INT64_MIN;
    result->geteventmsg_result = INT64_MIN;
    result->resume_result = INT64_MIN;
    result->exit_result = INT64_MIN;
}

void CloseParentPipeEnds(ScenarioPipes* pipes) noexcept {
    CloseFd(&pipes->traceme_gate[0]);
    CloseFd(&pipes->phase[1]);
    CloseFd(&pipes->exec_gate[0]);
}

void RunPhase1Scenario(HookselfRuntime* runtime, int32_t parent_tid,
                       bool use_waitid, bool detach_after_stop,
                       Phase1ScenarioResult* output) noexcept {
    InitializeScenario(output);
    ScenarioPipes pipes{};
    const int pipe_error = CreateScenarioPipes(&pipes);
    if (pipe_error != 0) {
        output->cleanup_result = pipe_error;
        return;
    }

    const long clone_result = hookself::platform::RawSyscall6(
            __NR_clone, SIGCHLD, 0, 0, 0, 0);
    const int clone_error = hookself::platform::RawError(clone_result);
    if (clone_error != 0 || clone_result < 0 || clone_result > INT32_MAX) {
        output->cleanup_result = clone_error != 0 ? clone_error : EOVERFLOW;
        CloseAllPipes(&pipes);
        return;
    }
    if (clone_result == 0) {
        const pid_t parent = static_cast<pid_t>(
                hookself::platform::RawSyscall6(__NR_getppid));
        RunTraceeChild(pipes, parent);
    }

    const pid_t child = static_cast<pid_t>(clone_result);
    output->child_pid = child;
    CloseParentPipeEnds(&pipes);
    int cleanup_error = 0;
    WaitReleaseContext release_context{};
    pthread_t worker{};
    bool worker_created = false;
    int worker_create_error = 0;

    const int child_event_error = WaitForNewTaskEvent(runtime, child);
    output->new_task_event = child_event_error == 0 ? 1 : 0;
    if (child_event_error != 0) {
        cleanup_error = child_event_error;
        goto cleanup;
    }

    {
        const uint8_t release = 1U;
        const int release_error = WriteExactUntil(
                pipes.traceme_gate[1], &release, sizeof(release), kGateTimeoutMs);
        if (release_error != 0) {
            cleanup_error = release_error;
            goto cleanup;
        }
    }
    {
        ChildPhase phase{};
        const int phase_error = ReadExactUntil(
                pipes.phase[0], &phase, sizeof(phase), kGateTimeoutMs);
        if (phase_error != 0) {
            cleanup_error = phase_error;
            goto cleanup;
        }
        output->traceme_result = phase.traceme_result;
        if (phase.stage != 1 || phase.traceme_result != 0) {
            cleanup_error = EPROTO;
            goto cleanup;
        }
    }

    if (use_waitid) {
        siginfo_t nohang_info{};
        for (size_t index = 0; index < sizeof(nohang_info); ++index) {
            reinterpret_cast<uint8_t*>(&nohang_info)[index] = 0xa5U;
        }
        output->nohang_result = hookself::platform::RawSyscall6(
                __NR_waitid, P_PID, child,
                reinterpret_cast<long>(&nohang_info), WSTOPPED | WNOHANG, 0);
        output->nohang_zero = output->nohang_result == 0 &&
                BytesAreZero(&nohang_info, sizeof(nohang_info)) ? 1 : 0;
        if (output->nohang_zero == 0) {
            cleanup_error = EPROTO;
            goto cleanup;
        }
    }

    DrainEvents(runtime);
    release_context.runtime = runtime;
    release_context.parent_tid = parent_tid;
    release_context.syscall_number = use_waitid ? __NR_waitid : __NR_wait4;
    release_context.exec_gate_fd = pipes.exec_gate[1];
    release_context.release_result = INT_MIN;
    release_context.worker_error = INT_MIN;
    worker_create_error = pthread_create(
            &worker, nullptr, RunWaitReleaseWorker, &release_context);
    if (worker_create_error != 0) {
        cleanup_error = worker_create_error;
        goto cleanup;
    }
    worker_created = true;
    {
        const int worker_start_error = WaitForWorkerStart(release_context);
        if (worker_start_error != 0) {
            (void)pthread_join(worker, nullptr);
            worker_created = false;
            cleanup_error = worker_start_error;
            goto cleanup;
        }
    }

    if (use_waitid) {
        siginfo_t info{};
        output->initial_wait_result = hookself::platform::RawSyscall6(
                __NR_waitid, P_PID, child, reinterpret_cast<long>(&info),
                WSTOPPED, 0);
        output->initial_siginfo_match = output->initial_wait_result == 0 &&
                info.si_signo == SIGCHLD && info.si_pid == child &&
                info.si_code == CLD_TRAPPED && info.si_status == SIGTRAP ? 1 : 0;
        output->initial_signal_stop = output->initial_siginfo_match;
        output->initial_wait_status = info.si_status;
    } else {
        int status = 0;
        output->initial_wait_result = hookself::platform::RawWait4(
                child, &status, 0);
        output->initial_wait_status = status;
        output->initial_signal_stop = output->initial_wait_result == child &&
                IsTrapSignalDeliveryStop(status) ? 1 : 0;
    }
    (void)pthread_join(worker, nullptr);
    worker_created = false;
    output->wait_entry_event = __atomic_load_n(
            &release_context.wait_entry_seen, __ATOMIC_ACQUIRE) != 0U ? 1 : 0;
    output->release_result = release_context.release_result;
    CloseFd(&pipes.exec_gate[1]);
    if (output->initial_wait_result != (use_waitid ? 0 : child) ||
        output->initial_signal_stop == 0 || output->wait_entry_event == 0 ||
        output->release_result != 0) {
        cleanup_error = EPROTO;
        goto cleanup;
    }

    output->setoptions_result = hookself::platform::RawPtrace(
            PTRACE_SETOPTIONS, child, 0,
            static_cast<uintptr_t>(PTRACE_O_TRACEEXEC));
    if (output->setoptions_result != 0) {
        cleanup_error = hookself::platform::RawError(output->setoptions_result);
        if (cleanup_error == 0) {
            cleanup_error = EPROTO;
        }
        goto cleanup;
    }
    output->first_cont_result = hookself::platform::RawPtrace(
            PTRACE_CONT, child, 0, 0);
    if (output->first_cont_result != 0) {
        cleanup_error = hookself::platform::RawError(output->first_cont_result);
        if (cleanup_error == 0) {
            cleanup_error = EPROTO;
        }
        goto cleanup;
    }

    if (use_waitid) {
        siginfo_t info{};
        output->exec_wait_result = hookself::platform::RawSyscall6(
                __NR_waitid, P_PID, child, reinterpret_cast<long>(&info),
                WSTOPPED, 0);
        output->exec_siginfo_match = output->exec_wait_result == 0 &&
                info.si_signo == SIGCHLD && info.si_pid == child &&
                info.si_code == CLD_TRAPPED && info.si_status == SIGTRAP ? 1 : 0;
        output->exec_stop = output->exec_siginfo_match;
        output->exec_wait_status = info.si_status;
    } else {
        int status = 0;
        output->exec_wait_result = hookself::platform::RawWait4(child, &status, 0);
        output->exec_wait_status = status;
        output->exec_stop = output->exec_wait_result == child &&
                IsExecStopStatus(status) ? 1 : 0;
    }
    if (output->exec_wait_result != (use_waitid ? 0 : child) ||
        output->exec_stop == 0) {
        cleanup_error = EPROTO;
        goto cleanup;
    }

    {
        unsigned long event_message = 0;
        output->geteventmsg_result = hookself::platform::RawPtrace(
                PTRACE_GETEVENTMSG, child, 0,
                reinterpret_cast<uintptr_t>(&event_message));
        output->event_message = static_cast<uint64_t>(event_message);
        output->event_message_match =
                output->geteventmsg_result == 0 &&
                EventMessageMatchesLeader(child, output->event_message) ? 1 : 0;
        if (output->event_message_match == 0) {
            cleanup_error = EPROTO;
            goto cleanup;
        }
    }

    output->resume_result = hookself::platform::RawPtrace(
            detach_after_stop ? PTRACE_DETACH : PTRACE_CONT, child, 0, 0);
    if (output->resume_result != 0) {
        cleanup_error = hookself::platform::RawError(output->resume_result);
        if (cleanup_error == 0) {
            cleanup_error = EPROTO;
        }
        goto cleanup;
    }
    {
        const int terminal_error = WaitForTerminal(
                child, kWaitTimeoutMs, &output->exit_result,
                &output->exit_status, false);
        if (terminal_error != 0 || output->exit_result != child ||
            !IsCleanExitStatus(output->exit_status)) {
            cleanup_error = terminal_error != 0 ? terminal_error : EPROTO;
            goto cleanup;
        }
    }
    output->child_pid = child;

cleanup:
    if (worker_created) {
        (void)pthread_join(worker, nullptr);
    }
    if (cleanup_error != 0) {
        int64_t ignored_result = INT64_MIN;
        int32_t ignored_status = 0;
        const int reap_error = KillAndReap(child, &ignored_result, &ignored_status);
        if (output->exit_result == INT64_MIN) {
            output->exit_result = ignored_result;
            output->exit_status = ignored_status;
        }
        output->cleanup_result = reap_error != 0 ? reap_error : cleanup_error;
    }
    CloseAllPipes(&pipes);
}

}  // namespace

NestedPtraceResidentSelfTestReport
RunNestedPtraceResidentSelfTest() noexcept {
    NestedPtraceResidentSelfTestReport report{};
    report.version = kNestedPtraceResidentSelfTestVersion;
    report.wait4_traceme_result = INT64_MIN;
    report.wait4_result = INT64_MIN;
    report.wait4_setoptions_result = INT64_MIN;
    report.wait4_first_cont_result = INT64_MIN;
    report.wait4_exec_result = INT64_MIN;
    report.wait4_geteventmsg_result = INT64_MIN;
    report.wait4_cont_result = INT64_MIN;
    report.wait4_exit_result = INT64_MIN;
    report.waitid_traceme_result = INT64_MIN;
    report.waitid_nohang_result = INT64_MIN;
    report.waitid_result = INT64_MIN;
    report.waitid_setoptions_result = INT64_MIN;
    report.waitid_first_cont_result = INT64_MIN;
    report.waitid_exec_result = INT64_MIN;
    report.waitid_geteventmsg_result = INT64_MIN;
    report.waitid_detach_result = INT64_MIN;
    report.waitid_exit_result = INT64_MIN;

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    // The two phase-1 scenarios run while the instrumentation process has
    // many active threads. Keep their NEW_TASK confirmations out of the
    // lossy public-ring tail generated by unrelated syscall events.
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;
    config.flags = HOOKSELF_CONFIG_CAPTURE_ARGUMENTS |
                   HOOKSELF_CONFIG_CAPTURE_RESULTS |
                   HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                   HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                   HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;
    report.validate_result = hookself_validate_config(&config);
    Check(&report, report.validate_result == HOOKSELF_OK, 1);

    HookselfRuntime* runtime = nullptr;
    if (report.validate_result == HOOKSELF_OK) {
        report.create_result = hookself_create(&config, &runtime);
    } else {
        report.create_result = report.validate_result;
    }
    Check(&report, report.create_result == HOOKSELF_OK && runtime != nullptr, 2);
    if (runtime == nullptr) {
        report.verdict = report.failures == 0U ? 1 : 0;
        return report;
    }

    report.start_result = hookself_start(runtime);
    Check(&report, report.start_result == HOOKSELF_OK, 3);
    if (report.start_result == HOOKSELF_OK) {
        (void)hookself_get_state(runtime, &report.running_state);
        Check(&report, report.running_state == HOOKSELF_STATE_RUNNING_FULL_PTRACE, 4);

        const int32_t parent_tid = static_cast<int32_t>(
                hookself::platform::RawSyscall6(__NR_gettid));
        Phase1ScenarioResult wait4{};
        RunPhase1Scenario(runtime, parent_tid, false, false, &wait4);
        report.wait4_child_pid = wait4.child_pid;
        report.wait4_new_task_event = wait4.new_task_event;
        report.wait4_traceme_result = wait4.traceme_result;
        report.wait4_wait_entry_event = wait4.wait_entry_event;
        report.wait4_release_result = wait4.release_result;
        report.wait4_result = wait4.initial_wait_result;
        report.wait4_status = wait4.initial_wait_status;
        report.wait4_initial_signal_stop = wait4.initial_signal_stop;
        report.wait4_setoptions_result = wait4.setoptions_result;
        report.wait4_first_cont_result = wait4.first_cont_result;
        report.wait4_exec_result = wait4.exec_wait_result;
        report.wait4_exec_status = wait4.exec_wait_status;
        report.wait4_exec_stop = wait4.exec_stop;
        report.wait4_geteventmsg_result = wait4.geteventmsg_result;
        report.wait4_event_message = wait4.event_message;
        report.wait4_event_message_match = wait4.event_message_match;
        report.wait4_cont_result = wait4.resume_result;
        report.wait4_exit_result = wait4.exit_result;
        report.wait4_exit_status = wait4.exit_status;
        report.wait4_cleanup_result = wait4.cleanup_result;
        Check(&report, wait4.child_pid > 0, 10);
        Check(&report, wait4.new_task_event != 0, 11);
        Check(&report, wait4.traceme_result == 0, 12);
        Check(&report, wait4.wait_entry_event != 0, 13);
        Check(&report, wait4.release_result == 0, 14);
        Check(&report, wait4.initial_wait_result == wait4.child_pid, 15);
        Check(&report, wait4.initial_signal_stop != 0, 16);
        Check(&report, wait4.setoptions_result == 0, 17);
        Check(&report, wait4.first_cont_result == 0, 18);
        Check(&report, wait4.exec_wait_result == wait4.child_pid, 19);
        Check(&report, wait4.exec_stop != 0, 20);
        Check(&report, wait4.geteventmsg_result == 0, 21);
        Check(&report, wait4.event_message_match != 0, 22);
        Check(&report, wait4.resume_result == 0, 23);
        Check(&report, wait4.exit_result == wait4.child_pid &&
                       IsCleanExitStatus(wait4.exit_status), 24);
        Check(&report, wait4.cleanup_result == 0, 25);

        int32_t state_before_waitid = 0;
        (void)hookself_get_state(runtime, &state_before_waitid);
        Phase1ScenarioResult waitid{};
        if (state_before_waitid == HOOKSELF_STATE_RUNNING_FULL_PTRACE) {
            RunPhase1Scenario(runtime, parent_tid, true, true, &waitid);
        }
        report.waitid_child_pid = waitid.child_pid;
        report.waitid_new_task_event = waitid.new_task_event;
        report.waitid_traceme_result = waitid.traceme_result;
        report.waitid_nohang_result = waitid.nohang_result;
        report.waitid_nohang_zero = waitid.nohang_zero;
        report.waitid_wait_entry_event = waitid.wait_entry_event;
        report.waitid_release_result = waitid.release_result;
        report.waitid_result = waitid.initial_wait_result;
        report.waitid_initial_siginfo_match = waitid.initial_siginfo_match;
        report.waitid_setoptions_result = waitid.setoptions_result;
        report.waitid_first_cont_result = waitid.first_cont_result;
        report.waitid_exec_result = waitid.exec_wait_result;
        report.waitid_exec_siginfo_match = waitid.exec_siginfo_match;
        report.waitid_geteventmsg_result = waitid.geteventmsg_result;
        report.waitid_event_message = waitid.event_message;
        report.waitid_event_message_match = waitid.event_message_match;
        report.waitid_detach_result = waitid.resume_result;
        report.waitid_exit_result = waitid.exit_result;
        report.waitid_exit_status = waitid.exit_status;
        report.waitid_cleanup_result = waitid.cleanup_result;
        Check(&report, waitid.child_pid > 0, 30);
        Check(&report, waitid.new_task_event != 0, 31);
        Check(&report, waitid.traceme_result == 0, 32);
        Check(&report, waitid.nohang_result == 0 && waitid.nohang_zero != 0, 33);
        Check(&report, waitid.wait_entry_event != 0, 34);
        Check(&report, waitid.release_result == 0, 35);
        Check(&report, waitid.initial_wait_result == 0 &&
                       waitid.initial_siginfo_match != 0, 36);
        Check(&report, waitid.setoptions_result == 0, 37);
        Check(&report, waitid.first_cont_result == 0, 38);
        Check(&report, waitid.exec_wait_result == 0 &&
                       waitid.exec_siginfo_match != 0, 39);
        Check(&report, waitid.geteventmsg_result == 0, 40);
        Check(&report, waitid.event_message_match != 0, 41);
        Check(&report, waitid.resume_result == 0, 42);
        Check(&report, waitid.exit_result == waitid.child_pid &&
                       IsCleanExitStatus(waitid.exit_status), 43);
        Check(&report, waitid.cleanup_result == 0, 44);

        HookselfStats stats{};
        stats.struct_size = sizeof(stats);
        report.stats_result = hookself_get_stats(runtime, &stats);
        report.fatal_code = stats.fatal_code;
        report.fatal_errno = stats.fatal_errno;
        report.dropped_events = stats.dropped_events;
        Check(&report, report.stats_result == HOOKSELF_OK, 50);
        Check(&report, report.fatal_code == HOOKSELF_FATAL_NONE, 51);
        Check(&report, report.dropped_events == 0U, 52);
    }

    report.stop_result = hookself_stop(runtime);
    if (report.start_result == HOOKSELF_OK) {
        Check(&report, report.stop_result == HOOKSELF_OK, 60);
    }
    (void)hookself_get_state(runtime, &report.stopped_state);
    if (report.stop_result == HOOKSELF_OK) {
        Check(&report, report.stopped_state == HOOKSELF_STATE_STOPPED, 61);
    }
    hookself_destroy(runtime);
    report.verdict = report.failures == 0U ? 1 : 0;
    return report;
}

}  // namespace hookself::internal
