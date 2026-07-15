#include "self_trace_probe.h"
#include "path_policy.h"

#include <android/api-level.h>
#include <android/log.h>
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <sstream>
#include <string>

#if !defined(__aarch64__)
#error "The M0 ptrace probe currently supports arm64-v8a only."
#endif

namespace hookself {
namespace {

constexpr char kLogTag[] = "HookSelfM0";
constexpr char kM1LogTag[] = "HookSelfM1";
constexpr char kM2LogTag[] = "HookSelfM2";
constexpr uint32_t kReportMagic = 0x4d305054;  // M0PT
constexpr uint32_t kM1ReportMagic = 0x4d315054;  // M1PT
constexpr uint32_t kM2ReportMagic = 0x4d325054;  // M2PT
constexpr uint32_t kReportVersion = 1;
constexpr int kMaxTasks = 512;
constexpr int kReportedTasks = 96;
constexpr int kMaxAttachRounds = 10;
constexpr int64_t kChildDeadlineMs = 5000;
constexpr int64_t kDetachRetryMs = 250;
constexpr uint64_t kCanaryOriginal = 0x1122334455667788ULL;
constexpr uint64_t kCanaryVmWrite = 0x2233445566778899ULL;
constexpr uint64_t kCanaryPtraceWrite = 0x33445566778899aaULL;
constexpr uint64_t kScratchGuardBefore = 0x4d32475541524431ULL;
constexpr uint64_t kScratchGuardAfter = 0x4d32475541524432ULL;
constexpr int32_t kM2BroadRuleId = 1;
constexpr int32_t kM2ExactRuleId = 2;

constexpr long kPtracePeekData = 2;
constexpr long kPtracePokeData = 5;
constexpr long kPtraceDetach = 17;
constexpr long kPtraceSyscall = 24;
constexpr long kPtraceGetRegSet = 0x4204;
constexpr long kPtraceSetRegSet = 0x4205;
constexpr long kPtraceSeize = 0x4206;
constexpr long kPtraceInterrupt = 0x4207;
constexpr unsigned long kPtraceOTraceSysgood = 0x00000001;
constexpr unsigned int kPtraceEventStop = 128;
constexpr unsigned long kNtPrStatus = 1;
constexpr unsigned long kNtArmSystemCall = 0x404;
constexpr int kWaitWall = 0x40000000;
constexpr int kPrSetPtracer = 0x59616d61;

enum class Verdict : int32_t {
    kNotRun = 0,
    kPassFull = 1,
    kPassAttachOnly = 2,
    kPartial = 3,
    kBlocked = 4,
    kInternalError = 5,
};

enum class FatalStep : int32_t {
    kNone = 0,
    kParentChanged = 1,
    kTaskEnumeration = 2,
    kTaskTableFull = 3,
    kStopTimeout = 4,
    kCoverageIncomplete = 5,
};

enum TaskFlags : uint32_t {
    kTaskSeenCurrent = 1U << 0,
    kTaskSeizeAttempted = 1U << 1,
    kTaskSeized = 1U << 2,
    kTaskInterruptSent = 1U << 3,
    kTaskStopped = 1U << 4,
    kTaskRegsRead = 1U << 5,
    kTaskDead = 1U << 6,
    kTaskDetached = 1U << 7,
    kTaskEverStopped = 1U << 8,
};

struct Arm64Regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static_assert(sizeof(Arm64Regs) == 272, "Unexpected arm64 register layout");

struct TaskState {
    int32_t tid;
    uint32_t flags;
    int32_t seize_errno;
    int32_t interrupt_errno;
    int32_t wait_status;
    int32_t pending_signal;
    int32_t getregset_errno;
    int32_t detach_errno;
    uint64_t pc;
    uint64_t sp;
    int64_t syscall_no;
};

struct TaskReport {
    int32_t tid;
    uint32_t flags;
    int32_t seize_errno;
    int32_t interrupt_errno;
    int32_t wait_status;
    int32_t getregset_errno;
    int32_t detach_errno;
};

struct ChildReport {
    uint32_t magic;
    uint32_t version;
    int32_t verdict;
    int32_t fatal_step;
    int32_t fatal_errno;
    int32_t target_pid;
    int32_t tracer_pid;
    int32_t bootstrap_tid;
    int32_t scan_rounds;
    int32_t final_discovered_tids;
    int32_t tracked_tasks;
    int32_t attached_tids;
    int32_t stopped_tids;
    int32_t regset_tids;
    int32_t detached_tids;
    int32_t attach_failures;
    int32_t detach_failures;
    int32_t identity_setreg_errno;
    int32_t arm_syscall_get_errno;
    int32_t arm_syscall_set_errno;
    int32_t vm_read_errno;
    int32_t vm_write_errno;
    int32_t vm_read_bytes;
    int32_t vm_write_bytes;
    int32_t peek_errno;
    int32_t poke_errno;
    int32_t memory_restored;
    int32_t report_task_count;
    uint64_t vm_read_value;
    uint64_t first_pc;
    uint64_t first_sp;
    int64_t first_syscall_no;
    TaskReport tasks[kReportedTasks];
};

enum class M1Verdict : int32_t {
    kNotRun = 0,
    kPass = 1,
    kPartial = 2,
    kBlocked = 3,
    kInternalError = 4,
};

struct ObservedSyscall {
    int32_t syscall_no;
    int32_t entry_seen;
    int32_t exit_seen;
    int32_t register_errno;
    int32_t path_errno;
    int32_t reserved;
    uint64_t args[6];
    int64_t result;
    char path[160];
};

struct M1Report {
    uint32_t magic;
    uint32_t version;
    int32_t verdict;
    int32_t fatal_errno;
    int32_t target_pid;
    int32_t tracer_pid;
    int32_t bootstrap_tid;
    int32_t discovered_tids;
    int32_t attached_tids;
    int32_t detached_tids;
    int32_t attach_failures;
    int32_t detach_failures;
    int32_t syscall_stops;
    int32_t signal_stops;
    int32_t unexpected_stops;
    int32_t ready_sent;
    int32_t tests_done_seen;
    int32_t event_loop_errno;
    int32_t transaction_phase;
    ObservedSyscall getpid_call;
    ObservedSyscall gettid_call;
    ObservedSyscall openat_call;
};

enum class M2Verdict : int32_t {
    kNotRun = 0,
    kPass = 1,
    kPartial = 2,
    kBlocked = 3,
    kInternalError = 4,
};

enum class M2Scenario : int32_t {
    kRedirectExisting = 0,
    kRedirectMissing = 1,
};

struct M2Report {
    uint32_t magic;
    uint32_t version;
    int32_t verdict;
    int32_t scenario;
    int32_t expected_errno;
    int32_t missing_target_observed;
    int32_t fatal_errno;
    int32_t target_pid;
    int32_t tracer_pid;
    int32_t bootstrap_tid;
    int32_t discovered_tids;
    int32_t attached_tids;
    int32_t detached_tids;
    int32_t attach_failures;
    int32_t detach_failures;
    int32_t syscall_stops;
    int32_t signal_stops;
    int32_t unexpected_stops;
    int32_t event_loop_errno;
    int32_t transaction_phase;
    int32_t entry_seen;
    int32_t exit_seen;
    int32_t entry_setreg_errno;
    int32_t entry_verify_errno;
    int32_t entry_syscall_verify_errno;
    int32_t entry_registers_verified;
    int32_t entry_syscall_verified;
    int32_t entry_args_verified;
    int32_t exit_setreg_errno;
    int32_t exit_verify_errno;
    int32_t exit_syscall_verify_errno;
    int32_t exit_registers_verified;
    int32_t exit_syscall_verified;
    int32_t exit_user_x8_verified;
    int32_t exit_redirect_seen;
    int32_t rewrite_active;
    int32_t rollback_attempted;
    int32_t rollback_errno;
    int32_t rollback_verified;
    int32_t orphan_cleanup_errno;
    int32_t unexpected_cleanup_failures;
    int32_t policy_action;
    int32_t policy_errno;
    int32_t policy_rule_id;
    int32_t policy_boundary_pass;
    int32_t policy_longest_match;
    int32_t original_path_read_only;
    int32_t original_path_memory_unchanged;
    int32_t original_path_errno;
    int32_t redirected_path_errno;
    int32_t scratch_write_len;
    int32_t scratch_guards_ok;
    int64_t result;
    uint64_t original_pointer;
    uint64_t redirected_pointer;
    char original_path[path_policy::kPathCapacity];
    char redirected_path[path_policy::kPathCapacity];
};

struct SharedProbe {
    ChildReport report;
    M1Report m1_report;
    uint32_t m1_stage;
    int64_t m1_expected_getpid;
    int64_t m1_expected_gettid;
    int64_t m1_expected_openat;
    M2Report m2_report;
    uint32_t m2_stage;
    int32_t m2_parent_content_ok;
    int64_t m2_expected_openat;
    char m2_source_path[512];
    char m2_redirect_path[512];
    char m2_near_prefix_path[512];
    int32_t m2_rule_count;
    path_policy::PrefixRule m2_rules[2];
    uint64_t m2_scratch_guard_before;
    char m2_scratch[512];
    uint64_t m2_scratch_guard_after;
    Arm64Regs m2_rollback_regs;
    int32_t m2_rollback_snapshot_valid;
    int32_t m2_rollback_syscall_valid;
    int32_t m2_rollback_syscall_number;
    int32_t task_count;
    TaskState tasks[kMaxTasks];
};

struct ParentOutcome {
    int32_t target_pid = 0;
    int32_t bootstrap_tid = 0;
    int32_t tracer_pid_before = 0;
    int32_t threads_before = 0;
    int32_t original_dumpable = -1;
    int32_t get_dumpable_errno = 0;
    int32_t set_dumpable_errno = 0;
    int32_t set_ptracer_errno = 0;
    int32_t ptracer_set = 0;
    int32_t clear_ptracer_errno = 0;
    int32_t restore_dumpable_errno = 0;
    int32_t restored_dumpable = 0;
    int32_t done_received = 0;
    int32_t parent_timeout = 0;
    int32_t tracer_exit_status = -1;
    int32_t parent_memory_restored = 0;
    int32_t api_level = 0;
    std::string kernel;
    std::string selinux_context;
    std::string yama_scope;
};

struct LinuxDirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[0];
};

static std::atomic_flag g_probe_running = ATOMIC_FLAG_INIT;
static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr),
              "M1 shared stage must be lock-free");

inline long RawSyscall6(long number, long arg0 = 0, long arg1 = 0, long arg2 = 0,
                        long arg3 = 0, long arg4 = 0, long arg5 = 0) {
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    register long x5 asm("x5") = arg5;
    register long x8 asm("x8") = number;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                 : "memory");
    return x0;
}

inline int RawError(long result) {
    return (result < 0 && result >= -4095) ? static_cast<int>(-result) : 0;
}

inline long RawPtrace(long request, pid_t tid, uintptr_t address, uintptr_t data) {
    return RawSyscall6(__NR_ptrace, request, tid, static_cast<long>(address),
                       static_cast<long>(data));
}

int RawPeekData(pid_t tid, uintptr_t address, uint64_t* value) {
    unsigned long output = 0;
    const long result = RawPtrace(kPtracePeekData, tid, address,
                                  reinterpret_cast<uintptr_t>(&output));
    const int error = RawError(result);
    if (error == 0) {
        *value = static_cast<uint64_t>(output);
    }
    return error;
}

inline long RawClose(int fd) {
    return RawSyscall6(__NR_close, fd);
}

inline long RawRead(int fd, void* buffer, size_t size) {
    return RawSyscall6(__NR_read, fd, reinterpret_cast<long>(buffer), static_cast<long>(size));
}

inline long RawWrite(int fd, const void* buffer, size_t size) {
    return RawSyscall6(__NR_write, fd, reinterpret_cast<long>(buffer), static_cast<long>(size));
}

inline int64_t RawNowMs() {
    timespec value{};
    const long result = RawSyscall6(__NR_clock_gettime, CLOCK_MONOTONIC,
                                    reinterpret_cast<long>(&value));
    if (result < 0) {
        return -1;
    }
    return static_cast<int64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}

inline void RawSleepOneMillisecond() {
    timespec value{};
    value.tv_nsec = 1000000;
    RawSyscall6(__NR_nanosleep, reinterpret_cast<long>(&value), 0);
}

[[noreturn]] void RawExit(int status) {
    RawSyscall6(__NR_exit_group, status);
    __builtin_unreachable();
}

bool IsStoppedStatus(int status) {
    return (status & 0xff) == 0x7f;
}

bool IsExitedStatus(int status) {
    return (status & 0x7f) == 0;
}

bool IsSignaledStatus(int status) {
    const int signal = status & 0x7f;
    return signal != 0 && signal != 0x7f;
}

int StopSignal(int status) {
    return (status >> 8) & 0xff;
}

unsigned int PtraceEvent(int status) {
    return static_cast<unsigned int>(status) >> 16;
}

TaskState* FindTask(SharedProbe* shared, pid_t tid) {
    for (int i = 0; i < shared->task_count; ++i) {
        if (shared->tasks[i].tid == tid) {
            return &shared->tasks[i];
        }
    }
    return nullptr;
}

TaskState* AddTask(SharedProbe* shared, pid_t tid) {
    TaskState* existing = FindTask(shared, tid);
    if (existing != nullptr) {
        return existing;
    }
    if (shared->task_count >= kMaxTasks) {
        return nullptr;
    }
    TaskState* task = &shared->tasks[shared->task_count++];
    task->tid = tid;
    task->flags = 0;
    task->seize_errno = 0;
    task->interrupt_errno = 0;
    task->wait_status = 0;
    task->pending_signal = 0;
    task->getregset_errno = 0;
    task->detach_errno = 0;
    task->pc = 0;
    task->sp = 0;
    task->syscall_no = -1;
    return task;
}

bool AppendDecimal(char* output, size_t capacity, size_t* length, pid_t value) {
    char reversed[16];
    size_t count = 0;
    unsigned int current = static_cast<unsigned int>(value);
    do {
        reversed[count++] = static_cast<char>('0' + current % 10);
        current /= 10;
    } while (current != 0 && count < sizeof(reversed));
    if (*length + count >= capacity) {
        return false;
    }
    while (count > 0) {
        output[(*length)++] = reversed[--count];
    }
    output[*length] = '\0';
    return true;
}

bool BuildTaskPath(pid_t pid, char output[64]) {
    constexpr char prefix[] = "/proc/";
    constexpr char suffix[] = "/task";
    size_t length = 0;
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
        output[length++] = prefix[i];
    }
    if (!AppendDecimal(output, 64, &length, pid)) {
        return false;
    }
    if (length + sizeof(suffix) >= 64) {
        return false;
    }
    for (size_t i = 0; i < sizeof(suffix); ++i) {
        output[length++] = suffix[i];
    }
    return true;
}

bool ParsePositivePid(const char* text, pid_t* result) {
    if (text[0] == '\0') {
        return false;
    }
    int64_t value = 0;
    for (size_t i = 0; text[i] != '\0'; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
        value = value * 10 + (text[i] - '0');
        if (value > INT32_MAX) {
            return false;
        }
    }
    if (value <= 0) {
        return false;
    }
    *result = static_cast<pid_t>(value);
    return true;
}

int EnumerateTids(pid_t target_pid, pid_t* tids, int capacity, int* error) {
    char path[64];
    if (!BuildTaskPath(target_pid, path)) {
        *error = ENAMETOOLONG;
        return -1;
    }
    const long fd_result = RawSyscall6(__NR_openat, AT_FDCWD, reinterpret_cast<long>(path),
                                       O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd_result < 0) {
        *error = RawError(fd_result);
        return -1;
    }
    const int fd = static_cast<int>(fd_result);
    alignas(8) char buffer[8192];
    int count = 0;
    for (;;) {
        const long bytes = RawSyscall6(__NR_getdents64, fd, reinterpret_cast<long>(buffer),
                                       sizeof(buffer));
        if (bytes == 0) {
            break;
        }
        if (bytes < 0) {
            *error = RawError(bytes);
            RawClose(fd);
            return -1;
        }
        long offset = 0;
        while (offset < bytes) {
            auto* entry = reinterpret_cast<LinuxDirent64*>(buffer + offset);
            if (entry->d_reclen < offsetof(LinuxDirent64, d_name) + 2 ||
                offset + entry->d_reclen > bytes) {
                *error = EIO;
                RawClose(fd);
                return -1;
            }
            pid_t tid = 0;
            if (ParsePositivePid(entry->d_name, &tid)) {
                if (count >= capacity) {
                    *error = EOVERFLOW;
                    RawClose(fd);
                    return -1;
                }
                tids[count++] = tid;
            }
            offset += entry->d_reclen;
        }
    }
    RawClose(fd);
    *error = 0;
    return count;
}

void HandleWaitStatus(SharedProbe* shared, pid_t tid, int status) {
    TaskState* task = FindTask(shared, tid);
    if (task == nullptr) {
        task = AddTask(shared, tid);
        if (task == nullptr) {
            shared->report.fatal_step = static_cast<int32_t>(FatalStep::kTaskTableFull);
            shared->report.fatal_errno = EOVERFLOW;
            return;
        }
        task->flags |= kTaskSeized;
    }
    task->wait_status = status;
    if (IsStoppedStatus(status)) {
        task->flags |= kTaskStopped | kTaskEverStopped;
        const int signal = StopSignal(status);
        const unsigned int event = PtraceEvent(status);
        if (signal == (SIGTRAP | 0x80)) {
            task->pending_signal = 0;
        } else if (event == kPtraceEventStop) {
            task->pending_signal = signal == SIGTRAP ? 0 : signal;
        } else {
            task->pending_signal = signal;
        }
    } else if (IsExitedStatus(status) || IsSignaledStatus(status)) {
        task->flags |= kTaskDead;
        task->flags &= ~kTaskStopped;
        task->pending_signal = 0;
    }
}

bool AllSeizedTasksStopped(const SharedProbe* shared) {
    for (int i = 0; i < shared->task_count; ++i) {
        const TaskState& task = shared->tasks[i];
        if ((task.flags & kTaskSeized) != 0 && (task.flags & kTaskDead) == 0 &&
            (task.flags & kTaskStopped) == 0) {
            return false;
        }
    }
    return true;
}

int DrainWaitUntilStopped(SharedProbe* shared, int64_t deadline_ms) {
    for (;;) {
        bool received = false;
        for (;;) {
            int status = 0;
            const long waited = RawSyscall6(__NR_wait4, -1, reinterpret_cast<long>(&status),
                                            kWaitWall | WNOHANG, 0);
            if (waited > 0) {
                received = true;
                HandleWaitStatus(shared, static_cast<pid_t>(waited), status);
                continue;
            }
            if (waited == 0 || RawError(waited) == ECHILD) {
                break;
            }
            if (RawError(waited) == EINTR) {
                continue;
            }
            return RawError(waited);
        }
        if (AllSeizedTasksStopped(shared)) {
            return 0;
        }
        const int64_t now = RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        if (!received) {
            RawSleepOneMillisecond();
        }
    }
}

bool CurrentCoverageComplete(SharedProbe* shared, const pid_t* tids, int count) {
    for (int i = 0; i < count; ++i) {
        TaskState* task = FindTask(shared, tids[i]);
        if (task == nullptr || (task->flags & kTaskSeized) == 0 ||
            (task->flags & kTaskStopped) == 0 || (task->flags & kTaskDead) != 0) {
            return false;
        }
    }
    return true;
}

int AttachAllCurrentTasks(SharedProbe* shared, pid_t target_pid, int64_t deadline_ms) {
    pid_t tids[kMaxTasks];
    int stable_rounds = 0;
    for (int round = 0; round < kMaxAttachRounds; ++round) {
        shared->report.scan_rounds = round + 1;
        for (int i = 0; i < shared->task_count; ++i) {
            shared->tasks[i].flags &= ~kTaskSeenCurrent;
        }

        int enumerate_errno = 0;
        const int count = EnumerateTids(target_pid, tids, kMaxTasks, &enumerate_errno);
        if (count < 0) {
            shared->report.fatal_step = static_cast<int32_t>(FatalStep::kTaskEnumeration);
            shared->report.fatal_errno = enumerate_errno;
            return -1;
        }
        shared->report.final_discovered_tids = count;
        int new_tasks = 0;
        for (int i = 0; i < count; ++i) {
            TaskState* task = FindTask(shared, tids[i]);
            if (task == nullptr) {
                task = AddTask(shared, tids[i]);
                if (task == nullptr) {
                    shared->report.fatal_step = static_cast<int32_t>(FatalStep::kTaskTableFull);
                    shared->report.fatal_errno = EOVERFLOW;
                    return -1;
                }
                ++new_tasks;
            }
            task->flags |= kTaskSeenCurrent;
            if ((task->flags & kTaskSeizeAttempted) == 0) {
                task->flags |= kTaskSeizeAttempted;
                const long result = RawPtrace(kPtraceSeize, task->tid, 0,
                                              kPtraceOTraceSysgood);
                if (result == 0) {
                    task->flags |= kTaskSeized;
                } else {
                    task->seize_errno = RawError(result);
                }
            }
        }

        for (int i = 0; i < shared->task_count; ++i) {
            TaskState& task = shared->tasks[i];
            if ((task.flags & kTaskSeized) == 0 || (task.flags & kTaskStopped) != 0 ||
                (task.flags & kTaskDead) != 0 || (task.flags & kTaskInterruptSent) != 0) {
                continue;
            }
            const long result = RawPtrace(kPtraceInterrupt, task.tid, 0, 0);
            if (result == 0) {
                task.flags |= kTaskInterruptSent;
            } else {
                task.interrupt_errno = RawError(result);
            }
        }

        const int wait_error = DrainWaitUntilStopped(shared, deadline_ms);
        if (wait_error != 0) {
            shared->report.fatal_step = static_cast<int32_t>(FatalStep::kStopTimeout);
            shared->report.fatal_errno = wait_error;
            return -1;
        }

        if (new_tasks == 0 && CurrentCoverageComplete(shared, tids, count)) {
            ++stable_rounds;
            if (stable_rounds >= 2) {
                return 0;
            }
        } else {
            stable_rounds = 0;
        }
        if (RawNowMs() >= deadline_ms) {
            shared->report.fatal_step = static_cast<int32_t>(FatalStep::kStopTimeout);
            shared->report.fatal_errno = ETIMEDOUT;
            return -1;
        }
    }
    shared->report.fatal_step = static_cast<int32_t>(FatalStep::kCoverageIncomplete);
    shared->report.fatal_errno = EAGAIN;
    return -1;
}

void ProbeRegisters(SharedProbe* shared, pid_t preferred_tid) {
    TaskState* identity_task = FindTask(shared, preferred_tid);
    if (identity_task == nullptr || (identity_task->flags & kTaskStopped) == 0) {
        identity_task = FindTask(shared, shared->report.target_pid);
    }

    bool first = true;
    Arm64Regs identity_regs{};
    bool have_identity_regs = false;
    for (int i = 0; i < shared->task_count; ++i) {
        TaskState& task = shared->tasks[i];
        if ((task.flags & kTaskSeenCurrent) == 0 || (task.flags & kTaskStopped) == 0 ||
            (task.flags & kTaskDead) != 0) {
            continue;
        }
        Arm64Regs regs{};
        iovec vector{&regs, sizeof(regs)};
        const long result = RawPtrace(kPtraceGetRegSet, task.tid, kNtPrStatus,
                                      reinterpret_cast<uintptr_t>(&vector));
        if (result == 0 && vector.iov_len == sizeof(regs)) {
            task.flags |= kTaskRegsRead;
            task.pc = regs.pc;
            task.sp = regs.sp;
            task.syscall_no = static_cast<int64_t>(regs.regs[8]);
            if (first) {
                shared->report.first_pc = regs.pc;
                shared->report.first_sp = regs.sp;
                shared->report.first_syscall_no = task.syscall_no;
                first = false;
            }
            if (identity_task == &task) {
                identity_regs = regs;
                have_identity_regs = true;
            }
        } else {
            task.getregset_errno = result == 0 ? EIO : RawError(result);
        }
    }

    shared->report.identity_setreg_errno = ENOENT;
    shared->report.arm_syscall_get_errno = ENOENT;
    shared->report.arm_syscall_set_errno = ENOENT;
    if (identity_task != nullptr && have_identity_regs) {
        iovec vector{&identity_regs, sizeof(identity_regs)};
        const long set_result = RawPtrace(kPtraceSetRegSet, identity_task->tid, kNtPrStatus,
                                          reinterpret_cast<uintptr_t>(&vector));
        shared->report.identity_setreg_errno = RawError(set_result);

        int32_t syscall_number = 0;
        iovec syscall_vector{&syscall_number, sizeof(syscall_number)};
        const long get_syscall = RawPtrace(kPtraceGetRegSet, identity_task->tid,
                                           kNtArmSystemCall,
                                           reinterpret_cast<uintptr_t>(&syscall_vector));
        shared->report.arm_syscall_get_errno = RawError(get_syscall);
        if (get_syscall == 0 && syscall_vector.iov_len == sizeof(syscall_number)) {
            syscall_vector.iov_len = sizeof(syscall_number);
            const long set_syscall = RawPtrace(kPtraceSetRegSet, identity_task->tid,
                                               kNtArmSystemCall,
                                               reinterpret_cast<uintptr_t>(&syscall_vector));
            shared->report.arm_syscall_set_errno = RawError(set_syscall);
        }
    }
}

void ProbeMemory(SharedProbe* shared, void* remote_canary) {
    const pid_t target_pid = shared->report.target_pid;
    const pid_t memory_tid = target_pid;
    uint64_t local_value = 0;
    iovec local{&local_value, sizeof(local_value)};
    iovec remote{remote_canary, sizeof(local_value)};

    const long read_result = RawSyscall6(__NR_process_vm_readv, target_pid,
                                         reinterpret_cast<long>(&local), 1,
                                         reinterpret_cast<long>(&remote), 1, 0);
    shared->report.vm_read_errno = RawError(read_result);
    shared->report.vm_read_bytes = read_result > 0 ? static_cast<int32_t>(read_result) : 0;
    shared->report.vm_read_value = local_value;

    uint64_t vm_write_value = kCanaryVmWrite;
    local.iov_base = &vm_write_value;
    const long write_result = RawSyscall6(__NR_process_vm_writev, target_pid,
                                          reinterpret_cast<long>(&local), 1,
                                          reinterpret_cast<long>(&remote), 1, 0);
    shared->report.vm_write_errno = RawError(write_result);
    shared->report.vm_write_bytes = write_result > 0 ? static_cast<int32_t>(write_result) : 0;

    const uint64_t expected_after_vm = write_result == static_cast<long>(sizeof(uint64_t))
                                           ? kCanaryVmWrite
                                           : kCanaryOriginal;
    uint64_t peek_value = 0;
    shared->report.peek_errno = RawPeekData(memory_tid,
                                            reinterpret_cast<uintptr_t>(remote_canary),
                                            &peek_value);
    if (shared->report.peek_errno == 0 && peek_value != expected_after_vm) {
        shared->report.peek_errno = EIO;
    }

    const long poke_result = RawPtrace(kPtracePokeData, memory_tid,
                                       reinterpret_cast<uintptr_t>(remote_canary),
                                       static_cast<uintptr_t>(kCanaryPtraceWrite));
    shared->report.poke_errno = RawError(poke_result);
    if (poke_result == 0) {
        uint64_t verify = 0;
        if (RawPeekData(memory_tid, reinterpret_cast<uintptr_t>(remote_canary), &verify) != 0 ||
            verify != kCanaryPtraceWrite) {
            shared->report.poke_errno = EIO;
        }
    }

    RawPtrace(kPtracePokeData, memory_tid, reinterpret_cast<uintptr_t>(remote_canary),
              static_cast<uintptr_t>(kCanaryOriginal));
    uint64_t restore_value = kCanaryOriginal;
    local.iov_base = &restore_value;
    RawSyscall6(__NR_process_vm_writev, target_pid, reinterpret_cast<long>(&local), 1,
                reinterpret_cast<long>(&remote), 1, 0);
    uint64_t restored_value = 0;
    local.iov_base = &restored_value;
    const long restored_read = RawSyscall6(__NR_process_vm_readv, target_pid,
                                            reinterpret_cast<long>(&local), 1,
                                            reinterpret_cast<long>(&remote), 1, 0);
    if (restored_read == static_cast<long>(sizeof(restored_value))) {
        shared->report.memory_restored = restored_value == kCanaryOriginal ? 1 : 0;
    } else {
        const int restored_error = RawPeekData(memory_tid,
                                               reinterpret_cast<uintptr_t>(remote_canary),
                                               &restored_value);
        shared->report.memory_restored =
                restored_error == 0 && restored_value == kCanaryOriginal ? 1 : 0;
    }
}

void RetryStopForDetach(SharedProbe* shared, TaskState* task, int64_t deadline_ms) {
    if ((task->flags & kTaskStopped) != 0 || (task->flags & kTaskDead) != 0) {
        return;
    }
    RawPtrace(kPtraceInterrupt, task->tid, 0, 0);
    while (RawNowMs() < deadline_ms) {
        int status = 0;
        const long waited = RawSyscall6(__NR_wait4, task->tid, reinterpret_cast<long>(&status),
                                        kWaitWall | WNOHANG, 0);
        if (waited == task->tid) {
            HandleWaitStatus(shared, task->tid, status);
            return;
        }
        if (waited < 0 && RawError(waited) == ECHILD) {
            task->flags |= kTaskDead;
            return;
        }
        RawSleepOneMillisecond();
    }
}

void DetachOne(SharedProbe* shared, TaskState* task) {
    if ((task->flags & kTaskSeized) == 0 || (task->flags & kTaskDetached) != 0 ||
        (task->flags & kTaskDead) != 0) {
        return;
    }
    RetryStopForDetach(shared, task, RawNowMs() + kDetachRetryMs);
    if ((task->flags & kTaskDead) != 0) {
        return;
    }
    const long result = RawPtrace(kPtraceDetach, task->tid, 0,
                                  static_cast<uintptr_t>(task->pending_signal));
    if (result == 0) {
        task->flags |= kTaskDetached;
        task->flags &= ~kTaskStopped;
        task->detach_errno = 0;
    } else {
        task->detach_errno = RawError(result);
        if (task->detach_errno == ESRCH) {
            const long alive = RawSyscall6(__NR_tgkill, shared->report.target_pid,
                                           task->tid, 0);
            if (RawError(alive) == ESRCH) {
                task->flags |= kTaskDead;
            }
        }
    }
}

void DetachAll(SharedProbe* shared, pid_t preferred_last_tid = 0) {
    for (int i = shared->task_count - 1; i >= 0; --i) {
        if (shared->tasks[i].tid != shared->report.target_pid &&
            shared->tasks[i].tid != preferred_last_tid) {
            DetachOne(shared, &shared->tasks[i]);
        }
    }
    TaskState* leader = FindTask(shared, shared->report.target_pid);
    if (leader != nullptr && leader->tid != preferred_last_tid) {
        DetachOne(shared, leader);
    }
    TaskState* preferred = FindTask(shared, preferred_last_tid);
    if (preferred != nullptr) {
        DetachOne(shared, preferred);
    }
}

void SummarizeTasks(SharedProbe* shared) {
    ChildReport& report = shared->report;
    report.tracked_tasks = shared->task_count;
    report.attached_tids = 0;
    report.stopped_tids = 0;
    report.regset_tids = 0;
    report.detached_tids = 0;
    report.attach_failures = 0;
    report.detach_failures = 0;
    report.report_task_count = shared->task_count < kReportedTasks
                                   ? shared->task_count
                                   : kReportedTasks;
    for (int i = 0; i < shared->task_count; ++i) {
        const TaskState& task = shared->tasks[i];
        if ((task.flags & kTaskSeenCurrent) != 0 && (task.flags & kTaskSeized) != 0) {
            ++report.attached_tids;
        }
        if ((task.flags & kTaskSeenCurrent) != 0 && (task.flags & kTaskEverStopped) != 0) {
            ++report.stopped_tids;
        }
        if ((task.flags & kTaskSeenCurrent) != 0 && (task.flags & kTaskRegsRead) != 0) {
            ++report.regset_tids;
        }
        if ((task.flags & kTaskSeenCurrent) != 0 &&
            ((task.flags & kTaskDetached) != 0 || (task.flags & kTaskDead) != 0)) {
            ++report.detached_tids;
        }
        if ((task.flags & kTaskSeenCurrent) != 0 && (task.flags & kTaskSeized) == 0) {
            ++report.attach_failures;
        }
        if ((task.flags & kTaskSeenCurrent) != 0 && (task.flags & kTaskSeized) != 0 &&
            (task.flags & kTaskDetached) == 0 && (task.flags & kTaskDead) == 0) {
            ++report.detach_failures;
        }
        if (i < kReportedTasks) {
            TaskReport& output = report.tasks[i];
            output.tid = task.tid;
            output.flags = task.flags;
            output.seize_errno = task.seize_errno;
            output.interrupt_errno = task.interrupt_errno;
            output.wait_status = task.wait_status;
            output.getregset_errno = task.getregset_errno;
            output.detach_errno = task.detach_errno;
        }
    }
}

void DecideVerdict(SharedProbe* shared) {
    ChildReport& report = shared->report;
    TaskState* leader = FindTask(shared, report.target_pid);
    if (leader == nullptr || (leader->flags & kTaskSeized) == 0) {
        report.verdict = static_cast<int32_t>(Verdict::kBlocked);
        return;
    }
    const bool full_coverage = report.final_discovered_tids > 0 &&
                               report.attached_tids == report.final_discovered_tids &&
                               report.regset_tids == report.final_discovered_tids &&
                               report.detached_tids == report.final_discovered_tids &&
                               report.attach_failures == 0 && report.detach_failures == 0;
    if (!full_coverage || report.fatal_step != static_cast<int32_t>(FatalStep::kNone)) {
        report.verdict = static_cast<int32_t>(Verdict::kPartial);
        return;
    }
    const bool process_vm_memory =
            report.vm_read_bytes == static_cast<int>(sizeof(uint64_t)) &&
            report.vm_write_bytes == static_cast<int>(sizeof(uint64_t)) &&
            report.vm_read_value == kCanaryOriginal;
    const bool ptrace_memory = report.peek_errno == 0 && report.poke_errno == 0;
    const bool full_memory = (process_vm_memory || ptrace_memory) &&
                             report.memory_restored != 0 && report.identity_setreg_errno == 0 &&
                             report.arm_syscall_get_errno == 0 &&
                             report.arm_syscall_set_errno == 0;
    report.verdict = static_cast<int32_t>(full_memory ? Verdict::kPassFull
                                                      : Verdict::kPassAttachOnly);
}

void RunChildProbe(SharedProbe* shared, pid_t target_pid, pid_t bootstrap_tid,
                   void* remote_canary) {
    ChildReport& report = shared->report;
    report.magic = kReportMagic;
    report.version = kReportVersion;
    report.verdict = static_cast<int32_t>(Verdict::kNotRun);
    report.target_pid = target_pid;
    report.tracer_pid = static_cast<int32_t>(RawSyscall6(__NR_getpid));
    report.bootstrap_tid = bootstrap_tid;
    report.first_syscall_no = -1;

    if (RawSyscall6(__NR_getppid) != target_pid) {
        report.fatal_step = static_cast<int32_t>(FatalStep::kParentChanged);
        report.fatal_errno = ESRCH;
        report.verdict = static_cast<int32_t>(Verdict::kInternalError);
        return;
    }

    const int64_t start = RawNowMs();
    const int64_t deadline = start < 0 ? kChildDeadlineMs : start + kChildDeadlineMs;
    const bool attached = AttachAllCurrentTasks(shared, target_pid, deadline) == 0;
    if (attached) {
        ProbeRegisters(shared, bootstrap_tid);
        ProbeMemory(shared, remote_canary);
    }
    DetachAll(shared);
    SummarizeTasks(shared);
    DecideVerdict(shared);
}

int ReadRemoteString(pid_t target_pid, uintptr_t address, char* output, size_t capacity) {
    if (address == 0 || capacity < 2) {
        return EFAULT;
    }
    iovec local{output, capacity - 1};
    iovec remote{reinterpret_cast<void*>(address), capacity - 1};
    const long result = RawSyscall6(__NR_process_vm_readv, target_pid,
                                    reinterpret_cast<long>(&local), 1,
                                    reinterpret_cast<long>(&remote), 1, 0);
    if (result <= 0) {
        return result < 0 ? RawError(result) : EFAULT;
    }
    const size_t bytes = static_cast<size_t>(result);
    for (size_t i = 0; i < bytes; ++i) {
        if (output[i] == '\0') {
            return 0;
        }
    }
    output[bytes < capacity ? bytes : capacity - 1] = '\0';
    return ENAMETOOLONG;
}

int ReadArm64Registers(pid_t tid, Arm64Regs* regs) {
    iovec regs_vector{regs, sizeof(*regs)};
    const long regs_result = RawPtrace(kPtraceGetRegSet, tid, kNtPrStatus,
                                       reinterpret_cast<uintptr_t>(&regs_vector));
    if (regs_result != 0 || regs_vector.iov_len != sizeof(*regs)) {
        return regs_result == 0 ? EIO : RawError(regs_result);
    }
    return 0;
}

int ReadArm64SyscallNumber(pid_t tid, int32_t* syscall_number) {
    iovec syscall_vector{syscall_number, sizeof(*syscall_number)};
    const long syscall_result = RawPtrace(kPtraceGetRegSet, tid, kNtArmSystemCall,
                                          reinterpret_cast<uintptr_t>(&syscall_vector));
    if (syscall_result != 0 || syscall_vector.iov_len != sizeof(*syscall_number)) {
        return syscall_result == 0 ? EIO : RawError(syscall_result);
    }
    return 0;
}

int WriteArm64SyscallNumber(pid_t tid, int32_t syscall_number) {
    iovec syscall_vector{&syscall_number, sizeof(syscall_number)};
    const long syscall_result = RawPtrace(kPtraceSetRegSet, tid, kNtArmSystemCall,
                                          reinterpret_cast<uintptr_t>(&syscall_vector));
    return RawError(syscall_result);
}

int ReadSyscallStop(pid_t tid, Arm64Regs* regs, int32_t* syscall_number) {
    const int registers_error = ReadArm64Registers(tid, regs);
    if (registers_error != 0) {
        return registers_error;
    }
    const int syscall_error = ReadArm64SyscallNumber(tid, syscall_number);
    if (syscall_error != 0) {
        *syscall_number = static_cast<int32_t>(regs->regs[8]);
        return syscall_error;
    }
    return 0;
}

bool RegistersMatchExceptX1(const Arm64Regs& expected, const Arm64Regs& actual,
                            uint64_t expected_x1) {
    for (int i = 0; i < 31; ++i) {
        if (i == 1) {
            if (actual.regs[i] != expected_x1) {
                return false;
            }
        } else if (actual.regs[i] != expected.regs[i]) {
            return false;
        }
    }
    return actual.sp == expected.sp && actual.pc == expected.pc &&
           actual.pstate == expected.pstate;
}

bool RegistersEqual(const Arm64Regs& expected, const Arm64Regs& actual) {
    for (int i = 0; i < 31; ++i) {
        if (actual.regs[i] != expected.regs[i]) {
            return false;
        }
    }
    return actual.sp == expected.sp && actual.pc == expected.pc &&
           actual.pstate == expected.pstate;
}

bool M2ScratchGuardsIntact(const SharedProbe* shared) {
    return shared->m2_scratch_guard_before == kScratchGuardBefore &&
           shared->m2_scratch_guard_after == kScratchGuardAfter;
}

ObservedSyscall* SelectObservation(M1Report* report, int32_t syscall_number) {
    if (syscall_number == __NR_getpid) {
        return &report->getpid_call;
    }
    if (syscall_number == __NR_gettid) {
        return &report->gettid_call;
    }
    if (syscall_number == __NR_openat) {
        return &report->openat_call;
    }
    return nullptr;
}

bool M1ObservationsComplete(const M1Report& report) {
    return report.transaction_phase == 7 &&
           report.getpid_call.entry_seen == 1 && report.getpid_call.exit_seen == 1 &&
           report.gettid_call.entry_seen == 1 && report.gettid_call.exit_seen == 1 &&
           report.openat_call.entry_seen == 1 && report.openat_call.exit_seen == 1;
}

int RecordObservation(SharedProbe* shared, const Arm64Regs& regs, int32_t syscall_number) {
    M1Report& report = shared->m1_report;
    ObservedSyscall* observation = SelectObservation(&report, syscall_number);
    if (observation == nullptr) {
        return 0;
    }
    int32_t expected_syscall = -1;
    if (report.transaction_phase == 1 || report.transaction_phase == 2) {
        expected_syscall = __NR_getpid;
    } else if (report.transaction_phase == 3 || report.transaction_phase == 4) {
        expected_syscall = __NR_gettid;
    } else if (report.transaction_phase == 5 || report.transaction_phase == 6) {
        expected_syscall = __NR_openat;
    }
    if (syscall_number != expected_syscall) {
        return EPROTO;
    }

    const bool is_entry = (report.transaction_phase & 1) != 0;
    if (is_entry) {
        if (observation->entry_seen != 0) {
            return EPROTO;
        }
        observation->entry_seen = 1;
        for (int i = 0; i < 6; ++i) {
            observation->args[i] = regs.regs[i];
        }
        if (syscall_number == __NR_openat) {
            observation->path_errno =
                    ReadRemoteString(report.target_pid, static_cast<uintptr_t>(regs.regs[1]),
                                     observation->path, sizeof(observation->path));
        }
    } else {
        if (observation->exit_seen != 0 || observation->entry_seen == 0) {
            return EPROTO;
        }
        observation->exit_seen = 1;
        observation->result = static_cast<int64_t>(regs.regs[0]);
    }
    ++report.transaction_phase;
    return 0;
}

int RestartWithSyscall(TaskState* task, int signal) {
    const long result = RawPtrace(kPtraceSyscall, task->tid, 0,
                                  static_cast<uintptr_t>(signal));
    if (result == 0) {
        task->flags &= ~kTaskStopped;
        task->pending_signal = 0;
        return 0;
    }
    return RawError(result);
}

int RunM1EventLoop(SharedProbe* shared, TaskState* bootstrap_task, int64_t deadline_ms) {
    M1Report& report = shared->m1_report;
    for (;;) {
        bool received = false;
        for (;;) {
            int status = 0;
            const long waited = RawSyscall6(__NR_wait4, -1, reinterpret_cast<long>(&status),
                                            kWaitWall | WNOHANG, 0);
            if (waited == 0 || (waited < 0 && RawError(waited) == ECHILD)) {
                break;
            }
            if (waited < 0) {
                if (RawError(waited) == EINTR) {
                    continue;
                }
                return RawError(waited);
            }
            received = true;
            const pid_t tid = static_cast<pid_t>(waited);
            TaskState* task = FindTask(shared, tid);
            if (task == nullptr) {
                ++report.unexpected_stops;
                HandleWaitStatus(shared, tid, status);
                return EPROTO;
            }
            HandleWaitStatus(shared, tid, status);
            if (IsExitedStatus(status) || IsSignaledStatus(status)) {
                if (task == bootstrap_task) {
                    return ESRCH;
                }
                continue;
            }
            if (!IsStoppedStatus(status)) {
                ++report.unexpected_stops;
                continue;
            }
            if (task != bootstrap_task) {
                ++report.unexpected_stops;
                return EPROTO;
            }

            const int signal = StopSignal(status);
            if (signal == (SIGTRAP | 0x80)) {
                ++report.syscall_stops;
                Arm64Regs regs{};
                int32_t syscall_number = -1;
                const int register_error =
                        ReadSyscallStop(task->tid, &regs, &syscall_number);
                if (register_error != 0) {
                    ObservedSyscall* observation =
                            SelectObservation(&report, syscall_number);
                    if (observation != nullptr) {
                        observation->register_errno = register_error;
                    }
                } else if (__atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) >= 1) {
                    const int observation_error =
                            RecordObservation(shared, regs, syscall_number);
                    if (observation_error != 0) {
                        return observation_error;
                    }
                }
                if (__atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) >= 2 &&
                    M1ObservationsComplete(report)) {
                    report.tests_done_seen = 1;
                    return 0;
                }
                const int restart_error = RestartWithSyscall(task, 0);
                if (restart_error != 0) {
                    return restart_error;
                }
            } else {
                ++report.signal_stops;
                return EINTR;
            }
        }

        const int64_t now = RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        if (!received) {
            RawSleepOneMillisecond();
        }
    }
}

bool ChildStringEquals(const char* left, const char* right) {
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

void SummarizeM1(SharedProbe* shared) {
    M1Report& report = shared->m1_report;
    report.discovered_tids = shared->report.final_discovered_tids;
    report.attached_tids = 0;
    report.detached_tids = 0;
    report.attach_failures = 0;
    report.detach_failures = 0;
    for (int i = 0; i < shared->task_count; ++i) {
        const TaskState& task = shared->tasks[i];
        if ((task.flags & kTaskSeenCurrent) == 0) {
            continue;
        }
        if ((task.flags & kTaskSeized) != 0) {
            ++report.attached_tids;
        } else {
            ++report.attach_failures;
        }
        if ((task.flags & kTaskDetached) != 0 || (task.flags & kTaskDead) != 0) {
            ++report.detached_tids;
        } else if ((task.flags & kTaskSeized) != 0) {
            ++report.detach_failures;
        }
    }
}

void DecideM1Verdict(SharedProbe* shared) {
    M1Report& report = shared->m1_report;
    TaskState* leader = FindTask(shared, report.target_pid);
    if (leader == nullptr || (leader->flags & kTaskSeized) == 0) {
        report.verdict = static_cast<int32_t>(M1Verdict::kBlocked);
        return;
    }
    const bool coverage = report.discovered_tids > 0 &&
                          report.attached_tids == report.discovered_tids &&
                          report.detached_tids == report.discovered_tids &&
                          report.attach_failures == 0 && report.detach_failures == 0;
    const bool results_match =
            report.getpid_call.result == shared->m1_expected_getpid &&
            report.gettid_call.result == shared->m1_expected_gettid &&
            report.openat_call.result == shared->m1_expected_openat;
    const bool path_matches = report.openat_call.path_errno == 0 &&
                              ChildStringEquals(report.openat_call.path,
                                                "/proc/self/status");
    if (coverage && report.event_loop_errno == 0 && M1ObservationsComplete(report) &&
        results_match && path_matches) {
        report.verdict = static_cast<int32_t>(M1Verdict::kPass);
    } else {
        report.verdict = static_cast<int32_t>(M1Verdict::kPartial);
    }
}

void RunChildM1(SharedProbe* shared, pid_t target_pid, pid_t bootstrap_tid, int ready_fd) {
    M1Report& report = shared->m1_report;
    report.magic = kM1ReportMagic;
    report.version = kReportVersion;
    report.verdict = static_cast<int32_t>(M1Verdict::kNotRun);
    report.target_pid = target_pid;
    shared->report.target_pid = target_pid;
    report.tracer_pid = static_cast<int32_t>(RawSyscall6(__NR_getpid));
    report.bootstrap_tid = bootstrap_tid;
    report.getpid_call.syscall_no = __NR_getpid;
    report.gettid_call.syscall_no = __NR_gettid;
    report.openat_call.syscall_no = __NR_openat;
    report.transaction_phase = 1;

    if (RawSyscall6(__NR_getppid) != target_pid) {
        report.verdict = static_cast<int32_t>(M1Verdict::kInternalError);
        report.fatal_errno = ESRCH;
        __atomic_store_n(&shared->m1_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        return;
    }

    const int64_t start = RawNowMs();
    const int64_t deadline = start < 0 ? kChildDeadlineMs : start + kChildDeadlineMs;
    if (AttachAllCurrentTasks(shared, target_pid, deadline) != 0) {
        report.fatal_errno = shared->report.fatal_errno;
        __atomic_store_n(&shared->m1_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        DetachAll(shared, bootstrap_tid);
        SummarizeM1(shared);
        DecideM1Verdict(shared);
        return;
    }

    TaskState* bootstrap_task = FindTask(shared, bootstrap_tid);
    if (bootstrap_task == nullptr || (bootstrap_task->flags & kTaskStopped) == 0 ||
        PtraceEvent(bootstrap_task->wait_status) != kPtraceEventStop ||
        bootstrap_task->pending_signal != 0) {
        report.fatal_errno = bootstrap_task == nullptr ? ESRCH : EINTR;
        __atomic_store_n(&shared->m1_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        DetachAll(shared, bootstrap_tid);
        SummarizeM1(shared);
        DecideM1Verdict(shared);
        return;
    }

    const char ready = 'R';
    report.ready_sent = RawWrite(ready_fd, &ready, 1) == 1 ? 1 : 0;
    RawClose(ready_fd);
    if (report.ready_sent == 0) {
        report.fatal_errno = EPIPE;
        __atomic_store_n(&shared->m1_stage, 3U, __ATOMIC_RELEASE);
    } else {
        report.event_loop_errno = RestartWithSyscall(bootstrap_task, 0);
        if (report.event_loop_errno == 0) {
            report.event_loop_errno = RunM1EventLoop(shared, bootstrap_task, deadline);
        }
        __atomic_store_n(&shared->m1_stage,
                         report.event_loop_errno == 0 ? 4U : 3U,
                         __ATOMIC_RELEASE);
    }

    DetachAll(shared, bootstrap_tid);
    SummarizeM1(shared);
    DecideM1Verdict(shared);
}

int HandleM2OpenatStop(SharedProbe* shared, TaskState* task, Arm64Regs* regs,
                       int32_t syscall_number) {
    M2Report& report = shared->m2_report;
    if (syscall_number != __NR_openat) {
        return 0;
    }
    if (report.transaction_phase == 1) {
        const Arm64Regs original_regs = *regs;
        report.entry_seen = 1;
        report.original_pointer = regs->regs[1];
        report.entry_args_verified =
                static_cast<int64_t>(regs->regs[0]) == AT_FDCWD &&
                regs->regs[2] == static_cast<uint64_t>(O_RDONLY | O_CLOEXEC) &&
                regs->regs[3] == 0 && regs->regs[8] == __NR_openat;
        if (report.entry_args_verified == 0) {
            return EPROTO;
        }
        if (!M2ScratchGuardsIntact(shared)) {
            report.scratch_guards_ok = 0;
            return EOVERFLOW;
        }
        report.original_path_errno =
                ReadRemoteString(report.target_pid,
                                 static_cast<uintptr_t>(report.original_pointer),
                                 report.original_path, sizeof(report.original_path));
        if (report.original_path_errno != 0 ||
            !ChildStringEquals(report.original_path, shared->m2_source_path)) {
            return report.original_path_errno != 0 ? report.original_path_errno : EPROTO;
        }
        if (shared->m2_rule_count <= 0 ||
            shared->m2_rule_count > static_cast<int32_t>(sizeof(shared->m2_rules) /
                                                         sizeof(shared->m2_rules[0]))) {
            return EINVAL;
        }

        const path_policy::Translation translation =
                path_policy::TranslateAbsolute(report.original_path,
                                               sizeof(report.original_path),
                                               shared->m2_rules,
                                               static_cast<size_t>(shared->m2_rule_count),
                                               shared->m2_scratch,
                                               sizeof(shared->m2_scratch));
        report.policy_action = translation.action;
        report.policy_errno = translation.error;
        report.policy_rule_id = translation.rule_id;
        report.policy_longest_match =
                translation.action == static_cast<int32_t>(path_policy::Action::kRedirect) &&
                translation.rule_id == kM2ExactRuleId;

        char boundary_output[path_policy::kPathCapacity];
        const path_policy::Translation boundary =
                path_policy::TranslateAbsolute(shared->m2_near_prefix_path,
                                               sizeof(shared->m2_near_prefix_path),
                                               &shared->m2_rules[0], 1,
                                               boundary_output, sizeof(boundary_output));
        report.policy_boundary_pass =
                boundary.error == 0 &&
                boundary.action == static_cast<int32_t>(path_policy::Action::kPass);
        if (translation.error != 0 ||
            translation.action != static_cast<int32_t>(path_policy::Action::kRedirect) ||
            report.policy_longest_match == 0 || report.policy_boundary_pass == 0) {
            return translation.error != 0 ? translation.error : EPROTO;
        }

        __atomic_thread_fence(__ATOMIC_RELEASE);
        report.scratch_write_len = static_cast<int32_t>(translation.output_length + 1);
        report.scratch_guards_ok = M2ScratchGuardsIntact(shared) ? 1 : 0;
        if (report.scratch_guards_ok == 0) {
            return EOVERFLOW;
        }
        report.redirected_pointer = reinterpret_cast<uintptr_t>(shared->m2_scratch);
        report.redirected_path_errno =
                ReadRemoteString(report.target_pid,
                                 static_cast<uintptr_t>(report.redirected_pointer),
                                 report.redirected_path, sizeof(report.redirected_path));
        if (report.redirected_path_errno != 0 ||
            !ChildStringEquals(report.redirected_path, shared->m2_redirect_path) ||
            report.original_pointer == report.redirected_pointer) {
            return EPROTO;
        }
        shared->m2_rollback_regs = original_regs;
        shared->m2_rollback_snapshot_valid = 1;
        shared->m2_rollback_syscall_valid = 1;
        shared->m2_rollback_syscall_number = syscall_number;
        report.rewrite_active = 1;
        regs->regs[1] = report.redirected_pointer;
        iovec vector{regs, sizeof(*regs)};
        const long result = RawPtrace(kPtraceSetRegSet, task->tid, kNtPrStatus,
                                      reinterpret_cast<uintptr_t>(&vector));
        report.entry_setreg_errno = RawError(result);
        if (result != 0) {
            return report.entry_setreg_errno;
        }
        Arm64Regs verified_regs{};
        report.entry_verify_errno = ReadArm64Registers(task->tid, &verified_regs);
        report.entry_registers_verified =
                report.entry_verify_errno == 0 &&
                RegistersMatchExceptX1(original_regs, verified_regs,
                                       report.redirected_pointer);
        if (report.entry_verify_errno == 0 && report.entry_registers_verified == 0) {
            report.entry_verify_errno = EIO;
        }

        int32_t verified_syscall = -1;
        report.entry_syscall_verify_errno =
                ReadArm64SyscallNumber(task->tid, &verified_syscall);
        report.entry_syscall_verified =
                report.entry_syscall_verify_errno == 0 && verified_syscall == __NR_openat;
        if (report.entry_syscall_verify_errno == 0 && report.entry_syscall_verified == 0) {
            report.entry_syscall_verify_errno = EIO;
        }
        if (report.entry_verify_errno != 0) {
            return report.entry_verify_errno;
        }
        if (report.entry_syscall_verify_errno != 0) {
            return report.entry_syscall_verify_errno;
        }
        shared->m2_rollback_snapshot_valid = 0;
        shared->m2_rollback_syscall_valid = 0;
        report.transaction_phase = 2;
        return 0;
    }
    if (report.transaction_phase == 2) {
        const Arm64Regs exit_regs = *regs;
        report.exit_seen = 1;
        report.result = static_cast<int64_t>(regs->regs[0]);
        report.exit_redirect_seen = regs->regs[1] == report.redirected_pointer ? 1 : 0;
        report.exit_user_x8_verified = regs->regs[8] == __NR_openat ? 1 : 0;

        shared->m2_rollback_regs = exit_regs;
        shared->m2_rollback_regs.regs[1] = report.original_pointer;
        shared->m2_rollback_regs.regs[8] = __NR_openat;
        shared->m2_rollback_snapshot_valid = 1;
        shared->m2_rollback_syscall_valid = 1;
        shared->m2_rollback_syscall_number = syscall_number;
        if (report.rewrite_active == 0 || report.exit_redirect_seen == 0 ||
            report.exit_user_x8_verified == 0) {
            return EPROTO;
        }
        if (!M2ScratchGuardsIntact(shared)) {
            report.scratch_guards_ok = 0;
            return EOVERFLOW;
        }
        regs->regs[1] = report.original_pointer;
        iovec vector{regs, sizeof(*regs)};
        const long result = RawPtrace(kPtraceSetRegSet, task->tid, kNtPrStatus,
                                      reinterpret_cast<uintptr_t>(&vector));
        report.exit_setreg_errno = RawError(result);
        if (result != 0) {
            return report.exit_setreg_errno;
        }

        Arm64Regs verified_regs{};
        report.exit_verify_errno = ReadArm64Registers(task->tid, &verified_regs);
        report.exit_registers_verified =
                report.exit_verify_errno == 0 &&
                RegistersMatchExceptX1(exit_regs, verified_regs, report.original_pointer) &&
                static_cast<int64_t>(verified_regs.regs[0]) == report.result;
        if (report.exit_verify_errno == 0 && report.exit_registers_verified == 0) {
            report.exit_verify_errno = EIO;
        }

        int32_t verified_syscall = -1;
        report.exit_syscall_verify_errno =
                ReadArm64SyscallNumber(task->tid, &verified_syscall);
        report.exit_syscall_verified =
                report.exit_syscall_verify_errno == 0 && verified_syscall == __NR_openat;
        if (report.exit_syscall_verify_errno == 0 && report.exit_syscall_verified == 0) {
            report.exit_syscall_verify_errno = EIO;
        }
        if (report.exit_verify_errno != 0) {
            return report.exit_verify_errno;
        }
        if (report.exit_syscall_verify_errno != 0) {
            return report.exit_syscall_verify_errno;
        }
        shared->m2_rollback_snapshot_valid = 0;
        shared->m2_rollback_syscall_valid = 0;
        report.rewrite_active = 0;
        report.transaction_phase = 3;
        return 0;
    }
    return EPROTO;
}

int RollbackM2Registers(SharedProbe* shared, TaskState* bootstrap_task) {
    M2Report& report = shared->m2_report;
    if (report.rewrite_active == 0) {
        return 0;
    }
    report.rollback_attempted = 1;
    if (bootstrap_task == nullptr) {
        report.rollback_errno = ESRCH;
        return report.rollback_errno;
    }

    RetryStopForDetach(shared, bootstrap_task, RawNowMs() + kDetachRetryMs);
    if ((bootstrap_task->flags & kTaskDead) != 0) {
        report.rollback_errno = ESRCH;
        return report.rollback_errno;
    }
    if ((bootstrap_task->flags & kTaskStopped) == 0) {
        report.rollback_errno = ETIMEDOUT;
        return report.rollback_errno;
    }

    Arm64Regs expected_regs{};
    if (shared->m2_rollback_snapshot_valid != 0) {
        expected_regs = shared->m2_rollback_regs;
    } else {
        report.rollback_errno = ReadArm64Registers(bootstrap_task->tid, &expected_regs);
        if (report.rollback_errno != 0) {
            return report.rollback_errno;
        }
        expected_regs.regs[1] = report.original_pointer;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        iovec vector{&expected_regs, sizeof(expected_regs)};
        const long set_result = RawPtrace(kPtraceSetRegSet, bootstrap_task->tid, kNtPrStatus,
                                          reinterpret_cast<uintptr_t>(&vector));
        report.rollback_errno = RawError(set_result);
        if (report.rollback_errno != 0) {
            continue;
        }
        if (shared->m2_rollback_syscall_valid != 0) {
            report.rollback_errno =
                    WriteArm64SyscallNumber(bootstrap_task->tid,
                                            shared->m2_rollback_syscall_number);
            if (report.rollback_errno != 0) {
                continue;
            }
        }

        Arm64Regs verified_regs{};
        report.rollback_errno = ReadArm64Registers(bootstrap_task->tid, &verified_regs);
        if (report.rollback_errno == 0 && !RegistersEqual(expected_regs, verified_regs)) {
            report.rollback_errno = EIO;
        }
        if (report.rollback_errno == 0 && shared->m2_rollback_syscall_valid != 0) {
            int32_t verified_syscall = -1;
            report.rollback_errno =
                    ReadArm64SyscallNumber(bootstrap_task->tid, &verified_syscall);
            if (report.rollback_errno == 0 &&
                verified_syscall != shared->m2_rollback_syscall_number) {
                report.rollback_errno = EIO;
            }
        }
        if (report.rollback_errno == 0) {
            report.rollback_verified = 1;
            report.rewrite_active = 0;
            shared->m2_rollback_snapshot_valid = 0;
            shared->m2_rollback_syscall_valid = 0;
            break;
        }
    }
    return report.rollback_errno;
}

int RunM2EventLoop(SharedProbe* shared, TaskState* bootstrap_task, int64_t deadline_ms) {
    M2Report& report = shared->m2_report;
    for (;;) {
        bool received = false;
        for (;;) {
            int status = 0;
            const long waited = RawSyscall6(__NR_wait4, -1, reinterpret_cast<long>(&status),
                                            kWaitWall | WNOHANG, 0);
            if (waited == 0 || (waited < 0 && RawError(waited) == ECHILD)) {
                break;
            }
            if (waited < 0) {
                if (RawError(waited) == EINTR) {
                    continue;
                }
                return RawError(waited);
            }
            received = true;
            const pid_t waited_tid = static_cast<pid_t>(waited);
            TaskState* task = FindTask(shared, waited_tid);
            if (task == nullptr) {
                ++report.unexpected_stops;
                HandleWaitStatus(shared, waited_tid, status);
                task = FindTask(shared, waited_tid);
                if (task == nullptr && IsStoppedStatus(status)) {
                    const int signal = StopSignal(status);
                    const unsigned int event = PtraceEvent(status);
                    const int pending_signal =
                            signal == (SIGTRAP | 0x80)
                                    ? 0
                                    : (event == kPtraceEventStop && signal == SIGTRAP
                                               ? 0
                                               : signal);
                    const long detach_result =
                            RawPtrace(kPtraceDetach, waited_tid, 0,
                                      static_cast<uintptr_t>(pending_signal));
                    report.orphan_cleanup_errno = RawError(detach_result);
                }
                return EPROTO;
            }
            HandleWaitStatus(shared, waited_tid, status);
            if (IsExitedStatus(status) || IsSignaledStatus(status)) {
                return task == bootstrap_task ? ESRCH : EPROTO;
            }
            if (!IsStoppedStatus(status)) {
                ++report.unexpected_stops;
                return EPROTO;
            }
            if (task != bootstrap_task) {
                ++report.unexpected_stops;
                return EPROTO;
            }

            const int signal = StopSignal(status);
            if (signal != (SIGTRAP | 0x80)) {
                ++report.signal_stops;
                return EINTR;
            }

            ++report.syscall_stops;
            if (__atomic_load_n(&shared->m2_stage, __ATOMIC_ACQUIRE) >= 2U &&
                report.transaction_phase == 3) {
                return 0;
            }

            Arm64Regs regs{};
            int32_t syscall_number = -1;
            const int register_error =
                    ReadSyscallStop(task->tid, &regs, &syscall_number);
            if (register_error != 0) {
                return register_error;
            }
            if (__atomic_load_n(&shared->m2_stage, __ATOMIC_ACQUIRE) >= 1U) {
                const int redirect_error =
                        HandleM2OpenatStop(shared, task, &regs, syscall_number);
                if (redirect_error != 0) {
                    return redirect_error;
                }
                if (report.transaction_phase == 3) {
                    return 0;
                }
            }
            const int restart_error = RestartWithSyscall(task, 0);
            if (restart_error != 0) {
                return restart_error;
            }
        }

        const int64_t now = RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        if (!received) {
            RawSleepOneMillisecond();
        }
    }
}

void SummarizeM2(SharedProbe* shared) {
    M2Report& report = shared->m2_report;
    report.discovered_tids = shared->report.final_discovered_tids;
    report.attached_tids = 0;
    report.detached_tids = 0;
    report.attach_failures = 0;
    report.detach_failures = 0;
    report.unexpected_cleanup_failures = 0;
    for (int i = 0; i < shared->task_count; ++i) {
        const TaskState& task = shared->tasks[i];
        if ((task.flags & kTaskSeenCurrent) == 0) {
            if ((task.flags & kTaskSeized) != 0 &&
                (task.flags & kTaskDetached) == 0 && (task.flags & kTaskDead) == 0) {
                ++report.unexpected_cleanup_failures;
            }
            continue;
        }
        if ((task.flags & kTaskSeized) != 0) {
            ++report.attached_tids;
        } else {
            ++report.attach_failures;
        }
        if ((task.flags & kTaskDetached) != 0 || (task.flags & kTaskDead) != 0) {
            ++report.detached_tids;
        } else if ((task.flags & kTaskSeized) != 0) {
            ++report.detach_failures;
        }
    }
}

void DecideM2Verdict(SharedProbe* shared) {
    M2Report& report = shared->m2_report;
    if (!M2ScratchGuardsIntact(shared)) {
        report.scratch_guards_ok = 0;
    }
    TaskState* leader = FindTask(shared, report.target_pid);
    if (leader == nullptr || (leader->flags & kTaskSeized) == 0) {
        report.verdict = static_cast<int32_t>(M2Verdict::kBlocked);
        return;
    }
    const bool coverage = report.discovered_tids > 0 &&
                          report.attached_tids == report.discovered_tids &&
                          report.detached_tids == report.discovered_tids &&
                          report.attach_failures == 0 && report.detach_failures == 0;
    const bool paths_match = report.original_path_errno == 0 &&
                             report.redirected_path_errno == 0 &&
                             ChildStringEquals(report.original_path,
                                               shared->m2_source_path) &&
                             ChildStringEquals(report.redirected_path,
                                               shared->m2_redirect_path);
    const bool rewrite_complete = report.transaction_phase == 3 &&
                                   report.entry_seen == 1 && report.exit_seen == 1 &&
                                   report.entry_setreg_errno == 0 &&
                                   report.entry_verify_errno == 0 &&
                                   report.entry_syscall_verify_errno == 0 &&
                                   report.entry_registers_verified == 1 &&
                                   report.entry_syscall_verified == 1 &&
                                   report.entry_args_verified == 1 &&
                                   report.exit_setreg_errno == 0 &&
                                   report.exit_verify_errno == 0 &&
                                   report.exit_syscall_verify_errno == 0 &&
                                   report.exit_registers_verified == 1 &&
                                   report.exit_syscall_verified == 1 &&
                                   report.exit_user_x8_verified == 1 &&
                                   report.exit_redirect_seen == 1 &&
                                   report.rewrite_active == 0;
    const bool result_matches =
            (report.expected_errno == 0 && report.result >= 0) ||
            (report.expected_errno > 0 && report.result == -report.expected_errno);
    if (coverage && report.event_loop_errno == 0 && rewrite_complete && paths_match &&
        result_matches && report.original_pointer != report.redirected_pointer &&
        report.scratch_write_len > 1 && report.scratch_guards_ok == 1 &&
        report.policy_action == static_cast<int32_t>(path_policy::Action::kRedirect) &&
        report.policy_errno == 0 && report.policy_rule_id == kM2ExactRuleId &&
        report.policy_boundary_pass == 1 && report.policy_longest_match == 1 &&
        report.original_path_read_only == 1 &&
        report.unexpected_stops == 0 && report.orphan_cleanup_errno == 0 &&
        report.unexpected_cleanup_failures == 0) {
        report.verdict = static_cast<int32_t>(M2Verdict::kPass);
    } else {
        report.verdict = static_cast<int32_t>(M2Verdict::kPartial);
    }
}

void RunChildM2(SharedProbe* shared, pid_t target_pid, pid_t bootstrap_tid, int ready_fd) {
    M2Report& report = shared->m2_report;
    report.magic = kM2ReportMagic;
    report.version = kReportVersion;
    report.verdict = static_cast<int32_t>(M2Verdict::kNotRun);
    report.target_pid = target_pid;
    shared->report.target_pid = target_pid;
    report.tracer_pid = static_cast<int32_t>(RawSyscall6(__NR_getpid));
    report.bootstrap_tid = bootstrap_tid;
    report.transaction_phase = 1;

    if (RawSyscall6(__NR_getppid) != target_pid) {
        report.verdict = static_cast<int32_t>(M2Verdict::kInternalError);
        report.fatal_errno = ESRCH;
        __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        return;
    }

    const int64_t start = RawNowMs();
    const int64_t deadline = start < 0 ? kChildDeadlineMs : start + kChildDeadlineMs;
    if (AttachAllCurrentTasks(shared, target_pid, deadline) != 0) {
        report.fatal_errno = shared->report.fatal_errno;
        __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        DetachAll(shared, bootstrap_tid);
        SummarizeM2(shared);
        DecideM2Verdict(shared);
        return;
    }

    TaskState* bootstrap_task = FindTask(shared, bootstrap_tid);
    if (bootstrap_task == nullptr || (bootstrap_task->flags & kTaskStopped) == 0 ||
        PtraceEvent(bootstrap_task->wait_status) != kPtraceEventStop ||
        bootstrap_task->pending_signal != 0) {
        report.fatal_errno = bootstrap_task == nullptr ? ESRCH : EINTR;
        __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
        DetachAll(shared, bootstrap_tid);
        SummarizeM2(shared);
        DecideM2Verdict(shared);
        return;
    }

    const char ready = 'R';
    if (RawWrite(ready_fd, &ready, 1) != 1) {
        report.fatal_errno = EPIPE;
        report.event_loop_errno = EPIPE;
        __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        RawClose(ready_fd);
    } else {
        RawClose(ready_fd);
        report.event_loop_errno = RestartWithSyscall(bootstrap_task, 0);
        if (report.event_loop_errno == 0) {
            report.event_loop_errno = RunM2EventLoop(shared, bootstrap_task, deadline);
        }
    }

    const int rollback_error = RollbackM2Registers(shared, bootstrap_task);
    if (rollback_error != 0) {
        if (report.event_loop_errno == 0) {
            report.event_loop_errno = rollback_error;
        }
        if (report.fatal_errno == 0) {
            report.fatal_errno = rollback_error;
        }
    }
    if (rollback_error != 0 && report.rewrite_active != 0) {
        __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        const long killed = RawSyscall6(__NR_kill, target_pid, SIGKILL);
        if (killed == 0) {
            RawExit(124);
        }
        for (;;) {
            RawSleepOneMillisecond();
        }
    }
    __atomic_store_n(&shared->m2_stage,
                     report.event_loop_errno == 0 ? 4U : 3U,
                     __ATOMIC_RELEASE);
    DetachAll(shared, bootstrap_tid);
    SummarizeM2(shared);
    DecideM2Verdict(shared);
}

std::string Trim(std::string value) {
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' || value.back() == '\0' ||
            value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    return value;
}

std::string ReadSmallFile(const char* path) {
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input) {
        return "unavailable";
    }
    std::ostringstream output;
    char buffer[8192];
    input.read(buffer, sizeof(buffer));
    output.write(buffer, input.gcount());
    return Trim(output.str());
}

bool WriteExactFile(const std::string& path, const std::string& content) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t written = write(fd, content.data() + offset, content.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            close(fd);
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return close(fd) == 0;
}

std::string ReadWholeFile(const std::string& path) {
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

int ParseStatusNumber(const std::string& status, const char* key, int fallback) {
    const std::string prefix = std::string(key) + ":";
    const size_t position = status.find(prefix);
    if (position == std::string::npos) {
        return fallback;
    }
    size_t cursor = position + prefix.size();
    while (cursor < status.size() && (status[cursor] == ' ' || status[cursor] == '\t')) {
        ++cursor;
    }
    int value = 0;
    bool found = false;
    while (cursor < status.size() && status[cursor] >= '0' && status[cursor] <= '9') {
        found = true;
        value = value * 10 + (status[cursor] - '0');
        ++cursor;
    }
    return found ? value : fallback;
}

const char* VerdictName(int32_t value) {
    switch (static_cast<Verdict>(value)) {
        case Verdict::kPassFull:
            return "PASS_FULL";
        case Verdict::kPassAttachOnly:
            return "PASS_ATTACH_ONLY";
        case Verdict::kPartial:
            return "PARTIAL";
        case Verdict::kBlocked:
            return "BLOCKED";
        case Verdict::kInternalError:
            return "INTERNAL_ERROR";
        case Verdict::kNotRun:
        default:
            return "NOT_RUN";
    }
}

const char* M1VerdictName(int32_t value) {
    switch (static_cast<M1Verdict>(value)) {
        case M1Verdict::kPass:
            return "PASS";
        case M1Verdict::kPartial:
            return "PARTIAL";
        case M1Verdict::kBlocked:
            return "BLOCKED";
        case M1Verdict::kInternalError:
            return "INTERNAL_ERROR";
        case M1Verdict::kNotRun:
        default:
            return "NOT_RUN";
    }
}

const char* M2VerdictName(int32_t value) {
    switch (static_cast<M2Verdict>(value)) {
        case M2Verdict::kPass:
            return "PASS";
        case M2Verdict::kPartial:
            return "PARTIAL";
        case M2Verdict::kBlocked:
            return "BLOCKED";
        case M2Verdict::kInternalError:
            return "INTERNAL_ERROR";
        case M2Verdict::kNotRun:
        default:
            return "NOT_RUN";
    }
}

std::string JsonEscape(const std::string& value) {
    std::string result;
    result.reserve(value.size() + 8);
    for (char character : value) {
        switch (character) {
            case '\\':
                result += "\\\\";
                break;
            case '"':
                result += "\\\"";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(character) >= 0x20) {
                    result.push_back(character);
                }
                break;
        }
    }
    return result;
}

std::string FormatReport(const ParentOutcome& parent, const ChildReport& report) {
    std::ostringstream json;
    json << "{\"verdict\":\"" << VerdictName(report.verdict) << "\""
         << ",\"target_pid\":" << parent.target_pid
         << ",\"tracer_pid\":" << report.tracer_pid
         << ",\"kernel\":\"" << JsonEscape(parent.kernel) << "\""
         << ",\"api\":" << parent.api_level
         << ",\"discovered_tids\":" << report.final_discovered_tids
         << ",\"attached_tids\":" << report.attached_tids
         << ",\"regset_tids\":" << report.regset_tids
         << ",\"detached_tids\":" << report.detached_tids
         << ",\"attach_failures\":" << report.attach_failures
         << ",\"detach_failures\":" << report.detach_failures
         << ",\"restored_dumpable\":" << (parent.restored_dumpable ? "true" : "false")
         << ",\"child_exit_status\":" << parent.tracer_exit_status
         << ",\"parent_memory_restored\":"
         << (parent.parent_memory_restored ? "true" : "false") << "}";

    std::ostringstream output;
    output << "HOOKSELF_M0_RESULT " << json.str() << "\n\n"
           << "Environment\n"
           << "  abi=arm64-v8a\n"
           << "  api=" << parent.api_level << "\n"
           << "  kernel=" << parent.kernel << "\n"
           << "  selinux=" << parent.selinux_context << "\n"
           << "  yama_scope=" << parent.yama_scope << "\n"
           << "  target_pid=" << parent.target_pid << "\n"
           << "  bootstrap_tid=" << parent.bootstrap_tid << "\n"
           << "  tracer_pid_before=" << parent.tracer_pid_before << "\n"
           << "  threads_before=" << parent.threads_before << "\n\n"
           << "Parent transaction\n"
           << "  original_dumpable=" << parent.original_dumpable << "\n"
           << "  set_dumpable_errno=" << parent.set_dumpable_errno << "\n"
           << "  set_ptracer_errno=" << parent.set_ptracer_errno << "\n"
           << "  clear_ptracer_errno=" << parent.clear_ptracer_errno
           << " (PR_SET_PTRACER has no getter)\n"
           << "  restore_dumpable_errno=" << parent.restore_dumpable_errno << "\n"
           << "  restored_dumpable=" << parent.restored_dumpable << "\n"
           << "  done_received=" << parent.done_received << "\n"
           << "  parent_timeout=" << parent.parent_timeout << "\n"
           << "  tracer_exit_status=" << parent.tracer_exit_status << "\n\n"
           << "Child attach\n"
           << "  verdict=" << VerdictName(report.verdict) << "\n"
           << "  fatal_step=" << report.fatal_step << "\n"
           << "  fatal_errno=" << report.fatal_errno << "\n"
           << "  scan_rounds=" << report.scan_rounds << "\n"
           << "  discovered_tids=" << report.final_discovered_tids << "\n"
           << "  tracked_tasks=" << report.tracked_tasks << "\n"
           << "  attached_tids=" << report.attached_tids << "\n"
           << "  stopped_tids=" << report.stopped_tids << "\n"
           << "  regset_tids=" << report.regset_tids << "\n"
           << "  detached_tids=" << report.detached_tids << "\n"
           << "  attach_failures=" << report.attach_failures << "\n"
           << "  detach_failures=" << report.detach_failures << "\n\n"
           << "Registers\n"
           << "  identity_setreg_errno=" << report.identity_setreg_errno << "\n"
           << "  nt_arm_system_call_get_errno=" << report.arm_syscall_get_errno << "\n"
           << "  nt_arm_system_call_set_errno=" << report.arm_syscall_set_errno << "\n"
           << "  first_pc=0x" << std::hex << report.first_pc << "\n"
           << "  first_sp=0x" << report.first_sp << std::dec << "\n"
           << "  first_syscall_no=" << report.first_syscall_no << "\n\n"
           << "Remote memory\n"
           << "  process_vm_readv_errno=" << report.vm_read_errno << "\n"
           << "  process_vm_readv_bytes=" << report.vm_read_bytes << "\n"
           << "  process_vm_writev_errno=" << report.vm_write_errno << "\n"
           << "  process_vm_writev_bytes=" << report.vm_write_bytes << "\n"
           << "  ptrace_peek_errno=" << report.peek_errno << "\n"
           << "  ptrace_poke_errno=" << report.poke_errno << "\n"
           << "  child_memory_restored=" << report.memory_restored << "\n"
           << "  parent_memory_restored=" << parent.parent_memory_restored << "\n";

    int printed = 0;
    for (int i = 0; i < report.report_task_count && printed < 16; ++i) {
        const TaskReport& task = report.tasks[i];
        if (task.seize_errno != 0 || task.interrupt_errno != 0 ||
            task.getregset_errno != 0 || task.detach_errno != 0) {
            output << "\nThread failure tid=" << task.tid << " flags=0x" << std::hex
                   << task.flags << std::dec << " seize=" << task.seize_errno
                   << " interrupt=" << task.interrupt_errno
                   << " getregset=" << task.getregset_errno
                   << " detach=" << task.detach_errno;
            ++printed;
        }
    }
    return output.str();
}

std::string FormatM1Report(const ParentOutcome& parent, const M1Report& report,
                           int64_t expected_getpid, int64_t expected_gettid,
                           int64_t expected_openat) {
    std::ostringstream json;
    json << "{\"verdict\":\"" << M1VerdictName(report.verdict) << "\""
         << ",\"target_pid\":" << parent.target_pid
         << ",\"tracer_pid\":" << report.tracer_pid
         << ",\"discovered_tids\":" << report.discovered_tids
         << ",\"attached_tids\":" << report.attached_tids
         << ",\"detached_tids\":" << report.detached_tids
         << ",\"attach_failures\":" << report.attach_failures
         << ",\"detach_failures\":" << report.detach_failures
         << ",\"getpid_entry\":" << report.getpid_call.entry_seen
         << ",\"getpid_exit\":" << report.getpid_call.exit_seen
         << ",\"getpid_result\":" << report.getpid_call.result
         << ",\"gettid_entry\":" << report.gettid_call.entry_seen
         << ",\"gettid_exit\":" << report.gettid_call.exit_seen
         << ",\"gettid_result\":" << report.gettid_call.result
         << ",\"openat_entry\":" << report.openat_call.entry_seen
         << ",\"openat_exit\":" << report.openat_call.exit_seen
         << ",\"openat_result\":" << report.openat_call.result
         << ",\"openat_path\":\"" << JsonEscape(report.openat_call.path) << "\""
         << ",\"restored_dumpable\":" << (parent.restored_dumpable ? "true" : "false")
         << ",\"child_exit_status\":" << parent.tracer_exit_status << "}";

    std::ostringstream output;
    output << "HOOKSELF_M1_RESULT " << json.str() << "\n\n"
           << "Environment\n"
           << "  kernel=" << parent.kernel << "\n"
           << "  api=" << parent.api_level << "\n"
           << "  target_pid=" << parent.target_pid << "\n"
           << "  bootstrap_tid=" << parent.bootstrap_tid << "\n"
           << "  original_dumpable=" << parent.original_dumpable << "\n"
           << "  set_ptracer_errno=" << parent.set_ptracer_errno << "\n"
           << "  restored_dumpable=" << parent.restored_dumpable << "\n"
           << "  tracer_exit_status=" << parent.tracer_exit_status << "\n\n"
           << "Coverage\n"
           << "  verdict=" << M1VerdictName(report.verdict) << "\n"
           << "  fatal_errno=" << report.fatal_errno << "\n"
           << "  event_loop_errno=" << report.event_loop_errno << "\n"
           << "  discovered_tids=" << report.discovered_tids << "\n"
           << "  attached_tids=" << report.attached_tids << "\n"
           << "  detached_tids=" << report.detached_tids << "\n"
           << "  attach_failures=" << report.attach_failures << "\n"
           << "  detach_failures=" << report.detach_failures << "\n"
           << "  syscall_stops=" << report.syscall_stops << "\n"
           << "  signal_stops=" << report.signal_stops << "\n"
           << "  unexpected_stops=" << report.unexpected_stops << "\n"
           << "  tests_done_seen=" << report.tests_done_seen << "\n\n"
           << "Observed syscalls\n"
           << "  getpid entry/exit=" << report.getpid_call.entry_seen << "/"
           << report.getpid_call.exit_seen << " result=" << report.getpid_call.result
           << " expected=" << expected_getpid << "\n"
           << "  gettid entry/exit=" << report.gettid_call.entry_seen << "/"
           << report.gettid_call.exit_seen << " result=" << report.gettid_call.result
           << " expected=" << expected_gettid << "\n"
           << "  openat entry/exit=" << report.openat_call.entry_seen << "/"
           << report.openat_call.exit_seen << " result=" << report.openat_call.result
           << " expected=" << expected_openat << "\n"
           << "  openat dirfd=" << static_cast<int64_t>(report.openat_call.args[0]) << "\n"
           << "  openat flags=0x" << std::hex << report.openat_call.args[2] << std::dec << "\n"
           << "  openat path_errno=" << report.openat_call.path_errno << "\n"
           << "  openat path=" << report.openat_call.path << "\n";
    return output.str();
}

std::string FormatM2Report(const ParentOutcome& parent, const M2Report& report,
                           int64_t parent_fd, bool target_inode_match,
                           bool source_inode_differs, bool target_content_match,
                           bool source_unchanged, bool cleanup_ok) {
    const bool missing_scenario =
            report.scenario == static_cast<int32_t>(M2Scenario::kRedirectMissing);
    const char* marker = missing_scenario
                                 ? "HOOKSELF_M2B_MISSING_RESULT"
                                 : "HOOKSELF_M2A_RESULT";
    std::ostringstream json;
    json << "{\"verdict\":\"" << M2VerdictName(report.verdict) << "\""
         << ",\"scenario\":\"" << (missing_scenario ? "REDIRECT_MISSING" : "REDIRECT_EXISTING")
         << "\""
         << ",\"expected_errno\":" << report.expected_errno
         << ",\"missing_target_observed\":" << report.missing_target_observed
         << ",\"target_pid\":" << parent.target_pid
         << ",\"tracer_pid\":" << report.tracer_pid
         << ",\"discovered_tids\":" << report.discovered_tids
         << ",\"attached_tids\":" << report.attached_tids
         << ",\"detached_tids\":" << report.detached_tids
         << ",\"attach_failures\":" << report.attach_failures
         << ",\"detach_failures\":" << report.detach_failures
         << ",\"unexpected_stops\":" << report.unexpected_stops
         << ",\"orphan_cleanup_errno\":" << report.orphan_cleanup_errno
         << ",\"unexpected_cleanup_failures\":"
         << report.unexpected_cleanup_failures
         << ",\"entry_seen\":" << report.entry_seen
         << ",\"exit_seen\":" << report.exit_seen
         << ",\"entry_args_verified\":" << report.entry_args_verified
         << ",\"entry_registers_verified\":" << report.entry_registers_verified
         << ",\"entry_syscall_verified\":" << report.entry_syscall_verified
         << ",\"exit_redirect_seen\":" << report.exit_redirect_seen
         << ",\"exit_registers_verified\":" << report.exit_registers_verified
         << ",\"exit_syscall_verified\":" << report.exit_syscall_verified
         << ",\"exit_user_x8_verified\":" << report.exit_user_x8_verified
         << ",\"rewrite_active\":" << report.rewrite_active
         << ",\"rollback_attempted\":" << report.rollback_attempted
         << ",\"rollback_verified\":" << report.rollback_verified
         << ",\"policy_action\":" << report.policy_action
         << ",\"policy_errno\":" << report.policy_errno
         << ",\"policy_rule_id\":" << report.policy_rule_id
         << ",\"policy_boundary_pass\":" << report.policy_boundary_pass
         << ",\"policy_longest_match\":" << report.policy_longest_match
         << ",\"original_path_read_only\":" << report.original_path_read_only
         << ",\"original_path_memory_unchanged\":"
         << report.original_path_memory_unchanged
         << ",\"child_result\":" << report.result
         << ",\"parent_fd\":" << parent_fd
         << ",\"original_path\":\"" << JsonEscape(report.original_path) << "\""
         << ",\"redirected_path\":\"" << JsonEscape(report.redirected_path) << "\""
         << ",\"pointer_changed\":"
         << (report.original_pointer != report.redirected_pointer ? "true" : "false")
         << ",\"scratch_write_len\":" << report.scratch_write_len
         << ",\"scratch_guards_ok\":" << (report.scratch_guards_ok ? "true" : "false")
         << ",\"target_inode_match\":" << (target_inode_match ? "true" : "false")
         << ",\"source_inode_differs\":" << (source_inode_differs ? "true" : "false")
         << ",\"target_content_match\":" << (target_content_match ? "true" : "false")
         << ",\"source_unchanged\":" << (source_unchanged ? "true" : "false")
         << ",\"restored_dumpable\":" << (parent.restored_dumpable ? "true" : "false")
         << ",\"child_exit_status\":" << parent.tracer_exit_status
         << ",\"cleanup_ok\":" << (cleanup_ok ? "true" : "false") << "}";

    std::ostringstream output;
    output << marker << " " << json.str() << "\n\n"
           << (missing_scenario ? "M2B missing-target openat redirect\n"
                                : "M2A absolute openat redirect\n")
           << "  verdict=" << M2VerdictName(report.verdict) << "\n"
           << "  target_pid=" << parent.target_pid << "\n"
           << "  tracer_pid=" << report.tracer_pid << "\n"
           << "  discovered/attached/detached=" << report.discovered_tids << "/"
           << report.attached_tids << "/" << report.detached_tids << "\n"
           << "  attach/detach failures=" << report.attach_failures << "/"
           << report.detach_failures << "\n"
           << "  syscall_stops=" << report.syscall_stops << "\n"
           << "  signal/unexpected stops=" << report.signal_stops << "/"
           << report.unexpected_stops << "\n"
           << "  event_loop_errno=" << report.event_loop_errno << "\n"
           << "  entry/exit=" << report.entry_seen << "/" << report.exit_seen << "\n"
           << "  entry/exit setreg errno=" << report.entry_setreg_errno << "/"
           << report.exit_setreg_errno << "\n"
           << "  entry verify regs/syscall/args=" << report.entry_registers_verified << "/"
           << report.entry_syscall_verified << "/" << report.entry_args_verified << "\n"
           << "  entry verify errno regs/syscall=" << report.entry_verify_errno << "/"
           << report.entry_syscall_verify_errno << "\n"
           << "  exit redirected/regs/syscall=" << report.exit_redirect_seen << "/"
           << report.exit_registers_verified << "/" << report.exit_syscall_verified << "\n"
           << "  exit user x8 verified=" << report.exit_user_x8_verified << "\n"
           << "  exit verify errno regs/syscall=" << report.exit_verify_errno << "/"
           << report.exit_syscall_verify_errno << "\n"
           << "  rewrite active=" << report.rewrite_active
           << " rollback attempted/verified/errno=" << report.rollback_attempted << "/"
           << report.rollback_verified << "/" << report.rollback_errno << "\n"
           << "  orphan_cleanup_errno=" << report.orphan_cleanup_errno
           << " unexpected_cleanup_failures=" << report.unexpected_cleanup_failures << "\n"
           << "  policy action/errno/rule=" << report.policy_action << "/"
           << report.policy_errno << "/" << report.policy_rule_id << "\n"
           << "  policy boundary/longest=" << report.policy_boundary_pass << "/"
           << report.policy_longest_match << "\n"
           << "  original path readonly/unchanged=" << report.original_path_read_only << "/"
           << report.original_path_memory_unchanged << "\n"
           << "  original_path=" << report.original_path << "\n"
           << "  redirected_path=" << report.redirected_path << "\n"
           << "  original_ptr=0x" << std::hex << report.original_pointer << "\n"
           << "  redirected_ptr=0x" << report.redirected_pointer << std::dec << "\n"
           << "  scratch_write_len=" << report.scratch_write_len << "\n"
           << "  scratch_guards_ok=" << report.scratch_guards_ok << "\n"
           << "  child_result=" << report.result << " parent_fd=" << parent_fd << "\n"
           << "  target_inode_match=" << target_inode_match << "\n"
           << "  source_inode_differs=" << source_inode_differs << "\n"
           << "  target_content_match=" << target_content_match << "\n"
           << "  source_unchanged=" << source_unchanged << "\n"
           << "  restored_dumpable=" << parent.restored_dumpable << "\n"
           << "  child_exit_status=" << parent.tracer_exit_status << "\n"
           << "  cleanup_ok=" << cleanup_ok << "\n";
    return output.str();
}

void LogTaggedReport(const char* tag, const std::string& report) {
    size_t start = 0;
    while (start < report.size()) {
        const size_t end = report.find('\n', start);
        const size_t length = (end == std::string::npos ? report.size() : end) - start;
        __android_log_print(ANDROID_LOG_INFO, tag, "%.*s", static_cast<int>(length),
                            report.data() + start);
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
}

void LogReport(const std::string& report) {
    LogTaggedReport(kLogTag, report);
}

class ProbeRunningGuard {
public:
    ~ProbeRunningGuard() {
        g_probe_running.clear(std::memory_order_release);
    }
};

}  // namespace

std::string RunM0Probe() {
    if (g_probe_running.test_and_set(std::memory_order_acquire)) {
        return "HOOKSELF_M0_RESULT {\"verdict\":\"BUSY\"}";
    }
    ProbeRunningGuard running_guard;

    ParentOutcome parent;
    parent.target_pid = getpid();
    parent.bootstrap_tid = static_cast<int32_t>(syscall(__NR_gettid));
    parent.api_level = android_get_device_api_level();
    const std::string status_before = ReadSmallFile("/proc/self/status");
    parent.tracer_pid_before = ParseStatusNumber(status_before, "TracerPid", -1);
    parent.threads_before = ParseStatusNumber(status_before, "Threads", -1);
    parent.selinux_context = ReadSmallFile("/proc/self/attr/current");
    parent.yama_scope = ReadSmallFile("/proc/sys/kernel/yama/ptrace_scope");
    utsname kernel_name{};
    parent.kernel = uname(&kernel_name) == 0 ? kernel_name.release : "unavailable";
    errno = 0;
    parent.original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    parent.get_dumpable_errno = parent.original_dumpable < 0 ? errno : 0;

    ChildReport empty_report{};
    empty_report.magic = kReportMagic;
    empty_report.version = kReportVersion;
    empty_report.target_pid = parent.target_pid;
    empty_report.bootstrap_tid = parent.bootstrap_tid;
    empty_report.verdict = static_cast<int32_t>(Verdict::kInternalError);

    if (parent.tracer_pid_before > 0) {
        empty_report.verdict = static_cast<int32_t>(Verdict::kBlocked);
        empty_report.fatal_errno = EBUSY;
        const std::string report = FormatReport(parent, empty_report);
        LogReport(report);
        return report;
    }
    if (parent.original_dumpable < 0) {
        empty_report.verdict = static_cast<int32_t>(Verdict::kBlocked);
        empty_report.fatal_errno = parent.get_dumpable_errno;
        const std::string report = FormatReport(parent, empty_report);
        LogReport(report);
        return report;
    }

    auto* shared = static_cast<SharedProbe*>(mmap(nullptr, sizeof(SharedProbe),
                                                   PROT_READ | PROT_WRITE,
                                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    auto* canary = static_cast<uint64_t*>(mmap(nullptr, sizeof(uint64_t),
                                                PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (shared == MAP_FAILED || canary == MAP_FAILED) {
        empty_report.fatal_errno = errno;
        if (shared != MAP_FAILED) {
            munmap(shared, sizeof(SharedProbe));
        }
        if (canary != MAP_FAILED) {
            munmap(canary, sizeof(uint64_t));
        }
        const std::string report = FormatReport(parent, empty_report);
        LogReport(report);
        return report;
    }
    std::memset(shared, 0, sizeof(*shared));
    *canary = kCanaryOriginal;

    int go_pipe[2] = {-1, -1};
    int done_pipe[2] = {-1, -1};
    if (pipe2(go_pipe, O_CLOEXEC) != 0 || pipe2(done_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        empty_report.fatal_errno = errno;
        if (go_pipe[0] >= 0) close(go_pipe[0]);
        if (go_pipe[1] >= 0) close(go_pipe[1]);
        if (done_pipe[0] >= 0) close(done_pipe[0]);
        if (done_pipe[1] >= 0) close(done_pipe[1]);
        munmap(shared, sizeof(SharedProbe));
        munmap(canary, sizeof(uint64_t));
        const std::string report = FormatReport(parent, empty_report);
        LogReport(report);
        return report;
    }

    errno = 0;
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        parent.set_dumpable_errno = errno;
        close(go_pipe[0]);
        close(go_pipe[1]);
        close(done_pipe[0]);
        close(done_pipe[1]);
        munmap(shared, sizeof(SharedProbe));
        munmap(canary, sizeof(uint64_t));
        empty_report.verdict = static_cast<int32_t>(Verdict::kBlocked);
        empty_report.fatal_errno = parent.set_dumpable_errno;
        const std::string report = FormatReport(parent, empty_report);
        LogReport(report);
        return report;
    }

    const pid_t child_pid = fork();
    if (child_pid == 0) {
        RawClose(go_pipe[1]);
        RawClose(done_pipe[0]);
        RawSyscall6(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        char command = 0;
        const long bytes = RawRead(go_pipe[0], &command, 1);
        RawClose(go_pipe[0]);
        if (bytes != 1 || command != 'G') {
            RawClose(done_pipe[1]);
            RawExit(120);
        }
        RunChildProbe(shared, parent.target_pid, parent.bootstrap_tid, canary);
        const char done = 'D';
        RawWrite(done_pipe[1], &done, 1);
        RawClose(done_pipe[1]);
        RawExit(0);
    }

    close(go_pipe[0]);
    close(done_pipe[1]);
    if (child_pid < 0) {
        empty_report.fatal_errno = errno;
        close(go_pipe[1]);
        close(done_pipe[0]);
    } else {
        errno = 0;
        if (prctl(kPrSetPtracer, child_pid, 0, 0, 0) != 0) {
            parent.set_ptracer_errno = errno;
        } else {
            parent.ptracer_set = 1;
        }
        const char go = 'G';
        if (write(go_pipe[1], &go, 1) != 1) {
            empty_report.fatal_errno = errno;
        }
        close(go_pipe[1]);

        pollfd descriptor{done_pipe[0], static_cast<short>(POLLIN | POLLHUP), 0};
        const int poll_result = poll(&descriptor, 1, 8000);
        if (poll_result > 0) {
            char done = 0;
            if (read(done_pipe[0], &done, 1) == 1 && done == 'D') {
                parent.done_received = 1;
            }
        } else if (poll_result == 0) {
            parent.parent_timeout = 1;
            kill(child_pid, SIGKILL);
        }
        close(done_pipe[0]);

        int child_status = 0;
        while (waitpid(child_pid, &child_status, 0) < 0 && errno == EINTR) {
        }
        parent.tracer_exit_status = child_status;
    }

    if (parent.ptracer_set != 0) {
        errno = 0;
        if (prctl(kPrSetPtracer, 0, 0, 0, 0) != 0) {
            parent.clear_ptracer_errno = errno;
        }
    }
    errno = 0;
    if (parent.original_dumpable >= 0 &&
        prctl(PR_SET_DUMPABLE, parent.original_dumpable, 0, 0, 0) != 0) {
        parent.restore_dumpable_errno = errno;
    }
    parent.restored_dumpable =
            parent.original_dumpable >= 0 &&
            prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == parent.original_dumpable;
    parent.parent_memory_restored = *canary == kCanaryOriginal;
    if (!parent.parent_memory_restored) {
        *canary = kCanaryOriginal;
    }

    ChildReport report = shared->report.magic == kReportMagic ? shared->report : empty_report;
    if (parent.parent_timeout != 0 && report.verdict == static_cast<int32_t>(Verdict::kNotRun)) {
        report.verdict = static_cast<int32_t>(Verdict::kInternalError);
        report.fatal_errno = ETIMEDOUT;
    }
    const bool parent_rollback_ok = parent.done_received != 0 &&
                                    parent.tracer_exit_status == 0 &&
                                    parent.restored_dumpable != 0 &&
                                    parent.restore_dumpable_errno == 0 &&
                                    parent.parent_memory_restored != 0 &&
                                    (parent.ptracer_set == 0 || parent.clear_ptracer_errno == 0);
    if (!parent_rollback_ok && report.verdict == static_cast<int32_t>(Verdict::kPassFull)) {
        report.verdict = static_cast<int32_t>(Verdict::kPartial);
    }
    munmap(shared, sizeof(SharedProbe));
    munmap(canary, sizeof(uint64_t));

    const std::string formatted = FormatReport(parent, report);
    LogReport(formatted);
    return formatted;
}

std::string RunM1Observation() {
    if (g_probe_running.test_and_set(std::memory_order_acquire)) {
        return "HOOKSELF_M1_RESULT {\"verdict\":\"BUSY\"}";
    }
    ProbeRunningGuard running_guard;

    ParentOutcome parent;
    parent.target_pid = getpid();
    parent.bootstrap_tid = static_cast<int32_t>(syscall(__NR_gettid));
    parent.api_level = android_get_device_api_level();
    const std::string status_before = ReadSmallFile("/proc/self/status");
    parent.tracer_pid_before = ParseStatusNumber(status_before, "TracerPid", -1);
    parent.threads_before = ParseStatusNumber(status_before, "Threads", -1);
    parent.selinux_context = ReadSmallFile("/proc/self/attr/current");
    parent.yama_scope = ReadSmallFile("/proc/sys/kernel/yama/ptrace_scope");
    utsname kernel_name{};
    parent.kernel = uname(&kernel_name) == 0 ? kernel_name.release : "unavailable";
    errno = 0;
    parent.original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    parent.get_dumpable_errno = parent.original_dumpable < 0 ? errno : 0;

    M1Report empty_report{};
    empty_report.magic = kM1ReportMagic;
    empty_report.version = kReportVersion;
    empty_report.target_pid = parent.target_pid;
    empty_report.bootstrap_tid = parent.bootstrap_tid;
    empty_report.verdict = static_cast<int32_t>(M1Verdict::kInternalError);

    if (parent.tracer_pid_before > 0) {
        empty_report.verdict = static_cast<int32_t>(M1Verdict::kBlocked);
        empty_report.fatal_errno = EBUSY;
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }
    if (parent.original_dumpable < 0) {
        empty_report.verdict = static_cast<int32_t>(M1Verdict::kBlocked);
        empty_report.fatal_errno = parent.get_dumpable_errno;
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }

    auto* shared = static_cast<SharedProbe*>(mmap(nullptr, sizeof(SharedProbe),
                                                   PROT_READ | PROT_WRITE,
                                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (shared == MAP_FAILED) {
        empty_report.fatal_errno = errno;
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }
    std::memset(shared, 0, sizeof(*shared));

    int go_pipe[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    int done_pipe[2] = {-1, -1};
    if (pipe2(go_pipe, O_CLOEXEC) != 0 || pipe2(ready_pipe, O_CLOEXEC) != 0 ||
        pipe2(done_pipe, O_CLOEXEC) != 0) {
        empty_report.fatal_errno = errno;
        for (int fd : go_pipe) if (fd >= 0) close(fd);
        for (int fd : ready_pipe) if (fd >= 0) close(fd);
        for (int fd : done_pipe) if (fd >= 0) close(fd);
        munmap(shared, sizeof(SharedProbe));
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }

    sigset_t blocked_signals{};
    sigset_t original_signals{};
    sigfillset(&blocked_signals);
    const int mask_error = pthread_sigmask(SIG_SETMASK, &blocked_signals, &original_signals);
    if (mask_error != 0) {
        empty_report.fatal_errno = mask_error;
        for (int fd : go_pipe) close(fd);
        for (int fd : ready_pipe) close(fd);
        for (int fd : done_pipe) close(fd);
        munmap(shared, sizeof(SharedProbe));
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }

    errno = 0;
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        parent.set_dumpable_errno = errno;
        empty_report.verdict = static_cast<int32_t>(M1Verdict::kBlocked);
        empty_report.fatal_errno = parent.set_dumpable_errno;
        pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);
        for (int fd : go_pipe) close(fd);
        for (int fd : ready_pipe) close(fd);
        for (int fd : done_pipe) close(fd);
        munmap(shared, sizeof(SharedProbe));
        const std::string report = FormatM1Report(parent, empty_report, 0, 0, 0);
        LogTaggedReport(kM1LogTag, report);
        return report;
    }

    const pid_t child_pid = fork();
    if (child_pid == 0) {
        RawClose(go_pipe[1]);
        RawClose(ready_pipe[0]);
        RawClose(done_pipe[0]);
        RawSyscall6(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        char command = 0;
        const long bytes = RawRead(go_pipe[0], &command, 1);
        RawClose(go_pipe[0]);
        if (bytes != 1 || command != 'G') {
            RawClose(ready_pipe[1]);
            RawClose(done_pipe[1]);
            RawExit(121);
        }
        RunChildM1(shared, parent.target_pid, parent.bootstrap_tid, ready_pipe[1]);
        const char done = 'D';
        RawWrite(done_pipe[1], &done, 1);
        RawClose(done_pipe[1]);
        RawExit(0);
    }

    close(go_pipe[0]);
    close(ready_pipe[1]);
    close(done_pipe[1]);
    if (child_pid < 0) {
        empty_report.fatal_errno = errno;
        close(go_pipe[1]);
        close(ready_pipe[0]);
        close(done_pipe[0]);
    } else {
        errno = 0;
        if (prctl(kPrSetPtracer, child_pid, 0, 0, 0) != 0) {
            parent.set_ptracer_errno = errno;
        } else {
            parent.ptracer_set = 1;
        }
        const char go = 'G';
        if (write(go_pipe[1], &go, 1) != 1) {
            empty_report.fatal_errno = errno;
        }
        close(go_pipe[1]);

        char ready = 0;
        const long ready_bytes = RawRead(ready_pipe[0], &ready, 1);
        RawClose(ready_pipe[0]);
        if (ready_bytes == 1 && ready == 'R' &&
            __atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) != 3U) {
            __atomic_store_n(&shared->m1_stage, 1U, __ATOMIC_SEQ_CST);
            __atomic_thread_fence(__ATOMIC_SEQ_CST);

            shared->m1_expected_getpid = RawSyscall6(__NR_getpid);
            if (__atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) != 3U) {
                shared->m1_expected_gettid = RawSyscall6(__NR_gettid);
            }
            if (__atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) != 3U) {
                constexpr char observed_path[] = "/proc/self/status";
                shared->m1_expected_openat =
                        RawSyscall6(__NR_openat, AT_FDCWD,
                                    reinterpret_cast<long>(observed_path),
                                    O_RDONLY | O_CLOEXEC, 0);
                if (shared->m1_expected_openat >= 0) {
                    RawClose(static_cast<int>(shared->m1_expected_openat));
                }
            }
            if (__atomic_load_n(&shared->m1_stage, __ATOMIC_ACQUIRE) != 3U) {
                __atomic_store_n(&shared->m1_stage, 2U, __ATOMIC_SEQ_CST);
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
            }
        } else {
            __atomic_store_n(&shared->m1_stage, 3U, __ATOMIC_RELEASE);
        }

        char done = 0;
        if (RawRead(done_pipe[0], &done, 1) == 1 && done == 'D') {
            parent.done_received = 1;
        }
        RawClose(done_pipe[0]);

        int child_status = 0;
        while (waitpid(child_pid, &child_status, 0) < 0 && errno == EINTR) {
        }
        parent.tracer_exit_status = child_status;
    }

    if (parent.ptracer_set != 0) {
        errno = 0;
        if (prctl(kPrSetPtracer, 0, 0, 0, 0) != 0) {
            parent.clear_ptracer_errno = errno;
        }
    }
    errno = 0;
    if (parent.original_dumpable >= 0 &&
        prctl(PR_SET_DUMPABLE, parent.original_dumpable, 0, 0, 0) != 0) {
        parent.restore_dumpable_errno = errno;
    }
    parent.restored_dumpable =
            parent.original_dumpable >= 0 &&
            prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == parent.original_dumpable;
    const int restore_mask_errno =
            pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);

    M1Report report = shared->m1_report.magic == kM1ReportMagic
                          ? shared->m1_report
                          : empty_report;
    const int64_t expected_getpid = shared->m1_expected_getpid;
    const int64_t expected_gettid = shared->m1_expected_gettid;
    const int64_t expected_openat = shared->m1_expected_openat;
    const bool parent_rollback_ok = parent.done_received != 0 &&
                                    parent.tracer_exit_status == 0 &&
                                    parent.restored_dumpable != 0 &&
                                    parent.restore_dumpable_errno == 0 &&
                                    restore_mask_errno == 0 &&
                                    (parent.ptracer_set == 0 || parent.clear_ptracer_errno == 0);
    if (!parent_rollback_ok && report.verdict == static_cast<int32_t>(M1Verdict::kPass)) {
        report.verdict = static_cast<int32_t>(M1Verdict::kPartial);
    }
    munmap(shared, sizeof(SharedProbe));

    const std::string formatted = FormatM1Report(parent, report, expected_getpid,
                                                  expected_gettid, expected_openat);
    LogTaggedReport(kM1LogTag, formatted);
    return formatted;
}

std::string RunM2RedirectImpl(const std::string& files_dir, M2Scenario scenario) {
    const bool missing_scenario = scenario == M2Scenario::kRedirectMissing;
    constexpr char source_content[] = "M2_SOURCE_PAYLOAD\n";
    constexpr char target_content[] = "M2_REDIRECT_TARGET_PAYLOAD_LONGER\n";

    ParentOutcome parent;
    parent.target_pid = getpid();
    parent.bootstrap_tid = static_cast<int32_t>(syscall(__NR_gettid));
    const std::string artifact_prefix =
            files_dir + "/.hookself-m2-" + std::to_string(parent.target_pid) + "-" +
            std::to_string(parent.bootstrap_tid);
    const std::string source_path =
            artifact_prefix + (missing_scenario ? "-missing-source.txt" : "-source.txt");
    const std::string redirect_path =
            artifact_prefix + (missing_scenario
                                       ? "-missing-redirect-target-longer-name.txt"
                                       : "-redirect-target-longer-name.txt");
    const std::string near_prefix_path = source_path + "-near";

    parent.api_level = android_get_device_api_level();
    const std::string status_before = ReadSmallFile("/proc/self/status");
    parent.tracer_pid_before = ParseStatusNumber(status_before, "TracerPid", -1);
    parent.threads_before = ParseStatusNumber(status_before, "Threads", -1);
    parent.selinux_context = ReadSmallFile("/proc/self/attr/current");
    parent.yama_scope = ReadSmallFile("/proc/sys/kernel/yama/ptrace_scope");
    utsname kernel_name{};
    parent.kernel = uname(&kernel_name) == 0 ? kernel_name.release : "unavailable";
    errno = 0;
    parent.original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    parent.get_dumpable_errno = parent.original_dumpable < 0 ? errno : 0;

    M2Report empty_report{};
    empty_report.magic = kM2ReportMagic;
    empty_report.version = kReportVersion;
    empty_report.scenario = static_cast<int32_t>(scenario);
    empty_report.expected_errno = missing_scenario ? ENOENT : 0;
    empty_report.target_pid = parent.target_pid;
    empty_report.bootstrap_tid = parent.bootstrap_tid;
    empty_report.verdict = static_cast<int32_t>(M2Verdict::kInternalError);

    const bool configuration_ok =
            !files_dir.empty() && source_path.size() < path_policy::kPathCapacity &&
            redirect_path.size() < path_policy::kPathCapacity &&
            near_prefix_path.size() < path_policy::kPathCapacity &&
            files_dir.size() < path_policy::kPathCapacity &&
            redirect_path.size() > source_path.size();
    if (!configuration_ok || parent.tracer_pid_before > 0 ||
        parent.original_dumpable < 0) {
        empty_report.verdict = static_cast<int32_t>(M2Verdict::kBlocked);
        empty_report.fatal_errno = !configuration_ok
                                       ? EINVAL
                                       : (parent.tracer_pid_before > 0
                                              ? EBUSY
                                              : parent.get_dumpable_errno);
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, false);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }

    unlink(source_path.c_str());
    unlink(redirect_path.c_str());
    const bool files_written = WriteExactFile(source_path, source_content) &&
                               (missing_scenario ||
                                WriteExactFile(redirect_path, target_content));
    struct stat source_stat{};
    struct stat redirect_stat{};
    const bool source_stat_ok = files_written && stat(source_path.c_str(), &source_stat) == 0;
    errno = 0;
    const int redirect_stat_result = stat(redirect_path.c_str(), &redirect_stat);
    const bool redirect_initial_ok = missing_scenario
                                             ? redirect_stat_result != 0 && errno == ENOENT
                                             : redirect_stat_result == 0;
    const bool initial_stats_ok = source_stat_ok && redirect_initial_ok;
    if (!initial_stats_ok) {
        empty_report.fatal_errno = errno != 0 ? errno : EIO;
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }

    auto* shared = static_cast<SharedProbe*>(mmap(nullptr, sizeof(SharedProbe),
                                                   PROT_READ | PROT_WRITE,
                                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (shared == MAP_FAILED) {
        empty_report.fatal_errno = errno;
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }
    std::memset(shared, 0, sizeof(*shared));
    shared->m2_report.scenario = static_cast<int32_t>(scenario);
    shared->m2_report.expected_errno = missing_scenario ? ENOENT : 0;
    std::memcpy(shared->m2_source_path, source_path.c_str(), source_path.size() + 1);
    std::memcpy(shared->m2_redirect_path, redirect_path.c_str(), redirect_path.size() + 1);
    std::memcpy(shared->m2_near_prefix_path, near_prefix_path.c_str(),
                near_prefix_path.size() + 1);
    shared->m2_rule_count = 2;
    shared->m2_rules[0].id = kM2ExactRuleId;
    std::memcpy(shared->m2_rules[0].guest_prefix, source_path.c_str(),
                source_path.size() + 1);
    std::memcpy(shared->m2_rules[0].host_prefix, redirect_path.c_str(),
                redirect_path.size() + 1);
    shared->m2_rules[1].id = kM2BroadRuleId;
    std::memcpy(shared->m2_rules[1].guest_prefix, files_dir.c_str(), files_dir.size() + 1);
    std::memcpy(shared->m2_rules[1].host_prefix, files_dir.c_str(), files_dir.size() + 1);
    std::memset(shared->m2_scratch, 0xa5, sizeof(shared->m2_scratch));
    shared->m2_scratch_guard_before = kScratchGuardBefore;
    shared->m2_scratch_guard_after = kScratchGuardAfter;

    int go_pipe[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    int done_pipe[2] = {-1, -1};
    if (pipe2(go_pipe, O_CLOEXEC) != 0 || pipe2(ready_pipe, O_CLOEXEC) != 0 ||
        pipe2(done_pipe, O_CLOEXEC) != 0) {
        empty_report.fatal_errno = errno;
        for (int fd : go_pipe) if (fd >= 0) close(fd);
        for (int fd : ready_pipe) if (fd >= 0) close(fd);
        for (int fd : done_pipe) if (fd >= 0) close(fd);
        munmap(shared, sizeof(SharedProbe));
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }

    sigset_t blocked_signals{};
    sigset_t original_signals{};
    sigfillset(&blocked_signals);
    const int mask_error = pthread_sigmask(SIG_SETMASK, &blocked_signals, &original_signals);
    if (mask_error != 0) {
        empty_report.fatal_errno = mask_error;
        for (int fd : go_pipe) close(fd);
        for (int fd : ready_pipe) close(fd);
        for (int fd : done_pipe) close(fd);
        munmap(shared, sizeof(SharedProbe));
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }

    errno = 0;
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        parent.set_dumpable_errno = errno;
        empty_report.verdict = static_cast<int32_t>(M2Verdict::kBlocked);
        empty_report.fatal_errno = parent.set_dumpable_errno;
        pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);
        for (int fd : go_pipe) close(fd);
        for (int fd : ready_pipe) close(fd);
        for (int fd : done_pipe) close(fd);
        munmap(shared, sizeof(SharedProbe));
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }

    const long page_size = sysconf(_SC_PAGESIZE);
    void* pathname_page = MAP_FAILED;
    int pathname_errno = 0;
    if (page_size <= 0 || source_path.size() + 1 > static_cast<size_t>(page_size)) {
        pathname_errno = EOVERFLOW;
    } else {
        pathname_page = mmap(nullptr, static_cast<size_t>(page_size),
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pathname_page == MAP_FAILED) {
            pathname_errno = errno;
        } else {
            std::memcpy(pathname_page, source_path.c_str(), source_path.size() + 1);
            if (mprotect(pathname_page, static_cast<size_t>(page_size), PROT_READ) != 0) {
                pathname_errno = errno;
                munmap(pathname_page, static_cast<size_t>(page_size));
                pathname_page = MAP_FAILED;
            }
        }
    }
    if (pathname_errno != 0) {
        empty_report.fatal_errno = pathname_errno;
        prctl(PR_SET_DUMPABLE, parent.original_dumpable, 0, 0, 0);
        parent.restored_dumpable =
                prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == parent.original_dumpable;
        pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);
        for (int fd : go_pipe) close(fd);
        for (int fd : ready_pipe) close(fd);
        for (int fd : done_pipe) close(fd);
        munmap(shared, sizeof(SharedProbe));
        unlink(source_path.c_str());
        unlink(redirect_path.c_str());
        const std::string report = FormatM2Report(parent, empty_report, -1, false,
                                                   false, false, false, true);
        LogTaggedReport(kM2LogTag, report);
        return report;
    }
    shared->m2_report.original_path_read_only = 1;

    const pid_t child_pid = fork();
    if (child_pid == 0) {
        RawClose(go_pipe[1]);
        RawClose(ready_pipe[0]);
        RawClose(done_pipe[0]);
        RawSyscall6(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        char command = 0;
        const long bytes = RawRead(go_pipe[0], &command, 1);
        RawClose(go_pipe[0]);
        if (bytes != 1 || command != 'G') {
            RawClose(ready_pipe[1]);
            RawClose(done_pipe[1]);
            RawExit(122);
        }
        RunChildM2(shared, parent.target_pid, parent.bootstrap_tid, ready_pipe[1]);
        const char done = 'D';
        RawWrite(done_pipe[1], &done, 1);
        RawClose(done_pipe[1]);
        RawExit(0);
    }

    close(go_pipe[0]);
    close(ready_pipe[1]);
    close(done_pipe[1]);
    int64_t parent_fd = -1;
    if (child_pid < 0) {
        empty_report.fatal_errno = errno;
        close(go_pipe[1]);
        close(ready_pipe[0]);
        close(done_pipe[0]);
    } else {
        errno = 0;
        if (prctl(kPrSetPtracer, child_pid, 0, 0, 0) != 0) {
            parent.set_ptracer_errno = errno;
        } else {
            parent.ptracer_set = 1;
        }
        const char go = 'G';
        if (write(go_pipe[1], &go, 1) != 1) {
            empty_report.fatal_errno = errno;
        }
        close(go_pipe[1]);

        char ready = 0;
        const long ready_bytes = RawRead(ready_pipe[0], &ready, 1);
        RawClose(ready_pipe[0]);
        if (ready_bytes == 1 && ready == 'R' &&
            __atomic_load_n(&shared->m2_stage, __ATOMIC_ACQUIRE) != 3U) {
            __atomic_store_n(&shared->m2_stage, 1U, __ATOMIC_SEQ_CST);
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            parent_fd = RawSyscall6(__NR_openat, AT_FDCWD,
                                    reinterpret_cast<long>(pathname_page),
                                    O_RDONLY | O_CLOEXEC, 0);
            shared->m2_expected_openat = parent_fd;
        } else {
            __atomic_store_n(&shared->m2_stage, 3U, __ATOMIC_RELEASE);
        }

        char done = 0;
        if (RawRead(done_pipe[0], &done, 1) == 1 && done == 'D') {
            parent.done_received = 1;
        }
        RawClose(done_pipe[0]);

        int child_status = 0;
        while (waitpid(child_pid, &child_status, 0) < 0 && errno == EINTR) {
        }
        parent.tracer_exit_status = child_status;
    }

    struct stat opened_stat{};
    bool opened_stat_ok = false;
    std::string opened_content;
    if (parent_fd >= 0) {
        opened_stat_ok = RawSyscall6(__NR_fstat, parent_fd,
                                     reinterpret_cast<long>(&opened_stat)) == 0;
        char content_buffer[128];
        size_t content_size = 0;
        for (;;) {
            const long bytes = RawRead(static_cast<int>(parent_fd),
                                       content_buffer + content_size,
                                       sizeof(content_buffer) - content_size);
            if (bytes < 0 && RawError(bytes) == EINTR) {
                continue;
            }
            if (bytes <= 0) {
                break;
            }
            content_size += static_cast<size_t>(bytes);
            if (content_size == sizeof(content_buffer)) {
                break;
            }
        }
        opened_content.assign(content_buffer, content_size);
        RawClose(static_cast<int>(parent_fd));
    }

    if (parent.ptracer_set != 0) {
        errno = 0;
        if (prctl(kPrSetPtracer, 0, 0, 0, 0) != 0) {
            parent.clear_ptracer_errno = errno;
        }
    }
    errno = 0;
    if (prctl(PR_SET_DUMPABLE, parent.original_dumpable, 0, 0, 0) != 0) {
        parent.restore_dumpable_errno = errno;
    }
    parent.restored_dumpable =
            prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == parent.original_dumpable;
    const int restore_mask_errno =
            pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);

    const bool original_path_memory_unchanged =
            pathname_page != MAP_FAILED &&
            std::memcmp(pathname_page, source_path.c_str(), source_path.size() + 1) == 0;
    const bool pathname_unmapped =
            pathname_page != MAP_FAILED &&
            munmap(pathname_page, static_cast<size_t>(page_size)) == 0;

    M2Report report = shared->m2_report.magic == kM2ReportMagic
                          ? shared->m2_report
                          : empty_report;
    report.original_path_memory_unchanged = original_path_memory_unchanged ? 1 : 0;
    const bool scratch_guards_final_ok = M2ScratchGuardsIntact(shared);
    if (!scratch_guards_final_ok) {
        report.scratch_guards_ok = 0;
    }
    errno = 0;
    struct stat final_redirect_stat{};
    const bool missing_target_observed =
            missing_scenario && stat(redirect_path.c_str(), &final_redirect_stat) != 0 &&
            errno == ENOENT;
    report.missing_target_observed = missing_target_observed ? 1 : 0;
    const bool target_inode_match =
            missing_scenario ||
            (opened_stat_ok && opened_stat.st_dev == redirect_stat.st_dev &&
             opened_stat.st_ino == redirect_stat.st_ino);
    const bool source_inode_differs =
            missing_scenario || source_stat.st_dev != redirect_stat.st_dev ||
            source_stat.st_ino != redirect_stat.st_ino;
    const bool target_content_match = missing_scenario || opened_content == target_content;
    const bool source_unchanged = ReadWholeFile(source_path) == source_content;
    const bool rollback_ok = parent.done_received != 0 && parent.tracer_exit_status == 0 &&
                             parent.restored_dumpable != 0 &&
                             parent.restore_dumpable_errno == 0 &&
                             restore_mask_errno == 0 &&
                             (parent.ptracer_set == 0 || parent.clear_ptracer_errno == 0);
    const bool register_validation_ok = report.entry_args_verified == 1 &&
                                        report.entry_registers_verified == 1 &&
                                        report.entry_syscall_verified == 1 &&
                                        report.exit_redirect_seen == 1 &&
                                        report.exit_registers_verified == 1 &&
                                        report.exit_syscall_verified == 1 &&
                                        report.exit_user_x8_verified == 1 &&
                                        report.rewrite_active == 0 &&
                                        report.policy_action ==
                                                static_cast<int32_t>(
                                                        path_policy::Action::kRedirect) &&
                                        report.policy_errno == 0 &&
                                        report.policy_rule_id == kM2ExactRuleId &&
                                        report.policy_boundary_pass == 1 &&
                                        report.policy_longest_match == 1 &&
                                        report.original_path_read_only == 1 &&
                                        report.original_path_memory_unchanged == 1 &&
                                        pathname_unmapped &&
                                        report.scratch_write_len ==
                                                static_cast<int32_t>(redirect_path.size() + 1);
    const bool result_validation_ok =
            missing_scenario
                    ? parent_fd == -ENOENT && report.result == -ENOENT &&
                      missing_target_observed
                    : parent_fd >= 0 && report.result == parent_fd;
    const bool parent_validation_ok = result_validation_ok &&
                                       target_inode_match && source_inode_differs &&
                                       target_content_match && source_unchanged && rollback_ok &&
                                       register_validation_ok && scratch_guards_final_ok;
    if (!parent_validation_ok && report.verdict == static_cast<int32_t>(M2Verdict::kPass)) {
        report.verdict = static_cast<int32_t>(M2Verdict::kPartial);
    }

    errno = 0;
    const bool source_removed = unlink(source_path.c_str()) == 0 || errno == ENOENT;
    errno = 0;
    const bool redirect_removed = unlink(redirect_path.c_str()) == 0 || errno == ENOENT;
    const bool cleanup_ok = source_removed && redirect_removed;
    if (!cleanup_ok && report.verdict == static_cast<int32_t>(M2Verdict::kPass)) {
        report.verdict = static_cast<int32_t>(M2Verdict::kPartial);
    }

    munmap(shared, sizeof(SharedProbe));
    const std::string formatted = FormatM2Report(parent, report, parent_fd,
                                                  target_inode_match,
                                                  source_inode_differs,
                                                  target_content_match,
                                                  source_unchanged, cleanup_ok);
    LogTaggedReport(kM2LogTag, formatted);
    return formatted;
}

std::string RunM2Redirect(const std::string& files_dir) {
    if (g_probe_running.test_and_set(std::memory_order_acquire)) {
        return "HOOKSELF_M2A_RESULT {\"verdict\":\"BUSY\"}";
    }
    ProbeRunningGuard running_guard;
    return RunM2RedirectImpl(files_dir, M2Scenario::kRedirectExisting);
}

std::string RunM2MissingRedirect(const std::string& files_dir) {
    if (g_probe_running.test_and_set(std::memory_order_acquire)) {
        return "HOOKSELF_M2B_MISSING_RESULT {\"verdict\":\"BUSY\"}";
    }
    ProbeRunningGuard running_guard;
    return RunM2RedirectImpl(files_dir, M2Scenario::kRedirectMissing);
}

}  // namespace hookself
