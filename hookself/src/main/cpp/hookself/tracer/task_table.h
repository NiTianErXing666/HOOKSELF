#pragma once

#include <stdint.h>

namespace hookself::tracer {

constexpr uint32_t kTaskTableCapacity = 512U;
constexpr uint32_t kInvalidTaskSlot = UINT32_MAX;
constexpr uint32_t kTaskTableMagic = 0x48535454U;  // HSTT
constexpr uint32_t kTaskTableVersion = 8U;

enum class TaskLifeState : uint32_t {
    kEmpty = 0,
    kDiscovered = 1,
    kAttaching = 2,
    kStopped = 3,
    kRunning = 4,
    kExecReinit = 5,
    kExiting = 6,
    kDead = 7,
};

enum class TaskStopState : uint32_t {
    kNone = 0,
    kInterrupt = 1,
    kSyscall = 2,
    kSeccomp = 3,
    kSignalDelivery = 4,
    kGroup = 5,
    kPtraceEvent = 6,
    kExitEvent = 7,
};

enum class TaskSyscallPhase : uint32_t {
    kUnknown = 0,
    kExpectEntry = 1,
    kAtEntry = 2,
    kExpectExit = 3,
    kAtExit = 4,
};

enum class TaskResumeMode : uint32_t {
    kUnknown = 0,
    kCont = 1,
    kSyscall = 2,
};

enum TaskRecordFlags : uint32_t {
    kTaskFlagNone = 0,
    kTaskFlagSeized = 1U << 0,
    kTaskFlagInterruptSent = 1U << 1,
    kTaskFlagOptionsApplied = 1U << 2,
    kTaskFlagNeedsDetach = 1U << 3,
    kTaskFlagSeenInScan = 1U << 4,
    kTaskFlagAutoAttached = 1U << 5,
    kTaskFlagIdentityProvisional = 1U << 6,
    kTaskFlagAwaitingParentEvent = 1U << 7,
    kTaskFlagExecTombstone = 1U << 8,
    kTaskFlagLogicalTraceme = 1U << 9,
    // A resident nested-ptrace bridge owns this physical stop until the
    // logical tracer resumes or detaches the tracee.
    kTaskFlagNestedPtraceTraceeHold = 1U << 10,
    // A logical wait is parked at the surrogate syscall-exit stop until a
    // matching nested-ptrace event wakes it.
    kTaskFlagNestedPtraceWaitExitHold = 1U << 11,
    // The physical tracee was resumed from a logical exec stop. ResumeTask()
    // records it as running, but its pending execve exit still needs address
    // space reinitialization before ordinary syscall processing resumes.
    kTaskFlagNestedPtraceExecReinitPending = 1U << 12,
};

enum ActiveSyscallFlags : uint32_t {
    kActiveSyscallNone = 0,
    kActiveSyscallValid = 1U << 0,
    kActiveSyscallEntryRegistersValid = 1U << 1,
    kActiveSyscallResultValid = 1U << 2,
    kActiveSyscallRegistersModified = 1U << 3,
    kActiveSyscallNeedsExit = 1U << 4,
    kActiveSyscallRestarted = 1U << 5,
    kActiveSyscallNumberModified = 1U << 6,
    kActiveSyscallArgumentsModified = 1U << 7,
    kActiveSyscallReplaceResult = 1U << 8,
    kActiveSyscallResultWriteUnknown = 1U << 9,
    kActiveSyscallVirtualFileOpen = 1U << 10,
    kActiveSyscallExecRecovered = 1U << 11,
    kActiveSyscallInternalFdOperation = 1U << 12,
    kActiveSyscallPtraceView = 1U << 13,
    kActiveSyscallProcStatusView = 1U << 14,
    kActiveSyscallLogBypass = 1U << 15,
    kActiveSyscallFromSeccomp = 1U << 16,
    kActiveSyscallPathState = 1U << 17,
    kActiveSyscallProcVirtualView = 1U << 18,
    kActiveSyscallProcVirtualReplay = 1U << 19,
    kActiveSyscallNestedPtraceDispatch = 1U << 20,
};

struct Arm64RegisterSnapshot {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct ActiveSyscallSnapshot {
    uint32_t flags;
    int32_t syscall_number;
    int32_t user_syscall_number;
    uint32_t modified_argument_mask;
    int32_t executed_syscall_number;
    int32_t entry_policy_action;
    uint32_t entry_policy_rule_id;
    uint32_t exit_policy_rule_id;
    uint64_t arguments[6];
    int64_t result;
    int64_t replacement_result;
    uint64_t rule_generation;
    uint32_t scratch_slot;
    uint32_t nested_ptrace_operation_slot;
    uint64_t scratch_generation;
    uint64_t internal_fd_sequence;
    Arm64RegisterSnapshot entry_registers;
};

struct TaskRecord {
    uint32_t occupied;
    uint32_t slot;
    int32_t tid;
    int32_t tgid;
    TaskLifeState life;
    TaskStopState stop;
    TaskSyscallPhase syscall_phase;
    uint32_t flags;
    int32_t pending_signal;
    int32_t last_wait_status;
    uint32_t last_ptrace_event;
    TaskResumeMode resume_mode;
    uint64_t ptrace_options;
    uint64_t exec_generation;
    uint64_t tracee_scratch_address;
    uint64_t stop_sequence;
    uint64_t last_ptrace_event_message;
    ActiveSyscallSnapshot active_syscall;
};

struct TaskTable {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t free_hint;
    uint64_t mutation_generation;
    uint64_t reserved[3];
    TaskRecord tasks[kTaskTableCapacity];
};

enum class TaskInsertResult : uint32_t {
    kInserted = 0,
    kAlreadyPresent = 1,
    kInvalidArgument = 2,
    kFull = 3,
    kIdentityConflict = 4,
};

static_assert(sizeof(Arm64RegisterSnapshot) == 272U,
              "Unexpected arm64 register layout");
static_assert(sizeof(TaskResumeMode) == sizeof(uint32_t),
              "Unexpected task resume mode layout");
static_assert(__is_standard_layout(ActiveSyscallSnapshot) &&
              __is_trivially_copyable(ActiveSyscallSnapshot));
static_assert(__is_standard_layout(TaskRecord) &&
              __is_trivially_copyable(TaskRecord));
static_assert(__is_standard_layout(TaskTable) &&
              __is_trivially_copyable(TaskTable));

void Init(TaskTable* table) noexcept;
bool IsInitialized(const TaskTable* table) noexcept;
bool Validate(const TaskTable* table) noexcept;

TaskRecord* Find(TaskTable* table, int32_t tid) noexcept;
const TaskRecord* Find(const TaskTable* table, int32_t tid) noexcept;
uint32_t FindSlot(const TaskTable* table, int32_t tid) noexcept;

TaskRecord* At(TaskTable* table, uint32_t slot) noexcept;
const TaskRecord* At(const TaskTable* table, uint32_t slot) noexcept;

TaskInsertResult Insert(TaskTable* table, int32_t tid, int32_t tgid,
                        TaskRecord** record) noexcept;
bool Erase(TaskTable* table, int32_t tid) noexcept;
bool EraseAt(TaskTable* table, uint32_t slot) noexcept;

uint32_t Count(const TaskTable* table) noexcept;
constexpr uint32_t Capacity() noexcept {
    return kTaskTableCapacity;
}
bool Empty(const TaskTable* table) noexcept;
bool Full(const TaskTable* table) noexcept;

void ClearActiveSyscall(TaskRecord* record) noexcept;

}  // namespace hookself::tracer
