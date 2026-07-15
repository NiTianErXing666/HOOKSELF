#pragma once

#include <cstddef>
#include <cstdint>

#include "tracer/logical_ptrace.h"

namespace hookself::internal {

constexpr uint32_t kLogicalPtraceDispatchCapacity = 512U;
constexpr uint32_t kLogicalPtraceDispatchMagic = 0x48534c44U;  // HSLD
constexpr uint32_t kLogicalPtraceDispatchVersion = 1U;
constexpr uint32_t kLogicalPtraceDispatchInvalidSlot = UINT32_MAX;

using LogicalPtraceResolveTask = int (*)(
        void* opaque, const tracer::LogicalTaskKey* caller, int32_t tid,
        tracer::LogicalTaskKey* output) noexcept;
using LogicalPtraceResolveParent = int (*)(
        void* opaque, const tracer::LogicalTaskKey* caller,
        tracer::LogicalTaskKey* output) noexcept;
using LogicalPtraceMayAttach = int (*)(
        void* opaque, const tracer::LogicalTaskKey* caller,
        const tracer::LogicalTaskKey* target,
        tracer::LogicalPtraceAttachKind kind) noexcept;
using LogicalPtraceReadMemory = int (*)(
        void* opaque, const tracer::LogicalTaskKey* task, uintptr_t address,
        void* output, size_t size) noexcept;
using LogicalPtraceWriteMemory = int (*)(
        void* opaque, const tracer::LogicalTaskKey* task, uintptr_t address,
        const void* input, size_t size) noexcept;
using LogicalPtraceQueryUid = int (*)(
        void* opaque, const tracer::LogicalTaskKey* task,
        uint32_t* uid) noexcept;
using LogicalPtraceFillRusage = int (*)(
        void* opaque, const tracer::LogicalTaskKey* tracee,
        const tracer::LogicalPtraceEvent* event, void* output,
        size_t size) noexcept;

struct LogicalPtraceDispatchIo {
    void* opaque;
    LogicalPtraceResolveTask resolve_task;
    LogicalPtraceResolveParent resolve_parent;
    LogicalPtraceMayAttach may_attach;
    LogicalPtraceReadMemory read_memory;
    LogicalPtraceWriteMemory write_memory;
    LogicalPtraceQueryUid query_uid;
    LogicalPtraceFillRusage fill_rusage;
};

enum class LogicalPtraceTargetAction : uint32_t {
    kNone = 0,
    kInterrupt = 1,
    kResumeCont = 2,
    kResumeSyscall = 3,
    kListen = 4,
    kDetach = 5,
    kResumeSingleStep = 6,
};

enum LogicalPtraceTargetFlags : uint32_t {
    kLogicalPtraceTargetNone = 0,
    kLogicalPtraceTargetRegistersValid = 1U << 0,
    kLogicalPtraceTargetSyscallNumberValid = 1U << 1,
    kLogicalPtraceTargetSiginfoValid = 1U << 2,
};

struct LogicalPtraceTargetRequest {
    LogicalPtraceTargetAction action;
    uint32_t flags;
    tracer::LogicalTaskKey target;
    int32_t signal_number;
    int32_t syscall_number;
    tracer::LogicalPtraceEventKind stop_kind;
    uint32_t reserved;
    siginfo_t signal_info;
    hookself::arch::Arm64Regs registers;
};

enum LogicalPtraceEntryFlags : uint32_t {
    kLogicalPtraceEntryNone = 0,
    kLogicalPtraceEntryHandled = 1U << 0,
    // Replace the user syscall with a harmless syscall and call the exit
    // dispatcher at the resulting syscall-exit stop.
    kLogicalPtraceEntrySuppress = 1U << 1,
    // The suppressed wait has no event yet. Its exit stop must be held.
    kLogicalPtraceEntryMayHold = 1U << 2,
    kLogicalPtraceEntryTargetAction = 1U << 3,
};

struct LogicalPtraceEntryResult {
    uint32_t flags;
    uint32_t operation_slot;
    int64_t visible_result;
    int32_t syscall_number;
    uint32_t reserved;
    LogicalPtraceTargetRequest target;
};

enum LogicalPtraceExitFlags : uint32_t {
    kLogicalPtraceExitNone = 0,
    kLogicalPtraceExitHandled = 1U << 0,
    kLogicalPtraceExitWriteResult = 1U << 1,
    kLogicalPtraceExitHold = 1U << 2,
};

struct LogicalPtraceExitResult {
    uint32_t flags;
    uint32_t operation_slot;
    int64_t visible_result;
};

enum class LogicalPtraceOperationState : uint32_t {
    kImmediate = 1,
    kHeldWait = 2,
    kHeldReady = 3,
};

struct LogicalPtraceDispatchOperation {
    uint32_t occupied;
    uint32_t slot;
    uint64_t generation;
    tracer::LogicalTaskKey caller;
    int32_t syscall_number;
    LogicalPtraceOperationState state;
    int64_t visible_result;
};

enum LogicalPtraceStopFlags : uint32_t {
    kLogicalPtraceStopNone = 0,
    kLogicalPtraceStopCurrentValid = 1U << 0,
    kLogicalPtraceStopInterruptPending = 1U << 1,
    kLogicalPtraceStopAttachPending = 1U << 2,
};

struct LogicalPtraceDispatchStop {
    uint32_t flags;
    uint32_t relation_slot;
    uint64_t relation_generation;
    tracer::LogicalTaskKey tracee;
    tracer::LogicalPtraceEvent current;
};

// The dispatcher is fixed-capacity and should be placed in mmap/static
// storage. It stores only identity keys and relation generations.
struct LogicalPtraceDispatcher {
    uint32_t magic;
    uint32_t version;
    uint32_t operation_count;
    uint32_t operation_free_hint;
    uint64_t mutation_generation;
    uint64_t next_operation_generation;
    LogicalPtraceDispatchOperation operations[kLogicalPtraceDispatchCapacity];
    LogicalPtraceDispatchStop stops[kLogicalPtraceDispatchCapacity];
};

static_assert(__is_standard_layout(LogicalPtraceDispatchOperation) &&
              __is_trivially_copyable(LogicalPtraceDispatchOperation));
static_assert(__is_standard_layout(LogicalPtraceDispatcher) &&
              __is_trivially_copyable(LogicalPtraceDispatcher));
static_assert(sizeof(LogicalPtraceDispatcher) <= 1024U * 1024U,
              "Logical ptrace dispatcher exceeded its memory budget");

void InitLogicalPtraceDispatcher(LogicalPtraceDispatcher* dispatcher) noexcept;
bool IsLogicalPtraceDispatcherInitialized(
        const LogicalPtraceDispatcher* dispatcher) noexcept;
bool ValidateLogicalPtraceDispatcher(
        const LogicalPtraceDispatcher* dispatcher,
        const tracer::LogicalPtraceTable* logical) noexcept;

const LogicalPtraceDispatchOperation* LogicalPtraceOperationAt(
        const LogicalPtraceDispatcher* dispatcher, uint32_t slot) noexcept;

// All functions return zero or a positive errno. Syscall-level failures are
// reported as a handled negative visible_result, not as the API return value.
int DispatchLogicalPtraceEntry(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const LogicalPtraceDispatchIo& io,
        const tracer::LogicalTaskKey& caller, int32_t syscall_number,
        const uint64_t arguments[6],
        LogicalPtraceEntryResult* result) noexcept;

int DispatchLogicalPtraceExit(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& caller, int32_t syscall_number,
        int64_t kernel_result, LogicalPtraceExitResult* result) noexcept;

// Queues an outer stop for a logical tracee. Resident code should use this
// wrapper instead of QueueLogicalPtraceEvent so pending ATTACH/INTERRUPT state
// stays synchronized.
int PublishLogicalPtraceStop(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& tracee,
        const tracer::LogicalPtraceEvent& event,
        uint64_t* sequence) noexcept;

// Attempts to complete one blocked wait. EAGAIN means it remains blocked;
// ESRCH means caller has no held wait. A successful completion changes the
// in-flight operation to kHeldReady; its existing syscall-exit stop can then
// be passed to DispatchLogicalPtraceExit.
int TryWakeLogicalPtraceWait(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const LogicalPtraceDispatchIo& io,
        const tracer::LogicalTaskKey& waiter) noexcept;

// Cancels one in-flight operation and its logical wait record. This is used
// by task-exit, exec migration failure and resident shutdown paths.
int CancelLogicalPtraceDispatch(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& caller) noexcept;

// Applies an exec de-thread/TID identity migration to both the logical ptrace
// table and the dispatcher's in-flight operation and delivered-stop views.
// The process identity must remain unchanged.
int RekeyLogicalPtraceDispatchTask(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& old_identity,
        const tracer::LogicalTaskKey& new_identity) noexcept;

}  // namespace hookself::internal
