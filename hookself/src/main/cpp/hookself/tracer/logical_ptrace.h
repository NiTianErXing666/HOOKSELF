#pragma once

#include <signal.h>
#include <stdint.h>

#include "arch/arm64_regs.h"

namespace hookself::tracer {

constexpr uint32_t kLogicalPtraceProcessCapacity = 512U;
constexpr uint32_t kLogicalPtraceRelationCapacity = 512U;
constexpr uint32_t kLogicalPtraceFakeTracemeCapacity = 512U;
constexpr uint32_t kLogicalPtraceWaitCapacity = 512U;
constexpr uint32_t kLogicalPtraceEventQueueCapacity = 4U;
constexpr uint32_t kInvalidLogicalPtraceSlot = UINT32_MAX;
constexpr uint32_t kLogicalPtraceMagic = 0x48534c50U;  // HSLP
constexpr uint32_t kLogicalPtraceVersion = 1U;

constexpr uint64_t kLogicalPtraceOptionTraceSysgood = 0x00000001ULL;
constexpr uint64_t kLogicalPtraceOptionTraceFork = 0x00000002ULL;
constexpr uint64_t kLogicalPtraceOptionTraceVfork = 0x00000004ULL;
constexpr uint64_t kLogicalPtraceOptionTraceClone = 0x00000008ULL;
constexpr uint64_t kLogicalPtraceOptionTraceExec = 0x00000010ULL;
constexpr uint64_t kLogicalPtraceOptionTraceVforkDone = 0x00000020ULL;
constexpr uint64_t kLogicalPtraceOptionTraceExit = 0x00000040ULL;
constexpr uint64_t kLogicalPtraceOptionTraceSeccomp = 0x00000080ULL;
constexpr uint64_t kLogicalPtraceOptionExitKill = 0x00100000ULL;
constexpr uint64_t kLogicalPtraceOptionSuspendSeccomp = 0x00200000ULL;
constexpr uint64_t kLogicalPtraceKnownOptionMask =
        kLogicalPtraceOptionTraceSysgood |
        kLogicalPtraceOptionTraceFork |
        kLogicalPtraceOptionTraceVfork |
        kLogicalPtraceOptionTraceClone |
        kLogicalPtraceOptionTraceExec |
        kLogicalPtraceOptionTraceVforkDone |
        kLogicalPtraceOptionTraceExit |
        kLogicalPtraceOptionTraceSeccomp |
        kLogicalPtraceOptionExitKill |
        kLogicalPtraceOptionSuspendSeccomp;

constexpr uint32_t kLogicalWaitNoHang = 0x00000001U;
constexpr uint32_t kLogicalWaitStopped = 0x00000002U;
constexpr uint32_t kLogicalWaitExited = 0x00000004U;
constexpr uint32_t kLogicalWaitContinued = 0x00000008U;
constexpr uint32_t kLogicalWaitNowait = 0x01000000U;
constexpr uint32_t kLogicalWaitNoThread = 0x20000000U;
constexpr uint32_t kLogicalWaitAll = 0x40000000U;
constexpr uint32_t kLogicalWaitClone = 0x80000000U;

struct LogicalProcessKey {
    int32_t tgid;
    uint32_t reserved;
    uint64_t generation;
};

struct LogicalTaskKey {
    int32_t tid;
    int32_t tgid;
    uint64_t generation;
    uint64_t process_generation;
};

struct LogicalPidIdentity {
    int32_t pid;
    uint32_t reserved;
    uint64_t start_time;
};

enum LogicalProcessFlags : uint32_t {
    kLogicalProcessFlagNone = 0,
    kLogicalProcessFlagParentKnown = 1U << 0,
};

struct LogicalProcessRecord {
    uint32_t occupied;
    uint32_t slot;
    LogicalProcessKey key;
    LogicalProcessKey parent;
    int32_t process_group;
    int32_t logical_dumpable;
    LogicalPidIdentity logical_ptracer;
    uint32_t flags;
    uint32_t reserved;
};

enum class LogicalPtraceAttachKind : uint32_t {
    kTraceme = 1,
    kAttach = 2,
    kSeize = 3,
};

enum class LogicalPtraceRelationState : uint32_t {
    kAttachPending = 1,
    kSeizeRunning = 2,
    kStopped = 3,
    kRunningCont = 4,
    kRunningSyscall = 5,
    kExitZombie = 6,
    kRunningSingleStep = 7,
    kListening = 8,
};

enum class LogicalPtraceResumeMode : uint32_t {
    kCont = 1,
    kSyscall = 2,
    kSingleStep = 3,
};

enum class LogicalPtraceWaitClass : uint32_t {
    kNormal = 1,
    kClone = 2,
};

enum class LogicalPtraceEventKind : uint32_t {
    kAttachStop = 1,
    kInterruptStop = 2,
    kSignalDelivery = 3,
    kGroupStop = 4,
    kSyscallEntry = 5,
    kSyscallExit = 6,
    kPtraceEvent = 7,
    kExited = 8,
    kSignaled = 9,
    kContinued = 10,
};

enum LogicalPtraceEventFlags : uint32_t {
    kLogicalPtraceEventFlagNone = 0,
    kLogicalPtraceEventFlagSiginfoValid = 1U << 0,
    kLogicalPtraceEventFlagRegistersValid = 1U << 1,
    kLogicalPtraceEventFlagSyscallNumberValid = 1U << 2,
};

struct LogicalPtraceEvent {
    uint64_t sequence;
    LogicalPtraceEventKind kind;
    uint32_t flags;
    int32_t wait_status;
    int32_t signal_number;
    uint32_t ptrace_event;
    int32_t guest_syscall_number;
    uint32_t reserved;
    uint64_t event_message;
    siginfo_t signal_info;
    hookself::arch::Arm64Regs guest_registers;
};

struct LogicalPtraceRelation {
    uint32_t occupied;
    uint32_t slot;
    uint64_t generation;
    LogicalTaskKey tracee;
    LogicalTaskKey tracer;
    LogicalPtraceAttachKind attach_kind;
    LogicalPtraceRelationState state;
    LogicalPtraceWaitClass wait_class;
    uint32_t event_head;
    uint32_t event_count;
    uint32_t reserved;
    uint64_t options;
    LogicalPtraceEvent events[kLogicalPtraceEventQueueCapacity];
};

struct LogicalFakeTracemeRecord {
    uint32_t occupied;
    uint32_t slot;
    LogicalTaskKey task;
};

enum class LogicalWaitKind : uint32_t {
    kWait4 = 1,
    kWaitId = 2,
};

enum class LogicalWaitSelectorKind : uint32_t {
    kAny = 1,
    kTid = 2,
    kProcessGroup = 3,
};

enum class LogicalWaitIdType : uint32_t {
    kAll = 1,
    kPid = 2,
    kProcessGroup = 3,
    kPidFd = 4,
};

struct LogicalWaitRequest {
    LogicalTaskKey waiter;
    LogicalWaitKind kind;
    LogicalWaitSelectorKind selector_kind;
    int32_t selector_id;
    uint32_t options;
    uint32_t nohang;
    uint32_t nowait;
    uint32_t reserved;
    uint64_t status_address;
    uint64_t info_address;
    uint64_t rusage_address;
    uint64_t token;
};

struct LogicalWaitRecord {
    uint32_t occupied;
    uint32_t slot;
    uint64_t generation;
    LogicalWaitRequest request;
};

struct LogicalWaitMatch {
    uint32_t relation_slot;
    uint32_t reserved;
    uint64_t relation_generation;
    uint64_t event_sequence;
};

// This table is intentionally large and should live in mmap/static storage,
// never on a tracer thread stack.
struct LogicalPtraceTable {
    uint32_t magic;
    uint32_t version;
    uint32_t process_count;
    uint32_t relation_count;
    uint32_t fake_traceme_count;
    uint32_t wait_count;
    uint32_t process_free_hint;
    uint32_t relation_free_hint;
    uint32_t fake_traceme_free_hint;
    uint32_t wait_free_hint;
    uint64_t mutation_generation;
    uint64_t next_relation_generation;
    uint64_t next_event_sequence;
    uint64_t next_wait_generation;
    LogicalProcessRecord processes[kLogicalPtraceProcessCapacity];
    LogicalPtraceRelation relations[kLogicalPtraceRelationCapacity];
    LogicalFakeTracemeRecord fake_traceme[kLogicalPtraceFakeTracemeCapacity];
    LogicalWaitRecord waits[kLogicalPtraceWaitCapacity];
};

static_assert(__is_standard_layout(LogicalProcessKey) &&
              __is_trivially_copyable(LogicalProcessKey));
static_assert(__is_standard_layout(LogicalTaskKey) &&
              __is_trivially_copyable(LogicalTaskKey));
static_assert(__is_standard_layout(LogicalPtraceEvent) &&
              __is_trivially_copyable(LogicalPtraceEvent));
static_assert(__is_standard_layout(LogicalPtraceTable) &&
              __is_trivially_copyable(LogicalPtraceTable));
static_assert(sizeof(LogicalPtraceTable) <= 2U * 1024U * 1024U,
              "Logical ptrace table exceeded its fixed memory budget");

bool LogicalProcessKeysEqual(const LogicalProcessKey& first,
                             const LogicalProcessKey& second) noexcept;
bool LogicalTaskKeysEqual(const LogicalTaskKey& first,
                          const LogicalTaskKey& second) noexcept;
LogicalProcessKey LogicalProcessKeyForTask(
        const LogicalTaskKey& task) noexcept;

void InitLogicalPtraceTable(LogicalPtraceTable* table) noexcept;
bool IsLogicalPtraceTableInitialized(const LogicalPtraceTable* table) noexcept;
bool ValidateLogicalPtraceTable(const LogicalPtraceTable* table) noexcept;

const LogicalProcessRecord* FindLogicalProcess(
        const LogicalPtraceTable* table,
        const LogicalProcessKey& key) noexcept;
const LogicalProcessRecord* LogicalProcessAt(
        const LogicalPtraceTable* table, uint32_t slot) noexcept;
int InsertLogicalProcess(LogicalPtraceTable* table,
                         const LogicalProcessKey& key,
                         const LogicalProcessKey* parent,
                         int32_t process_group, int32_t logical_dumpable,
                         const LogicalPidIdentity& logical_ptracer,
                         uint32_t* slot) noexcept;
int InheritLogicalProcess(LogicalPtraceTable* table,
                          const LogicalProcessKey& child,
                          const LogicalProcessKey& parent,
                          int32_t child_process_group,
                          uint32_t* slot) noexcept;
int EraseLogicalProcess(LogicalPtraceTable* table,
                        const LogicalProcessKey& key) noexcept;
int SetLogicalProcessDumpable(LogicalPtraceTable* table,
                              const LogicalProcessKey& key,
                              int32_t logical_dumpable) noexcept;
int SetLogicalProcessPtracer(LogicalPtraceTable* table,
                             const LogicalProcessKey& key,
                             const LogicalPidIdentity& logical_ptracer) noexcept;
int SetLogicalProcessGroup(LogicalPtraceTable* table,
                           const LogicalProcessKey& key,
                           int32_t process_group) noexcept;
int SetLogicalProcessParent(LogicalPtraceTable* table,
                            const LogicalProcessKey& key,
                            const LogicalProcessKey* parent) noexcept;

// Fake TRACEME records provide the Level-1 anti-debug view only. They never
// create a LogicalPtraceRelation or affect logical wait selection.
int ClaimLogicalFakeTraceme(LogicalPtraceTable* table,
                            const LogicalTaskKey& task) noexcept;
bool HasLogicalFakeTraceme(const LogicalPtraceTable* table,
                           const LogicalTaskKey& task) noexcept;
int ClearLogicalFakeTraceme(LogicalPtraceTable* table,
                            const LogicalTaskKey& task) noexcept;

const LogicalPtraceRelation* FindLogicalPtraceRelation(
        const LogicalPtraceTable* table,
        const LogicalTaskKey& tracee) noexcept;
const LogicalPtraceRelation* LogicalPtraceRelationAt(
        const LogicalPtraceTable* table, uint32_t slot) noexcept;
int CreateLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                const LogicalTaskKey& tracer,
                                LogicalPtraceAttachKind attach_kind,
                                LogicalPtraceWaitClass wait_class,
                                uint64_t options,
                                uint32_t* slot) noexcept;

// Creates the auto-attached relation for a TRACEFORK/TRACEVFORK/TRACECLONE
// child and queues its first stop as one transaction. The new relation
// inherits the parent relation's tracer, attach kind and options. On error,
// the table is unchanged and both optional outputs are reset.
int CreateInheritedLogicalPtraceRelation(
        LogicalPtraceTable* table,
        const LogicalTaskKey& parent_tracee,
        const LogicalTaskKey& child_tracee,
        LogicalPtraceWaitClass wait_class,
        const LogicalPtraceEvent& initial_stop,
        uint32_t* slot, uint64_t* sequence) noexcept;
int EraseLogicalPtraceRelation(LogicalPtraceTable* table,
                               const LogicalTaskKey& tracee,
                               bool discard_pending_events) noexcept;
int SetLogicalPtraceOptions(LogicalPtraceTable* table,
                            const LogicalTaskKey& tracee,
                            uint64_t options) noexcept;
int ResumeLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                LogicalPtraceResumeMode mode) noexcept;
int ListenLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee) noexcept;

// The event sequence is assigned by the table. The caller should leave
// event.sequence as zero. Queueing an exit event moves the relation to
// kExitZombie; all other events move it to kStopped.
int QueueLogicalPtraceEvent(LogicalPtraceTable* table,
                            const LogicalTaskKey& tracee,
                            const LogicalPtraceEvent& event,
                            uint64_t* sequence) noexcept;
int PeekLogicalPtraceEvent(const LogicalPtraceTable* table,
                           const LogicalTaskKey& tracee,
                           LogicalPtraceEvent* event) noexcept;
int SetLogicalPtraceEventRegisters(
        LogicalPtraceTable* table, const LogicalTaskKey& tracee,
        const hookself::arch::Arm64Regs& registers,
        bool syscall_number_valid, int32_t syscall_number) noexcept;
int SetLogicalPtraceEventSiginfo(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                const siginfo_t& signal_info) noexcept;
int ConsumeLogicalPtraceEvent(LogicalPtraceTable* table,
                              const LogicalTaskKey& tracee,
                              bool preserve, LogicalPtraceEvent* event) noexcept;

int BuildLogicalWait4Request(const LogicalTaskKey& waiter, int32_t pid,
                             int32_t caller_process_group, uint32_t options,
                             uint64_t status_address,
                             uint64_t rusage_address, uint64_t token,
                             LogicalWaitRequest* request) noexcept;
int BuildLogicalWaitIdRequest(const LogicalTaskKey& waiter,
                              LogicalWaitIdType id_type, uint64_t id,
                              int32_t caller_process_group, uint32_t options,
                              uint64_t info_address,
                              uint64_t rusage_address, uint64_t token,
                              LogicalWaitRequest* request) noexcept;
int BeginLogicalWait(LogicalPtraceTable* table,
                     const LogicalWaitRequest& request,
                     uint32_t* slot) noexcept;
const LogicalWaitRecord* FindLogicalWait(const LogicalPtraceTable* table,
                                         const LogicalTaskKey& waiter) noexcept;
const LogicalWaitRecord* LogicalWaitAt(const LogicalPtraceTable* table,
                                       uint32_t slot) noexcept;
int EndLogicalWait(LogicalPtraceTable* table,
                   const LogicalTaskKey& waiter) noexcept;

// Returns 0 with the oldest matching event, EAGAIN when matching logical
// ptracees exist but none has a selectable event, or ECHILD when no logical
// ptracee matches the request.
int SelectLogicalWaitEvent(const LogicalPtraceTable* table,
                           const LogicalTaskKey& waiter,
                           LogicalWaitMatch* match) noexcept;

// Completes the registered logical wait. WNOWAIT preserves the event. A
// consumed exit event also retires its kExitZombie relation.
int ConsumeLogicalWaitEvent(LogicalPtraceTable* table,
                            const LogicalTaskKey& waiter,
                            const LogicalWaitMatch& match,
                            LogicalPtraceEvent* event) noexcept;

// Atomically replaces every fake-TRACEME, relation and wait reference to old
// identity. This is intended for exec de-thread migration and TID reuse-safe
// identity refresh; it does not create or erase a process record.
int RekeyLogicalPtraceTask(LogicalPtraceTable* table,
                           const LogicalTaskKey& old_identity,
                           const LogicalTaskKey& new_identity) noexcept;

}  // namespace hookself::tracer
