#pragma once

#include <cstddef>
#include <cstdint>

#include "internal/logical_ptrace_dispatcher.h"

namespace hookself::internal {

constexpr uint32_t kLogicalPtraceResidentCapacity = 512U;
constexpr uint32_t kLogicalPtraceResidentMagic = 0x48534c52U;  // HSLR
constexpr uint32_t kLogicalPtraceResidentVersion = 1U;

enum LogicalPtraceResidentTaskFlags : uint32_t {
    kLogicalPtraceResidentTaskNone = 0,
    kLogicalPtraceResidentTaskActive = 1U << 0,
    kLogicalPtraceResidentTaskExited = 1U << 1,
    kLogicalPtraceResidentTaskParentValid = 1U << 2,
};

struct LogicalPtraceResidentTask {
    uint32_t occupied;
    uint32_t slot;
    uint32_t flags;
    uint32_t reserved;
    tracer::LogicalTaskKey key;
    tracer::LogicalTaskKey parent;
};

// This state is intentionally mmap-sized. It owns every logical ptrace table
// and the TID-reuse-safe identity index used by resident callbacks.
struct LogicalPtraceResidentState {
    uint32_t magic;
    uint32_t version;
    uint32_t task_count;
    uint32_t reserved;
    uint64_t mutation_generation;
    LogicalPtraceResidentTask tasks[kLogicalPtraceResidentCapacity];
    tracer::LogicalPtraceTable logical;
    LogicalPtraceDispatcher dispatcher;
};

static_assert(__is_standard_layout(LogicalPtraceResidentTask) &&
              __is_trivially_copyable(LogicalPtraceResidentTask));
static_assert(__is_standard_layout(LogicalPtraceResidentState) &&
              __is_trivially_copyable(LogicalPtraceResidentState));

struct LogicalPtraceResidentIoContext {
    LogicalPtraceResidentState* state;
    void* backend_opaque;
    LogicalPtraceMayAttach may_attach;
    LogicalPtraceReadMemory read_memory;
    LogicalPtraceWriteMemory write_memory;
    LogicalPtraceQueryUid query_uid;
    LogicalPtraceFillRusage fill_rusage;
};

void InitLogicalPtraceResidentState(
        LogicalPtraceResidentState* state) noexcept;
bool IsLogicalPtraceResidentStateInitialized(
        const LogicalPtraceResidentState* state) noexcept;
bool ValidateLogicalPtraceResidentState(
        const LogicalPtraceResidentState* state) noexcept;

const LogicalPtraceResidentTask* LogicalPtraceResidentTaskAt(
        const LogicalPtraceResidentState* state, uint32_t slot) noexcept;
const LogicalPtraceResidentTask* FindLogicalPtraceResidentTask(
        const LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept;
// Resolves the currently active identity for tid. Exited identities remain
// addressable by their complete LogicalTaskKey but are never returned here.
const LogicalPtraceResidentTask* FindLogicalPtraceResidentTid(
        const LogicalPtraceResidentState* state, int32_t tid) noexcept;

// process_group/dumpable/ptracer are used only when this is the first task in
// a TGID. parent may be null or a task in another registered TGID.
int RegisterLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state, uint32_t slot,
        const tracer::LogicalTaskKey& key,
        const tracer::LogicalTaskKey* parent, int32_t process_group,
        int32_t dumpable,
        const tracer::LogicalPidIdentity& ptracer) noexcept;

int MarkLogicalPtraceResidentTaskExited(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept;

// Retiring requires all logical relations/waits involving this exact task to
// be gone. Immediate dispatch and fake-TRACEME state are cancelled here.
int RetireLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept;

int RekeyLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& old_identity,
        const tracer::LogicalTaskKey& new_identity) noexcept;

// Atomically merges an execing nonleader into the already registered leader
// identity used after exec de-thread. Both keys must belong to the same TGID
// and process generation. The former task wins for thread-local logical
// state; displaced leader operations, waits, fake-TRACEME state and tracee
// relation are discarded. Relations owned by either task are retained under
// destination_identity. On any error, state is byte-for-byte unchanged.
int MergeExecLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& former_identity,
        const tracer::LogicalTaskKey& destination_identity) noexcept;

// Removes unreferenced process records left behind while descendants still
// held parent identities. Returns the number of collected records.
uint32_t CollectLogicalPtraceResidentProcesses(
        LogicalPtraceResidentState* state) noexcept;

// The returned dispatcher IO object points at io_context, which must outlive
// each dispatcher call. Task and parent resolution are supplied by state;
// all other callbacks delegate to the backend fields above.
LogicalPtraceDispatchIo MakeLogicalPtraceResidentIo(
        LogicalPtraceResidentIoContext* io_context) noexcept;

}  // namespace hookself::internal
