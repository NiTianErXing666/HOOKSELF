#include "internal/logical_ptrace_resident_state.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

namespace hookself::internal {
namespace {

constexpr uint32_t kResidentTaskFlagMask =
        kLogicalPtraceResidentTaskActive |
        kLogicalPtraceResidentTaskExited |
        kLogicalPtraceResidentTaskParentValid;

bool TaskKeyValid(const tracer::LogicalTaskKey& task) noexcept {
    return task.tid > 0 && task.tgid > 0 && task.generation != 0U &&
           task.process_generation != 0U;
}

void ClearTask(LogicalPtraceResidentTask* task, uint32_t slot) noexcept {
    memset(task, 0, sizeof(*task));
    task->slot = slot;
}

bool TaskReferencedByRelation(const LogicalPtraceResidentState* state,
                              const tracer::LogicalTaskKey& key) noexcept {
    for (uint32_t slot = 0; slot < tracer::kLogicalPtraceRelationCapacity;
         ++slot) {
        const tracer::LogicalPtraceRelation* relation =
                tracer::LogicalPtraceRelationAt(&state->logical, slot);
        if (relation != nullptr &&
            (tracer::LogicalTaskKeysEqual(relation->tracee, key) ||
             tracer::LogicalTaskKeysEqual(relation->tracer, key))) {
            return true;
        }
    }
    return false;
}

void ClearStaleStop(LogicalPtraceResidentState* state,
                    const tracer::LogicalTaskKey& key) noexcept {
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        LogicalPtraceDispatchStop& stop = state->dispatcher.stops[slot];
        const tracer::LogicalPtraceRelation* relation =
                tracer::LogicalPtraceRelationAt(&state->logical, slot);
        if (stop.relation_generation == 0U ||
            !tracer::LogicalTaskKeysEqual(stop.tracee, key) ||
            (relation != nullptr &&
             relation->generation == stop.relation_generation &&
             tracer::LogicalTaskKeysEqual(relation->tracee, stop.tracee))) {
            continue;
        }
        memset(&stop, 0, sizeof(stop));
        stop.relation_slot = slot;
        stop.current.guest_syscall_number = -1;
        ++state->dispatcher.mutation_generation;
    }
}

int ResolveTaskCallback(void* opaque,
                        const tracer::LogicalTaskKey*, int32_t tid,
                        tracer::LogicalTaskKey* output) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    if (io == nullptr || io->state == nullptr || output == nullptr) {
        return EINVAL;
    }
    const LogicalPtraceResidentTask* task =
            FindLogicalPtraceResidentTid(io->state, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    *output = task->key;
    return 0;
}

int ResolveParentCallback(void* opaque,
                          const tracer::LogicalTaskKey* caller,
                          tracer::LogicalTaskKey* output) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    if (io == nullptr || io->state == nullptr || caller == nullptr ||
        output == nullptr) {
        return EINVAL;
    }
    const LogicalPtraceResidentTask* task =
            FindLogicalPtraceResidentTask(io->state, *caller);
    if (task == nullptr ||
        (task->flags & kLogicalPtraceResidentTaskParentValid) == 0U) {
        return ESRCH;
    }
    const LogicalPtraceResidentTask* parent =
            FindLogicalPtraceResidentTask(io->state, task->parent);
    if (parent == nullptr ||
        (parent->flags & kLogicalPtraceResidentTaskActive) == 0U) {
        return ESRCH;
    }
    *output = task->parent;
    return 0;
}

int MayAttachCallback(void* opaque,
                      const tracer::LogicalTaskKey* caller,
                      const tracer::LogicalTaskKey* target,
                      tracer::LogicalPtraceAttachKind kind) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    if (io == nullptr) {
        return EINVAL;
    }
    return io->may_attach == nullptr
            ? 0
            : io->may_attach(io->backend_opaque, caller, target, kind);
}

int ReadMemoryCallback(void* opaque, const tracer::LogicalTaskKey* task,
                       uintptr_t address, void* output,
                       size_t size) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    return io == nullptr || io->read_memory == nullptr
            ? ENOSYS
            : io->read_memory(io->backend_opaque, task, address, output,
                              size);
}

int WriteMemoryCallback(void* opaque, const tracer::LogicalTaskKey* task,
                        uintptr_t address, const void* input,
                        size_t size) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    return io == nullptr || io->write_memory == nullptr
            ? ENOSYS
            : io->write_memory(io->backend_opaque, task, address, input,
                               size);
}

int QueryUidCallback(void* opaque, const tracer::LogicalTaskKey* task,
                     uint32_t* uid) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    if (io == nullptr || uid == nullptr) {
        return EINVAL;
    }
    if (io->query_uid == nullptr) {
        *uid = 0;
        return 0;
    }
    return io->query_uid(io->backend_opaque, task, uid);
}

int FillRusageCallback(void* opaque,
                       const tracer::LogicalTaskKey* tracee,
                       const tracer::LogicalPtraceEvent* event,
                       void* output, size_t size) noexcept {
    const auto* io = static_cast<const LogicalPtraceResidentIoContext*>(
            opaque);
    if (io == nullptr) {
        return EINVAL;
    }
    if (io->fill_rusage == nullptr) {
        memset(output, 0, size);
        return 0;
    }
    return io->fill_rusage(io->backend_opaque, tracee, event, output, size);
}

int DiscardExecDestinationThreadState(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& destination) noexcept {
    int error = CancelLogicalPtraceDispatch(
            &state->dispatcher, &state->logical, destination);
    if (error != 0 && error != ESRCH) {
        return error;
    }
    error = tracer::EndLogicalWait(&state->logical, destination);
    if (error != 0 && error != ESRCH) {
        return error;
    }
    error = tracer::ClearLogicalFakeTraceme(
            &state->logical, destination);
    if (error != 0 && error != ESRCH) {
        return error;
    }
    if (tracer::FindLogicalPtraceRelation(
                &state->logical, destination) != nullptr) {
        error = tracer::EraseLogicalPtraceRelation(
                &state->logical, destination, true);
        if (error != 0) {
            return error;
        }
    }
    ClearStaleStop(state, destination);
    return 0;
}

int MergeExecLogicalPtraceResidentTaskInPlace(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& former_identity,
        const tracer::LogicalTaskKey& destination_identity) noexcept {
    if (!ValidateLogicalPtraceResidentState(state) ||
        !TaskKeyValid(former_identity) ||
        !TaskKeyValid(destination_identity) ||
        tracer::LogicalTaskKeysEqual(
                former_identity, destination_identity) ||
        former_identity.tid == former_identity.tgid ||
        destination_identity.tid != destination_identity.tgid) {
        return EINVAL;
    }
    if (former_identity.tgid != destination_identity.tgid ||
        former_identity.process_generation !=
                destination_identity.process_generation) {
        return EXDEV;
    }
    auto* former = const_cast<LogicalPtraceResidentTask*>(
            FindLogicalPtraceResidentTask(state, former_identity));
    auto* destination = const_cast<LogicalPtraceResidentTask*>(
            FindLogicalPtraceResidentTask(state, destination_identity));
    if (former == nullptr || destination == nullptr) {
        return ESRCH;
    }
    if (former == destination || former->slot == destination->slot ||
        (former->flags & kLogicalPtraceResidentTaskActive) == 0U) {
        return EINVAL;
    }

    int error = DiscardExecDestinationThreadState(
            state, destination_identity);
    if (error != 0) {
        return error;
    }
    error = RekeyLogicalPtraceDispatchTask(
            &state->dispatcher, &state->logical, former_identity,
            destination_identity);
    if (error != 0 && error != ESRCH) {
        return error;
    }

    const uint32_t former_slot = former->slot;
    const uint32_t destination_slot = destination->slot;
    LogicalPtraceResidentTask merged = *former;
    merged.slot = destination_slot;
    merged.key = destination_identity;
    ClearTask(&state->tasks[former_slot], former_slot);
    state->tasks[destination_slot] = merged;
    --state->task_count;

    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        LogicalPtraceResidentTask& task = state->tasks[slot];
        if (task.occupied == 0U ||
            (task.flags & kLogicalPtraceResidentTaskParentValid) == 0U) {
            continue;
        }
        if (tracer::LogicalTaskKeysEqual(task.parent, former_identity)) {
            task.parent = destination_identity;
        }
        if (tracer::LogicalTaskKeysEqual(task.parent, task.key)) {
            task.flags &= ~kLogicalPtraceResidentTaskParentValid;
            memset(&task.parent, 0, sizeof(task.parent));
        }
    }
    ++state->mutation_generation;
    return ValidateLogicalPtraceResidentState(state) ? 0 : EPROTO;
}

}  // namespace

void InitLogicalPtraceResidentState(
        LogicalPtraceResidentState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    memset(state, 0, sizeof(*state));
    state->magic = kLogicalPtraceResidentMagic;
    state->version = kLogicalPtraceResidentVersion;
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        ClearTask(&state->tasks[slot], slot);
    }
    tracer::InitLogicalPtraceTable(&state->logical);
    InitLogicalPtraceDispatcher(&state->dispatcher);
}

bool IsLogicalPtraceResidentStateInitialized(
        const LogicalPtraceResidentState* state) noexcept {
    return state != nullptr && state->magic == kLogicalPtraceResidentMagic &&
           state->version == kLogicalPtraceResidentVersion &&
           state->task_count <= kLogicalPtraceResidentCapacity &&
           tracer::IsLogicalPtraceTableInitialized(&state->logical) &&
           IsLogicalPtraceDispatcherInitialized(&state->dispatcher);
}

const LogicalPtraceResidentTask* LogicalPtraceResidentTaskAt(
        const LogicalPtraceResidentState* state, uint32_t slot) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) ||
        slot >= kLogicalPtraceResidentCapacity ||
        state->tasks[slot].occupied == 0U) {
        return nullptr;
    }
    return &state->tasks[slot];
}

const LogicalPtraceResidentTask* FindLogicalPtraceResidentTask(
        const LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) ||
        !TaskKeyValid(key)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        const LogicalPtraceResidentTask& task = state->tasks[slot];
        if (task.occupied != 0U &&
            tracer::LogicalTaskKeysEqual(task.key, key)) {
            return &task;
        }
    }
    return nullptr;
}

const LogicalPtraceResidentTask* FindLogicalPtraceResidentTid(
        const LogicalPtraceResidentState* state, int32_t tid) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) || tid <= 0) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        const LogicalPtraceResidentTask& task = state->tasks[slot];
        if (task.occupied != 0U && task.key.tid == tid &&
            (task.flags & kLogicalPtraceResidentTaskActive) != 0U) {
            return &task;
        }
    }
    return nullptr;
}

int RegisterLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state, uint32_t slot,
        const tracer::LogicalTaskKey& key,
        const tracer::LogicalTaskKey* parent, int32_t process_group,
        int32_t dumpable,
        const tracer::LogicalPidIdentity& ptracer) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) ||
        slot >= kLogicalPtraceResidentCapacity || !TaskKeyValid(key) ||
        process_group <= 0 || dumpable < 0 || dumpable > 2 ||
        ptracer.pid < -1 || ptracer.reserved != 0U ||
        (ptracer.pid <= 0 && ptracer.start_time != 0U) ||
        (parent != nullptr && !TaskKeyValid(*parent))) {
        return EINVAL;
    }
    LogicalPtraceResidentTask* entry = &state->tasks[slot];
    if (entry->occupied != 0U) {
        return tracer::LogicalTaskKeysEqual(entry->key, key) &&
                       (entry->flags &
                        kLogicalPtraceResidentTaskActive) != 0U
                ? 0
                : EEXIST;
    }
    if (FindLogicalPtraceResidentTask(state, key) != nullptr) {
        return EEXIST;
    }
    if (FindLogicalPtraceResidentTid(state, key.tid) != nullptr) {
        return EEXIST;
    }

    const tracer::LogicalProcessKey process_key =
            tracer::LogicalProcessKeyForTask(key);
    const tracer::LogicalProcessRecord* process =
            tracer::FindLogicalProcess(&state->logical, process_key);
    tracer::LogicalProcessKey parent_process {};
    const tracer::LogicalProcessKey* parent_process_pointer = nullptr;
    if (parent != nullptr && parent->tgid != key.tgid) {
        parent_process = tracer::LogicalProcessKeyForTask(*parent);
        if (tracer::FindLogicalProcess(&state->logical, parent_process) ==
            nullptr) {
            return ESRCH;
        }
        parent_process_pointer = &parent_process;
    }
    if (process == nullptr) {
        const int process_error = tracer::InsertLogicalProcess(
                &state->logical, process_key, parent_process_pointer,
                process_group, dumpable, ptracer, nullptr);
        if (process_error != 0) {
            return process_error;
        }
    } else if (parent_process_pointer != nullptr &&
               (process->flags & tracer::kLogicalProcessFlagParentKnown) ==
                       0U) {
        const int parent_error = tracer::SetLogicalProcessParent(
                &state->logical, process_key, parent_process_pointer);
        if (parent_error != 0) {
            return parent_error;
        }
    }

    ClearTask(entry, slot);
    entry->occupied = 1U;
    entry->flags = kLogicalPtraceResidentTaskActive;
    entry->key = key;
    if (parent != nullptr) {
        entry->flags |= kLogicalPtraceResidentTaskParentValid;
        entry->parent = *parent;
    }
    ++state->task_count;
    ++state->mutation_generation;
    return 0;
}

int MarkLogicalPtraceResidentTaskExited(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept {
    auto* task = const_cast<LogicalPtraceResidentTask*>(
            FindLogicalPtraceResidentTask(state, key));
    if (task == nullptr) {
        return ESRCH;
    }
    task->flags &= ~kLogicalPtraceResidentTaskActive;
    task->flags |= kLogicalPtraceResidentTaskExited;
    ++state->mutation_generation;
    return 0;
}

uint32_t CollectLogicalPtraceResidentProcesses(
        LogicalPtraceResidentState* state) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state)) {
        return 0;
    }
    uint32_t collected = 0;
    bool progress = true;
    while (progress) {
        progress = false;
        for (uint32_t slot = 0;
             slot < tracer::kLogicalPtraceProcessCapacity; ++slot) {
            const tracer::LogicalProcessRecord* process =
                    tracer::LogicalProcessAt(&state->logical, slot);
            if (process == nullptr) {
                continue;
            }
            bool has_task = false;
            for (uint32_t task_slot = 0;
                 task_slot < kLogicalPtraceResidentCapacity; ++task_slot) {
                const LogicalPtraceResidentTask& task =
                        state->tasks[task_slot];
                if (task.occupied != 0U && task.key.tgid == process->key.tgid &&
                    task.key.process_generation == process->key.generation) {
                    has_task = true;
                    break;
                }
            }
            const tracer::LogicalProcessKey key = process->key;
            if (!has_task &&
                tracer::EraseLogicalProcess(&state->logical, key) == 0) {
                ++collected;
                progress = true;
                break;
            }
        }
    }
    if (collected != 0U) {
        ++state->mutation_generation;
    }
    return collected;
}

int RetireLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& key) noexcept {
    auto* task = const_cast<LogicalPtraceResidentTask*>(
            FindLogicalPtraceResidentTask(state, key));
    if (task == nullptr) {
        return ESRCH;
    }
    if (TaskReferencedByRelation(state, key) ||
        tracer::FindLogicalWait(&state->logical, key) != nullptr) {
        return EBUSY;
    }
    const int cancel_error = CancelLogicalPtraceDispatch(
            &state->dispatcher, &state->logical, key);
    if (cancel_error != 0 && cancel_error != ESRCH) {
        return cancel_error;
    }
    const int fake_error = tracer::ClearLogicalFakeTraceme(
            &state->logical, key);
    if (fake_error != 0 && fake_error != ESRCH) {
        return fake_error;
    }
    ClearStaleStop(state, key);
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        LogicalPtraceResidentTask& child = state->tasks[slot];
        if (child.occupied != 0U &&
            (child.flags & kLogicalPtraceResidentTaskParentValid) != 0U &&
            tracer::LogicalTaskKeysEqual(child.parent, key)) {
            child.flags &= ~kLogicalPtraceResidentTaskParentValid;
            memset(&child.parent, 0, sizeof(child.parent));
        }
    }
    const uint32_t task_slot = task->slot;
    ClearTask(task, task_slot);
    --state->task_count;
    ++state->mutation_generation;
    (void)CollectLogicalPtraceResidentProcesses(state);
    return 0;
}

int RekeyLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& old_identity,
        const tracer::LogicalTaskKey& new_identity) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) ||
        !TaskKeyValid(old_identity) || !TaskKeyValid(new_identity)) {
        return EINVAL;
    }
    if (tracer::LogicalTaskKeysEqual(old_identity, new_identity)) {
        return 0;
    }
    auto* task = const_cast<LogicalPtraceResidentTask*>(
            FindLogicalPtraceResidentTask(state, old_identity));
    const LogicalPtraceResidentTask* exact_duplicate =
            FindLogicalPtraceResidentTask(state, new_identity);
    const LogicalPtraceResidentTask* active_duplicate =
            FindLogicalPtraceResidentTid(state, new_identity.tid);
    if (task == nullptr) {
        return ESRCH;
    }
    if ((exact_duplicate != nullptr && exact_duplicate != task) ||
        (active_duplicate != nullptr && active_duplicate != task)) {
        return EEXIST;
    }
    const int rekey_error = RekeyLogicalPtraceDispatchTask(
            &state->dispatcher, &state->logical, old_identity, new_identity);
    if (rekey_error != 0 && rekey_error != ESRCH) {
        return rekey_error;
    }
    task->key = new_identity;
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        LogicalPtraceResidentTask& child = state->tasks[slot];
        if (child.occupied != 0U &&
            (child.flags & kLogicalPtraceResidentTaskParentValid) != 0U &&
            tracer::LogicalTaskKeysEqual(child.parent, old_identity)) {
            child.parent = new_identity;
        }
    }
    ++state->mutation_generation;
    return 0;
}

int MergeExecLogicalPtraceResidentTask(
        LogicalPtraceResidentState* state,
        const tracer::LogicalTaskKey& former_identity,
        const tracer::LogicalTaskKey& destination_identity) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state)) {
        return EINVAL;
    }
    const tracer::LogicalTaskKey former = former_identity;
    const tracer::LogicalTaskKey destination = destination_identity;
    void* memory = mmap(nullptr, sizeof(LogicalPtraceResidentState),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        return errno != 0 ? errno : ENOMEM;
    }
    auto* candidate = static_cast<LogicalPtraceResidentState*>(memory);
    memcpy(candidate, state, sizeof(*candidate));
    const int error = MergeExecLogicalPtraceResidentTaskInPlace(
            candidate, former, destination);
    if (error == 0) {
        memcpy(state, candidate, sizeof(*state));
    }
    (void)munmap(memory, sizeof(LogicalPtraceResidentState));
    return error;
}

bool ValidateLogicalPtraceResidentState(
        const LogicalPtraceResidentState* state) noexcept {
    if (!IsLogicalPtraceResidentStateInitialized(state) ||
        !ValidateLogicalPtraceDispatcher(&state->dispatcher,
                                         &state->logical)) {
        return false;
    }
    uint32_t count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        const LogicalPtraceResidentTask& task = state->tasks[slot];
        if (task.slot != slot || task.occupied > 1U) {
            return false;
        }
        if (task.occupied == 0U) {
            if (task.flags != 0U || task.key.tid != 0 || task.parent.tid != 0) {
                return false;
            }
            continue;
        }
        const uint32_t life_flags = task.flags &
                (kLogicalPtraceResidentTaskActive |
                 kLogicalPtraceResidentTaskExited);
        if (task.reserved != 0U || !TaskKeyValid(task.key) ||
            (task.flags & ~kResidentTaskFlagMask) != 0U ||
            (life_flags != kLogicalPtraceResidentTaskActive &&
             life_flags != kLogicalPtraceResidentTaskExited) ||
            tracer::FindLogicalProcess(
                    &state->logical,
                    tracer::LogicalProcessKeyForTask(task.key)) == nullptr) {
            return false;
        }
        if ((task.flags & kLogicalPtraceResidentTaskParentValid) != 0U) {
            if (!TaskKeyValid(task.parent) ||
                tracer::LogicalTaskKeysEqual(task.parent, task.key) ||
                tracer::FindLogicalProcess(
                        &state->logical,
                        tracer::LogicalProcessKeyForTask(task.parent)) ==
                        nullptr) {
                return false;
            }
        } else if (task.parent.tid != 0 || task.parent.tgid != 0 ||
                   task.parent.generation != 0U ||
                   task.parent.process_generation != 0U) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceResidentCapacity; ++other) {
            const LogicalPtraceResidentTask& candidate = state->tasks[other];
            if (candidate.occupied == 0U) {
                continue;
            }
            if (tracer::LogicalTaskKeysEqual(candidate.key, task.key)) {
                return false;
            }
            if (candidate.key.tid == task.key.tid &&
                (candidate.flags & kLogicalPtraceResidentTaskActive) != 0U &&
                (task.flags & kLogicalPtraceResidentTaskActive) != 0U) {
                return false;
            }
        }
        ++count;
    }
    return count == state->task_count;
}

LogicalPtraceDispatchIo MakeLogicalPtraceResidentIo(
        LogicalPtraceResidentIoContext* io_context) noexcept {
    LogicalPtraceDispatchIo io {};
    io.opaque = io_context;
    io.resolve_task = ResolveTaskCallback;
    io.resolve_parent = ResolveParentCallback;
    io.may_attach = MayAttachCallback;
    io.read_memory = ReadMemoryCallback;
    io.write_memory = WriteMemoryCallback;
    io.query_uid = QueryUidCallback;
    io.fill_rusage = FillRusageCallback;
    return io;
}

}  // namespace hookself::internal
