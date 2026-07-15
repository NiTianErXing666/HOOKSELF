#include "tracer/logical_ptrace.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>

namespace hookself::tracer {
namespace {

constexpr uint32_t kLogicalPtraceEventFlagMask =
        kLogicalPtraceEventFlagSiginfoValid |
        kLogicalPtraceEventFlagRegistersValid |
        kLogicalPtraceEventFlagSyscallNumberValid;
constexpr uint32_t kWait4OptionMask =
        kLogicalWaitNoHang | kLogicalWaitStopped |
        kLogicalWaitContinued | kLogicalWaitNoThread |
        kLogicalWaitAll | kLogicalWaitClone;
constexpr uint32_t kWaitIdOptionMask =
        kLogicalWaitNoHang | kLogicalWaitStopped |
        kLogicalWaitExited | kLogicalWaitContinued |
        kLogicalWaitNowait | kLogicalWaitNoThread |
        kLogicalWaitAll | kLogicalWaitClone;

void ZeroBytes(void* memory, size_t size) noexcept {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
}

bool ProcessKeyValid(const LogicalProcessKey& key) noexcept {
    return key.tgid > 0 && key.reserved == 0 && key.generation != 0;
}

bool TaskKeyValid(const LogicalTaskKey& key) noexcept {
    return key.tid > 0 && key.tgid > 0 && key.generation != 0 &&
           key.process_generation != 0;
}

bool PidIdentityValid(const LogicalPidIdentity& identity) noexcept {
    if (identity.pid < -1 || identity.reserved != 0) {
        return false;
    }
    return identity.pid > 0 || identity.start_time == 0;
}

bool DumpableValid(int32_t dumpable) noexcept {
    return dumpable >= 0 && dumpable <= 2;
}

bool AttachKindValid(LogicalPtraceAttachKind kind) noexcept {
    return kind == LogicalPtraceAttachKind::kTraceme ||
           kind == LogicalPtraceAttachKind::kAttach ||
           kind == LogicalPtraceAttachKind::kSeize;
}

bool RelationStateValid(LogicalPtraceRelationState state) noexcept {
    return state == LogicalPtraceRelationState::kAttachPending ||
           state == LogicalPtraceRelationState::kSeizeRunning ||
           state == LogicalPtraceRelationState::kStopped ||
           state == LogicalPtraceRelationState::kRunningCont ||
           state == LogicalPtraceRelationState::kRunningSyscall ||
           state == LogicalPtraceRelationState::kExitZombie ||
           state == LogicalPtraceRelationState::kRunningSingleStep ||
           state == LogicalPtraceRelationState::kListening;
}

bool WaitClassValid(LogicalPtraceWaitClass wait_class) noexcept {
    return wait_class == LogicalPtraceWaitClass::kNormal ||
           wait_class == LogicalPtraceWaitClass::kClone;
}

bool EventKindValid(LogicalPtraceEventKind kind) noexcept {
    return kind >= LogicalPtraceEventKind::kAttachStop &&
           kind <= LogicalPtraceEventKind::kContinued;
}

bool EventIsExit(const LogicalPtraceEvent& event) noexcept {
    return event.kind == LogicalPtraceEventKind::kExited ||
           event.kind == LogicalPtraceEventKind::kSignaled;
}

bool WaitKindValid(LogicalWaitKind kind) noexcept {
    return kind == LogicalWaitKind::kWait4 ||
           kind == LogicalWaitKind::kWaitId;
}

bool WaitSelectorValid(LogicalWaitSelectorKind kind) noexcept {
    return kind == LogicalWaitSelectorKind::kAny ||
           kind == LogicalWaitSelectorKind::kTid ||
           kind == LogicalWaitSelectorKind::kProcessGroup;
}

bool WaitRequestValid(const LogicalWaitRequest& request) noexcept {
    if (!TaskKeyValid(request.waiter) || !WaitKindValid(request.kind) ||
        !WaitSelectorValid(request.selector_kind) ||
        request.nohang > 1U || request.nowait > 1U ||
        request.reserved != 0U ||
        request.nohang !=
                ((request.options & kLogicalWaitNoHang) != 0U ? 1U : 0U) ||
        request.nowait !=
                ((request.options & kLogicalWaitNowait) != 0U ? 1U : 0U)) {
        return false;
    }
    if (request.selector_kind == LogicalWaitSelectorKind::kAny) {
        if (request.selector_id != 0) {
            return false;
        }
    } else if (request.selector_id <= 0) {
        return false;
    }
    if (request.kind == LogicalWaitKind::kWait4) {
        return (request.options & ~kWait4OptionMask) == 0U &&
               request.nowait == 0U && request.info_address == 0;
    }
    return (request.options & ~kWaitIdOptionMask) == 0U &&
           (request.options & (kLogicalWaitStopped | kLogicalWaitExited |
                               kLogicalWaitContinued)) != 0U &&
           request.status_address == 0;
}

uint64_t AllocateSequence(uint64_t* next) noexcept {
    uint64_t value = *next;
    if (value == 0) {
        value = 1;
    }
    *next = value + 1U;
    if (*next == 0) {
        *next = 1;
    }
    return value;
}

void AdvanceHint(uint32_t slot, uint32_t capacity,
                 uint32_t* hint) noexcept {
    *hint = slot + 1U;
    if (*hint == capacity) {
        *hint = 0;
    }
}

void ClearProcessRecord(LogicalProcessRecord* record,
                        uint32_t slot) noexcept {
    ZeroBytes(record, sizeof(*record));
    record->slot = slot;
}

void ClearRelationRecord(LogicalPtraceRelation* relation,
                         uint32_t slot) noexcept {
    ZeroBytes(relation, sizeof(*relation));
    relation->slot = slot;
    for (uint32_t index = 0; index < kLogicalPtraceEventQueueCapacity;
         ++index) {
        relation->events[index].guest_syscall_number = -1;
    }
}

void ClearFakeTracemeRecord(LogicalFakeTracemeRecord* record,
                            uint32_t slot) noexcept {
    ZeroBytes(record, sizeof(*record));
    record->slot = slot;
}

void ClearWaitRecord(LogicalWaitRecord* record, uint32_t slot) noexcept {
    ZeroBytes(record, sizeof(*record));
    record->slot = slot;
}

LogicalProcessRecord* MutableLogicalProcess(
        LogicalPtraceTable* table, const LogicalProcessKey& key) noexcept {
    return const_cast<LogicalProcessRecord*>(FindLogicalProcess(table, key));
}

LogicalPtraceRelation* MutableLogicalRelation(
        LogicalPtraceTable* table, const LogicalTaskKey& tracee) noexcept {
    return const_cast<LogicalPtraceRelation*>(
            FindLogicalPtraceRelation(table, tracee));
}

LogicalFakeTracemeRecord* FindFakeTraceme(
        LogicalPtraceTable* table, const LogicalTaskKey& task) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(task)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceFakeTracemeCapacity;
         ++slot) {
        LogicalFakeTracemeRecord& record = table->fake_traceme[slot];
        if (record.occupied != 0U &&
            LogicalTaskKeysEqual(record.task, task)) {
            return &record;
        }
    }
    return nullptr;
}

LogicalWaitRecord* MutableLogicalWait(
        LogicalPtraceTable* table, const LogicalTaskKey& waiter) noexcept {
    return const_cast<LogicalWaitRecord*>(FindLogicalWait(table, waiter));
}

bool ProcessReferenced(const LogicalPtraceTable* table,
                       const LogicalProcessKey& key) noexcept {
    for (uint32_t slot = 0; slot < kLogicalPtraceProcessCapacity; ++slot) {
        const LogicalProcessRecord& process = table->processes[slot];
        if (process.occupied != 0U &&
            (process.flags & kLogicalProcessFlagParentKnown) != 0U &&
            LogicalProcessKeysEqual(process.parent, key)) {
            return true;
        }
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        const LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.occupied == 0U) {
            continue;
        }
        if (LogicalProcessKeysEqual(
                    LogicalProcessKeyForTask(relation.tracee), key) ||
            LogicalProcessKeysEqual(
                    LogicalProcessKeyForTask(relation.tracer), key)) {
            return true;
        }
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceFakeTracemeCapacity;
         ++slot) {
        const LogicalFakeTracemeRecord& fake = table->fake_traceme[slot];
        if (fake.occupied != 0U &&
            LogicalProcessKeysEqual(
                    LogicalProcessKeyForTask(fake.task), key)) {
            return true;
        }
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceWaitCapacity; ++slot) {
        const LogicalWaitRecord& wait = table->waits[slot];
        if (wait.occupied != 0U &&
            LogicalProcessKeysEqual(
                    LogicalProcessKeyForTask(wait.request.waiter), key)) {
            return true;
        }
    }
    return false;
}

bool ParentChainContains(const LogicalPtraceTable* table,
                         LogicalProcessKey current,
                         const LogicalProcessKey& expected) noexcept {
    for (uint32_t depth = 0; depth < kLogicalPtraceProcessCapacity;
         ++depth) {
        if (LogicalProcessKeysEqual(current, expected)) {
            return true;
        }
        const LogicalProcessRecord* process =
                FindLogicalProcess(table, current);
        if (process == nullptr ||
            (process->flags & kLogicalProcessFlagParentKnown) == 0U) {
            return false;
        }
        current = process->parent;
    }
    return true;
}

bool PtraceChainContains(const LogicalPtraceTable* table,
                         LogicalTaskKey current,
                         const LogicalTaskKey& expected) noexcept {
    for (uint32_t depth = 0; depth < kLogicalPtraceRelationCapacity;
         ++depth) {
        if (LogicalTaskKeysEqual(current, expected)) {
            return true;
        }
        const LogicalPtraceRelation* relation =
                FindLogicalPtraceRelation(table, current);
        if (relation == nullptr) {
            return false;
        }
        current = relation->tracer;
    }
    return true;
}

bool RelationInitialStateValid(const LogicalPtraceRelation& relation) noexcept {
    if (relation.state == LogicalPtraceRelationState::kAttachPending) {
        return relation.attach_kind == LogicalPtraceAttachKind::kAttach;
    }
    if (relation.state == LogicalPtraceRelationState::kSeizeRunning) {
        return relation.attach_kind == LogicalPtraceAttachKind::kSeize;
    }
    if (relation.state == LogicalPtraceRelationState::kListening) {
        return relation.attach_kind == LogicalPtraceAttachKind::kSeize;
    }
    return true;
}

bool EventValid(const LogicalPtraceEvent& event) noexcept {
    if (event.sequence == 0 || !EventKindValid(event.kind) ||
        (event.flags & ~kLogicalPtraceEventFlagMask) != 0U ||
        event.signal_number < 0 || event.signal_number >= NSIG ||
        event.reserved != 0U) {
        return false;
    }
    if ((event.flags & kLogicalPtraceEventFlagSyscallNumberValid) == 0U &&
        event.guest_syscall_number != -1) {
        return false;
    }
    return true;
}

bool EventMatchesWaitKind(const LogicalWaitRequest& request,
                          const LogicalPtraceEvent& event) noexcept {
    if (request.kind == LogicalWaitKind::kWait4) {
        return event.kind != LogicalPtraceEventKind::kContinued ||
               (request.options & kLogicalWaitContinued) != 0U;
    }
    if (EventIsExit(event)) {
        return (request.options & kLogicalWaitExited) != 0U;
    }
    if (event.kind == LogicalPtraceEventKind::kContinued) {
        return (request.options & kLogicalWaitContinued) != 0U;
    }
    return (request.options & kLogicalWaitStopped) != 0U;
}

bool WaitClassMatches(uint32_t options,
                      LogicalPtraceWaitClass wait_class) noexcept {
    if ((options & kLogicalWaitAll) != 0U) {
        return true;
    }
    const bool wants_clone = (options & kLogicalWaitClone) != 0U;
    return wants_clone == (wait_class == LogicalPtraceWaitClass::kClone);
}

bool RelationOwnedByWaiter(const LogicalPtraceRelation& relation,
                           const LogicalWaitRequest& request) noexcept {
    if (relation.tracer.tgid != request.waiter.tgid ||
        relation.tracer.process_generation !=
                request.waiter.process_generation) {
        return false;
    }
    return (request.options & kLogicalWaitNoThread) == 0U ||
           LogicalTaskKeysEqual(relation.tracer, request.waiter);
}

bool SelectorMatches(const LogicalPtraceTable* table,
                     const LogicalPtraceRelation& relation,
                     const LogicalWaitRequest& request) noexcept {
    if (request.selector_kind == LogicalWaitSelectorKind::kAny) {
        return true;
    }
    if (request.selector_kind == LogicalWaitSelectorKind::kTid) {
        return relation.tracee.tid == request.selector_id;
    }
    const LogicalProcessRecord* process = FindLogicalProcess(
            table, LogicalProcessKeyForTask(relation.tracee));
    return process != nullptr &&
           process->process_group == request.selector_id;
}

void PopRelationEvent(LogicalPtraceRelation* relation) noexcept {
    LogicalPtraceEvent* event = &relation->events[relation->event_head];
    ZeroBytes(event, sizeof(*event));
    event->guest_syscall_number = -1;
    relation->event_head =
            (relation->event_head + 1U) % kLogicalPtraceEventQueueCapacity;
    --relation->event_count;
    if (relation->event_count == 0U) {
        relation->event_head = 0;
    }
}

void EraseRelationAt(LogicalPtraceTable* table, uint32_t slot) noexcept {
    ClearRelationRecord(&table->relations[slot], slot);
    --table->relation_count;
    table->relation_free_hint = slot;
    ++table->mutation_generation;
}

void EraseWaitAt(LogicalPtraceTable* table, uint32_t slot) noexcept {
    ClearWaitRecord(&table->waits[slot], slot);
    --table->wait_count;
    table->wait_free_hint = slot;
    ++table->mutation_generation;
}

}  // namespace

bool LogicalProcessKeysEqual(const LogicalProcessKey& first,
                             const LogicalProcessKey& second) noexcept {
    return first.tgid == second.tgid &&
           first.generation == second.generation;
}

bool LogicalTaskKeysEqual(const LogicalTaskKey& first,
                          const LogicalTaskKey& second) noexcept {
    return first.tid == second.tid && first.tgid == second.tgid &&
           first.generation == second.generation &&
           first.process_generation == second.process_generation;
}

LogicalProcessKey LogicalProcessKeyForTask(
        const LogicalTaskKey& task) noexcept {
    return {task.tgid, 0U, task.process_generation};
}

void InitLogicalPtraceTable(LogicalPtraceTable* table) noexcept {
    if (table == nullptr) {
        return;
    }
    ZeroBytes(table, sizeof(*table));
    table->magic = kLogicalPtraceMagic;
    table->version = kLogicalPtraceVersion;
    table->next_relation_generation = 1;
    table->next_event_sequence = 1;
    table->next_wait_generation = 1;
    for (uint32_t slot = 0; slot < kLogicalPtraceProcessCapacity; ++slot) {
        ClearProcessRecord(&table->processes[slot], slot);
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        ClearRelationRecord(&table->relations[slot], slot);
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceFakeTracemeCapacity;
         ++slot) {
        ClearFakeTracemeRecord(&table->fake_traceme[slot], slot);
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceWaitCapacity; ++slot) {
        ClearWaitRecord(&table->waits[slot], slot);
    }
}

bool IsLogicalPtraceTableInitialized(const LogicalPtraceTable* table) noexcept {
    return table != nullptr && table->magic == kLogicalPtraceMagic &&
           table->version == kLogicalPtraceVersion &&
           table->process_count <= kLogicalPtraceProcessCapacity &&
           table->relation_count <= kLogicalPtraceRelationCapacity &&
           table->fake_traceme_count <= kLogicalPtraceFakeTracemeCapacity &&
           table->wait_count <= kLogicalPtraceWaitCapacity &&
           table->process_free_hint < kLogicalPtraceProcessCapacity &&
           table->relation_free_hint < kLogicalPtraceRelationCapacity &&
           table->fake_traceme_free_hint <
                   kLogicalPtraceFakeTracemeCapacity &&
           table->wait_free_hint < kLogicalPtraceWaitCapacity &&
           table->next_relation_generation != 0 &&
           table->next_event_sequence != 0 &&
           table->next_wait_generation != 0;
}

const LogicalProcessRecord* FindLogicalProcess(
        const LogicalPtraceTable* table,
        const LogicalProcessKey& key) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !ProcessKeyValid(key)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceProcessCapacity; ++slot) {
        const LogicalProcessRecord& process = table->processes[slot];
        if (process.occupied != 0U &&
            LogicalProcessKeysEqual(process.key, key)) {
            return &process;
        }
    }
    return nullptr;
}

const LogicalProcessRecord* LogicalProcessAt(
        const LogicalPtraceTable* table, uint32_t slot) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        slot >= kLogicalPtraceProcessCapacity ||
        table->processes[slot].occupied == 0U) {
        return nullptr;
    }
    return &table->processes[slot];
}

int InsertLogicalProcess(LogicalPtraceTable* table,
                         const LogicalProcessKey& key,
                         const LogicalProcessKey* parent,
                         int32_t process_group, int32_t logical_dumpable,
                         const LogicalPidIdentity& logical_ptracer,
                         uint32_t* slot) noexcept {
    if (slot != nullptr) {
        *slot = kInvalidLogicalPtraceSlot;
    }
    if (!IsLogicalPtraceTableInitialized(table) || !ProcessKeyValid(key) ||
        process_group <= 0 || !DumpableValid(logical_dumpable) ||
        !PidIdentityValid(logical_ptracer)) {
        return EINVAL;
    }
    if (FindLogicalProcess(table, key) != nullptr) {
        return EEXIST;
    }
    if (parent != nullptr &&
        (!ProcessKeyValid(*parent) ||
         LogicalProcessKeysEqual(key, *parent) ||
         FindLogicalProcess(table, *parent) == nullptr)) {
        return ESRCH;
    }
    if (table->process_count == kLogicalPtraceProcessCapacity) {
        return ENOSPC;
    }
    for (uint32_t offset = 0; offset < kLogicalPtraceProcessCapacity;
         ++offset) {
        uint32_t candidate = table->process_free_hint + offset;
        if (candidate >= kLogicalPtraceProcessCapacity) {
            candidate -= kLogicalPtraceProcessCapacity;
        }
        LogicalProcessRecord* process = &table->processes[candidate];
        if (process->occupied != 0U) {
            continue;
        }
        ClearProcessRecord(process, candidate);
        process->occupied = 1;
        process->key = key;
        process->process_group = process_group;
        process->logical_dumpable = logical_dumpable;
        process->logical_ptracer = logical_ptracer;
        if (parent != nullptr) {
            process->parent = *parent;
            process->flags |= kLogicalProcessFlagParentKnown;
        }
        ++table->process_count;
        ++table->mutation_generation;
        AdvanceHint(candidate, kLogicalPtraceProcessCapacity,
                    &table->process_free_hint);
        if (slot != nullptr) {
            *slot = candidate;
        }
        return 0;
    }
    return ENOSPC;
}

int InheritLogicalProcess(LogicalPtraceTable* table,
                          const LogicalProcessKey& child,
                          const LogicalProcessKey& parent,
                          int32_t child_process_group,
                          uint32_t* slot) noexcept {
    if (!IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    const LogicalProcessRecord* parent_record =
            FindLogicalProcess(table, parent);
    if (parent_record == nullptr) {
        return ESRCH;
    }
    return InsertLogicalProcess(table, child, &parent, child_process_group,
                                parent_record->logical_dumpable,
                                parent_record->logical_ptracer, slot);
}

int EraseLogicalProcess(LogicalPtraceTable* table,
                        const LogicalProcessKey& key) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !ProcessKeyValid(key)) {
        return EINVAL;
    }
    LogicalProcessRecord* process = MutableLogicalProcess(table, key);
    if (process == nullptr) {
        return ESRCH;
    }
    if (ProcessReferenced(table, key)) {
        return EBUSY;
    }
    const uint32_t slot = process->slot;
    ClearProcessRecord(process, slot);
    --table->process_count;
    table->process_free_hint = slot;
    ++table->mutation_generation;
    return 0;
}

int SetLogicalProcessDumpable(LogicalPtraceTable* table,
                              const LogicalProcessKey& key,
                              int32_t logical_dumpable) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        !DumpableValid(logical_dumpable)) {
        return EINVAL;
    }
    LogicalProcessRecord* process = MutableLogicalProcess(table, key);
    if (process == nullptr) {
        return ESRCH;
    }
    process->logical_dumpable = logical_dumpable;
    ++table->mutation_generation;
    return 0;
}

int SetLogicalProcessPtracer(LogicalPtraceTable* table,
                             const LogicalProcessKey& key,
                             const LogicalPidIdentity& logical_ptracer) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        !PidIdentityValid(logical_ptracer)) {
        return EINVAL;
    }
    LogicalProcessRecord* process = MutableLogicalProcess(table, key);
    if (process == nullptr) {
        return ESRCH;
    }
    process->logical_ptracer = logical_ptracer;
    ++table->mutation_generation;
    return 0;
}

int SetLogicalProcessGroup(LogicalPtraceTable* table,
                           const LogicalProcessKey& key,
                           int32_t process_group) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || process_group <= 0) {
        return EINVAL;
    }
    LogicalProcessRecord* process = MutableLogicalProcess(table, key);
    if (process == nullptr) {
        return ESRCH;
    }
    process->process_group = process_group;
    ++table->mutation_generation;
    return 0;
}

int SetLogicalProcessParent(LogicalPtraceTable* table,
                            const LogicalProcessKey& key,
                            const LogicalProcessKey* parent) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !ProcessKeyValid(key)) {
        return EINVAL;
    }
    LogicalProcessRecord* process = MutableLogicalProcess(table, key);
    if (process == nullptr) {
        return ESRCH;
    }
    if (parent != nullptr && !ProcessKeyValid(*parent)) {
        return EINVAL;
    }
    if (parent != nullptr &&
        (LogicalProcessKeysEqual(key, *parent) ||
         ParentChainContains(table, *parent, key))) {
        return ELOOP;
    }
    if (parent != nullptr && FindLogicalProcess(table, *parent) == nullptr) {
        return ESRCH;
    }
    ZeroBytes(&process->parent, sizeof(process->parent));
    process->flags &= ~kLogicalProcessFlagParentKnown;
    if (parent != nullptr) {
        process->parent = *parent;
        process->flags |= kLogicalProcessFlagParentKnown;
    }
    ++table->mutation_generation;
    return 0;
}

int ClaimLogicalFakeTraceme(LogicalPtraceTable* table,
                            const LogicalTaskKey& task) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(task)) {
        return EINVAL;
    }
    if (FindLogicalProcess(table, LogicalProcessKeyForTask(task)) == nullptr) {
        return ESRCH;
    }
    if (FindFakeTraceme(table, task) != nullptr) {
        return EPERM;
    }
    if (table->fake_traceme_count == kLogicalPtraceFakeTracemeCapacity) {
        return ENOSPC;
    }
    for (uint32_t offset = 0;
         offset < kLogicalPtraceFakeTracemeCapacity; ++offset) {
        uint32_t candidate = table->fake_traceme_free_hint + offset;
        if (candidate >= kLogicalPtraceFakeTracemeCapacity) {
            candidate -= kLogicalPtraceFakeTracemeCapacity;
        }
        LogicalFakeTracemeRecord* record = &table->fake_traceme[candidate];
        if (record->occupied != 0U) {
            continue;
        }
        ClearFakeTracemeRecord(record, candidate);
        record->occupied = 1;
        record->task = task;
        ++table->fake_traceme_count;
        ++table->mutation_generation;
        AdvanceHint(candidate, kLogicalPtraceFakeTracemeCapacity,
                    &table->fake_traceme_free_hint);
        return 0;
    }
    return ENOSPC;
}

bool HasLogicalFakeTraceme(const LogicalPtraceTable* table,
                           const LogicalTaskKey& task) noexcept {
    return FindFakeTraceme(const_cast<LogicalPtraceTable*>(table), task) !=
           nullptr;
}

int ClearLogicalFakeTraceme(LogicalPtraceTable* table,
                            const LogicalTaskKey& task) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(task)) {
        return EINVAL;
    }
    LogicalFakeTracemeRecord* record = FindFakeTraceme(table, task);
    if (record == nullptr) {
        return ESRCH;
    }
    const uint32_t slot = record->slot;
    ClearFakeTracemeRecord(record, slot);
    --table->fake_traceme_count;
    table->fake_traceme_free_hint = slot;
    ++table->mutation_generation;
    return 0;
}

const LogicalPtraceRelation* FindLogicalPtraceRelation(
        const LogicalPtraceTable* table,
        const LogicalTaskKey& tracee) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(tracee)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        const LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.occupied != 0U &&
            LogicalTaskKeysEqual(relation.tracee, tracee)) {
            return &relation;
        }
    }
    return nullptr;
}

const LogicalPtraceRelation* LogicalPtraceRelationAt(
        const LogicalPtraceTable* table, uint32_t slot) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        slot >= kLogicalPtraceRelationCapacity ||
        table->relations[slot].occupied == 0U) {
        return nullptr;
    }
    return &table->relations[slot];
}

int CreateLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                const LogicalTaskKey& tracer,
                                LogicalPtraceAttachKind attach_kind,
                                LogicalPtraceWaitClass wait_class,
                                uint64_t options,
                                uint32_t* slot) noexcept {
    if (slot != nullptr) {
        *slot = kInvalidLogicalPtraceSlot;
    }
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(tracee) ||
        !TaskKeyValid(tracer) || !AttachKindValid(attach_kind) ||
        !WaitClassValid(wait_class) ||
        (options & ~kLogicalPtraceKnownOptionMask) != 0U) {
        return EINVAL;
    }
    if (tracee.tgid == tracer.tgid) {
        return EPERM;
    }
    const LogicalProcessRecord* tracee_process = FindLogicalProcess(
            table, LogicalProcessKeyForTask(tracee));
    const LogicalProcessRecord* tracer_process = FindLogicalProcess(
            table, LogicalProcessKeyForTask(tracer));
    if (tracee_process == nullptr || tracer_process == nullptr) {
        return ESRCH;
    }
    if (attach_kind == LogicalPtraceAttachKind::kTraceme &&
        ((tracee_process->flags & kLogicalProcessFlagParentKnown) == 0U ||
         !LogicalProcessKeysEqual(tracee_process->parent,
                                  tracer_process->key))) {
        return EPERM;
    }
    if (PtraceChainContains(table, tracer, tracee)) {
        return ELOOP;
    }
    if (FindLogicalPtraceRelation(table, tracee) != nullptr) {
        return EPERM;
    }
    if (table->relation_count == kLogicalPtraceRelationCapacity) {
        return ENOSPC;
    }
    for (uint32_t offset = 0; offset < kLogicalPtraceRelationCapacity;
         ++offset) {
        uint32_t candidate = table->relation_free_hint + offset;
        if (candidate >= kLogicalPtraceRelationCapacity) {
            candidate -= kLogicalPtraceRelationCapacity;
        }
        LogicalPtraceRelation* relation = &table->relations[candidate];
        if (relation->occupied != 0U) {
            continue;
        }
        ClearRelationRecord(relation, candidate);
        relation->occupied = 1;
        relation->generation = AllocateSequence(
                &table->next_relation_generation);
        relation->tracee = tracee;
        relation->tracer = tracer;
        relation->attach_kind = attach_kind;
        relation->wait_class = wait_class;
        relation->options = options;
        relation->state =
                attach_kind == LogicalPtraceAttachKind::kAttach
                        ? LogicalPtraceRelationState::kAttachPending
                        : attach_kind == LogicalPtraceAttachKind::kSeize
                                  ? LogicalPtraceRelationState::kSeizeRunning
                                  : LogicalPtraceRelationState::kRunningCont;
        ++table->relation_count;
        ++table->mutation_generation;
        AdvanceHint(candidate, kLogicalPtraceRelationCapacity,
                    &table->relation_free_hint);
        if (slot != nullptr) {
            *slot = candidate;
        }
        return 0;
    }
    return ENOSPC;
}

int CreateInheritedLogicalPtraceRelation(
        LogicalPtraceTable* table,
        const LogicalTaskKey& parent_tracee,
        const LogicalTaskKey& child_tracee,
        LogicalPtraceWaitClass wait_class,
        const LogicalPtraceEvent& initial_stop,
        uint32_t* slot, uint64_t* sequence) noexcept {
    if (slot != nullptr) {
        *slot = kInvalidLogicalPtraceSlot;
    }
    if (sequence != nullptr) {
        *sequence = 0;
    }
    if (!IsLogicalPtraceTableInitialized(table) ||
        !TaskKeyValid(parent_tracee) || !TaskKeyValid(child_tracee) ||
        !WaitClassValid(wait_class) || initial_stop.sequence != 0U ||
        !EventKindValid(initial_stop.kind) || EventIsExit(initial_stop) ||
        initial_stop.kind == LogicalPtraceEventKind::kContinued ||
        (initial_stop.flags & ~kLogicalPtraceEventFlagMask) != 0U ||
        initial_stop.signal_number < 0 ||
        initial_stop.signal_number >= NSIG || initial_stop.reserved != 0U) {
        return EINVAL;
    }

    const LogicalPtraceRelation* parent =
            FindLogicalPtraceRelation(table, parent_tracee);
    if (parent == nullptr ||
        parent->state == LogicalPtraceRelationState::kExitZombie) {
        return ESRCH;
    }
    if (child_tracee.tgid == parent->tracer.tgid) {
        return EPERM;
    }
    if (FindLogicalProcess(
                table, LogicalProcessKeyForTask(child_tracee)) == nullptr ||
        FindLogicalProcess(
                table, LogicalProcessKeyForTask(parent->tracer)) == nullptr) {
        return ESRCH;
    }
    if (PtraceChainContains(table, parent->tracer, child_tracee)) {
        return ELOOP;
    }
    if (FindLogicalPtraceRelation(table, child_tracee) != nullptr) {
        return EPERM;
    }
    if (table->relation_count == kLogicalPtraceRelationCapacity) {
        return ENOSPC;
    }

    uint32_t candidate = kInvalidLogicalPtraceSlot;
    for (uint32_t offset = 0; offset < kLogicalPtraceRelationCapacity;
         ++offset) {
        uint32_t current = table->relation_free_hint + offset;
        if (current >= kLogicalPtraceRelationCapacity) {
            current -= kLogicalPtraceRelationCapacity;
        }
        if (table->relations[current].occupied == 0U) {
            candidate = current;
            break;
        }
    }
    if (candidate == kInvalidLogicalPtraceSlot) {
        return ENOSPC;
    }

    LogicalPtraceRelation* child = &table->relations[candidate];
    ClearRelationRecord(child, candidate);
    child->occupied = 1U;
    child->generation = AllocateSequence(&table->next_relation_generation);
    child->tracee = child_tracee;
    child->tracer = parent->tracer;
    child->attach_kind = parent->attach_kind;
    child->state = LogicalPtraceRelationState::kStopped;
    child->wait_class = wait_class;
    child->event_count = 1U;
    child->options = parent->options;

    LogicalPtraceEvent stored = initial_stop;
    stored.sequence = AllocateSequence(&table->next_event_sequence);
    if ((stored.flags & kLogicalPtraceEventFlagSyscallNumberValid) == 0U) {
        stored.guest_syscall_number = -1;
    }
    child->events[0] = stored;
    ++table->relation_count;
    ++table->mutation_generation;
    AdvanceHint(candidate, kLogicalPtraceRelationCapacity,
                &table->relation_free_hint);
    if (slot != nullptr) {
        *slot = candidate;
    }
    if (sequence != nullptr) {
        *sequence = stored.sequence;
    }
    return 0;
}

int EraseLogicalPtraceRelation(LogicalPtraceTable* table,
                               const LogicalTaskKey& tracee,
                               bool discard_pending_events) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(tracee)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (!discard_pending_events && relation->event_count != 0U) {
        return EBUSY;
    }
    EraseRelationAt(table, relation->slot);
    return 0;
}

int SetLogicalPtraceOptions(LogicalPtraceTable* table,
                            const LogicalTaskKey& tracee,
                            uint64_t options) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        (options & ~kLogicalPtraceKnownOptionMask) != 0U) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->state != LogicalPtraceRelationState::kStopped) {
        return EBUSY;
    }
    relation->options = options;
    ++table->mutation_generation;
    return 0;
}

int ResumeLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                LogicalPtraceResumeMode mode) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        (mode != LogicalPtraceResumeMode::kCont &&
         mode != LogicalPtraceResumeMode::kSyscall &&
         mode != LogicalPtraceResumeMode::kSingleStep)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->state != LogicalPtraceRelationState::kStopped) {
        return relation->state == LogicalPtraceRelationState::kExitZombie
                       ? ESRCH
                       : EBUSY;
    }
    if (relation->event_count != 0U) {
        return EBUSY;
    }
    relation->state = mode == LogicalPtraceResumeMode::kCont
                              ? LogicalPtraceRelationState::kRunningCont
                      : mode == LogicalPtraceResumeMode::kSyscall
                              ? LogicalPtraceRelationState::kRunningSyscall
                              : LogicalPtraceRelationState::
                                        kRunningSingleStep;
    ++table->mutation_generation;
    return 0;
}

int ListenLogicalPtraceRelation(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee) noexcept {
    if (!IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->attach_kind != LogicalPtraceAttachKind::kSeize) {
        return EIO;
    }
    if (relation->state != LogicalPtraceRelationState::kStopped ||
        relation->event_count != 0U) {
        return relation->state == LogicalPtraceRelationState::kExitZombie
                       ? ESRCH
                       : EBUSY;
    }
    relation->state = LogicalPtraceRelationState::kListening;
    ++table->mutation_generation;
    return 0;
}

int QueueLogicalPtraceEvent(LogicalPtraceTable* table,
                            const LogicalTaskKey& tracee,
                            const LogicalPtraceEvent& event,
                            uint64_t* sequence) noexcept {
    if (sequence != nullptr) {
        *sequence = 0;
    }
    if (!IsLogicalPtraceTableInitialized(table) || event.sequence != 0 ||
        !EventKindValid(event.kind) ||
        (event.flags & ~kLogicalPtraceEventFlagMask) != 0U ||
        event.signal_number < 0 || event.signal_number >= NSIG ||
        event.reserved != 0U) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->state == LogicalPtraceRelationState::kExitZombie) {
        return ESRCH;
    }
    if (relation->event_count == kLogicalPtraceEventQueueCapacity) {
        return ENOSPC;
    }
    const uint32_t event_slot =
            (relation->event_head + relation->event_count) %
            kLogicalPtraceEventQueueCapacity;
    LogicalPtraceEvent stored = event;
    stored.sequence = AllocateSequence(&table->next_event_sequence);
    if ((stored.flags &
         kLogicalPtraceEventFlagSyscallNumberValid) == 0U) {
        stored.guest_syscall_number = -1;
    }
    relation->events[event_slot] = stored;
    ++relation->event_count;
    relation->state = EventIsExit(stored)
                              ? LogicalPtraceRelationState::kExitZombie
                              : LogicalPtraceRelationState::kStopped;
    ++table->mutation_generation;
    if (sequence != nullptr) {
        *sequence = stored.sequence;
    }
    return 0;
}

int PeekLogicalPtraceEvent(const LogicalPtraceTable* table,
                           const LogicalTaskKey& tracee,
                           LogicalPtraceEvent* event) noexcept {
    if (event == nullptr || !IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    const LogicalPtraceRelation* relation =
            FindLogicalPtraceRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->event_count == 0U) {
        return EAGAIN;
    }
    *event = relation->events[relation->event_head];
    return 0;
}

int SetLogicalPtraceEventRegisters(
        LogicalPtraceTable* table, const LogicalTaskKey& tracee,
        const hookself::arch::Arm64Regs& registers,
        bool syscall_number_valid, int32_t syscall_number) noexcept {
    if (!IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->event_count == 0U ||
        (relation->state != LogicalPtraceRelationState::kStopped &&
         relation->state != LogicalPtraceRelationState::kExitZombie)) {
        return EBUSY;
    }
    LogicalPtraceEvent* event = &relation->events[relation->event_head];
    event->guest_registers = registers;
    event->flags |= kLogicalPtraceEventFlagRegistersValid;
    if (syscall_number_valid) {
        event->flags |= kLogicalPtraceEventFlagSyscallNumberValid;
        event->guest_syscall_number = syscall_number;
    } else {
        event->flags &= ~kLogicalPtraceEventFlagSyscallNumberValid;
        event->guest_syscall_number = -1;
    }
    ++table->mutation_generation;
    return 0;
}

int SetLogicalPtraceEventSiginfo(LogicalPtraceTable* table,
                                const LogicalTaskKey& tracee,
                                const siginfo_t& signal_info) noexcept {
    if (!IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->event_count == 0U ||
        (relation->state != LogicalPtraceRelationState::kStopped &&
         relation->state != LogicalPtraceRelationState::kExitZombie)) {
        return EBUSY;
    }
    LogicalPtraceEvent* event = &relation->events[relation->event_head];
    event->signal_info = signal_info;
    event->flags |= kLogicalPtraceEventFlagSiginfoValid;
    ++table->mutation_generation;
    return 0;
}

int ConsumeLogicalPtraceEvent(LogicalPtraceTable* table,
                              const LogicalTaskKey& tracee,
                              bool preserve, LogicalPtraceEvent* event) noexcept {
    if (event == nullptr || !IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    LogicalPtraceRelation* relation = MutableLogicalRelation(table, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    if (relation->event_count == 0U) {
        return EAGAIN;
    }
    *event = relation->events[relation->event_head];
    if (preserve) {
        return 0;
    }
    const bool exit_event = EventIsExit(*event);
    if (exit_event && relation->event_count != 1U) {
        return EPROTO;
    }
    PopRelationEvent(relation);
    ++table->mutation_generation;
    if (exit_event) {
        if (relation->event_count != 0U) {
            return EPROTO;
        }
        EraseRelationAt(table, relation->slot);
    }
    return 0;
}

int BuildLogicalWait4Request(const LogicalTaskKey& waiter, int32_t pid,
                             int32_t caller_process_group, uint32_t options,
                             uint64_t status_address,
                             uint64_t rusage_address, uint64_t token,
                             LogicalWaitRequest* request) noexcept {
    if (request == nullptr || !TaskKeyValid(waiter) ||
        (options & ~kWait4OptionMask) != 0U) {
        return EINVAL;
    }
    LogicalWaitSelectorKind selector = LogicalWaitSelectorKind::kAny;
    int32_t selector_id = 0;
    if (pid > 0) {
        selector = LogicalWaitSelectorKind::kTid;
        selector_id = pid;
    } else if (pid == 0) {
        if (caller_process_group <= 0) {
            return EINVAL;
        }
        selector = LogicalWaitSelectorKind::kProcessGroup;
        selector_id = caller_process_group;
    } else if (pid != -1) {
        if (pid == INT32_MIN) {
            return EINVAL;
        }
        selector = LogicalWaitSelectorKind::kProcessGroup;
        selector_id = -pid;
    }
    ZeroBytes(request, sizeof(*request));
    request->waiter = waiter;
    request->kind = LogicalWaitKind::kWait4;
    request->selector_kind = selector;
    request->selector_id = selector_id;
    request->options = options;
    request->nohang = (options & kLogicalWaitNoHang) != 0U ? 1U : 0U;
    request->status_address = status_address;
    request->rusage_address = rusage_address;
    request->token = token;
    return 0;
}

int BuildLogicalWaitIdRequest(const LogicalTaskKey& waiter,
                              LogicalWaitIdType id_type, uint64_t id,
                              int32_t caller_process_group, uint32_t options,
                              uint64_t info_address,
                              uint64_t rusage_address, uint64_t token,
                              LogicalWaitRequest* request) noexcept {
    if (request == nullptr || !TaskKeyValid(waiter) ||
        (options & ~kWaitIdOptionMask) != 0U ||
        (options & (kLogicalWaitStopped | kLogicalWaitExited |
                    kLogicalWaitContinued)) == 0U) {
        return EINVAL;
    }
    LogicalWaitSelectorKind selector = LogicalWaitSelectorKind::kAny;
    int32_t selector_id = 0;
    switch (id_type) {
        case LogicalWaitIdType::kAll:
            break;
        case LogicalWaitIdType::kPid:
            if (id == 0 || id > INT32_MAX) {
                return EINVAL;
            }
            selector = LogicalWaitSelectorKind::kTid;
            selector_id = static_cast<int32_t>(id);
            break;
        case LogicalWaitIdType::kProcessGroup:
            if (id > INT32_MAX || (id == 0 && caller_process_group <= 0)) {
                return EINVAL;
            }
            selector = LogicalWaitSelectorKind::kProcessGroup;
            selector_id = id == 0 ? caller_process_group
                                  : static_cast<int32_t>(id);
            break;
        case LogicalWaitIdType::kPidFd:
            return EOPNOTSUPP;
        default:
            return EINVAL;
    }
    ZeroBytes(request, sizeof(*request));
    request->waiter = waiter;
    request->kind = LogicalWaitKind::kWaitId;
    request->selector_kind = selector;
    request->selector_id = selector_id;
    request->options = options;
    request->nohang = (options & kLogicalWaitNoHang) != 0U ? 1U : 0U;
    request->nowait = (options & kLogicalWaitNowait) != 0U ? 1U : 0U;
    request->info_address = info_address;
    request->rusage_address = rusage_address;
    request->token = token;
    return 0;
}

int BeginLogicalWait(LogicalPtraceTable* table,
                     const LogicalWaitRequest& request,
                     uint32_t* slot) noexcept {
    if (slot != nullptr) {
        *slot = kInvalidLogicalPtraceSlot;
    }
    if (!IsLogicalPtraceTableInitialized(table) ||
        !WaitRequestValid(request)) {
        return EINVAL;
    }
    if (FindLogicalProcess(
                table, LogicalProcessKeyForTask(request.waiter)) == nullptr) {
        return ESRCH;
    }
    if (FindLogicalWait(table, request.waiter) != nullptr) {
        return EBUSY;
    }
    if (table->wait_count == kLogicalPtraceWaitCapacity) {
        return ENOSPC;
    }
    for (uint32_t offset = 0; offset < kLogicalPtraceWaitCapacity;
         ++offset) {
        uint32_t candidate = table->wait_free_hint + offset;
        if (candidate >= kLogicalPtraceWaitCapacity) {
            candidate -= kLogicalPtraceWaitCapacity;
        }
        LogicalWaitRecord* wait = &table->waits[candidate];
        if (wait->occupied != 0U) {
            continue;
        }
        ClearWaitRecord(wait, candidate);
        wait->occupied = 1;
        wait->generation = AllocateSequence(&table->next_wait_generation);
        wait->request = request;
        ++table->wait_count;
        ++table->mutation_generation;
        AdvanceHint(candidate, kLogicalPtraceWaitCapacity,
                    &table->wait_free_hint);
        if (slot != nullptr) {
            *slot = candidate;
        }
        return 0;
    }
    return ENOSPC;
}

const LogicalWaitRecord* FindLogicalWait(const LogicalPtraceTable* table,
                                         const LogicalTaskKey& waiter) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(waiter)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceWaitCapacity; ++slot) {
        const LogicalWaitRecord& wait = table->waits[slot];
        if (wait.occupied != 0U &&
            LogicalTaskKeysEqual(wait.request.waiter, waiter)) {
            return &wait;
        }
    }
    return nullptr;
}

const LogicalWaitRecord* LogicalWaitAt(const LogicalPtraceTable* table,
                                       uint32_t slot) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        slot >= kLogicalPtraceWaitCapacity ||
        table->waits[slot].occupied == 0U) {
        return nullptr;
    }
    return &table->waits[slot];
}

int EndLogicalWait(LogicalPtraceTable* table,
                   const LogicalTaskKey& waiter) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) || !TaskKeyValid(waiter)) {
        return EINVAL;
    }
    LogicalWaitRecord* wait = MutableLogicalWait(table, waiter);
    if (wait == nullptr) {
        return ESRCH;
    }
    EraseWaitAt(table, wait->slot);
    return 0;
}

int SelectLogicalWaitEvent(const LogicalPtraceTable* table,
                           const LogicalTaskKey& waiter,
                           LogicalWaitMatch* match) noexcept {
    if (match == nullptr || !IsLogicalPtraceTableInitialized(table)) {
        return EINVAL;
    }
    ZeroBytes(match, sizeof(*match));
    match->relation_slot = kInvalidLogicalPtraceSlot;
    const LogicalWaitRecord* wait = FindLogicalWait(table, waiter);
    if (wait == nullptr) {
        return ESRCH;
    }
    bool matching_relation = false;
    uint64_t oldest_sequence = UINT64_MAX;
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        const LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.occupied == 0U ||
            !RelationOwnedByWaiter(relation, wait->request) ||
            !SelectorMatches(table, relation, wait->request) ||
            !WaitClassMatches(wait->request.options, relation.wait_class)) {
            continue;
        }
        matching_relation = true;
        if (relation.event_count == 0U) {
            continue;
        }
        const LogicalPtraceEvent& event =
                relation.events[relation.event_head];
        if (!EventMatchesWaitKind(wait->request, event) ||
            event.sequence >= oldest_sequence) {
            continue;
        }
        oldest_sequence = event.sequence;
        match->relation_slot = slot;
        match->relation_generation = relation.generation;
        match->event_sequence = event.sequence;
    }
    if (match->relation_slot != kInvalidLogicalPtraceSlot) {
        return 0;
    }
    return matching_relation ? EAGAIN : ECHILD;
}

int ConsumeLogicalWaitEvent(LogicalPtraceTable* table,
                            const LogicalTaskKey& waiter,
                            const LogicalWaitMatch& match,
                            LogicalPtraceEvent* event) noexcept {
    if (event == nullptr || !IsLogicalPtraceTableInitialized(table) ||
        match.relation_slot >= kLogicalPtraceRelationCapacity ||
        match.relation_generation == 0 || match.event_sequence == 0) {
        return EINVAL;
    }
    LogicalWaitRecord* wait = MutableLogicalWait(table, waiter);
    if (wait == nullptr) {
        return ESRCH;
    }
    LogicalPtraceRelation* relation =
            &table->relations[match.relation_slot];
    if (relation->occupied == 0U ||
        relation->generation != match.relation_generation ||
        relation->event_count == 0U ||
        relation->events[relation->event_head].sequence !=
                match.event_sequence ||
        !RelationOwnedByWaiter(*relation, wait->request) ||
        !SelectorMatches(table, *relation, wait->request) ||
        !WaitClassMatches(wait->request.options, relation->wait_class) ||
        !EventMatchesWaitKind(
                wait->request, relation->events[relation->event_head])) {
        return ESTALE;
    }
    *event = relation->events[relation->event_head];
    const bool preserve = wait->request.nowait != 0U;
    const uint32_t wait_slot = wait->slot;
    if (!preserve) {
        const bool exit_event = EventIsExit(*event);
        if (exit_event && relation->event_count != 1U) {
            return EPROTO;
        }
        PopRelationEvent(relation);
        if (exit_event) {
            EraseRelationAt(table, relation->slot);
        } else {
            ++table->mutation_generation;
        }
    }
    EraseWaitAt(table, wait_slot);
    return 0;
}

int RekeyLogicalPtraceTask(LogicalPtraceTable* table,
                           const LogicalTaskKey& old_identity,
                           const LogicalTaskKey& new_identity) noexcept {
    if (!IsLogicalPtraceTableInitialized(table) ||
        !TaskKeyValid(old_identity) || !TaskKeyValid(new_identity)) {
        return EINVAL;
    }
    if (LogicalTaskKeysEqual(old_identity, new_identity)) {
        return 0;
    }
    if (old_identity.tgid != new_identity.tgid ||
        old_identity.process_generation !=
                new_identity.process_generation) {
        return EXDEV;
    }
    if (FindLogicalProcess(
                table, LogicalProcessKeyForTask(old_identity)) == nullptr ||
        FindLogicalProcess(
                table, LogicalProcessKeyForTask(new_identity)) == nullptr) {
        return ESRCH;
    }

    LogicalFakeTracemeRecord* old_fake = FindFakeTraceme(
            table, old_identity);
    LogicalFakeTracemeRecord* new_fake = FindFakeTraceme(
            table, new_identity);
    if (old_fake != nullptr && new_fake != nullptr) {
        return EEXIST;
    }
    LogicalWaitRecord* old_wait = MutableLogicalWait(table, old_identity);
    LogicalWaitRecord* new_wait = MutableLogicalWait(table, new_identity);
    if (old_wait != nullptr && new_wait != nullptr) {
        return EEXIST;
    }
    LogicalPtraceRelation* old_tracee = MutableLogicalRelation(
            table, old_identity);
    LogicalPtraceRelation* new_tracee = MutableLogicalRelation(
            table, new_identity);
    if (old_tracee != nullptr && new_tracee != nullptr) {
        return EEXIST;
    }
    if (old_tracee != nullptr && old_tracee->tracer.tgid == new_identity.tgid) {
        return EPERM;
    }

    bool referenced = old_fake != nullptr || old_wait != nullptr ||
                      old_tracee != nullptr;
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.occupied == 0U ||
            !LogicalTaskKeysEqual(relation.tracer, old_identity)) {
            continue;
        }
        if (relation.tracee.tgid == new_identity.tgid) {
            return EPERM;
        }
        referenced = true;
    }
    if (!referenced) {
        return ESRCH;
    }

    if (old_fake != nullptr) {
        old_fake->task = new_identity;
    }
    if (old_wait != nullptr) {
        old_wait->request.waiter = new_identity;
    }
    if (old_tracee != nullptr) {
        old_tracee->tracee = new_identity;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.occupied != 0U &&
            LogicalTaskKeysEqual(relation.tracer, old_identity)) {
            relation.tracer = new_identity;
        }
    }
    ++table->mutation_generation;
    return 0;
}

bool ValidateLogicalPtraceTable(const LogicalPtraceTable* table) noexcept {
    if (!IsLogicalPtraceTableInitialized(table)) {
        return false;
    }
    uint32_t process_count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceProcessCapacity; ++slot) {
        const LogicalProcessRecord& process = table->processes[slot];
        if (process.slot != slot || process.occupied > 1U) {
            return false;
        }
        if (process.occupied == 0U) {
            if (process.key.tgid != 0 || process.key.generation != 0) {
                return false;
            }
            continue;
        }
        if (!ProcessKeyValid(process.key) || process.process_group <= 0 ||
            !DumpableValid(process.logical_dumpable) ||
            !PidIdentityValid(process.logical_ptracer) ||
            process.reserved != 0U ||
            (process.flags & ~kLogicalProcessFlagParentKnown) != 0U) {
            return false;
        }
        if ((process.flags & kLogicalProcessFlagParentKnown) != 0U) {
            if (!ProcessKeyValid(process.parent) ||
                LogicalProcessKeysEqual(process.key, process.parent) ||
                FindLogicalProcess(table, process.parent) == nullptr ||
                ParentChainContains(table, process.parent, process.key)) {
                return false;
            }
        } else if (process.parent.tgid != 0 ||
                   process.parent.generation != 0) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceProcessCapacity; ++other) {
            if (table->processes[other].occupied != 0U &&
                LogicalProcessKeysEqual(
                        process.key, table->processes[other].key)) {
                return false;
            }
        }
        ++process_count;
    }

    uint32_t relation_count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceRelationCapacity; ++slot) {
        const LogicalPtraceRelation& relation = table->relations[slot];
        if (relation.slot != slot || relation.occupied > 1U) {
            return false;
        }
        if (relation.occupied == 0U) {
            if (relation.generation != 0 || relation.event_count != 0U) {
                return false;
            }
            continue;
        }
        if (relation.generation == 0 || !TaskKeyValid(relation.tracee) ||
            !TaskKeyValid(relation.tracer) ||
            relation.tracee.tgid == relation.tracer.tgid ||
            !AttachKindValid(relation.attach_kind) ||
            !RelationStateValid(relation.state) ||
            !WaitClassValid(relation.wait_class) ||
            !RelationInitialStateValid(relation) ||
            PtraceChainContains(table, relation.tracer, relation.tracee) ||
            (relation.options & ~kLogicalPtraceKnownOptionMask) != 0U ||
            relation.event_head >= kLogicalPtraceEventQueueCapacity ||
            relation.event_count > kLogicalPtraceEventQueueCapacity ||
            relation.reserved != 0U ||
            FindLogicalProcess(
                    table, LogicalProcessKeyForTask(relation.tracee)) == nullptr ||
            FindLogicalProcess(
                    table, LogicalProcessKeyForTask(relation.tracer)) == nullptr) {
            return false;
        }
        if ((relation.state == LogicalPtraceRelationState::kAttachPending ||
             relation.state == LogicalPtraceRelationState::kSeizeRunning ||
             relation.state == LogicalPtraceRelationState::kRunningCont ||
             relation.state == LogicalPtraceRelationState::kRunningSyscall ||
             relation.state ==
                     LogicalPtraceRelationState::kRunningSingleStep ||
             relation.state == LogicalPtraceRelationState::kListening) &&
            relation.event_count != 0U) {
            return false;
        }
        if (relation.state == LogicalPtraceRelationState::kExitZombie &&
            relation.event_count == 0U) {
            return false;
        }
        bool exit_seen = false;
        for (uint32_t index = 0; index < relation.event_count; ++index) {
            const uint32_t event_slot =
                    (relation.event_head + index) %
                    kLogicalPtraceEventQueueCapacity;
            const LogicalPtraceEvent& event = relation.events[event_slot];
            if (!EventValid(event) || exit_seen) {
                return false;
            }
            exit_seen = EventIsExit(event);
        }
        if (exit_seen !=
            (relation.state == LogicalPtraceRelationState::kExitZombie)) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceRelationCapacity; ++other) {
            if (table->relations[other].occupied != 0U &&
                LogicalTaskKeysEqual(
                        relation.tracee, table->relations[other].tracee)) {
                return false;
            }
        }
        ++relation_count;
    }

    uint32_t fake_count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceFakeTracemeCapacity;
         ++slot) {
        const LogicalFakeTracemeRecord& fake = table->fake_traceme[slot];
        if (fake.slot != slot || fake.occupied > 1U) {
            return false;
        }
        if (fake.occupied == 0U) {
            if (fake.task.tid != 0 || fake.task.generation != 0) {
                return false;
            }
            continue;
        }
        if (!TaskKeyValid(fake.task) ||
            FindLogicalProcess(
                    table, LogicalProcessKeyForTask(fake.task)) == nullptr) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceFakeTracemeCapacity; ++other) {
            if (table->fake_traceme[other].occupied != 0U &&
                LogicalTaskKeysEqual(
                        fake.task, table->fake_traceme[other].task)) {
                return false;
            }
        }
        ++fake_count;
    }

    uint32_t wait_count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceWaitCapacity; ++slot) {
        const LogicalWaitRecord& wait = table->waits[slot];
        if (wait.slot != slot || wait.occupied > 1U) {
            return false;
        }
        if (wait.occupied == 0U) {
            if (wait.generation != 0 || wait.request.waiter.tid != 0) {
                return false;
            }
            continue;
        }
        if (wait.generation == 0 || !WaitRequestValid(wait.request) ||
            FindLogicalProcess(
                    table,
                    LogicalProcessKeyForTask(wait.request.waiter)) == nullptr) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceWaitCapacity; ++other) {
            if (table->waits[other].occupied != 0U &&
                LogicalTaskKeysEqual(
                        wait.request.waiter,
                        table->waits[other].request.waiter)) {
                return false;
            }
        }
        ++wait_count;
    }

    return process_count == table->process_count &&
           relation_count == table->relation_count &&
           fake_count == table->fake_traceme_count &&
           wait_count == table->wait_count;
}

}  // namespace hookself::tracer
