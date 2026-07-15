#include "internal/logical_ptrace_dispatcher.h"

#include <asm/unistd.h>
#include <elf.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>

namespace hookself::internal {
namespace {

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

constexpr uint32_t kLogicalPtraceStopFlagMask =
        kLogicalPtraceStopCurrentValid |
        kLogicalPtraceStopInterruptPending |
        kLogicalPtraceStopAttachPending;
constexpr uint32_t kLogicalPtraceEventFlagMask =
        tracer::kLogicalPtraceEventFlagSiginfoValid |
        tracer::kLogicalPtraceEventFlagRegistersValid |
        tracer::kLogicalPtraceEventFlagSyscallNumberValid;

struct RemoteIovec64 {
    uint64_t base;
    uint64_t length;
};

struct PtraceOutcome {
    bool handled;
    int64_t result;
    LogicalPtraceTargetRequest target;
};

static_assert(sizeof(RemoteIovec64) == 16U);

void ZeroBytes(void* memory, size_t size) noexcept {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
}

bool TaskKeyValid(const tracer::LogicalTaskKey& task) noexcept {
    return task.tid > 0 && task.tgid > 0 && task.generation != 0 &&
           task.process_generation != 0;
}

bool OperationStateValid(LogicalPtraceOperationState state) noexcept {
    return state == LogicalPtraceOperationState::kImmediate ||
           state == LogicalPtraceOperationState::kHeldWait ||
           state == LogicalPtraceOperationState::kHeldReady;
}

bool EventSnapshotValid(const tracer::LogicalPtraceEvent& event) noexcept {
    return event.sequence != 0 &&
           event.kind >= tracer::LogicalPtraceEventKind::kAttachStop &&
           event.kind <= tracer::LogicalPtraceEventKind::kContinued &&
           (event.flags & ~kLogicalPtraceEventFlagMask) == 0U &&
           event.signal_number >= 0 && event.signal_number < NSIG &&
           event.reserved == 0U &&
           ((event.flags &
             tracer::kLogicalPtraceEventFlagSyscallNumberValid) != 0U ||
            event.guest_syscall_number == -1);
}

int CallbackError(int error) noexcept {
    return error >= 0 ? error : EPROTO;
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

void ClearOperation(LogicalPtraceDispatchOperation* operation,
                    uint32_t slot) noexcept {
    ZeroBytes(operation, sizeof(*operation));
    operation->slot = slot;
}

void ClearStop(LogicalPtraceDispatchStop* stop, uint32_t slot) noexcept {
    ZeroBytes(stop, sizeof(*stop));
    stop->relation_slot = slot;
    stop->current.guest_syscall_number = -1;
}

LogicalPtraceDispatchOperation* FindOperation(
        LogicalPtraceDispatcher* dispatcher,
        const tracer::LogicalTaskKey& caller) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher)) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        LogicalPtraceDispatchOperation& operation =
                dispatcher->operations[slot];
        if (operation.occupied != 0U &&
            tracer::LogicalTaskKeysEqual(operation.caller, caller)) {
            return &operation;
        }
    }
    return nullptr;
}

int InsertOperation(LogicalPtraceDispatcher* dispatcher,
                    const tracer::LogicalTaskKey& caller,
                    int32_t syscall_number,
                    LogicalPtraceOperationState state, int64_t result,
                    uint32_t* slot) noexcept {
    if (slot != nullptr) {
        *slot = kLogicalPtraceDispatchInvalidSlot;
    }
    if (FindOperation(dispatcher, caller) != nullptr) {
        return EBUSY;
    }
    if (dispatcher->operation_count == kLogicalPtraceDispatchCapacity) {
        return ENOSPC;
    }
    for (uint32_t offset = 0; offset < kLogicalPtraceDispatchCapacity;
         ++offset) {
        uint32_t candidate = dispatcher->operation_free_hint + offset;
        if (candidate >= kLogicalPtraceDispatchCapacity) {
            candidate -= kLogicalPtraceDispatchCapacity;
        }
        LogicalPtraceDispatchOperation* operation =
                &dispatcher->operations[candidate];
        if (operation->occupied != 0U) {
            continue;
        }
        ClearOperation(operation, candidate);
        operation->occupied = 1U;
        operation->generation = AllocateSequence(
                &dispatcher->next_operation_generation);
        operation->caller = caller;
        operation->syscall_number = syscall_number;
        operation->state = state;
        operation->visible_result = result;
        ++dispatcher->operation_count;
        ++dispatcher->mutation_generation;
        dispatcher->operation_free_hint = candidate + 1U;
        if (dispatcher->operation_free_hint ==
            kLogicalPtraceDispatchCapacity) {
            dispatcher->operation_free_hint = 0;
        }
        if (slot != nullptr) {
            *slot = candidate;
        }
        return 0;
    }
    return ENOSPC;
}

void EraseOperation(LogicalPtraceDispatcher* dispatcher,
                    uint32_t slot) noexcept {
    ClearOperation(&dispatcher->operations[slot], slot);
    --dispatcher->operation_count;
    dispatcher->operation_free_hint = slot;
    ++dispatcher->mutation_generation;
}

int ReadMemory(const LogicalPtraceDispatchIo& io,
               const tracer::LogicalTaskKey& task, uintptr_t address,
               void* output, size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (io.read_memory == nullptr) {
        return ENOSYS;
    }
    if (address == 0 || output == nullptr ||
        address > UINTPTR_MAX - (size - 1U)) {
        return EFAULT;
    }
    return CallbackError(
            io.read_memory(io.opaque, &task, address, output, size));
}

int WriteMemory(const LogicalPtraceDispatchIo& io,
                const tracer::LogicalTaskKey& task, uintptr_t address,
                const void* input, size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (io.write_memory == nullptr) {
        return ENOSYS;
    }
    if (address == 0 || input == nullptr ||
        address > UINTPTR_MAX - (size - 1U)) {
        return EFAULT;
    }
    return CallbackError(
            io.write_memory(io.opaque, &task, address, input, size));
}

int ResolveTask(const LogicalPtraceDispatchIo& io,
                const tracer::LogicalTaskKey& caller, int32_t tid,
                tracer::LogicalTaskKey* output) noexcept {
    if (io.resolve_task == nullptr || output == nullptr) {
        return ENOSYS;
    }
    ZeroBytes(output, sizeof(*output));
    const int error = CallbackError(
            io.resolve_task(io.opaque, &caller, tid, output));
    if (error != 0) {
        return error;
    }
    return TaskKeyValid(*output) ? 0 : EPROTO;
}

int ResolveParent(const LogicalPtraceDispatchIo& io,
                  const tracer::LogicalTaskKey& caller,
                  tracer::LogicalTaskKey* output) noexcept {
    if (io.resolve_parent == nullptr || output == nullptr) {
        return ENOSYS;
    }
    ZeroBytes(output, sizeof(*output));
    const int error = CallbackError(
            io.resolve_parent(io.opaque, &caller, output));
    if (error != 0) {
        return error;
    }
    return TaskKeyValid(*output) ? 0 : EPROTO;
}

int CheckAttachPermission(const LogicalPtraceDispatchIo& io,
                          const tracer::LogicalTaskKey& caller,
                          const tracer::LogicalTaskKey& target,
                          tracer::LogicalPtraceAttachKind kind) noexcept {
    if (io.may_attach == nullptr) {
        return 0;
    }
    return CallbackError(io.may_attach(io.opaque, &caller, &target, kind));
}

bool RelationOwnedByCaller(const tracer::LogicalPtraceRelation& relation,
                           const tracer::LogicalTaskKey& caller) noexcept {
    return relation.tracer.tgid == caller.tgid &&
           relation.tracer.process_generation ==
                   caller.process_generation;
}

LogicalPtraceDispatchStop* EnsureStopRecord(
        LogicalPtraceDispatcher* dispatcher,
        const tracer::LogicalPtraceRelation& relation) noexcept {
    if (relation.slot >= kLogicalPtraceDispatchCapacity) {
        return nullptr;
    }
    LogicalPtraceDispatchStop* stop = &dispatcher->stops[relation.slot];
    if (stop->relation_generation != relation.generation ||
        !tracer::LogicalTaskKeysEqual(stop->tracee, relation.tracee)) {
        ClearStop(stop, relation.slot);
        stop->relation_generation = relation.generation;
        stop->tracee = relation.tracee;
    }
    return stop;
}

LogicalPtraceDispatchStop* CurrentStop(
        LogicalPtraceDispatcher* dispatcher,
        const tracer::LogicalPtraceRelation& relation) noexcept {
    LogicalPtraceDispatchStop* stop = EnsureStopRecord(dispatcher, relation);
    return stop != nullptr &&
                   (stop->flags & kLogicalPtraceStopCurrentValid) != 0U
           ? stop
           : nullptr;
}

void ForgetStop(LogicalPtraceDispatcher* dispatcher,
                uint32_t relation_slot) noexcept {
    if (relation_slot < kLogicalPtraceDispatchCapacity) {
        ClearStop(&dispatcher->stops[relation_slot], relation_slot);
        ++dispatcher->mutation_generation;
    }
}

void RememberDeliveredStop(LogicalPtraceDispatcher* dispatcher,
                           uint32_t relation_slot,
                           uint64_t relation_generation,
                           const tracer::LogicalTaskKey& tracee,
                           const tracer::LogicalPtraceEvent& event) noexcept {
    if (relation_slot >= kLogicalPtraceDispatchCapacity) {
        return;
    }
    LogicalPtraceDispatchStop* stop = &dispatcher->stops[relation_slot];
    ClearStop(stop, relation_slot);
    stop->flags = kLogicalPtraceStopCurrentValid;
    stop->relation_generation = relation_generation;
    stop->tracee = tracee;
    stop->current = event;
    ++dispatcher->mutation_generation;
}

void FillTargetFromStop(LogicalPtraceTargetAction action,
                        const tracer::LogicalTaskKey& target,
                        int32_t signal_number,
                        const LogicalPtraceDispatchStop* stop,
                        LogicalPtraceTargetRequest* request) noexcept {
    *request = {};
    request->action = action;
    request->target = target;
    request->signal_number = signal_number;
    request->syscall_number = -1;
    if (stop == nullptr) {
        return;
    }
    request->stop_kind = stop->current.kind;
    if ((stop->current.flags &
         tracer::kLogicalPtraceEventFlagRegistersValid) != 0U) {
        request->flags |= kLogicalPtraceTargetRegistersValid;
        request->registers = stop->current.guest_registers;
    }
    if ((stop->current.flags &
         tracer::kLogicalPtraceEventFlagSyscallNumberValid) != 0U) {
        request->flags |= kLogicalPtraceTargetSyscallNumberValid;
        request->syscall_number = stop->current.guest_syscall_number;
    }
    if ((stop->current.flags &
         tracer::kLogicalPtraceEventFlagSiginfoValid) != 0U) {
        request->flags |= kLogicalPtraceTargetSiginfoValid;
        request->signal_info = stop->current.signal_info;
    }
}

int UpdateQueuedRegisters(tracer::LogicalPtraceTable* logical,
                          const tracer::LogicalPtraceRelation& relation,
                          const hookself::arch::Arm64Regs& registers,
                          bool syscall_number_valid,
                          int32_t syscall_number) noexcept {
    if (relation.event_count == 0U) {
        return 0;
    }
    return tracer::SetLogicalPtraceEventRegisters(
            logical, relation.tracee, registers, syscall_number_valid,
            syscall_number);
}

int UpdateQueuedSyscallNumber(
        tracer::LogicalPtraceTable* logical,
        tracer::LogicalPtraceRelation& relation,
        int32_t syscall_number) noexcept {
    if (relation.event_count == 0U) {
        return 0;
    }
    if (relation.state != tracer::LogicalPtraceRelationState::kStopped &&
        relation.state != tracer::LogicalPtraceRelationState::kExitZombie) {
        return EBUSY;
    }
    tracer::LogicalPtraceEvent* event =
            &relation.events[relation.event_head];
    event->guest_syscall_number = syscall_number;
    event->flags |= tracer::kLogicalPtraceEventFlagSyscallNumberValid;
    ++logical->mutation_generation;
    return 0;
}

int UpdateQueuedSiginfo(tracer::LogicalPtraceTable* logical,
                        const tracer::LogicalPtraceRelation& relation,
                        const siginfo_t& signal_info) noexcept {
    if (relation.event_count == 0U) {
        return 0;
    }
    return tracer::SetLogicalPtraceEventSiginfo(logical, relation.tracee,
                                                signal_info);
}

bool EventIsExit(const tracer::LogicalPtraceEvent& event) noexcept {
    return event.kind == tracer::LogicalPtraceEventKind::kExited ||
           event.kind == tracer::LogicalPtraceEventKind::kSignaled;
}

int QueryUid(const LogicalPtraceDispatchIo& io,
             const tracer::LogicalTaskKey& tracee,
             uint32_t* uid) noexcept {
    *uid = 0;
    if (io.query_uid == nullptr) {
        return 0;
    }
    return CallbackError(io.query_uid(io.opaque, &tracee, uid));
}

int FillWaitRusage(const LogicalPtraceDispatchIo& io,
                   const tracer::LogicalTaskKey& tracee,
                   const tracer::LogicalPtraceEvent& event,
                   struct rusage* usage) noexcept {
    ZeroBytes(usage, sizeof(*usage));
    if (io.fill_rusage == nullptr) {
        return 0;
    }
    return CallbackError(io.fill_rusage(io.opaque, &tracee, &event, usage,
                                        sizeof(*usage)));
}

void BuildWaitIdSiginfo(const tracer::LogicalTaskKey& tracee,
                        const tracer::LogicalPtraceEvent& event,
                        uint32_t uid, siginfo_t* info) noexcept {
    ZeroBytes(info, sizeof(*info));
    info->si_signo = SIGCHLD;
    info->si_pid = tracee.tid;
    info->si_uid = uid;
    if (event.kind == tracer::LogicalPtraceEventKind::kExited) {
        info->si_code = CLD_EXITED;
        info->si_status = WIFEXITED(event.wait_status)
                                  ? WEXITSTATUS(event.wait_status)
                                  : 0;
    } else if (event.kind == tracer::LogicalPtraceEventKind::kSignaled) {
        info->si_code = WCOREDUMP(event.wait_status) ? CLD_DUMPED : CLD_KILLED;
        info->si_status = WIFSIGNALED(event.wait_status)
                                  ? WTERMSIG(event.wait_status)
                                  : event.signal_number;
    } else if (event.kind == tracer::LogicalPtraceEventKind::kContinued) {
        info->si_code = CLD_CONTINUED;
        info->si_status = SIGCONT;
    } else {
        info->si_code = CLD_TRAPPED;
        info->si_status = WIFSTOPPED(event.wait_status)
                                  ? WSTOPSIG(event.wait_status)
                                  : event.signal_number;
    }
}

int WriteWaitOutput(const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalWaitRecord& wait,
                    const tracer::LogicalTaskKey& tracee,
                    const tracer::LogicalPtraceEvent& event,
                    int64_t* visible_result) noexcept {
    const tracer::LogicalWaitRequest& request = wait.request;
    if (request.kind == tracer::LogicalWaitKind::kWait4) {
        if (request.status_address != 0) {
            const int32_t status = event.wait_status;
            const int error = WriteMemory(
                    io, request.waiter,
                    static_cast<uintptr_t>(request.status_address), &status,
                    sizeof(status));
            if (error != 0) {
                return error;
            }
        }
        if (request.rusage_address != 0) {
            struct rusage usage {};
            int error = FillWaitRusage(io, tracee, event, &usage);
            if (error == 0) {
                error = WriteMemory(
                        io, request.waiter,
                        static_cast<uintptr_t>(request.rusage_address),
                        &usage, sizeof(usage));
            }
            if (error != 0) {
                return error;
            }
        }
        *visible_result = tracee.tid;
        return 0;
    }

    uint32_t uid = 0;
    int error = QueryUid(io, tracee, &uid);
    if (error != 0) {
        return error;
    }
    if (request.info_address != 0) {
        siginfo_t info {};
        BuildWaitIdSiginfo(tracee, event, uid, &info);
        error = WriteMemory(io, request.waiter,
                            static_cast<uintptr_t>(request.info_address),
                            &info, sizeof(info));
        if (error != 0) {
            return error;
        }
    }
    if (request.rusage_address != 0) {
        struct rusage usage {};
        error = FillWaitRusage(io, tracee, event, &usage);
        if (error == 0) {
            error = WriteMemory(
                    io, request.waiter,
                    static_cast<uintptr_t>(request.rusage_address), &usage,
                    sizeof(usage));
        }
        if (error != 0) {
            return error;
        }
    }
    *visible_result = 0;
    return 0;
}

int CompleteSelectedWait(LogicalPtraceDispatcher* dispatcher,
                         tracer::LogicalPtraceTable* logical,
                         const LogicalPtraceDispatchIo& io,
                         const tracer::LogicalTaskKey& waiter,
                         const tracer::LogicalWaitMatch& match,
                         int64_t* visible_result) noexcept {
    const tracer::LogicalWaitRecord* wait =
            tracer::FindLogicalWait(logical, waiter);
    const tracer::LogicalPtraceRelation* relation =
            tracer::LogicalPtraceRelationAt(logical, match.relation_slot);
    if (wait == nullptr || relation == nullptr ||
        relation->generation != match.relation_generation ||
        relation->event_count == 0U) {
        return ESTALE;
    }
    const tracer::LogicalPtraceEvent& pending =
            relation->events[relation->event_head];
    if (pending.sequence != match.event_sequence) {
        return ESTALE;
    }
    const tracer::LogicalTaskKey tracee = relation->tracee;
    const uint32_t relation_slot = relation->slot;
    const uint64_t relation_generation = relation->generation;
    tracer::LogicalPtraceEvent event = pending;
    const int output_error = WriteWaitOutput(
            io, *wait, tracee, event, visible_result);
    if (output_error != 0) {
        (void)tracer::EndLogicalWait(logical, waiter);
        *visible_result = -output_error;
        return 0;
    }
    const int consume_error = tracer::ConsumeLogicalWaitEvent(
            logical, waiter, match, &event);
    if (consume_error != 0) {
        return consume_error;
    }
    if (!EventIsExit(event)) {
        RememberDeliveredStop(dispatcher, relation_slot,
                              relation_generation, tracee, event);
    } else {
        ForgetStop(dispatcher, relation_slot);
    }
    return 0;
}

int ZeroNoHangWaitId(const LogicalPtraceDispatchIo& io,
                     const tracer::LogicalWaitRequest& request) noexcept {
    if (request.kind != tracer::LogicalWaitKind::kWaitId ||
        request.info_address == 0) {
        return 0;
    }
    siginfo_t empty {};
    return WriteMemory(io, request.waiter,
                       static_cast<uintptr_t>(request.info_address), &empty,
                       sizeof(empty));
}

}  // namespace

namespace {

int HandlePtraceEntry(LogicalPtraceDispatcher* dispatcher,
                      tracer::LogicalPtraceTable* logical,
                      const LogicalPtraceDispatchIo& io,
                      const tracer::LogicalTaskKey& caller,
                      const uint64_t arguments[6],
                      PtraceOutcome* outcome) noexcept;

int HandleWaitEntry(LogicalPtraceDispatcher* dispatcher,
                    tracer::LogicalPtraceTable* logical,
                    const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalTaskKey& caller,
                    int32_t syscall_number, const uint64_t arguments[6],
                    LogicalPtraceEntryResult* result) noexcept;

}  // namespace

void InitLogicalPtraceDispatcher(
        LogicalPtraceDispatcher* dispatcher) noexcept {
    if (dispatcher == nullptr) {
        return;
    }
    ZeroBytes(dispatcher, sizeof(*dispatcher));
    dispatcher->magic = kLogicalPtraceDispatchMagic;
    dispatcher->version = kLogicalPtraceDispatchVersion;
    dispatcher->next_operation_generation = 1;
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        ClearOperation(&dispatcher->operations[slot], slot);
        ClearStop(&dispatcher->stops[slot], slot);
    }
}

bool IsLogicalPtraceDispatcherInitialized(
        const LogicalPtraceDispatcher* dispatcher) noexcept {
    return dispatcher != nullptr &&
           dispatcher->magic == kLogicalPtraceDispatchMagic &&
           dispatcher->version == kLogicalPtraceDispatchVersion &&
           dispatcher->operation_count <= kLogicalPtraceDispatchCapacity &&
           dispatcher->operation_free_hint <
                   kLogicalPtraceDispatchCapacity &&
           dispatcher->next_operation_generation != 0;
}

const LogicalPtraceDispatchOperation* LogicalPtraceOperationAt(
        const LogicalPtraceDispatcher* dispatcher, uint32_t slot) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        slot >= kLogicalPtraceDispatchCapacity ||
        dispatcher->operations[slot].occupied == 0U) {
        return nullptr;
    }
    return &dispatcher->operations[slot];
}

bool ValidateLogicalPtraceDispatcher(
        const LogicalPtraceDispatcher* dispatcher,
        const tracer::LogicalPtraceTable* logical) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::ValidateLogicalPtraceTable(logical)) {
        return false;
    }
    uint32_t operation_count = 0;
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        const LogicalPtraceDispatchOperation& operation =
                dispatcher->operations[slot];
        if (operation.slot != slot || operation.occupied > 1U) {
            return false;
        }
        if (operation.occupied == 0U) {
            if (operation.generation != 0 || operation.caller.tid != 0) {
                return false;
            }
            continue;
        }
        if (operation.generation == 0 || !TaskKeyValid(operation.caller) ||
            operation.syscall_number < 0 ||
            !OperationStateValid(operation.state) ||
            tracer::FindLogicalProcess(
                    logical,
                    tracer::LogicalProcessKeyForTask(operation.caller)) ==
                    nullptr) {
            return false;
        }
        const tracer::LogicalWaitRecord* wait =
                tracer::FindLogicalWait(logical, operation.caller);
        if ((operation.state == LogicalPtraceOperationState::kHeldWait) !=
            (wait != nullptr)) {
            return false;
        }
        for (uint32_t other = slot + 1;
             other < kLogicalPtraceDispatchCapacity; ++other) {
            if (dispatcher->operations[other].occupied != 0U &&
                tracer::LogicalTaskKeysEqual(
                        operation.caller,
                        dispatcher->operations[other].caller)) {
                return false;
            }
        }
        ++operation_count;
    }

    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        const LogicalPtraceDispatchStop& stop = dispatcher->stops[slot];
        if (stop.relation_slot != slot ||
            (stop.flags & ~kLogicalPtraceStopFlagMask) != 0U ||
            ((stop.flags & kLogicalPtraceStopCurrentValid) != 0U &&
             (stop.flags & (kLogicalPtraceStopInterruptPending |
                            kLogicalPtraceStopAttachPending)) != 0U)) {
            return false;
        }
        if (stop.relation_generation == 0) {
            if (stop.flags != 0U || stop.tracee.tid != 0 ||
                stop.current.sequence != 0) {
                return false;
            }
            continue;
        }
        const tracer::LogicalPtraceRelation* relation =
                tracer::LogicalPtraceRelationAt(logical, slot);
        if (relation == nullptr ||
            relation->generation != stop.relation_generation ||
            !tracer::LogicalTaskKeysEqual(relation->tracee, stop.tracee)) {
            return false;
        }
        if ((stop.flags & kLogicalPtraceStopCurrentValid) != 0U &&
            (!EventSnapshotValid(stop.current) ||
             relation->state !=
                      tracer::LogicalPtraceRelationState::kStopped)) {
            return false;
        }
        if ((stop.flags & kLogicalPtraceStopCurrentValid) == 0U &&
            stop.current.sequence != 0U) {
            return false;
        }
        if ((stop.flags & kLogicalPtraceStopCurrentValid) != 0U &&
            relation->event_count != 0U &&
            (relation->event_count != 1U ||
             relation->events[relation->event_head].sequence !=
                     stop.current.sequence)) {
            return false;
        }
        if ((stop.flags & kLogicalPtraceStopAttachPending) != 0U &&
            (relation->attach_kind !=
                     tracer::LogicalPtraceAttachKind::kAttach ||
             relation->state !=
                     tracer::LogicalPtraceRelationState::kAttachPending)) {
            return false;
        }
        if ((stop.flags & kLogicalPtraceStopInterruptPending) != 0U &&
            (relation->attach_kind !=
                     tracer::LogicalPtraceAttachKind::kSeize ||
             relation->state ==
                     tracer::LogicalPtraceRelationState::kStopped ||
             relation->state ==
                     tracer::LogicalPtraceRelationState::kExitZombie)) {
            return false;
        }
    }
    return operation_count == dispatcher->operation_count;
}

int DispatchLogicalPtraceEntry(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const LogicalPtraceDispatchIo& io,
        const tracer::LogicalTaskKey& caller, int32_t syscall_number,
        const uint64_t arguments[6],
        LogicalPtraceEntryResult* result) noexcept {
    if (result == nullptr || arguments == nullptr ||
        !IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(caller) ||
        tracer::FindLogicalProcess(
                logical, tracer::LogicalProcessKeyForTask(caller)) == nullptr) {
        return EINVAL;
    }
    *result = {};
    result->operation_slot = kLogicalPtraceDispatchInvalidSlot;
    result->syscall_number = syscall_number;
    result->target.syscall_number = -1;
    if (FindOperation(dispatcher, caller) != nullptr) {
        return EBUSY;
    }

    if (syscall_number == __NR_wait4 || syscall_number == __NR_waitid) {
        return HandleWaitEntry(dispatcher, logical, io, caller,
                               syscall_number, arguments, result);
    }
    if (syscall_number != __NR_ptrace) {
        return 0;
    }

    PtraceOutcome outcome {};
    const int ptrace_error = HandlePtraceEntry(
            dispatcher, logical, io, caller, arguments, &outcome);
    if (ptrace_error != 0 || !outcome.handled) {
        return ptrace_error;
    }
    uint32_t operation_slot = kLogicalPtraceDispatchInvalidSlot;
    const int insert_error = InsertOperation(
            dispatcher, caller, syscall_number,
            LogicalPtraceOperationState::kImmediate, outcome.result,
            &operation_slot);
    if (insert_error != 0) {
        return insert_error;
    }
    result->flags = kLogicalPtraceEntryHandled |
                    kLogicalPtraceEntrySuppress;
    result->operation_slot = operation_slot;
    result->visible_result = outcome.result;
    result->target = outcome.target;
    if (outcome.target.action != LogicalPtraceTargetAction::kNone) {
        result->flags |= kLogicalPtraceEntryTargetAction;
    }
    return 0;
}

int DispatchLogicalPtraceExit(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& caller, int32_t syscall_number,
        int64_t kernel_result, LogicalPtraceExitResult* result) noexcept {
    (void)kernel_result;
    if (result == nullptr ||
        !IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(caller)) {
        return EINVAL;
    }
    *result = {};
    result->operation_slot = kLogicalPtraceDispatchInvalidSlot;
    LogicalPtraceDispatchOperation* operation =
            FindOperation(dispatcher, caller);
    if (operation == nullptr) {
        return 0;
    }
    if (operation->syscall_number != syscall_number) {
        return ESTALE;
    }
    result->flags = kLogicalPtraceExitHandled;
    result->operation_slot = operation->slot;
    if (operation->state == LogicalPtraceOperationState::kHeldWait) {
        result->flags |= kLogicalPtraceExitHold;
        return 0;
    }
    result->flags |= kLogicalPtraceExitWriteResult;
    result->visible_result = operation->visible_result;
    EraseOperation(dispatcher, operation->slot);
    return 0;
}

int PublishLogicalPtraceStop(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& tracee,
        const tracer::LogicalPtraceEvent& event,
        uint64_t* sequence) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(tracee)) {
        return EINVAL;
    }
    const tracer::LogicalPtraceRelation* relation =
            tracer::FindLogicalPtraceRelation(logical, tracee);
    if (relation == nullptr) {
        return ESRCH;
    }
    LogicalPtraceDispatchStop* stop = EnsureStopRecord(dispatcher, *relation);
    if (stop == nullptr) {
        return EPROTO;
    }
    if ((stop->flags & kLogicalPtraceStopAttachPending) != 0U &&
        event.kind != tracer::LogicalPtraceEventKind::kAttachStop &&
        !EventIsExit(event)) {
        return EPROTO;
    }
    if ((stop->flags & kLogicalPtraceStopCurrentValid) != 0U) {
        return EBUSY;
    }
    if ((stop->flags & kLogicalPtraceStopInterruptPending) != 0U &&
        event.kind != tracer::LogicalPtraceEventKind::kInterruptStop &&
        !EventIsExit(event)) {
        return EPROTO;
    }
    const int error = tracer::QueueLogicalPtraceEvent(
            logical, tracee, event, sequence);
    if (error != 0) {
        return error;
    }
    stop->flags &= ~(kLogicalPtraceStopAttachPending |
                     kLogicalPtraceStopInterruptPending |
                     kLogicalPtraceStopCurrentValid);
    ZeroBytes(&stop->current, sizeof(stop->current));
    stop->current.guest_syscall_number = -1;
    ++dispatcher->mutation_generation;
    return 0;
}

int TryWakeLogicalPtraceWait(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const LogicalPtraceDispatchIo& io,
        const tracer::LogicalTaskKey& waiter) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(waiter)) {
        return EINVAL;
    }
    LogicalPtraceDispatchOperation* operation =
            FindOperation(dispatcher, waiter);
    if (operation == nullptr ||
        operation->state != LogicalPtraceOperationState::kHeldWait) {
        return ESRCH;
    }
    tracer::LogicalWaitMatch match {};
    const int select_error = tracer::SelectLogicalWaitEvent(
            logical, waiter, &match);
    if (select_error == EAGAIN) {
        return EAGAIN;
    }
    if (select_error == ECHILD) {
        (void)tracer::EndLogicalWait(logical, waiter);
        operation->visible_result = -ECHILD;
        operation->state = LogicalPtraceOperationState::kHeldReady;
        ++dispatcher->mutation_generation;
        return 0;
    }
    if (select_error != 0) {
        return select_error;
    }
    int64_t visible_result = 0;
    const int complete_error = CompleteSelectedWait(
            dispatcher, logical, io, waiter, match, &visible_result);
    if (complete_error != 0) {
        return complete_error;
    }
    operation->visible_result = visible_result;
    operation->state = LogicalPtraceOperationState::kHeldReady;
    ++dispatcher->mutation_generation;
    return 0;
}

int CancelLogicalPtraceDispatch(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& caller) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(caller)) {
        return EINVAL;
    }
    LogicalPtraceDispatchOperation* operation =
            FindOperation(dispatcher, caller);
    if (operation == nullptr) {
        return ESRCH;
    }
    if (operation->state == LogicalPtraceOperationState::kHeldWait) {
        const int wait_error = tracer::EndLogicalWait(logical, caller);
        if (wait_error != 0 && wait_error != ESRCH) {
            return wait_error;
        }
    }
    EraseOperation(dispatcher, operation->slot);
    return 0;
}

int RekeyLogicalPtraceDispatchTask(
        LogicalPtraceDispatcher* dispatcher,
        tracer::LogicalPtraceTable* logical,
        const tracer::LogicalTaskKey& old_identity,
        const tracer::LogicalTaskKey& new_identity) noexcept {
    if (!IsLogicalPtraceDispatcherInitialized(dispatcher) ||
        !tracer::IsLogicalPtraceTableInitialized(logical) ||
        !TaskKeyValid(old_identity) || !TaskKeyValid(new_identity)) {
        return EINVAL;
    }
    if (tracer::LogicalTaskKeysEqual(old_identity, new_identity)) {
        return 0;
    }
    if (old_identity.tgid != new_identity.tgid ||
        old_identity.process_generation != new_identity.process_generation) {
        return EXDEV;
    }
    if (tracer::FindLogicalProcess(
                logical,
                tracer::LogicalProcessKeyForTask(old_identity)) == nullptr) {
        return ESRCH;
    }

    LogicalPtraceDispatchOperation* old_operation =
            FindOperation(dispatcher, old_identity);
    LogicalPtraceDispatchOperation* new_operation =
            FindOperation(dispatcher, new_identity);
    if (old_operation != nullptr && new_operation != nullptr &&
        old_operation != new_operation) {
        return EEXIST;
    }

    bool dispatcher_referenced = old_operation != nullptr;
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        const LogicalPtraceDispatchStop& stop = dispatcher->stops[slot];
        dispatcher_referenced = dispatcher_referenced ||
                (stop.relation_generation != 0U &&
                 tracer::LogicalTaskKeysEqual(stop.tracee, old_identity));
    }

    const int logical_error = tracer::RekeyLogicalPtraceTask(
            logical, old_identity, new_identity);
    if (logical_error != 0 &&
        !(logical_error == ESRCH && dispatcher_referenced)) {
        return logical_error;
    }

    bool dispatcher_changed = false;
    if (old_operation != nullptr) {
        old_operation->caller = new_identity;
        dispatcher_changed = true;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        LogicalPtraceDispatchStop& stop = dispatcher->stops[slot];
        if (stop.relation_generation != 0U &&
            tracer::LogicalTaskKeysEqual(stop.tracee, old_identity)) {
            stop.tracee = new_identity;
            dispatcher_changed = true;
        }
    }
    if (dispatcher_changed) {
        ++dispatcher->mutation_generation;
    }
    return 0;
}

namespace {

int FindOwnedRelation(tracer::LogicalPtraceTable* logical,
                      const tracer::LogicalTaskKey& caller,
                      const tracer::LogicalTaskKey& target,
                      tracer::LogicalPtraceRelation** output) noexcept {
    *output = const_cast<tracer::LogicalPtraceRelation*>(
            tracer::FindLogicalPtraceRelation(logical, target));
    if (*output == nullptr || !RelationOwnedByCaller(**output, caller)) {
        *output = nullptr;
        return ESRCH;
    }
    return 0;
}

int GetDeliveredStop(LogicalPtraceDispatcher* dispatcher,
                     tracer::LogicalPtraceRelation& relation,
                     LogicalPtraceDispatchStop** output) noexcept {
    *output = CurrentStop(dispatcher, relation);
    if (*output == nullptr ||
        relation.state != tracer::LogicalPtraceRelationState::kStopped) {
        *output = nullptr;
        return ESRCH;
    }
    return 0;
}

int ReadRemoteIovec(const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalTaskKey& caller, uint64_t address,
                    RemoteIovec64* vector) noexcept {
    return ReadMemory(io, caller, static_cast<uintptr_t>(address), vector,
                      sizeof(*vector));
}

int WriteRemoteIovec(const LogicalPtraceDispatchIo& io,
                     const tracer::LogicalTaskKey& caller, uint64_t address,
                     const RemoteIovec64& vector) noexcept {
    return WriteMemory(io, caller, static_cast<uintptr_t>(address), &vector,
                       sizeof(vector));
}

int HandleGetRegset(const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalTaskKey& caller, uint64_t note_type,
                    uint64_t vector_address,
                    const LogicalPtraceDispatchStop& stop) noexcept {
    RemoteIovec64 vector {};
    int error = ReadRemoteIovec(io, caller, vector_address, &vector);
    if (error != 0) {
        return error;
    }
    const void* source = nullptr;
    size_t source_size = 0;
    int32_t syscall_number = stop.current.guest_syscall_number;
    if (note_type == NT_PRSTATUS) {
        if ((stop.current.flags &
             tracer::kLogicalPtraceEventFlagRegistersValid) == 0U) {
            return EIO;
        }
        source = &stop.current.guest_registers;
        source_size = sizeof(stop.current.guest_registers);
    } else if (note_type == NT_ARM_SYSTEM_CALL) {
        if ((stop.current.flags &
             tracer::kLogicalPtraceEventFlagSyscallNumberValid) == 0U) {
            return EIO;
        }
        source = &syscall_number;
        source_size = sizeof(syscall_number);
    } else {
        return EINVAL;
    }
    const size_t copy_size =
            vector.length < source_size
                    ? static_cast<size_t>(vector.length)
                    : source_size;
    if (copy_size != 0) {
        error = WriteMemory(io, caller, static_cast<uintptr_t>(vector.base),
                            source, copy_size);
        if (error != 0) {
            return error;
        }
    }
    vector.length = copy_size;
    return WriteRemoteIovec(io, caller, vector_address, vector);
}

int HandleSetRegset(LogicalPtraceDispatcher* dispatcher,
                    tracer::LogicalPtraceTable* logical,
                    const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalTaskKey& caller, uint64_t note_type,
                    uint64_t vector_address,
                    tracer::LogicalPtraceRelation& relation,
                    LogicalPtraceDispatchStop* stop) noexcept {
    RemoteIovec64 vector {};
    int error = ReadRemoteIovec(io, caller, vector_address, &vector);
    if (error != 0) {
        return error;
    }
    if (note_type == NT_PRSTATUS) {
        if (vector.length < sizeof(stop->current.guest_registers)) {
            return EINVAL;
        }
        hookself::arch::Arm64Regs registers {};
        error = ReadMemory(io, caller, static_cast<uintptr_t>(vector.base),
                           &registers, sizeof(registers));
        if (error != 0) {
            return error;
        }
        error = UpdateQueuedRegisters(
                logical, relation, registers,
                (stop->current.flags &
                 tracer::kLogicalPtraceEventFlagSyscallNumberValid) != 0U,
                stop->current.guest_syscall_number);
        if (error == 0) {
            stop->current.guest_registers = registers;
            stop->current.flags |=
                    tracer::kLogicalPtraceEventFlagRegistersValid;
        }
    } else if (note_type == NT_ARM_SYSTEM_CALL) {
        if (vector.length < sizeof(int32_t)) {
            return EINVAL;
        }
        int32_t syscall_number = -1;
        error = ReadMemory(io, caller, static_cast<uintptr_t>(vector.base),
                           &syscall_number, sizeof(syscall_number));
        if (error != 0) {
            return error;
        }
        error = UpdateQueuedSyscallNumber(logical, relation, syscall_number);
        if (error == 0) {
            stop->current.guest_syscall_number = syscall_number;
            stop->current.flags |=
                    tracer::kLogicalPtraceEventFlagSyscallNumberValid;
        }
    } else {
        return EINVAL;
    }
    if (error == 0) {
        ++dispatcher->mutation_generation;
    }
    return error;
}

int HandlePeekUser(const LogicalPtraceDispatchIo& io,
                   const tracer::LogicalTaskKey& caller, uint64_t offset,
                   uint64_t output_address,
                   const LogicalPtraceDispatchStop& stop) noexcept {
    if ((stop.current.flags &
         tracer::kLogicalPtraceEventFlagRegistersValid) == 0U ||
        (offset & (sizeof(uint64_t) - 1U)) != 0U ||
        offset > sizeof(stop.current.guest_registers) - sizeof(uint64_t)) {
        return EIO;
    }
    uint64_t value = 0;
    const auto* bytes = reinterpret_cast<const uint8_t*>(
            &stop.current.guest_registers);
    memcpy(&value, bytes + static_cast<size_t>(offset), sizeof(value));
    return WriteMemory(io, caller, static_cast<uintptr_t>(output_address),
                       &value, sizeof(value));
}

int HandleGetSyscallInfo(const LogicalPtraceDispatchIo& io,
                         const tracer::LogicalTaskKey& caller,
                         uint64_t output_capacity, uint64_t output_address,
                         const LogicalPtraceDispatchStop& stop,
                         int64_t* visible_result) noexcept {
    struct ptrace_syscall_info info {};
    size_t info_size = offsetof(struct ptrace_syscall_info, entry);
    const bool registers_valid =
            (stop.current.flags &
             tracer::kLogicalPtraceEventFlagRegistersValid) != 0U;
    const bool syscall_number_valid =
            (stop.current.flags &
             tracer::kLogicalPtraceEventFlagSyscallNumberValid) != 0U;
    if (registers_valid) {
        info.arch = AUDIT_ARCH_AARCH64;
        info.instruction_pointer = stop.current.guest_registers.pc;
        info.stack_pointer = stop.current.guest_registers.sp;
    }
    if (stop.current.kind ==
        tracer::LogicalPtraceEventKind::kSyscallEntry) {
        if (!registers_valid || !syscall_number_valid) {
            return EIO;
        }
        info.op = PTRACE_SYSCALL_INFO_ENTRY;
        info.entry.nr = static_cast<uint64_t>(
                static_cast<int64_t>(stop.current.guest_syscall_number));
        for (size_t index = 0; index < 6U; ++index) {
            info.entry.args[index] =
                    stop.current.guest_registers.regs[index];
        }
        info_size = offsetof(struct ptrace_syscall_info, entry) +
                    sizeof(info.entry);
    } else if (stop.current.kind ==
               tracer::LogicalPtraceEventKind::kSyscallExit) {
        if (!registers_valid) {
            return EIO;
        }
        info.op = PTRACE_SYSCALL_INFO_EXIT;
        info.exit.rval = static_cast<int64_t>(
                stop.current.guest_registers.regs[0]);
        info.exit.is_error = info.exit.rval < 0 && info.exit.rval >= -4095
                ? 1U
                : 0U;
        info_size = offsetof(struct ptrace_syscall_info, exit) +
                    sizeof(info.exit);
    } else if (stop.current.kind ==
                       tracer::LogicalPtraceEventKind::kPtraceEvent &&
               stop.current.ptrace_event == PTRACE_EVENT_SECCOMP) {
        if (!registers_valid || !syscall_number_valid) {
            return EIO;
        }
        info.op = PTRACE_SYSCALL_INFO_SECCOMP;
        info.seccomp.nr = static_cast<uint64_t>(
                static_cast<int64_t>(stop.current.guest_syscall_number));
        for (size_t index = 0; index < 6U; ++index) {
            info.seccomp.args[index] =
                    stop.current.guest_registers.regs[index];
        }
        info.seccomp.ret_data = static_cast<uint32_t>(
                stop.current.event_message);
        info_size = offsetof(struct ptrace_syscall_info, seccomp) +
                    sizeof(info.seccomp);
    } else {
        info.op = PTRACE_SYSCALL_INFO_NONE;
    }

    const size_t capacity = static_cast<size_t>(output_capacity);
    const size_t copy_size = capacity < info_size ? capacity : info_size;
    if (copy_size != 0U) {
        const int error = WriteMemory(
                io, caller, static_cast<uintptr_t>(output_address), &info,
                copy_size);
        if (error != 0) {
            return error;
        }
    }
    *visible_result = static_cast<int64_t>(info_size);
    return 0;
}

int HandlePokeUser(LogicalPtraceDispatcher* dispatcher,
                   tracer::LogicalPtraceTable* logical, uint64_t offset,
                   uint64_t value, tracer::LogicalPtraceRelation& relation,
                   LogicalPtraceDispatchStop* stop) noexcept {
    if ((stop->current.flags &
         tracer::kLogicalPtraceEventFlagRegistersValid) == 0U ||
        (offset & (sizeof(uint64_t) - 1U)) != 0U ||
        offset > sizeof(stop->current.guest_registers) - sizeof(uint64_t)) {
        return EIO;
    }
    hookself::arch::Arm64Regs registers = stop->current.guest_registers;
    auto* bytes = reinterpret_cast<uint8_t*>(&registers);
    memcpy(bytes + static_cast<size_t>(offset), &value, sizeof(value));
    const int error = UpdateQueuedRegisters(
            logical, relation, registers,
            (stop->current.flags &
             tracer::kLogicalPtraceEventFlagSyscallNumberValid) != 0U,
            stop->current.guest_syscall_number);
    if (error == 0) {
        stop->current.guest_registers = registers;
        ++dispatcher->mutation_generation;
    }
    return error;
}

int HandleResume(LogicalPtraceDispatcher* dispatcher,
                 tracer::LogicalPtraceTable* logical,
                 const tracer::LogicalTaskKey& target, uint64_t request,
                 uint64_t raw_signal, tracer::LogicalPtraceRelation& relation,
                 LogicalPtraceDispatchStop* stop,
                 LogicalPtraceTargetRequest* target_request) noexcept {
    if (request != PTRACE_KILL &&
        raw_signal >= static_cast<uint64_t>(NSIG)) {
        return EIO;
    }
    const int32_t signal_number = request == PTRACE_KILL
            ? SIGKILL
            : static_cast<int32_t>(raw_signal);
    const uint32_t relation_slot = relation.slot;
    if (request == PTRACE_LISTEN &&
        (raw_signal != 0 ||
         relation.attach_kind != tracer::LogicalPtraceAttachKind::kSeize ||
         stop->current.kind != tracer::LogicalPtraceEventKind::kGroupStop)) {
        return EIO;
    }
    if (relation.event_count != 0U) {
        if (relation.event_count != 1U ||
            relation.events[relation.event_head].sequence !=
                    stop->current.sequence) {
            return EBUSY;
        }
        tracer::LogicalPtraceEvent discarded {};
        const int consume_error = tracer::ConsumeLogicalPtraceEvent(
                logical, target, false, &discarded);
        if (consume_error != 0) {
            return consume_error;
        }
    }
    int error = 0;
    if (request == PTRACE_DETACH) {
        FillTargetFromStop(LogicalPtraceTargetAction::kDetach, target,
                           signal_number, stop, target_request);
        error = tracer::EraseLogicalPtraceRelation(logical, target, false);
    } else if (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
               request == PTRACE_SINGLESTEP || request == PTRACE_KILL) {
        const tracer::LogicalPtraceResumeMode mode =
                request == PTRACE_SYSCALL
                        ? tracer::LogicalPtraceResumeMode::kSyscall
                : request == PTRACE_SINGLESTEP
                        ? tracer::LogicalPtraceResumeMode::kSingleStep
                        : tracer::LogicalPtraceResumeMode::kCont;
        const LogicalPtraceTargetAction action =
                request == PTRACE_SYSCALL
                        ? LogicalPtraceTargetAction::kResumeSyscall
                        : request == PTRACE_SINGLESTEP
                                  ? LogicalPtraceTargetAction::
                                            kResumeSingleStep
                                  : LogicalPtraceTargetAction::kResumeCont;
        FillTargetFromStop(
                action, target, signal_number, stop, target_request);
        error = tracer::ResumeLogicalPtraceRelation(logical, target, mode);
    } else if (request == PTRACE_LISTEN) {
        FillTargetFromStop(LogicalPtraceTargetAction::kListen, target, 0,
                           stop, target_request);
        error = tracer::ListenLogicalPtraceRelation(logical, target);
    } else {
        return EINVAL;
    }
    if (error == 0) {
        ForgetStop(dispatcher, relation_slot);
    }
    return error;
}

int HandleStoppedRequest(LogicalPtraceDispatcher* dispatcher,
                         tracer::LogicalPtraceTable* logical,
                         const LogicalPtraceDispatchIo& io,
                         const tracer::LogicalTaskKey& caller,
                         const tracer::LogicalTaskKey& target,
                         uint64_t request, uint64_t address, uint64_t data,
                         tracer::LogicalPtraceRelation& relation,
                         PtraceOutcome* outcome) noexcept {
    LogicalPtraceDispatchStop* stop = nullptr;
    int error = GetDeliveredStop(dispatcher, relation, &stop);
    if (error != 0) {
        outcome->result = -error;
        return 0;
    }

    if (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
        request == PTRACE_SINGLESTEP || request == PTRACE_KILL ||
        request == PTRACE_DETACH || request == PTRACE_LISTEN) {
        error = HandleResume(dispatcher, logical, target, request, data,
                             relation, stop, &outcome->target);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_SETOPTIONS) {
        error = tracer::SetLogicalPtraceOptions(logical, target, data);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_GETEVENTMSG) {
        if (stop->current.kind != tracer::LogicalPtraceEventKind::kPtraceEvent) {
            outcome->result = -EINVAL;
            return 0;
        }
        error = WriteMemory(io, caller, static_cast<uintptr_t>(data),
                            &stop->current.event_message,
                            sizeof(stop->current.event_message));
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_GETSIGINFO) {
        if ((stop->current.flags &
             tracer::kLogicalPtraceEventFlagSiginfoValid) == 0U) {
            outcome->result = -EINVAL;
            return 0;
        }
        error = WriteMemory(io, caller, static_cast<uintptr_t>(data),
                            &stop->current.signal_info,
                            sizeof(stop->current.signal_info));
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_SETSIGINFO) {
        if (stop->current.kind !=
            tracer::LogicalPtraceEventKind::kSignalDelivery) {
            outcome->result = -EINVAL;
            return 0;
        }
        siginfo_t signal_info {};
        error = ReadMemory(io, caller, static_cast<uintptr_t>(data),
                           &signal_info, sizeof(signal_info));
        if (error == 0) {
            error = UpdateQueuedSiginfo(logical, relation, signal_info);
        }
        if (error == 0) {
            stop->current.signal_info = signal_info;
            stop->current.flags |=
                    tracer::kLogicalPtraceEventFlagSiginfoValid;
            ++dispatcher->mutation_generation;
        }
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_GETREGSET) {
        error = HandleGetRegset(io, caller, address, data, *stop);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_SETREGSET) {
        error = HandleSetRegset(dispatcher, logical, io, caller, address,
                                data, relation, stop);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_PEEKTEXT || request == PTRACE_PEEKDATA) {
        uint64_t value = 0;
        error = ReadMemory(io, target, static_cast<uintptr_t>(address),
                           &value, sizeof(value));
        if (error == 0) {
            error = WriteMemory(io, caller, static_cast<uintptr_t>(data),
                                &value, sizeof(value));
        }
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        error = WriteMemory(io, target, static_cast<uintptr_t>(address),
                            &data, sizeof(data));
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_PEEKUSR) {
        error = HandlePeekUser(io, caller, address, data, *stop);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_POKEUSR) {
        error = HandlePokeUser(dispatcher, logical, address, data, relation,
                               stop);
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }
    if (request == PTRACE_GET_SYSCALL_INFO) {
        error = HandleGetSyscallInfo(io, caller, address, data, *stop,
                                     &outcome->result);
        if (error != 0) {
            outcome->result = -error;
        }
        return 0;
    }
    outcome->result = -EIO;
    return 0;
}

int HandlePtraceEntry(LogicalPtraceDispatcher* dispatcher,
                      tracer::LogicalPtraceTable* logical,
                      const LogicalPtraceDispatchIo& io,
                      const tracer::LogicalTaskKey& caller,
                      const uint64_t arguments[6],
                      PtraceOutcome* outcome) noexcept {
    *outcome = {};
    const uint64_t request = arguments[0];
    if (request == PTRACE_TRACEME) {
        tracer::LogicalTaskKey parent {};
        int error = ResolveParent(io, caller, &parent);
        if (error == ESRCH || error == ENOENT || error == ENOSYS) {
            outcome->handled = true;
            if (dispatcher->operation_count ==
                kLogicalPtraceDispatchCapacity) {
                return ENOSPC;
            }
            error = tracer::ClaimLogicalFakeTraceme(logical, caller);
            outcome->result = error == 0 ? 0 : -error;
            return 0;
        }
        outcome->handled = true;
        if (dispatcher->operation_count ==
            kLogicalPtraceDispatchCapacity) {
            return ENOSPC;
        }
        if (error == 0) {
            error = CheckAttachPermission(
                    io, parent, caller,
                    tracer::LogicalPtraceAttachKind::kTraceme);
        }
        if (error == 0) {
            error = tracer::CreateLogicalPtraceRelation(
                    logical, caller, parent,
                    tracer::LogicalPtraceAttachKind::kTraceme,
                    tracer::LogicalPtraceWaitClass::kNormal, 0, nullptr);
        }
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }

    if (arguments[1] == 0 || arguments[1] > INT32_MAX) {
        if (dispatcher->operation_count ==
            kLogicalPtraceDispatchCapacity) {
            return ENOSPC;
        }
        outcome->handled = true;
        outcome->result = -ESRCH;
        return 0;
    }
    tracer::LogicalTaskKey target {};
    int error = ResolveTask(io, caller, static_cast<int32_t>(arguments[1]),
                            &target);
    if (error == ESRCH || error == ENOENT || error == ENOSYS) {
        return 0;
    }
    outcome->handled = true;
    if (dispatcher->operation_count == kLogicalPtraceDispatchCapacity) {
        return ENOSPC;
    }
    if (error != 0) {
        outcome->result = -error;
        return 0;
    }

    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        const tracer::LogicalPtraceAttachKind kind =
                request == PTRACE_ATTACH
                        ? tracer::LogicalPtraceAttachKind::kAttach
                        : tracer::LogicalPtraceAttachKind::kSeize;
        if (request == PTRACE_SEIZE && arguments[2] != 0U) {
            outcome->result = -EIO;
            return 0;
        }
        error = CheckAttachPermission(io, caller, target, kind);
        if (error == 0) {
            error = tracer::CreateLogicalPtraceRelation(
                    logical, target, caller, kind,
                    tracer::LogicalPtraceWaitClass::kNormal,
                    request == PTRACE_SEIZE ? arguments[3] : 0, nullptr);
        }
        if (error == 0) {
            const tracer::LogicalPtraceRelation* relation =
                    tracer::FindLogicalPtraceRelation(logical, target);
            LogicalPtraceDispatchStop* stop = relation == nullptr
                    ? nullptr
                    : EnsureStopRecord(dispatcher, *relation);
            if (stop == nullptr) {
                (void)tracer::EraseLogicalPtraceRelation(logical, target,
                                                         true);
                return EPROTO;
            }
            if (request == PTRACE_ATTACH) {
                stop->flags |= kLogicalPtraceStopAttachPending;
                FillTargetFromStop(LogicalPtraceTargetAction::kInterrupt,
                                   target, 0, nullptr, &outcome->target);
                ++dispatcher->mutation_generation;
            }
        }
        outcome->result = error == 0 ? 0 : -error;
        return 0;
    }

    tracer::LogicalPtraceRelation* relation = nullptr;
    error = FindOwnedRelation(logical, caller, target, &relation);
    if (error != 0) {
        outcome->result = -error;
        return 0;
    }
    if (request == PTRACE_INTERRUPT) {
        LogicalPtraceDispatchStop* stop = EnsureStopRecord(dispatcher,
                                                            *relation);
        if (arguments[2] != 0U || arguments[3] != 0U ||
            relation->attach_kind != tracer::LogicalPtraceAttachKind::kSeize ||
            relation->state == tracer::LogicalPtraceRelationState::kStopped ||
            relation->state == tracer::LogicalPtraceRelationState::kExitZombie ||
            stop == nullptr ||
            (stop->flags & (kLogicalPtraceStopInterruptPending |
                            kLogicalPtraceStopCurrentValid)) != 0U) {
            outcome->result = -EIO;
            return 0;
        }
        stop->flags |= kLogicalPtraceStopInterruptPending;
        FillTargetFromStop(LogicalPtraceTargetAction::kInterrupt, target, 0,
                           nullptr, &outcome->target);
        ++dispatcher->mutation_generation;
        outcome->result = 0;
        return 0;
    }
    return HandleStoppedRequest(dispatcher, logical, io, caller, target,
                                request, arguments[2], arguments[3],
                                *relation, outcome);
}

int MapWaitIdType(uint64_t raw, tracer::LogicalWaitIdType* type) noexcept {
    switch (raw) {
        case 0:
            *type = tracer::LogicalWaitIdType::kAll;
            return 0;
        case 1:
            *type = tracer::LogicalWaitIdType::kPid;
            return 0;
        case 2:
            *type = tracer::LogicalWaitIdType::kProcessGroup;
            return 0;
        case 3:
            *type = tracer::LogicalWaitIdType::kPidFd;
            return 0;
        default:
            return EINVAL;
    }
}

int BuildWaitRequest(const tracer::LogicalPtraceTable* logical,
                     const tracer::LogicalTaskKey& caller,
                     int32_t syscall_number, const uint64_t arguments[6],
                     tracer::LogicalWaitRequest* request) noexcept {
    const tracer::LogicalProcessRecord* process = tracer::FindLogicalProcess(
            logical, tracer::LogicalProcessKeyForTask(caller));
    if (process == nullptr) {
        return ESRCH;
    }
    if (syscall_number == __NR_wait4) {
        return tracer::BuildLogicalWait4Request(
                caller, static_cast<int32_t>(arguments[0]),
                process->process_group, static_cast<uint32_t>(arguments[2]),
                arguments[1], arguments[3], 0, request);
    }
    tracer::LogicalWaitIdType type {};
    int error = MapWaitIdType(arguments[0], &type);
    if (error != 0) {
        return error;
    }
    return tracer::BuildLogicalWaitIdRequest(
            caller, type, arguments[1], process->process_group,
            static_cast<uint32_t>(arguments[3]), arguments[2], arguments[4],
            0, request);
}

int HandleWaitEntry(LogicalPtraceDispatcher* dispatcher,
                    tracer::LogicalPtraceTable* logical,
                    const LogicalPtraceDispatchIo& io,
                    const tracer::LogicalTaskKey& caller,
                    int32_t syscall_number, const uint64_t arguments[6],
                    LogicalPtraceEntryResult* result) noexcept {
    tracer::LogicalWaitRequest request {};
    int error = BuildWaitRequest(logical, caller, syscall_number, arguments,
                                 &request);
    if (error != 0) {
        return 0;
    }
    error = tracer::BeginLogicalWait(logical, request, nullptr);
    if (error != 0) {
        return error;
    }
    tracer::LogicalWaitMatch match {};
    const int select_error = tracer::SelectLogicalWaitEvent(
            logical, caller, &match);
    if ((select_error == 0 || select_error == EAGAIN) &&
        dispatcher->operation_count == kLogicalPtraceDispatchCapacity) {
        (void)tracer::EndLogicalWait(logical, caller);
        return ENOSPC;
    }
    int64_t visible_result = 0;
    LogicalPtraceOperationState state =
            LogicalPtraceOperationState::kImmediate;
    if (select_error == 0) {
        error = CompleteSelectedWait(dispatcher, logical, io, caller, match,
                                     &visible_result);
        if (error != 0) {
            return error;
        }
    } else if (select_error == EAGAIN && request.nohang != 0U) {
        const int output_error = ZeroNoHangWaitId(io, request);
        (void)tracer::EndLogicalWait(logical, caller);
        visible_result = output_error == 0 ? 0 : -output_error;
    } else if (select_error == EAGAIN) {
        state = LogicalPtraceOperationState::kHeldWait;
    } else if (select_error == ECHILD) {
        (void)tracer::EndLogicalWait(logical, caller);
        return 0;
    } else {
        (void)tracer::EndLogicalWait(logical, caller);
        return select_error;
    }
    uint32_t operation_slot = kLogicalPtraceDispatchInvalidSlot;
    error = InsertOperation(dispatcher, caller, syscall_number, state,
                            visible_result, &operation_slot);
    if (error != 0) {
        if (state == LogicalPtraceOperationState::kHeldWait) {
            (void)tracer::EndLogicalWait(logical, caller);
        }
        return error;
    }
    result->flags = kLogicalPtraceEntryHandled |
                    kLogicalPtraceEntrySuppress;
    if (state == LogicalPtraceOperationState::kHeldWait) {
        result->flags |= kLogicalPtraceEntryMayHold;
    }
    result->operation_slot = operation_slot;
    result->visible_result = visible_result;
    result->syscall_number = syscall_number;
    return 0;
}

}  // namespace

}  // namespace hookself::internal
