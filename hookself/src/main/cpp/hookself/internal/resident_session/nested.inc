bool NestedPtraceEnabled(const TracerContext* context) noexcept {
    return context != nullptr && context->nested_ptrace_phase1 &&
           context->logical_ptrace != nullptr &&
           context->logical_ptrace_rollback != nullptr &&
           IsLogicalPtraceResidentStateInitialized(context->logical_ptrace);
}

const LogicalPtraceResidentTask* FindNestedPtraceTask(
        const TracerContext* context, const TaskRecord* task) noexcept {
    if (!NestedPtraceEnabled(context) || task == nullptr) {
        return nullptr;
    }
    const LogicalPtraceResidentTask* logical =
            FindLogicalPtraceResidentTid(context->logical_ptrace, task->tid);
    return logical != nullptr && logical->key.tgid == task->tgid
           ? logical
           : nullptr;
}

int ResolveNestedPtracePhysicalTask(
        TracerContext* context, const hookself::tracer::LogicalTaskKey& key,
        TaskRecord** output) noexcept {
    if (output == nullptr || !NestedPtraceEnabled(context)) {
        return EINVAL;
    }
    *output = nullptr;
    const LogicalPtraceResidentTask* logical =
            FindLogicalPtraceResidentTask(context->logical_ptrace, key);
    if (logical == nullptr ||
        (logical->flags & kLogicalPtraceResidentTaskActive) == 0U) {
        return ESRCH;
    }
    TaskRecord* physical = hookself::tracer::Find(context->tasks, key.tid);
    if (physical == nullptr || physical->tgid != key.tgid) {
        return ESRCH;
    }
    *output = physical;
    return 0;
}

int NestedPtraceMayAttach(
        void* opaque, const hookself::tracer::LogicalTaskKey* caller,
        const hookself::tracer::LogicalTaskKey* target,
        hookself::tracer::LogicalPtraceAttachKind kind) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (!NestedPtraceEnabled(context) || caller == nullptr ||
        target == nullptr ||
        kind != hookself::tracer::LogicalPtraceAttachKind::kTraceme ||
        caller->tgid != context->target_pid ||
        target->tgid == context->target_pid || target->tid != target->tgid) {
        return EPERM;
    }
    const LogicalPtraceResidentTask* child =
            FindLogicalPtraceResidentTask(context->logical_ptrace, *target);
    return child != nullptr &&
                   (child->flags &
                    kLogicalPtraceResidentTaskParentValid) != 0U &&
                   hookself::tracer::LogicalTaskKeysEqual(child->parent,
                                                           *caller)
           ? 0
           : EPERM;
}

int NestedPtraceReadMemory(
        void* opaque, const hookself::tracer::LogicalTaskKey* key,
        uintptr_t address, void* output, size_t size) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (key == nullptr || (size != 0U && (address == 0 || output == nullptr))) {
        return EFAULT;
    }
    if (size == 0U) {
        return 0;
    }
    TaskRecord* task = nullptr;
    const int resolve_error = ResolveNestedPtracePhysicalTask(
            context, *key, &task);
    return resolve_error != 0
           ? resolve_error
           : ReadRemoteBytes(task->tgid, task->tid, address, output, size);
}

int NestedPtraceWriteMemory(
        void* opaque, const hookself::tracer::LogicalTaskKey* key,
        uintptr_t address, const void* input, size_t size) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (key == nullptr || (size != 0U && (address == 0 || input == nullptr))) {
        return EFAULT;
    }
    if (size == 0U) {
        return 0;
    }
    TaskRecord* task = nullptr;
    const int resolve_error = ResolveNestedPtracePhysicalTask(
            context, *key, &task);
    return resolve_error != 0
           ? resolve_error
           : WriteRemoteBytes(task->tgid, task->tid, address, input, size);
}

int NestedPtraceQueryUid(void* opaque,
                         const hookself::tracer::LogicalTaskKey*,
                         uint32_t* uid) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (!NestedPtraceEnabled(context) || uid == nullptr) {
        return EINVAL;
    }
    const long result = RawSyscall6(__NR_getuid);
    if (RawError(result) != 0 || result < 0 || result > UINT32_MAX) {
        return RawError(result) != 0 ? RawError(result) : EIO;
    }
    *uid = static_cast<uint32_t>(result);
    return 0;
}

int NestedPtraceFillRusage(void* opaque,
                           const hookself::tracer::LogicalTaskKey*,
                           const hookself::tracer::LogicalPtraceEvent*,
                           void* output, size_t size) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (!NestedPtraceEnabled(context) || output == nullptr) {
        return EINVAL;
    }
    memset(output, 0, size);
    return 0;
}

uint64_t NextNestedPtraceSequence(uint64_t* sequence) noexcept {
    if (sequence == nullptr) {
        return 0;
    }
    ++*sequence;
    if (*sequence == 0U) {
        ++*sequence;
    }
    return *sequence;
}

uint64_t FindNestedPtraceProcessGeneration(
        const LogicalPtraceResidentState* state, pid_t tgid) noexcept {
    if (state == nullptr || tgid <= 0) {
        return 0;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        const LogicalPtraceResidentTask* task =
                LogicalPtraceResidentTaskAt(state, slot);
        if (task != nullptr &&
            (task->flags & kLogicalPtraceResidentTaskActive) != 0U &&
            task->key.tgid == tgid) {
            return task->key.process_generation;
        }
    }
    return 0;
}

uint32_t FindFreeNestedPtraceResidentSlot(
        const LogicalPtraceResidentState* state) noexcept {
    if (state == nullptr) {
        return kLogicalPtraceResidentCapacity;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        if (state->tasks[slot].occupied == 0U) {
            return slot;
        }
    }
    return kLogicalPtraceResidentCapacity;
}

int RegisterNestedPtraceTask(TracerContext* context, TaskRecord* task,
                             const TaskRecord* parent) noexcept {
    if (!NestedPtraceEnabled(context) || task == nullptr || task->tid <= 0 ||
        task->tgid <= 0) {
        return NestedPtraceEnabled(context) ? EINVAL : 0;
    }
    if (FindNestedPtraceTask(context, task) != nullptr) {
        return 0;
    }
    const uint32_t slot = FindFreeNestedPtraceResidentSlot(
            context->logical_ptrace);
    if (slot == kLogicalPtraceResidentCapacity) {
        return ENOSPC;
    }

    const LogicalPtraceResidentTask* parent_logical =
            FindNestedPtraceTask(context, parent);
    uint64_t process_generation = FindNestedPtraceProcessGeneration(
            context->logical_ptrace, task->tgid);
    if (process_generation == 0U && parent_logical != nullptr &&
        parent_logical->key.tgid == task->tgid) {
        process_generation = parent_logical->key.process_generation;
    }
    if (process_generation == 0U) {
        process_generation = NextNestedPtraceSequence(
                &context->next_logical_process_generation);
    }
    const uint64_t task_generation = NextNestedPtraceSequence(
            &context->next_logical_task_generation);
    if (task_generation == 0U || process_generation == 0U) {
        return EOVERFLOW;
    }

    hookself::tracer::LogicalTaskKey key{};
    key.tid = task->tid;
    key.tgid = task->tgid;
    key.generation = task_generation;
    key.process_generation = process_generation;
    hookself::tracer::LogicalTaskKey parent_key{};
    const hookself::tracer::LogicalTaskKey* parent_pointer = nullptr;
    if (parent_logical != nullptr) {
        parent_key = parent_logical->key;
        parent_pointer = &parent_key;
    }

    const long raw_group = RawSyscall6(__NR_getpgid, task->tgid);
    const int32_t process_group = RawError(raw_group) == 0 && raw_group > 0 &&
                                           raw_group <= INT32_MAX
            ? static_cast<int32_t>(raw_group)
            : task->tgid;
    int32_t dumpable = __atomic_load_n(&context->control->ptrace_view_dumpable,
                                       __ATOMIC_ACQUIRE);
    if (dumpable < 0 || dumpable > 2) {
        dumpable = 1;
    }
    hookself::tracer::LogicalPidIdentity ptracer{};
    return RegisterLogicalPtraceResidentTask(
            context->logical_ptrace, slot, key, parent_pointer, process_group,
            dumpable, ptracer);
}

int RetireNestedPtraceTask(TracerContext* context,
                           const TaskRecord* task) noexcept {
    const LogicalPtraceResidentTask* logical =
            FindNestedPtraceTask(context, task);
    if (logical == nullptr) {
        return 0;
    }
    const hookself::tracer::LogicalTaskKey key = logical->key;
    const int mark_error = MarkLogicalPtraceResidentTaskExited(
            context->logical_ptrace, key);
    if (mark_error != 0 && mark_error != ESRCH) {
        return mark_error;
    }
    const int retire_error = RetireLogicalPtraceResidentTask(
            context->logical_ptrace, key);
    if (retire_error != 0 && retire_error != EBUSY &&
        retire_error != ESRCH) {
        return retire_error;
    }
    return CollectNestedPtraceRetiredTasks(context);
}

int CollectNestedPtraceRetiredTasks(TracerContext* context) noexcept {
    if (!NestedPtraceEnabled(context)) {
        return 0;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceResidentCapacity; ++slot) {
        const LogicalPtraceResidentTask* task =
                LogicalPtraceResidentTaskAt(context->logical_ptrace, slot);
        if (task == nullptr ||
            (task->flags & kLogicalPtraceResidentTaskExited) == 0U) {
            continue;
        }
        const hookself::tracer::LogicalTaskKey key = task->key;
        const int retire_error = RetireLogicalPtraceResidentTask(
                context->logical_ptrace, key);
        if (retire_error != 0 && retire_error != EBUSY &&
            retire_error != ESRCH) {
            return retire_error;
        }
    }
    (void)CollectLogicalPtraceResidentProcesses(context->logical_ptrace);
    return 0;
}

int MergeNestedPtraceExecTask(TracerContext* context,
                               const TaskRecord* former,
                               const TaskRecord* destination) noexcept {
    if (!NestedPtraceEnabled(context) || former == nullptr ||
        destination == nullptr) {
        return NestedPtraceEnabled(context) ? EINVAL : 0;
    }
    const LogicalPtraceResidentTask* former_logical =
            FindNestedPtraceTask(context, former);
    const LogicalPtraceResidentTask* destination_logical =
            FindNestedPtraceTask(context, destination);
    if (former_logical == nullptr || destination_logical == nullptr) {
        return EPROTO;
    }
    return MergeExecLogicalPtraceResidentTask(
            context->logical_ptrace, former_logical->key,
            destination_logical->key);
}

NestedPtracePhysicalHold* FindNestedPtracePhysicalHold(
        TracerContext* context,
        const hookself::tracer::LogicalTaskKey& tracee) noexcept {
    if (!NestedPtraceEnabled(context)) {
        return nullptr;
    }
    for (uint32_t slot = 0;
         slot < hookself::tracer::kLogicalPtraceRelationCapacity; ++slot) {
        NestedPtracePhysicalHold* hold = &context->nested_ptrace_holds[slot];
        if (hold->occupied != 0U &&
            hookself::tracer::LogicalTaskKeysEqual(hold->tracee, tracee)) {
            return hold;
        }
    }
    return nullptr;
}

void ClearNestedPtracePhysicalHold(NestedPtracePhysicalHold* hold) noexcept {
    if (hold != nullptr) {
        memset(hold, 0, sizeof(*hold));
    }
}

int DiscardLostNestedPtraceTracee(
        TracerContext* context,
        const hookself::tracer::LogicalTaskKey& tracee) noexcept {
    if (!NestedPtraceEnabled(context)) {
        return EINVAL;
    }
    const int relation_error = hookself::tracer::EraseLogicalPtraceRelation(
            &context->logical_ptrace->logical, tracee, true);
    if (relation_error != 0 && relation_error != ESRCH) {
        return relation_error;
    }
    const int mark_error = MarkLogicalPtraceResidentTaskExited(
            context->logical_ptrace, tracee);
    if (mark_error != 0 && mark_error != ESRCH) {
        return mark_error;
    }
    const int retire_error = RetireLogicalPtraceResidentTask(
            context->logical_ptrace, tracee);
    if (retire_error != 0 && retire_error != ESRCH) {
        return retire_error;
    }
    return CollectNestedPtraceRetiredTasks(context);
}

int ResumeNestedPtraceTracee(TracerContext* context,
                              const LogicalPtraceTargetRequest& request,
                              bool* tracee_lost) noexcept {
    if (tracee_lost != nullptr) {
        *tracee_lost = false;
    }
    if (request.action != LogicalPtraceTargetAction::kResumeCont &&
        request.action != LogicalPtraceTargetAction::kDetach) {
        return EOPNOTSUPP;
    }
    NestedPtracePhysicalHold* hold = FindNestedPtracePhysicalHold(
            context, request.target);
    if (hold == nullptr) {
        return ESRCH;
    }
    TaskRecord* task = nullptr;
    const int resolve_error = ResolveNestedPtracePhysicalTask(
            context, request.target, &task);
    if (resolve_error != 0 || task->tid != hold->physical_tid ||
        task->stop_sequence != hold->physical_stop_sequence ||
        (task->flags & hookself::tracer::kTaskFlagNestedPtraceTraceeHold) ==
                0U) {
        return resolve_error != 0 ? resolve_error : ESTALE;
    }
    const pid_t physical_tid = task->tid;
    const pid_t physical_tgid = task->tgid;
    const bool exec_reinit_pending =
            task->life == TaskLifeState::kExecReinit;
    task->pending_signal = request.signal_number;
    const int resume_error = ResumeTask(context, task);
    if (resume_error != 0) {
        return resume_error;
    }
    // ResumeTask owns generic ESRCH cleanup and removes the table record. Do
    // not dereference the stale pointer in that path; make the logical result
    // match the missing physical tracee and discard its orphaned relation.
    TaskRecord* resumed = hookself::tracer::Find(context->tasks, physical_tid);
    if (resumed == nullptr || resumed->tgid != physical_tgid) {
        ClearNestedPtracePhysicalHold(hold);
        if (tracee_lost != nullptr) {
            *tracee_lost = true;
        }
        const int discard_error = DiscardLostNestedPtraceTracee(
                context, request.target);
        return discard_error != 0 ? discard_error : ESRCH;
    }
    if (exec_reinit_pending) {
        resumed->flags |=
                hookself::tracer::kTaskFlagNestedPtraceExecReinitPending;
    }
    resumed->flags &= ~hookself::tracer::kTaskFlagNestedPtraceTraceeHold;
    ClearNestedPtracePhysicalHold(hold);
    return 0;
}

bool NestedPtraceTracemeCandidate(const TracerContext* context,
                                  const TaskRecord* task) noexcept {
    const LogicalPtraceResidentTask* logical =
            FindNestedPtraceTask(context, task);
    return logical != nullptr && task->tid == task->tgid &&
           task->tgid != context->target_pid &&
           (logical->flags & kLogicalPtraceResidentTaskParentValid) != 0U &&
           logical->parent.tgid == context->target_pid;
}

int ApplyNestedPtraceEntry(TracerContext* context, TaskRecord* task,
                            bool* handled) noexcept {
    if (handled == nullptr) {
        return EINVAL;
    }
    *handled = false;
    if (!NestedPtraceEnabled(context) || task == nullptr ||
        context->selective_mode || context->quiescing) {
        return 0;
    }
    const int32_t syscall_number = task->active_syscall.syscall_number;
    const uint64_t* arguments = task->active_syscall.arguments;
    if (syscall_number != __NR_ptrace && syscall_number != __NR_wait4 &&
        syscall_number != __NR_waitid) {
        return 0;
    }
    if ((syscall_number == __NR_wait4 || syscall_number == __NR_waitid) &&
        task->tgid != context->target_pid) {
        return 0;
    }
    if (syscall_number == __NR_ptrace) {
        const uint64_t request = arguments[0];
        if (request == PTRACE_TRACEME) {
            if (!NestedPtraceTracemeCandidate(context, task)) {
                return 0;
            }
        } else if (task->tgid != context->target_pid) {
            return 0;
        } else {
            const bool phase1_setoptions =
                    request == PTRACE_SETOPTIONS &&
                    (arguments[3] &
                     ~static_cast<uint64_t>(PTRACE_O_TRACEEXEC)) == 0U;
            const bool supported_request =
                    request == PTRACE_GETEVENTMSG || request == PTRACE_CONT ||
                    request == PTRACE_DETACH || phase1_setoptions;
            if (!supported_request) {
                const LogicalPtraceResidentTask* target =
                        arguments[1] > 0 && arguments[1] <= INT32_MAX
                                ? FindLogicalPtraceResidentTid(
                                          context->logical_ptrace,
                                          static_cast<int32_t>(arguments[1]))
                                : nullptr;
                if (target == nullptr ||
                    hookself::tracer::FindLogicalPtraceRelation(
                            &context->logical_ptrace->logical, target->key) ==
                            nullptr) {
                    return 0;
                }
                const int suppress_error = SuppressSyscallWithHarmlessCall(task);
                if (suppress_error != 0) {
                    return suppress_error;
                }
                task->active_syscall.flags |=
                        hookself::tracer::kActiveSyscallReplaceResult;
                task->active_syscall.replacement_result = -EOPNOTSUPP;
                task->active_syscall.exit_policy_rule_id =
                        HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
                *handled = true;
                return 0;
            }
        }
    }

    const LogicalPtraceResidentTask* caller =
            FindNestedPtraceTask(context, task);
    if (caller == nullptr) {
        return 0;
    }
    memcpy(context->logical_ptrace_rollback, context->logical_ptrace,
           sizeof(*context->logical_ptrace));
    LogicalPtraceDispatchIo io = MakeLogicalPtraceResidentIo(
            &context->logical_ptrace_io_context);
    LogicalPtraceEntryResult entry{};
    const int dispatch_error = DispatchLogicalPtraceEntry(
            &context->logical_ptrace->dispatcher,
            &context->logical_ptrace->logical, io, caller->key,
            syscall_number, arguments, &entry);
    if (dispatch_error != 0) {
        memcpy(context->logical_ptrace, context->logical_ptrace_rollback,
               sizeof(*context->logical_ptrace));
        return dispatch_error;
    }
    if ((entry.flags & kLogicalPtraceEntryHandled) == 0U) {
        return 0;
    }
    const int suppress_error = SuppressSyscallWithHarmlessCall(task);
    if (suppress_error != 0) {
        memcpy(context->logical_ptrace, context->logical_ptrace_rollback,
               sizeof(*context->logical_ptrace));
        return suppress_error;
    }

    if ((entry.flags & kLogicalPtraceEntryTargetAction) != 0U) {
        bool tracee_lost = false;
        const int action_error = ResumeNestedPtraceTracee(
                context, entry.target, &tracee_lost);
        if (action_error != 0) {
            if (tracee_lost) {
                const int cancel_error = CancelLogicalPtraceDispatch(
                        &context->logical_ptrace->dispatcher,
                        &context->logical_ptrace->logical, caller->key);
                if (cancel_error != 0 && cancel_error != ESRCH) {
                    return cancel_error;
                }
            } else {
                memcpy(context->logical_ptrace, context->logical_ptrace_rollback,
                       sizeof(*context->logical_ptrace));
            }
            task->active_syscall.flags |=
                    hookself::tracer::kActiveSyscallReplaceResult;
            task->active_syscall.replacement_result = -action_error;
            task->active_syscall.exit_policy_rule_id =
                    HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
            *handled = true;
            return 0;
        }
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallNestedPtraceDispatch;
    task->active_syscall.nested_ptrace_operation_slot = entry.operation_slot;
    task->active_syscall.exit_policy_rule_id =
            HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
    EmitSyscallPolicyEvent(context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
                           HOOKSELF_SYSCALL_REPLACE_RESULT,
                           HOOKSELF_BUILTIN_RULE_NESTED_PTRACE, 0);
    *handled = true;
    return 0;
}

int StoreNestedPtraceWaitExitHold(TracerContext* context, TaskRecord* task,
                                  uint32_t operation_slot) noexcept {
    if (!NestedPtraceEnabled(context) || task == nullptr ||
        operation_slot >= kLogicalPtraceDispatchCapacity) {
        return EINVAL;
    }
    const LogicalPtraceResidentTask* logical =
            FindNestedPtraceTask(context, task);
    const LogicalPtraceDispatchOperation* operation =
            LogicalPtraceOperationAt(&context->logical_ptrace->dispatcher,
                                     operation_slot);
    if (logical == nullptr || operation == nullptr ||
        operation->state != LogicalPtraceOperationState::kHeldWait ||
        !hookself::tracer::LogicalTaskKeysEqual(operation->caller,
                                                logical->key)) {
        return ESTALE;
    }
    NestedPtraceWaitExitHold* hold =
            &context->nested_ptrace_wait_holds[operation_slot];
    if (hold->occupied != 0U) {
        return EBUSY;
    }
    hold->occupied = 1U;
    hold->operation_slot = operation_slot;
    hold->operation_generation = operation->generation;
    hold->waiter = logical->key;
    hold->physical_tid = task->tid;
    hold->physical_stop_sequence = task->stop_sequence;
    task->flags |= hookself::tracer::kTaskFlagNestedPtraceWaitExitHold;
    return 0;
}

int CompleteNestedPtraceExit(TracerContext* context, TaskRecord* task,
                              int64_t kernel_result,
                              bool* wait_exit_held) noexcept {
    if (wait_exit_held == nullptr) {
        return EINVAL;
    }
    *wait_exit_held = false;
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallNestedPtraceDispatch) == 0U) {
        return 0;
    }
    if (!NestedPtraceEnabled(context) ||
        task->active_syscall.nested_ptrace_operation_slot >=
                kLogicalPtraceDispatchCapacity) {
        return EPROTO;
    }
    const LogicalPtraceResidentTask* caller =
            FindNestedPtraceTask(context, task);
    if (caller == nullptr) {
        return ESTALE;
    }
    LogicalPtraceExitResult exit{};
    const int dispatch_error = DispatchLogicalPtraceExit(
            &context->logical_ptrace->dispatcher,
            &context->logical_ptrace->logical, caller->key,
            task->active_syscall.syscall_number, kernel_result, &exit);
    if (dispatch_error != 0 ||
        (exit.flags & kLogicalPtraceExitHandled) == 0U) {
        return dispatch_error != 0 ? dispatch_error : EPROTO;
    }
    if ((exit.flags & kLogicalPtraceExitHold) != 0U) {
        const int restore_error = RestoreEntryMutations(context, task, true);
        if (restore_error != 0) {
            return restore_error;
        }
        const int hold_error = StoreNestedPtraceWaitExitHold(
                context, task, exit.operation_slot);
        if (hold_error != 0) {
            return hold_error;
        }
        task->syscall_phase = TaskSyscallPhase::kExpectEntry;
        *wait_exit_held = true;
        return 0;
    }
    if ((exit.flags & kLogicalPtraceExitWriteResult) == 0U) {
        return EPROTO;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallReplaceResult;
    task->active_syscall.replacement_result = exit.visible_result;
    task->active_syscall.exit_policy_rule_id =
            HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
    return CollectNestedPtraceRetiredTasks(context);
}

int CompleteNestedPtraceHeldWait(TracerContext* context,
                                  NestedPtraceWaitExitHold* hold) noexcept {
    if (!NestedPtraceEnabled(context) || hold == nullptr ||
        hold->occupied == 0U ||
        hold->operation_slot >= kLogicalPtraceDispatchCapacity) {
        return EINVAL;
    }
    const LogicalPtraceDispatchOperation* operation =
            LogicalPtraceOperationAt(&context->logical_ptrace->dispatcher,
                                     hold->operation_slot);
    if (operation == nullptr || operation->generation != hold->operation_generation ||
        operation->state != LogicalPtraceOperationState::kHeldReady ||
        !hookself::tracer::LogicalTaskKeysEqual(operation->caller,
                                                hold->waiter)) {
        return ESTALE;
    }
    TaskRecord* task = nullptr;
    const int resolve_error = ResolveNestedPtracePhysicalTask(
            context, hold->waiter, &task);
    if (resolve_error != 0 || task->tid != hold->physical_tid ||
        task->stop_sequence != hold->physical_stop_sequence ||
        (task->flags &
         hookself::tracer::kTaskFlagNestedPtraceWaitExitHold) == 0U ||
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallNestedPtraceDispatch) == 0U ||
        task->active_syscall.nested_ptrace_operation_slot !=
                hold->operation_slot) {
        return resolve_error != 0 ? resolve_error : ESTALE;
    }
    LogicalPtraceExitResult exit{};
    const int dispatch_error = DispatchLogicalPtraceExit(
            &context->logical_ptrace->dispatcher,
            &context->logical_ptrace->logical, hold->waiter,
            operation->syscall_number, 0, &exit);
    if (dispatch_error != 0 ||
        (exit.flags & (kLogicalPtraceExitHandled |
                       kLogicalPtraceExitWriteResult)) !=
                (kLogicalPtraceExitHandled |
                 kLogicalPtraceExitWriteResult)) {
        return dispatch_error != 0 ? dispatch_error : EPROTO;
    }

    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallReplaceResult;
    task->active_syscall.replacement_result = exit.visible_result;
    task->active_syscall.exit_policy_rule_id =
            HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
    int64_t effective_result = 0;
    const int write_error = ApplyExitSyscallPolicy(
            context, task, 0, &effective_result);
    if (write_error != 0) {
        return write_error;
    }
    task->active_syscall.result = effective_result;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallResultValid;
    EmitSyscallEvent(context, task, task->active_syscall.syscall_number,
                     HOOKSELF_SYSCALL_PHASE_EXIT,
                     task->active_syscall.arguments, effective_result, 0);
    ClearPendingPath(context, task);
    hookself::tracer::ClearActiveSyscall(task);
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    task->flags &= ~hookself::tracer::kTaskFlagNestedPtraceWaitExitHold;
    memset(hold, 0, sizeof(*hold));
    return ResumeTask(context, task);
}

int WakeNestedPtraceWaiters(TracerContext* context) noexcept {
    if (!NestedPtraceEnabled(context)) {
        return 0;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        const LogicalPtraceDispatchOperation* operation =
                LogicalPtraceOperationAt(&context->logical_ptrace->dispatcher,
                                         slot);
        if (operation == nullptr ||
            operation->state != LogicalPtraceOperationState::kHeldWait) {
            continue;
        }
        const int wake_error = TryWakeLogicalPtraceWait(
                &context->logical_ptrace->dispatcher,
                &context->logical_ptrace->logical,
                MakeLogicalPtraceResidentIo(&context->logical_ptrace_io_context),
                operation->caller);
        if (wake_error != 0 && wake_error != EAGAIN && wake_error != ESRCH) {
            return wake_error;
        }
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        NestedPtraceWaitExitHold* hold =
                &context->nested_ptrace_wait_holds[slot];
        if (hold->occupied == 0U) {
            continue;
        }
        const LogicalPtraceDispatchOperation* operation =
                LogicalPtraceOperationAt(&context->logical_ptrace->dispatcher,
                                         slot);
        if (operation == nullptr) {
            return ESTALE;
        }
        if (operation->state == LogicalPtraceOperationState::kHeldWait) {
            continue;
        }
        if (operation->state != LogicalPtraceOperationState::kHeldReady) {
            return EPROTO;
        }
        const int complete_error = CompleteNestedPtraceHeldWait(context, hold);
        if (complete_error != 0) {
            return complete_error;
        }
    }
    return CollectNestedPtraceRetiredTasks(context);
}

int CancelNestedPtraceHeldWait(TracerContext* context,
                                NestedPtraceWaitExitHold* hold,
                                int64_t visible_result) noexcept {
    if (!NestedPtraceEnabled(context) || hold == nullptr ||
        hold->occupied == 0U) {
        return EINVAL;
    }
    TaskRecord* task = nullptr;
    const int resolve_error = ResolveNestedPtracePhysicalTask(
            context, hold->waiter, &task);
    if (resolve_error != 0 || task->tid != hold->physical_tid ||
        task->stop_sequence != hold->physical_stop_sequence ||
        (task->flags &
         hookself::tracer::kTaskFlagNestedPtraceWaitExitHold) == 0U) {
        return resolve_error != 0 ? resolve_error : ESTALE;
    }
    const int cancel_error = CancelLogicalPtraceDispatch(
            &context->logical_ptrace->dispatcher,
            &context->logical_ptrace->logical, hold->waiter);
    if (cancel_error != 0 && cancel_error != ESRCH) {
        return cancel_error;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallReplaceResult;
    task->active_syscall.replacement_result = visible_result;
    task->active_syscall.exit_policy_rule_id =
            HOOKSELF_BUILTIN_RULE_NESTED_PTRACE;
    int64_t effective_result = 0;
    const int write_error = ApplyExitSyscallPolicy(
            context, task, 0, &effective_result);
    if (write_error != 0) {
        return write_error;
    }
    task->active_syscall.result = effective_result;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallResultValid;
    EmitSyscallEvent(context, task, task->active_syscall.syscall_number,
                     HOOKSELF_SYSCALL_PHASE_EXIT,
                     task->active_syscall.arguments, effective_result, 0);
    ClearPendingPath(context, task);
    hookself::tracer::ClearActiveSyscall(task);
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    task->flags &= ~hookself::tracer::kTaskFlagNestedPtraceWaitExitHold;
    memset(hold, 0, sizeof(*hold));
    return ResumeTask(context, task);
}

int CancelNestedPtraceHoldsForShutdown(TracerContext* context) noexcept {
    if (!NestedPtraceEnabled(context)) {
        return 0;
    }
    for (uint32_t slot = 0; slot < kLogicalPtraceDispatchCapacity; ++slot) {
        NestedPtraceWaitExitHold* hold =
                &context->nested_ptrace_wait_holds[slot];
        if (hold->occupied == 0U) {
            continue;
        }
        const int cancel_error = CancelNestedPtraceHeldWait(
                context, hold, -EINTR);
        if (cancel_error == ESRCH) {
            memset(hold, 0, sizeof(*hold));
            continue;
        }
        if (cancel_error != 0) {
            return cancel_error;
        }
    }
    for (uint32_t slot = 0;
         slot < hookself::tracer::kLogicalPtraceRelationCapacity; ++slot) {
        NestedPtracePhysicalHold* hold = &context->nested_ptrace_holds[slot];
        if (hold->occupied == 0U) {
            continue;
        }
        LogicalPtraceTargetRequest request{};
        request.action = LogicalPtraceTargetAction::kResumeCont;
        request.target = hold->tracee;
        const int resume_error = ResumeNestedPtraceTracee(
                context, request, nullptr);
        if (resume_error != 0 && resume_error != ESRCH) {
            return resume_error;
        }
        if (resume_error == ESRCH) {
            ClearNestedPtracePhysicalHold(hold);
        }
    }
    return CollectNestedPtraceRetiredTasks(context);
}

int MaybePublishNestedPtraceStop(TracerContext* context, TaskRecord* task,
                                 const StopEvent& event,
                                 bool* physical_stop_held) noexcept {
    if (physical_stop_held == nullptr) {
        return EINVAL;
    }
    *physical_stop_held = false;
    if (!NestedPtraceEnabled(context) || task == nullptr ||
        context->quiescing ||
        event.kind != StopEventKind::kPtraceEvent ||
        event.ptrace_event != PTRACE_EVENT_EXEC || task->tid != task->tgid) {
        return 0;
    }
    const LogicalPtraceResidentTask* logical =
            FindNestedPtraceTask(context, task);
    if (logical == nullptr) {
        return 0;
    }
    const hookself::tracer::LogicalPtraceRelation* relation =
            hookself::tracer::FindLogicalPtraceRelation(
                    &context->logical_ptrace->logical, logical->key);
    if (relation == nullptr ||
        relation->attach_kind !=
                hookself::tracer::LogicalPtraceAttachKind::kTraceme ||
        relation->tracer.tgid != context->target_pid) {
        return 0;
    }
    if (FindNestedPtracePhysicalHold(context, logical->key) != nullptr) {
        return EBUSY;
    }

    // The outer tracer always requests TRACEEXEC for its own bookkeeping.
    // Reconstruct the inner ptrace ABI instead: ordinary TRACEME exec stops
    // are SIGTRAP delivery stops, while PTRACE_O_TRACEEXEC opts into the
    // PTRACE_EVENT_EXEC status and GETEVENTMSG payload.
    const bool trace_exec =
            (relation->options &
             hookself::tracer::kLogicalPtraceOptionTraceExec) != 0U;

    Arm64Regs registers{};
    const int register_error = hookself::arch::ReadRegisters(task->tid,
                                                              &registers);
    if (register_error != 0) {
        return register_error;
    }
    hookself::tracer::LogicalPtraceEvent logical_event{};
    logical_event.kind = trace_exec
            ? hookself::tracer::LogicalPtraceEventKind::kPtraceEvent
            : hookself::tracer::LogicalPtraceEventKind::kSignalDelivery;
    logical_event.flags = hookself::tracer::kLogicalPtraceEventFlagRegistersValid;
    logical_event.wait_status = trace_exec
            ? event.raw_status
            : static_cast<int32_t>((SIGTRAP << 8) | 0x7f);
    logical_event.signal_number = SIGTRAP;
    logical_event.ptrace_event = trace_exec ? PTRACE_EVENT_EXEC : 0U;
    logical_event.guest_syscall_number = -1;
    logical_event.event_message = trace_exec
            ? task->last_ptrace_event_message
            : 0U;
    logical_event.guest_registers = registers;
    uint64_t event_sequence = 0;
    const int publish_error = PublishLogicalPtraceStop(
            &context->logical_ptrace->dispatcher,
            &context->logical_ptrace->logical, logical->key, logical_event,
            &event_sequence);
    if (publish_error != 0) {
        return publish_error;
    }
    relation = hookself::tracer::FindLogicalPtraceRelation(
            &context->logical_ptrace->logical, logical->key);
    if (relation == nullptr || relation->slot >=
            hookself::tracer::kLogicalPtraceRelationCapacity) {
        return EPROTO;
    }
    NestedPtracePhysicalHold* hold =
            &context->nested_ptrace_holds[relation->slot];
    if (hold->occupied != 0U) {
        return EBUSY;
    }
    hold->occupied = 1U;
    hold->relation_slot = relation->slot;
    hold->relation_generation = relation->generation;
    hold->tracee = logical->key;
    hold->physical_tid = task->tid;
    hold->physical_stop_sequence = task->stop_sequence;
    hold->event_sequence = event_sequence;
    task->flags |= hookself::tracer::kTaskFlagNestedPtraceTraceeHold;
    const int wake_error = WakeNestedPtraceWaiters(context);
    if (wake_error != 0) {
        return wake_error;
    }
    *physical_stop_held = true;
    return 0;
}

int PublishNestedPtraceTerminal(TracerContext* context, TaskRecord* task,
                                const StopEvent& event) noexcept {
    if (context != nullptr && context->quiescing) {
        return 0;
    }
    const LogicalPtraceResidentTask* logical =
            FindNestedPtraceTask(context, task);
    if (logical == nullptr) {
        return 0;
    }
    const hookself::tracer::LogicalTaskKey key = logical->key;
    const hookself::tracer::LogicalPtraceRelation* relation =
            hookself::tracer::FindLogicalPtraceRelation(
                    &context->logical_ptrace->logical, key);
    if (relation != nullptr) {
        hookself::tracer::LogicalPtraceEvent terminal{};
        terminal.kind = event.kind == StopEventKind::kExited
                ? hookself::tracer::LogicalPtraceEventKind::kExited
                : hookself::tracer::LogicalPtraceEventKind::kSignaled;
        terminal.wait_status = event.raw_status;
        terminal.signal_number = event.kind == StopEventKind::kSignaled
                ? event.signal
                : 0;
        terminal.guest_syscall_number = -1;
        const int publish_error = PublishLogicalPtraceStop(
                &context->logical_ptrace->dispatcher,
                &context->logical_ptrace->logical, key, terminal, nullptr);
        if (publish_error != 0 && publish_error != ESRCH) {
            return publish_error;
        }
        NestedPtracePhysicalHold* hold = FindNestedPtracePhysicalHold(
                context, key);
        if (hold != nullptr) {
            ClearNestedPtracePhysicalHold(hold);
        }
        task->flags &= ~hookself::tracer::kTaskFlagNestedPtraceTraceeHold;
        const int wake_error = WakeNestedPtraceWaiters(context);
        if (wake_error != 0) {
            return wake_error;
        }
    }
    const int retire_error = RetireNestedPtraceTask(context, task);
    if (retire_error != 0) {
        return retire_error;
    }
    return CollectNestedPtraceRetiredTasks(context);
}

