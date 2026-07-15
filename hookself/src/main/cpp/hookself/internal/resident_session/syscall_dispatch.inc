int ProcessSyscallEntry(TracerContext* context, TaskRecord* task,
                        int32_t syscall_number,
                        const uint64_t arguments[6],
                        uint64_t instruction_pointer,
                        uint32_t event_flags) noexcept {
    SaveSyscallEntry(task, syscall_number, arguments);
    ClearPendingPath(context, task);
    if (PathStateSyscallNeedsExit(syscall_number)) {
        task->active_syscall.flags |=
                hookself::tracer::kActiveSyscallPathState;
        if (context->pending_paths != nullptr &&
            task->slot < hookself::tracer::Capacity()) {
            PendingPathIdentity* pending =
                    &context->pending_paths->entries[task->slot];
            pending->flags = kPendingPathActive;
            pending->syscall_number = syscall_number;
        }
        if (syscall_number ==
            hookself::tracer::kMountStateMountSetattr) {
            CaptureMountSetattr(context, task, arguments);
        }
    }
    const bool log_bypass =
            ShouldBypassLogSyscall(context, task) ||
            ShouldBypassRuntimeApiSyscall(
                    context, task, syscall_number, instruction_pointer);
    if (log_bypass) {
        task->active_syscall.flags |=
                hookself::tracer::kActiveSyscallLogBypass;
    }

    bool suppress_path_redirect = false;
    bool protected_fd_handled = false;
    bool proc_virtual_handled = false;
    int policy_error = ApplyProtectedFdPolicy(
            context, task, &protected_fd_handled);
    if (policy_error != 0) {
        return policy_error;
    }
    if (context->selective_passthrough) {
        task->active_syscall.flags |=
                hookself::tracer::kActiveSyscallLogBypass;
        FinalizeSelectiveEntry(context, task, false);
        return 0;
    }
    if (log_bypass) {
        FinalizeSelectiveEntry(context, task, false);
        return 0;
    }

    if (!protected_fd_handled) {
        bool nested_ptrace_handled = false;
        policy_error = ApplyNestedPtraceEntry(
                context, task, &nested_ptrace_handled);
        if (policy_error == 0 && nested_ptrace_handled) {
            suppress_path_redirect = true;
        } else if (policy_error == 0) {
            bool ptrace_view_handled = false;
            policy_error = ApplyPtraceViewPolicy(
                    context, task, &ptrace_view_handled);
            if (policy_error == 0 && !ptrace_view_handled) {
                policy_error = ApplyProcVirtualEntry(
                        context, task, &proc_virtual_handled);
                if (policy_error == 0 && !proc_virtual_handled) {
                    policy_error = ApplyEntrySyscallPolicy(
                            context, task, &suppress_path_redirect);
                } else if (proc_virtual_handled) {
                    suppress_path_redirect = true;
                }
            } else if (ptrace_view_handled) {
                suppress_path_redirect = true;
            }
        }
    } else {
        suppress_path_redirect = true;
    }
    if (policy_error == 0 && !protected_fd_handled) {
        bool effective_protected_fd_handled = false;
        policy_error = ApplyEffectiveProtectedFdPolicy(
                context, task, &effective_protected_fd_handled);
        if (effective_protected_fd_handled) {
            suppress_path_redirect = true;
        }
    }
    if (policy_error != 0) {
        return policy_error;
    }
    if (!suppress_path_redirect) {
        const int redirect_error = MaybeRedirectPaths(
                context, task, syscall_number, arguments);
        if (redirect_error != 0) {
            return redirect_error;
        }
    }

    constexpr uint32_t kProcViewConflictFlags =
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallReplaceResult;
    if (!suppress_path_redirect &&
        (task->active_syscall.flags & kProcViewConflictFlags) == 0) {
        const int proc_view_error = ApplyProcStatusReadView(context, task);
        if (proc_view_error != 0) {
            return proc_view_error;
        }
    }
    EmitSyscallEvent(context, task, syscall_number,
                     HOOKSELF_SYSCALL_PHASE_ENTRY, arguments, 0,
                     event_flags);
    FinalizeSelectiveEntry(context, task);
    return 0;
}

int ProcessSyscallExit(TracerContext* context, TaskRecord* task,
                       int64_t kernel_result,
                       uint32_t event_flags) noexcept {
    const bool exec_reinit =
            task->life == TaskLifeState::kExecReinit ||
            (task->flags &
             hookself::tracer::kTaskFlagNestedPtraceExecReinitPending) != 0U;
    if (exec_reinit && !HasActiveExecSyscall(task)) {
        NoteFailure(context, FatalStage::kExecMigration, task->tid);
        return EPROTO;
    }
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallValid) == 0) {
        task->syscall_phase = TaskSyscallPhase::kExpectEntry;
        return 0;
    }
    bool nested_wait_exit_held = false;
    int error = CompleteNestedPtraceExit(
            context, task, kernel_result, &nested_wait_exit_held);
    if (error != 0 || nested_wait_exit_held) {
        return error;
    }
    if (exec_reinit) {
        // PTRACE_EVENT_EXEC occurs before the traced execve exit-stop.
        // Rebuild injects PTRACE_CONT syscalls, so wait until that stop is consumed.
        if (kernel_result != 0) {
            NoteFailure(context, FatalStage::kExecMigration, task->tid);
            return EPROTO;
        }
        const int rebuild_error = RebuildExecAddressSpace(context, task);
        if (rebuild_error != 0) {
            NoteFailure(context, FatalStage::kExecMigration, task->tid);
            return rebuild_error;
        }
        task->life = TaskLifeState::kStopped;
        task->flags &=
                ~hookself::tracer::kTaskFlagNestedPtraceExecReinitPending;
    }
    bool close_range_replay_scheduled = false;
    error = ContinueProtectedCloseRangeReplay(
            context, task, kernel_result, &close_range_replay_scheduled);
    if (error != 0 || close_range_replay_scheduled) {
        return error;
    }
    int64_t proc_visible_result = kernel_result;
    bool proc_replay_scheduled = false;
    error = CompleteProcVirtualExit(
            context, task, kernel_result, &proc_visible_result,
            &proc_replay_scheduled);
    if (error != 0 || proc_replay_scheduled) {
        return error;
    }
    const bool restarting = IsKernelRestartResult(proc_visible_result);
    error = CompleteProcStatusReadView(
            context, task, proc_visible_result);
    if (error != 0) {
        return error;
    }
    error = RestoreEntryMutations(context, task, true);
    if (error != 0) {
        return error;
    }
    error = CompleteInternalFdOperation(
            context, task, proc_visible_result);
    if (error != 0) {
        return error;
    }
    int64_t path_visible_result = proc_visible_result;
    error = CompletePathStateSyscall(
            context, task, proc_visible_result, &path_visible_result);
    if (error != 0) {
        return error;
    }

    int64_t effective_result = path_visible_result;
    if (!restarting &&
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallLogBypass) == 0) {
        error = ApplyExitSyscallPolicy(
                context, task, path_visible_result, &effective_result);
        if (error != 0) {
            return error;
        }
    }
    task->active_syscall.result = effective_result;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallResultValid;
    const uint32_t exit_flags =
            event_flags |
            (restarting ? HOOKSELF_EVENT_F_SYSCALL_RESTART : 0) |
            ((task->active_syscall.flags &
              hookself::tracer::kActiveSyscallExecRecovered) != 0
                     ? HOOKSELF_EVENT_F_EXEC_RECOVERED
                     : 0);
    EmitSyscallEvent(context, task, task->active_syscall.syscall_number,
                     HOOKSELF_SYSCALL_PHASE_EXIT,
                     task->active_syscall.arguments, effective_result,
                     exit_flags);
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallVirtualFileOpen) != 0 &&
        effective_result >= 0) {
        __atomic_fetch_add(&context->control->virtual_file_opens, 1U,
                           __ATOMIC_RELAXED);
    }
    ClearPendingPath(context, task);
    hookself::tracer::ClearActiveSyscall(task);
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    if (context->selective_mode) {
        task->resume_mode = TaskResumeMode::kCont;
    }
    return 0;
}

int HandleSyscallStop(TracerContext* context, TaskRecord* task) noexcept {
    ptrace_syscall_info info{};
    const long info_result = RawPtrace(
            PTRACE_GET_SYSCALL_INFO, task->tid, sizeof(info),
            reinterpret_cast<uintptr_t>(&info));
    const int info_error = RawError(info_result);
    if (info_error == ESRCH) {
        return ESRCH;
    }
    if (info_result >= 0 &&
        (info.op == PTRACE_SYSCALL_INFO_ENTRY ||
         info.op == PTRACE_SYSCALL_INFO_SECCOMP)) {
        if (context->selective_mode &&
            info.op != PTRACE_SYSCALL_INFO_SECCOMP) {
            return EPROTO;
        }
        const uint64_t number = info.op == PTRACE_SYSCALL_INFO_ENTRY
                                        ? info.entry.nr
                                        : info.seccomp.nr;
        uint64_t arguments[6]{};
        for (size_t i = 0; i < 6; ++i) {
            arguments[i] = info.op == PTRACE_SYSCALL_INFO_ENTRY
                                   ? static_cast<uint64_t>(info.entry.args[i])
                                   : static_cast<uint64_t>(info.seccomp.args[i]);
        }
        if (number > INT32_MAX) {
            return EPROTO;
        }
        return ProcessSyscallEntry(
                context, task, static_cast<int32_t>(number), arguments,
                info.instruction_pointer, 0);
    }
    if (info_result >= 0 && info.op == PTRACE_SYSCALL_INFO_EXIT) {
        return ProcessSyscallExit(context, task, info.exit.rval, 0);
    }

    Arm64Regs registers{};
    const int registers_error = hookself::arch::ReadRegisters(task->tid, &registers);
    if (registers_error != 0) {
        return registers_error;
    }
    int32_t syscall_number = static_cast<int32_t>(registers.regs[8]);
    (void)hookself::arch::ReadSyscallNumber(task->tid, &syscall_number);
    const uint32_t fallback_flag = HOOKSELF_EVENT_F_SYSCALL_INFO_FALLBACK;
    if ((task->active_syscall.flags & hookself::tracer::kActiveSyscallValid) == 0 ||
        task->syscall_phase != TaskSyscallPhase::kExpectExit) {
        uint64_t arguments[6]{};
        for (size_t i = 0; i < 6; ++i) {
            arguments[i] = registers.regs[i];
        }
        return ProcessSyscallEntry(
                context, task, syscall_number, arguments, registers.pc,
                fallback_flag);
    } else {
        return ProcessSyscallExit(
                context, task, static_cast<int64_t>(registers.regs[0]),
                fallback_flag);
    }
}

void InitializeFallbackSyscallPhase(TaskRecord* task) noexcept {
    if (task == nullptr) {
        return;
    }
    hookself::tracer::ClearActiveSyscall(task);
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    int32_t syscall_number = -1;
    if (hookself::arch::ReadSyscallNumber(task->tid, &syscall_number) != 0 ||
        syscall_number < 0 ||
        syscall_number >= static_cast<int32_t>(HOOKSELF_SYSCALL_LIMIT)) {
        return;
    }
    Arm64Regs registers{};
    if (hookself::arch::ReadRegisters(task->tid, &registers) != 0) {
        return;
    }
    uint64_t arguments[6]{};
    for (size_t i = 0; i < 6; ++i) {
        arguments[i] = registers.regs[i];
    }
    SaveSyscallEntry(task, syscall_number, arguments);
}

int ResumeTask(TracerContext* context, TaskRecord* task) noexcept {
    long request = PTRACE_SYSCALL;
    if (context->selective_requested) {
        if (task->resume_mode == TaskResumeMode::kCont) {
            request = PTRACE_CONT;
        } else if (task->resume_mode == TaskResumeMode::kSyscall) {
            request = PTRACE_SYSCALL;
        } else {
            return EPROTO;
        }
    }
    int signal_number = task->pending_signal;
    if (task->stop == TaskStopState::kGroup) {
        request = PTRACE_LISTEN;
        signal_number = 0;
    } else if ((task->flags & hookself::tracer::kTaskFlagAutoAttached) != 0 &&
               task->stop == TaskStopState::kSignalDelivery &&
               signal_number == SIGSTOP) {
        signal_number = 0;
    }
    const int resume_error = RawError(
            RawPtrace(request, task->tid, 0, static_cast<uintptr_t>(signal_number)));
    if (resume_error == ESRCH) {
        if (task->tid != task->tgid && HasActiveExecSyscall(task)) {
            DiscardTaskMutation(context, task, false);
            task->life = TaskLifeState::kDead;
            task->stop = TaskStopState::kNone;
            task->pending_signal = 0;
            task->flags |= hookself::tracer::kTaskFlagExecTombstone;
            return 0;
        }
        const int nested_retire_error = RetireNestedPtraceTask(context, task);
        if (nested_retire_error != 0) {
            return nested_retire_error;
        }
        DiscardTaskMutation(context, task, true);
        (void)hookself::tracer::Erase(context->tasks, task->tid);
        UpdateTrackedTasks(context);
        return 0;
    }
    if (resume_error != 0) {
        return resume_error;
    }
    task->flags &= ~(hookself::tracer::kTaskFlagInterruptSent |
                     hookself::tracer::kTaskFlagAutoAttached);
    task->pending_signal = 0;
    task->life = TaskLifeState::kRunning;
    task->stop = TaskStopState::kNone;
    return 0;
}

bool GroupHasPendingExec(const TracerContext* context,
                         const TaskRecord* excluded) noexcept {
    if (excluded == nullptr) {
        return false;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* candidate = hookself::tracer::At(
                context->tasks, slot);
        if (candidate != nullptr && candidate != excluded &&
            candidate->tgid == excluded->tgid &&
            HasActiveExecSyscall(candidate) &&
            candidate->syscall_phase == TaskSyscallPhase::kExpectExit) {
            return true;
        }
    }
    return false;
}

void RetireDeadTask(TracerContext* context, TaskRecord* task) noexcept {
    if (task == nullptr) {
        return;
    }
    const pid_t tid = task->tid;
    (void)RetireNestedPtraceTask(context, task);
    DiscardTaskMutation(context, task, true);
    (void)hookself::tracer::Erase(context->tasks, tid);
    UpdateTrackedTasks(context);
}

int ResumeAllTasks(TracerContext* context) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr ||
            (task->flags & hookself::tracer::kTaskFlagSeized) == 0) {
            continue;
        }
        const int resume_error = ResumeTask(context, task);
        if (resume_error != 0) {
            return resume_error;
        }
    }
    return 0;
}

void InitializeFallbackSyscallPhases(TracerContext* context) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr) {
            continue;
        }
        InitializeFallbackSyscallPhase(task);
    }
}

bool StopCommandPending(TracerContext* context) noexcept {
    const uint64_t sequence = __atomic_load_n(
            &context->control->parent_command_sequence, __ATOMIC_ACQUIRE);
    if (sequence == context->acknowledged_command) {
        return false;
    }
    const uint64_t command = __atomic_load_n(
            &context->control->parent_command, __ATOMIC_ACQUIRE);
    const uint32_t opcode = DecodeParentCommandOpcode(command);
    if (opcode == static_cast<uint32_t>(SharedCommand::kStop)) {
        const pid_t owner_tid = DecodeParentCommandOwner(command);
        context->stop_owner_tid =
                owner_tid > 0 ? owner_tid : context->header->bootstrap_tid;
        context->acknowledged_command = sequence;
        return true;
    }
    if (opcode == static_cast<uint32_t>(SharedCommand::kResume) &&
        context->selective_mode && context->selective_passthrough) {
        context->selective_passthrough = false;
        __atomic_store_n(
                &context->control->selective_install.policy_enabled, 1U,
                __ATOMIC_RELEASE);
        __atomic_store_n(&context->control->tracer_ack_sequence, sequence,
                         __ATOMIC_RELEASE);
        context->acknowledged_command = sequence;
        AtomicStoreState(context->control, HOOKSELF_STATE_RUNNING_SELECTIVE);
        EmitLifecycle(context, HOOKSELF_STATE_RUNNING_SELECTIVE);
        if (!WriteStatusByte(context->status_write_fd, kStatusReady)) {
            NoteFailure(context, FatalStage::kControl, context->target_pid);
            context->stop_requested = true;
        }
        return false;
    }
    if (opcode == static_cast<uint32_t>(SharedCommand::kTeardownFreeze)) {
        context->teardown_owner_tid = DecodeParentCommandOwner(command);
        context->teardown_command_sequence = sequence;
        context->teardown_freeze_requested = true;
        context->acknowledged_command = sequence;
        return false;
    }
    context->acknowledged_command = sequence;
    __atomic_store_n(&context->control->tracer_ack_sequence, sequence,
                     __ATOMIC_RELEASE);
    return false;
}

int ConsumeShutdownCommit(TracerContext* context) noexcept {
    const uint64_t sequence = __atomic_load_n(
            &context->control->parent_command_sequence, __ATOMIC_ACQUIRE);
    if (sequence == context->acknowledged_command) {
        return EAGAIN;
    }
    const uint64_t command = __atomic_load_n(
            &context->control->parent_command, __ATOMIC_ACQUIRE);
    const uint32_t opcode = DecodeParentCommandOpcode(command);
    const pid_t owner_tid = DecodeParentCommandOwner(command);
    context->acknowledged_command = sequence;
    __atomic_store_n(&context->control->tracer_ack_sequence, sequence,
                     __ATOMIC_RELEASE);
    if (owner_tid != context->stop_owner_tid) {
        return EPROTO;
    }
    if (opcode == kParentCommandShutdownCommit) {
        return 0;
    }
    return opcode == kParentCommandShutdownAbort ? ECANCELED : EPROTO;
}

int ValidateSelectiveSeccompStop(TracerContext* context,
                                 TaskRecord* task) noexcept {
    if (context == nullptr || task == nullptr || !context->selective_mode ||
        context->selective_plan == nullptr) {
        return EPROTO;
    }
    unsigned long message = 0;
    const int message_error = ReadEventMessage(task->tid, &message);
    if (message_error != 0 || message > UINT16_MAX) {
        return message_error != 0 ? message_error : EPROTO;
    }

    int32_t syscall_number = -1;
    uint16_t info_class = 0;
    ptrace_syscall_info info{};
    const long info_result = RawPtrace(
            PTRACE_GET_SYSCALL_INFO, task->tid, sizeof(info),
            reinterpret_cast<uintptr_t>(&info));
    if (RawError(info_result) == 0) {
        if (info.op != PTRACE_SYSCALL_INFO_SECCOMP ||
            info.seccomp.nr > INT32_MAX ||
            info.seccomp.ret_data > UINT16_MAX) {
            return EPROTO;
        }
        syscall_number = static_cast<int32_t>(info.seccomp.nr);
        info_class = static_cast<uint16_t>(info.seccomp.ret_data);
    } else {
        const int register_error = hookself::arch::ReadSyscallNumber(
                task->tid, &syscall_number);
        if (register_error != 0) {
            return register_error;
        }
        info_class = static_cast<uint16_t>(message);
    }

    uint16_t expected_class = 0;
    if (!FindSelectiveSeccompClass(
                context->selective_plan, syscall_number, &expected_class) ||
        expected_class != static_cast<uint16_t>(message) ||
        expected_class != info_class) {
        return EPROTO;
    }
    return 0;
}

bool CloseRangeReplayAwaitsEntry(TracerContext* context,
                                 const TaskRecord* task) noexcept {
    const PendingPathIdentity* pending = PendingPathForTask(context, task);
    return pending != nullptr &&
           (pending->flags & kPendingPathCloseRangeAwaitEntry) != 0;
}

int HandleCloseRangeReplayEntry(TracerContext* context,
                                TaskRecord* task) noexcept {
    PendingPathIdentity* pending = PendingPathForTask(context, task);
    if (pending == nullptr ||
        (pending->flags & kPendingPathCloseRangeAwaitEntry) == 0 ||
        task->syscall_phase != TaskSyscallPhase::kExpectEntry) {
        return EPROTO;
    }

    int32_t syscall_number = -1;
    uint64_t arguments[3]{};
    ptrace_syscall_info info{};
    const long info_result = RawPtrace(
            PTRACE_GET_SYSCALL_INFO, task->tid, sizeof(info),
            reinterpret_cast<uintptr_t>(&info));
    const int info_error = RawError(info_result);
    if (info_error == ESRCH) {
        return ESRCH;
    }
    if (info_result >= 0) {
        const bool expected_op = context->selective_mode
                ? info.op == PTRACE_SYSCALL_INFO_SECCOMP
                : info.op == PTRACE_SYSCALL_INFO_ENTRY;
        if (!expected_op) {
            return EPROTO;
        }
        const uint64_t number = context->selective_mode
                ? info.seccomp.nr
                : info.entry.nr;
        if (number > INT32_MAX) {
            return EPROTO;
        }
        syscall_number = static_cast<int32_t>(number);
        for (size_t index = 0; index < 3U; ++index) {
            arguments[index] = context->selective_mode
                    ? static_cast<uint64_t>(info.seccomp.args[index])
                    : static_cast<uint64_t>(info.entry.args[index]);
        }
    } else {
        Arm64Regs registers{};
        int error = hookself::arch::ReadSyscallNumber(
                task->tid, &syscall_number);
        if (error == 0) {
            error = hookself::arch::ReadRegisters(task->tid, &registers);
        }
        if (error != 0) {
            return error;
        }
        for (size_t index = 0; index < 3U; ++index) {
            arguments[index] = registers.regs[index];
        }
    }
    if (syscall_number != kSyscallCloseRange ||
        arguments[0] != pending->replay_first ||
        arguments[1] != pending->replay_last ||
        arguments[2] != pending->replay_flags ||
        pending->replay_sequence == 0) {
        return EPROTO;
    }
    pending->flags &= ~kPendingPathCloseRangeAwaitEntry;
    task->syscall_phase = TaskSyscallPhase::kExpectExit;
    task->resume_mode = TaskResumeMode::kSyscall;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallNeedsExit;
    return 0;
}

bool ProcVirtualReplayAwaitsEntry(const TaskRecord* task) noexcept {
    return task != nullptr &&
           (task->active_syscall.flags &
            hookself::tracer::kActiveSyscallProcVirtualReplay) != 0;
}

int HandleProcVirtualReplayEntry(TracerContext* context,
                                 TaskRecord* task) noexcept {
    if (context == nullptr || context->proc_virtual == nullptr ||
        task == nullptr || !ProcVirtualReplayAwaitsEntry(task) ||
        task->slot >= kProcVirtualDispatchTaskCapacity ||
        task->syscall_phase != TaskSyscallPhase::kExpectEntry) {
        return EPROTO;
    }
    const ProcVirtualPending& pending =
            context->proc_virtual->pending.entries[task->slot];
    if ((pending.flags &
         (kProcVirtualPendingActive | kProcVirtualPendingDirents)) !=
                (kProcVirtualPendingActive | kProcVirtualPendingDirents) ||
        pending.syscall_number != __NR_getdents64 ||
        pending.replay_count == 0) {
        return EPROTO;
    }

    int32_t syscall_number = -1;
    uint64_t arguments[6]{};
    ptrace_syscall_info info{};
    const long info_result = RawPtrace(
            PTRACE_GET_SYSCALL_INFO, task->tid, sizeof(info),
            reinterpret_cast<uintptr_t>(&info));
    const int info_error = RawError(info_result);
    if (info_error == ESRCH) {
        return ESRCH;
    }
    if (info_result >= 0) {
        const bool expected_op = context->selective_mode
                                         ? info.op ==
                                                   PTRACE_SYSCALL_INFO_SECCOMP
                                         : info.op ==
                                                   PTRACE_SYSCALL_INFO_ENTRY;
        if (!expected_op) {
            return EPROTO;
        }
        const uint64_t number = context->selective_mode
                                        ? info.seccomp.nr
                                        : info.entry.nr;
        if (number > INT32_MAX) {
            return EPROTO;
        }
        syscall_number = static_cast<int32_t>(number);
        for (size_t index = 0; index < 6U; ++index) {
            arguments[index] = context->selective_mode
                                       ? static_cast<uint64_t>(
                                                 info.seccomp.args[index])
                                       : static_cast<uint64_t>(
                                                 info.entry.args[index]);
        }
    } else {
        Arm64Regs registers{};
        int error = hookself::arch::ReadSyscallNumber(
                task->tid, &syscall_number);
        if (error == 0) {
            error = hookself::arch::ReadRegisters(task->tid, &registers);
        }
        if (error != 0) {
            return error;
        }
        for (size_t index = 0; index < 6U; ++index) {
            arguments[index] = registers.regs[index];
        }
    }
    if (syscall_number != pending.syscall_number) {
        return EPROTO;
    }
    for (size_t index = 0; index < 6U; ++index) {
        if (arguments[index] != pending.arguments[index]) {
            return EPROTO;
        }
    }
    task->active_syscall.flags &=
            ~hookself::tracer::kActiveSyscallProcVirtualReplay;
    task->syscall_phase = TaskSyscallPhase::kExpectExit;
    task->resume_mode = TaskResumeMode::kSyscall;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallNeedsExit;
    return 0;
}

int ProcessStoppedTaskEvent(TracerContext* context, TaskRecord* task,
                            const StopEvent& event) noexcept {
    bool nested_tracee_held = false;
    const int nested_error = MaybePublishNestedPtraceStop(
            context, task, event, &nested_tracee_held);
    if (nested_error != 0 || nested_tracee_held) {
        return nested_error;
    }
    if (CloseRangeReplayAwaitsEntry(context, task) &&
        (event.kind == StopEventKind::kSeccompStop ||
         event.kind == StopEventKind::kSyscallStop)) {
        int replay_error = 0;
        if (context->selective_mode) {
            replay_error = event.kind == StopEventKind::kSeccompStop
                    ? ValidateSelectiveSeccompStop(context, task)
                    : EPROTO;
        } else if (event.kind != StopEventKind::kSyscallStop) {
            replay_error = EPROTO;
        }
        if (replay_error == 0) {
            replay_error = HandleCloseRangeReplayEntry(context, task);
        }
        if (replay_error != 0) {
            NoteFailure(context, FatalStage::kSyscall, task->tid);
        }
        return replay_error;
    }
    if (ProcVirtualReplayAwaitsEntry(task) &&
        (event.kind == StopEventKind::kSeccompStop ||
         event.kind == StopEventKind::kSyscallStop)) {
        int replay_error = 0;
        if (context->selective_mode) {
            replay_error = event.kind == StopEventKind::kSeccompStop
                                   ? ValidateSelectiveSeccompStop(
                                             context, task)
                                   : EPROTO;
        } else if (event.kind != StopEventKind::kSyscallStop) {
            replay_error = EPROTO;
        }
        if (replay_error == 0) {
            replay_error = HandleProcVirtualReplayEntry(context, task);
        }
        if (replay_error != 0) {
            NoteFailure(context, FatalStage::kSyscall, task->tid);
        }
        return replay_error;
    }
    if (event.kind == StopEventKind::kSeccompStop) {
        const int validation_error = ValidateSelectiveSeccompStop(
                context, task);
        if (validation_error != 0 ||
            (task->active_syscall.flags &
             hookself::tracer::kActiveSyscallValid) != 0 ||
            task->syscall_phase != TaskSyscallPhase::kExpectEntry) {
            NoteFailure(context, FatalStage::kSeccompProtocol, task->tid);
            return validation_error != 0 ? validation_error : EPROTO;
        }
        const int syscall_error = HandleSyscallStop(context, task);
        if (syscall_error != 0) {
            NoteFailure(context, FatalStage::kSyscall, task->tid);
            return syscall_error;
        }
    } else if (event.kind == StopEventKind::kSyscallStop) {
        if (context->selective_mode &&
            (task->resume_mode != TaskResumeMode::kSyscall ||
             task->syscall_phase != TaskSyscallPhase::kExpectExit ||
             (task->active_syscall.flags &
              hookself::tracer::kActiveSyscallNeedsExit) == 0)) {
            NoteFailure(context, FatalStage::kSeccompProtocol, task->tid);
            return EPROTO;
        }
        const int syscall_error = HandleSyscallStop(context, task);
        if (syscall_error != 0) {
            if (syscall_error == ESRCH && !HasActiveExecSyscall(task) &&
                GroupHasPendingExec(context, task)) {
                RetireDeadTask(context, task);
                return 0;
            }
            NoteFailure(context, FatalStage::kSyscall, task->tid);
            return syscall_error;
        }
    } else if (event.kind == StopEventKind::kSignalDelivery) {
        EmitSignalEvent(context, *task, event.signal);
    }
    return 0;
}

