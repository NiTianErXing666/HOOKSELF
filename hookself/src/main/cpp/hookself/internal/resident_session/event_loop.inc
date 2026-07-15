int HandleRuntimeStatus(TracerContext* context, pid_t tid, int status) noexcept {
    TaskRecord* task = nullptr;
    StopEvent event{};
    const int apply_error = ApplyWaitStatus(context, tid, status, &task, &event);
    if (apply_error != 0 || task == nullptr) {
        if (apply_error != 0 &&
            context->last_failure_stage == FatalStage::kNone) {
            NoteFailure(context, FatalStage::kTaskIdentity, tid);
        }
        return apply_error;
    }
    if (StopCommandPending(context)) {
        context->stop_requested = true;
    }
    if ((task->flags &
         hookself::tracer::kTaskFlagAwaitingParentEvent) != 0) {
        return 0;
    }
    const int event_error = ProcessStoppedTaskEvent(context, task, event);
    if (event_error != 0) {
        return event_error;
    }
    if (context->stop_requested || context->teardown_freeze_requested) {
        return 0;
    }
    if ((task->flags &
         (hookself::tracer::kTaskFlagNestedPtraceTraceeHold |
          hookself::tracer::kTaskFlagNestedPtraceWaitExitHold)) != 0U) {
        return 0;
    }
    const int resume_error = ResumeTask(context, task);
    if (resume_error != 0) {
        NoteFailure(context, FatalStage::kResume, tid);
    }
    return resume_error;
}

bool HasActiveSnapshot(const TaskRecord* task) noexcept {
    return task != nullptr &&
           (task->active_syscall.flags &
            hookself::tracer::kActiveSyscallValid) != 0;
}

bool NeedsSyscallCompletion(const TaskRecord* task) noexcept {
    if (!HasActiveSnapshot(task)) {
        return false;
    }
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallFromSeccomp) != 0) {
        return (task->active_syscall.flags &
                hookself::tracer::kActiveSyscallNeedsExit) != 0 &&
               task->syscall_phase == TaskSyscallPhase::kExpectExit;
    }
    constexpr uint32_t kFullPtraceCompletionFlags =
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallReplaceResult |
            hookself::tracer::kActiveSyscallResultWriteUnknown |
            hookself::tracer::kActiveSyscallInternalFdOperation |
            hookself::tracer::kActiveSyscallPtraceView |
            hookself::tracer::kActiveSyscallProcStatusView |
            hookself::tracer::kActiveSyscallPathState;
    return (task->active_syscall.flags & kFullPtraceCompletionFlags) != 0;
}

bool AllTasksQuiesced(const TracerContext* context) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* task = hookself::tracer::At(
                context->tasks, slot);
        if (task == nullptr ||
            (task->flags & hookself::tracer::kTaskFlagSeized) == 0) {
            continue;
        }
        if (NeedsSyscallCompletion(task) ||
            (task->life != TaskLifeState::kStopped &&
             task->life != TaskLifeState::kExecReinit &&
             task->life != TaskLifeState::kExiting)) {
            return false;
        }
    }
    return true;
}

int QuiesceForShutdown(TracerContext* context,
                       int64_t deadline_ms) noexcept {
    context->quiescing = true;
    const int nested_cancel_error = CancelNestedPtraceHoldsForShutdown(context);
    if (nested_cancel_error != 0) {
        return nested_cancel_error;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr ||
            (task->flags & hookself::tracer::kTaskFlagSeized) == 0) {
            continue;
        }
        if (HasActiveSnapshot(task) && !NeedsSyscallCompletion(task) &&
            (task->life == TaskLifeState::kStopped ||
             task->life == TaskLifeState::kExecReinit ||
             task->life == TaskLifeState::kExiting)) {
            hookself::tracer::ClearActiveSyscall(task);
            continue;
        }
        if (NeedsSyscallCompletion(task) &&
            (task->life == TaskLifeState::kStopped ||
             task->life == TaskLifeState::kExecReinit ||
             task->life == TaskLifeState::kExiting)) {
            const int resume_error = ResumeTask(context, task);
            if (resume_error != 0) {
                NoteFailure(context, FatalStage::kResume, task->tid);
                return resume_error;
            }
            continue;
        }
        if (!NeedsSyscallCompletion(task) &&
            task->life != TaskLifeState::kStopped &&
            task->life != TaskLifeState::kExecReinit &&
            task->life != TaskLifeState::kExiting &&
            (task->flags &
             hookself::tracer::kTaskFlagInterruptSent) == 0) {
            const int interrupt_error = RawError(
                    RawPtrace(PTRACE_INTERRUPT, task->tid, 0, 0));
            if (interrupt_error == ESRCH) {
                RetireDeadTask(context, task);
                continue;
            }
            if (interrupt_error != 0) {
                NoteFailure(context, FatalStage::kInterrupt, task->tid);
                return interrupt_error;
            }
            task->flags |= hookself::tracer::kTaskFlagInterruptSent;
        }
    }

    while (!AllTasksQuiesced(context)) {
        int status = 0;
        const long waited = hookself::platform::RawWait4(
                -1, &status, kWaitWall | WNOHANG);
        if (waited < 0) {
            const int error = RawError(waited);
            if (error == EINTR) {
                continue;
            }
            NoteFailure(context, FatalStage::kWait, 0);
            return error;
        }
        if (waited == 0) {
            const int64_t now = hookself::platform::RawNowMs();
            if (now < 0 || now >= deadline_ms) {
                return ETIMEDOUT;
            }
            hookself::platform::RawSleepOneMillisecond();
            continue;
        }

        const pid_t tid = static_cast<pid_t>(waited);
        TaskRecord* before = hookself::tracer::Find(context->tasks, tid);
        const bool expected_completion = NeedsSyscallCompletion(before);
        TaskRecord* task = nullptr;
        StopEvent event{};
        const int apply_error = ApplyWaitStatus(
                context, tid, status, &task, &event);
        if (apply_error != 0) {
            if (context->last_failure_stage == FatalStage::kNone) {
                NoteFailure(context, FatalStage::kTaskIdentity, tid);
            }
            return apply_error;
        }
        if (task == nullptr) {
            continue;
        }
        if (event.kind == StopEventKind::kSyscallStop &&
            expected_completion) {
            const int syscall_error = HandleSyscallStop(context, task);
            if (syscall_error == ESRCH && !HasActiveExecSyscall(task) &&
                GroupHasPendingExec(context, task)) {
                RetireDeadTask(context, task);
                continue;
            }
            if (syscall_error != 0) {
                NoteFailure(context, FatalStage::kSyscall, tid);
                return syscall_error;
            }
        } else if (event.kind == StopEventKind::kSignalDelivery) {
            EmitSignalEvent(context, *task, event.signal);
        }
        if (NeedsSyscallCompletion(task)) {
            const int resume_error = ResumeTask(context, task);
            if (resume_error != 0) {
                NoteFailure(context, FatalStage::kResume, tid);
                return resume_error;
            }
        } else if (HasActiveSnapshot(task)) {
            hookself::tracer::ClearActiveSyscall(task);
        }
    }
    context->quiescing = false;
    return 0;
}

int VerifyTeardownFreezeCoverage(TracerContext* context,
                                 pid_t owner_tid) noexcept {
    if (context == nullptr || owner_tid <= 0 || !AllTasksQuiesced(context) ||
        !AllSeizedTasksStopped(*context)) {
        return EPROTO;
    }
    pid_t tids[hookself::tracer::kTaskTableCapacity]{};
    size_t tid_count = 0;
    const int enumerate_error = hookself::platform::EnumerateTaskTids(
            context->target_pid, tids, hookself::tracer::Capacity(),
            &tid_count);
    if (enumerate_error != 0) {
        return enumerate_error;
    }
    if (tid_count == 0 || !CurrentCoverageComplete(context, tids, tid_count)) {
        return EPROTO;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr) {
            continue;
        }
        if ((task->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
            NeedsSyscallCompletion(task) || HasActiveSnapshot(task) ||
            (task->life != TaskLifeState::kStopped &&
             task->life != TaskLifeState::kExecReinit &&
             task->life != TaskLifeState::kExiting)) {
            return EPROTO;
        }
    }
    const TaskRecord* owner = hookself::tracer::Find(
            context->tasks, owner_tid);
    if (owner == nullptr || owner->tgid != context->target_pid ||
        (owner->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
        owner->life != TaskLifeState::kStopped ||
        owner->stop == TaskStopState::kGroup ||
        owner->stop == TaskStopState::kExitEvent) {
        return ESRCH;
    }
    return 0;
}

int HandleTeardownFrozenStatus(TracerContext* context, pid_t owner_tid,
                               pid_t tid, int status) noexcept {
    TaskRecord* task = nullptr;
    StopEvent event{};
    const int apply_error = ApplyWaitStatus(
            context, tid, status, &task, &event);
    if (apply_error != 0) {
        return apply_error;
    }
    if (task == nullptr) {
        return tid == owner_tid ? ESRCH : 0;
    }
    if (task->tid != owner_tid) {
        return EPROTO;
    }
    if ((task->flags & hookself::tracer::kTaskFlagAwaitingParentEvent) != 0 ||
        event.kind == StopEventKind::kGroupStop ||
        (event.kind == StopEventKind::kPtraceEvent &&
         (event.ptrace_event == PTRACE_EVENT_EXEC ||
          event.ptrace_event == PTRACE_EVENT_EXIT))) {
        return EPROTO;
    }
    const int event_error = ProcessStoppedTaskEvent(context, task, event);
    if (event_error != 0) {
        return event_error;
    }
    TaskRecord* const current = hookself::tracer::Find(
            context->tasks, owner_tid);
    if (current == nullptr) {
        return ESRCH;
    }
    const int resume_error = ResumeTask(context, current);
    if (resume_error != 0) {
        NoteFailure(context, FatalStage::kResume, owner_tid);
    }
    return resume_error;
}

int RunTeardownFrozenLoop(TracerContext* context, pid_t owner_tid,
                          int64_t deadline_ms) noexcept {
    for (;;) {
        const int identity_error = ValidateRuntimeTargetIdentity(context);
        if (identity_error != 0) {
            NoteFailure(context, FatalStage::kIdentity,
                        context->target_pid);
            return identity_error;
        }
        bool received = false;
        uint32_t batch_count = 0;
        for (;;) {
            int status = 0;
            const long waited = hookself::platform::RawWait4(
                    -1, &status, kWaitWall | WNOHANG);
            if (waited == 0) {
                break;
            }
            if (waited < 0) {
                const int wait_error = RawError(waited);
                if (wait_error == EINTR) {
                    continue;
                }
                NoteFailure(context, FatalStage::kWait, 0);
                return wait_error;
            }
            received = true;
            const int status_error = HandleTeardownFrozenStatus(
                    context, owner_tid, static_cast<pid_t>(waited), status);
            if (status_error != 0) {
                return status_error;
            }
            if (++batch_count >= 64U) {
                break;
            }
        }
        __atomic_store_n(&context->control->tracer_heartbeat_ns,
                         static_cast<uint64_t>(MonotonicNanoseconds()),
                         __ATOMIC_RELEASE);
        if (__atomic_load_n(&context->control->teardown_release,
                            __ATOMIC_ACQUIRE) != 0U) {
            return 0;
        }
        const int64_t now = hookself::platform::RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        if (!received) {
            hookself::platform::RawSleepOneMillisecond();
        }
    }
}

int ResumeTasksAfterTeardown(TracerContext* context,
                             pid_t owner_tid) noexcept {
    TaskRecord* const owner = hookself::tracer::Find(
            context->tasks, owner_tid);
    if (owner == nullptr || owner->tgid != context->target_pid ||
        (owner->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
        owner->life != TaskLifeState::kRunning) {
        return ESRCH;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr || task->tid == owner_tid) {
            continue;
        }
        if ((task->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
            HasActiveSnapshot(task) ||
            (task->life != TaskLifeState::kStopped &&
             task->life != TaskLifeState::kExecReinit &&
             task->life != TaskLifeState::kExiting)) {
            return EPROTO;
        }
        const int resume_error = ResumeTask(context, task);
        if (resume_error != 0) {
            NoteFailure(context, FatalStage::kResume, task->tid);
            return resume_error;
        }
    }
    return 0;
}

int FreezeTasksForTeardown(TracerContext* context, pid_t owner_tid,
                           uint64_t sequence) noexcept {
    if (context == nullptr || !context->selective_mode ||
        !context->selective_passthrough || owner_tid <= 0 || sequence == 0 ||
        __atomic_load_n(&context->control->selective_install.policy_enabled,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_frozen,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_release,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_bypass_tid,
                        __ATOMIC_RELAXED) != owner_tid ||
        __atomic_load_n(&context->control->teardown_bypass_fd,
                        __ATOMIC_RELAXED) != -1) {
        return EPROTO;
    }
    const uint64_t published_sequence = __atomic_load_n(
            &context->control->parent_command_sequence, __ATOMIC_ACQUIRE);
    const uint64_t published_command = __atomic_load_n(
            &context->control->parent_command, __ATOMIC_ACQUIRE);
    if (published_sequence != sequence ||
        DecodeParentCommandOpcode(published_command) !=
                static_cast<uint32_t>(SharedCommand::kTeardownFreeze) ||
        DecodeParentCommandOwner(published_command) != owner_tid) {
        return EPROTO;
    }

    const int64_t now = hookself::platform::RawNowMs();
    const int quiesce_error = QuiesceForShutdown(
            context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
    if (quiesce_error != 0) {
        return quiesce_error;
    }
    const int coverage_error = VerifyTeardownFreezeCoverage(
            context, owner_tid);
    if (coverage_error != 0) {
        NoteFailure(context, FatalStage::kCoverage, owner_tid);
        return coverage_error;
    }

    TaskRecord* const owner = hookself::tracer::Find(
            context->tasks, owner_tid);
    if (owner == nullptr) {
        return ESRCH;
    }
    DiscardTaskMutation(context, owner, true);
    owner->syscall_phase = TaskSyscallPhase::kExpectEntry;
    owner->resume_mode = TaskResumeMode::kCont;
    context->quiescing = true;
    const int owner_resume_error = ResumeTask(context, owner);
    if (owner_resume_error != 0) {
        NoteFailure(context, FatalStage::kResume, owner_tid);
        return owner_resume_error;
    }
    const TaskRecord* const resumed_owner = hookself::tracer::Find(
            context->tasks, owner_tid);
    if (resumed_owner == nullptr ||
        resumed_owner->tgid != context->target_pid ||
        (resumed_owner->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
        resumed_owner->life != TaskLifeState::kRunning) {
        NoteFailure(context, FatalStage::kResume, owner_tid);
        return ESRCH;
    }

    __atomic_store_n(&context->control->teardown_frozen, 1U,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->control->tracer_ack_sequence, sequence,
                     __ATOMIC_RELEASE);
    if (!WriteStatusByte(context->status_write_fd,
                         kStatusTeardownFrozen)) {
        return EPIPE;
    }
    const int64_t frozen_started = hookself::platform::RawNowMs();
    const int frozen_error = RunTeardownFrozenLoop(
            context, owner_tid,
            (frozen_started < 0 ? 0 : frozen_started) +
                    kTeardownFrozenTimeoutMs);
    if (frozen_error != 0) {
        return frozen_error;
    }
    if (__atomic_load_n(&context->control->protected_fd_count,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&context->control->teardown_bypass_fd,
                        __ATOMIC_RELAXED) != -1) {
        return EPROTO;
    }
    const int resume_error = ResumeTasksAfterTeardown(context, owner_tid);
    if (resume_error != 0) {
        return resume_error;
    }
    context->quiescing = false;
    context->teardown_freeze_requested = false;
    context->teardown_owner_tid = 0;
    context->teardown_command_sequence = 0;
    __atomic_store_n(&context->control->teardown_release, 0U,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->control->teardown_frozen, 0U,
                     __ATOMIC_RELEASE);
    return 0;
}

int EnterSelectivePassthrough(TracerContext* context) noexcept {
    const int64_t now = hookself::platform::RawNowMs();
    const int quiesce_error = QuiesceForShutdown(
            context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
    if (quiesce_error != 0) {
        return quiesce_error;
    }
    PrepareTasksForSelectiveCont(context);
    context->stop_requested = false;
    context->selective_passthrough = true;
    __atomic_store_n(
            &context->control->selective_install.policy_enabled, 0U,
            __ATOMIC_RELEASE);
    const int resume_error = ResumeAllTasks(context);
    if (resume_error != 0) {
        return resume_error;
    }
    __atomic_store_n(&context->control->tracer_ack_sequence,
                     context->acknowledged_command, __ATOMIC_RELEASE);
    AtomicStoreState(context->control, HOOKSELF_STATE_STOPPED);
    EmitLifecycle(context, HOOKSELF_STATE_STOPPED);
    if (!WriteStatusByte(context->status_write_fd, kStatusStopped)) {
        return EPIPE;
    }
    return 0;
}

int WaitForRuntimeEvents(TracerContext* context) noexcept {
    while (!context->shutting_down) {
        const int identity_error = ValidateRuntimeTargetIdentity(context);
        if (identity_error != 0) {
            NoteFailure(context, FatalStage::kIdentity,
                        context->target_pid);
            return identity_error;
        }
        if (StopCommandPending(context)) {
            context->stop_requested = true;
        }
        if (context->teardown_freeze_requested) {
            const int freeze_error = FreezeTasksForTeardown(
                    context, context->teardown_owner_tid,
                    context->teardown_command_sequence);
            if (freeze_error != 0) {
                return freeze_error;
            }
            continue;
        }
        if (context->stop_requested) {
            if (context->selective_mode) {
                const int passthrough_error =
                        EnterSelectivePassthrough(context);
                if (passthrough_error != 0) {
                    return passthrough_error;
                }
                continue;
            }
            const int64_t now = hookself::platform::RawNowMs();
            const int quiesce_error = QuiesceForShutdown(
                    context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
            if (quiesce_error != 0) {
                return quiesce_error;
            }
            context->shutting_down = true;
            break;
        }
        bool received = false;
        uint32_t batch_count = 0;
        for (;;) {
            int status = 0;
            const long waited = hookself::platform::RawWait4(
                    -1, &status, kWaitWall | WNOHANG);
            if (RawError(waited) == ECHILD) {
                NoteFailure(context, FatalStage::kWait, 0);
                return ECHILD;
            }
            if (waited == 0) {
                break;
            }
            if (waited < 0) {
                if (RawError(waited) == EINTR) {
                    continue;
                }
                NoteFailure(context, FatalStage::kWait, 0);
                return RawError(waited);
            }
            received = true;
            const int status_error = HandleRuntimeStatus(
                    context, static_cast<pid_t>(waited), status);
            if (status_error != 0) {
                return status_error;
            }
            if (context->stop_requested ||
                context->teardown_freeze_requested) {
                break;
            }
            if (++batch_count >= 64) {
                break;
            }
        }
        __atomic_store_n(&context->control->tracer_heartbeat_ns,
                         static_cast<uint64_t>(MonotonicNanoseconds()),
                         __ATOMIC_RELEASE);
        if (context->teardown_freeze_requested) {
            const int freeze_error = FreezeTasksForTeardown(
                    context, context->teardown_owner_tid,
                    context->teardown_command_sequence);
            if (freeze_error != 0) {
                return freeze_error;
            }
            continue;
        }
        if (context->stop_requested) {
            if (context->selective_mode) {
                const int passthrough_error =
                        EnterSelectivePassthrough(context);
                if (passthrough_error != 0) {
                    return passthrough_error;
                }
                continue;
            }
            const int64_t now = hookself::platform::RawNowMs();
            const int quiesce_error = QuiesceForShutdown(
                    context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
            if (quiesce_error != 0) {
                return quiesce_error;
            }
            context->shutting_down = true;
            break;
        }
        if (!received) {
            pollfd descriptors[2]{
                    {context->control_event_fd, POLLIN, 0},
                    {context->signal_event_fd, POLLIN, 0},
            };
            timespec timeout{};
            timeout.tv_sec = 1;
            const long poll_result = RawSyscall6(
                    __NR_ppoll, reinterpret_cast<long>(descriptors), 2,
                    reinterpret_cast<long>(&timeout), 0, 0);
            const int poll_error = RawError(poll_result);
            if (poll_error != 0 && poll_error != EINTR) {
                NoteFailure(context, FatalStage::kPoll, 0);
                return poll_error;
            }
            if (poll_result > 0 && (descriptors[0].revents & POLLIN) != 0) {
                uint64_t value = 0;
                (void)hookself::platform::RawRead(
                        context->control_event_fd, &value, sizeof(value));
            }
            if (poll_result > 0 && (descriptors[1].revents & POLLIN) != 0) {
                signalfd_siginfo signal_info{};
                while (hookself::platform::RawRead(
                               context->signal_event_fd, &signal_info,
                               sizeof(signal_info)) ==
                       static_cast<long>(sizeof(signal_info))) {
                }
            }
        }
    }
    return 0;
}

int StopAllTasks(TracerContext* context, int64_t deadline_ms) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr ||
            (task->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
            task->life == TaskLifeState::kStopped ||
            task->life == TaskLifeState::kExecReinit ||
            task->life == TaskLifeState::kExiting) {
            continue;
        }
        const int interrupt_error = RawError(
                RawPtrace(PTRACE_INTERRUPT, task->tid, 0, 0));
        if (interrupt_error == ESRCH) {
            (void)hookself::tracer::Erase(context->tasks, task->tid);
            UpdateTrackedTasks(context);
            continue;
        }
        if (interrupt_error != 0) {
            return interrupt_error;
        }
        task->flags |= hookself::tracer::kTaskFlagInterruptSent;
    }
    return DrainUntilAllStopped(context, deadline_ms);
}

int DetachTask(TracerContext* context, TaskRecord* task) noexcept {
    int signal_number = task->pending_signal;
    if ((task->flags & hookself::tracer::kTaskFlagAutoAttached) != 0 &&
        signal_number == SIGSTOP) {
        signal_number = 0;
    }
    const int detach_error = RawError(
            RawPtrace(PTRACE_DETACH, task->tid, 0,
                      static_cast<uintptr_t>(signal_number)));
    if (detach_error != 0 && detach_error != ESRCH) {
        return detach_error;
    }
    const pid_t tid = task->tid;
    (void)hookself::tracer::Erase(context->tasks, tid);
    UpdateTrackedTasks(context);
    return 0;
}

int DetachAllTasks(TracerContext* context) noexcept {
    int first_error = 0;
    const pid_t bootstrap_tid = context->header->bootstrap_tid;
    for (int slot = static_cast<int>(hookself::tracer::Capacity()) - 1;
         slot >= 0; --slot) {
        TaskRecord* task = hookself::tracer::At(
                context->tasks, static_cast<uint32_t>(slot));
        if (task == nullptr || task->tid == context->target_pid ||
            task->tid == bootstrap_tid) {
            continue;
        }
        const int error = DetachTask(context, task);
        if (first_error == 0 && error != 0) {
            first_error = error;
        }
    }
    TaskRecord* leader = hookself::tracer::Find(
            context->tasks, context->target_pid);
    if (leader != nullptr && leader->tid != bootstrap_tid) {
        const int error = DetachTask(context, leader);
        if (first_error == 0 && error != 0) {
            first_error = error;
        }
    }
    TaskRecord* bootstrap = hookself::tracer::Find(
            context->tasks, bootstrap_tid);
    if (bootstrap != nullptr) {
        const int error = DetachTask(context, bootstrap);
        if (first_error == 0 && error != 0) {
            first_error = error;
        }
    }
    return first_error;
}

int WaitForShutdownCommit(TracerContext* context,
                          int64_t deadline_ms) noexcept {
    for (;;) {
        const int commit_result = ConsumeShutdownCommit(context);
        if (commit_result != EAGAIN) {
            return commit_result;
        }
        uint64_t wake = 0;
        const long read_result = hookself::platform::RawRead(
                context->control_event_fd, &wake, sizeof(wake));
        const int read_error = RawError(read_result);
        if (read_result != static_cast<long>(sizeof(wake)) &&
            read_error != EAGAIN && read_error != EINTR) {
            return read_error != 0 ? read_error : EIO;
        }
        const int64_t now = hookself::platform::RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
}

int CommitLogicalProcessStateBeforeDetach(TracerContext* context) noexcept {
    if (!context->runtime_started || !context->stop_requested ||
        context->stop_owner_tid <= 0) {
        return 0;
    }
    TaskRecord* owner = hookself::tracer::Find(
            context->tasks, context->stop_owner_tid);
    if (owner == nullptr || owner->tgid != context->target_pid ||
        (owner->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
        (owner->life != TaskLifeState::kStopped &&
         owner->life != TaskLifeState::kExecReinit)) {
        return ESRCH;
    }
    const int detach_error = DetachTask(context, owner);
    if (detach_error != 0) {
        return detach_error;
    }
    if (!WriteStatusByte(context->status_write_fd, kStatusCommitReady)) {
        return EPIPE;
    }
    const int64_t now = hookself::platform::RawNowMs();
    return WaitForShutdownCommit(
            context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
}

int RollbackAllMutations(TracerContext* context) noexcept {
    int first_error = 0;
    constexpr uint32_t kMutationFlags =
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallResultWriteUnknown;
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr ||
            (task->active_syscall.flags & kMutationFlags) == 0) {
            continue;
        }
        int error = 0;
        if ((task->active_syscall.flags &
             hookself::tracer::kActiveSyscallResultWriteUnknown) != 0 ||
            ((task->active_syscall.flags &
              hookself::tracer::kActiveSyscallArgumentsModified) != 0 &&
             (task->active_syscall.modified_argument_mask & 1U) != 0)) {
            error = EOWNERDEAD;
        } else {
            error = RestoreEntryMutations(context, task, false);
        }
        if (error == ESRCH && task->life == TaskLifeState::kExiting) {
            task->active_syscall.flags &= ~kMutationFlags;
            continue;
        }
        if (first_error == 0 && error != 0) {
            first_error = error;
        }
    }
    return first_error;
}

bool HasDirtyMutations(const TracerContext* context) noexcept {
    constexpr uint32_t kMutationFlags =
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallResultWriteUnknown;
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task != nullptr &&
            (task->active_syscall.flags & kMutationFlags) != 0) {
            return true;
        }
    }
    return false;
}

void TerminateMutationOwners(TracerContext* context) noexcept {
    constexpr uint32_t kMutationFlags =
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallResultWriteUnknown;
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task != nullptr &&
            (task->active_syscall.flags & kMutationFlags) != 0) {
            (void)RawSyscall6(__NR_kill, task->tgid, SIGKILL);
        }
    }
    (void)RawSyscall6(__NR_kill, context->target_pid, SIGKILL);
}

int ShutdownTracer(TracerContext* context) noexcept {
    context->shutting_down = true;
    // No new logical dispatch may be created while releasing an already held
    // surrogate syscall. Release holds before stopping tasks so their visible
    // result is committed instead of exposing the harmless replacement call.
    context->quiescing = true;
    int first_error = CancelNestedPtraceHoldsForShutdown(context);
    const bool already_fatal = __atomic_load_n(
            &context->control->fatal_code, __ATOMIC_ACQUIRE) != 0;
    if (!already_fatal) {
        AtomicStoreState(context->control, HOOKSELF_STATE_STOPPING);
    }
    EmitLifecycle(context, HOOKSELF_STATE_STOPPING);
    const int64_t now = hookself::platform::RawNowMs();
    const int stop_error = StopAllTasks(
            context, (now < 0 ? 0 : now) + kDetachTimeoutMs);
    if (stop_error != 0) {
        if (HasDirtyMutations(context)) {
            TerminateMutationOwners(context);
        }
        return first_error != 0 ? first_error : stop_error;
    }
    const int rollback_error = RollbackAllMutations(context);
    if (rollback_error != 0) {
        TerminateMutationOwners(context);
        return first_error != 0 ? first_error : rollback_error;
    }
    const int state_commit_error =
            CommitLogicalProcessStateBeforeDetach(context);
    if (state_commit_error != 0) {
        if (context->control->failure_mode == HOOKSELF_FAILURE_FAIL_CLOSED) {
            TerminateMutationOwners(context);
        } else {
            (void)DetachAllTasks(context);
        }
        return first_error != 0 ? first_error : state_commit_error;
    }
    const int detach_error = DetachAllTasks(context);
    return first_error != 0 ? first_error : detach_error;
}

int MapWritableScratch(TracerContext* context) noexcept {
    if (context == nullptr || context->header == nullptr ||
        context->mapping.fd < 0 || context->mapping.scratch_size == 0 ||
        context->header->scratch.offset != context->mapping.prefix_size ||
        context->header->scratch.size != context->mapping.scratch_size) {
        return EPROTO;
    }
    const long mapping_result = RawSyscall6(
            __NR_mmap, 0, static_cast<long>(context->mapping.scratch_size),
            PROT_READ | PROT_WRITE, MAP_SHARED, context->mapping.fd,
            static_cast<long>(context->header->scratch.offset));
    const int mapping_error = RawError(mapping_result);
    if (mapping_error != 0) {
        return mapping_error;
    }
    context->writable_scratch =
            reinterpret_cast<SharedScratchFrame*>(mapping_result);
    return 0;
}

int WaitForStartGate(TracerContext* context) noexcept {
    const int64_t deadline = hookself::platform::RawNowMs() + kAttachTimeoutMs;
    for (;;) {
        const int identity_error = ValidateTargetIdentity(context);
        if (identity_error != 0) {
            return identity_error;
        }
        uint64_t value = 0;
        const long result = hookself::platform::RawRead(
                context->control_event_fd, &value, sizeof(value));
        if (result == static_cast<long>(sizeof(value)) && value != 0) {
            return 0;
        }
        const int error = RawError(result);
        if (error != EAGAIN && error != EINTR) {
            return error != 0 ? error : EIO;
        }
        const int64_t now = hookself::platform::RawNowMs();
        if (now < 0 || now >= deadline) {
            return ETIMEDOUT;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
}

