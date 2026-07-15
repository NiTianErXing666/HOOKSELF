int CreateSignalEventFd() noexcept {
    constexpr size_t kKernelSignalSetBytes = sizeof(uint64_t);
    const uint64_t signal_mask = 1ULL << (SIGCHLD - 1);
    const long mask_result = RawSyscall6(
            __NR_rt_sigprocmask, SIG_SETMASK,
            reinterpret_cast<long>(&signal_mask), 0,
            kKernelSignalSetBytes);
    const int mask_error = RawError(mask_result);
    if (mask_error != 0) {
        return -mask_error;
    }
    const long fd_result = RawSyscall6(
            __NR_signalfd4, -1, reinterpret_cast<long>(&signal_mask),
            kKernelSignalSetBytes, SFD_CLOEXEC | SFD_NONBLOCK);
    return RawError(fd_result) == 0 ? static_cast<int>(fd_result)
                                    : -RawError(fd_result);
}

void StoreSelectiveInstallState(SharedSelectiveInstall* install,
                                SharedSelectiveInstallState state) noexcept {
    __atomic_store_n(&install->state, static_cast<uint32_t>(state),
                     __ATOMIC_RELEASE);
}

int AdvancePastSelectiveCommitTrap(TaskRecord* task) noexcept {
    siginfo_t signal_info{};
    const int siginfo_error = RawError(RawPtrace(
            PTRACE_GETSIGINFO, task->tid, 0,
            reinterpret_cast<uintptr_t>(&signal_info)));
    if (siginfo_error != 0 || signal_info.si_signo != SIGTRAP) {
        return siginfo_error != 0 ? siginfo_error : EPROTO;
    }
    Arm64Regs registers{};
    int error = hookself::arch::ReadRegisters(task->tid, &registers);
    if (error != 0) {
        return error;
    }
    uint32_t instruction = 0;
    error = ReadRemoteBytes(task->tgid, task->tid,
                            static_cast<uintptr_t>(registers.pc),
                            &instruction, sizeof(instruction));
    bool advance_pc = error == 0 &&
                      instruction == kSelectiveCommitBrkInstruction;
    if (!advance_pc && registers.pc >= sizeof(instruction)) {
        instruction = 0;
        error = ReadRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(registers.pc - sizeof(instruction)),
                &instruction, sizeof(instruction));
        if (error == 0 && instruction == kSelectiveCommitBrkInstruction) {
            task->pending_signal = 0;
            return 0;
        }
    }
    if (!advance_pc || registers.pc > UINT64_MAX - sizeof(instruction)) {
        return error != 0 ? error : EPROTO;
    }
    registers.pc += sizeof(instruction);
    error = hookself::arch::WriteRegisters(task->tid, &registers);
    if (error != 0) {
        return error;
    }
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || verified.pc != registers.pc) {
        return error != 0 ? error : EIO;
    }
    task->pending_signal = 0;
    return 0;
}

void PrepareTasksForSelectiveCont(TracerContext* context) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr) {
            continue;
        }
        hookself::tracer::ClearActiveSyscall(task);
        task->syscall_phase = TaskSyscallPhase::kExpectEntry;
        task->resume_mode = TaskResumeMode::kCont;
    }
}

int CommitSelectiveRuntime(TracerContext* context) noexcept {
    if (context == nullptr || context->selective_plan == nullptr ||
        context->header == nullptr || context->control == nullptr) {
        return EINVAL;
    }
    SharedSelectiveInstall* install = &context->control->selective_install;
    const uint64_t sequence = __atomic_load_n(
            &install->sequence, __ATOMIC_ACQUIRE);
    if (sequence == 0 || install->installer_tid != context->header->bootstrap_tid ||
        install->plan_hash != context->selective_plan->syscall_set_hash ||
        install->instruction_count !=
                context->selective_plan->filter.instruction_count ||
        install->rule_count != context->selective_plan->rule_count ||
        __atomic_load_n(&install->state, __ATOMIC_ACQUIRE) !=
                static_cast<uint32_t>(
                        SharedSelectiveInstallState::kPlanReady)) {
        return EPROTO;
    }
    TaskRecord* installer = hookself::tracer::Find(
            context->tasks, install->installer_tid);
    if (installer == nullptr || installer->tgid != context->target_pid ||
        installer->life != TaskLifeState::kStopped ||
        !AllSeizedTasksStopped(*context)) {
        return ESRCH;
    }

    install->prepared_tid_count = hookself::tracer::Count(context->tasks);
    StoreSelectiveInstallState(
            install, SharedSelectiveInstallState::kWorldStopped);
    AtomicStoreState(context->control, HOOKSELF_STATE_INSTALLING_FILTER);
    if (!WriteStatusByte(context->status_write_fd, kStatusInstallReady)) {
        return EPIPE;
    }

    installer->resume_mode = TaskResumeMode::kCont;
    int error = ResumeTask(context, installer);
    if (error != 0) {
        return error;
    }
    context->selective_installer_released = true;

    const int64_t deadline =
            hookself::platform::RawNowMs() + kAttachTimeoutMs;
    for (;;) {
        int status = 0;
        const long waited = hookself::platform::RawWait4(
                -1, &status, kWaitWall | WNOHANG);
        if (waited < 0) {
            error = RawError(waited);
            if (error == EINTR) {
                continue;
            }
            return error;
        }
        if (waited == 0) {
            const int64_t now = hookself::platform::RawNowMs();
            if (now < 0 || now >= deadline) {
                return ETIMEDOUT;
            }
            hookself::platform::RawSleepOneMillisecond();
            continue;
        }

        TaskRecord* stopped = nullptr;
        StopEvent event{};
        error = ApplyWaitStatus(
                context, static_cast<pid_t>(waited), status, &stopped, &event);
        if (error != 0) {
            return error;
        }
        if (stopped == nullptr || stopped->tid != install->installer_tid) {
            return EPROTO;
        }
        if (event.kind == StopEventKind::kSignalDelivery &&
            event.signal != SIGTRAP) {
            error = ResumeTask(context, stopped);
            if (error != 0) {
                return error;
            }
            continue;
        }
        if (event.kind != StopEventKind::kSignalDelivery ||
            event.signal != SIGTRAP) {
            return EPROTO;
        }
        if (__atomic_load_n(&install->response_sequence,
                            __ATOMIC_ACQUIRE) != sequence) {
            return EPROTO;
        }
        error = AdvancePastSelectiveCommitTrap(stopped);
        if (error != 0) {
            return error;
        }

        const uint32_t state = __atomic_load_n(
                &install->state, __ATOMIC_ACQUIRE);
        if (state != static_cast<uint32_t>(
                             SharedSelectiveInstallState::kInstallSucceeded) ||
            install->install_errno != 0 || install->failed_tid != 0 ||
            install->filter_committed != 1U) {
            StoreSelectiveInstallState(
                    install,
                    SharedSelectiveInstallState::kAbortedPrecommit);
            __atomic_store_n(&install->ack_sequence, sequence,
                             __ATOMIC_RELEASE);
            return install->install_errno != 0 ? install->install_errno
                                               : EPROTO;
        }

        pid_t tids[hookself::tracer::kTaskTableCapacity]{};
        size_t tid_count = 0;
        error = hookself::platform::EnumerateTaskTids(
                context->target_pid, tids, hookself::tracer::Capacity(),
                &tid_count);
        if (error != 0 || tid_count != hookself::tracer::Count(context->tasks) ||
            !CurrentCoverageComplete(context, tids, tid_count)) {
            StoreSelectiveInstallState(
                    install, SharedSelectiveInstallState::kAmbiguousFatal);
            return error != 0 ? error : EPROTO;
        }
        install->verified_tid_count = static_cast<uint32_t>(tid_count);
        context->selective_mode = true;
        context->selective_passthrough = false;
        PrepareTasksForSelectiveCont(context);
        __atomic_store_n(&install->policy_enabled, 1U, __ATOMIC_RELEASE);
        StoreSelectiveInstallState(
                install, SharedSelectiveInstallState::kCommitted);
        __atomic_store_n(&install->ack_sequence, sequence, __ATOMIC_RELEASE);
        return 0;
    }
}

int RunSelectiveInstallerOwner(const SelectiveSeccompPlan& plan,
                               SharedControlPage* control) noexcept {
    if (control == nullptr) {
        return EINVAL;
    }
    SharedSelectiveInstall* install = &control->selective_install;
    const uint64_t sequence = __atomic_load_n(
            &install->sequence, __ATOMIC_ACQUIRE);
    const long tid_result = RawSyscall6(__NR_gettid);
    const bool protocol_valid =
            sequence != 0 && RawError(tid_result) == 0 &&
            tid_result == install->installer_tid &&
            install->plan_hash == plan.syscall_set_hash &&
            __atomic_load_n(&install->state, __ATOMIC_ACQUIRE) ==
                    static_cast<uint32_t>(
                            SharedSelectiveInstallState::kWorldStopped);
    if (!protocol_valid) {
        install->nnp_before = -1;
        install->nnp_errno = EPROTO;
        install->install_errno = EPROTO;
        install->failed_tid = 0;
        install->filter_committed = 0;
        StoreSelectiveInstallState(
                install, SharedSelectiveInstallState::kInstallFailed);
        __atomic_store_n(&install->response_sequence, sequence,
                         __ATOMIC_RELEASE);
        __asm__ volatile("brk #0x4853" ::: "memory");
        return EPROTO;
    }

    StoreSelectiveInstallState(
            install, SharedSelectiveInstallState::kInstallerRunning);
    errno = 0;
    const int nnp_before = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    install->nnp_before = nnp_before;
    int nnp_error = nnp_before < 0 ? errno : 0;
    if (nnp_error == 0 && nnp_before == 0 &&
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        nnp_error = errno;
    }
    if (nnp_error == 0 && nnp_before != 0 && nnp_before != 1) {
        nnp_error = EPROTO;
    }
    install->nnp_errno = nnp_error;

    int32_t failed_tid = 0;
    const int install_error = nnp_error == 0
                                      ? InstallSelectiveSeccompFilter(
                                                &plan.filter,
                                                SECCOMP_FILTER_FLAG_TSYNC,
                                                &failed_tid)
                                      : nnp_error;
    install->install_errno = install_error;
    install->failed_tid = failed_tid;
    install->filter_committed = install_error == 0 ? 1U : 0U;
    StoreSelectiveInstallState(
            install,
            install_error == 0
                    ? SharedSelectiveInstallState::kInstallSucceeded
                    : SharedSelectiveInstallState::kInstallFailed);
    __atomic_store_n(&install->response_sequence, sequence, __ATOMIC_RELEASE);
    __asm__ volatile("brk #0x4853" ::: "memory");
    return install_error;
}

[[noreturn]] void RunTracerChild(SharedSessionMapping mapping,
                                 int control_event_fd,
                                 int status_write_fd,
                                 const SelectiveSeccompPlan* selective_plan) noexcept {
    SharedControlPage* control = GetSharedControl(mapping);
    const int fd_close_error = CloseInheritedFileDescriptors(
            mapping.fd, control_event_fd, status_write_fd, control);

    TracerContext context{};
    context.mapping = mapping;
    context.header = GetSharedHeader(mapping);
    context.control = control;
    context.event_ring = GetSharedEventRing(mapping);
    context.target_pid = context.header == nullptr ? 0 : context.header->target_pid;
    context.tracer_pid = static_cast<pid_t>(RawSyscall6(__NR_getpid));
    context.control_event_fd = control_event_fd;
    context.status_write_fd = status_write_fd;
    context.selective_requested =
            control != nullptr &&
            (control->config_flags &
             HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0;
    context.selective_plan = selective_plan;

    int setup_error = fd_close_error;
    if (setup_error == 0 &&
        (!ValidateSharedSession(mapping) || context.header == nullptr ||
         context.control == nullptr || context.event_ring == nullptr)) {
        setup_error = EPROTO;
    }
    if (setup_error == 0) {
        setup_error = ValidateTargetIdentity(&context);
    }
    if (setup_error == 0) {
        // Best effort: this permits exec descendants to reopen tracer-owned
        // protected descriptors through procfs on kernels enforcing Yama.
        (void)prctl(kPrSetPtracer, context.target_pid, 0, 0, 0);
    }
    if (setup_error == 0) {
        setup_error = WaitForStartGate(&context);
    }
    if (setup_error == 0) {
        setup_error = ValidateTargetIdentity(&context);
    }
    if (setup_error == 0) {
        InitializeProtectedFdIdentities(&context);
    }
    if (setup_error != 0) {
        if (control != nullptr) {
            control->fatal_code = static_cast<int32_t>(
                    setup_error == EPROTO ? FatalStage::kSharedAbi
                                          : FatalStage::kIdentity);
            control->fatal_errno = setup_error;
            AtomicStoreState(control, HOOKSELF_STATE_FATAL);
        }
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(120);
    }

    context.signal_event_fd = CreateSignalEventFd();
    context.ptrace_options = BuildPtraceOptions(*control);

    if (context.signal_event_fd < 0) {
        RecordFatal(&context, FatalStage::kControl,
                    -context.signal_event_fd);
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(121);
    }

    if ((control->config_flags &
         (HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
          HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES)) != 0) {
        const int scratch_error = MapWritableScratch(&context);
        if (scratch_error != 0) {
            RecordFatal(&context, FatalStage::kScratchMapping, scratch_error);
            (void)WriteStatusByte(status_write_fd, kStatusFatal);
            hookself::platform::RawExit(122);
        }
    }

    const long workspace_result = RawSyscall6(
            __NR_mmap, 0, sizeof(hookself::tracer::TaskTable),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (RawError(workspace_result) != 0) {
        RecordFatal(&context, FatalStage::kWorkspace,
                    RawError(workspace_result));
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(122);
    }
    context.tasks = reinterpret_cast<hookself::tracer::TaskTable*>(
            workspace_result);
    hookself::tracer::Init(context.tasks);

    const long path_state_result = RawSyscall6(
            __NR_mmap, 0, sizeof(hookself::tracer::PathStateTable),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (RawError(path_state_result) != 0) {
        RecordFatal(&context, FatalStage::kWorkspace,
                    RawError(path_state_result));
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(122);
    }
    context.path_state =
            reinterpret_cast<hookself::tracer::PathStateTable*>(
                    path_state_result);
    hookself::tracer::InitPathState(context.path_state);
    const long pending_path_result = RawSyscall6(
            __NR_mmap, 0, sizeof(PathPendingTable),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (RawError(pending_path_result) != 0) {
        RecordFatal(&context, FatalStage::kWorkspace,
                    RawError(pending_path_result));
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(122);
    }
    context.pending_paths = reinterpret_cast<PathPendingTable*>(
            pending_path_result);

    const long proc_virtual_result = RawSyscall6(
            __NR_mmap, 0, sizeof(ProcVirtualResidentState),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (RawError(proc_virtual_result) != 0) {
        RecordFatal(&context, FatalStage::kWorkspace,
                    RawError(proc_virtual_result));
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(122);
    }
    context.proc_virtual = reinterpret_cast<ProcVirtualResidentState*>(
            proc_virtual_result);
    InitProcVirtualResidentState(context.proc_virtual);
    const int proc_virtual_init_error =
            InitializeProcVirtualHiddenRanges(&context);
    if (proc_virtual_init_error != 0) {
        RecordFatal(&context, FatalStage::kWorkspace,
                    proc_virtual_init_error);
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(122);
    }

    if ((control->config_flags & HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE) != 0U) {
        const long logical_result = RawSyscall6(
                __NR_mmap, 0, sizeof(LogicalPtraceResidentState),
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        const long rollback_result = RawSyscall6(
                __NR_mmap, 0, sizeof(LogicalPtraceResidentState),
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (RawError(logical_result) != 0 || RawError(rollback_result) != 0) {
            RecordFatal(&context, FatalStage::kWorkspace,
                        RawError(logical_result) != 0
                                ? RawError(logical_result)
                                : RawError(rollback_result));
            (void)WriteStatusByte(status_write_fd, kStatusFatal);
            hookself::platform::RawExit(122);
        }
        context.logical_ptrace = reinterpret_cast<LogicalPtraceResidentState*>(
                logical_result);
        context.logical_ptrace_rollback =
                reinterpret_cast<LogicalPtraceResidentState*>(rollback_result);
        InitLogicalPtraceResidentState(context.logical_ptrace);
        context.nested_ptrace_phase1 = true;
        context.logical_ptrace_io_context.state = context.logical_ptrace;
        context.logical_ptrace_io_context.backend_opaque = &context;
        context.logical_ptrace_io_context.may_attach = NestedPtraceMayAttach;
        context.logical_ptrace_io_context.read_memory = NestedPtraceReadMemory;
        context.logical_ptrace_io_context.write_memory = NestedPtraceWriteMemory;
        context.logical_ptrace_io_context.query_uid = NestedPtraceQueryUid;
        context.logical_ptrace_io_context.fill_rusage = NestedPtraceFillRusage;
    }

    const int attach_error = AttachAllTasks(&context);
    if (attach_error != 0) {
        RecordFatal(&context, FatalStage::kSeize, attach_error,
                    context.target_pid);
        (void)ShutdownTracer(&context);
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(123);
    }
    if (context.nested_ptrace_phase1) {
        int nested_init_error = 0;
        for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
            TaskRecord* task = hookself::tracer::At(context.tasks, slot);
            if (task == nullptr) {
                continue;
            }
            nested_init_error = RegisterNestedPtraceTask(&context, task,
                                                          nullptr);
            if (nested_init_error != 0) {
                break;
            }
        }
        if (nested_init_error != 0 ||
            !ValidateLogicalPtraceResidentState(context.logical_ptrace)) {
            RecordFatal(&context, FatalStage::kWorkspace,
                        nested_init_error != 0 ? nested_init_error : EPROTO);
            (void)ShutdownTracer(&context);
            (void)WriteStatusByte(status_write_fd, kStatusFatal);
            hookself::platform::RawExit(123);
        }
    }
    const int path_state_error = InitializeAttachedPathState(&context);
    if (path_state_error != 0) {
        RecordFatal(&context, FatalStage::kWorkspace, path_state_error,
                    context.target_pid);
        (void)ShutdownTracer(&context);
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(123);
    }
    int selective_commit_error = 0;
    if (context.selective_requested) {
        selective_commit_error = CommitSelectiveRuntime(&context);
        if (selective_commit_error != 0) {
            RecordFatal(&context, FatalStage::kSeccompCommit,
                        selective_commit_error,
                        context.header->bootstrap_tid);
            SharedSelectiveInstall* install =
                    &context.control->selective_install;
            const uint64_t sequence = __atomic_load_n(
                    &install->sequence, __ATOMIC_ACQUIRE);
            const bool confirmed_precommit_abort =
                    sequence != 0 &&
                    __atomic_load_n(&install->response_sequence,
                                    __ATOMIC_ACQUIRE) == sequence &&
                    __atomic_load_n(&install->state, __ATOMIC_ACQUIRE) ==
                            static_cast<uint32_t>(
                                    SharedSelectiveInstallState::
                                            kAbortedPrecommit) &&
                    install->filter_committed == 0U &&
                    (install->nnp_before == 1 || install->nnp_errno != 0);
            if (!context.selective_installer_released ||
                confirmed_precommit_abort) {
                (void)ShutdownTracer(&context);
            }
            (void)WriteStatusByte(status_write_fd, kStatusFatal);
            hookself::platform::RawExit(124);
        }
    } else {
        InitializeFallbackSyscallPhases(&context);
    }
    const int resume_error = ResumeAllTasks(&context);
    if (resume_error != 0) {
        RecordFatal(&context, FatalStage::kResume, resume_error,
                    context.target_pid);
        if (context.selective_mode) {
            (void)WriteStatusByte(status_write_fd, kStatusFatal);
            hookself::platform::RawExit(124);
        }
        (void)ShutdownTracer(&context);
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(124);
    }
    context.runtime_started = true;

    const HookselfRuntimeState running_state =
            context.selective_mode ? HOOKSELF_STATE_RUNNING_SELECTIVE
                                   : HOOKSELF_STATE_RUNNING_FULL_PTRACE;
    AtomicStoreState(control, running_state);
    EmitLifecycle(&context, running_state);
    if (!WriteStatusByte(status_write_fd, kStatusReady)) {
        RecordFatal(&context, FatalStage::kControl, EPIPE);
        if (context.selective_mode) {
            hookself::platform::RawExit(125);
        }
        (void)ShutdownTracer(&context);
        hookself::platform::RawExit(125);
    }

    const int loop_error = WaitForRuntimeEvents(&context);
    if (loop_error != 0) {
        const FatalStage stage =
                context.last_failure_stage == FatalStage::kNone
                        ? FatalStage::kWait
                        : context.last_failure_stage;
        RecordFatal(&context, stage, loop_error,
                    context.last_failure_tid);
    }
    if (context.selective_mode && loop_error != 0) {
        (void)WriteStatusByte(status_write_fd, kStatusFatal);
        hookself::platform::RawExit(126);
    }
    const int shutdown_error = ShutdownTracer(&context);
    if (shutdown_error != 0) {
        RecordFatal(&context, FatalStage::kDetach, shutdown_error);
    }

    const bool fatal = __atomic_load_n(&control->fatal_code, __ATOMIC_ACQUIRE) != 0;
    __atomic_store_n(&control->tracer_ack_sequence,
                     context.acknowledged_command, __ATOMIC_RELEASE);
    if (!fatal) {
        AtomicStoreState(control, HOOKSELF_STATE_STOPPED);
        EmitLifecycle(&context, HOOKSELF_STATE_STOPPED);
    } else {
        AtomicStoreState(control, HOOKSELF_STATE_FATAL);
    }
    (void)WriteStatusByte(status_write_fd,
                          fatal ? kStatusFatal : kStatusStopped);
    (void)hookself::platform::RawClose(status_write_fd);
    (void)hookself::platform::RawClose(control_event_fd);
    (void)hookself::platform::RawClose(context.signal_event_fd);
    hookself::platform::RawExit(fatal ? 126 : 0);
}

