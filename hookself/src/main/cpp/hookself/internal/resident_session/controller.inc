void InitializeResidentController(ResidentSessionController* controller) noexcept {
    if (controller == nullptr) {
        return;
    }
    controller->tracer_pid = -1;
    controller->control_event_fd = -1;
    controller->status_read_fd = -1;
    controller->original_dumpable = -1;
    controller->ptracer_configured = 0;
    controller->logical_dumpable = -1;
    controller->logical_ptracer = 0;
    controller->logical_ptracer_start_time = 0;
    controller->ptrace_view_enabled = 0;
    controller->selective_committed = 0;
    controller->selective_passthrough = 0;
    ClearFdObjectIdentity(&controller->control_event_identity);
    ClearFdObjectIdentity(&controller->status_read_identity);
}

int32_t StartResidentSession(const HookselfConfig& config,
                             SharedSessionMapping* mapping,
                             ResidentSessionController* controller,
                             const int32_t* protected_fds,
                             uint32_t protected_fd_count) noexcept {
    if (mapping == nullptr || controller == nullptr ||
        !ValidateSharedSession(*mapping)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if (controller->tracer_pid > 0) {
        if (controller->selective_committed == 0 ||
            controller->selective_passthrough == 0 ||
            (config.flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) == 0 ||
            controller->control_event_fd < 0 ||
            controller->status_read_fd < 0 ||
            CheckFdObjectIdentity(controller->control_event_fd,
                                  controller->control_event_identity) != 0 ||
            CheckFdObjectIdentity(controller->status_read_fd,
                                  controller->status_read_identity) != 0) {
            return HOOKSELF_E_INVALID_STATE;
        }
        SharedControlPage* existing_control = GetSharedControl(*mapping);
        if (existing_control == nullptr) {
            return HOOKSELF_E_INTERNAL;
        }
        const long owner_result = RawSyscall6(__NR_gettid);
        if (RawError(owner_result) != 0 || owner_result <= 0 ||
            owner_result > INT32_MAX) {
            return HOOKSELF_E_INTERNAL;
        }
        __atomic_store_n(
                &existing_control->parent_command,
                EncodeParentCommand(
                        static_cast<uint32_t>(SharedCommand::kResume),
                        static_cast<pid_t>(owner_result)),
                __ATOMIC_RELEASE);
        const uint64_t sequence = __atomic_add_fetch(
                &existing_control->parent_command_sequence, 1U,
                __ATOMIC_RELEASE);
        const uint64_t wake = 1;
        ssize_t written = -1;
        do {
            written = write(controller->control_event_fd, &wake,
                            sizeof(wake));
        } while (written < 0 && errno == EINTR);
        if (written != static_cast<ssize_t>(sizeof(wake))) {
            return HOOKSELF_E_INTERNAL;
        }
        char status = 0;
        const int wait_error = WaitForStatusByte(
                controller->status_read_fd, kDefaultStopTimeoutMs, &status);
        if (wait_error != 0 || status != kStatusReady ||
            __atomic_load_n(&existing_control->tracer_ack_sequence,
                            __ATOMIC_ACQUIRE) != sequence ||
            __atomic_load_n(&existing_control->tracer_state,
                            __ATOMIC_ACQUIRE) !=
                    HOOKSELF_STATE_RUNNING_SELECTIVE ||
            __atomic_load_n(
                    &existing_control->selective_install.policy_enabled,
                    __ATOMIC_ACQUIRE) == 0U) {
            return wait_error == ETIMEDOUT ? HOOKSELF_E_BUSY
                                           : HOOKSELF_E_INTERNAL;
        }
        controller->selective_passthrough = 0;
        return HOOKSELF_OK;
    }
    const int supported = ConfigurationSupported(config);
    if (supported != HOOKSELF_OK) {
        return supported;
    }

    const bool selective_requested =
            (config.flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0;
    SelectiveSeccompPlan selective_plan{};
    if (selective_requested) {
        const int plan_error = BuildSelectiveSeccompPlan(
                &config, &selective_plan);
        if (plan_error != 0) {
            return plan_error == E2BIG ? HOOKSELF_E_CAPACITY
                   : plan_error == EOPNOTSUPP || plan_error == ENOSYS
                           ? HOOKSELF_E_UNSUPPORTED
                           : plan_error == EINVAL ||
                                             plan_error == EPROTONOSUPPORT
                                   ? HOOKSELF_E_INVALID_ARGUMENT
                                   : HOOKSELF_E_INTERNAL;
        }
    }

    const int original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (original_dumpable < 0) {
        return HOOKSELF_E_INTERNAL;
    }
    if (original_dumpable != 0 && original_dumpable != 1) {
        return HOOKSELF_E_UNSUPPORTED;
    }
    if (original_dumpable != 1 &&
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
        return HOOKSELF_E_UNSUPPORTED;
    }

    // Protected descriptors deliberately survive traced exec. Their physical
    // FD_CLOEXEC bit stays clear; the syscall view still reports CLOEXEC and
    // rejects attempts to alter or close them.
    const int control_fd = eventfd(0, EFD_NONBLOCK);
    FdObjectIdentity control_identity{};
    int status_pipe[2] = {-1, -1};
    FdObjectIdentity status_read_identity{};
    FdObjectIdentity status_write_identity{};
    if (control_fd < 0) {
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }
    if (CaptureRawFdObjectIdentity(control_fd, &control_identity) != 0) {
        (void)RawSyscall6(__NR_close, control_fd);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }
    if (pipe2(status_pipe, O_NONBLOCK) != 0) {
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }
    if (CaptureRawFdObjectIdentity(
                status_pipe[0], &status_read_identity) != 0 ||
        CaptureRawFdObjectIdentity(
                status_pipe[1], &status_write_identity) != 0) {
        (void)RawSyscall6(__NR_close, status_pipe[0]);
        (void)RawSyscall6(__NR_close, status_pipe[1]);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }

    const int32_t registry_result = SetProtectedFdRegistry(
            mapping, protected_fds, protected_fd_count);
    const int32_t control_registry_result =
            registry_result == HOOKSELF_OK
                    ? AppendProtectedFd(mapping, control_fd)
                    : registry_result;
    const int32_t status_registry_result =
            control_registry_result == HOOKSELF_OK
                    ? AppendProtectedFd(mapping, status_pipe[0])
                    : control_registry_result;
    if (status_registry_result != HOOKSELF_OK) {
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(status_pipe[1], status_write_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return status_registry_result;
    }

    SharedControlPage* control = GetSharedControl(*mapping);
    SharedHeader* header = GetSharedHeader(*mapping);
    const long start_tid_result = RawSyscall6(__NR_gettid);
    if (control == nullptr || header == nullptr ||
        RawError(start_tid_result) != 0 || start_tid_result <= 0 ||
        start_tid_result > INT32_MAX) {
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(status_pipe[1], status_write_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }
    header->bootstrap_tid = static_cast<int32_t>(start_tid_result);
    control->close_range_capabilities = ProbeCloseRangeCapabilities();
    control->ptrace_view_dumpable = original_dumpable;
    control->ptrace_view_ptracer = 0;
    control->ptrace_view_ptracer_start_time = 0;
    control->ptrace_view_flags =
            (config.flags & HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) != 0
                    ? kPtraceViewInitialized
                    : 0U;
    __atomic_store_n(
            &control->fd_operation.state,
            static_cast<uint32_t>(SharedFdOperationState::kIdle),
            __ATOMIC_RELEASE);
    __atomic_store_n(&control->internal_bypass_active, 0U,
                     __ATOMIC_RELEASE);
    control->internal_bypass_tid = 0;
    control->internal_bypass_fd = -1;
    __atomic_store_n(&control->log_bypass_active, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(&control->log_bypass_tid, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_bypass_active, 0U,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&control->teardown_bypass_tid, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_bypass_fd, -1, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_frozen, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(&control->teardown_release, 0U, __ATOMIC_RELEASE);
    control->fatal_code = 0;
    control->fatal_errno = 0;
    control->fatal_tid = 0;
    control->parent_command = static_cast<uint64_t>(SharedCommand::kNone);
    control->parent_command_sequence = 0;
    control->tracer_ack_sequence = 0;
    control->tracked_tasks = 0;
    SharedSelectiveInstall* install = &control->selective_install;
    *install = {};
    if (selective_requested) {
        install->sequence = 1;
        install->plan_hash = selective_plan.syscall_set_hash;
        install->rule_generation = control->published_generation;
        install->installer_tid = header->bootstrap_tid;
        install->instruction_count =
                selective_plan.filter.instruction_count;
        install->rule_count = selective_plan.rule_count;
        install->nnp_before = -1;
        StoreSelectiveInstallState(
                install, SharedSelectiveInstallState::kPlanReady);
    }
    AtomicStoreState(control, HOOKSELF_STATE_STARTING);

    sigset_t previous_signal_mask{};
    bool signal_mask_changed = false;
    if (selective_requested) {
        sigset_t blocked_signals{};
        if (sigfillset(&blocked_signals) != 0 ||
            sigprocmask(SIG_SETMASK, &blocked_signals,
                        &previous_signal_mask) != 0) {
            (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
            (void)CloseOwnedDescriptor(status_pipe[1], status_write_identity);
            (void)CloseOwnedDescriptor(control_fd, control_identity);
            (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
            return HOOKSELF_E_INTERNAL;
        }
        signal_mask_changed = true;
    }

    const long clone_result = RawSyscall6(__NR_clone, SIGCHLD, 0, 0, 0, 0);
    const pid_t child_pid = RawError(clone_result) == 0
                                    ? static_cast<pid_t>(clone_result)
                                    : -1;
    if (child_pid == 0) {
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        RunTracerChild(*mapping, control_fd, status_pipe[1],
                       selective_requested ? &selective_plan : nullptr);
    }
    (void)CloseOwnedDescriptor(status_pipe[1], status_write_identity);
    if (child_pid < 0) {
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        if (signal_mask_changed) {
            (void)sigprocmask(SIG_SETMASK, &previous_signal_mask, nullptr);
        }
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        AtomicStoreState(control, HOOKSELF_STATE_FATAL);
        return HOOKSELF_E_INTERNAL;
    }

    int ptracer_configured = 0;
    if (prctl(kPrSetPtracer, child_pid, 0, 0, 0) == 0) {
        ptracer_configured = 1;
    }
    const uint64_t gate = 1;
    if (write(control_fd, &gate, sizeof(gate)) != static_cast<ssize_t>(sizeof(gate))) {
        (void)ReapTracer(child_pid, true, kReapTimeoutMs);
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        if (ptracer_configured != 0) {
            (void)prctl(kPrSetPtracer, 0, 0, 0, 0);
        }
        if (signal_mask_changed) {
            (void)sigprocmask(SIG_SETMASK, &previous_signal_mask, nullptr);
        }
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }

    char child_status = 0;
    int wait_error = WaitForStatusByte(status_pipe[0], 12000, &child_status);
    int installer_error = 0;
    if (selective_requested && wait_error == 0 &&
        child_status == kStatusInstallReady) {
        installer_error = RunSelectiveInstallerOwner(
                selective_plan, control);
        child_status = 0;
        wait_error = WaitForStatusByte(
                status_pipe[0], 12000, &child_status);
    }
    const bool selective_commit_verified =
            !selective_requested ||
            (__atomic_load_n(&install->ack_sequence, __ATOMIC_ACQUIRE) ==
                     install->sequence &&
             __atomic_load_n(&install->state, __ATOMIC_ACQUIRE) ==
                     static_cast<uint32_t>(
                             SharedSelectiveInstallState::kCommitted) &&
             __atomic_load_n(&install->policy_enabled, __ATOMIC_ACQUIRE) ==
                     1U &&
             install->filter_committed == 1U);
    if (wait_error != 0 || child_status != kStatusReady ||
        !selective_commit_verified) {
        int reap_error = ReapTracer(
                child_pid, wait_error != 0, kReapTimeoutMs);
        if (reap_error == ETIMEDOUT) {
            reap_error = ReapTracer(child_pid, true, kReapTimeoutMs);
        }
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        if (ptracer_configured != 0) {
            (void)prctl(kPrSetPtracer, 0, 0, 0, 0);
        }
        if (signal_mask_changed) {
            (void)sigprocmask(SIG_SETMASK, &previous_signal_mask, nullptr);
        }
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        if (reap_error != 0) {
            return HOOKSELF_E_INTERNAL;
        }
        return wait_error == ETIMEDOUT ? HOOKSELF_E_BUSY
               : installer_error == E2BIG ? HOOKSELF_E_CAPACITY
                                          : HOOKSELF_E_UNSUPPORTED;
    }

    if (signal_mask_changed &&
        sigprocmask(SIG_SETMASK, &previous_signal_mask, nullptr) != 0) {
        (void)ReapTracer(child_pid, true, kReapTimeoutMs);
        (void)CloseOwnedDescriptor(status_pipe[0], status_read_identity);
        (void)CloseOwnedDescriptor(control_fd, control_identity);
        (void)prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0);
        return HOOKSELF_E_INTERNAL;
    }

    controller->tracer_pid = child_pid;
    controller->control_event_fd = control_fd;
    controller->status_read_fd = status_pipe[0];
    controller->control_event_identity = control_identity;
    controller->status_read_identity = status_read_identity;
    controller->original_dumpable = original_dumpable;
    controller->ptracer_configured = ptracer_configured;
    controller->logical_dumpable = original_dumpable;
    controller->logical_ptracer = 0;
    controller->logical_ptracer_start_time = 0;
    controller->ptrace_view_enabled =
            (config.flags & HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) != 0 ? 1 : 0;
    controller->selective_committed = selective_requested ? 1 : 0;
    controller->selective_passthrough = 0;
    return HOOKSELF_OK;
}

int32_t StopResidentSession(SharedSessionMapping* mapping,
                            ResidentSessionController* controller,
                            uint32_t timeout_ms) noexcept {
    if (mapping == nullptr || controller == nullptr ||
        controller->tracer_pid <= 0 || controller->control_event_fd < 0 ||
        CheckFdObjectIdentity(controller->control_event_fd,
                              controller->control_event_identity) != 0 ||
        (controller->status_read_fd >= 0 &&
         CheckFdObjectIdentity(controller->status_read_fd,
                               controller->status_read_identity) != 0)) {
        return HOOKSELF_E_INVALID_STATE;
    }
    SharedControlPage* control = GetSharedControl(*mapping);
    if (control == nullptr) {
        return HOOKSELF_E_INTERNAL;
    }
    const long owner_result = RawSyscall6(__NR_gettid);
    if (RawError(owner_result) != 0 || owner_result <= 0 ||
        owner_result > INT32_MAX) {
        return HOOKSELF_E_INTERNAL;
    }
    const pid_t stop_owner_tid = static_cast<pid_t>(owner_result);
    __atomic_store_n(&control->parent_command,
                     EncodeParentCommand(
                             static_cast<uint32_t>(SharedCommand::kStop),
                             stop_owner_tid),
                     __ATOMIC_RELEASE);
    const uint64_t command_sequence = __atomic_add_fetch(
            &control->parent_command_sequence, 1U, __ATOMIC_RELEASE);
    const uint64_t wake = 1;
    (void)write(controller->control_event_fd, &wake, sizeof(wake));

    char child_status = 0;
    const uint32_t effective_timeout = timeout_ms == 0
                                               ? kDefaultStopTimeoutMs
                                               : timeout_ms;
    int wait_error = WaitForStatusByte(
            controller->status_read_fd, effective_timeout, &child_status);
    if (controller->ptrace_view_enabled != 0) {
        controller->logical_dumpable = __atomic_load_n(
                &control->ptrace_view_dumpable, __ATOMIC_ACQUIRE);
        controller->logical_ptracer = __atomic_load_n(
                &control->ptrace_view_ptracer, __ATOMIC_ACQUIRE);
        controller->logical_ptracer_start_time = __atomic_load_n(
                &control->ptrace_view_ptracer_start_time,
                __ATOMIC_ACQUIRE);
    }
    if (controller->selective_committed != 0) {
        const bool stopped =
                wait_error == 0 && child_status == kStatusStopped &&
                __atomic_load_n(&control->tracer_ack_sequence,
                                __ATOMIC_ACQUIRE) == command_sequence &&
                __atomic_load_n(&control->tracer_state,
                                __ATOMIC_ACQUIRE) ==
                        HOOKSELF_STATE_STOPPED &&
                __atomic_load_n(
                        &control->selective_install.policy_enabled,
                        __ATOMIC_ACQUIRE) == 0U;
        if (stopped) {
            controller->selective_passthrough = 1;
            return HOOKSELF_OK;
        }
        return wait_error == ETIMEDOUT ? HOOKSELF_E_BUSY
                                       : HOOKSELF_E_INTERNAL;
    }
    int restore_error = 0;
    const bool commit_ready =
            wait_error == 0 && child_status == kStatusCommitReady;
    if (commit_ready) {
        restore_error = RestoreDumpable(controller);
        __atomic_store_n(
                &control->parent_command,
                EncodeParentCommand(
                        restore_error == 0
                                ? kParentCommandShutdownCommit
                                : kParentCommandShutdownAbort,
                        stop_owner_tid),
                __ATOMIC_RELEASE);
        (void)__atomic_add_fetch(&control->parent_command_sequence, 1U,
                                 __ATOMIC_RELEASE);
        const uint64_t commit_wake = 1;
        ssize_t wake_bytes = -1;
        do {
            wake_bytes = write(controller->control_event_fd, &commit_wake,
                               sizeof(commit_wake));
        } while (wake_bytes < 0 && errno == EINTR);
        if (wake_bytes != static_cast<ssize_t>(sizeof(commit_wake))) {
            wait_error = wake_bytes < 0 ? errno : EIO;
        } else {
            child_status = 0;
            wait_error = WaitForStatusByte(
                    controller->status_read_fd, effective_timeout,
                    &child_status);
        }
    }
    const bool force_kill = wait_error != 0;
    int reap_error = ReapTracer(
            controller->tracer_pid, force_kill, kReapTimeoutMs);
    if (reap_error == ETIMEDOUT) {
        reap_error = ReapTracer(controller->tracer_pid, true, kReapTimeoutMs);
    }
    const bool stopped = wait_error == 0 && child_status == kStatusStopped;
    CloseControllerFds(controller);
    if (!commit_ready) {
        restore_error = RestoreDumpable(controller);
    }
    if (reap_error == 0) {
        controller->tracer_pid = -1;
    }
    if (restore_error == 0) {
        controller->original_dumpable = -1;
        controller->ptracer_configured = 0;
    }
    if (reap_error == 0 && restore_error == 0) {
        InitializeResidentController(controller);
    }
    return stopped && reap_error == 0 && restore_error == 0 ? HOOKSELF_OK
                   : wait_error == ETIMEDOUT ? HOOKSELF_E_BUSY
                                              : HOOKSELF_E_INTERNAL;
}

void ForceDestroyResidentSession(SharedSessionMapping* mapping,
                                 ResidentSessionController* controller) noexcept {
    if (controller == nullptr) {
        return;
    }
    if (controller->selective_committed != 0) {
        if (controller->tracer_pid <= 0 || mapping == nullptr) {
            hookself::platform::RawExit(127);
        }
        if (controller->selective_passthrough == 0) {
            const int32_t stop_result = StopResidentSession(
                    mapping, controller, kDefaultStopTimeoutMs);
            if (stop_result != HOOKSELF_OK ||
                controller->selective_passthrough == 0) {
                hookself::platform::RawExit(127);
            }
        }
        return;
    }
    if (controller->tracer_pid > 0 && mapping != nullptr) {
        const int32_t result = StopResidentSession(
                mapping, controller, kDefaultStopTimeoutMs);
        if (result == HOOKSELF_OK) {
            return;
        }
    }
    (void)ReapTracer(controller->tracer_pid, true, kReapTimeoutMs);
    CloseControllerFds(controller);
    (void)RestoreDumpable(controller);
    InitializeResidentController(controller);
}

int32_t BeginResidentTeardownFreeze(SharedSessionMapping* mapping,
                                    ResidentSessionController* controller,
                                    uint32_t timeout_ms) noexcept {
    if (mapping == nullptr || controller == nullptr ||
        controller->selective_committed == 0 ||
        controller->selective_passthrough == 0 ||
        controller->tracer_pid <= 0 || controller->control_event_fd < 0 ||
        controller->status_read_fd < 0 ||
        CheckFdObjectIdentity(controller->control_event_fd,
                              controller->control_event_identity) != 0 ||
        CheckFdObjectIdentity(controller->status_read_fd,
                              controller->status_read_identity) != 0) {
        return HOOKSELF_E_INVALID_STATE;
    }
    SharedControlPage* const control = GetSharedControl(*mapping);
    const long owner_result = RawSyscall6(__NR_gettid);
    if (control == nullptr || RawError(owner_result) != 0 ||
        owner_result <= 0 || owner_result > INT32_MAX ||
        __atomic_load_n(&control->selective_install.policy_enabled,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->protected_fd_count,
                        __ATOMIC_ACQUIRE) == 0U) {
        return HOOKSELF_E_INTERNAL;
    }
    const pid_t owner_tid = static_cast<pid_t>(owner_result);
    __atomic_store_n(&control->teardown_bypass_tid, owner_tid,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_bypass_fd, -1, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_release, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(&control->teardown_frozen, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(
            &control->parent_command,
            EncodeParentCommand(
                    static_cast<uint32_t>(SharedCommand::kTeardownFreeze),
                    owner_tid),
            __ATOMIC_RELEASE);
    const uint64_t sequence = __atomic_add_fetch(
            &control->parent_command_sequence, 1U, __ATOMIC_RELEASE);
    const uint64_t wake = 1U;
    ssize_t wake_bytes = -1;
    do {
        wake_bytes = write(controller->control_event_fd, &wake, sizeof(wake));
    } while (wake_bytes < 0 && errno == EINTR);
    if (wake_bytes != static_cast<ssize_t>(sizeof(wake))) {
        return HOOKSELF_E_INTERNAL;
    }

    char status = 0;
    const uint32_t effective_timeout = timeout_ms == 0U
                                               ? kDefaultStopTimeoutMs
                                               : timeout_ms;
    const int wait_error = WaitForStatusByte(
            controller->status_read_fd, effective_timeout, &status);
    if (wait_error != 0) {
        return wait_error == ETIMEDOUT ? HOOKSELF_E_BUSY
                                       : HOOKSELF_E_INTERNAL;
    }
    const bool frozen = status == kStatusTeardownFrozen &&
            __atomic_load_n(&control->tracer_ack_sequence,
                            __ATOMIC_ACQUIRE) == sequence &&
            __atomic_load_n(&control->teardown_frozen,
                            __ATOMIC_ACQUIRE) == 1U &&
            __atomic_load_n(&control->teardown_release,
                            __ATOMIC_ACQUIRE) == 0U;
    if (!frozen || RestoreDumpable(controller) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    controller->original_dumpable = -1;
    controller->ptracer_configured = 0;
    return HOOKSELF_OK;
}

int CloseResidentTeardownFd(SharedSessionMapping* mapping, int fd,
                            const FdObjectIdentity& identity) noexcept {
    if (mapping == nullptr || fd < 0) {
        return EINVAL;
    }
    SharedControlPage* const control = GetSharedControl(*mapping);
    const long owner_result = RawSyscall6(__NR_gettid);
    if (control == nullptr || RawError(owner_result) != 0 ||
        owner_result <= 0 || owner_result > INT32_MAX ||
        __atomic_load_n(&control->teardown_bypass_tid,
                        __ATOMIC_RELAXED) != owner_result ||
        __atomic_load_n(&control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_frozen,
                        __ATOMIC_ACQUIRE) != 1U ||
        __atomic_load_n(&control->teardown_release,
                        __ATOMIC_ACQUIRE) != 0U ||
        !ProtectedFdRegistered(control, fd)) {
        return EPROTO;
    }
    const int identity_error = CheckFdObjectIdentity(fd, identity);
    if (identity_error == ESTALE) {
        return RemoveProtectedFd(control, fd);
    }
    if (identity_error != 0) {
        return identity_error;
    }
    __atomic_store_n(&control->teardown_bypass_fd, fd, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_bypass_active, 1U,
                     __ATOMIC_RELEASE);
    const int close_error = CloseFdObject(fd, identity);
    __atomic_store_n(&control->teardown_bypass_active, 0U,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&control->teardown_bypass_fd, -1,
                     __ATOMIC_RELAXED);
    return close_error == 0 ? RemoveProtectedFd(control, fd) : close_error;
}

int32_t ReleaseResidentTeardown(SharedSessionMapping* mapping,
                                uint32_t timeout_ms) noexcept {
    if (mapping == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    SharedControlPage* const control = GetSharedControl(*mapping);
    const long owner_result = RawSyscall6(__NR_gettid);
    if (control == nullptr || RawError(owner_result) != 0 ||
        owner_result <= 0 || owner_result > INT32_MAX ||
        __atomic_load_n(&control->teardown_bypass_tid,
                        __ATOMIC_RELAXED) != owner_result ||
        __atomic_load_n(&control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_bypass_fd,
                        __ATOMIC_RELAXED) != -1 ||
        __atomic_load_n(&control->protected_fd_count,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_frozen,
                        __ATOMIC_ACQUIRE) != 1U) {
        return HOOKSELF_E_INTERNAL;
    }
    const int64_t started = hookself::platform::RawNowMs();
    if (started < 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const int64_t deadline = started + static_cast<int64_t>(
            timeout_ms == 0U ? kDefaultStopTimeoutMs : timeout_ms);
    __atomic_store_n(&control->teardown_release, 1U, __ATOMIC_RELEASE);
    while (__atomic_load_n(&control->teardown_frozen,
                           __ATOMIC_ACQUIRE) != 0U) {
        const int64_t now = hookself::platform::RawNowMs();
        if (now < 0 || now >= deadline) {
            return HOOKSELF_E_BUSY;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
    return __atomic_load_n(&control->teardown_release,
                           __ATOMIC_ACQUIRE) == 0U
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INTERNAL;
}

void FinishResidentTeardown(SharedSessionMapping* mapping) noexcept {
    if (mapping == nullptr) {
        return;
    }
    SharedControlPage* const control = GetSharedControl(*mapping);
    if (control == nullptr) {
        return;
    }
    if (__atomic_load_n(&control->protected_fd_count,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_frozen,
                        __ATOMIC_ACQUIRE) != 0U ||
        __atomic_load_n(&control->teardown_release,
                        __ATOMIC_ACQUIRE) != 0U) {
        return;
    }
    __atomic_store_n(&control->teardown_bypass_active, 0U,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&control->teardown_bypass_tid, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&control->teardown_bypass_fd, -1,
                     __ATOMIC_RELAXED);
}

