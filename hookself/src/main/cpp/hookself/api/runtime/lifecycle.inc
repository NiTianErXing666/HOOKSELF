extern "C" int32_t hookself_create(const HookselfConfig* config,
                                      HookselfRuntime** runtime) {
    RuntimeApiBypassGuard bypass(false);
    if (!bypass.ok()) {
        return HOOKSELF_E_BUSY;
    }
    if (runtime == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *runtime = nullptr;
    const int32_t validation = hookself_validate_config(config);
    if (validation != HOOKSELF_OK) {
        return validation;
    }

    auto* created = new (std::nothrow) HookselfRuntime{};
    if (created == nullptr) {
        return HOOKSELF_E_NO_MEMORY;
    }
    const int runtime_mutex_error = pthread_mutex_init(&created->mutex, nullptr);
    if (runtime_mutex_error != 0) {
        LogCreateFailure("runtime-mutex", runtime_mutex_error);
        delete created;
        return HOOKSELF_E_INTERNAL;
    }
    const int event_reader_mutex_error =
            pthread_mutex_init(&created->event_reader_mutex, nullptr);
    if (event_reader_mutex_error != 0) {
        LogCreateFailure("event-reader-mutex", event_reader_mutex_error);
        pthread_mutex_destroy(&created->mutex);
        delete created;
        return HOOKSELF_E_INTERNAL;
    }
    const int lifecycle_condition_error =
            pthread_cond_init(&created->lifecycle_cv, nullptr);
    if (lifecycle_condition_error != 0) {
        LogCreateFailure("lifecycle-condition", lifecycle_condition_error);
        pthread_mutex_destroy(&created->event_reader_mutex);
        pthread_mutex_destroy(&created->mutex);
        delete created;
        return HOOKSELF_E_INTERNAL;
    }
    hookself::internal::InitializeVirtualBackingSession(
            &created->virtual_backing_session);
    for (uint32_t i = 0; i < HOOKSELF_MAX_VIRTUAL_FILES; ++i) {
        hookself::internal::InitializeVirtualFileBacking(
                &created->virtual_backings[i]);
        created->virtual_file_fds[i] = -1;
        created->virtual_provider_source_fds[i] = -1;
        hookself::internal::ClearFdObjectIdentity(
                &created->virtual_provider_source_identities[i]);
    }
    if (!RegisterRuntime(created)) {
        LogCreateFailure("runtime-registry", EBUSY);
        FinalizeRuntime(created, nullptr);
        return HOOKSELF_E_INTERNAL;
    }

    created->state = HOOKSELF_STATE_CONFIGURED;
    created->config = *config;
    const int32_t target_pid = static_cast<int32_t>(getpid());
    created->target_pid = target_pid;
    const int32_t bootstrap_tid = static_cast<int32_t>(syscall(__NR_gettid));
    bool needs_provider_scratch = false;
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        needs_provider_scratch |=
                config->virtual_files[i].provider >=
                HOOKSELF_VFILE_PROC_STATUS;
    }
    if (needs_provider_scratch) {
        void* scratch = mmap(nullptr, HOOKSELF_MAX_VIRTUAL_FILE_SIZE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (scratch == MAP_FAILED) {
            hookself_destroy(created);
            return HOOKSELF_E_NO_MEMORY;
        }
        created->virtual_provider_scratch = static_cast<uint8_t*>(scratch);
        created->virtual_provider_scratch_size =
                HOOKSELF_MAX_VIRTUAL_FILE_SIZE;
    }
    for (uint32_t i = 0; i < config->path_rule_count; ++i) {
        created->path_rules[i] = config->path_rules[i];
    }
    created->config.path_rules = created->path_rules;
    for (uint32_t i = 0; i < config->syscall_rule_count; ++i) {
        created->syscall_rules[i] = config->syscall_rules[i];
    }
    created->config.syscall_rules = created->syscall_rules;
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        const HookselfVirtualFile& source = config->virtual_files[i];
        created->virtual_files[i] = source;
        created->virtual_files[i].initial_content = nullptr;
        const bool provider = source.provider >= HOOKSELF_VFILE_PROC_STATUS;
        if (provider) {
            const bool configured_content =
                    source.provider == HOOKSELF_VFILE_SELINUX_CONTEXT &&
                    source.initial_content_size != 0;
            created->virtual_provider_uses_configured_content[i] =
                    configured_content ? 1U : 0U;
            if (!configured_content) {
                const int source_error =
                        hookself::internal::OpenVirtualFileProviderSource(
                                source.provider, target_pid,
                                &created->virtual_provider_source_fds[i]);
                if (source_error != 0) {
                    hookself_destroy(created);
                    return HOOKSELF_E_UNSUPPORTED;
                }
                if (hookself::internal::CaptureRawFdObjectIdentity(
                            created->virtual_provider_source_fds[i],
                            &created->virtual_provider_source_identities[i]) !=
                    0) {
                    (void)syscall(
                            __NR_close,
                            created->virtual_provider_source_fds[i]);
                    created->virtual_provider_source_fds[i] = -1;
                    hookself_destroy(created);
                    return HOOKSELF_E_INTERNAL;
                }
            }
            auto* generated = created->virtual_provider_scratch;
            hookself::internal::VirtualFileHiddenRange
                    hidden_ranges[HOOKSELF_MAX_VIRTUAL_FILES + 32]{};
            const size_t hidden_range_count = BuildProviderHiddenRanges(
                    created, hidden_ranges,
                    HOOKSELF_MAX_VIRTUAL_FILES + 32);
            size_t generated_size = 0;
            const int generate_error =
                    hookself::internal::GenerateVirtualFileProviderSnapshot(
                            source.provider, source.flags,
                            created->virtual_provider_source_fds[i],
                            configured_content ? source.initial_content : nullptr,
                            configured_content ? source.initial_content_size : 0,
                            hidden_ranges, hidden_range_count,
                            generated, HOOKSELF_MAX_VIRTUAL_FILE_SIZE,
                            &generated_size);
            if (generate_error != 0 ||
                generated_size > HOOKSELF_MAX_VIRTUAL_FILE_SIZE) {
                hookself_destroy(created);
                return generate_error == ENOMEM
                               ? HOOKSELF_E_NO_MEMORY
                               : (generate_error == EFBIG ||
                                  generate_error == EOVERFLOW)
                                         ? HOOKSELF_E_CAPACITY
                                         : HOOKSELF_E_INTERNAL;
            }
            if (generated_size != 0) {
                created->virtual_contents[i] =
                        new (std::nothrow) uint8_t[generated_size];
                if (created->virtual_contents[i] == nullptr) {
                    hookself_destroy(created);
                    return HOOKSELF_E_NO_MEMORY;
                }
                for (size_t j = 0; j < generated_size; ++j) {
                    created->virtual_contents[i][j] = generated[j];
                }
                created->virtual_files[i].initial_content =
                        created->virtual_contents[i];
            }
            created->virtual_files[i].initial_content_size =
                    static_cast<uint32_t>(generated_size);
        } else if (source.initial_content_size != 0) {
            const uint32_t size = source.initial_content_size;
            created->virtual_contents[i] = new (std::nothrow) uint8_t[size];
            if (created->virtual_contents[i] == nullptr) {
                hookself_destroy(created);
                return HOOKSELF_E_NO_MEMORY;
            }
            for (uint32_t j = 0; j < size; ++j) {
                created->virtual_contents[i][j] = source.initial_content[j];
            }
            created->virtual_files[i].initial_content = created->virtual_contents[i];
        }
    }
    created->config.virtual_files = created->virtual_files;
    uint64_t target_start_time = 0;
    const int start_time_error = hookself::platform::ReadProcessStartTime(
            target_pid, &target_start_time);
    if (start_time_error != 0) {
        LogCreateFailure("process-start-time", start_time_error);
        hookself_destroy(created);
        return HOOKSELF_E_INTERNAL;
    }
    const uint64_t nonce = GenerateSessionNonce(created, target_pid, bootstrap_tid);
    if (config->virtual_file_count != 0) {
        const int backing_session_error =
                hookself::internal::CreateVirtualBackingSession(
                        created->config.virtual_backing_dir, nonce,
                        &created->virtual_backing_session);
        if (backing_session_error != 0) {
            LogCreateFailure("virtual-backing-session", backing_session_error);
            hookself_destroy(created);
            return backing_session_error == ENOMEM ? HOOKSELF_E_NO_MEMORY
                                                   : HOOKSELF_E_INTERNAL;
        }
    }
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        const int backing_error = hookself::internal::CreateVirtualFileBacking(
                created->virtual_files[i].initial_content,
                created->virtual_files[i].initial_content_size,
                created->virtual_files[i].provider,
                created->virtual_files[i].mode,
                created->virtual_files[i].file_id,
                &created->virtual_backing_session,
                &created->virtual_backings[i]);
        if (backing_error != 0) {
            LogCreateFailure("virtual-backing", backing_error);
            hookself_destroy(created);
            return backing_error == ENOMEM ? HOOKSELF_E_NO_MEMORY
                                           : HOOKSELF_E_INTERNAL;
        }
        created->virtual_file_fds[i] =
                created->virtual_backings[i].stable_fd;
    }
    const char* virtual_backing_paths[HOOKSELF_MAX_VIRTUAL_FILES]{};
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        virtual_backing_paths[i] = created->virtual_backings[i].backing_path;
    }
    const int32_t shared_result = hookself::internal::CreateSharedSession(
            created->config, target_pid, bootstrap_tid, target_start_time, nonce,
            &created->shared_session, created->virtual_file_fds,
            virtual_backing_paths);
    if (shared_result != HOOKSELF_OK) {
        LogCreateFailure("shared-session", shared_result);
        hookself_destroy(created);
        return NormalizeSharedSessionResult(shared_result);
    }
    created->event_ring =
            hookself::internal::GetSharedEventRing(created->shared_session);
    if (created->event_ring == nullptr ||
        !hookself::internal::ValidateSharedSession(created->shared_session)) {
        LogCreateFailure("shared-validation", EPROTO);
        hookself_destroy(created);
        return HOOKSELF_E_INTERNAL;
    }
    bool provider_refreshed = false;
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        if (created->virtual_files[i].provider <
            HOOKSELF_VFILE_PROC_STATUS) {
            continue;
        }
        const int32_t refresh_result =
                RefreshVirtualFileProviderLocked(created, i);
        if (refresh_result != HOOKSELF_OK) {
            hookself_destroy(created);
            return refresh_result;
        }
        provider_refreshed = true;
    }
    if (provider_refreshed) {
        const int32_t publish_result = hookself::internal::PublishSharedConfig(
                created->config, &created->shared_session,
                created->virtual_file_fds, virtual_backing_paths);
        if (publish_result != HOOKSELF_OK) {
            hookself_destroy(created);
            return publish_result;
        }
    }
    created->stats.struct_size = sizeof(HookselfStats);
    created->stats.state = HOOKSELF_STATE_CONFIGURED;
    *runtime = created;
    return HOOKSELF_OK;
}

extern "C" void hookself_destroy(HookselfRuntime* runtime) {
    if (runtime == nullptr) {
        return;
    }
    RuntimeApiBypassGuard bypass(true);
    if (!bypass.ok()) {
        return;
    }
    const bool reentrant = ThreadHasRuntimeCall(runtime);
    if (pthread_mutex_lock(&gRuntimeRegistryMutex) != 0) {
        return;
    }
    HookselfRuntime** link = &gRuntimeRegistryHead;
    while (*link != nullptr && *link != runtime) {
        link = &(*link)->registry_next;
    }
    if (*link == nullptr) {
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return;
    }
    if (pthread_mutex_lock(&runtime->mutex) != 0) {
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return;
    }
    *link = runtime->registry_next;
    runtime->registry_next = nullptr;
    hookself::internal::SharedControlPage* const runtime_control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    uint32_t expected_retire_owner = kBypassRetireOwnerNone;
    const bool destroy_owns_retire = __atomic_compare_exchange_n(
            &runtime->bypass_retire_owner, &expected_retire_owner,
            kBypassRetireOwnerDestroy, false, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);
    if (!destroy_owns_retire &&
        expected_retire_owner == kBypassRetireOwnerCall) {
        bypass.ReleasePinnedControl(runtime_control);
    }
    __atomic_store_n(&runtime->closing, 1U, __ATOMIC_RELEASE);
    if (reentrant) {
        runtime->deferred_destroy = 1;
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        pthread_mutex_unlock(&runtime->mutex);
        return;
    }
    if (runtime->destroy_waiter != 0) {
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        pthread_mutex_unlock(&runtime->mutex);
        return;
    }
    runtime->destroy_waiter = 1;
    pthread_mutex_unlock(&gRuntimeRegistryMutex);
    while (runtime->active_calls != 0 ||
           __atomic_load_n(&runtime->bypass_retire_owner,
                           __ATOMIC_ACQUIRE) ==
                   kBypassRetireOwnerCall) {
        (void)pthread_cond_wait(&runtime->lifecycle_cv, &runtime->mutex);
    }
    pthread_mutex_unlock(&runtime->mutex);
    FinalizeRuntime(runtime, bypass.token());
}

extern "C" int32_t hookself_start(HookselfRuntime* runtime) {
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (!call.BeginBypassPublication()) {
        return HOOKSELF_E_BUSY;
    }
    pthread_mutex_lock(&runtime->mutex);
    if ((runtime->state != HOOKSELF_STATE_CONFIGURED &&
         runtime->state != HOOKSELF_STATE_STOPPED) ||
        __atomic_load_n(&runtime->bypass_retire_owner,
                        __ATOMIC_ACQUIRE) !=
                kBypassRetireOwnerNone) {
        pthread_mutex_unlock(&runtime->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    for (uint32_t i = 0; i < runtime->config.virtual_file_count; ++i) {
        const int32_t source_result = ReopenVirtualProviderSource(runtime, i);
        if (source_result != HOOKSELF_OK) {
            pthread_mutex_unlock(&runtime->mutex);
            return source_result;
        }
    }
    const bool acquired_resident_lease = runtime->resident_lease_owned == 0;
    if (acquired_resident_lease && !AcquireResidentLease(runtime)) {
        pthread_mutex_unlock(&runtime->mutex);
        return HOOKSELF_E_BUSY;
    }
    runtime->resident_lease_owned = 1;
    hookself::internal::SharedControlPage* const control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    const bool bypass_published =
            control != nullptr && PublishRuntimeApiBypassControl(control);
    if (!bypass_published || !call.ActivateBypass(control)) {
        if (bypass_published && acquired_resident_lease) {
            (void)call.ScheduleBypassRetire(control, runtime);
        }
        if (acquired_resident_lease && !bypass_published) {
            runtime->resident_lease_owned = 0;
        }
        pthread_mutex_unlock(&runtime->mutex);
        if (!bypass_published) {
            call.EndBypassPublication();
        }
        if (acquired_resident_lease && !bypass_published) {
            ReleaseResidentLease(runtime);
        }
        return HOOKSELF_E_BUSY;
    }
    call.EndBypassPublication();
    __atomic_store_n(&runtime->state, HOOKSELF_STATE_STARTING, __ATOMIC_RELEASE);
    int32_t protected_fds[hookself::internal::kMaxProtectedFds]{};
    uint32_t protected_fd_count = 0;
    int32_t protected_fd_setup_result = HOOKSELF_OK;
    protected_fds[protected_fd_count++] = runtime->shared_session.fd;
    if (runtime->config.virtual_file_count != 0) {
        if (runtime->virtual_backing_session.root_fd < 0 ||
            runtime->virtual_backing_session.session_fd < 0 ||
            hookself::internal::CheckFdObjectIdentity(
                    runtime->virtual_backing_session.root_fd,
                    runtime->virtual_backing_session.root_identity) != 0 ||
            hookself::internal::CheckFdObjectIdentity(
                    runtime->virtual_backing_session.session_fd,
                    runtime->virtual_backing_session.session_identity) != 0 ||
            protected_fd_count + 2U > hookself::internal::kMaxProtectedFds) {
            protected_fd_setup_result = HOOKSELF_E_INTERNAL;
        } else {
            protected_fds[protected_fd_count++] =
                    runtime->virtual_backing_session.root_fd;
            protected_fds[protected_fd_count++] =
                    runtime->virtual_backing_session.session_fd;
        }
    }
    for (uint32_t i = 0;
         i < runtime->config.virtual_file_count &&
         protected_fd_setup_result == HOOKSELF_OK;
         ++i) {
        if (protected_fd_count == hookself::internal::kMaxProtectedFds) {
            protected_fd_setup_result = HOOKSELF_E_CAPACITY;
            break;
        }
        protected_fds[protected_fd_count++] = runtime->virtual_file_fds[i];
        if (runtime->virtual_provider_source_fds[i] >= 0) {
            if (protected_fd_count == hookself::internal::kMaxProtectedFds) {
                protected_fd_setup_result = HOOKSELF_E_CAPACITY;
                break;
            }
            protected_fds[protected_fd_count++] =
                    runtime->virtual_provider_source_fds[i];
        }
    }
    const int32_t result = protected_fd_setup_result == HOOKSELF_OK
            ? hookself::internal::StartResidentSession(
                      runtime->config, &runtime->shared_session,
                      &runtime->resident_controller, protected_fds,
                      protected_fd_count)
            : protected_fd_setup_result;
    int32_t next_state = HOOKSELF_STATE_FATAL;
    if (result == HOOKSELF_OK) {
        next_state = (runtime->config.flags &
                      HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0
                             ? HOOKSELF_STATE_RUNNING_SELECTIVE
                             : HOOKSELF_STATE_RUNNING_FULL_PTRACE;
    } else if (result == HOOKSELF_E_NOT_IMPLEMENTED) {
        next_state = HOOKSELF_STATE_CONFIGURED;
    }
    __atomic_store_n(&runtime->state, next_state, __ATOMIC_RELEASE);
    const bool release_failed_lease =
            result != HOOKSELF_OK && acquired_resident_lease &&
            runtime->resident_controller.tracer_pid <= 0;
    if (release_failed_lease) {
        (void)call.ScheduleBypassRetire(control, runtime);
    }
    pthread_mutex_unlock(&runtime->mutex);
    return result;
}

extern "C" int32_t hookself_stop(HookselfRuntime* runtime) {
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    pthread_mutex_lock(&runtime->mutex);
    if (!IsTracingRuntimeState(runtime->state) &&
        runtime->state != HOOKSELF_STATE_FATAL) {
        pthread_mutex_unlock(&runtime->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    __atomic_store_n(&runtime->state, HOOKSELF_STATE_STOPPING, __ATOMIC_RELEASE);
    const int32_t result = hookself::internal::StopResidentSession(
            &runtime->shared_session, &runtime->resident_controller, 5000);
    __atomic_store_n(&runtime->state,
                     result == HOOKSELF_OK ? HOOKSELF_STATE_STOPPED
                                           : HOOKSELF_STATE_FATAL,
                     __ATOMIC_RELEASE);
    hookself::internal::SharedControlPage* const control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    const bool release_full_ptrace_lease =
            runtime->resident_controller.tracer_pid <= 0 &&
            runtime->resident_controller.selective_committed == 0 &&
            runtime->resident_lease_owned != 0;
    if (release_full_ptrace_lease) {
        (void)call.ScheduleBypassRetire(control, runtime);
    }
    pthread_mutex_unlock(&runtime->mutex);
    return result;
}

extern "C" int32_t hookself_get_state(const HookselfRuntime* runtime, int32_t* state) {
    if (runtime == nullptr || state == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    RuntimeCallGuard call(const_cast<HookselfRuntime*>(runtime));
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    const hookself::internal::SharedControlPage* control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    const int32_t local_state = __atomic_load_n(&runtime->state, __ATOMIC_ACQUIRE);
    if (local_state == HOOKSELF_STATE_FATAL || control == nullptr) {
        *state = local_state;
        return HOOKSELF_OK;
    }
    if (!IsTracingRuntimeState(local_state) &&
        local_state != HOOKSELF_STATE_STOPPING) {
        *state = local_state;
        return HOOKSELF_OK;
    }

    const int32_t shared_state = static_cast<int32_t>(__atomic_load_n(
            &control->tracer_state, __ATOMIC_ACQUIRE));
    bool dead = false;
    if (shared_state == HOOKSELF_STATE_RUNNING_FULL_PTRACE ||
        shared_state == HOOKSELF_STATE_RUNNING_SELECTIVE) {
        dead = ResidentTracerLooksDead(runtime, control);
    }
    const int32_t confirmed_local = __atomic_load_n(
            &runtime->state, __ATOMIC_ACQUIRE);
    *state = dead && confirmed_local == local_state
                     ? HOOKSELF_STATE_FATAL
                     : shared_state;
    return HOOKSELF_OK;
}

extern "C" int32_t hookself_get_stats(const HookselfRuntime* runtime,
                                        HookselfStats* stats) {
    if (runtime == nullptr || stats == nullptr || stats->struct_size != sizeof(HookselfStats)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    RuntimeCallGuard call(const_cast<HookselfRuntime*>(runtime));
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    *stats = runtime->stats;
    int32_t current_state = HOOKSELF_STATE_IDLE;
    (void)hookself_get_state(runtime, &current_state);
    stats->state = static_cast<uint32_t>(current_state);
    const hookself::internal::SharedControlPage* control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    if (control != nullptr) {
        stats->observed_syscalls = __atomic_load_n(
                &control->observed_syscalls, __ATOMIC_ACQUIRE);
        stats->redirected_paths = __atomic_load_n(
                &control->redirected_paths, __ATOMIC_ACQUIRE);
        stats->virtual_file_opens = __atomic_load_n(
                &control->virtual_file_opens, __ATOMIC_ACQUIRE);
        stats->internal_errors = __atomic_load_n(
                &control->internal_errors, __ATOMIC_ACQUIRE);
        stats->protected_fd_blocks = __atomic_load_n(
                &control->protected_fd_blocks, __ATOMIC_ACQUIRE);
        stats->internal_fd_operations = __atomic_load_n(
                &control->internal_fd_operations, __ATOMIC_ACQUIRE);
        stats->ptrace_view_operations = __atomic_load_n(
                &control->ptrace_view_operations, __ATOMIC_ACQUIRE);
        stats->proc_status_patches = __atomic_load_n(
                &control->proc_status_patches, __ATOMIC_ACQUIRE);
        stats->tracked_tasks = __atomic_load_n(
                &control->tracked_tasks, __ATOMIC_ACQUIRE);
        stats->fatal_code = __atomic_load_n(
                &control->fatal_code, __ATOMIC_ACQUIRE);
        stats->fatal_errno = __atomic_load_n(
                &control->fatal_errno, __ATOMIC_ACQUIRE);
        stats->fatal_tid = __atomic_load_n(
                &control->fatal_tid, __ATOMIC_ACQUIRE);
    }
    stats->emitted_events = __atomic_load_n(
            &runtime->event_ring->write_sequence, __ATOMIC_ACQUIRE);
    stats->dropped_events = hookself::internal::EventRingDropped(runtime->event_ring);
    return HOOKSELF_OK;
}

