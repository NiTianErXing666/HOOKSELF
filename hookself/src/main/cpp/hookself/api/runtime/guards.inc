struct RuntimeApiBypassToken {
    hookself::internal::SharedControlPage* control;
    int32_t tid;
    uint32_t slot;
    bool active;
    bool pinned;
};

struct PendingRuntimeApiBypassRetire {
    hookself::internal::SharedControlPage* control;
    HookselfRuntime* runtime;
    uintptr_t resident_lease_owner;
};

thread_local hookself::internal::SharedControlPage*
        gRuntimeApiBypassThreadControl = nullptr;
thread_local int32_t gRuntimeApiBypassThreadTid = 0;
thread_local uint32_t gRuntimeApiBypassThreadSlot = UINT32_MAX;
thread_local uint32_t gRuntimeApiBypassThreadDepth = 0;
thread_local PendingRuntimeApiBypassRetire gPendingRuntimeApiBypassRetire{};

hookself::internal::SharedControlPage* ActiveRuntimeApiBypassControl() {
    return reinterpret_cast<hookself::internal::SharedControlPage*>(
            __atomic_load_n(&gRuntimeApiBypassControl, __ATOMIC_ACQUIRE));
}

void LockRuntimeApiBypassWriter() {
    for (;;) {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(
                    &gRuntimeApiBypassWriter, &expected, 1U, false,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            return;
        }
        __asm__ volatile("yield" ::: "memory");
    }
}

void UnlockRuntimeApiBypassWriter() {
    __atomic_store_n(&gRuntimeApiBypassWriter, 0U, __ATOMIC_RELEASE);
}

void LockRuntimeApiBypassPublisher() {
    for (;;) {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(
                    &gRuntimeApiBypassPublisher, &expected, 1U, false,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            return;
        }
        __asm__ volatile("yield" ::: "memory");
    }
}

void UnlockRuntimeApiBypassPublisher() {
    __atomic_store_n(&gRuntimeApiBypassPublisher, 0U, __ATOMIC_RELEASE);
}

bool PublishRuntimeApiBypassControl(
        hookself::internal::SharedControlPage* control) {
    if (control == nullptr) {
        return false;
    }
    const uintptr_t desired = reinterpret_cast<uintptr_t>(control);
    LockRuntimeApiBypassWriter();
    const uintptr_t current = __atomic_load_n(
            &gRuntimeApiBypassControl, __ATOMIC_ACQUIRE);
    const bool accepted = current == 0 || current == desired;
    if (accepted) {
        __atomic_store_n(&gRuntimeApiBypassControl, desired,
                         __ATOMIC_RELEASE);
    }
    UnlockRuntimeApiBypassWriter();
    return accepted;
}

void RetireRuntimeApiBypassControl(
        hookself::internal::SharedControlPage* control) {
    if (control == nullptr) {
        return;
    }
    LockRuntimeApiBypassWriter();
    __atomic_store_n(&gRuntimeApiBypassClosing, 1U, __ATOMIC_RELEASE);
    const uintptr_t expected = reinterpret_cast<uintptr_t>(control);
    if (__atomic_load_n(&gRuntimeApiBypassControl, __ATOMIC_ACQUIRE) ==
        expected) {
        __atomic_store_n(&gRuntimeApiBypassControl, 0U, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&gRuntimeApiBypassClosing, 0U, __ATOMIC_RELEASE);
    UnlockRuntimeApiBypassWriter();
}

bool BeginRuntimeApiBypass(
        hookself::internal::SharedControlPage* expected_control,
        bool allow_destroy_slot, RuntimeApiBypassToken* token) {
    if (token == nullptr) {
        return false;
    }
    *token = {};
    if (gRuntimeApiBypassThreadDepth != 0) {
        if ((expected_control != nullptr &&
             gRuntimeApiBypassThreadControl != expected_control) ||
            gRuntimeApiBypassThreadDepth == UINT32_MAX) {
            return false;
        }
        ++gRuntimeApiBypassThreadDepth;
        token->control = gRuntimeApiBypassThreadControl;
        token->tid = gRuntimeApiBypassThreadTid;
        token->slot = gRuntimeApiBypassThreadSlot;
        token->active = true;
        return true;
    }

    for (;;) {
        if (__atomic_load_n(&gRuntimeApiBypassClosing,
                            __ATOMIC_ACQUIRE) != 0U) {
            __asm__ volatile("yield" ::: "memory");
            continue;
        }
        __atomic_fetch_add(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
        if (__atomic_load_n(&gRuntimeApiBypassClosing,
                            __ATOMIC_ACQUIRE) == 0U) {
            break;
        }
        __atomic_fetch_sub(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
    }
    hookself::internal::SharedControlPage* const control =
            ActiveRuntimeApiBypassControl();
    if (control == nullptr ||
        (expected_control != nullptr && control != expected_control)) {
        __atomic_fetch_sub(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
        return control == nullptr && expected_control == nullptr;
    }

    const long tid_result = hookself::platform::RawRuntimeBypassGettid();
    if (hookself::platform::RawError(tid_result) != 0 || tid_result <= 0 ||
        tid_result > INT32_MAX) {
        __atomic_fetch_sub(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
        return false;
    }
    const int32_t tid = static_cast<int32_t>(tid_result);
    uint32_t claimed_slot = UINT32_MAX;
    const uint32_t slot_limit =
            hookself::internal::kMaxRuntimeApiBypassSlots -
            (allow_destroy_slot
                     ? 0U
                     : hookself::internal::kReservedDestroyBypassSlots);
    for (uint32_t slot = 0; slot < slot_limit; ++slot) {
        int32_t expected = 0;
        if (__atomic_compare_exchange_n(
                    &control->runtime_api_bypass_tids[slot], &expected, tid,
                    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            claimed_slot = slot;
            break;
        }
    }
    if (claimed_slot == UINT32_MAX) {
        __atomic_fetch_sub(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
        return false;
    }

    gRuntimeApiBypassThreadControl = control;
    gRuntimeApiBypassThreadTid = tid;
    gRuntimeApiBypassThreadSlot = claimed_slot;
    gRuntimeApiBypassThreadDepth = 1;
    token->control = control;
    token->tid = tid;
    token->slot = claimed_slot;
    token->active = true;
    token->pinned = true;
    return true;
}

void EndRuntimeApiBypass(RuntimeApiBypassToken* token) {
    if (token == nullptr || !token->active) {
        return;
    }
    token->active = false;
    if (gRuntimeApiBypassThreadDepth == 0 ||
        gRuntimeApiBypassThreadControl != token->control ||
        gRuntimeApiBypassThreadTid != token->tid ||
        gRuntimeApiBypassThreadSlot != token->slot) {
        return;
    }
    --gRuntimeApiBypassThreadDepth;
    if (gRuntimeApiBypassThreadDepth != 0) {
        return;
    }
    int32_t expected = token->tid;
    (void)__atomic_compare_exchange_n(
            &token->control->runtime_api_bypass_tids[token->slot], &expected,
            0, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    gRuntimeApiBypassThreadControl = nullptr;
    gRuntimeApiBypassThreadTid = 0;
    gRuntimeApiBypassThreadSlot = UINT32_MAX;
    if (token->pinned) {
        token->pinned = false;
        __atomic_fetch_sub(&gRuntimeApiBypassPins, 1U, __ATOMIC_ACQ_REL);
    }
}

void WaitForRuntimeApiBypassPins() {
    while (__atomic_load_n(&gRuntimeApiBypassPins,
                           __ATOMIC_ACQUIRE) != 0U) {
        hookself::platform::RawSleepOneMillisecond();
    }
}

bool HasResidentIntegrityTracer(const HookselfRuntime* runtime) {
    return runtime != nullptr &&
           (IsTracingRuntimeState(runtime->state) ||
            (runtime->state == HOOKSELF_STATE_STOPPED &&
             runtime->resident_controller.selective_committed != 0 &&
             runtime->resident_controller.tracer_pid > 0));
}

void FinalizeRuntime(HookselfRuntime* runtime,
                     RuntimeApiBypassToken* bypass_token) {
    const bool permanent_selective_tracer =
            runtime->resident_controller.selective_committed != 0;
    const uintptr_t resident_lease_owner =
            reinterpret_cast<uintptr_t>(runtime);
    const bool release_resident_lease =
            runtime->resident_lease_owned != 0 &&
            !permanent_selective_tracer;
    sigset_t previous_signal_mask{};
    bool signals_blocked = false;
    if (permanent_selective_tracer) {
        sigset_t blocked_signals{};
        if (sigfillset(&blocked_signals) != 0 ||
            sigprocmask(SIG_SETMASK, &blocked_signals,
                        &previous_signal_mask) != 0) {
            hookself::platform::RawExit(127);
        }
        signals_blocked = true;
    }
    hookself::internal::SharedControlPage* const control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    const bool owns_published_bypass =
            ActiveRuntimeApiBypassControl() == control;
    hookself::internal::ForceDestroyResidentSession(
            &runtime->shared_session, &runtime->resident_controller);
    if (permanent_selective_tracer && !owns_published_bypass) {
        hookself::platform::RawExit(127);
    }
    if (owns_published_bypass) {
        RetireRuntimeApiBypassControl(control);
        EndRuntimeApiBypass(bypass_token);
        WaitForRuntimeApiBypassPins();
    }
    if (permanent_selective_tracer) {
        for (uint32_t i = 0; i < HOOKSELF_MAX_VIRTUAL_FILES; ++i) {
            delete[] runtime->virtual_contents[i];
            runtime->virtual_contents[i] = nullptr;
        }
        if (runtime->virtual_provider_scratch != nullptr) {
            munmap(runtime->virtual_provider_scratch,
                   runtime->virtual_provider_scratch_size);
            runtime->virtual_provider_scratch = nullptr;
            runtime->virtual_provider_scratch_size = 0;
        }
        if (hookself::internal::BeginResidentTeardownFreeze(
                    &runtime->shared_session,
                    &runtime->resident_controller, 5000) != HOOKSELF_OK) {
            hookself::platform::RawExit(127);
        }
    }
    for (uint32_t i = 0; i < HOOKSELF_MAX_VIRTUAL_FILES; ++i) {
        if (permanent_selective_tracer &&
            runtime->virtual_backings[i].stable_fd >= 0) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->virtual_backings[i].stable_fd,
                        runtime->virtual_backings[i].stable_identity) != 0) {
                hookself::platform::RawExit(127);
            }
            runtime->virtual_backings[i].stable_fd = -1;
            runtime->virtual_backings[i].stable_identity_valid = 0;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->virtual_backings[i].stable_identity);
            hookself::internal::DestroyVirtualFileBacking(
                    &runtime->virtual_backings[i]);
            runtime->virtual_file_fds[i] = -1;
        } else {
            hookself::internal::DestroyVirtualFileBacking(
                    &runtime->virtual_backings[i]);
        }
        if (runtime->virtual_provider_source_fds[i] >= 0) {
            if (permanent_selective_tracer) {
                if (hookself::internal::CloseResidentTeardownFd(
                            &runtime->shared_session,
                            runtime->virtual_provider_source_fds[i],
                            runtime->virtual_provider_source_identities[i]) !=
                    0) {
                    hookself::platform::RawExit(127);
                }
            } else {
                (void)hookself::internal::CloseFdObject(
                        runtime->virtual_provider_source_fds[i],
                        runtime->virtual_provider_source_identities[i]);
            }
            runtime->virtual_provider_source_fds[i] = -1;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->virtual_provider_source_identities[i]);
        }
        if (!permanent_selective_tracer) {
            delete[] runtime->virtual_contents[i];
            runtime->virtual_contents[i] = nullptr;
        }
    }
    if (permanent_selective_tracer) {
        if (hookself::internal::RemoveVirtualBackingSessionDirectory(
                    &runtime->virtual_backing_session) != 0) {
            hookself::platform::RawExit(127);
        }
        if (runtime->virtual_backing_session.session_fd >= 0) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->virtual_backing_session.session_fd,
                        runtime->virtual_backing_session.session_identity) !=
                0) {
                hookself::platform::RawExit(127);
            }
            runtime->virtual_backing_session.session_fd = -1;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->virtual_backing_session.session_identity);
        }
        if (runtime->virtual_backing_session.root_fd >= 0) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->virtual_backing_session.root_fd,
                        runtime->virtual_backing_session.root_identity) != 0) {
                hookself::platform::RawExit(127);
            }
            runtime->virtual_backing_session.root_fd = -1;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->virtual_backing_session.root_identity);
        }
        hookself::internal::InitializeVirtualBackingSession(
                &runtime->virtual_backing_session);
    } else {
        hookself::internal::DestroyVirtualBackingSession(
                &runtime->virtual_backing_session);
    }
    if (permanent_selective_tracer) {
        if (runtime->resident_controller.control_event_fd >= 0) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->resident_controller.control_event_fd,
                        runtime->resident_controller.control_event_identity) !=
                0) {
                hookself::platform::RawExit(127);
            }
            runtime->resident_controller.control_event_fd = -1;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->resident_controller.control_event_identity);
        }
        if (runtime->resident_controller.status_read_fd >= 0) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->resident_controller.status_read_fd,
                        runtime->resident_controller.status_read_identity) !=
                0) {
                hookself::platform::RawExit(127);
            }
            runtime->resident_controller.status_read_fd = -1;
            hookself::internal::ClearFdObjectIdentity(
                    &runtime->resident_controller.status_read_identity);
        }
    }
    if (runtime->shared_session.fd >= 0) {
        if (permanent_selective_tracer) {
            if (hookself::internal::CloseResidentTeardownFd(
                        &runtime->shared_session,
                        runtime->shared_session.fd,
                        runtime->shared_session.fd_identity) != 0) {
                hookself::platform::RawExit(127);
            }
        } else {
            (void)hookself::internal::CloseFdObject(
                    runtime->shared_session.fd,
                    runtime->shared_session.fd_identity);
        }
        runtime->shared_session.fd = -1;
        hookself::internal::ClearFdObjectIdentity(
                &runtime->shared_session.fd_identity);
    }
    if (permanent_selective_tracer) {
        if (hookself::internal::ReleaseResidentTeardown(
                    &runtime->shared_session, 5000) != HOOKSELF_OK) {
            hookself::platform::RawExit(127);
        }
        hookself::internal::FinishResidentTeardown(
                &runtime->shared_session);
    }
    runtime->event_ring = nullptr;
    hookself::internal::DestroySharedSession(&runtime->shared_session);
    if (runtime->virtual_provider_scratch != nullptr) {
        munmap(runtime->virtual_provider_scratch,
               runtime->virtual_provider_scratch_size);
        runtime->virtual_provider_scratch = nullptr;
        runtime->virtual_provider_scratch_size = 0;
    }
    pthread_cond_destroy(&runtime->lifecycle_cv);
    pthread_mutex_destroy(&runtime->event_reader_mutex);
    pthread_mutex_destroy(&runtime->mutex);
    delete runtime;
    if (signals_blocked &&
        sigprocmask(SIG_SETMASK, &previous_signal_mask, nullptr) != 0) {
        hookself::platform::RawExit(127);
    }
    if (!owns_published_bypass) {
        EndRuntimeApiBypass(bypass_token);
    }
    if (release_resident_lease) {
        ReleaseResidentLease(resident_lease_owner);
    }
}

bool ThreadHasRuntimeCall(const HookselfRuntime* runtime) {
    for (const RuntimeCallFrame* frame = gRuntimeCallFrame;
         frame != nullptr; frame = frame->previous) {
        if (frame->runtime == runtime) {
            return true;
        }
    }
    return false;
}

bool RegisterRuntime(HookselfRuntime* runtime) {
    if (runtime == nullptr ||
        pthread_mutex_lock(&gRuntimeRegistryMutex) != 0) {
        return false;
    }
    runtime->registry_next = gRuntimeRegistryHead;
    gRuntimeRegistryHead = runtime;
    pthread_mutex_unlock(&gRuntimeRegistryMutex);
    return true;
}

int32_t BeginRuntimeCall(HookselfRuntime* runtime) {
    if (runtime == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    const bool nested = ThreadHasRuntimeCall(runtime);
    if (pthread_mutex_lock(&gRuntimeRegistryMutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    bool registered = false;
    for (const HookselfRuntime* candidate = gRuntimeRegistryHead;
         candidate != nullptr; candidate = candidate->registry_next) {
        if (candidate == runtime) {
            registered = true;
            break;
        }
    }
    if (!registered && !nested) {
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    if (pthread_mutex_lock(&runtime->mutex) != 0) {
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return HOOKSELF_E_INTERNAL;
    }
    if (__atomic_load_n(&runtime->closing, __ATOMIC_ACQUIRE) != 0 &&
        !nested) {
        pthread_mutex_unlock(&runtime->mutex);
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    if (runtime->active_calls == UINT32_MAX) {
        pthread_mutex_unlock(&runtime->mutex);
        pthread_mutex_unlock(&gRuntimeRegistryMutex);
        return HOOKSELF_E_CAPACITY;
    }
    ++runtime->active_calls;
    pthread_mutex_unlock(&runtime->mutex);
    pthread_mutex_unlock(&gRuntimeRegistryMutex);
    return HOOKSELF_OK;
}

bool EndRuntimeCall(HookselfRuntime* runtime) {
    bool finalize = false;
    pthread_mutex_lock(&runtime->mutex);
    if (runtime->active_calls != 0) {
        --runtime->active_calls;
    }
    if (runtime->active_calls == 0) {
        if (runtime->closing != 0 && runtime->destroy_waiter != 0) {
            pthread_cond_broadcast(&runtime->lifecycle_cv);
        }
        if (runtime->closing != 0 && runtime->deferred_destroy != 0 &&
            runtime->destroy_waiter == 0) {
            runtime->deferred_destroy = 0;
            finalize = true;
        }
    }
    pthread_mutex_unlock(&runtime->mutex);
    return finalize;
}

class RuntimeCallGuard {
  public:
    explicit RuntimeCallGuard(HookselfRuntime* runtime)
        : frame_{runtime, gRuntimeCallFrame} {
        if (!BeginRuntimeApiBypass(nullptr, false, &bypass_token_)) {
            result_ = HOOKSELF_E_BUSY;
            return;
        }
        if (!bypass_token_.active && !RegisterUnpinnedCall()) {
            result_ = HOOKSELF_E_BUSY;
            return;
        }
        result_ = BeginRuntimeCall(runtime);
        if (result_ == HOOKSELF_OK && bypass_token_.active &&
            hookself::internal::GetSharedControl(runtime->shared_session) !=
                    bypass_token_.control) {
            result_ = HOOKSELF_E_BUSY;
            const bool finalize = EndRuntimeCall(runtime);
            UnregisterUnpinnedCall();
            if (finalize) {
                FinalizeRuntime(runtime, &bypass_token_);
            } else {
                EndRuntimeApiBypass(&bypass_token_);
            }
            return;
        }
        if (result_ == HOOKSELF_OK) {
            gRuntimeCallFrame = &frame_;
            active_ = true;
        } else {
            UnregisterUnpinnedCall();
            EndRuntimeApiBypass(&bypass_token_);
        }
    }

    ~RuntimeCallGuard() {
        if (!active_) {
            return;
        }
        EndBypassPublication();
        const bool completing_retire = BeginPendingRetire();
        gRuntimeCallFrame = frame_.previous;
        const bool finalize = EndRuntimeCall(frame_.runtime);
        if (completing_retire) {
            FinishPendingRetire();
        }
        if (finalize) {
            FinalizeRuntime(frame_.runtime, &bypass_token_);
        } else {
            EndRuntimeApiBypass(&bypass_token_);
        }
        UnregisterUnpinnedCall();
    }

    RuntimeCallGuard(const RuntimeCallGuard&) = delete;
    RuntimeCallGuard& operator=(const RuntimeCallGuard&) = delete;

    int32_t result() const {
        return result_;
    }

    bool ActivateBypass(hookself::internal::SharedControlPage* control) {
        if (result_ != HOOKSELF_OK) {
            return false;
        }
        if (bypass_token_.active) {
            return bypass_token_.control == control;
        }
        return BeginRuntimeApiBypass(control, false, &bypass_token_);
    }

    bool BeginBypassPublication() {
        if (result_ != HOOKSELF_OK || bypass_token_.active) {
            return result_ == HOOKSELF_OK;
        }
        if (frame_.previous != nullptr) {
            return false;
        }
        UnregisterUnpinnedCall();
        LockRuntimeApiBypassPublisher();
        hookself::internal::SharedControlPage* const published =
                ActiveRuntimeApiBypassControl();
        if (published != nullptr) {
            UnlockRuntimeApiBypassPublisher();
            return BeginRuntimeApiBypass(
                    published, false, &bypass_token_);
        }
        __atomic_store_n(&gRuntimeApiBypassPublishPending, 1U,
                         __ATOMIC_RELEASE);
        while (__atomic_load_n(&gRuntimeApiBypassUnpinnedCalls,
                               __ATOMIC_ACQUIRE) != 0U) {
            __asm__ volatile("yield" ::: "memory");
        }
        publication_active_ = true;
        return true;
    }

    void EndBypassPublication() {
        if (!publication_active_) {
            return;
        }
        publication_active_ = false;
        __atomic_store_n(&gRuntimeApiBypassPublishPending, 0U,
                         __ATOMIC_RELEASE);
        UnlockRuntimeApiBypassPublisher();
    }

    bool ScheduleBypassRetire(
            hookself::internal::SharedControlPage* control,
            const void* resident_lease_owner) {
        EndBypassPublication();
        if (control == nullptr || !bypass_token_.active ||
            bypass_token_.control != control) {
            return false;
        }
        if (gPendingRuntimeApiBypassRetire.control != nullptr &&
            gPendingRuntimeApiBypassRetire.control != control) {
            return false;
        }
        uint32_t expected_owner = kBypassRetireOwnerNone;
        if (!__atomic_compare_exchange_n(
                    &frame_.runtime->bypass_retire_owner, &expected_owner,
                    kBypassRetireOwnerCall, false, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE)) {
            return false;
        }
        gPendingRuntimeApiBypassRetire.control = control;
        gPendingRuntimeApiBypassRetire.runtime = frame_.runtime;
        gPendingRuntimeApiBypassRetire.resident_lease_owner =
                reinterpret_cast<uintptr_t>(resident_lease_owner);
        return true;
    }

  private:
    bool BeginPendingRetire() {
        if (!bypass_token_.pinned ||
            gPendingRuntimeApiBypassRetire.control == nullptr ||
            gPendingRuntimeApiBypassRetire.control != bypass_token_.control) {
            return false;
        }
        PendingRuntimeApiBypassRetire pending =
                gPendingRuntimeApiBypassRetire;
        gPendingRuntimeApiBypassRetire = {};
        if (pending.runtime == nullptr ||
            __atomic_load_n(&pending.runtime->bypass_retire_owner,
                            __ATOMIC_ACQUIRE) !=
                    kBypassRetireOwnerCall) {
            return false;
        }
        LockRuntimeApiBypassPublisher();
        __atomic_store_n(&gRuntimeApiBypassPublishPending, 1U,
                         __ATOMIC_RELEASE);
        while (__atomic_load_n(&gRuntimeApiBypassUnpinnedCalls,
                               __ATOMIC_ACQUIRE) != 0U) {
            __asm__ volatile("yield" ::: "memory");
        }
        completing_retire_ = pending;
        RetireRuntimeApiBypassControl(pending.control);
        EndRuntimeApiBypass(&bypass_token_);
        WaitForRuntimeApiBypassPins();
        return true;
    }

    void FinishPendingRetire() {
        HookselfRuntime* const runtime = completing_retire_.runtime;
        if (runtime == nullptr) {
            hookself::platform::RawExit(127);
        }
        if (pthread_mutex_lock(&runtime->mutex) != 0) {
            hookself::platform::RawExit(127);
        }
        const bool closing = __atomic_load_n(
                &runtime->closing, __ATOMIC_ACQUIRE) != 0U;
        if (!closing) {
            runtime->resident_lease_owned = 0;
        }
        __atomic_store_n(&runtime->bypass_retire_owner,
                         kBypassRetireOwnerNone, __ATOMIC_RELEASE);
        if (runtime->destroy_waiter != 0) {
            pthread_cond_broadcast(&runtime->lifecycle_cv);
        }
        pthread_mutex_unlock(&runtime->mutex);
        if (!closing && completing_retire_.resident_lease_owner != 0U) {
            ReleaseResidentLease(
                    completing_retire_.resident_lease_owner);
        }
        completing_retire_ = {};
        __atomic_store_n(&gRuntimeApiBypassPublishPending, 0U,
                         __ATOMIC_RELEASE);
        UnlockRuntimeApiBypassPublisher();
    }

    bool RegisterUnpinnedCall() {
        for (;;) {
            while (__atomic_load_n(&gRuntimeApiBypassPublishPending,
                                   __ATOMIC_ACQUIRE) != 0U) {
                __asm__ volatile("yield" ::: "memory");
            }
            hookself::internal::SharedControlPage* const published =
                    ActiveRuntimeApiBypassControl();
            if (published != nullptr) {
                return BeginRuntimeApiBypass(
                        published, false, &bypass_token_) &&
                       bypass_token_.active;
            }
            __atomic_fetch_add(&gRuntimeApiBypassUnpinnedCalls, 1U,
                               __ATOMIC_ACQ_REL);
            if (__atomic_load_n(&gRuntimeApiBypassPublishPending,
                                __ATOMIC_ACQUIRE) == 0U &&
                ActiveRuntimeApiBypassControl() == nullptr) {
                unpinned_registered_ = true;
                return true;
            }
            __atomic_fetch_sub(&gRuntimeApiBypassUnpinnedCalls, 1U,
                               __ATOMIC_ACQ_REL);
        }
    }

    void UnregisterUnpinnedCall() {
        if (!unpinned_registered_) {
            return;
        }
        unpinned_registered_ = false;
        __atomic_fetch_sub(&gRuntimeApiBypassUnpinnedCalls, 1U,
                           __ATOMIC_ACQ_REL);
    }

    RuntimeCallFrame frame_{};
    RuntimeApiBypassToken bypass_token_{};
    PendingRuntimeApiBypassRetire completing_retire_{};
    int32_t result_ = HOOKSELF_E_INTERNAL;
    bool active_ = false;
    bool unpinned_registered_ = false;
    bool publication_active_ = false;
};

class RuntimeApiBypassGuard {
  public:
    explicit RuntimeApiBypassGuard(bool destroy_call) {
        for (;;) {
            if (!BeginRuntimeApiBypass(
                        nullptr, destroy_call, &token_)) {
                if (!destroy_call) {
                    return;
                }
                __asm__ volatile("yield" ::: "memory");
                continue;
            }
            if (token_.active) {
                ok_ = true;
                return;
            }
            while (__atomic_load_n(&gRuntimeApiBypassPublishPending,
                                   __ATOMIC_ACQUIRE) != 0U) {
                __asm__ volatile("yield" ::: "memory");
            }
            hookself::internal::SharedControlPage* const published =
                    ActiveRuntimeApiBypassControl();
            if (published != nullptr) {
                continue;
            }
            __atomic_fetch_add(&gRuntimeApiBypassUnpinnedCalls, 1U,
                               __ATOMIC_ACQ_REL);
            if (__atomic_load_n(&gRuntimeApiBypassPublishPending,
                                __ATOMIC_ACQUIRE) == 0U &&
                ActiveRuntimeApiBypassControl() == nullptr) {
                unpinned_registered_ = true;
                ok_ = true;
                return;
            }
            __atomic_fetch_sub(&gRuntimeApiBypassUnpinnedCalls, 1U,
                               __ATOMIC_ACQ_REL);
        }
    }

    ~RuntimeApiBypassGuard() {
        if (unpinned_registered_) {
            unpinned_registered_ = false;
            __atomic_fetch_sub(&gRuntimeApiBypassUnpinnedCalls, 1U,
                               __ATOMIC_ACQ_REL);
        }
        EndRuntimeApiBypass(&token_);
    }

    RuntimeApiBypassGuard(const RuntimeApiBypassGuard&) = delete;
    RuntimeApiBypassGuard& operator=(const RuntimeApiBypassGuard&) = delete;

    bool ok() const {
        return ok_;
    }

    RuntimeApiBypassToken* token() {
        return &token_;
    }

    void ReleasePinnedControl(
            hookself::internal::SharedControlPage* control) {
        if (token_.active && token_.pinned && token_.control == control) {
            EndRuntimeApiBypass(&token_);
        }
    }

  private:
    RuntimeApiBypassToken token_{};
    bool ok_ = false;
    bool unpinned_registered_ = false;
};

bool RuntimeClosing(const HookselfRuntime* runtime) {
    return __atomic_load_n(&runtime->closing, __ATOMIC_ACQUIRE) != 0;
}

