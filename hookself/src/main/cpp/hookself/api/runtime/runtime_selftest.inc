constexpr uint32_t kRuntimeApiStressWorkerCount =
        hookself::internal::kMaxRuntimeApiBypassSlots -
        hookself::internal::kReservedDestroyBypassSlots;

struct RuntimeApiBypassStressContext {
    HookselfRuntime* runtime;
    uint32_t ready;
    uint32_t failures;
    uint32_t release;
    uint32_t workers_done;
    uint32_t destroy_done;
};

void* HoldRuntimeApiBypassSlot(void* opaque) {
    auto* context = static_cast<RuntimeApiBypassStressContext*>(opaque);
    {
        RuntimeCallGuard call(context->runtime);
        if (call.result() != HOOKSELF_OK) {
            __atomic_fetch_add(&context->failures, 1U, __ATOMIC_ACQ_REL);
        } else {
            __atomic_fetch_add(&context->ready, 1U, __ATOMIC_ACQ_REL);
            while (__atomic_load_n(&context->release,
                                   __ATOMIC_ACQUIRE) == 0U) {
                hookself::platform::RawSleepOneMillisecond();
            }
        }
    }
    __atomic_fetch_add(&context->workers_done, 1U, __ATOMIC_ACQ_REL);
    return nullptr;
}

void* DestroyRuntimeApiStressRuntime(void* opaque) {
    auto* context = static_cast<RuntimeApiBypassStressContext*>(opaque);
    hookself_destroy(context->runtime);
    __atomic_store_n(&context->destroy_done, 1U, __ATOMIC_RELEASE);
    return nullptr;
}

void WaitForRuntimeApiStressCompletion(const uint32_t* completed,
                                       uint32_t expected) noexcept {
    constexpr int64_t kTimeoutMs = 10000;
    const int64_t started = hookself::platform::RawNowMs();
    if (completed == nullptr || started < 0 ||
        started > INT64_MAX - kTimeoutMs) {
        hookself::platform::RawExit(127);
    }
    const int64_t deadline = started + kTimeoutMs;
    for (;;) {
        const uint32_t current = __atomic_load_n(completed, __ATOMIC_ACQUIRE);
        if (current == expected) {
            return;
        }
        const int64_t now = hookself::platform::RawNowMs();
        if (current > expected || now < 0 || now >= deadline) {
            hookself::platform::RawExit(127);
        }
        hookself::platform::RawSleepOneMillisecond();
    }
}

void JoinRuntimeApiStressWorkers(
        pthread_t* workers, uint32_t count,
        const RuntimeApiBypassStressContext& context) noexcept {
    WaitForRuntimeApiStressCompletion(&context.workers_done, count);
    for (uint32_t i = 0; i < count; ++i) {
        if (pthread_join(workers[i], nullptr) != 0) {
            hookself::platform::RawExit(127);
        }
    }
}

void JoinRuntimeApiStressDestroy(
        pthread_t thread,
        const RuntimeApiBypassStressContext& context) noexcept {
    WaitForRuntimeApiStressCompletion(&context.destroy_done, 1U);
    if (pthread_join(thread, nullptr) != 0) {
        hookself::platform::RawExit(127);
    }
}

int32_t RunRuntimeApiBypassDestroyStressImpl(HookselfRuntime* runtime,
                                             bool* destroyed) noexcept {
    if (runtime == nullptr || destroyed == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *destroyed = false;
    RuntimeApiBypassStressContext context{runtime, 0U, 0U, 0U, 0U, 0U};
    hookself::internal::SharedControlPage* const control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    const uint32_t tracked_tasks = control == nullptr
                                           ? UINT32_MAX
                                           : __atomic_load_n(
                                                     &control->tracked_tasks,
                                                     __ATOMIC_ACQUIRE);
    constexpr uint32_t kTaskHeadroom = 8U;
    if (control == nullptr ||
        tracked_tasks > hookself::internal::kMaxTrackedTasks -
                                kRuntimeApiStressWorkerCount -
                                kTaskHeadroom) {
        return HOOKSELF_E_CAPACITY;
    }
    pthread_t workers[kRuntimeApiStressWorkerCount]{};
    uint32_t created = 0;
    for (; created < kRuntimeApiStressWorkerCount; ++created) {
        if (pthread_create(&workers[created], nullptr,
                           HoldRuntimeApiBypassSlot, &context) != 0) {
            break;
        }
    }

    const int64_t started = hookself::platform::RawNowMs();
    const int64_t ready_deadline = started < 0 ? 0 : started + 5000;
    while (started >= 0 &&
           __atomic_load_n(&context.ready, __ATOMIC_ACQUIRE) +
                           __atomic_load_n(&context.failures,
                                           __ATOMIC_ACQUIRE) <
                   created &&
           hookself::platform::RawNowMs() < ready_deadline) {
        hookself::platform::RawSleepOneMillisecond();
    }
    const bool workers_ready =
            created == kRuntimeApiStressWorkerCount &&
            __atomic_load_n(&context.ready, __ATOMIC_ACQUIRE) == created &&
            __atomic_load_n(&context.failures, __ATOMIC_ACQUIRE) == 0U;
    if (!workers_ready) {
        __atomic_store_n(&context.release, 1U, __ATOMIC_RELEASE);
        JoinRuntimeApiStressWorkers(workers, created, context);
        return created != kRuntimeApiStressWorkerCount
                       ? HOOKSELF_E_CAPACITY
                       : HOOKSELF_E_INTERNAL;
    }
    uint32_t occupied_slots = 0;
    for (uint32_t slot = 0; slot < kRuntimeApiStressWorkerCount; ++slot) {
        if (__atomic_load_n(&control->runtime_api_bypass_tids[slot],
                            __ATOMIC_ACQUIRE) > 0) {
            ++occupied_slots;
        }
    }
    const bool slots_saturated =
            ActiveRuntimeApiBypassControl() == control &&
            occupied_slots == kRuntimeApiStressWorkerCount &&
            __atomic_load_n(
                    &control->runtime_api_bypass_tids[
                            kRuntimeApiStressWorkerCount],
                    __ATOMIC_ACQUIRE) == 0;
    if (!slots_saturated) {
        __atomic_store_n(&context.release, 1U, __ATOMIC_RELEASE);
        JoinRuntimeApiStressWorkers(workers, created, context);
        return HOOKSELF_E_INTERNAL;
    }

    pthread_t destroy_thread{};
    if (pthread_create(&destroy_thread, nullptr,
                       DestroyRuntimeApiStressRuntime, &context) != 0) {
        __atomic_store_n(&context.release, 1U, __ATOMIC_RELEASE);
        JoinRuntimeApiStressWorkers(workers, created, context);
        return HOOKSELF_E_INTERNAL;
    }
    const int64_t destroy_started = hookself::platform::RawNowMs();
    const int64_t closing_deadline =
            destroy_started < 0 ? 0 : destroy_started + 5000;
    bool closing_seen = false;
    while (destroy_started >= 0 &&
           hookself::platform::RawNowMs() < closing_deadline) {
        if (__atomic_load_n(&runtime->closing, __ATOMIC_ACQUIRE) != 0U) {
            closing_seen = true;
            break;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
    __atomic_store_n(&context.release, 1U, __ATOMIC_RELEASE);
    JoinRuntimeApiStressWorkers(workers, created, context);
    JoinRuntimeApiStressDestroy(destroy_thread, context);
    *destroyed = true;
    return closing_seen &&
                   __atomic_load_n(&context.destroy_done,
                                   __ATOMIC_ACQUIRE) != 0U &&
                   __atomic_load_n(&context.failures,
                                   __ATOMIC_ACQUIRE) == 0U
                    ? HOOKSELF_OK
                    : HOOKSELF_E_INTERNAL;
}
