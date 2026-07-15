extern "C" HOOKSELF_API int32_t hookself_framework_start(
        HookselfFramework* framework) {
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    if (framework->lifecycle_busy != 0U) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_BUSY;
    }
    RuntimeLease lease;
    HookselfRuntime* const existing = framework->runtime;
    if (existing != nullptr) {
        const int32_t lease_result = lease.AcquireLocked(framework);
        if (lease_result != HOOKSELF_OK) {
            pthread_mutex_unlock(&framework->mutex);
            return lease_result;
        }
    }
    framework->lifecycle_busy = 1U;
    framework->runtime_starting = 1U;
    const uint64_t expected_generation = framework->runtime_generation;
    HookselfLogSink const sink = framework->log_sink;
    void* const sink_user_data = framework->log_sink_user_data;
    HookselfConfig built{};
    if (existing == nullptr) {
        BuildConfigLocked(framework, &built);
    }
    pthread_mutex_unlock(&framework->mutex);

    if (existing != nullptr) {
        int32_t state = HOOKSELF_STATE_IDLE;
        int32_t result = hookself_get_state(lease.runtime(), &state);
        if (result == HOOKSELF_OK &&
            (state == HOOKSELF_STATE_RUNNING_FULL_PTRACE ||
             state == HOOKSELF_STATE_RUNNING_SELECTIVE)) {
            lease.Release();
            FinishLifecycle(framework);
            return HOOKSELF_OK;
        }
        if (result == HOOKSELF_OK) {
            result = hookself_start(lease.runtime());
        }
        lease.Release();
        FinishLifecycle(framework);
        return result;
    }

    HookselfRuntime* runtime = nullptr;
    int32_t result = hookself_create(&built, &runtime);
    if (result == HOOKSELF_OK && sink != nullptr) {
        result = hookself_set_log_sink(runtime, sink, sink_user_data);
    }
    if (result == HOOKSELF_OK) {
        result = hookself_start(runtime);
    }
    if (result != HOOKSELF_OK) {
        hookself_destroy(runtime);
        FinishLifecycle(framework);
        return result;
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        (void)hookself_stop(runtime);
        hookself_destroy(runtime);
        FinishLifecycle(framework);
        return HOOKSELF_E_INTERNAL;
    }
    if (framework->closing != 0U || framework->runtime != nullptr ||
        framework->runtime_generation != expected_generation) {
        const int32_t publish_result = framework->closing != 0U
                                               ? HOOKSELF_E_INVALID_STATE
                                               : HOOKSELF_E_BUSY;
        framework->runtime_starting = 0U;
        framework->lifecycle_busy = 0U;
        pthread_cond_broadcast(&framework->lifecycle_cv);
        pthread_mutex_unlock(&framework->mutex);
        (void)hookself_stop(runtime);
        hookself_destroy(runtime);
        return publish_result;
    }
    framework->runtime = runtime;
    ++framework->runtime_generation;
    framework->registry_frozen =
            (built.flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0U
                    ? 1U
                    : 0U;
    framework->runtime_starting = 0U;
    framework->lifecycle_busy = 0U;
    pthread_cond_broadcast(&framework->lifecycle_cv);
    pthread_mutex_unlock(&framework->mutex);
    return HOOKSELF_OK;
}

extern "C" HOOKSELF_API int32_t hookself_framework_stop(
        HookselfFramework* framework) {
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    if (framework->lifecycle_busy != 0U) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_BUSY;
    }
    HookselfRuntime* const runtime = framework->runtime;
    if (runtime == nullptr) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_OK;
    }
    RuntimeLease lease;
    const int32_t lease_result = lease.AcquireLocked(framework);
    if (lease_result != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return lease_result;
    }
    framework->lifecycle_busy = 1U;
    pthread_mutex_unlock(&framework->mutex);
    int32_t state = HOOKSELF_STATE_IDLE;
    int32_t result = hookself_get_state(lease.runtime(), &state);
    if (result == HOOKSELF_OK &&
        (state == HOOKSELF_STATE_STOPPED ||
         state == HOOKSELF_STATE_CONFIGURED)) {
        lease.Release();
        FinishLifecycle(framework);
        return HOOKSELF_OK;
    }
    if (result == HOOKSELF_OK) {
        result = hookself_stop(lease.runtime());
    }
    lease.Release();
    FinishLifecycle(framework);
    return result;
}

extern "C" HOOKSELF_API int32_t hookself_framework_get_state(
        const HookselfFramework* framework, int32_t* state) {
    if (state == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    auto* mutable_framework = const_cast<HookselfFramework*>(framework);
    FrameworkCall call(mutable_framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&mutable_framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    if (mutable_framework->runtime == nullptr) {
        *state = mutable_framework->runtime_starting != 0U
                         ? HOOKSELF_STATE_STARTING
                         : HOOKSELF_STATE_CONFIGURED;
        pthread_mutex_unlock(&mutable_framework->mutex);
        return HOOKSELF_OK;
    }
    RuntimeLease lease;
    const int32_t lease_result = lease.AcquireLocked(mutable_framework);
    pthread_mutex_unlock(&mutable_framework->mutex);
    if (lease_result != HOOKSELF_OK) {
        return lease_result;
    }
    return hookself_get_state(lease.runtime(), state);
}

extern "C" HOOKSELF_API int32_t hookself_framework_get_stats(
        const HookselfFramework* framework, HookselfStats* stats) {
    if (stats == nullptr || stats->struct_size != sizeof(HookselfStats)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    auto* mutable_framework = const_cast<HookselfFramework*>(framework);
    FrameworkCall call(mutable_framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&mutable_framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const uint32_t state = mutable_framework->runtime_starting != 0U
                                   ? HOOKSELF_STATE_STARTING
                                   : HOOKSELF_STATE_CONFIGURED;
    RuntimeLease lease;
    const int32_t lease_result = mutable_framework->runtime == nullptr
                                         ? HOOKSELF_OK
                                         : lease.AcquireLocked(
                                                   mutable_framework);
    pthread_mutex_unlock(&mutable_framework->mutex);
    if (lease_result != HOOKSELF_OK) {
        return lease_result;
    }
    if (lease.runtime() != nullptr) {
        return hookself_get_stats(lease.runtime(), stats);
    }
    HookselfStats empty{};
    empty.struct_size = sizeof(HookselfStats);
    empty.state = state;
    *stats = empty;
    return HOOKSELF_OK;
}
