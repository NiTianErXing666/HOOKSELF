namespace hookself::internal {

void RequestRuntimeDrainAbort(HookselfRuntime* runtime) noexcept {
    if (runtime != nullptr) {
        __atomic_store_n(&runtime->drain_abort_requested, 1U,
                         __ATOMIC_RELEASE);
    }
}

}  // namespace hookself::internal

namespace {

bool RuntimeDrainAbortRequested(const HookselfRuntime* runtime) {
    return __atomic_load_n(&runtime->drain_abort_requested,
                           __ATOMIC_ACQUIRE) != 0U;
}

}  // namespace

extern "C" size_t hookself_read_events(HookselfRuntime* runtime,
                                          HookselfEvent* events, size_t capacity) {
    if (runtime == nullptr || events == nullptr || capacity == 0) {
        return 0;
    }
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return 0;
    }
    if (pthread_mutex_trylock(&runtime->event_reader_mutex) != 0) {
        return 0;
    }
    if (runtime->event_consumer_mode == kEventConsumerLogs) {
        pthread_mutex_unlock(&runtime->event_reader_mutex);
        return 0;
    }
    runtime->event_consumer_mode = kEventConsumerRaw;
    const size_t count = hookself::internal::ReadEvents(
            runtime->event_ring, events, capacity);
    pthread_mutex_unlock(&runtime->event_reader_mutex);
    return count;
}

extern "C" int32_t hookself_set_log_sink(HookselfRuntime* runtime,
                                            HookselfLogSink sink,
                                            void* user_data) {
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (sink != nullptr) {
        (void)CachedLogTid();
    }
    const int reader_lock = pthread_mutex_trylock(
            &runtime->event_reader_mutex);
    if (reader_lock != 0) {
        return reader_lock == EBUSY ? HOOKSELF_E_BUSY
                                    : HOOKSELF_E_INTERNAL;
    }
    pthread_mutex_lock(&runtime->mutex);
    runtime->log_sink = sink;
    runtime->log_sink_user_data = sink == nullptr ? nullptr : user_data;
    pthread_mutex_unlock(&runtime->mutex);
    pthread_mutex_unlock(&runtime->event_reader_mutex);
    return HOOKSELF_OK;
}

extern "C" int32_t hookself_drain_logs(HookselfRuntime* runtime,
                                          size_t max_events,
                                          size_t* consumed_events,
                                         size_t* emitted_logs) {
    if (runtime == nullptr || max_events == 0 || consumed_events == nullptr ||
        emitted_logs == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *consumed_events = 0;
    *emitted_logs = 0;
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    pthread_mutex_lock(&runtime->mutex);
    const int32_t configured_level = runtime->config.log_level;
    pthread_mutex_unlock(&runtime->mutex);
    if (configured_level == HOOKSELF_LOG_OFF) {
        return HOOKSELF_OK;
    }
    const int reader_lock = pthread_mutex_trylock(
            &runtime->event_reader_mutex);
    if (reader_lock != 0) {
        return reader_lock == EBUSY ? HOOKSELF_E_BUSY
                                    : HOOKSELF_E_INTERNAL;
    }
    if (RuntimeClosing(runtime) || RuntimeDrainAbortRequested(runtime)) {
        pthread_mutex_unlock(&runtime->event_reader_mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    if (runtime->event_consumer_mode == kEventConsumerRaw) {
        pthread_mutex_unlock(&runtime->event_reader_mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    runtime->event_consumer_mode = kEventConsumerLogs;
    pthread_mutex_lock(&runtime->mutex);
    const HookselfLogSink sink = runtime->log_sink;
    void* const user_data = runtime->log_sink_user_data;
    pthread_mutex_unlock(&runtime->mutex);

    const int32_t drain_tid = CachedLogTid();
    hookself::internal::SharedControlPage* control =
            hookself::internal::GetSharedControl(runtime->shared_session);
    if (control != nullptr && drain_tid > 0) {
        __atomic_store_n(&control->log_bypass_tid, drain_tid,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&control->log_bypass_active, 1U,
                         __ATOMIC_RELEASE);
    }

    int32_t result = HOOKSELF_OK;
    HookselfEvent event{};
    while (*consumed_events < max_events) {
        if (RuntimeClosing(runtime) || RuntimeDrainAbortRequested(runtime)) {
            result = HOOKSELF_E_INVALID_STATE;
            break;
        }
        const size_t count = hookself::internal::ReadEvents(
                runtime->event_ring, &event, 1);
        if (count == 0) {
            break;
        }
        ++*consumed_events;
        const int32_t event_level = hookself_event_log_level(&event);
        if (event_level < HOOKSELF_LOG_ERROR ||
            event_level > configured_level) {
            continue;
        }
        char message[HOOKSELF_LOG_MESSAGE_CAPACITY]{};
        size_t required = 0;
        const int32_t format_result = hookself_format_event(
                &event, message, sizeof(message), &required);
        if (format_result != HOOKSELF_OK) {
            result = format_result;
            break;
        }
        if (sink != nullptr) {
            sink(event_level, &event, message, user_data);
            ++*emitted_logs;
            if (RuntimeClosing(runtime) ||
                RuntimeDrainAbortRequested(runtime)) {
                result = HOOKSELF_E_INVALID_STATE;
                break;
            }
            continue;
        }
        int priority = ANDROID_LOG_INFO;
        if (event_level == HOOKSELF_LOG_ERROR) {
            priority = ANDROID_LOG_ERROR;
        } else if (event_level == HOOKSELF_LOG_WARN) {
            priority = ANDROID_LOG_WARN;
        } else if (event_level == HOOKSELF_LOG_DEBUG) {
            priority = ANDROID_LOG_DEBUG;
        } else if (event_level == HOOKSELF_LOG_TRACE) {
            priority = ANDROID_LOG_VERBOSE;
        }
        (void)__android_log_write(priority, "Hookself", message);
        ++*emitted_logs;
    }
    if (control != nullptr) {
        __atomic_store_n(&control->log_bypass_active, 0U,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&control->log_bypass_tid, 0, __ATOMIC_RELAXED);
    }
    pthread_mutex_unlock(&runtime->event_reader_mutex);
    return result;
}
