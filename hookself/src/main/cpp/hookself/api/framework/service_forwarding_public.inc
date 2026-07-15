extern "C" HOOKSELF_API size_t hookself_framework_read_events(
        HookselfFramework* framework, HookselfEvent* events, size_t capacity) {
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return 0U;
    }
    RuntimeLease lease;
    if (RuntimeForForwarding(framework, &lease) != HOOKSELF_OK) {
        return 0U;
    }
    return hookself_read_events(lease.runtime(), events, capacity);
}

extern "C" HOOKSELF_API int32_t hookself_framework_set_log_sink(
        HookselfFramework* framework, HookselfLogSink sink, void* user_data) {
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
        framework->log_sink = sink;
        framework->log_sink_user_data = sink == nullptr ? nullptr : user_data;
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
    const uint64_t generation = lease.generation();
    pthread_mutex_unlock(&framework->mutex);
    int32_t result = hookself_set_log_sink(lease.runtime(), sink, user_data);
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const bool same_runtime = framework->runtime == lease.runtime() &&
                              framework->runtime_generation == generation;
    if (result == HOOKSELF_OK && same_runtime) {
        framework->log_sink = sink;
        framework->log_sink_user_data = sink == nullptr ? nullptr : user_data;
    } else if (result == HOOKSELF_OK) {
        result = HOOKSELF_E_BUSY;
    }
    lease.ReleaseLocked();
    framework->lifecycle_busy = 0U;
    pthread_cond_broadcast(&framework->lifecycle_cv);
    pthread_mutex_unlock(&framework->mutex);
    return result;
}

extern "C" HOOKSELF_API int32_t hookself_framework_drain_logs(
        HookselfFramework* framework, size_t max_events,
        size_t* consumed_events, size_t* emitted_logs) {
    if (max_events == 0U || consumed_events == nullptr ||
        emitted_logs == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *consumed_events = 0U;
    *emitted_logs = 0U;
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    RuntimeLease lease;
    const int32_t runtime_result = RuntimeForForwarding(framework, &lease);
    if (runtime_result != HOOKSELF_OK) {
        return runtime_result;
    }
    return hookself_drain_logs(lease.runtime(), max_events, consumed_events,
                               emitted_logs);
}

extern "C" HOOKSELF_API int32_t hookself_framework_publish_virtual_file(
        HookselfFramework* framework, uint32_t file_id,
        const uint8_t* content, size_t content_size) {
    if ((content_size != 0U && content == nullptr) ||
        content_size > HOOKSELF_MAX_VIRTUAL_FILE_SIZE) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
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
    if (framework->runtime == nullptr) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    uint32_t file_index = HOOKSELF_MAX_VIRTUAL_FILES;
    for (uint32_t index = 0;
         index < framework->config.virtual_file_count; ++index) {
        if (framework->virtual_files[index].file_id == file_id) {
            file_index = index;
            break;
        }
    }
    if (file_index == HOOKSELF_MAX_VIRTUAL_FILES) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if (framework->virtual_files[file_index].provider !=
        HOOKSELF_VFILE_DYNAMIC_SNAPSHOT) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    RuntimeLease lease;
    const int32_t lease_result = lease.AcquireLocked(framework);
    if (lease_result != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return lease_result;
    }
    framework->lifecycle_busy = 1U;
    const uint64_t generation = lease.generation();
    pthread_mutex_unlock(&framework->mutex);

    auto* replacement = content_size == 0U
                                ? nullptr
                                : new (std::nothrow) uint8_t[content_size];
    if (content_size != 0U && replacement == nullptr) {
        if (pthread_mutex_lock(&framework->mutex) == 0) {
            lease.ReleaseLocked();
            framework->lifecycle_busy = 0U;
            pthread_cond_broadcast(&framework->lifecycle_cv);
            pthread_mutex_unlock(&framework->mutex);
        }
        return HOOKSELF_E_NO_MEMORY;
    }
    for (size_t index = 0; index < content_size; ++index) {
        replacement[index] = content[index];
    }
    uint32_t snapshot_published = 0U;
    int32_t result = hookself::internal::PublishRuntimeVirtualFile(
            lease.runtime(), file_id, replacement, content_size,
            &snapshot_published);
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        delete[] replacement;
        return HOOKSELF_E_INTERNAL;
    }
    const bool same_runtime = framework->runtime == lease.runtime() &&
                              framework->runtime_generation == generation;
    uint8_t* previous = nullptr;
    if ((result == HOOKSELF_OK || snapshot_published != 0U) && same_runtime) {
        previous = framework->virtual_contents[file_index];
        framework->virtual_contents[file_index] = replacement;
        framework->virtual_files[file_index].initial_content = replacement;
        framework->virtual_files[file_index].initial_content_size =
                static_cast<uint32_t>(content_size);
        replacement = nullptr;
    } else if (result == HOOKSELF_OK) {
        result = HOOKSELF_E_BUSY;
    }
    lease.ReleaseLocked();
    framework->lifecycle_busy = 0U;
    pthread_cond_broadcast(&framework->lifecycle_cv);
    pthread_mutex_unlock(&framework->mutex);
    delete[] replacement;
    delete[] previous;
    return result;
}

extern "C" HOOKSELF_API int32_t hookself_framework_refresh_virtual_file(
        HookselfFramework* framework, uint32_t file_id) {
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    RuntimeLease lease;
    const int32_t runtime_result = RuntimeForForwarding(framework, &lease);
    if (runtime_result != HOOKSELF_OK) {
        return runtime_result;
    }
    return hookself_refresh_virtual_file(lease.runtime(), file_id);
}
