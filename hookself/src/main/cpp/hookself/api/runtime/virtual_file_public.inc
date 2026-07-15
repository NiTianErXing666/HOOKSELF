namespace hookself::internal {

int32_t PublishRuntimeVirtualFile(
        HookselfRuntime* runtime, uint32_t file_id, const uint8_t* content,
        size_t content_size, uint32_t* snapshot_published) {
    if (snapshot_published != nullptr) {
        *snapshot_published = 0U;
    }
    if (runtime == nullptr || (content_size != 0 && content == nullptr) ||
        content_size > HOOKSELF_MAX_VIRTUAL_FILE_SIZE) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    pthread_mutex_lock(&runtime->mutex);
    if (runtime->state != HOOKSELF_STATE_CONFIGURED &&
        runtime->state != HOOKSELF_STATE_RUNNING_FULL_PTRACE &&
        runtime->state != HOOKSELF_STATE_RUNNING_SELECTIVE &&
        runtime->state != HOOKSELF_STATE_STOPPED) {
        pthread_mutex_unlock(&runtime->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    for (uint32_t i = 0; i < runtime->config.virtual_file_count; ++i) {
        if (runtime->virtual_files[i].file_id != file_id) {
            continue;
        }
        if (runtime->virtual_files[i].provider !=
            HOOKSELF_VFILE_DYNAMIC_SNAPSHOT) {
            pthread_mutex_unlock(&runtime->mutex);
            return HOOKSELF_E_INVALID_STATE;
        }
        const int32_t result = ReplaceVirtualFileSnapshotLocked(
                runtime, i, content, content_size, snapshot_published);
        pthread_mutex_unlock(&runtime->mutex);
        return result;
    }
    pthread_mutex_unlock(&runtime->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}

}  // namespace hookself::internal

extern "C" int32_t hookself_publish_virtual_file(HookselfRuntime* runtime,
                                                   uint32_t file_id,
                                                  const uint8_t* content,
                                                  size_t content_size) {
    return hookself::internal::PublishRuntimeVirtualFile(
            runtime, file_id, content, content_size, nullptr);
}

extern "C" int32_t hookself_refresh_virtual_file(HookselfRuntime* runtime,
                                                    uint32_t file_id) {
    RuntimeCallGuard call(runtime);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    pthread_mutex_lock(&runtime->mutex);
    if (runtime->state != HOOKSELF_STATE_CONFIGURED &&
        runtime->state != HOOKSELF_STATE_RUNNING_FULL_PTRACE &&
        runtime->state != HOOKSELF_STATE_RUNNING_SELECTIVE &&
        runtime->state != HOOKSELF_STATE_STOPPED) {
        pthread_mutex_unlock(&runtime->mutex);
        return HOOKSELF_E_INVALID_STATE;
    }
    for (uint32_t i = 0; i < runtime->config.virtual_file_count; ++i) {
        if (runtime->virtual_files[i].file_id != file_id) {
            continue;
        }
        const int32_t source_result = ReopenVirtualProviderSource(runtime, i);
        if (source_result != HOOKSELF_OK) {
            pthread_mutex_unlock(&runtime->mutex);
            return source_result;
        }
        const int32_t result = RefreshVirtualFileProviderLocked(runtime, i);
        pthread_mutex_unlock(&runtime->mutex);
        return result;
    }
    pthread_mutex_unlock(&runtime->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}
