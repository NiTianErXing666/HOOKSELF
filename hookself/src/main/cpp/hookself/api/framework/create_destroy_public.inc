extern "C" HOOKSELF_API void hookself_framework_default_config(
        HookselfConfig* config) {
    hookself_default_config(config);
    if (config != nullptr) {
        config->failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    }
}

extern "C" HOOKSELF_API void hookself_framework_default_redirect_options(
        HookselfRedirectOptions* options) {
    if (options == nullptr) {
        return;
    }
    *options = {};
    options->struct_size = sizeof(HookselfRedirectOptions);
    options->operation_mask = HOOKSELF_PATH_OP_ALL;
}

extern "C" HOOKSELF_API int32_t hookself_framework_create(
        const HookselfConfig* config, HookselfFramework** framework) {
    if (framework == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *framework = nullptr;
    const int32_t validation = hookself_validate_config(config);
    if (validation != HOOKSELF_OK) {
        return validation;
    }
    auto* created = new (std::nothrow) HookselfFramework{};
    if (created == nullptr) {
        return HOOKSELF_E_NO_MEMORY;
    }
    if (pthread_mutex_init(&created->mutex, nullptr) != 0) {
        delete created;
        return HOOKSELF_E_INTERNAL;
    }
    if (pthread_cond_init(&created->lifecycle_cv, nullptr) != 0) {
        pthread_mutex_destroy(&created->mutex);
        delete created;
        return HOOKSELF_E_INTERNAL;
    }
    created->next_handle = 1U;
    created->next_path_rule_id = 1U;
    created->config = *config;
    created->config.path_rule_count = 0U;
    created->config.path_rules = nullptr;
    created->config.syscall_rule_count = 0U;
    created->config.syscall_rules = nullptr;
    created->config.virtual_files = config->virtual_file_count == 0U
                                            ? nullptr
                                            : created->virtual_files;

    for (uint32_t index = 0; index < config->path_rule_count; ++index) {
        PathRuleSlot& slot = created->path_slots[index];
        slot.rule = config->path_rules[index];
        slot.handle = AllocateHandleLocked(created);
        slot.used = 1U;
        slot.enabled = 1U;
    }
    for (uint32_t index = 0; index < config->syscall_rule_count; ++index) {
        SyscallRuleSlot& slot = created->syscall_slots[index];
        slot.rule = config->syscall_rules[index];
        slot.handle = AllocateHandleLocked(created);
        slot.used = 1U;
        slot.enabled = 1U;
    }
    for (uint32_t index = 0; index < config->virtual_file_count; ++index) {
        const HookselfVirtualFile& source = config->virtual_files[index];
        HookselfVirtualFile& destination = created->virtual_files[index];
        destination = source;
        destination.initial_content = nullptr;
        if (source.initial_content_size == 0U) {
            continue;
        }
        auto* content = new (std::nothrow) uint8_t[source.initial_content_size];
        if (content == nullptr) {
            FinalizeFramework(created);
            return HOOKSELF_E_NO_MEMORY;
        }
        for (uint32_t byte = 0; byte < source.initial_content_size; ++byte) {
            content[byte] = source.initial_content[byte];
        }
        created->virtual_contents[index] = content;
        destination.initial_content = content;
    }
    if (!RegisterFramework(created)) {
        FinalizeFramework(created);
        return HOOKSELF_E_INTERNAL;
    }
    *framework = created;
    return HOOKSELF_OK;
}

extern "C" HOOKSELF_API void hookself_framework_destroy(
        HookselfFramework* framework) {
    if (framework == nullptr) {
        return;
    }
    const bool reentrant = ThreadHasFrameworkCall(framework);
    if (pthread_mutex_lock(&gFrameworkRegistryMutex) != 0) {
        return;
    }
    HookselfFramework** link = &gFrameworkRegistryHead;
    while (*link != nullptr && *link != framework) {
        link = &(*link)->registry_next;
    }
    if (*link == nullptr) {
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return;
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        return;
    }
    *link = framework->registry_next;
    framework->registry_next = nullptr;
    framework->closing = 1U;
    if (reentrant) {
        framework->deferred_destroy = 1U;
        HookselfRuntime* const runtime = framework->runtime;
        pthread_mutex_unlock(&gFrameworkRegistryMutex);
        pthread_mutex_unlock(&framework->mutex);
        hookself::internal::RequestRuntimeDrainAbort(runtime);
        return;
    }
    framework->destroy_waiter = 1U;
    pthread_mutex_unlock(&gFrameworkRegistryMutex);
    while (framework->active_calls != 0U) {
        (void)pthread_cond_wait(&framework->lifecycle_cv, &framework->mutex);
    }
    HookselfRuntime* const runtime = framework->runtime;
    framework->runtime = nullptr;
    ++framework->runtime_generation;
    pthread_mutex_unlock(&framework->mutex);
    hookself_destroy(runtime);
    FinalizeFramework(framework);
}
