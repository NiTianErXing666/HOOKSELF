extern "C" HOOKSELF_API int32_t hookself_framework_register_syscall_rule(
        HookselfFramework* framework, const HookselfSyscallRule* rule,
        int32_t enabled, HookselfRuleHandle* handle) {
    if (rule == nullptr || handle == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *handle = HOOKSELF_INVALID_RULE_HANDLE;
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const int32_t allowed = RegistryMutationAllowedLocked(framework);
    if (allowed != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return allowed;
    }
    uint32_t slot_index = HOOKSELF_MAX_SYSCALL_RULES;
    for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
        if (framework->syscall_slots[index].used == 0U) {
            slot_index = index;
            break;
        }
    }
    if (slot_index == HOOKSELF_MAX_SYSCALL_RULES) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_CAPACITY;
    }
    const HookselfRuleHandle candidate_handle =
            AllocateHandleLocked(framework);
    if (candidate_handle == HOOKSELF_INVALID_RULE_HANDLE) {
        pthread_mutex_unlock(&framework->mutex);
        return HOOKSELF_E_CAPACITY;
    }
    SyscallRuleSlot& slot = framework->syscall_slots[slot_index];
    slot = {};
    slot.rule = *rule;
    slot.handle = candidate_handle;
    slot.used = 1U;
    slot.enabled = 1U;
    const int32_t result = ValidateRegistryLocked(framework);
    if (result != HOOKSELF_OK) {
        slot = {};
        pthread_mutex_unlock(&framework->mutex);
        return result;
    }
    slot.enabled = enabled != 0 ? 1U : 0U;
    *handle = candidate_handle;
    HookselfRuntime* const detached =
            DetachStoppedRuntimeAfterMutationLocked(framework);
    pthread_mutex_unlock(&framework->mutex);
    DestroyDetachedRuntime(framework, detached);
    return HOOKSELF_OK;
}

extern "C" HOOKSELF_API int32_t hookself_framework_register_path_rule(
        HookselfFramework* framework, const HookselfPathRule* rule,
        int32_t enabled, HookselfRuleHandle* handle) {
    if (rule == nullptr || handle == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *handle = HOOKSELF_INVALID_RULE_HANDLE;
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const int32_t result = RegisterPathRuleLocked(
            framework, *rule, enabled != 0, rule->action != HOOKSELF_PATH_PASS,
            handle);
    HookselfRuntime* const detached = result == HOOKSELF_OK
            ? DetachStoppedRuntimeAfterMutationLocked(framework)
            : nullptr;
    pthread_mutex_unlock(&framework->mutex);
    DestroyDetachedRuntime(framework, detached);
    return result;
}

extern "C" HOOKSELF_API int32_t hookself_framework_register_redirect(
        HookselfFramework* framework, const char* guest_prefix,
        const char* host_prefix, const HookselfRedirectOptions* options,
        int32_t enabled, HookselfRuleHandle* handle) {
    if (guest_prefix == nullptr || host_prefix == nullptr || handle == nullptr ||
        (options != nullptr &&
         options->struct_size != sizeof(HookselfRedirectOptions))) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if (options != nullptr) {
        for (uint32_t reserved : options->reserved) {
            if (reserved != 0U) {
                return HOOKSELF_E_INVALID_ARGUMENT;
            }
        }
    }
    *handle = HOOKSELF_INVALID_RULE_HANDLE;
    HookselfRedirectOptions resolved{};
    hookself_framework_default_redirect_options(&resolved);
    if (options != nullptr) {
        resolved = *options;
    }
    HookselfPathRule rule{};
    rule.struct_size = sizeof(HookselfPathRule);
    rule.rule_id = resolved.rule_id;
    rule.priority = resolved.priority;
    rule.action = HOOKSELF_PATH_REDIRECT;
    rule.operation_mask = resolved.operation_mask;
    rule.flags = resolved.flags;
    if (!CopyBoundedString(rule.guest_prefix, sizeof(rule.guest_prefix),
                           guest_prefix) ||
        !CopyBoundedString(rule.host_prefix, sizeof(rule.host_prefix),
                           host_prefix)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const int32_t allowed = RegistryMutationAllowedLocked(framework);
    if (allowed != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return allowed;
    }
    if (rule.rule_id == 0U) {
        rule.rule_id = AllocatePathRuleIdLocked(framework);
        if (rule.rule_id == 0U) {
            pthread_mutex_unlock(&framework->mutex);
            return HOOKSELF_E_CAPACITY;
        }
    }
    const int32_t result = RegisterPathRuleLocked(
            framework, rule, enabled != 0, true, handle);
    HookselfRuntime* const detached = result == HOOKSELF_OK
            ? DetachStoppedRuntimeAfterMutationLocked(framework)
            : nullptr;
    pthread_mutex_unlock(&framework->mutex);
    DestroyDetachedRuntime(framework, detached);
    return result;
}

extern "C" HOOKSELF_API int32_t hookself_framework_find_rule(
        const HookselfFramework* framework, HookselfRuleKind kind,
        uint32_t rule_id, HookselfRuleHandle* handle) {
    if (handle == nullptr || rule_id == 0U ||
        (kind != HOOKSELF_RULE_KIND_PATH &&
         kind != HOOKSELF_RULE_KIND_SYSCALL)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *handle = HOOKSELF_INVALID_RULE_HANDLE;
    auto* mutable_framework = const_cast<HookselfFramework*>(framework);
    FrameworkCall call(mutable_framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&mutable_framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    if (kind == HOOKSELF_RULE_KIND_PATH) {
        for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
            const PathRuleSlot& slot = mutable_framework->path_slots[index];
            if (slot.used != 0U && slot.rule.rule_id == rule_id) {
                *handle = slot.handle;
                pthread_mutex_unlock(&mutable_framework->mutex);
                return HOOKSELF_OK;
            }
        }
    } else {
        for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
            const SyscallRuleSlot& slot =
                    mutable_framework->syscall_slots[index];
            if (slot.used != 0U && slot.rule.rule_id == rule_id) {
                *handle = slot.handle;
                pthread_mutex_unlock(&mutable_framework->mutex);
                return HOOKSELF_OK;
            }
        }
    }
    pthread_mutex_unlock(&mutable_framework->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}

extern "C" HOOKSELF_API int32_t hookself_framework_unregister_rule(
        HookselfFramework* framework, HookselfRuleHandle handle) {
    if (handle == HOOKSELF_INVALID_RULE_HANDLE) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const int32_t allowed = RegistryMutationAllowedLocked(framework);
    if (allowed != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return allowed;
    }
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        PathRuleSlot& slot = framework->path_slots[index];
        if (slot.used != 0U && slot.handle == handle) {
            slot = {};
            HookselfRuntime* const detached =
                    DetachStoppedRuntimeAfterMutationLocked(framework);
            pthread_mutex_unlock(&framework->mutex);
            DestroyDetachedRuntime(framework, detached);
            return HOOKSELF_OK;
        }
    }
    for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
        SyscallRuleSlot& slot = framework->syscall_slots[index];
        if (slot.used != 0U && slot.handle == handle) {
            slot = {};
            HookselfRuntime* const detached =
                    DetachStoppedRuntimeAfterMutationLocked(framework);
            pthread_mutex_unlock(&framework->mutex);
            DestroyDetachedRuntime(framework, detached);
            return HOOKSELF_OK;
        }
    }
    pthread_mutex_unlock(&framework->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}

extern "C" HOOKSELF_API int32_t hookself_framework_set_rule_enabled(
        HookselfFramework* framework, HookselfRuleHandle handle,
        int32_t enabled) {
    if (handle == HOOKSELF_INVALID_RULE_HANDLE) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    FrameworkCall call(framework);
    if (call.result() != HOOKSELF_OK) {
        return call.result();
    }
    if (pthread_mutex_lock(&framework->mutex) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const uint32_t next_enabled = enabled != 0 ? 1U : 0U;
    PathRuleSlot* path_match = nullptr;
    SyscallRuleSlot* syscall_match = nullptr;
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        PathRuleSlot& slot = framework->path_slots[index];
        if (slot.used != 0U && slot.handle == handle) {
            if (slot.enabled == next_enabled) {
                pthread_mutex_unlock(&framework->mutex);
                return HOOKSELF_OK;
            }
            path_match = &slot;
            break;
        }
    }
    if (path_match == nullptr) {
        for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES;
             ++index) {
            SyscallRuleSlot& slot = framework->syscall_slots[index];
            if (slot.used != 0U && slot.handle == handle) {
                if (slot.enabled == next_enabled) {
                    pthread_mutex_unlock(&framework->mutex);
                    return HOOKSELF_OK;
                }
                syscall_match = &slot;
                break;
            }
        }
    }
    const int32_t allowed = RegistryMutationAllowedLocked(framework);
    if (allowed != HOOKSELF_OK) {
        pthread_mutex_unlock(&framework->mutex);
        return allowed;
    }
    if (path_match != nullptr) {
        path_match->enabled = next_enabled;
        HookselfRuntime* const detached =
                DetachStoppedRuntimeAfterMutationLocked(framework);
        pthread_mutex_unlock(&framework->mutex);
        DestroyDetachedRuntime(framework, detached);
        return HOOKSELF_OK;
    }
    if (syscall_match != nullptr) {
        syscall_match->enabled = next_enabled;
        HookselfRuntime* const detached =
                DetachStoppedRuntimeAfterMutationLocked(framework);
        pthread_mutex_unlock(&framework->mutex);
        DestroyDetachedRuntime(framework, detached);
        return HOOKSELF_OK;
    }
    pthread_mutex_unlock(&framework->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}

extern "C" HOOKSELF_API int32_t hookself_framework_is_rule_enabled(
        const HookselfFramework* framework, HookselfRuleHandle handle,
        int32_t* enabled) {
    if (handle == HOOKSELF_INVALID_RULE_HANDLE || enabled == nullptr) {
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
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        const PathRuleSlot& slot = mutable_framework->path_slots[index];
        if (slot.used != 0U && slot.handle == handle) {
            *enabled = slot.enabled != 0U ? 1 : 0;
            pthread_mutex_unlock(&mutable_framework->mutex);
            return HOOKSELF_OK;
        }
    }
    for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
        const SyscallRuleSlot& slot = mutable_framework->syscall_slots[index];
        if (slot.used != 0U && slot.handle == handle) {
            *enabled = slot.enabled != 0U ? 1 : 0;
            pthread_mutex_unlock(&mutable_framework->mutex);
            return HOOKSELF_OK;
        }
    }
    pthread_mutex_unlock(&mutable_framework->mutex);
    return HOOKSELF_E_INVALID_ARGUMENT;
}

