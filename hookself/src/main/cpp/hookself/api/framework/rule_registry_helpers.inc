bool CopyBoundedString(char* destination, size_t capacity,
                       const char* source) {
    if (destination == nullptr || capacity == 0U || source == nullptr) {
        return false;
    }
    size_t length = 0;
    while (length < capacity && source[length] != '\0') {
        ++length;
    }
    if (length == capacity) {
        return false;
    }
    for (size_t index = 0; index <= length; ++index) {
        destination[index] = source[index];
    }
    return true;
}

bool HandleInUseLocked(const HookselfFramework* framework,
                       HookselfRuleHandle handle) {
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        if (framework->path_slots[index].used != 0U &&
            framework->path_slots[index].handle == handle) {
            return true;
        }
    }
    for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
        if (framework->syscall_slots[index].used != 0U &&
            framework->syscall_slots[index].handle == handle) {
            return true;
        }
    }
    return false;
}

HookselfRuleHandle AllocateHandleLocked(HookselfFramework* framework) {
    for (uint32_t attempt = 0;
         attempt <= HOOKSELF_MAX_PATH_RULES + HOOKSELF_MAX_SYSCALL_RULES;
         ++attempt) {
        HookselfRuleHandle candidate = framework->next_handle++;
        if (candidate == HOOKSELF_INVALID_RULE_HANDLE) {
            candidate = framework->next_handle++;
        }
        if (candidate != HOOKSELF_INVALID_RULE_HANDLE &&
            !HandleInUseLocked(framework, candidate)) {
            return candidate;
        }
    }
    return HOOKSELF_INVALID_RULE_HANDLE;
}

bool PathRuleIdInUseLocked(const HookselfFramework* framework,
                           uint32_t rule_id) {
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        if (framework->path_slots[index].used != 0U &&
            framework->path_slots[index].rule.rule_id == rule_id) {
            return true;
        }
    }
    return false;
}

uint32_t AllocatePathRuleIdLocked(HookselfFramework* framework) {
    for (uint32_t attempt = 0; attempt <= HOOKSELF_MAX_PATH_RULES; ++attempt) {
        uint32_t candidate = framework->next_path_rule_id++;
        if (candidate == 0U || candidate >= HOOKSELF_BUILTIN_RULE_ID_MIN) {
            framework->next_path_rule_id = 2U;
            candidate = 1U;
        }
        if (!PathRuleIdInUseLocked(framework, candidate)) {
            return candidate;
        }
    }
    return 0U;
}

void BuildConfigLocked(HookselfFramework* framework, HookselfConfig* output) {
    *output = framework->config;
    output->path_rule_count = 0U;
    output->path_rules = nullptr;
    output->syscall_rule_count = 0U;
    output->syscall_rules = nullptr;
    bool enable_path_policy = false;
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        const PathRuleSlot& slot = framework->path_slots[index];
        if (slot.used == 0U) {
            continue;
        }
        HookselfPathRule& built =
                framework->built_path_rules[output->path_rule_count++];
        built = slot.rule;
        if (slot.enabled == 0U) {
            built.action = HOOKSELF_PATH_PASS;
        }
        enable_path_policy |= slot.enable_path_policy != 0U;
    }
    if (output->path_rule_count != 0U) {
        output->path_rules = framework->built_path_rules;
    }
    if (enable_path_policy) {
        output->flags |= HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT;
    }
    for (uint32_t index = 0; index < HOOKSELF_MAX_SYSCALL_RULES; ++index) {
        const SyscallRuleSlot& slot = framework->syscall_slots[index];
        if (slot.used == 0U) {
            continue;
        }
        HookselfSyscallRule& built =
                framework->built_syscall_rules[output->syscall_rule_count++];
        built = slot.rule;
        if (slot.enabled == 0U) {
            built.action = HOOKSELF_SYSCALL_PASS;
        }
    }
    if (output->syscall_rule_count != 0U) {
        output->syscall_rules = framework->built_syscall_rules;
    }
    output->virtual_files = output->virtual_file_count == 0U
                                    ? nullptr
                                    : framework->virtual_files;
}

int32_t ValidateRegistryLocked(HookselfFramework* framework) {
    HookselfConfig candidate{};
    BuildConfigLocked(framework, &candidate);
    return hookself_validate_config(&candidate);
}

int32_t RegistryMutationAllowedLocked(const HookselfFramework* framework) {
    if (framework->lifecycle_busy != 0U || framework->runtime_users != 0U) {
        return HOOKSELF_E_BUSY;
    }
    if (framework->closing != 0U || framework->registry_frozen != 0U) {
        return HOOKSELF_E_INVALID_STATE;
    }
    if (framework->runtime == nullptr) {
        return HOOKSELF_OK;
    }
    int32_t state = HOOKSELF_STATE_IDLE;
    const int32_t result = hookself_get_state(framework->runtime, &state);
    if (result != HOOKSELF_OK) {
        return result;
    }
    return state == HOOKSELF_STATE_STOPPED ||
                   state == HOOKSELF_STATE_CONFIGURED
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INVALID_STATE;
}

HookselfRuntime* DetachStoppedRuntimeAfterMutationLocked(
        HookselfFramework* framework) {
    HookselfRuntime* const runtime = framework->runtime;
    if (runtime != nullptr) {
        framework->runtime = nullptr;
        ++framework->runtime_generation;
        framework->lifecycle_busy = 1U;
    }
    return runtime;
}

void FinishLifecycle(HookselfFramework* framework);

void DestroyDetachedRuntime(HookselfFramework* framework,
                            HookselfRuntime* runtime) {
    if (runtime == nullptr) {
        return;
    }
    hookself_destroy(runtime);
    FinishLifecycle(framework);
}

int32_t RegisterPathRuleLocked(HookselfFramework* framework,
                               const HookselfPathRule& rule, bool enabled,
                               bool enable_path_policy,
                               HookselfRuleHandle* handle) {
    if (rule.rule_id == 0U ||
        rule.rule_id >= HOOKSELF_BUILTIN_RULE_ID_MIN) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    const int32_t allowed = RegistryMutationAllowedLocked(framework);
    if (allowed != HOOKSELF_OK) {
        return allowed;
    }
    uint32_t slot_index = HOOKSELF_MAX_PATH_RULES;
    for (uint32_t index = 0; index < HOOKSELF_MAX_PATH_RULES; ++index) {
        if (framework->path_slots[index].used == 0U) {
            slot_index = index;
            break;
        }
    }
    if (slot_index == HOOKSELF_MAX_PATH_RULES) {
        return HOOKSELF_E_CAPACITY;
    }
    const HookselfRuleHandle candidate_handle =
            AllocateHandleLocked(framework);
    if (candidate_handle == HOOKSELF_INVALID_RULE_HANDLE) {
        return HOOKSELF_E_CAPACITY;
    }
    PathRuleSlot& slot = framework->path_slots[slot_index];
    slot = {};
    slot.rule = rule;
    slot.handle = candidate_handle;
    slot.used = 1U;
    slot.enabled = 1U;
    slot.enable_path_policy = enable_path_policy ? 1U : 0U;
    const int32_t validation = ValidateRegistryLocked(framework);
    if (validation != HOOKSELF_OK) {
        slot = {};
        return validation;
    }
    slot.enabled = enabled ? 1U : 0U;
    *handle = candidate_handle;
    return HOOKSELF_OK;
}

