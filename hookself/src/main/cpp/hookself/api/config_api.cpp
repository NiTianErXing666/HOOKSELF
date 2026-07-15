#include "hookself/public_api.h"

#include <cstddef>
#include <cstdint>

#include "internal/logical_ptrace_resident_state.h"
#include "internal/virtual_file_store.h"

namespace {

constexpr uint32_t kKnownConfigFlags =
        HOOKSELF_CONFIG_OBSERVE_ALL |
        HOOKSELF_CONFIG_CAPTURE_PATHS |
        HOOKSELF_CONFIG_CAPTURE_ARGUMENTS |
        HOOKSELF_CONFIG_CAPTURE_RESULTS |
        HOOKSELF_CONFIG_TRACE_DESCENDANTS |
        HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
        HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
        HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
        HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP |
        HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW |
        HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE;

constexpr uint64_t kRuntimePtraceFeatures =
        HOOKSELF_PTRACE_FEATURE_TRACEME_VIEW |
        HOOKSELF_PTRACE_FEATURE_DUMPABLE_PTRACER_VIEW |
        HOOKSELF_PTRACE_FEATURE_PROC_STATUS_VIEW |
        HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC;

constexpr uint64_t kLogicalEnginePtraceFeatures =
        HOOKSELF_PTRACE_FEATURE_TRACEME_VIEW |
        HOOKSELF_PTRACE_FEATURE_DESCENDANT_TGID_STATE |
        HOOKSELF_PTRACE_FEATURE_ATTACH_SEIZE |
        HOOKSELF_PTRACE_FEATURE_RESUME_CONTROL |
        HOOKSELF_PTRACE_FEATURE_WAIT_EMULATION |
        HOOKSELF_PTRACE_FEATURE_SIGNAL_STATE |
        HOOKSELF_PTRACE_FEATURE_MEMORY_ACCESS |
        HOOKSELF_PTRACE_FEATURE_REGSET |
        HOOKSELF_PTRACE_FEATURE_SYSCALL_INFO;

bool BoundedString(const char* value, size_t capacity, size_t* length) {
    for (size_t i = 0; i < capacity; ++i) {
        if (value[i] == '\0') {
            if (length != nullptr) {
                *length = i;
            }
            return true;
        }
    }
    return false;
}

bool CanonicalAbsolutePrefix(const char* value, size_t capacity) {
    size_t length = 0;
    if (!BoundedString(value, capacity, &length) || length == 0 || value[0] != '/') {
        return false;
    }
    if (length == 1) {
        return true;
    }
    if (value[length - 1] == '/') {
        return false;
    }
    size_t segment_start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && value[i] != '/') {
            continue;
        }
        const size_t segment_length = i - segment_start;
        if (segment_length == 0 ||
            (segment_length == 1 && value[segment_start] == '.') ||
            (segment_length == 2 && value[segment_start] == '.' &&
             value[segment_start + 1] == '.')) {
            return false;
        }
        segment_start = i + 1;
    }
    return true;
}

template <typename T>
bool UniqueRuleIds(const T* rules, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        for (uint32_t j = i + 1; j < count; ++j) {
            if (rules[i].rule_id == rules[j].rule_id) {
                return false;
            }
        }
    }
    return true;
}

bool UniqueVirtualFileIds(const HookselfVirtualFile* files, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        for (uint32_t j = i + 1; j < count; ++j) {
            if (files[i].file_id == files[j].file_id) {
                return false;
            }
        }
    }
    return true;
}

int32_t ValidatePathRules(const HookselfConfig* config) {
    if (config->path_rule_count > HOOKSELF_MAX_PATH_RULES ||
        (config->path_rule_count != 0 && config->path_rules == nullptr)) {
        return HOOKSELF_E_CAPACITY;
    }
    for (uint32_t i = 0; i < config->path_rule_count; ++i) {
        const HookselfPathRule& rule = config->path_rules[i];
        if (rule.struct_size != sizeof(HookselfPathRule) || rule.rule_id == 0 ||
            rule.rule_id >= HOOKSELF_BUILTIN_RULE_ID_MIN ||
            rule.action < HOOKSELF_PATH_PASS ||
            rule.action > HOOKSELF_PATH_VIRTUAL_FILE ||
            rule.operation_mask == 0 ||
            (rule.operation_mask & ~HOOKSELF_PATH_OP_ALL) != 0 ||
            (rule.flags & ~(HOOKSELF_PATH_RULE_FOLLOW_FINAL |
                            HOOKSELF_PATH_RULE_READ_ONLY |
                            HOOKSELF_PATH_RULE_REVERSE_VISIBLE)) != 0 ||
            !CanonicalAbsolutePrefix(rule.guest_prefix, sizeof(rule.guest_prefix))) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (rule.action == HOOKSELF_PATH_REDIRECT &&
            !CanonicalAbsolutePrefix(rule.host_prefix, sizeof(rule.host_prefix))) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (rule.action == HOOKSELF_PATH_DENY &&
            (rule.deny_errno <= 0 || rule.deny_errno > 4095)) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
    }
    return UniqueRuleIds(config->path_rules, config->path_rule_count)
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INVALID_ARGUMENT;
}

int32_t ValidateSyscallRules(const HookselfConfig* config) {
    if (config->syscall_rule_count > HOOKSELF_MAX_SYSCALL_RULES ||
        (config->syscall_rule_count != 0 && config->syscall_rules == nullptr)) {
        return HOOKSELF_E_CAPACITY;
    }
    for (uint32_t i = 0; i < config->syscall_rule_count; ++i) {
        const HookselfSyscallRule& rule = config->syscall_rules[i];
        if (rule.struct_size != sizeof(HookselfSyscallRule) || rule.rule_id == 0 ||
            rule.rule_id >= HOOKSELF_BUILTIN_RULE_ID_MIN ||
            rule.syscall_number < 0 ||
            rule.syscall_number >= static_cast<int32_t>(HOOKSELF_SYSCALL_LIMIT) ||
            rule.action < HOOKSELF_SYSCALL_PASS ||
            rule.action > HOOKSELF_SYSCALL_REPLACE_ARGUMENT ||
            rule.phase_mask == 0 || (rule.phase_mask & ~HOOKSELF_SYSCALL_PHASE_BOTH) != 0 ||
            rule.argument_index >= 6) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (rule.action == HOOKSELF_SYSCALL_DENY &&
            (rule.deny_errno <= 0 || rule.deny_errno > 4095)) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (rule.action == HOOKSELF_SYSCALL_REPLACE_NUMBER &&
            (rule.replacement_syscall_number < 0 ||
             rule.replacement_syscall_number >=
                     static_cast<int32_t>(HOOKSELF_SYSCALL_LIMIT))) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if ((rule.action == HOOKSELF_SYSCALL_DENY ||
             rule.action == HOOKSELF_SYSCALL_REPLACE_NUMBER ||
             rule.action == HOOKSELF_SYSCALL_REPLACE_ARGUMENT) &&
            (rule.phase_mask & HOOKSELF_SYSCALL_PHASE_ENTRY) == 0) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (rule.action == HOOKSELF_SYSCALL_REPLACE_RESULT &&
            (rule.phase_mask & HOOKSELF_SYSCALL_PHASE_EXIT) == 0) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
    }
    return UniqueRuleIds(config->syscall_rules, config->syscall_rule_count)
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INVALID_ARGUMENT;
}

int32_t ValidateVirtualFiles(const HookselfConfig* config) {
    if (config->virtual_file_count > HOOKSELF_MAX_VIRTUAL_FILES ||
        (config->virtual_file_count != 0 && config->virtual_files == nullptr)) {
        return HOOKSELF_E_CAPACITY;
    }
    if (config->virtual_file_count != 0) {
        size_t backing_root_length = 0;
        if (!CanonicalAbsolutePrefix(config->virtual_backing_dir,
                                     sizeof(config->virtual_backing_dir)) ||
            !BoundedString(config->virtual_backing_dir,
                           sizeof(config->virtual_backing_dir),
                           &backing_root_length) ||
            backing_root_length + 1U +
                    (hookself::internal::kVirtualBackingSessionNameCapacity -
                     1U) +
                    1U +
                    (hookself::internal::kVirtualBackingFileNameCapacity -
                     1U) +
                    1U >
                    sizeof(config->virtual_backing_dir)) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
    }
    for (uint32_t i = 0; i < config->virtual_file_count; ++i) {
        const HookselfVirtualFile& file = config->virtual_files[i];
        if (file.struct_size != sizeof(HookselfVirtualFile) || file.file_id == 0 ||
            file.provider < HOOKSELF_VFILE_STATIC ||
            file.provider > HOOKSELF_VFILE_SELINUX_CONTEXT ||
            !CanonicalAbsolutePrefix(file.guest_path, sizeof(file.guest_path)) ||
            file.initial_content_size > HOOKSELF_MAX_VIRTUAL_FILE_SIZE ||
            (file.initial_content_size != 0 && file.initial_content == nullptr) ||
            (file.flags & ~HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS) != 0 ||
            (file.flags != 0 && file.provider != HOOKSELF_VFILE_PROC_MAPS) ||
            (file.mode & ~0777U) != 0 ||
            (file.mode & 0222U) != 0) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        for (uint32_t other = i + 1; other < config->virtual_file_count; ++other) {
            size_t left_length = 0;
            size_t right_length = 0;
            if (!BoundedString(file.guest_path, sizeof(file.guest_path),
                               &left_length) ||
                !BoundedString(config->virtual_files[other].guest_path,
                               sizeof(config->virtual_files[other].guest_path),
                               &right_length) ||
                (left_length == right_length &&
                 __builtin_memcmp(file.guest_path,
                                  config->virtual_files[other].guest_path,
                                  left_length) == 0)) {
                return HOOKSELF_E_INVALID_ARGUMENT;
            }
        }
    }
    return UniqueVirtualFileIds(config->virtual_files, config->virtual_file_count)
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INVALID_ARGUMENT;
}

}  // namespace

extern "C" void hookself_default_config(HookselfConfig* config) {
    if (config == nullptr) {
        return;
    }
    *config = {};
    config->struct_size = sizeof(HookselfConfig);
    config->abi_version = HOOKSELF_ABI_VERSION;
    config->backend = HOOKSELF_BACKEND_FORK_RAW;
    config->failure_mode = HOOKSELF_FAILURE_FULL_PTRACE_FAIL_OPEN;
    config->log_level = HOOKSELF_LOG_INFO;
    config->flags = HOOKSELF_CONFIG_CAPTURE_PATHS |
                    HOOKSELF_CONFIG_CAPTURE_ARGUMENTS |
                    HOOKSELF_CONFIG_CAPTURE_RESULTS;
    config->event_capacity = 256;
}

extern "C" int32_t hookself_validate_config(const HookselfConfig* config) {
    if (config == nullptr || config->struct_size != sizeof(HookselfConfig)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if (config->abi_version != HOOKSELF_ABI_VERSION) {
        return HOOKSELF_E_ABI_MISMATCH;
    }
    if (config->backend < HOOKSELF_BACKEND_FORK_RAW ||
        config->backend > HOOKSELF_BACKEND_APP_SERVICE ||
        config->failure_mode < HOOKSELF_FAILURE_FULL_PTRACE_FAIL_OPEN ||
        config->failure_mode > HOOKSELF_FAILURE_FAIL_CLOSED ||
        config->log_level < HOOKSELF_LOG_OFF || config->log_level > HOOKSELF_LOG_TRACE ||
        (config->flags & ~kKnownConfigFlags) != 0 || config->event_capacity == 0 ||
        config->event_capacity > HOOKSELF_MAX_EVENT_CAPACITY) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if ((config->flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0 &&
        (config->failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED ||
         (config->flags & HOOKSELF_CONFIG_TRACE_DESCENDANTS) == 0 ||
         (config->flags & HOOKSELF_CONFIG_OBSERVE_ALL) != 0)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if ((config->flags & HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE) != 0 &&
        (config->failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED ||
         (config->flags & HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0 ||
         (config->flags & HOOKSELF_CONFIG_TRACE_DESCENDANTS) == 0 ||
         (config->flags &
          HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if (config->virtual_file_count != 0 &&
        (config->flags & HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES) == 0) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if ((config->flags & (HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                          HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
                          HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                          HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE |
                          HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW)) != 0 &&
        config->failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    int32_t result = ValidatePathRules(config);
    if (result != HOOKSELF_OK) {
        return result;
    }
    result = ValidateSyscallRules(config);
    if (result != HOOKSELF_OK) {
        return result;
    }
    if (config->failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED) {
        for (uint32_t i = 0; i < config->syscall_rule_count; ++i) {
            if (config->syscall_rules[i].action > HOOKSELF_SYSCALL_OBSERVE) {
                return HOOKSELF_E_INVALID_ARGUMENT;
            }
        }
    }
    return ValidateVirtualFiles(config);
}

extern "C" const char* hookself_result_string(int32_t result) {
    switch (result) {
        case HOOKSELF_OK: return "OK";
        case HOOKSELF_E_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case HOOKSELF_E_ABI_MISMATCH: return "ABI_MISMATCH";
        case HOOKSELF_E_INVALID_STATE: return "INVALID_STATE";
        case HOOKSELF_E_BUSY: return "BUSY";
        case HOOKSELF_E_NO_MEMORY: return "NO_MEMORY";
        case HOOKSELF_E_UNSUPPORTED: return "UNSUPPORTED";
        case HOOKSELF_E_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
        case HOOKSELF_E_CAPACITY: return "CAPACITY";
        case HOOKSELF_E_INTERNAL: return "INTERNAL";
        default: return "UNKNOWN";
    }
}

extern "C" int32_t hookself_get_ptrace_capabilities(
        HookselfPtraceCapabilities* capabilities) {
    if (capabilities == nullptr ||
        capabilities->struct_size != sizeof(HookselfPtraceCapabilities)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    HookselfPtraceCapabilities output{};
    output.struct_size = sizeof(output);
    output.version = HOOKSELF_PTRACE_CAPABILITIES_VERSION;
    output.runtime_features = kRuntimePtraceFeatures;
    output.engine_features = kLogicalEnginePtraceFeatures;
    output.max_tasks = hookself::internal::kLogicalPtraceResidentCapacity;
    output.max_relations =
            hookself::tracer::kLogicalPtraceRelationCapacity;
    output.max_pending_waits =
            hookself::tracer::kLogicalPtraceWaitCapacity;
    output.per_tracee_event_capacity =
            hookself::tracer::kLogicalPtraceEventQueueCapacity;
    *capabilities = output;
    return HOOKSELF_OK;
}
