#include "framework_facade_selftest.h"

#include <asm/unistd.h>

#include <cstddef>
#include <cstdint>

#include "framework_facade_lifetime_selftest.h"
#include "hookself/framework.h"

namespace hookself::internal {
namespace {

void Check(FrameworkFacadeSelfTestReport* report, bool condition,
           int32_t failure) {
    ++report->checks;
    if (!condition) {
        ++report->failures;
        if (report->first_failure == 0) {
            report->first_failure = failure;
        }
    }
}

void CopyString(char* destination, size_t capacity, const char* source) {
    size_t index = 0;
    while (index + 1U < capacity && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

bool RedirectReservedIsZero(const HookselfRedirectOptions& options) {
    for (uint32_t reserved : options.reserved) {
        if (reserved != 0U) {
            return false;
        }
    }
    return true;
}

bool StatsAreEmpty(const HookselfStats& stats) {
    return stats.emitted_events == 0U && stats.dropped_events == 0U &&
           stats.observed_syscalls == 0U && stats.redirected_paths == 0U &&
           stats.virtual_file_opens == 0U && stats.internal_errors == 0U &&
           stats.protected_fd_blocks == 0U &&
           stats.internal_fd_operations == 0U &&
           stats.ptrace_view_operations == 0U &&
           stats.proc_status_patches == 0U && stats.tracked_tasks == 0U &&
           stats.fatal_code == 0 && stats.fatal_errno == 0 &&
           stats.fatal_tid == 0;
}

}  // namespace

FrameworkFacadeSelfTestReport RunFrameworkFacadeSelfTest() {
    FrameworkFacadeSelfTestReport report{};

    HookselfPathRule initial_path{};
    initial_path.struct_size = sizeof(initial_path);
    initial_path.rule_id = 0x6411U;
    initial_path.action = HOOKSELF_PATH_PASS;
    initial_path.operation_mask = HOOKSELF_PATH_OP_ALL;
    CopyString(initial_path.guest_prefix, sizeof(initial_path.guest_prefix),
               "/hookself-facade-initial");

    HookselfSyscallRule initial_syscall{};
    initial_syscall.struct_size = sizeof(initial_syscall);
    initial_syscall.rule_id = 0x6412U;
    initial_syscall.syscall_number = __NR_getpid;
    initial_syscall.action = HOOKSELF_SYSCALL_OBSERVE;
    initial_syscall.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;

    HookselfConfig facade_config{};
    hookself_framework_default_config(&facade_config);
    facade_config.path_rule_count = 1U;
    facade_config.path_rules = &initial_path;
    facade_config.syscall_rule_count = 1U;
    facade_config.syscall_rules = &initial_syscall;
    HookselfFramework* facade = nullptr;
    const int32_t create_result = hookself_framework_create(
            &facade_config, &facade);
    initial_path.rule_id = 0x6413U;
    initial_syscall.rule_id = 0x6414U;
    Check(&report,
          facade_config.failure_mode == HOOKSELF_FAILURE_FAIL_CLOSED &&
                  create_result == HOOKSELF_OK && facade != nullptr,
          6401);

    int32_t facade_state = HOOKSELF_STATE_IDLE;
    Check(&report,
          facade != nullptr &&
                  hookself_framework_get_state(facade, &facade_state) ==
                          HOOKSELF_OK &&
                  facade_state == HOOKSELF_STATE_CONFIGURED,
          6402);

    HookselfRuleHandle initial_path_handle = HOOKSELF_INVALID_RULE_HANDLE;
    HookselfRuleHandle initial_syscall_handle = HOOKSELF_INVALID_RULE_HANDLE;
    int32_t initial_path_enabled = 0;
    int32_t initial_syscall_enabled = 0;
    const bool initial_handles_found = facade != nullptr &&
            hookself_framework_find_rule(
                    facade, HOOKSELF_RULE_KIND_PATH, 0x6411U,
                    &initial_path_handle) == HOOKSELF_OK &&
            hookself_framework_find_rule(
                    facade, HOOKSELF_RULE_KIND_SYSCALL, 0x6412U,
                    &initial_syscall_handle) == HOOKSELF_OK &&
            initial_path_handle != HOOKSELF_INVALID_RULE_HANDLE &&
            initial_syscall_handle != HOOKSELF_INVALID_RULE_HANDLE &&
            initial_path_handle != initial_syscall_handle &&
            hookself_framework_is_rule_enabled(
                    facade, initial_path_handle,
                    &initial_path_enabled) == HOOKSELF_OK &&
            hookself_framework_is_rule_enabled(
                    facade, initial_syscall_handle,
                    &initial_syscall_enabled) == HOOKSELF_OK &&
            initial_path_enabled == 1 && initial_syscall_enabled == 1;
    Check(&report, initial_handles_found, 6409);

    HookselfRuleHandle mutated_handle = UINT64_C(99);
    const bool input_rules_copied = facade != nullptr &&
            hookself_framework_find_rule(
                    facade, HOOKSELF_RULE_KIND_PATH, 0x6413U,
                    &mutated_handle) == HOOKSELF_E_INVALID_ARGUMENT &&
            mutated_handle == HOOKSELF_INVALID_RULE_HANDLE &&
            hookself_framework_find_rule(
                    facade, HOOKSELF_RULE_KIND_SYSCALL, 0x6414U,
                    &mutated_handle) == HOOKSELF_E_INVALID_ARGUMENT &&
            mutated_handle == HOOKSELF_INVALID_RULE_HANDLE;
    Check(&report, input_rules_copied, 6410);

    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    Check(&report,
          facade != nullptr &&
                  hookself_framework_get_stats(facade, &stats) ==
                          HOOKSELF_OK &&
                  stats.struct_size == sizeof(stats) &&
                  stats.state == HOOKSELF_STATE_CONFIGURED &&
                  StatsAreEmpty(stats),
          6411);

    HookselfEvent event{};
    size_t consumed = 7U;
    size_t emitted = 9U;
    const uint8_t snapshot[] = {'n', 'o', '-', 'r', 'u', 'n', 't', 'i', 'm', 'e'};
    const bool no_runtime_forwarding = facade != nullptr &&
            hookself_framework_read_events(facade, &event, 1U) == 0U &&
            hookself_framework_drain_logs(
                    facade, 1U, &consumed,
                    &emitted) == HOOKSELF_E_INVALID_STATE &&
            consumed == 0U && emitted == 0U &&
            hookself_framework_publish_virtual_file(
                    facade, 1U, snapshot,
                    sizeof(snapshot)) == HOOKSELF_E_INVALID_STATE &&
            hookself_framework_refresh_virtual_file(
                    facade, 1U) == HOOKSELF_E_INVALID_STATE &&
            hookself_framework_set_log_sink(
                    facade, nullptr, nullptr) == HOOKSELF_OK &&
            hookself_framework_stop(facade) == HOOKSELF_OK;
    Check(&report, no_runtime_forwarding, 6412);

    HookselfSyscallRule syscall_rule{};
    syscall_rule.struct_size = sizeof(syscall_rule);
    syscall_rule.rule_id = 0x6401U;
    syscall_rule.syscall_number = __NR_getpid;
    syscall_rule.action = HOOKSELF_SYSCALL_OBSERVE;
    syscall_rule.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    HookselfRuleHandle syscall_handle = HOOKSELF_INVALID_RULE_HANDLE;
    Check(&report,
          facade != nullptr &&
                  hookself_framework_register_syscall_rule(
                          facade, &syscall_rule, 0,
                          &syscall_handle) == HOOKSELF_OK &&
                  syscall_handle != HOOKSELF_INVALID_RULE_HANDLE,
          6403);

    int32_t enabled = -1;
    Check(&report,
          hookself_framework_is_rule_enabled(
                  facade, syscall_handle, &enabled) == HOOKSELF_OK &&
                  enabled == 0,
          6404);
    Check(&report,
          hookself_framework_set_rule_enabled(
                  facade, syscall_handle, 1) == HOOKSELF_OK &&
                  hookself_framework_is_rule_enabled(
                          facade, syscall_handle, &enabled) == HOOKSELF_OK &&
                  enabled == 1,
          6405);
    const bool enable_disable_noops =
            hookself_framework_set_rule_enabled(
                    facade, syscall_handle, 1) == HOOKSELF_OK &&
            hookself_framework_set_rule_enabled(
                    facade, syscall_handle, 0) == HOOKSELF_OK &&
            hookself_framework_is_rule_enabled(
                    facade, syscall_handle, &enabled) == HOOKSELF_OK &&
            enabled == 0 &&
            hookself_framework_set_rule_enabled(
                    facade, syscall_handle, 0) == HOOKSELF_OK &&
            hookself_framework_set_rule_enabled(
                    facade, syscall_handle, 1) == HOOKSELF_OK;
    Check(&report, enable_disable_noops, 6413);

    HookselfRedirectOptions redirect_options{};
    hookself_framework_default_redirect_options(&redirect_options);
    const bool redirect_defaults =
            redirect_options.struct_size == sizeof(redirect_options) &&
            redirect_options.rule_id == 0U &&
            redirect_options.priority == 0 &&
            redirect_options.operation_mask == HOOKSELF_PATH_OP_ALL &&
            redirect_options.flags == 0U &&
            RedirectReservedIsZero(redirect_options);
    Check(&report, redirect_defaults, 6414);

    redirect_options.rule_id = 0x6402U;
    redirect_options.operation_mask = HOOKSELF_PATH_OP_READ;
    HookselfRuleHandle redirect_handle = HOOKSELF_INVALID_RULE_HANDLE;
    Check(&report,
          hookself_framework_register_redirect(
                  facade, "/hookself-facade-guest",
                  "/hookself-facade-host", &redirect_options, 0,
                  &redirect_handle) == HOOKSELF_OK &&
                  redirect_handle != HOOKSELF_INVALID_RULE_HANDLE,
          6406);
    Check(&report,
          hookself_framework_is_rule_enabled(
                  facade, redirect_handle, &enabled) == HOOKSELF_OK &&
                  enabled == 0,
          6407);

    HookselfRuleHandle default_redirect_handle =
            HOOKSELF_INVALID_RULE_HANDLE;
    HookselfRuleHandle found_default_redirect =
            HOOKSELF_INVALID_RULE_HANDLE;
    const bool default_redirect_registered =
            hookself_framework_register_redirect(
                    facade, "/hookself-facade-default-guest",
                    "/hookself-facade-default-host", nullptr, 1,
                    &default_redirect_handle) == HOOKSELF_OK &&
            default_redirect_handle != HOOKSELF_INVALID_RULE_HANDLE &&
            hookself_framework_find_rule(
                    facade, HOOKSELF_RULE_KIND_PATH, 1U,
                    &found_default_redirect) == HOOKSELF_OK &&
            found_default_redirect == default_redirect_handle;
    Check(&report, default_redirect_registered, 6415);

    HookselfRedirectOptions invalid_options{};
    hookself_framework_default_redirect_options(&invalid_options);
    invalid_options.reserved[2] = 1U;
    HookselfRuleHandle invalid_handle = HOOKSELF_INVALID_RULE_HANDLE;
    const bool reserved_rejected =
            hookself_framework_register_redirect(
                    facade, "/hookself-facade-reserved-guest",
                    "/hookself-facade-reserved-host", &invalid_options, 1,
                    &invalid_handle) == HOOKSELF_E_INVALID_ARGUMENT;
    Check(&report, reserved_rejected, 6416);

    hookself_framework_default_redirect_options(&invalid_options);
    invalid_options.rule_id = HOOKSELF_BUILTIN_RULE_ID_MIN;
    const bool redirect_builtin_rejected =
            hookself_framework_register_redirect(
                    facade, "/hookself-facade-builtin-guest",
                    "/hookself-facade-builtin-host", &invalid_options, 1,
                    &invalid_handle) == HOOKSELF_E_INVALID_ARGUMENT;
    Check(&report, redirect_builtin_rejected, 6417);

    HookselfPathRule invalid_path{};
    invalid_path.struct_size = sizeof(invalid_path);
    invalid_path.action = HOOKSELF_PATH_PASS;
    invalid_path.operation_mask = HOOKSELF_PATH_OP_ALL;
    CopyString(invalid_path.guest_prefix, sizeof(invalid_path.guest_prefix),
               "/hookself-facade-invalid-id");
    invalid_path.rule_id = 0U;
    const int32_t zero_id_result = hookself_framework_register_path_rule(
            facade, &invalid_path, 1, &invalid_handle);
    invalid_path.rule_id = HOOKSELF_BUILTIN_RULE_ID_MIN;
    const int32_t builtin_id_result = hookself_framework_register_path_rule(
            facade, &invalid_path, 1, &invalid_handle);
    Check(&report,
          zero_id_result == HOOKSELF_E_INVALID_ARGUMENT &&
                  builtin_id_result == HOOKSELF_E_INVALID_ARGUMENT,
          6418);

    HookselfConfig builtin_path_config{};
    hookself_framework_default_config(&builtin_path_config);
    builtin_path_config.path_rule_count = 1U;
    builtin_path_config.path_rules = &invalid_path;
    HookselfFramework* builtin_path_facade = nullptr;
    Check(&report,
          hookself_framework_create(
                  &builtin_path_config,
                  &builtin_path_facade) == HOOKSELF_E_INVALID_ARGUMENT &&
                  builtin_path_facade == nullptr,
          6419);

    Check(&report,
          hookself_framework_unregister_rule(
                  facade, redirect_handle) == HOOKSELF_OK &&
                  hookself_framework_unregister_rule(
                          facade, syscall_handle) == HOOKSELF_OK &&
                  hookself_framework_unregister_rule(
                          facade, default_redirect_handle) == HOOKSELF_OK,
          6408);
    hookself_framework_destroy(facade);

    Check(&report, RunFrameworkFacadeLifetimeSelfTest(), 6490);
    return report;
}

}  // namespace hookself::internal
