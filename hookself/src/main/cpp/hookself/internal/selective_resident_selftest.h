#pragma once

#include <cstdint>
#include <string>

namespace hookself::internal {

constexpr uint32_t kSelectiveResidentSelfTestVersion = 1U;
constexpr uint32_t kSelectiveResidentSelfTestMaxIterations = 10000U;

struct SelectiveResidentSelfTestReport {
    uint32_t version;
    int32_t verdict;
    int32_t first_failure;
    uint32_t requested_iterations;
    uint32_t completed_iterations;
    uint32_t config_flags;
    int32_t failure_mode;
    uint32_t rule_count;
    int32_t validate_result;
    int32_t create_result;
    int32_t configured_state;
    uint32_t start_calls;
    uint32_t start_successes;
    int32_t last_start_result;
    uint32_t running_state_checks;
    int32_t last_running_state;
    uint32_t stop_calls;
    uint32_t stop_successes;
    int32_t last_stop_result;
    uint32_t stopped_state_checks;
    int32_t last_stopped_state;
    uint32_t active_rounds;
    uint32_t active_rounds_passed;
    uint32_t passthrough_rounds;
    uint32_t passthrough_rounds_passed;
    int32_t expected_pid;
    int32_t expected_tid;
    int32_t expected_ppid;
    int64_t last_active_gettid;
    int64_t last_active_getpid;
    int64_t last_active_getppid;
    int64_t last_passthrough_gettid;
    int64_t last_passthrough_getpid;
    int64_t last_passthrough_getppid;
    uint32_t active_gettid_calls;
    uint32_t active_getpid_calls;
    uint32_t active_getppid_calls;
    uint32_t passthrough_gettid_calls;
    uint32_t passthrough_getpid_calls;
    uint32_t passthrough_getppid_calls;
    uint32_t gettid_entry_events;
    uint32_t gettid_exit_events;
    uint32_t gettid_result_matches;
    uint32_t getpid_entry_events;
    uint32_t getpid_exit_events;
    uint32_t getppid_deny_entry_events;
    uint32_t getppid_deny_exit_events;
    uint32_t getppid_deny_result_matches;
    uint32_t control_rule_events;
    uint32_t passthrough_rule_events;
    uint32_t unexpected_rule_events;
    uint64_t events_read;
    int32_t final_stop_result;
    int32_t final_state;
    int32_t stats_result;
    uint32_t stats_state;
    uint64_t emitted_events;
    uint64_t observed_syscalls;
    uint64_t dropped_events;
    uint64_t internal_errors;
    uint32_t tracked_tasks;
    int32_t fatal_code;
    int32_t fatal_errno;
    int32_t fatal_tid;
};

SelectiveResidentSelfTestReport RunSelectiveResidentSelfTest(
        uint32_t iterations, const char* virtual_backing_dir) noexcept;
std::string FormatSelectiveResidentSelfTestReport(
        const SelectiveResidentSelfTestReport& report);

}  // namespace hookself::internal
