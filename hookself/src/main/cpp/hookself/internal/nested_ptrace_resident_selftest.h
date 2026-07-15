#pragma once

#include <cstdint>

namespace hookself::internal {

constexpr uint32_t kNestedPtraceResidentSelfTestVersion = 1U;

// A fixed-size report so JNI callers can format the result without depending
// on the resident tracer's private state.
struct NestedPtraceResidentSelfTestReport {
    uint32_t version;
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
    int32_t verdict;

    int32_t validate_result;
    int32_t create_result;
    int32_t start_result;
    int32_t running_state;
    int32_t stop_result;
    int32_t stopped_state;
    int32_t stats_result;
    int32_t fatal_code;
    int32_t fatal_errno;
    uint64_t dropped_events;

    int32_t wait4_child_pid;
    int32_t wait4_new_task_event;
    int64_t wait4_traceme_result;
    int32_t wait4_wait_entry_event;
    int32_t wait4_release_result;
    int64_t wait4_result;
    int32_t wait4_status;
    int32_t wait4_initial_signal_stop;
    int64_t wait4_setoptions_result;
    int64_t wait4_first_cont_result;
    int64_t wait4_exec_result;
    int32_t wait4_exec_status;
    int32_t wait4_exec_stop;
    int64_t wait4_geteventmsg_result;
    uint64_t wait4_event_message;
    int32_t wait4_event_message_match;
    int64_t wait4_cont_result;
    int64_t wait4_exit_result;
    int32_t wait4_exit_status;
    int32_t wait4_cleanup_result;

    int32_t waitid_child_pid;
    int32_t waitid_new_task_event;
    int64_t waitid_traceme_result;
    int64_t waitid_nohang_result;
    int32_t waitid_nohang_zero;
    int32_t waitid_wait_entry_event;
    int32_t waitid_release_result;
    int64_t waitid_result;
    int32_t waitid_initial_siginfo_match;
    int64_t waitid_setoptions_result;
    int64_t waitid_first_cont_result;
    int64_t waitid_exec_result;
    int32_t waitid_exec_siginfo_match;
    int64_t waitid_geteventmsg_result;
    uint64_t waitid_event_message;
    int32_t waitid_event_message_match;
    int64_t waitid_detach_result;
    int64_t waitid_exit_result;
    int32_t waitid_exit_status;
    int32_t waitid_cleanup_result;
};

NestedPtraceResidentSelfTestReport
RunNestedPtraceResidentSelfTest() noexcept;

}  // namespace hookself::internal
