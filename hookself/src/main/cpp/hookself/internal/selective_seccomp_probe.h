#pragma once

#include <cstdint>
#include <string>

namespace hookself::internal {

enum SelectiveSeccompProbeFlags : uint32_t {
    kSelectiveSeccompProbeForceRegisterFallback = 1U << 0,
    kSelectiveSeccompProbeInjectSupervisorHang = 1U << 1,
    kSelectiveSeccompProbeInjectTsyncHang = 1U << 2,
};

struct SelectiveSeccompProbeReport {
    uint32_t version;
    uint32_t probe_flags;
    int32_t verdict;
    int32_t fatal_errno;
    int64_t duration_ms;
    int32_t caller_status_before_errno;
    int32_t caller_status_after_errno;
    int32_t caller_no_new_privs_before_errno;
    int32_t caller_no_new_privs_after_errno;
    int32_t caller_no_new_privs_before;
    int32_t caller_no_new_privs_after;
    int32_t caller_seccomp_mode_before;
    int32_t caller_seccomp_mode_after;
    int32_t caller_filter_count_before;
    int32_t caller_filter_count_after;
    int32_t caller_filter_count_supported;
    int32_t caller_pid;

    int32_t supervisor_pid;
    int32_t tracee_pid;
    int32_t supervisor_timeout;
    int32_t supervisor_exit_status;
    int32_t supervisor_cleanup_errno;
    int32_t supervisor_parent_check;
    int32_t supervisor_pdeathsig_errno;
    int32_t supervisor_pdeathsig_value;
    int32_t tracee_cleanup_errno;
    int32_t tracee_identity_errno;
    uint64_t tracee_start_time;
    int32_t tracee_pdeathsig_errno;
    int32_t tracee_pdeathsig_value;
    int32_t traceme_errno;
    int32_t initial_stop_seen;
    int32_t setoptions_errno;
    int32_t tracee_no_new_privs_before_errno;
    int32_t tracee_no_new_privs_before;
    int32_t tracee_no_new_privs_errno;
    int32_t tracee_status_before_errno;
    int32_t tracee_status_after_errno;
    int32_t tracee_seccomp_mode_before;
    int32_t tracee_seccomp_mode_after;
    int32_t tracee_filter_count_before;
    int32_t tracee_filter_count_after;
    int32_t tracee_filter_count_supported;
    int32_t tracee_filter_build_errno;
    int32_t tracee_filter_install_errno;
    int32_t tracee_filter_failed_tid;
    int32_t seccomp_event_count;
    int32_t event_data_match_count;
    int32_t syscall_info_supported;
    int32_t seccomp_info_match_count;
    int32_t seccomp_fallback_match_count;
    int32_t cont_resume_errno;
    int32_t syscall_resume_errno;
    int32_t syscall_exit_stop_seen;
    int32_t syscall_exit_info_match;
    int32_t syscall_exit_fallback_match;
    int32_t final_resume_errno;
    int32_t detach_stop_seen;
    int32_t detach_errno;
    int32_t unexpected_stop_count;
    int64_t first_gettid_result;
    int64_t second_gettid_result;
    int64_t post_detach_gettid_result;
    int64_t observed_exit_result;
    int32_t tracee_exit_status;

    int32_t tsync_pid;
    int32_t tsync_timeout;
    int32_t tsync_exit_status;
    int32_t tsync_cleanup_errno;
    int32_t tsync_parent_check;
    int32_t tsync_pdeathsig_errno;
    int32_t tsync_pdeathsig_value;
    int32_t tsync_signal_mask_errno;
    int32_t tsync_clone_errno;
    int32_t tsync_worker_tid;
    int32_t tsync_worker_ready;
    int32_t tsync_no_new_privs_before_errno;
    int32_t tsync_no_new_privs_before;
    int32_t tsync_no_new_privs_errno;
    int32_t tsync_leader_status_before_errno;
    int32_t tsync_worker_status_before_errno;
    int32_t tsync_leader_status_after_errno;
    int32_t tsync_worker_status_after_errno;
    int32_t tsync_leader_mode_before;
    int32_t tsync_worker_mode_before;
    int32_t tsync_leader_mode_after;
    int32_t tsync_worker_mode_after;
    int32_t tsync_leader_filters_before;
    int32_t tsync_worker_filters_before;
    int32_t tsync_leader_filters_after;
    int32_t tsync_worker_filters_after;
    int32_t tsync_filter_count_supported;
    int32_t tsync_filter_build_errno;
    int32_t tsync_filter_install_errno;
    int32_t tsync_filter_failed_tid;
    int64_t tsync_main_baseline_result;
    int64_t tsync_worker_baseline_result;
    int64_t tsync_main_no_tracer_result;
    int64_t tsync_worker_no_tracer_result;
    int32_t tsync_worker_exited;
};

// Runs only in forked sacrificial processes. The calling App process never
// installs a seccomp filter and retains its pre-probe no_new_privs state.
SelectiveSeccompProbeReport RunSelectiveSeccompCapabilityProbe(
        uint32_t flags = 0);

std::string FormatSelectiveSeccompProbeReport(
        const SelectiveSeccompProbeReport& report);

}  // namespace hookself::internal
