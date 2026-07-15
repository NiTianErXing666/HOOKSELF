#include <jni.h>
#include <string>

#include "self_trace_probe.h"
#include "hookself/internal/framework_selftest.h"
#include "hookself/internal/nested_ptrace_resident_selftest.h"
#include "hookself/internal/proc_virtual_selftest.h"
#include "hookself/internal/resident_selftest.h"
#include "hookself/internal/selective_resident_selftest.h"
#include "hookself/internal/selective_seccomp_probe.h"

namespace {

jstring RunM4CapabilityProbe(JNIEnv* env, uint32_t flags) {
    try {
        const hookself::internal::SelectiveSeccompProbeReport result =
                hookself::internal::RunSelectiveSeccompCapabilityProbe(flags);
        const std::string report =
                hookself::internal::FormatSelectiveSeccompProbeReport(result);
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_M4_PROBE_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"version\":1,\"fatal_errno\":12}");
    }
}

bool CopyJString(JNIEnv* env, jstring value, std::string* output) {
    if (env == nullptr || value == nullptr || output == nullptr) {
        return false;
    }
    const char* raw = env->GetStringUTFChars(value, nullptr);
    if (raw == nullptr) {
        return false;
    }
    *output = raw;
    env->ReleaseStringUTFChars(value, raw);
    return true;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM0Probe(
        JNIEnv* env,
        jobject /* this */) {
    try {
        const std::string report = hookself::RunM0Probe();
        return env->NewStringUTF(report.c_str());
    } catch (const std::exception& error) {
        const std::string report =
                std::string("HOOKSELF_M0_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"") +
                error.what() + "\"}";
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_M0_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"unknown\"}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM1Observation(
        JNIEnv* env,
        jobject /* this */) {
    try {
        const std::string report = hookself::RunM1Observation();
        return env->NewStringUTF(report.c_str());
    } catch (const std::exception& error) {
        const std::string report =
                std::string("HOOKSELF_M1_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"") +
                error.what() + "\"}";
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_M1_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"unknown\"}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM2Redirect(
        JNIEnv* env,
        jobject /* this */,
        jstring filesDir) {
    const char* raw_files_dir = env->GetStringUTFChars(filesDir, nullptr);
    if (raw_files_dir == nullptr) {
        return env->NewStringUTF(
                "HOOKSELF_M2A_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"filesDir\"}");
    }
    const std::string files_dir(raw_files_dir);
    env->ReleaseStringUTFChars(filesDir, raw_files_dir);
    try {
        const std::string report = hookself::RunM2Redirect(files_dir);
        return env->NewStringUTF(report.c_str());
    } catch (const std::exception& error) {
        const std::string report =
                std::string("HOOKSELF_M2A_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"") +
                error.what() + "\"}";
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_M2A_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"unknown\"}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM2MissingRedirect(
        JNIEnv* env,
        jobject /* this */,
        jstring filesDir) {
    const char* raw_files_dir = env->GetStringUTFChars(filesDir, nullptr);
    if (raw_files_dir == nullptr) {
        return env->NewStringUTF(
                "HOOKSELF_M2B_MISSING_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"filesDir\"}");
    }
    const std::string files_dir(raw_files_dir);
    env->ReleaseStringUTFChars(filesDir, raw_files_dir);
    try {
        const std::string report = hookself::RunM2MissingRedirect(files_dir);
        return env->NewStringUTF(report.c_str());
    } catch (const std::exception& error) {
        const std::string report =
                std::string("HOOKSELF_M2B_MISSING_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"") +
                error.what() + "\"}";
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_M2B_MISSING_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"error\":\"unknown\"}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM4CapabilityProbe(
        JNIEnv* env,
        jobject /* this */) {
    return RunM4CapabilityProbe(env, 0);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM4CapabilityProbeForceFallback(
        JNIEnv* env,
        jobject /* this */) {
    return RunM4CapabilityProbe(
            env,
            hookself::internal::kSelectiveSeccompProbeForceRegisterFallback);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runM4FaultProbe(
        JNIEnv* env,
        jobject /* this */,
        jint flags) {
    return RunM4CapabilityProbe(env, static_cast<uint32_t>(flags));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runSelectiveRuntimeSelfTestNative(
        JNIEnv* env,
        jobject /* this */,
        jint iterations,
        jstring virtualBackingDir) {
    std::string virtual_backing_dir;
    if (!CopyJString(env, virtualBackingDir, &virtual_backing_dir)) {
        return env->NewStringUTF(
                "HOOKSELF_SELECTIVE_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"version\":1,\"first_failure\":3}");
    }
    try {
        const hookself::internal::SelectiveResidentSelfTestReport result =
                hookself::internal::RunSelectiveResidentSelfTest(
                        iterations > 0 ? static_cast<uint32_t>(iterations)
                                       : 0U,
                        virtual_backing_dir.c_str());
        const std::string report =
                hookself::internal::FormatSelectiveResidentSelfTestReport(
                        result);
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_SELECTIVE_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"version\":1,\"first_failure\":16}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runFrameworkSelfTestNative(
        JNIEnv* env,
        jobject /* this */,
        jstring virtualBackingDir) {
    std::string virtual_backing_dir;
    if (!CopyJString(env, virtualBackingDir, &virtual_backing_dir)) {
        return env->NewStringUTF(
                "HOOKSELF_API_RESULT {\"verdict\":\"FAILED\",\"checks\":0,\"failures\":1,\"first_failure\":6810,\"chroot_path_result\":-1,\"chroot_path_first_failure\":0}");
    }
    const hookself::internal::FrameworkSelfTestReport result =
            hookself::internal::RunFrameworkSelfTest(
                    virtual_backing_dir.c_str());
    const std::string report =
            std::string("HOOKSELF_API_RESULT {\"verdict\":\"") +
            (result.failures == 0 ? "PASS" : "FAILED") +
            "\",\"checks\":" + std::to_string(result.checks) +
            ",\"failures\":" + std::to_string(result.failures) +
            ",\"first_failure\":" + std::to_string(result.first_failure) +
            ",\"chroot_path_result\":" +
            std::to_string(result.chroot_path_result) +
            ",\"chroot_path_first_failure\":" +
            std::to_string(result.chroot_path_first_failure) + "}";
    return env->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runProcVirtualResidentSmokeTestNative(
        JNIEnv* env,
        jobject /* this */,
        jstring virtualBackingDir) {
    std::string virtual_backing_dir;
    if (!CopyJString(env, virtualBackingDir, &virtual_backing_dir)) {
        return env->NewStringUTF(
                "HOOKSELF_PROC_VIRTUAL_RESULT {\"verdict\":\"FAILED\",\"create_result\":-10001}");
    }
    const hookself::internal::ProcVirtualResidentSmokeReport result =
            hookself::internal::RunProcVirtualResidentSmokeTest(
                    virtual_backing_dir.c_str());
    const std::string report =
            std::string("HOOKSELF_PROC_VIRTUAL_RESULT {\"verdict\":\"") +
            (result.verdict != 0 ? "PASS" : "FAILED") +
            "\",\"create_result\":" +
            std::to_string(result.create_result) +
            ",\"start_result\":" + std::to_string(result.start_result) +
            ",\"stop_result\":" + std::to_string(result.stop_result) +
            ",\"tracer_pid\":" + std::to_string(result.tracer_pid) +
            ",\"maps_hidden\":" + std::to_string(result.maps_hidden) +
            ",\"smaps_hidden\":" + std::to_string(result.smaps_hidden) +
            ",\"proc_dir_hidden\":" +
            std::to_string(result.proc_dir_hidden) +
            ",\"xattr_get_match\":" +
            std::to_string(result.xattr_get_match) +
            ",\"xattr_list_match\":" +
            std::to_string(result.xattr_list_match) +
            ",\"xattr_open_result\":" +
            std::to_string(result.xattr_open_result) +
            ",\"xattr_open_errno\":" +
            std::to_string(result.xattr_open_errno) +
            ",\"xattr_get_result\":" +
            std::to_string(result.xattr_get_result) +
            ",\"xattr_get_errno\":" +
            std::to_string(result.xattr_get_errno) +
            ",\"xattr_list_result\":" +
            std::to_string(result.xattr_list_result) +
            ",\"xattr_list_errno\":" +
            std::to_string(result.xattr_list_errno) +
            ",\"fatal_code\":" + std::to_string(result.fatal_code) +
            ",\"fatal_errno\":" + std::to_string(result.fatal_errno) +
            "}";
    return env->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runNestedPtraceResidentSelfTestNative(
        JNIEnv* env,
        jobject /* this */) {
    try {
        const hookself::internal::NestedPtraceResidentSelfTestReport result =
                hookself::internal::RunNestedPtraceResidentSelfTest();
        const std::string report =
                std::string("HOOKSELF_NESTED_PTRACE_RESULT {\"verdict\":\"") +
                (result.verdict != 0 ? "PASS" : "FAILED") +
                "\",\"version\":" + std::to_string(result.version) +
                ",\"checks\":" + std::to_string(result.checks) +
                ",\"failures\":" + std::to_string(result.failures) +
                ",\"first_failure\":" + std::to_string(result.first_failure) +
                ",\"validate_result\":" +
                std::to_string(result.validate_result) +
                ",\"create_result\":" + std::to_string(result.create_result) +
                ",\"start_result\":" + std::to_string(result.start_result) +
                ",\"stop_result\":" + std::to_string(result.stop_result) +
                ",\"fatal_code\":" + std::to_string(result.fatal_code) +
                ",\"fatal_errno\":" + std::to_string(result.fatal_errno) +
                ",\"dropped_events\":" +
                std::to_string(result.dropped_events) +
                ",\"wait4_initial_signal_stop\":" +
                std::to_string(result.wait4_initial_signal_stop) +
                ",\"wait4_setoptions_result\":" +
                std::to_string(result.wait4_setoptions_result) +
                ",\"wait4_exec_stop\":" +
                std::to_string(result.wait4_exec_stop) +
                ",\"wait4_geteventmsg_result\":" +
                std::to_string(result.wait4_geteventmsg_result) +
                ",\"wait4_event_message_match\":" +
                std::to_string(result.wait4_event_message_match) +
                ",\"wait4_cont_result\":" +
                std::to_string(result.wait4_cont_result) +
                ",\"wait4_exit_result\":" +
                std::to_string(result.wait4_exit_result) +
                ",\"wait4_cleanup_result\":" +
                std::to_string(result.wait4_cleanup_result) +
                ",\"waitid_nohang_zero\":" +
                std::to_string(result.waitid_nohang_zero) +
                ",\"waitid_initial_siginfo_match\":" +
                std::to_string(result.waitid_initial_siginfo_match) +
                ",\"waitid_setoptions_result\":" +
                std::to_string(result.waitid_setoptions_result) +
                ",\"waitid_exec_siginfo_match\":" +
                std::to_string(result.waitid_exec_siginfo_match) +
                ",\"waitid_geteventmsg_result\":" +
                std::to_string(result.waitid_geteventmsg_result) +
                ",\"waitid_event_message_match\":" +
                std::to_string(result.waitid_event_message_match) +
                ",\"waitid_detach_result\":" +
                std::to_string(result.waitid_detach_result) +
                ",\"waitid_exit_result\":" +
                std::to_string(result.waitid_exit_result) +
                ",\"waitid_cleanup_result\":" +
                std::to_string(result.waitid_cleanup_result) +
                "}";
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_NESTED_PTRACE_RESULT {\"verdict\":\"INTERNAL_ERROR\",\"version\":1,\"failures\":1,\"first_failure\":99}");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runResidentSelfTestNative(
        JNIEnv* env,
        jobject /* this */,
        jstring virtualBackingDir) {
    std::string virtual_backing_dir;
    if (!CopyJString(env, virtualBackingDir, &virtual_backing_dir)) {
        return env->NewStringUTF(
                "HOOKSELF_RESIDENT_RESULT {\"verdict\":\"FAILED\",\"start_result\":-10001}");
    }
    const hookself::internal::ResidentSelfTestReport result =
            hookself::internal::RunResidentSelfTest(
                    virtual_backing_dir.c_str());
    const std::string report =
            std::string("HOOKSELF_RESIDENT_RESULT {\"verdict\":\"") +
            (result.verdict != 0 ? "PASS" : "FAILED") +
            "\",\"start_result\":" + std::to_string(result.start_result) +
            ",\"stop_result\":" + std::to_string(result.stop_result) +
            ",\"running_state\":" + std::to_string(result.running_state) +
            ",\"stopped_state\":" + std::to_string(result.stopped_state) +
            ",\"expected_pid\":" + std::to_string(result.expected_pid) +
            ",\"expected_tid\":" + std::to_string(result.expected_tid) +
            ",\"getpid_entry\":" + std::to_string(result.getpid_entry) +
            ",\"getpid_exit\":" + std::to_string(result.getpid_exit) +
            ",\"gettid_entry\":" + std::to_string(result.gettid_entry) +
            ",\"gettid_exit\":" + std::to_string(result.gettid_exit) +
            ",\"openat_entry\":" + std::to_string(result.openat_entry) +
            ",\"openat_exit\":" + std::to_string(result.openat_exit) +
            ",\"openat_path_match\":" + std::to_string(result.openat_path_match) +
            ",\"result_match\":" + std::to_string(result.result_match) +
            ",\"worker_tid\":" + std::to_string(result.worker_tid) +
            ",\"clone_event\":" + std::to_string(result.clone_event) +
            ",\"worker_gettid_entry\":" +
            std::to_string(result.worker_gettid_entry) +
            ",\"worker_gettid_exit\":" +
            std::to_string(result.worker_gettid_exit) +
            ",\"child_pid\":" + std::to_string(result.child_pid) +
            ",\"fork_event\":" + std::to_string(result.fork_event) +
            ",\"child_getpid_entry\":" +
            std::to_string(result.child_getpid_entry) +
            ",\"child_getpid_exit\":" +
            std::to_string(result.child_getpid_exit) +
            ",\"exec_child_pid\":" + std::to_string(result.exec_child_pid) +
            ",\"exec_former_tid\":" + std::to_string(result.exec_former_tid) +
            ",\"exec_event\":" + std::to_string(result.exec_event) +
            ",\"execve_exit\":" + std::to_string(result.execve_exit) +
            ",\"signal_event\":" + std::to_string(result.signal_event) +
            ",\"signal_delivered\":" +
            std::to_string(result.signal_delivered) +
            ",\"group_stop_resumed\":" +
            std::to_string(result.group_stop_resumed) +
            ",\"selected_rule_pass\":" +
            std::to_string(result.selected_rule_pass) +
            ",\"syscall_policy_pass\":" +
            std::to_string(result.syscall_policy_pass) +
            ",\"syscall_deny_result\":" +
            std::to_string(result.syscall_deny_result) +
            ",\"syscall_number_result\":" +
            std::to_string(result.syscall_number_result) +
            ",\"syscall_result_result\":" +
            std::to_string(result.syscall_result_result) +
            ",\"syscall_argument_result\":" +
            std::to_string(result.syscall_argument_result) +
            ",\"syscall_policy_events\":" +
            std::to_string(result.syscall_policy_events) +
            ",\"ptrace_view_pass\":" +
            std::to_string(result.ptrace_view_pass) +
            ",\"ptrace_view_validation_pass\":" +
            std::to_string(result.ptrace_view_validation_pass) +
            ",\"ptrace_view_event_pairs_pass\":" +
            std::to_string(result.ptrace_view_event_pairs_pass) +
            ",\"ptrace_view_preexisting_worker_pass\":" +
            std::to_string(result.ptrace_view_preexisting_worker_pass) +
            ",\"ptrace_view_new_worker_pass\":" +
            std::to_string(result.ptrace_view_new_worker_pass) +
            ",\"ptrace_view_shared_dumpable_pass\":" +
            std::to_string(result.ptrace_view_shared_dumpable_pass) +
            ",\"ptrace_view_descendant_isolation_pass\":" +
            std::to_string(result.ptrace_view_descendant_isolation_pass) +
            ",\"ptrace_view_stop_concurrency_pass\":" +
            std::to_string(result.ptrace_view_stop_concurrency_pass) +
            ",\"ptrace_traceme_first\":" +
            std::to_string(result.ptrace_traceme_first) +
            ",\"ptrace_traceme_second\":" +
            std::to_string(result.ptrace_traceme_second) +
            ",\"ptrace_dumpable_zero\":" +
            std::to_string(result.ptrace_dumpable_zero) +
            ",\"ptrace_dumpable_invalid\":" +
            std::to_string(result.ptrace_dumpable_invalid) +
            ",\"ptrace_dumpable_one\":" +
            std::to_string(result.ptrace_dumpable_one) +
            ",\"ptrace_ptracer_any\":" +
            std::to_string(result.ptrace_ptracer_any) +
            ",\"ptrace_ptracer_invalid\":" +
            std::to_string(result.ptrace_ptracer_invalid) +
            ",\"ptrace_ptracer_self\":" +
            std::to_string(result.ptrace_ptracer_self) +
            ",\"ptrace_ptracer_zero\":" +
            std::to_string(result.ptrace_ptracer_zero) +
            ",\"ptrace_view_passthrough\":" +
            std::to_string(result.ptrace_view_passthrough) +
            ",\"ptrace_view_events\":" +
            std::to_string(result.ptrace_view_events) +
            ",\"ptrace_view_event_pair_errors\":" +
            std::to_string(result.ptrace_view_event_pair_errors) +
            ",\"ptrace_view_child_pid\":" +
            std::to_string(result.ptrace_view_child_pid) +
            ",\"ptrace_view_child_set_dumpable_zero\":" +
            std::to_string(result.ptrace_view_child_set_dumpable_zero) +
            ",\"ptrace_view_child_get_dumpable_zero\":" +
            std::to_string(result.ptrace_view_child_get_dumpable_zero) +
            ",\"ptrace_view_parent_get_after_child\":" +
            std::to_string(result.ptrace_view_parent_get_after_child) +
            ",\"ptrace_view_stop_worker_tid\":" +
            std::to_string(result.ptrace_view_stop_worker_tid) +
            ",\"ptrace_view_stop_worker_calls\":" +
            std::to_string(result.ptrace_view_stop_worker_calls) +
            ",\"ptrace_view_stop_overlap_calls\":" +
            std::to_string(result.ptrace_view_stop_overlap_calls) +
            ",\"ptrace_view_stop_worker_unexpected_results\":" +
            std::to_string(
                    result.ptrace_view_stop_worker_unexpected_results) +
            ",\"ptrace_view_stop_worker_entry\":" +
            std::to_string(result.ptrace_view_stop_worker_entry) +
            ",\"ptrace_view_stop_worker_exit\":" +
            std::to_string(result.ptrace_view_stop_worker_exit) +
            ",\"ptrace_view_operations\":" +
            std::to_string(result.ptrace_view_operations) +
            ",\"ptrace_view_dropped_events\":" +
            std::to_string(result.ptrace_view_dropped_events) +
            ",\"ptrace_view_fatal_code\":" +
            std::to_string(result.ptrace_view_fatal_code) +
            ",\"ptrace_view_fatal_errno\":" +
            std::to_string(result.ptrace_view_fatal_errno) +
            ",\"ptrace_view_entry_dumpable\":" +
            std::to_string(result.ptrace_view_entry_dumpable) +
            ",\"ptrace_view_final_logical_dumpable\":" +
            std::to_string(result.ptrace_view_final_logical_dumpable) +
            ",\"ptrace_view_stop_result\":" +
            std::to_string(result.ptrace_view_stop_result) +
            ",\"ptrace_view_restored_dumpable\":" +
            std::to_string(result.ptrace_view_restored_dumpable) +
            ",\"ptrace_view_cleanup_restored_dumpable\":" +
            std::to_string(result.ptrace_view_cleanup_restored_dumpable) +
            ",\"proc_status_view_pass\":" +
            std::to_string(result.proc_status_view_pass) +
            ",\"proc_status_preopen_fd\":" +
            std::to_string(result.proc_status_preopen_fd) +
            ",\"proc_status_pread_result\":" +
            std::to_string(result.proc_status_pread_result) +
            ",\"proc_status_pread_match\":" +
            std::to_string(result.proc_status_pread_match) +
            ",\"proc_status_dup_read_result\":" +
            std::to_string(result.proc_status_dup_read_result) +
            ",\"proc_status_dup_read_match\":" +
            std::to_string(result.proc_status_dup_read_match) +
            ",\"proc_status_readv_result\":" +
            std::to_string(result.proc_status_readv_result) +
            ",\"proc_status_readv_match\":" +
            std::to_string(result.proc_status_readv_match) +
            ",\"proc_status_readv_cross_iov\":" +
            std::to_string(result.proc_status_readv_cross_iov) +
            ",\"proc_status_worker_tid\":" +
            std::to_string(result.proc_status_worker_tid) +
            ",\"proc_status_worker_tgid\":" +
            std::to_string(result.proc_status_worker_tgid) +
            ",\"proc_status_worker_pid\":" +
            std::to_string(result.proc_status_worker_pid) +
            ",\"proc_status_worker_match\":" +
            std::to_string(result.proc_status_worker_match) +
            ",\"proc_status_fake_memfd_unchanged\":" +
            std::to_string(result.proc_status_fake_memfd_unchanged) +
            ",\"proc_status_event_pairs_pass\":" +
            std::to_string(result.proc_status_event_pairs_pass) +
            ",\"proc_status_event_pair_errors\":" +
            std::to_string(result.proc_status_event_pair_errors) +
            ",\"proc_status_events\":" +
            std::to_string(result.proc_status_events) +
            ",\"proc_status_patches\":" +
            std::to_string(result.proc_status_patches) +
            ",\"proc_status_dropped_events\":" +
            std::to_string(result.proc_status_dropped_events) +
            ",\"proc_status_fatal_code\":" +
            std::to_string(result.proc_status_fatal_code) +
            ",\"proc_status_fatal_errno\":" +
            std::to_string(result.proc_status_fatal_errno) +
            ",\"proc_status_stop_result\":" +
            std::to_string(result.proc_status_stop_result) +
            ",\"virtual_file_pass\":" +
            std::to_string(result.virtual_file_pass) +
            ",\"virtual_static_match\":" +
            std::to_string(result.virtual_static_match) +
            ",\"virtual_old_snapshot_match\":" +
            std::to_string(result.virtual_old_snapshot_match) +
            ",\"virtual_new_snapshot_match\":" +
            std::to_string(result.virtual_new_snapshot_match) +
            ",\"virtual_write_result\":" +
            std::to_string(result.virtual_write_result) +
            ",\"virtual_readlink_result\":" +
            std::to_string(result.virtual_readlink_result) +
            ",\"virtual_events\":" +
            std::to_string(result.virtual_events) +
            ",\"virtual_file_opens\":" +
            std::to_string(result.virtual_file_opens) +
            ",\"virtual_publish_result\":" +
            std::to_string(result.virtual_publish_result) +
            ",\"virtual_stable_fd\":" +
            std::to_string(result.virtual_stable_fd) +
            ",\"virtual_protected_close_result\":" +
            std::to_string(result.virtual_protected_close_result) +
            ",\"virtual_after_close_match\":" +
            std::to_string(result.virtual_after_close_match) +
            ",\"virtual_protected_dup3_result\":" +
            std::to_string(result.virtual_protected_dup3_result) +
            ",\"virtual_after_dup3_match\":" +
            std::to_string(result.virtual_after_dup3_match) +
            ",\"virtual_protected_setfd_result\":" +
            std::to_string(result.virtual_protected_setfd_result) +
            ",\"virtual_protected_getfd_result\":" +
            std::to_string(result.virtual_protected_getfd_result) +
            ",\"virtual_close_range_base_result\":" +
            std::to_string(result.virtual_close_range_base_result) +
            ",\"virtual_ordinary_close_range_cloexec_result\":" +
            std::to_string(
                    result.virtual_ordinary_close_range_cloexec_result) +
            ",\"virtual_ordinary_close_range_getfd_result\":" +
            std::to_string(result.virtual_ordinary_close_range_getfd_result) +
            ",\"virtual_ordinary_close_range_cloexec_set\":" +
            std::to_string(result.virtual_ordinary_close_range_cloexec_set) +
            ",\"virtual_protected_close_range_cloexec_result\":" +
            std::to_string(
                    result.virtual_protected_close_range_cloexec_result) +
            ",\"virtual_protected_close_range_getfd_result\":" +
            std::to_string(result.virtual_protected_close_range_getfd_result) +
            ",\"virtual_protected_close_range_cloexec_set\":" +
            std::to_string(result.virtual_protected_close_range_cloexec_set) +
            ",\"virtual_protected_close_range_result\":" +
            std::to_string(result.virtual_protected_close_range_result) +
            ",\"virtual_fd_reuse_target_fd\":" +
            std::to_string(result.virtual_fd_reuse_target_fd) +
            ",\"virtual_fd_reuse_register_result\":" +
            std::to_string(result.virtual_fd_reuse_register_result) +
            ",\"virtual_fd_reuse_unregister_result\":" +
            std::to_string(result.virtual_fd_reuse_unregister_result) +
            ",\"virtual_fd_reuse_protected_close_result\":" +
            std::to_string(result.virtual_fd_reuse_protected_close_result) +
            ",\"virtual_fd_reuse_duplicate_result\":" +
            std::to_string(result.virtual_fd_reuse_duplicate_result) +
            ",\"virtual_fd_reuse_ordinary_close_result\":" +
            std::to_string(result.virtual_fd_reuse_ordinary_close_result) +
            ",\"virtual_fd_reuse_ordinary_getfd_result\":" +
            std::to_string(result.virtual_fd_reuse_ordinary_getfd_result) +
            ",\"virtual_fd_reuse_pass\":" +
            std::to_string(result.virtual_fd_reuse_pass) +
            ",\"virtual_segmented_close_range_result\":" +
            std::to_string(result.virtual_segmented_close_range_result) +
            ",\"virtual_segmented_close_range_left_fd\":" +
            std::to_string(result.virtual_segmented_close_range_left_fd) +
            ",\"virtual_segmented_close_range_right_fd\":" +
            std::to_string(result.virtual_segmented_close_range_right_fd) +
            ",\"virtual_segmented_close_range_left_getfd\":" +
            std::to_string(result.virtual_segmented_close_range_left_getfd) +
            ",\"virtual_segmented_close_range_right_getfd\":" +
            std::to_string(result.virtual_segmented_close_range_right_getfd) +
            ",\"virtual_segmented_close_range_protected_getfd\":" +
            std::to_string(
                    result.virtual_segmented_close_range_protected_getfd) +
            ",\"virtual_segmented_close_range_pass\":" +
            std::to_string(result.virtual_segmented_close_range_pass) +
            ",\"virtual_segmented_unshare_close_range_result\":" +
            std::to_string(
                    result.virtual_segmented_unshare_close_range_result) +
            ",\"virtual_segmented_unshare_close_range_left_getfd\":" +
            std::to_string(
                    result.virtual_segmented_unshare_close_range_left_getfd) +
            ",\"virtual_segmented_unshare_close_range_right_getfd\":" +
            std::to_string(
                    result.virtual_segmented_unshare_close_range_right_getfd) +
            ",\"virtual_segmented_unshare_close_range_protected_getfd\":" +
            std::to_string(
                    result.virtual_segmented_unshare_close_range_protected_getfd) +
            ",\"virtual_segmented_unshare_close_range_pass\":" +
            std::to_string(
                    result.virtual_segmented_unshare_close_range_pass) +
            ",\"protected_fd_blocks\":" +
            std::to_string(result.protected_fd_blocks) +
            ",\"internal_fd_operations\":" +
            std::to_string(result.internal_fd_operations) +
            ",\"virtual_provider_pass\":" +
            std::to_string(result.virtual_provider_pass) +
            ",\"virtual_status_refresh_result\":" +
            std::to_string(result.virtual_status_refresh_result) +
            ",\"virtual_maps_refresh_result\":" +
            std::to_string(result.virtual_maps_refresh_result) +
            ",\"virtual_selinux_refresh_result\":" +
            std::to_string(result.virtual_selinux_refresh_result) +
            ",\"virtual_status_match\":" +
            std::to_string(result.virtual_status_match) +
            ",\"virtual_maps_match\":" +
            std::to_string(result.virtual_maps_match) +
            ",\"virtual_selinux_match\":" +
            std::to_string(result.virtual_selinux_match) +
            ",\"singleton_pass\":" +
            std::to_string(result.singleton_pass) +
            ",\"liveness_tracer_pid\":" +
            std::to_string(result.liveness_tracer_pid) +
            ",\"liveness_state\":" +
            std::to_string(result.liveness_state) +
            ",\"liveness_stop_result\":" +
            std::to_string(result.liveness_stop_result) +
            ",\"liveness_detected\":" +
            std::to_string(result.liveness_detected) +
            ",\"liveness_dumpable_restored\":" +
            std::to_string(result.liveness_dumpable_restored) +
            ",\"liveness_cleanup_ms\":" +
            std::to_string(result.liveness_cleanup_ms) +
            ",\"redirect_setup_stage\":" +
            std::to_string(result.redirect_setup_stage) +
            ",\"redirect_setup_result\":" +
            std::to_string(result.redirect_setup_result) +
            ",\"redirect_create_result\":" +
            std::to_string(result.redirect_create_result) +
            ",\"redirect_start_result\":" +
            std::to_string(result.redirect_start_result) +
            ",\"redirect_stop_result\":" +
            std::to_string(result.redirect_stop_result) +
            ",\"redirect_open_result\":" +
            std::to_string(result.redirect_open_result) +
            ",\"redirect_read_result\":" +
            std::to_string(result.redirect_read_result) +
            ",\"redirect_metadata_result\":" +
            std::to_string(result.redirect_metadata_result) +
            ",\"redirect_access_result\":" +
            std::to_string(result.redirect_access_result) +
            ",\"redirect_readlink_result\":" +
            std::to_string(result.redirect_readlink_result) +
            ",\"redirect_rename_result\":" +
            std::to_string(result.redirect_rename_result) +
            ",\"redirect_link_result\":" +
            std::to_string(result.redirect_link_result) +
            ",\"redirect_link_expected_result\":" +
            std::to_string(result.redirect_link_expected_result) +
            ",\"redirect_symlink_result\":" +
            std::to_string(result.redirect_symlink_result) +
            ",\"redirect_cleanup_pass\":" +
            std::to_string(result.redirect_cleanup_pass) +
            ",\"redirect_generic_events\":" +
            std::to_string(result.redirect_generic_events) +
            ",\"redirect_dual_path_events\":" +
            std::to_string(result.redirect_dual_path_events) +
            ",\"redirect_relative_open_result\":" +
            std::to_string(result.redirect_relative_open_result) +
            ",\"redirect_relative_read_result\":" +
            std::to_string(result.redirect_relative_read_result) +
            ",\"redirect_relative_content_match\":" +
            std::to_string(result.redirect_relative_content_match) +
            ",\"redirect_relative_event\":" +
            std::to_string(result.redirect_relative_event) +
            ",\"redirect_openat2_beneath_result\":" +
            std::to_string(result.redirect_openat2_beneath_result) +
            ",\"redirect_openat2_in_root_result\":" +
            std::to_string(result.redirect_openat2_in_root_result) +
            ",\"redirect_empty_newfstatat_result\":" +
            std::to_string(result.redirect_empty_newfstatat_result) +
            ",\"redirect_empty_statx_result\":" +
            std::to_string(result.redirect_empty_statx_result) +
            ",\"redirect_absolute_symlink_result\":" +
            std::to_string(result.redirect_absolute_symlink_result) +
            ",\"redirect_absolute_readlink_match\":" +
            std::to_string(result.redirect_absolute_readlink_match) +
            ",\"redirect_empty_readlink_match\":" +
            std::to_string(result.redirect_empty_readlink_match) +
            ",\"redirect_extended_path_pass\":" +
            std::to_string(result.redirect_extended_path_pass) +
            ",\"redirect_deny_result\":" +
            std::to_string(result.redirect_deny_result) +
            ",\"redirect_deny_event\":" +
            std::to_string(result.redirect_deny_event) +
            ",\"redirect_content_match\":" +
            std::to_string(result.redirect_content_match) +
            ",\"redirect_path_event\":" +
            std::to_string(result.redirect_path_event) +
            ",\"redirect_guest_path_match\":" +
            std::to_string(result.redirect_guest_path_match) +
            ",\"redirect_translated_path_match\":" +
            std::to_string(result.redirect_translated_path_match) +
            ",\"redirected_paths\":" +
            std::to_string(result.redirected_paths) +
            ",\"events_read\":" + std::to_string(result.events_read) +
            ",\"observed_syscalls\":" + std::to_string(result.observed_syscalls) +
            ",\"dropped_events\":" + std::to_string(result.dropped_events) +
            ",\"tracked_tasks_running\":" +
            std::to_string(result.tracked_tasks_running) +
            ",\"fatal_code\":" + std::to_string(result.fatal_code) +
            ",\"fatal_errno\":" + std::to_string(result.fatal_errno) +
            ",\"fatal_tid\":" + std::to_string(result.fatal_tid) + "}";
    return env->NewStringUTF(report.c_str());
}
