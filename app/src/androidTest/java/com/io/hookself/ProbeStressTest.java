package com.io.hookself;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.system.OsConstants;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
// selectiveRuntime installs a process-wide TSYNC filter, so it must run last
// when AndroidJUnitRunner executes this class in one target process.
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ProbeStressTest {
    private static final String TAG = "HookSelfStress";
    private static final String ARG_ITERATIONS = "iterations";
    private static final int DEFAULT_ITERATIONS = 1;
    private static final int MAX_ITERATIONS = 10_000;
    private static final int M4_INJECT_SUPERVISOR_HANG = 1 << 1;
    private static final int M4_INJECT_TSYNC_HANG = 1 << 2;
    private static final int SELECTIVE_CONFIG_FLAGS =
            (1 << 3) | (1 << 4) | (1 << 6) | (1 << 8);
    private static final int SELECTIVE_FAILURE_FAIL_CLOSED = 2;
    private static final int STATE_CONFIGURED = 1;
    private static final int STATE_RUNNING_FULL_PTRACE = 3;
    private static final int STATE_RUNNING_SELECTIVE = 5;
    private static final int STATE_STOPPED = 7;

    @Test
    public void demoLoggingFlow() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);
        try {
            instrumentation.waitForIdleSync();
            assertFalse("demo runtime unexpectedly attached",
                    activity.isSelfAttachedForLogging());

            JSONObject attach = parseFirstLine(
                    "DEMO_ATTACH", "HOOKSELF_DEMO_ATTACH",
                    activity.attachSelfForLogging());
            assertEquals("demo attach: " + attach,
                    "PASS", attach.getString("verdict"));
            assertEquals("demo running state: " + attach,
                    STATE_RUNNING_FULL_PTRACE, attach.getInt("state"));
            assertTrue("demo attach state not published",
                    activity.isSelfAttachedForLogging());
            assertTrue("demo attach emitted no logs: " + attach,
                    attach.getLong("logs_emitted") > 0);

            JSONObject status = parseFirstLine(
                    "DEMO_OPEN_STAT", "HOOKSELF_DEMO_OPEN_STAT",
                    activity.openStatProcStatusForLogging());
            assertEquals("demo open/stat: " + status,
                    "PASS", status.getString("verdict"));
            assertEquals("newfstatat failed: " + status,
                    0, status.getInt("newfstatat_errno"));
            assertEquals("TracerPid was not hidden: " + status,
                    0, status.getInt("tracer_pid"));
            assertEquals("status hook was not observed: " + status,
                    1, status.getInt("hook_effect_observed"));
            assertTrue("status operation emitted no logs: " + status,
                    status.getLong("logs_emitted") > 0);

            JSONObject ptrace = parseFirstLine(
                    "DEMO_PTRACE", "HOOKSELF_DEMO_PTRACE",
                    activity.runPtraceDetectionForLogging());
            assertEquals("demo ptrace: " + ptrace,
                    "PASS", ptrace.getString("verdict"));
            assertEquals("PTRACE_TRACEME was not virtualized: " + ptrace,
                    0L, ptrace.getLong("ptrace_traceme_result"));
            assertEquals("ptrace status did not hide TracerPid: " + ptrace,
                    0, ptrace.getInt("tracer_pid"));
            assertEquals("ptrace hook was not observed: " + ptrace,
                    1, ptrace.getInt("hook_effect_observed"));
            assertTrue("ptrace operation emitted no logs: " + ptrace,
                    ptrace.getLong("logs_emitted") > 0);
        } finally {
            if (activity.isSelfAttachedForLogging()) {
                JSONObject detach = parseFirstLine(
                        "DEMO_DETACH", "HOOKSELF_DEMO_DETACH",
                        NativeTestBridge.detachDemo());
                assertEquals("demo detach: " + detach,
                        "PASS", detach.getString("verdict"));
            }
            assertFalse("demo runtime remained attached",
                    activity.isSelfAttachedForLogging());
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void frameworkOnly() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);
        try {
            instrumentation.waitForIdleSync();
            JSONObject api = parseFirstLine(
                    "API", "HOOKSELF_API_RESULT",
                    NativeTestBridge.runFrameworkSelfTest(targetContext));
            assertEquals("framework API self-test verdict: " + api,
                    "PASS", api.getString("verdict"));
            assertEquals("framework API self-test failures", 0, api.getInt("failures"));
            assertEquals("framework chroot path self-test", 0,
                    api.getInt("chroot_path_result"));
            assertEquals("framework chroot path first failure", 0,
                    api.getInt("chroot_path_first_failure"));
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void inlineHookOnly() throws Exception {
        JSONObject result = parseFirstLine(
                "INLINE", "HOOKSELF_INLINE_RESULT",
                NativeTestBridge.runInlineHookSelfTest());
        Log.i(TAG, "inline hook self-test: " + result);
        assertEquals("inline hook verdict: " + result,
                "PASS", result.getString("verdict"));
        assertEquals("inline hook failures: " + result,
                0, result.getInt("failures"));
        assertTrue("inline hook coverage is incomplete: " + result,
                result.getInt("checks") >= 350);
        assertEquals("inline hook fixture count: " + result,
                20, result.getInt("fixtures"));
        assertTrue("inline hook expanded relocation coverage missing: " + result,
                result.getInt("expanded_relocations") > 0);
        assertEquals("inline hook BTI coverage: " + result,
                1, result.getInt("bti_paths"));
        int guardedBtiSupported = result.getInt("bti_guarded_supported");
        assertTrue("inline hook guarded BTI support value: " + result,
                guardedBtiSupported == 0 || guardedBtiSupported == 1);
        assertEquals("inline hook guarded BTI coverage: " + result,
                guardedBtiSupported, result.getInt("bti_guarded_paths"));
        assertTrue("inline hook guarded BTI bridge value: " + result,
                result.getInt("bti_guarded_far_bridge") == 0 ||
                        result.getInt("bti_guarded_far_bridge") == 1);
        assertEquals("inline hook PAC coverage: " + result,
                2, result.getInt("pac_paths"));
        assertEquals("inline hook unsupported relocation coverage: " + result,
                1, result.getInt("unsupported_relocations"));
        assertEquals("inline hook mapping retained RWX: " + result,
                0, result.getInt("rwx_violations"));
        assertEquals("inline hook concurrent cycle count: " + result,
                96, result.getInt("concurrent_cycles"));
        assertTrue("inline hook concurrent calls missing: " + result,
                result.getLong("concurrent_calls") > 0L);
    }

    @Test
    public void elfHookOnly() throws Exception {
        JSONObject result = parseFirstLine(
                "ELF", "HOOKSELF_ELF_RESULT",
                NativeTestBridge.runElfHookSelfTest());
        Log.i(TAG, "ELF hook self-test: " + result);
        assertEquals("ELF hook verdict: " + result,
                "PASS", result.getString("verdict"));
        assertEquals("ELF hook failures: " + result,
                0, result.getInt("failures"));
        assertTrue("ELF hook coverage is incomplete: " + result,
                result.getInt("checks") >= 200);
        assertEquals("GNU hash symbol resolution: " + result,
                1, result.getInt("gnu_resolves"));
        assertEquals("SysV hash symbol resolution: " + result,
                1, result.getInt("sysv_resolves"));
        assertEquals("ELF hook cycle count: " + result,
                103, result.getInt("hook_cycles"));
        assertTrue("RELRO restoration coverage missing: " + result,
                result.getInt("relro_restores") >= 3);
        assertEquals("slot conflict coverage: " + result,
                1, result.getInt("conflict_checks"));
        assertEquals("loader/registry lock-order coverage: " + result,
                1, result.getInt("lock_order_checks"));
        assertEquals("loader callback fork coverage: " + result,
                1, result.getInt("loader_forks"));
        assertEquals("parallel same-page transaction coverage: " + result,
                16, result.getInt("parallel_transactions"));
        assertEquals("fork snapshot coverage: " + result,
                8, result.getInt("fork_snapshots"));
        assertEquals("execute-only replacement coverage: " + result,
                1, result.getInt("xom_replacements"));
        assertEquals("recovery transaction coverage: " + result,
                2, result.getInt("recovery_transactions"));
        assertEquals("orphaned module coverage: " + result,
                1, result.getInt("orphaned_modules"));
        assertTrue("concurrent GOT calls missing: " + result,
                result.getLong("concurrent_calls") > 0L);
    }

    @Test
    public void procVirtualResidentOnly() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);
        try {
            instrumentation.waitForIdleSync();
            JSONObject result = parseFirstLine(
                    "PROC_VIRTUAL", "HOOKSELF_PROC_VIRTUAL_RESULT",
                    NativeTestBridge.runProcVirtualResidentSmokeTest(targetContext));
            Log.i(TAG, "procVirtualResidentOnly: " + result);
            assertEquals("proc virtual resident smoke: " + result,
                    "PASS", result.getString("verdict"));
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void residentOnly() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);
        try {
            instrumentation.waitForIdleSync();
            JSONObject resident = parseFirstLine(
                    "RESIDENT", "HOOKSELF_RESIDENT_RESULT",
                    NativeTestBridge.runResidentSelfTest(targetContext));
            Log.i(TAG, "residentOnly: " + resident);
            assertEquals("resident self-test verdict: " + resident,
                    "PASS", resident.getString("verdict"));
            long base = resident.getLong("virtual_close_range_base_result");
            assertEquals("protected close_range replay result: " + resident,
                    base == -38 ? -38 : 0,
                    resident.getLong("virtual_protected_close_range_result"));
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void nestedPtraceResidentOnly() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);
        try {
            instrumentation.waitForIdleSync();
            JSONObject result = parseFirstLine(
                    "NESTED_PTRACE", "HOOKSELF_NESTED_PTRACE_RESULT",
                    NativeTestBridge.runNestedPtraceResidentSelfTestNative());
            Log.i(TAG, "nestedPtraceResidentOnly: " + result);
            assertEquals("nested ptrace resident verdict: " + result,
                    "PASS", result.getString("verdict"));
            assertEquals("nested ptrace failures: " + result,
                    0, result.getInt("failures"));
            assertTrue("nested ptrace coverage is incomplete: " + result,
                    result.getInt("checks") >= 39);
            assertEquals("nested ptrace dropped events: " + result,
                    0L, result.getLong("dropped_events"));
            assertEquals("wait4 initial SIGTRAP stop: " + result,
                    1, result.getInt("wait4_initial_signal_stop"));
            assertEquals("wait4 TRACEEXEC event: " + result,
                    1, result.getInt("wait4_exec_stop"));
            assertEquals("wait4 event message: " + result,
                    1, result.getInt("wait4_event_message_match"));
            assertEquals("waitid WNOHANG: " + result,
                    1, result.getInt("waitid_nohang_zero"));
            assertEquals("waitid TRACEEXEC event: " + result,
                    1, result.getInt("waitid_exec_siginfo_match"));
            assertEquals("waitid event message: " + result,
                    1, result.getInt("waitid_event_message_match"));
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void repeatAll() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        int iterations = readIterations(InstrumentationRegistry.getArguments());

        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);

        try {
            instrumentation.waitForIdleSync();

            JSONObject api = parseFirstLine(
                    "API", "HOOKSELF_API_RESULT",
                    NativeTestBridge.runFrameworkSelfTest(targetContext));
            assertEquals("framework API self-test verdict: " + api,
                    "PASS", api.getString("verdict"));
            assertTrue("framework API self-test did not execute enough checks",
                    api.getInt("checks") >= 20);
            assertEquals("framework API self-test failures", 0, api.getInt("failures"));
            assertEquals("framework chroot path self-test", 0,
                    api.getInt("chroot_path_result"));
            assertEquals("framework chroot path first failure", 0,
                    api.getInt("chroot_path_first_failure"));

            JSONObject forcedFallback = parseFirstLine(
                    "M4_FALLBACK", "HOOKSELF_M4_PROBE_RESULT",
                    NativeTestBridge.runM4CapabilityProbeForceFallback());
            Log.i(TAG, "M4 forced fallback: " + forcedFallback);
            assertM4Result("M4_FALLBACK", 0, forcedFallback, true);
            assertProcTaskStateClean("after M4 forced fallback");

            JSONObject supervisorFault = parseFirstLine(
                    "M4_SUPERVISOR_FAULT", "HOOKSELF_M4_PROBE_RESULT",
                    NativeTestBridge.runM4FaultProbe(M4_INJECT_SUPERVISOR_HANG));
            assertM4FaultResult("M4_SUPERVISOR_FAULT", supervisorFault,
                    M4_INJECT_SUPERVISOR_HANG);
            assertProcTaskStateClean("after M4 supervisor fault");

            JSONObject tsyncFault = parseFirstLine(
                    "M4_TSYNC_FAULT", "HOOKSELF_M4_PROBE_RESULT",
                    NativeTestBridge.runM4FaultProbe(M4_INJECT_TSYNC_HANG));
            assertM4FaultResult("M4_TSYNC_FAULT", tsyncFault,
                    M4_INJECT_TSYNC_HANG);
            assertProcTaskStateClean("after M4 TSYNC fault");

            for (int iteration = 1; iteration <= iterations; iteration++) {
                JSONObject resident = parseFirstLine(
                        "RESIDENT", "HOOKSELF_RESIDENT_RESULT",
                        NativeTestBridge.runResidentSelfTest(targetContext));
                Log.i(TAG, "resident iteration " + iteration + ": " + resident);
                assertEquals("resident iteration " + iteration + ": " + resident,
                        "PASS", resident.getString("verdict"));
                assertEquals("resident start result", 0,
                        resident.getInt("start_result"));
                assertEquals("resident stop result", 0,
                        resident.getInt("stop_result"));
                assertTrue("resident getpid pair missing",
                        resident.getInt("getpid_entry") > 0 &&
                                resident.getInt("getpid_exit") > 0);
                assertTrue("resident gettid pair missing",
                        resident.getInt("gettid_entry") > 0 &&
                                resident.getInt("gettid_exit") > 0);
                assertTrue("resident openat pair missing",
                        resident.getInt("openat_entry") > 0 &&
                                resident.getInt("openat_exit") > 0);
                assertEquals("resident pathname capture", 1,
                        resident.getInt("openat_path_match"));
                assertTrue("resident did not track tasks",
                        resident.getInt("tracked_tasks_running") > 0);
                assertTrue("resident clone event missing",
                        resident.getInt("worker_tid") > 0 &&
                                resident.getInt("clone_event") > 0);
                assertTrue("resident worker syscall pair missing",
                        resident.getInt("worker_gettid_entry") > 0 &&
                                resident.getInt("worker_gettid_exit") > 0);
                assertTrue("resident fork event missing",
                        resident.getInt("child_pid") > 0 &&
                                resident.getInt("fork_event") > 0);
                assertTrue("resident child syscall pair missing",
                        resident.getInt("child_getpid_entry") > 0 &&
                                resident.getInt("child_getpid_exit") > 0);
                assertTrue("resident exec event missing",
                        resident.getInt("exec_child_pid") > 0 &&
                                resident.getInt("exec_event") > 0);
                assertTrue("resident non-leader exec TID migration not exercised",
                        resident.getInt("exec_former_tid") > 0 &&
                                resident.getInt("exec_former_tid") !=
                                        resident.getInt("exec_child_pid"));
                assertTrue("resident successful execve exit missing",
                        resident.getInt("execve_exit") > 0);
                assertTrue("resident signal forwarding failed",
                        resident.getInt("signal_event") > 0 &&
                                resident.getInt("signal_delivered") == 1);
                assertEquals("resident group stop did not resume", 1,
                        resident.getInt("group_stop_resumed"));
                assertEquals("selected syscall rule filter failed", 1,
                        resident.getInt("selected_rule_pass"));
                assertEquals("syscall mutation policy check failed", 1,
                        resident.getInt("syscall_policy_pass"));
                assertEquals("syscall deny result mismatch", -13,
                        resident.getLong("syscall_deny_result"));
                assertTrue("syscall number replacement did not return pid",
                        resident.getLong("syscall_number_result") > 0);
                assertEquals("syscall result replacement mismatch", 0x1234,
                        resident.getLong("syscall_result_result"));
                assertEquals("syscall argument replacement mismatch", 2,
                        resident.getLong("syscall_argument_result"));
                assertEquals("syscall policy event coverage", 5,
                        resident.getInt("syscall_policy_events"));
                assertEquals("ptrace logical view check failed", 1,
                        resident.getInt("ptrace_view_pass"));
                assertEquals("ptrace logical view validation failed", 1,
                        resident.getInt("ptrace_view_validation_pass"));
                assertEquals("ptrace event pairing failed", 1,
                        resident.getInt("ptrace_view_event_pairs_pass"));
                assertEquals("ptrace event pairing errors", 0,
                        resident.getInt("ptrace_view_event_pair_errors"));
                assertEquals("preexisting TID ptrace view failed", 1,
                        resident.getInt("ptrace_view_preexisting_worker_pass"));
                assertEquals("new TID ptrace view failed", 1,
                        resident.getInt("ptrace_view_new_worker_pass"));
                assertEquals("TGID dumpable view was not shared", 1,
                        resident.getInt("ptrace_view_shared_dumpable_pass"));
                assertEquals("descendant ptrace view isolation failed", 1,
                        resident.getInt("ptrace_view_descendant_isolation_pass"));
                assertEquals("stop concurrency check failed", 1,
                        resident.getInt("ptrace_view_stop_concurrency_pass"));
                assertEquals("first logical PTRACE_TRACEME", 0,
                        resident.getLong("ptrace_traceme_first"));
                assertEquals("repeated logical PTRACE_TRACEME", -1,
                        resident.getLong("ptrace_traceme_second"));
                assertEquals("logical PR_GET_DUMPABLE after SET 0", 0,
                        resident.getLong("ptrace_dumpable_zero"));
                assertEquals("wide PR_SET_DUMPABLE was not rejected", -22,
                        resident.getLong("ptrace_dumpable_invalid"));
                assertEquals("logical PR_GET_DUMPABLE after SET 1", 1,
                        resident.getLong("ptrace_dumpable_one"));
                assertEquals("logical PR_SET_PTRACER_ANY", 0,
                        resident.getLong("ptrace_ptracer_any"));
                assertEquals("UINT32_MAX PR_SET_PTRACER was not rejected", -22,
                        resident.getLong("ptrace_ptracer_invalid"));
                assertEquals("logical PR_SET_PTRACER self", 0,
                        resident.getLong("ptrace_ptracer_self"));
                assertEquals("logical PR_SET_PTRACER 0", 0,
                        resident.getLong("ptrace_ptracer_zero"));
                assertEquals("unrelated prctl did not pass through", 0,
                        resident.getLong("ptrace_view_passthrough"));
                assertTrue("descendant process was not exercised",
                        resident.getInt("ptrace_view_child_pid") > 0);
                assertEquals("descendant PR_SET_DUMPABLE did not execute", 0,
                        resident.getLong("ptrace_view_child_set_dumpable_zero"));
                assertEquals("descendant real dumpable did not become zero", 0,
                        resident.getLong("ptrace_view_child_get_dumpable_zero"));
                assertEquals("descendant changed parent logical dumpable", 1,
                        resident.getLong("ptrace_view_parent_get_after_child"));
                assertTrue("stop GET_DUMPABLE worker did not run",
                        resident.getInt("ptrace_view_stop_worker_tid") > 0 &&
                                resident.getLong("ptrace_view_stop_worker_calls") > 0 &&
                                resident.getLong("ptrace_view_stop_worker_calls") <= 64);
                assertTrue("GET_DUMPABLE worker did not overlap stop",
                        resident.getLong("ptrace_view_stop_overlap_calls") > 0);
                assertEquals("GET_DUMPABLE changed across stop commit", 0,
                        resident.getLong(
                                "ptrace_view_stop_worker_unexpected_results"));
                assertTrue("stop worker syscall entry/exit mismatch",
                        resident.getInt("ptrace_view_stop_worker_entry") > 0 &&
                                resident.getInt("ptrace_view_stop_worker_entry") ==
                                        resident.getInt("ptrace_view_stop_worker_exit"));
                assertTrue("ptrace view event count was not paired",
                        resident.getInt("ptrace_view_events") > 0 &&
                                (resident.getInt("ptrace_view_events") & 1) == 0);
                assertEquals("ptrace view operation/event mismatch",
                        resident.getLong("ptrace_view_events") / 2,
                        resident.getLong("ptrace_view_operations"));
                assertEquals("ptrace view dropped events", 0,
                        resident.getLong("ptrace_view_dropped_events"));
                assertEquals("ptrace view fatal stage", 0,
                        resident.getInt("ptrace_view_fatal_code"));
                assertEquals("ptrace view fatal errno", 0,
                        resident.getInt("ptrace_view_fatal_errno"));
                int entryDumpable = resident.getInt("ptrace_view_entry_dumpable");
                int finalDumpable = resident.getInt(
                        "ptrace_view_final_logical_dumpable");
                assertTrue("invalid entry dumpable", entryDumpable == 0 || entryDumpable == 1);
                assertEquals("final logical dumpable was not changed",
                        entryDumpable == 0 ? 1 : 0, finalDumpable);
                assertEquals("ptrace view stop result", 0,
                        resident.getInt("ptrace_view_stop_result"));
                assertEquals("stop did not apply final logical dumpable",
                        finalDumpable,
                        resident.getInt("ptrace_view_restored_dumpable"));
                assertEquals("ptrace view did not restore entry dumpable", 1,
                        resident.getInt("ptrace_view_cleanup_restored_dumpable"));
                assertEquals("proc status Level-2 check failed", 1,
                        resident.getInt("proc_status_view_pass"));
                assertTrue("proc status FD was not opened before start",
                        resident.getInt("proc_status_preopen_fd") >= 0);
                assertTrue("proc status pread64 returned no data",
                        resident.getLong("proc_status_pread_result") > 0);
                assertEquals("proc status pread64 view mismatch", 1,
                        resident.getInt("proc_status_pread_match"));
                assertTrue("duplicated proc status FD returned no data",
                        resident.getLong("proc_status_dup_read_result") > 0);
                assertEquals("duplicated proc status read mismatch", 1,
                        resident.getInt("proc_status_dup_read_match"));
                assertTrue("proc status readv returned no data",
                        resident.getLong("proc_status_readv_result") > 0);
                assertEquals("proc status readv view mismatch", 1,
                        resident.getInt("proc_status_readv_match"));
                assertEquals("TracerPid did not cross readv iovecs", 1,
                        resident.getInt("proc_status_readv_cross_iov"));
                int statusWorkerTid = resident.getInt("proc_status_worker_tid");
                assertTrue("proc thread-self worker was not a nonleader",
                        statusWorkerTid > 0 && statusWorkerTid != Process.myPid());
                assertEquals("proc thread-self worker Tgid mismatch",
                        Process.myPid(), resident.getInt("proc_status_worker_tgid"));
                assertEquals("proc thread-self worker Pid mismatch",
                        statusWorkerTid, resident.getInt("proc_status_worker_pid"));
                assertEquals("proc thread-self status view mismatch", 1,
                        resident.getInt("proc_status_worker_match"));
                assertEquals("ordinary fake status memfd was modified", 1,
                        resident.getInt("proc_status_fake_memfd_unchanged"));
                assertEquals("proc status event pairing failed", 1,
                        resident.getInt("proc_status_event_pairs_pass"));
                assertEquals("proc status event pairing errors", 0,
                        resident.getInt("proc_status_event_pair_errors"));
                assertTrue("proc status event count was not paired",
                        resident.getInt("proc_status_events") > 0 &&
                                (resident.getInt("proc_status_events") & 1) == 0);
                assertTrue("proc status patch stats missing",
                        resident.getLong("proc_status_patches") >= 4);
                assertEquals("proc status dropped events", 0,
                        resident.getLong("proc_status_dropped_events"));
                assertEquals("proc status fatal stage", 0,
                        resident.getInt("proc_status_fatal_code"));
                assertEquals("proc status fatal errno", 0,
                        resident.getInt("proc_status_fatal_errno"));
                assertEquals("proc status stop result", 0,
                        resident.getInt("proc_status_stop_result"));
                assertEquals("virtual file check failed", 1,
                        resident.getInt("virtual_file_pass"));
                assertEquals("static virtual content mismatch", 1,
                        resident.getInt("virtual_static_match"));
                assertEquals("old dynamic snapshot changed", 1,
                        resident.getInt("virtual_old_snapshot_match"));
                assertEquals("new dynamic snapshot mismatch", 1,
                        resident.getInt("virtual_new_snapshot_match"));
                assertEquals("virtual write was not denied", -30,
                        resident.getLong("virtual_write_result"));
                assertEquals("virtual readlink did not emulate regular file", -22,
                        resident.getLong("virtual_readlink_result"));
                assertTrue("virtual file PATH events missing",
                        resident.getInt("virtual_events") >= 5);
                assertTrue("virtual file open stats missing",
                        resident.getLong("virtual_file_opens") >= 3);
                long closeRangeBase =
                        resident.getLong("virtual_close_range_base_result");
                assertTrue("close_range base probe was not exercised",
                        closeRangeBase != Long.MIN_VALUE);
                if (closeRangeBase != -OsConstants.ENOSYS) {
                    long ordinaryCloseRangeCloexec = resident.getLong(
                            "virtual_ordinary_close_range_cloexec_result");
                    long protectedCloseRangeCloexec = resident.getLong(
                            "virtual_protected_close_range_cloexec_result");
                    assertEquals("protected CLOEXEC did not match ordinary FD",
                            ordinaryCloseRangeCloexec, protectedCloseRangeCloexec);
                    assertTrue("protected CLOEXEC was rejected as destructive",
                            protectedCloseRangeCloexec != -16);
                    long ordinaryCloseRangeGetfd = resident.getLong(
                            "virtual_ordinary_close_range_getfd_result");
                    assertTrue("ordinary CLOEXEC F_GETFD failed",
                            ordinaryCloseRangeGetfd >= 0);
                    assertEquals("ordinary CLOEXEC descriptor flag mismatch",
                            ordinaryCloseRangeCloexec == 0 ? 1 : 0,
                            (ordinaryCloseRangeGetfd & 1) != 0 ? 1 : 0);
                    assertEquals("ordinary CLOEXEC report mismatch",
                            (ordinaryCloseRangeGetfd & 1) != 0 ? 1 : 0,
                            resident.getInt(
                                    "virtual_ordinary_close_range_cloexec_set"));
                    long protectedCloseRangeGetfd = resident.getLong(
                            "virtual_protected_close_range_getfd_result");
                    assertTrue("protected CLOEXEC F_GETFD failed",
                            protectedCloseRangeGetfd >= 0);
                    assertTrue("protected stable FD raw CLOEXEC bit was cleared",
                            (protectedCloseRangeGetfd & 1) != 0);
                    assertEquals("protected stable FD lost CLOEXEC", 1,
                            resident.getInt(
                                    "virtual_protected_close_range_cloexec_set"));
                }
                assertEquals("protected flags=0 close_range result mismatch",
                        closeRangeBase == -38 ? -38 : 0,
                        resident.getLong(
                                "virtual_protected_close_range_result"));
                assertEquals("resident process singleton failed", 1,
                        resident.getInt("singleton_pass"));
                assertTrue("resident liveness tracer pid missing",
                        resident.getInt("liveness_tracer_pid") > 0);
                assertEquals("resident tracer death was not detected", 1,
                        resident.getInt("liveness_detected"));
                assertEquals("resident stale state was not fatalized", 8,
                        resident.getInt("liveness_state"));
                assertEquals("resident killed-tracer cleanup result", -10009,
                        resident.getInt("liveness_stop_result"));
                assertEquals("resident dumpable restoration failed", 1,
                        resident.getInt("liveness_dumpable_restored"));
                assertTrue("resident killed-tracer cleanup exceeded bound",
                        resident.getLong("liveness_cleanup_ms") >= 0 &&
                                resident.getLong("liveness_cleanup_ms") <= 3000);
                assertEquals("resident redirect create result", 0,
                        resident.getInt("redirect_create_result"));
                assertEquals("resident redirect start result", 0,
                        resident.getInt("redirect_start_result"));
                assertEquals("resident redirect stop result", 0,
                        resident.getInt("redirect_stop_result"));
                assertTrue("resident redirected openat failed",
                        resident.getLong("redirect_open_result") >= 0);
                assertTrue("resident redirected status read failed",
                        resident.getLong("redirect_read_result") > 0);
                assertEquals("resident newfstatat redirect failed", 0,
                        resident.getLong("redirect_metadata_result"));
                assertEquals("resident faccessat redirect failed", 0,
                        resident.getLong("redirect_access_result"));
                assertTrue("resident readlinkat redirect failed",
                        resident.getLong("redirect_readlink_result") > 0);
                assertEquals("resident dual-path renameat redirect failed", 0,
                        resident.getLong("redirect_rename_result"));
                assertEquals("resident dual-path linkat redirect failed",
                        resident.getLong("redirect_link_expected_result"),
                        resident.getLong("redirect_link_result"));
                assertEquals("resident symlinkat redirect failed", 0,
                        resident.getLong("redirect_symlink_result"));
                assertEquals("resident redirected cleanup failed", 1,
                        resident.getInt("redirect_cleanup_pass"));
                assertTrue("resident generic path events missing",
                        resident.getInt("redirect_generic_events") >= 7);
                assertTrue("resident dual path argument events missing",
                        resident.getInt("redirect_dual_path_events") >= 4);
                assertTrue("resident dirfd-relative openat redirect failed",
                        resident.getLong("redirect_relative_open_result") >= 0);
                assertTrue("resident dirfd-relative read failed",
                        resident.getLong("redirect_relative_read_result") > 0);
                assertEquals("resident relative redirect content mismatch", 1,
                        resident.getInt("redirect_relative_content_match"));
                assertTrue("resident relative PATH event missing",
                        resident.getInt("redirect_relative_event") > 0);
                long beneathResult =
                        resident.getLong("redirect_openat2_beneath_result");
                long inRootResult =
                        resident.getLong("redirect_openat2_in_root_result");
                assertTrue("resident constrained openat2 results mismatch",
                        (beneathResult == -OsConstants.ENOSYS &&
                                inRootResult == -OsConstants.ENOSYS) ||
                                (beneathResult >= 0 && inRootResult >= 0));
                assertEquals("resident newfstatat AT_EMPTY_PATH failed", 0,
                        resident.getLong("redirect_empty_newfstatat_result"));
                long statxResult = resident.getLong("redirect_empty_statx_result");
                assertTrue("resident statx AT_EMPTY_PATH failed",
                        statxResult == 0 || statxResult == -OsConstants.ENOSYS);
                assertEquals("resident absolute symlink redirect failed", 0,
                        resident.getLong("redirect_absolute_symlink_result"));
                assertEquals("resident absolute readlink guest view mismatch", 1,
                        resident.getInt("redirect_absolute_readlink_match"));
                assertEquals("resident readlinkat AT_EMPTY_PATH mismatch", 1,
                        resident.getInt("redirect_empty_readlink_match"));
                assertEquals("resident extended path semantics failed", 1,
                        resident.getInt("redirect_extended_path_pass"));
                assertEquals("resident path deny result mismatch", -13,
                        resident.getLong("redirect_deny_result"));
                assertTrue("resident path deny event missing",
                        resident.getInt("redirect_deny_event") > 0);
                assertEquals("resident redirected status did not contain Name:", 1,
                        resident.getInt("redirect_content_match"));
                assertTrue("resident PATH REDIRECT event missing",
                        resident.getInt("redirect_path_event") > 0);
                assertEquals("resident PATH event guest path mismatch", 1,
                        resident.getInt("redirect_guest_path_match"));
                assertEquals("resident PATH event translated path mismatch", 1,
                        resident.getInt("redirect_translated_path_match"));
                assertTrue("resident redirected path stats missing",
                        resident.getLong("redirected_paths") >= 13);
                assertProcTaskStateClean("after resident iteration " + iteration);

                JSONObject m0 = parseFirstLine(
                        "M0", "HOOKSELF_M0_RESULT", NativeTestBridge.runM0Probe());
                assertCommonResult("M0", iteration, m0, "PASS_FULL");
                assertEquals(message("M0", iteration, m0, "regset coverage"),
                        m0.getInt("discovered_tids"), m0.getInt("regset_tids"));
                assertTrue(message("M0", iteration, m0, "parent memory not restored"),
                        m0.getBoolean("parent_memory_restored"));
                assertProcTaskStateClean("after M0 iteration " + iteration);

                JSONObject m1 = parseFirstLine(
                        "M1", "HOOKSELF_M1_RESULT", NativeTestBridge.runM1Observation());
                assertCommonResult("M1", iteration, m1, "PASS");
                assertEquals(message("M1", iteration, m1, "getpid entry count"),
                        1, m1.getInt("getpid_entry"));
                assertEquals(message("M1", iteration, m1, "getpid exit count"),
                        1, m1.getInt("getpid_exit"));
                assertEquals(message("M1", iteration, m1, "gettid entry count"),
                        1, m1.getInt("gettid_entry"));
                assertEquals(message("M1", iteration, m1, "gettid exit count"),
                        1, m1.getInt("gettid_exit"));
                assertEquals(message("M1", iteration, m1, "openat entry count"),
                        1, m1.getInt("openat_entry"));
                assertEquals(message("M1", iteration, m1, "openat exit count"),
                        1, m1.getInt("openat_exit"));
                assertEquals(message("M1", iteration, m1, "observed target pid"),
                        Process.myPid(), m1.getInt("getpid_result"));
                assertEquals(message("M1", iteration, m1, "observed openat path"),
                        "/proc/self/status", m1.getString("openat_path"));
                assertProcTaskStateClean("after M1 iteration " + iteration);

                JSONObject m2 = parseFirstLine(
                        "M2A", "HOOKSELF_M2A_RESULT",
                        NativeTestBridge.runM2Redirect(
                                targetContext.getFilesDir().getAbsolutePath()));
                assertCommonResult("M2A", iteration, m2, "PASS");
                assertEquals(message("M2A", iteration, m2, "rewrite still active"),
                        0, m2.getInt("rewrite_active"));
                assertEquals(message("M2A", iteration, m2, "entry count"),
                        1, m2.getInt("entry_seen"));
                assertEquals(message("M2A", iteration, m2, "exit count"),
                        1, m2.getInt("exit_seen"));
                assertEquals(message("M2A", iteration, m2, "entry args not verified"),
                        1, m2.getInt("entry_args_verified"));
                assertEquals(message("M2A", iteration, m2, "entry registers not verified"),
                        1, m2.getInt("entry_registers_verified"));
                assertEquals(message("M2A", iteration, m2, "entry syscall not verified"),
                        1, m2.getInt("entry_syscall_verified"));
                assertEquals(message("M2A", iteration, m2, "redirected exit not observed"),
                        1, m2.getInt("exit_redirect_seen"));
                assertEquals(message("M2A", iteration, m2, "exit registers not verified"),
                        1, m2.getInt("exit_registers_verified"));
                assertEquals(message("M2A", iteration, m2, "exit syscall not verified"),
                        1, m2.getInt("exit_syscall_verified"));
                assertEquals(message("M2A", iteration, m2, "exit user x8 not verified"),
                        1, m2.getInt("exit_user_x8_verified"));
                assertTrue(message("M2A", iteration, m2, "openat failed"),
                        m2.getLong("parent_fd") >= 0);
                assertEquals(message("M2A", iteration, m2, "parent/child fd mismatch"),
                        m2.getLong("child_result"), m2.getLong("parent_fd"));
                assertTrue(message("M2A", iteration, m2, "path pointer did not change"),
                        m2.getBoolean("pointer_changed"));
                assertTrue(message("M2A", iteration, m2, "scratch guards damaged"),
                        m2.getBoolean("scratch_guards_ok"));
                assertTrue(message("M2A", iteration, m2, "target inode mismatch"),
                        m2.getBoolean("target_inode_match"));
                assertTrue(message("M2A", iteration, m2, "source/target inode collision"),
                        m2.getBoolean("source_inode_differs"));
                assertTrue(message("M2A", iteration, m2, "target content mismatch"),
                        m2.getBoolean("target_content_match"));
                assertTrue(message("M2A", iteration, m2, "source content changed"),
                        m2.getBoolean("source_unchanged"));
                assertEquals(message("M2A", iteration, m2, "unexpected rollback attempt"),
                        0, m2.getInt("rollback_attempted"));
                assertEquals(message("M2A", iteration, m2, "unexpected ptrace stop"),
                        0, m2.getInt("unexpected_stops"));
                assertEquals(message("M2A", iteration, m2, "orphan cleanup error"),
                        0, m2.getInt("orphan_cleanup_errno"));
                assertEquals(message("M2A", iteration, m2, "unexpected cleanup failure"),
                        0, m2.getInt("unexpected_cleanup_failures"));
                assertEquals(message("M2A", iteration, m2, "policy action"),
                        1, m2.getInt("policy_action"));
                assertEquals(message("M2A", iteration, m2, "policy error"),
                        0, m2.getInt("policy_errno"));
                assertEquals(message("M2A", iteration, m2, "longest rule id"),
                        2, m2.getInt("policy_rule_id"));
                assertEquals(message("M2A", iteration, m2, "near-prefix boundary"),
                        1, m2.getInt("policy_boundary_pass"));
                assertEquals(message("M2A", iteration, m2, "longest-prefix selection"),
                        1, m2.getInt("policy_longest_match"));
                assertEquals(message("M2A", iteration, m2, "pathname page not read-only"),
                        1, m2.getInt("original_path_read_only"));
                assertEquals(message("M2A", iteration, m2, "pathname memory changed"),
                        1, m2.getInt("original_path_memory_unchanged"));
                assertTrue(message("M2A", iteration, m2, "dumpable not restored"),
                        m2.getBoolean("restored_dumpable"));
                assertTrue(message("M2A", iteration, m2, "test files were not cleaned"),
                        m2.getBoolean("cleanup_ok"));
                assertProcTaskStateClean("after M2A iteration " + iteration);

                JSONObject missing = parseFirstLine(
                        "M2B", "HOOKSELF_M2B_MISSING_RESULT",
                        NativeTestBridge.runM2MissingRedirect(
                                targetContext.getFilesDir().getAbsolutePath()));
                assertCommonResult("M2B", iteration, missing, "PASS");
                assertEquals(message("M2B", iteration, missing, "scenario"),
                        "REDIRECT_MISSING", missing.getString("scenario"));
                assertEquals(message("M2B", iteration, missing, "expected errno"),
                        OsConstants.ENOENT, missing.getInt("expected_errno"));
                assertEquals(message("M2B", iteration, missing, "missing target not observed"),
                        1, missing.getInt("missing_target_observed"));
                assertEquals(message("M2B", iteration, missing, "child result"),
                        -OsConstants.ENOENT, missing.getLong("child_result"));
                assertEquals(message("M2B", iteration, missing, "parent result"),
                        -OsConstants.ENOENT, missing.getLong("parent_fd"));
                assertEquals(message("M2B", iteration, missing, "entry registers"),
                        1, missing.getInt("entry_registers_verified"));
                assertEquals(message("M2B", iteration, missing, "exit registers"),
                        1, missing.getInt("exit_registers_verified"));
                assertEquals(message("M2B", iteration, missing, "rewrite still active"),
                        0, missing.getInt("rewrite_active"));
                assertEquals(message("M2B", iteration, missing, "policy error"),
                        0, missing.getInt("policy_errno"));
                assertEquals(message("M2B", iteration, missing, "pathname page not read-only"),
                        1, missing.getInt("original_path_read_only"));
                assertEquals(message("M2B", iteration, missing, "pathname memory changed"),
                        1, missing.getInt("original_path_memory_unchanged"));
                assertTrue(message("M2B", iteration, missing, "test files were not cleaned"),
                        missing.getBoolean("cleanup_ok"));
                assertProcTaskStateClean("after M2B iteration " + iteration);

                JSONObject m4 = parseFirstLine(
                        "M4", "HOOKSELF_M4_PROBE_RESULT",
                        NativeTestBridge.runM4CapabilityProbe());
                Log.i(TAG, "M4 iteration " + iteration + ": " + m4);
                assertM4Result("M4", iteration, m4, false);
                assertProcTaskStateClean("after M4 iteration " + iteration);

                instrumentation.waitForIdleSync();
                Log.i(TAG, "completed iteration " + iteration + "/" + iterations);
            }
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    @Test
    public void selectiveRuntime() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context targetContext = instrumentation.getTargetContext();
        int iterations = readIterations(InstrumentationRegistry.getArguments());

        Intent intent = new Intent(targetContext, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(intent);
        assertNotNull("MainActivity did not start", activity);

        try {
            instrumentation.waitForIdleSync();
            JSONObject result = parseFirstLine(
                    "SELECTIVE", "HOOKSELF_SELECTIVE_RESULT",
                    NativeTestBridge.runSelectiveRuntimeSelfTest(
                            targetContext, iterations));
            Log.i(TAG, "selective runtime: " + result);
            assertSelectiveRuntimeResult(result, iterations);
            assertSelectivePostDestroyTaskStates("after selective destroy");
            SystemClock.sleep(25);
            assertSelectivePostDestroyTaskStates(
                    "after selective destroy settle");
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    private static void assertSelectiveRuntimeResult(
            JSONObject result, int iterations) throws JSONException {
        String prefix = "selective iterations=" + iterations + ": ";
        int activeRounds = iterations + 1;
        int stopCalls = iterations + 1;

        assertEquals(prefix + "verdict: " + result,
                "PASS", result.getString("verdict"));
        assertEquals(prefix + "schema field count: " + result,
                64, result.length());
        assertEquals(prefix + "schema version", 1, result.getInt("version"));
        assertEquals(prefix + "first failure", 0,
                result.getInt("first_failure"));
        assertEquals(prefix + "requested iterations", iterations,
                result.getInt("requested_iterations"));
        assertEquals(prefix + "completed iterations", iterations,
                result.getInt("completed_iterations"));
        assertEquals(prefix + "config flags", SELECTIVE_CONFIG_FLAGS,
                result.getInt("config_flags"));
        assertEquals(prefix + "failure mode", SELECTIVE_FAILURE_FAIL_CLOSED,
                result.getInt("failure_mode"));
        assertEquals(prefix + "rule count", 3, result.getInt("rule_count"));
        assertEquals(prefix + "config validation", 0,
                result.getInt("validate_result"));
        assertEquals(prefix + "runtime create", 0,
                result.getInt("create_result"));
        assertEquals(prefix + "configured state", STATE_CONFIGURED,
                result.getInt("configured_state"));

        assertEquals(prefix + "start calls", activeRounds,
                result.getInt("start_calls"));
        assertEquals(prefix + "start successes", activeRounds,
                result.getInt("start_successes"));
        assertEquals(prefix + "last start result", 0,
                result.getInt("last_start_result"));
        assertEquals(prefix + "running state checks", activeRounds,
                result.getInt("running_state_checks"));
        assertEquals(prefix + "last running state", STATE_RUNNING_SELECTIVE,
                result.getInt("last_running_state"));
        assertEquals(prefix + "stop calls", stopCalls,
                result.getInt("stop_calls"));
        assertEquals(prefix + "stop successes", stopCalls,
                result.getInt("stop_successes"));
        assertEquals(prefix + "last stop result", 0,
                result.getInt("last_stop_result"));
        assertEquals(prefix + "stopped state checks", stopCalls,
                result.getInt("stopped_state_checks"));
        assertEquals(prefix + "last stopped state", STATE_STOPPED,
                result.getInt("last_stopped_state"));

        assertEquals(prefix + "active rounds", activeRounds,
                result.getInt("active_rounds"));
        assertEquals(prefix + "active rounds passed", activeRounds,
                result.getInt("active_rounds_passed"));
        assertEquals(prefix + "passthrough rounds", iterations,
                result.getInt("passthrough_rounds"));
        assertEquals(prefix + "passthrough rounds passed", iterations,
                result.getInt("passthrough_rounds_passed"));
        assertEquals(prefix + "expected pid", Process.myPid(),
                result.getInt("expected_pid"));
        assertEquals(prefix + "expected tid", Process.myTid(),
                result.getInt("expected_tid"));
        int expectedPpid = result.getInt("expected_ppid");
        assertTrue(prefix + "expected ppid", expectedPpid > 0);

        assertEquals(prefix + "active gettid result", Process.myTid(),
                result.getLong("last_active_gettid"));
        assertEquals(prefix + "active getpid result", Process.myPid(),
                result.getLong("last_active_getpid"));
        assertEquals(prefix + "active getppid deny result", -OsConstants.EACCES,
                result.getLong("last_active_getppid"));
        assertEquals(prefix + "passthrough gettid result", Process.myTid(),
                result.getLong("last_passthrough_gettid"));
        assertEquals(prefix + "passthrough getpid result", Process.myPid(),
                result.getLong("last_passthrough_getpid"));
        assertEquals(prefix + "passthrough getppid result", expectedPpid,
                result.getLong("last_passthrough_getppid"));
        assertEquals(prefix + "active gettid calls", activeRounds,
                result.getInt("active_gettid_calls"));
        assertEquals(prefix + "active getpid calls", activeRounds,
                result.getInt("active_getpid_calls"));
        assertEquals(prefix + "active getppid calls", activeRounds,
                result.getInt("active_getppid_calls"));
        assertEquals(prefix + "passthrough gettid calls", iterations,
                result.getInt("passthrough_gettid_calls"));
        assertEquals(prefix + "passthrough getpid calls", iterations,
                result.getInt("passthrough_getpid_calls"));
        assertEquals(prefix + "passthrough getppid calls", iterations,
                result.getInt("passthrough_getppid_calls"));

        assertEquals(prefix + "gettid entry events", activeRounds,
                result.getInt("gettid_entry_events"));
        assertEquals(prefix + "gettid exit events", activeRounds,
                result.getInt("gettid_exit_events"));
        assertEquals(prefix + "gettid result matches", activeRounds,
                result.getInt("gettid_result_matches"));
        assertEquals(prefix + "getpid entry-only events", activeRounds,
                result.getInt("getpid_entry_events"));
        assertEquals(prefix + "unexpected getpid exit events", 0,
                result.getInt("getpid_exit_events"));
        assertEquals(prefix + "getppid deny entry events", activeRounds,
                result.getInt("getppid_deny_entry_events"));
        assertEquals(prefix + "getppid deny exit events", activeRounds,
                result.getInt("getppid_deny_exit_events"));
        assertEquals(prefix + "getppid deny result matches", activeRounds,
                result.getInt("getppid_deny_result_matches"));
        assertEquals(prefix + "runtime API bypass events", 0,
                result.getInt("control_rule_events"));
        assertEquals(prefix + "stopped passthrough emitted rule events", 0,
                result.getInt("passthrough_rule_events"));
        assertEquals(prefix + "unexpected rule events", 0,
                result.getInt("unexpected_rule_events"));
        assertTrue(prefix + "events read: " + result,
                result.getLong("events_read") >= (long) activeRounds * 7L);

        assertEquals(prefix + "final stop result", 0,
                result.getInt("final_stop_result"));
        assertEquals(prefix + "final state", STATE_STOPPED,
                result.getInt("final_state"));
        assertEquals(prefix + "stats result", 0,
                result.getInt("stats_result"));
        assertEquals(prefix + "stats state", STATE_STOPPED,
                result.getInt("stats_state"));
        assertTrue(prefix + "emitted/read event mismatch: " + result,
                result.getLong("emitted_events") >= result.getLong("events_read"));
        assertTrue(prefix + "observed syscall count: " + result,
                result.getLong("observed_syscalls") >= (long) activeRounds * 3L);
        assertEquals(prefix + "dropped events", 0L,
                result.getLong("dropped_events"));
        assertEquals(prefix + "internal errors", 0L,
                result.getLong("internal_errors"));
        assertTrue(prefix + "tracked tasks: " + result,
                result.getInt("tracked_tasks") > 0);
        assertEquals(prefix + "fatal code", 0, result.getInt("fatal_code"));
        assertEquals(prefix + "fatal errno", 0, result.getInt("fatal_errno"));
        assertEquals(prefix + "fatal tid", 0, result.getInt("fatal_tid"));
    }

    private static void assertM4Result(
            String probe, int iteration, JSONObject result, boolean forceFallback)
            throws JSONException {
        assertEquals(message(probe, iteration, result, "verdict"),
                "PASS", result.getString("verdict"));
        assertEquals(message(probe, iteration, result, "schema version"),
                1, result.getInt("version"));
        assertEquals(message(probe, iteration, result, "probe flags"),
                forceFallback ? 1 : 0, result.getInt("probe_flags"));
        assertEquals(message(probe, iteration, result, "fatal errno"),
                0, result.getInt("fatal_errno"));
        assertTrue(message(probe, iteration, result, "negative duration"),
                result.getLong("duration_ms") >= 0);
        assertEquals(message(probe, iteration, result, "caller pid"),
                Process.myPid(), result.getInt("caller_pid"));
        assertEquals(message(probe, iteration, result, "caller status before"),
                0, result.getInt("caller_status_before_errno"));
        assertEquals(message(probe, iteration, result, "caller status after"),
                0, result.getInt("caller_status_after_errno"));
        assertEquals(message(probe, iteration, result, "caller NNP before errno"),
                0, result.getInt("caller_no_new_privs_before_errno"));
        assertEquals(message(probe, iteration, result, "caller NNP after errno"),
                0, result.getInt("caller_no_new_privs_after_errno"));
        int callerNnp = result.getInt("caller_no_new_privs_before");
        assertTrue(message(probe, iteration, result, "invalid caller NNP"),
                callerNnp == 0 || callerNnp == 1);
        assertEquals(message(probe, iteration, result, "caller NNP changed"),
                callerNnp, result.getInt("caller_no_new_privs_after"));
        assertEquals(message(probe, iteration, result, "caller seccomp before"),
                2, result.getInt("caller_seccomp_mode_before"));
        assertEquals(message(probe, iteration, result, "caller seccomp changed"),
                result.getInt("caller_seccomp_mode_before"),
                result.getInt("caller_seccomp_mode_after"));
        assertFilterCountPair(probe, iteration, result,
                "caller_filter_count_supported",
                "caller_filter_count_before", "caller_filter_count_after",
                false);

        int supervisorPid = result.getInt("supervisor_pid");
        int traceePid = result.getInt("tracee_pid");
        int tsyncPid = result.getInt("tsync_pid");
        int workerTid = result.getInt("tsync_worker_tid");
        assertTrue(message(probe, iteration, result, "invalid process identities"),
                supervisorPid > 0 && traceePid > 0 && tsyncPid > 0 &&
                        workerTid > 0 && supervisorPid != traceePid &&
                        tsyncPid != workerTid && supervisorPid != Process.myPid() &&
                        traceePid != Process.myPid() && tsyncPid != Process.myPid());
        assertEquals(message(probe, iteration, result, "supervisor timeout"),
                0, result.getInt("supervisor_timeout"));
        assertEquals(message(probe, iteration, result, "supervisor exit"),
                0, result.getInt("supervisor_exit_status"));
        assertEquals(message(probe, iteration, result, "supervisor cleanup"),
                0, result.getInt("supervisor_cleanup_errno"));
        assertEquals(message(probe, iteration, result, "supervisor parent check"),
                1, result.getInt("supervisor_parent_check"));
        assertEquals(message(probe, iteration, result, "supervisor PDEATHSIG set"),
                0, result.getInt("supervisor_pdeathsig_errno"));
        assertEquals(message(probe, iteration, result, "supervisor PDEATHSIG value"),
                OsConstants.SIGKILL, result.getInt("supervisor_pdeathsig_value"));
        assertEquals(message(probe, iteration, result, "tracee cleanup"),
                0, result.getInt("tracee_cleanup_errno"));
        assertEquals(message(probe, iteration, result, "tracee identity read"),
                0, result.getInt("tracee_identity_errno"));
        assertTrue(message(probe, iteration, result, "tracee starttime missing"),
                result.getLong("tracee_start_time") > 0);
        assertEquals(message(probe, iteration, result, "tracee PDEATHSIG set"),
                0, result.getInt("tracee_pdeathsig_errno"));
        assertEquals(message(probe, iteration, result, "tracee PDEATHSIG value"),
                OsConstants.SIGKILL, result.getInt("tracee_pdeathsig_value"));
        assertEquals(message(probe, iteration, result, "TRACEME"),
                0, result.getInt("traceme_errno"));
        assertEquals(message(probe, iteration, result, "initial ptrace stop"),
                1, result.getInt("initial_stop_seen"));
        assertEquals(message(probe, iteration, result, "ptrace options"),
                0, result.getInt("setoptions_errno"));
        assertEquals(message(probe, iteration, result, "tracee NNP read"),
                0, result.getInt("tracee_no_new_privs_before_errno"));
        assertEquals(message(probe, iteration, result, "tracee inherited NNP"),
                callerNnp, result.getInt("tracee_no_new_privs_before"));
        assertEquals(message(probe, iteration, result, "tracee NNP set"),
                0, result.getInt("tracee_no_new_privs_errno"));
        assertEquals(message(probe, iteration, result, "tracee status before"),
                0, result.getInt("tracee_status_before_errno"));
        assertEquals(message(probe, iteration, result, "tracee status after"),
                0, result.getInt("tracee_status_after_errno"));
        assertEquals(message(probe, iteration, result, "tracee seccomp before"),
                2, result.getInt("tracee_seccomp_mode_before"));
        assertEquals(message(probe, iteration, result, "tracee seccomp after"),
                2, result.getInt("tracee_seccomp_mode_after"));
        assertFilterCountPair(probe, iteration, result,
                "tracee_filter_count_supported",
                "tracee_filter_count_before", "tracee_filter_count_after",
                true);
        assertEquals(message(probe, iteration, result, "tracee filter build"),
                0, result.getInt("tracee_filter_build_errno"));
        assertEquals(message(probe, iteration, result, "tracee filter install"),
                0, result.getInt("tracee_filter_install_errno"));
        assertEquals(message(probe, iteration, result, "tracee TSYNC failed TID"),
                0, result.getInt("tracee_filter_failed_tid"));
        assertEquals(message(probe, iteration, result, "seccomp event count"),
                2, result.getInt("seccomp_event_count"));
        assertEquals(message(probe, iteration, result, "seccomp class data"),
                2, result.getInt("event_data_match_count"));

        int syscallInfoSupported = result.getInt("syscall_info_supported");
        if (forceFallback || syscallInfoSupported == 0) {
            assertEquals(message(probe, iteration, result, "fallback mode"),
                    0, syscallInfoSupported);
            assertEquals(message(probe, iteration, result, "inactive seccomp info"),
                    0, result.getInt("seccomp_info_match_count"));
            assertEquals(message(probe, iteration, result, "inactive exit info"),
                    0, result.getInt("syscall_exit_info_match"));
            assertEquals(message(probe, iteration, result, "seccomp register fallback"),
                    2, result.getInt("seccomp_fallback_match_count"));
            assertEquals(message(probe, iteration, result, "exit register fallback"),
                    1, result.getInt("syscall_exit_fallback_match"));
        } else {
            assertEquals(message(probe, iteration, result, "syscall info support"),
                    1, syscallInfoSupported);
            assertEquals(message(probe, iteration, result, "seccomp syscall info"),
                    2, result.getInt("seccomp_info_match_count"));
            assertEquals(message(probe, iteration, result, "exit syscall info"),
                    1, result.getInt("syscall_exit_info_match"));
            assertEquals(message(probe, iteration, result, "inactive entry fallback"),
                    0, result.getInt("seccomp_fallback_match_count"));
            assertEquals(message(probe, iteration, result, "inactive exit fallback"),
                    0, result.getInt("syscall_exit_fallback_match"));
        }
        assertEquals(message(probe, iteration, result, "CONT resume"),
                0, result.getInt("cont_resume_errno"));
        assertEquals(message(probe, iteration, result, "SYSCALL resume"),
                0, result.getInt("syscall_resume_errno"));
        assertEquals(message(probe, iteration, result, "syscall exit stop"),
                1, result.getInt("syscall_exit_stop_seen"));
        assertEquals(message(probe, iteration, result, "final CONT resume"),
                0, result.getInt("final_resume_errno"));
        assertEquals(message(probe, iteration, result, "detach stop"),
                1, result.getInt("detach_stop_seen"));
        assertEquals(message(probe, iteration, result, "detach result"),
                0, result.getInt("detach_errno"));
        assertEquals(message(probe, iteration, result, "unexpected ptrace stops"),
                0, result.getInt("unexpected_stop_count"));
        assertEquals(message(probe, iteration, result, "first gettid result"),
                traceePid, result.getLong("first_gettid_result"));
        assertEquals(message(probe, iteration, result, "second gettid result"),
                traceePid, result.getLong("second_gettid_result"));
        assertEquals(message(probe, iteration, result, "observed exit result"),
                traceePid, result.getLong("observed_exit_result"));
        assertEquals(message(probe, iteration, result, "post-detach result"),
                -OsConstants.ENOSYS, result.getLong("post_detach_gettid_result"));
        assertEquals(message(probe, iteration, result, "tracee exit"),
                0, result.getInt("tracee_exit_status"));

        assertEquals(message(probe, iteration, result, "TSYNC timeout"),
                0, result.getInt("tsync_timeout"));
        assertEquals(message(probe, iteration, result, "TSYNC child exit"),
                0, result.getInt("tsync_exit_status"));
        assertEquals(message(probe, iteration, result, "TSYNC cleanup"),
                0, result.getInt("tsync_cleanup_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC parent check"),
                1, result.getInt("tsync_parent_check"));
        assertEquals(message(probe, iteration, result, "TSYNC PDEATHSIG set"),
                0, result.getInt("tsync_pdeathsig_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC PDEATHSIG value"),
                OsConstants.SIGKILL, result.getInt("tsync_pdeathsig_value"));
        assertEquals(message(probe, iteration, result, "TSYNC signal mask"),
                0, result.getInt("tsync_signal_mask_errno"));
        assertEquals(message(probe, iteration, result, "raw clone"),
                0, result.getInt("tsync_clone_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC worker readiness"),
                1, result.getInt("tsync_worker_ready"));
        assertEquals(message(probe, iteration, result, "TSYNC NNP read"),
                0, result.getInt("tsync_no_new_privs_before_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC inherited NNP"),
                callerNnp, result.getInt("tsync_no_new_privs_before"));
        assertEquals(message(probe, iteration, result, "TSYNC NNP set"),
                0, result.getInt("tsync_no_new_privs_errno"));
        assertEquals(message(probe, iteration, result, "leader status before"),
                0, result.getInt("tsync_leader_status_before_errno"));
        assertEquals(message(probe, iteration, result, "worker status before"),
                0, result.getInt("tsync_worker_status_before_errno"));
        assertEquals(message(probe, iteration, result, "leader status after"),
                0, result.getInt("tsync_leader_status_after_errno"));
        assertEquals(message(probe, iteration, result, "worker status after"),
                0, result.getInt("tsync_worker_status_after_errno"));
        assertEquals(message(probe, iteration, result, "leader seccomp before"),
                2, result.getInt("tsync_leader_mode_before"));
        assertEquals(message(probe, iteration, result, "worker seccomp before"),
                2, result.getInt("tsync_worker_mode_before"));
        assertEquals(message(probe, iteration, result, "leader seccomp after"),
                2, result.getInt("tsync_leader_mode_after"));
        assertEquals(message(probe, iteration, result, "worker seccomp after"),
                2, result.getInt("tsync_worker_mode_after"));
        assertFilterCountPair(probe, iteration, result,
                "tsync_filter_count_supported",
                "tsync_leader_filters_before", "tsync_leader_filters_after",
                true);
        if (result.getInt("tsync_filter_count_supported") != 0) {
            assertEquals(message(probe, iteration, result,
                            "TSYNC initial thread filter counts"),
                    result.getInt("tsync_leader_filters_before"),
                    result.getInt("tsync_worker_filters_before"));
            assertEquals(message(probe, iteration, result,
                            "TSYNC final thread filter counts"),
                    result.getInt("tsync_leader_filters_after"),
                    result.getInt("tsync_worker_filters_after"));
        } else {
            assertEquals(message(probe, iteration, result,
                            "unsupported worker filter count before"),
                    -1, result.getInt("tsync_worker_filters_before"));
            assertEquals(message(probe, iteration, result,
                            "unsupported worker filter count after"),
                    -1, result.getInt("tsync_worker_filters_after"));
        }
        assertEquals(message(probe, iteration, result, "TSYNC filter build"),
                0, result.getInt("tsync_filter_build_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC filter install"),
                0, result.getInt("tsync_filter_install_errno"));
        assertEquals(message(probe, iteration, result, "TSYNC failed TID"),
                0, result.getInt("tsync_filter_failed_tid"));
        assertEquals(message(probe, iteration, result, "leader baseline"),
                Process.myPid(), result.getLong("tsync_main_baseline_result"));
        assertEquals(message(probe, iteration, result, "worker baseline"),
                Process.myPid(), result.getLong("tsync_worker_baseline_result"));
        assertEquals(message(probe, iteration, result, "no-tracer leader result"),
                -OsConstants.ENOSYS, result.getLong("tsync_main_no_tracer_result"));
        assertEquals(message(probe, iteration, result, "no-tracer worker result"),
                -OsConstants.ENOSYS, result.getLong("tsync_worker_no_tracer_result"));
        assertEquals(message(probe, iteration, result, "TSYNC worker exit"),
                1, result.getInt("tsync_worker_exited"));
    }

    private static void assertFilterCountPair(
            String probe, int iteration, JSONObject result, String supportKey,
            String beforeKey, String afterKey, boolean allowIncrement)
            throws JSONException {
        int supported = result.getInt(supportKey);
        int before = result.getInt(beforeKey);
        int after = result.getInt(afterKey);
        assertTrue(message(probe, iteration, result, "invalid " + supportKey),
                supported == 0 || supported == 1);
        if (supported == 0) {
            assertEquals(message(probe, iteration, result,
                    "unsupported filter count before"), -1, before);
            assertEquals(message(probe, iteration, result,
                    "unsupported filter count after"), -1, after);
            return;
        }
        assertTrue(message(probe, iteration, result, "invalid filter count before"),
                before >= 1);
        if (allowIncrement) {
            assertTrue(message(probe, iteration, result,
                            "filter count changed unexpectedly"),
                    after == before || after == before + 1);
        } else {
            assertEquals(message(probe, iteration, result,
                    "filter count changed"), before, after);
        }
    }

    private static void assertM4FaultResult(
            String probe, JSONObject result, int expectedFlag) throws JSONException {
        assertEquals(probe + ": verdict: " + result,
                "FAILED", result.getString("verdict"));
        assertEquals(probe + ": schema: " + result, 1, result.getInt("version"));
        assertEquals(probe + ": flags: " + result,
                expectedFlag, result.getInt("probe_flags"));
        assertEquals(probe + ": fatal errno: " + result,
                OsConstants.ETIMEDOUT, result.getInt("fatal_errno"));
        assertEquals(probe + ": caller pid: " + result,
                Process.myPid(), result.getInt("caller_pid"));
        assertEquals(probe + ": caller NNP before read: " + result,
                0, result.getInt("caller_no_new_privs_before_errno"));
        assertEquals(probe + ": caller NNP after read: " + result,
                0, result.getInt("caller_no_new_privs_after_errno"));
        assertEquals(probe + ": caller NNP changed: " + result,
                result.getInt("caller_no_new_privs_before"),
                result.getInt("caller_no_new_privs_after"));
        assertEquals(probe + ": caller seccomp changed: " + result,
                result.getInt("caller_seccomp_mode_before"),
                result.getInt("caller_seccomp_mode_after"));
        assertEquals(probe + ": caller filter count changed: " + result,
                result.getInt("caller_filter_count_before"),
                result.getInt("caller_filter_count_after"));
        assertEquals(probe + ": supervisor cleanup: " + result,
                0, result.getInt("supervisor_cleanup_errno"));
        assertEquals(probe + ": supervisor PDEATHSIG: " + result,
                0, result.getInt("supervisor_pdeathsig_errno"));
        assertEquals(probe + ": supervisor PDEATHSIG value: " + result,
                OsConstants.SIGKILL,
                result.getInt("supervisor_pdeathsig_value"));
        assertEquals(probe + ": tracee cleanup: " + result,
                0, result.getInt("tracee_cleanup_errno"));
        assertEquals(probe + ": TSYNC cleanup: " + result,
                0, result.getInt("tsync_cleanup_errno"));
        if (expectedFlag == M4_INJECT_SUPERVISOR_HANG) {
            assertEquals(probe + ": supervisor timeout: " + result,
                    1, result.getInt("supervisor_timeout"));
            assertEquals(probe + ": supervisor kill status: " + result,
                    128 + OsConstants.SIGKILL,
                    result.getInt("supervisor_exit_status"));
            assertEquals(probe + ": TSYNC subcase should complete: " + result,
                    0, result.getInt("tsync_exit_status"));
        } else {
            assertEquals(probe + ": supervisor should complete: " + result,
                    0, result.getInt("supervisor_exit_status"));
            assertEquals(probe + ": TSYNC timeout: " + result,
                    1, result.getInt("tsync_timeout"));
            assertEquals(probe + ": TSYNC kill status: " + result,
                    128 + OsConstants.SIGKILL,
                    result.getInt("tsync_exit_status"));
        }
    }

    private static int readIterations(Bundle arguments) {
        String value = arguments.getString(ARG_ITERATIONS);
        if (value == null || value.trim().isEmpty()) {
            return DEFAULT_ITERATIONS;
        }
        final int iterations;
        try {
            iterations = Integer.parseInt(value.trim());
        } catch (NumberFormatException error) {
            throw new AssertionError("Invalid instrumentation argument iterations=" + value,
                    error);
        }
        assertTrue("iterations must be between 1 and " + MAX_ITERATIONS,
                iterations >= 1 && iterations <= MAX_ITERATIONS);
        return iterations;
    }

    private static JSONObject parseFirstLine(String probe, String marker, String report)
            throws JSONException {
        assertNotNull(probe + " returned null", report);
        int lineEnd = report.indexOf('\n');
        String firstLine = (lineEnd >= 0 ? report.substring(0, lineEnd) : report).trim();
        String prefix = marker + " ";
        assertTrue(probe + " report has an invalid first line: " + firstLine,
                firstLine.startsWith(prefix));
        return new JSONObject(firstLine.substring(prefix.length()));
    }

    private static void assertCommonResult(
            String probe, int iteration, JSONObject result, String expectedVerdict)
            throws JSONException {
        assertEquals(message(probe, iteration, result, "verdict"),
                expectedVerdict, result.getString("verdict"));
        assertEquals(message(probe, iteration, result, "target pid"),
                Process.myPid(), result.getInt("target_pid"));
        int discovered = result.getInt("discovered_tids");
        int attached = result.getInt("attached_tids");
        int detached = result.getInt("detached_tids");
        assertTrue(message(probe, iteration, result, "no threads discovered"),
                discovered > 0);
        assertEquals(message(probe, iteration, result, "partial attach"),
                discovered, attached);
        assertEquals(message(probe, iteration, result, "attach/detach mismatch"),
                attached, detached);
        assertEquals(message(probe, iteration, result, "attach failures"),
                0, result.getInt("attach_failures"));
        assertEquals(message(probe, iteration, result, "detach failures"),
                0, result.getInt("detach_failures"));
        assertTrue(message(probe, iteration, result, "dumpable not restored"),
                result.getBoolean("restored_dumpable"));
        assertEquals(message(probe, iteration, result, "tracer exit status"),
                0, result.getInt("child_exit_status"));
    }

    private static String message(
            String probe, int iteration, JSONObject result, String failure) {
        return probe + " iteration " + iteration + ": " + failure + ": " + result;
    }

    private static void assertProcTaskStateClean(String phase) throws IOException {
        File[] taskDirectories = new File("/proc/self/task").listFiles(File::isDirectory);
        assertNotNull(phase + ": cannot enumerate /proc/self/task", taskDirectories);

        int checkedTasks = 0;
        for (File taskDirectory : taskDirectories) {
            if (!isDecimal(taskDirectory.getName())) {
                continue;
            }
            File statusFile = new File(taskDirectory, "status");
            if (!statusFile.exists()) {
                continue;
            }

            Integer tracerPid = null;
            Character state = null;
            try (BufferedReader reader = new BufferedReader(new FileReader(statusFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        tracerPid = Integer.parseInt(line.substring("TracerPid:".length()).trim());
                    } else if (line.startsWith("State:")) {
                        String value = line.substring("State:".length()).trim();
                        if (!value.isEmpty()) {
                            state = value.charAt(0);
                        }
                    }
                }
            } catch (IOException error) {
                if (!statusFile.exists()) {
                    continue;
                }
                throw error;
            }

            String task = phase + ", tid=" + taskDirectory.getName();
            assertNotNull(task + ": missing TracerPid", tracerPid);
            assertEquals(task + ": tracer remains attached", 0, tracerPid.intValue());
            assertNotNull(task + ": missing State", state);
            assertFalse(task + ": task remains stopped/traced/zombie, state=" + state,
                    state == 'T' || state == 't' || state == 'Z');
            checkedTasks++;
        }
        assertTrue(phase + ": no task status was checked", checkedTasks > 0);
    }

    private static void assertSelectivePostDestroyTaskStates(String phase)
            throws IOException {
        final long deadline = SystemClock.uptimeMillis() + 2_500L;
        Integer consecutiveTracerPid = null;
        int consecutiveStableRounds = 0;
        int completedRounds = 0;
        int lastCheckedTasks = 0;
        String lastIssue = "no task scan completed";

        while (SystemClock.uptimeMillis() < deadline) {
            completedRounds++;
            File[] taskDirectories =
                    new File("/proc/self/task").listFiles(File::isDirectory);
            if (taskDirectories == null) {
                consecutiveStableRounds = 0;
                consecutiveTracerPid = null;
                lastCheckedTasks = 0;
                lastIssue = "cannot enumerate /proc/self/task";
            } else {
                Integer roundTracerPid = null;
                int checkedTasks = 0;
                boolean roundStable = true;
                String roundIssue = null;

                for (File taskDirectory : taskDirectories) {
                    String tid = taskDirectory.getName();
                    if (!isDecimal(tid)) {
                        continue;
                    }
                    File statusFile = new File(taskDirectory, "status");
                    if (!statusFile.exists()) {
                        continue;
                    }

                    Integer tracerPid = null;
                    Character state = null;
                    try (BufferedReader reader =
                                 new BufferedReader(new FileReader(statusFile))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("TracerPid:")) {
                                tracerPid = Integer.parseInt(
                                        line.substring("TracerPid:".length()).trim());
                            } else if (line.startsWith("State:")) {
                                String value = line.substring("State:".length()).trim();
                                if (!value.isEmpty()) {
                                    state = value.charAt(0);
                                }
                            }
                        }
                    } catch (IOException error) {
                        if (!statusFile.exists()) {
                            continue;
                        }
                        roundStable = false;
                        roundIssue = "tid=" + tid + ": status read failed: " +
                                error.getClass().getSimpleName() + ": " +
                                error.getMessage();
                        break;
                    }
                    if (!statusFile.exists()) {
                        continue;
                    }

                    checkedTasks++;
                    if (tracerPid == null) {
                        roundStable = false;
                        roundIssue = "tid=" + tid + ": missing TracerPid";
                        break;
                    }
                    if (tracerPid <= 0) {
                        roundStable = false;
                        roundIssue = "tid=" + tid +
                                ": resident tracer missing, TracerPid=" + tracerPid;
                        break;
                    }
                    if (state == null) {
                        roundStable = false;
                        roundIssue = "tid=" + tid + ": missing State";
                        break;
                    }
                    if (state == 'T' || state == 't' || state == 'Z') {
                        roundStable = false;
                        roundIssue = "tid=" + tid +
                                ": task remains stopped/traced/zombie, state=" + state +
                                ", TracerPid=" + tracerPid;
                        break;
                    }
                    if (roundTracerPid == null) {
                        roundTracerPid = tracerPid;
                    } else if (!roundTracerPid.equals(tracerPid)) {
                        roundStable = false;
                        roundIssue = "tid=" + tid + ": inconsistent resident tracer, " +
                                "expected=" + roundTracerPid + ", actual=" + tracerPid;
                        break;
                    }
                }

                lastCheckedTasks = checkedTasks;
                if (roundStable && checkedTasks == 0) {
                    roundStable = false;
                    roundIssue = "no live task status was checked";
                }
                if (roundStable && consecutiveTracerPid != null &&
                        !consecutiveTracerPid.equals(roundTracerPid)) {
                    roundStable = false;
                    roundIssue = "resident tracer changed between stable rounds, expected=" +
                            consecutiveTracerPid + ", actual=" + roundTracerPid;
                }
                if (roundStable) {
                    consecutiveTracerPid = roundTracerPid;
                    consecutiveStableRounds++;
                    if (consecutiveStableRounds >= 2) {
                        return;
                    }
                    lastIssue = "only one stable round completed, TracerPid=" +
                            roundTracerPid + ", checkedTasks=" + checkedTasks;
                } else {
                    consecutiveTracerPid = null;
                    consecutiveStableRounds = 0;
                    lastIssue = roundIssue == null ? "task scan was unstable" : roundIssue;
                }
            }

            long remaining = deadline - SystemClock.uptimeMillis();
            if (remaining > 0L) {
                SystemClock.sleep(Math.min(20L, remaining));
            }
        }

        fail(phase + ": tasks did not reach two consecutive stable rounds within " +
                "2500ms; rounds=" + completedRounds +
                ", lastCheckedTasks=" + lastCheckedTasks +
                ", lastIssue=" + lastIssue);
    }

    private static boolean isDecimal(String value) {
        if (value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
