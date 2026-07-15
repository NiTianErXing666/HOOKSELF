#include "selective_resident_selftest.h"

#include <asm/unistd.h>
#include <errno.h>

#include <cstring>

#include "hookself/public_api.h"
#include "platform/raw_syscall_arm64.h"
#include "runtime_api_selftest.h"

namespace hookself::internal {
namespace {

constexpr uint32_t kGettidRuleId = 8401U;
constexpr uint32_t kGetpidRuleId = 8402U;
constexpr uint32_t kGetppidDenyRuleId = 8403U;

enum FailureStage : int32_t {
    kFailureNone = 0,
    kFailureIterations = 1,
    kFailureBaseline = 2,
    kFailureConfig = 3,
    kFailureCreate = 4,
    kFailureConfiguredState = 5,
    kFailureStart = 6,
    kFailureRunningState = 7,
    kFailureActiveCall = 8,
    kFailureActiveEvents = 9,
    kFailureStop = 10,
    kFailureStoppedState = 11,
    kFailurePassthroughCall = 12,
    kFailurePassthroughEvents = 13,
    kFailureStats = 14,
    kFailureInvariant = 15,
    kFailureRuntimeApiStress = 16,
};

enum class DrainMode {
    kControl,
    kActive,
    kPassthrough,
};

struct EventSnapshot {
    uint32_t gettid_entry;
    uint32_t gettid_exit;
    uint32_t gettid_result_matches;
    uint32_t getpid_entry;
    uint32_t getpid_exit;
    uint32_t getppid_deny_entry;
    uint32_t getppid_deny_exit;
    uint32_t getppid_deny_result_matches;
    uint32_t unexpected;
};

void NoteFailure(SelectiveResidentSelfTestReport* report,
                 FailureStage stage) noexcept {
    if (report->first_failure == kFailureNone) {
        report->first_failure = stage;
    }
}

bool IsSelfTestRule(uint32_t rule_id) noexcept {
    return rule_id == kGettidRuleId || rule_id == kGetpidRuleId ||
           rule_id == kGetppidDenyRuleId;
}

EventSnapshot SnapshotEvents(
        const SelectiveResidentSelfTestReport& report) noexcept {
    return {
            report.gettid_entry_events,
            report.gettid_exit_events,
            report.gettid_result_matches,
            report.getpid_entry_events,
            report.getpid_exit_events,
            report.getppid_deny_entry_events,
            report.getppid_deny_exit_events,
            report.getppid_deny_result_matches,
            report.unexpected_rule_events,
    };
}

bool ActiveEventDeltaMatches(
        const EventSnapshot& before,
        const SelectiveResidentSelfTestReport& report) noexcept {
    return report.gettid_entry_events == before.gettid_entry + 1U &&
           report.gettid_exit_events == before.gettid_exit + 1U &&
           report.gettid_result_matches ==
                   before.gettid_result_matches + 1U &&
           report.getpid_entry_events == before.getpid_entry + 1U &&
           report.getpid_exit_events == before.getpid_exit &&
           report.getppid_deny_entry_events ==
                   before.getppid_deny_entry + 1U &&
           report.getppid_deny_exit_events ==
                   before.getppid_deny_exit + 1U &&
           report.getppid_deny_result_matches ==
                   before.getppid_deny_result_matches + 1U &&
           report.unexpected_rule_events == before.unexpected;
}

void ConsumeEvents(HookselfRuntime* runtime, DrainMode mode,
                   SelectiveResidentSelfTestReport* report) noexcept {
    HookselfEvent events[64]{};
    for (;;) {
        const size_t count = hookself_read_events(runtime, events, 64U);
        if (count == 0U) {
            return;
        }
        report->events_read += count;
        for (size_t index = 0; index < count; ++index) {
            const HookselfEvent& event = events[index];
            if (event.tid != report->expected_tid ||
                !IsSelfTestRule(event.rule_id)) {
                continue;
            }
            if (mode == DrainMode::kPassthrough) {
                ++report->passthrough_rule_events;
                continue;
            }
            if (mode == DrainMode::kControl) {
                ++report->control_rule_events;
                const bool valid_gettid =
                        event.kind == HOOKSELF_EVENT_SYSCALL &&
                        event.rule_id == kGettidRuleId &&
                        event.syscall_number == __NR_gettid &&
                        event.action == HOOKSELF_SYSCALL_OBSERVE &&
                        (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY ||
                         (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
                          event.result == report->expected_tid));
                if (!valid_gettid) {
                    ++report->unexpected_rule_events;
                }
                continue;
            }

            if (event.kind != HOOKSELF_EVENT_SYSCALL) {
                ++report->unexpected_rule_events;
                continue;
            }
            if (event.rule_id == kGettidRuleId &&
                event.syscall_number == __NR_gettid &&
                event.action == HOOKSELF_SYSCALL_OBSERVE) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->gettid_entry_events;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    ++report->gettid_exit_events;
                    if (event.result == report->expected_tid) {
                        ++report->gettid_result_matches;
                    } else {
                        ++report->unexpected_rule_events;
                    }
                } else {
                    ++report->unexpected_rule_events;
                }
                continue;
            }
            if (event.rule_id == kGetpidRuleId &&
                event.syscall_number == __NR_getpid &&
                event.action == HOOKSELF_SYSCALL_OBSERVE) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->getpid_entry_events;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    ++report->getpid_exit_events;
                } else {
                    ++report->unexpected_rule_events;
                }
                continue;
            }
            if (event.rule_id == kGetppidDenyRuleId &&
                event.syscall_number == __NR_getppid &&
                event.action == HOOKSELF_SYSCALL_DENY) {
                if (event.phase == HOOKSELF_SYSCALL_PHASE_ENTRY) {
                    ++report->getppid_deny_entry_events;
                } else if (event.phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
                    ++report->getppid_deny_exit_events;
                    if (event.result == -EACCES && event.error == EACCES) {
                        ++report->getppid_deny_result_matches;
                    } else {
                        ++report->unexpected_rule_events;
                    }
                } else {
                    ++report->unexpected_rule_events;
                }
                continue;
            }
            ++report->unexpected_rule_events;
        }
    }
}

bool QueryState(HookselfRuntime* runtime, int32_t expected,
                int32_t* last_state, uint32_t* successful_checks,
                SelectiveResidentSelfTestReport* report,
                FailureStage failure) noexcept {
    int32_t state = HOOKSELF_STATE_IDLE;
    const int32_t result = hookself_get_state(runtime, &state);
    *last_state = state;
    if (result == HOOKSELF_OK && state == expected) {
        ++*successful_checks;
        return true;
    }
    NoteFailure(report, failure);
    return false;
}

bool StartAndCheck(HookselfRuntime* runtime,
                   SelectiveResidentSelfTestReport* report) noexcept {
    ++report->start_calls;
    report->last_start_result = hookself_start(runtime);
    if (report->last_start_result != HOOKSELF_OK) {
        NoteFailure(report, kFailureStart);
        return false;
    }
    ++report->start_successes;
    if (!QueryState(runtime, HOOKSELF_STATE_RUNNING_SELECTIVE,
                    &report->last_running_state,
                    &report->running_state_checks, report,
                    kFailureRunningState)) {
        return false;
    }
    ConsumeEvents(runtime, DrainMode::kControl, report);
    return true;
}

bool StopAndCheck(HookselfRuntime* runtime,
                  SelectiveResidentSelfTestReport* report) noexcept {
    ++report->stop_calls;
    report->last_stop_result = hookself_stop(runtime);
    if (report->last_stop_result != HOOKSELF_OK) {
        NoteFailure(report, kFailureStop);
        return false;
    }
    ++report->stop_successes;
    if (!QueryState(runtime, HOOKSELF_STATE_STOPPED,
                    &report->last_stopped_state,
                    &report->stopped_state_checks, report,
                    kFailureStoppedState)) {
        return false;
    }
    ConsumeEvents(runtime, DrainMode::kControl, report);
    return true;
}

void RunActiveRound(HookselfRuntime* runtime,
                    SelectiveResidentSelfTestReport* report) noexcept {
    const EventSnapshot before = SnapshotEvents(*report);
    ++report->active_rounds;
    HookselfStats active_stats{};
    active_stats.struct_size = sizeof(active_stats);
    if (hookself_get_stats(runtime, &active_stats) != HOOKSELF_OK ||
        active_stats.state != HOOKSELF_STATE_RUNNING_SELECTIVE) {
        NoteFailure(report, kFailureActiveCall);
    }
    ++report->active_gettid_calls;
    report->last_active_gettid =
            hookself::platform::RawSyscall6(__NR_gettid);
    ++report->active_getpid_calls;
    report->last_active_getpid =
            hookself::platform::RawSyscall6(__NR_getpid);
    ++report->active_getppid_calls;
    report->last_active_getppid =
            hookself::platform::RawSyscall6(__NR_getppid);
    ConsumeEvents(runtime, DrainMode::kActive, report);

    const bool calls_match =
            report->last_active_gettid == report->expected_tid &&
            report->last_active_getpid == report->expected_pid &&
            report->last_active_getppid == -EACCES;
    const bool events_match = ActiveEventDeltaMatches(before, *report);
    if (!calls_match) {
        NoteFailure(report, kFailureActiveCall);
    }
    if (!events_match) {
        NoteFailure(report, kFailureActiveEvents);
    }
    if (calls_match && events_match) {
        ++report->active_rounds_passed;
    }
}

void RunPassthroughRound(HookselfRuntime* runtime,
                         SelectiveResidentSelfTestReport* report) noexcept {
    const uint32_t before_events = report->passthrough_rule_events;
    ++report->passthrough_rounds;
    ++report->passthrough_gettid_calls;
    report->last_passthrough_gettid =
            hookself::platform::RawSyscall6(__NR_gettid);
    ++report->passthrough_getpid_calls;
    report->last_passthrough_getpid =
            hookself::platform::RawSyscall6(__NR_getpid);
    ++report->passthrough_getppid_calls;
    report->last_passthrough_getppid =
            hookself::platform::RawSyscall6(__NR_getppid);
    ConsumeEvents(runtime, DrainMode::kPassthrough, report);

    const bool calls_match =
            report->last_passthrough_gettid == report->expected_tid &&
            report->last_passthrough_getpid == report->expected_pid &&
            report->last_passthrough_getppid == report->expected_ppid;
    const bool events_match =
            report->passthrough_rule_events == before_events;
    if (!calls_match) {
        NoteFailure(report, kFailurePassthroughCall);
    }
    if (!events_match) {
        NoteFailure(report, kFailurePassthroughEvents);
    }
    if (calls_match && events_match) {
        ++report->passthrough_rounds_passed;
    }
}

void AppendSigned(std::string* output, const char* key,
                  int64_t value) {
    output->append(",\"");
    output->append(key);
    output->append("\":");
    output->append(std::to_string(value));
}

void AppendUnsigned(std::string* output, const char* key,
                    uint64_t value) {
    output->append(",\"");
    output->append(key);
    output->append("\":");
    output->append(std::to_string(value));
}

}  // namespace

SelectiveResidentSelfTestReport RunSelectiveResidentSelfTest(
        uint32_t iterations, const char* virtual_backing_dir) noexcept {
    SelectiveResidentSelfTestReport report{};
    report.version = kSelectiveResidentSelfTestVersion;
    report.requested_iterations = iterations;
    report.last_start_result = HOOKSELF_E_INVALID_STATE;
    report.last_stop_result = HOOKSELF_E_INVALID_STATE;
    report.final_stop_result = HOOKSELF_E_INVALID_STATE;
    report.stats_result = HOOKSELF_E_INVALID_STATE;

    if (iterations == 0U ||
        iterations > kSelectiveResidentSelfTestMaxIterations) {
        NoteFailure(&report, kFailureIterations);
        return report;
    }

    const long pid = hookself::platform::RawSyscall6(__NR_getpid);
    const long tid = hookself::platform::RawSyscall6(__NR_gettid);
    const long ppid = hookself::platform::RawSyscall6(__NR_getppid);
    if (hookself::platform::RawError(pid) != 0 ||
        hookself::platform::RawError(tid) != 0 ||
        hookself::platform::RawError(ppid) != 0 || pid <= 0 || tid <= 0 ||
        ppid <= 0 || pid > INT32_MAX || tid > INT32_MAX ||
        ppid > INT32_MAX) {
        NoteFailure(&report, kFailureBaseline);
        return report;
    }
    report.expected_pid = static_cast<int32_t>(pid);
    report.expected_tid = static_cast<int32_t>(tid);
    report.expected_ppid = static_cast<int32_t>(ppid);

    HookselfSyscallRule rules[3]{};
    rules[0].struct_size = sizeof(HookselfSyscallRule);
    rules[0].rule_id = kGettidRuleId;
    rules[0].syscall_number = __NR_gettid;
    rules[0].action = HOOKSELF_SYSCALL_OBSERVE;
    rules[0].phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    rules[1].struct_size = sizeof(HookselfSyscallRule);
    rules[1].rule_id = kGetpidRuleId;
    rules[1].syscall_number = __NR_getpid;
    rules[1].action = HOOKSELF_SYSCALL_OBSERVE;
    rules[1].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    rules[2].struct_size = sizeof(HookselfSyscallRule);
    rules[2].rule_id = kGetppidDenyRuleId;
    rules[2].syscall_number = __NR_getppid;
    rules[2].action = HOOKSELF_SYSCALL_DENY;
    rules[2].phase_mask = HOOKSELF_SYSCALL_PHASE_ENTRY;
    rules[2].deny_errno = EACCES;

    static constexpr uint8_t kStaticVirtualContent[] =
            "selective-static\n";
    HookselfVirtualFile virtual_files[2]{};
    virtual_files[0].struct_size = sizeof(HookselfVirtualFile);
    virtual_files[0].file_id = 8501U;
    virtual_files[0].provider = HOOKSELF_VFILE_STATIC;
    virtual_files[0].mode = 0444U;
    virtual_files[0].initial_content_size =
            sizeof(kStaticVirtualContent) - 1U;
    virtual_files[0].initial_content = kStaticVirtualContent;
    __builtin_strcpy(virtual_files[0].guest_path,
                     "/hookself/selective-static");
    virtual_files[1].struct_size = sizeof(HookselfVirtualFile);
    virtual_files[1].file_id = 8502U;
    virtual_files[1].provider = HOOKSELF_VFILE_PROC_STATUS;
    virtual_files[1].mode = 0444U;
    __builtin_strcpy(virtual_files[1].guest_path,
                     "/hookself/selective-status");

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.log_level = HOOKSELF_LOG_OFF;
    config.flags = HOOKSELF_CONFIG_CAPTURE_RESULTS |
                   HOOKSELF_CONFIG_TRACE_DESCENDANTS |
                   HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
                   HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP;
    config.event_capacity = HOOKSELF_MAX_EVENT_CAPACITY;
    config.syscall_rule_count = 3U;
    config.syscall_rules = rules;
    config.virtual_file_count = 2U;
    config.virtual_files = virtual_files;
    const size_t backing_length = virtual_backing_dir == nullptr
            ? 0
            : strnlen(virtual_backing_dir,
                      sizeof(config.virtual_backing_dir));
    if (backing_length == 0 ||
        backing_length == sizeof(config.virtual_backing_dir)) {
        report.validate_result = HOOKSELF_E_INVALID_ARGUMENT;
        NoteFailure(&report, kFailureConfig);
        return report;
    }
    memcpy(config.virtual_backing_dir, virtual_backing_dir,
           backing_length + 1U);
    report.config_flags = config.flags;
    report.failure_mode = config.failure_mode;
    report.rule_count = config.syscall_rule_count;
    report.validate_result = hookself_validate_config(&config);
    if (report.validate_result != HOOKSELF_OK) {
        NoteFailure(&report, kFailureConfig);
        return report;
    }

    HookselfRuntime* runtime = nullptr;
    report.create_result = hookself_create(&config, &runtime);
    if (report.create_result != HOOKSELF_OK || runtime == nullptr) {
        NoteFailure(&report, kFailureCreate);
        return report;
    }

    bool active = false;
    int32_t configured_state = HOOKSELF_STATE_IDLE;
    const int32_t configured_result =
            hookself_get_state(runtime, &configured_state);
    report.configured_state = configured_state;
    if (configured_result != HOOKSELF_OK ||
        configured_state != HOOKSELF_STATE_CONFIGURED) {
        NoteFailure(&report, kFailureConfiguredState);
    } else if (StartAndCheck(runtime, &report)) {
        active = true;
        RunActiveRound(runtime, &report);

        for (uint32_t iteration = 0; iteration < iterations; ++iteration) {
            if (!StopAndCheck(runtime, &report)) {
                break;
            }
            active = false;
            RunPassthroughRound(runtime, &report);
            if (!StartAndCheck(runtime, &report)) {
                break;
            }
            active = true;
            RunActiveRound(runtime, &report);
            ++report.completed_iterations;
        }

        if (report.completed_iterations == iterations && active) {
            if (StopAndCheck(runtime, &report)) {
                active = false;
                report.final_stop_result = report.last_stop_result;
                report.final_state = report.last_stopped_state;
            } else {
                report.final_stop_result = report.last_stop_result;
                report.final_state = report.last_stopped_state;
            }
        }
    }

    if (active) {
        (void)hookself_stop(runtime);
        active = false;
    }

    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    report.stats_result = hookself_get_stats(runtime, &stats);
    if (report.stats_result == HOOKSELF_OK) {
        report.stats_state = stats.state;
        report.emitted_events = stats.emitted_events;
        report.observed_syscalls = stats.observed_syscalls;
        report.dropped_events = stats.dropped_events;
        report.internal_errors = stats.internal_errors;
        report.tracked_tasks = stats.tracked_tasks;
        report.fatal_code = stats.fatal_code;
        report.fatal_errno = stats.fatal_errno;
        report.fatal_tid = stats.fatal_tid;
    } else {
        NoteFailure(&report, kFailureStats);
    }

    const uint32_t expected_active_rounds = iterations + 1U;
    const uint32_t expected_stop_calls = iterations + 1U;
    const uint64_t expected_observations =
            static_cast<uint64_t>(expected_active_rounds) * 3U;
    const bool invariant =
            report.completed_iterations == iterations &&
            report.start_calls == expected_active_rounds &&
            report.start_successes == expected_active_rounds &&
            report.running_state_checks == expected_active_rounds &&
            report.stop_calls == expected_stop_calls &&
            report.stop_successes == expected_stop_calls &&
            report.stopped_state_checks == expected_stop_calls &&
            report.active_rounds == expected_active_rounds &&
            report.active_rounds_passed == expected_active_rounds &&
            report.passthrough_rounds == iterations &&
            report.passthrough_rounds_passed == iterations &&
            report.active_gettid_calls == expected_active_rounds &&
            report.active_getpid_calls == expected_active_rounds &&
            report.active_getppid_calls == expected_active_rounds &&
            report.passthrough_gettid_calls == iterations &&
            report.passthrough_getpid_calls == iterations &&
            report.passthrough_getppid_calls == iterations &&
            report.gettid_entry_events == expected_active_rounds &&
            report.gettid_exit_events == expected_active_rounds &&
            report.gettid_result_matches == expected_active_rounds &&
            report.getpid_entry_events == expected_active_rounds &&
            report.getpid_exit_events == 0U &&
            report.getppid_deny_entry_events == expected_active_rounds &&
            report.getppid_deny_exit_events == expected_active_rounds &&
            report.getppid_deny_result_matches == expected_active_rounds &&
            report.control_rule_events == 0U &&
            report.passthrough_rule_events == 0U &&
            report.unexpected_rule_events == 0U &&
            report.final_stop_result == HOOKSELF_OK &&
            report.final_state == HOOKSELF_STATE_STOPPED &&
            report.stats_result == HOOKSELF_OK &&
            report.stats_state == HOOKSELF_STATE_STOPPED &&
            report.emitted_events >= report.events_read &&
            report.observed_syscalls >= expected_observations &&
            report.dropped_events == 0U && report.internal_errors == 0U &&
            report.tracked_tasks > 0U &&
            report.fatal_code == HOOKSELF_FATAL_NONE &&
            report.fatal_errno == 0 && report.fatal_tid == 0;
    if (!invariant) {
        NoteFailure(&report, kFailureInvariant);
    }
    bool runtime_destroyed = false;
    if (report.first_failure == kFailureNone &&
        RunRuntimeApiBypassDestroyStress(
                runtime, &runtime_destroyed) != HOOKSELF_OK) {
        NoteFailure(&report, kFailureRuntimeApiStress);
    }
    report.verdict = report.first_failure == kFailureNone ? 1 : 0;
    if (!runtime_destroyed) {
        hookself_destroy(runtime);
    }
    return report;
}

std::string FormatSelectiveResidentSelfTestReport(
        const SelectiveResidentSelfTestReport& report) {
    std::string output = "HOOKSELF_SELECTIVE_RESULT {\"verdict\":\"";
    output.append(report.verdict != 0 ? "PASS" : "FAILED");
    output.push_back('"');
    output.reserve(3072U);
    AppendUnsigned(&output, "version", report.version);
    AppendSigned(&output, "first_failure", report.first_failure);
    AppendUnsigned(&output, "requested_iterations",
                   report.requested_iterations);
    AppendUnsigned(&output, "completed_iterations",
                   report.completed_iterations);
    AppendUnsigned(&output, "config_flags", report.config_flags);
    AppendSigned(&output, "failure_mode", report.failure_mode);
    AppendUnsigned(&output, "rule_count", report.rule_count);
    AppendSigned(&output, "validate_result", report.validate_result);
    AppendSigned(&output, "create_result", report.create_result);
    AppendSigned(&output, "configured_state", report.configured_state);
    AppendUnsigned(&output, "start_calls", report.start_calls);
    AppendUnsigned(&output, "start_successes", report.start_successes);
    AppendSigned(&output, "last_start_result", report.last_start_result);
    AppendUnsigned(&output, "running_state_checks",
                   report.running_state_checks);
    AppendSigned(&output, "last_running_state", report.last_running_state);
    AppendUnsigned(&output, "stop_calls", report.stop_calls);
    AppendUnsigned(&output, "stop_successes", report.stop_successes);
    AppendSigned(&output, "last_stop_result", report.last_stop_result);
    AppendUnsigned(&output, "stopped_state_checks",
                   report.stopped_state_checks);
    AppendSigned(&output, "last_stopped_state", report.last_stopped_state);
    AppendUnsigned(&output, "active_rounds", report.active_rounds);
    AppendUnsigned(&output, "active_rounds_passed",
                   report.active_rounds_passed);
    AppendUnsigned(&output, "passthrough_rounds",
                   report.passthrough_rounds);
    AppendUnsigned(&output, "passthrough_rounds_passed",
                   report.passthrough_rounds_passed);
    AppendSigned(&output, "expected_pid", report.expected_pid);
    AppendSigned(&output, "expected_tid", report.expected_tid);
    AppendSigned(&output, "expected_ppid", report.expected_ppid);
    AppendSigned(&output, "last_active_gettid", report.last_active_gettid);
    AppendSigned(&output, "last_active_getpid", report.last_active_getpid);
    AppendSigned(&output, "last_active_getppid", report.last_active_getppid);
    AppendSigned(&output, "last_passthrough_gettid",
                 report.last_passthrough_gettid);
    AppendSigned(&output, "last_passthrough_getpid",
                 report.last_passthrough_getpid);
    AppendSigned(&output, "last_passthrough_getppid",
                 report.last_passthrough_getppid);
    AppendUnsigned(&output, "active_gettid_calls",
                   report.active_gettid_calls);
    AppendUnsigned(&output, "active_getpid_calls",
                   report.active_getpid_calls);
    AppendUnsigned(&output, "active_getppid_calls",
                   report.active_getppid_calls);
    AppendUnsigned(&output, "passthrough_gettid_calls",
                   report.passthrough_gettid_calls);
    AppendUnsigned(&output, "passthrough_getpid_calls",
                   report.passthrough_getpid_calls);
    AppendUnsigned(&output, "passthrough_getppid_calls",
                   report.passthrough_getppid_calls);
    AppendUnsigned(&output, "gettid_entry_events",
                   report.gettid_entry_events);
    AppendUnsigned(&output, "gettid_exit_events", report.gettid_exit_events);
    AppendUnsigned(&output, "gettid_result_matches",
                   report.gettid_result_matches);
    AppendUnsigned(&output, "getpid_entry_events",
                   report.getpid_entry_events);
    AppendUnsigned(&output, "getpid_exit_events", report.getpid_exit_events);
    AppendUnsigned(&output, "getppid_deny_entry_events",
                   report.getppid_deny_entry_events);
    AppendUnsigned(&output, "getppid_deny_exit_events",
                   report.getppid_deny_exit_events);
    AppendUnsigned(&output, "getppid_deny_result_matches",
                   report.getppid_deny_result_matches);
    AppendUnsigned(&output, "control_rule_events",
                   report.control_rule_events);
    AppendUnsigned(&output, "passthrough_rule_events",
                   report.passthrough_rule_events);
    AppendUnsigned(&output, "unexpected_rule_events",
                   report.unexpected_rule_events);
    AppendUnsigned(&output, "events_read", report.events_read);
    AppendSigned(&output, "final_stop_result", report.final_stop_result);
    AppendSigned(&output, "final_state", report.final_state);
    AppendSigned(&output, "stats_result", report.stats_result);
    AppendUnsigned(&output, "stats_state", report.stats_state);
    AppendUnsigned(&output, "emitted_events", report.emitted_events);
    AppendUnsigned(&output, "observed_syscalls", report.observed_syscalls);
    AppendUnsigned(&output, "dropped_events", report.dropped_events);
    AppendUnsigned(&output, "internal_errors", report.internal_errors);
    AppendUnsigned(&output, "tracked_tasks", report.tracked_tasks);
    AppendSigned(&output, "fatal_code", report.fatal_code);
    AppendSigned(&output, "fatal_errno", report.fatal_errno);
    AppendSigned(&output, "fatal_tid", report.fatal_tid);
    output.push_back('}');
    return output;
}

}  // namespace hookself::internal
