#include "internal/logical_ptrace_resident_state_selftest.h"

#include <asm/unistd.h>
#include <errno.h>
#include <linux/ptrace.h>
#include <string.h>
#include <sys/mman.h>

#include "internal/logical_ptrace_resident_state.h"

namespace hookself::internal {
namespace {

bool Check(LogicalPtraceResidentStateSelfTestReport* report, bool condition,
           int32_t failure) noexcept {
    ++report->checks;
    if (!condition) {
        ++report->failures;
        if (report->first_failure == 0) {
            report->first_failure = failure;
        }
    }
    return condition;
}

int ReadMemory(void*, const tracer::LogicalTaskKey*, uintptr_t address,
               void* output, size_t size) noexcept {
    memcpy(output, reinterpret_cast<const void*>(address), size);
    return 0;
}

int WriteMemory(void*, const tracer::LogicalTaskKey*, uintptr_t address,
                const void* input, size_t size) noexcept {
    memcpy(reinterpret_cast<void*>(address), input, size);
    return 0;
}

bool DispatchImmediate(LogicalPtraceResidentStateSelfTestReport* report,
                       LogicalPtraceResidentState* state,
                       LogicalPtraceResidentIoContext* io_context,
                       const tracer::LogicalTaskKey& caller,
                       const uint64_t arguments[6], int64_t expected,
                       int32_t failure) noexcept {
    const LogicalPtraceDispatchIo io =
            MakeLogicalPtraceResidentIo(io_context);
    LogicalPtraceEntryResult entry {};
    if (!Check(report,
               DispatchLogicalPtraceEntry(
                       &state->dispatcher, &state->logical, io, caller,
                       __NR_ptrace, arguments, &entry) == 0,
               failure) ||
        !Check(report,
               (entry.flags & (kLogicalPtraceEntryHandled |
                               kLogicalPtraceEntrySuppress)) ==
                       (kLogicalPtraceEntryHandled |
                        kLogicalPtraceEntrySuppress),
               failure + 1) ||
        !Check(report, entry.visible_result == expected, failure + 2)) {
        return false;
    }
    LogicalPtraceExitResult exit {};
    return Check(report,
                 DispatchLogicalPtraceExit(
                         &state->dispatcher, &state->logical, caller,
                         __NR_ptrace, -ENOSYS, &exit) == 0,
                 failure + 3) &&
           Check(report,
                 (exit.flags & kLogicalPtraceExitWriteResult) != 0U &&
                         exit.visible_result == expected,
                 failure + 4);
}

bool DispatchImmediateSyscall(
        LogicalPtraceResidentStateSelfTestReport* report,
        LogicalPtraceResidentState* state,
        LogicalPtraceResidentIoContext* io_context,
        const tracer::LogicalTaskKey& caller, int32_t syscall_number,
        const uint64_t arguments[6], int64_t expected,
        int32_t failure) noexcept {
    const LogicalPtraceDispatchIo io =
            MakeLogicalPtraceResidentIo(io_context);
    LogicalPtraceEntryResult entry {};
    if (!Check(report,
               DispatchLogicalPtraceEntry(
                       &state->dispatcher, &state->logical, io, caller,
                       syscall_number, arguments, &entry) == 0,
               failure) ||
        !Check(report,
               (entry.flags & (kLogicalPtraceEntryHandled |
                               kLogicalPtraceEntrySuppress)) ==
                       (kLogicalPtraceEntryHandled |
                        kLogicalPtraceEntrySuppress),
               failure + 1) ||
        !Check(report, entry.visible_result == expected, failure + 2)) {
        return false;
    }
    LogicalPtraceExitResult exit {};
    return Check(report,
                 DispatchLogicalPtraceExit(
                         &state->dispatcher, &state->logical, caller,
                         syscall_number, -ENOSYS, &exit) == 0,
                 failure + 3) &&
           Check(report,
                 (exit.flags & kLogicalPtraceExitWriteResult) != 0U &&
                         exit.visible_result == expected,
                 failure + 4);
}

tracer::LogicalPtraceEvent MakeStop(
        tracer::LogicalPtraceEventKind kind,
        int32_t signal_number) noexcept {
    tracer::LogicalPtraceEvent event {};
    event.kind = kind;
    event.signal_number = signal_number;
    event.wait_status = (signal_number << 8) | 0x7f;
    event.guest_syscall_number = -1;
    return event;
}

}  // namespace

LogicalPtraceResidentStateSelfTestReport
RunLogicalPtraceResidentStateSelfTest() noexcept {
    LogicalPtraceResidentStateSelfTestReport report {};
    void* memory = mmap(nullptr, sizeof(LogicalPtraceResidentState),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!Check(&report, memory != MAP_FAILED, 1)) {
        return report;
    }
    auto* state = static_cast<LogicalPtraceResidentState*>(memory);
    InitLogicalPtraceResidentState(state);

    const tracer::LogicalTaskKey parent {1001, 1000, 11, 101};
    const tracer::LogicalTaskKey sibling {1002, 1000, 12, 101};
    const tracer::LogicalTaskKey sibling_exec {1000, 1000, 13, 101};
    const tracer::LogicalTaskKey child {2001, 2000, 21, 201};
    const tracer::LogicalPidIdentity ptracer {};
    if (!Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 0, parent, nullptr, 1000, 1, ptracer) == 0,
               10) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 1, sibling, nullptr, 1000, 1, ptracer) == 0,
               11) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 2, child, &parent, 2000, 1, ptracer) == 0,
               12) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 13)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    LogicalPtraceResidentIoContext io_context {};
    io_context.state = state;
    io_context.read_memory = ReadMemory;
    io_context.write_memory = WriteMemory;
    uint64_t arguments[6] {};
    arguments[0] = PTRACE_TRACEME;
    if (!DispatchImmediate(&report, state, &io_context, child, arguments, 0,
                           20) ||
        !Check(&report,
               tracer::FindLogicalPtraceRelation(&state->logical, child) !=
                       nullptr,
               25) ||
        !Check(&report,
               tracer::EraseLogicalPtraceRelation(&state->logical, child,
                                                  false) == 0,
               26) ||
        !Check(&report,
               RekeyLogicalPtraceResidentTask(
                       state, sibling, sibling_exec) == 0,
               27) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 28)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    if (!Check(&report,
               MarkLogicalPtraceResidentTaskExited(state, parent) == 0,
               30) ||
        !DispatchImmediate(&report, state, &io_context, child, arguments, 0,
                           31) ||
        !Check(&report,
               tracer::HasLogicalFakeTraceme(&state->logical, child), 36) ||
        !Check(&report,
               tracer::ClearLogicalFakeTraceme(&state->logical, child) == 0,
               37) ||
        !Check(&report,
               MarkLogicalPtraceResidentTaskExited(state, child) == 0,
               38) ||
        !Check(&report,
               RetireLogicalPtraceResidentTask(state, child) == 0, 39) ||
        !Check(&report,
               RetireLogicalPtraceResidentTask(state, parent) == 0, 40) ||
        !Check(&report,
               MarkLogicalPtraceResidentTaskExited(
                       state, sibling_exec) == 0,
               41) ||
        !Check(&report,
               RetireLogicalPtraceResidentTask(state, sibling_exec) == 0,
               42) ||
        !Check(&report,
               state->task_count == 0U &&
                       state->logical.process_count == 0U,
               43) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 44)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    InitLogicalPtraceResidentState(state);
    const tracer::LogicalTaskKey leader {3000, 3000, 31, 301};
    const tracer::LogicalTaskKey former {3001, 3000, 32, 301};
    const tracer::LogicalTaskKey thread_child {3002, 3000, 33, 301};
    const tracer::LogicalTaskKey outer_tracer {4000, 4000, 41, 401};
    const tracer::LogicalTaskKey former_tracee {5000, 5000, 51, 501};
    const tracer::LogicalTaskKey leader_tracee {6000, 6000, 61, 601};
    if (!Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 0, leader, nullptr, 3000, 1, ptracer) == 0,
               1000) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 1, former, &leader, 3000, 1, ptracer) == 0,
               1001) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 2, thread_child, &former, 3000, 1,
                       ptracer) == 0,
               1002) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 3, outer_tracer, nullptr, 4000, 1,
                       ptracer) == 0,
               1003) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 4, former_tracee, &former, 5000, 1,
                       ptracer) == 0,
               1004) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 5, leader_tracee, &leader, 6000, 1,
                       ptracer) == 0,
               1005) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 1006)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    uint32_t former_relation_slot = tracer::kInvalidLogicalPtraceSlot;
    uint32_t leader_relation_slot = tracer::kInvalidLogicalPtraceSlot;
    uint32_t former_owned_slot = tracer::kInvalidLogicalPtraceSlot;
    uint32_t leader_owned_slot = tracer::kInvalidLogicalPtraceSlot;
    if (!Check(&report,
               tracer::CreateLogicalPtraceRelation(
                       &state->logical, former, outer_tracer,
                       tracer::LogicalPtraceAttachKind::kSeize,
                       tracer::LogicalPtraceWaitClass::kNormal, 0,
                       &former_relation_slot) == 0,
               1010) ||
        !Check(&report,
               tracer::CreateLogicalPtraceRelation(
                       &state->logical, leader, outer_tracer,
                       tracer::LogicalPtraceAttachKind::kSeize,
                       tracer::LogicalPtraceWaitClass::kNormal, 0,
                       &leader_relation_slot) == 0,
               1011) ||
        !Check(&report,
               tracer::CreateLogicalPtraceRelation(
                       &state->logical, former_tracee, former,
                       tracer::LogicalPtraceAttachKind::kSeize,
                       tracer::LogicalPtraceWaitClass::kNormal, 0,
                       &former_owned_slot) == 0,
               1012) ||
        !Check(&report,
               tracer::CreateLogicalPtraceRelation(
                       &state->logical, leader_tracee, leader,
                       tracer::LogicalPtraceAttachKind::kSeize,
                       tracer::LogicalPtraceWaitClass::kNormal, 0,
                       &leader_owned_slot) == 0,
               1013)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }
    const uint64_t former_relation_generation =
            tracer::LogicalPtraceRelationAt(
                    &state->logical, former_relation_slot)->generation;

    tracer::LogicalPtraceEvent stop = MakeStop(
            tracer::LogicalPtraceEventKind::kSignalDelivery, SIGUSR1);
    int32_t outer_wait_status = 0;
    uint64_t outer_wait_arguments[6] {};
    outer_wait_arguments[0] = static_cast<uint64_t>(former.tid);
    outer_wait_arguments[1] =
            reinterpret_cast<uintptr_t>(&outer_wait_status);
    if (!Check(&report,
               PublishLogicalPtraceStop(
                       &state->dispatcher, &state->logical, former, stop,
                       nullptr) == 0,
               1020) ||
        !DispatchImmediateSyscall(
                &report, state, &io_context, outer_tracer, __NR_wait4,
                outer_wait_arguments, former.tid, 1021) ||
        !Check(&report, outer_wait_status == stop.wait_status, 1026)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }
    stop = MakeStop(
            tracer::LogicalPtraceEventKind::kSignalDelivery, SIGUSR2);
    if (!Check(&report,
               PublishLogicalPtraceStop(
                       &state->dispatcher, &state->logical, leader, stop,
                       nullptr) == 0,
               1027) ||
        !Check(&report,
               tracer::ClaimLogicalFakeTraceme(
                       &state->logical, former) == 0 &&
                       tracer::ClaimLogicalFakeTraceme(
                               &state->logical, leader) == 0,
               1028)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    int32_t held_wait_status = 0;
    uint64_t held_arguments[6] {};
    held_arguments[0] = static_cast<uint64_t>(former_tracee.tid);
    held_arguments[1] = reinterpret_cast<uintptr_t>(&held_wait_status);
    const LogicalPtraceDispatchIo merge_io =
            MakeLogicalPtraceResidentIo(&io_context);
    LogicalPtraceEntryResult held_entry {};
    LogicalPtraceExitResult held_exit {};
    if (!Check(&report,
               DispatchLogicalPtraceEntry(
                       &state->dispatcher, &state->logical, merge_io, former,
                       __NR_wait4, held_arguments, &held_entry) == 0 &&
                       (held_entry.flags &
                        kLogicalPtraceEntryMayHold) != 0U,
               1030) ||
        !Check(&report,
               DispatchLogicalPtraceExit(
                       &state->dispatcher, &state->logical, former,
                       __NR_wait4, -ENOSYS, &held_exit) == 0 &&
                       (held_exit.flags & kLogicalPtraceExitHold) != 0U,
               1031)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    uint64_t leader_arguments[6] {};
    leader_arguments[0] = PTRACE_TRACEME;
    LogicalPtraceEntryResult leader_entry {};
    if (!Check(&report,
               DispatchLogicalPtraceEntry(
                       &state->dispatcher, &state->logical, merge_io, leader,
                       __NR_ptrace, leader_arguments, &leader_entry) == 0 &&
                       (leader_entry.flags &
                        kLogicalPtraceEntryHandled) != 0U &&
                       leader_entry.visible_result == -EPERM,
               1032) ||
        !Check(&report,
               state->dispatcher.operation_count == 2U &&
                       state->logical.wait_count == 1U &&
                       state->logical.relation_count == 4U &&
                       state->logical.fake_traceme_count == 2U &&
                       ValidateLogicalPtraceResidentState(state),
               1033)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    void* unchanged_memory = mmap(
            nullptr, sizeof(LogicalPtraceResidentState),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!Check(&report, unchanged_memory != MAP_FAILED, 1039)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }
    memcpy(unchanged_memory, state, sizeof(*state));
    const tracer::LogicalTaskKey missing_leader {3000, 3000, 99, 301};
    const bool failed_merge_checks =
            Check(&report,
                  MergeExecLogicalPtraceResidentTask(
                          state, former, outer_tracer) == EXDEV &&
                          memcmp(state, unchanged_memory,
                                 sizeof(*state)) == 0,
                  1040) &&
            Check(&report,
                  MergeExecLogicalPtraceResidentTask(
                          state, leader, former) == EINVAL &&
                          memcmp(state, unchanged_memory,
                                 sizeof(*state)) == 0,
                  1041) &&
            Check(&report,
                  MergeExecLogicalPtraceResidentTask(
                          state, former, missing_leader) == ESRCH &&
                          memcmp(state, unchanged_memory,
                                 sizeof(*state)) == 0,
                  1042) &&
            Check(&report, ValidateLogicalPtraceResidentState(state), 1043);
    (void)munmap(unchanged_memory, sizeof(LogicalPtraceResidentState));
    if (!failed_merge_checks) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    if (!Check(&report,
               MergeExecLogicalPtraceResidentTask(
                       state, former, leader) == 0,
               1050) ||
        !Check(&report,
               state->task_count == 5U &&
                       state->logical.process_count == 4U &&
                       state->logical.relation_count == 3U &&
                       state->logical.fake_traceme_count == 1U &&
                       state->logical.wait_count == 1U &&
                       state->dispatcher.operation_count == 1U,
               1051) ||
        !Check(&report,
               FindLogicalPtraceResidentTask(state, former) == nullptr &&
                       FindLogicalPtraceResidentTask(state, leader) ==
                               &state->tasks[0] &&
                       state->tasks[1].occupied == 0U,
               1052) ||
        !Check(&report,
               (state->tasks[0].flags &
                kLogicalPtraceResidentTaskParentValid) == 0U &&
                       (state->tasks[2].flags &
                        kLogicalPtraceResidentTaskParentValid) != 0U &&
                       tracer::LogicalTaskKeysEqual(
                               state->tasks[2].parent, leader),
               1053) ||
        !Check(&report,
               tracer::HasLogicalFakeTraceme(
                       &state->logical, leader) &&
                       !tracer::HasLogicalFakeTraceme(
                               &state->logical, former),
               1054)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    const tracer::LogicalPtraceRelation* merged_relation =
            tracer::FindLogicalPtraceRelation(&state->logical, leader);
    const LogicalPtraceDispatchOperation* merged_operation =
            LogicalPtraceOperationAt(
                    &state->dispatcher, held_entry.operation_slot);
    if (!Check(&report,
               merged_relation != nullptr &&
                       merged_relation->slot == former_relation_slot &&
                       merged_relation->generation ==
                               former_relation_generation &&
                       tracer::LogicalTaskKeysEqual(
                               merged_relation->tracer, outer_tracer),
               1060) ||
        !Check(&report,
               tracer::LogicalPtraceRelationAt(
                       &state->logical, leader_relation_slot) == nullptr &&
                       state->dispatcher
                                       .stops[leader_relation_slot]
                                       .relation_generation == 0U,
               1061) ||
        !Check(&report,
               tracer::LogicalTaskKeysEqual(
                       tracer::LogicalPtraceRelationAt(
                               &state->logical, former_owned_slot)->tracer,
                       leader) &&
                       tracer::LogicalTaskKeysEqual(
                               tracer::LogicalPtraceRelationAt(
                                       &state->logical,
                                       leader_owned_slot)->tracer,
                               leader),
               1062) ||
        !Check(&report,
               merged_operation != nullptr &&
                       tracer::LogicalTaskKeysEqual(
                               merged_operation->caller, leader) &&
                       merged_operation->state ==
                               LogicalPtraceOperationState::kHeldWait &&
                       LogicalPtraceOperationAt(
                               &state->dispatcher,
                               leader_entry.operation_slot) == nullptr,
               1063) ||
        !Check(&report,
               tracer::FindLogicalWait(&state->logical, former) == nullptr &&
                       tracer::FindLogicalWait(
                               &state->logical, leader) != nullptr,
               1064) ||
        !Check(&report,
               (state->dispatcher.stops[former_relation_slot].flags &
                kLogicalPtraceStopCurrentValid) != 0U &&
                       tracer::LogicalTaskKeysEqual(
                               state->dispatcher
                                       .stops[former_relation_slot]
                                       .tracee,
                               leader) &&
                       ValidateLogicalPtraceResidentState(state),
               1065)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    stop = MakeStop(
            tracer::LogicalPtraceEventKind::kSignalDelivery, SIGTERM);
    held_exit = {};
    if (!Check(&report,
               PublishLogicalPtraceStop(
                       &state->dispatcher, &state->logical, former_tracee,
                       stop, nullptr) == 0,
               1070) ||
        !Check(&report,
               TryWakeLogicalPtraceWait(
                       &state->dispatcher, &state->logical, merge_io,
                       leader) == 0,
               1071) ||
        !Check(&report,
               DispatchLogicalPtraceExit(
                       &state->dispatcher, &state->logical, leader,
                       __NR_wait4, -ENOSYS, &held_exit) == 0 &&
                       (held_exit.flags &
                        kLogicalPtraceExitWriteResult) != 0U &&
                       held_exit.visible_result == former_tracee.tid &&
                       held_wait_status == stop.wait_status,
               1072) ||
        !Check(&report,
               state->dispatcher.operation_count == 0U &&
                       state->logical.wait_count == 0U &&
                       ValidateLogicalPtraceResidentState(state),
               1073)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    InitLogicalPtraceResidentState(state);
    const tracer::LogicalTaskKey reused_old {8100, 8100, 81, 801};
    const tracer::LogicalTaskKey reused_current {8100, 8100, 82, 802};
    const tracer::LogicalTaskKey reused_future {8100, 8100, 83, 803};
    if (!Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 0, reused_old, nullptr, 8100, 1,
                       ptracer) == 0,
               1100) ||
        !Check(&report,
               MarkLogicalPtraceResidentTaskExited(
                       state, reused_old) == 0 &&
                       FindLogicalPtraceResidentTid(state, 8100) == nullptr,
               1101) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 1, reused_current, nullptr, 8100, 1,
                       ptracer) == 0,
               1102) ||
        !Check(&report,
               FindLogicalPtraceResidentTid(state, 8100) ==
                               &state->tasks[1] &&
                       FindLogicalPtraceResidentTask(state, reused_old) ==
                               &state->tasks[0],
               1103) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 2, reused_future, nullptr, 8100, 1,
                       ptracer) == EEXIST &&
                       RegisterLogicalPtraceResidentTask(
                               state, 3, reused_old, nullptr, 8100, 1,
                               ptracer) == EEXIST,
               1104) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 1105)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    state->tasks[0].flags &= ~kLogicalPtraceResidentTaskExited;
    state->tasks[0].flags |= kLogicalPtraceResidentTaskActive;
    const bool duplicate_active_rejected =
            Check(&report, !ValidateLogicalPtraceResidentState(state), 1110);
    state->tasks[0].flags &= ~kLogicalPtraceResidentTaskActive;
    state->tasks[0].flags |= kLogicalPtraceResidentTaskExited;
    const tracer::LogicalTaskKey saved_current_key = state->tasks[1].key;
    state->tasks[1].key = reused_old;
    const bool exact_duplicate_rejected =
            Check(&report, !ValidateLogicalPtraceResidentState(state), 1111);
    state->tasks[1].key = saved_current_key;
    if (!duplicate_active_rejected || !exact_duplicate_rejected ||
        !Check(&report,
               MarkLogicalPtraceResidentTaskExited(
                       state, reused_current) == 0 &&
                       FindLogicalPtraceResidentTid(state, 8100) == nullptr,
               1112) ||
        !Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 2, reused_future, nullptr, 8100, 1,
                       ptracer) == 0 &&
                       FindLogicalPtraceResidentTid(state, 8100) ==
                               &state->tasks[2],
               1113) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 1114)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    InitLogicalPtraceResidentState(state);
    const tracer::LogicalTaskKey inherited_tracer {9000, 9000, 91, 901};
    const tracer::LogicalTaskKey inherited_parent {9100, 9100, 92, 902};
    const tracer::LogicalTaskKey inherited_child {9200, 9200, 93, 903};
    constexpr uint64_t inherited_options =
            tracer::kLogicalPtraceOptionTraceSysgood |
            tracer::kLogicalPtraceOptionTraceFork;
    uint32_t inherited_parent_slot = tracer::kInvalidLogicalPtraceSlot;
    if (!Check(&report,
               RegisterLogicalPtraceResidentTask(
                       state, 0, inherited_tracer, nullptr, 9000, 1,
                       ptracer) == 0 &&
                       RegisterLogicalPtraceResidentTask(
                               state, 1, inherited_parent, nullptr, 9100, 1,
                               ptracer) == 0 &&
                       RegisterLogicalPtraceResidentTask(
                               state, 2, inherited_child, &inherited_parent,
                               9200, 1, ptracer) == 0,
               1120) ||
        !Check(&report,
               tracer::CreateLogicalPtraceRelation(
                       &state->logical, inherited_parent, inherited_tracer,
                       tracer::LogicalPtraceAttachKind::kSeize,
                       tracer::LogicalPtraceWaitClass::kNormal,
                       inherited_options, &inherited_parent_slot) == 0,
               1121) ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 1122)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    void* transaction_snapshot = mmap(
            nullptr, sizeof(tracer::LogicalPtraceTable),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!Check(&report, transaction_snapshot != MAP_FAILED, 1123)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }
    auto* logical_snapshot =
            static_cast<tracer::LogicalPtraceTable*>(transaction_snapshot);
    memcpy(logical_snapshot, &state->logical, sizeof(*logical_snapshot));
    tracer::LogicalPtraceEvent inherited_stop = MakeStop(
            tracer::LogicalPtraceEventKind::kSignalDelivery, SIGSTOP);
    tracer::LogicalPtraceEvent invalid_stop = inherited_stop;
    invalid_stop.sequence = 1U;
    uint32_t inherited_child_slot = 7U;
    uint64_t inherited_sequence = 7U;
    const bool invalid_inherit_atomic = Check(
            &report,
            tracer::CreateInheritedLogicalPtraceRelation(
                    &state->logical, inherited_parent, inherited_child,
                    tracer::LogicalPtraceWaitClass::kClone, invalid_stop,
                    &inherited_child_slot, &inherited_sequence) == EINVAL &&
                    inherited_child_slot ==
                            tracer::kInvalidLogicalPtraceSlot &&
                    inherited_sequence == 0U &&
                    memcmp(&state->logical, logical_snapshot,
                           sizeof(*logical_snapshot)) == 0,
            1124);
    if (!invalid_inherit_atomic ||
        !Check(&report,
               tracer::CreateInheritedLogicalPtraceRelation(
                       &state->logical, inherited_parent, inherited_child,
                       tracer::LogicalPtraceWaitClass::kClone,
                       inherited_stop, &inherited_child_slot,
                       &inherited_sequence) == 0,
               1125)) {
        munmap(transaction_snapshot, sizeof(*logical_snapshot));
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    const tracer::LogicalPtraceRelation* inherited_relation =
            tracer::FindLogicalPtraceRelation(
                    &state->logical, inherited_child);
    tracer::LogicalPtraceEvent inherited_queued {};
    if (!Check(&report,
               inherited_relation != nullptr &&
                       inherited_relation->slot == inherited_child_slot &&
                       tracer::LogicalTaskKeysEqual(
                               inherited_relation->tracer,
                               inherited_tracer) &&
                       inherited_relation->attach_kind ==
                               tracer::LogicalPtraceAttachKind::kSeize &&
                       inherited_relation->wait_class ==
                               tracer::LogicalPtraceWaitClass::kClone &&
                       inherited_relation->options == inherited_options &&
                       inherited_relation->state ==
                               tracer::LogicalPtraceRelationState::kStopped &&
                       inherited_relation->event_count == 1U,
               1126) ||
        !Check(&report,
               tracer::PeekLogicalPtraceEvent(
                       &state->logical, inherited_child,
                       &inherited_queued) == 0 &&
                       inherited_queued.sequence == inherited_sequence &&
                       inherited_queued.kind == inherited_stop.kind &&
                       inherited_queued.signal_number == SIGSTOP &&
                       inherited_queued.wait_status ==
                               inherited_stop.wait_status,
               1127) ||
        !Check(&report,
               tracer::LogicalPtraceRelationAt(
                       &state->logical, inherited_parent_slot) != nullptr &&
                       ValidateLogicalPtraceResidentState(state),
               1128)) {
        munmap(transaction_snapshot, sizeof(*logical_snapshot));
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    memcpy(logical_snapshot, &state->logical, sizeof(*logical_snapshot));
    inherited_child_slot = 9U;
    inherited_sequence = 9U;
    const bool duplicate_inherit_atomic = Check(
            &report,
            tracer::CreateInheritedLogicalPtraceRelation(
                    &state->logical, inherited_parent, inherited_child,
                    tracer::LogicalPtraceWaitClass::kNormal, inherited_stop,
                    &inherited_child_slot, &inherited_sequence) == EPERM &&
                    inherited_child_slot ==
                            tracer::kInvalidLogicalPtraceSlot &&
                    inherited_sequence == 0U &&
                    memcmp(&state->logical, logical_snapshot,
                           sizeof(*logical_snapshot)) == 0,
            1129);
    munmap(transaction_snapshot, sizeof(*logical_snapshot));
    if (!duplicate_inherit_atomic ||
        !Check(&report, ValidateLogicalPtraceResidentState(state), 1130)) {
        munmap(memory, sizeof(LogicalPtraceResidentState));
        return report;
    }

    munmap(memory, sizeof(LogicalPtraceResidentState));
    return report;
}

}  // namespace hookself::internal
