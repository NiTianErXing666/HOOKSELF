#include "internal/logical_ptrace_dispatcher_selftest.h"

#include <asm/unistd.h>
#include <elf.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "internal/logical_ptrace_dispatcher.h"

namespace hookself::internal {
namespace {

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

constexpr size_t kFixtureTaskCapacity = 8U;

struct TestIovec64 {
    uint64_t base;
    uint64_t length;
};

struct Fixture {
    tracer::LogicalPtraceTable* logical;
    LogicalPtraceDispatcher* dispatcher;
    tracer::LogicalTaskKey tasks[kFixtureTaskCapacity];
    tracer::LogicalTaskKey parents[kFixtureTaskCapacity];
    size_t task_count;
    uint32_t attach_checks;
};

bool Check(LogicalPtraceDispatcherSelfTestReport* report, bool condition,
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

int ResolveTask(void* opaque, const tracer::LogicalTaskKey*, int32_t tid,
                tracer::LogicalTaskKey* output) noexcept {
    const auto* fixture = static_cast<const Fixture*>(opaque);
    for (size_t index = 0; index < fixture->task_count; ++index) {
        if (fixture->tasks[index].tid == tid) {
            *output = fixture->tasks[index];
            return 0;
        }
    }
    return ESRCH;
}

int ResolveParent(void* opaque, const tracer::LogicalTaskKey* caller,
                  tracer::LogicalTaskKey* output) noexcept {
    const auto* fixture = static_cast<const Fixture*>(opaque);
    for (size_t index = 0; index < fixture->task_count; ++index) {
        if (tracer::LogicalTaskKeysEqual(fixture->tasks[index], *caller) &&
            fixture->parents[index].tid != 0) {
            *output = fixture->parents[index];
            return 0;
        }
    }
    return ESRCH;
}

int MayAttach(void* opaque, const tracer::LogicalTaskKey*,
              const tracer::LogicalTaskKey*,
              tracer::LogicalPtraceAttachKind) noexcept {
    auto* fixture = static_cast<Fixture*>(opaque);
    ++fixture->attach_checks;
    return 0;
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

int QueryUid(void*, const tracer::LogicalTaskKey*, uint32_t* uid) noexcept {
    *uid = 1234U;
    return 0;
}

int FillRusage(void*, const tracer::LogicalTaskKey*,
               const tracer::LogicalPtraceEvent*, void* output,
               size_t size) noexcept {
    if (size != sizeof(struct rusage)) {
        return EINVAL;
    }
    auto* usage = static_cast<struct rusage*>(output);
    memset(usage, 0, sizeof(*usage));
    usage->ru_utime.tv_sec = 7;
    return 0;
}

LogicalPtraceDispatchIo BuildIo(Fixture* fixture) noexcept {
    LogicalPtraceDispatchIo io {};
    io.opaque = fixture;
    io.resolve_task = ResolveTask;
    io.resolve_parent = ResolveParent;
    io.may_attach = MayAttach;
    io.read_memory = ReadMemory;
    io.write_memory = WriteMemory;
    io.query_uid = QueryUid;
    io.fill_rusage = FillRusage;
    return io;
}

bool InsertProcess(LogicalPtraceDispatcherSelfTestReport* report,
                   tracer::LogicalPtraceTable* logical,
                   const tracer::LogicalTaskKey& task,
                   const tracer::LogicalTaskKey* parent,
                   int32_t failure) noexcept {
    const tracer::LogicalProcessKey key =
            tracer::LogicalProcessKeyForTask(task);
    tracer::LogicalProcessKey parent_key {};
    const tracer::LogicalProcessKey* parent_pointer = nullptr;
    if (parent != nullptr) {
        parent_key = tracer::LogicalProcessKeyForTask(*parent);
        parent_pointer = &parent_key;
    }
    const tracer::LogicalPidIdentity ptracer {};
    return Check(report,
                 tracer::InsertLogicalProcess(logical, key, parent_pointer,
                                              task.tgid, 1, ptracer,
                                              nullptr) == 0,
                 failure);
}

bool DispatchImmediate(LogicalPtraceDispatcherSelfTestReport* report,
                       Fixture* fixture,
                       const LogicalPtraceDispatchIo& io,
                       const tracer::LogicalTaskKey& caller,
                       int32_t syscall_number, const uint64_t arguments[6],
                       int64_t expected_result, int32_t failure,
                       LogicalPtraceEntryResult* captured) noexcept {
    LogicalPtraceEntryResult entry {};
    if (!Check(report,
               DispatchLogicalPtraceEntry(
                       fixture->dispatcher, fixture->logical, io, caller,
                       syscall_number, arguments, &entry) == 0,
               failure) ||
        !Check(report,
               (entry.flags & (kLogicalPtraceEntryHandled |
                               kLogicalPtraceEntrySuppress)) ==
                       (kLogicalPtraceEntryHandled |
                        kLogicalPtraceEntrySuppress),
               failure + 1) ||
        !Check(report, entry.visible_result == expected_result,
               failure + 2)) {
        return false;
    }
    if (captured != nullptr) {
        *captured = entry;
    }
    LogicalPtraceExitResult exit {};
    return Check(report,
                 DispatchLogicalPtraceExit(
                         fixture->dispatcher, fixture->logical, caller,
                         syscall_number, 0, &exit) == 0,
                 failure + 3) &&
           Check(report,
                 (exit.flags & (kLogicalPtraceExitHandled |
                                kLogicalPtraceExitWriteResult)) ==
                         (kLogicalPtraceExitHandled |
                          kLogicalPtraceExitWriteResult),
                 failure + 4) &&
           Check(report, exit.visible_result == expected_result,
                 failure + 5);
}

tracer::LogicalPtraceEvent MakeStop(
        tracer::LogicalPtraceEventKind kind, int32_t signal_number,
        uint32_t flags) noexcept {
    tracer::LogicalPtraceEvent event {};
    event.kind = kind;
    event.flags = flags;
    event.signal_number = signal_number;
    event.wait_status = (signal_number << 8) | 0x7f;
    event.guest_syscall_number = -1;
    return event;
}

}  // namespace

LogicalPtraceDispatcherSelfTestReport
RunLogicalPtraceDispatcherSelfTest() noexcept {
    LogicalPtraceDispatcherSelfTestReport report {};
    report.version = kLogicalPtraceDispatcherSelfTestVersion;

    void* logical_memory = mmap(nullptr, sizeof(tracer::LogicalPtraceTable),
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void* dispatcher_memory = mmap(nullptr, sizeof(LogicalPtraceDispatcher),
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!Check(&report, logical_memory != MAP_FAILED, 1) ||
        !Check(&report, dispatcher_memory != MAP_FAILED, 2)) {
        if (logical_memory != MAP_FAILED) {
            munmap(logical_memory, sizeof(tracer::LogicalPtraceTable));
        }
        if (dispatcher_memory != MAP_FAILED) {
            munmap(dispatcher_memory, sizeof(LogicalPtraceDispatcher));
        }
        return report;
    }

    auto* logical = static_cast<tracer::LogicalPtraceTable*>(logical_memory);
    auto* dispatcher =
            static_cast<LogicalPtraceDispatcher*>(dispatcher_memory);
    tracer::InitLogicalPtraceTable(logical);
    InitLogicalPtraceDispatcher(dispatcher);

    const bool completed = [&]() noexcept -> bool {
        const tracer::LogicalTaskKey tracer_main {1001, 1000, 11, 101};
        const tracer::LogicalTaskKey tracer_sibling {1002, 1000, 12, 101};
        const tracer::LogicalTaskKey tracee {2001, 2000, 21, 201};
        const tracer::LogicalTaskKey child {3001, 3000, 31, 301};
        const tracer::LogicalTaskKey seized {4001, 4000, 41, 401};
        const tracer::LogicalTaskKey seized_exec {4000, 4000, 42, 401};
        const tracer::LogicalTaskKey exit_race {5001, 5000, 51, 501};

        Fixture fixture {};
        fixture.logical = logical;
        fixture.dispatcher = dispatcher;
        fixture.tasks[0] = tracer_main;
        fixture.tasks[1] = tracer_sibling;
        fixture.tasks[2] = tracee;
        fixture.tasks[3] = child;
        fixture.tasks[4] = seized;
        fixture.tasks[5] = exit_race;
        fixture.parents[2] = tracer_main;
        fixture.parents[3] = tracer_main;
        fixture.parents[4] = tracer_main;
        fixture.parents[5] = tracer_main;
        fixture.task_count = 6;
        const LogicalPtraceDispatchIo io = BuildIo(&fixture);

        if (!InsertProcess(&report, logical, tracer_main, nullptr, 10) ||
            !InsertProcess(&report, logical, tracee, &tracer_main, 11) ||
            !InsertProcess(&report, logical, child, &tracer_main, 12) ||
            !InsertProcess(&report, logical, seized, &tracer_main, 13) ||
            !InsertProcess(&report, logical, exit_race, &tracer_main, 14) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical), 15)) {
            return false;
        }

        uint64_t arguments[6] {};
        arguments[0] = PTRACE_TRACEME;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 90, nullptr) ||
            !Check(&report,
                   tracer::HasLogicalFakeTraceme(logical, tracer_main),
                   96) ||
            !Check(&report,
                   tracer::ClearLogicalFakeTraceme(logical, tracer_main) ==
                           0,
                   97)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_TRACEME;
        if (!DispatchImmediate(&report, &fixture, io, child, __NR_ptrace,
                               arguments, 0, 100, nullptr)) {
            return false;
        }
        const tracer::LogicalPtraceRelation* relation =
                tracer::FindLogicalPtraceRelation(logical, child);
        if (!Check(&report, relation != nullptr, 106) ||
            !Check(&report,
                   relation->attach_kind ==
                           tracer::LogicalPtraceAttachKind::kTraceme,
                   107) ||
            !Check(&report,
                   tracer::LogicalTaskKeysEqual(relation->tracer,
                                                tracer_main),
                   108) ||
            !Check(&report,
                   tracer::EraseLogicalPtraceRelation(logical, child,
                                                      false) == 0,
                   109)) {
            return false;
        }
        ++report.scenarios;

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_ATTACH;
        arguments[1] = tracee.tid;
        LogicalPtraceEntryResult attach_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 200,
                               &attach_entry) ||
            !Check(&report,
                   (attach_entry.flags &
                    kLogicalPtraceEntryTargetAction) != 0U &&
                           attach_entry.target.action ==
                                   LogicalPtraceTargetAction::kInterrupt,
                   206)) {
            return false;
        }

        tracer::LogicalPtraceEvent event = MakeStop(
                tracer::LogicalPtraceEventKind::kAttachStop, SIGSTOP,
                tracer::kLogicalPtraceEventFlagRegistersValid |
                        tracer::kLogicalPtraceEventFlagSiginfoValid);
        event.guest_registers.regs[0] = 0x1111222233334444ULL;
        event.signal_info.si_signo = SIGSTOP;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, tracee,
                                            event, nullptr) == 0,
                   207)) {
            return false;
        }

        int32_t wait_status = 0;
        struct rusage usage {};
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = tracee.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        arguments[3] = reinterpret_cast<uintptr_t>(&usage);
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_wait4, arguments, tracee.tid, 210,
                               nullptr) ||
            !Check(&report, wait_status == event.wait_status, 216) ||
            !Check(&report, usage.ru_utime.tv_sec == 7, 217)) {
            return false;
        }

        hookself::arch::Arm64Regs read_registers {};
        TestIovec64 vector {
                reinterpret_cast<uintptr_t>(&read_registers),
                sizeof(read_registers)};
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_GETREGSET;
        arguments[1] = tracee.tid;
        arguments[2] = NT_PRSTATUS;
        arguments[3] = reinterpret_cast<uintptr_t>(&vector);
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 220, nullptr) ||
            !Check(&report,
                   read_registers.regs[0] ==
                           event.guest_registers.regs[0],
                   226)) {
            return false;
        }

        hookself::arch::Arm64Regs replacement = read_registers;
        replacement.regs[0] = 0xaabbccddeeff0011ULL;
        vector.base = reinterpret_cast<uintptr_t>(&replacement);
        vector.length = sizeof(replacement);
        arguments[0] = PTRACE_SETREGSET;
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 230, nullptr)) {
            return false;
        }

        uint64_t target_word = 0x0123456789abcdefULL;
        uint64_t peeked_word = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_PEEKDATA;
        arguments[1] = tracee.tid;
        arguments[2] = reinterpret_cast<uintptr_t>(&target_word);
        arguments[3] = reinterpret_cast<uintptr_t>(&peeked_word);
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 240, nullptr) ||
            !Check(&report, peeked_word == target_word, 246)) {
            return false;
        }
        arguments[0] = PTRACE_POKEDATA;
        arguments[3] = 0x8877665544332211ULL;
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 250, nullptr) ||
            !Check(&report,
                   target_word == 0x8877665544332211ULL, 256)) {
            return false;
        }

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_SYSCALL;
        arguments[1] = tracee.tid;
        LogicalPtraceEntryResult syscall_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 260,
                               &syscall_entry) ||
            !Check(&report,
                   syscall_entry.target.action ==
                           LogicalPtraceTargetAction::kResumeSyscall &&
                           (syscall_entry.target.flags &
                            kLogicalPtraceTargetRegistersValid) != 0U &&
                           syscall_entry.target.registers.regs[0] ==
                                   replacement.regs[0],
                   266)) {
            return false;
        }

        event = MakeStop(tracer::LogicalPtraceEventKind::kSyscallEntry,
                         SIGTRAP,
                         tracer::kLogicalPtraceEventFlagSyscallNumberValid);
        event.guest_syscall_number = __NR_openat;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, tracee,
                                            event, nullptr) == 0,
                   270)) {
            return false;
        }
        siginfo_t wait_info {};
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = 1;  // P_PID
        arguments[1] = tracee.tid;
        arguments[2] = reinterpret_cast<uintptr_t>(&wait_info);
        arguments[3] = tracer::kLogicalWaitStopped |
                       tracer::kLogicalWaitNowait;
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_waitid, arguments, 0, 280, nullptr) ||
            !Check(&report,
                   wait_info.si_pid == tracee.tid &&
                           wait_info.si_uid == 1234U,
                   286)) {
            return false;
        }

        int32_t replacement_syscall = __NR_readlinkat;
        vector.base = reinterpret_cast<uintptr_t>(&replacement_syscall);
        vector.length = sizeof(replacement_syscall);
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_SETREGSET;
        arguments[1] = tracee.tid;
        arguments[2] = NT_ARM_SYSTEM_CALL;
        arguments[3] = reinterpret_cast<uintptr_t>(&vector);
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 290, nullptr)) {
            return false;
        }
        relation = tracer::FindLogicalPtraceRelation(logical, tracee);
        if (!Check(&report,
                   relation != nullptr && relation->event_count == 1U &&
                           relation->events[relation->event_head]
                                           .guest_syscall_number ==
                                   replacement_syscall &&
                           (relation->events[relation->event_head].flags &
                            tracer::kLogicalPtraceEventFlagRegistersValid) ==
                                   0U,
                   296)) {
            return false;
        }

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_CONT;
        arguments[1] = tracee.tid;
        LogicalPtraceEntryResult cont_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 300,
                               &cont_entry)) {
            return false;
        }
        relation = tracer::FindLogicalPtraceRelation(logical, tracee);
        if (!Check(&report,
                   relation != nullptr && relation->event_count == 0U &&
                           relation->state ==
                                   tracer::LogicalPtraceRelationState::
                                           kRunningCont &&
                           cont_entry.target.syscall_number ==
                                   replacement_syscall,
                   306) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical),
                   307)) {
            return false;
        }
        event = MakeStop(
                tracer::LogicalPtraceEventKind::kSyscallEntry, SIGTRAP,
                tracer::kLogicalPtraceEventFlagRegistersValid |
                        tracer::kLogicalPtraceEventFlagSyscallNumberValid);
        event.guest_syscall_number = __NR_statx;
        event.guest_registers.regs[0] = 0x10;
        event.guest_registers.regs[1] = 0x20;
        event.guest_registers.pc = 0x12345000;
        event.guest_registers.sp = 0x76543000;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, tracee,
                                            event, nullptr) == 0,
                   330)) {
            return false;
        }
        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = tracee.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_wait4, arguments, tracee.tid, 332,
                               nullptr)) {
            return false;
        }
        struct ptrace_syscall_info syscall_info {};
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_GET_SYSCALL_INFO;
        arguments[1] = tracee.tid;
        arguments[2] = sizeof(syscall_info);
        arguments[3] = reinterpret_cast<uintptr_t>(&syscall_info);
        const int64_t syscall_info_size = static_cast<int64_t>(
                offsetof(struct ptrace_syscall_info, entry) +
                sizeof(syscall_info.entry));
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, syscall_info_size,
                               340, nullptr) ||
            !Check(&report,
                   syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY &&
                           syscall_info.arch == AUDIT_ARCH_AARCH64 &&
                           syscall_info.entry.nr == __NR_statx &&
                           syscall_info.entry.args[0] == 0x10 &&
                           syscall_info.entry.args[1] == 0x20 &&
                           syscall_info.instruction_pointer == 0x12345000 &&
                           syscall_info.stack_pointer == 0x76543000,
                   346)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_CONT;
        arguments[1] = tracee.tid;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 350, nullptr)) {
            return false;
        }
        event = MakeStop(tracer::LogicalPtraceEventKind::kSignalDelivery,
                         SIGUSR2, 0);
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, tracee,
                                            event, nullptr) == 0,
                   308)) {
            return false;
        }
        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = tracee.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_wait4, arguments, tracee.tid, 310,
                               nullptr)) {
            return false;
        }
        uint64_t event_message = UINT64_MAX;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_GETEVENTMSG;
        arguments[1] = tracee.tid;
        arguments[3] = reinterpret_cast<uintptr_t>(&event_message);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, -EINVAL, 314,
                               nullptr) ||
            !Check(&report, event_message == UINT64_MAX, 320)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_KILL;
        arguments[1] = tracee.tid;
        arguments[3] = UINT64_MAX;
        LogicalPtraceEntryResult kill_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 330,
                               &kill_entry) ||
            !Check(&report,
                    kill_entry.target.action ==
                                    LogicalPtraceTargetAction::kResumeCont &&
                            kill_entry.target.signal_number == SIGKILL,
                   336) ||
            !Check(&report,
                   tracer::EraseLogicalPtraceRelation(logical, tracee,
                                                       false) == 0,
                   337)) {
            return false;
        }
        ++report.scenarios;

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_SEIZE;
        arguments[1] = seized.tid;
        arguments[2] = 1;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, -EIO, 400, nullptr) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical, seized) ==
                           nullptr,
                   406)) {
            return false;
        }
        arguments[2] = 0;
        arguments[3] = tracer::kLogicalPtraceOptionTraceExec;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 410, nullptr)) {
            return false;
        }

        arguments[0] = PTRACE_INTERRUPT;
        arguments[2] = 0;
        arguments[3] = 1;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, -EIO, 420, nullptr)) {
            return false;
        }
        arguments[3] = 0;
        LogicalPtraceEntryResult interrupt_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 430,
                               &interrupt_entry) ||
            !Check(&report,
                   interrupt_entry.target.action ==
                           LogicalPtraceTargetAction::kInterrupt,
                   436)) {
            return false;
        }
        event = MakeStop(tracer::LogicalPtraceEventKind::kInterruptStop,
                         SIGTRAP,
                         tracer::kLogicalPtraceEventFlagRegistersValid);
        event.guest_registers.regs[1] = 0x55aa55aaULL;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, seized,
                                            event, nullptr) == 0,
                   437)) {
            return false;
        }
        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = seized.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_wait4, arguments, seized.tid, 440,
                               nullptr)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_SINGLESTEP;
        arguments[1] = seized.tid;
        LogicalPtraceEntryResult step_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 450,
                               &step_entry) ||
            !Check(&report,
                   step_entry.target.action ==
                           LogicalPtraceTargetAction::kResumeSingleStep,
                   455) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical, seized)->state ==
                           tracer::LogicalPtraceRelationState::
                                   kRunningSingleStep,
                   456)) {
            return false;
        }

        event = MakeStop(tracer::LogicalPtraceEventKind::kGroupStop,
                         SIGSTOP, 0);
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, seized,
                                            event, nullptr) == 0,
                   456)) {
            return false;
        }
        memset(&wait_info, 0, sizeof(wait_info));
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = 1;
        arguments[1] = seized.tid;
        arguments[2] = reinterpret_cast<uintptr_t>(&wait_info);
        arguments[3] = tracer::kLogicalWaitStopped |
                       tracer::kLogicalWaitNowait;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_waitid, arguments, 0, 460, nullptr)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_LISTEN;
        arguments[1] = seized.tid;
        arguments[3] = 1;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, -EIO, 470, nullptr)) {
            return false;
        }
        relation = tracer::FindLogicalPtraceRelation(logical, seized);
        if (!Check(&report,
                   relation != nullptr && relation->event_count == 1U,
                   476)) {
            return false;
        }
        arguments[3] = 0;
        LogicalPtraceEntryResult listen_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 480,
                               &listen_entry) ||
            !Check(&report,
                   listen_entry.target.action ==
                           LogicalPtraceTargetAction::kListen,
                   486) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical, seized)->state ==
                           tracer::LogicalPtraceRelationState::kListening,
                   487)) {
            return false;
        }
        ++report.scenarios;

        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = seized.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        LogicalPtraceEntryResult held_entry {};
        if (!Check(&report,
                   DispatchLogicalPtraceEntry(
                           dispatcher, logical, io, tracer_sibling,
                           __NR_wait4, arguments, &held_entry) == 0,
                   500) ||
            !Check(&report,
                   (held_entry.flags & kLogicalPtraceEntryMayHold) != 0U,
                   501)) {
            return false;
        }
        LogicalPtraceExitResult held_exit {};
        if (!Check(&report,
                   DispatchLogicalPtraceExit(
                           dispatcher, logical, tracer_sibling, __NR_wait4,
                           0, &held_exit) == 0 &&
                           (held_exit.flags & kLogicalPtraceExitHold) != 0U,
                   502)) {
            return false;
        }
        event = MakeStop(tracer::LogicalPtraceEventKind::kSignalDelivery,
                         SIGUSR1,
                         tracer::kLogicalPtraceEventFlagRegistersValid |
                                 tracer::kLogicalPtraceEventFlagSiginfoValid);
        event.signal_info.si_signo = SIGUSR1;
        event.guest_registers.regs[2] = 0x1234;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, seized,
                                            event, nullptr) == 0,
                   503) ||
            !Check(&report,
                   TryWakeLogicalPtraceWait(dispatcher, logical, io,
                                            tracer_sibling) == 0,
                   504)) {
            return false;
        }
        held_exit = {};
        if (!Check(&report,
                   DispatchLogicalPtraceExit(
                           dispatcher, logical, tracer_sibling, __NR_wait4,
                           0, &held_exit) == 0 &&
                           (held_exit.flags &
                            kLogicalPtraceExitWriteResult) != 0U &&
                           held_exit.visible_result == seized.tid,
                   505) ||
            !Check(&report, wait_status == event.wait_status, 506)) {
            return false;
        }

        fixture.tasks[4] = seized_exec;
        fixture.parents[4] = tracer_main;
        if (!Check(&report,
                   RekeyLogicalPtraceDispatchTask(
                           dispatcher, logical, seized, seized_exec) == 0,
                   510) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical,
                                                     seized_exec) != nullptr,
                   511) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical),
                   512)) {
            return false;
        }

        read_registers = {};
        vector.base = reinterpret_cast<uintptr_t>(&read_registers);
        vector.length = sizeof(read_registers);
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_GETREGSET;
        arguments[1] = seized_exec.tid;
        arguments[2] = NT_PRSTATUS;
        arguments[3] = reinterpret_cast<uintptr_t>(&vector);
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 520, nullptr) ||
            !Check(&report, read_registers.regs[2] == 0x1234, 526)) {
            return false;
        }

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_DETACH;
        arguments[1] = seized_exec.tid;
        LogicalPtraceEntryResult detach_entry {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_sibling,
                               __NR_ptrace, arguments, 0, 530,
                               &detach_entry) ||
            !Check(&report,
                   detach_entry.target.action ==
                           LogicalPtraceTargetAction::kDetach,
                   536) ||
            !Check(&report,
                   dispatcher->operation_count == 0U &&
                           logical->relation_count == 0U &&
                           logical->wait_count == 0U,
                   538) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical),
                   539)) {
            return false;
        }
        ++report.scenarios;

        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_SEIZE;
        arguments[1] = exit_race.tid;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 600, nullptr)) {
            return false;
        }
        arguments[0] = PTRACE_INTERRUPT;
        LogicalPtraceEntryResult race_interrupt {};
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 610,
                               &race_interrupt) ||
            !Check(&report,
                   race_interrupt.target.action ==
                           LogicalPtraceTargetAction::kInterrupt,
                   616)) {
            return false;
        }
        event = {};
        event.kind = tracer::LogicalPtraceEventKind::kExited;
        event.signal_number = 0;
        event.wait_status = 7 << 8;
        event.guest_syscall_number = -1;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, exit_race,
                                            event, nullptr) == 0,
                   617)) {
            return false;
        }
        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = exit_race.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_wait4, arguments, exit_race.tid, 620,
                               nullptr) ||
            !Check(&report, wait_status == (7 << 8), 626) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical, exit_race) ==
                           nullptr,
                   627) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical),
                   628)) {
            return false;
        }
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = PTRACE_ATTACH;
        arguments[1] = exit_race.tid;
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_ptrace, arguments, 0, 630, nullptr)) {
            return false;
        }
        event = {};
        event.kind = tracer::LogicalPtraceEventKind::kSignaled;
        event.signal_number = SIGTERM;
        event.wait_status = SIGTERM;
        event.guest_syscall_number = -1;
        if (!Check(&report,
                   PublishLogicalPtraceStop(dispatcher, logical, exit_race,
                                            event, nullptr) == 0,
                   636)) {
            return false;
        }
        wait_status = 0;
        memset(arguments, 0, sizeof(arguments));
        arguments[0] = exit_race.tid;
        arguments[1] = reinterpret_cast<uintptr_t>(&wait_status);
        if (!DispatchImmediate(&report, &fixture, io, tracer_main,
                               __NR_wait4, arguments, exit_race.tid, 640,
                               nullptr) ||
            !Check(&report, wait_status == SIGTERM, 646) ||
            !Check(&report,
                   tracer::FindLogicalPtraceRelation(logical, exit_race) ==
                           nullptr,
                   647) ||
            !Check(&report,
                   ValidateLogicalPtraceDispatcher(dispatcher, logical),
                   648)) {
            return false;
        }
        ++report.scenarios;
        return true;
    }();

    Check(&report, completed, 900);
    munmap(dispatcher_memory, sizeof(LogicalPtraceDispatcher));
    munmap(logical_memory, sizeof(tracer::LogicalPtraceTable));
    return report;
}

}  // namespace hookself::internal
