namespace {

using hookself::arch::Arm64Regs;
using hookself::platform::RawError;
using hookself::platform::RawPtrace;
using hookself::platform::RawSyscall6;
using hookself::tracer::StopEvent;
using hookself::tracer::StopEventKind;
using hookself::tracer::TaskLifeState;
using hookself::tracer::TaskRecord;
using hookself::tracer::TaskResumeMode;
using hookself::tracer::TaskStopState;
using hookself::tracer::TaskSyscallPhase;

constexpr int kPrSetPtracer = 0x59616d61;
constexpr int kWaitWall = 0x40000000;
constexpr int kMaxAttachRounds = 12;
constexpr int64_t kAttachTimeoutMs = 7000;
constexpr int64_t kDetachTimeoutMs = 3000;
constexpr int64_t kTeardownFrozenTimeoutMs = 30000;
constexpr uint32_t kDefaultStopTimeoutMs = 5000;
constexpr uint32_t kReapTimeoutMs = 2000;
constexpr uint32_t kCloseRangeUnshare = 1U << 1;
constexpr uint32_t kCloseRangeCloexec = 1U << 2;
constexpr int32_t kSyscallCloseRange = 436;
constexpr uint64_t kMountFlagBind = 4096ULL;
constexpr uint64_t kMountFlagMove = 8192ULL;
constexpr uint32_t kMoveMountFromEmptyPath = 0x00000004U;
constexpr uint32_t kMoveMountToEmptyPath = 0x00000040U;
constexpr uint32_t kPtraceViewInitialized = 1U << 0;
constexpr uint32_t kPtraceViewPtracerTouched = 1U << 1;
constexpr uint64_t kPrSetPtracerAny = UINT64_MAX;
constexpr size_t kProcStatusReadCapacity = 4096U;
constexpr uint32_t kMaxProcStatusIov = 1024U;
constexpr uint64_t kParentCommandOpcodeMask = UINT32_MAX;
constexpr uint32_t kParentCommandShutdownCommit = 2U;
constexpr uint32_t kParentCommandShutdownAbort = 3U;

int CloseOwnedDescriptor(int fd,
                         const FdObjectIdentity& identity) noexcept {
    if (fd < 0) {
        return 0;
    }
    return CloseFdObject(fd, identity);
}

uint32_t ProbeCloseRangeCapabilities() noexcept {
    // A blocked close_range probe may terminate an Android app even when it
    // is issued by a short-lived child. Until an externally supplied
    // capability source is available, leave protected close_range replay off.
    return kCloseRangeCapabilityNone;
}

bool CloseRangeCapabilitiesPermitPolicy(uint32_t capabilities,
                                        uint32_t flags) noexcept {
    if ((flags & ~(kCloseRangeUnshare | kCloseRangeCloexec)) != 0U ||
        (capabilities & kCloseRangeCapabilitySyscall) == 0U) {
        return false;
    }
    if ((flags & kCloseRangeCloexec) != 0U &&
        (capabilities & kCloseRangeCapabilityCloexec) == 0U) {
        return false;
    }
    return (flags & kCloseRangeUnshare) == 0U ||
           (capabilities & kCloseRangeCapabilityUnshare) != 0U;
}

enum PendingPathFlags : uint32_t {
    kPendingPathNone = 0,
    kPendingPathActive = 1U << 0,
    kPendingPathRedirected = 1U << 1,
    kPendingPathReverseVisible = 1U << 2,
    kPendingPathVirtual = 1U << 3,
    kPendingPathCloseRangeReplay = 1U << 4,
    kPendingPathCloseRangeAwaitEntry = 1U << 5,
    kPendingPathCloseRangeSynthetic = 1U << 6,
};

struct PendingPathIdentity {
    uint32_t flags;
    int32_t syscall_number;
    uint32_t path_count;
    uint32_t reserved;
    uint64_t open_flags;
    uint64_t open_resolve;
    uint32_t mount_attr_valid;
    uint32_t mount_attr_size;
    uint64_t mount_attr_set;
    uint64_t mount_attr_clear;
    uint64_t mount_propagation;
    uint32_t replay_first;
    uint32_t replay_last;
    uint32_t replay_flags;
    uint32_t replay_sequence;
    hookself::tracer::CloseRangeReplayCursor close_range_replay;
    uint32_t argument_indices[kScratchPathSlots];
    uint32_t origin_flags[kScratchPathSlots];
    uint32_t rule_ids[kScratchPathSlots];
    uint32_t reserved32[kScratchPathSlots];
    char guest_paths[kScratchPathSlots][HOOKSELF_PATH_CAPACITY];
    char host_paths[kScratchPathSlots][HOOKSELF_PATH_CAPACITY];
};

struct PathPendingTable {
    PendingPathIdentity entries[hookself::tracer::kTaskTableCapacity];
};

constexpr char kStatusReady = 'R';
constexpr char kStatusInstallReady = 'I';
constexpr char kStatusCommitReady = 'C';
constexpr char kStatusStopped = 'S';
constexpr char kStatusTeardownFrozen = 'T';
constexpr char kStatusFatal = 'F';
constexpr uint32_t kSelectiveCommitBrkInstruction =
        0xd4200000U | (0x4853U << 5U);

enum class FatalStage : int32_t {
    kNone = 0,
    kIdentity = 1,
    kSharedAbi = 2,
    kWorkspace = 3,
    kTaskEnumeration = 4,
    kTaskTableFull = 5,
    kSeize = 6,
    kInterrupt = 7,
    kWait = 8,
    kCoverage = 9,
    kRegisters = 10,
    kResume = 11,
    kEventMessage = 12,
    kDetach = 13,
    kControl = 14,
    kScratchMapping = 15,
    kExecMigration = 16,
    kTaskIdentity = 17,
    kSyscall = 18,
    kPoll = 19,
    kSeccompPlan = 20,
    kSeccompInstall = 21,
    kSeccompCommit = 22,
    kSeccompProtocol = 23,
};

// The shared registry contains descriptor numbers because the tracee and its
// tracer initially inherit matching FD tables.  A descriptor number can later
// be reused by an unrelated subsystem, so policy decisions must also confirm
// the object currently installed in the tracee table.
struct ProtectedFdIdentity {
    int32_t fd;
    uint32_t valid;
    uint64_t device;
    uint64_t inode;
    uint64_t rdev;
    uint32_t type;
};

// The logical dispatcher tracks virtual ptrace state. These records bind a
// delivered logical stop or a parked wait to the real outer-ptrace stop which
// must remain stopped until the logical operation has completed.
struct NestedPtracePhysicalHold {
    uint32_t occupied;
    uint32_t relation_slot;
    uint64_t relation_generation;
    hookself::tracer::LogicalTaskKey tracee;
    pid_t physical_tid;
    uint32_t reserved;
    uint64_t physical_stop_sequence;
    uint64_t event_sequence;
};

struct NestedPtraceWaitExitHold {
    uint32_t occupied;
    uint32_t operation_slot;
    uint64_t operation_generation;
    hookself::tracer::LogicalTaskKey waiter;
    pid_t physical_tid;
    uint32_t reserved;
    uint64_t physical_stop_sequence;
};

struct TracerContext {
    SharedSessionMapping mapping;
    SharedHeader* header;
    SharedControlPage* control;
    EventRingHeader* event_ring;
    SharedScratchFrame* writable_scratch;
    hookself::tracer::TaskTable* tasks;
    hookself::tracer::PathStateTable* path_state;
    PathPendingTable* pending_paths;
    ProcVirtualResidentState* proc_virtual;
    LogicalPtraceResidentState* logical_ptrace;
    LogicalPtraceResidentState* logical_ptrace_rollback;
    LogicalPtraceResidentIoContext logical_ptrace_io_context;
    uint64_t next_logical_task_generation;
    uint64_t next_logical_process_generation;
    NestedPtracePhysicalHold
            nested_ptrace_holds[hookself::tracer::kLogicalPtraceRelationCapacity];
    NestedPtraceWaitExitHold
            nested_ptrace_wait_holds[kLogicalPtraceDispatchCapacity];
    pid_t target_pid;
    pid_t tracer_pid;
    uint64_t ptrace_options;
    uint64_t acknowledged_command;
    pid_t stop_owner_tid;
    uint64_t teardown_command_sequence;
    pid_t teardown_owner_tid;
    int control_event_fd;
    int signal_event_fd;
    int status_write_fd;
    uint64_t next_start_time_check_ns;
    FatalStage last_failure_stage;
    pid_t last_failure_tid;
    bool shutting_down;
    bool runtime_started;
    bool stop_requested;
    bool quiescing;
    bool selective_requested;
    bool selective_mode;
    bool selective_passthrough;
    bool nested_ptrace_phase1;
    bool selective_installer_released;
    bool teardown_freeze_requested;
    uint64_t protected_fd_registry_generation;
    ProtectedFdIdentity protected_fd_identities[kMaxProtectedFds];
    const SelectiveSeccompPlan* selective_plan;
};

int RebuildExecAddressSpace(TracerContext* context,
                            TaskRecord* task) noexcept;
bool IsProtectedFdForTask(TracerContext* context, const TaskRecord* task,
                          int32_t fd) noexcept;
void InitializeProtectedFdIdentities(TracerContext* context) noexcept;

uint64_t EncodeParentCommand(uint32_t opcode, pid_t owner_tid) noexcept {
    return (static_cast<uint64_t>(static_cast<uint32_t>(owner_tid)) << 32U) |
           static_cast<uint64_t>(opcode);
}

uint32_t DecodeParentCommandOpcode(uint64_t command) noexcept {
    return static_cast<uint32_t>(command & kParentCommandOpcodeMask);
}

pid_t DecodeParentCommandOwner(uint64_t command) noexcept {
    const uint32_t encoded = static_cast<uint32_t>(command >> 32U);
    return encoded <= static_cast<uint32_t>(INT32_MAX)
                   ? static_cast<pid_t>(encoded)
                   : static_cast<pid_t>(-1);
}

void InitializeFallbackSyscallPhase(TaskRecord* task) noexcept;
void SaveSyscallEntry(TaskRecord* task, int32_t syscall_number,
                      const uint64_t arguments[6]) noexcept;
int ReadRemoteBytes(pid_t tgid, pid_t tid, uintptr_t address, void* output,
                    size_t size) noexcept;
int ResumeTask(TracerContext* context, TaskRecord* task) noexcept;
void PrepareTasksForSelectiveCont(TracerContext* context) noexcept;
int RegisterNestedPtraceTask(TracerContext* context, TaskRecord* task,
                             const TaskRecord* parent) noexcept;
int RetireNestedPtraceTask(TracerContext* context,
                           const TaskRecord* task) noexcept;
int CollectNestedPtraceRetiredTasks(TracerContext* context) noexcept;
int MergeNestedPtraceExecTask(TracerContext* context,
                               const TaskRecord* former,
                               const TaskRecord* destination) noexcept;
int PublishNestedPtraceTerminal(TracerContext* context, TaskRecord* task,
                                const StopEvent& event) noexcept;

void ClearPendingPath(TracerContext* context,
                      const TaskRecord* task) noexcept {
    if (context == nullptr || context->pending_paths == nullptr ||
        task == nullptr || task->slot >= hookself::tracer::Capacity()) {
        return;
    }
    auto* bytes = reinterpret_cast<uint8_t*>(
            &context->pending_paths->entries[task->slot]);
    for (size_t index = 0; index < sizeof(PendingPathIdentity); ++index) {
        bytes[index] = 0;
    }
}

struct LinuxDirent64 {
    uint64_t inode;
    int64_t offset;
    uint16_t record_length;
    uint8_t type;
    char name[1];
};

bool ParseFdNumber(const char* value, size_t capacity, int* fd) noexcept {
    if (capacity == 0 || value[0] == '\0') {
        return false;
    }
    int parsed = 0;
    size_t index = 0;
    for (; index < capacity && value[index] != '\0'; ++index) {
        if (value[index] < '0' || value[index] > '9' ||
            parsed > (INT32_MAX - (value[index] - '0')) / 10) {
            return false;
        }
        parsed = parsed * 10 + (value[index] - '0');
    }
    if (index == capacity) {
        return false;
    }
    *fd = parsed;
    return true;
}

bool IsInheritedProtectedFd(const SharedControlPage* control,
                            int fd) noexcept {
    if (control == nullptr || fd < 0) {
        return false;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (control->protected_fds[index] == fd) {
            return true;
        }
    }
    return false;
}

int CloseInheritedFileDescriptors(int keep0, int keep1, int keep2,
                                  const SharedControlPage* control) noexcept {
    constexpr char kFdDirectory[] = "/proc/self/fd";
    const long directory_result = hookself::platform::RawOpenAt(
            AT_FDCWD, kFdDirectory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const int open_error = RawError(directory_result);
    if (open_error != 0) {
        return open_error;
    }
    const int directory_fd = static_cast<int>(directory_result);
    alignas(8) char buffer[4096];
    for (;;) {
        const long read_result = hookself::platform::RawGetdents64(
                directory_fd, buffer, sizeof(buffer));
        if (read_result == 0) {
            break;
        }
        const int read_error = RawError(read_result);
        if (read_error != 0) {
            (void)hookself::platform::RawClose(directory_fd);
            return read_error;
        }
        const size_t bytes = static_cast<size_t>(read_result);
        size_t offset = 0;
        while (offset < bytes) {
            const auto* entry = reinterpret_cast<const LinuxDirent64*>(
                    buffer + offset);
            const size_t name_offset = offsetof(LinuxDirent64, name);
            if (entry->record_length < name_offset + 2 ||
                entry->record_length > bytes - offset) {
                (void)hookself::platform::RawClose(directory_fd);
                return EIO;
            }
            int candidate = -1;
            if (ParseFdNumber(entry->name,
                              entry->record_length - name_offset,
                              &candidate) &&
                candidate != directory_fd && candidate != keep0 &&
                candidate != keep1 && candidate != keep2 &&
                !IsInheritedProtectedFd(control, candidate)) {
                (void)hookself::platform::RawClose(candidate);
            }
            offset += entry->record_length;
        }
    }
    (void)hookself::platform::RawClose(directory_fd);
    return 0;
}

int64_t MonotonicNanoseconds() noexcept {
    timespec value{};
    if (RawError(hookself::platform::RawClockGettime(CLOCK_MONOTONIC, &value)) != 0) {
        return 0;
    }
    return static_cast<int64_t>(value.tv_sec) * 1000000000LL + value.tv_nsec;
}

void AtomicStoreState(SharedControlPage* control, HookselfRuntimeState state) noexcept {
    __atomic_store_n(&control->tracer_state, static_cast<uint64_t>(state),
                     __ATOMIC_RELEASE);
}

void UpdateTrackedTasks(TracerContext* context) noexcept {
    __atomic_store_n(&context->control->tracked_tasks,
                     hookself::tracer::Count(context->tasks), __ATOMIC_RELEASE);
}

int ValidateTargetParent(const TracerContext* context) noexcept {
    if (context == nullptr || context->header == nullptr ||
        context->target_pid <= 0 ||
        RawSyscall6(__NR_getppid) != context->target_pid) {
        return ESRCH;
    }
    return 0;
}

int ValidateTargetStartTime(const TracerContext* context) noexcept {
    if (context == nullptr || context->header == nullptr ||
        context->target_pid <= 0) {
        return ESRCH;
    }
    if (context->header->target_start_time == 0) {
        return 0;
    }
    uint64_t start_time = 0;
    const int start_error = hookself::platform::ReadProcessStartTime(
            context->target_pid, &start_time);
    if (start_error != 0) {
        return start_error;
    }
    return start_time == context->header->target_start_time ? 0 : ESTALE;
}

int ValidateTargetIdentity(const TracerContext* context) noexcept {
    const int parent_error = ValidateTargetParent(context);
    return parent_error != 0 ? parent_error : ValidateTargetStartTime(context);
}

int ValidateRuntimeTargetIdentity(TracerContext* context) noexcept {
    const int parent_error = ValidateTargetParent(context);
    if (parent_error != 0) {
        return parent_error;
    }
    const int64_t now = MonotonicNanoseconds();
    if (now <= 0) {
        return EIO;
    }
    if (context->next_start_time_check_ns != 0 &&
        static_cast<uint64_t>(now) < context->next_start_time_check_ns) {
        return 0;
    }
    const int start_error = ValidateTargetStartTime(context);
    context->next_start_time_check_ns =
            static_cast<uint64_t>(now) + 1000000000ULL;
    return start_error;
}

void RecordFatal(TracerContext* context, FatalStage stage, int error,
                 pid_t tid = 0) noexcept {
    if (__atomic_load_n(&context->control->fatal_code, __ATOMIC_ACQUIRE) == 0) {
        __atomic_store_n(&context->control->fatal_errno, error, __ATOMIC_RELAXED);
        __atomic_store_n(&context->control->fatal_tid, tid, __ATOMIC_RELAXED);
        __atomic_store_n(&context->control->fatal_code,
                         static_cast<int32_t>(stage), __ATOMIC_RELEASE);
    }
    __atomic_fetch_add(&context->control->internal_errors, 1U, __ATOMIC_RELAXED);
    AtomicStoreState(context->control, HOOKSELF_STATE_FATAL);
}

void NoteFailure(TracerContext* context, FatalStage stage,
                 pid_t tid) noexcept {
    context->last_failure_stage = stage;
    context->last_failure_tid = tid;
}

bool WriteStatusByte(int fd, char status) noexcept {
    for (;;) {
        const long result = hookself::platform::RawWrite(fd, &status, 1);
        if (result == 1) {
            return true;
        }
        const int error = RawError(result);
        if (error != EINTR) {
            return false;
        }
    }
}

bool EmitEvent(TracerContext* context, HookselfEvent* event) noexcept {
    event->struct_size = sizeof(*event);
    event->monotonic_time_ns = MonotonicNanoseconds();
    return PushEvent(context->event_ring, *event);
}

void EmitLifecycle(TracerContext* context, HookselfRuntimeState state) noexcept {
    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_LIFECYCLE;
    event.tgid = context->target_pid;
    event.tid = context->target_pid;
    event.action = static_cast<int32_t>(state);
    event.result = context->tracer_pid;
    (void)EmitEvent(context, &event);
}

void EmitProcessEvent(TracerContext* context, const TaskRecord& task,
                      uint32_t flags, uint32_t ptrace_event) noexcept {
    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_PROCESS;
    event.tgid = task.tgid;
    event.tid = task.tid;
    event.action = static_cast<int32_t>(ptrace_event);
    event.flags = flags;
    (void)EmitEvent(context, &event);
}

void EmitSignalEvent(TracerContext* context, const TaskRecord& task,
                     int signal_number) noexcept {
    if ((context->control->config_flags & HOOKSELF_CONFIG_OBSERVE_ALL) == 0) {
        return;
    }
    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_SIGNAL;
    event.tgid = task.tgid;
    event.tid = task.tid;
    event.action = signal_number;
    (void)EmitEvent(context, &event);
}

int ConfigurationSupported(const HookselfConfig& config) noexcept {
    if (config.backend != HOOKSELF_BACKEND_FORK_RAW) {
        return HOOKSELF_E_NOT_IMPLEMENTED;
    }
    if ((config.flags & HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE) != 0U &&
        ((config.flags & HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0U ||
         (config.flags & HOOKSELF_CONFIG_TRACE_DESCENDANTS) == 0U ||
         (config.flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0U ||
         config.failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if ((config.flags & HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0 &&
        ((config.flags & HOOKSELF_CONFIG_OBSERVE_ALL) != 0 ||
         (config.flags & HOOKSELF_CONFIG_TRACE_DESCENDANTS) == 0 ||
         config.failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    if ((config.flags & (HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                         HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES |
                         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW |
                         HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW)) != 0 &&
        config.failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < config.path_rule_count; ++i) {
        if (config.path_rules[i].action != HOOKSELF_PATH_PASS &&
            config.path_rules[i].action != HOOKSELF_PATH_REDIRECT &&
            config.path_rules[i].action != HOOKSELF_PATH_DENY) {
            return HOOKSELF_E_NOT_IMPLEMENTED;
        }
    }
    for (uint32_t i = 0; i < config.syscall_rule_count; ++i) {
        const int32_t action = config.syscall_rules[i].action;
        if (action < HOOKSELF_SYSCALL_PASS ||
            action > HOOKSELF_SYSCALL_REPLACE_ARGUMENT) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
        if (action > HOOKSELF_SYSCALL_OBSERVE &&
            config.failure_mode != HOOKSELF_FAILURE_FAIL_CLOSED) {
            return HOOKSELF_E_INVALID_ARGUMENT;
        }
    }
    return HOOKSELF_OK;
}

uint64_t BuildPtraceOptions(const SharedControlPage& control) noexcept {
    uint64_t options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
                       PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    if ((control.config_flags & HOOKSELF_CONFIG_TRACE_DESCENDANTS) != 0) {
        options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACEVFORKDONE;
    }
    if (control.failure_mode == HOOKSELF_FAILURE_FAIL_CLOSED) {
        options |= PTRACE_O_EXITKILL;
    }
    if ((control.config_flags &
         HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP) != 0) {
        options |= PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL;
    }
    return options;
}

TaskRecord* InsertTask(TracerContext* context, pid_t tid, pid_t tgid,
                       bool auto_attached, int* error) noexcept {
    TaskRecord* task = nullptr;
    const auto result = hookself::tracer::Insert(context->tasks, tid, tgid, &task);
    if (result == hookself::tracer::TaskInsertResult::kFull) {
        *error = EOVERFLOW;
        return nullptr;
    }
    if (result == hookself::tracer::TaskInsertResult::kInvalidArgument ||
        result == hookself::tracer::TaskInsertResult::kIdentityConflict) {
        *error = EPROTO;
        return nullptr;
    }
    if (result == hookself::tracer::TaskInsertResult::kInserted) {
        task->ptrace_options = context->ptrace_options;
        task->tracee_scratch_address =
                context->header == nullptr
                        ? 0
                        : context->header->tracee_scratch_address;
        task->syscall_phase = TaskSyscallPhase::kExpectEntry;
        task->resume_mode = context->selective_requested
                                    ? TaskResumeMode::kCont
                                    : TaskResumeMode::kSyscall;
        if (auto_attached) {
            task->flags |= hookself::tracer::kTaskFlagSeized |
                           hookself::tracer::kTaskFlagNeedsDetach |
                           hookself::tracer::kTaskFlagOptionsApplied |
                           hookself::tracer::kTaskFlagAutoAttached;
        }
        UpdateTrackedTasks(context);
        if (context->nested_ptrace_phase1 &&
            task->tgid == context->target_pid) {
            const int nested_error = RegisterNestedPtraceTask(
                    context, task, nullptr);
            if (nested_error != 0) {
                (void)hookself::tracer::Erase(context->tasks, task->tid);
                UpdateTrackedTasks(context);
                *error = nested_error;
                return nullptr;
            }
        }
    }
    *error = 0;
    return task;
}

pid_t ResolveTaskTgid(TracerContext* context, pid_t tid,
                      uint32_t ptrace_event, pid_t parent_tgid) noexcept {
    if (ptrace_event == PTRACE_EVENT_FORK || ptrace_event == PTRACE_EVENT_VFORK) {
        return tid;
    }
    pid_t tgid = 0;
    return hookself::platform::ReadTaskTgid(tid, &tgid) == 0
                   ? tgid
                   : parent_tgid > 0 ? parent_tgid : context->target_pid;
}

StopEvent DecodeStatus(pid_t tid, int status, uint64_t options) noexcept {
    hookself::tracer::WaitDecodeOptions decode_options{};
    decode_options.ptrace_options = options;
    StopEvent event = hookself::tracer::DecodeWaitStatus(status, decode_options);
    if (event.kind == StopEventKind::kSignalDelivery &&
        hookself::tracer::IsJobControlStopSignal(event.signal)) {
        siginfo_t signal_info{};
        const long result = RawPtrace(PTRACE_GETSIGINFO, tid, 0,
                                      reinterpret_cast<uintptr_t>(&signal_info));
        decode_options.signal_stop_hint =
                RawError(result) == EINVAL
                        ? hookself::tracer::SignalStopHint::kGroupStop
                        : hookself::tracer::SignalStopHint::kSignalDelivery;
        event = hookself::tracer::DecodeWaitStatus(status, decode_options);
    }
    return event;
}

void SetStoppedState(TaskRecord* task, const StopEvent& event,
                     int status) noexcept {
    task->last_wait_status = status;
    task->last_ptrace_event = event.ptrace_event;
    task->life = TaskLifeState::kStopped;
    task->pending_signal = 0;
    ++task->stop_sequence;
    switch (event.kind) {
        case StopEventKind::kSyscallStop:
            task->stop = TaskStopState::kSyscall;
            break;
        case StopEventKind::kSeccompStop:
            task->stop = TaskStopState::kSeccomp;
            break;
        case StopEventKind::kGroupStop:
            task->stop = TaskStopState::kGroup;
            task->pending_signal = event.signal;
            break;
        case StopEventKind::kSignalDelivery:
            task->stop = TaskStopState::kSignalDelivery;
            task->pending_signal = event.signal;
            break;
        case StopEventKind::kPtraceEvent:
            task->stop = event.ptrace_event == PTRACE_EVENT_EXIT
                                 ? TaskStopState::kExitEvent
                                 : event.event_stop_reason ==
                                                   hookself::tracer::EventStopReason::kInterrupt
                                           ? TaskStopState::kInterrupt
                                           : TaskStopState::kPtraceEvent;
            break;
        default:
            task->stop = TaskStopState::kNone;
            break;
    }
}

int ReadEventMessage(pid_t tid, unsigned long* message) noexcept {
    if (message == nullptr) {
        return EINVAL;
    }
    *message = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const long result = RawPtrace(
                PTRACE_GETEVENTMSG, tid, 0,
                reinterpret_cast<uintptr_t>(message));
        const int error = RawError(result);
        if (error == 0) {
            return 0;
        }
        if (error != ESRCH || attempt != 0) {
            return error;
        }
    }
    return ESRCH;
}

bool HasActiveExecSyscall(const TaskRecord* task) noexcept {
    if (task == nullptr ||
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallValid) == 0) {
        return false;
    }
    return task->active_syscall.syscall_number == __NR_execve ||
           task->active_syscall.syscall_number == __NR_execveat;
}

void DiscardTaskMutation(TracerContext* context, TaskRecord* task,
                         bool clear_snapshot) noexcept {
    if (task == nullptr) {
        return;
    }
    ClearPendingPath(context, task);
    if (context != nullptr && context->proc_virtual != nullptr &&
        task->slot < kProcVirtualDispatchTaskCapacity) {
        (void)ClearProcVirtualPending(&context->proc_virtual->pending,
                                      task->slot);
    }
    if (context->writable_scratch != nullptr &&
        task->active_syscall.scratch_slot < hookself::tracer::Capacity()) {
        SharedScratchFrame* frame = &context->writable_scratch[
                task->active_syscall.scratch_slot];
        if (frame->owner_tid == task->tid &&
            frame->generation == task->active_syscall.scratch_generation) {
            frame->state = 0;
            frame->owner_tid = 0;
        }
    }
    if (clear_snapshot) {
        hookself::tracer::ClearActiveSyscall(task);
        return;
    }
    constexpr uint32_t kDiscardedFlags =
            hookself::tracer::kActiveSyscallEntryRegistersValid |
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallResultWriteUnknown;
    task->active_syscall.flags &= ~kDiscardedFlags;
    task->active_syscall.modified_argument_mask = 0;
    task->active_syscall.scratch_slot = hookself::tracer::kInvalidTaskSlot;
    task->active_syscall.scratch_generation = 0;
}

void SynthesizeExecSnapshot(TaskRecord* task, int32_t syscall_number) noexcept {
    uint64_t arguments[6]{};
    SaveSyscallEntry(task, syscall_number == __NR_execveat
                                   ? __NR_execveat
                                   : __NR_execve,
                     arguments);
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallExecRecovered;
}

uint64_t PathCloneFlags(const TaskRecord* parent, uint32_t event_code,
                        pid_t child_tgid) noexcept {
    if (event_code == PTRACE_EVENT_FORK ||
        event_code == PTRACE_EVENT_VFORK) {
        return 0;
    }
    if (parent != nullptr &&
        (parent->active_syscall.flags &
         hookself::tracer::kActiveSyscallValid) != 0) {
        if (parent->active_syscall.syscall_number == __NR_clone) {
            return parent->active_syscall.arguments[0];
        }
#ifdef __NR_clone3
        if (parent->active_syscall.syscall_number == __NR_clone3 &&
            parent->active_syscall.arguments[0] != 0 &&
            parent->active_syscall.arguments[1] >= sizeof(uint64_t)) {
            uint64_t flags = 0;
            if (ReadRemoteBytes(
                        parent->tgid, parent->tid,
                        static_cast<uintptr_t>(
                                parent->active_syscall.arguments[0]),
                        &flags, sizeof(flags)) == 0) {
                return flags;
            }
        }
#endif
    }
    return parent != nullptr && child_tgid == parent->tgid
                   ? hookself::tracer::kPathCloneFs |
                             hookself::tracer::kPathCloneFiles
                   : 0;
}

int ClonePathStateForEvent(TracerContext* context, const TaskRecord* parent,
                           const TaskRecord* child,
                           uint32_t event_code) noexcept {
    if (context == nullptr || context->path_state == nullptr ||
        parent == nullptr || child == nullptr) {
        return EINVAL;
    }
    if (hookself::tracer::FindPathTask(
                context->path_state, child->tid) != nullptr) {
        return 0;
    }
    if (hookself::tracer::FindPathTask(
                context->path_state, parent->tid) == nullptr) {
        // AttachAllTasks can observe a clone event before the initial task
        // snapshot has been converted into path state. The complete stopped
        // task set is initialized transactionally after attach converges.
        return 0;
    }
    const uint64_t flags = PathCloneFlags(
            parent, event_code, child->tgid);
    return hookself::tracer::ClonePathTask(
            context->path_state, parent->tid, child->tid, flags);
}

void RemovePathTaskState(TracerContext* context, pid_t tid) noexcept {
    if (context == nullptr || context->path_state == nullptr || tid <= 0 ||
        hookself::tracer::FindPathTask(context->path_state, tid) == nullptr) {
        return;
    }
    (void)hookself::tracer::RemovePathTask(context->path_state, tid);
}

int GetEventTask(TracerContext* context, TaskRecord* parent,
                  uint32_t event_code) noexcept {
    if (event_code != PTRACE_EVENT_CLONE && event_code != PTRACE_EVENT_FORK &&
        event_code != PTRACE_EVENT_VFORK) {
        return 0;
    }
    unsigned long message = 0;
    const int ptrace_error = ReadEventMessage(parent->tid, &message);
    if (ptrace_error != 0 || message == 0 || message > INT32_MAX) {
        NoteFailure(context, FatalStage::kEventMessage, parent->tid);
        return ptrace_error != 0 ? ptrace_error : EPROTO;
    }
    const pid_t tid = static_cast<pid_t>(message);
    const pid_t tgid = ResolveTaskTgid(
            context, tid, event_code, parent->tgid);
    TaskRecord* child = hookself::tracer::Find(context->tasks, tid);
    const bool already_tracked = child != nullptr;
    if (child != nullptr) {
        if (child->tgid != tgid &&
            (child->flags &
             hookself::tracer::kTaskFlagIdentityProvisional) == 0) {
            NoteFailure(context, FatalStage::kTaskIdentity, tid);
            return EPROTO;
        }
        child->tgid = tgid;
        child->flags &=
                ~hookself::tracer::kTaskFlagIdentityProvisional;
    } else {
        int insert_error = 0;
        child = InsertTask(context, tid, tgid, true, &insert_error);
        if (child == nullptr) {
            NoteFailure(context, FatalStage::kTaskIdentity, tid);
            return insert_error;
        }
    }
    if (!already_tracked) {
        child->life = TaskLifeState::kAttaching;
    }
    if (parent->exec_generation > child->exec_generation) {
        child->exec_generation = parent->exec_generation;
    }
    child->tracee_scratch_address = parent->tracee_scratch_address;
    const int path_state_error = ClonePathStateForEvent(
            context, parent, child, event_code);
    if (path_state_error != 0) {
        NoteFailure(context, FatalStage::kTaskIdentity, tid);
        return path_state_error;
    }
    const int nested_error = RegisterNestedPtraceTask(context, child, parent);
    if (nested_error != 0) {
        NoteFailure(context, FatalStage::kTaskIdentity, tid);
        return nested_error;
    }
    const bool awaiting_parent =
            (child->flags &
             hookself::tracer::kTaskFlagAwaitingParentEvent) != 0;
    child->flags &= ~hookself::tracer::kTaskFlagAwaitingParentEvent;
    EmitProcessEvent(context, *child, HOOKSELF_EVENT_F_NEW_TASK, event_code);
    if (awaiting_parent && context->runtime_started && !context->quiescing &&
        child->life == TaskLifeState::kStopped) {
        const int resume_error = ResumeTask(context, child);
        if (resume_error != 0) {
            NoteFailure(context, FatalStage::kResume, tid);
            return resume_error;
        }
    }
    return 0;
}

int MigrateExecTask(TracerContext* context, pid_t tid,
                    TaskRecord** task, bool* recovered) noexcept {
    if (recovered != nullptr) {
        *recovered = false;
    }
    // GETEVENTMSG is per-stop data. Do not carry a prior exec's message into
    // an Android-kernel fallback where the current message is unavailable.
    if (task != nullptr && *task != nullptr) {
        (*task)->last_ptrace_event_message = 0;
    }
    unsigned long message = 0;
    const int ptrace_error = ReadEventMessage(tid, &message);
    if (ptrace_error == 0 && task != nullptr && *task != nullptr) {
        (*task)->last_ptrace_event_message = message;
    }
    // Some Android kernels transiently deny GETEVENTMSG after exec de-thread
    // has replaced the former leader. The unique active-exec scan below is
    // the same identity-safe recovery used when that task already vanished.
    if (ptrace_error != 0 && ptrace_error != ESRCH &&
        ptrace_error != EACCES) {
        NoteFailure(context, FatalStage::kExecMigration, tid);
        return ptrace_error;
    }
    if (ptrace_error == 0 &&
        (message == 0 || message == static_cast<unsigned long>(tid))) {
        return 0;
    }
    if ((ptrace_error == 0 && message > INT32_MAX) ||
        task == nullptr || *task == nullptr) {
        NoteFailure(context, FatalStage::kExecMigration, tid);
        return EPROTO;
    }

    TaskRecord* former = ptrace_error == 0
                                 ? hookself::tracer::Find(
                                           context->tasks,
                                           static_cast<pid_t>(message))
                                 : nullptr;
    const bool found_by_message = former != nullptr;
    if (former == nullptr) {
        TaskRecord* candidate = nullptr;
        for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
            TaskRecord* current = hookself::tracer::At(context->tasks, slot);
            if (current == nullptr || current == *task ||
                current->tgid != tid || !HasActiveExecSyscall(current)) {
                continue;
            }
            if (candidate != nullptr) {
                NoteFailure(context, FatalStage::kExecMigration, tid);
                return EPROTO;
            }
            candidate = current;
        }
        former = candidate;
    }

    if (former != nullptr && former != *task) {
        const uint32_t destination_slot = (*task)->slot;
        const uint32_t former_slot = former->slot;
        if (context->path_state != nullptr) {
            const int path_migration_error =
                    hookself::tracer::MigrateExecPathTask(
                            context->path_state, former->tid, tid);
            if (path_migration_error != 0) {
                NoteFailure(context, FatalStage::kExecMigration, tid);
                return path_migration_error;
            }
        }
        const int nested_migration_error = MergeNestedPtraceExecTask(
                context, former, *task);
        if (nested_migration_error != 0) {
            NoteFailure(context, FatalStage::kExecMigration, tid);
            return nested_migration_error;
        }
        DiscardTaskMutation(context, *task, true);
        DiscardTaskMutation(context, former, false);
        TaskRecord migrated = *former;
        migrated.last_ptrace_event_message =
                ptrace_error == 0 ? message : 0;
        if (!hookself::tracer::EraseAt(context->tasks, former_slot)) {
            NoteFailure(context, FatalStage::kExecMigration, tid);
            return EPROTO;
        }
        migrated.slot = destination_slot;
        migrated.tid = tid;
        migrated.tgid = tid;
        migrated.occupied = 1;
        migrated.flags &=
                ~(hookself::tracer::kTaskFlagExecTombstone |
                  hookself::tracer::kTaskFlagIdentityProvisional |
                  hookself::tracer::kTaskFlagAwaitingParentEvent);
        *(*task) = migrated;
        UpdateTrackedTasks(context);
        if (recovered != nullptr &&
            (ptrace_error != 0 || !found_by_message)) {
            *recovered = true;
        }
        return 0;
    }

    const int32_t syscall_number =
            HasActiveExecSyscall(*task)
                    ? (*task)->active_syscall.syscall_number
                    : __NR_execve;
    DiscardTaskMutation(context, *task, true);
    SynthesizeExecSnapshot(*task, syscall_number);
    if (recovered != nullptr) {
        *recovered = true;
    }
    return 0;
}

int ApplyWaitStatus(TracerContext* context, pid_t tid, int status,
                    TaskRecord** stopped_task, StopEvent* decoded) noexcept {
    *stopped_task = nullptr;
    TaskRecord* task = hookself::tracer::Find(context->tasks, tid);
    bool inserted_unknown = false;
    if (task == nullptr) {
        pid_t tgid = 0;
        const bool provisional =
                hookself::platform::ReadTaskTgid(tid, &tgid) != 0;
        if (provisional) {
            tgid = tid;
        }
        int insert_error = 0;
        task = InsertTask(context, tid, tgid, true, &insert_error);
        if (task == nullptr) {
            NoteFailure(context, FatalStage::kTaskIdentity, tid);
            return insert_error;
        }
        inserted_unknown = true;
        if (provisional) {
            task->flags |=
                    hookself::tracer::kTaskFlagIdentityProvisional;
        }
    }

    const StopEvent event = DecodeStatus(tid, status, task->ptrace_options);
    *decoded = event;
    if (event.kind == StopEventKind::kExited ||
        event.kind == StopEventKind::kSignaled) {
        if (task->tid != task->tgid && HasActiveExecSyscall(task)) {
            DiscardTaskMutation(context, task, false);
            task->life = TaskLifeState::kDead;
            task->stop = TaskStopState::kNone;
            task->pending_signal = 0;
            task->flags |= hookself::tracer::kTaskFlagExecTombstone;
            return 0;
        }
        const int nested_terminal_error = PublishNestedPtraceTerminal(
                context, task, event);
        if (nested_terminal_error != 0) {
            return nested_terminal_error;
        }
        EmitProcessEvent(context, *task, HOOKSELF_EVENT_F_EXIT, 0);
        const pid_t exited_tgid = task->tgid;
        const bool group_leader_exited = task->tid == task->tgid;
        DiscardTaskMutation(context, task, true);
        RemovePathTaskState(context, tid);
        (void)hookself::tracer::Erase(context->tasks, tid);
        if (group_leader_exited) {
            for (uint32_t slot = 0;
                 slot < hookself::tracer::Capacity(); ++slot) {
                TaskRecord* remaining = hookself::tracer::At(
                        context->tasks, slot);
                if (remaining == nullptr || remaining->tgid != exited_tgid ||
                    (remaining->flags &
                     hookself::tracer::kTaskFlagExecTombstone) == 0) {
                    continue;
                }
                DiscardTaskMutation(context, remaining, true);
                RemovePathTaskState(context, remaining->tid);
                (void)hookself::tracer::EraseAt(context->tasks, slot);
            }
        }
        UpdateTrackedTasks(context);
        return 0;
    }
    if (event.kind == StopEventKind::kUnknown) {
        return EPROTO;
    }

    if (event.kind == StopEventKind::kPtraceEvent &&
        event.ptrace_event == PTRACE_EVENT_EXEC) {
        bool recovered = false;
        const int migration_error = MigrateExecTask(
                context, tid, &task, &recovered);
        if (migration_error != 0) {
            return migration_error;
        }
        DiscardTaskMutation(context, task, false);
        if (!HasActiveExecSyscall(task)) {
            SynthesizeExecSnapshot(task, __NR_execve);
            recovered = true;
        }
        if (recovered) {
            task->active_syscall.flags |=
                    hookself::tracer::kActiveSyscallExecRecovered;
        }
        if (context->path_state != nullptr) {
            const int path_exec_error = hookself::tracer::ExecPathTask(
                    context->path_state, task->tid);
            if (path_exec_error != 0) {
                NoteFailure(context, FatalStage::kExecMigration, tid);
                return path_exec_error;
            }
        }
    }

    SetStoppedState(task, event, status);
    if (!context->selective_requested &&
        (task->flags & hookself::tracer::kTaskFlagAutoAttached) != 0 &&
        task->stop_sequence == 1) {
        InitializeFallbackSyscallPhase(task);
    }
    if (inserted_unknown && event.kind == StopEventKind::kPtraceEvent &&
        event.ptrace_event == PTRACE_EVENT_STOP) {
        task->flags |=
                hookself::tracer::kTaskFlagAwaitingParentEvent;
    }
    *stopped_task = task;
    if (event.kind == StopEventKind::kPtraceEvent) {
        const int child_error = GetEventTask(context, task, event.ptrace_event);
        if (child_error != 0) {
            return child_error;
        }
        if (event.ptrace_event == PTRACE_EVENT_EXEC) {
            ++task->exec_generation;
            task->life = TaskLifeState::kExecReinit;
            if (context->selective_mode) {
                task->active_syscall.flags |=
                        hookself::tracer::kActiveSyscallFromSeccomp |
                        hookself::tracer::kActiveSyscallNeedsExit;
                task->resume_mode = TaskResumeMode::kSyscall;
            }
            task->syscall_phase =
                    (task->active_syscall.flags &
                     hookself::tracer::kActiveSyscallValid) != 0
                            ? TaskSyscallPhase::kExpectExit
                            : TaskSyscallPhase::kExpectEntry;
            const uint32_t exec_flags =
                    HOOKSELF_EVENT_F_EXEC |
                    ((task->active_syscall.flags &
                      hookself::tracer::kActiveSyscallExecRecovered) != 0
                             ? HOOKSELF_EVENT_F_EXEC_RECOVERED
                             : 0);
            EmitProcessEvent(context, *task, exec_flags,
                             event.ptrace_event);
        } else if (event.ptrace_event == PTRACE_EVENT_EXIT) {
            if (context->selective_mode) {
                DiscardTaskMutation(context, task, true);
                task->syscall_phase = TaskSyscallPhase::kExpectEntry;
                task->resume_mode = TaskResumeMode::kCont;
            }
            task->life = TaskLifeState::kExiting;
        }
    }
    return 0;
}

bool AllSeizedTasksStopped(const TracerContext& context) noexcept {
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* task = hookself::tracer::At(context.tasks, slot);
        if (task != nullptr &&
            (task->flags & hookself::tracer::kTaskFlagSeized) != 0 &&
            task->life != TaskLifeState::kStopped &&
            task->life != TaskLifeState::kExecReinit &&
            task->life != TaskLifeState::kExiting) {
            return false;
        }
    }
    return true;
}

int DrainUntilAllStopped(TracerContext* context, int64_t deadline_ms) noexcept {
    for (;;) {
        bool received = false;
        for (;;) {
            int status = 0;
            const long waited = hookself::platform::RawWait4(
                    -1, &status, kWaitWall | WNOHANG);
            if (waited == 0 || RawError(waited) == ECHILD) {
                break;
            }
            if (waited < 0) {
                if (RawError(waited) == EINTR) {
                    continue;
                }
                return RawError(waited);
            }
            received = true;
            TaskRecord* stopped = nullptr;
            StopEvent event{};
            const int apply_error = ApplyWaitStatus(
                    context, static_cast<pid_t>(waited), status, &stopped, &event);
            if (apply_error != 0) {
                return apply_error;
            }
        }
        if (AllSeizedTasksStopped(*context)) {
            return 0;
        }
        const int64_t now = hookself::platform::RawNowMs();
        if (now < 0 || now >= deadline_ms) {
            return ETIMEDOUT;
        }
        if (!received) {
            hookself::platform::RawSleepOneMillisecond();
        }
    }
}

bool CurrentCoverageComplete(TracerContext* context, const pid_t* tids,
                             size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        const TaskRecord* task = hookself::tracer::Find(context->tasks, tids[i]);
        if (task == nullptr ||
            (task->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
            (task->life != TaskLifeState::kStopped &&
             task->life != TaskLifeState::kExecReinit &&
             task->life != TaskLifeState::kExiting)) {
            return false;
        }
    }
    return true;
}

int AttachAllTasks(TracerContext* context) noexcept {
    pid_t tids[hookself::tracer::kTaskTableCapacity];
    int stable_rounds = 0;
    const int64_t deadline = hookself::platform::RawNowMs() + kAttachTimeoutMs;
    for (int round = 0; round < kMaxAttachRounds; ++round) {
        for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
            TaskRecord* task = hookself::tracer::At(context->tasks, slot);
            if (task != nullptr) {
                task->flags &= ~hookself::tracer::kTaskFlagSeenInScan;
            }
        }

        size_t tid_count = 0;
        const int enumerate_error = hookself::platform::EnumerateTaskTids(
                context->target_pid, tids, hookself::tracer::Capacity(), &tid_count);
        if (enumerate_error != 0) {
            return enumerate_error;
        }
        int new_tasks = 0;
        for (size_t i = 0; i < tid_count; ++i) {
            int insert_error = 0;
            TaskRecord* task = InsertTask(context, tids[i], context->target_pid,
                                          false, &insert_error);
            if (task == nullptr) {
                return insert_error;
            }
            if ((task->flags & hookself::tracer::kTaskFlagSeized) == 0) {
                const long result = RawPtrace(PTRACE_SEIZE, task->tid, 0,
                                              context->ptrace_options);
                const int seize_error = RawError(result);
                if (seize_error != 0) {
                    if (seize_error == ESRCH) {
                        (void)hookself::tracer::Erase(context->tasks, task->tid);
                        UpdateTrackedTasks(context);
                        continue;
                    }
                    return seize_error;
                }
                task->flags |= hookself::tracer::kTaskFlagSeized |
                               hookself::tracer::kTaskFlagNeedsDetach |
                               hookself::tracer::kTaskFlagOptionsApplied;
                task->life = TaskLifeState::kAttaching;
                ++new_tasks;
            }
            task->flags |= hookself::tracer::kTaskFlagSeenInScan;
        }

        for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
            TaskRecord* task = hookself::tracer::At(context->tasks, slot);
            if (task == nullptr ||
                (task->flags & hookself::tracer::kTaskFlagSeized) == 0 ||
                task->life == TaskLifeState::kStopped ||
                task->life == TaskLifeState::kExecReinit ||
                task->life == TaskLifeState::kExiting ||
                (task->flags & hookself::tracer::kTaskFlagInterruptSent) != 0) {
                continue;
            }
            const int interrupt_error = RawError(
                    RawPtrace(PTRACE_INTERRUPT, task->tid, 0, 0));
            if (interrupt_error == ESRCH) {
                (void)hookself::tracer::Erase(context->tasks, task->tid);
                UpdateTrackedTasks(context);
                continue;
            }
            if (interrupt_error != 0) {
                return interrupt_error;
            }
            task->flags |= hookself::tracer::kTaskFlagInterruptSent;
        }

        const int wait_error = DrainUntilAllStopped(context, deadline);
        if (wait_error != 0) {
            return wait_error;
        }
        if (new_tasks == 0 && CurrentCoverageComplete(context, tids, tid_count)) {
            if (++stable_rounds >= 2) {
                return 0;
            }
        } else {
            stable_rounds = 0;
        }
        if (hookself::platform::RawNowMs() >= deadline) {
            return ETIMEDOUT;
        }
    }
    return EAGAIN;
}

