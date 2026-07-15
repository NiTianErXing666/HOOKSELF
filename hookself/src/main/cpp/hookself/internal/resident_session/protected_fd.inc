void StoreProtectedFdIdentity(ProtectedFdIdentity* identity, int32_t fd,
                              const struct stat& value) noexcept {
    if (identity == nullptr || fd < 0) {
        return;
    }
    identity->fd = fd;
    identity->device = static_cast<uint64_t>(value.st_dev);
    identity->inode = static_cast<uint64_t>(value.st_ino);
    identity->rdev = static_cast<uint64_t>(value.st_rdev);
    identity->type = static_cast<uint32_t>(value.st_mode & S_IFMT);
    identity->valid = 1;
}

bool ProtectedFdIdentityMatches(const ProtectedFdIdentity& identity,
                                const struct stat& value) noexcept {
    return identity.valid != 0 &&
           identity.device == static_cast<uint64_t>(value.st_dev) &&
           identity.inode == static_cast<uint64_t>(value.st_ino) &&
           identity.rdev == static_cast<uint64_t>(value.st_rdev) &&
           identity.type == static_cast<uint32_t>(value.st_mode & S_IFMT);
}

ProtectedFdIdentity* FindProtectedFdIdentity(TracerContext* context,
                                             int32_t fd) noexcept {
    if (context == nullptr || fd < 0) {
        return nullptr;
    }
    for (uint32_t index = 0; index < kMaxProtectedFds; ++index) {
        ProtectedFdIdentity* identity =
                &context->protected_fd_identities[index];
        if (identity->valid != 0 && identity->fd == fd) {
            return identity;
        }
    }
    return nullptr;
}

void ClearProtectedFdIdentities(TracerContext* context) noexcept {
    if (context == nullptr) {
        return;
    }
    for (uint32_t index = 0; index < kMaxProtectedFds; ++index) {
        context->protected_fd_identities[index] = {};
        context->protected_fd_identities[index].fd = -1;
    }
}

void SynchronizeProtectedFdIdentityGeneration(
        TracerContext* context) noexcept {
    if (context == nullptr || context->control == nullptr) {
        return;
    }
    const uint64_t generation = __atomic_load_n(
            &context->control->protected_fd_registry_generation,
            __ATOMIC_ACQUIRE);
    if (generation == context->protected_fd_registry_generation) {
        return;
    }
    ClearProtectedFdIdentities(context);
    context->protected_fd_registry_generation = generation;
}

int ReadTraceeFdStat(const TaskRecord* task, int32_t fd,
                     struct stat* output) noexcept {
    if (task == nullptr || task->tid <= 0 || fd < 0 || output == nullptr) {
        return EINVAL;
    }
    char path[96]{};
    const int path_error = BuildProcFdEntryPath(
            task->tid, fd, false, path, sizeof(path));
    if (path_error != 0) {
        return path_error;
    }
    const long result = RawSyscall6(
            __NR_newfstatat, AT_FDCWD, reinterpret_cast<long>(path),
            reinterpret_cast<long>(output), 0);
    return RawError(result);
}

bool IsProtectedFdRegistered(const TracerContext* context, int32_t fd) noexcept {
    if (context == nullptr || context->control == nullptr || fd < 0) {
        return false;
    }
    const uint32_t count = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (context->control->protected_fds[index] == fd) {
            return true;
        }
    }
    return false;
}

ProtectedFdIdentity* CaptureTraceeProtectedFdIdentity(
        TracerContext* context, const TaskRecord* task, int32_t fd) noexcept {
    SynchronizeProtectedFdIdentityGeneration(context);
    if (!IsProtectedFdRegistered(context, fd)) {
        return nullptr;
    }
    ProtectedFdIdentity* existing = FindProtectedFdIdentity(context, fd);
    if (existing != nullptr) {
        return existing;
    }
    struct stat value {};
    if (ReadTraceeFdStat(task, fd, &value) != 0) {
        return nullptr;
    }
    for (uint32_t index = 0; index < kMaxProtectedFds; ++index) {
        ProtectedFdIdentity* identity =
                &context->protected_fd_identities[index];
        if (identity->valid == 0) {
            StoreProtectedFdIdentity(identity, fd, value);
            return identity;
        }
    }
    return nullptr;
}

void RefreshProtectedFdIdentityFromTask(TracerContext* context,
                                        const TaskRecord* task,
                                        int32_t fd) noexcept {
    SynchronizeProtectedFdIdentityGeneration(context);
    if (!IsProtectedFdRegistered(context, fd)) {
        return;
    }
    struct stat value {};
    if (ReadTraceeFdStat(task, fd, &value) != 0) {
        return;
    }
    ProtectedFdIdentity* identity = FindProtectedFdIdentity(context, fd);
    if (identity == nullptr) {
        for (uint32_t index = 0; index < kMaxProtectedFds; ++index) {
            if (context->protected_fd_identities[index].valid == 0) {
                identity = &context->protected_fd_identities[index];
                break;
            }
        }
    }
    if (identity != nullptr) {
        StoreProtectedFdIdentity(identity, fd, value);
    }
}

bool IsProtectedFdForTask(TracerContext* context, const TaskRecord* task,
                          int32_t fd) noexcept {
    ProtectedFdIdentity* identity = CaptureTraceeProtectedFdIdentity(
            context, task, fd);
    if (identity == nullptr) {
        return false;
    }
    struct stat current {};
    return ReadTraceeFdStat(task, fd, &current) == 0 &&
           ProtectedFdIdentityMatches(*identity, current);
}

void InitializeProtectedFdIdentities(TracerContext* context) noexcept {
    if (context == nullptr || context->control == nullptr) {
        return;
    }
    ClearProtectedFdIdentities(context);
    context->protected_fd_registry_generation = __atomic_load_n(
            &context->control->protected_fd_registry_generation,
            __ATOMIC_ACQUIRE);
    const uint32_t count = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return;
    }
    for (uint32_t index = 0; index < count; ++index) {
        const int32_t fd = context->control->protected_fds[index];
        if (fd < 0) {
            continue;
        }
        struct stat value {};
        if (fstat(fd, &value) == 0) {
            StoreProtectedFdIdentity(
                    &context->protected_fd_identities[index], fd, value);
        }
    }
}

bool ProtectedFdRegistered(const SharedControlPage* control,
                           int32_t fd) noexcept {
    if (control == nullptr || fd < 0) {
        return false;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (control->protected_fds[i] == fd) {
            return true;
        }
    }
    return false;
}

int RemoveProtectedFd(SharedControlPage* control, int32_t fd) noexcept {
    if (control == nullptr || fd < 0) {
        return EINVAL;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count == 0U || count > kMaxProtectedFds) {
        return EPROTO;
    }
    uint32_t index = count;
    for (uint32_t i = 0; i < count; ++i) {
        if (control->protected_fds[i] == fd) {
            index = i;
            break;
        }
    }
    if (index == count) {
        return EPROTO;
    }
    for (uint32_t i = index + 1U; i < count; ++i) {
        control->protected_fds[i - 1U] = control->protected_fds[i];
    }
    control->protected_fds[count - 1U] = -1;
    __atomic_store_n(&control->protected_fd_count, count - 1U,
                     __ATOMIC_RELEASE);
    PublishProtectedFdRegistryMutation(control);
    return 0;
}

uint32_t CollectProtectedFdsForTask(TracerContext* context,
                                    const TaskRecord* task, uint32_t first,
                                    uint32_t last, int32_t output[],
                                    uint32_t output_capacity) noexcept {
    if (context == nullptr || task == nullptr || output == nullptr) {
        return 0;
    }
    const uint32_t count = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return 0;
    }
    uint32_t written = 0;
    for (uint32_t index = 0; index < count; ++index) {
        const int32_t fd = context->control->protected_fds[index];
        if (fd < 0 || static_cast<uint32_t>(fd) < first ||
            static_cast<uint32_t>(fd) > last ||
            !IsProtectedFdForTask(context, task, fd)) {
            continue;
        }
        if (written == output_capacity) {
            return 0;
        }
        output[written++] = fd;
    }
    return written;
}

bool ProtectedFdInRangeForTask(TracerContext* context,
                               const TaskRecord* task, uint32_t first,
                               uint32_t last) noexcept {
    int32_t protected_fds[kMaxProtectedFds]{};
    return CollectProtectedFdsForTask(context, task, first, last,
                                      protected_fds, kMaxProtectedFds) != 0;
}

bool ClaimInternalDup3(TracerContext* context, TaskRecord* task,
                       int32_t source_fd, int32_t target_fd,
                       uint32_t flags) noexcept {
    SharedFdOperation* operation = &context->control->fd_operation;
    if (__atomic_load_n(&operation->state, __ATOMIC_ACQUIRE) !=
        static_cast<uint32_t>(SharedFdOperationState::kPending)) {
        return false;
    }
    const uint64_t sequence = __atomic_load_n(
            &operation->request_sequence, __ATOMIC_ACQUIRE);
    if (sequence == 0 || operation->owner_tid != task->tid ||
        operation->opcode !=
                static_cast<int32_t>(SharedFdOperationCode::kDup3Replace) ||
        operation->source_fd != source_fd ||
        operation->target_fd != target_fd || operation->flags != flags) {
        return false;
    }
    uint32_t expected = static_cast<uint32_t>(
            SharedFdOperationState::kPending);
    if (!__atomic_compare_exchange_n(
                &operation->state, &expected,
                static_cast<uint32_t>(
                        SharedFdOperationState::kInFlight),
                false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return false;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallInternalFdOperation;
    task->active_syscall.internal_fd_sequence = sequence;
    return true;
}

int CompleteInternalFdOperation(TracerContext* context, TaskRecord* task,
                                int64_t result) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallInternalFdOperation) == 0) {
        return 0;
    }
    SharedFdOperation* operation = &context->control->fd_operation;
    const uint64_t sequence = task->active_syscall.internal_fd_sequence;
    if (sequence == 0 ||
        __atomic_load_n(&operation->state, __ATOMIC_ACQUIRE) !=
                static_cast<uint32_t>(
                        SharedFdOperationState::kInFlight) ||
        __atomic_load_n(&operation->request_sequence, __ATOMIC_ACQUIRE) !=
                sequence || operation->owner_tid != task->tid) {
        return EPROTO;
    }
    const int32_t target_fd = operation->target_fd;
    __atomic_store_n(&operation->result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&operation->ack_sequence, sequence, __ATOMIC_RELEASE);
    __atomic_store_n(
            &operation->state,
            static_cast<uint32_t>(SharedFdOperationState::kComplete),
            __ATOMIC_RELEASE);
    __atomic_fetch_add(&context->control->internal_fd_operations, 1U,
                       __ATOMIC_RELAXED);
    if (result == target_fd) {
        RefreshProtectedFdIdentityFromTask(context, task, target_fd);
    }
    return 0;
}

int SuppressProtectedFdSyscall(TracerContext* context, TaskRecord* task,
                               int64_t replacement_result) noexcept {
    task->active_syscall.entry_policy_action = HOOKSELF_SYSCALL_DENY;
    task->active_syscall.entry_policy_rule_id =
            HOOKSELF_BUILTIN_RULE_PROTECTED_FD;
    task->active_syscall.replacement_result = replacement_result;
    const int error = SuppressSyscallWithHarmlessCall(task);
    if (error == 0) {
        EmitSyscallPolicyEvent(
                context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
                HOOKSELF_SYSCALL_DENY, HOOKSELF_BUILTIN_RULE_PROTECTED_FD, 0);
        __atomic_fetch_add(&context->control->protected_fd_blocks, 1U,
                           __ATOMIC_RELAXED);
    }
    return error;
}

PendingPathIdentity* PendingPathForTask(TracerContext* context,
                                        const TaskRecord* task) noexcept {
    return context == nullptr || context->pending_paths == nullptr ||
                   task == nullptr ||
                   task->slot >= hookself::tracer::Capacity()
                   ? nullptr
                   : &context->pending_paths->entries[task->slot];
}

int InstallCloseRangeReplaySegment(
        TaskRecord* task,
        const hookself::tracer::CloseRangeReplaySegment& segment,
        bool rewind_syscall) noexcept {
    if (task == nullptr || segment.first > segment.last ||
        (segment.flags & ~hookself::tracer::kCloseRangeReplayKnownFlags) != 0) {
        return EINVAL;
    }
    Arm64Regs current{};
    int error = hookself::arch::ReadRegisters(task->tid, &current);
    if (error != 0) {
        return error;
    }
    if (!rewind_syscall) {
        if (current.regs[0] != task->active_syscall.arguments[0] ||
            current.regs[1] != task->active_syscall.arguments[1] ||
            current.regs[2] != task->active_syscall.arguments[2]) {
            return EPROTO;
        }
        if ((task->active_syscall.flags &
             hookself::tracer::kActiveSyscallEntryRegistersValid) == 0) {
            SaveEntryRegisters(task, current);
        }
    } else {
        if (current.pc < sizeof(uint32_t)) {
            return EPROTO;
        }
        uint32_t instruction = 0;
        error = ReadRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(current.pc - sizeof(uint32_t)),
                &instruction, sizeof(instruction));
        constexpr uint32_t kArm64SvcZero = 0xd4000001U;
        if (error != 0 || instruction != kArm64SvcZero) {
            return error != 0 ? error : EPROTO;
        }
    }

    Arm64Regs modified = current;
    modified.regs[0] = segment.first;
    modified.regs[1] = segment.last;
    modified.regs[2] = segment.flags;
    modified.regs[8] = static_cast<uint64_t>(kSyscallCloseRange);
    if (rewind_syscall) {
        modified.pc -= sizeof(uint32_t);
    }
    error = hookself::arch::WriteRegisters(task->tid, &modified);
    if (error != 0) {
        return error;
    }
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || !hookself::arch::RegistersEqual(modified, verified)) {
        return error != 0 ? error : EIO;
    }
    task->active_syscall.modified_argument_mask |= 0x7U;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallArgumentsModified;
    return 0;
}

int BeginProtectedCloseRangeReplay(TracerContext* context, TaskRecord* task,
                                   bool* handled) noexcept {
    if (context == nullptr || task == nullptr || handled == nullptr) {
        return EINVAL;
    }
    *handled = false;
    PendingPathIdentity* pending = PendingPathForTask(context, task);
    if (pending == nullptr) {
        return EPROTO;
    }
    int32_t protected_fds[kMaxProtectedFds]{};
    const uint32_t count = CollectProtectedFdsForTask(
            context, task,
            static_cast<uint32_t>(task->active_syscall.arguments[0]),
            static_cast<uint32_t>(task->active_syscall.arguments[1]),
            protected_fds, kMaxProtectedFds);
    hookself::tracer::CloseRangeReplayDisposition disposition =
            hookself::tracer::CloseRangeReplayDisposition::kInvalid;
    const int error = hookself::tracer::PrepareCloseRangeReplay(
            static_cast<uint32_t>(task->active_syscall.arguments[0]),
            static_cast<uint32_t>(task->active_syscall.arguments[1]),
            static_cast<uint32_t>(task->active_syscall.arguments[2]),
            protected_fds, count,
            &pending->close_range_replay, &disposition);
    if (error != 0) {
        return error;
    }
    if (disposition !=
        hookself::tracer::CloseRangeReplayDisposition::kReplay) {
        return 0;
    }

    pending->flags |= kPendingPathCloseRangeReplay;
    hookself::tracer::CloseRangeReplaySegment segment{};
    bool has_segment = false;
    int segment_error = hookself::tracer::NextCloseRangeReplaySegment(
            &pending->close_range_replay, &segment, &has_segment);
    if (segment_error != 0) {
        return segment_error;
    }
    *handled = true;
    __atomic_fetch_add(&context->control->protected_fd_blocks, 1U,
                       __ATOMIC_RELAXED);
    if (!has_segment) {
        pending->flags |= kPendingPathCloseRangeSynthetic;
        const int path_error =
                hookself::tracer::CloseFdIdentityRangePreservingProtected(
                        context->path_state, task->tid,
                        pending->close_range_replay.original_first,
                        pending->close_range_replay.original_last,
                        pending->close_range_replay.original_flags);
        if (path_error != 0) {
            return path_error;
        }
        return SuppressProtectedFdSyscall(context, task, 0);
    }
    pending->replay_first = segment.first;
    pending->replay_last = segment.last;
    pending->replay_flags = segment.flags;
    pending->replay_sequence = segment.sequence;
    segment_error = InstallCloseRangeReplaySegment(task, segment, false);
    if (segment_error == 0) {
        EmitSyscallPolicyEvent(
                context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
                HOOKSELF_SYSCALL_REPLACE_ARGUMENT,
                HOOKSELF_BUILTIN_RULE_PROTECTED_FD, 0);
    }
    return segment_error;
}

int ContinueProtectedCloseRangeReplay(TracerContext* context,
                                      TaskRecord* task,
                                      int64_t kernel_result,
                                      bool* replay_scheduled) noexcept {
    if (replay_scheduled == nullptr) {
        return EINVAL;
    }
    *replay_scheduled = false;
    PendingPathIdentity* pending = PendingPathForTask(context, task);
    if (pending == nullptr ||
        (pending->flags & kPendingPathCloseRangeReplay) == 0 ||
        (pending->flags & kPendingPathCloseRangeSynthetic) != 0 ||
        kernel_result != 0) {
        return 0;
    }
    if (context == nullptr || context->path_state == nullptr ||
        task == nullptr || pending->replay_sequence == 0 ||
        pending->replay_sequence !=
                pending->close_range_replay.segment_count ||
        pending->replay_first > pending->replay_last ||
        (pending->replay_flags &
         ~hookself::tracer::kCloseRangeReplayKnownFlags) != 0 ||
        !hookself::tracer::IsCloseRangeReplayCursorValid(
                &pending->close_range_replay)) {
        return EPROTO;
    }
    int error = hookself::tracer::CloseFdIdentityRange(
            context->path_state, task->tid, pending->replay_first,
            pending->replay_last, pending->replay_flags);
    if (error != 0) {
        return error;
    }
    hookself::tracer::CloseRangeReplaySegment segment{};
    bool has_segment = false;
    error = hookself::tracer::NextCloseRangeReplaySegment(
            &pending->close_range_replay, &segment, &has_segment);
    if (error != 0) {
        return error;
    }
    if (!has_segment) {
        return hookself::tracer::CloseFdIdentityRangePreservingProtected(
                context->path_state, task->tid,
                pending->close_range_replay.original_first,
                pending->close_range_replay.original_last,
                pending->close_range_replay.original_flags);
    }
    error = InstallCloseRangeReplaySegment(task, segment, true);
    if (error != 0) {
        return error;
    }
    pending->replay_first = segment.first;
    pending->replay_last = segment.last;
    pending->replay_flags = segment.flags;
    pending->replay_sequence = segment.sequence;
    pending->flags |= kPendingPathCloseRangeAwaitEntry;
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    task->resume_mode = TaskResumeMode::kSyscall;
    *replay_scheduled = true;
    return 0;
}

int SuppressPtraceViewSyscall(TracerContext* context, TaskRecord* task,
                              int64_t replacement_result,
                              uint32_t rule_id) noexcept {
    const int error = SuppressSyscallWithHarmlessCall(task);
    if (error != 0) {
        return error;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallReplaceResult |
            hookself::tracer::kActiveSyscallPtraceView;
    task->active_syscall.exit_policy_rule_id = rule_id;
    task->active_syscall.replacement_result = replacement_result;
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
            HOOKSELF_SYSCALL_REPLACE_RESULT, rule_id, 0);
    __atomic_fetch_add(&context->control->ptrace_view_operations, 1U,
                       __ATOMIC_RELAXED);
    return 0;
}

int ApplyPtraceViewPolicy(TracerContext* context, TaskRecord* task,
                          bool* handled) noexcept {
    *handled = false;
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0) {
        return 0;
    }
    if (task->tgid != context->target_pid) {
        return 0;
    }
    const int32_t syscall_number = task->active_syscall.syscall_number;
    const uint64_t* arguments = task->active_syscall.arguments;
    if (syscall_number == __NR_ptrace &&
        arguments[0] == static_cast<uint64_t>(PTRACE_TRACEME)) {
        *handled = true;
        const bool already_logical =
                (task->flags &
                 hookself::tracer::kTaskFlagLogicalTraceme) != 0;
        const int error = SuppressPtraceViewSyscall(
                context, task, already_logical ? -EPERM : 0,
                HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME);
        if (error == 0 && !already_logical) {
            task->flags |= hookself::tracer::kTaskFlagLogicalTraceme;
        }
        return error;
    }
    if (syscall_number != __NR_prctl) {
        return 0;
    }
    const int32_t option = static_cast<int32_t>(arguments[0]);
    if (option == PR_GET_DUMPABLE) {
        *handled = true;
        const int32_t logical = __atomic_load_n(
                &context->control->ptrace_view_dumpable,
                __ATOMIC_ACQUIRE);
        return SuppressPtraceViewSyscall(
                context, task, logical,
                HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW);
    }
    if (option == PR_SET_DUMPABLE) {
        *handled = true;
        const uint64_t raw_value = arguments[1];
        const bool valid = raw_value == 0 || raw_value == 1;
        const int32_t value = static_cast<int32_t>(raw_value);
        const int error = SuppressPtraceViewSyscall(
                context, task, valid ? 0 : -EINVAL,
                HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW);
        if (error == 0 && valid) {
            __atomic_store_n(&context->control->ptrace_view_dumpable,
                             value, __ATOMIC_RELEASE);
        }
        return error;
    }
    if (option != kPrSetPtracer) {
        return 0;
    }
    *handled = true;
    const uint64_t raw_value = arguments[1];
    int32_t logical_value = 0;
    uint64_t logical_start_time = 0;
    bool valid = raw_value == 0;
    if (raw_value == kPrSetPtracerAny) {
        valid = true;
        logical_value = -1;
    } else if (raw_value > 0 && raw_value <= INT32_MAX) {
        logical_value = static_cast<int32_t>(raw_value);
        const int exists_error = RawError(
                RawSyscall6(__NR_kill, logical_value, 0));
        valid = exists_error == 0 || exists_error == EPERM;
        if (valid) {
            const int start_error =
                    hookself::platform::ReadProcessStartTime(
                            logical_value, &logical_start_time);
            if (start_error == ENOENT || start_error == ESRCH) {
                valid = false;
            } else if (start_error != 0) {
                logical_start_time = 0;
            }
        }
    }
    const int error = SuppressPtraceViewSyscall(
            context, task, valid ? 0 : -EINVAL,
            HOOKSELF_BUILTIN_RULE_PTRACER_VIEW);
    if (error == 0 && valid) {
        __atomic_store_n(
                &context->control->ptrace_view_ptracer_start_time,
                logical_start_time, __ATOMIC_RELEASE);
        __atomic_store_n(&context->control->ptrace_view_ptracer,
                         logical_value, __ATOMIC_RELEASE);
        __atomic_fetch_or(&context->control->ptrace_view_flags,
                          kPtraceViewPtracerTouched, __ATOMIC_RELEASE);
    }
    return error;
}

