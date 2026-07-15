int VerifyTraceeScratchFrame(const TracerContext* context,
                             const TaskRecord* task,
                             const SharedScratchFrame* frame,
                             uint32_t path_count) noexcept {
    if (context == nullptr || context->header == nullptr || task == nullptr ||
        frame == nullptr || path_count == 0 ||
        path_count > kScratchPathSlots ||
        task->slot >= hookself::tracer::Capacity()) {
        return EINVAL;
    }
    if (task->tracee_scratch_address == 0) {
        return ESTALE;
    }
    const uintptr_t remote_base =
            task->tracee_scratch_address +
            static_cast<uintptr_t>(task->slot) * sizeof(SharedScratchFrame);
    SharedScratchFrame observed{};
    const size_t prefix_size = offsetof(SharedScratchFrame, paths);
    int error = ReadRemoteBytes(task->tgid, task->tid, remote_base, &observed,
                                prefix_size);
    for (uint32_t slot = 0; error == 0 && slot < path_count; ++slot) {
        if (frame->path_lengths[slot] >= HOOKSELF_PATH_CAPACITY) {
            return EINVAL;
        }
        error = ReadRemoteBytes(
                task->tgid, task->tid,
                remote_base + offsetof(SharedScratchFrame, paths) +
                        static_cast<uintptr_t>(slot) * HOOKSELF_PATH_CAPACITY,
                observed.paths[slot],
                static_cast<size_t>(frame->path_lengths[slot]) + 1U);
    }
    if (error == 0) {
        error = ReadRemoteBytes(
                task->tgid, task->tid,
                remote_base + offsetof(SharedScratchFrame, guard_after),
                &observed.guard_after, sizeof(observed.guard_after));
    }
    if (error != 0) {
        return error;
    }
    if (observed.guard_before != frame->guard_before ||
        observed.guard_after != frame->guard_after ||
        observed.owner_tid != frame->owner_tid ||
        observed.state != frame->state ||
        observed.generation != frame->generation) {
        return ESTALE;
    }
    for (uint32_t slot = 0; slot < path_count; ++slot) {
        if (observed.path_lengths[slot] != frame->path_lengths[slot]) {
            return ESTALE;
        }
        for (size_t i = 0; i <= frame->path_lengths[slot]; ++i) {
            if (observed.paths[slot][i] != frame->paths[slot][i]) {
                return ESTALE;
            }
        }
    }
    return 0;
}

int RestorePathMutation(TracerContext* context, TaskRecord* task,
                        bool syscall_completed) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallRegistersModified) == 0) {
        return 0;
    }
    if (task->active_syscall.scratch_slot >= hookself::tracer::Capacity() ||
        context->writable_scratch == nullptr) {
        return EPROTO;
    }
    SharedScratchFrame* frame = &context->writable_scratch[
            task->active_syscall.scratch_slot];
    if (frame->guard_before != kScratchGuardBefore ||
        frame->guard_after != kScratchGuardAfter ||
        frame->owner_tid != task->tid ||
        frame->generation != task->active_syscall.scratch_generation) {
        return EIO;
    }

    Arm64Regs current{};
    int error = hookself::arch::ReadRegisters(task->tid, &current);
    if (error != 0) {
        return error;
    }
    Arm64Regs expected = current;
    const uint32_t argument_mask =
            task->active_syscall.modified_argument_mask;
    if (argument_mask == 0 || (argument_mask & ~0x3fU) != 0) {
        return EPROTO;
    }
    const uint32_t first_argument = syscall_completed ? 1U : 0U;
    for (uint32_t argument_index = first_argument;
         argument_index < 6; ++argument_index) {
        if ((argument_mask & (1U << argument_index)) != 0) {
            expected.regs[argument_index] =
                    task->active_syscall.arguments[argument_index];
        }
    }
    error = hookself::arch::WriteRegisters(task->tid, &expected);
    if (error != 0) {
        return error;
    }
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || !hookself::arch::RegistersEqual(expected, verified)) {
        return error != 0 ? error : EIO;
    }
    frame->state = 0;
    frame->owner_tid = 0;
    task->active_syscall.flags &=
            ~hookself::tracer::kActiveSyscallRegistersModified;
    task->active_syscall.modified_argument_mask = 0;
    return 0;
}

int RestoreEntryMutations(TracerContext* context, TaskRecord* task,
                          bool syscall_completed) noexcept {
    int error = RestorePathMutation(context, task, syscall_completed);
    if (error != 0) {
        return error;
    }
    error = RestoreGenericArgumentMutation(task, syscall_completed);
    if (error != 0) {
        return error;
    }
    return RestoreSyscallNumberMutation(task);
}

struct RedirectedOperand {
    PathOperandSpec spec;
    const SharedPathRuleDesc* rule;
    const SharedVirtualFileDesc* virtual_file;
    int32_t policy_action;
    int32_t policy_errno;
    uint32_t policy_id;
    uint32_t scratch_index;
    uint32_t pending_index;
    uint32_t origin_flags;
    size_t original_length;
    size_t canonical_length;
    size_t host_canonical_length;
    bool resolved_relative;
    bool empty_path;
    bool mount_translation;
    uint32_t event_flags;
    char original[HOOKSELF_PATH_CAPACITY];
    char canonical[HOOKSELF_PATH_CAPACITY];
    char host_canonical[HOOKSELF_PATH_CAPACITY];
};

int MaybeRedirectPaths(TracerContext* context, TaskRecord* task,
                       int32_t syscall_number,
                       const uint64_t arguments[6]) noexcept {
    const bool path_redirect_enabled =
            (context->control->config_flags &
             HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT) != 0;
    const bool virtual_files_enabled =
            (context->control->config_flags &
             HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES) != 0;
    const bool mount_resolution_enabled = context->path_state != nullptr;
    if (!path_redirect_enabled && !virtual_files_enabled &&
        !mount_resolution_enabled) {
        return 0;
    }

    PathOperandSpec operands[2]{};
    const size_t operand_count = PathOperandsForSyscall(
            syscall_number, arguments, operands);
    if (operand_count == 0) {
        return 0;
    }
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank == nullptr) {
        return EPROTO;
    }

    RedirectedOperand redirected[2]{};
    RedirectedOperand denied{};
    bool deny_selected = false;
    uint32_t redirect_count = 0;
    PendingPathIdentity* pending =
            context->pending_paths != nullptr &&
                    task->slot < hookself::tracer::Capacity()
                    ? &context->pending_paths->entries[task->slot]
                    : nullptr;
    if (pending != nullptr && syscall_number == __NR_openat) {
        pending->open_flags = arguments[2];
    }
    open_how how{};
    const bool open_how_valid = syscall_number == __NR_openat2 &&
                                ReadOpenAt2How(task, arguments, &how);
    if (open_how_valid) {
        operands[0].operations = OpenPathOperations(how.flags);
        if (pending != nullptr) {
            pending->open_flags = how.flags;
            pending->open_resolve = how.resolve;
        }
    }
    for (size_t operand_index = 0; operand_index < operand_count; ++operand_index) {
        const uint32_t argument_index = operands[operand_index].argument_index;
        if (argument_index >= 6) {
            continue;
        }
        RedirectedOperand candidate{};
        candidate.spec = operands[operand_index];
        uint32_t capture_flags = 0;
        const int read_error = ReadRemotePath(
                task->tgid, task->tid,
                static_cast<uintptr_t>(arguments[argument_index]),
                candidate.original, sizeof(candidate.original), &capture_flags);
        if (read_error != 0) {
            continue;
        }
        candidate.event_flags = capture_flags;
        candidate.original_length = BoundedLength(
                candidate.original, sizeof(candidate.original));
        if (candidate.original_length == sizeof(candidate.original)) {
            continue;
        }
        int resolve_error = 0;
        if (candidate.original_length == 0 &&
            EmptyPathAllowed(syscall_number, operand_index, arguments) &&
            candidate.spec.dirfd_argument_index >= 0) {
            const int32_t fd = static_cast<int32_t>(
                    arguments[candidate.spec.dirfd_argument_index]);
            resolve_error = ResolvePathBases(
                    context, task, bank, fd,
                    candidate.canonical, sizeof(candidate.canonical),
                    &candidate.canonical_length,
                    candidate.host_canonical,
                    sizeof(candidate.host_canonical),
                    &candidate.host_canonical_length,
                    &candidate.origin_flags);
            candidate.empty_path = resolve_error == 0;
        } else {
            resolve_error = UsesOpenAt2InRoot(
                                    syscall_number, open_how_valid, how)
                                    ? ResolvePolicyPathInRoot(
                                              context, task, bank, candidate.spec,
                                              arguments, candidate.original,
                                              candidate.original_length,
                                              candidate.canonical,
                                              sizeof(candidate.canonical),
                                              &candidate.canonical_length,
                                              candidate.host_canonical,
                                              sizeof(candidate.host_canonical),
                                              &candidate.host_canonical_length,
                                              &candidate.origin_flags,
                                              &candidate.resolved_relative)
                                    : ResolvePolicyPath(
                                              context, task, bank, candidate.spec,
                                              arguments, candidate.original,
                                              candidate.original_length,
                                              candidate.canonical,
                                              sizeof(candidate.canonical),
                                              &candidate.canonical_length,
                                              candidate.host_canonical,
                                              sizeof(candidate.host_canonical),
                                              &candidate.host_canonical_length,
                                              &candidate.origin_flags,
                                              &candidate.resolved_relative);
        }
        if (resolve_error != 0 ||
            !CanonicalAbsolutePath(candidate.canonical,
                                   candidate.canonical_length)) {
            continue;
        }
        candidate.pending_index = static_cast<uint32_t>(operand_index);
        if (pending != nullptr && operand_index < kScratchPathSlots) {
            pending->path_count = static_cast<uint32_t>(operand_index + 1U);
            pending->argument_indices[operand_index] = argument_index;
            pending->origin_flags[operand_index] = candidate.origin_flags;
            for (size_t index = 0; index <= candidate.canonical_length;
                 ++index) {
                pending->guest_paths[operand_index][index] =
                        candidate.canonical[index];
            }
            for (size_t index = 0;
                 index <= candidate.host_canonical_length; ++index) {
                pending->host_paths[operand_index][index] =
                        candidate.host_canonical[index];
            }
        }
        if (virtual_files_enabled) {
            candidate.virtual_file = SelectVirtualFile(
                    bank, candidate.canonical, candidate.canonical_length);
            if (candidate.virtual_file != nullptr &&
                candidate.virtual_file->provider >=
                        HOOKSELF_VFILE_PROC_STATUS &&
                task->tgid != context->target_pid) {
                candidate.virtual_file = nullptr;
            }
            if (candidate.virtual_file != nullptr) {
                if (candidate.virtual_file->target_fd < 0) {
                    return EBADF;
                }
                candidate.policy_id = candidate.virtual_file->file_id;
                if (!IsProtectedFdForTask(
                            context, task,
                            candidate.virtual_file->target_fd)) {
                    // The backing FD number was reused in this FD table.  Do
                    // not redirect a virtual path to an unrelated object.
                    candidate.policy_action = HOOKSELF_PATH_DENY;
                    candidate.policy_errno = ESTALE;
                    denied = candidate;
                    deny_selected = true;
                    break;
                }
                candidate.policy_errno = VirtualFileDenyErrno(
                        syscall_number, arguments, how.flags,
                        open_how_valid);
                candidate.policy_action = candidate.policy_errno == 0
                                                  ? HOOKSELF_PATH_VIRTUAL_FILE
                                                  : HOOKSELF_PATH_DENY;
                if (candidate.policy_errno != 0) {
                    denied = candidate;
                    deny_selected = true;
                    break;
                }
                if (candidate.empty_path) {
                    EmitPathPolicyEvent(
                            context, *task, syscall_number,
                            candidate.spec.argument_index,
                            HOOKSELF_PATH_VIRTUAL_FILE,
                            candidate.policy_id, 0, candidate.original,
                            candidate.host_canonical, candidate.event_flags);
                    __atomic_fetch_add(
                            &context->control->redirected_paths, 1U,
                            __ATOMIC_RELAXED);
                    continue;
                }
                candidate.scratch_index = redirect_count;
                redirected[redirect_count++] = candidate;
                continue;
            }
        }
        candidate.rule = path_redirect_enabled
                ? SelectPathRule(
                          bank, candidate.canonical,
                          candidate.canonical_length,
                          candidate.spec.operations)
                : nullptr;
        if (candidate.rule == nullptr ||
            candidate.rule->action == HOOKSELF_PATH_PASS) {
            if (!candidate.empty_path && mount_resolution_enabled) {
                hookself::tracer::MountPathTranslation mount{};
                const int mount_error = hookself::tracer::TranslateMountPath(
                        context->path_state, task->tid,
                        candidate.canonical, &mount);
                if (mount_error != 0) {
                    return mount_error;
                }
                if (mount.matched != 0) {
                    const size_t translated_length = BoundedLength(
                            mount.host_path, sizeof(mount.host_path));
                    if (translated_length >=
                        sizeof(candidate.host_canonical)) {
                        return ENAMETOOLONG;
                    }
                    const bool already_resolved = PathsEqual(
                            mount.host_path, translated_length,
                            candidate.host_canonical,
                            candidate.host_canonical_length);
                    for (size_t index = 0;
                         index <= translated_length; ++index) {
                        candidate.host_canonical[index] =
                                mount.host_path[index];
                    }
                    candidate.host_canonical_length = translated_length;
                    candidate.origin_flags |=
                            hookself::tracer::kPathOriginRedirected |
                            hookself::tracer::kPathOriginReverseVisible;
                    if (pending != nullptr &&
                        candidate.pending_index < kScratchPathSlots) {
                        const uint32_t pending_index =
                                candidate.pending_index;
                        for (size_t index = 0;
                             index <= translated_length; ++index) {
                            pending->host_paths[pending_index][index] =
                                    mount.host_path[index];
                        }
                        pending->origin_flags[pending_index] |=
                                hookself::tracer::kPathOriginRedirected |
                                hookself::tracer::kPathOriginReverseVisible;
                        pending->flags |= kPendingPathRedirected |
                                          kPendingPathReverseVisible;
                    }
                    if (!already_resolved) {
                        candidate.mount_translation = true;
                        candidate.policy_action = HOOKSELF_PATH_REDIRECT;
                        candidate.policy_id = 0;
                        candidate.scratch_index = redirect_count;
                        redirected[redirect_count++] = candidate;
                    }
                }
            }
            continue;
        }
        candidate.policy_action = candidate.rule->action;
        candidate.policy_errno = candidate.rule->deny_errno;
        candidate.policy_id = candidate.rule->rule_id;
        constexpr uint32_t kMutatingOperations =
                HOOKSELF_PATH_OP_WRITE | HOOKSELF_PATH_OP_CREATE |
                HOOKSELF_PATH_OP_DELETE | HOOKSELF_PATH_OP_RENAME |
                HOOKSELF_PATH_OP_METADATA;
        if ((candidate.rule->flags & HOOKSELF_PATH_RULE_READ_ONLY) != 0 &&
            (candidate.spec.operations & kMutatingOperations) != 0) {
            candidate.policy_action = HOOKSELF_PATH_DENY;
            candidate.policy_errno = EROFS;
        }
        if (candidate.policy_action == HOOKSELF_PATH_DENY) {
            denied = candidate;
            deny_selected = true;
            break;
        }
        if (candidate.rule->action != HOOKSELF_PATH_REDIRECT) {
            return ENOTSUP;
        }
        if (candidate.empty_path) {
            EmitPathPolicyEvent(
                    context, *task, syscall_number,
                    candidate.spec.argument_index,
                    HOOKSELF_PATH_REDIRECT, candidate.policy_id, 0,
                    candidate.original, candidate.host_canonical,
                    candidate.event_flags);
            __atomic_fetch_add(&context->control->redirected_paths, 1U,
                               __ATOMIC_RELAXED);
            continue;
        }
        const bool constrained_openat2 =
                syscall_number == __NR_openat2 && open_how_valid &&
                (how.resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) != 0;
        if (constrained_openat2 && candidate.resolved_relative) {
            char translated[HOOKSELF_PATH_CAPACITY]{};
            uint32_t translated_length = 0;
            if (TranslatePath(bank, *candidate.rule, candidate.canonical,
                              candidate.canonical_length, translated,
                              sizeof(translated), &translated_length) &&
                PathsEqual(translated, translated_length,
                           candidate.host_canonical,
                           candidate.host_canonical_length)) {
                if (pending != nullptr &&
                    candidate.pending_index < kScratchPathSlots) {
                    const uint32_t pending_index = candidate.pending_index;
                    pending->rule_ids[pending_index] = candidate.policy_id;
                    pending->origin_flags[pending_index] |=
                            hookself::tracer::kPathOriginRedirected;
                    pending->flags |= kPendingPathRedirected;
                    if ((candidate.rule->flags &
                         HOOKSELF_PATH_RULE_REVERSE_VISIBLE) != 0) {
                        pending->origin_flags[pending_index] |=
                                hookself::tracer::kPathOriginReverseVisible;
                        pending->flags |= kPendingPathReverseVisible;
                    }
                }
                EmitPathPolicyEvent(
                        context, *task, syscall_number,
                        candidate.spec.argument_index,
                        HOOKSELF_PATH_REDIRECT, candidate.policy_id, 0,
                        candidate.original, translated,
                        candidate.event_flags |
                                HOOKSELF_EVENT_F_PATH_RESOLVED_RELATIVE);
                __atomic_fetch_add(&context->control->redirected_paths, 1U,
                                   __ATOMIC_RELAXED);
                continue;
            }
        }
        candidate.scratch_index = redirect_count;
        redirected[redirect_count++] = candidate;
    }
    if (deny_selected) {
        task->active_syscall.entry_policy_action = HOOKSELF_SYSCALL_DENY;
        task->active_syscall.entry_policy_rule_id = denied.policy_id;
        task->active_syscall.replacement_result = -denied.policy_errno;
        const int deny_error = SuppressSyscallWithHarmlessCall(task);
        if (deny_error != 0) {
            return deny_error;
        }
        EmitPathPolicyEvent(
                context, *task, syscall_number, denied.spec.argument_index,
                HOOKSELF_PATH_DENY, denied.policy_id,
                denied.policy_errno, denied.original, nullptr,
                denied.event_flags |
                        (denied.resolved_relative
                                 ? HOOKSELF_EVENT_F_PATH_RESOLVED_RELATIVE
                                 : 0));
        return 0;
    }
    if (redirect_count == 0) {
        return 0;
    }
    if (context->writable_scratch == nullptr) {
        return ESTALE;
    }

    SharedScratchFrame* frame = &context->writable_scratch[task->slot];
    frame->guard_before = kScratchGuardBefore;
    frame->guard_after = kScratchGuardAfter;
    frame->owner_tid = task->tid;
    frame->state = 1;
    ++frame->generation;
    if (frame->generation == 0) {
        frame->generation = 1;
    }
    for (uint32_t slot = 0; slot < kScratchPathSlots; ++slot) {
        frame->path_lengths[slot] = 0;
        frame->paths[slot][0] = '\0';
    }
    frame->aux_length = redirect_count;
    for (uint32_t index = 0; index < redirect_count; ++index) {
        uint32_t translated_length = 0;
        bool translated = false;
        if (redirected[index].mount_translation) {
            translated_length = static_cast<uint32_t>(
                    redirected[index].host_canonical_length);
            if (translated_length + 1U <= sizeof(frame->paths[index])) {
                for (size_t offset = 0;
                     offset <= translated_length; ++offset) {
                    frame->paths[index][offset] =
                            redirected[index].host_canonical[offset];
                }
                translated = true;
            }
        } else if (redirected[index].virtual_file != nullptr) {
            translated = BuildVirtualFilePath(
                    bank, redirected[index].virtual_file,
                    frame->paths[index], sizeof(frame->paths[index]),
                    &translated_length);
        } else {
            translated = TranslatePath(
                    bank, *redirected[index].rule,
                    redirected[index].canonical,
                    redirected[index].canonical_length,
                    frame->paths[index], sizeof(frame->paths[index]),
                    &translated_length);
        }
        if (!translated) {
            frame->state = 0;
            frame->owner_tid = 0;
            return ENAMETOOLONG;
        }
        frame->path_lengths[index] = translated_length;
        frame->auxiliary[index] = static_cast<uint8_t>(
                redirected[index].spec.argument_index);
        if (pending != nullptr &&
            redirected[index].pending_index < kScratchPathSlots) {
            const uint32_t pending_index = redirected[index].pending_index;
            for (size_t offset = 0; offset <= translated_length; ++offset) {
                pending->host_paths[pending_index][offset] =
                        frame->paths[index][offset];
            }
            pending->rule_ids[pending_index] =
                    redirected[index].policy_id;
            pending->origin_flags[pending_index] |=
                    hookself::tracer::kPathOriginRedirected;
            pending->flags |= kPendingPathRedirected;
            if (redirected[index].rule != nullptr &&
                (redirected[index].rule->flags &
                 HOOKSELF_PATH_RULE_REVERSE_VISIBLE) != 0) {
                pending->origin_flags[pending_index] |=
                        hookself::tracer::kPathOriginReverseVisible;
                pending->flags |= kPendingPathReverseVisible;
            }
            if (redirected[index].mount_translation) {
                pending->origin_flags[pending_index] |=
                        hookself::tracer::kPathOriginReverseVisible;
                pending->flags |= kPendingPathReverseVisible;
            }
            if (redirected[index].virtual_file != nullptr) {
                pending->flags |= kPendingPathVirtual;
            }
        }
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    const int scratch_error = VerifyTraceeScratchFrame(
            context, task, frame, redirect_count);
    if (scratch_error != 0) {
        frame->state = 0;
        frame->owner_tid = 0;
        return scratch_error;
    }

    Arm64Regs registers{};
    int error = hookself::arch::ReadRegisters(task->tid, &registers);
    if (error != 0) {
        frame->state = 0;
        frame->owner_tid = 0;
        return error;
    }
    uint32_t argument_mask = 0;
    for (uint32_t index = 0; index < redirect_count; ++index) {
        const uint32_t argument_index =
                redirected[index].spec.argument_index;
        if (registers.regs[argument_index] != arguments[argument_index]) {
            frame->state = 0;
            frame->owner_tid = 0;
            return EPROTO;
        }
        argument_mask |= 1U << argument_index;
    }
    SaveEntryRegisters(task, registers);
    Arm64Regs modified = registers;
    if (task->tracee_scratch_address == 0) {
        frame->state = 0;
        frame->owner_tid = 0;
        return ESTALE;
    }
    const uint64_t remote_frame =
            task->tracee_scratch_address +
            static_cast<uint64_t>(task->slot) * sizeof(SharedScratchFrame);
    for (uint32_t index = 0; index < redirect_count; ++index) {
        modified.regs[redirected[index].spec.argument_index] =
                remote_frame + offsetof(SharedScratchFrame, paths) +
                static_cast<uint64_t>(index) * HOOKSELF_PATH_CAPACITY;
    }
    task->active_syscall.modified_argument_mask = argument_mask;
    error = hookself::arch::WriteRegisters(task->tid, &modified);
    if (error != 0) {
        frame->state = 0;
        frame->owner_tid = 0;
        task->active_syscall.modified_argument_mask = 0;
        return error;
    }
    task->active_syscall.scratch_slot = task->slot;
    task->active_syscall.scratch_generation = frame->generation;
    task->active_syscall.rule_generation = bank->generation;
    for (uint32_t index = 0; index < redirect_count; ++index) {
        if (redirected[index].virtual_file != nullptr &&
            (syscall_number == __NR_openat ||
             syscall_number == __NR_openat2)) {
            task->active_syscall.flags |=
                    hookself::tracer::kActiveSyscallVirtualFileOpen;
        }
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallRegistersModified;
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || !hookself::arch::RegistersEqual(modified, verified)) {
        const int rollback_error = RestorePathMutation(context, task, false);
        if (rollback_error != 0) {
            return EOWNERDEAD;
        }
        return error != 0 ? error : EIO;
    }

    for (uint32_t index = 0; index < redirect_count; ++index) {
        EmitPathPolicyEvent(
                context, *task, syscall_number,
                redirected[index].spec.argument_index,
                redirected[index].policy_action,
                redirected[index].policy_id,
                0, redirected[index].original, frame->paths[index],
                redirected[index].event_flags |
                        (redirected[index].resolved_relative
                        ? HOOKSELF_EVENT_F_PATH_RESOLVED_RELATIVE
                        : 0));
    }
    __atomic_fetch_add(&context->control->redirected_paths, redirect_count,
                       __ATOMIC_RELAXED);
    return 0;
}

void EmitSyscallEvent(TracerContext* context, TaskRecord* task,
                      int32_t syscall_number, uint32_t phase,
                      const uint64_t arguments[6], int64_t result,
                      uint32_t extra_flags) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallLogBypass) != 0) {
        return;
    }
    uint32_t rule_id = 0;
    if (!SelectObservationRule(context, syscall_number, phase, arguments,
                               &rule_id)) {
        return;
    }

    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_SYSCALL;
    event.tgid = task->tgid;
    event.tid = task->tid;
    event.syscall_number = syscall_number;
    event.phase = phase;
    event.action = HOOKSELF_SYSCALL_OBSERVE;
    event.rule_id = rule_id;
    event.flags = extra_flags;
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallNestedPtraceDispatch) != 0U) {
        event.flags |= HOOKSELF_EVENT_F_NESTED_PTRACE;
    }
    if ((context->control->config_flags & HOOKSELF_CONFIG_CAPTURE_ARGUMENTS) != 0) {
        for (size_t i = 0; i < 6; ++i) {
            event.arguments[i] = arguments[i];
        }
    }
    if (phase == HOOKSELF_SYSCALL_PHASE_EXIT &&
        (context->control->config_flags & HOOKSELF_CONFIG_CAPTURE_RESULTS) != 0) {
        event.result = result;
        if (result < 0 && result >= -4095) {
            event.error = static_cast<int32_t>(-result);
        }
    }
    if (phase == HOOKSELF_SYSCALL_PHASE_ENTRY &&
        (context->control->config_flags & HOOKSELF_CONFIG_CAPTURE_PATHS) != 0) {
        const int argument_index = PathArgumentIndex(syscall_number);
        if (argument_index >= 0) {
            const int path_error = ReadRemotePath(
                    task->tgid, task->tid,
                    static_cast<uintptr_t>(arguments[argument_index]), event.path,
                    sizeof(event.path), &event.flags);
            if (path_error != 0 && path_error != ENAMETOOLONG) {
                event.flags |= HOOKSELF_EVENT_F_PATH_CAPTURE_FAILED;
            }
        }
    }
    if (EmitEvent(context, &event)) {
        __atomic_fetch_add(&context->control->observed_syscalls, 1U,
                           __ATOMIC_RELAXED);
    }
}

bool IsKernelRestartResult(int64_t result) noexcept {
    return result == -512 || result == -513 || result == -514 ||
           result == -516;
}

bool ShouldBypassLogSyscall(const TracerContext* context,
                            const TaskRecord* task) noexcept {
    return __atomic_load_n(&context->control->log_bypass_active,
                           __ATOMIC_ACQUIRE) != 0 &&
           __atomic_load_n(&context->control->log_bypass_tid,
                           __ATOMIC_RELAXED) == task->tid;
}

bool ShouldBypassRuntimeApiSyscall(const TracerContext* context,
                                   const TaskRecord* task,
                                   int32_t syscall_number,
                                   uint64_t instruction_pointer) noexcept {
    if (syscall_number == __NR_gettid &&
        hookself::platform::IsRuntimeBypassGettidInstructionPointer(
                instruction_pointer)) {
        return true;
    }
    for (uint32_t slot = 0; slot < kMaxRuntimeApiBypassSlots; ++slot) {
        if (__atomic_load_n(
                    &context->control->runtime_api_bypass_tids[slot],
                    __ATOMIC_ACQUIRE) == task->tid) {
            return true;
        }
    }
    return false;
}

struct MountAttrWire {
    uint64_t attr_set;
    uint64_t attr_clear;
    uint64_t propagation;
    uint64_t userns_fd;
};

void CaptureMountSetattr(TracerContext* context, TaskRecord* task,
                         const uint64_t arguments[6]) noexcept {
    if (context == nullptr || task == nullptr ||
        context->pending_paths == nullptr ||
        task->slot >= hookself::tracer::Capacity() || arguments[3] == 0 ||
        arguments[4] < sizeof(MountAttrWire)) {
        return;
    }
    MountAttrWire attr{};
    if (ReadRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(arguments[3]), &attr,
                sizeof(attr)) != 0) {
        return;
    }
    PendingPathIdentity* pending =
            &context->pending_paths->entries[task->slot];
    pending->mount_attr_valid = 1;
    pending->mount_attr_size = arguments[4] > UINT32_MAX
            ? UINT32_MAX
            : static_cast<uint32_t>(arguments[4]);
    pending->mount_attr_set = attr.attr_set;
    pending->mount_attr_clear = attr.attr_clear;
    pending->mount_propagation = attr.propagation;
}

bool PathStateSyscallNeedsExit(int32_t syscall_number) noexcept {
    switch (syscall_number) {
        case __NR_openat:
        case __NR_openat2:
        case __NR_close:
        case __NR_dup:
        case __NR_dup3:
        case __NR_fcntl:
        case __NR_chdir:
        case __NR_fchdir:
        case __NR_getcwd:
        case __NR_readlinkat:
        case __NR_unshare:
        case __NR_clone:
#ifdef __NR_clone3
        case __NR_clone3:
#endif
        case __NR_execve:
        case __NR_execveat:
        case hookself::tracer::kMountStateMount:
        case hookself::tracer::kMountStateUmount2:
        case hookself::tracer::kMountStatePivotRoot:
        case hookself::tracer::kMountStateChroot:
        case hookself::tracer::kMountStateOpenTree:
        case hookself::tracer::kMountStateMoveMount:
        case hookself::tracer::kMountStateMountSetattr:
        case kSyscallCloseRange:
            return true;
        default:
            return false;
    }
}

int WriteTraceeSyscallResult(TaskRecord* task, int64_t result) noexcept {
    Arm64Regs registers{};
    int error = hookself::arch::ReadRegisters(task->tid, &registers);
    if (error != 0) {
        return error;
    }
    registers.regs[0] = static_cast<uint64_t>(result);
    error = hookself::arch::WriteRegisters(task->tid, &registers);
    if (error != 0) {
        return error;
    }
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    return error != 0 || verified.regs[0] != registers.regs[0]
                   ? (error != 0 ? error : EIO)
                   : 0;
}

int RecordOpenedPathIdentity(TracerContext* context, TaskRecord* task,
                              int32_t fd,
                              const PendingPathIdentity& pending) noexcept {
    if (fd < 0 || pending.path_count == 0 ||
        pending.guest_paths[0][0] != '/' ||
        pending.host_paths[0][0] != '/') {
        return 0;
    }
    hookself::tracer::FdIdentitySpec identity{};
    identity.origin_flags = pending.origin_flags[0] |
                            hookself::tracer::kPathOriginGuestValid |
                            hookself::tracer::kPathOriginHostValid;
    identity.directory = (pending.open_flags & O_DIRECTORY) != 0 ? 1U : 0U;
    identity.cloexec = (pending.open_flags & O_CLOEXEC) != 0 ? 1U : 0U;
    identity.guest_path = pending.guest_paths[0];
    identity.host_path = pending.host_paths[0];
    return hookself::tracer::RecordFdIdentity(
            context->path_state, task->tid, fd, identity);
}

int SetTaskCwdFromHostPath(TracerContext* context, TaskRecord* task,
                           const char* host, size_t host_length) noexcept {
    if (context == nullptr || context->path_state == nullptr || task == nullptr ||
        host == nullptr || host_length == 0U || host[0] != '/') {
        return EINVAL;
    }
    char guest[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_length = 0;
    bool translated = false;
    uint32_t rule_id = 0;
    const SharedRuleBankHeader* const bank = context->control == nullptr
            ? nullptr
            : ActiveRuleBank(context);
    const int reverse_error = ResolveHostPathToGuest(
            context, task, bank, host, host_length, guest,
            sizeof(guest), &guest_length, &translated, &rule_id);
    if (reverse_error != 0) {
        return reverse_error;
    }
    const uint32_t flags = hookself::tracer::kPathOriginGuestValid |
                           hookself::tracer::kPathOriginHostValid |
                           hookself::tracer::kPathOriginAmbiguous |
                           (translated
                                    ? hookself::tracer::kPathOriginReverseVisible
                                    : 0U);
    (void)rule_id;
    return hookself::tracer::SetTaskCwd(
            context->path_state, task->tid, guest, host, flags, 0, 0);
}

int ResolveVisibleGuestCwd(const hookself::tracer::FsContext* fs,
                           char* output, size_t output_capacity,
                           size_t* output_length) noexcept {
    if (fs == nullptr || output == nullptr || output_length == nullptr ||
        output_capacity < 2U ||
        (fs->cwd_origin_flags & hookself::tracer::kPathOriginGuestValid) == 0) {
        return fs == nullptr ? ESRCH : EINVAL;
    }
    const size_t cwd_length = BoundedLength(fs->guest_cwd,
                                             sizeof(fs->guest_cwd));
    if (cwd_length == 0U || cwd_length >= sizeof(fs->guest_cwd) ||
        cwd_length + 1U > output_capacity) {
        return cwd_length == 0U ? EPROTO : ENAMETOOLONG;
    }

    const size_t root_length = BoundedLength(fs->guest_root,
                                              sizeof(fs->guest_root));
    constexpr uint32_t kGuestOrigin = hookself::tracer::kPathOriginGuestValid;
    if ((fs->root_origin_flags & kGuestOrigin) == 0 || root_length == 0U ||
        root_length >= sizeof(fs->guest_root) ||
        !PrefixMatches(fs->guest_cwd, cwd_length, fs->guest_root,
                       root_length)) {
        for (size_t index = 0; index <= cwd_length; ++index) {
            output[index] = fs->guest_cwd[index];
        }
        *output_length = cwd_length;
        return 0;
    }

    if (root_length == 1U) {
        for (size_t index = 0; index <= cwd_length; ++index) {
            output[index] = fs->guest_cwd[index];
        }
        *output_length = cwd_length;
        return 0;
    }
    if (cwd_length == root_length) {
        output[0] = '/';
        output[1] = '\0';
        *output_length = 1U;
        return 0;
    }

    const size_t suffix = root_length + 1U;
    const size_t visible_length = cwd_length - root_length;
    if (suffix > cwd_length || visible_length + 1U > output_capacity) {
        return EPROTO;
    }
    output[0] = '/';
    for (size_t index = suffix; index < cwd_length; ++index) {
        output[index - root_length] = fs->guest_cwd[index];
    }
    output[visible_length] = '\0';
    *output_length = visible_length;
    return 0;
}

int SetCwdFromPendingPath(TracerContext* context, TaskRecord* task,
                           const PendingPathIdentity& pending) noexcept {
    if (pending.path_count == 0 || pending.guest_paths[0][0] != '/' ||
        pending.host_paths[0][0] != '/') {
        char host[HOOKSELF_PATH_CAPACITY]{};
        size_t host_length = 0;
        const int read_error = ReadTaskPathBase(
                task, AT_FDCWD, host, sizeof(host), &host_length);
        if (read_error != 0) {
            return read_error;
        }
        return SetTaskCwdFromHostPath(context, task, host, host_length);
    }
    const uint32_t flags = pending.origin_flags[0] |
                           hookself::tracer::kPathOriginGuestValid |
                           hookself::tracer::kPathOriginHostValid;
    return hookself::tracer::SetTaskCwd(
            context->path_state, task->tid, pending.guest_paths[0],
            pending.host_paths[0], flags, 0, 0);
}

int SetCwdFromFdIdentity(TracerContext* context, TaskRecord* task,
                          int32_t fd) noexcept {
    hookself::tracer::FdIdentityView view{};
    const int view_error = hookself::tracer::ResolveFdIdentityView(
            context->path_state, task->tid, fd, &view);
    if (view_error == 0 &&
        (view.origin_flags &
         (hookself::tracer::kPathOriginGuestValid |
          hookself::tracer::kPathOriginHostValid)) ==
                (hookself::tracer::kPathOriginGuestValid |
                 hookself::tracer::kPathOriginHostValid)) {
        return hookself::tracer::SetTaskCwd(
                context->path_state, task->tid, view.guest_path,
                view.host_path, view.origin_flags, 0, 0);
    }
    const hookself::tracer::FdIdentity* identity =
            hookself::tracer::LookupFdIdentity(
                    context->path_state, task->tid, fd);
    if (identity == nullptr ||
        (identity->origin_flags &
         (hookself::tracer::kPathOriginGuestValid |
          hookself::tracer::kPathOriginHostValid)) !=
                (hookself::tracer::kPathOriginGuestValid |
                 hookself::tracer::kPathOriginHostValid)) {
        char guest[HOOKSELF_PATH_CAPACITY]{};
        char host[HOOKSELF_PATH_CAPACITY]{};
        size_t guest_length = 0;
        size_t host_length = 0;
        uint32_t origin_flags = 0;
        const int resolve_error = ResolvePathBases(
                context, task, ActiveRuleBank(context), fd,
                guest, sizeof(guest), &guest_length,
                host, sizeof(host), &host_length, &origin_flags);
        if (resolve_error != 0) {
            return resolve_error;
        }
        return hookself::tracer::SetTaskCwd(
                context->path_state, task->tid, guest, host,
                origin_flags, 0, 0);
    }
    return hookself::tracer::SetTaskCwd(
            context->path_state, task->tid, identity->guest_path,
            identity->host_path, identity->origin_flags, identity->device,
            identity->inode);
}

int RewriteGetcwdResult(TracerContext* context, TaskRecord* task,
                        int64_t* visible_result) noexcept {
    const hookself::tracer::FsContext* fs =
            hookself::tracer::GetTaskFsContext(
                    context->path_state, task->tid);
    if (fs == nullptr ||
        (fs->cwd_origin_flags & hookself::tracer::kPathOriginGuestValid) == 0) {
        return fs == nullptr ? ESRCH : 0;
    }
    char guest_cwd[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_length = 0;
    const int cwd_error = ResolveVisibleGuestCwd(
            fs, guest_cwd, sizeof(guest_cwd), &guest_length);
    if (cwd_error != 0) {
        return cwd_error;
    }
    const uintptr_t output = static_cast<uintptr_t>(
            task->active_syscall.arguments[0]);
    const uint64_t capacity = task->active_syscall.arguments[1];
    const int64_t replacement = capacity > guest_length
                                        ? static_cast<int64_t>(guest_length + 1U)
                                        : -ERANGE;
    if (replacement > 0) {
        const int write_error = WriteRemoteBytes(
                task->tgid, task->tid, output, guest_cwd,
                static_cast<size_t>(replacement));
        if (write_error != 0) {
            return write_error;
        }
    } else if (output != 0 && capacity != 0) {
        const char zero = '\0';
        const int write_error = WriteRemoteBytes(
                task->tgid, task->tid, output, &zero, sizeof(zero));
        if (write_error != 0) {
            return write_error;
        }
    }
    const int result_error = WriteTraceeSyscallResult(task, replacement);
    if (result_error == 0) {
        *visible_result = replacement;
    }
    return result_error;
}

int RewriteReadlinkResult(TracerContext* context, TaskRecord* task,
                          int64_t kernel_result,
                          int64_t* visible_result) noexcept {
    if (kernel_result <= 0 ||
        static_cast<uint64_t>(kernel_result) >= HOOKSELF_PATH_CAPACITY) {
        return kernel_result <= 0 ? 0 : EOVERFLOW;
    }
    char host_target[HOOKSELF_PATH_CAPACITY]{};
    const int read_error = ReadRemoteBytes(
            task->tgid, task->tid,
            static_cast<uintptr_t>(task->active_syscall.arguments[2]),
            host_target, static_cast<size_t>(kernel_result));
    if (read_error != 0) {
        return read_error;
    }
    if (host_target[0] != '/') {
        return 0;
    }
    char guest_target[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_length = 0;
    bool translated = false;
    uint32_t rule_id = 0;
    const int reverse_error = ResolveHostPathToGuest(
            context, task, ActiveRuleBank(context), host_target,
            static_cast<size_t>(kernel_result), guest_target,
            sizeof(guest_target), &guest_length, &translated, &rule_id);
    if (reverse_error != 0) {
        return reverse_error;
    }
    if (!translated) {
        return 0;
    }
    const size_t capacity = static_cast<size_t>(
            task->active_syscall.arguments[3]);
    const size_t written = guest_length < capacity ? guest_length : capacity;
    if (written != 0) {
        const int write_error = WriteRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(task->active_syscall.arguments[2]),
                guest_target, written);
        if (write_error != 0) {
            return write_error;
        }
    }
    const int64_t replacement = static_cast<int64_t>(written);
    const int result_error = WriteTraceeSyscallResult(task, replacement);
    if (result_error == 0) {
        *visible_result = replacement;
    }
    (void)rule_id;
    return result_error;
}

bool PendingMountPathUsable(const PendingPathIdentity& pending,
                            uint32_t index) noexcept {
    if (index >= kScratchPathSlots || index >= pending.path_count ||
        pending.guest_paths[index][0] != '/' ||
        pending.host_paths[index][0] != '/') {
        return false;
    }
    constexpr uint32_t required =
            hookself::tracer::kPathOriginGuestValid |
            hookself::tracer::kPathOriginHostValid;
    return (pending.origin_flags[index] & required) == required;
}

int CompleteMountStateSyscall(TracerContext* context, TaskRecord* task,
                              int64_t kernel_result,
                              const PendingPathIdentity& pending) noexcept {
    const int32_t syscall_number = task->active_syscall.syscall_number;
    if (!hookself::tracer::IsMountStateSyscall(syscall_number) ||
        kernel_result < 0) {
        return 0;
    }
    const uint64_t* arguments = task->active_syscall.arguments;
    const bool first_path = PendingMountPathUsable(pending, 0);
    const bool second_path = PendingMountPathUsable(pending, 1);
    bool capture_complete = first_path;
    switch (syscall_number) {
        case hookself::tracer::kMountStateMount:
            capture_complete = first_path &&
                    (((arguments[3] &
                       (kMountFlagBind | kMountFlagMove)) == 0) ||
                     second_path);
            break;
        case hookself::tracer::kMountStatePivotRoot:
        case hookself::tracer::kMountStateMoveMount:
            capture_complete = first_path && second_path;
            break;
        case hookself::tracer::kMountStateMountSetattr:
            capture_complete = first_path && pending.mount_attr_valid != 0;
            break;
        default:
            break;
    }
    if (!capture_complete) {
        return 0;
    }

    hookself::tracer::MountSyscallCompletion completion{};
    completion.syscall_number = syscall_number;
    completion.path_count = pending.path_count > 2U
            ? 2U
            : pending.path_count;
    completion.kernel_result = kernel_result;
    for (uint32_t index = 0; index < 6U; ++index) {
        completion.arguments[index] = arguments[index];
    }
    completion.mount_attr_valid = pending.mount_attr_valid;
    completion.mount_attr_set = pending.mount_attr_set;
    completion.mount_attr_clear = pending.mount_attr_clear;
    completion.mount_propagation = pending.mount_propagation;
    for (uint32_t index = 0; index < 2U; ++index) {
        if (!PendingMountPathUsable(pending, index)) {
            continue;
        }
        completion.paths[index].valid = 1;
        completion.paths[index].origin_flags = pending.origin_flags[index];
        completion.paths[index].guest_path = pending.guest_paths[index];
        completion.paths[index].host_path = pending.host_paths[index];
    }
    return hookself::tracer::ApplyMountSyscallCompletion(
            context->path_state, task->tid, completion);
}

int CompletePathStateSyscall(TracerContext* context, TaskRecord* task,
                             int64_t kernel_result,
                             int64_t* visible_result) noexcept {
    if (context == nullptr || context->path_state == nullptr ||
        task == nullptr) {
        return 0;
    }
    const bool rewrite_getcwd_erange =
            task->active_syscall.syscall_number == __NR_getcwd &&
            kernel_result == -ERANGE;
    if (task->active_syscall.entry_policy_action == HOOKSELF_SYSCALL_DENY ||
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallPathState) == 0 ||
        IsKernelRestartResult(kernel_result) ||
        (kernel_result < 0 && !rewrite_getcwd_erange)) {
        return 0;
    }
    const uint64_t* arguments = task->active_syscall.arguments;
    const PendingPathIdentity empty_pending{};
    const PendingPathIdentity& pending =
            context->pending_paths != nullptr &&
                    task->slot < hookself::tracer::Capacity()
                    ? context->pending_paths->entries[task->slot]
                    : empty_pending;
    if (hookself::tracer::IsMountStateSyscall(
                task->active_syscall.syscall_number)) {
        return CompleteMountStateSyscall(
                context, task, kernel_result, pending);
    }
    switch (task->active_syscall.syscall_number) {
        case __NR_openat:
        case __NR_openat2:
            return RecordOpenedPathIdentity(
                    context, task, static_cast<int32_t>(kernel_result),
                    pending);
        case __NR_chdir:
            return kernel_result == 0
                           ? SetCwdFromPendingPath(context, task, pending)
                           : 0;
        case __NR_fchdir:
            return kernel_result == 0
                           ? SetCwdFromFdIdentity(
                                     context, task,
                                     static_cast<int32_t>(arguments[0]))
                           : 0;
        case __NR_getcwd:
            return (kernel_result > 0 || rewrite_getcwd_erange) &&
                           visible_result != nullptr
                           ? RewriteGetcwdResult(
                                     context, task, visible_result)
                           : 0;
        case __NR_readlinkat:
            return visible_result != nullptr
                           ? RewriteReadlinkResult(
                                     context, task, kernel_result,
                                     visible_result)
                           : 0;
        case __NR_close:
            return kernel_result == 0
                           ? hookself::tracer::CloseFdIdentity(
                                     context->path_state, task->tid,
                                     static_cast<int32_t>(arguments[0]))
                           : 0;
        case __NR_dup:
            return hookself::tracer::DuplicateFdIdentity(
                    context->path_state, task->tid,
                    static_cast<int32_t>(arguments[0]),
                    static_cast<int32_t>(kernel_result), false);
        case __NR_dup3:
            if ((task->active_syscall.flags &
                 hookself::tracer::kActiveSyscallInternalFdOperation) != 0) {
                return 0;
            }
            return hookself::tracer::DuplicateFdIdentity(
                    context->path_state, task->tid,
                    static_cast<int32_t>(arguments[0]),
                    static_cast<int32_t>(kernel_result),
                    (arguments[2] & O_CLOEXEC) != 0);
        case __NR_fcntl: {
            const int32_t command = static_cast<int32_t>(arguments[1]);
            if (command == F_DUPFD || command == F_DUPFD_CLOEXEC) {
                return hookself::tracer::DuplicateFdIdentity(
                        context->path_state, task->tid,
                        static_cast<int32_t>(arguments[0]),
                        static_cast<int32_t>(kernel_result),
                        command == F_DUPFD_CLOEXEC);
            }
            if (command == F_SETFD && kernel_result == 0) {
                return hookself::tracer::SetFdIdentityCloexec(
                        context->path_state, task->tid,
                        static_cast<int32_t>(arguments[0]),
                        (arguments[2] & FD_CLOEXEC) != 0);
            }
            return 0;
        }
        case __NR_unshare:
            return kernel_result == 0
                           ? hookself::tracer::UnsharePathTask(
                                     context->path_state, task->tid,
                                     arguments[0])
                           : 0;
        case kSyscallCloseRange:
            if (kernel_result != 0) {
                return 0;
            }
            // Replay segments are committed after each successful physical
            // close_range call. Reapplying the original interval here would
            // duplicate UNSHARE and lose partial-success semantics.
            return (pending.flags & kPendingPathCloseRangeReplay) != 0
                           ? 0
                           : hookself::tracer::CloseFdIdentityRange(
                                     context->path_state, task->tid,
                                     static_cast<uint32_t>(arguments[0]),
                                     static_cast<uint32_t>(arguments[1]),
                                     static_cast<uint32_t>(arguments[2]));
        default:
            return 0;
    }
}

