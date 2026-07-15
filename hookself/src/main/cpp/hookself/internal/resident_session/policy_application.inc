int ApplyProtectedFdPolicy(TracerContext* context, TaskRecord* task,
                           bool* handled) noexcept {
    *handled = false;
    const uint64_t* arguments = task->active_syscall.arguments;
    const int32_t syscall_number = task->active_syscall.syscall_number;
    if (syscall_number == __NR_dup3) {
        const int32_t source_fd = static_cast<int32_t>(arguments[0]);
        const int32_t target_fd = static_cast<int32_t>(arguments[1]);
        const uint32_t flags = static_cast<uint32_t>(arguments[2]);
        if (source_fd != target_fd &&
            IsProtectedFdForTask(context, task, target_fd)) {
            *handled = true;
            if (ClaimInternalDup3(
                        context, task, source_fd, target_fd, flags)) {
                return 0;
            }
            return SuppressProtectedFdSyscall(context, task, -EBUSY);
        }
    }
    if (__atomic_load_n(&context->control->internal_bypass_active,
                        __ATOMIC_ACQUIRE) != 0 &&
        context->control->internal_bypass_tid == task->tid &&
        (context->control->internal_bypass_fd < 0 ||
         context->control->internal_bypass_fd ==
                 static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return 0;
    }
    if (syscall_number == __NR_close &&
        __atomic_load_n(&context->control->teardown_bypass_active,
                        __ATOMIC_ACQUIRE) != 0 &&
        __atomic_load_n(&context->control->teardown_bypass_tid,
                        __ATOMIC_RELAXED) == task->tid &&
        __atomic_load_n(&context->control->teardown_bypass_fd,
                        __ATOMIC_RELAXED) ==
                static_cast<int32_t>(arguments[0]) &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return 0;
    }
    if (syscall_number == __NR_close &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return SuppressProtectedFdSyscall(context, task, 0);
    }
#ifdef __NR_dup2
    if (syscall_number == __NR_dup2) {
        const int32_t source_fd = static_cast<int32_t>(arguments[0]);
        const int32_t target_fd = static_cast<int32_t>(arguments[1]);
        if (source_fd != target_fd &&
            IsProtectedFdForTask(context, task, target_fd)) {
            *handled = true;
            return SuppressProtectedFdSyscall(context, task, -EBUSY);
        }
    }
#endif
    if (syscall_number == __NR_fcntl &&
        static_cast<int32_t>(arguments[1]) == F_SETFD &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return SuppressProtectedFdSyscall(context, task, 0);
    }
    if (syscall_number == __NR_fcntl &&
        static_cast<int32_t>(arguments[1]) == F_GETFD &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return SuppressProtectedFdSyscall(context, task, FD_CLOEXEC);
    }
    if (syscall_number == __NR_ioctl &&
        (arguments[1] == static_cast<uint64_t>(FIOCLEX) ||
         arguments[1] == static_cast<uint64_t>(FIONCLEX)) &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        *handled = true;
        return SuppressProtectedFdSyscall(context, task, 0);
    }
    if (syscall_number == kSyscallCloseRange) {
        const uint32_t first = static_cast<uint32_t>(arguments[0]);
        const uint32_t last = static_cast<uint32_t>(arguments[1]);
        const uint32_t flags = static_cast<uint32_t>(arguments[2]);
        if (!CloseRangeCapabilitiesPermitPolicy(
                    context->control->close_range_capabilities, flags)) {
            return 0;
        }
        if (first <= last &&
            ProtectedFdInRangeForTask(context, task, first, last)) {
            return BeginProtectedCloseRangeReplay(
                    context, task, handled);
        }
    }
    return 0;
}

int ApplyEffectiveProtectedFdPolicy(TracerContext* context, TaskRecord* task,
                                    bool* handled) noexcept {
    *handled = false;
    constexpr uint32_t kRelevantMutationFlags =
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified;
    if ((task->active_syscall.flags & kRelevantMutationFlags) == 0) {
        return 0;
    }
    int32_t syscall_number = -1;
    Arm64Regs registers{};
    int error = hookself::arch::ReadSyscallNumber(
            task->tid, &syscall_number);
    if (error == 0) {
        error = hookself::arch::ReadRegisters(task->tid, &registers);
    }
    if (error != 0 ||
        syscall_number != task->active_syscall.executed_syscall_number) {
        return error != 0 ? error : EPROTO;
    }
    const uint64_t* arguments = registers.regs;
    int64_t replacement_result = 0;
    bool blocked = false;
    if (syscall_number == __NR_close &&
        IsProtectedFdForTask(
                context, task, static_cast<int32_t>(arguments[0]))) {
        blocked = true;
    } else if (syscall_number == __NR_dup3) {
        const int32_t source_fd = static_cast<int32_t>(arguments[0]);
        const int32_t target_fd = static_cast<int32_t>(arguments[1]);
        blocked = source_fd != target_fd &&
                  IsProtectedFdForTask(context, task, target_fd);
        replacement_result = -EBUSY;
#ifdef __NR_dup2
    } else if (syscall_number == __NR_dup2) {
        const int32_t source_fd = static_cast<int32_t>(arguments[0]);
        const int32_t target_fd = static_cast<int32_t>(arguments[1]);
        blocked = source_fd != target_fd &&
                  IsProtectedFdForTask(context, task, target_fd);
        replacement_result = -EBUSY;
#endif
    } else if (syscall_number == __NR_fcntl &&
               static_cast<int32_t>(arguments[1]) == F_SETFD &&
               IsProtectedFdForTask(
                       context, task, static_cast<int32_t>(arguments[0]))) {
        blocked = true;
    } else if (syscall_number == __NR_ioctl &&
               (arguments[1] == static_cast<uint64_t>(FIOCLEX) ||
                arguments[1] == static_cast<uint64_t>(FIONCLEX)) &&
               IsProtectedFdForTask(
                       context, task, static_cast<int32_t>(arguments[0]))) {
        blocked = true;
    } else if (syscall_number == kSyscallCloseRange) {
        const uint32_t first = static_cast<uint32_t>(arguments[0]);
        const uint32_t last = static_cast<uint32_t>(arguments[1]);
        const uint32_t flags = static_cast<uint32_t>(arguments[2]);
        blocked = CloseRangeCapabilitiesPermitPolicy(
                          context->control->close_range_capabilities, flags) &&
                  first <= last &&
                  (flags & kCloseRangeCloexec) == 0U &&
                  ProtectedFdInRangeForTask(context, task, first, last);
        replacement_result = -EBUSY;
    }
    if (!blocked) {
        return 0;
    }
    *handled = true;
    return SuppressProtectedFdSyscall(
            context, task, replacement_result);
}

int ApplyEntrySyscallPolicy(TracerContext* context, TaskRecord* task,
                            bool* suppress_path_redirect) noexcept {
    *suppress_path_redirect = false;
    const SharedSyscallRuleDesc* exit_rule = SelectExitPolicyRule(
            context, task->active_syscall.syscall_number,
            task->active_syscall.arguments);
    if (exit_rule != nullptr) {
        task->active_syscall.flags |=
                hookself::tracer::kActiveSyscallReplaceResult;
        task->active_syscall.exit_policy_rule_id = exit_rule->rule_id;
        task->active_syscall.replacement_result =
                static_cast<int64_t>(exit_rule->replacement_value);
    }

    const SharedSyscallRuleDesc* entry_rule = SelectEntryPolicyRule(
            context, task->active_syscall.syscall_number,
            task->active_syscall.arguments);
    if (entry_rule == nullptr) {
        return 0;
    }
    *suppress_path_redirect = true;
    task->active_syscall.entry_policy_action = entry_rule->action;
    task->active_syscall.entry_policy_rule_id = entry_rule->rule_id;
    int error = 0;
    switch (entry_rule->action) {
        case HOOKSELF_SYSCALL_DENY:
            task->active_syscall.replacement_result = -entry_rule->deny_errno;
            error = SuppressSyscallWithHarmlessCall(task);
            break;
        case HOOKSELF_SYSCALL_REPLACE_NUMBER:
            error = ModifySyscallNumber(
                    task, entry_rule->replacement_syscall_number);
            break;
        case HOOKSELF_SYSCALL_REPLACE_ARGUMENT:
            error = ModifySyscallArgument(
                    task, entry_rule->argument_index,
                    entry_rule->replacement_value);
            break;
        default:
            return EINVAL;
    }
    if (error == 0) {
        EmitSyscallPolicyEvent(
                context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
                entry_rule->action, entry_rule->rule_id, 0);
    }
    return error;
}

int ApplyExitSyscallPolicy(TracerContext* context, TaskRecord* task,
                           int64_t kernel_result,
                           int64_t* effective_result) noexcept {
    *effective_result = kernel_result;
    int32_t action = HOOKSELF_SYSCALL_PASS;
    uint32_t rule_id = 0;
    if (task->active_syscall.entry_policy_action == HOOKSELF_SYSCALL_DENY) {
        action = HOOKSELF_SYSCALL_DENY;
        rule_id = task->active_syscall.entry_policy_rule_id;
        *effective_result = task->active_syscall.replacement_result;
    } else if ((task->active_syscall.flags &
                hookself::tracer::kActiveSyscallReplaceResult) != 0) {
        action = HOOKSELF_SYSCALL_REPLACE_RESULT;
        rule_id = task->active_syscall.exit_policy_rule_id;
        *effective_result = task->active_syscall.replacement_result;
    }
    if (action == HOOKSELF_SYSCALL_PASS) {
        return 0;
    }

    Arm64Regs current{};
    int error = hookself::arch::ReadRegisters(task->tid, &current);
    if (error != 0) {
        return error;
    }
    Arm64Regs modified = current;
    modified.regs[0] = static_cast<uint64_t>(*effective_result);
    error = hookself::arch::WriteRegisters(task->tid, &modified);
    if (error != 0) {
        return error;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallResultWriteUnknown;
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || !hookself::arch::RegistersEqual(modified, verified)) {
        return EOWNERDEAD;
    }
    task->active_syscall.flags &=
            ~hookself::tracer::kActiveSyscallResultWriteUnknown;
    EmitSyscallPolicyEvent(context, *task, HOOKSELF_SYSCALL_PHASE_EXIT,
                           action, rule_id, *effective_result);
    return 0;
}

