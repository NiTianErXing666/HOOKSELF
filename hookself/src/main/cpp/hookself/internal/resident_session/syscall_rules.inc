void CopyEventPath(char* destination, const char* source) noexcept {
    size_t i = 0;
    while (i + 1 < HOOKSELF_EVENT_PATH_CAPACITY && source[i] != '\0') {
        destination[i] = source[i];
        ++i;
    }
    destination[i] = '\0';
}

void EmitPathPolicyEvent(TracerContext* context, const TaskRecord& task,
                         int32_t syscall_number, uint32_t argument_index,
                         int32_t action, uint32_t rule_id, int32_t error,
                         const char* original, const char* translated,
                         uint32_t extra_flags) noexcept {
    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_PATH;
    event.tgid = task.tgid;
    event.tid = task.tid;
    event.syscall_number = syscall_number;
    event.phase = HOOKSELF_SYSCALL_PHASE_ENTRY;
    event.action = action;
    event.error = error;
    event.rule_id = rule_id;
    event.flags = extra_flags |
                  (argument_index << HOOKSELF_EVENT_F_PATH_ARGUMENT_SHIFT);
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_CAPTURE_ARGUMENTS) != 0) {
        for (size_t index = 0; index < 6; ++index) {
            event.arguments[index] = task.active_syscall.arguments[index];
        }
    }
    if ((context->control->config_flags & HOOKSELF_CONFIG_CAPTURE_PATHS) != 0) {
        CopyEventPath(event.path, original);
        if (translated != nullptr) {
            CopyEventPath(event.translated_path, translated);
        }
    }
    (void)EmitEvent(context, &event);
}

const SharedRuleBankHeader* ActiveRuleBank(TracerContext* context) noexcept {
    const uint64_t index = __atomic_load_n(
            &context->control->active_rule_bank, __ATOMIC_ACQUIRE);
    return index < 2 ? GetSharedRuleBank(context->mapping,
                                         static_cast<uint32_t>(index))
                     : nullptr;
}

bool SyscallRuleMatches(const SharedSyscallRuleDesc& rule, int32_t syscall_number,
                        uint32_t phase, const uint64_t arguments[6]) noexcept {
    if (rule.syscall_number != syscall_number ||
        (rule.phase_mask & phase) == 0 || rule.argument_index >= 6) {
        return false;
    }
    if (rule.argument_match_mask == 0) {
        return true;
    }
    return (arguments[rule.argument_index] & rule.argument_match_mask) ==
           (rule.argument_match_value & rule.argument_match_mask);
}

bool SelectObservationRule(TracerContext* context, int32_t syscall_number,
                           uint32_t phase, const uint64_t arguments[6],
                           uint32_t* rule_id) noexcept {
    *rule_id = 0;
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank != nullptr) {
        const auto* base = reinterpret_cast<const uint8_t*>(bank);
        const auto* rules = reinterpret_cast<const SharedSyscallRuleDesc*>(
                base + bank->syscall_rules_offset);
        for (uint32_t i = 0; i < bank->syscall_rule_count; ++i) {
            if (rules[i].action == HOOKSELF_SYSCALL_OBSERVE &&
                SyscallRuleMatches(rules[i], syscall_number, phase, arguments)) {
                *rule_id = rules[i].rule_id;
                return true;
            }
        }
    }
    return (context->control->config_flags & HOOKSELF_CONFIG_OBSERVE_ALL) != 0;
}

const SharedSyscallRuleDesc* SelectEntryPolicyRule(
        TracerContext* context, int32_t syscall_number,
        const uint64_t arguments[6]) noexcept {
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank == nullptr) {
        return nullptr;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    const auto* rules = reinterpret_cast<const SharedSyscallRuleDesc*>(
            base + bank->syscall_rules_offset);
    for (uint32_t i = 0; i < bank->syscall_rule_count; ++i) {
        if (!SyscallRuleMatches(rules[i], syscall_number,
                                HOOKSELF_SYSCALL_PHASE_ENTRY, arguments)) {
            continue;
        }
        if (rules[i].action == HOOKSELF_SYSCALL_PASS) {
            return nullptr;
        }
        if (rules[i].action == HOOKSELF_SYSCALL_DENY ||
            rules[i].action == HOOKSELF_SYSCALL_REPLACE_NUMBER ||
            rules[i].action == HOOKSELF_SYSCALL_REPLACE_ARGUMENT) {
            return &rules[i];
        }
    }
    return nullptr;
}

const SharedSyscallRuleDesc* SelectExitPolicyRule(
        TracerContext* context, int32_t syscall_number,
        const uint64_t arguments[6]) noexcept {
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank == nullptr) {
        return nullptr;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    const auto* rules = reinterpret_cast<const SharedSyscallRuleDesc*>(
            base + bank->syscall_rules_offset);
    for (uint32_t i = 0; i < bank->syscall_rule_count; ++i) {
        if (!SyscallRuleMatches(rules[i], syscall_number,
                                HOOKSELF_SYSCALL_PHASE_EXIT, arguments)) {
            continue;
        }
        if (rules[i].action == HOOKSELF_SYSCALL_PASS) {
            return nullptr;
        }
        if (rules[i].action == HOOKSELF_SYSCALL_REPLACE_RESULT) {
            return &rules[i];
        }
    }
    return nullptr;
}

void EmitSyscallPolicyEvent(TracerContext* context, const TaskRecord& task,
                            uint32_t phase, int32_t action, uint32_t rule_id,
                            int64_t result) noexcept {
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallLogBypass) != 0) {
        return;
    }
    HookselfEvent event{};
    event.kind = HOOKSELF_EVENT_SYSCALL;
    event.tgid = task.tgid;
    event.tid = task.tid;
    event.syscall_number = task.active_syscall.syscall_number;
    event.phase = phase;
    event.action = action;
    event.rule_id = rule_id;
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallPtraceView) != 0) {
        event.flags |= HOOKSELF_EVENT_F_PTRACE_VIEW;
    }
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallProcStatusView) != 0) {
        event.flags |= HOOKSELF_EVENT_F_PROC_STATUS_VIEW;
    }
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallProcStatView) != 0) {
        event.flags |= HOOKSELF_EVENT_F_PROC_STAT_VIEW;
    }
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallProcWchanView) != 0) {
        event.flags |= HOOKSELF_EVENT_F_PROC_WCHAN_VIEW;
    }
    if ((task.active_syscall.flags &
         hookself::tracer::kActiveSyscallNestedPtraceDispatch) != 0U) {
        event.flags |= HOOKSELF_EVENT_F_NESTED_PTRACE;
    }
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_CAPTURE_ARGUMENTS) != 0) {
        for (size_t i = 0; i < 6; ++i) {
            event.arguments[i] = task.active_syscall.arguments[i];
        }
    }
    if (phase == HOOKSELF_SYSCALL_PHASE_EXIT) {
        event.result = result;
        if (result < 0 && result >= -4095) {
            event.error = static_cast<int32_t>(-result);
        }
    }
    (void)EmitEvent(context, &event);
}

void SaveSyscallEntry(TaskRecord* task, int32_t syscall_number,
                      const uint64_t arguments[6]) noexcept {
    hookself::tracer::ClearActiveSyscall(task);
    task->active_syscall.flags = hookself::tracer::kActiveSyscallValid |
                                 hookself::tracer::kActiveSyscallNeedsExit;
    task->active_syscall.syscall_number = syscall_number;
    task->active_syscall.user_syscall_number = syscall_number;
    task->active_syscall.executed_syscall_number = syscall_number;
    for (size_t i = 0; i < 6; ++i) {
        task->active_syscall.arguments[i] = arguments[i];
    }
    task->active_syscall.rule_generation = 0;
    task->syscall_phase = TaskSyscallPhase::kExpectExit;
}

void SaveEntryRegisters(TaskRecord* task, const Arm64Regs& registers) noexcept {
    for (size_t i = 0; i < 31; ++i) {
        task->active_syscall.entry_registers.x[i] = registers.regs[i];
    }
    task->active_syscall.entry_registers.sp = registers.sp;
    task->active_syscall.entry_registers.pc = registers.pc;
    task->active_syscall.entry_registers.pstate = registers.pstate;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallEntryRegistersValid;
}

int RestoreSyscallNumberMutation(TaskRecord* task) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallNumberModified) == 0) {
        return 0;
    }
    int error = hookself::arch::WriteSyscallNumber(
            task->tid, task->active_syscall.syscall_number);
    if (error != 0) {
        return error;
    }
    int32_t verified_number = -1;
    error = hookself::arch::ReadSyscallNumber(task->tid, &verified_number);
    if (error != 0 ||
        verified_number != task->active_syscall.syscall_number) {
        return error != 0 ? error : EIO;
    }
    task->active_syscall.flags &=
            ~hookself::tracer::kActiveSyscallNumberModified;
    task->active_syscall.executed_syscall_number =
            task->active_syscall.syscall_number;
    return 0;
}

int ModifySyscallNumber(TaskRecord* task, int32_t replacement) noexcept {
    int error = hookself::arch::WriteSyscallNumber(task->tid, replacement);
    if (error != 0) {
        return error;
    }
    task->active_syscall.executed_syscall_number = replacement;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallNumberModified;
    int32_t verified_number = -1;
    error = hookself::arch::ReadSyscallNumber(task->tid, &verified_number);
    if (error == 0 && verified_number == replacement) {
        return 0;
    }
    const int rollback_error = RestoreSyscallNumberMutation(task);
    return rollback_error != 0 ? EOWNERDEAD : error != 0 ? error : EIO;
}

// Android's baseline seccomp policy may terminate a process that reaches the
// kernel with a negative syscall number. getpid has no observable side effect
// for the tracee and lets the normal exit-stop path install the replacement
// result before control returns to user space.
int SuppressSyscallWithHarmlessCall(TaskRecord* task) noexcept {
    return ModifySyscallNumber(task, __NR_getpid);
}

int RestoreGenericArgumentMutation(TaskRecord* task,
                                   bool syscall_completed) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallArgumentsModified) == 0) {
        return 0;
    }
    uint32_t restore_mask = task->active_syscall.modified_argument_mask;
    if (syscall_completed) {
        restore_mask &= ~1U;
    }
    if (restore_mask != 0) {
        Arm64Regs current{};
        int error = hookself::arch::ReadRegisters(task->tid, &current);
        if (error != 0) {
            return error;
        }
        Arm64Regs expected = current;
        for (uint32_t index = 0; index < 6; ++index) {
            if ((restore_mask & (1U << index)) != 0) {
                expected.regs[index] = task->active_syscall.arguments[index];
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
    }
    task->active_syscall.flags &=
            ~hookself::tracer::kActiveSyscallArgumentsModified;
    task->active_syscall.modified_argument_mask = 0;
    return 0;
}

int ModifySyscallArgument(TaskRecord* task, uint32_t argument_index,
                          uint64_t replacement) noexcept {
    if (argument_index >= 6 ||
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallRegistersModified) != 0) {
        return EINVAL;
    }
    Arm64Regs current{};
    int error = hookself::arch::ReadRegisters(task->tid, &current);
    if (error != 0 ||
        current.regs[argument_index] !=
                task->active_syscall.arguments[argument_index]) {
        return error != 0 ? error : EPROTO;
    }
    SaveEntryRegisters(task, current);
    Arm64Regs modified = current;
    modified.regs[argument_index] = replacement;
    error = hookself::arch::WriteRegisters(task->tid, &modified);
    if (error != 0) {
        return error;
    }
    task->active_syscall.modified_argument_mask = 1U << argument_index;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallArgumentsModified;
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error == 0 && hookself::arch::RegistersEqual(modified, verified)) {
        return 0;
    }
    const int rollback_error = RestoreGenericArgumentMutation(task, false);
    return rollback_error != 0 ? EOWNERDEAD : error != 0 ? error : EIO;
}

