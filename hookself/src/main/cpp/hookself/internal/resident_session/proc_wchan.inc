// ---------------------------------------------------------------------------
// /proc/<pid>/wchan 视图：被 ptrace 停止的任务 wchan="ptrace_stop"，
// 是调试器/注入器无法通过 stat/status 隐藏后的典型残留指纹。
// 仅当 tracer 侧读到的内容确实含 "ptrace" 时置视图标志（等长改写见
// RewriteProcWchanContent），无指纹的 wchan 原样放行，避免事件量膨胀。

bool IsProcWchanReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

int ApplyProcWchanReadView(TracerContext* context,
                           TaskRecord* task) noexcept {
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0 ||
        !IsProcWchanReadSyscall(task->active_syscall.syscall_number)) {
        return 0;
    }
    const int32_t fd = static_cast<int32_t>(
            task->active_syscall.arguments[0]);
    if (fd < 0) {
        return 0;
    }
    char resolved[HOOKSELF_PATH_CAPACITY]{};
    size_t resolved_length = 0;
    const int resolve_error = ResolveTargetFdPath(
            task, fd, resolved, sizeof(resolved), &resolved_length);
    if (resolve_error != 0 || !ProcWchanPath(resolved, resolved_length)) {
        return 0;
    }
    int32_t owner = 0;
    const int owner_error = ParseProcFileOwnerPid(
            resolved, resolved_length, task->tgid, &owner);
    if (owner_error != 0 || !IsTraceTreePid(context, owner)) {
        return 0;
    }

    uint8_t source[kProcStatusReadCapacity]{};
    size_t source_size = 0;
    // wchan 视图与 stat 同为宽作用域，任何读取异常一律放行。
    if (ReadLocalFile(resolved, source, sizeof(source), &source_size) != 0) {
        return 0;
    }
    if (RewriteProcWchanContent(source, source_size) == 0) {
        return 0;  // 内容无 ptrace 指纹，不置标志不生成事件
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallProcWchanView;
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
            HOOKSELF_SYSCALL_OBSERVE,
            HOOKSELF_BUILTIN_RULE_PROC_WCHAN_VIEW, 0);
    return 0;
}

int CompleteProcWchanReadView(TracerContext* context, TaskRecord* task,
                              int64_t kernel_result) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallProcWchanView) == 0) {
        return 0;
    }
    if (kernel_result > 0) {
        if (static_cast<uint64_t>(kernel_result) >
            kProcStatusReadCapacity) {
            return EOVERFLOW;
        }
        iovec vectors[kMaxProcStatusIov]{};
        size_t vector_count = 0;
        if (task->active_syscall.syscall_number == __NR_readv) {
            const int snapshot_error = SnapshotProcStatusReadIov(
                    task, kernel_result, vectors, kMaxProcStatusIov,
                    &vector_count);
            if (snapshot_error != 0) {
                return snapshot_error;
            }
        }
        uint8_t output[kProcStatusReadCapacity]{};
        const int gather_error = GatherProcStatusReadOutput(
                task, kernel_result, vectors, vector_count, output,
                sizeof(output));
        if (gather_error != 0) {
            return gather_error;
        }
        const size_t rewritten = RewriteProcWchanContent(
                output, static_cast<size_t>(kernel_result));
        if (rewritten != 0) {
            const int scatter_error = ScatterProcStatusReadOutput(
                    task, kernel_result, vectors, vector_count, output);
            if (scatter_error != 0) {
                return scatter_error;
            }
            uint8_t verified[kProcStatusReadCapacity]{};
            const int verify_error = GatherProcStatusReadOutput(
                    task, kernel_result, vectors, vector_count, verified,
                    sizeof(verified));
            if (verify_error != 0) {
                return verify_error;
            }
            for (size_t i = 0; i < static_cast<size_t>(kernel_result); ++i) {
                if (verified[i] != output[i]) {
                    return EIO;
                }
            }
        }
    }
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_EXIT,
            HOOKSELF_SYSCALL_OBSERVE,
            HOOKSELF_BUILTIN_RULE_PROC_WCHAN_VIEW, kernel_result);
    return 0;
}
