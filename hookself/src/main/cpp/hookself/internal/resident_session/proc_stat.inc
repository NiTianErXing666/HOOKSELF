// ---------------------------------------------------------------------------
// /proc/<pid>/stat 视图：State 字段 't'(tracing stop) → 'S'。
// stat 不虚拟化时 state='t' 直接暴露 tracer 存在，与 status 的 TracerPid 隐藏
// 自相矛盾。等长单字符改写，read 返回值不变。

bool IsProcStatReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

int ApplyProcStatReadView(TracerContext* context,
                          TaskRecord* task) noexcept {
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0 ||
        !IsProcStatReadSyscall(task->active_syscall.syscall_number)) {
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
    if (resolve_error != 0 || !ProcStatPath(resolved, resolved_length)) {
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
    const int read_error = ReadLocalFile(
            resolved, source, sizeof(source), &source_size);
    // stat 视图是新作用域（含后代/线程文件），任何解析/读取异常一律放行，
    // 不允许把 trace 会话打成 fatal。
    if (read_error != 0) {
        return 0;
    }
    ProcStatStateMetadata metadata{};
    const int parse_error = ParseProcStatStateMetadata(
            source, source_size, owner, &metadata);
    if (parse_error != 0) {
        return 0;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallProcStatView;
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
            HOOKSELF_SYSCALL_OBSERVE,
            HOOKSELF_BUILTIN_RULE_PROC_STAT_VIEW, 0);
    return 0;
}

int CompleteProcStatReadView(TracerContext* context, TaskRecord* task,
                             int64_t kernel_result) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallProcStatView) == 0) {
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
        const size_t rewritten = RewriteProcStatStateTraced(
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
            HOOKSELF_BUILTIN_RULE_PROC_STAT_VIEW, kernel_result);
    return 0;
}
