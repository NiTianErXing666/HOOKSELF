bool IsProcStatusReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

// 文件归属 pid 是否属于本 trace 树（target 或任何已跟踪任务）。
// task table 只含 trace 树成员，扫描即可；后代进程（TRACE_DESCENDANTS 下
// fork/exec 的 cat 等）也在此表内，从而被 proc 视图覆盖。
bool IsTraceTreePid(TracerContext* context, int32_t pid) noexcept {
    if (context == nullptr || context->tasks == nullptr || pid <= 0) {
        return false;
    }
    if (pid == context->target_pid) {
        return true;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* candidate =
                hookself::tracer::At(context->tasks, slot);
        if (candidate != nullptr &&
            (candidate->tgid == pid || candidate->tid == pid)) {
            return true;
        }
    }
    return false;
}

// 路径里的归属 pid 可能是线程 TID（"/proc/<tid>/..."、"task/<T>"/..."），
// 而 status 内容里的 Tgid 恒为线程组 ID。查任务表把 pid 解析成内容比对用的
// tgid；查不到（任务已退出/pid 复用）返回错误，调用方按放行处理。
int ResolveProcOwnerTgid(TracerContext* context, int32_t owner_pid,
                         int32_t* owner_tgid) noexcept {
    if (context == nullptr || context->tasks == nullptr ||
        owner_pid <= 0 || owner_tgid == nullptr) {
        return EINVAL;
    }
    if (owner_pid == context->target_pid) {
        *owner_tgid = owner_pid;
        return 0;
    }
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        const TaskRecord* candidate =
                hookself::tracer::At(context->tasks, slot);
        if (candidate != nullptr &&
            (candidate->tid == owner_pid || candidate->tgid == owner_pid)) {
            *owner_tgid = candidate->tgid;
            return 0;
        }
    }
    return ENOENT;
}

int ApplyProcStatusReadView(TracerContext* context,
                            TaskRecord* task) noexcept {
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0 ||
        !IsProcStatusReadSyscall(task->active_syscall.syscall_number)) {
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
    if (resolve_error != 0 ||
        !ProcStatusPath(resolved, resolved_length)) {
        return 0;
    }
    // 归属校验：只虚拟化 trace 树成员的 status（含 target 自身与后代），
    // 外部进程的 proc 文件原样放行。路径 pid 可能是线程 TID，先解析成
    // 内容 Tgid 比对用的 tgid。
    int32_t owner = 0;
    const int owner_error = ParseProcFileOwnerPid(
            resolved, resolved_length, task->tgid, &owner);
    if (owner_error != 0) {
        return 0;
    }
    int32_t owner_tgid = 0;
    if (ResolveProcOwnerTgid(context, owner, &owner_tgid) != 0 ||
        !IsTraceTreePid(context, owner_tgid)) {
        return 0;
    }

    uint8_t source[kProcStatusReadCapacity]{};
    size_t source_size = 0;
    const int read_error = ReadLocalFile(
            resolved, source, sizeof(source), &source_size);
    if (read_error != 0) {
        // target 自读保持历史严格语义，其余场景一律放行，避免竞态
        // （fd 指向已退出任务等）把整个 trace 会话打死。
        return owner_tgid == task->tgid &&
                               owner_tgid == context->target_pid
               ? read_error
               : 0;
    }
    ProcStatusMetadata metadata{};
    const int parse_error = ParseProcStatusMetadata(
            source, source_size, owner_tgid, &metadata);
    if (parse_error != 0) {
        return owner_tgid == task->tgid &&
                               owner_tgid == context->target_pid
               ? parse_error
               : 0;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallProcStatusView;
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_ENTRY,
            HOOKSELF_SYSCALL_OBSERVE,
            HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW, 0);
    return 0;
}

int SnapshotProcStatusReadIov(const TaskRecord* task, int64_t result,
                              iovec* vectors, size_t capacity,
                              size_t* vector_count) noexcept {
    if (task == nullptr || result <= 0 || vectors == nullptr ||
        vector_count == nullptr ||
        task->active_syscall.syscall_number != __NR_readv) {
        return EINVAL;
    }
    const int64_t raw_count = static_cast<int64_t>(
            task->active_syscall.arguments[2]);
    if (raw_count <= 0 || raw_count > kMaxProcStatusIov ||
        static_cast<uint64_t>(raw_count) > capacity) {
        return EPROTO;
    }
    const uintptr_t remote_iov = static_cast<uintptr_t>(
            task->active_syscall.arguments[1]);
    const size_t count = static_cast<size_t>(raw_count);
    const size_t byte_count = count * sizeof(iovec);
    if (remote_iov == 0 ||
        remote_iov > UINTPTR_MAX - (byte_count - 1U)) {
        return EOVERFLOW;
    }
    const int read_error = ReadRemoteBytes(
            task->tgid, task->tid, remote_iov, vectors, byte_count);
    if (read_error != 0) {
        return read_error;
    }

    size_t remaining = static_cast<size_t>(result);
    for (size_t index = 0; index < count && remaining != 0; ++index) {
        const size_t chunk = vectors[index].iov_len < remaining
                                     ? vectors[index].iov_len
                                     : remaining;
        const uintptr_t base = reinterpret_cast<uintptr_t>(
                vectors[index].iov_base);
        if (chunk != 0 &&
            (base == 0 || base > UINTPTR_MAX - (chunk - 1U))) {
            return EFAULT;
        }
        remaining -= chunk;
    }
    if (remaining != 0) {
        return EPROTO;
    }
    *vector_count = count;
    return 0;
}

int GatherProcStatusReadOutput(const TaskRecord* task, int64_t result,
                               const iovec* vectors, size_t vector_count,
                               uint8_t* output, size_t capacity) noexcept {
    if (result <= 0 || static_cast<uint64_t>(result) > capacity) {
        return result <= 0 ? EINVAL : EOVERFLOW;
    }
    const size_t result_size = static_cast<size_t>(result);
    const int32_t syscall_number = task->active_syscall.syscall_number;
    if (syscall_number == __NR_read || syscall_number == __NR_pread64) {
        return ReadRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(task->active_syscall.arguments[1]),
                output, result_size);
    }
    if (syscall_number != __NR_readv) {
        return EINVAL;
    }
    if (vectors == nullptr || vector_count == 0 ||
        vector_count > kMaxProcStatusIov) {
        return EPROTO;
    }
    size_t copied = 0;
    for (size_t index = 0; index < vector_count && copied < result_size;
         ++index) {
        const size_t remaining = result_size - copied;
        const size_t chunk = vectors[index].iov_len < remaining
                                     ? vectors[index].iov_len
                                     : remaining;
        if (chunk != 0) {
            const int read_error = ReadRemoteBytes(
                    task->tgid, task->tid,
                    reinterpret_cast<uintptr_t>(vectors[index].iov_base),
                    output + copied, chunk);
            if (read_error != 0) {
                return read_error;
            }
            copied += chunk;
        }
    }
    return copied == result_size ? 0 : EPROTO;
}

int ScatterProcStatusReadOutput(const TaskRecord* task, int64_t result,
                                const iovec* vectors, size_t vector_count,
                                const uint8_t* input) noexcept {
    const size_t result_size = static_cast<size_t>(result);
    const int32_t syscall_number = task->active_syscall.syscall_number;
    if (syscall_number == __NR_read || syscall_number == __NR_pread64) {
        return WriteRemoteBytes(
                task->tgid, task->tid,
                static_cast<uintptr_t>(task->active_syscall.arguments[1]),
                input, result_size);
    }
    if (syscall_number != __NR_readv) {
        return EINVAL;
    }
    if (vectors == nullptr || vector_count == 0 ||
        vector_count > kMaxProcStatusIov) {
        return EPROTO;
    }
    size_t copied = 0;
    for (size_t index = 0; index < vector_count && copied < result_size;
         ++index) {
        const size_t remaining = result_size - copied;
        const size_t chunk = vectors[index].iov_len < remaining
                                     ? vectors[index].iov_len
                                     : remaining;
        if (chunk != 0) {
            const int write_error = WriteRemoteBytes(
                    task->tgid, task->tid,
                    reinterpret_cast<uintptr_t>(vectors[index].iov_base),
                    input + copied, chunk);
            if (write_error != 0) {
                return write_error;
            }
            copied += chunk;
        }
    }
    return copied == result_size ? 0 : EPROTO;
}

size_t RewriteProcStatusReadOutput(uint8_t* output, size_t size) noexcept {
    // TracerPid 与 State 行都必须虚拟化且等长：
    // 只藏 TracerPid 会留下 "State: t (tracing stop)" 的自相矛盾证据
    size_t rewritten = RewriteTracerPidValue(output, size);
    rewritten += RewriteProcStatusStateLine(output, size);
    return rewritten;
}

int CompleteProcStatusReadView(TracerContext* context, TaskRecord* task,
                               int64_t kernel_result) noexcept {
    if ((task->active_syscall.flags &
         hookself::tracer::kActiveSyscallProcStatusView) == 0) {
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
        const size_t rewritten = RewriteProcStatusReadOutput(
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
            __atomic_fetch_add(&context->control->proc_status_patches, 1U,
                               __ATOMIC_RELAXED);
        }
    }
    EmitSyscallPolicyEvent(
            context, *task, HOOKSELF_SYSCALL_PHASE_EXIT,
            HOOKSELF_SYSCALL_OBSERVE,
            HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW, kernel_result);
    return 0;
}

