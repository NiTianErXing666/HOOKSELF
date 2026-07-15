bool IsProcStatusReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

int ApplyProcStatusReadView(TracerContext* context,
                            TaskRecord* task) noexcept {
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) == 0 ||
        task->tgid != context->target_pid ||
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

    uint8_t source[kProcStatusReadCapacity]{};
    size_t source_size = 0;
    const int read_error = ReadLocalFile(
            resolved, source, sizeof(source), &source_size);
    if (read_error != 0) {
        return read_error;
    }
    ProcStatusMetadata metadata{};
    const int parse_error = ParseProcStatusMetadata(
            source, source_size, context->target_pid, &metadata);
    if (parse_error != 0) {
        return parse_error;
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
    return RewriteTracerPidValue(output, size);
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

