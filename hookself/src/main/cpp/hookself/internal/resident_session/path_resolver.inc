int PathArgumentIndex(int32_t syscall_number) noexcept {
    switch (syscall_number) {
        case __NR_openat:
        case __NR_newfstatat:
        case __NR_faccessat:
        case __NR_readlinkat:
        case __NR_unlinkat:
        case __NR_mkdirat:
        case __NR_mknodat:
        case __NR_utimensat:
        case __NR_statx:
        case __NR_fchmodat:
        case __NR_fchownat:
        case __NR_openat2:
        case __NR_faccessat2:
        case __NR_execveat:
        case hookself::tracer::kMountStateMount:
        case hookself::tracer::kMountStateOpenTree:
        case hookself::tracer::kMountStateMountSetattr:
            return 1;
        case __NR_renameat:
        case __NR_renameat2:
        case __NR_linkat:
            return 1;
        case __NR_symlinkat:
            return 2;
        case __NR_chdir:
        case __NR_execve:
        case hookself::tracer::kMountStateUmount2:
        case hookself::tracer::kMountStatePivotRoot:
        case hookself::tracer::kMountStateChroot:
            return 0;
        case hookself::tracer::kMountStateMoveMount:
            return 3;
        default:
            return -1;
    }
}

int ReadRemotePath(pid_t tgid, pid_t tid, uintptr_t address, char* output,
                   size_t capacity, uint32_t* event_flags) noexcept {
    if (address == 0 || output == nullptr || capacity < 2) {
        return EFAULT;
    }
    iovec local{output, capacity};
    iovec remote{reinterpret_cast<void*>(address), capacity};
    const long vm_result = RawSyscall6(
            __NR_process_vm_readv, tgid, reinterpret_cast<long>(&local), 1,
            reinterpret_cast<long>(&remote), 1, 0);
    if (vm_result > 0) {
        const size_t bytes = static_cast<size_t>(vm_result);
        for (size_t i = 0; i < bytes; ++i) {
            if (output[i] == '\0') {
                return 0;
            }
        }
        if (bytes == capacity) {
            output[capacity - 1] = '\0';
            *event_flags |= HOOKSELF_EVENT_F_PATH_TRUNCATED;
            return ENAMETOOLONG;
        }
    }

    size_t copied = 0;
    while (copied < capacity) {
        uint64_t word = 0;
        const int peek_error = hookself::platform::PtracePeekData(
                tid, address + copied, &word);
        if (peek_error != 0) {
            output[copied < capacity ? copied : capacity - 1] = '\0';
            return peek_error;
        }
        const auto* bytes = reinterpret_cast<const uint8_t*>(&word);
        for (size_t i = 0; i < sizeof(word) && copied < capacity; ++i) {
            output[copied++] = static_cast<char>(bytes[i]);
            if (bytes[i] == 0) {
                return 0;
            }
        }
    }
    output[capacity - 1] = '\0';
    *event_flags |= HOOKSELF_EVENT_F_PATH_TRUNCATED;
    return ENAMETOOLONG;
}

int ReadRemoteBytes(pid_t tgid, pid_t tid, uintptr_t address, void* output,
                    size_t size) noexcept {
    if (address == 0 || output == nullptr || size == 0) {
        return EFAULT;
    }
    iovec local{output, size};
    iovec remote{reinterpret_cast<void*>(address), size};
    const long vm_result = RawSyscall6(
            __NR_process_vm_readv, tgid, reinterpret_cast<long>(&local), 1,
            reinterpret_cast<long>(&remote), 1, 0);
    if (vm_result == static_cast<long>(size)) {
        return 0;
    }

    auto* bytes = static_cast<uint8_t*>(output);
    size_t copied = 0;
    while (copied < size) {
        uint64_t word = 0;
        const int peek_error = hookself::platform::PtracePeekData(
                tid, address + copied, &word);
        if (peek_error != 0) {
            return peek_error;
        }
        const size_t remaining = size - copied;
        const size_t chunk = remaining < sizeof(word) ? remaining : sizeof(word);
        const auto* word_bytes = reinterpret_cast<const uint8_t*>(&word);
        for (size_t i = 0; i < chunk; ++i) {
            bytes[copied + i] = word_bytes[i];
        }
        copied += chunk;
    }
    return 0;
}

int WriteRemoteBytes(pid_t tgid, pid_t tid, uintptr_t address,
                     const void* input, size_t size) noexcept {
    if (address == 0 || input == nullptr || size == 0) {
        return EFAULT;
    }
    iovec local{const_cast<void*>(input), size};
    iovec remote{reinterpret_cast<void*>(address), size};
    const long vm_result = RawSyscall6(
            __NR_process_vm_writev, tgid, reinterpret_cast<long>(&local), 1,
            reinterpret_cast<long>(&remote), 1, 0);
    if (vm_result == static_cast<long>(size)) {
        return 0;
    }

    const auto* input_bytes = static_cast<const uint8_t*>(input);
    size_t copied = 0;
    while (copied < size) {
        const uintptr_t current = address + copied;
        const uintptr_t aligned = current & ~(sizeof(uint64_t) - 1U);
        const size_t word_offset = static_cast<size_t>(current - aligned);
        const size_t remaining = size - copied;
        const size_t chunk = remaining < sizeof(uint64_t) - word_offset
                                     ? remaining
                                     : sizeof(uint64_t) - word_offset;
        uint64_t word = 0;
        const int peek_error = hookself::platform::PtracePeekData(
                tid, aligned, &word);
        if (peek_error != 0) {
            return peek_error;
        }
        auto* word_bytes = reinterpret_cast<uint8_t*>(&word);
        for (size_t i = 0; i < chunk; ++i) {
            word_bytes[word_offset + i] = input_bytes[copied + i];
        }
        const int poke_error = RawError(
                RawPtrace(PTRACE_POKEDATA, tid, aligned, word));
        if (poke_error != 0) {
            return poke_error;
        }
        copied += chunk;
    }
    return 0;
}

bool AppendText(char* output, size_t capacity, size_t* length,
                const char* text) noexcept {
    size_t written = *length;
    for (size_t i = 0; text[i] != '\0'; ++i) {
        if (written + 1 >= capacity) {
            return false;
        }
        output[written++] = text[i];
    }
    output[written] = '\0';
    *length = written;
    return true;
}

bool AppendPositiveDecimal(char* output, size_t capacity, size_t* length,
                           uint32_t value) noexcept {
    char reversed[16]{};
    size_t digits = 0;
    do {
        reversed[digits++] = static_cast<char>('0' + value % 10U);
        value /= 10U;
    } while (value != 0 && digits < sizeof(reversed));
    if (*length + digits + 1 > capacity) {
        return false;
    }
    while (digits != 0) {
        output[(*length)++] = reversed[--digits];
    }
    output[*length] = '\0';
    return true;
}

int InvokeExecRemoteSyscall(TaskRecord* task, int32_t syscall_number,
                            const uint64_t arguments[6],
                            int64_t* value) noexcept {
    if (task == nullptr || arguments == nullptr || value == nullptr) {
        return EINVAL;
    }
    hookself::tracer::RemoteSyscallArm64Result result{};
    const int error = hookself::tracer::InvokeStoppedArm64Syscall(
            task->tid, syscall_number, arguments, &result);
    if (error == 0) {
        *value = result.value;
    }
    return error;
}

int VerifyExecRemoteFd(TaskRecord* task, int32_t fd) noexcept {
    if (task == nullptr || fd < 0) {
        return EINVAL;
    }
    const uint64_t getfd_arguments[6] = {
            static_cast<uint64_t>(static_cast<int64_t>(fd)), F_GETFD,
            0, 0, 0, 0};
    int64_t getfd_result = -EIO;
    int error = InvokeExecRemoteSyscall(
            task, __NR_fcntl, getfd_arguments, &getfd_result);
    if (error != 0) {
        return error;
    }
    return RawError(static_cast<long>(getfd_result));
}

int MapExecTraceeScratch(TracerContext* context, TaskRecord* task) noexcept {
    if (context == nullptr || context->header == nullptr || task == nullptr ||
        context->mapping.fd < 0 || context->mapping.scratch_size == 0) {
        return EINVAL;
    }
    constexpr uint64_t kMapFixedNoReplace = 0x100000U;
    uint64_t requested_address = task->tracee_scratch_address;
    uint64_t flags = MAP_SHARED;
    if (requested_address != 0) {
        flags |= kMapFixedNoReplace;
    }
    uint64_t arguments[6] = {
            requested_address, context->mapping.scratch_size, PROT_READ,
            flags, static_cast<uint64_t>(context->mapping.fd),
            context->header->scratch.offset};
    int64_t mmap_result = -EIO;
    int error = InvokeExecRemoteSyscall(
            task, __NR_mmap, arguments, &mmap_result);
    if (error != 0) {
        return error;
    }
    int mmap_error = RawError(static_cast<long>(mmap_result));
    if (mmap_error != 0 && requested_address != 0 &&
        (mmap_error == EEXIST || mmap_error == EINVAL ||
         mmap_error == ENOTSUP)) {
        arguments[0] = 0;
        arguments[3] = MAP_SHARED;
        error = InvokeExecRemoteSyscall(
                task, __NR_mmap, arguments, &mmap_result);
        if (error != 0) {
            return error;
        }
        mmap_error = RawError(static_cast<long>(mmap_result));
    }
    if (mmap_error != 0 || mmap_result <= 0) {
        return mmap_error != 0 ? mmap_error : EFAULT;
    }
    if ((flags & kMapFixedNoReplace) != 0 &&
        arguments[0] != 0 && mmap_result != static_cast<int64_t>(arguments[0])) {
        return EPROTO;
    }
    task->tracee_scratch_address = static_cast<uint64_t>(mmap_result);
    return 0;
}

int RebuildExecAddressSpace(TracerContext* context,
                            TaskRecord* task) noexcept {
    if (context == nullptr || context->control == nullptr || task == nullptr) {
        return EINVAL;
    }
    const uint32_t count = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return EPROTO;
    }
    for (uint32_t index = 0; index < count; ++index) {
        const int32_t fd = context->control->protected_fds[index];
        if (!IsProtectedFdForTask(context, task, fd)) {
            continue;
        }
        int error = VerifyExecRemoteFd(task, fd);
        if (error != 0) {
            return error;
        }
        if (context->path_state != nullptr &&
            hookself::tracer::FindPathTask(
                    context->path_state, task->tid) != nullptr) {
            hookself::tracer::FdIdentitySpec identity{};
            identity.origin_flags = hookself::tracer::kPathOriginProtected;
            identity.cloexec = 0;
            error = hookself::tracer::RecordFdIdentity(
                    context->path_state, task->tid, fd, identity);
            if (error != 0) {
                return error;
            }
        }
    }
    if (context->writable_scratch != nullptr) {
        return MapExecTraceeScratch(context, task);
    }
    task->tracee_scratch_address = 0;
    return 0;
}

int BuildProcFdEntryPath(pid_t tid, int32_t fd, bool fdinfo, char* output,
                         size_t capacity) noexcept {
    if (tid <= 0 || fd < 0 || output == nullptr || capacity < 2) {
        return EINVAL;
    }
    size_t length = 0;
    if (!AppendText(output, capacity, &length, "/proc/") ||
        !AppendPositiveDecimal(output, capacity, &length,
                               static_cast<uint32_t>(tid)) ||
        !AppendText(output, capacity, &length,
                    fdinfo ? "/fdinfo/" : "/fd/") ||
        !AppendPositiveDecimal(output, capacity, &length,
                               static_cast<uint32_t>(fd))) {
        return ENAMETOOLONG;
    }
    return 0;
}

int ReadLocalFile(const char* path, uint8_t* output, size_t capacity,
                  size_t* output_size) noexcept {
    if (path == nullptr || output == nullptr || capacity == 0 ||
        output_size == nullptr) {
        return EINVAL;
    }
    const long fd_result = hookself::platform::RawOpenAt(
            AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    const int open_error = RawError(fd_result);
    if (open_error != 0) {
        return open_error;
    }
    const int fd = static_cast<int>(fd_result);
    size_t length = 0;
    int result = 0;
    while (length < capacity) {
        const long read_result = hookself::platform::RawRead(
                fd, output + length, capacity - length);
        const int read_error = RawError(read_result);
        if (read_error == EINTR) {
            continue;
        }
        if (read_error != 0) {
            result = read_error;
            break;
        }
        if (read_result == 0) {
            break;
        }
        length += static_cast<size_t>(read_result);
    }
    if (result == 0 && length == capacity) {
        uint8_t extra = 0;
        const long extra_result = hookself::platform::RawRead(fd, &extra, 1);
        if (extra_result > 0) {
            result = EOVERFLOW;
        } else if (RawError(extra_result) != 0 &&
                   RawError(extra_result) != EINTR) {
            result = RawError(extra_result);
        }
    }
    (void)hookself::platform::RawClose(fd);
    *output_size = length;
    return result;
}

bool ProcStatusPath(const char* path, size_t length) noexcept {
    constexpr char kPrefix[] = "/proc/";
    constexpr char kSuffix[] = "/status";
    if (path == nullptr || length < sizeof(kPrefix) - 1U +
                                       sizeof(kSuffix) - 1U) {
        return false;
    }
    for (size_t i = 0; i < sizeof(kPrefix) - 1U; ++i) {
        if (path[i] != kPrefix[i]) {
            return false;
        }
    }
    const size_t suffix_start = length - (sizeof(kSuffix) - 1U);
    for (size_t i = 0; i < sizeof(kSuffix) - 1U; ++i) {
        if (path[suffix_start + i] != kSuffix[i]) {
            return false;
        }
    }
    return true;
}

// "/proc/..." 前缀 + "/stat" 后缀。"/statm" 因后缀多一个字符不会误配。
bool ProcStatPath(const char* path, size_t length) noexcept {
    constexpr char kPrefix[] = "/proc/";
    constexpr char kSuffix[] = "/stat";
    if (path == nullptr || length < sizeof(kPrefix) - 1U +
                                       sizeof(kSuffix) - 1U) {
        return false;
    }
    for (size_t i = 0; i < sizeof(kPrefix) - 1U; ++i) {
        if (path[i] != kPrefix[i]) {
            return false;
        }
    }
    const size_t suffix_start = length - (sizeof(kSuffix) - 1U);
    for (size_t i = 0; i < sizeof(kSuffix) - 1U; ++i) {
        if (path[suffix_start + i] != kSuffix[i]) {
            return false;
        }
    }
    return true;
}

// "/proc/..." 前缀 + "/wchan" 后缀。
bool ProcWchanPath(const char* path, size_t length) noexcept {
    constexpr char kPrefix[] = "/proc/";
    constexpr char kSuffix[] = "/wchan";
    if (path == nullptr || length < sizeof(kPrefix) - 1U +
                                       sizeof(kSuffix) - 1U) {
        return false;
    }
    for (size_t i = 0; i < sizeof(kPrefix) - 1U; ++i) {
        if (path[i] != kPrefix[i]) {
            return false;
        }
    }
    const size_t suffix_start = length - (sizeof(kSuffix) - 1U);
    for (size_t i = 0; i < sizeof(kSuffix) - 1U; ++i) {
        if (path[suffix_start + i] != kSuffix[i]) {
            return false;
        }
    }
    return true;
}

bool ProcPathPrefixEquals(const char* path, const char* prefix,
                          size_t prefix_length) noexcept {
    for (size_t i = 0; i < prefix_length; ++i) {
        if (path[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

// 从 "/proc/<N>/..." 或 "/proc/self|thread-self[/task/<T>]/..." 解析出
// proc 文件归属的进程/TID。"self" 解析为读取者的 tgid，"task/<T>" 覆盖为 T。
int ParseProcFileOwnerPid(const char* path, size_t length,
                          int32_t reader_tgid, int32_t* owner) noexcept {
    if (path == nullptr || owner == nullptr || reader_tgid <= 0) {
        return EINVAL;
    }
    *owner = 0;
    constexpr char kPrefix[] = "/proc/";
    constexpr size_t kPrefixLength = sizeof(kPrefix) - 1U;
    if (length < kPrefixLength + 2U ||
        !ProcPathPrefixEquals(path, kPrefix, kPrefixLength)) {
        return EPROTO;
    }
    size_t cursor = kPrefixLength;
    size_t seg_start = cursor;
    while (cursor < length && path[cursor] != '/') {
        ++cursor;
    }
    if (cursor == seg_start) {
        return EPROTO;
    }
    const size_t seg_length = cursor - seg_start;
    int64_t owner_value = -1;
    if (seg_length == 4 && path[seg_start] == 's' &&
        path[seg_start + 1U] == 'e' && path[seg_start + 2U] == 'l' &&
        path[seg_start + 3U] == 'f') {
        owner_value = reader_tgid;
    } else if (seg_length == 11 &&
               path[seg_start] == 't' && path[seg_start + 1U] == 'h' &&
               path[seg_start + 2U] == 'r' && path[seg_start + 3U] == 'e' &&
               path[seg_start + 4U] == 'a' && path[seg_start + 5U] == 'd' &&
               path[seg_start + 6U] == '-' && path[seg_start + 7U] == 's' &&
               path[seg_start + 8U] == 'e' && path[seg_start + 9U] == 'l' &&
               path[seg_start + 10U] == 'f') {
        // thread-self 归属读取线程所在线程组
        owner_value = reader_tgid;
    } else {
        owner_value = 0;
        bool digits = true;
        for (size_t i = 0; i < seg_length; ++i) {
            if (path[seg_start + i] < '0' || path[seg_start + i] > '9') {
                digits = false;
                break;
            }
            owner_value = owner_value * 10 + (path[seg_start + i] - '0');
            if (owner_value > INT32_MAX) {
                return EPROTO;
            }
        }
        if (!digits || owner_value <= 0) {
            return EPROTO;
        }
    }
    // "/proc/<N>/task/<T>/status|stat" 归属线程 T
    if (cursor < length) {
        size_t rest = cursor + 1U;
        constexpr char kTask[] = "task/";
        constexpr size_t kTaskLength = sizeof(kTask) - 1U;
        if (length - rest >= kTaskLength &&
            ProcPathPrefixEquals(path + rest, kTask, kTaskLength)) {
            rest += kTaskLength;
            const size_t tid_start = rest;
            while (rest < length && path[rest] != '/') {
                ++rest;
            }
            if (rest == tid_start) {
                return EPROTO;
            }
            int64_t tid_value = 0;
            for (size_t i = tid_start; i < rest; ++i) {
                if (path[i] < '0' || path[i] > '9') {
                    return EPROTO;
                }
                tid_value = tid_value * 10 + (path[i] - '0');
                if (tid_value > INT32_MAX) {
                    return EPROTO;
                }
            }
            if (tid_value <= 0) {
                return EPROTO;
            }
            owner_value = tid_value;
        }
    }
    *owner = static_cast<int32_t>(owner_value);
    return 0;
}

int ResolveTargetFdPath(const TaskRecord* task, int32_t fd, char* output,
                        size_t capacity, size_t* output_length) noexcept {
    char proc_path[96]{};
    const int path_error = BuildProcFdEntryPath(
            task->tid, fd, false, proc_path, sizeof(proc_path));
    if (path_error != 0) {
        return path_error;
    }
    const long link_result = RawSyscall6(
            __NR_readlinkat, AT_FDCWD, reinterpret_cast<long>(proc_path),
            reinterpret_cast<long>(output), static_cast<long>(capacity - 1U));
    const int link_error = RawError(link_result);
    if (link_error != 0) {
        return link_error;
    }
    if (link_result <= 0 || static_cast<size_t>(link_result) >= capacity) {
        return link_result == 0 ? ENOENT : ENAMETOOLONG;
    }
    *output_length = static_cast<size_t>(link_result);
    output[*output_length] = '\0';
    return 0;
}

int ReadTaskPathBase(const TaskRecord* task, int32_t dirfd, char* output,
                     size_t capacity, size_t* output_length) noexcept {
    if (task == nullptr || output == nullptr || capacity < 2 ||
        output_length == nullptr || (dirfd < 0 && dirfd != AT_FDCWD)) {
        return EINVAL;
    }
    char proc_path[96]{};
    size_t proc_length = 0;
    if (!AppendText(proc_path, sizeof(proc_path), &proc_length, "/proc/") ||
        !AppendPositiveDecimal(proc_path, sizeof(proc_path), &proc_length,
                               static_cast<uint32_t>(task->tid))) {
        return ENAMETOOLONG;
    }
    if (dirfd == AT_FDCWD) {
        if (!AppendText(proc_path, sizeof(proc_path), &proc_length, "/cwd")) {
            return ENAMETOOLONG;
        }
    } else {
        if (!AppendText(proc_path, sizeof(proc_path), &proc_length, "/fd/") ||
            !AppendPositiveDecimal(proc_path, sizeof(proc_path), &proc_length,
                                   static_cast<uint32_t>(dirfd))) {
            return ENAMETOOLONG;
        }
    }
    const long link_result = RawSyscall6(
            __NR_readlinkat, AT_FDCWD, reinterpret_cast<long>(proc_path),
            reinterpret_cast<long>(output), static_cast<long>(capacity - 1U));
    const int link_error = RawError(link_result);
    if (link_error != 0) {
        return link_error;
    }
    if (link_result <= 0 || static_cast<size_t>(link_result) >= capacity - 1U) {
        return link_result == 0 ? ENOENT : ENAMETOOLONG;
    }
    *output_length = static_cast<size_t>(link_result);
    output[*output_length] = '\0';
    return output[0] == '/' ? 0 : ENOTDIR;
}

int InitializeAttachedPathState(TracerContext* context) noexcept {
    if (context == nullptr || context->path_state == nullptr ||
        context->tasks == nullptr ||
        !hookself::tracer::IsPathStateInitialized(context->path_state)) {
        return EINVAL;
    }
    TaskRecord* seed = nullptr;
    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* candidate = hookself::tracer::At(context->tasks, slot);
        if (candidate != nullptr && candidate->tgid == context->target_pid) {
            seed = candidate;
            if (candidate->tid == context->target_pid) {
                break;
            }
        }
    }
    if (seed == nullptr) {
        return ESRCH;
    }

    char cwd[HOOKSELF_PATH_CAPACITY]{};
    size_t cwd_length = 0;
    int error = ReadTaskPathBase(
            seed, AT_FDCWD, cwd, sizeof(cwd), &cwd_length);
    if (error != 0 || cwd_length == 0) {
        return error != 0 ? error : EPROTO;
    }
    error = hookself::tracer::InsertInitialPathTask(
            context->path_state, seed->tid, cwd, cwd);
    if (error != 0) {
        return error;
    }

    for (uint32_t slot = 0; slot < hookself::tracer::Capacity(); ++slot) {
        TaskRecord* task = hookself::tracer::At(context->tasks, slot);
        if (task == nullptr || task->tid == seed->tid) {
            continue;
        }
        if (task->tgid != seed->tgid) {
            return EPROTO;
        }
        error = hookself::tracer::ClonePathTask(
                context->path_state, seed->tid, task->tid,
                hookself::tracer::kPathCloneFs |
                        hookself::tracer::kPathCloneFiles);
        if (error != 0) {
            return error;
        }
    }

    const uint32_t protected_count = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (protected_count > kMaxProtectedFds) {
        return EPROTO;
    }
    for (uint32_t index = 0; index < protected_count; ++index) {
        const int32_t fd = context->control->protected_fds[index];
        hookself::tracer::FdIdentitySpec identity{};
        identity.origin_flags = hookself::tracer::kPathOriginProtected;
        identity.cloexec = 0;
        error = hookself::tracer::RecordFdIdentity(
                context->path_state, seed->tid, fd, identity);
        if (error != 0) {
            return error;
        }
    }
    return hookself::tracer::ValidatePathState(context->path_state)
                   ? 0
                   : EPROTO;
}

int NormalizeAbsolutePath(const char* input, size_t input_length, char* output,
                          size_t capacity, size_t* output_length) noexcept {
    if (input == nullptr || output == nullptr || output_length == nullptr ||
        input_length == 0 || input[0] != '/' || capacity < 2) {
        return EINVAL;
    }
    const bool trailing_slash = input_length > 1 && input[input_length - 1] == '/';
    size_t written = 1;
    output[0] = '/';
    size_t cursor = 1;
    while (cursor < input_length) {
        while (cursor < input_length && input[cursor] == '/') {
            ++cursor;
        }
        const size_t segment_start = cursor;
        while (cursor < input_length && input[cursor] != '/') {
            ++cursor;
        }
        const size_t segment_length = cursor - segment_start;
        if (segment_length == 0 ||
            (segment_length == 1 && input[segment_start] == '.')) {
            continue;
        }
        if (segment_length == 2 && input[segment_start] == '.' &&
            input[segment_start + 1] == '.') {
            while (written > 1 && output[written - 1] != '/') {
                --written;
            }
            if (written > 1) {
                --written;
            }
            continue;
        }
        const size_t separator = written > 1 ? 1U : 0U;
        if (written + separator + segment_length + 1 > capacity) {
            return ENAMETOOLONG;
        }
        if (separator != 0) {
            output[written++] = '/';
        }
        for (size_t i = 0; i < segment_length; ++i) {
            output[written++] = input[segment_start + i];
        }
    }
    if (trailing_slash && written > 1) {
        if (written + 2 > capacity) {
            return ENAMETOOLONG;
        }
        output[written++] = '/';
    }
    output[written] = '\0';
    *output_length = written;
    return 0;
}

struct PathOperandSpec {
    uint32_t argument_index;
    uint32_t operations;
    int32_t dirfd_argument_index;
};

size_t BoundedLength(const char* value, size_t capacity) noexcept;

int ReverseTranslatePath(const SharedRuleBankHeader* bank,
                          const char* host_path, size_t host_length,
                          char* guest_path, size_t guest_capacity,
                          size_t* guest_length, bool* translated,
                          uint32_t* rule_id) noexcept;

int ResolveHostPathToGuest(TracerContext* context, const TaskRecord* task,
                           const SharedRuleBankHeader* bank,
                           const char* host_path, size_t host_length,
                           char* guest_path, size_t guest_capacity,
                           size_t* guest_length, bool* translated,
                           uint32_t* rule_id) noexcept;

int CombineAndNormalizePath(const char* base, size_t base_length,
                            const char* relative, size_t relative_length,
                            char* output, size_t output_capacity,
                            size_t* output_length) noexcept {
    if (base == nullptr || relative == nullptr || output == nullptr ||
        output_length == nullptr || base_length == 0 || base[0] != '/') {
        return EINVAL;
    }
    char combined[HOOKSELF_PATH_CAPACITY]{};
    if (base_length + relative_length + 2U > sizeof(combined)) {
        return ENAMETOOLONG;
    }
    size_t combined_length = 0;
    for (size_t index = 0; index < base_length; ++index) {
        combined[combined_length++] = base[index];
    }
    if (combined[combined_length - 1U] != '/') {
        combined[combined_length++] = '/';
    }
    for (size_t index = 0; index < relative_length; ++index) {
        combined[combined_length++] = relative[index];
    }
    combined[combined_length] = '\0';
    return NormalizeAbsolutePath(
            combined, combined_length, output, output_capacity,
            output_length);
}

// Uses root as a lexical floor. This covers absolute lookups after chroot and
// both absolute and relative lookups constrained by openat2 RESOLVE_IN_ROOT.
int CombineRootAndNormalizePath(const char* root, size_t root_length,
                                const char* path,
                                size_t path_length, char* output,
                                size_t output_capacity,
                                size_t* output_length) noexcept {
    if (root == nullptr || path == nullptr || output == nullptr ||
        output_length == nullptr || root_length == 0 || root[0] != '/' ||
        path_length == 0 || output_capacity < 2U) {
        return EINVAL;
    }

    char normalized_root[HOOKSELF_PATH_CAPACITY]{};
    size_t normalized_root_length = 0;
    int error = NormalizeAbsolutePath(
            root, root_length, normalized_root, sizeof(normalized_root),
            &normalized_root_length);
    if (error != 0) {
        return error;
    }
    while (normalized_root_length > 1U &&
           normalized_root[normalized_root_length - 1U] == '/') {
        --normalized_root_length;
    }
    if (normalized_root_length + 1U > output_capacity) {
        return ENAMETOOLONG;
    }
    for (size_t index = 0; index < normalized_root_length; ++index) {
        output[index] = normalized_root[index];
    }
    size_t written = normalized_root_length;
    const size_t root_floor = written;
    const bool trailing_slash = path_length > 1U &&
                                path[path_length - 1U] == '/';
    size_t cursor = path[0] == '/' ? 1U : 0U;
    while (cursor < path_length) {
        while (cursor < path_length && path[cursor] == '/') {
            ++cursor;
        }
        const size_t segment_start = cursor;
        while (cursor < path_length && path[cursor] != '/') {
            ++cursor;
        }
        const size_t segment_length = cursor - segment_start;
        if (segment_length == 0U ||
            (segment_length == 1U && path[segment_start] == '.')) {
            continue;
        }
        if (segment_length == 2U && path[segment_start] == '.' &&
            path[segment_start + 1U] == '.') {
            while (written > root_floor && output[written - 1U] != '/') {
                --written;
            }
            if (written > root_floor) {
                --written;
            }
            continue;
        }
        const size_t separator = written > 1U ? 1U : 0U;
        if (written + separator + segment_length + 1U > output_capacity) {
            return ENAMETOOLONG;
        }
        if (separator != 0U) {
            output[written++] = '/';
        }
        for (size_t index = 0; index < segment_length; ++index) {
            output[written++] = path[segment_start + index];
        }
    }
    if (trailing_slash && written > root_floor) {
        if (written + 2U > output_capacity) {
            return ENAMETOOLONG;
        }
        output[written++] = '/';
    }
    output[written] = '\0';
    *output_length = written;
    return 0;
}

int ResolveAbsolutePathFromTaskRoot(
        TracerContext* context, const TaskRecord* task, const char* original,
        size_t original_length, char* guest_canonical,
        size_t guest_capacity, size_t* guest_length, char* host_canonical,
        size_t host_capacity, size_t* host_length,
        uint32_t* origin_flags) noexcept {
    if (original == nullptr || guest_canonical == nullptr ||
        guest_length == nullptr || host_canonical == nullptr ||
        host_length == nullptr || original_length == 0U || original[0] != '/') {
        return EINVAL;
    }
    constexpr uint32_t kRequiredOrigins =
            hookself::tracer::kPathOriginGuestValid |
            hookself::tracer::kPathOriginHostValid;
    const hookself::tracer::FsContext* fs =
            context == nullptr || task == nullptr || context->path_state == nullptr
                    ? nullptr
                    : hookself::tracer::GetTaskFsContext(
                              context->path_state, task->tid);
    if (fs != nullptr && (fs->root_origin_flags & kRequiredOrigins) ==
                              kRequiredOrigins) {
        const size_t guest_root_length = BoundedLength(
                fs->guest_root, sizeof(fs->guest_root));
        const size_t host_root_length = BoundedLength(
                fs->host_root, sizeof(fs->host_root));
        if (guest_root_length >= sizeof(fs->guest_root) ||
            host_root_length >= sizeof(fs->host_root)) {
            return EPROTO;
        }
        int error = CombineRootAndNormalizePath(
                fs->guest_root, guest_root_length, original, original_length,
                guest_canonical, guest_capacity, guest_length);
        if (error == 0) {
            error = CombineRootAndNormalizePath(
                    fs->host_root, host_root_length, original, original_length,
                    host_canonical, host_capacity, host_length);
        }
        if (error == 0 && origin_flags != nullptr) {
            *origin_flags = fs->root_origin_flags | kRequiredOrigins;
        }
        return error;
    }

    int error = NormalizeAbsolutePath(
            original, original_length, guest_canonical, guest_capacity,
            guest_length);
    if (error == 0) {
        error = NormalizeAbsolutePath(
                original, original_length, host_canonical, host_capacity,
                host_length);
    }
    if (error == 0 && origin_flags != nullptr) {
        *origin_flags = kRequiredOrigins;
    }
    return error;
}

int ResolvePathBases(TracerContext* context, const TaskRecord* task,
                     const SharedRuleBankHeader* bank, int32_t dirfd,
                     char* guest_base, size_t guest_capacity,
                     size_t* guest_length, char* host_base,
                     size_t host_capacity, size_t* host_length,
                     uint32_t* origin_flags) noexcept {
    if (context == nullptr || task == nullptr || guest_base == nullptr ||
        guest_length == nullptr || host_base == nullptr ||
        host_length == nullptr || origin_flags == nullptr) {
        return EINVAL;
    }
    *origin_flags = 0;
    const char* known_guest = nullptr;
    const char* known_host = nullptr;
    uint32_t known_flags = 0;
    hookself::tracer::FdIdentityView fd_view{};
    if (context->path_state != nullptr) {
        if (dirfd == AT_FDCWD) {
            const hookself::tracer::FsContext* fs =
                    hookself::tracer::GetTaskFsContext(
                            context->path_state, task->tid);
            if (fs != nullptr) {
                known_guest = fs->guest_cwd;
                known_host = fs->host_cwd;
                known_flags = fs->cwd_origin_flags;
            }
        } else {
            if (hookself::tracer::ResolveFdIdentityView(
                        context->path_state, task->tid, dirfd,
                        &fd_view) == 0) {
                known_guest = fd_view.guest_path;
                known_host = fd_view.host_path;
                known_flags = fd_view.origin_flags;
            }
        }
    }
    const uint32_t required = hookself::tracer::kPathOriginGuestValid |
                              hookself::tracer::kPathOriginHostValid;
    if ((known_flags & required) == required) {
        const size_t known_guest_length = BoundedLength(
                known_guest, HOOKSELF_PATH_CAPACITY);
        const size_t known_host_length = BoundedLength(
                known_host, HOOKSELF_PATH_CAPACITY);
        if (known_guest_length >= guest_capacity ||
            known_host_length >= host_capacity) {
            return ENAMETOOLONG;
        }
        for (size_t index = 0; index <= known_guest_length; ++index) {
            guest_base[index] = known_guest[index];
        }
        for (size_t index = 0; index <= known_host_length; ++index) {
            host_base[index] = known_host[index];
        }
        *guest_length = known_guest_length;
        *host_length = known_host_length;
        *origin_flags = known_flags;
        return 0;
    }

    const int base_error = ReadTaskPathBase(
            task, dirfd, host_base, host_capacity, host_length);
    if (base_error != 0) {
        return base_error;
    }
    bool reversed = false;
    uint32_t reverse_rule_id = 0;
    const int reverse_error = ResolveHostPathToGuest(
            context, task, bank, host_base, *host_length, guest_base,
            guest_capacity, guest_length, &reversed, &reverse_rule_id);
    if (reverse_error != 0) {
        return reverse_error;
    }
    *origin_flags = required | hookself::tracer::kPathOriginAmbiguous |
                    (reversed
                             ? hookself::tracer::kPathOriginReverseVisible
                             : 0U);
    if (dirfd != AT_FDCWD && context->path_state != nullptr) {
        hookself::tracer::FdIdentitySpec identity{};
        identity.origin_flags = *origin_flags;
        identity.directory = 1;
        identity.guest_path = guest_base;
        identity.host_path = host_base;
        const int record_error = hookself::tracer::RecordFdIdentity(
                context->path_state, task->tid, dirfd, identity);
        if (record_error != 0) {
            return record_error;
        }
    }
    (void)reverse_rule_id;
    return 0;
}

int ResolvePolicyPath(TracerContext* context, const TaskRecord* task,
                      const SharedRuleBankHeader* bank,
                      const PathOperandSpec& operand,
                      const uint64_t arguments[6], const char* original,
                      size_t original_length, char* guest_canonical,
                      size_t guest_capacity, size_t* guest_length,
                      char* host_canonical, size_t host_capacity,
                      size_t* host_length, uint32_t* origin_flags,
                      bool* resolved_relative) noexcept {
    *resolved_relative = false;
    if (original_length != 0 && original[0] == '/') {
        return ResolveAbsolutePathFromTaskRoot(
                context, task, original, original_length, guest_canonical,
                guest_capacity, guest_length, host_canonical, host_capacity,
                host_length, origin_flags);
    }
    if (original_length == 0 || operand.dirfd_argument_index < -2 ||
        operand.dirfd_argument_index >= 6 ||
        operand.dirfd_argument_index == -1) {
        return ENOENT;
    }
    const int32_t dirfd = operand.dirfd_argument_index == -2
                                  ? AT_FDCWD
                                  : static_cast<int32_t>(
                                            arguments[
                                                    operand.dirfd_argument_index]);
    char guest_base[HOOKSELF_PATH_CAPACITY]{};
    char host_base[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_base_length = 0;
    size_t host_base_length = 0;
    uint32_t resolved_origin_flags = 0;
    const int base_error = ResolvePathBases(
            context, task, bank, dirfd,
            guest_base, sizeof(guest_base), &guest_base_length,
            host_base, sizeof(host_base), &host_base_length,
            &resolved_origin_flags);
    if (base_error != 0) {
        return base_error;
    }
    int normalize_error = CombineAndNormalizePath(
            guest_base, guest_base_length, original, original_length,
            guest_canonical, guest_capacity, guest_length);
    if (normalize_error == 0) {
        normalize_error = CombineAndNormalizePath(
                host_base, host_base_length, original, original_length,
                host_canonical, host_capacity, host_length);
    }
    if (normalize_error == 0) {
        *resolved_relative = true;
        if (origin_flags != nullptr) {
            *origin_flags = resolved_origin_flags;
        }
    }
    return normalize_error;
}

int ResolvePolicyPathInRoot(TracerContext* context, const TaskRecord* task,
                            const SharedRuleBankHeader* bank,
                            const PathOperandSpec& operand,
                            const uint64_t arguments[6], const char* original,
                            size_t original_length, char* guest_canonical,
                            size_t guest_capacity, size_t* guest_length,
                            char* host_canonical, size_t host_capacity,
                            size_t* host_length, uint32_t* origin_flags,
                            bool* resolved_relative) noexcept {
    *resolved_relative = false;
    if (original == nullptr || original_length == 0U ||
        operand.dirfd_argument_index < -2 || operand.dirfd_argument_index >= 6 ||
        operand.dirfd_argument_index == -1) {
        return ENOENT;
    }
    const int32_t dirfd = operand.dirfd_argument_index == -2
                                  ? AT_FDCWD
                                  : static_cast<int32_t>(
                                            arguments[
                                                    operand.dirfd_argument_index]);
    char guest_base[HOOKSELF_PATH_CAPACITY]{};
    char host_base[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_base_length = 0;
    size_t host_base_length = 0;
    uint32_t resolved_origin_flags = 0;
    const int base_error = ResolvePathBases(
            context, task, bank, dirfd,
            guest_base, sizeof(guest_base), &guest_base_length,
            host_base, sizeof(host_base), &host_base_length,
            &resolved_origin_flags);
    if (base_error != 0) {
        return base_error;
    }
    int normalize_error = CombineRootAndNormalizePath(
            guest_base, guest_base_length, original, original_length,
            guest_canonical, guest_capacity, guest_length);
    if (normalize_error == 0) {
        normalize_error = CombineRootAndNormalizePath(
                host_base, host_base_length, original, original_length,
                host_canonical, host_capacity, host_length);
    }
    if (normalize_error == 0) {
        *resolved_relative = true;
        if (origin_flags != nullptr) {
            *origin_flags = resolved_origin_flags;
        }
    }
    return normalize_error;
}

size_t BoundedLength(const char* value, size_t capacity) noexcept {
    if (value == nullptr) {
        return capacity;
    }
    for (size_t i = 0; i < capacity; ++i) {
        if (value[i] == '\0') {
            return i;
        }
    }
    return capacity;
}

bool PathsEqual(const char* left, size_t left_length,
                const char* right, size_t right_length) noexcept {
    if (left == nullptr || right == nullptr || left_length != right_length) {
        return false;
    }
    for (size_t index = 0; index < left_length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

bool CanonicalAbsolutePath(const char* path, size_t length) noexcept {
    if (length == 0 || path[0] != '/') {
        return false;
    }
    if (length == 1) {
        return true;
    }
    size_t segment_start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && path[i] != '/') {
            continue;
        }
        const size_t segment_length = i - segment_start;
        if (segment_length == 0 && i == length) {
            return true;
        }
        if (segment_length == 0 ||
            (segment_length == 1 && path[segment_start] == '.') ||
            (segment_length == 2 && path[segment_start] == '.' &&
             path[segment_start + 1] == '.')) {
            return false;
        }
        segment_start = i + 1;
    }
    return true;
}

bool PrefixMatches(const char* path, size_t path_length, const char* prefix,
                   size_t prefix_length) noexcept {
    if (prefix_length > path_length) {
        return false;
    }
    for (size_t i = 0; i < prefix_length; ++i) {
        if (path[i] != prefix[i]) {
            return false;
        }
    }
    return (prefix_length == 1 && prefix[0] == '/') ||
           prefix_length == path_length || path[prefix_length] == '/';
}

uint32_t OpenPathOperations(uint64_t flags) noexcept {
    uint32_t operations = HOOKSELF_PATH_OP_LOOKUP;
    const int access_mode = static_cast<int>(flags) & O_ACCMODE;
    if (access_mode == O_RDONLY || access_mode == O_RDWR) {
        operations |= HOOKSELF_PATH_OP_READ;
    }
    if (access_mode == O_WRONLY || access_mode == O_RDWR) {
        operations |= HOOKSELF_PATH_OP_WRITE;
    }
    if ((flags & O_CREAT) != 0) {
        operations |= HOOKSELF_PATH_OP_CREATE;
    }
    return operations;
}

bool ReadOpenAt2How(const TaskRecord* task, const uint64_t arguments[6],
                    open_how* how) noexcept {
    if (task == nullptr || how == nullptr || arguments[2] == 0 ||
        arguments[3] < sizeof(open_how)) {
        return false;
    }
    *how = {};
    return ReadRemoteBytes(
                   task->tgid, task->tid,
                   static_cast<uintptr_t>(arguments[2]), how,
                   sizeof(*how)) == 0;
}

bool UsesOpenAt2InRoot(int32_t syscall_number, bool open_how_valid,
                       const open_how& how) noexcept {
    return syscall_number == __NR_openat2 && open_how_valid &&
           (how.resolve & RESOLVE_IN_ROOT) != 0;
}

uint32_t AccessPathOperations(uint64_t mode) noexcept {
    uint32_t operations = HOOKSELF_PATH_OP_LOOKUP;
    if ((mode & R_OK) != 0) {
        operations |= HOOKSELF_PATH_OP_READ;
    }
    if ((mode & W_OK) != 0) {
        operations |= HOOKSELF_PATH_OP_WRITE;
    }
    if ((mode & X_OK) != 0) {
        operations |= HOOKSELF_PATH_OP_EXECUTE;
    }
    return operations;
}

size_t PathOperandsForSyscall(int32_t syscall_number,
                              const uint64_t arguments[6],
                              PathOperandSpec operands[2]) noexcept {
    switch (syscall_number) {
        case __NR_openat:
            operands[0] = {1, OpenPathOperations(arguments[2]), 0};
            return 1;
        case __NR_openat2:
            operands[0] = {1, HOOKSELF_PATH_OP_ALL, 0};
            return 1;
        case __NR_newfstatat:
        case __NR_statx:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ |
                                      HOOKSELF_PATH_OP_METADATA, 0};
            return 1;
        case __NR_faccessat:
        case __NR_faccessat2:
            operands[0] = {1, AccessPathOperations(arguments[2]), 0};
            return 1;
        case __NR_readlinkat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ, 0};
            return 1;
        case __NR_unlinkat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_DELETE, 0};
            return 1;
        case __NR_mkdirat:
        case __NR_mknodat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_CREATE, 0};
            return 1;
        case __NR_utimensat:
        case __NR_fchmodat:
        case __NR_fchownat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, 0};
            return 1;
        case __NR_renameat:
        case __NR_renameat2:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_DELETE |
                                      HOOKSELF_PATH_OP_RENAME, 0};
            operands[1] = {3, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_CREATE |
                                      HOOKSELF_PATH_OP_RENAME, 2};
            return 2;
        case __NR_linkat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ, 0};
            operands[1] = {3, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_CREATE, 2};
            return 2;
        case __NR_symlinkat:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ, -1};
            operands[1] = {2, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_CREATE, 1};
            return 2;
        case __NR_chdir:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP, -2};
            return 1;
        case hookself::tracer::kMountStateMount:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, -2};
            if ((arguments[3] &
                 (kMountFlagBind | kMountFlagMove)) != 0) {
                operands[1] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                          HOOKSELF_PATH_OP_READ, -2};
                return 2;
            }
            return 1;
        case hookself::tracer::kMountStateUmount2:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, -2};
            return 1;
        case hookself::tracer::kMountStatePivotRoot:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, -2};
            operands[1] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, -2};
            return 2;
        case hookself::tracer::kMountStateChroot:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_METADATA, -2};
            return 1;
        case hookself::tracer::kMountStateOpenTree:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ |
                                      HOOKSELF_PATH_OP_METADATA, 0};
            return 1;
        case hookself::tracer::kMountStateMoveMount:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_READ |
                                      HOOKSELF_PATH_OP_METADATA, 0};
            operands[1] = {3, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, 2};
            return 2;
        case hookself::tracer::kMountStateMountSetattr:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_WRITE |
                                      HOOKSELF_PATH_OP_METADATA, 0};
            return 1;
        case __NR_execve:
            operands[0] = {0, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_EXECUTE, -2};
            return 1;
        case __NR_execveat:
            operands[0] = {1, HOOKSELF_PATH_OP_LOOKUP |
                                      HOOKSELF_PATH_OP_EXECUTE, 0};
            return 1;
        default:
            return 0;
    }
}

bool EmptyPathAllowed(int32_t syscall_number, size_t operand_index,
                      const uint64_t arguments[6]) noexcept {
    switch (syscall_number) {
        case __NR_newfstatat:
            return (arguments[3] & AT_EMPTY_PATH) != 0;
        case __NR_statx:
            return (arguments[2] & AT_EMPTY_PATH) != 0;
        case __NR_faccessat2:
            return (arguments[3] & AT_EMPTY_PATH) != 0;
        case __NR_execveat:
            return (arguments[4] & AT_EMPTY_PATH) != 0;
        case __NR_linkat:
            return operand_index == 0 &&
                   (arguments[4] & AT_EMPTY_PATH) != 0;
        case __NR_readlinkat:
            return true;
        case hookself::tracer::kMountStateOpenTree:
            return operand_index == 0 &&
                   (arguments[2] & AT_EMPTY_PATH) != 0;
        case hookself::tracer::kMountStateMoveMount:
            return (operand_index == 0 &&
                    (arguments[4] & kMoveMountFromEmptyPath) != 0) ||
                   (operand_index == 1 &&
                    (arguments[4] & kMoveMountToEmptyPath) != 0);
        case hookself::tracer::kMountStateMountSetattr:
            return operand_index == 0 &&
                   (arguments[2] & AT_EMPTY_PATH) != 0;
        default:
            return false;
    }
}

const char* BankString(const SharedRuleBankHeader* bank,
                       const SharedStringRef& reference) noexcept {
    return reinterpret_cast<const char*>(bank) + reference.offset;
}

const SharedPathRuleDesc* SelectPathRule(const SharedRuleBankHeader* bank,
                                         const char* path, size_t path_length,
                                         uint32_t operations) noexcept {
    if (bank == nullptr) {
        return nullptr;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    const auto* rules = reinterpret_cast<const SharedPathRuleDesc*>(
            base + bank->path_rules_offset);
    const SharedPathRuleDesc* selected = nullptr;
    size_t selected_length = 0;
    for (uint32_t i = 0; i < bank->path_rule_count; ++i) {
        const size_t guest_length = rules[i].guest_prefix.length == 0
                                            ? 0
                                            : rules[i].guest_prefix.length - 1U;
        const char* guest = BankString(bank, rules[i].guest_prefix);
        if ((rules[i].operation_mask & operations) == 0 ||
            !PrefixMatches(path, path_length, guest, guest_length)) {
            continue;
        }
        if (selected == nullptr || guest_length > selected_length ||
            (guest_length == selected_length &&
             rules[i].priority >= selected->priority)) {
            selected = &rules[i];
            selected_length = guest_length;
        }
    }
    return selected;
}

const SharedVirtualFileDesc* SelectVirtualFile(
        const SharedRuleBankHeader* bank, const char* path,
        size_t path_length) noexcept {
    if (bank == nullptr) {
        return nullptr;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    const auto* files = reinterpret_cast<const SharedVirtualFileDesc*>(
            base + bank->virtual_files_offset);
    for (uint32_t i = 0; i < bank->virtual_file_count; ++i) {
        if (files[i].guest_path.length == 0 ||
            files[i].guest_path.length - 1U != path_length) {
            continue;
        }
        const char* guest = BankString(bank, files[i].guest_path);
        bool equal = true;
        for (size_t offset = 0; offset < path_length; ++offset) {
            if (guest[offset] != path[offset]) {
                equal = false;
                break;
            }
        }
        if (equal) {
            return &files[i];
        }
    }
    return nullptr;
}

int VirtualFileDenyErrno(int32_t syscall_number,
                         const uint64_t arguments[6],
                         uint64_t open_flags,
                         bool open_how_valid) noexcept {
    if (syscall_number == __NR_openat ||
        syscall_number == __NR_openat2) {
        if (syscall_number == __NR_openat2 && !open_how_valid) {
            return 0;
        }
        const uint64_t flags = syscall_number == __NR_openat
                                       ? arguments[2]
                                       : open_flags;
        if ((flags & O_ACCMODE) != O_RDONLY ||
            (flags & (O_CREAT | O_TRUNC)) != 0
#if defined(O_TMPFILE)
            || (flags & O_TMPFILE) == O_TMPFILE
#endif
        ) {
            return EROFS;
        }
        return 0;
    }
    if (syscall_number == __NR_newfstatat || syscall_number == __NR_statx ||
        syscall_number == __NR_faccessat ||
        syscall_number == __NR_faccessat2) {
        return 0;
    }
    if (syscall_number == __NR_readlinkat) {
        return EINVAL;
    }
    return EROFS;
}

bool BuildVirtualFilePath(const SharedRuleBankHeader* bank,
                          const SharedVirtualFileDesc* virtual_file,
                          char* output, size_t capacity,
                          uint32_t* output_length) noexcept {
    if (bank == nullptr || virtual_file == nullptr || output == nullptr ||
        output_length == nullptr || virtual_file->backing_path.length == 0 ||
        virtual_file->backing_path.length > capacity) {
        return false;
    }
    const char* const backing_path = BankString(
            bank, virtual_file->backing_path);
    const uint32_t length = virtual_file->backing_path.length - 1U;
    for (uint32_t index = 0; index <= length; ++index) {
        output[index] = backing_path[index];
    }
    *output_length = length;
    return true;
}

bool TranslatePath(const SharedRuleBankHeader* bank,
                   const SharedPathRuleDesc& rule, const char* input,
                   size_t input_length, char* output, size_t output_capacity,
                   uint32_t* output_length) noexcept {
    const char* host = BankString(bank, rule.host_prefix);
    const size_t guest_length = rule.guest_prefix.length - 1U;
    const size_t host_length = rule.host_prefix.length - 1U;
    size_t written = 0;
    for (size_t i = 0; i < host_length; ++i) {
        if (written + 1 >= output_capacity) {
            return false;
        }
        output[written++] = host[i];
    }
    size_t suffix_start = guest_length;
    if (guest_length == 1) {
        if (suffix_start < input_length &&
            !(host_length == 1 && host[0] == '/')) {
            if (written + 1 >= output_capacity) {
                return false;
            }
            output[written++] = '/';
        }
    } else if (suffix_start < input_length && host_length == 1 && host[0] == '/') {
        ++suffix_start;
    }
    for (size_t i = suffix_start; i < input_length; ++i) {
        if (written + 1 >= output_capacity) {
            return false;
        }
        output[written++] = input[i];
    }
    output[written] = '\0';
    *output_length = static_cast<uint32_t>(written);
    return true;
}

int ReverseTranslatePath(const SharedRuleBankHeader* bank,
                         const char* host_path, size_t host_length,
                         char* guest_path, size_t guest_capacity,
                         size_t* guest_length, bool* translated,
                         uint32_t* rule_id) noexcept {
    if (host_path == nullptr || guest_path == nullptr ||
        guest_capacity == 0 || guest_length == nullptr ||
        translated == nullptr || rule_id == nullptr) {
        return EINVAL;
    }
    *translated = false;
    *rule_id = 0;
    const SharedPathRuleDesc* selected = nullptr;
    size_t selected_host_length = 0;
    if (bank != nullptr) {
        const auto* base = reinterpret_cast<const uint8_t*>(bank);
        const auto* rules = reinterpret_cast<const SharedPathRuleDesc*>(
                base + bank->path_rules_offset);
        for (uint32_t index = 0; index < bank->path_rule_count; ++index) {
            if (rules[index].action != HOOKSELF_PATH_REDIRECT ||
                (rules[index].flags &
                 HOOKSELF_PATH_RULE_REVERSE_VISIBLE) == 0 ||
                rules[index].host_prefix.length == 0) {
                continue;
            }
            const size_t candidate_length =
                    rules[index].host_prefix.length - 1U;
            const char* candidate = BankString(
                    bank, rules[index].host_prefix);
            if (!PrefixMatches(host_path, host_length, candidate,
                               candidate_length)) {
                continue;
            }
            if (selected == nullptr ||
                candidate_length > selected_host_length ||
                (candidate_length == selected_host_length &&
                 rules[index].priority >= selected->priority)) {
                selected = &rules[index];
                selected_host_length = candidate_length;
            }
        }
    }
    if (selected == nullptr) {
        if (host_length + 1U > guest_capacity) {
            return ENAMETOOLONG;
        }
        for (size_t index = 0; index < host_length; ++index) {
            guest_path[index] = host_path[index];
        }
        guest_path[host_length] = '\0';
        *guest_length = host_length;
        return 0;
    }

    const char* guest_prefix = BankString(bank, selected->guest_prefix);
    const size_t guest_prefix_length = selected->guest_prefix.length - 1U;
    size_t written = 0;
    for (size_t index = 0; index < guest_prefix_length; ++index) {
        if (written + 1U >= guest_capacity) {
            return ENAMETOOLONG;
        }
        guest_path[written++] = guest_prefix[index];
    }
    size_t suffix_start = selected_host_length;
    if (selected_host_length == 1U) {
        if (suffix_start < host_length &&
            !(guest_prefix_length == 1U && guest_prefix[0] == '/')) {
            if (written + 1U >= guest_capacity) {
                return ENAMETOOLONG;
            }
            guest_path[written++] = '/';
        }
    } else if (suffix_start < host_length &&
               guest_prefix_length == 1U && guest_prefix[0] == '/') {
        ++suffix_start;
    }
    for (size_t index = suffix_start; index < host_length; ++index) {
        if (written + 1U >= guest_capacity) {
            return ENAMETOOLONG;
        }
        guest_path[written++] = host_path[index];
    }
    guest_path[written] = '\0';
    *guest_length = written;
    *translated = true;
    *rule_id = selected->rule_id;
    return 0;
}

int ReverseTaskRootPath(const TracerContext* context, const TaskRecord* task,
                        const char* host_path, size_t host_length,
                        char* guest_path, size_t guest_capacity,
                        size_t* guest_length) noexcept {
    if (context == nullptr || task == nullptr ||
        context->path_state == nullptr || host_path == nullptr ||
        guest_path == nullptr || guest_length == nullptr) {
        return EINVAL;
    }
    const hookself::tracer::FsContext* fs =
            hookself::tracer::GetTaskFsContext(context->path_state, task->tid);
    constexpr uint32_t kRequiredOrigins =
            hookself::tracer::kPathOriginGuestValid |
            hookself::tracer::kPathOriginHostValid;
    if (fs == nullptr || (fs->root_origin_flags & kRequiredOrigins) !=
                              kRequiredOrigins) {
        return ENOENT;
    }
    const size_t host_root_length = BoundedLength(
            fs->host_root, sizeof(fs->host_root));
    const size_t guest_root_length = BoundedLength(
            fs->guest_root, sizeof(fs->guest_root));
    if (host_root_length == 0U || guest_root_length == 0U ||
        host_root_length >= sizeof(fs->host_root) ||
        guest_root_length >= sizeof(fs->guest_root) ||
        !PrefixMatches(host_path, host_length, fs->host_root,
                       host_root_length)) {
        return ENOENT;
    }

    size_t written = 0;
    if (guest_root_length + 1U > guest_capacity) {
        return ENAMETOOLONG;
    }
    for (size_t index = 0; index < guest_root_length; ++index) {
        guest_path[written++] = fs->guest_root[index];
    }
    size_t suffix = host_root_length;
    if (suffix < host_length && fs->guest_root[guest_root_length - 1U] == '/' &&
        host_path[suffix] == '/') {
        ++suffix;
    } else if (suffix < host_length && host_path[suffix] != '/' &&
               guest_root_length != 1U) {
        if (written + 1U >= guest_capacity) {
            return ENAMETOOLONG;
        }
        guest_path[written++] = '/';
    }
    if (written + (host_length - suffix) + 1U > guest_capacity) {
        return ENAMETOOLONG;
    }
    for (; suffix < host_length; ++suffix) {
        guest_path[written++] = host_path[suffix];
    }
    guest_path[written] = '\0';
    *guest_length = written;
    return 0;
}

int ResolveHostPathToGuest(TracerContext* context, const TaskRecord* task,
                           const SharedRuleBankHeader* bank,
                           const char* host_path, size_t host_length,
                           char* guest_path, size_t guest_capacity,
                           size_t* guest_length, bool* translated,
                           uint32_t* rule_id) noexcept {
    if (host_path == nullptr || host_length == 0U || host_path[0] != '/' ||
        guest_path == nullptr || guest_length == nullptr || translated == nullptr ||
        rule_id == nullptr) {
        return EINVAL;
    }
    int error = ReverseTranslatePath(
            bank, host_path, host_length, guest_path, guest_capacity,
            guest_length, translated, rule_id);
    if (error != 0 || *translated || context == nullptr || task == nullptr ||
        context->path_state == nullptr) {
        return error;
    }

    hookself::tracer::MountPathTranslation mount{};
    error = hookself::tracer::ReverseMountPath(
            context->path_state, task->tid, host_path, &mount);
    if (error != 0) {
        return error;
    }
    if (mount.matched != 0) {
        const size_t mount_guest_length = BoundedLength(
                mount.guest_path, sizeof(mount.guest_path));
        if (mount_guest_length >= guest_capacity) {
            return ENAMETOOLONG;
        }
        for (size_t index = 0; index <= mount_guest_length; ++index) {
            guest_path[index] = mount.guest_path[index];
        }
        *guest_length = mount_guest_length;
        *translated = true;
        return 0;
    }

    error = ReverseTaskRootPath(
            context, task, host_path, host_length, guest_path,
            guest_capacity, guest_length);
    if (error == 0) {
        *translated = true;
        return 0;
    }
    return error == ENOENT ? 0 : error;
}

