bool IsProcVirtualXattrSyscall(int32_t syscall_number) noexcept {
    switch (syscall_number) {
        case __NR_getxattr:
        case __NR_lgetxattr:
        case __NR_fgetxattr:
        case __NR_listxattr:
        case __NR_llistxattr:
        case __NR_flistxattr:
            return true;
        default:
            return false;
    }
}

bool IsProcVirtualReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

ProcVirtualDispatchTask MakeProcVirtualTask(
        const TaskRecord* task) noexcept {
    ProcVirtualDispatchTask result{};
    result.task_slot = task->slot;
    result.tgid = task->tgid;
    result.tid = task->tid;
    result.generation = task->exec_generation + 1U;
    const int64_t now = MonotonicNanoseconds();
    result.monotonic_time_ns = now > 0 ? static_cast<uint64_t>(now) : 0U;
    return result;
}

const TaskRecord* FindProcVirtualTask(
        const TracerContext* context,
        const ProcVirtualDispatchTask& task) noexcept {
    const TaskRecord* current = context == nullptr || context->tasks == nullptr
                                        ? nullptr
                                        : hookself::tracer::Find(
                                                  context->tasks, task.tid);
    return current != nullptr && current->slot == task.task_slot &&
                   current->tgid == task.tgid &&
                   current->exec_generation + 1U == task.generation
           ? current
           : nullptr;
}

int CopyProcVirtualPath(const char* source, size_t source_length,
                        char* output, size_t output_capacity,
                        size_t* output_length) noexcept {
    if (source == nullptr || output == nullptr || output_length == nullptr ||
        source_length >= output_capacity) {
        return source_length >= output_capacity ? ENAMETOOLONG : EINVAL;
    }
    if (source_length != 0) {
        memcpy(output, source, source_length);
    }
    output[source_length] = '\0';
    *output_length = source_length;
    return 0;
}

int ProcVirtualReadRemoteCallback(void* opaque, int32_t tgid, int32_t tid,
                                  uintptr_t remote_address,
                                  void* local_output, size_t size) noexcept {
    (void)opaque;
    return size == 0 ? 0 : ReadRemoteBytes(
                                   tgid, tid, remote_address, local_output,
                                   size);
}

int ProcVirtualWriteRemoteCallback(void* opaque, int32_t tgid, int32_t tid,
                                   uintptr_t remote_address,
                                   const void* local_input,
                                   size_t size) noexcept {
    (void)opaque;
    return size == 0 ? 0 : WriteRemoteBytes(
                                   tgid, tid, remote_address, local_input,
                                   size);
}

int ReverseResolvedProcVirtualPath(TracerContext* context,
                                   const TaskRecord* task,
                                   const char* host_path,
                                   size_t host_path_length, char* output,
                                   size_t output_capacity,
                                   size_t* output_length) noexcept {
    if (context->path_state != nullptr) {
        hookself::tracer::MountPathTranslation mount{};
        const int mount_error = hookself::tracer::ReverseMountPath(
                context->path_state, task->tid, host_path, &mount);
        if (mount_error != 0) {
            return mount_error;
        }
        if (mount.matched != 0) {
            const size_t length = BoundedLength(
                    mount.guest_path, sizeof(mount.guest_path));
            return CopyProcVirtualPath(mount.guest_path, length, output,
                                       output_capacity, output_length);
        }
    }
    bool translated = false;
    uint32_t rule_id = 0;
    return ReverseTranslatePath(
            ActiveRuleBank(context), host_path, host_path_length, output,
            output_capacity, output_length, &translated, &rule_id);
}

int ProcVirtualResolveIdentityCallback(
        void* opaque, const ProcVirtualIdentityQuery* query, char* output,
        size_t output_capacity, size_t* output_length) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (context == nullptr || query == nullptr || output == nullptr ||
        output_length == nullptr || output_capacity < 2U) {
        return EINVAL;
    }
    const TaskRecord* task = FindProcVirtualTask(context, query->task);
    if (task == nullptr) {
        return ESTALE;
    }
    if ((query->flags & kProcVirtualIdentityFd) != 0) {
        if (query->fd < 0) {
            return EBADF;
        }
        if (query->source == ProcVirtualIdentitySource::kTrackedGuest &&
            context->path_state != nullptr) {
            const hookself::tracer::FdIdentity* identity =
                    hookself::tracer::LookupFdIdentity(
                            context->path_state, task->tid, query->fd);
            if (identity != nullptr &&
                (identity->origin_flags &
                 hookself::tracer::kPathOriginGuestValid) != 0) {
                const size_t length = BoundedLength(
                        identity->guest_path, sizeof(identity->guest_path));
                return CopyProcVirtualPath(
                        identity->guest_path, length, output, output_capacity,
                        output_length);
            }
            return ENODATA;
        }
        char host[HOOKSELF_PATH_CAPACITY]{};
        size_t host_length = 0;
        const int resolve_error = ResolveTargetFdPath(
                task, query->fd, host, sizeof(host), &host_length);
        return resolve_error != 0
                       ? resolve_error
                       : ReverseResolvedProcVirtualPath(
                                 context, task, host, host_length, output,
                                 output_capacity, output_length);
    }

    if ((query->flags & kProcVirtualIdentityRemotePath) == 0 ||
        query->remote_path == 0 ||
        query->path_argument_index >= 6U) {
        return ENOENT;
    }
    char original[HOOKSELF_PATH_CAPACITY]{};
    uint32_t event_flags = 0;
    int error = ReadRemotePath(
            task->tgid, task->tid, query->remote_path, original,
            sizeof(original), &event_flags);
    if (error != 0) {
        return error;
    }
    const size_t original_length = BoundedLength(original, sizeof(original));
    char guest[HOOKSELF_PATH_CAPACITY]{};
    char host[HOOKSELF_PATH_CAPACITY]{};
    size_t guest_length = 0;
    size_t host_length = 0;
    uint32_t origin_flags = 0;
    bool resolved_relative = false;
    uint64_t arguments[6]{};
    arguments[query->path_argument_index] = query->remote_path;
    const PathOperandSpec operand{
            query->path_argument_index, HOOKSELF_PATH_OP_METADATA, -2};
    error = ResolvePolicyPath(
            context, task, ActiveRuleBank(context), operand, arguments,
            original, original_length, guest, sizeof(guest), &guest_length,
            host, sizeof(host), &host_length, &origin_flags,
            &resolved_relative);
    if (error != 0) {
        return error;
    }
    return CopyProcVirtualPath(guest, guest_length, output, output_capacity,
                               output_length);
}

uint32_t ProcVirtualFdOwnerSlot(const TracerContext* context,
                                const TaskRecord* task) noexcept {
    const hookself::tracer::PathTaskState* path_task =
            context->path_state == nullptr
                    ? nullptr
                    : hookself::tracer::FindPathTask(
                              context->path_state, task->tid);
    return path_task == nullptr
                   ? static_cast<uint32_t>(task->tgid)
                   : path_task->fd_table_slot;
}

int ReadProcVirtualFdPosition(const TaskRecord* task, int32_t fd,
                              uint64_t* position) noexcept {
    if (position == nullptr) {
        return EINVAL;
    }
    char path[96]{};
    int error = BuildProcFdEntryPath(
            task->tid, fd, true, path, sizeof(path));
    if (error != 0) {
        return error;
    }
    uint8_t data[1024]{};
    size_t data_size = 0;
    error = ReadLocalFile(path, data, sizeof(data), &data_size);
    if (error != 0) {
        return error;
    }
    constexpr char kPosition[] = "pos:";
    for (size_t index = 0; index + sizeof(kPosition) - 1U < data_size;
         ++index) {
        if ((index != 0 && data[index - 1U] != '\n') ||
            memcmp(data + index, kPosition, sizeof(kPosition) - 1U) != 0) {
            continue;
        }
        size_t cursor = index + sizeof(kPosition) - 1U;
        while (cursor < data_size &&
               (data[cursor] == ' ' || data[cursor] == '\t')) {
            ++cursor;
        }
        if (cursor == data_size || data[cursor] < '0' ||
            data[cursor] > '9') {
            return EPROTO;
        }
        uint64_t parsed = 0;
        while (cursor < data_size && data[cursor] >= '0' &&
               data[cursor] <= '9') {
            const uint64_t digit = data[cursor] - '0';
            if (parsed > (UINT64_MAX - digit) / 10U) {
                return EOVERFLOW;
            }
            parsed = parsed * 10U + digit;
            ++cursor;
        }
        *position = parsed;
        return 0;
    }
    return ENODATA;
}

int BuildTraceeProcSnapshotPath(const ProcVirtualSnapshotRequest& request,
                                char* output, size_t output_capacity) noexcept {
    if (request.identity_path == nullptr || request.identity_path_length == 0 ||
        output == nullptr || output_capacity < 2U) {
        return EINVAL;
    }
    constexpr char kSelf[] = "/proc/self";
    constexpr char kThreadSelf[] = "/proc/thread-self";
    const char* suffix = nullptr;
    size_t suffix_length = 0;
    size_t length = 0;
    if (request.identity_path_length >= sizeof(kSelf) - 1U &&
        memcmp(request.identity_path, kSelf, sizeof(kSelf) - 1U) == 0 &&
        (request.identity_path_length == sizeof(kSelf) - 1U ||
         request.identity_path[sizeof(kSelf) - 1U] == '/')) {
        if (!AppendText(output, output_capacity, &length, "/proc/") ||
            !AppendPositiveDecimal(
                    output, output_capacity, &length,
                    static_cast<uint32_t>(request.task.tgid))) {
            return ENAMETOOLONG;
        }
        suffix = request.identity_path + sizeof(kSelf) - 1U;
        suffix_length = request.identity_path_length - (sizeof(kSelf) - 1U);
    } else if (request.identity_path_length >=
                       sizeof(kThreadSelf) - 1U &&
               memcmp(request.identity_path, kThreadSelf,
                      sizeof(kThreadSelf) - 1U) == 0 &&
               (request.identity_path_length == sizeof(kThreadSelf) - 1U ||
                request.identity_path[sizeof(kThreadSelf) - 1U] == '/')) {
        if (!AppendText(output, output_capacity, &length, "/proc/") ||
            !AppendPositiveDecimal(
                    output, output_capacity, &length,
                    static_cast<uint32_t>(request.task.tgid)) ||
            !AppendText(output, output_capacity, &length, "/task/") ||
            !AppendPositiveDecimal(
                    output, output_capacity, &length,
                    static_cast<uint32_t>(request.task.tid))) {
            return ENAMETOOLONG;
        }
        suffix = request.identity_path + sizeof(kThreadSelf) - 1U;
        suffix_length = request.identity_path_length -
                        (sizeof(kThreadSelf) - 1U);
    } else {
        return CopyProcVirtualPath(
                request.identity_path, request.identity_path_length, output,
                output_capacity, &length);
    }
    if (suffix_length + length >= output_capacity) {
        return ENAMETOOLONG;
    }
    if (suffix_length != 0) {
        memcpy(output + length, suffix, suffix_length);
    }
    output[length + suffix_length] = '\0';
    return 0;
}

const SharedVirtualFileDesc* FindProcVirtualProvider(
        TracerContext* context, int32_t provider) noexcept {
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank == nullptr) {
        return nullptr;
    }
    const auto* files = reinterpret_cast<const SharedVirtualFileDesc*>(
            reinterpret_cast<const uint8_t*>(bank) +
            bank->virtual_files_offset);
    for (uint32_t index = 0; index < bank->virtual_file_count; ++index) {
        if (files[index].provider == provider && files[index].target_fd >= 0) {
            return &files[index];
        }
    }
    return nullptr;
}

int ReadProcVirtualProvider(TracerContext* context,
                            int32_t provider, uint8_t* output,
                            size_t output_capacity,
                            size_t* output_size) noexcept {
    const SharedVirtualFileDesc* file = FindProcVirtualProvider(
            context, provider);
    if (file == nullptr) {
        return ENOENT;
    }
    char path[HOOKSELF_PATH_CAPACITY]{};
    uint32_t path_length = 0;
    return BuildVirtualFilePath(ActiveRuleBank(context), file, path,
                                sizeof(path), &path_length)
                   ? ReadLocalFile(path, output, output_capacity, output_size)
                   : ENAMETOOLONG;
}

int TranslateProcVirtualSnapshotPath(TracerContext* context,
                                     const TaskRecord* task,
                                     const char* guest_path,
                                     size_t guest_path_length, char* output,
                                     size_t output_capacity) noexcept {
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    const SharedVirtualFileDesc* virtual_file = SelectVirtualFile(
            bank, guest_path, guest_path_length);
    if (virtual_file != nullptr && virtual_file->target_fd >= 0) {
        size_t ignored = 0;
        return CopyProcVirtualPath(
                BankString(bank, virtual_file->backing_path),
                virtual_file->backing_path.length - 1U, output,
                output_capacity, &ignored);
    }
    if (context->path_state != nullptr) {
        hookself::tracer::MountPathTranslation mount{};
        const int mount_error = hookself::tracer::TranslateMountPath(
                context->path_state, task->tid, guest_path, &mount);
        if (mount_error != 0) {
            return mount_error;
        }
        if (mount.matched != 0) {
            size_t ignored = 0;
            return CopyProcVirtualPath(
                    mount.host_path,
                    BoundedLength(mount.host_path, sizeof(mount.host_path)),
                    output, output_capacity, &ignored);
        }
    }
    const SharedPathRuleDesc* rule = SelectPathRule(
            bank, guest_path, guest_path_length, HOOKSELF_PATH_OP_METADATA);
    if (rule != nullptr && rule->action == HOOKSELF_PATH_REDIRECT) {
        uint32_t translated_length = 0;
        return TranslatePath(
                       bank, *rule, guest_path, guest_path_length, output,
                       output_capacity, &translated_length)
               ? 0
               : ENAMETOOLONG;
    }
    size_t ignored = 0;
    return CopyProcVirtualPath(guest_path, guest_path_length, output,
                               output_capacity, &ignored);
}

int ReadProcVirtualXattrList(
        TracerContext* context, const ProcVirtualSnapshotRequest& request,
        uint8_t* output, size_t output_capacity,
        size_t* output_size) noexcept {
    const TaskRecord* task = FindProcVirtualTask(context, request.task);
    if (task == nullptr || request.identity_path == nullptr ||
        output_size == nullptr) {
        return task == nullptr ? ESTALE : EINVAL;
    }
    char host[HOOKSELF_PATH_CAPACITY]{};
    const int path_error = TranslateProcVirtualSnapshotPath(
            context, task, request.identity_path,
            request.identity_path_length, host, sizeof(host));
    if (path_error != 0) {
        return path_error;
    }
    const int32_t syscall_number = request.syscall_number == __NR_llistxattr
                                           ? __NR_llistxattr
                                           : __NR_listxattr;
    const long result = RawSyscall6(
            syscall_number, reinterpret_cast<long>(host),
            reinterpret_cast<long>(output),
            static_cast<long>(output_capacity));
    const int error = RawError(result);
    if (error != 0) {
        return error;
    }
    if (result < 0 || static_cast<uint64_t>(result) > output_capacity) {
        return EOVERFLOW;
    }
    *output_size = static_cast<size_t>(result);
    return 0;
}

int ProcVirtualSnapshotCallback(
        void* opaque, const ProcVirtualSnapshotRequest* request,
        uint8_t* output, size_t output_capacity, size_t* output_size,
        uint64_t* logical_offset) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (context == nullptr || context->proc_virtual == nullptr ||
        request == nullptr || output == nullptr || output_size == nullptr ||
        logical_offset == nullptr || output_capacity == 0) {
        return EINVAL;
    }
    *output_size = 0;
    *logical_offset = 0;
    if (request->kind == ProcVirtualSnapshotKind::kXattrList) {
        return ReadProcVirtualXattrList(
                context, *request, output, output_capacity, output_size);
    }
    if (request->kind != ProcVirtualSnapshotKind::kProcText) {
        return EINVAL;
    }
    const TaskRecord* task = FindProcVirtualTask(context, request->task);
    if (task == nullptr) {
        return ESTALE;
    }

    int error = ENOENT;
    if (request->node == ProcVirtualNodeKind::kAttrCurrent) {
        error = ReadProcVirtualProvider(
                context, HOOKSELF_VFILE_SELINUX_CONTEXT, output,
                output_capacity, output_size);
    }
    if (error == ENOENT) {
        char path[kProcVirtualDispatchPathCapacity]{};
        error = BuildTraceeProcSnapshotPath(
                *request, path, sizeof(path));
        if (error == 0) {
            error = ReadLocalFile(path, output, output_capacity, output_size);
        }
    }
    if (error != 0) {
        return error;
    }
    if (request->syscall_number == __NR_pread64) {
        *logical_offset = request->requested_offset;
        return 0;
    }

    uint64_t raw_end = 0;
    error = ReadProcVirtualFdPosition(task, request->fd, &raw_end);
    if (error != 0) {
        return error;
    }
    const uint64_t consumed = request->kernel_result > 0
                                      ? static_cast<uint64_t>(
                                                request->kernel_result)
                                      : 0U;
    const uint64_t raw_start = raw_end >= consumed ? raw_end - consumed : 0U;
    return BeginProcVirtualSequentialRead(
            context->proc_virtual, ProcVirtualFdOwnerSlot(context, task),
            request->fd, request->identity_path,
            request->identity_path_length, raw_start, raw_end,
            logical_offset);
}

bool AppendUniqueProcVirtualFd(int32_t fd, int32_t* output, size_t capacity,
                               size_t* count) noexcept {
    if (fd < 0) {
        return true;
    }
    for (size_t index = 0; index < *count; ++index) {
        if (output[index] == fd) {
            return true;
        }
    }
    if (*count >= capacity) {
        return false;
    }
    output[(*count)++] = fd;
    return true;
}

int ProcVirtualProtectedFdSnapshotCallback(
        void* opaque, const ProcVirtualDispatchTask* dispatch_task,
        int32_t* output, size_t output_capacity,
        size_t* output_count) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (context == nullptr || dispatch_task == nullptr || output == nullptr ||
        output_count == nullptr) {
        return EINVAL;
    }
    const TaskRecord* task = FindProcVirtualTask(context, *dispatch_task);
    if (task == nullptr) {
        return ESTALE;
    }
    *output_count = 0;
    const uint32_t registered = __atomic_load_n(
            &context->control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (registered > kMaxProtectedFds) {
        return EPROTO;
    }
    for (uint32_t index = 0; index < registered; ++index) {
        if (!AppendUniqueProcVirtualFd(
                    context->control->protected_fds[index], output,
                    output_capacity, output_count)) {
            return ENOSPC;
        }
    }
    if (context->path_state != nullptr) {
        int32_t after_fd = -1;
        for (;;) {
            const hookself::tracer::FdIdentity* identity =
                    hookself::tracer::NextProtectedFdIdentity(
                            context->path_state, task->tid, after_fd);
            if (identity == nullptr) {
                break;
            }
            if (!AppendUniqueProcVirtualFd(
                        identity->fd, output, output_capacity,
                        output_count)) {
                return ENOSPC;
            }
            after_fd = identity->fd;
        }
    }
    return 0;
}

int ProcVirtualWriteResultCallback(
        void* opaque, const ProcVirtualDispatchTask* dispatch_task,
        int64_t result) noexcept {
    auto* context = static_cast<TracerContext*>(opaque);
    if (context == nullptr || dispatch_task == nullptr) {
        return EINVAL;
    }
    TaskRecord* task = hookself::tracer::Find(
            context->tasks, dispatch_task->tid);
    return task == nullptr || task->slot != dispatch_task->task_slot ||
                   task->tgid != dispatch_task->tgid
           ? ESTALE
           : WriteTraceeSyscallResult(task, result);
}

ProcVirtualIo MakeProcVirtualIo(TracerContext* context) noexcept {
    ProcVirtualIo io{};
    io.opaque = context;
    io.read_remote = ProcVirtualReadRemoteCallback;
    io.write_remote = ProcVirtualWriteRemoteCallback;
    io.resolve_identity = ProcVirtualResolveIdentityCallback;
    io.snapshot = ProcVirtualSnapshotCallback;
    io.snapshot_protected_fds = ProcVirtualProtectedFdSnapshotCallback;
    io.write_syscall_result = ProcVirtualWriteResultCallback;
    return io;
}

int LoadProcVirtualSelinuxRule(TracerContext* context) noexcept {
    ProcVirtualResidentState* state = context->proc_virtual;
    state->xattr_rule_count = 0;
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES) == 0) {
        return 0;
    }
    const SharedVirtualFileDesc* provider = FindProcVirtualProvider(
            context, HOOKSELF_VFILE_SELINUX_CONTEXT);
    if (provider == nullptr) {
        return 0;
    }
    char path[HOOKSELF_PATH_CAPACITY]{};
    uint32_t path_length = 0;
    size_t value_size = 0;
    int error = BuildVirtualFilePath(ActiveRuleBank(context), provider, path,
                                     sizeof(path), &path_length)
            ? ReadLocalFile(path, state->xattr_values[0],
                            kProcVirtualResidentXattrValueCapacity - 1U,
                            &value_size)
            : ENAMETOOLONG;
    if (error == ENOENT || error == EBADF) {
        return 0;
    }
    if (error != 0) {
        return error;
    }
    while (value_size != 0 &&
           (state->xattr_values[0][value_size - 1U] == '\n' ||
            state->xattr_values[0][value_size - 1U] == '\r')) {
        --value_size;
    }
    if (value_size == 0 || state->xattr_values[0][value_size - 1U] != 0) {
        state->xattr_values[0][value_size++] = 0;
    }
    static constexpr char kRoot[] = "/";
    static constexpr char kSelinux[] = "security.selinux";
    ProcVirtualXattrRule& rule = state->xattr_rules[0];
    rule.path_prefix = kRoot;
    rule.path_prefix_length = sizeof(kRoot) - 1U;
    rule.name = kSelinux;
    rule.name_length = sizeof(kSelinux) - 1U;
    rule.value = state->xattr_values[0];
    rule.value_size = value_size;
    rule.priority = INT32_MAX;
    rule.flags = kProcVirtualXattrRuleEmulate;
    state->xattr_rule_count = 1;
    return 0;
}

int BuildProcVirtualConfig(TracerContext* context, const TaskRecord* task,
                           ProcVirtualDispatchConfig* config) noexcept {
    if (context == nullptr || context->proc_virtual == nullptr ||
        task == nullptr || config == nullptr) {
        return EINVAL;
    }
    ProcVirtualResidentState* state = context->proc_virtual;
    state->reverse_rule_count = 0;
    const SharedRuleBankHeader* bank = ActiveRuleBank(context);
    if (bank != nullptr) {
        const auto* rules = reinterpret_cast<const SharedPathRuleDesc*>(
                reinterpret_cast<const uint8_t*>(bank) +
                bank->path_rules_offset);
        for (uint32_t index = 0; index < bank->path_rule_count; ++index) {
            if (rules[index].action != HOOKSELF_PATH_REDIRECT ||
                (rules[index].flags &
                 HOOKSELF_PATH_RULE_REVERSE_VISIBLE) == 0 ||
                rules[index].guest_prefix.length == 0 ||
                rules[index].host_prefix.length == 0) {
                continue;
            }
            if (state->reverse_rule_count >=
                kProcVirtualResidentReverseRuleCapacity) {
                return ENOSPC;
            }
            ProcReversePathRule& destination =
                    state->reverse_rules[state->reverse_rule_count++];
            destination.host_prefix = BankString(
                    bank, rules[index].host_prefix);
            destination.host_prefix_length =
                    rules[index].host_prefix.length - 1U;
            destination.guest_prefix = BankString(
                    bank, rules[index].guest_prefix);
            destination.guest_prefix_length =
                    rules[index].guest_prefix.length - 1U;
            destination.priority = rules[index].priority;
            destination.flags = kProcReversePathRuleVisible;
        }
    }
    const int xattr_error = LoadProcVirtualSelinuxRule(context);
    if (xattr_error != 0) {
        return xattr_error;
    }
    *config = {};
    config->generation = context->header->nonce == 0
                                 ? 1U
                                 : context->header->nonce;
    config->tracer_pid = context->tracer_pid;
    config->max_iov_count = kProcVirtualDispatchMaxIov;
    config->max_getdents_replays = 32U;
    config->getdents_replay_timeout_ns = 1000000000ULL;
    if ((context->control->config_flags &
         HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW) != 0 &&
        task->exec_generation == 0) {
        config->hidden_ranges = state->hidden_ranges;
        config->hidden_range_count = state->hidden_range_count;
    }
    config->reverse_rules = state->reverse_rules;
    config->reverse_rule_count = state->reverse_rule_count;
    config->xattr_rules = state->xattr_rules;
    config->xattr_rule_count = state->xattr_rule_count;
    config->snapshot_buffer = state->snapshot_buffer;
    config->snapshot_capacity = sizeof(state->snapshot_buffer);
    config->rewrite_buffer = state->rewrite_buffer;
    config->rewrite_capacity = sizeof(state->rewrite_buffer);
    return 0;
}

bool ProcVirtualLineContains(const uint8_t* line, size_t line_size,
                             const char* needle) noexcept {
    size_t needle_size = 0;
    while (needle[needle_size] != '\0') {
        ++needle_size;
    }
    if (needle_size == 0 || needle_size > line_size) {
        return false;
    }
    for (size_t offset = 0; offset <= line_size - needle_size; ++offset) {
        if (memcmp(line + offset, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
}

bool ParseProcVirtualHex(const uint8_t* text, size_t size,
                         uintptr_t* value) noexcept {
    if (text == nullptr || value == nullptr || size == 0) {
        return false;
    }
    uintptr_t parsed = 0;
    for (size_t index = 0; index < size; ++index) {
        uint8_t digit = 0;
        if (text[index] >= '0' && text[index] <= '9') {
            digit = text[index] - '0';
        } else if (text[index] >= 'a' && text[index] <= 'f') {
            digit = static_cast<uint8_t>(text[index] - 'a' + 10U);
        } else if (text[index] >= 'A' && text[index] <= 'F') {
            digit = static_cast<uint8_t>(text[index] - 'A' + 10U);
        } else {
            return false;
        }
        if (parsed > (UINTPTR_MAX - digit) / 16U) {
            return false;
        }
        parsed = parsed * 16U + digit;
    }
    *value = parsed;
    return true;
}

int InitializeProcVirtualHiddenRanges(TracerContext* context) noexcept {
    if (context == nullptr || context->proc_virtual == nullptr ||
        context->header == nullptr) {
        return EINVAL;
    }
    int error = 0;
    if (context->mapping.prefix_mapping != nullptr &&
        context->mapping.prefix_size != 0) {
        error = AppendProcVirtualHiddenRange(
                context->proc_virtual,
                reinterpret_cast<uintptr_t>(
                        context->mapping.prefix_mapping),
                context->mapping.prefix_size);
        if (error != 0) {
            return error;
        }
    }
    if (context->header->tracee_scratch_address != 0 &&
        context->mapping.scratch_size != 0) {
        error = AppendProcVirtualHiddenRange(
                context->proc_virtual,
                static_cast<uintptr_t>(
                        context->header->tracee_scratch_address),
                context->mapping.scratch_size);
        if (error != 0) {
            return error;
        }
    }

    char maps_path[64]{};
    size_t maps_path_length = 0;
    if (!AppendText(maps_path, sizeof(maps_path), &maps_path_length,
                    "/proc/") ||
        !AppendPositiveDecimal(
                maps_path, sizeof(maps_path), &maps_path_length,
                static_cast<uint32_t>(context->target_pid)) ||
        !AppendText(maps_path, sizeof(maps_path), &maps_path_length,
                    "/maps")) {
        return ENAMETOOLONG;
    }
    size_t maps_size = 0;
    error = ReadLocalFile(
            maps_path, context->proc_virtual->snapshot_buffer,
            sizeof(context->proc_virtual->snapshot_buffer), &maps_size);
    if (error != 0) {
        return 0;
    }
    size_t cursor = 0;
    while (cursor < maps_size) {
        size_t line_end = cursor;
        while (line_end < maps_size &&
               context->proc_virtual->snapshot_buffer[line_end] != '\n') {
            ++line_end;
        }
        const uint8_t* line =
                context->proc_virtual->snapshot_buffer + cursor;
        const size_t line_size = line_end - cursor;
        const bool internal =
                ProcVirtualLineContains(line, line_size, "libhookself.so") ||
                ProcVirtualLineContains(line, line_size,
                                        "hookself-session") ||
                ProcVirtualLineContains(line, line_size, "hookself-vfile");
        if (internal) {
            size_t dash = 0;
            size_t range_end = 0;
            while (dash < line_size && line[dash] != '-') {
                ++dash;
            }
            range_end = dash + 1U;
            while (range_end < line_size && line[range_end] != ' ') {
                ++range_end;
            }
            uintptr_t start = 0;
            uintptr_t end = 0;
            if (dash != 0 && dash + 1U < range_end &&
                ParseProcVirtualHex(line, dash, &start) &&
                ParseProcVirtualHex(
                        line + dash + 1U, range_end - dash - 1U, &end) &&
                start < end) {
                error = AppendProcVirtualHiddenRange(
                        context->proc_virtual, start,
                        static_cast<size_t>(end - start));
                if (error != 0 && error != ENOSPC) {
                    return error;
                }
            }
        }
        cursor = line_end < maps_size ? line_end + 1U : line_end;
    }
    return 0;
}

bool IsProcVirtualStateError(int error) noexcept {
    return error == ESTALE || error == ESRCH || error == EOWNERDEAD;
}

int ApplyProcVirtualEntry(TracerContext* context, TaskRecord* task,
                          bool* handled) noexcept {
    if (handled == nullptr) {
        return EINVAL;
    }
    *handled = false;
    const int32_t syscall_number = task->active_syscall.syscall_number;
    const bool proc_enabled =
            (context->control->config_flags &
             HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW) != 0;
    const bool is_xattr_call = IsProcVirtualXattrSyscall(syscall_number);
    const bool xattr_enabled = is_xattr_call &&
            (context->control->config_flags &
             HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES) != 0 &&
            FindProcVirtualProvider(
                    context, HOOKSELF_VFILE_SELINUX_CONTEXT) != nullptr;
    const bool proc_call =
            proc_enabled &&
            (IsProcVirtualReadSyscall(syscall_number) ||
             syscall_number == __NR_getdents64);
    const bool xattr_call = xattr_enabled;
    if (context->proc_virtual == nullptr || (!proc_call && !xattr_call)) {
        return 0;
    }
    ProcVirtualDispatchConfig config{};
    int error = BuildProcVirtualConfig(context, task, &config);
    if (error != 0) {
        (void)ClearProcVirtualPending(
                &context->proc_virtual->pending, task->slot);
        return IsProcVirtualStateError(error) ? error : 0;
    }
    ProcVirtualEntryResult result{};
    const ProcVirtualDispatchTask dispatch_task = MakeProcVirtualTask(task);
    const ProcVirtualIo io = MakeProcVirtualIo(context);
    error = DispatchProcVirtualEntry(
            config, io, &context->proc_virtual->pending, dispatch_task,
            syscall_number, task->active_syscall.arguments, &result);
    if (error != 0) {
        (void)ClearProcVirtualPending(
                &context->proc_virtual->pending, task->slot);
        return IsProcVirtualStateError(error) ? error : 0;
    }
    if ((result.flags & kProcVirtualEntryHandled) == 0) {
        return 0;
    }
    *handled = true;
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallProcVirtualView;
    if ((result.flags & kProcVirtualEntrySuppress) != 0) {
        error = SuppressSyscallWithHarmlessCall(task);
        if (error != 0) {
            (void)ClearProcVirtualPending(
                    &context->proc_virtual->pending, task->slot);
        }
    }
    return error;
}

int ScheduleProcVirtualReplay(TaskRecord* task,
                              const ProcVirtualExitResult& result) noexcept {
    if (result.replay_syscall_number != __NR_getdents64 ||
        result.instruction_rewind_bytes != sizeof(uint32_t) ||
        result.records_seen == 0 ||
        result.records_hidden != result.records_seen) {
        return EPROTO;
    }
    Arm64Regs registers{};
    int error = hookself::arch::ReadRegisters(task->tid, &registers);
    if (error != 0 || registers.pc < result.instruction_rewind_bytes) {
        return error != 0 ? error : EOVERFLOW;
    }
    for (size_t index = 0; index < 6U; ++index) {
        registers.regs[index] = result.replay_arguments[index];
    }
    registers.regs[8] = static_cast<uint64_t>(
            result.replay_syscall_number);
    registers.pc -= result.instruction_rewind_bytes;
    error = hookself::arch::WriteRegisters(task->tid, &registers);
    if (error != 0) {
        return error;
    }
    Arm64Regs verified{};
    error = hookself::arch::ReadRegisters(task->tid, &verified);
    if (error != 0 || !hookself::arch::RegistersEqual(registers, verified)) {
        return error != 0 ? error : EIO;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallProcVirtualReplay |
            hookself::tracer::kActiveSyscallNeedsExit;
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    task->resume_mode = TaskResumeMode::kSyscall;
    return 0;
}

int CompleteProcVirtualExit(TracerContext* context, TaskRecord* task,
                            int64_t kernel_result, int64_t* visible_result,
                            bool* replay_scheduled) noexcept {
    if (visible_result == nullptr || replay_scheduled == nullptr) {
        return EINVAL;
    }
    *visible_result = kernel_result;
    *replay_scheduled = false;
    if (context->proc_virtual == nullptr ||
        (task->active_syscall.flags &
         hookself::tracer::kActiveSyscallProcVirtualView) == 0) {
        return 0;
    }
    const ProcVirtualPending pending =
            context->proc_virtual->pending.entries[task->slot];
    ProcVirtualDispatchConfig config{};
    int error = BuildProcVirtualConfig(context, task, &config);
    if (error != 0) {
        (void)ClearProcVirtualPending(
                &context->proc_virtual->pending, task->slot);
        task->active_syscall.flags &=
                ~hookself::tracer::kActiveSyscallProcVirtualView;
        // The underlying read may already have written unfiltered proc bytes,
        // while emulated xattr calls have executed only the harmless syscall.
        // The proc-virtual feature is fail-closed, so an incomplete exit
        // transaction must reach the session fatal path instead of exposing
        // either result to the tracee.
        return error;
    }
    ProcVirtualExitResult result{};
    const ProcVirtualDispatchTask dispatch_task = MakeProcVirtualTask(task);
    const ProcVirtualIo io = MakeProcVirtualIo(context);
    error = DispatchProcVirtualExit(
            config, io, &context->proc_virtual->pending, dispatch_task,
            kernel_result, &result);
    if (error != 0) {
        (void)ClearProcVirtualPending(
                &context->proc_virtual->pending, task->slot);
        task->active_syscall.flags &=
                ~hookself::tracer::kActiveSyscallProcVirtualView;
        return error;
    }
    if ((result.flags & kProcVirtualExitHandled) == 0) {
        return 0;
    }
    if ((result.flags & kProcVirtualExitReplay) != 0) {
        error = ScheduleProcVirtualReplay(task, result);
        if (error == 0) {
            *replay_scheduled = true;
        }
        return error;
    }
    *visible_result = result.visible_result;
    if ((pending.flags & kProcVirtualPendingProcText) != 0 &&
        pending.syscall_number != __NR_pread64) {
        const uint32_t owner_slot = ProcVirtualFdOwnerSlot(context, task);
        const int cursor_error = AdvanceProcVirtualSequentialRead(
                context->proc_virtual, owner_slot, pending.fd,
                pending.identity_path, pending.path_length,
                result.bytes_written);
        if (cursor_error != 0 && cursor_error != ENOENT) {
            return cursor_error;
        }
    }
    if ((result.flags & kProcVirtualExitOutputPatched) != 0) {
        __atomic_fetch_add(&context->control->proc_status_patches, 1U,
                           __ATOMIC_RELAXED);
    }
    return 0;
}

bool SelectiveEntryNeedsExit(TracerContext* context,
                             const TaskRecord* task,
                             bool include_observation) noexcept {
    constexpr uint32_t kCompletionFlags =
            hookself::tracer::kActiveSyscallEntryRegistersValid |
            hookself::tracer::kActiveSyscallRegistersModified |
            hookself::tracer::kActiveSyscallNumberModified |
            hookself::tracer::kActiveSyscallArgumentsModified |
            hookself::tracer::kActiveSyscallReplaceResult |
            hookself::tracer::kActiveSyscallResultWriteUnknown |
            hookself::tracer::kActiveSyscallVirtualFileOpen |
            hookself::tracer::kActiveSyscallInternalFdOperation |
            hookself::tracer::kActiveSyscallPtraceView |
            hookself::tracer::kActiveSyscallProcStatusView |
            hookself::tracer::kActiveSyscallProcVirtualView |
            hookself::tracer::kActiveSyscallPathState;
    if ((task->active_syscall.flags & kCompletionFlags) != 0) {
        return true;
    }
    if (include_observation) {
        uint32_t ignored_rule_id = 0;
        return SelectObservationRule(
                context, task->active_syscall.syscall_number,
                HOOKSELF_SYSCALL_PHASE_EXIT, task->active_syscall.arguments,
                &ignored_rule_id);
    }
    return false;
}

void FinalizeSelectiveEntry(TracerContext* context, TaskRecord* task,
                            bool include_observation = true) noexcept {
    if (!context->selective_mode) {
        return;
    }
    task->active_syscall.flags |=
            hookself::tracer::kActiveSyscallFromSeccomp;
    if (SelectiveEntryNeedsExit(context, task, include_observation)) {
        task->active_syscall.flags |=
                hookself::tracer::kActiveSyscallNeedsExit;
        task->syscall_phase = TaskSyscallPhase::kExpectExit;
        task->resume_mode = TaskResumeMode::kSyscall;
        return;
    }
    hookself::tracer::ClearActiveSyscall(task);
    task->syscall_phase = TaskSyscallPhase::kExpectEntry;
    task->resume_mode = TaskResumeMode::kCont;
}

