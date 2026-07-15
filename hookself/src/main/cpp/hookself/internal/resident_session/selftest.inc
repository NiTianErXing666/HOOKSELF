
int RunChrootPathResolutionSelfTest(int32_t* first_failure) noexcept {
    constexpr int32_t kTid = 701;
    constexpr int32_t kFailureMapPathState = 6604;
    constexpr int32_t kFailureInsertInitialTask = 6605;
    constexpr int32_t kFailureApplyChroot = 6606;
    constexpr int32_t kFailureChrootRoots = 6607;
    constexpr int32_t kFailureSetInitialCwd = 6608;
    constexpr int32_t kFailureRecordDirectoryFd = 6609;
    constexpr int32_t kFailureAbsolutePath = 6610;
    constexpr int32_t kFailureAbsolutePathFloor = 6611;
    constexpr int32_t kFailureReverseHostPath = 6612;
    constexpr int32_t kFailureReverseHostSibling = 6613;
    constexpr int32_t kFailureOpenAt2InRoot = 6614;
    constexpr int32_t kFailureInRootPath = 6615;
    constexpr int32_t kFailureInRootPathFloor = 6616;
    constexpr int32_t kFailureInRootRelativeFloor = 6617;
    constexpr int32_t kFailureSetCwdFromHostWork = 6618;
    constexpr int32_t kFailureVisibleWorkCwd = 6619;
    constexpr int32_t kFailureSetCwdFromHostRoot = 6620;
    constexpr int32_t kFailureVisibleRootCwd = 6621;
    constexpr int32_t kFailureSetCwdFromHostSibling = 6622;
    constexpr int32_t kFailureVisibleSiblingCwd = 6623;
    constexpr int32_t kFailureRestoreHostWorkCwd = 6624;
    constexpr int32_t kFailureFinalPathState = 6625;
    constexpr uint32_t kOrigins =
            hookself::tracer::kPathOriginGuestValid |
            hookself::tracer::kPathOriginHostValid;
    constexpr char kGuestRoot[] = "/guest/root";
    constexpr char kHostRoot[] = "/host/root";
    constexpr char kGuestWork[] = "/guest/root/work";
    constexpr char kHostWork[] = "/host/root/work";
    constexpr char kGuestDir[] = "/guest/root/dir";
    constexpr char kHostDir[] = "/host/root/dir";
    int32_t local_first_failure = 0;
    int32_t* const recorded_failure =
            first_failure == nullptr ? &local_first_failure : first_failure;
    *recorded_failure = 0;
    const auto record_failure = [recorded_failure](int32_t failure) {
        if (*recorded_failure == 0) {
            *recorded_failure = failure;
        }
    };

    void* const memory = mmap(nullptr, sizeof(hookself::tracer::PathStateTable),
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        record_failure(kFailureMapPathState);
        return errno != 0 ? errno : ENOMEM;
    }
    auto* const path_state =
            static_cast<hookself::tracer::PathStateTable*>(memory);
    hookself::tracer::InitPathState(path_state);
    int result = 0;
    do {
        result = hookself::tracer::InsertInitialPathTask(
                path_state, kTid, kGuestRoot, kHostRoot);
        if (result != 0) {
            record_failure(kFailureInsertInitialTask);
            break;
        }

        hookself::tracer::MountSyscallCompletion chroot{};
        chroot.syscall_number = hookself::tracer::kMountStateChroot;
        chroot.path_count = 1U;
        chroot.kernel_result = 0;
        chroot.paths[0].valid = 1U;
        chroot.paths[0].origin_flags = kOrigins;
        chroot.paths[0].guest_path = kGuestRoot;
        chroot.paths[0].host_path = kHostRoot;
        result = hookself::tracer::ApplyMountSyscallCompletion(
                path_state, kTid, chroot);
        if (result != 0) {
            record_failure(kFailureApplyChroot);
            break;
        }
        const hookself::tracer::FsContext* fs =
                hookself::tracer::GetTaskFsContext(path_state, kTid);
        if (fs == nullptr || strcmp(fs->guest_root, kGuestRoot) != 0 ||
            strcmp(fs->host_root, kHostRoot) != 0) {
            result = EPROTO;
            record_failure(kFailureChrootRoots);
            break;
        }

        result = hookself::tracer::SetTaskCwd(
                path_state, kTid, kGuestWork, kHostWork, kOrigins, 0, 0);
        if (result != 0) {
            record_failure(kFailureSetInitialCwd);
            break;
        }
        hookself::tracer::FdIdentitySpec directory{};
        directory.origin_flags = kOrigins;
        directory.directory = 1U;
        directory.guest_path = kGuestDir;
        directory.host_path = kHostDir;
        result = hookself::tracer::RecordFdIdentity(
                path_state, kTid, 42, directory);
        if (result != 0) {
            record_failure(kFailureRecordDirectoryFd);
            break;
        }

        TracerContext context{};
        context.path_state = path_state;
        TaskRecord task{};
        task.tid = kTid;
        task.tgid = kTid;
        const PathOperandSpec operand{1U, HOOKSELF_PATH_OP_LOOKUP, 0};
        uint64_t arguments[6]{};
        arguments[0] = static_cast<uint64_t>(static_cast<int64_t>(AT_FDCWD));
        char guest[HOOKSELF_PATH_CAPACITY]{};
        char host[HOOKSELF_PATH_CAPACITY]{};
        size_t guest_length = 0;
        size_t host_length = 0;
        uint32_t origin_flags = 0;
        bool resolved_relative = false;
        result = ResolvePolicyPath(
                &context, &task, nullptr, operand, arguments, "/etc/config",
                sizeof("/etc/config") - 1U, guest, sizeof(guest),
                &guest_length, host, sizeof(host), &host_length, &origin_flags,
                &resolved_relative);
        if (result != 0 || resolved_relative ||
            strcmp(guest, "/guest/root/etc/config") != 0 ||
            strcmp(host, "/host/root/etc/config") != 0 ||
            (origin_flags & kOrigins) != kOrigins) {
            result = EPROTO;
            record_failure(kFailureAbsolutePath);
            break;
        }
        result = ResolvePolicyPath(
                &context, &task, nullptr, operand, arguments,
                "/../../etc/hosts", sizeof("/../../etc/hosts") - 1U, guest,
                sizeof(guest), &guest_length, host, sizeof(host), &host_length,
                &origin_flags, &resolved_relative);
        if (result != 0 || resolved_relative ||
            strcmp(guest, "/guest/root/etc/hosts") != 0 ||
            strcmp(host, "/host/root/etc/hosts") != 0) {
            result = EPROTO;
            record_failure(kFailureAbsolutePathFloor);
            break;
        }

        bool reversed = false;
        uint32_t reverse_rule_id = 0;
        result = ResolveHostPathToGuest(
                &context, &task, nullptr, kHostWork,
                sizeof(kHostWork) - 1U, guest, sizeof(guest), &guest_length,
                &reversed, &reverse_rule_id);
        if (result != 0 || !reversed || reverse_rule_id != 0U ||
            strcmp(guest, kGuestWork) != 0) {
            result = EPROTO;
            record_failure(kFailureReverseHostPath);
            break;
        }
        constexpr char kHostRootSibling[] = "/host/rootish/work";
        result = ResolveHostPathToGuest(
                &context, &task, nullptr, kHostRootSibling,
                sizeof(kHostRootSibling) - 1U, guest, sizeof(guest),
                &guest_length, &reversed, &reverse_rule_id);
        if (result != 0 || reversed || reverse_rule_id != 0U ||
            strcmp(guest, kHostRootSibling) != 0) {
            result = EPROTO;
            record_failure(kFailureReverseHostSibling);
            break;
        }

        open_how how{};
        how.resolve = RESOLVE_IN_ROOT;
        if (!UsesOpenAt2InRoot(__NR_openat2, true, how) ||
            UsesOpenAt2InRoot(__NR_openat, true, how)) {
            result = EPROTO;
            record_failure(kFailureOpenAt2InRoot);
            break;
        }
        arguments[0] = 42U;
        result = ResolvePolicyPathInRoot(
                &context, &task, nullptr, operand, arguments, "/inside",
                sizeof("/inside") - 1U, guest, sizeof(guest), &guest_length,
                host, sizeof(host), &host_length, &origin_flags,
                &resolved_relative);
        if (result != 0 || !resolved_relative ||
            strcmp(guest, "/guest/root/dir/inside") != 0 ||
            strcmp(host, "/host/root/dir/inside") != 0) {
            result = EPROTO;
            record_failure(kFailureInRootPath);
            break;
        }
        result = ResolvePolicyPathInRoot(
                &context, &task, nullptr, operand, arguments,
                "/../../inside", sizeof("/../../inside") - 1U,
                guest, sizeof(guest), &guest_length, host, sizeof(host),
                &host_length, &origin_flags, &resolved_relative);
        if (result != 0 || !resolved_relative ||
            strcmp(guest, "/guest/root/dir/inside") != 0 ||
            strcmp(host, "/host/root/dir/inside") != 0) {
            result = EPROTO;
            record_failure(kFailureInRootPathFloor);
            break;
        }
        result = ResolvePolicyPathInRoot(
                &context, &task, nullptr, operand, arguments,
                "../../inside", sizeof("../../inside") - 1U,
                guest, sizeof(guest), &guest_length, host, sizeof(host),
                &host_length, &origin_flags, &resolved_relative);
        if (result != 0 || !resolved_relative ||
            strcmp(guest, "/guest/root/dir/inside") != 0 ||
            strcmp(host, "/host/root/dir/inside") != 0) {
            result = EPROTO;
            record_failure(kFailureInRootRelativeFloor);
            break;
        }

        result = SetTaskCwdFromHostPath(
                &context, &task, kHostWork, sizeof(kHostWork) - 1U);
        if (result != 0) {
            record_failure(kFailureSetCwdFromHostWork);
            break;
        }
        fs = hookself::tracer::GetTaskFsContext(path_state, kTid);
        char visible_cwd[HOOKSELF_PATH_CAPACITY]{};
        size_t visible_cwd_length = 0;
        result = ResolveVisibleGuestCwd(
                fs, visible_cwd, sizeof(visible_cwd), &visible_cwd_length);
        if (result != 0 || visible_cwd_length != sizeof("/work") - 1U ||
            strcmp(visible_cwd, "/work") != 0 ||
            !hookself::tracer::ValidatePathState(path_state)) {
            result = EPROTO;
            record_failure(kFailureVisibleWorkCwd);
            break;
        }
        result = SetTaskCwdFromHostPath(
                &context, &task, kHostRoot, sizeof(kHostRoot) - 1U);
        if (result != 0) {
            record_failure(kFailureSetCwdFromHostRoot);
            break;
        }
        fs = hookself::tracer::GetTaskFsContext(path_state, kTid);
        result = ResolveVisibleGuestCwd(
                fs, visible_cwd, sizeof(visible_cwd), &visible_cwd_length);
        if (result != 0 || visible_cwd_length != 1U ||
            strcmp(visible_cwd, "/") != 0) {
            result = EPROTO;
            record_failure(kFailureVisibleRootCwd);
            break;
        }
        result = SetTaskCwdFromHostPath(
                &context, &task, kHostRootSibling,
                sizeof(kHostRootSibling) - 1U);
        if (result != 0) {
            record_failure(kFailureSetCwdFromHostSibling);
            break;
        }
        fs = hookself::tracer::GetTaskFsContext(path_state, kTid);
        result = ResolveVisibleGuestCwd(
                fs, visible_cwd, sizeof(visible_cwd), &visible_cwd_length);
        if (result != 0 ||
            visible_cwd_length != sizeof(kHostRootSibling) - 1U ||
            strcmp(visible_cwd, kHostRootSibling) != 0) {
            result = EPROTO;
            record_failure(kFailureVisibleSiblingCwd);
            break;
        }
        result = SetTaskCwdFromHostPath(
                &context, &task, kHostWork, sizeof(kHostWork) - 1U);
        if (result != 0) {
            record_failure(kFailureRestoreHostWorkCwd);
            break;
        }
        if (!hookself::tracer::ValidatePathState(path_state)) {
            result = EPROTO;
            record_failure(kFailureFinalPathState);
            break;
        }
    } while (false);
    (void)hookself::tracer::RemovePathTask(path_state, kTid);
    (void)munmap(memory, sizeof(hookself::tracer::PathStateTable));
    return result;
}

int RunCloseRangeCapabilityPolicySelfTest() noexcept {
    constexpr uint32_t kBase = kCloseRangeCapabilitySyscall;
    constexpr uint32_t kAll =
            kBase | kCloseRangeCapabilityCloexec |
            kCloseRangeCapabilityUnshare;
    return !CloseRangeCapabilitiesPermitPolicy(kCloseRangeCapabilityNone, 0) &&
                           CloseRangeCapabilitiesPermitPolicy(kBase, 0) &&
                           !CloseRangeCapabilitiesPermitPolicy(
                                   kBase, kCloseRangeCloexec) &&
                           CloseRangeCapabilitiesPermitPolicy(
                                   kBase | kCloseRangeCapabilityCloexec,
                                   kCloseRangeCloexec) &&
                           !CloseRangeCapabilitiesPermitPolicy(
                                   kBase, kCloseRangeUnshare) &&
                           CloseRangeCapabilitiesPermitPolicy(
                                   kBase | kCloseRangeCapabilityUnshare,
                                   kCloseRangeUnshare) &&
                           CloseRangeCapabilitiesPermitPolicy(
                                   kAll, kCloseRangeUnshare |
                                                 kCloseRangeCloexec) &&
                           !CloseRangeCapabilitiesPermitPolicy(kAll, 1U)
                   ? 0
                   : EOWNERDEAD;
}

int RunProtectedFdIdentitySelfTest() noexcept {
    constexpr char kProtectedName[] = "hookself-protected-identity";
    constexpr char kReplacementName[] = "hookself-reused-identity";
    const long protected_result = RawSyscall6(
            __NR_memfd_create, reinterpret_cast<long>(kProtectedName), 0);
    if (RawError(protected_result) != 0 || protected_result < 0) {
        return RawError(protected_result) != 0
                ? RawError(protected_result)
                : EIO;
    }
    const int protected_fd = static_cast<int>(protected_result);
    const long replacement_result = RawSyscall6(
            __NR_memfd_create, reinterpret_cast<long>(kReplacementName), 0);
    if (RawError(replacement_result) != 0 || replacement_result < 0) {
        (void)hookself::platform::RawClose(protected_fd);
        return RawError(replacement_result) != 0
                ? RawError(replacement_result)
                : EIO;
    }
    const int replacement_fd = static_cast<int>(replacement_result);
    int result = EIO;
    bool target_closed = false;
    do {
        const long tid_result = RawSyscall6(__NR_gettid);
        if (RawError(tid_result) != 0 || tid_result <= 0 ||
            tid_result > INT32_MAX) {
            result = RawError(tid_result) != 0 ? RawError(tid_result) : EIO;
            break;
        }
        SharedControlPage control{};
        control.protected_fds[0] = protected_fd;
        __atomic_store_n(&control.protected_fd_registry_generation, 1U,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&control.protected_fd_count, 1U, __ATOMIC_RELEASE);
        TracerContext context{};
        context.control = &control;
        TaskRecord task{};
        task.tid = static_cast<pid_t>(tid_result);
        InitializeProtectedFdIdentities(&context);
        if (!IsProtectedFdForTask(&context, &task, protected_fd)) {
            result = EPROTO;
            break;
        }
        if (hookself::platform::RawClose(protected_fd) != 0 ||
            RawSyscall6(__NR_dup3, replacement_fd, protected_fd, 0) !=
                    protected_fd) {
            result = EIO;
            break;
        }
        if (IsProtectedFdForTask(&context, &task, protected_fd)) {
            result = EOWNERDEAD;
            break;
        }
        __atomic_store_n(&control.protected_fd_count, 0U, __ATOMIC_RELEASE);
        PublishProtectedFdRegistryMutation(&control);
        if (hookself::platform::RawClose(protected_fd) != 0 ||
            RawSyscall6(__NR_dup3, replacement_fd, protected_fd, 0) !=
                    protected_fd) {
            result = EIO;
            break;
        }
        control.protected_fds[0] = protected_fd;
        __atomic_store_n(&control.protected_fd_count, 1U, __ATOMIC_RELEASE);
        PublishProtectedFdRegistryMutation(&control);
        if (!IsProtectedFdForTask(&context, &task, protected_fd)) {
            result = EOWNERDEAD;
            break;
        }
        if (hookself::platform::RawClose(protected_fd) != 0) {
            result = EIO;
            break;
        }
        target_closed = true;
        result = 0;
    } while (false);
    if (!target_closed) {
        (void)hookself::platform::RawClose(protected_fd);
    }
    (void)hookself::platform::RawClose(replacement_fd);
    return result;
}

