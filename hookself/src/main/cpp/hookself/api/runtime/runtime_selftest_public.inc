int32_t RunRuntimeApiBypassDestroyStress(HookselfRuntime* runtime,
                                         bool* destroyed) noexcept {
    return RunRuntimeApiBypassDestroyStressImpl(runtime, destroyed);
}

int32_t RegisterProtectedFdForSelfTest(HookselfRuntime* runtime,
                                       int32_t fd) noexcept {
    if (runtime == nullptr || fd < 0) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    SharedControlPage* const control = GetSharedControl(
            runtime->shared_session);
    if (control == nullptr) {
        return HOOKSELF_E_INVALID_STATE;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count >= kMaxProtectedFds) {
        return HOOKSELF_E_CAPACITY;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (control->protected_fds[index] == fd) {
            return HOOKSELF_E_INVALID_STATE;
        }
    }
    control->protected_fds[count] = fd;
    __atomic_store_n(&control->protected_fd_count, count + 1U,
                     __ATOMIC_RELEASE);
    PublishProtectedFdRegistryMutation(control);
    return HOOKSELF_OK;
}

int32_t UnregisterProtectedFdForSelfTest(HookselfRuntime* runtime,
                                         int32_t fd) noexcept {
    if (runtime == nullptr || fd < 0) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    SharedControlPage* const control = GetSharedControl(
            runtime->shared_session);
    if (control == nullptr) {
        return HOOKSELF_E_INVALID_STATE;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count == 0 || count > kMaxProtectedFds) {
        return HOOKSELF_E_INVALID_STATE;
    }
    uint32_t index = 0;
    while (index < count && control->protected_fds[index] != fd) {
        ++index;
    }
    if (index == count) {
        return HOOKSELF_E_INVALID_STATE;
    }
    control->protected_fds[index] = control->protected_fds[count - 1U];
    control->protected_fds[count - 1U] = -1;
    __atomic_store_n(&control->protected_fd_count, count - 1U,
                     __ATOMIC_RELEASE);
    PublishProtectedFdRegistryMutation(control);
    return HOOKSELF_OK;
}

int64_t CloseProtectedFdForSelfTest(HookselfRuntime* runtime,
                                    int32_t fd) noexcept {
    if (runtime == nullptr || fd < 0 || !HasResidentIntegrityTracer(runtime)) {
        return -EINVAL;
    }
    SharedControlPage* const control = GetSharedControl(runtime->shared_session);
    if (control == nullptr) {
        return -ENODEV;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return -EPROTO;
    }
    bool registered = false;
    for (uint32_t index = 0; index < count; ++index) {
        if (control->protected_fds[index] == fd) {
            registered = true;
            break;
        }
    }
    if (!registered) {
        return -EINVAL;
    }
    // Let the tracer observe the original descriptor before the exact close
    // bypass. A later reuse of this number must not inherit its protection.
    const long identity_probe = hookself::platform::RawSyscall6(
            __NR_fcntl, fd, F_GETFD, 0);
    if (hookself::platform::RawError(identity_probe) != 0) {
        return identity_probe;
    }
    const long tid_result = hookself::platform::RawSyscall6(__NR_gettid);
    if (hookself::platform::RawError(tid_result) != 0 || tid_result <= 0 ||
        tid_result > INT32_MAX) {
        return -EIO;
    }
    if (!BeginInternalProviderIo(control, static_cast<int32_t>(tid_result), fd)) {
        return -EBUSY;
    }
    const long close_result = hookself::platform::RawClose(fd);
    EndInternalProviderIo(control);
    return close_result;
}

uint32_t CloseRangeCapabilitiesForSelfTest(
        const HookselfRuntime* runtime) noexcept {
    if (runtime == nullptr || !HasResidentIntegrityTracer(runtime)) {
        return kCloseRangeCapabilityNone;
    }
    const SharedControlPage* const control = GetSharedControl(
            runtime->shared_session);
    return control == nullptr
                   ? kCloseRangeCapabilityNone
                   : __atomic_load_n(&control->close_range_capabilities,
                                     __ATOMIC_ACQUIRE);
}

void SetVirtualPublishPostCommitFailureForSelfTest(bool enabled) noexcept {
    __atomic_store_n(&gForceVirtualPublishPostCommitFailure,
                     enabled ? 1U : 0U, __ATOMIC_RELEASE);
}
