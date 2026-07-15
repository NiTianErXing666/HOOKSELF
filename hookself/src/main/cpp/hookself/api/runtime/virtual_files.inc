bool AppendHiddenRange(
        hookself::internal::VirtualFileHiddenRange* ranges, size_t capacity,
        size_t* count, uintptr_t start, size_t size) {
    if (start == 0 || size == 0 || *count >= capacity) {
        return false;
    }
    ranges[*count] = {start, size};
    ++*count;
    return true;
}

struct ModuleRangeContext {
    uintptr_t target;
    hookself::internal::VirtualFileHiddenRange* ranges;
    size_t capacity;
    size_t* count;
};

int CollectContainingModuleRanges(dl_phdr_info* info, size_t,
                                  void* opaque) {
    auto* context = static_cast<ModuleRangeContext*>(opaque);
    bool contains_target = false;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& header = info->dlpi_phdr[i];
        if (header.p_type != PT_LOAD) {
            continue;
        }
        const uintptr_t start = info->dlpi_addr + header.p_vaddr;
        if (header.p_memsz <= UINTPTR_MAX - start &&
            context->target >= start &&
            context->target < start + header.p_memsz) {
            contains_target = true;
            break;
        }
    }
    if (!contains_target) {
        return 0;
    }
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& header = info->dlpi_phdr[i];
        if (header.p_type == PT_LOAD) {
            (void)AppendHiddenRange(
                    context->ranges, context->capacity, context->count,
                    info->dlpi_addr + header.p_vaddr,
                    static_cast<size_t>(header.p_memsz));
        }
    }
    return 1;
}

size_t BuildProviderHiddenRanges(
        HookselfRuntime* runtime,
        hookself::internal::VirtualFileHiddenRange* ranges,
        size_t capacity) {
    size_t count = 0;
    (void)AppendHiddenRange(
            ranges, capacity, &count,
            reinterpret_cast<uintptr_t>(runtime->virtual_provider_scratch),
            runtime->virtual_provider_scratch_size);
    (void)AppendHiddenRange(
            ranges, capacity, &count,
            reinterpret_cast<uintptr_t>(runtime->shared_session.prefix_mapping),
            runtime->shared_session.prefix_size);
    (void)AppendHiddenRange(
            ranges, capacity, &count,
            reinterpret_cast<uintptr_t>(
                    runtime->shared_session.tracee_scratch_mapping),
            runtime->shared_session.scratch_size);
    for (uint32_t i = 0; i < runtime->config.virtual_file_count; ++i) {
        (void)AppendHiddenRange(
                ranges, capacity, &count,
                reinterpret_cast<uintptr_t>(runtime->virtual_contents[i]),
                runtime->virtual_files[i].initial_content_size);
    }
    ModuleRangeContext module{
            reinterpret_cast<uintptr_t>(&hookself_refresh_virtual_file),
            ranges, capacity, &count};
    (void)dl_iterate_phdr(CollectContainingModuleRanges, &module);
    return count;
}

int32_t ReopenVirtualProviderSource(HookselfRuntime* runtime,
                                    uint32_t index) {
    if (runtime->virtual_provider_uses_configured_content[index] != 0 ||
        runtime->virtual_files[index].provider <
                HOOKSELF_VFILE_PROC_STATUS) {
        return HOOKSELF_OK;
    }
    if (HasResidentIntegrityTracer(runtime)) {
        return runtime->virtual_provider_source_fds[index] >= 0 &&
                       hookself::internal::CheckFdObjectIdentity(
                               runtime->virtual_provider_source_fds[index],
                               runtime->virtual_provider_source_identities[
                                       index]) == 0
                       ? HOOKSELF_OK
                       : HOOKSELF_E_INTERNAL;
    }
    if (runtime->virtual_provider_source_fds[index] >= 0) {
        (void)hookself::internal::CloseFdObject(
                runtime->virtual_provider_source_fds[index],
                runtime->virtual_provider_source_identities[index]);
        runtime->virtual_provider_source_fds[index] = -1;
        hookself::internal::ClearFdObjectIdentity(
                &runtime->virtual_provider_source_identities[index]);
    }
    const int error = hookself::internal::OpenVirtualFileProviderSource(
            runtime->virtual_files[index].provider, runtime->target_pid,
            &runtime->virtual_provider_source_fds[index]);
    if (error != 0) {
        return HOOKSELF_E_UNSUPPORTED;
    }
    if (hookself::internal::CaptureRawFdObjectIdentity(
                runtime->virtual_provider_source_fds[index],
                &runtime->virtual_provider_source_identities[index]) != 0) {
        (void)syscall(__NR_close,
                      runtime->virtual_provider_source_fds[index]);
        runtime->virtual_provider_source_fds[index] = -1;
        return HOOKSELF_E_INTERNAL;
    }
    return HOOKSELF_OK;
}

bool ResidentTracerLooksDead(const HookselfRuntime* runtime,
                             const hookself::internal::SharedControlPage* control) {
    const pid_t tracer_pid = __atomic_load_n(
            &runtime->resident_controller.tracer_pid, __ATOMIC_ACQUIRE);
    const int status_fd = __atomic_load_n(
            &runtime->resident_controller.status_read_fd, __ATOMIC_ACQUIRE);
    if (tracer_pid <= 0 || status_fd < 0 ||
        hookself::internal::CheckFdObjectIdentity(
                status_fd,
                runtime->resident_controller.status_read_identity) != 0) {
        return true;
    }

    pollfd descriptor{status_fd,
                      static_cast<short>(POLLIN | POLLHUP | POLLERR), 0};
    const int poll_result = poll(&descriptor, 1, 0);
    if (poll_result > 0 &&
        (descriptor.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
        return true;
    }
    if (kill(tracer_pid, 0) != 0 && errno == ESRCH) {
        return true;
    }

    const uint64_t heartbeat = __atomic_load_n(
            &control->tracer_heartbeat_ns, __ATOMIC_ACQUIRE);
    const uint64_t now = MonotonicTimeNanoseconds();
    return heartbeat != 0 && now > heartbeat &&
           now - heartbeat > 3000000000ULL;
}

int32_t ReplaceVirtualFileSnapshotLocked(HookselfRuntime* runtime,
                                         uint32_t index,
                                         const uint8_t* content,
                                         size_t content_size,
                                         uint32_t* snapshot_published_out) {
    if (snapshot_published_out != nullptr) {
        *snapshot_published_out = 0U;
    }
    hookself::internal::SharedControlPage* control = nullptr;
    bool bypass_owned = false;
    const int32_t owner_tid = static_cast<int32_t>(syscall(__NR_gettid));
    if (HasResidentIntegrityTracer(runtime)) {
        control = hookself::internal::GetSharedControl(runtime->shared_session);
        const uint32_t active = control == nullptr
                                        ? 0U
                                        : __atomic_load_n(
                                                  &control->internal_bypass_active,
                                                  __ATOMIC_ACQUIRE);
        if (active == 0) {
            bypass_owned = BeginInternalProviderIo(control, owner_tid, -1);
            if (!bypass_owned) {
                return HOOKSELF_E_BUSY;
            }
        } else if (control->internal_bypass_tid != owner_tid ||
                   control->internal_bypass_fd != -1) {
            return HOOKSELF_E_BUSY;
        }
    }
    auto* replacement = content_size == 0
                                ? nullptr
                                : new (std::nothrow) uint8_t[content_size];
    if (content_size != 0 && replacement == nullptr) {
        if (bypass_owned) {
            EndInternalProviderIo(control);
        }
        return HOOKSELF_E_NO_MEMORY;
    }
    for (size_t j = 0; j < content_size; ++j) {
        replacement[j] = content[j];
    }
    int snapshot_fd = -1;
    const int prepare_error = hookself::internal::PrepareVirtualFileSnapshot(
            &runtime->virtual_backings[index], replacement, content_size,
            &snapshot_fd);
    if (prepare_error != 0) {
        delete[] replacement;
        if (bypass_owned) {
            EndInternalProviderIo(control);
        }
        return HOOKSELF_E_INTERNAL;
    }
    hookself::internal::FdObjectIdentity snapshot_identity{};
    if (hookself::internal::CaptureRawFdObjectIdentity(
                snapshot_fd, &snapshot_identity) != 0) {
        (void)hookself::internal::DiscardVirtualFileSnapshot(
                &runtime->virtual_backings[index], snapshot_fd);
        delete[] replacement;
        if (bypass_owned) {
            EndInternalProviderIo(control);
        }
        return HOOKSELF_E_INTERNAL;
    }
    uint64_t internal_sequence = 0;
    int handshake_error = 0;
    if (HasResidentIntegrityTracer(runtime)) {
        handshake_error = BeginInternalFdOperation(
                control, owner_tid,
                hookself::internal::SharedFdOperationCode::kDup3Replace,
                snapshot_fd, runtime->virtual_backings[index].stable_fd,
                0, &internal_sequence);
    }
    const int backing_error =
            handshake_error == 0
                    ? hookself::internal::CommitVirtualFileSnapshot(
                              &runtime->virtual_backings[index], snapshot_fd)
                    : handshake_error;
    const bool snapshot_published =
            runtime->virtual_backings[index].last_commit_published != 0;
    if (snapshot_published_out != nullptr && snapshot_published) {
        *snapshot_published_out = 1U;
    }
    const bool stable_synchronized =
            runtime->virtual_backings[index].last_commit_stable_synchronized !=
            0;
    bool handshake_matched = handshake_error == 0;
    if (HasResidentIntegrityTracer(runtime) &&
        handshake_error == 0) {
        const int64_t expected_result =
                stable_synchronized
                        ? runtime->virtual_backings[index].stable_fd
                        : -backing_error;
        handshake_matched = FinishInternalFdOperation(
                control, internal_sequence, expected_result);
    }
    if (backing_error != 0) {
        if (snapshot_published) {
            (void)hookself::internal::CloseFdObject(snapshot_fd,
                                                    snapshot_identity);
            uint8_t* const old_content = runtime->virtual_contents[index];
            runtime->virtual_contents[index] = replacement;
            runtime->virtual_files[index].initial_content = replacement;
            runtime->virtual_files[index].initial_content_size =
                    static_cast<uint32_t>(content_size);
            delete[] old_content;
        } else {
            (void)hookself::internal::DiscardVirtualFileSnapshot(
                    &runtime->virtual_backings[index], snapshot_fd);
            delete[] replacement;
        }
        if (bypass_owned) {
            EndInternalProviderIo(control);
        }
        return HOOKSELF_E_INTERNAL;
    }
    (void)hookself::internal::CloseFdObject(snapshot_fd,
                                            snapshot_identity);
    uint8_t* const old_content = runtime->virtual_contents[index];
    runtime->virtual_contents[index] = replacement;
    runtime->virtual_files[index].initial_content = replacement;
    runtime->virtual_files[index].initial_content_size =
            static_cast<uint32_t>(content_size);
    delete[] old_content;
    if (bypass_owned) {
        EndInternalProviderIo(control);
    }
#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
    const bool forced_post_commit_failure = __atomic_exchange_n(
            &gForceVirtualPublishPostCommitFailure, 0U,
            __ATOMIC_ACQ_REL) != 0U;
#else
    constexpr bool forced_post_commit_failure = false;
#endif
    return handshake_matched && !forced_post_commit_failure
                   ? HOOKSELF_OK
                   : HOOKSELF_E_INTERNAL;
}

int32_t RefreshVirtualFileProviderLocked(HookselfRuntime* runtime,
                                         uint32_t index) {
    const int32_t provider = runtime->virtual_files[index].provider;
    if (provider < HOOKSELF_VFILE_PROC_STATUS ||
        provider > HOOKSELF_VFILE_SELINUX_CONTEXT) {
        return HOOKSELF_E_INVALID_STATE;
    }
    hookself::internal::SharedControlPage* control = nullptr;
    bool bypass_active = false;
    if (HasResidentIntegrityTracer(runtime)) {
        control = hookself::internal::GetSharedControl(runtime->shared_session);
        bypass_active = BeginInternalProviderIo(
                control, static_cast<int32_t>(syscall(__NR_gettid)), -1);
        if (!bypass_active) {
            return HOOKSELF_E_BUSY;
        }
    }
    auto* generated = runtime->virtual_provider_scratch;
    if (generated == nullptr) {
        if (bypass_active) {
            EndInternalProviderIo(control);
        }
        return HOOKSELF_E_NO_MEMORY;
    }
    const bool configured_content =
            runtime->virtual_provider_uses_configured_content[index] != 0;
    hookself::internal::VirtualFileHiddenRange
            hidden_ranges[HOOKSELF_MAX_VIRTUAL_FILES + 32]{};
    const size_t hidden_range_count = BuildProviderHiddenRanges(
            runtime, hidden_ranges, HOOKSELF_MAX_VIRTUAL_FILES + 32);
    size_t generated_size = 0;
    const int generate_error =
            hookself::internal::GenerateVirtualFileProviderSnapshot(
                    provider, runtime->virtual_files[index].flags,
                    runtime->virtual_provider_source_fds[index],
                    configured_content
                            ? runtime->virtual_contents[index]
                            : nullptr,
                    configured_content
                            ? runtime->virtual_files[index].initial_content_size
                            : 0,
                    hidden_ranges, hidden_range_count,
                    generated, HOOKSELF_MAX_VIRTUAL_FILE_SIZE,
                    &generated_size);
    if (generate_error != 0) {
        if (bypass_active) {
            EndInternalProviderIo(control);
        }
        return generate_error == ENOMEM
                       ? HOOKSELF_E_NO_MEMORY
                       : (generate_error == EFBIG ||
                          generate_error == EOVERFLOW)
                                 ? HOOKSELF_E_CAPACITY
                                 : HOOKSELF_E_INTERNAL;
    }
    const int32_t replace_result = ReplaceVirtualFileSnapshotLocked(
            runtime, index, generated, generated_size, nullptr);
    if (bypass_active) {
        EndInternalProviderIo(control);
    }
    return replace_result;
}
