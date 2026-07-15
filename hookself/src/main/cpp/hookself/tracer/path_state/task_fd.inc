
const PathTaskState* FindPathTask(const PathStateTable* table,
                                  int32_t tid) noexcept {
    return FindPathTask(const_cast<PathStateTable*>(table), tid);
}

const FsContext* GetTaskFsContext(const PathStateTable* table,
                                  int32_t tid) noexcept {
    const PathTaskState* task = FindPathTask(table, tid);
    return task == nullptr ? nullptr :
            &table->fs_contexts[task->fs_context_slot];
}

const MountNamespaceState* GetTaskMountNamespace(
        const PathStateTable* table, int32_t tid) noexcept {
    const PathTaskState* task = FindPathTask(table, tid);
    return task == nullptr ? nullptr :
            &table->mount_namespaces[task->mount_namespace_slot];
}

int InsertInitialPathTask(PathStateTable* table, int32_t tid,
                          const char* guest_cwd,
                          const char* host_cwd) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    int error = ValidateAbsolutePath(guest_cwd);
    if (error == 0) {
        error = ValidateAbsolutePath(host_cwd);
    }
    if (error != 0) {
        return error;
    }
    if (FindTaskUnchecked(table, tid) != nullptr) {
        return EEXIST;
    }
    const uint32_t task_slot = FindFreeTaskSlot(table);
    const uint32_t fs_slot = FindFreeFsContextSlot(table);
    const uint32_t fd_table_slot = FindFreeFdTableSlot(table);
    const uint32_t mount_namespace_slot = FindFreeMountNamespaceSlot(table);
    if (task_slot == kInvalidPathStateSlot ||
        fs_slot == kInvalidPathStateSlot ||
        fd_table_slot == kInvalidPathStateSlot ||
        mount_namespace_slot == kInvalidPathStateSlot) {
        return ENOSPC;
    }

    OccupyInitialFsContext(table, fs_slot, guest_cwd, host_cwd);
    OccupyEmptyFdTable(table, fd_table_slot, 1);
    OccupyInitialMountNamespace(table, mount_namespace_slot);
    const uint64_t task_generation = NoteMutation(table);
    OccupyTask(table, task_slot, tid, fs_slot, fd_table_slot,
               mount_namespace_slot,
               task_generation);
    return 0;
}

int ClonePathTask(PathStateTable* table, int32_t parent_tid,
                  int32_t child_tid, uint64_t clone_flags) noexcept {
    if (!IsPathStateInitialized(table) || parent_tid <= 0 || child_tid <= 0) {
        return EINVAL;
    }
    PathTaskState* parent = FindTaskUnchecked(table, parent_tid);
    if (parent == nullptr) {
        return ESRCH;
    }
    if (FindTaskUnchecked(table, child_tid) != nullptr) {
        return EEXIST;
    }
    const bool share_fs = (clone_flags & kPathCloneFs) != 0;
    const bool share_files = (clone_flags & kPathCloneFiles) != 0;
    const bool new_mount_namespace =
            (clone_flags & kPathCloneNewns) != 0;
    if (share_fs && new_mount_namespace) {
        return EINVAL;
    }
    FsContext* parent_fs = &table->fs_contexts[parent->fs_context_slot];
    FdTable* parent_fds = &table->fd_tables[parent->fd_table_slot];
    MountNamespaceState* parent_mount_namespace =
            &table->mount_namespaces[parent->mount_namespace_slot];
    if ((share_fs && parent_fs->refcount == UINT32_MAX) ||
        (share_files && parent_fds->refcount == UINT32_MAX) ||
        (!new_mount_namespace &&
         (parent_mount_namespace->refcount == UINT32_MAX ||
          parent_mount_namespace->task_refcount == UINT32_MAX))) {
        return EOVERFLOW;
    }

    const uint32_t task_slot = FindFreeTaskSlot(table);
    const uint32_t fs_slot = share_fs ? parent->fs_context_slot
                                      : FindFreeFsContextSlot(table);
    const uint32_t fd_table_slot = share_files ? parent->fd_table_slot
                                               : FindFreeFdTableSlot(table);
    const uint32_t mount_namespace_slot =
            new_mount_namespace ? FindFreeMountNamespaceSlot(table)
                                : parent->mount_namespace_slot;
    if (task_slot == kInvalidPathStateSlot ||
        fs_slot == kInvalidPathStateSlot ||
        fd_table_slot == kInvalidPathStateSlot ||
        mount_namespace_slot == kInvalidPathStateSlot) {
        return ENOSPC;
    }
    if (!share_files && parent_fds->entry_count >
                                CountFreeFdIdentitySlots(table)) {
        return ENOSPC;
    }
    if (new_mount_namespace &&
        parent_mount_namespace->binding_count >
                CountFreeMountBindingSlots(table)) {
        return ENOSPC;
    }

    if (!share_fs) {
        CopyFsContextToSlot(table, *parent_fs, fs_slot);
    }
    if (!share_files) {
        const int copy_error = CopyFdTableToSlot(
                table, parent->fd_table_slot, fd_table_slot,
                FdCopyMode::kAll, 0, 0);
        if (copy_error != 0) {
            if (!share_fs) {
                EraseFsContextSlot(table, fs_slot);
            }
            return copy_error;
        }
    }
    if (new_mount_namespace) {
        const int copy_error = CopyMountNamespaceToSlot(
                table, parent->mount_namespace_slot,
                mount_namespace_slot, true);
        if (copy_error != 0) {
            if (!share_files) {
                EraseFdTableSlot(table, fd_table_slot);
            }
            if (!share_fs) {
                EraseFsContextSlot(table, fs_slot);
            }
            return copy_error;
        }
    }
    if (share_fs) {
        ++parent_fs->refcount;
    }
    if (share_files) {
        ++parent_fds->refcount;
    }
    if (!new_mount_namespace) {
        ++parent_mount_namespace->refcount;
        ++parent_mount_namespace->task_refcount;
    }
    const uint64_t task_generation = NoteMutation(table);
    OccupyTask(table, task_slot, child_tid, fs_slot, fd_table_slot,
               mount_namespace_slot,
               task_generation);
    return 0;
}

int RemovePathTask(PathStateTable* table, int32_t tid) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t task_slot = task->slot;
    const uint32_t fs_slot = task->fs_context_slot;
    const uint32_t fd_table_slot = task->fd_table_slot;
    const uint32_t mount_namespace_slot = task->mount_namespace_slot;
    EraseTaskSlot(table, task_slot);
    ReleaseFsReference(table, fs_slot);
    ReleaseFdTableReference(table, fd_table_slot);
    ReleaseMountNamespaceTaskReference(table, mount_namespace_slot);
    NoteMutation(table);
    return 0;
}

int MigrateExecPathTask(PathStateTable* table, int32_t former_tid,
                        int32_t new_tid) noexcept {
    if (!IsPathStateInitialized(table) || former_tid <= 0 || new_tid <= 0) {
        return EINVAL;
    }
    PathTaskState* source = FindTaskUnchecked(table, former_tid);
    if (source == nullptr) {
        return ESRCH;
    }
    if (former_tid == new_tid) {
        return 0;
    }

    PathTaskState* displaced = FindTaskUnchecked(table, new_tid);
    if (displaced != nullptr) {
        const uint32_t displaced_task_slot = displaced->slot;
        const uint32_t displaced_fs_slot = displaced->fs_context_slot;
        const uint32_t displaced_fd_table_slot = displaced->fd_table_slot;
        const uint32_t displaced_mount_namespace_slot =
                displaced->mount_namespace_slot;
        EraseTaskSlot(table, displaced_task_slot);
        ReleaseFsReference(table, displaced_fs_slot);
        ReleaseFdTableReference(table, displaced_fd_table_slot);
        ReleaseMountNamespaceTaskReference(
                table, displaced_mount_namespace_slot);
    }
    source->tid = new_tid;
    source->identity_generation = NoteMutation(table);
    return 0;
}

int ExecPathTask(PathStateTable* table, int32_t tid) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FsContext* current_fs = &table->fs_contexts[task->fs_context_slot];
    FdTable* current_fds = &table->fd_tables[task->fd_table_slot];
    const bool copy_fs = current_fs->refcount > 1U;
    const bool copy_fds = current_fds->refcount > 1U;
    const uint32_t new_fs_slot = copy_fs ? FindFreeFsContextSlot(table)
                                         : task->fs_context_slot;
    const uint32_t new_fd_slot = copy_fds ? FindFreeFdTableSlot(table)
                                          : task->fd_table_slot;
    if (new_fs_slot == kInvalidPathStateSlot ||
        new_fd_slot == kInvalidPathStateSlot) {
        return ENOSPC;
    }
    if (copy_fds) {
        const uint32_t needed = CountCopiedIdentities(
                table, task->fd_table_slot, FdCopyMode::kExec, 0, 0);
        if (needed > CountFreeFdIdentitySlots(table)) {
            return ENOSPC;
        }
    }

    if (copy_fs) {
        CopyFsContextToSlot(table, *current_fs, new_fs_slot);
    }
    if (copy_fds) {
        const uint32_t old_slot = task->fd_table_slot;
        const int copy_error = CopyFdTableToSlot(
                table, old_slot, new_fd_slot, FdCopyMode::kExec, 0, 0);
        if (copy_error != 0) {
            if (copy_fs) {
                EraseFsContextSlot(table, new_fs_slot);
            }
            return copy_error;
        }
        task->fd_table_slot = new_fd_slot;
        ReleaseFdTableReference(table, old_slot);
    } else {
        for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
            FdIdentity* identity = &table->fd_identities[slot];
            if (identity->occupied != 0 &&
                identity->fd_table_slot == task->fd_table_slot &&
                identity->cloexec != 0) {
                EraseIdentitySlot(table, slot);
            }
        }
        current_fds->generation = NextGeneration(current_fds->generation);
    }
    if (copy_fs) {
        const uint32_t old_slot = task->fs_context_slot;
        task->fs_context_slot = new_fs_slot;
        ReleaseFsReference(table, old_slot);
    }
    NoteMutation(table);
    return 0;
}

int UnsharePathTask(PathStateTable* table, int32_t tid,
                    uint64_t unshare_flags) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FsContext* current_fs = &table->fs_contexts[task->fs_context_slot];
    FdTable* current_fds = &table->fd_tables[task->fd_table_slot];
    MountNamespaceState* current_mount_namespace =
            &table->mount_namespaces[task->mount_namespace_slot];
    const bool copy_mount_namespace =
            (unshare_flags & kPathCloneNewns) != 0;
    const bool copy_fs =
            (unshare_flags & (kPathCloneFs | kPathCloneNewns)) != 0 &&
                          current_fs->refcount > 1U;
    const bool copy_files = (unshare_flags & kPathCloneFiles) != 0 &&
                            current_fds->refcount > 1U;
    if (!copy_fs && !copy_files && !copy_mount_namespace) {
        return 0;
    }

    const uint32_t new_fs_slot = copy_fs ? FindFreeFsContextSlot(table)
                                         : task->fs_context_slot;
    const uint32_t new_fd_table_slot = copy_files
                                               ? FindFreeFdTableSlot(table)
                                               : task->fd_table_slot;
    const uint32_t new_mount_namespace_slot = copy_mount_namespace
            ? FindFreeMountNamespaceSlot(table)
            : task->mount_namespace_slot;
    if (new_fs_slot == kInvalidPathStateSlot ||
        new_fd_table_slot == kInvalidPathStateSlot ||
        new_mount_namespace_slot == kInvalidPathStateSlot ||
        (copy_files && current_fds->entry_count >
                               CountFreeFdIdentitySlots(table)) ||
        (copy_mount_namespace && current_mount_namespace->binding_count >
                                         CountFreeMountBindingSlots(table))) {
        return ENOSPC;
    }

    if (copy_fs) {
        CopyFsContextToSlot(table, *current_fs, new_fs_slot);
    }
    if (copy_files) {
        const int copy_error = CopyFdTableToSlot(
                table, task->fd_table_slot, new_fd_table_slot,
                FdCopyMode::kAll, 0, 0);
        if (copy_error != 0) {
            if (copy_fs) {
                EraseFsContextSlot(table, new_fs_slot);
            }
            return copy_error;
        }
    }
    if (copy_mount_namespace) {
        const int copy_error = CopyMountNamespaceToSlot(
                table, task->mount_namespace_slot,
                new_mount_namespace_slot, true);
        if (copy_error != 0) {
            if (copy_files) {
                EraseFdTableSlot(table, new_fd_table_slot);
            }
            if (copy_fs) {
                EraseFsContextSlot(table, new_fs_slot);
            }
            return copy_error;
        }
    }

    if (copy_fs) {
        const uint32_t old_slot = task->fs_context_slot;
        task->fs_context_slot = new_fs_slot;
        ReleaseFsReference(table, old_slot);
    }
    if (copy_files) {
        const uint32_t old_slot = task->fd_table_slot;
        task->fd_table_slot = new_fd_table_slot;
        ReleaseFdTableReference(table, old_slot);
    }
    if (copy_mount_namespace) {
        const uint32_t old_slot = task->mount_namespace_slot;
        task->mount_namespace_slot = new_mount_namespace_slot;
        ReleaseMountNamespaceTaskReference(table, old_slot);
    }
    NoteMutation(table);
    return 0;
}

int SetTaskCwd(PathStateTable* table, int32_t tid,
               const char* guest_cwd, const char* host_cwd,
               uint32_t origin_flags, uint64_t device,
               uint64_t inode) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        (origin_flags &
         (kPathOriginGuestValid | kPathOriginHostValid)) !=
                (kPathOriginGuestValid | kPathOriginHostValid) ||
        (origin_flags & kPathOriginProtected) != 0) {
        return EINVAL;
    }
    const int origin_error = ValidateOrigin(origin_flags, guest_cwd, host_cwd);
    if (origin_error != 0) {
        return origin_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FsContext* context = &table->fs_contexts[task->fs_context_slot];
    context->cwd_origin_flags = origin_flags;
    context->cwd_device = device;
    context->cwd_inode = inode;
    context->cwd_mount_id = 0;
    CopyPath(context->guest_cwd, guest_cwd);
    CopyPath(context->host_cwd, host_cwd);
    context->generation = NextGeneration(context->generation);
    NoteMutation(table);
    return 0;
}

int SetTaskRoot(PathStateTable* table, int32_t tid,
                const char* guest_root, const char* host_root,
                uint32_t origin_flags, uint64_t device,
                uint64_t inode, uint64_t mount_id) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        (origin_flags &
         (kPathOriginGuestValid | kPathOriginHostValid)) !=
                (kPathOriginGuestValid | kPathOriginHostValid) ||
        (origin_flags & kPathOriginProtected) != 0) {
        return EINVAL;
    }
    const int origin_error = ValidateOrigin(
            origin_flags, guest_root, host_root);
    if (origin_error != 0) {
        return origin_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[task->mount_namespace_slot];
    if (mount_id != 0 && mount_id != mount_namespace.root_mount_id &&
        FindMountBindingById(table, task->mount_namespace_slot,
                             mount_id) == nullptr) {
        return ENOENT;
    }
    FsContext* context = &table->fs_contexts[task->fs_context_slot];
    context->root_origin_flags = origin_flags;
    context->root_device = device;
    context->root_inode = inode;
    context->root_mount_id = mount_id;
    CopyPath(context->guest_root, guest_root);
    CopyPath(context->host_root, host_root);
    context->generation = NextGeneration(context->generation);
    NoteMutation(table);
    return 0;
}

const FdIdentity* LookupFdIdentity(const PathStateTable* table, int32_t tid,
                                   int32_t fd) noexcept {
    if (fd < 0) {
        return nullptr;
    }
    const PathTaskState* task = FindPathTask(table, tid);
    return task == nullptr ? nullptr :
            FindIdentityUnchecked(table, task->fd_table_slot, fd);
}

int ResolveFdIdentityView(const PathStateTable* table, int32_t tid,
                          int32_t fd, FdIdentityView* view) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 || fd < 0 ||
        view == nullptr) {
        return EINVAL;
    }
    ZeroBytes(view, sizeof(*view));
    const PathTaskState* task = FindPathTask(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const FdIdentity* identity = LookupFdIdentity(table, tid, fd);
    if (identity == nullptr) {
        return ENOENT;
    }
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[task->mount_namespace_slot];
    view->origin_flags = identity->origin_flags;
    view->namespace_identity = mount_namespace.identity_generation;
    view->namespace_generation = mount_namespace.generation;
    if ((identity->origin_flags & kPathOriginGuestValid) != 0) {
        CopyPath(view->guest_path, identity->guest_path);
    }
    if ((identity->origin_flags & kPathOriginHostValid) != 0) {
        CopyPath(view->host_path, identity->host_path);
    }

    const bool namespace_changed =
            identity->mount_namespace_slot != task->mount_namespace_slot ||
            identity->mount_namespace_identity !=
                    mount_namespace.identity_generation;
    const bool namespace_mutated =
            !namespace_changed &&
            identity->mount_namespace_generation !=
                    mount_namespace.generation;
    if (namespace_changed) {
        view->flags |= kFdIdentityViewNamespaceChanged;
    }
    if (namespace_mutated) {
        view->flags |= kFdIdentityViewNamespaceMutated;
    }
    if ((!namespace_changed && !namespace_mutated) ||
        (identity->origin_flags & kPathOriginHostValid) == 0) {
        return 0;
    }

    MountPathTranslation translation{};
    const int reverse_error = ReverseMountPath(
            table, tid, identity->host_path, &translation);
    if (reverse_error != 0) {
        return reverse_error;
    }
    if (translation.matched != 0) {
        CopyPath(view->guest_path, translation.guest_path);
        view->origin_flags |= kPathOriginGuestValid |
                              kPathOriginReverseVisible;
        view->flags |= kFdIdentityViewMountTranslated;
        view->mount_id = translation.mount_id;
        return 0;
    }
    if ((identity->origin_flags & kPathOriginGuestValid) != 0) {
        view->flags |= kFdIdentityViewCapturedFallback;
        return 0;
    }
    CopyPath(view->guest_path, identity->host_path);
    view->origin_flags |= kPathOriginGuestValid | kPathOriginAmbiguous;
    view->flags |= kFdIdentityViewCapturedFallback;
    return 0;
}

const FdIdentity* NextProtectedFdIdentity(const PathStateTable* table,
                                          int32_t tid,
                                          int32_t after_fd) noexcept {
    const PathTaskState* task = FindPathTask(table, tid);
    return task == nullptr ? nullptr : NextProtectedFdIdentityInTable(
            table, task->fd_table_slot, after_fd);
}

const FdIdentity* NextProtectedFdIdentityInTable(
        const PathStateTable* table, uint32_t fd_table_slot,
        int32_t after_fd) noexcept {
    if (!IsPathStateInitialized(table) ||
        fd_table_slot >= kPathStateFdTableCapacity ||
        table->fd_tables[fd_table_slot].occupied == 0) {
        return nullptr;
    }
    const FdIdentity* selected = nullptr;
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        const FdIdentity* identity = &table->fd_identities[slot];
        if (identity->occupied == 0 ||
            identity->fd_table_slot != fd_table_slot ||
            (identity->origin_flags & kPathOriginProtected) == 0 ||
            identity->fd <= after_fd) {
            continue;
        }
        if (selected == nullptr || identity->fd < selected->fd) {
            selected = identity;
        }
    }
    return selected;
}

int RecordFdIdentity(PathStateTable* table, int32_t tid, int32_t fd,
                     const FdIdentitySpec& identity) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 || fd < 0) {
        return EINVAL;
    }
    const int validation_error = ValidateIdentitySpec(identity);
    if (validation_error != 0) {
        return validation_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[task->mount_namespace_slot];
    FdIdentity* existing = FindIdentityUnchecked(
            table, task->fd_table_slot, fd);
    if (existing != nullptr) {
        const uint32_t slot = existing->slot;
        const uint32_t old_object_kind = existing->object_kind;
        const uint32_t old_object_slot = existing->object_slot;
        const bool was_protected =
                (existing->origin_flags & kPathOriginProtected) != 0;
        const bool now_protected =
                (identity.origin_flags & kPathOriginProtected) != 0;
        FillIdentity(existing, slot, task->fd_table_slot, fd, identity,
                     task->mount_namespace_slot,
                     mount_namespace.identity_generation,
                     mount_namespace.generation);
        if (was_protected != now_protected) {
            if (now_protected) {
                ++fd_table->protected_count;
            } else {
                --fd_table->protected_count;
            }
        }
        if (old_object_kind == kFdIdentityObjectMountTree &&
            old_object_slot < kPathStateMountTreeCapacity) {
            ReleaseMountTreeReference(table, old_object_slot);
        }
    } else {
        const uint32_t slot = FindFreeFdIdentitySlot(table);
        if (slot == kInvalidPathStateSlot) {
            return ENOSPC;
        }
        FillIdentity(&table->fd_identities[slot], slot,
                     task->fd_table_slot, fd, identity,
                     task->mount_namespace_slot,
                     mount_namespace.identity_generation,
                     mount_namespace.generation);
        ++fd_table->entry_count;
        if ((identity.origin_flags & kPathOriginProtected) != 0) {
            ++fd_table->protected_count;
        }
        ++table->fd_identity_count;
        AdvanceHint(slot, kPathStateFdIdentityCapacity,
                    &table->fd_identity_free_hint);
    }
    fd_table->generation = NextGeneration(fd_table->generation);
    NoteMutation(table);
    return 0;
}

int DuplicateFdIdentity(PathStateTable* table, int32_t tid, int32_t old_fd,
                        int32_t new_fd, bool cloexec) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        old_fd < 0 || new_fd < 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    if (old_fd == new_fd) {
        return 0;
    }
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    FdIdentity* source = FindIdentityUnchecked(
            table, task->fd_table_slot, old_fd);
    FdIdentity* destination = FindIdentityUnchecked(
            table, task->fd_table_slot, new_fd);
    if (source == nullptr) {
        if (destination != nullptr) {
            EraseIdentitySlot(table, destination->slot);
            fd_table->generation = NextGeneration(fd_table->generation);
            NoteMutation(table);
        }
        return 0;
    }

    const FdIdentity source_copy = *source;
    if (destination == nullptr) {
        const uint32_t slot = FindFreeFdIdentitySlot(table);
        if (slot == kInvalidPathStateSlot) {
            return ENOSPC;
        }
        if (source_copy.object_kind == kFdIdentityObjectMountTree) {
            const int retain_error = RetainMountTreeReference(
                    table, source_copy.object_slot);
            if (retain_error != 0) {
                return retain_error;
            }
        }
        destination = &table->fd_identities[slot];
        *destination = source_copy;
        destination->slot = slot;
        destination->fd = new_fd;
        destination->cloexec = cloexec ? 1U : 0U;
        ++fd_table->entry_count;
        if ((destination->origin_flags & kPathOriginProtected) != 0) {
            ++fd_table->protected_count;
        }
        ++table->fd_identity_count;
        AdvanceHint(slot, kPathStateFdIdentityCapacity,
                    &table->fd_identity_free_hint);
    } else {
        const uint32_t slot = destination->slot;
        const uint32_t old_object_kind = destination->object_kind;
        const uint32_t old_object_slot = destination->object_slot;
        const bool was_protected =
                (destination->origin_flags & kPathOriginProtected) != 0;
        if (source_copy.object_kind == kFdIdentityObjectMountTree) {
            const int retain_error = RetainMountTreeReference(
                    table, source_copy.object_slot);
            if (retain_error != 0) {
                return retain_error;
            }
        }
        *destination = source_copy;
        destination->slot = slot;
        destination->fd_table_slot = task->fd_table_slot;
        destination->fd = new_fd;
        destination->cloexec = cloexec ? 1U : 0U;
        const bool now_protected =
                (destination->origin_flags & kPathOriginProtected) != 0;
        if (was_protected != now_protected) {
            if (now_protected) {
                ++fd_table->protected_count;
            } else {
                --fd_table->protected_count;
            }
        }
        if (old_object_kind == kFdIdentityObjectMountTree &&
            old_object_slot < kPathStateMountTreeCapacity) {
            ReleaseMountTreeReference(table, old_object_slot);
        }
    }
    fd_table->generation = NextGeneration(fd_table->generation);
    NoteMutation(table);
    return 0;
}

int CloseFdIdentity(PathStateTable* table, int32_t tid, int32_t fd) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 || fd < 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdIdentity* identity = FindIdentityUnchecked(
            table, task->fd_table_slot, fd);
    if (identity == nullptr) {
        return 0;
    }
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    EraseIdentitySlot(table, identity->slot);
    fd_table->generation = NextGeneration(fd_table->generation);
    NoteMutation(table);
    return 0;
}

int SetFdIdentityCloexec(PathStateTable* table, int32_t tid, int32_t fd,
                         bool cloexec) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 || fd < 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdIdentity* identity = FindIdentityUnchecked(
            table, task->fd_table_slot, fd);
    if (identity == nullptr || identity->cloexec == (cloexec ? 1U : 0U)) {
        return 0;
    }
    identity->cloexec = cloexec ? 1U : 0U;
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    fd_table->generation = NextGeneration(fd_table->generation);
    NoteMutation(table);
    return 0;
}

int CloseFdIdentityRange(PathStateTable* table, int32_t tid, uint32_t first,
                         uint32_t last, uint32_t flags) noexcept {
    constexpr uint32_t kKnownFlags =
            kPathCloseRangeUnshare | kPathCloseRangeCloexec;
    if (!IsPathStateInitialized(table) || tid <= 0 || first > last ||
        (flags & ~kKnownFlags) != 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    const bool unshare = (flags & kPathCloseRangeUnshare) != 0;
    const bool set_cloexec = (flags & kPathCloseRangeCloexec) != 0;
    if (unshare && fd_table->refcount > 1U) {
        const uint32_t new_slot = FindFreeFdTableSlot(table);
        const FdCopyMode mode = set_cloexec
                                        ? FdCopyMode::kCloexecRange
                                        : FdCopyMode::kCloseRange;
        const uint32_t needed = CountCopiedIdentities(
                table, task->fd_table_slot, mode, first, last);
        if (new_slot == kInvalidPathStateSlot ||
            needed > CountFreeFdIdentitySlots(table)) {
            return ENOSPC;
        }
        const uint32_t old_slot = task->fd_table_slot;
        const int copy_error = CopyFdTableToSlot(
                table, old_slot, new_slot, mode, first, last);
        if (copy_error != 0) {
            return copy_error;
        }
        task->fd_table_slot = new_slot;
        ReleaseFdTableReference(table, old_slot);
        NoteMutation(table);
        return 0;
    }

    bool changed = false;
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        FdIdentity* identity = &table->fd_identities[slot];
        if (identity->occupied == 0 ||
            identity->fd_table_slot != task->fd_table_slot ||
            !FdInRange(identity->fd, first, last)) {
            continue;
        }
        if (set_cloexec) {
            if (identity->cloexec == 0) {
                identity->cloexec = 1;
                changed = true;
            }
        } else {
            EraseIdentitySlot(table, slot);
            changed = true;
        }
    }
    if (changed) {
        fd_table->generation = NextGeneration(fd_table->generation);
        NoteMutation(table);
    }
    return 0;
}

int CloseFdIdentityRangePreservingProtected(
        PathStateTable* table, int32_t tid, uint32_t first, uint32_t last,
        uint32_t flags) noexcept {
    constexpr uint32_t kKnownFlags =
            kPathCloseRangeUnshare | kPathCloseRangeCloexec;
    if (!IsPathStateInitialized(table) || tid <= 0 || first > last ||
        (flags & ~kKnownFlags) != 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdTable* fd_table = &table->fd_tables[task->fd_table_slot];
    const bool unshare = (flags & kPathCloseRangeUnshare) != 0;
    const bool set_cloexec = (flags & kPathCloseRangeCloexec) != 0;
    if (unshare && fd_table->refcount > 1U) {
        const uint32_t new_slot = FindFreeFdTableSlot(table);
        const FdCopyMode mode = set_cloexec
                                        ? FdCopyMode::kCloexecRangePreserveProtected
                                        : FdCopyMode::kCloseRangePreserveProtected;
        const uint32_t needed = CountCopiedIdentities(
                table, task->fd_table_slot, mode, first, last);
        if (new_slot == kInvalidPathStateSlot ||
            needed > CountFreeFdIdentitySlots(table)) {
            return ENOSPC;
        }
        const uint32_t old_slot = task->fd_table_slot;
        const int copy_error = CopyFdTableToSlot(
                table, old_slot, new_slot, mode, first, last);
        if (copy_error != 0) {
            return copy_error;
        }
        task->fd_table_slot = new_slot;
        ReleaseFdTableReference(table, old_slot);
        NoteMutation(table);
        return 0;
    }

    bool changed = false;
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        FdIdentity* identity = &table->fd_identities[slot];
        if (identity->occupied == 0 ||
            identity->fd_table_slot != task->fd_table_slot ||
            !FdInRange(identity->fd, first, last)) {
            continue;
        }
        if (set_cloexec) {
            if (identity->cloexec == 0) {
                identity->cloexec = 1;
                changed = true;
            }
        } else if ((identity->origin_flags & kPathOriginProtected) == 0) {
            EraseIdentitySlot(table, slot);
            changed = true;
        }
    }
    if (changed) {
        fd_table->generation = NextGeneration(fd_table->generation);
        NoteMutation(table);
    }
    return 0;
}
