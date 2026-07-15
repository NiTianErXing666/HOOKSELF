
namespace {

bool BindingDescendsFrom(const PathStateTable* table,
                         const MountBindingState& binding,
                         uint64_t ancestor_mount_id) noexcept {
    uint64_t parent = binding.parent_mount_id;
    for (uint32_t depth = 0; depth < kPathStateMountBindingCapacity; ++depth) {
        if (parent == ancestor_mount_id) {
            return true;
        }
        const MountNamespaceState& mount_namespace =
                table->mount_namespaces[binding.mount_namespace_slot];
        if (parent == mount_namespace.root_mount_id) {
            return false;
        }
        const MountBindingState* ancestor = FindMountBindingById(
                table, binding.mount_namespace_slot, parent);
        if (ancestor == nullptr) {
            return false;
        }
        parent = ancestor->parent_mount_id;
    }
    return false;
}

bool MountIdIsSelected(const PathStateTable* table, uint32_t namespace_slot,
                       uint64_t mount_id,
                       const bool selected_slots[
                               kPathStateMountBindingCapacity]) noexcept {
    const MountBindingState* binding = FindMountBindingById(
            table, namespace_slot, mount_id);
    return binding != nullptr && selected_slots[binding->slot];
}

bool MountIdDescendsFrom(const PathStateTable* table, uint32_t namespace_slot,
                         uint64_t mount_id,
                         uint64_t ancestor_mount_id) noexcept {
    if (mount_id == ancestor_mount_id) {
        return true;
    }
    const MountBindingState* binding = FindMountBindingById(
            table, namespace_slot, mount_id);
    return binding != nullptr &&
           BindingDescendsFrom(table, *binding, ancestor_mount_id);
}

int ValidateMountBindingSpec(const MountBindingSpec& binding) noexcept {
    if (binding.kind < kMountBindingBind ||
        binding.kind > kMountBindingRoot ||
        (binding.state_flags & ~kMountBindingStateKnownFlags) != 0 ||
        (binding.state_flags & kMountBindingStateDetached) != 0) {
        return EINVAL;
    }
    int error = ValidateCanonicalPath(binding.target_guest);
    if (error == 0) {
        error = ValidateCanonicalPath(binding.source_guest);
    }
    if (error == 0) {
        error = ValidateCanonicalPath(binding.source_host);
    }
    return error;
}

uint64_t VisibleParentMountId(const PathStateTable* table,
                              uint32_t namespace_slot,
                              const char* target_guest) noexcept {
    const MountBindingState* visible = ResolveVisibleMount(
            table, namespace_slot, target_guest);
    if (visible == nullptr) {
        return table->mount_namespaces[namespace_slot].root_mount_id;
    }
    return PathEquals(visible->target_guest, target_guest)
                   ? visible->parent_mount_id
                   : visible->mount_id;
}

int AddMountBindingInternal(PathStateTable* table, uint32_t namespace_slot,
                            const MountBindingSpec& binding,
                            uint64_t* mount_id,
                            MountBindingState** created) noexcept {
    if (created != nullptr) {
        *created = nullptr;
    }
    const int validation_error = ValidateMountBindingSpec(binding);
    if (validation_error != 0) {
        return validation_error;
    }
    const uint32_t slot = FindFreeMountBindingSlot(table);
    if (slot == kInvalidPathStateSlot) {
        return ENOSPC;
    }
    MountNamespaceState* mount_namespace =
            &table->mount_namespaces[namespace_slot];
    uint64_t parent_mount_id = binding.parent_mount_id;
    if (parent_mount_id == 0) {
        parent_mount_id = VisibleParentMountId(
                table, namespace_slot, binding.target_guest);
    } else if (parent_mount_id != mount_namespace->root_mount_id &&
               FindMountBindingById(table, namespace_slot,
                                    parent_mount_id) == nullptr) {
        return ENOENT;
    }

    const uint64_t sequence = NoteMutation(table);
    MountBindingState* destination = &table->mount_bindings[slot];
    ClearMountBinding(destination, slot);
    destination->occupied = 1;
    destination->mount_namespace_slot = namespace_slot;
    destination->kind = binding.kind;
    destination->state_flags = binding.state_flags;
    destination->mount_id = sequence;
    destination->parent_mount_id = parent_mount_id;
    destination->sequence = sequence;
    destination->mount_flags = binding.mount_flags;
    destination->mount_attributes = binding.mount_attributes;
    destination->propagation = binding.propagation;
    CopyPath(destination->target_guest, binding.target_guest);
    CopyPath(destination->source_guest, binding.source_guest);
    CopyPath(destination->source_host, binding.source_host);
    ++mount_namespace->binding_count;
    mount_namespace->generation = NextGeneration(
            mount_namespace->generation);
    ++table->mount_binding_count;
    AdvanceHint(slot, kPathStateMountBindingCapacity,
                &table->mount_binding_free_hint);
    if (mount_id != nullptr) {
        *mount_id = destination->mount_id;
    }
    if (created != nullptr) {
        *created = destination;
    }
    return 0;
}

void InitializeTranslation(MountPathTranslation* translation) noexcept {
    ZeroBytes(translation, sizeof(*translation));
    translation->binding_slot = kInvalidPathStateSlot;
}

void FillTranslationMetadata(const MountNamespaceState& mount_namespace,
                             const MountBindingState* binding,
                             MountPathTranslation* translation) noexcept {
    translation->matched = 1;
    translation->namespace_generation = mount_namespace.generation;
    if (binding == nullptr) {
        translation->kind = kMountBindingRoot;
        translation->mount_id = mount_namespace.root_mount_id;
        translation->mount_flags = mount_namespace.root_mount_flags;
        translation->mount_attributes =
                mount_namespace.root_mount_attributes;
        return;
    }
    translation->binding_slot = binding->slot;
    translation->kind = binding->kind;
    translation->state_flags = binding->state_flags;
    translation->mount_id = binding->mount_id;
    translation->binding_sequence = binding->sequence;
    translation->mount_flags = binding->mount_flags;
    translation->mount_attributes = binding->mount_attributes;
}

bool NamespaceRootChanged(const MountNamespaceState& mount_namespace) noexcept {
    return !PathEquals(mount_namespace.root_source_guest, "/") ||
           !PathEquals(mount_namespace.root_source_host, "/");
}

bool ReverseBindingRoundTrips(
        const PathStateTable* table, uint32_t namespace_slot,
        const MountBindingState& binding, const char* host_path,
        char guest_path[HOOKSELF_PATH_CAPACITY]) noexcept {
    if (SubstitutePathPrefix(host_path, binding.source_host,
                             binding.target_guest, guest_path) != 0) {
        return false;
    }
    return ResolveVisibleMount(table, namespace_slot, guest_path) == &binding;
}

bool ReverseRootRoundTrips(
        const PathStateTable* table, uint32_t namespace_slot,
        const char* host_path,
        char guest_path[HOOKSELF_PATH_CAPACITY]) noexcept {
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[namespace_slot];
    if (SubstitutePathPrefix(host_path,
                             mount_namespace.root_source_host, "/",
                             guest_path) != 0) {
        return false;
    }
    return ResolveVisibleMount(table, namespace_slot, guest_path) == nullptr;
}

}  // namespace

int AddMountBinding(PathStateTable* table, int32_t tid,
                    const MountBindingSpec& binding,
                    uint64_t* mount_id) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    return AddMountBindingInternal(table, task->mount_namespace_slot,
                                   binding, mount_id, nullptr);
}

int AddRecursiveMountBinding(PathStateTable* table, int32_t tid,
                             const MountBindingSpec& binding,
                             uint64_t* mount_id) noexcept {
    if (mount_id != nullptr) {
        *mount_id = 0;
    }
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        binding.kind != kMountBindingBind ||
        (binding.state_flags & kMountBindingStateRecursive) == 0) {
        return EINVAL;
    }
    const int validation_error = ValidateMountBindingSpec(binding);
    if (validation_error != 0) {
        return validation_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    bool included[kPathStateMountBindingCapacity]{};
    uint32_t child_count = 0;
    size_t source_length = 0;
    int error = PathLength(binding.source_guest, &source_length);
    if (error != 0) {
        return error;
    }
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            (candidate.state_flags & kMountBindingStateDetached) != 0 ||
            PathEquals(candidate.target_guest, binding.source_guest) ||
            !PathPrefixMatches(candidate.target_guest,
                               binding.source_guest, source_length) ||
            ResolveVisibleMount(table, namespace_slot,
                                candidate.target_guest) != &candidate) {
            continue;
        }
        included[slot] = true;
        ++child_count;
    }
    if (child_count + 1U > CountFreeMountBindingSlots(table)) {
        return ENOSPC;
    }

    bool created_slots[kPathStateMountBindingCapacity]{};
    uint64_t cloned_ids[kPathStateMountBindingCapacity]{};
    MountBindingState* top = nullptr;
    uint64_t top_id = 0;
    error = AddMountBindingInternal(table, namespace_slot, binding,
                                    &top_id, &top);
    if (error != 0) {
        return error;
    }
    created_slots[top->slot] = true;

    uint32_t remaining = child_count;
    while (remaining != 0) {
        bool progressed = false;
        for (uint32_t slot = 0;
             slot < kPathStateMountBindingCapacity; ++slot) {
            if (!included[slot] || cloned_ids[slot] != 0) {
                continue;
            }
            const MountBindingState& source = table->mount_bindings[slot];
            uint32_t parent_slot = kInvalidPathStateSlot;
            size_t parent_length = 0;
            for (uint32_t candidate_slot = 0;
                 candidate_slot < kPathStateMountBindingCapacity;
                 ++candidate_slot) {
                if (!included[candidate_slot] || candidate_slot == slot) {
                    continue;
                }
                const MountBindingState& candidate =
                        table->mount_bindings[candidate_slot];
                size_t candidate_length = 0;
                if (PathLength(candidate.target_guest,
                               &candidate_length) != 0 ||
                    candidate_length >= HOOKSELF_PATH_CAPACITY ||
                    !PathPrefixMatches(source.target_guest,
                                       candidate.target_guest,
                                       candidate_length) ||
                    PathEquals(source.target_guest,
                               candidate.target_guest)) {
                    continue;
                }
                if (parent_slot == kInvalidPathStateSlot ||
                    candidate_length > parent_length) {
                    parent_slot = candidate_slot;
                    parent_length = candidate_length;
                }
            }
            if (parent_slot != kInvalidPathStateSlot &&
                cloned_ids[parent_slot] == 0) {
                continue;
            }

            char target[HOOKSELF_PATH_CAPACITY]{};
            error = SubstitutePathPrefix(
                    source.target_guest, binding.source_guest,
                    binding.target_guest, target);
            if (error != 0) {
                break;
            }
            MountBindingSpec child{};
            child.kind = source.kind;
            child.state_flags = source.state_flags &
                                ~kMountBindingStateDetached;
            child.parent_mount_id = parent_slot == kInvalidPathStateSlot
                    ? top_id
                    : cloned_ids[parent_slot];
            child.mount_flags = source.mount_flags;
            child.mount_attributes = source.mount_attributes;
            child.propagation = source.propagation;
            child.target_guest = target;
            child.source_guest = source.source_guest;
            child.source_host = source.source_host;
            MountBindingState* created = nullptr;
            error = AddMountBindingInternal(
                    table, namespace_slot, child, &cloned_ids[slot],
                    &created);
            if (error != 0) {
                break;
            }
            created_slots[created->slot] = true;
            --remaining;
            progressed = true;
        }
        if (error != 0 || !progressed) {
            if (error == 0) {
                error = EPROTO;
            }
            break;
        }
    }
    if (error != 0) {
        for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity;
             ++slot) {
            if (created_slots[slot]) {
                EraseMountBindingSlot(table, slot);
            }
        }
        return error;
    }
    if (mount_id != nullptr) {
        *mount_id = top_id;
    }
    return 0;
}

int RemoveMountBinding(PathStateTable* table, int32_t tid,
                       const char* target_guest, uint32_t flags,
                       uint64_t* removed_mount_id) noexcept {
    if (removed_mount_id != nullptr) {
        *removed_mount_id = 0;
    }
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        (flags & ~kMountRemoveKnownFlags) != 0) {
        return EINVAL;
    }
    const int path_error = ValidateCanonicalPath(target_guest);
    if (path_error != 0) {
        return path_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    const MountBindingState* selected = ResolveVisibleExactMount(
            table, namespace_slot, target_guest);
    if (selected == nullptr) {
        return EINVAL;
    }
    const uint64_t selected_id = selected->mount_id;
    bool has_children = false;
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.occupied != 0 &&
            candidate.mount_namespace_slot == namespace_slot &&
            (candidate.state_flags & kMountBindingStateDetached) == 0 &&
            candidate.parent_mount_id == selected_id) {
            has_children = true;
            break;
        }
    }
    if (has_children && (flags & kMountRemoveSubtree) == 0) {
        return EBUSY;
    }

    bool remove_slots[kPathStateMountBindingCapacity]{};
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        remove_slots[slot] =
                candidate.occupied != 0 &&
                candidate.mount_namespace_slot == namespace_slot &&
                (candidate.state_flags & kMountBindingStateDetached) == 0 &&
                (candidate.mount_id == selected_id ||
                 ((flags & kMountRemoveSubtree) != 0 &&
                  BindingDescendsFrom(table, candidate, selected_id)));
    }
    bool retain_detached = (flags & kMountRemoveDetached) != 0;
    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        MountTreeState* tree = &table->mount_trees[slot];
        if (tree->occupied == 0) {
            continue;
        }
        if (tree->mount_namespace_slot == namespace_slot &&
            MountIdIsSelected(table, namespace_slot, tree->source_mount_id,
                              remove_slots)) {
            retain_detached = true;
        }
        if (tree->attached_namespace_slot == namespace_slot &&
            MountIdIsSelected(table, namespace_slot,
                              tree->attached_mount_id, remove_slots)) {
            DetachMountTree(tree);
        }
    }
    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        const PathTaskState& candidate = table->tasks[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot) {
            continue;
        }
        const FsContext& fs = table->fs_contexts[candidate.fs_context_slot];
        if (MountIdIsSelected(table, namespace_slot, fs.cwd_mount_id,
                              remove_slots) ||
            MountIdIsSelected(table, namespace_slot, fs.root_mount_id,
                              remove_slots)) {
            retain_detached = true;
        }
    }
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        if (!remove_slots[slot]) {
            continue;
        }
        if (retain_detached) {
            table->mount_bindings[slot].state_flags |=
                    kMountBindingStateDetached;
        } else {
            EraseMountBindingSlot(table, slot);
        }
    }
    MountNamespaceState* mount_namespace =
            &table->mount_namespaces[namespace_slot];
    mount_namespace->generation = NextGeneration(
            mount_namespace->generation);
    NoteMutation(table);
    if (removed_mount_id != nullptr) {
        *removed_mount_id = selected_id;
    }
    return 0;
}

int MoveMountBinding(PathStateTable* table, int32_t tid,
                     const char* from_guest,
                     const char* to_guest) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    int error = ValidateCanonicalPath(from_guest);
    if (error == 0) {
        error = ValidateCanonicalPath(to_guest);
    }
    if (error != 0 || PathEquals(from_guest, to_guest)) {
        return error != 0 ? error : 0;
    }
    size_t from_length = 0;
    (void)PathLength(from_guest, &from_length);
    if (PathPrefixMatches(to_guest, from_guest, from_length)) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    MountBindingState* selected = const_cast<MountBindingState*>(
            ResolveVisibleExactMount(table, namespace_slot, from_guest));
    if (selected == nullptr) {
        return EINVAL;
    }
    const uint64_t selected_id = selected->mount_id;
    const uint64_t new_parent = VisibleParentMountId(
            table, namespace_slot, to_guest);
    if (new_parent == selected_id ||
        (new_parent != table->mount_namespaces[
                               namespace_slot].root_mount_id &&
         BindingDescendsFrom(table,
                             *FindMountBindingById(table, namespace_slot,
                                                   new_parent),
                             selected_id))) {
        return EINVAL;
    }

    char rewritten[HOOKSELF_PATH_CAPACITY]{};
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            (candidate.mount_id != selected_id &&
             !BindingDescendsFrom(table, candidate, selected_id))) {
            continue;
        }
        error = SubstitutePathPrefix(candidate.target_guest, from_guest,
                                     to_guest, rewritten);
        if (error != 0) {
            return error;
        }
    }
    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        const MountTreeState& tree = table->mount_trees[slot];
        if (tree.occupied == 0) {
            continue;
        }
        if (tree.mount_namespace_slot == namespace_slot &&
            MountIdDescendsFrom(table, namespace_slot, tree.source_mount_id,
                                selected_id) &&
            SubstitutePathPrefix(tree.source_guest, from_guest, to_guest,
                                 rewritten) != 0) {
            return EPROTO;
        }
        if (tree.attached_namespace_slot == namespace_slot &&
            MountIdDescendsFrom(table, namespace_slot,
                                tree.attached_mount_id, selected_id) &&
            SubstitutePathPrefix(tree.attached_target_guest, from_guest,
                                 to_guest, rewritten) != 0) {
            return EPROTO;
        }
    }
    bool checked_fs[kPathStateFsContextCapacity]{};
    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        const PathTaskState& candidate = table->tasks[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            checked_fs[candidate.fs_context_slot]) {
            continue;
        }
        checked_fs[candidate.fs_context_slot] = true;
        const FsContext& fs = table->fs_contexts[candidate.fs_context_slot];
        if (MountIdDescendsFrom(table, namespace_slot, fs.cwd_mount_id,
                                selected_id)) {
            if (PathPrefixMatches(fs.guest_cwd, from_guest, from_length) &&
                SubstitutePathPrefix(fs.guest_cwd, from_guest, to_guest,
                                     rewritten) != 0) {
                return EPROTO;
            }
        }
        if (MountIdDescendsFrom(table, namespace_slot, fs.root_mount_id,
                                selected_id)) {
            if (PathPrefixMatches(fs.guest_root, from_guest, from_length) &&
                SubstitutePathPrefix(fs.guest_root, from_guest, to_guest,
                                     rewritten) != 0) {
                return EPROTO;
            }
        }
    }

    const uint64_t sequence = NoteMutation(table);
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        MountBindingState* candidate = &table->mount_bindings[slot];
        if (candidate->occupied == 0 ||
            candidate->mount_namespace_slot != namespace_slot ||
            (candidate->mount_id != selected_id &&
             !BindingDescendsFrom(table, *candidate, selected_id))) {
            continue;
        }
        (void)SubstitutePathPrefix(candidate->target_guest, from_guest,
                                   to_guest, rewritten);
        CopyPath(candidate->target_guest, rewritten);
    }
    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        MountTreeState* tree = &table->mount_trees[slot];
        if (tree->occupied == 0) {
            continue;
        }
        if (tree->mount_namespace_slot == namespace_slot &&
            MountIdDescendsFrom(table, namespace_slot, tree->source_mount_id,
                                selected_id)) {
            (void)SubstitutePathPrefix(tree->source_guest, from_guest,
                                       to_guest, rewritten);
            CopyPath(tree->source_guest, rewritten);
        }
        if (tree->attached_namespace_slot == namespace_slot &&
            MountIdDescendsFrom(table, namespace_slot,
                                tree->attached_mount_id, selected_id)) {
            (void)SubstitutePathPrefix(tree->attached_target_guest,
                                       from_guest, to_guest, rewritten);
            CopyPath(tree->attached_target_guest, rewritten);
        }
    }
    bool updated_fs[kPathStateFsContextCapacity]{};
    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        const PathTaskState& candidate = table->tasks[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            updated_fs[candidate.fs_context_slot]) {
            continue;
        }
        updated_fs[candidate.fs_context_slot] = true;
        FsContext* fs = &table->fs_contexts[candidate.fs_context_slot];
        bool changed = false;
        if (MountIdDescendsFrom(table, namespace_slot, fs->cwd_mount_id,
                                selected_id) &&
            PathPrefixMatches(fs->guest_cwd, from_guest, from_length)) {
            (void)SubstitutePathPrefix(fs->guest_cwd, from_guest, to_guest,
                                       rewritten);
            CopyPath(fs->guest_cwd, rewritten);
            changed = true;
        }
        if (MountIdDescendsFrom(table, namespace_slot, fs->root_mount_id,
                                selected_id) &&
            PathPrefixMatches(fs->guest_root, from_guest, from_length)) {
            (void)SubstitutePathPrefix(fs->guest_root, from_guest, to_guest,
                                       rewritten);
            CopyPath(fs->guest_root, rewritten);
            changed = true;
        }
        if (changed) {
            fs->generation = NextGeneration(fs->generation);
        }
    }
    selected->parent_mount_id = new_parent;
    selected->sequence = sequence;
    table->mount_namespaces[namespace_slot].generation = NextGeneration(
            table->mount_namespaces[namespace_slot].generation);
    return 0;
}

int SetMountBindingAttributes(PathStateTable* table, int32_t tid,
                              const char* target_guest,
                              uint64_t attributes_set,
                              uint64_t attributes_clear,
                              uint64_t propagation,
                              bool recursive) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        (attributes_set & attributes_clear) != 0) {
        return EINVAL;
    }
    const int path_error = ValidateCanonicalPath(target_guest);
    if (path_error != 0) {
        return path_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    MountNamespaceState* mount_namespace =
            &table->mount_namespaces[namespace_slot];
    MountBindingState* selected = const_cast<MountBindingState*>(
            ResolveVisibleMount(table, namespace_slot, target_guest));
    const uint64_t selected_id = selected == nullptr
                                         ? mount_namespace->root_mount_id
                                         : selected->mount_id;
    if (selected == nullptr) {
        mount_namespace->root_mount_attributes =
                (mount_namespace->root_mount_attributes & ~attributes_clear) |
                attributes_set;
        if (propagation != 0) {
            mount_namespace->root_propagation = propagation;
        }
    } else {
        selected->mount_attributes =
                (selected->mount_attributes & ~attributes_clear) |
                attributes_set;
        if (propagation != 0) {
            selected->propagation = propagation;
        }
    }
    if (recursive) {
        for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
            MountBindingState* candidate = &table->mount_bindings[slot];
            if (candidate->occupied == 0 ||
                candidate->mount_namespace_slot != namespace_slot ||
                candidate == selected ||
                (selected != nullptr &&
                 !BindingDescendsFrom(table, *candidate, selected_id))) {
                continue;
            }
            candidate->mount_attributes =
                    (candidate->mount_attributes & ~attributes_clear) |
                    attributes_set;
            if (propagation != 0) {
                candidate->propagation = propagation;
            }
        }
    }
    mount_namespace->generation = NextGeneration(
            mount_namespace->generation);
    NoteMutation(table);
    return 0;
}

int TranslateMountPath(const PathStateTable* table, int32_t tid,
                       const char* guest_path,
                       MountPathTranslation* translation) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        translation == nullptr) {
        return EINVAL;
    }
    InitializeTranslation(translation);
    const int path_error = ValidateCanonicalPath(guest_path);
    if (path_error != 0) {
        return path_error;
    }
    const PathTaskState* task = FindPathTask(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[task->mount_namespace_slot];
    const MountBindingState* binding = ResolveVisibleMount(
            table, task->mount_namespace_slot, guest_path);
    if (binding != nullptr) {
        int error = SubstitutePathPrefix(
                guest_path, binding->target_guest, binding->source_guest,
                translation->guest_path);
        if (error == 0) {
            error = SubstitutePathPrefix(
                    guest_path, binding->target_guest, binding->source_host,
                    translation->host_path);
        }
        if (error != 0) {
            return error;
        }
        FillTranslationMetadata(mount_namespace, binding, translation);
        return 0;
    }
    CopyPath(translation->guest_path, guest_path);
    if (!NamespaceRootChanged(mount_namespace)) {
        return 0;
    }
    int error = SubstitutePathPrefix(
            guest_path, "/", mount_namespace.root_source_guest,
            translation->guest_path);
    if (error == 0) {
        error = SubstitutePathPrefix(
                guest_path, "/", mount_namespace.root_source_host,
                translation->host_path);
    }
    if (error == 0) {
        FillTranslationMetadata(mount_namespace, nullptr, translation);
    }
    return error;
}

int ReverseMountPath(const PathStateTable* table, int32_t tid,
                     const char* host_path,
                     MountPathTranslation* translation) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        translation == nullptr) {
        return EINVAL;
    }
    InitializeTranslation(translation);
    const int path_error = ValidateCanonicalPath(host_path);
    if (path_error != 0) {
        return path_error;
    }
    const PathTaskState* task = FindPathTask(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[namespace_slot];
    const MountBindingState* selected = nullptr;
    size_t selected_length = 0;
    char candidate_guest[HOOKSELF_PATH_CAPACITY]{};
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            (candidate.state_flags &
             kMountBindingStateReverseVisible) == 0 ||
            !ReverseBindingRoundTrips(table, namespace_slot, candidate,
                                      host_path, candidate_guest)) {
            continue;
        }
        size_t source_length = 0;
        if (PathLength(candidate.source_host, &source_length) != 0 ||
            !PathPrefixMatches(host_path, candidate.source_host,
                               source_length)) {
            continue;
        }
        if (selected == nullptr || source_length > selected_length ||
            (source_length == selected_length &&
             candidate.sequence > selected->sequence)) {
            selected = &candidate;
            selected_length = source_length;
        }
    }
    bool select_root = false;
    char root_guest[HOOKSELF_PATH_CAPACITY]{};
    if (NamespaceRootChanged(mount_namespace)) {
        size_t root_length = 0;
        (void)PathLength(mount_namespace.root_source_host, &root_length);
        select_root =
                (selected == nullptr || root_length > selected_length) &&
                PathPrefixMatches(host_path,
                                  mount_namespace.root_source_host,
                                  root_length) &&
                ReverseRootRoundTrips(table, namespace_slot, host_path,
                                      root_guest);
    }
    if (select_root) {
        CopyPath(translation->guest_path, root_guest);
        CopyPath(translation->host_path, host_path);
        FillTranslationMetadata(mount_namespace, nullptr, translation);
        return 0;
    }
    if (selected != nullptr) {
        const int error = SubstitutePathPrefix(
                host_path, selected->source_host, selected->target_guest,
                translation->guest_path);
        if (error != 0) {
            return error;
        }
        CopyPath(translation->host_path, host_path);
        FillTranslationMetadata(mount_namespace, selected, translation);
        return 0;
    }
    return 0;
}

int PivotRootMountNamespace(PathStateTable* table, int32_t tid,
                            const char* new_root_guest,
                            const char* new_root_host,
                            const char* put_old_guest,
                            const char* put_old_host) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return EINVAL;
    }
    int error = ValidateCanonicalPath(new_root_guest);
    if (error == 0) {
        error = ValidateCanonicalPath(new_root_host);
    }
    if (error == 0) {
        error = ValidateCanonicalPath(put_old_guest);
    }
    if (error == 0) {
        error = ValidateCanonicalPath(put_old_host);
    }
    if (error != 0) {
        return error;
    }
    size_t new_root_length = 0;
    (void)PathLength(new_root_guest, &new_root_length);
    if (PathEquals(put_old_guest, new_root_guest) ||
        !PathPrefixMatches(put_old_guest, new_root_guest,
                           new_root_length)) {
        return EINVAL;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t namespace_slot = task->mount_namespace_slot;
    MountNamespaceState* mount_namespace =
            &table->mount_namespaces[namespace_slot];
    MountBindingState* new_root = const_cast<MountBindingState*>(
            ResolveVisibleExactMount(table, namespace_slot, new_root_guest));
    if (new_root == nullptr ||
        new_root->mount_id == mount_namespace->root_mount_id) {
        return EINVAL;
    }
    MountPathTranslation new_root_translation{};
    MountPathTranslation put_old_translation{};
    error = TranslateMountPath(table, tid, new_root_guest,
                               &new_root_translation);
    if (error == 0) {
        error = TranslateMountPath(table, tid, put_old_guest,
                                   &put_old_translation);
    }
    if (error != 0 || new_root_translation.matched == 0 ||
        put_old_translation.matched == 0 ||
        !PathEquals(new_root_translation.host_path, new_root_host) ||
        !PathEquals(put_old_translation.host_path, put_old_host)) {
        return error != 0 ? error : EINVAL;
    }
    constexpr uint64_t kMountPropagationShared = 1ULL << 20U;
    if ((new_root->propagation & kMountPropagationShared) != 0 ||
        (mount_namespace->root_propagation &
         kMountPropagationShared) != 0) {
        return EINVAL;
    }

    char put_old_visible[HOOKSELF_PATH_CAPACITY]{};
    error = SubstitutePathPrefix(put_old_guest, new_root_guest, "/",
                                 put_old_visible);
    if (error != 0) {
        return error;
    }
    bool new_root_descendants[kPathStateMountBindingCapacity]{};
    char rewritten[HOOKSELF_PATH_CAPACITY]{};
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& binding = table->mount_bindings[slot];
        if (binding.occupied == 0 ||
            binding.mount_namespace_slot != namespace_slot ||
            binding.mount_id == new_root->mount_id) {
            continue;
        }
        new_root_descendants[slot] = BindingDescendsFrom(
                table, binding, new_root->mount_id);
        error = new_root_descendants[slot]
                        ? SubstitutePathPrefix(
                                  binding.target_guest, new_root_guest, "/",
                                  rewritten)
                        : SubstitutePathPrefix(
                                  binding.target_guest, "/", put_old_visible,
                                  rewritten);
        if (error != 0) {
            return error;
        }
    }

    const uint64_t old_root_mount_id = mount_namespace->root_mount_id;
    const uint64_t new_root_mount_id = new_root->mount_id;
    char old_root_guest[HOOKSELF_PATH_CAPACITY]{};
    char old_root_host[HOOKSELF_PATH_CAPACITY]{};
    CopyPath(old_root_guest, mount_namespace->root_source_guest);
    CopyPath(old_root_host, mount_namespace->root_source_host);
    char new_root_source_guest[HOOKSELF_PATH_CAPACITY]{};
    char new_root_source_host[HOOKSELF_PATH_CAPACITY]{};
    CopyPath(new_root_source_guest, new_root->source_guest);
    CopyPath(new_root_source_host, new_root->source_host);
    const uint64_t new_root_flags = new_root->mount_flags;
    const uint64_t new_root_attributes = new_root->mount_attributes;
    const uint64_t new_root_propagation = new_root->propagation;
    const uint64_t sequence = NoteMutation(table);

    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        MountBindingState* binding = &table->mount_bindings[slot];
        if (binding->occupied == 0 ||
            binding->mount_namespace_slot != namespace_slot ||
            binding == new_root) {
            continue;
        }
        (void)(new_root_descendants[slot]
                       ? SubstitutePathPrefix(
                                 binding->target_guest, new_root_guest, "/",
                                 rewritten)
                       : SubstitutePathPrefix(
                                 binding->target_guest, "/", put_old_visible,
                                 rewritten));
        CopyPath(binding->target_guest, rewritten);
    }

    new_root->kind = kMountBindingRoot;
    new_root->state_flags = kMountBindingStateRuntime |
                            kMountBindingStateReverseVisible;
    new_root->mount_id = old_root_mount_id;
    new_root->parent_mount_id = new_root_mount_id;
    new_root->sequence = sequence;
    new_root->mount_flags = mount_namespace->root_mount_flags;
    new_root->mount_attributes =
            mount_namespace->root_mount_attributes;
    new_root->propagation = mount_namespace->root_propagation;
    CopyPath(new_root->target_guest, put_old_visible);
    CopyPath(new_root->source_guest, old_root_guest);
    CopyPath(new_root->source_host, old_root_host);

    mount_namespace->root_mount_id = new_root_mount_id;
    mount_namespace->root_mount_flags = new_root_flags;
    mount_namespace->root_mount_attributes = new_root_attributes;
    mount_namespace->root_propagation = new_root_propagation;
    CopyPath(mount_namespace->root_source_guest,
             new_root_source_guest);
    CopyPath(mount_namespace->root_source_host, new_root_source_host);
    mount_namespace->generation = NextGeneration(
            mount_namespace->generation);

    for (uint32_t tree_slot = 0; tree_slot < kPathStateMountTreeCapacity;
         ++tree_slot) {
        MountTreeState* tree = &table->mount_trees[tree_slot];
        if (tree->occupied == 0 ||
            tree->attached_namespace_slot != namespace_slot ||
            tree->attached_mount_id == 0) {
            continue;
        }
        const MountBindingState* attached = FindMountBindingById(
                table, namespace_slot, tree->attached_mount_id);
        if (attached != nullptr) {
            CopyPath(tree->attached_target_guest,
                     attached->target_guest);
        } else if (tree->attached_mount_id ==
                   mount_namespace->root_mount_id) {
            CopyPath(tree->attached_target_guest, "/");
        }
    }

    bool updated_fs[kPathStateFsContextCapacity]{};
    for (uint32_t task_slot = 0; task_slot < kPathStateTaskCapacity;
         ++task_slot) {
        const PathTaskState& candidate = table->tasks[task_slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != namespace_slot ||
            updated_fs[candidate.fs_context_slot]) {
            continue;
        }
        updated_fs[candidate.fs_context_slot] = true;
        FsContext* fs = &table->fs_contexts[candidate.fs_context_slot];
        bool changed = false;
        if (fs->root_mount_id == old_root_mount_id &&
            PathEquals(fs->guest_root, "/")) {
            fs->root_mount_id = new_root_mount_id;
            CopyPath(fs->host_root, new_root_source_host);
            changed = true;
        }
        if (fs->cwd_mount_id == old_root_mount_id &&
            PathEquals(fs->guest_cwd, "/")) {
            fs->cwd_mount_id = new_root_mount_id;
            CopyPath(fs->host_cwd, new_root_source_host);
            changed = true;
        }
        if (changed) {
            fs->generation = NextGeneration(fs->generation);
        }
    }
    return 0;
}

int RecordMountTreeFdIdentity(PathStateTable* table, int32_t tid, int32_t fd,
                              const char* source_guest,
                              const char* source_host, bool cloexec,
                              bool clone_tree,
                              uint64_t* handle_id) noexcept {
    if (handle_id != nullptr) {
        *handle_id = 0;
    }
    if (!IsPathStateInitialized(table) || tid <= 0 || fd < 0) {
        return EINVAL;
    }
    int error = ValidateCanonicalPath(source_guest);
    if (error == 0) {
        error = ValidateCanonicalPath(source_host);
    }
    if (error != 0) {
        return error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    const uint32_t tree_slot = FindFreeMountTreeSlot(table);
    if (tree_slot == kInvalidPathStateSlot) {
        return ENOSPC;
    }
    uint32_t tree_namespace_slot = task->mount_namespace_slot;
    if (clone_tree) {
        tree_namespace_slot = FindFreeMountNamespaceSlot(table);
        const MountNamespaceState& source_namespace =
                table->mount_namespaces[task->mount_namespace_slot];
        if (tree_namespace_slot == kInvalidPathStateSlot ||
            source_namespace.binding_count >
                    CountFreeMountBindingSlots(table)) {
            return ENOSPC;
        }
        error = CopyMountNamespaceToSlot(
                table, task->mount_namespace_slot,
                tree_namespace_slot, false);
        if (error != 0) {
            return error;
        }
    } else {
        MountNamespaceState* live_namespace =
                &table->mount_namespaces[tree_namespace_slot];
        if (live_namespace->refcount == UINT32_MAX ||
            live_namespace->handle_refcount == UINT32_MAX) {
            return EOVERFLOW;
        }
        ++live_namespace->refcount;
        ++live_namespace->handle_refcount;
    }

    const MountBindingState* source_mount = ResolveVisibleMount(
            table, tree_namespace_slot, source_guest);
    MountTreeState* tree = &table->mount_trees[tree_slot];
    ClearMountTree(tree, tree_slot);
    tree->occupied = 1;
    tree->refcount = 1;
    tree->state_flags = clone_tree
                                ? kMountTreeStateClone |
                                          kMountTreeStateDetached
                                : kMountTreeStateAttached;
    tree->mount_namespace_slot = tree_namespace_slot;
    tree->generation = NoteMutation(table);
    tree->handle_id = tree->generation;
    tree->source_mount_id = source_mount == nullptr
                                    ? table->mount_namespaces[
                                              tree_namespace_slot].root_mount_id
                                    : source_mount->mount_id;
    if (!clone_tree) {
        tree->attached_namespace_slot = tree_namespace_slot;
        tree->attached_mount_id = tree->source_mount_id;
        CopyPath(tree->attached_target_guest,
                 source_mount == nullptr ? "/" : source_mount->target_guest);
    }
    CopyPath(tree->source_guest, source_guest);
    CopyPath(tree->source_host, source_host);
    ++table->mount_tree_count;
    AdvanceHint(tree_slot, kPathStateMountTreeCapacity,
                &table->mount_tree_free_hint);

    FdIdentitySpec identity{};
    identity.origin_flags = kPathOriginGuestValid | kPathOriginHostValid;
    identity.directory = 1;
    identity.cloexec = cloexec ? 1U : 0U;
    identity.guest_path = source_guest;
    identity.host_path = source_host;
    error = RecordFdIdentity(table, tid, fd, identity);
    if (error != 0) {
        ReleaseMountTreeReference(table, tree_slot);
        return error;
    }
    FdIdentity* fd_identity = FindIdentityUnchecked(
            table, task->fd_table_slot, fd);
    if (fd_identity == nullptr) {
        ReleaseMountTreeReference(table, tree_slot);
        return EPROTO;
    }
    fd_identity->object_kind = kFdIdentityObjectMountTree;
    fd_identity->object_slot = tree_slot;
    fd_identity->object_generation = tree->generation;
    if (handle_id != nullptr) {
        *handle_id = tree->handle_id;
    }
    return 0;
}

const MountTreeState* LookupMountTreeByFd(const PathStateTable* table,
                                          int32_t tid, int32_t fd) noexcept {
    const FdIdentity* identity = LookupFdIdentity(table, tid, fd);
    if (identity == nullptr ||
        identity->object_kind != kFdIdentityObjectMountTree ||
        identity->object_slot >= kPathStateMountTreeCapacity) {
        return nullptr;
    }
    const MountTreeState* tree = &table->mount_trees[identity->object_slot];
    return tree->occupied != 0 &&
                   tree->generation == identity->object_generation
                   ? tree
                   : nullptr;
}

int AttachMountTree(PathStateTable* table, int32_t tid, int32_t tree_fd,
                    const char* target_guest,
                    uint64_t* mount_id) noexcept {
    if (mount_id != nullptr) {
        *mount_id = 0;
    }
    if (!IsPathStateInitialized(table) || tid <= 0 || tree_fd < 0) {
        return EINVAL;
    }
    const int path_error = ValidateCanonicalPath(target_guest);
    if (path_error != 0) {
        return path_error;
    }
    PathTaskState* task = FindTaskUnchecked(table, tid);
    if (task == nullptr) {
        return ESRCH;
    }
    FdIdentity* identity = FindIdentityUnchecked(
            table, task->fd_table_slot, tree_fd);
    if (identity == nullptr ||
        identity->object_kind != kFdIdentityObjectMountTree ||
        identity->object_slot >= kPathStateMountTreeCapacity) {
        return EBADF;
    }
    MountTreeState* tree = &table->mount_trees[identity->object_slot];
    if (tree->occupied == 0 ||
        tree->generation != identity->object_generation) {
        return ESTALE;
    }
    if (tree->attached_mount_id != 0) {
        if (tree->attached_namespace_slot != task->mount_namespace_slot) {
            return EXDEV;
        }
        MountBindingState* attached = FindMountBindingById(
                table, tree->attached_namespace_slot,
                tree->attached_mount_id);
        if (attached == nullptr ||
            !PathEquals(attached->target_guest,
                        tree->attached_target_guest)) {
            return ESTALE;
        }
        const int move_error = MoveMountBinding(
                table, tid, tree->attached_target_guest, target_guest);
        if (move_error != 0) {
            return move_error;
        }
        CopyPath(tree->attached_target_guest, target_guest);
        if (mount_id != nullptr) {
            *mount_id = tree->attached_mount_id;
        }
        return 0;
    }

    const MountNamespaceState& source_namespace =
            table->mount_namespaces[tree->mount_namespace_slot];
    const MountBindingState* source_binding = FindMountBindingById(
            table, tree->mount_namespace_slot, tree->source_mount_id);
    size_t source_length = 0;
    (void)PathLength(tree->source_guest, &source_length);
    bool include_source_slots[kPathStateMountBindingCapacity]{};
    uint32_t descendant_count = 0;
    char rewritten_target[HOOKSELF_PATH_CAPACITY]{};
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.occupied == 0 ||
            candidate.mount_namespace_slot != tree->mount_namespace_slot ||
            (candidate.state_flags & kMountBindingStateDetached) != 0 ||
            candidate.mount_id == tree->source_mount_id ||
            !BindingDescendsFrom(table, candidate, tree->source_mount_id)) {
            continue;
        }
        if (!PathPrefixMatches(candidate.target_guest, tree->source_guest,
                               source_length)) {
            continue;
        }
        const int rewrite_error = SubstitutePathPrefix(
                candidate.target_guest, tree->source_guest, target_guest,
                rewritten_target);
        if (rewrite_error != 0) {
            return rewrite_error;
        }
        include_source_slots[slot] = true;
        ++descendant_count;
    }
    if (descendant_count + 1U > CountFreeMountBindingSlots(table)) {
        return ENOSPC;
    }

    // Every included mount must either hang directly from the source root or
    // have its parent included. This keeps attachment transactional.
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        if (!include_source_slots[slot]) {
            continue;
        }
        const MountBindingState& candidate = table->mount_bindings[slot];
        if (candidate.parent_mount_id == tree->source_mount_id) {
            continue;
        }
        const MountBindingState* parent = FindMountBindingById(
                table, tree->mount_namespace_slot,
                candidate.parent_mount_id);
        if (parent == nullptr || !include_source_slots[parent->slot]) {
            return EPROTO;
        }
    }
    MountBindingSpec binding{};
    binding.kind = kMountBindingTree;
    binding.state_flags = kMountBindingStateRuntime |
                          kMountBindingStateReverseVisible;
    binding.mount_flags = source_binding == nullptr
                                  ? source_namespace.root_mount_flags
                                  : source_binding->mount_flags;
    binding.mount_attributes = source_binding == nullptr
                                       ? source_namespace.root_mount_attributes
                                       : source_binding->mount_attributes;
    binding.propagation = source_binding == nullptr
                                  ? source_namespace.root_propagation
                                  : source_binding->propagation;
    binding.target_guest = target_guest;
    binding.source_guest = tree->source_guest;
    binding.source_host = tree->source_host;
    uint64_t attached_id = 0;
    const int add_error = AddMountBindingInternal(
            table, task->mount_namespace_slot, binding,
            &attached_id, nullptr);
    if (add_error != 0) {
        return add_error;
    }

    uint64_t attached_ids[kPathStateMountBindingCapacity]{};
    bool created_slots[kPathStateMountBindingCapacity]{};
    uint32_t created_count = 0;
    while (created_count < descendant_count) {
        uint32_t selected_source_slot = kInvalidPathStateSlot;
        uint64_t selected_sequence = UINT64_MAX;
        uint64_t selected_parent_id = 0;
        for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity;
             ++slot) {
            if (!include_source_slots[slot] || attached_ids[slot] != 0) {
                continue;
            }
            const MountBindingState& candidate = table->mount_bindings[slot];
            uint64_t parent_id = 0;
            if (candidate.parent_mount_id == tree->source_mount_id) {
                parent_id = attached_id;
            } else {
                const MountBindingState* parent = FindMountBindingById(
                        table, tree->mount_namespace_slot,
                        candidate.parent_mount_id);
                if (parent == nullptr || attached_ids[parent->slot] == 0) {
                    continue;
                }
                parent_id = attached_ids[parent->slot];
            }
            if (selected_source_slot == kInvalidPathStateSlot ||
                candidate.sequence < selected_sequence) {
                selected_source_slot = slot;
                selected_sequence = candidate.sequence;
                selected_parent_id = parent_id;
            }
        }
        if (selected_source_slot == kInvalidPathStateSlot) {
            for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity;
                 ++slot) {
                if (created_slots[slot]) {
                    EraseMountBindingSlot(table, slot);
                }
            }
            MountBindingState* top = FindMountBindingById(
                    table, task->mount_namespace_slot, attached_id);
            if (top != nullptr) {
                EraseMountBindingSlot(table, top->slot);
            }
            return EPROTO;
        }

        const MountBindingState& source_child =
                table->mount_bindings[selected_source_slot];
        const int rewrite_error = SubstitutePathPrefix(
                source_child.target_guest, tree->source_guest, target_guest,
                rewritten_target);
        if (rewrite_error != 0) {
            return rewrite_error;
        }
        MountBindingSpec child{};
        child.kind = source_child.kind;
        child.state_flags = source_child.state_flags &
                            ~kMountBindingStateDetached;
        child.parent_mount_id = selected_parent_id;
        child.mount_flags = source_child.mount_flags;
        child.mount_attributes = source_child.mount_attributes;
        child.propagation = source_child.propagation;
        child.target_guest = rewritten_target;
        child.source_guest = source_child.source_guest;
        child.source_host = source_child.source_host;
        MountBindingState* created = nullptr;
        uint64_t child_id = 0;
        const int child_error = AddMountBindingInternal(
                table, task->mount_namespace_slot, child, &child_id,
                &created);
        if (child_error != 0 || created == nullptr) {
            for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity;
                 ++slot) {
                if (created_slots[slot]) {
                    EraseMountBindingSlot(table, slot);
                }
            }
            MountBindingState* top = FindMountBindingById(
                    table, task->mount_namespace_slot, attached_id);
            if (top != nullptr) {
                EraseMountBindingSlot(table, top->slot);
            }
            return child_error != 0 ? child_error : EPROTO;
        }
        attached_ids[selected_source_slot] = child_id;
        created_slots[created->slot] = true;
        ++created_count;
    }
    tree->state_flags &= ~kMountTreeStateDetached;
    tree->state_flags |= kMountTreeStateAttached;
    tree->attached_namespace_slot = task->mount_namespace_slot;
    tree->attached_mount_id = attached_id;
    CopyPath(tree->attached_target_guest, target_guest);
    if (mount_id != nullptr) {
        *mount_id = attached_id;
    }
    return 0;
}
