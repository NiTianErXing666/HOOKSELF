namespace {

enum class FdCopyMode : uint32_t {
    kAll = 0,
    kExec = 1,
    kCloseRange = 2,
    kCloexecRange = 3,
    kCloseRangePreserveProtected = 4,
    kCloexecRangePreserveProtected = 5,
};

void ReleaseMountTreeReference(PathStateTable* table,
                               uint32_t tree_slot) noexcept;
void DetachTreesFromNamespace(PathStateTable* table,
                              uint32_t namespace_slot) noexcept;

void ZeroBytes(void* memory, size_t size) noexcept {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
}

uint64_t NextGeneration(uint64_t generation) noexcept {
    ++generation;
    return generation == 0 ? 1 : generation;
}

uint64_t NoteMutation(PathStateTable* table) noexcept {
    table->mutation_generation = NextGeneration(table->mutation_generation);
    return table->mutation_generation;
}

int ValidateAbsolutePath(const char* path) noexcept {
    if (path == nullptr || path[0] != '/') {
        return EINVAL;
    }
    for (size_t i = 1; i < HOOKSELF_PATH_CAPACITY; ++i) {
        if (path[i] == '\0') {
            return 0;
        }
    }
    return ENAMETOOLONG;
}

int PathLength(const char* path, size_t* length) noexcept {
    if (path == nullptr || length == nullptr) {
        return EINVAL;
    }
    for (size_t i = 0; i < HOOKSELF_PATH_CAPACITY; ++i) {
        if (path[i] == '\0') {
            *length = i;
            return 0;
        }
    }
    return ENAMETOOLONG;
}

int ValidateCanonicalPath(const char* path) noexcept {
    size_t length = 0;
    const int length_error = PathLength(path, &length);
    if (length_error != 0) {
        return length_error;
    }
    if (length == 0 || path[0] != '/' ||
        (length > 1 && path[length - 1U] == '/')) {
        return EINVAL;
    }
    if (length == 1) {
        return 0;
    }
    size_t segment_start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && path[i] != '/') {
            continue;
        }
        const size_t segment_length = i - segment_start;
        if (segment_length == 0 ||
            (segment_length == 1 && path[segment_start] == '.') ||
            (segment_length == 2 && path[segment_start] == '.' &&
             path[segment_start + 1U] == '.')) {
            return EINVAL;
        }
        segment_start = i + 1U;
    }
    return 0;
}

bool PathEquals(const char* left, const char* right) noexcept {
    for (size_t i = 0; i < HOOKSELF_PATH_CAPACITY; ++i) {
        if (left[i] != right[i]) {
            return false;
        }
        if (left[i] == '\0') {
            return true;
        }
    }
    return false;
}

bool PathStorageIsPadded(const char* path) noexcept {
    bool terminated = false;
    for (size_t i = 0; i < HOOKSELF_PATH_CAPACITY; ++i) {
        if (terminated && path[i] != '\0') {
            return false;
        }
        terminated = terminated || path[i] == '\0';
    }
    return terminated;
}

bool PathStorageIsEmpty(const char* path) noexcept {
    for (size_t i = 0; i < HOOKSELF_PATH_CAPACITY; ++i) {
        if (path[i] != '\0') {
            return false;
        }
    }
    return true;
}

bool PathPrefixMatches(const char* path, const char* prefix,
                       size_t prefix_length) noexcept {
    for (size_t i = 0; i < prefix_length; ++i) {
        if (path[i] != prefix[i]) {
            return false;
        }
    }
    return (prefix_length == 1 && prefix[0] == '/') ||
           path[prefix_length] == '\0' || path[prefix_length] == '/';
}

int SubstitutePathPrefix(const char* input, const char* old_prefix,
                         const char* new_prefix,
                         char output[HOOKSELF_PATH_CAPACITY]) noexcept {
    size_t input_length = 0;
    size_t old_length = 0;
    size_t new_length = 0;
    int error = PathLength(input, &input_length);
    if (error == 0) {
        error = PathLength(old_prefix, &old_length);
    }
    if (error == 0) {
        error = PathLength(new_prefix, &new_length);
    }
    if (error != 0 || !PathPrefixMatches(input, old_prefix, old_length)) {
        return error != 0 ? error : EINVAL;
    }

    size_t suffix = old_length;
    if (old_length == 1) {
        suffix = input_length == 1 ? input_length : 1;
    }
    const bool new_is_root = new_length == 1 && new_prefix[0] == '/';
    if (new_is_root && suffix < input_length && input[suffix] == '/') {
        ++suffix;
    }
    const bool needs_separator = !new_is_root && suffix < input_length &&
                                 input[suffix] != '/';
    const size_t suffix_length = input_length - suffix;
    if (new_length + (needs_separator ? 1U : 0U) + suffix_length + 1U >
        HOOKSELF_PATH_CAPACITY) {
        return ENAMETOOLONG;
    }
    size_t written = 0;
    for (size_t i = 0; i < new_length; ++i) {
        output[written++] = new_prefix[i];
    }
    if (needs_separator) {
        output[written++] = '/';
    }
    for (size_t i = suffix; i < input_length; ++i) {
        output[written++] = input[i];
    }
    output[written] = '\0';
    for (++written; written < HOOKSELF_PATH_CAPACITY; ++written) {
        output[written] = '\0';
    }
    return 0;
}

void CopyPath(char destination[HOOKSELF_PATH_CAPACITY],
              const char* source) noexcept {
    size_t i = 0;
    if (source != nullptr) {
        while (i + 1U < HOOKSELF_PATH_CAPACITY && source[i] != '\0') {
            destination[i] = source[i];
            ++i;
        }
    }
    destination[i] = '\0';
    for (++i; i < HOOKSELF_PATH_CAPACITY; ++i) {
        destination[i] = '\0';
    }
}

int ValidateOrigin(uint32_t flags, const char* guest_path,
                   const char* host_path) noexcept {
    if ((flags & ~kPathOriginKnownFlags) != 0) {
        return EINVAL;
    }
    if ((flags & (kPathOriginRedirected | kPathOriginReverseVisible)) != 0 &&
        (flags & (kPathOriginGuestValid | kPathOriginHostValid)) !=
                (kPathOriginGuestValid | kPathOriginHostValid)) {
        return EINVAL;
    }
    if ((flags & kPathOriginGuestValid) != 0) {
        const int error = ValidateAbsolutePath(guest_path);
        if (error != 0) {
            return error;
        }
    } else if (guest_path != nullptr && guest_path[0] != '\0') {
        return EINVAL;
    }
    if ((flags & kPathOriginHostValid) != 0) {
        const int error = ValidateAbsolutePath(host_path);
        if (error != 0) {
            return error;
        }
    } else if (host_path != nullptr && host_path[0] != '\0') {
        return EINVAL;
    }
    return 0;
}

void ClearTask(PathTaskState* task, uint32_t slot) noexcept {
    ZeroBytes(task, sizeof(*task));
    task->slot = slot;
    task->fs_context_slot = kInvalidPathStateSlot;
    task->fd_table_slot = kInvalidPathStateSlot;
    task->mount_namespace_slot = kInvalidPathStateSlot;
}

void ClearFsContext(FsContext* context, uint32_t slot) noexcept {
    ZeroBytes(context, sizeof(*context));
    context->slot = slot;
}

void ClearFdTable(FdTable* fd_table, uint32_t slot) noexcept {
    ZeroBytes(fd_table, sizeof(*fd_table));
    fd_table->slot = slot;
}

void ClearFdIdentity(FdIdentity* identity, uint32_t slot) noexcept {
    ZeroBytes(identity, sizeof(*identity));
    identity->slot = slot;
    identity->fd_table_slot = kInvalidPathStateSlot;
    identity->fd = -1;
    identity->mount_namespace_slot = kInvalidPathStateSlot;
    identity->object_slot = kInvalidPathStateSlot;
}

void ClearMountNamespace(MountNamespaceState* mount_namespace,
                         uint32_t slot) noexcept {
    ZeroBytes(mount_namespace, sizeof(*mount_namespace));
    mount_namespace->slot = slot;
}

void ClearMountBinding(MountBindingState* binding, uint32_t slot) noexcept {
    ZeroBytes(binding, sizeof(*binding));
    binding->slot = slot;
    binding->mount_namespace_slot = kInvalidPathStateSlot;
}

void ClearMountTree(MountTreeState* tree, uint32_t slot) noexcept {
    ZeroBytes(tree, sizeof(*tree));
    tree->slot = slot;
    tree->mount_namespace_slot = kInvalidPathStateSlot;
    tree->attached_namespace_slot = kInvalidPathStateSlot;
}

uint32_t FindFreeTaskSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->task_free_hint;
    for (uint32_t offset = 0; offset < kPathStateTaskCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateTaskCapacity) {
            slot -= kPathStateTaskCapacity;
        }
        if (table->tasks[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeFsContextSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->fs_context_free_hint;
    for (uint32_t offset = 0; offset < kPathStateFsContextCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateFsContextCapacity) {
            slot -= kPathStateFsContextCapacity;
        }
        if (table->fs_contexts[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeFdTableSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->fd_table_free_hint;
    for (uint32_t offset = 0; offset < kPathStateFdTableCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateFdTableCapacity) {
            slot -= kPathStateFdTableCapacity;
        }
        if (table->fd_tables[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeFdIdentitySlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->fd_identity_free_hint;
    for (uint32_t offset = 0; offset < kPathStateFdIdentityCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateFdIdentityCapacity) {
            slot -= kPathStateFdIdentityCapacity;
        }
        if (table->fd_identities[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeMountNamespaceSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->mount_namespace_free_hint;
    for (uint32_t offset = 0;
         offset < kPathStateMountNamespaceCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateMountNamespaceCapacity) {
            slot -= kPathStateMountNamespaceCapacity;
        }
        if (table->mount_namespaces[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeMountBindingSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->mount_binding_free_hint;
    for (uint32_t offset = 0; offset < kPathStateMountBindingCapacity;
         ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateMountBindingCapacity) {
            slot -= kPathStateMountBindingCapacity;
        }
        if (table->mount_bindings[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t FindFreeMountTreeSlot(const PathStateTable* table) noexcept {
    const uint32_t start = table->mount_tree_free_hint;
    for (uint32_t offset = 0; offset < kPathStateMountTreeCapacity;
         ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kPathStateMountTreeCapacity) {
            slot -= kPathStateMountTreeCapacity;
        }
        if (table->mount_trees[slot].occupied == 0) {
            return slot;
        }
    }
    return kInvalidPathStateSlot;
}

uint32_t CountFreeFdIdentitySlots(const PathStateTable* table) noexcept {
    return kPathStateFdIdentityCapacity - table->fd_identity_count;
}

uint32_t CountFreeMountBindingSlots(const PathStateTable* table) noexcept {
    return kPathStateMountBindingCapacity - table->mount_binding_count;
}

PathTaskState* FindTaskUnchecked(PathStateTable* table, int32_t tid) noexcept {
    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        PathTaskState* task = &table->tasks[slot];
        if (task->occupied != 0 && task->tid == tid) {
            return task;
        }
    }
    return nullptr;
}

FdIdentity* FindIdentityUnchecked(PathStateTable* table,
                                  uint32_t fd_table_slot,
                                  int32_t fd) noexcept {
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        FdIdentity* identity = &table->fd_identities[slot];
        if (identity->occupied != 0 &&
            identity->fd_table_slot == fd_table_slot && identity->fd == fd) {
            return identity;
        }
    }
    return nullptr;
}

const FdIdentity* FindIdentityUnchecked(const PathStateTable* table,
                                        uint32_t fd_table_slot,
                                        int32_t fd) noexcept {
    return FindIdentityUnchecked(const_cast<PathStateTable*>(table),
                                 fd_table_slot, fd);
}

MountBindingState* FindMountBindingById(PathStateTable* table,
                                        uint32_t namespace_slot,
                                        uint64_t mount_id) noexcept {
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        MountBindingState* binding = &table->mount_bindings[slot];
        if (binding->occupied != 0 &&
            binding->mount_namespace_slot == namespace_slot &&
            binding->mount_id == mount_id) {
            return binding;
        }
    }
    return nullptr;
}

const MountBindingState* FindMountBindingById(
        const PathStateTable* table, uint32_t namespace_slot,
        uint64_t mount_id) noexcept {
    return FindMountBindingById(const_cast<PathStateTable*>(table),
                                namespace_slot, mount_id);
}

const MountBindingState* ResolveVisibleMount(
        const PathStateTable* table, uint32_t namespace_slot,
        const char* guest_path) noexcept {
    const MountNamespaceState& mount_namespace =
            table->mount_namespaces[namespace_slot];
    uint64_t parent_mount_id = mount_namespace.root_mount_id;
    const MountBindingState* selected = nullptr;
    for (uint32_t depth = 0; depth < kPathStateMountBindingCapacity; ++depth) {
        const MountBindingState* child = nullptr;
        size_t child_length = 0;
        for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
            const MountBindingState& candidate = table->mount_bindings[slot];
            if (candidate.occupied == 0 ||
                candidate.mount_namespace_slot != namespace_slot ||
                candidate.parent_mount_id != parent_mount_id ||
                (candidate.state_flags & kMountBindingStateDetached) != 0) {
                continue;
            }
            size_t target_length = 0;
            if (PathLength(candidate.target_guest, &target_length) != 0 ||
                !PathPrefixMatches(guest_path, candidate.target_guest,
                                   target_length)) {
                continue;
            }
            if (child == nullptr || target_length > child_length ||
                (target_length == child_length &&
                 candidate.sequence > child->sequence)) {
                child = &candidate;
                child_length = target_length;
            }
        }
        if (child == nullptr) {
            return selected;
        }
        selected = child;
        parent_mount_id = child->mount_id;
    }
    return nullptr;
}

const MountBindingState* ResolveVisibleExactMount(
        const PathStateTable* table, uint32_t namespace_slot,
        const char* guest_path) noexcept {
    const MountBindingState* binding = ResolveVisibleMount(
            table, namespace_slot, guest_path);
    return binding != nullptr && PathEquals(binding->target_guest, guest_path)
                   ? binding
                   : nullptr;
}

void AdvanceHint(uint32_t slot, uint32_t capacity, uint32_t* hint) noexcept {
    *hint = slot + 1U;
    if (*hint == capacity) {
        *hint = 0;
    }
}

void OccupyTask(PathStateTable* table, uint32_t slot, int32_t tid,
                uint32_t fs_context_slot, uint32_t fd_table_slot,
                uint32_t mount_namespace_slot,
                uint64_t identity_generation) noexcept {
    PathTaskState* task = &table->tasks[slot];
    ClearTask(task, slot);
    task->occupied = 1;
    task->tid = tid;
    task->fs_context_slot = fs_context_slot;
    task->fd_table_slot = fd_table_slot;
    task->mount_namespace_slot = mount_namespace_slot;
    task->identity_generation = identity_generation;
    ++table->task_count;
    AdvanceHint(slot, kPathStateTaskCapacity, &table->task_free_hint);
}

void EraseTaskSlot(PathStateTable* table, uint32_t slot) noexcept {
    ClearTask(&table->tasks[slot], slot);
    --table->task_count;
    table->task_free_hint = slot;
}

void OccupyInitialFsContext(PathStateTable* table, uint32_t slot,
                            const char* guest_cwd,
                            const char* host_cwd) noexcept {
    FsContext* context = &table->fs_contexts[slot];
    ClearFsContext(context, slot);
    context->occupied = 1;
    context->refcount = 1;
    context->cwd_origin_flags =
            kPathOriginGuestValid | kPathOriginHostValid;
    context->generation = 1;
    context->cwd_mount_id = 1;
    CopyPath(context->guest_cwd, guest_cwd);
    CopyPath(context->host_cwd, host_cwd);
    context->root_origin_flags =
            kPathOriginGuestValid | kPathOriginHostValid;
    context->root_mount_id = 1;
    CopyPath(context->guest_root, "/");
    CopyPath(context->host_root, "/");
    ++table->fs_context_count;
    AdvanceHint(slot, kPathStateFsContextCapacity,
                &table->fs_context_free_hint);
}

void CopyFsContextToSlot(PathStateTable* table, const FsContext& source,
                         uint32_t slot) noexcept {
    FsContext* destination = &table->fs_contexts[slot];
    *destination = source;
    destination->occupied = 1;
    destination->slot = slot;
    destination->refcount = 1;
    destination->generation = NextGeneration(source.generation);
    ++table->fs_context_count;
    AdvanceHint(slot, kPathStateFsContextCapacity,
                &table->fs_context_free_hint);
}

void EraseFsContextSlot(PathStateTable* table, uint32_t slot) noexcept {
    ClearFsContext(&table->fs_contexts[slot], slot);
    --table->fs_context_count;
    table->fs_context_free_hint = slot;
}

void OccupyEmptyFdTable(PathStateTable* table, uint32_t slot,
                        uint64_t generation) noexcept {
    FdTable* fd_table = &table->fd_tables[slot];
    ClearFdTable(fd_table, slot);
    fd_table->occupied = 1;
    fd_table->refcount = 1;
    fd_table->generation = generation == 0 ? 1 : generation;
    ++table->fd_table_count;
    AdvanceHint(slot, kPathStateFdTableCapacity, &table->fd_table_free_hint);
}

void EraseIdentitySlot(PathStateTable* table, uint32_t slot) noexcept {
    FdIdentity* identity = &table->fd_identities[slot];
    FdTable* owner = &table->fd_tables[identity->fd_table_slot];
    const uint32_t object_kind = identity->object_kind;
    const uint32_t object_slot = identity->object_slot;
    if ((identity->origin_flags & kPathOriginProtected) != 0) {
        --owner->protected_count;
    }
    --owner->entry_count;
    ClearFdIdentity(identity, slot);
    --table->fd_identity_count;
    table->fd_identity_free_hint = slot;
    if (object_kind == kFdIdentityObjectMountTree &&
        object_slot < kPathStateMountTreeCapacity) {
        ReleaseMountTreeReference(table, object_slot);
    }
}

void EraseFdTableSlot(PathStateTable* table, uint32_t slot) noexcept {
    for (uint32_t identity_slot = 0;
         identity_slot < kPathStateFdIdentityCapacity; ++identity_slot) {
        FdIdentity* identity = &table->fd_identities[identity_slot];
        if (identity->occupied != 0 && identity->fd_table_slot == slot) {
            EraseIdentitySlot(table, identity_slot);
        }
    }
    ClearFdTable(&table->fd_tables[slot], slot);
    --table->fd_table_count;
    table->fd_table_free_hint = slot;
}

void OccupyInitialMountNamespace(PathStateTable* table,
                                 uint32_t slot) noexcept {
    MountNamespaceState* mount_namespace = &table->mount_namespaces[slot];
    ClearMountNamespace(mount_namespace, slot);
    mount_namespace->occupied = 1;
    mount_namespace->refcount = 1;
    mount_namespace->task_refcount = 1;
    mount_namespace->generation = 1;
    mount_namespace->identity_generation =
            NextGeneration(table->mutation_generation);
    mount_namespace->root_mount_id = 1;
    mount_namespace->root_origin_flags =
            kPathOriginGuestValid | kPathOriginHostValid;
    CopyPath(mount_namespace->root_source_guest, "/");
    CopyPath(mount_namespace->root_source_host, "/");
    ++table->mount_namespace_count;
    AdvanceHint(slot, kPathStateMountNamespaceCapacity,
                &table->mount_namespace_free_hint);
}

void EraseMountBindingSlot(PathStateTable* table, uint32_t slot) noexcept {
    MountBindingState* binding = &table->mount_bindings[slot];
    MountNamespaceState* owner =
            &table->mount_namespaces[binding->mount_namespace_slot];
    --owner->binding_count;
    ClearMountBinding(binding, slot);
    --table->mount_binding_count;
    table->mount_binding_free_hint = slot;
}

void EraseMountNamespaceSlot(PathStateTable* table, uint32_t slot) noexcept {
    for (uint32_t binding_slot = 0;
         binding_slot < kPathStateMountBindingCapacity; ++binding_slot) {
        MountBindingState* binding = &table->mount_bindings[binding_slot];
        if (binding->occupied != 0 &&
            binding->mount_namespace_slot == slot) {
            EraseMountBindingSlot(table, binding_slot);
        }
    }
    ClearMountNamespace(&table->mount_namespaces[slot], slot);
    --table->mount_namespace_count;
    table->mount_namespace_free_hint = slot;
}

int CopyMountNamespaceToSlot(PathStateTable* table,
                             uint32_t source_namespace_slot,
                             uint32_t destination_namespace_slot,
                             bool task_reference) noexcept {
    const MountNamespaceState source =
            table->mount_namespaces[source_namespace_slot];
    if (source.binding_count > CountFreeMountBindingSlots(table)) {
        return ENOSPC;
    }
    MountNamespaceState* destination =
            &table->mount_namespaces[destination_namespace_slot];
    *destination = source;
    destination->occupied = 1;
    destination->slot = destination_namespace_slot;
    destination->refcount = 1;
    destination->task_refcount = task_reference ? 1U : 0U;
    destination->handle_refcount = task_reference ? 0U : 1U;
    destination->binding_count = 0;
    destination->generation = NextGeneration(source.generation);
    destination->identity_generation =
            NextGeneration(table->mutation_generation);
    ++table->mount_namespace_count;
    AdvanceHint(destination_namespace_slot,
                kPathStateMountNamespaceCapacity,
                &table->mount_namespace_free_hint);

    for (uint32_t source_slot = 0;
         source_slot < kPathStateMountBindingCapacity; ++source_slot) {
        const MountBindingState source_binding =
                table->mount_bindings[source_slot];
        if (source_binding.occupied == 0 ||
            source_binding.mount_namespace_slot != source_namespace_slot) {
            continue;
        }
        const uint32_t destination_slot = FindFreeMountBindingSlot(table);
        if (destination_slot == kInvalidPathStateSlot) {
            EraseMountNamespaceSlot(table, destination_namespace_slot);
            return EPROTO;
        }
        MountBindingState* destination_binding =
                &table->mount_bindings[destination_slot];
        *destination_binding = source_binding;
        destination_binding->occupied = 1;
        destination_binding->slot = destination_slot;
        destination_binding->mount_namespace_slot =
                destination_namespace_slot;
        ++destination->binding_count;
        ++table->mount_binding_count;
        AdvanceHint(destination_slot, kPathStateMountBindingCapacity,
                    &table->mount_binding_free_hint);
    }
    return 0;
}

void ReleaseMountNamespaceTaskReference(PathStateTable* table,
                                         uint32_t slot) noexcept {
    MountNamespaceState* mount_namespace = &table->mount_namespaces[slot];
    --mount_namespace->task_refcount;
    if (mount_namespace->task_refcount == 0) {
        DetachTreesFromNamespace(table, slot);
    }
    if (--mount_namespace->refcount == 0) {
        EraseMountNamespaceSlot(table, slot);
    }
}

void ReleaseMountNamespaceHandleReference(PathStateTable* table,
                                          uint32_t slot) noexcept {
    MountNamespaceState* mount_namespace = &table->mount_namespaces[slot];
    --mount_namespace->handle_refcount;
    if (--mount_namespace->refcount == 0) {
        EraseMountNamespaceSlot(table, slot);
    }
}

int RetainMountTreeReference(PathStateTable* table,
                             uint32_t tree_slot) noexcept {
    if (tree_slot >= kPathStateMountTreeCapacity ||
        table->mount_trees[tree_slot].occupied == 0) {
        return ESTALE;
    }
    MountTreeState* tree = &table->mount_trees[tree_slot];
    if (tree->refcount == UINT32_MAX) {
        return EOVERFLOW;
    }
    ++tree->refcount;
    return 0;
}

void ReleaseMountTreeReference(PathStateTable* table,
                               uint32_t tree_slot) noexcept {
    MountTreeState* tree = &table->mount_trees[tree_slot];
    if (--tree->refcount != 0) {
        return;
    }
    const uint32_t namespace_slot = tree->mount_namespace_slot;
    ClearMountTree(tree, tree_slot);
    --table->mount_tree_count;
    table->mount_tree_free_hint = tree_slot;
    ReleaseMountNamespaceHandleReference(table, namespace_slot);
}

void DetachMountTree(MountTreeState* tree) noexcept {
    tree->state_flags &= ~kMountTreeStateAttached;
    tree->state_flags |= kMountTreeStateDetached;
    tree->attached_namespace_slot = kInvalidPathStateSlot;
    tree->attached_mount_id = 0;
    CopyPath(tree->attached_target_guest, nullptr);
}

void DetachTreesFromNamespace(PathStateTable* table,
                              uint32_t namespace_slot) noexcept {
    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        MountTreeState* tree = &table->mount_trees[slot];
        if (tree->occupied != 0 &&
            tree->attached_namespace_slot == namespace_slot) {
            DetachMountTree(tree);
        }
    }
}

bool FdInRange(int32_t fd, uint32_t first, uint32_t last) noexcept {
    return fd >= 0 && static_cast<uint32_t>(fd) >= first &&
           static_cast<uint32_t>(fd) <= last;
}

bool ShouldCopyIdentity(const FdIdentity& identity, FdCopyMode mode,
                        uint32_t first, uint32_t last) noexcept {
    if (mode == FdCopyMode::kExec) {
        return identity.cloexec == 0;
    }
    if (mode == FdCopyMode::kCloseRange &&
        FdInRange(identity.fd, first, last)) {
        return false;
    }
    if (mode == FdCopyMode::kCloseRangePreserveProtected &&
        FdInRange(identity.fd, first, last) &&
        (identity.origin_flags & kPathOriginProtected) == 0) {
        return false;
    }
    return true;
}

uint32_t CountCopiedIdentities(const PathStateTable* table,
                               uint32_t source_table_slot, FdCopyMode mode,
                               uint32_t first, uint32_t last) noexcept {
    uint32_t count = 0;
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        const FdIdentity& identity = table->fd_identities[slot];
        if (identity.occupied != 0 &&
            identity.fd_table_slot == source_table_slot &&
            ShouldCopyIdentity(identity, mode, first, last)) {
            ++count;
        }
    }
    return count;
}

int CopyFdTableToSlot(PathStateTable* table, uint32_t source_table_slot,
                      uint32_t destination_table_slot, FdCopyMode mode,
                      uint32_t first, uint32_t last) noexcept {
    const FdTable source = table->fd_tables[source_table_slot];
    const uint32_t needed = CountCopiedIdentities(
            table, source_table_slot, mode, first, last);
    if (needed > CountFreeFdIdentitySlots(table)) {
        return ENOSPC;
    }
    OccupyEmptyFdTable(table, destination_table_slot,
                       NextGeneration(source.generation));

    for (uint32_t source_slot = 0;
         source_slot < kPathStateFdIdentityCapacity; ++source_slot) {
        const FdIdentity source_identity = table->fd_identities[source_slot];
        if (source_identity.occupied == 0 ||
            source_identity.fd_table_slot != source_table_slot ||
            !ShouldCopyIdentity(source_identity, mode, first, last)) {
            continue;
        }
        const uint32_t destination_slot = FindFreeFdIdentitySlot(table);
        if (destination_slot == kInvalidPathStateSlot) {
            EraseFdTableSlot(table, destination_table_slot);
            return EPROTO;
        }
        if (source_identity.object_kind == kFdIdentityObjectMountTree) {
            const int retain_error = RetainMountTreeReference(
                    table, source_identity.object_slot);
            if (retain_error != 0) {
                EraseFdTableSlot(table, destination_table_slot);
                return retain_error;
            }
        }
        FdIdentity* destination = &table->fd_identities[destination_slot];
        *destination = source_identity;
        destination->occupied = 1;
        destination->slot = destination_slot;
        destination->fd_table_slot = destination_table_slot;
        if ((mode == FdCopyMode::kCloexecRange ||
             mode == FdCopyMode::kCloexecRangePreserveProtected) &&
            FdInRange(destination->fd, first, last)) {
            destination->cloexec = 1;
        }
        FdTable* destination_table =
                &table->fd_tables[destination_table_slot];
        ++destination_table->entry_count;
        if ((destination->origin_flags & kPathOriginProtected) != 0) {
            ++destination_table->protected_count;
        }
        ++table->fd_identity_count;
        AdvanceHint(destination_slot, kPathStateFdIdentityCapacity,
                    &table->fd_identity_free_hint);
    }
    return 0;
}

void ReleaseFsReference(PathStateTable* table, uint32_t slot) noexcept {
    FsContext* context = &table->fs_contexts[slot];
    if (--context->refcount == 0) {
        EraseFsContextSlot(table, slot);
    }
}

void ReleaseFdTableReference(PathStateTable* table, uint32_t slot) noexcept {
    FdTable* fd_table = &table->fd_tables[slot];
    if (--fd_table->refcount == 0) {
        EraseFdTableSlot(table, slot);
    }
}

int ValidateIdentitySpec(const FdIdentitySpec& identity) noexcept {
    if (identity.directory > 1U || identity.cloexec > 1U ||
        identity.reserved != 0) {
        return EINVAL;
    }
    return ValidateOrigin(identity.origin_flags, identity.guest_path,
                          identity.host_path);
}

void FillIdentity(FdIdentity* destination, uint32_t slot,
                  uint32_t fd_table_slot, int32_t fd,
                  const FdIdentitySpec& source,
                  uint32_t mount_namespace_slot,
                  uint64_t mount_namespace_identity,
                  uint64_t mount_namespace_generation) noexcept {
    ClearFdIdentity(destination, slot);
    destination->occupied = 1;
    destination->fd_table_slot = fd_table_slot;
    destination->fd = fd;
    destination->origin_flags = source.origin_flags;
    destination->directory = source.directory;
    destination->cloexec = source.cloexec;
    destination->device = source.device;
    destination->inode = source.inode;
    destination->mount_namespace_slot = mount_namespace_slot;
    destination->mount_namespace_identity = mount_namespace_identity;
    destination->mount_namespace_generation = mount_namespace_generation;
    CopyPath(destination->guest_path,
             (source.origin_flags & kPathOriginGuestValid) != 0
                     ? source.guest_path
                     : nullptr);
    CopyPath(destination->host_path,
             (source.origin_flags & kPathOriginHostValid) != 0
                     ? source.host_path
                     : nullptr);
}

}  // namespace

void InitPathState(PathStateTable* table) noexcept {
    if (table == nullptr) {
        return;
    }
    ZeroBytes(table, sizeof(*table));
    table->magic = kPathStateMagic;
    table->version = kPathStateVersion;
    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        ClearTask(&table->tasks[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateFsContextCapacity; ++slot) {
        ClearFsContext(&table->fs_contexts[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateFdTableCapacity; ++slot) {
        ClearFdTable(&table->fd_tables[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        ClearFdIdentity(&table->fd_identities[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateMountNamespaceCapacity;
         ++slot) {
        ClearMountNamespace(&table->mount_namespaces[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        ClearMountBinding(&table->mount_bindings[slot], slot);
    }
    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        ClearMountTree(&table->mount_trees[slot], slot);
    }
}

bool IsPathStateInitialized(const PathStateTable* table) noexcept {
    return table != nullptr && table->magic == kPathStateMagic &&
           table->version == kPathStateVersion &&
           table->task_count <= kPathStateTaskCapacity &&
           table->fs_context_count <= kPathStateFsContextCapacity &&
           table->fd_table_count <= kPathStateFdTableCapacity &&
           table->fd_identity_count <= kPathStateFdIdentityCapacity &&
           table->mount_namespace_count <=
                   kPathStateMountNamespaceCapacity &&
           table->mount_binding_count <= kPathStateMountBindingCapacity &&
           table->mount_tree_count <= kPathStateMountTreeCapacity &&
           table->task_free_hint < kPathStateTaskCapacity &&
           table->fs_context_free_hint < kPathStateFsContextCapacity &&
           table->fd_table_free_hint < kPathStateFdTableCapacity &&
           table->fd_identity_free_hint < kPathStateFdIdentityCapacity &&
           table->mount_namespace_free_hint <
                   kPathStateMountNamespaceCapacity &&
           table->mount_binding_free_hint < kPathStateMountBindingCapacity &&
           table->mount_tree_free_hint < kPathStateMountTreeCapacity &&
           table->reserved_count == 0 && table->reserved_hint == 0;
}

bool ValidatePathState(const PathStateTable* table) noexcept {
    if (!IsPathStateInitialized(table)) {
        return false;
    }
    if (table->reserved[0] != 0 || table->reserved[1] != 0 ||
        table->reserved[2] != 0) {
        return false;
    }

    uint32_t fs_references[kPathStateFsContextCapacity]{};
    uint32_t fd_table_references[kPathStateFdTableCapacity]{};
    uint32_t fd_entry_counts[kPathStateFdTableCapacity]{};
    uint32_t protected_counts[kPathStateFdTableCapacity]{};
    uint32_t mount_task_references[kPathStateMountNamespaceCapacity]{};
    uint32_t mount_handle_references[kPathStateMountNamespaceCapacity]{};
    uint32_t mount_binding_counts[kPathStateMountNamespaceCapacity]{};
    uint32_t mount_tree_references[kPathStateMountTreeCapacity]{};
    uint32_t task_count = 0;
    uint32_t fs_context_count = 0;
    uint32_t fd_table_count = 0;
    uint32_t fd_identity_count = 0;
    uint32_t mount_namespace_count = 0;
    uint32_t mount_binding_count = 0;
    uint32_t mount_tree_count = 0;

    for (uint32_t slot = 0; slot < kPathStateTaskCapacity; ++slot) {
        const PathTaskState& task = table->tasks[slot];
        if (task.slot != slot || task.occupied > 1U) {
            return false;
        }
        if (task.occupied == 0) {
            if (task.tid != 0 || task.reserved != 0 || task.reserved2 != 0 ||
                task.fs_context_slot != kInvalidPathStateSlot ||
                task.fd_table_slot != kInvalidPathStateSlot ||
                task.mount_namespace_slot != kInvalidPathStateSlot ||
                task.identity_generation != 0) {
                return false;
            }
            continue;
        }
        if (task.tid <= 0 || task.reserved != 0 || task.reserved2 != 0 ||
            task.identity_generation == 0 ||
            task.fs_context_slot >= kPathStateFsContextCapacity ||
            task.fd_table_slot >= kPathStateFdTableCapacity ||
            task.mount_namespace_slot >=
                    kPathStateMountNamespaceCapacity ||
            table->fs_contexts[task.fs_context_slot].occupied == 0 ||
            table->fd_tables[task.fd_table_slot].occupied == 0 ||
            table->mount_namespaces[
                    task.mount_namespace_slot].occupied == 0) {
            return false;
        }
        for (uint32_t other = slot + 1U;
             other < kPathStateTaskCapacity; ++other) {
            if (table->tasks[other].occupied != 0 &&
                table->tasks[other].tid == task.tid) {
                return false;
            }
        }
        const FsContext& task_fs = table->fs_contexts[task.fs_context_slot];
        const MountNamespaceState& task_mount_namespace =
                table->mount_namespaces[task.mount_namespace_slot];
        if ((task_fs.cwd_mount_id != 0 &&
             task_fs.cwd_mount_id != task_mount_namespace.root_mount_id &&
             FindMountBindingById(table, task.mount_namespace_slot,
                                  task_fs.cwd_mount_id) == nullptr) ||
            (task_fs.root_mount_id != 0 &&
             task_fs.root_mount_id != task_mount_namespace.root_mount_id &&
             FindMountBindingById(table, task.mount_namespace_slot,
                                  task_fs.root_mount_id) == nullptr)) {
            return false;
        }
        ++fs_references[task.fs_context_slot];
        ++fd_table_references[task.fd_table_slot];
        ++mount_task_references[task.mount_namespace_slot];
        for (uint32_t other = 0; other < slot; ++other) {
            if (table->tasks[other].occupied != 0 &&
                table->tasks[other].fs_context_slot == task.fs_context_slot &&
                table->tasks[other].mount_namespace_slot !=
                        task.mount_namespace_slot) {
                return false;
            }
        }
        ++task_count;
    }

    for (uint32_t slot = 0; slot < kPathStateFsContextCapacity; ++slot) {
        const FsContext& context = table->fs_contexts[slot];
        if (context.slot != slot || context.occupied > 1U) {
            return false;
        }
        if (context.occupied == 0) {
            if (context.refcount != 0 || context.cwd_origin_flags != 0 ||
                context.generation != 0 || context.cwd_device != 0 ||
                context.cwd_inode != 0 || context.cwd_mount_id != 0 ||
                context.root_origin_flags != 0 || context.reserved != 0 ||
                context.root_device != 0 || context.root_inode != 0 ||
                context.root_mount_id != 0 ||
                !PathStorageIsEmpty(context.guest_cwd) ||
                !PathStorageIsEmpty(context.host_cwd) ||
                !PathStorageIsEmpty(context.guest_root) ||
                !PathStorageIsEmpty(context.host_root)) {
                return false;
            }
            continue;
        }
        if (context.refcount == 0 || context.generation == 0 ||
            context.refcount != fs_references[slot] ||
            (context.cwd_origin_flags & kPathOriginProtected) != 0 ||
            context.reserved != 0 ||
            (context.cwd_origin_flags &
             (kPathOriginGuestValid | kPathOriginHostValid)) !=
                    (kPathOriginGuestValid | kPathOriginHostValid) ||
             ValidateOrigin(context.cwd_origin_flags, context.guest_cwd,
                            context.host_cwd) != 0 ||
            !PathStorageIsPadded(context.guest_cwd) ||
            !PathStorageIsPadded(context.host_cwd) ||
            (context.root_origin_flags & kPathOriginProtected) != 0 ||
            (context.root_origin_flags &
             (kPathOriginGuestValid | kPathOriginHostValid)) !=
                    (kPathOriginGuestValid | kPathOriginHostValid) ||
             ValidateOrigin(context.root_origin_flags, context.guest_root,
                            context.host_root) != 0 ||
            !PathStorageIsPadded(context.guest_root) ||
            !PathStorageIsPadded(context.host_root)) {
            return false;
        }
        ++fs_context_count;
    }

    for (uint32_t slot = 0; slot < kPathStateFdIdentityCapacity; ++slot) {
        const FdIdentity& identity = table->fd_identities[slot];
        if (identity.slot != slot || identity.occupied > 1U) {
            return false;
        }
        if (identity.occupied == 0) {
            if (identity.fd_table_slot != kInvalidPathStateSlot ||
                identity.fd != -1 || identity.origin_flags != 0 ||
                identity.directory != 0 || identity.cloexec != 0 ||
                identity.object_kind != kFdIdentityObjectNone ||
                identity.object_flags != 0 ||
                identity.object_slot != kInvalidPathStateSlot ||
                identity.object_generation != 0 ||
                identity.reserved != 0 || identity.reserved2 != 0 ||
                identity.reserved3 != 0 ||
                identity.mount_namespace_slot != kInvalidPathStateSlot ||
                identity.mount_namespace_identity != 0 ||
                identity.mount_namespace_generation != 0 ||
                 identity.device != 0 || identity.inode != 0 ||
                 !PathStorageIsEmpty(identity.guest_path) ||
                 !PathStorageIsEmpty(identity.host_path)) {
                return false;
            }
            continue;
        }
        if (identity.fd_table_slot >= kPathStateFdTableCapacity ||
            table->fd_tables[identity.fd_table_slot].occupied == 0 ||
            identity.fd < 0 || identity.directory > 1U ||
            identity.cloexec > 1U || identity.reserved != 0 ||
            identity.reserved2 != 0 || identity.reserved3 != 0 ||
            identity.mount_namespace_slot >=
                    kPathStateMountNamespaceCapacity ||
            identity.mount_namespace_identity == 0 ||
            identity.mount_namespace_generation == 0 ||
             ValidateOrigin(identity.origin_flags, identity.guest_path,
                            identity.host_path) != 0 ||
            !PathStorageIsPadded(identity.guest_path) ||
            !PathStorageIsPadded(identity.host_path)) {
            return false;
        }
        if (identity.object_kind == kFdIdentityObjectNone) {
            if (identity.object_flags != 0 ||
                identity.object_slot != kInvalidPathStateSlot ||
                identity.object_generation != 0) {
                return false;
            }
        } else if (identity.object_kind == kFdIdentityObjectMountTree) {
            if (identity.object_flags != 0 ||
                identity.object_slot >= kPathStateMountTreeCapacity ||
                table->mount_trees[identity.object_slot].occupied == 0 ||
                table->mount_trees[identity.object_slot].generation !=
                        identity.object_generation) {
                return false;
            }
            ++mount_tree_references[identity.object_slot];
        } else {
            return false;
        }
        for (uint32_t other = slot + 1U;
             other < kPathStateFdIdentityCapacity; ++other) {
            const FdIdentity& candidate = table->fd_identities[other];
            if (candidate.occupied != 0 &&
                candidate.fd_table_slot == identity.fd_table_slot &&
                candidate.fd == identity.fd) {
                return false;
            }
        }
        ++fd_entry_counts[identity.fd_table_slot];
        if ((identity.origin_flags & kPathOriginProtected) != 0) {
            ++protected_counts[identity.fd_table_slot];
        }
        ++fd_identity_count;
    }

    for (uint32_t slot = 0; slot < kPathStateFdTableCapacity; ++slot) {
        const FdTable& fd_table = table->fd_tables[slot];
        if (fd_table.slot != slot || fd_table.occupied > 1U) {
            return false;
        }
        if (fd_table.occupied == 0) {
            if (fd_table.refcount != 0 || fd_table.entry_count != 0 ||
                fd_table.protected_count != 0 || fd_table.reserved != 0 ||
                fd_table.generation != 0) {
                return false;
            }
            continue;
        }
        if (fd_table.refcount == 0 || fd_table.generation == 0 ||
            fd_table.reserved != 0 ||
            fd_table.refcount != fd_table_references[slot] ||
            fd_table.entry_count != fd_entry_counts[slot] ||
            fd_table.protected_count != protected_counts[slot] ||
            fd_table.protected_count > fd_table.entry_count) {
            return false;
        }
        ++fd_table_count;
    }

    for (uint32_t slot = 0; slot < kPathStateMountBindingCapacity; ++slot) {
        const MountBindingState& binding = table->mount_bindings[slot];
        if (binding.slot != slot || binding.occupied > 1U) {
            return false;
        }
        if (binding.occupied == 0) {
            if (binding.mount_namespace_slot != kInvalidPathStateSlot ||
                binding.kind != 0 || binding.state_flags != 0 ||
                binding.reserved != 0 || binding.mount_id != 0 ||
                binding.parent_mount_id != 0 || binding.sequence != 0 ||
                binding.mount_flags != 0 || binding.mount_attributes != 0 ||
                binding.propagation != 0 ||
                !PathStorageIsEmpty(binding.target_guest) ||
                !PathStorageIsEmpty(binding.source_guest) ||
                !PathStorageIsEmpty(binding.source_host)) {
                return false;
            }
            continue;
        }
        if (binding.mount_namespace_slot >=
                    kPathStateMountNamespaceCapacity ||
            table->mount_namespaces[
                    binding.mount_namespace_slot].occupied == 0 ||
            binding.kind < kMountBindingBind ||
            binding.kind > kMountBindingRoot || binding.reserved != 0 ||
            (binding.state_flags & ~kMountBindingStateKnownFlags) != 0 ||
            binding.mount_id == 0 || binding.sequence == 0 ||
             ValidateCanonicalPath(binding.target_guest) != 0 ||
             ValidateCanonicalPath(binding.source_guest) != 0 ||
             ValidateCanonicalPath(binding.source_host) != 0 ||
            !PathStorageIsPadded(binding.target_guest) ||
            !PathStorageIsPadded(binding.source_guest) ||
            !PathStorageIsPadded(binding.source_host)) {
            return false;
        }
        const MountNamespaceState& mount_namespace =
                table->mount_namespaces[binding.mount_namespace_slot];
        if (binding.parent_mount_id != mount_namespace.root_mount_id &&
            FindMountBindingById(table, binding.mount_namespace_slot,
                                 binding.parent_mount_id) == nullptr) {
            return false;
        }
        for (uint32_t other = slot + 1U;
             other < kPathStateMountBindingCapacity; ++other) {
            if (table->mount_bindings[other].occupied != 0 &&
                table->mount_bindings[other].mount_namespace_slot ==
                        binding.mount_namespace_slot &&
                table->mount_bindings[other].mount_id == binding.mount_id) {
                return false;
            }
        }
        uint64_t parent = binding.parent_mount_id;
        for (uint32_t depth = 0; depth <= kPathStateMountBindingCapacity;
             ++depth) {
            if (parent == mount_namespace.root_mount_id) {
                break;
            }
            const MountBindingState* ancestor = FindMountBindingById(
                    table, binding.mount_namespace_slot, parent);
            if (ancestor == nullptr || ancestor->mount_id == binding.mount_id ||
                depth == kPathStateMountBindingCapacity) {
                return false;
            }
            parent = ancestor->parent_mount_id;
        }
        ++mount_binding_counts[binding.mount_namespace_slot];
        ++mount_binding_count;
    }

    for (uint32_t slot = 0; slot < kPathStateMountTreeCapacity; ++slot) {
        const MountTreeState& tree = table->mount_trees[slot];
        if (tree.slot != slot || tree.occupied > 1U) {
            return false;
        }
        if (tree.occupied == 0) {
            if (tree.refcount != 0 || tree.state_flags != 0 ||
                tree.mount_namespace_slot != kInvalidPathStateSlot ||
                tree.reserved != 0 || tree.generation != 0 ||
                tree.handle_id != 0 || tree.source_mount_id != 0 ||
                tree.attached_namespace_slot != kInvalidPathStateSlot ||
                tree.reserved2 != 0 || tree.attached_mount_id != 0 ||
                !PathStorageIsEmpty(tree.source_guest) ||
                !PathStorageIsEmpty(tree.source_host) ||
                !PathStorageIsEmpty(tree.attached_target_guest)) {
                return false;
            }
            continue;
        }
        const bool tree_attached =
                (tree.state_flags & kMountTreeStateAttached) != 0;
        const bool tree_detached =
                (tree.state_flags & kMountTreeStateDetached) != 0;
        if (tree.refcount == 0 || tree.reserved != 0 ||
            tree.refcount != mount_tree_references[slot] ||
            (tree.state_flags & ~kMountTreeStateKnownFlags) != 0 ||
            tree_attached == tree_detached ||
            tree.mount_namespace_slot >=
                    kPathStateMountNamespaceCapacity ||
            table->mount_namespaces[
                    tree.mount_namespace_slot].occupied == 0 ||
            tree.generation == 0 || tree.handle_id == 0 ||
            tree.source_mount_id == 0 ||
            ValidateCanonicalPath(tree.source_guest) != 0 ||
            ValidateCanonicalPath(tree.source_host) != 0 ||
            !PathStorageIsPadded(tree.source_guest) ||
            !PathStorageIsPadded(tree.source_host) || tree.reserved2 != 0) {
            return false;
        }
        const MountNamespaceState& source_namespace =
                table->mount_namespaces[tree.mount_namespace_slot];
        if (tree.source_mount_id != source_namespace.root_mount_id &&
            FindMountBindingById(table, tree.mount_namespace_slot,
                                 tree.source_mount_id) == nullptr) {
            return false;
        }
        if (tree_detached) {
            if (tree.attached_namespace_slot != kInvalidPathStateSlot ||
                tree.attached_mount_id != 0 ||
                !PathStorageIsEmpty(tree.attached_target_guest)) {
                return false;
            }
        } else {
            if (tree.attached_namespace_slot >=
                        kPathStateMountNamespaceCapacity ||
                table->mount_namespaces[
                        tree.attached_namespace_slot].occupied == 0 ||
                tree.attached_mount_id == 0 ||
                ValidateCanonicalPath(tree.attached_target_guest) != 0 ||
                !PathStorageIsPadded(tree.attached_target_guest)) {
                return false;
            }
            const MountNamespaceState& attached_namespace =
                    table->mount_namespaces[tree.attached_namespace_slot];
            if (tree.attached_mount_id != attached_namespace.root_mount_id &&
                FindMountBindingById(table, tree.attached_namespace_slot,
                                     tree.attached_mount_id) == nullptr) {
                return false;
            }
        }
        for (uint32_t other = slot + 1U;
             other < kPathStateMountTreeCapacity; ++other) {
            if (table->mount_trees[other].occupied != 0 &&
                table->mount_trees[other].handle_id == tree.handle_id) {
                return false;
            }
        }
        ++mount_handle_references[tree.mount_namespace_slot];
        ++mount_tree_count;
    }

    for (uint32_t slot = 0; slot < kPathStateMountNamespaceCapacity;
         ++slot) {
        const MountNamespaceState& mount_namespace =
                table->mount_namespaces[slot];
        if (mount_namespace.slot != slot || mount_namespace.occupied > 1U) {
            return false;
        }
        if (mount_namespace.occupied == 0) {
            if (mount_namespace.refcount != 0 ||
                mount_namespace.task_refcount != 0 ||
                mount_namespace.handle_refcount != 0 ||
                mount_namespace.binding_count != 0 ||
                mount_namespace.generation != 0 ||
                mount_namespace.identity_generation != 0 ||
                mount_namespace.root_mount_id != 0 ||
                mount_namespace.root_mount_flags != 0 ||
                mount_namespace.root_mount_attributes != 0 ||
                mount_namespace.root_propagation != 0 ||
                mount_namespace.root_origin_flags != 0 ||
                mount_namespace.reserved != 0 ||
                !PathStorageIsEmpty(mount_namespace.root_source_guest) ||
                !PathStorageIsEmpty(mount_namespace.root_source_host)) {
                return false;
            }
            continue;
        }
        if (mount_namespace.refcount == 0 ||
            mount_namespace.refcount != mount_namespace.task_refcount +
                                                mount_namespace.handle_refcount ||
            mount_namespace.task_refcount != mount_task_references[slot] ||
            mount_namespace.handle_refcount !=
                    mount_handle_references[slot] ||
            mount_namespace.binding_count != mount_binding_counts[slot] ||
            mount_namespace.generation == 0 ||
            mount_namespace.identity_generation == 0 ||
            mount_namespace.root_mount_id == 0 ||
            mount_namespace.reserved != 0 ||
            (mount_namespace.root_origin_flags &
             (kPathOriginGuestValid | kPathOriginHostValid)) !=
                    (kPathOriginGuestValid | kPathOriginHostValid) ||
             ValidateOrigin(mount_namespace.root_origin_flags,
                            mount_namespace.root_source_guest,
                            mount_namespace.root_source_host) != 0 ||
            ValidateCanonicalPath(mount_namespace.root_source_guest) != 0 ||
            ValidateCanonicalPath(mount_namespace.root_source_host) != 0 ||
            !PathStorageIsPadded(mount_namespace.root_source_guest) ||
            !PathStorageIsPadded(mount_namespace.root_source_host)) {
            return false;
        }
        for (uint32_t other = slot + 1U;
             other < kPathStateMountNamespaceCapacity; ++other) {
            if (table->mount_namespaces[other].occupied != 0 &&
                table->mount_namespaces[other].identity_generation ==
                        mount_namespace.identity_generation) {
                return false;
            }
        }
        ++mount_namespace_count;
    }

    return task_count == table->task_count &&
           fs_context_count == table->fs_context_count &&
           fd_table_count == table->fd_table_count &&
           fd_identity_count == table->fd_identity_count &&
           mount_namespace_count == table->mount_namespace_count &&
           mount_binding_count == table->mount_binding_count &&
           mount_tree_count == table->mount_tree_count;
}

PathTaskState* FindPathTask(PathStateTable* table, int32_t tid) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0) {
        return nullptr;
    }
    return FindTaskUnchecked(table, tid);
}
