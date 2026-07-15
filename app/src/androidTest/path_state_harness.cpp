#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "hookself/tracer/mount_syscall_state.h"
#include "hookself/tracer/path_state.h"

namespace {

using namespace hookself::tracer;

PathStateTable g_state;

int Fail(const char* expression, int line) {
    fprintf(stderr, "FAIL line %d: %s\n", line, expression);
    return line;
}

#define CHECK(expression)                    \
    do {                                     \
        if (!(expression)) {                 \
            return Fail(#expression, __LINE__); \
        }                                    \
    } while (0)

FdIdentitySpec Identity(const char* guest, const char* host, bool cloexec,
                        bool protected_fd = false) {
    FdIdentitySpec identity{};
    identity.origin_flags = kPathOriginGuestValid | kPathOriginHostValid |
                            (protected_fd ? kPathOriginProtected : 0U);
    identity.directory = 1;
    identity.cloexec = cloexec ? 1U : 0U;
    identity.guest_path = guest;
    identity.host_path = host;
    return identity;
}

MountBindingSpec Binding(const char* target, const char* source_guest,
                         const char* source_host) {
    MountBindingSpec binding{};
    binding.kind = kMountBindingBind;
    binding.state_flags = kMountBindingStateRuntime |
                          kMountBindingStateReverseVisible;
    binding.target_guest = target;
    binding.source_guest = source_guest;
    binding.source_host = source_host;
    return binding;
}

MountResolvedPath Resolved(const char* guest, const char* host) {
    MountResolvedPath path{};
    path.valid = 1;
    path.origin_flags = kPathOriginGuestValid | kPathOriginHostValid |
                        kPathOriginReverseVisible;
    path.guest_path = guest;
    path.host_path = host;
    return path;
}

bool Equals(const char* left, const char* right) {
    return strcmp(left, right) == 0;
}

void DumpState() {
    fprintf(stderr, "counts task=%u fs=%u fdt=%u fdi=%u ns=%u bind=%u tree=%u\n",
            g_state.task_count, g_state.fs_context_count,
            g_state.fd_table_count, g_state.fd_identity_count,
            g_state.mount_namespace_count, g_state.mount_binding_count,
            g_state.mount_tree_count);
    for (uint32_t i = 0; i < kPathStateTaskCapacity; ++i) {
        const PathTaskState& task = g_state.tasks[i];
        if (task.occupied != 0) {
            fprintf(stderr, "task %d fs=%u fdt=%u ns=%u\n", task.tid,
                    task.fs_context_slot, task.fd_table_slot,
                    task.mount_namespace_slot);
        }
    }
    for (uint32_t i = 0; i < kPathStateFsContextCapacity; ++i) {
        const FsContext& fs = g_state.fs_contexts[i];
        if (fs.occupied != 0) {
            fprintf(stderr, "fs %u refs=%u gen=%llu cwd=%s root=%s cm=%llu rm=%llu\n",
                    i, fs.refcount,
                    static_cast<unsigned long long>(fs.generation),
                    fs.guest_cwd, fs.guest_root,
                    static_cast<unsigned long long>(fs.cwd_mount_id),
                    static_cast<unsigned long long>(fs.root_mount_id));
        }
    }
    for (uint32_t i = 0; i < kPathStateFdTableCapacity; ++i) {
        const FdTable& fds = g_state.fd_tables[i];
        if (fds.occupied != 0) {
            fprintf(stderr, "fdt %u refs=%u entries=%u protected=%u gen=%llu\n",
                    i, fds.refcount, fds.entry_count, fds.protected_count,
                    static_cast<unsigned long long>(fds.generation));
        }
    }
    for (uint32_t i = 0; i < kPathStateFdIdentityCapacity; ++i) {
        const FdIdentity& id = g_state.fd_identities[i];
        if (id.occupied != 0) {
            fprintf(stderr,
                    "fdi %u owner=%u fd=%d flags=%x dir=%u ce=%u obj=%u/%u/%llu\n",
                    i, id.fd_table_slot, id.fd, id.origin_flags,
                    id.directory, id.cloexec, id.object_kind, id.object_slot,
                    static_cast<unsigned long long>(id.object_generation));
        }
    }
    for (uint32_t i = 0; i < kPathStateMountNamespaceCapacity; ++i) {
        const MountNamespaceState& ns = g_state.mount_namespaces[i];
        if (ns.occupied != 0) {
            fprintf(stderr, "ns %u refs=%u task=%u handle=%u root=%llu gen=%llu\n",
                    i, ns.refcount, ns.task_refcount, ns.handle_refcount,
                    static_cast<unsigned long long>(ns.root_mount_id),
                    static_cast<unsigned long long>(ns.generation));
        }
    }
}

int TestExecUnsharesFsAndFiles() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 100, "/cwd", "/host/cwd") == 0);
    CHECK(RecordFdIdentity(&g_state, 100, 3,
                           Identity("/fd3", "/host/fd3", false)) == 0);
    CHECK(RecordFdIdentity(&g_state, 100, 4,
                           Identity("/fd4", "/host/fd4", true)) == 0);
    CHECK(ClonePathTask(&g_state, 100, 101,
                        kPathCloneFs | kPathCloneFiles) == 0);
    const PathTaskState* parent_before = FindPathTask(&g_state, 100);
    const PathTaskState* child_before = FindPathTask(&g_state, 101);
    CHECK(parent_before != nullptr && child_before != nullptr);
    CHECK(parent_before->fs_context_slot == child_before->fs_context_slot);
    CHECK(parent_before->fd_table_slot == child_before->fd_table_slot);

    CHECK(ExecPathTask(&g_state, 101) == 0);
    if (!ValidatePathState(&g_state)) {
        DumpState();
    }
    CHECK(ValidatePathState(&g_state));
    const PathTaskState* parent = FindPathTask(&g_state, 100);
    const PathTaskState* child = FindPathTask(&g_state, 101);
    CHECK(parent->fs_context_slot != child->fs_context_slot);
    CHECK(parent->fd_table_slot != child->fd_table_slot);
    CHECK(LookupFdIdentity(&g_state, 101, 3) != nullptr);
    CHECK(LookupFdIdentity(&g_state, 101, 4) == nullptr);
    CHECK(LookupFdIdentity(&g_state, 100, 4) != nullptr);
    CHECK(ValidatePathState(&g_state));
    CHECK(SetTaskCwd(&g_state, 100, "/parent", "/host/parent",
                     kPathOriginGuestValid | kPathOriginHostValid,
                     1, 2) == 0);
    CHECK(Equals(GetTaskFsContext(&g_state, 101)->guest_cwd, "/cwd"));
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 101) == 0);
    CHECK(RemovePathTask(&g_state, 100) == 0);
    CHECK(ValidatePathState(&g_state));
    return 0;
}

int TestMountVisibilityTreesAndNewns() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 200, "/", "/") == 0);
    CHECK(AddMountBinding(&g_state, 200,
                          Binding("/a", "/real/a", "/host/a")) == 0);
    CHECK(AddMountBinding(&g_state, 200,
                          Binding("/a/b", "/real/b", "/host/b")) == 0);
    CHECK(AddMountBinding(&g_state, 200,
                          Binding("/a", "/real/c", "/host/c")) == 0);

    MountPathTranslation translation{};
    CHECK(TranslateMountPath(&g_state, 200, "/a/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/c/b/x"));
    CHECK(ReverseMountPath(&g_state, 200, "/host/a/b/x", &translation) == 0);
    CHECK(translation.matched == 0);
    CHECK(ReverseMountPath(&g_state, 200, "/host/c/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.guest_path, "/a/b/x"));

    CHECK(RemoveMountBinding(&g_state, 200, "/a", kMountRemoveNone) == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/a/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/b/x"));

    CHECK(RecordMountTreeFdIdentity(&g_state, 200, 12, "/a/deep",
                                    "/host/a/deep", false, false) == 0);
    CHECK(Equals(LookupMountTreeByFd(&g_state, 200, 12)
                         ->attached_target_guest,
                 "/a"));
    CHECK(AttachMountTree(&g_state, 200, 12, "/moved") == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/moved/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/b/x"));
    CHECK(AttachMountTree(&g_state, 200, 12, "/a") == 0);
    CHECK(CloseFdIdentity(&g_state, 200, 12) == 0);
    CHECK(ValidatePathState(&g_state));

    CHECK(ClonePathTask(&g_state, 200, 201, kPathCloneNewns) == 0);
    CHECK(FindPathTask(&g_state, 200)->mount_namespace_slot !=
          FindPathTask(&g_state, 201)->mount_namespace_slot);
    CHECK(FindPathTask(&g_state, 200)->fs_context_slot !=
          FindPathTask(&g_state, 201)->fs_context_slot);
    CHECK(AddMountBinding(&g_state, 201,
                          Binding("/child", "/real/child", "/host/child")) == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/child", &translation) == 0);
    CHECK(translation.matched == 0);
    CHECK(RemovePathTask(&g_state, 201) == 0);

    uint64_t handle_id = 0;
    CHECK(RecordMountTreeFdIdentity(&g_state, 200, 10, "/a", "/host/a",
                                    true, true, &handle_id) == 0);
    CHECK(handle_id != 0);
    CHECK(DuplicateFdIdentity(&g_state, 200, 10, 11, false) == 0);
    CHECK(LookupMountTreeByFd(&g_state, 200, 11)->refcount == 2);
    CHECK(ExecPathTask(&g_state, 200) == 0);
    CHECK(LookupMountTreeByFd(&g_state, 200, 10) == nullptr);
    CHECK(LookupMountTreeByFd(&g_state, 200, 11)->refcount == 1);

    CHECK(AttachMountTree(&g_state, 200, 11, "/tree") == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/tree/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/b/x"));
    CHECK(ValidatePathState(&g_state));

    CHECK(RemoveMountBinding(&g_state, 200, "/tree",
                             kMountRemoveSubtree |
                                     kMountRemoveDetached) == 0);
    const MountTreeState* detached = LookupMountTreeByFd(&g_state, 200, 11);
    CHECK(detached != nullptr &&
          (detached->state_flags & kMountTreeStateDetached) != 0 &&
          detached->attached_mount_id == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/tree/b/x", &translation) == 0);
    CHECK(translation.matched == 0);

    CHECK(AttachMountTree(&g_state, 200, 11, "/tree2") == 0);
    CHECK(AttachMountTree(&g_state, 200, 11, "/tree3") == 0);
    CHECK(TranslateMountPath(&g_state, 200, "/tree3/b/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/b/x"));
    CHECK(ValidatePathState(&g_state));
    CHECK(CloseFdIdentity(&g_state, 200, 11) == 0);
    CHECK(g_state.mount_tree_count == 0);
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 200) == 0);
    CHECK(ValidatePathState(&g_state));
    return 0;
}

int TestProtectedCloseRangeReplay() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 300, "/", "/") == 0);
    CHECK(RecordFdIdentity(&g_state, 300, 50,
                           Identity("/protected", "/host/protected", false,
                                    true)) == 0);
    CHECK(RecordFdIdentity(&g_state, 300, 51,
                           Identity("/normal", "/host/normal", false)) == 0);
    CHECK(ClonePathTask(&g_state, 300, 301, kPathCloneFiles) == 0);
    CHECK(CloseFdIdentityRangePreservingProtected(
                  &g_state, 301, 50, 51, kPathCloseRangeUnshare) == 0);
    CHECK(FindPathTask(&g_state, 300)->fd_table_slot !=
          FindPathTask(&g_state, 301)->fd_table_slot);
    CHECK(LookupFdIdentity(&g_state, 301, 50) != nullptr);
    CHECK(LookupFdIdentity(&g_state, 301, 51) == nullptr);
    CHECK(LookupFdIdentity(&g_state, 300, 50) != nullptr);
    CHECK(LookupFdIdentity(&g_state, 300, 51) != nullptr);
    CHECK(ClonePathTask(&g_state, 300, 302, kPathCloneFiles) == 0);
    CHECK(CloseFdIdentityRangePreservingProtected(
                  &g_state, 302, 50, 51,
                  kPathCloseRangeUnshare | kPathCloseRangeCloexec) == 0);
    CHECK(FindPathTask(&g_state, 300)->fd_table_slot !=
          FindPathTask(&g_state, 302)->fd_table_slot);
    CHECK(LookupFdIdentity(&g_state, 302, 50)->cloexec != 0);
    CHECK(LookupFdIdentity(&g_state, 302, 51)->cloexec != 0);
    CHECK(CloseFdIdentityRangePreservingProtected(
                  &g_state, 300, 50, 51, kPathCloseRangeCloexec) == 0);
    CHECK(LookupFdIdentity(&g_state, 300, 50)->cloexec != 0);
    CHECK(LookupFdIdentity(&g_state, 300, 51)->cloexec != 0);
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 302) == 0);
    CHECK(RemovePathTask(&g_state, 301) == 0);
    CHECK(RemovePathTask(&g_state, 300) == 0);
    return 0;
}

int TestSharedFdIdentityAcrossMountNamespaces() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 350, "/", "/") == 0);
    CHECK(RecordFdIdentity(&g_state, 350, 70,
                           Identity("/source", "/host/shared", false)) == 0);
    CHECK(ClonePathTask(&g_state, 350, 351, kPathCloneFiles) == 0);
    CHECK(FindPathTask(&g_state, 350)->fd_table_slot ==
          FindPathTask(&g_state, 351)->fd_table_slot);
    CHECK(UnsharePathTask(&g_state, 351, kPathCloneNewns) == 0);
    CHECK(FindPathTask(&g_state, 350)->mount_namespace_slot !=
          FindPathTask(&g_state, 351)->mount_namespace_slot);
    CHECK(FindPathTask(&g_state, 350)->fd_table_slot ==
          FindPathTask(&g_state, 351)->fd_table_slot);
    CHECK(AddMountBinding(&g_state, 351,
                          Binding("/child-fd", "/source",
                                  "/host/shared")) == 0);

    FdIdentityView parent_view{};
    FdIdentityView child_view{};
    CHECK(ResolveFdIdentityView(&g_state, 350, 70, &parent_view) == 0);
    CHECK(parent_view.flags == kFdIdentityViewNone);
    CHECK(Equals(parent_view.guest_path, "/source"));
    CHECK(ResolveFdIdentityView(&g_state, 351, 70, &child_view) == 0);
    CHECK((child_view.flags & kFdIdentityViewNamespaceChanged) != 0);
    CHECK((child_view.flags & kFdIdentityViewMountTranslated) != 0);
    CHECK(Equals(child_view.guest_path, "/child-fd"));
    CHECK(Equals(child_view.host_path, "/host/shared"));

    CHECK(RemoveMountBinding(&g_state, 351, "/child-fd",
                             kMountRemoveNone) == 0);
    CHECK(ResolveFdIdentityView(&g_state, 351, 70, &child_view) == 0);
    CHECK((child_view.flags & kFdIdentityViewNamespaceChanged) != 0);
    CHECK((child_view.flags & kFdIdentityViewCapturedFallback) != 0);
    CHECK((child_view.flags & kFdIdentityViewMountTranslated) == 0);
    CHECK(Equals(child_view.guest_path, "/source"));

    CHECK(AddMountBinding(&g_state, 350,
                          Binding("/live-alias", "/source",
                                  "/host/shared")) == 0);
    CHECK(ResolveFdIdentityView(&g_state, 350, 70, &parent_view) == 0);
    CHECK((parent_view.flags & kFdIdentityViewNamespaceMutated) != 0);
    CHECK((parent_view.flags & kFdIdentityViewMountTranslated) != 0);
    CHECK(Equals(parent_view.guest_path, "/live-alias"));
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 351) == 0);
    CHECK(RemovePathTask(&g_state, 350) == 0);
    CHECK(ValidatePathState(&g_state));
    return 0;
}

int TestFdIdentityNamespaceSlotReuse() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 360, "/", "/") == 0);
    CHECK(RecordFdIdentity(&g_state, 360, 71,
                           Identity("/source", "/host/reused", false)) == 0);
    const FdIdentity* identity = LookupFdIdentity(&g_state, 360, 71);
    CHECK(identity != nullptr);
    const uint32_t origin_slot = identity->mount_namespace_slot;
    const uint64_t origin_namespace = identity->mount_namespace_identity;
    CHECK(ClonePathTask(&g_state, 360, 361, kPathCloneFiles) == 0);
    CHECK(RemovePathTask(&g_state, 360) == 0);
    CHECK(UnsharePathTask(&g_state, 361, kPathCloneNewns) == 0);
    CHECK(UnsharePathTask(&g_state, 361, kPathCloneNewns) == 0);
    const PathTaskState* task = FindPathTask(&g_state, 361);
    const MountNamespaceState* mount_namespace =
            GetTaskMountNamespace(&g_state, 361);
    CHECK(task != nullptr && mount_namespace != nullptr);
    CHECK(task->mount_namespace_slot == origin_slot);
    CHECK(mount_namespace->identity_generation != origin_namespace);
    CHECK(AddMountBinding(&g_state, 361,
                          Binding("/reused-alias", "/source",
                                  "/host/reused")) == 0);
    FdIdentityView view{};
    CHECK(ResolveFdIdentityView(&g_state, 361, 71, &view) == 0);
    CHECK((view.flags & kFdIdentityViewNamespaceChanged) != 0);
    CHECK((view.flags & kFdIdentityViewMountTranslated) != 0);
    CHECK(Equals(view.guest_path, "/reused-alias"));
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 361) == 0);
    CHECK(ValidatePathState(&g_state));
    return 0;
}

int TestPivotAndValidator() {
    InitPathState(&g_state);
    CHECK(ValidatePathState(&g_state));
    g_state.reserved[0] = 1;
    CHECK(!ValidatePathState(&g_state));
    g_state.reserved[0] = 0;
    CHECK(InsertInitialPathTask(&g_state, 400, "/", "/") == 0);
    CHECK(AddMountBinding(&g_state, 400,
                          Binding("/new", "/guest/new", "/host/new")) == 0);
    CHECK(PivotRootMountNamespace(&g_state, 400, "/new", "/host/new",
                                  "/new", "/host/new") == EINVAL);
    CHECK(PivotRootMountNamespace(&g_state, 400, "/new", "/host/new",
                                  "/new/old", "/host/new/old") == 0);
    MountPathTranslation translation{};
    CHECK(TranslateMountPath(&g_state, 400, "/x", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/new/x"));
    CHECK(TranslateMountPath(&g_state, 400, "/old/x", &translation) == 0);
    CHECK(translation.matched != 0 && Equals(translation.host_path, "/x"));
    CHECK(ReverseMountPath(&g_state, 400, "/host/new/x", &translation) == 0);
    CHECK(translation.matched != 0 && Equals(translation.guest_path, "/x"));
    CHECK(ValidatePathState(&g_state));

    MountNamespaceState* mount_namespace = const_cast<MountNamespaceState*>(
            GetTaskMountNamespace(&g_state, 400));
    const size_t root_host_length = strlen(mount_namespace->root_source_host);
    mount_namespace->root_source_host[root_host_length + 1U] = 'x';
    CHECK(!ValidatePathState(&g_state));
    mount_namespace->root_source_host[root_host_length + 1U] = '\0';
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 400) == 0);
    return 0;
}

int TestMountSyscallAdapter() {
    InitPathState(&g_state);
    CHECK(InsertInitialPathTask(&g_state, 500, "/", "/") == 0);
    CHECK(AddMountBinding(&g_state, 500,
                          Binding("/src/sub", "/real/sub",
                                  "/host/sub")) == 0);

    MountSyscallCompletion completion{};
    completion.syscall_number = kMountStateMount;
    completion.path_count = 2;
    completion.kernel_result = 0;
    completion.arguments[3] = 4096;  // MS_BIND
    completion.paths[0] = Resolved("/mnt", "/mnt");
    completion.paths[1] = Resolved("/src", "/host/src");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    MountPathTranslation translation{};
    CHECK(TranslateMountPath(&g_state, 500, "/mnt/file", &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/src/file"));

    completion = {};
    completion.syscall_number = kMountStateMount;
    completion.path_count = 2;
    completion.kernel_result = 0;
    completion.arguments[3] = 4096U | 16384U;  // MS_BIND | MS_REC
    completion.paths[0] = Resolved("/recursive", "/recursive");
    completion.paths[1] = Resolved("/src", "/host/src");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    CHECK(TranslateMountPath(&g_state, 500, "/recursive/file",
                             &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/src/file"));
    CHECK(TranslateMountPath(&g_state, 500, "/recursive/sub/file",
                             &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/sub/file"));

    completion = {};
    completion.syscall_number = kMountStateOpenTree;
    completion.path_count = 1;
    completion.kernel_result = 10;
    completion.arguments[2] = 1U | static_cast<uint32_t>(O_CLOEXEC);
    completion.paths[0] = Resolved("/mnt", "/host/src");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    CHECK(LookupMountTreeByFd(&g_state, 500, 10) != nullptr);

    completion = {};
    completion.syscall_number = kMountStateMoveMount;
    completion.path_count = 2;
    completion.kernel_result = 0;
    completion.arguments[0] = 10;
    completion.arguments[4] = 4U;  // MOVE_MOUNT_F_EMPTY_PATH
    completion.paths[1] = Resolved("/attached", "/attached");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    CHECK(TranslateMountPath(&g_state, 500, "/attached/file",
                             &translation) == 0);
    CHECK(translation.matched != 0 &&
          Equals(translation.host_path, "/host/src/file"));

    completion = {};
    completion.syscall_number = kMountStateMountSetattr;
    completion.path_count = 1;
    completion.kernel_result = 0;
    completion.mount_attr_valid = 1;
    completion.mount_attr_set = 1U;
    completion.arguments[2] = 0x8000U;  // AT_RECURSIVE
    completion.paths[0] = Resolved("/attached", "/host/src");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    CHECK(TranslateMountPath(&g_state, 500, "/attached/file",
                             &translation) == 0);
    CHECK((translation.mount_attributes & 1U) != 0);

    completion = {};
    completion.syscall_number = kMountStateUmount2;
    completion.path_count = 1;
    completion.kernel_result = 0;
    completion.arguments[1] = 2U;  // MNT_DETACH
    completion.paths[0] = Resolved("/attached", "/host/src");
    CHECK(ApplyMountSyscallCompletion(&g_state, 500, completion) == 0);
    CHECK(TranslateMountPath(&g_state, 500, "/attached/file",
                             &translation) == 0);
    CHECK(translation.matched == 0);
    CHECK(ValidatePathState(&g_state));
    CHECK(RemovePathTask(&g_state, 500) == 0);
    return 0;
}

}  // namespace

int main() {
    int error = TestExecUnsharesFsAndFiles();
    if (error == 0) {
        error = TestMountVisibilityTreesAndNewns();
    }
    if (error == 0) {
        error = TestProtectedCloseRangeReplay();
    }
    if (error == 0) {
        error = TestSharedFdIdentityAcrossMountNamespaces();
    }
    if (error == 0) {
        error = TestFdIdentityNamespaceSlotReuse();
    }
    if (error == 0) {
        error = TestPivotAndValidator();
    }
    if (error == 0) {
        error = TestMountSyscallAdapter();
    }
    if (error != 0) {
        return 1;
    }
    puts("path_state_harness: PASS");
    return 0;
}
