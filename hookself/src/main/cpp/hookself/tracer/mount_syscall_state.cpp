#include "mount_syscall_state.h"

#include <errno.h>
#include <fcntl.h>

namespace hookself::tracer {
namespace {

constexpr uint64_t kMsRemount = 32ULL;
constexpr uint64_t kMsBind = 4096ULL;
constexpr uint64_t kMsMove = 8192ULL;
constexpr uint64_t kMsRec = 16384ULL;
constexpr uint64_t kMsUnbindable = 1ULL << 17U;
constexpr uint64_t kMsPrivate = 1ULL << 18U;
constexpr uint64_t kMsSlave = 1ULL << 19U;
constexpr uint64_t kMsShared = 1ULL << 20U;
constexpr uint64_t kPropagationMask =
        kMsUnbindable | kMsPrivate | kMsSlave | kMsShared;
constexpr uint32_t kMntDetach = 2U;
constexpr uint32_t kOpenTreeClone = 1U;
constexpr uint32_t kMoveMountFromEmptyPath = 0x00000004U;
constexpr uint32_t kAtRecursive = 0x8000U;

bool PathUsable(const MountResolvedPath& path) noexcept {
    const uint32_t required = kPathOriginGuestValid | kPathOriginHostValid;
    return path.valid != 0 && (path.origin_flags & required) == required &&
           path.guest_path != nullptr && path.host_path != nullptr &&
           path.guest_path[0] == '/' && path.host_path[0] == '/';
}

int IgnoreUnknownMount(int error) noexcept {
    return error == EINVAL || error == ENOENT ? 0 : error;
}

int ApplyMount(PathStateTable* table, int32_t tid,
               const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0])) {
        return EPROTO;
    }
    const uint64_t flags = completion.arguments[3];
    if ((flags & kMsMove) != 0) {
        return PathUsable(completion.paths[1])
                ? IgnoreUnknownMount(MoveMountBinding(
                          table, tid, completion.paths[1].guest_path,
                          completion.paths[0].guest_path))
                : EPROTO;
    }
    if ((flags & kPropagationMask) != 0 &&
        !PathUsable(completion.paths[1])) {
        return IgnoreUnknownMount(SetMountBindingAttributes(
                table, tid, completion.paths[0].guest_path, 0, 0,
                flags & kPropagationMask, (flags & kMsRec) != 0));
    }
    if ((flags & kMsRemount) != 0) {
        return 0;
    }

    const MountResolvedPath& source = PathUsable(completion.paths[1])
            ? completion.paths[1]
            : completion.paths[0];
    MountBindingSpec spec{};
    spec.kind = (flags & kMsBind) != 0
            ? kMountBindingBind
            : kMountBindingSynthetic;
    spec.state_flags = kMountBindingStateRuntime |
                       kMountBindingStateReverseVisible |
                       ((flags & kMsRec) != 0
                                ? kMountBindingStateRecursive
                                : 0U);
    spec.mount_flags = flags;
    spec.propagation = flags & kPropagationMask;
    spec.target_guest = completion.paths[0].guest_path;
    spec.source_guest = source.guest_path;
    spec.source_host = source.host_path;
    return (flags & (kMsBind | kMsRec)) == (kMsBind | kMsRec)
            ? AddRecursiveMountBinding(table, tid, spec)
            : AddMountBinding(table, tid, spec);
}

int ApplyUmount(PathStateTable* table, int32_t tid,
                const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0])) {
        return EPROTO;
    }
    const uint32_t syscall_flags = static_cast<uint32_t>(
            completion.arguments[1]);
    const uint32_t remove_flags = (syscall_flags & kMntDetach) != 0
            ? kMountRemoveSubtree | kMountRemoveDetached
            : kMountRemoveNone;
    return IgnoreUnknownMount(RemoveMountBinding(
            table, tid, completion.paths[0].guest_path, remove_flags));
}

int ApplyChroot(PathStateTable* table, int32_t tid,
                const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0])) {
        return EPROTO;
    }
    MountPathTranslation translation{};
    const int translate_error = TranslateMountPath(
            table, tid, completion.paths[0].guest_path, &translation);
    if (translate_error != 0) {
        return translate_error;
    }
    const MountNamespaceState* mount_namespace = GetTaskMountNamespace(
            table, tid);
    if (mount_namespace == nullptr) {
        return ESRCH;
    }
    const uint64_t mount_id = translation.matched != 0
            ? translation.mount_id
            : mount_namespace->root_mount_id;
    return SetTaskRoot(table, tid, completion.paths[0].guest_path,
                       completion.paths[0].host_path,
                       completion.paths[0].origin_flags, 0, 0, mount_id);
}

int ApplyPivotRoot(PathStateTable* table, int32_t tid,
                   const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0]) ||
        !PathUsable(completion.paths[1])) {
        return EPROTO;
    }
    int error = PivotRootMountNamespace(
            table, tid, completion.paths[0].guest_path,
            completion.paths[0].host_path,
            completion.paths[1].guest_path,
            completion.paths[1].host_path);
    if (error != EINVAL) {
        return error;
    }
    MountBindingSpec root{};
    root.kind = kMountBindingRoot;
    root.state_flags = kMountBindingStateRuntime |
                       kMountBindingStateReverseVisible;
    root.target_guest = completion.paths[0].guest_path;
    root.source_guest = completion.paths[0].guest_path;
    root.source_host = completion.paths[0].host_path;
    error = AddMountBinding(table, tid, root);
    return error != 0 ? error : PivotRootMountNamespace(
            table, tid, completion.paths[0].guest_path,
            completion.paths[0].host_path,
            completion.paths[1].guest_path,
            completion.paths[1].host_path);
}

int ApplyOpenTree(PathStateTable* table, int32_t tid,
                  const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0]) || completion.kernel_result < 0 ||
        completion.kernel_result > INT32_MAX) {
        return EPROTO;
    }
    const uint32_t flags = static_cast<uint32_t>(completion.arguments[2]);
    return RecordMountTreeFdIdentity(
            table, tid, static_cast<int32_t>(completion.kernel_result),
            completion.paths[0].guest_path,
            completion.paths[0].host_path,
            (flags & static_cast<uint32_t>(O_CLOEXEC)) != 0,
            (flags & kOpenTreeClone) != 0);
}

int ApplyMoveMount(PathStateTable* table, int32_t tid,
                   const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[1])) {
        return EPROTO;
    }
    const uint32_t flags = static_cast<uint32_t>(completion.arguments[4]);
    if ((flags & kMoveMountFromEmptyPath) != 0) {
        return AttachMountTree(
                table, tid, static_cast<int32_t>(completion.arguments[0]),
                completion.paths[1].guest_path);
    }
    return PathUsable(completion.paths[0])
            ? IgnoreUnknownMount(MoveMountBinding(
                      table, tid, completion.paths[0].guest_path,
                      completion.paths[1].guest_path))
            : EPROTO;
}

int ApplyMountSetattr(PathStateTable* table, int32_t tid,
                     const MountSyscallCompletion& completion) noexcept {
    if (!PathUsable(completion.paths[0]) ||
        completion.mount_attr_valid == 0) {
        return EPROTO;
    }
    return IgnoreUnknownMount(SetMountBindingAttributes(
            table, tid, completion.paths[0].guest_path,
            completion.mount_attr_set, completion.mount_attr_clear,
            completion.mount_propagation,
            (completion.arguments[2] & kAtRecursive) != 0));
}

}  // namespace

bool IsMountStateSyscall(int32_t syscall_number) noexcept {
    switch (syscall_number) {
        case kMountStateUmount2:
        case kMountStateMount:
        case kMountStatePivotRoot:
        case kMountStateChroot:
        case kMountStateOpenTree:
        case kMountStateMoveMount:
        case kMountStateMountSetattr:
            return true;
        default:
            return false;
    }
}

int ApplyMountSyscallCompletion(PathStateTable* table, int32_t tid,
                                const MountSyscallCompletion& completion) noexcept {
    if (!IsPathStateInitialized(table) || tid <= 0 ||
        !IsMountStateSyscall(completion.syscall_number) ||
        completion.path_count > 2U) {
        return EINVAL;
    }
    if (completion.kernel_result < 0) {
        return 0;
    }
    switch (completion.syscall_number) {
        case kMountStateMount:
            return ApplyMount(table, tid, completion);
        case kMountStateUmount2:
            return ApplyUmount(table, tid, completion);
        case kMountStateChroot:
            return ApplyChroot(table, tid, completion);
        case kMountStatePivotRoot:
            return ApplyPivotRoot(table, tid, completion);
        case kMountStateOpenTree:
            return ApplyOpenTree(table, tid, completion);
        case kMountStateMoveMount:
            return ApplyMoveMount(table, tid, completion);
        case kMountStateMountSetattr:
            return ApplyMountSetattr(table, tid, completion);
        default:
            return EINVAL;
    }
}

}  // namespace hookself::tracer
