#pragma once

#include <stdint.h>

#include "tracer/path_state.h"

namespace hookself::tracer {

constexpr int32_t kMountStateUmount2 = 39;
constexpr int32_t kMountStateMount = 40;
constexpr int32_t kMountStatePivotRoot = 41;
constexpr int32_t kMountStateChroot = 51;
constexpr int32_t kMountStateOpenTree = 428;
constexpr int32_t kMountStateMoveMount = 429;
constexpr int32_t kMountStateMountSetattr = 442;

struct MountResolvedPath {
    uint32_t valid;
    uint32_t origin_flags;
    const char* guest_path;
    const char* host_path;
};

struct MountSyscallCompletion {
    int32_t syscall_number;
    uint32_t path_count;
    int64_t kernel_result;
    uint32_t mount_attr_valid;
    uint32_t reserved;
    uint64_t arguments[6];
    uint64_t mount_attr_set;
    uint64_t mount_attr_clear;
    uint64_t mount_propagation;
    MountResolvedPath paths[2];
};

static_assert(__is_standard_layout(MountResolvedPath) &&
              __is_trivially_copyable(MountResolvedPath));
static_assert(__is_standard_layout(MountSyscallCompletion) &&
              __is_trivially_copyable(MountSyscallCompletion));

bool IsMountStateSyscall(int32_t syscall_number) noexcept;

// Applies state only after a successful kernel result. Path conventions:
// mount: target, source; umount/chroot/open_tree/mount_setattr: target;
// pivot_root: new_root, put_old; move_mount: from, to.
int ApplyMountSyscallCompletion(PathStateTable* table, int32_t tid,
                                const MountSyscallCompletion& completion) noexcept;

}  // namespace hookself::tracer
