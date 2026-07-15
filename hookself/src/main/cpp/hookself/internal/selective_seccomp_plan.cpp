#include "internal/selective_seccomp_plan.h"

#include <asm/unistd.h>
#include <errno.h>

#include <cstring>

#include "tracer/mount_syscall_state.h"

namespace hookself::internal {
namespace {

constexpr int32_t kArm64CloseRange = 436;

constexpr int32_t kProtectedFdSyscalls[] = {
        __NR_dup3,
        __NR_fcntl,
        __NR_ioctl,
        __NR_close,
        kArm64CloseRange,
};

constexpr int32_t kPathStateSyscalls[] = {
        __NR_dup,
        __NR_unshare,
        __NR_clone,
        __NR_clone3,
        __NR_execve,
        __NR_execveat,
        hookself::tracer::kMountStateMount,
        hookself::tracer::kMountStateUmount2,
        hookself::tracer::kMountStatePivotRoot,
        hookself::tracer::kMountStateChroot,
        hookself::tracer::kMountStateOpenTree,
        hookself::tracer::kMountStateMoveMount,
        hookself::tracer::kMountStateMountSetattr,
};

// This list mirrors PathOperandsForSyscall() in resident_session.cpp. Keep it
// separate from PathArgumentIndex(), whose extra entries are capture-only.
constexpr int32_t kPathPolicySyscalls[] = {
        __NR_openat,
        __NR_openat2,
        __NR_newfstatat,
        __NR_statx,
        __NR_faccessat,
        __NR_faccessat2,
        __NR_readlinkat,
        __NR_unlinkat,
        __NR_mkdirat,
        __NR_mknodat,
        __NR_utimensat,
        __NR_fchmodat,
        __NR_fchownat,
        __NR_renameat,
        __NR_renameat2,
        __NR_linkat,
        __NR_symlinkat,
        __NR_chdir,
        __NR_fchdir,
        __NR_getcwd,
        __NR_execve,
        __NR_execveat,
};

constexpr int32_t kPtraceAndStatusViewSyscalls[] = {
        __NR_ptrace,
        __NR_prctl,
        __NR_read,
        __NR_pread64,
        __NR_readv,
};

constexpr int32_t kNestedPtraceWaitSyscalls[] = {
        __NR_wait4,
        __NR_waitid,
};

constexpr int32_t kProcVirtualViewSyscalls[] = {
        __NR_read,
        __NR_pread64,
        __NR_readv,
        __NR_getdents64,
};

constexpr int32_t kVirtualOutputSyscalls[] = {
        __NR_getxattr,
        __NR_lgetxattr,
        __NR_fgetxattr,
        __NR_listxattr,
        __NR_llistxattr,
        __NR_flistxattr,
};

template <size_t Size>
constexpr size_t ArraySize(const int32_t (&)[Size]) noexcept {
    return Size;
}

bool HasSelinuxVirtualProvider(const HookselfConfig& config) noexcept {
    for (uint32_t index = 0; index < config.virtual_file_count; ++index) {
        if (config.virtual_files[index].provider ==
            HOOKSELF_VFILE_SELINUX_CONTEXT) {
            return true;
        }
    }
    return false;
}

static_assert(HOOKSELF_MAX_SYSCALL_RULES +
                      ArraySize(kProtectedFdSyscalls) +
                      ArraySize(kPathStateSyscalls) +
                      ArraySize(kPathPolicySyscalls) +
                      ArraySize(kPtraceAndStatusViewSyscalls) +
                      ArraySize(kProcVirtualViewSyscalls) +
                      ArraySize(kVirtualOutputSyscalls) <=
              kMaxSelectiveSeccompRules,
              "selective plan must hold the public worst-case union");
#ifdef __NR_close_range
static_assert(__NR_close_range == kArm64CloseRange,
              "arm64 close_range syscall number changed");
#endif

constexpr uint64_t kFnv1aOffsetBasis = 14695981039346656037ULL;
constexpr uint64_t kFnv1aPrime = 1099511628211ULL;

void HashByte(uint8_t value, uint64_t* hash) noexcept {
    *hash = (*hash ^ value) * kFnv1aPrime;
}

void HashUint16(uint16_t value, uint64_t* hash) noexcept {
    HashByte(static_cast<uint8_t>(value), hash);
    HashByte(static_cast<uint8_t>(value >> 8U), hash);
}

void HashUint32(uint32_t value, uint64_t* hash) noexcept {
    for (uint32_t shift = 0; shift < 32U; shift += 8U) {
        HashByte(static_cast<uint8_t>(value >> shift), hash);
    }
}

int AddSortedSyscall(int32_t syscall_number,
                     SelectiveSeccompPlan* plan) noexcept {
    if (syscall_number < 0 ||
        syscall_number >= static_cast<int32_t>(HOOKSELF_SYSCALL_LIMIT)) {
        return EINVAL;
    }

    size_t insertion = 0;
    while (insertion < plan->rule_count &&
           plan->rules[insertion].syscall_number < syscall_number) {
        ++insertion;
    }
    if (insertion < plan->rule_count &&
        plan->rules[insertion].syscall_number == syscall_number) {
        return 0;
    }
    if (plan->rule_count >= kMaxSelectiveSeccompRules) {
        return E2BIG;
    }

    for (size_t index = plan->rule_count; index > insertion; --index) {
        plan->rules[index] = plan->rules[index - 1U];
    }
    plan->rules[insertion] = {
            syscall_number, kSelectiveSeccompUnifiedClassId};
    ++plan->rule_count;
    return 0;
}

template <size_t Size>
int AddSyscalls(const int32_t (&syscalls)[Size],
                SelectiveSeccompPlan* plan) noexcept {
    for (int32_t syscall_number : syscalls) {
        const int error = AddSortedSyscall(syscall_number, plan);
        if (error != 0) {
            return error;
        }
    }
    return 0;
}

int ValidateConfigShape(const HookselfConfig& config) noexcept {
    if (config.struct_size != sizeof(HookselfConfig)) {
        return EINVAL;
    }
    if (config.abi_version != HOOKSELF_ABI_VERSION) {
        return EPROTONOSUPPORT;
    }
    if (config.path_rule_count > HOOKSELF_MAX_PATH_RULES ||
        (config.path_rule_count != 0U && config.path_rules == nullptr) ||
        config.syscall_rule_count > HOOKSELF_MAX_SYSCALL_RULES ||
        (config.syscall_rule_count != 0U && config.syscall_rules == nullptr) ||
        config.virtual_file_count > HOOKSELF_MAX_VIRTUAL_FILES ||
        (config.virtual_file_count != 0U && config.virtual_files == nullptr)) {
        return EINVAL;
    }
    if ((config.flags & HOOKSELF_CONFIG_OBSERVE_ALL) != 0U) {
        return EOPNOTSUPP;
    }
    return 0;
}

uint64_t ComputePlanHash(const SelectiveSeccompPlan& plan) noexcept {
    uint64_t hash = kFnv1aOffsetBasis;
    HashUint32(kSelectiveSeccompPlanSchemaVersion, &hash);
    HashUint32(static_cast<uint32_t>(
                       SelectiveSeccompArchMismatchAction::kKillProcess),
               &hash);
    HashUint16(plan.class_id, &hash);
    HashUint16(plan.rule_count, &hash);
    for (size_t index = 0; index < plan.rule_count; ++index) {
        HashUint32(static_cast<uint32_t>(
                           plan.rules[index].syscall_number),
                   &hash);
    }
    return hash;
}

}  // namespace

int BuildSelectiveSeccompPlan(const HookselfConfig* config,
                              SelectiveSeccompPlan* output) noexcept {
    if (output == nullptr) {
        return EINVAL;
    }
    std::memset(output, 0, sizeof(*output));
    if (config == nullptr) {
        return EINVAL;
    }

    const int shape_error = ValidateConfigShape(*config);
    if (shape_error != 0) {
        return shape_error;
    }

    SelectiveSeccompPlan candidate{};
    candidate.schema_version = kSelectiveSeccompPlanSchemaVersion;
    candidate.class_id = kSelectiveSeccompUnifiedClassId;

    int error = AddSyscalls(kProtectedFdSyscalls, &candidate);
    if (error != 0) {
        return error;
    }
    error = AddSyscalls(kPathStateSyscalls, &candidate);
    if (error != 0) {
        return error;
    }

    // Every public syscall rule is an explicit selection point. Including PASS
    // keeps ordered rule evaluation available without making the BPF depend on
    // action or rule ordering.
    for (uint32_t index = 0; index < config->syscall_rule_count; ++index) {
        error = AddSortedSyscall(
                config->syscall_rules[index].syscall_number, &candidate);
        if (error != 0) {
            return error;
        }
    }

    if ((config->flags & (HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT |
                          HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES)) != 0U) {
        error = AddSyscalls(kPathPolicySyscalls, &candidate);
        if (error != 0) {
            return error;
        }
    }
    if ((config->flags & HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES) != 0U &&
        HasSelinuxVirtualProvider(*config)) {
        error = AddSyscalls(kVirtualOutputSyscalls, &candidate);
        if (error != 0) {
            return error;
        }
    }
    if ((config->flags & HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW) != 0U) {
        error = AddSyscalls(kPtraceAndStatusViewSyscalls, &candidate);
        if (error != 0) {
            return error;
        }
    }
    if ((config->flags & HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE) != 0U) {
        error = AddSyscalls(kNestedPtraceWaitSyscalls, &candidate);
        if (error != 0) {
            return error;
        }
    }
    if ((config->flags &
         HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW) != 0U) {
        error = AddSyscalls(kProcVirtualViewSyscalls, &candidate);
        if (error != 0) {
            return error;
        }
    }

    candidate.syscall_set_hash = ComputePlanHash(candidate);
    error = BuildSelectiveSeccompFilter(
            candidate.rules, candidate.rule_count,
            SelectiveSeccompArchMismatchAction::kKillProcess,
            &candidate.filter);
    if (error != 0) {
        return error;
    }

    *output = candidate;
    return 0;
}

bool FindSelectiveSeccompClass(const SelectiveSeccompPlan* plan,
                               int32_t syscall_number,
                               uint16_t* class_id) noexcept {
    if (class_id != nullptr) {
        *class_id = 0;
    }
    if (plan == nullptr || class_id == nullptr || syscall_number < 0 ||
        plan->schema_version != kSelectiveSeccompPlanSchemaVersion ||
        plan->class_id != kSelectiveSeccompUnifiedClassId ||
        plan->rule_count > kMaxSelectiveSeccompRules) {
        return false;
    }

    size_t first = 0;
    size_t last = plan->rule_count;
    while (first < last) {
        const size_t middle = first + (last - first) / 2U;
        const int32_t candidate = plan->rules[middle].syscall_number;
        if (candidate < syscall_number) {
            first = middle + 1U;
        } else {
            last = middle;
        }
    }
    if (first >= plan->rule_count ||
        plan->rules[first].syscall_number != syscall_number ||
        plan->rules[first].class_id != plan->class_id) {
        return false;
    }
    *class_id = plan->rules[first].class_id;
    return true;
}

}  // namespace hookself::internal
