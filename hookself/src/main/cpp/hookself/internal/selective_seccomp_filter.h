#pragma once

#if !defined(__aarch64__)
#error "hookself selective seccomp support is currently arm64-only"
#endif

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <cstddef>
#include <cstdint>

namespace hookself::internal {

constexpr size_t kMaxSelectiveSeccompRules = 192U;
constexpr size_t kSelectiveSeccompBaseInstructionCount = 5U;
constexpr size_t kMaxSelectiveSeccompInstructions =
        kSelectiveSeccompBaseInstructionCount + 2U * kMaxSelectiveSeccompRules;

struct SelectiveSeccompRule {
    int32_t syscall_number;
    uint16_t class_id;
};

enum class SelectiveSeccompArchMismatchAction : uint32_t {
    kKillProcess = SECCOMP_RET_KILL_PROCESS,
    kAllow = SECCOMP_RET_ALLOW,
};

// Owns the cBPF instruction storage. No sock_fprog pointer is retained, so the
// value remains valid after copying or moving it.
struct SelectiveSeccompFilter {
    sock_filter instructions[kMaxSelectiveSeccompInstructions];
    uint16_t instruction_count;
    uint16_t rule_count;
    uint32_t arch_mismatch_action;
};

// Builds an arm64 seccomp filter. A matching syscall returns
// SECCOMP_RET_TRACE | class_id; every unmatched syscall returns ALLOW.
// Zero rules are valid and produce an allow-only arm64 filter. Duplicate
// syscall numbers are rejected even when their class IDs are equal.
//
// Returns 0 on success or a positive errno on failure. If output is non-null,
// it is cleared before validation and remains cleared on every failure.
int BuildSelectiveSeccompFilter(
        const SelectiveSeccompRule* rules, size_t rule_count,
        SelectiveSeccompArchMismatchAction arch_mismatch_action,
        SelectiveSeccompFilter* output) noexcept;

// Installs a filter with the raw seccomp(2) syscall. Supported flags are
// TSYNC, LOG, SPEC_ALLOW and TSYNC_ESRCH; NEW_LISTENER is deliberately excluded
// because its successful return value is a file descriptor rather than zero.
// The caller must arrange no_new_privs or an appropriate capability first.
//
// Returns 0 on success or a positive errno on failure. A positive kernel return
// from a TSYNC operation is reported as EBUSY and copied to failed_tid. On all
// other returns failed_tid is zero when that pointer is supplied.
int InstallSelectiveSeccompFilter(const SelectiveSeccompFilter* filter,
                                  uint32_t flags,
                                  int32_t* failed_tid = nullptr) noexcept;

}  // namespace hookself::internal
