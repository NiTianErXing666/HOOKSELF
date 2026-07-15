#include "internal/selective_seccomp_filter.h"

#include <asm/unistd.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>

#include <climits>
#include <cstddef>
#include <cstring>

#include "platform/raw_syscall_arm64.h"

namespace hookself::internal {
namespace {

constexpr uint16_t kLoadAbsoluteWord = BPF_LD | BPF_W | BPF_ABS;
constexpr uint16_t kJumpEqualConstant = BPF_JMP | BPF_JEQ | BPF_K;
constexpr uint16_t kReturnConstant = BPF_RET | BPF_K;
constexpr uint32_t kAllowedInstallFlags =
        SECCOMP_FILTER_FLAG_TSYNC |
        SECCOMP_FILTER_FLAG_LOG |
        SECCOMP_FILTER_FLAG_SPEC_ALLOW |
        SECCOMP_FILTER_FLAG_TSYNC_ESRCH;

static_assert(sizeof(sock_filter) == 8U, "classic BPF instructions must be 8 bytes");
static_assert(kMaxSelectiveSeccompInstructions <= USHRT_MAX,
              "sock_fprog length must hold the generated program");
static_assert(offsetof(seccomp_data, nr) <= UINT32_MAX);
static_assert(offsetof(seccomp_data, arch) <= UINT32_MAX);

sock_filter Statement(uint16_t code, uint32_t value) noexcept {
    return sock_filter{code, 0, 0, value};
}

sock_filter Jump(uint16_t code, uint32_t value, uint8_t jump_true,
                 uint8_t jump_false) noexcept {
    return sock_filter{code, jump_true, jump_false, value};
}

bool IsValidArchMismatchAction(
        SelectiveSeccompArchMismatchAction action) noexcept {
    return action == SelectiveSeccompArchMismatchAction::kKillProcess ||
           action == SelectiveSeccompArchMismatchAction::kAllow;
}

bool SameInstruction(const sock_filter& left,
                     const sock_filter& right) noexcept {
    return left.code == right.code && left.jt == right.jt &&
           left.jf == right.jf && left.k == right.k;
}

int ValidateFilter(const SelectiveSeccompFilter& filter) noexcept {
    if (filter.rule_count > kMaxSelectiveSeccompRules ||
        filter.instruction_count !=
                kSelectiveSeccompBaseInstructionCount +
                        2U * static_cast<size_t>(filter.rule_count)) {
        return EINVAL;
    }

    const auto arch_action = static_cast<SelectiveSeccompArchMismatchAction>(
            filter.arch_mismatch_action);
    if (!IsValidArchMismatchAction(arch_action)) {
        return EINVAL;
    }

    const sock_filter expected_prefix[] = {
            Statement(kLoadAbsoluteWord,
                      static_cast<uint32_t>(offsetof(seccomp_data, arch))),
            Jump(kJumpEqualConstant, AUDIT_ARCH_AARCH64, 1, 0),
            Statement(kReturnConstant, filter.arch_mismatch_action),
            Statement(kLoadAbsoluteWord,
                      static_cast<uint32_t>(offsetof(seccomp_data, nr))),
    };
    for (size_t index = 0; index < sizeof(expected_prefix) / sizeof(expected_prefix[0]);
         ++index) {
        if (!SameInstruction(filter.instructions[index], expected_prefix[index])) {
            return EINVAL;
        }
    }

    for (size_t rule_index = 0; rule_index < filter.rule_count; ++rule_index) {
        const size_t instruction_index = 4U + 2U * rule_index;
        const sock_filter& comparison = filter.instructions[instruction_index];
        const sock_filter& result = filter.instructions[instruction_index + 1U];
        if (comparison.code != kJumpEqualConstant || comparison.jt != 0U ||
            comparison.jf != 1U || comparison.k > INT32_MAX ||
            result.code != kReturnConstant || result.jt != 0U ||
            result.jf != 0U ||
            (result.k & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_TRACE) {
            return EINVAL;
        }

        for (size_t previous = 0; previous < rule_index; ++previous) {
            if (filter.instructions[4U + 2U * previous].k == comparison.k) {
                return EEXIST;
            }
        }
    }

    const sock_filter expected_tail = Statement(kReturnConstant, SECCOMP_RET_ALLOW);
    if (!SameInstruction(filter.instructions[filter.instruction_count - 1U],
                         expected_tail)) {
        return EINVAL;
    }
    return 0;
}

}  // namespace

int BuildSelectiveSeccompFilter(
        const SelectiveSeccompRule* rules, size_t rule_count,
        SelectiveSeccompArchMismatchAction arch_mismatch_action,
        SelectiveSeccompFilter* output) noexcept {
    if (output == nullptr) {
        return EINVAL;
    }
    std::memset(output, 0, sizeof(*output));

    if (rule_count > kMaxSelectiveSeccompRules ||
        (rule_count != 0U && rules == nullptr) ||
        !IsValidArchMismatchAction(arch_mismatch_action)) {
        return EINVAL;
    }

    for (size_t index = 0; index < rule_count; ++index) {
        if (rules[index].syscall_number < 0) {
            return EINVAL;
        }
        for (size_t previous = 0; previous < index; ++previous) {
            if (rules[previous].syscall_number == rules[index].syscall_number) {
                return EEXIST;
            }
        }
    }

    SelectiveSeccompFilter candidate{};
    candidate.rule_count = static_cast<uint16_t>(rule_count);
    candidate.instruction_count = static_cast<uint16_t>(
            kSelectiveSeccompBaseInstructionCount + 2U * rule_count);
    candidate.arch_mismatch_action = static_cast<uint32_t>(arch_mismatch_action);

    size_t cursor = 0;
    candidate.instructions[cursor++] = Statement(
            kLoadAbsoluteWord,
            static_cast<uint32_t>(offsetof(seccomp_data, arch)));
    candidate.instructions[cursor++] = Jump(
            kJumpEqualConstant, AUDIT_ARCH_AARCH64, 1, 0);
    candidate.instructions[cursor++] = Statement(
            kReturnConstant, candidate.arch_mismatch_action);
    candidate.instructions[cursor++] = Statement(
            kLoadAbsoluteWord,
            static_cast<uint32_t>(offsetof(seccomp_data, nr)));

    for (size_t index = 0; index < rule_count; ++index) {
        candidate.instructions[cursor++] = Jump(
                kJumpEqualConstant,
                static_cast<uint32_t>(rules[index].syscall_number), 0, 1);
        candidate.instructions[cursor++] = Statement(
                kReturnConstant,
                SECCOMP_RET_TRACE | static_cast<uint32_t>(rules[index].class_id));
    }
    candidate.instructions[cursor++] = Statement(kReturnConstant, SECCOMP_RET_ALLOW);

    if (cursor != candidate.instruction_count) {
        return EIO;
    }
    const int validation_error = ValidateFilter(candidate);
    if (validation_error != 0) {
        return validation_error;
    }
    *output = candidate;
    return 0;
}

int InstallSelectiveSeccompFilter(const SelectiveSeccompFilter* filter,
                                  uint32_t flags,
                                  int32_t* failed_tid) noexcept {
    if (failed_tid != nullptr) {
        *failed_tid = 0;
    }
    if (filter == nullptr || (flags & ~kAllowedInstallFlags) != 0U ||
        ((flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH) != 0U &&
         (flags & SECCOMP_FILTER_FLAG_TSYNC) == 0U)) {
        return EINVAL;
    }

    const int validation_error = ValidateFilter(*filter);
    if (validation_error != 0) {
        return validation_error;
    }

    sock_fprog program{};
    program.len = filter->instruction_count;
    program.filter = const_cast<sock_filter*>(filter->instructions);
    const long result = platform::RawSyscall6(
            __NR_seccomp, SECCOMP_SET_MODE_FILTER, static_cast<long>(flags),
            reinterpret_cast<long>(&program));
    const int syscall_error = platform::RawError(result);
    if (syscall_error != 0) {
        return syscall_error;
    }
    if (result == 0) {
        return 0;
    }

    if ((flags & SECCOMP_FILTER_FLAG_TSYNC) != 0U &&
        result > 0 && result <= INT32_MAX) {
        if (failed_tid != nullptr) {
            *failed_tid = static_cast<int32_t>(result);
        }
        return EBUSY;
    }
    return EIO;
}

}  // namespace hookself::internal
