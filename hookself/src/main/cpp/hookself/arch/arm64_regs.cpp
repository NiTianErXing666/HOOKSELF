#include "arch/arm64_regs.h"

#include "platform/raw_syscall_arm64.h"

#include <errno.h>
#include <sys/uio.h>

namespace hookself {
namespace arch {
namespace {

constexpr long kPtraceGetRegSet = 0x4204;
constexpr long kPtraceSetRegSet = 0x4205;
constexpr uintptr_t kNtPrStatus = 1;
constexpr uintptr_t kNtArmSystemCall = 0x404;

}  // namespace

int ReadRegisters(pid_t tid, Arm64Regs* regs) noexcept {
    if (tid <= 0 || regs == nullptr) {
        return EINVAL;
    }

    iovec vector{regs, sizeof(*regs)};
    const long result = platform::RawPtrace(
            kPtraceGetRegSet, tid, kNtPrStatus,
            reinterpret_cast<uintptr_t>(&vector));
    const int error = platform::RawError(result);
    if (error != 0) {
        return error;
    }
    return vector.iov_len == sizeof(*regs) ? 0 : EIO;
}

int WriteRegisters(pid_t tid, const Arm64Regs* regs) noexcept {
    if (tid <= 0 || regs == nullptr) {
        return EINVAL;
    }

    iovec vector{const_cast<Arm64Regs*>(regs), sizeof(*regs)};
    const long result = platform::RawPtrace(
            kPtraceSetRegSet, tid, kNtPrStatus,
            reinterpret_cast<uintptr_t>(&vector));
    return platform::RawError(result);
}

int ReadSyscallNumber(pid_t tid, int32_t* syscall_number) noexcept {
    if (tid <= 0 || syscall_number == nullptr) {
        return EINVAL;
    }

    iovec vector{syscall_number, sizeof(*syscall_number)};
    const long result = platform::RawPtrace(
            kPtraceGetRegSet, tid, kNtArmSystemCall,
            reinterpret_cast<uintptr_t>(&vector));
    const int error = platform::RawError(result);
    if (error != 0) {
        return error;
    }
    return vector.iov_len == sizeof(*syscall_number) ? 0 : EIO;
}

int WriteSyscallNumber(pid_t tid, int32_t syscall_number) noexcept {
    if (tid <= 0) {
        return EINVAL;
    }

    iovec vector{&syscall_number, sizeof(syscall_number)};
    const long result = platform::RawPtrace(
            kPtraceSetRegSet, tid, kNtArmSystemCall,
            reinterpret_cast<uintptr_t>(&vector));
    return platform::RawError(result);
}

bool RegistersEqual(const Arm64Regs& expected, const Arm64Regs& actual) noexcept {
    for (size_t i = 0; i < kArm64GeneralRegisterCount; ++i) {
        if (expected.regs[i] != actual.regs[i]) {
            return false;
        }
    }
    return expected.sp == actual.sp && expected.pc == actual.pc &&
           expected.pstate == actual.pstate;
}

}  // namespace arch
}  // namespace hookself
