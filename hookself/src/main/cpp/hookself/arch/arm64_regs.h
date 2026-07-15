#ifndef HOOKSELF_ARCH_ARM64_REGS_H_
#define HOOKSELF_ARCH_ARM64_REGS_H_

#if !defined(__aarch64__)
#error "hookself register support is currently arm64-only"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

namespace hookself {
namespace arch {

constexpr size_t kArm64GeneralRegisterCount = 31;

struct Arm64Regs {
    uint64_t regs[kArm64GeneralRegisterCount];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static_assert(sizeof(Arm64Regs) == 272, "unexpected arm64 NT_PRSTATUS layout");

// These helpers return 0 on success or a positive errno on failure. They do
// not read or write libc errno and do not allocate.
int ReadRegisters(pid_t tid, Arm64Regs* regs) noexcept;
int WriteRegisters(pid_t tid, const Arm64Regs* regs) noexcept;
int ReadSyscallNumber(pid_t tid, int32_t* syscall_number) noexcept;
int WriteSyscallNumber(pid_t tid, int32_t syscall_number) noexcept;

bool RegistersEqual(const Arm64Regs& expected, const Arm64Regs& actual) noexcept;

}  // namespace arch
}  // namespace hookself

#endif  // HOOKSELF_ARCH_ARM64_REGS_H_
