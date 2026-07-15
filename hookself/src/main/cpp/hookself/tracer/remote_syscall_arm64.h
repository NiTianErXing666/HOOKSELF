#pragma once

#include <cstdint>
#include <sys/types.h>

namespace hookself::tracer {

struct RemoteSyscallArm64Result {
    int64_t value;
    uint32_t seccomp_stops;
    uint32_t reserved;
};

// Executes one syscall while tid is in a ptrace stop. The helper temporarily
// installs `svc; brk` at the saved PC, consumes only stops for tid, then
// restores both code and registers. It returns zero or a positive errno and
// leaves the task stopped on every recoverable path.
int InvokeStoppedArm64Syscall(
        pid_t tid, int32_t syscall_number, const uint64_t arguments[6],
        RemoteSyscallArm64Result* result) noexcept;

}  // namespace hookself::tracer
