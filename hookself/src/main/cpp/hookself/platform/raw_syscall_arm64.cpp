#include "platform/raw_syscall_arm64.h"

#include <asm/unistd.h>
#include <errno.h>
#include <limits.h>

namespace hookself {
namespace platform {
namespace {

constexpr long kPtracePeekData = 2;

extern "C" long hookself_runtime_bypass_gettid() noexcept;
extern "C" char hookself_runtime_bypass_gettid_svc[];
extern "C" char hookself_runtime_bypass_gettid_after_svc[];

}  // namespace

static_assert(sizeof(long) == sizeof(uint64_t), "arm64 syscall words must be 64-bit");
static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "arm64 pointers must be 64-bit");

long RawSyscall6(long number, long arg0, long arg1, long arg2, long arg3,
                 long arg4, long arg5) noexcept {
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    register long x5 asm("x5") = arg5;
    register long x8 asm("x8") = number;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                 : "memory");
    return x0;
}

long RawRuntimeBypassGettid() noexcept {
    return hookself_runtime_bypass_gettid();
}

bool IsRuntimeBypassGettidInstructionPointer(uint64_t pc) noexcept {
    const uintptr_t first = reinterpret_cast<uintptr_t>(
            hookself_runtime_bypass_gettid_svc);
    const uintptr_t after = reinterpret_cast<uintptr_t>(
            hookself_runtime_bypass_gettid_after_svc);
    return pc >= first && pc <= after;
}

bool IsRawError(long result) noexcept {
    return result < 0 && result >= -4095;
}

int RawError(long result) noexcept {
    return IsRawError(result) ? static_cast<int>(-result) : 0;
}

long RawPtrace(long request, pid_t tid, uintptr_t address, uintptr_t data) noexcept {
    return RawSyscall6(__NR_ptrace, request, static_cast<long>(tid),
                       static_cast<long>(address), static_cast<long>(data));
}

int PtracePeekData(pid_t tid, uintptr_t address, uint64_t* value) noexcept {
    if (tid <= 0 || value == nullptr) {
        return EINVAL;
    }

    unsigned long output = 0;
    const long result = RawPtrace(kPtracePeekData, tid, address,
                                  reinterpret_cast<uintptr_t>(&output));
    const int error = RawError(result);
    if (error == 0) {
        *value = static_cast<uint64_t>(output);
    }
    return error;
}

long RawWait4(pid_t target, int* status, int options) noexcept {
    return RawSyscall6(__NR_wait4, static_cast<long>(target),
                       reinterpret_cast<long>(status), static_cast<long>(options), 0);
}

long RawRead(int fd, void* buffer, size_t size) noexcept {
    return RawSyscall6(__NR_read, fd, reinterpret_cast<long>(buffer),
                       static_cast<long>(size));
}

long RawWrite(int fd, const void* buffer, size_t size) noexcept {
    return RawSyscall6(__NR_write, fd, reinterpret_cast<long>(buffer),
                       static_cast<long>(size));
}

long RawOpenAt(int dirfd, const char* path, int flags, mode_t mode) noexcept {
    return RawSyscall6(__NR_openat, dirfd, reinterpret_cast<long>(path), flags,
                       static_cast<long>(mode));
}

long RawClose(int fd) noexcept {
    return RawSyscall6(__NR_close, fd);
}

long RawGetdents64(int fd, void* buffer, size_t size) noexcept {
    return RawSyscall6(__NR_getdents64, fd, reinterpret_cast<long>(buffer),
                       static_cast<long>(size));
}

long RawClockGettime(clockid_t clock_id, timespec* value) noexcept {
    return RawSyscall6(__NR_clock_gettime, static_cast<long>(clock_id),
                       reinterpret_cast<long>(value));
}

long RawNanosleep(const timespec* request, timespec* remaining) noexcept {
    return RawSyscall6(__NR_nanosleep, reinterpret_cast<long>(request),
                       reinterpret_cast<long>(remaining));
}

int MonotonicNowMilliseconds(int64_t* value_ms) noexcept {
    if (value_ms == nullptr) {
        return EINVAL;
    }

    timespec value{};
    const long result = RawClockGettime(CLOCK_MONOTONIC, &value);
    const int error = RawError(result);
    if (error != 0) {
        return error;
    }
    if (value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1000000000L) {
        return EIO;
    }
    if (value.tv_sec > (INT64_MAX - value.tv_nsec / 1000000L) / 1000) {
        return EOVERFLOW;
    }

    *value_ms = static_cast<int64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000L;
    return 0;
}

int SleepForNanoseconds(int64_t nanoseconds) noexcept {
    if (nanoseconds < 0) {
        return EINVAL;
    }

    timespec request{};
    request.tv_sec = static_cast<time_t>(nanoseconds / 1000000000LL);
    request.tv_nsec = static_cast<long>(nanoseconds % 1000000000LL);
    return RawError(RawNanosleep(&request));
}

int64_t RawNowMs() noexcept {
    int64_t value_ms = -1;
    return MonotonicNowMilliseconds(&value_ms) == 0 ? value_ms : -1;
}

void RawSleepOneMillisecond() noexcept {
    (void)SleepForNanoseconds(1000000);
}

bool IsStoppedStatus(int status) noexcept {
    return (status & 0xff) == 0x7f;
}

bool IsExitedStatus(int status) noexcept {
    return (status & 0x7f) == 0;
}

bool IsSignaledStatus(int status) noexcept {
    const int signal = status & 0x7f;
    return signal != 0 && signal != 0x7f;
}

int StopSignal(int status) noexcept {
    return (status >> 8) & 0xff;
}

unsigned int PtraceEvent(int status) noexcept {
    return static_cast<unsigned int>(status) >> 16;
}

[[noreturn]] void RawExit(int status) noexcept {
    (void)RawSyscall6(__NR_exit_group, status);
    __builtin_unreachable();
}

}  // namespace platform
}  // namespace hookself
