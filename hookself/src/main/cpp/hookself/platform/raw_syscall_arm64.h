#ifndef HOOKSELF_PLATFORM_RAW_SYSCALL_ARM64_H_
#define HOOKSELF_PLATFORM_RAW_SYSCALL_ARM64_H_

#if !defined(__aarch64__)
#error "hookself raw syscall support is currently arm64-only"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

namespace hookself {
namespace platform {

constexpr int kWaitWall = 0x40000000;

// Raw calls never read or write libc errno. They return the kernel ABI result:
// a non-negative success value, or -errno in the range [-4095, -1].
long RawSyscall6(long number, long arg0 = 0, long arg1 = 0, long arg2 = 0,
                 long arg3 = 0, long arg4 = 0, long arg5 = 0) noexcept;
// This dedicated gettid entry point lets the tracer recognize the API bypass
// claim before the caller has a TID registered in shared memory.
long RawRuntimeBypassGettid() noexcept;
bool IsRuntimeBypassGettidInstructionPointer(uint64_t pc) noexcept;
bool IsRawError(long result) noexcept;
int RawError(long result) noexcept;

long RawPtrace(long request, pid_t tid, uintptr_t address = 0,
               uintptr_t data = 0) noexcept;
int PtracePeekData(pid_t tid, uintptr_t address, uint64_t* value) noexcept;
long RawWait4(pid_t target, int* status, int options) noexcept;
long RawRead(int fd, void* buffer, size_t size) noexcept;
long RawWrite(int fd, const void* buffer, size_t size) noexcept;
long RawOpenAt(int dirfd, const char* path, int flags, mode_t mode = 0) noexcept;
long RawClose(int fd) noexcept;
long RawGetdents64(int fd, void* buffer, size_t size) noexcept;
long RawClockGettime(clockid_t clock_id, timespec* value) noexcept;
long RawNanosleep(const timespec* request, timespec* remaining = nullptr) noexcept;

// Checked helpers return 0 on success or a positive errno on failure.
int MonotonicNowMilliseconds(int64_t* value_ms) noexcept;
int SleepForNanoseconds(int64_t nanoseconds) noexcept;

// Compatibility helpers preserve the current probe contract: RawNowMs returns
// -1 for any clock error, and the sleep helper intentionally ignores EINTR.
int64_t RawNowMs() noexcept;
void RawSleepOneMillisecond() noexcept;

bool IsStoppedStatus(int status) noexcept;
bool IsExitedStatus(int status) noexcept;
bool IsSignaledStatus(int status) noexcept;
int StopSignal(int status) noexcept;
unsigned int PtraceEvent(int status) noexcept;

// Terminates the whole raw tracer process with exit_group(2).
[[noreturn]] void RawExit(int status) noexcept;

}  // namespace platform
}  // namespace hookself

#endif  // HOOKSELF_PLATFORM_RAW_SYSCALL_ARM64_H_
