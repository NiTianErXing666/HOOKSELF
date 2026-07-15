#ifndef HOOKSELF_PLATFORM_PROCFS_H_
#define HOOKSELF_PLATFORM_PROCFS_H_

#if !defined(__aarch64__)
#error "hookself procfs support is currently arm64-only"
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

namespace hookself {
namespace platform {

constexpr size_t kTaskDirectoryPathCapacity = 64;
constexpr size_t kTaskDirectoryReadCapacity = 8192;
constexpr size_t kProcMetadataReadCapacity = 4096;

// Takes one unsorted snapshot of /proc/<target_pid>/task without allocation.
// Returns 0 on success or a positive errno on failure. On every return,
// *tid_count is the number of entries already stored. EOVERFLOW means the
// caller-provided array filled before the directory snapshot was complete.
int EnumerateTaskTids(pid_t target_pid, pid_t* tids, size_t capacity,
                      size_t* tid_count) noexcept;

// Reads field 22 (starttime, in clock ticks since boot) from /proc/<pid>/stat.
// The parser locates the final ')' before field 3, so spaces and ')' inside
// the comm field do not shift field numbering.
int ReadProcessStartTime(pid_t pid, uint64_t* start_time) noexcept;

// Reads the exact line-leading Tgid field from /proc/<tid>/status.
int ReadTaskTgid(pid_t tid, pid_t* tgid) noexcept;

}  // namespace platform
}  // namespace hookself

#endif  // HOOKSELF_PLATFORM_PROCFS_H_
