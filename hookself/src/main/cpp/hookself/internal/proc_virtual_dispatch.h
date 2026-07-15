#pragma once

#include <cstddef>
#include <cstdint>

#include "proc_virtual_view.h"

namespace hookself::internal {

constexpr uint32_t kProcVirtualDispatchTaskCapacity = 512U;
constexpr uint32_t kProcVirtualDispatchMagic = 0x48535056U; // HSPV
constexpr uint32_t kProcVirtualDispatchVersion = 1U;
constexpr uint32_t kProcVirtualDispatchMaxIov = 1024U;
constexpr uint32_t kProcVirtualDispatchMaxProtectedFds = 256U;
constexpr uint32_t kProcVirtualDispatchDefaultDirentReplays = 32U;
constexpr size_t kProcVirtualDispatchPathCapacity = 512U;
constexpr size_t kProcVirtualDispatchXattrNameCapacity =
        kProcVirtualXattrNameMax + 1U;
constexpr uint32_t kProcVirtualInvalidRule = UINT32_MAX;
constexpr uint32_t kProcVirtualInvalidArgument = UINT32_MAX;

struct ProcVirtualDispatchTask {
    uint32_t task_slot;
    int32_t tgid;
    int32_t tid;
    uint32_t reserved;
    uint64_t generation;
    uint64_t monotonic_time_ns;
};

enum class ProcVirtualIdentitySource : uint32_t {
    // The resident should answer this from its guest/host FD and pending-path
    // identity tables. ENOENT/ENODATA asks the dispatcher to try the fallback.
    kTrackedGuest = 1,
    // The resident may answer this with a lazy /proc/<tgid>/fd readlink or an
    // equivalent canonical-path resolver.
    kResolved = 2,
};

enum ProcVirtualIdentityQueryFlags : uint32_t {
    kProcVirtualIdentityNone = 0,
    kProcVirtualIdentityFd = 1U << 0,
    kProcVirtualIdentityRemotePath = 1U << 1,
};

struct ProcVirtualIdentityQuery {
    ProcVirtualDispatchTask task;
    ProcVirtualIdentitySource source;
    uint32_t flags;
    int32_t syscall_number;
    int32_t fd;
    uint32_t path_argument_index;
    uint32_t reserved;
    uintptr_t remote_path;
};

enum class ProcVirtualSnapshotKind : uint32_t {
    kProcText = 1,
    kXattrList = 2,
};

struct ProcVirtualSnapshotRequest {
    ProcVirtualDispatchTask task;
    ProcVirtualSnapshotKind kind;
    ProcVirtualNodeKind node;
    int32_t syscall_number;
    int32_t fd;
    uint64_t requested_offset;
    size_t requested_size;
    int64_t kernel_result;
    const char* identity_path;
    size_t identity_path_length;
};

using ProcVirtualReadRemote = int (*)(void* opaque, int32_t tgid, int32_t tid,
                                      uintptr_t remote_address,
                                      void* local_output, size_t size) noexcept;
using ProcVirtualWriteRemote = int (*)(void* opaque, int32_t tgid, int32_t tid,
                                       uintptr_t remote_address,
                                       const void* local_input,
                                       size_t size) noexcept;
using ProcVirtualResolveIdentity = int (*)(
        void* opaque, const ProcVirtualIdentityQuery* query, char* output,
        size_t output_capacity, size_t* output_length) noexcept;
// For kProcText, output contains the complete snapshot and logical_offset
// identifies the first byte requested in the rewritten view. Maps/smaps are
// raw provider text; smaps_rollup and attr/current are provider-synthesized
// visible text because a rollup cannot be filtered one mapping at a time.
// For pread64 logical_offset must equal requested_offset. For kXattrList the
// provider returns the exact NUL-separated backing list for a nonempty size
// query and logical_offset is zero.
using ProcVirtualSnapshotProvider =
        int (*)(void* opaque, const ProcVirtualSnapshotRequest* request,
                uint8_t* output, size_t output_capacity, size_t* output_size,
                uint64_t* logical_offset) noexcept;
using ProcVirtualProtectedFdSnapshot = int (*)(
        void* opaque, const ProcVirtualDispatchTask* task, int32_t* output,
        size_t output_capacity, size_t* output_count) noexcept;
using ProcVirtualWriteSyscallResult =
        int (*)(void* opaque, const ProcVirtualDispatchTask* task,
                int64_t result) noexcept;

struct ProcVirtualIo {
    void* opaque;
    ProcVirtualReadRemote read_remote;
    ProcVirtualWriteRemote write_remote;
    ProcVirtualResolveIdentity resolve_identity;
    ProcVirtualSnapshotProvider snapshot;
    ProcVirtualProtectedFdSnapshot snapshot_protected_fds;
    ProcVirtualWriteSyscallResult write_syscall_result;
};

enum ProcVirtualXattrRuleFlags : uint32_t {
    kProcVirtualXattrRuleNone = 0,
    // Without this flag path_prefix is a component-boundary prefix.
    kProcVirtualXattrRuleExactPath = 1U << 0,
    kProcVirtualXattrRuleFollowOnly = 1U << 1,
    kProcVirtualXattrRuleNoFollowOnly = 1U << 2,
    kProcVirtualXattrRuleFdOnly = 1U << 3,
    kProcVirtualXattrRulePathOnly = 1U << 4,
    // Suppress the backing getxattr-family syscall and always expose value.
    // Without this flag target/permission errors from the backing call win.
    kProcVirtualXattrRuleEmulate = 1U << 5,
};

constexpr uint32_t kProcVirtualXattrKnownRuleFlags =
        kProcVirtualXattrRuleExactPath | kProcVirtualXattrRuleFollowOnly |
        kProcVirtualXattrRuleNoFollowOnly | kProcVirtualXattrRuleFdOnly |
        kProcVirtualXattrRulePathOnly | kProcVirtualXattrRuleEmulate;

struct ProcVirtualXattrRule {
    const char* path_prefix;
    size_t path_prefix_length;
    const char* name;
    size_t name_length;
    const uint8_t* value;
    size_t value_size;
    int32_t priority;
    uint32_t flags;
};

struct ProcVirtualDispatchConfig {
    uint64_t generation;
    int32_t tracer_pid;
    uint32_t max_iov_count;
    uint32_t max_getdents_replays;
    uint32_t reserved;
    uint64_t getdents_replay_timeout_ns;
    const ProcVirtualAddressRange* hidden_ranges;
    size_t hidden_range_count;
    const ProcReversePathRule* reverse_rules;
    size_t reverse_rule_count;
    const int32_t* protected_fds;
    size_t protected_fd_count;
    const ProcVirtualXattrRule* xattr_rules;
    size_t xattr_rule_count;
    // Work buffers are shared by the single-threaded resident dispatcher.
    // They must be disjoint and remain valid for the dispatcher's lifetime.
    uint8_t* snapshot_buffer;
    size_t snapshot_capacity;
    uint8_t* rewrite_buffer;
    size_t rewrite_capacity;
};

enum ProcVirtualPendingFlags : uint32_t {
    kProcVirtualPendingNone = 0,
    kProcVirtualPendingActive = 1U << 0,
    kProcVirtualPendingProcText = 1U << 1,
    kProcVirtualPendingDirents = 1U << 2,
    kProcVirtualPendingXattrGet = 1U << 3,
    kProcVirtualPendingXattrList = 1U << 4,
    kProcVirtualPendingEmulated = 1U << 5,
};

struct ProcVirtualPending {
    uint32_t flags;
    uint32_t task_slot;
    int32_t tgid;
    int32_t tid;
    uint64_t task_generation;
    uint64_t config_generation;
    int32_t syscall_number;
    int32_t fd;
    ProcVirtualNodeKind node;
    uint32_t replay_count;
    uint64_t replay_deadline_ns;
    uint64_t arguments[6];
    uint32_t xattr_rule_index;
    uint32_t path_length;
    char identity_path[kProcVirtualDispatchPathCapacity];
};

struct ProcVirtualPendingTable {
    uint32_t magic;
    uint32_t version;
    uint32_t active_count;
    uint32_t reserved;
    uint64_t mutation_generation;
    uint64_t reserved64[3];
    ProcVirtualPending entries[kProcVirtualDispatchTaskCapacity];
};

enum ProcVirtualEntryFlags : uint32_t {
    kProcVirtualEntryNone = 0,
    kProcVirtualEntryHandled = 1U << 0,
    kProcVirtualEntryNeedsExit = 1U << 1,
    // The resident may replace this syscall with a harmless syscall. The
    // original user-visible result is produced by DispatchProcVirtualExit.
    kProcVirtualEntrySuppress = 1U << 2,
};

struct ProcVirtualEntryResult {
    uint32_t flags;
    ProcVirtualNodeKind node;
    uint32_t pending_slot;
    uint32_t reserved;
};

enum ProcVirtualExitFlags : uint32_t {
    kProcVirtualExitNone = 0,
    kProcVirtualExitHandled = 1U << 0,
    kProcVirtualExitWriteResult = 1U << 1,
    kProcVirtualExitResultWritten = 1U << 2,
    // Re-execute the same getdents64 without emitting a synthetic EOF. The
    // pending entry remains live; call only the exit dispatcher after replay.
    kProcVirtualExitReplay = 1U << 3,
    kProcVirtualExitOutputPatched = 1U << 4,
};

struct ProcVirtualExitResult {
    uint32_t flags;
    ProcVirtualNodeKind node;
    int64_t visible_result;
    int32_t replay_syscall_number;
    uint32_t replay_count;
    uint32_t instruction_rewind_bytes;
    uint32_t reserved;
    uint64_t replay_arguments[6];
    size_t bytes_read;
    size_t bytes_written;
    size_t records_seen;
    size_t records_hidden;
    size_t mappings_seen;
    size_t mappings_hidden;
    size_t paths_rewritten;
    size_t xattr_names_seen;
    size_t xattr_names_emitted;
};

static_assert(__is_standard_layout(ProcVirtualDispatchTask) &&
              __is_trivially_copyable(ProcVirtualDispatchTask));
static_assert(__is_standard_layout(ProcVirtualPending) &&
              __is_trivially_copyable(ProcVirtualPending));
static_assert(__is_standard_layout(ProcVirtualPendingTable) &&
              __is_trivially_copyable(ProcVirtualPendingTable));

void InitProcVirtualPendingTable(ProcVirtualPendingTable* table) noexcept;
bool IsProcVirtualPendingTableInitialized(
        const ProcVirtualPendingTable* table) noexcept;
bool ValidateProcVirtualPendingTable(
        const ProcVirtualPendingTable* table) noexcept;
int ClearProcVirtualPending(ProcVirtualPendingTable* table,
                            uint32_t task_slot) noexcept;

// All APIs return zero or a positive errno. A missing pending entry is a
// successful, unhandled exit. A stale slot/TID/generation returns ESTALE.
int DispatchProcVirtualEntry(const ProcVirtualDispatchConfig& config,
                             const ProcVirtualIo& io,
                             ProcVirtualPendingTable* table,
                             const ProcVirtualDispatchTask& task,
                             int32_t syscall_number,
                             const uint64_t arguments[6],
                             ProcVirtualEntryResult* result) noexcept;

int DispatchProcVirtualExit(const ProcVirtualDispatchConfig& config,
                            const ProcVirtualIo& io,
                            ProcVirtualPendingTable* table,
                            const ProcVirtualDispatchTask& task,
                            int64_t kernel_result,
                            ProcVirtualExitResult* result) noexcept;

} // namespace hookself::internal
