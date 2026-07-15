#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "event_ring.h"
#include "hookself/public_api.h"
#include "internal/fd_identity.h"

namespace hookself::internal {

constexpr uint32_t kSharedMagic = 0x48535341U;  // HSSA
constexpr uint32_t kSharedAbiVersion = 12U;
constexpr uint32_t kSharedArchArm64 = 1U;
constexpr uint32_t kMaxTrackedTasks = 512U;
constexpr uint32_t kScratchPathSlots = 2U;
constexpr uint32_t kScratchAuxCapacity = 256U;
constexpr uint64_t kScratchGuardBefore = 0x4853534352415441ULL;
constexpr uint64_t kScratchGuardAfter = 0x4853534352415442ULL;
constexpr uint32_t kMaxProtectedFds = 160U;
constexpr uint32_t kMaxRuntimeApiBypassSlots = 64U;
constexpr uint32_t kReservedDestroyBypassSlots = 1U;

enum class SharedFdOperationState : uint32_t {
    kIdle = 0,
    kPending = 1,
    kInFlight = 2,
    kComplete = 3,
};

enum class SharedFdOperationCode : int32_t {
    kNone = 0,
    kDup3Replace = 1,
};

enum SharedCloseRangeCapabilities : uint32_t {
    kCloseRangeCapabilityNone = 0,
    kCloseRangeCapabilitySyscall = 1U << 0,
    kCloseRangeCapabilityCloexec = 1U << 1,
    kCloseRangeCapabilityUnshare = 1U << 2,
};

struct alignas(64) SharedFdOperation {
    alignas(8) uint64_t request_sequence;
    alignas(8) uint64_t ack_sequence;
    alignas(8) int64_t result;
    int32_t owner_tid;
    int32_t opcode;
    int32_t source_fd;
    int32_t target_fd;
    uint32_t flags;
    uint32_t state;
    uint64_t reserved[2];
};

enum class SharedCommand : uint64_t {
    kNone = 0,
    kStop = 1,
    kResume = 4,
    kTeardownFreeze = 5,
};

enum class SharedSelectiveInstallState : uint32_t {
    kDisabled = 0,
    kPlanReady = 1,
    kWorldStopped = 2,
    kInstallerRunning = 3,
    kInstallSucceeded = 4,
    kInstallFailed = 5,
    kCommitted = 6,
    kAbortedPrecommit = 7,
    kAmbiguousFatal = 8,
};

struct alignas(64) SharedSelectiveInstall {
    alignas(8) uint64_t sequence;
    alignas(8) uint64_t response_sequence;
    alignas(8) uint64_t ack_sequence;
    alignas(8) uint64_t plan_hash;
    alignas(8) uint64_t rule_generation;
    int32_t installer_tid;
    uint32_t state;
    uint32_t instruction_count;
    uint32_t rule_count;
    uint32_t prepared_tid_count;
    uint32_t verified_tid_count;
    int32_t nnp_before;
    int32_t nnp_errno;
    int32_t install_errno;
    int32_t failed_tid;
    uint32_t filter_committed;
    uint32_t policy_enabled;
    uint64_t reserved[4];
};

struct SharedRegion {
    uint64_t offset;
    uint64_t size;
};

struct SharedStringRef {
    uint32_t offset;
    uint32_t length;
};

struct alignas(64) SharedHeader {
    uint32_t magic;
    uint32_t abi_version;
    uint32_t header_size;
    uint32_t arch;
    uint32_t page_size;
    uint32_t total_size;
    int32_t target_pid;
    int32_t bootstrap_tid;
    uint64_t nonce;
    uint64_t target_start_time;
    uint64_t tracee_scratch_address;
    SharedRegion control;
    SharedRegion event_ring;
    SharedRegion rule_banks[2];
    SharedRegion scratch;
    uint64_t reserved[8];
};

struct alignas(64) SharedControlPage {
    alignas(8) uint64_t parent_command_sequence;
    alignas(8) uint64_t parent_command;
    alignas(8) uint64_t tracer_ack_sequence;
    alignas(8) uint64_t tracer_state;
    alignas(8) uint64_t tracer_heartbeat_ns;
    alignas(8) uint64_t active_rule_bank;
    alignas(8) uint64_t published_generation;
    alignas(8) uint64_t applied_generation;
    alignas(8) uint64_t retired_generation;
    int32_t fatal_code;
    int32_t fatal_errno;
    int32_t fatal_tid;
    uint32_t flags;
    uint32_t config_flags;
    int32_t failure_mode;
    int32_t log_level;
    int32_t backend;
    uint32_t tracked_tasks;
    alignas(8) uint64_t observed_syscalls;
    alignas(8) uint64_t redirected_paths;
    alignas(8) uint64_t virtual_file_opens;
    alignas(8) uint64_t internal_errors;
    alignas(8) uint64_t protected_fd_blocks;
    alignas(8) uint64_t internal_fd_operations;
    alignas(8) uint64_t ptrace_view_operations;
    alignas(8) uint64_t proc_status_patches;
    int32_t ptrace_view_dumpable;
    int32_t ptrace_view_ptracer;
    uint32_t ptrace_view_flags;
    uint32_t ptrace_view_reserved;
    alignas(8) uint64_t ptrace_view_ptracer_start_time;
    uint32_t protected_fd_count;
    uint32_t close_range_capabilities;
    alignas(8) uint64_t protected_fd_registry_generation;
    int32_t internal_bypass_tid;
    int32_t internal_bypass_fd;
    uint32_t internal_bypass_active;
    uint32_t log_bypass_active;
    int32_t log_bypass_tid;
    int32_t log_bypass_reserved;
    int32_t teardown_bypass_tid;
    int32_t teardown_bypass_fd;
    uint32_t teardown_bypass_active;
    uint32_t teardown_frozen;
    uint32_t teardown_release;
    int32_t runtime_api_bypass_tids[kMaxRuntimeApiBypassSlots];
    int32_t protected_fds[kMaxProtectedFds];
    SharedFdOperation fd_operation;
    SharedSelectiveInstall selective_install;
    uint64_t reserved[6];
};

// A descriptor number can be removed and later reused for another object.
// The tracer uses this generation to discard cached identities only when the
// registry itself changes, rather than accepting a replacement of a still
// registered protected descriptor.
inline void PublishProtectedFdRegistryMutation(
        SharedControlPage* control) noexcept {
    if (control == nullptr) {
        return;
    }
    const uint64_t generation = __atomic_add_fetch(
            &control->protected_fd_registry_generation, 1U,
            __ATOMIC_RELEASE);
    if (generation == 0U) {
        __atomic_store_n(&control->protected_fd_registry_generation, 1U,
                         __ATOMIC_RELEASE);
    }
}

struct SharedPathRuleDesc {
    uint32_t rule_id;
    int32_t priority;
    int32_t action;
    uint32_t operation_mask;
    uint32_t flags;
    int32_t deny_errno;
    SharedStringRef guest_prefix;
    SharedStringRef host_prefix;
};

struct SharedSyscallRuleDesc {
    uint32_t rule_id;
    int32_t syscall_number;
    int32_t action;
    uint32_t phase_mask;
    uint32_t argument_index;
    uint64_t argument_match_mask;
    uint64_t argument_match_value;
    uint64_t replacement_value;
    int32_t replacement_syscall_number;
    int32_t deny_errno;
    uint32_t flags;
    uint32_t reserved;
};

struct SharedVirtualFileDesc {
    uint32_t file_id;
    int32_t provider;
    uint32_t mode;
    uint32_t flags;
    int32_t target_fd;
    uint32_t reserved;
    SharedStringRef guest_path;
    SharedStringRef backing_path;
};

struct alignas(64) SharedRuleBankHeader {
    uint64_t generation;
    uint64_t checksum;
    uint32_t bank_size;
    uint32_t path_rule_count;
    uint32_t syscall_rule_count;
    uint32_t virtual_file_count;
    uint32_t path_rules_offset;
    uint32_t syscall_rules_offset;
    uint32_t virtual_files_offset;
    uint32_t arena_offset;
    uint32_t arena_capacity;
    uint32_t arena_used;
    uint32_t reserved32[4];
    uint64_t reserved64[4];
};

struct alignas(64) SharedScratchFrame {
    uint64_t guard_before;
    int32_t owner_tid;
    uint32_t state;
    uint64_t generation;
    uint32_t path_lengths[kScratchPathSlots];
    uint32_t aux_length;
    uint32_t reserved;
    char paths[kScratchPathSlots][HOOKSELF_PATH_CAPACITY];
    uint8_t auxiliary[kScratchAuxCapacity];
    uint64_t guard_after;
};

struct SharedSessionMapping {
    int fd = -1;
    void* prefix_mapping = nullptr;
    size_t prefix_size = 0;
    void* tracee_scratch_mapping = nullptr;
    size_t scratch_size = 0;
    size_t total_size = 0;
    FdObjectIdentity fd_identity{};
};

static_assert(std::is_standard_layout_v<SharedHeader> &&
              std::is_trivially_copyable_v<SharedHeader>);
static_assert(std::is_standard_layout_v<SharedControlPage> &&
              std::is_trivially_copyable_v<SharedControlPage>);
static_assert(std::is_standard_layout_v<SharedRuleBankHeader> &&
              std::is_trivially_copyable_v<SharedRuleBankHeader>);
static_assert(std::is_standard_layout_v<SharedScratchFrame> &&
              std::is_trivially_copyable_v<SharedScratchFrame>);
static_assert(std::is_standard_layout_v<SharedFdOperation> &&
              std::is_trivially_copyable_v<SharedFdOperation>);
static_assert(std::is_standard_layout_v<SharedSelectiveInstall> &&
              std::is_trivially_copyable_v<SharedSelectiveInstall>);
static_assert(sizeof(SharedControlPage) <= 4096U);
static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
              "Shared ABI requires lock-free 64-bit atomics");

size_t SharedRuleBankBytes();
size_t SharedScratchBytes();
int32_t CreateSharedSession(const HookselfConfig& config, int32_t target_pid,
                            int32_t bootstrap_tid, uint64_t target_start_time,
                            uint64_t nonce, SharedSessionMapping* mapping,
                            const int32_t* virtual_file_fds = nullptr,
                            const char* const* virtual_file_paths = nullptr);
int32_t PublishSharedConfig(const HookselfConfig& config,
                            SharedSessionMapping* mapping,
                            const int32_t* virtual_file_fds = nullptr,
                            const char* const* virtual_file_paths = nullptr);
void DestroySharedSession(SharedSessionMapping* mapping);

SharedHeader* GetSharedHeader(const SharedSessionMapping& mapping);
SharedControlPage* GetSharedControl(const SharedSessionMapping& mapping);
EventRingHeader* GetSharedEventRing(const SharedSessionMapping& mapping);
SharedRuleBankHeader* GetSharedRuleBank(const SharedSessionMapping& mapping,
                                        uint32_t bank_index);
bool ValidateSharedSession(const SharedSessionMapping& mapping);
int32_t SetProtectedFdRegistry(SharedSessionMapping* mapping,
                               const int32_t* fds, uint32_t count);
int32_t AppendProtectedFd(SharedSessionMapping* mapping, int32_t fd);

}  // namespace hookself::internal
