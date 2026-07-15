#pragma once

#include <stdint.h>

#include "hookself/public_api.h"

namespace hookself::tracer {

// Path state is deliberately fixed-capacity. The resident tracer creates the
// whole table before it starts dispatching syscalls and none of these APIs
// allocate memory.
constexpr uint32_t kPathStateTaskCapacity = 512U;
constexpr uint32_t kPathStateFsContextCapacity = 512U;
constexpr uint32_t kPathStateFdTableCapacity = 512U;
constexpr uint32_t kPathStateFdIdentityCapacity = 4096U;
constexpr uint32_t kPathStateMountNamespaceCapacity = 512U;
constexpr uint32_t kPathStateMountBindingCapacity = 1024U;
constexpr uint32_t kPathStateMountTreeCapacity = 512U;
constexpr uint32_t kInvalidPathStateSlot = UINT32_MAX;
constexpr uint32_t kPathStateMagic = 0x48535053U;  // HSPS
constexpr uint32_t kPathStateVersion = 3U;

// Linux UAPI values. Keeping these local avoids depending on the NDK version
// used to compile the tracer.
constexpr uint64_t kPathCloneFs = 0x00000200ULL;
constexpr uint64_t kPathCloneFiles = 0x00000400ULL;
constexpr uint64_t kPathCloneNewns = 0x00020000ULL;
constexpr uint32_t kPathCloseRangeUnshare = 1U << 1;
constexpr uint32_t kPathCloseRangeCloexec = 1U << 2;

enum PathOriginFlags : uint32_t {
    kPathOriginNone = 0,
    kPathOriginGuestValid = 1U << 0,
    kPathOriginHostValid = 1U << 1,
    kPathOriginRedirected = 1U << 2,
    kPathOriginReverseVisible = 1U << 3,
    kPathOriginDeleted = 1U << 4,
    kPathOriginAmbiguous = 1U << 5,
    kPathOriginProtected = 1U << 6,
};

constexpr uint32_t kPathOriginKnownFlags =
        kPathOriginGuestValid | kPathOriginHostValid |
        kPathOriginRedirected | kPathOriginReverseVisible |
        kPathOriginDeleted | kPathOriginAmbiguous |
        kPathOriginProtected;

struct PathTaskState {
    uint32_t occupied;
    uint32_t slot;
    int32_t tid;
    uint32_t reserved;
    uint32_t fs_context_slot;
    uint32_t fd_table_slot;
    uint32_t mount_namespace_slot;
    uint32_t reserved2;
    uint64_t identity_generation;
};

// A FileSystemNameSpace equivalent for the state needed by path translation.
// Tasks created with CLONE_FS reference the same slot; other clones get a
// value copy. Updating cwd through a shared slot is therefore immediately
// visible to every sharing task.
struct FsContext {
    uint32_t occupied;
    uint32_t slot;
    uint32_t refcount;
    uint32_t cwd_origin_flags;
    uint64_t generation;
    uint64_t cwd_device;
    uint64_t cwd_inode;
    uint64_t cwd_mount_id;
    char guest_cwd[HOOKSELF_PATH_CAPACITY];
    char host_cwd[HOOKSELF_PATH_CAPACITY];
    uint32_t root_origin_flags;
    uint32_t reserved;
    uint64_t root_device;
    uint64_t root_inode;
    uint64_t root_mount_id;
    char guest_root[HOOKSELF_PATH_CAPACITY];
    char host_root[HOOKSELF_PATH_CAPACITY];
};

// FdIdentity entries are sparse and owned by one FdTable slot. A table is
// shared for CLONE_FILES and deep-copied otherwise. Only descriptors relevant
// to path identity need to be recorded.
struct FdTable {
    uint32_t occupied;
    uint32_t slot;
    uint32_t refcount;
    uint32_t entry_count;
    uint32_t protected_count;
    uint32_t reserved;
    uint64_t generation;
};

struct FdIdentity {
    uint32_t occupied;
    uint32_t slot;
    uint32_t fd_table_slot;
    int32_t fd;
    uint32_t origin_flags;
    uint32_t directory;
    uint32_t cloexec;
    uint32_t reserved;
    uint64_t device;
    uint64_t inode;
    uint32_t mount_namespace_slot;
    uint32_t reserved2;
    uint64_t mount_namespace_identity;
    uint64_t mount_namespace_generation;
    uint32_t object_kind;
    uint32_t object_flags;
    uint32_t object_slot;
    uint32_t reserved3;
    uint64_t object_generation;
    char guest_path[HOOKSELF_PATH_CAPACITY];
    char host_path[HOOKSELF_PATH_CAPACITY];
};

// Input form for RecordFd. A path pointer may be null only when its matching
// valid flag is clear. Strings must terminate within HOOKSELF_PATH_CAPACITY.
struct FdIdentitySpec {
    uint32_t origin_flags;
    uint32_t directory;
    uint32_t cloexec;
    uint32_t reserved;
    uint64_t device;
    uint64_t inode;
    const char* guest_path;
    const char* host_path;
};

typedef enum MountBindingKind : uint32_t {
    kMountBindingBind = 1,
    kMountBindingTree = 2,
    kMountBindingSynthetic = 3,
    kMountBindingRoot = 4,
} MountBindingKind;

enum MountBindingStateFlags : uint32_t {
    kMountBindingStateNone = 0,
    kMountBindingStateRuntime = 1U << 0,
    kMountBindingStateReverseVisible = 1U << 1,
    kMountBindingStateRecursive = 1U << 2,
    kMountBindingStateDetached = 1U << 3,
};

constexpr uint32_t kMountBindingStateKnownFlags =
        kMountBindingStateRuntime | kMountBindingStateReverseVisible |
        kMountBindingStateRecursive | kMountBindingStateDetached;

enum MountRemoveFlags : uint32_t {
    kMountRemoveNone = 0,
    kMountRemoveSubtree = 1U << 0,
    kMountRemoveDetached = 1U << 1,
};

constexpr uint32_t kMountRemoveKnownFlags =
        kMountRemoveSubtree | kMountRemoveDetached;

typedef enum FdIdentityObjectKind : uint32_t {
    kFdIdentityObjectNone = 0,
    kFdIdentityObjectMountTree = 1,
} FdIdentityObjectKind;

enum MountTreeStateFlags : uint32_t {
    kMountTreeStateNone = 0,
    kMountTreeStateClone = 1U << 0,
    kMountTreeStateDetached = 1U << 1,
    kMountTreeStateAttached = 1U << 2,
};

constexpr uint32_t kMountTreeStateKnownFlags =
        kMountTreeStateClone | kMountTreeStateDetached |
        kMountTreeStateAttached;

struct MountNamespaceState {
    uint32_t occupied;
    uint32_t slot;
    uint32_t refcount;
    uint32_t binding_count;
    uint32_t task_refcount;
    uint32_t handle_refcount;
    uint64_t generation;
    uint64_t identity_generation;
    uint64_t root_mount_id;
    uint64_t root_mount_flags;
    uint64_t root_mount_attributes;
    uint64_t root_propagation;
    uint32_t root_origin_flags;
    uint32_t reserved;
    char root_source_guest[HOOKSELF_PATH_CAPACITY];
    char root_source_host[HOOKSELF_PATH_CAPACITY];
};

// Each binding maps a visible namespace target prefix to a resolved source
// identity. Newer sequence values stack above older mounts at the same target.
struct MountBindingState {
    uint32_t occupied;
    uint32_t slot;
    uint32_t mount_namespace_slot;
    uint32_t kind;
    uint32_t state_flags;
    uint32_t reserved;
    uint64_t mount_id;
    uint64_t parent_mount_id;
    uint64_t sequence;
    uint64_t mount_flags;
    uint64_t mount_attributes;
    uint64_t propagation;
    char target_guest[HOOKSELF_PATH_CAPACITY];
    char source_guest[HOOKSELF_PATH_CAPACITY];
    char source_host[HOOKSELF_PATH_CAPACITY];
};

struct MountTreeState {
    uint32_t occupied;
    uint32_t slot;
    uint32_t refcount;
    uint32_t state_flags;
    uint32_t mount_namespace_slot;
    uint32_t reserved;
    uint64_t generation;
    uint64_t handle_id;
    uint64_t source_mount_id;
    uint32_t attached_namespace_slot;
    uint32_t reserved2;
    uint64_t attached_mount_id;
    char source_guest[HOOKSELF_PATH_CAPACITY];
    char source_host[HOOKSELF_PATH_CAPACITY];
    char attached_target_guest[HOOKSELF_PATH_CAPACITY];
};

struct MountBindingSpec {
    uint32_t kind;
    uint32_t state_flags;
    uint64_t parent_mount_id;
    uint64_t mount_flags;
    uint64_t mount_attributes;
    uint64_t propagation;
    const char* target_guest;
    const char* source_guest;
    const char* source_host;
};

struct MountPathTranslation {
    uint32_t matched;
    uint32_t binding_slot;
    uint32_t kind;
    uint32_t state_flags;
    uint64_t mount_id;
    uint64_t namespace_generation;
    uint64_t binding_sequence;
    uint64_t mount_flags;
    uint64_t mount_attributes;
    char guest_path[HOOKSELF_PATH_CAPACITY];
    char host_path[HOOKSELF_PATH_CAPACITY];
};

enum FdIdentityViewFlags : uint32_t {
    kFdIdentityViewNone = 0,
    kFdIdentityViewNamespaceChanged = 1U << 0,
    kFdIdentityViewNamespaceMutated = 1U << 1,
    kFdIdentityViewMountTranslated = 1U << 2,
    kFdIdentityViewCapturedFallback = 1U << 3,
};

constexpr uint32_t kFdIdentityViewKnownFlags =
        kFdIdentityViewNamespaceChanged |
        kFdIdentityViewNamespaceMutated |
        kFdIdentityViewMountTranslated |
        kFdIdentityViewCapturedFallback;

// A task-relative view of an fd identity. The stored identity belongs to the
// shared FD table, while this result is resolved against the caller's current
// mount namespace without mutating that shared table.
struct FdIdentityView {
    uint32_t flags;
    uint32_t origin_flags;
    uint64_t namespace_identity;
    uint64_t namespace_generation;
    uint64_t mount_id;
    char guest_path[HOOKSELF_PATH_CAPACITY];
    char host_path[HOOKSELF_PATH_CAPACITY];
};

struct PathStateTable {
    uint32_t magic;
    uint32_t version;
    uint32_t task_count;
    uint32_t fs_context_count;
    uint32_t fd_table_count;
    uint32_t fd_identity_count;
    uint32_t mount_namespace_count;
    uint32_t mount_binding_count;
    uint32_t mount_tree_count;
    uint32_t reserved_count;
    uint32_t task_free_hint;
    uint32_t fs_context_free_hint;
    uint32_t fd_table_free_hint;
    uint32_t fd_identity_free_hint;
    uint32_t mount_namespace_free_hint;
    uint32_t mount_binding_free_hint;
    uint32_t mount_tree_free_hint;
    uint32_t reserved_hint;
    uint64_t mutation_generation;
    uint64_t reserved[3];
    PathTaskState tasks[kPathStateTaskCapacity];
    FsContext fs_contexts[kPathStateFsContextCapacity];
    FdTable fd_tables[kPathStateFdTableCapacity];
    FdIdentity fd_identities[kPathStateFdIdentityCapacity];
    MountNamespaceState mount_namespaces[
            kPathStateMountNamespaceCapacity];
    MountBindingState mount_bindings[kPathStateMountBindingCapacity];
    MountTreeState mount_trees[kPathStateMountTreeCapacity];
};

static_assert(__is_standard_layout(PathTaskState) &&
              __is_trivially_copyable(PathTaskState));
static_assert(__is_standard_layout(FsContext) &&
              __is_trivially_copyable(FsContext));
static_assert(__is_standard_layout(FdTable) &&
              __is_trivially_copyable(FdTable));
static_assert(__is_standard_layout(FdIdentity) &&
              __is_trivially_copyable(FdIdentity));
static_assert(__is_standard_layout(MountNamespaceState) &&
              __is_trivially_copyable(MountNamespaceState));
static_assert(__is_standard_layout(MountBindingState) &&
              __is_trivially_copyable(MountBindingState));
static_assert(__is_standard_layout(MountTreeState) &&
              __is_trivially_copyable(MountTreeState));
static_assert(__is_standard_layout(FdIdentityView) &&
              __is_trivially_copyable(FdIdentityView));
static_assert(__is_standard_layout(PathStateTable) &&
              __is_trivially_copyable(PathStateTable));

void InitPathState(PathStateTable* table) noexcept;
bool IsPathStateInitialized(const PathStateTable* table) noexcept;

// Performs a full structural audit: slot/count consistency, unique tids,
// unique (FdTable, fd) pairs, exact reference counts, and exact entry counts.
bool ValidatePathState(const PathStateTable* table) noexcept;

PathTaskState* FindPathTask(PathStateTable* table, int32_t tid) noexcept;
const PathTaskState* FindPathTask(const PathStateTable* table,
                                  int32_t tid) noexcept;
const FsContext* GetTaskFsContext(const PathStateTable* table,
                                  int32_t tid) noexcept;
const MountNamespaceState* GetTaskMountNamespace(
        const PathStateTable* table, int32_t tid) noexcept;

// Creates the first independent FsContext and FdTable for tid. Both cwd paths
// must be non-empty absolute paths. Returns EEXIST for an existing tid.
int InsertInitialPathTask(PathStateTable* table, int32_t tid,
                          const char* guest_cwd,
                          const char* host_cwd) noexcept;

// Inherits parent state. CLONE_FS/CLONE_FILES share the corresponding object;
// without those flags a fixed-capacity value copy is created transactionally.
int ClonePathTask(PathStateTable* table, int32_t parent_tid,
                  int32_t child_tid, uint64_t clone_flags) noexcept;

// Drops the task and releases its referenced objects. The final FdTable
// release also removes every sparse FdIdentity owned by that table.
int RemovePathTask(PathStateTable* table, int32_t tid) noexcept;

// Handles the Linux de-thread rename performed when a non-leader execs. State
// from former_tid wins; an existing new_tid record is released first. The
// surviving slot receives a new identity generation.
int MigrateExecPathTask(PathStateTable* table, int32_t former_tid,
                        int32_t new_tid) noexcept;

// Models exec's CLONE_FS/CLONE_FILES unshare and close-on-exec sweep. Shared
// objects are copied transactionally; the new descriptor table omits CLOEXEC
// entries before the task references change.
int ExecPathTask(PathStateTable* table, int32_t tid) noexcept;

// Models the CLONE_FS and CLONE_FILES portions of unshare(2). Other flag bits
// are ignored by this path-only state layer. Both requested copies commit as
// one transaction.
int UnsharePathTask(PathStateTable* table, int32_t tid,
                    uint64_t unshare_flags) noexcept;

// Updates the task's current shared FsContext. The supplied origin flags must
// mark both guest and host paths valid.
int SetTaskCwd(PathStateTable* table, int32_t tid,
               const char* guest_cwd, const char* host_cwd,
               uint32_t origin_flags, uint64_t device,
               uint64_t inode) noexcept;

// Changes the task's logical root identity (chroot semantics). CLONE_FS
// sharers observe the same update; cwd is intentionally left unchanged.
int SetTaskRoot(PathStateTable* table, int32_t tid,
                const char* guest_root, const char* host_root,
                uint32_t origin_flags, uint64_t device,
                uint64_t inode, uint64_t mount_id = 0) noexcept;

const FdIdentity* LookupFdIdentity(const PathStateTable* table, int32_t tid,
                                   int32_t fd) noexcept;

// Resolves a shared fd identity for one task. If the namespace identity or
// mount generation changed since the fd was recorded, a reverse mount lookup
// is attempted using the stored host identity. A captured guest path remains
// the deterministic fallback when the object has no visible mount alias.
int ResolveFdIdentityView(const PathStateTable* table, int32_t tid,
                          int32_t fd, FdIdentityView* view) noexcept;

// Returns the protected identity in this task's current FdTable whose fd is
// the smallest value greater than after_fd. Start with -1 for allocation-free
// ascending enumeration. Shared tasks naturally enumerate the same table.
const FdIdentity* NextProtectedFdIdentity(const PathStateTable* table,
                                          int32_t tid,
                                          int32_t after_fd) noexcept;
const FdIdentity* NextProtectedFdIdentityInTable(
        const PathStateTable* table, uint32_t fd_table_slot,
        int32_t after_fd) noexcept;

// Inserts or replaces fd in the task's current FdTable. Mutations are visible
// to all CLONE_FILES sharers. Replacement reuses the existing sparse slot.
int RecordFdIdentity(PathStateTable* table, int32_t tid, int32_t fd,
                     const FdIdentitySpec& identity) noexcept;

// Copies tracked origin from old_fd to new_fd after a successful dup-family
// syscall. If old_fd is untracked, any stale new_fd identity is removed.
int DuplicateFdIdentity(PathStateTable* table, int32_t tid, int32_t old_fd,
                        int32_t new_fd, bool cloexec) noexcept;

int CloseFdIdentity(PathStateTable* table, int32_t tid, int32_t fd) noexcept;
int SetFdIdentityCloexec(PathStateTable* table, int32_t tid, int32_t fd,
                         bool cloexec) noexcept;

// Applies close_range after kernel success. UNSHARE first creates a private
// table when needed; CLOEXEC marks entries, otherwise matching entries close.
// Unknown flag bits and first > last return EINVAL.
int CloseFdIdentityRange(PathStateTable* table, int32_t tid, uint32_t first,
                         uint32_t last, uint32_t flags) noexcept;

// Replay variant used after protected tracer descriptors were excluded from
// the kernel close operation. CLOEXEC still marks every tracked descriptor;
// close mode retains identities carrying kPathOriginProtected.
int CloseFdIdentityRangePreservingProtected(
        PathStateTable* table, int32_t tid, uint32_t first, uint32_t last,
        uint32_t flags) noexcept;

// Adds one mount layer to the task's current namespace. The three paths must
// be canonical absolute paths. Equal targets are valid and stack by sequence.
int AddMountBinding(PathStateTable* table, int32_t tid,
                    const MountBindingSpec& binding,
                    uint64_t* mount_id = nullptr) noexcept;

// Adds a recursive bind snapshot. The top layer uses binding and every
// currently visible child mount below source_guest is cloned below the new
// target while preserving parent relationships and mount attributes.
int AddRecursiveMountBinding(PathStateTable* table, int32_t tid,
                             const MountBindingSpec& binding,
                             uint64_t* mount_id = nullptr) noexcept;

// Removes the newest exact-target layer. SUBTREE includes child mounts.
// DETACHED, cwd/root pins, or open tree handles preserve an invisible detached
// identity so later fchdir/move_mount state remains coherent.
int RemoveMountBinding(PathStateTable* table, int32_t tid,
                       const char* target_guest, uint32_t flags,
                       uint64_t* removed_mount_id = nullptr) noexcept;

// Retargets the newest exact source mount together with all child mountpoints.
int MoveMountBinding(PathStateTable* table, int32_t tid,
                     const char* from_guest,
                     const char* to_guest) noexcept;

// Applies mount_setattr-style set/clear updates to the mount containing target.
// recursive extends the update to child mountpoints.
int SetMountBindingAttributes(PathStateTable* table, int32_t tid,
                              const char* target_guest,
                              uint64_t attributes_set,
                              uint64_t attributes_clear,
                              uint64_t propagation,
                              bool recursive) noexcept;

// Re-roots the namespace and rebases all mount targets. put_old_guest must be
// a strict descendant of new_root_guest. All tasks in the namespace keep the
// namespace across exec and receive rebased cwd/root identities.
int PivotRootMountNamespace(PathStateTable* table, int32_t tid,
                            const char* new_root_guest,
                            const char* new_root_host,
                            const char* put_old_guest,
                            const char* put_old_host) noexcept;

// Resolves a canonical guest path through the newest longest-prefix mount
// layer. A changed pivot root acts as the fallback root layer. On no overlay,
// matched is zero and guest_path is unchanged.
int TranslateMountPath(const PathStateTable* table, int32_t tid,
                       const char* guest_path,
                       MountPathTranslation* translation) noexcept;

// Reverse mapping is limited to bindings explicitly marked REVERSE_VISIBLE;
// the namespace root mapping is always eligible after pivot_root.
int ReverseMountPath(const PathStateTable* table, int32_t tid,
                     const char* host_path,
                     MountPathTranslation* translation) noexcept;

// Records an open_tree-style descriptor. clone_tree snapshots the current
// namespace overlay; otherwise the handle references the live namespace.
int RecordMountTreeFdIdentity(PathStateTable* table, int32_t tid, int32_t fd,
                              const char* source_guest,
                              const char* source_host, bool cloexec,
                              bool clone_tree,
                              uint64_t* handle_id = nullptr) noexcept;

const MountTreeState* LookupMountTreeByFd(const PathStateTable* table,
                                          int32_t tid, int32_t fd) noexcept;

// Attaches or moves the tree referenced by tree_fd at target_guest, including
// descendant mountpoints captured by its source snapshot. The handle remains
// usable and transitions from DETACHED to ATTACHED after success.
int AttachMountTree(PathStateTable* table, int32_t tid, int32_t tree_fd,
                    const char* target_guest,
                    uint64_t* mount_id = nullptr) noexcept;

}  // namespace hookself::tracer
