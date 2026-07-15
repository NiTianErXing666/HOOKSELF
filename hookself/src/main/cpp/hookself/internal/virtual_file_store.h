#pragma once

#include <cstddef>
#include <cstdint>

#include "fd_identity.h"
#include "hookself/public_api.h"

namespace hookself::internal {

constexpr size_t kVirtualBackingSessionNameCapacity = 64U;
constexpr size_t kVirtualBackingFileNameCapacity = 64U;

// One runtime owns one subdirectory below the caller-provided backing root.
// The root itself is never created, renamed, or removed by this component.
struct VirtualBackingSession {
    int root_fd;
    int session_fd;
    uint32_t active_backings;
    uint32_t directory_created;
    FdObjectIdentity root_identity;
    FdObjectIdentity session_identity;
    char root_path[HOOKSELF_PATH_CAPACITY];
    char session_name[kVirtualBackingSessionNameCapacity];
    char session_path[HOOKSELF_PATH_CAPACITY];
};

struct VirtualFileBacking {
    int stable_fd;
    int32_t provider;
    uint32_t mode;
    uint64_t generation;
    uint64_t stable_device;
    uint64_t stable_inode;
    uint32_t stable_file_type;
    uint32_t stable_identity_valid;
    FdObjectIdentity stable_identity;
    VirtualBackingSession* session;
    uint32_t file_id;
    uint32_t final_created;
    uint32_t last_commit_published;
    uint32_t last_commit_stable_synchronized;
    int pending_snapshot_fd;
    uint64_t pending_snapshot_generation;
    uint64_t pending_snapshot_serial;
    FdObjectIdentity pending_snapshot_identity;
    char final_name[kVirtualBackingFileNameCapacity];
    char pending_temp_name[kVirtualBackingFileNameCapacity];
    char backing_path[HOOKSELF_PATH_CAPACITY];
};

void InitializeVirtualBackingSession(VirtualBackingSession* session) noexcept;
int CreateVirtualBackingSession(const char* backing_root,
                                uint64_t session_nonce,
                                VirtualBackingSession* session) noexcept;
int RemoveVirtualBackingSessionDirectory(
        VirtualBackingSession* session) noexcept;
void DestroyVirtualBackingSession(VirtualBackingSession* session) noexcept;

void InitializeVirtualFileBacking(VirtualFileBacking* backing) noexcept;
int CreateVirtualFileBacking(const uint8_t* content, size_t content_size,
                             int32_t provider, uint32_t mode, uint32_t file_id,
                             VirtualBackingSession* session,
                             VirtualFileBacking* backing) noexcept;
int PrepareVirtualFileSnapshot(VirtualFileBacking* backing,
                               const uint8_t* content, size_t content_size,
                               int* snapshot_fd) noexcept;
int CommitVirtualFileSnapshot(VirtualFileBacking* backing,
                              int snapshot_fd) noexcept;
int DiscardVirtualFileSnapshot(VirtualFileBacking* backing,
                               int snapshot_fd) noexcept;
void DestroyVirtualFileBacking(VirtualFileBacking* backing) noexcept;

}  // namespace hookself::internal
