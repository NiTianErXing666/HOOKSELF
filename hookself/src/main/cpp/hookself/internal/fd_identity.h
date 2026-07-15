#pragma once

#include <cerrno>
#include <cstdint>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" uint64_t android_fdsan_get_owner_tag(int fd)
        __attribute__((weak));
extern "C" int android_fdsan_close_with_tag(int fd, uint64_t tag)
        __attribute__((weak));

namespace hookself::internal {

constexpr uint32_t kFdObjectIdentityValid = 1U << 0;
constexpr uint32_t kFdObjectIdentityTracksFdsan = 1U << 1;

struct FdObjectIdentity {
    uint64_t device;
    uint64_t inode;
    uint64_t rdev;
    uint64_t owner_tag;
    uint32_t type;
    uint32_t valid;
};

static_assert(__is_standard_layout(FdObjectIdentity) &&
              __is_trivially_copyable(FdObjectIdentity));

inline void ClearFdObjectIdentity(FdObjectIdentity* identity) noexcept {
    if (identity == nullptr) {
        return;
    }
    *identity = {};
}

inline int CaptureFdObjectIdentityImpl(int fd, FdObjectIdentity* identity,
                                       bool track_fdsan) noexcept {
    if (fd < 0 || identity == nullptr) {
        return EINVAL;
    }
    struct stat value {};
    if (fstat(fd, &value) != 0) {
        return errno;
    }
    identity->device = static_cast<uint64_t>(value.st_dev);
    identity->inode = static_cast<uint64_t>(value.st_ino);
    identity->rdev = static_cast<uint64_t>(value.st_rdev);
    identity->type = static_cast<uint32_t>(value.st_mode & S_IFMT);
    identity->owner_tag = track_fdsan && android_fdsan_get_owner_tag != nullptr
                                  ? android_fdsan_get_owner_tag(fd)
                                  : 0U;
    identity->valid = kFdObjectIdentityValid |
                      (track_fdsan && android_fdsan_get_owner_tag != nullptr
                               ? kFdObjectIdentityTracksFdsan
                               : 0U);
    return 0;
}

inline int CaptureFdObjectIdentity(int fd,
                                   FdObjectIdentity* identity) noexcept {
    return CaptureFdObjectIdentityImpl(fd, identity, true);
}

// Runtime-owned descriptors are created without a fdsan owner. After
// CLOSE_RANGE_UNSHARE, bionic's process-wide tag table may describe a different
// object at the same fd in another files_struct, so these identities must never
// inspect or mutate that tag.
inline int CaptureRawFdObjectIdentity(int fd,
                                      FdObjectIdentity* identity) noexcept {
    return CaptureFdObjectIdentityImpl(fd, identity, false);
}

inline bool FdObjectIdentityMatchesStat(
        const FdObjectIdentity& identity, const struct stat& value) noexcept {
    return (identity.valid & kFdObjectIdentityValid) != 0U &&
           identity.device == static_cast<uint64_t>(value.st_dev) &&
           identity.inode == static_cast<uint64_t>(value.st_ino) &&
           identity.rdev == static_cast<uint64_t>(value.st_rdev) &&
           identity.type == static_cast<uint32_t>(value.st_mode & S_IFMT);
}

inline int CheckFdObjectIdentity(int fd,
                                 const FdObjectIdentity& identity) noexcept {
    if (fd < 0 ||
        (identity.valid & kFdObjectIdentityValid) == 0U) {
        return EINVAL;
    }
    struct stat current {};
    if (fstat(fd, &current) != 0) {
        return errno == EBADF ? ESTALE : errno;
    }
    if (!FdObjectIdentityMatchesStat(identity, current)) {
        return ESTALE;
    }
    if ((identity.valid & kFdObjectIdentityTracksFdsan) != 0U &&
        android_fdsan_get_owner_tag != nullptr &&
        android_fdsan_get_owner_tag(fd) != identity.owner_tag) {
        return ESTALE;
    }
    return 0;
}

inline int CloseFdObject(int fd, const FdObjectIdentity& identity) noexcept {
    const int identity_error = CheckFdObjectIdentity(fd, identity);
    if (identity_error != 0) {
        return identity_error;
    }
    if ((identity.valid & kFdObjectIdentityTracksFdsan) != 0U &&
        android_fdsan_close_with_tag != nullptr) {
        return android_fdsan_close_with_tag(fd, identity.owner_tag) == 0
                       ? 0
                       : errno;
    }
    return syscall(__NR_close, fd) == 0 ? 0 : errno;
}

}  // namespace hookself::internal
