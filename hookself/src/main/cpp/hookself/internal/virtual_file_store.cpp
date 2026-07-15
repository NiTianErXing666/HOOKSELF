#include "virtual_file_store.h"

#include <android/log.h>
#include <asm/unistd.h>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace hookself::internal {
namespace {

constexpr mode_t kSessionDirectoryMode = 0700;
constexpr mode_t kCreationMode = 0600;
constexpr uint32_t kCreateAttempts = 32U;

bool CopyText(char* destination, size_t capacity, const char* source) noexcept {
    if (destination == nullptr || source == nullptr || capacity == 0) {
        return false;
    }
    size_t index = 0;
    for (; source[index] != '\0'; ++index) {
        if (index + 1U >= capacity) {
            destination[0] = '\0';
            return false;
        }
        destination[index] = source[index];
    }
    destination[index] = '\0';
    return true;
}

size_t TextLength(const char* value, size_t capacity) noexcept {
    if (value == nullptr) {
        return capacity;
    }
    for (size_t index = 0; index < capacity; ++index) {
        if (value[index] == '\0') {
            return index;
        }
    }
    return capacity;
}

bool JoinPath(const char* directory, const char* name, char* output,
              size_t capacity) noexcept {
    if (directory == nullptr || name == nullptr || output == nullptr ||
        capacity == 0) {
        return false;
    }
    const size_t directory_length = TextLength(directory, capacity);
    const size_t name_length = TextLength(name, capacity);
    if (directory_length == 0 || directory_length == capacity ||
        name_length == 0 || name_length == capacity) {
        return false;
    }
    const bool root_directory = directory_length == 1U && directory[0] == '/';
    const size_t separator = root_directory ? 0U : 1U;
    if (directory_length + separator + name_length + 1U > capacity) {
        return false;
    }
    size_t output_index = 0;
    for (size_t index = 0; index < directory_length; ++index) {
        output[output_index++] = directory[index];
    }
    if (!root_directory) {
        output[output_index++] = '/';
    }
    for (size_t index = 0; index < name_length; ++index) {
        output[output_index++] = name[index];
    }
    output[output_index] = '\0';
    return true;
}

int CloseExact(int fd, const FdObjectIdentity& identity) noexcept {
    if (fd < 0) {
        return 0;
    }
    if ((identity.valid & kFdObjectIdentityValid) == 0U) {
        return syscall(__NR_close, fd) == 0 ? 0 : errno;
    }
    return CloseFdObject(fd, identity);
}

int CacheStableIdentity(VirtualFileBacking* backing) noexcept {
    if (backing == nullptr || backing->stable_fd < 0) {
        return EINVAL;
    }
    ClearFdObjectIdentity(&backing->stable_identity);
    const int identity_error = CaptureRawFdObjectIdentity(
            backing->stable_fd, &backing->stable_identity);
    if (identity_error != 0) {
        backing->stable_device = 0;
        backing->stable_inode = 0;
        backing->stable_file_type = 0;
        backing->stable_identity_valid = 0;
        return identity_error;
    }
    backing->stable_device = backing->stable_identity.device;
    backing->stable_inode = backing->stable_identity.inode;
    backing->stable_file_type = backing->stable_identity.type;
    backing->stable_identity_valid = 1;
    return 0;
}

bool StableIdentityMatches(const VirtualFileBacking& backing,
                           struct stat* observed) noexcept {
    if (backing.stable_fd < 0 || backing.stable_identity_valid == 0 ||
        backing.stable_identity.valid == 0) {
        return false;
    }
    struct stat value {};
    if (fstat(backing.stable_fd, &value) != 0) {
        return false;
    }
    if (observed != nullptr) {
        *observed = value;
    }
    return static_cast<uint64_t>(value.st_dev) == backing.stable_device &&
           static_cast<uint64_t>(value.st_ino) == backing.stable_inode &&
           static_cast<uint32_t>(value.st_mode & S_IFMT) ==
                   backing.stable_file_type &&
           FdObjectIdentityMatchesStat(backing.stable_identity, value) &&
           CheckFdObjectIdentity(backing.stable_fd,
                                 backing.stable_identity) == 0;
}

bool SessionIdentityMatches(const VirtualBackingSession& session) noexcept {
    if (session.root_fd < 0 || session.session_fd < 0 ||
        session.directory_created == 0 ||
        CheckFdObjectIdentity(session.root_fd, session.root_identity) != 0 ||
        CheckFdObjectIdentity(session.session_fd, session.session_identity) !=
                0) {
        return false;
    }
    struct stat root {};
    struct stat child {};
    return fstat(session.root_fd, &root) == 0 &&
           fstat(session.session_fd, &child) == 0 &&
           S_ISDIR(root.st_mode) && S_ISDIR(child.st_mode);
}

int WriteAll(int fd, const uint8_t* content, size_t content_size) noexcept {
    size_t written = 0;
    while (written < content_size) {
        const ssize_t result = write(fd, content + written,
                                     content_size - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return result < 0 ? errno : EIO;
        }
        written += static_cast<size_t>(result);
    }
    return 0;
}

int FinalMode(uint32_t mode) noexcept {
    return static_cast<int>(mode == 0 ? 0444U : mode & 0777U);
}

int RemoveNamedFile(const VirtualBackingSession& session,
                    const char* name) noexcept {
    if (!SessionIdentityMatches(session) || name == nullptr || name[0] == '\0') {
        return ESTALE;
    }
    if (unlinkat(session.session_fd, name, 0) == 0 || errno == ENOENT) {
        return 0;
    }
    return errno;
}

void ClearPendingSnapshot(VirtualFileBacking* backing) noexcept {
    if (backing == nullptr) {
        return;
    }
    backing->pending_snapshot_fd = -1;
    backing->pending_snapshot_generation = 0;
    ClearFdObjectIdentity(&backing->pending_snapshot_identity);
    backing->pending_temp_name[0] = '\0';
}

int CleanPendingSnapshot(VirtualFileBacking* backing,
                         int snapshot_fd) noexcept {
    if (backing == nullptr || snapshot_fd < 0 ||
        backing->pending_snapshot_fd != snapshot_fd) {
        return EINVAL;
    }
    int result = CloseExact(snapshot_fd, backing->pending_snapshot_identity);
    if (backing->session != nullptr && backing->pending_temp_name[0] != '\0') {
        const int remove_error = RemoveNamedFile(*backing->session,
                                                 backing->pending_temp_name);
        if (result == 0 && remove_error != 0) {
            result = remove_error;
        }
    }
    ClearPendingSnapshot(backing);
    return result;
}

void LogCleanupFailure(const char* operation, int error) noexcept {
    if (error != 0) {
        __android_log_print(ANDROID_LOG_WARN, "HookSelf",
                            "virtual backing cleanup %s failed: %d",
                            operation, error);
    }
}

}  // namespace

void InitializeVirtualBackingSession(VirtualBackingSession* session) noexcept {
    if (session == nullptr) {
        return;
    }
    session->root_fd = -1;
    session->session_fd = -1;
    session->active_backings = 0;
    session->directory_created = 0;
    ClearFdObjectIdentity(&session->root_identity);
    ClearFdObjectIdentity(&session->session_identity);
    session->root_path[0] = '\0';
    session->session_name[0] = '\0';
    session->session_path[0] = '\0';
}

int CreateVirtualBackingSession(const char* backing_root,
                                uint64_t session_nonce,
                                VirtualBackingSession* session) noexcept {
    if (backing_root == nullptr || session == nullptr ||
        session->root_fd >= 0 || session->session_fd >= 0 ||
        TextLength(backing_root, HOOKSELF_PATH_CAPACITY) == 0 ||
        TextLength(backing_root, HOOKSELF_PATH_CAPACITY) ==
                HOOKSELF_PATH_CAPACITY) {
        return EINVAL;
    }
    const int root_fd = open(backing_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (root_fd < 0) {
        return errno;
    }
    FdObjectIdentity root_identity{};
    int error = CaptureRawFdObjectIdentity(root_fd, &root_identity);
    struct stat root_stat {};
    if (error == 0 && (fstat(root_fd, &root_stat) != 0 ||
                       !S_ISDIR(root_stat.st_mode))) {
        error = fstat(root_fd, &root_stat) == 0 ? ENOTDIR : errno;
    }
    if (error != 0) {
        (void)CloseExact(root_fd, root_identity);
        return error;
    }

    char session_name[kVirtualBackingSessionNameCapacity]{};
    int session_fd = -1;
    FdObjectIdentity session_identity{};
    for (uint32_t attempt = 0; attempt < kCreateAttempts; ++attempt) {
        const int formatted = snprintf(
                session_name, sizeof(session_name),
                "hookself-vf-%08x-%08x-%02u",
                static_cast<uint32_t>(session_nonce >> 32U),
                static_cast<uint32_t>(session_nonce), attempt);
        if (formatted <= 0 || static_cast<size_t>(formatted) >=
                                      sizeof(session_name)) {
            error = ENAMETOOLONG;
            break;
        }
        if (mkdirat(root_fd, session_name, kSessionDirectoryMode) != 0) {
            if (errno == EEXIST) {
                continue;
            }
            error = errno;
            break;
        }
        session_fd = openat(root_fd, session_name,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (session_fd < 0) {
            error = errno;
            (void)unlinkat(root_fd, session_name, AT_REMOVEDIR);
            break;
        }
        error = CaptureRawFdObjectIdentity(session_fd, &session_identity);
        struct stat session_stat {};
        if (error == 0 && (fstat(session_fd, &session_stat) != 0 ||
                           !S_ISDIR(session_stat.st_mode))) {
            error = fstat(session_fd, &session_stat) == 0 ? ENOTDIR : errno;
        }
        if (error != 0) {
            (void)CloseExact(session_fd, session_identity);
            session_fd = -1;
            (void)unlinkat(root_fd, session_name, AT_REMOVEDIR);
            break;
        }
        break;
    }
    if (session_fd < 0) {
        (void)CloseExact(root_fd, root_identity);
        return error == 0 ? EEXIST : error;
    }

    VirtualBackingSession created{};
    InitializeVirtualBackingSession(&created);
    created.root_fd = root_fd;
    created.session_fd = session_fd;
    created.root_identity = root_identity;
    created.session_identity = session_identity;
    created.directory_created = 1;
    if (!CopyText(created.root_path, sizeof(created.root_path), backing_root) ||
        !CopyText(created.session_name, sizeof(created.session_name),
                  session_name) ||
        !JoinPath(created.root_path, created.session_name,
                  created.session_path, sizeof(created.session_path))) {
        (void)unlinkat(root_fd, session_name, AT_REMOVEDIR);
        (void)CloseExact(session_fd, session_identity);
        (void)CloseExact(root_fd, root_identity);
        return ENAMETOOLONG;
    }
    *session = created;
    return 0;
}

int RemoveVirtualBackingSessionDirectory(
        VirtualBackingSession* session) noexcept {
    if (session == nullptr) {
        return EINVAL;
    }
    if (session->directory_created == 0) {
        return 0;
    }
    if (session->active_backings != 0 || !SessionIdentityMatches(*session)) {
        return session->active_backings != 0 ? EBUSY : ESTALE;
    }
    if (unlinkat(session->root_fd, session->session_name, AT_REMOVEDIR) != 0 &&
        errno != ENOENT) {
        return errno;
    }
    session->directory_created = 0;
    return 0;
}

void DestroyVirtualBackingSession(VirtualBackingSession* session) noexcept {
    if (session == nullptr) {
        return;
    }
    LogCleanupFailure("session-directory",
                      RemoveVirtualBackingSessionDirectory(session));
    LogCleanupFailure("session-fd",
                      CloseExact(session->session_fd, session->session_identity));
    LogCleanupFailure("root-fd",
                      CloseExact(session->root_fd, session->root_identity));
    InitializeVirtualBackingSession(session);
}

void InitializeVirtualFileBacking(VirtualFileBacking* backing) noexcept {
    if (backing == nullptr) {
        return;
    }
    backing->stable_fd = -1;
    backing->provider = 0;
    backing->mode = 0;
    backing->generation = 0;
    backing->stable_device = 0;
    backing->stable_inode = 0;
    backing->stable_file_type = 0;
    backing->stable_identity_valid = 0;
    ClearFdObjectIdentity(&backing->stable_identity);
    backing->session = nullptr;
    backing->file_id = 0;
    backing->final_created = 0;
    backing->last_commit_published = 0;
    backing->last_commit_stable_synchronized = 0;
    backing->pending_snapshot_fd = -1;
    backing->pending_snapshot_generation = 0;
    backing->pending_snapshot_serial = 0;
    ClearFdObjectIdentity(&backing->pending_snapshot_identity);
    backing->final_name[0] = '\0';
    backing->pending_temp_name[0] = '\0';
    backing->backing_path[0] = '\0';
}

int CreateVirtualFileBacking(const uint8_t* content, size_t content_size,
                             int32_t provider, uint32_t mode, uint32_t file_id,
                             VirtualBackingSession* session,
                             VirtualFileBacking* backing) noexcept {
    if (backing == nullptr || session == nullptr || file_id == 0 ||
        (content_size != 0 && content == nullptr) || backing->stable_fd >= 0 ||
        !SessionIdentityMatches(*session)) {
        return EINVAL;
    }
    char final_name[kVirtualBackingFileNameCapacity]{};
    const int formatted = snprintf(final_name, sizeof(final_name),
                                   "vfile-%08x", file_id);
    if (formatted <= 0 || static_cast<size_t>(formatted) >= sizeof(final_name)) {
        return ENAMETOOLONG;
    }
    char backing_path[HOOKSELF_PATH_CAPACITY]{};
    if (!JoinPath(session->session_path, final_name, backing_path,
                  sizeof(backing_path))) {
        return ENAMETOOLONG;
    }

    const int stable_fd = openat(session->session_fd, final_name,
                                 O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
                                 kCreationMode);
    if (stable_fd < 0) {
        return errno;
    }
    FdObjectIdentity stable_identity{};
    int error = CaptureRawFdObjectIdentity(stable_fd, &stable_identity);
    if (error == 0) {
        error = WriteAll(stable_fd, content, content_size);
    }
    if (error == 0 && fchmod(stable_fd, static_cast<mode_t>(FinalMode(mode))) != 0) {
        error = errno;
    }
    if (error == 0 && fsync(stable_fd) != 0) {
        error = errno;
    }
    if (error != 0) {
        (void)CloseExact(stable_fd, stable_identity);
        (void)RemoveNamedFile(*session, final_name);
        return error;
    }

    backing->stable_fd = stable_fd;
    backing->provider = provider;
    backing->mode = static_cast<uint32_t>(FinalMode(mode));
    backing->generation = 1;
    backing->session = session;
    backing->file_id = file_id;
    backing->final_created = 1;
    CopyText(backing->final_name, sizeof(backing->final_name), final_name);
    CopyText(backing->backing_path, sizeof(backing->backing_path), backing_path);
    const int identity_error = CacheStableIdentity(backing);
    if (identity_error != 0) {
        (void)CloseExact(stable_fd, stable_identity);
        (void)RemoveNamedFile(*session, final_name);
        InitializeVirtualFileBacking(backing);
        return identity_error;
    }
    ++session->active_backings;
    return 0;
}

int PrepareVirtualFileSnapshot(VirtualFileBacking* backing,
                               const uint8_t* content, size_t content_size,
                               int* snapshot_fd) noexcept {
    if (backing == nullptr || backing->session == nullptr ||
        backing->stable_fd < 0 || snapshot_fd == nullptr ||
        (content_size != 0 && content == nullptr)) {
        return EINVAL;
    }
    *snapshot_fd = -1;
    backing->last_commit_published = 0;
    backing->last_commit_stable_synchronized = 0;
    if (!StableIdentityMatches(*backing, nullptr) ||
        !SessionIdentityMatches(*backing->session)) {
        return ESTALE;
    }
    if (backing->pending_snapshot_fd >= 0) {
        return EBUSY;
    }

    char temporary_name[kVirtualBackingFileNameCapacity]{};
    int fd = -1;
    uint64_t serial = backing->pending_snapshot_serial;
    for (uint32_t attempt = 0; attempt < kCreateAttempts; ++attempt) {
        ++serial;
        if (serial == 0) {
            ++serial;
        }
        const int formatted = snprintf(temporary_name, sizeof(temporary_name),
                                       ".vfile-%08x-%08x.tmp", backing->file_id,
                                       static_cast<uint32_t>(serial));
        if (formatted <= 0 || static_cast<size_t>(formatted) >=
                                      sizeof(temporary_name)) {
            return ENAMETOOLONG;
        }
        fd = openat(backing->session->session_fd, temporary_name,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    kCreationMode);
        if (fd >= 0) {
            break;
        }
        if (errno != EEXIST) {
            return errno;
        }
    }
    if (fd < 0) {
        return EEXIST;
    }
    FdObjectIdentity identity{};
    int error = CaptureRawFdObjectIdentity(fd, &identity);
    if (error == 0) {
        error = WriteAll(fd, content, content_size);
    }
    if (error == 0 &&
        fchmod(fd, static_cast<mode_t>(FinalMode(backing->mode))) != 0) {
        error = errno;
    }
    if (error == 0 && fsync(fd) != 0) {
        error = errno;
    }
    if (error != 0) {
        (void)CloseExact(fd, identity);
        (void)RemoveNamedFile(*backing->session, temporary_name);
        return error;
    }

    backing->pending_snapshot_fd = fd;
    backing->pending_snapshot_generation = backing->generation;
    backing->pending_snapshot_serial = serial;
    backing->pending_snapshot_identity = identity;
    CopyText(backing->pending_temp_name, sizeof(backing->pending_temp_name),
             temporary_name);
    *snapshot_fd = fd;
    return 0;
}

int CommitVirtualFileSnapshot(VirtualFileBacking* backing,
                              int snapshot_fd) noexcept {
    if (backing == nullptr || backing->session == nullptr ||
        backing->stable_fd < 0 || snapshot_fd < 0 ||
        snapshot_fd == backing->stable_fd ||
        backing->pending_snapshot_fd != snapshot_fd) {
        return EINVAL;
    }
    backing->last_commit_published = 0;
    backing->last_commit_stable_synchronized = 0;
    if (!StableIdentityMatches(*backing, nullptr) ||
        !SessionIdentityMatches(*backing->session) ||
        backing->pending_snapshot_generation != backing->generation ||
        CheckFdObjectIdentity(snapshot_fd,
                              backing->pending_snapshot_identity) != 0) {
        return ESTALE;
    }
    if (renameat(backing->session->session_fd, backing->pending_temp_name,
                 backing->session->session_fd, backing->final_name) != 0) {
        return errno;
    }
    // The named backing path is authoritative once rename succeeds. A later
    // stable-FD synchronization failure must not make the committed pathname
    // look like the old snapshot. The stable FD remains a protected lifecycle
    // anchor until a later publish can synchronize it again.
    backing->last_commit_published = 1;
    int result = fsync(backing->session->session_fd) == 0 ? 0 : errno;
    if (syscall(__NR_dup3, snapshot_fd, backing->stable_fd, 0) ==
        backing->stable_fd) {
        const int identity_error = CacheStableIdentity(backing);
        if (identity_error == 0) {
            backing->last_commit_stable_synchronized = 1;
        } else if (result == 0) {
            result = identity_error;
        }
    } else if (result == 0) {
        result = errno;
    }
    ++backing->generation;
    if (backing->generation == 0) {
        backing->generation = 1;
    }
    ClearPendingSnapshot(backing);
    return result;
}

int DiscardVirtualFileSnapshot(VirtualFileBacking* backing,
                               int snapshot_fd) noexcept {
    return CleanPendingSnapshot(backing, snapshot_fd);
}

void DestroyVirtualFileBacking(VirtualFileBacking* backing) noexcept {
    if (backing == nullptr) {
        return;
    }
    if (backing->pending_snapshot_fd >= 0) {
        LogCleanupFailure("snapshot", CleanPendingSnapshot(
                backing, backing->pending_snapshot_fd));
    }
    if (backing->stable_fd >= 0) {
        struct stat observed {};
        if (StableIdentityMatches(*backing, &observed)) {
            LogCleanupFailure("stable-fd", CloseExact(backing->stable_fd,
                                                        backing->stable_identity));
        } else {
            __android_log_print(
                    ANDROID_LOG_WARN, "HookSelf",
                    "virtual backing identity mismatch fd=%d expected=(%llu,%llu,%u) observed=(%llu,%llu,%u)",
                    backing->stable_fd,
                    static_cast<unsigned long long>(backing->stable_device),
                    static_cast<unsigned long long>(backing->stable_inode),
                    backing->stable_file_type,
                    static_cast<unsigned long long>(observed.st_dev),
                    static_cast<unsigned long long>(observed.st_ino),
                    static_cast<uint32_t>(observed.st_mode & S_IFMT));
        }
    }
    VirtualBackingSession* const session = backing->session;
    if (backing->final_created != 0 && session != nullptr) {
        LogCleanupFailure("final-file", RemoveNamedFile(*session,
                                                         backing->final_name));
    }
    if (session != nullptr && session->active_backings != 0) {
        --session->active_backings;
    }
    InitializeVirtualFileBacking(backing);
}

}  // namespace hookself::internal
