#include "proc_virtual_dispatch.h"

#include <asm/unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

namespace hookself::internal {
namespace {

struct RemoteIovec64 {
    uint64_t base;
    uint64_t length;
};

static_assert(sizeof(RemoteIovec64) == 16U);

struct XattrCall {
    bool valid;
    bool list;
    bool fd_form;
    bool follows;
    int32_t fd;
    uint32_t path_argument_index;
    uintptr_t remote_path;
    uintptr_t remote_name;
    uintptr_t remote_output;
    size_t output_capacity;
};

bool AddSize(size_t left, size_t right, size_t* output) noexcept {
    if (output == nullptr || left > SIZE_MAX - right) {
        return false;
    }
    *output = left + right;
    return true;
}

bool AddAddress(uintptr_t address, size_t offset, uintptr_t* output) noexcept {
    if (output == nullptr || address > UINTPTR_MAX - offset) {
        return false;
    }
    *output = address + offset;
    return true;
}

int CallbackError(int error) noexcept { return error >= 0 ? error : EPROTO; }

bool MissingIdentityError(int error) noexcept {
    return error == ENOENT || error == ENODATA || error == ENOTSUP ||
           error == EBADF || error == ENOTDIR;
}

bool BoundedBytes(const char* value, size_t size) noexcept {
    if (size != 0 && value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        if (value[index] == '\0') {
            return false;
        }
    }
    return true;
}

bool BuffersOverlap(const void* left, size_t left_size, const void* right,
                    size_t right_size) noexcept {
    if (left == nullptr || right == nullptr || left_size == 0 ||
        right_size == 0) {
        return false;
    }
    const uintptr_t left_start = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_start = reinterpret_cast<uintptr_t>(right);
    if (left_start > UINTPTR_MAX - left_size ||
        right_start > UINTPTR_MAX - right_size) {
        return true;
    }
    return left_start < right_start + right_size &&
           right_start < left_start + left_size;
}

int ValidateConfig(const ProcVirtualDispatchConfig& config) noexcept {
    if ((config.hidden_range_count != 0 && config.hidden_ranges == nullptr) ||
        (config.reverse_rule_count != 0 && config.reverse_rules == nullptr) ||
        (config.protected_fd_count != 0 && config.protected_fds == nullptr) ||
        (config.xattr_rule_count != 0 && config.xattr_rules == nullptr) ||
        (config.snapshot_capacity != 0 && config.snapshot_buffer == nullptr) ||
        (config.rewrite_capacity != 0 && config.rewrite_buffer == nullptr) ||
        config.protected_fd_count > kProcVirtualDispatchMaxProtectedFds ||
        config.xattr_rule_count > UINT32_MAX ||
        config.max_iov_count > kProcVirtualDispatchMaxIov ||
        BuffersOverlap(config.snapshot_buffer, config.snapshot_capacity,
                       config.rewrite_buffer, config.rewrite_capacity)) {
        return EINVAL;
    }
    for (size_t index = 0; index < config.hidden_range_count; ++index) {
        if (config.hidden_ranges[index].size != 0 &&
            config.hidden_ranges[index].start >
                    UINTPTR_MAX - config.hidden_ranges[index].size) {
            return EOVERFLOW;
        }
    }
    for (size_t index = 0; index < config.xattr_rule_count; ++index) {
        const ProcVirtualXattrRule& rule = config.xattr_rules[index];
        if ((rule.flags & ~kProcVirtualXattrKnownRuleFlags) != 0 ||
            ((rule.flags & kProcVirtualXattrRuleFollowOnly) != 0 &&
             (rule.flags & kProcVirtualXattrRuleNoFollowOnly) != 0) ||
            ((rule.flags & kProcVirtualXattrRuleFdOnly) != 0 &&
             (rule.flags & kProcVirtualXattrRulePathOnly) != 0) ||
            !BoundedBytes(rule.path_prefix, rule.path_prefix_length) ||
            rule.name_length == 0 ||
            rule.name_length > kProcVirtualXattrNameMax ||
            !BoundedBytes(rule.name, rule.name_length) ||
            (rule.value_size != 0 && rule.value == nullptr)) {
            return EINVAL;
        }
    }
    return 0;
}

int ReadRemote(const ProcVirtualIo& io, const ProcVirtualDispatchTask& task,
               uintptr_t address, void* output, size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (io.read_remote == nullptr || address == 0 || output == nullptr ||
        address > UINTPTR_MAX - (size - 1U)) {
        return io.read_remote == nullptr ? ENOSYS : EFAULT;
    }
    return CallbackError(io.read_remote(io.opaque, task.tgid, task.tid, address,
                                        output, size));
}

int WriteRemote(const ProcVirtualIo& io, const ProcVirtualDispatchTask& task,
                uintptr_t address, const void* input, size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (io.write_remote == nullptr || address == 0 || input == nullptr ||
        address > UINTPTR_MAX - (size - 1U)) {
        return io.write_remote == nullptr ? ENOSYS : EFAULT;
    }
    return CallbackError(io.write_remote(io.opaque, task.tgid, task.tid,
                                         address, input, size));
}

int ReadRemoteCString(const ProcVirtualIo& io,
                      const ProcVirtualDispatchTask& task, uintptr_t address,
                      char* output, size_t capacity,
                      size_t* output_length) noexcept {
    if (output == nullptr || output_length == nullptr || capacity == 0 ||
        address == 0) {
        return EINVAL;
    }
    *output_length = 0;
    for (size_t index = 0; index < capacity; ++index) {
        uintptr_t current = 0;
        if (!AddAddress(address, index, &current)) {
            return EOVERFLOW;
        }
        const int error = ReadRemote(io, task, current, output + index, 1U);
        if (error != 0) {
            output[0] = '\0';
            return error;
        }
        if (output[index] == '\0') {
            *output_length = index;
            return 0;
        }
    }
    output[capacity - 1U] = '\0';
    return ENAMETOOLONG;
}

int TryResolvedIdentity(const ProcVirtualIo& io,
                        const ProcVirtualIdentityQuery& base,
                        ProcVirtualIdentitySource source, char* output,
                        size_t capacity, size_t* output_length,
                        bool* found) noexcept {
    *found = false;
    if (io.resolve_identity == nullptr) {
        return 0;
    }
    ProcVirtualIdentityQuery query = base;
    query.source = source;
    output[0] = '\0';
    *output_length = 0;
    const int error = CallbackError(io.resolve_identity(
            io.opaque, &query, output, capacity, output_length));
    if (MissingIdentityError(error)) {
        return 0;
    }
    if (error != 0) {
        return error;
    }
    if (*output_length >= capacity || output[*output_length] != '\0' ||
        !BoundedBytes(output, *output_length)) {
        return EPROTO;
    }
    *found = true;
    return 0;
}

int ResolveIdentityPath(const ProcVirtualIo& io,
                        const ProcVirtualDispatchTask& task,
                        int32_t syscall_number, int32_t fd,
                        uint32_t path_argument_index, uintptr_t remote_path,
                        char* output, size_t capacity,
                        size_t* output_length) noexcept {
    if (output == nullptr || output_length == nullptr || capacity == 0) {
        return EINVAL;
    }
    ProcVirtualIdentityQuery query{};
    query.task = task;
    query.flags =
            fd >= 0 ? kProcVirtualIdentityFd : kProcVirtualIdentityRemotePath;
    query.syscall_number = syscall_number;
    query.fd = fd;
    query.path_argument_index = path_argument_index;
    query.remote_path = remote_path;

    bool found = false;
    int error = TryResolvedIdentity(io, query,
                                    ProcVirtualIdentitySource::kTrackedGuest,
                                    output, capacity, output_length, &found);
    if (error != 0 || found) {
        return error;
    }
    error = TryResolvedIdentity(io, query, ProcVirtualIdentitySource::kResolved,
                                output, capacity, output_length, &found);
    if (error != 0 || found) {
        return error;
    }
    if (fd >= 0) {
        return ENOENT;
    }
    return ReadRemoteCString(io, task, remote_path, output, capacity,
                             output_length);
}

bool IsProcTextNode(ProcVirtualNodeKind node) noexcept {
    return node == ProcVirtualNodeKind::kMaps ||
           node == ProcVirtualNodeKind::kSmaps ||
           node == ProcVirtualNodeKind::kSmapsRollup ||
           node == ProcVirtualNodeKind::kAttrCurrent;
}

bool IsProcDirectoryNode(ProcVirtualNodeKind node) noexcept {
    return node == ProcVirtualNodeKind::kRootDirectory ||
           node == ProcVirtualNodeKind::kFdDirectory ||
           node == ProcVirtualNodeKind::kFdInfoDirectory ||
           node == ProcVirtualNodeKind::kMapFilesDirectory;
}

bool IsReadSyscall(int32_t syscall_number) noexcept {
    return syscall_number == __NR_read || syscall_number == __NR_pread64 ||
           syscall_number == __NR_readv;
}

XattrCall DecodeXattrCall(int32_t syscall_number,
                          const uint64_t arguments[6]) noexcept {
    XattrCall call{};
    switch (syscall_number) {
    case __NR_getxattr:
    case __NR_lgetxattr:
        call.valid = true;
        call.follows = syscall_number == __NR_getxattr;
        call.path_argument_index = 0;
        call.remote_path = static_cast<uintptr_t>(arguments[0]);
        call.remote_name = static_cast<uintptr_t>(arguments[1]);
        call.remote_output = static_cast<uintptr_t>(arguments[2]);
        call.output_capacity = static_cast<size_t>(arguments[3]);
        break;
    case __NR_fgetxattr:
        call.valid = true;
        call.fd_form = true;
        call.follows = true;
        call.fd = static_cast<int32_t>(arguments[0]);
        call.path_argument_index = kProcVirtualInvalidArgument;
        call.remote_name = static_cast<uintptr_t>(arguments[1]);
        call.remote_output = static_cast<uintptr_t>(arguments[2]);
        call.output_capacity = static_cast<size_t>(arguments[3]);
        break;
    case __NR_listxattr:
    case __NR_llistxattr:
        call.valid = true;
        call.list = true;
        call.follows = syscall_number == __NR_listxattr;
        call.path_argument_index = 0;
        call.remote_path = static_cast<uintptr_t>(arguments[0]);
        call.remote_output = static_cast<uintptr_t>(arguments[1]);
        call.output_capacity = static_cast<size_t>(arguments[2]);
        break;
    case __NR_flistxattr:
        call.valid = true;
        call.list = true;
        call.fd_form = true;
        call.follows = true;
        call.fd = static_cast<int32_t>(arguments[0]);
        call.path_argument_index = kProcVirtualInvalidArgument;
        call.remote_output = static_cast<uintptr_t>(arguments[1]);
        call.output_capacity = static_cast<size_t>(arguments[2]);
        break;
    default:
        break;
    }
    return call;
}

bool PathPrefixMatches(const char* path, size_t path_length,
                       const ProcVirtualXattrRule& rule) noexcept {
    if (rule.path_prefix_length == 0) {
        return true;
    }
    if (path == nullptr || rule.path_prefix_length > path_length ||
        memcmp(path, rule.path_prefix, rule.path_prefix_length) != 0) {
        return false;
    }
    if ((rule.flags & kProcVirtualXattrRuleExactPath) != 0) {
        return rule.path_prefix_length == path_length;
    }
    return (rule.path_prefix_length == 1U && rule.path_prefix[0] == '/') ||
           rule.path_prefix_length == path_length ||
           path[rule.path_prefix_length] == '/';
}

bool XattrRuleMatchesCall(const ProcVirtualXattrRule& rule,
                          const XattrCall& call, const char* path,
                          size_t path_length) noexcept {
    if ((rule.flags & kProcVirtualXattrRuleFdOnly) != 0 && !call.fd_form) {
        return false;
    }
    if ((rule.flags & kProcVirtualXattrRulePathOnly) != 0 && call.fd_form) {
        return false;
    }
    if ((rule.flags & kProcVirtualXattrRuleFollowOnly) != 0 && !call.follows) {
        return false;
    }
    if ((rule.flags & kProcVirtualXattrRuleNoFollowOnly) != 0 &&
        (call.fd_form || call.follows)) {
        return false;
    }
    return PathPrefixMatches(path, path_length, rule);
}

uint32_t SelectXattrGetRule(const ProcVirtualDispatchConfig& config,
                            const XattrCall& call, const char* path,
                            size_t path_length, const char* name,
                            size_t name_length) noexcept {
    uint32_t selected = kProcVirtualInvalidRule;
    for (size_t index = 0; index < config.xattr_rule_count; ++index) {
        const ProcVirtualXattrRule& rule = config.xattr_rules[index];
        if (rule.name_length != name_length ||
            memcmp(rule.name, name, name_length) != 0 ||
            !XattrRuleMatchesCall(rule, call, path, path_length)) {
            continue;
        }
        if (selected == kProcVirtualInvalidRule ||
            rule.priority > config.xattr_rules[selected].priority ||
            (rule.priority == config.xattr_rules[selected].priority &&
             rule.path_prefix_length >
                     config.xattr_rules[selected].path_prefix_length)) {
            selected = static_cast<uint32_t>(index);
        }
    }
    return selected;
}

bool HasXattrListRule(const ProcVirtualDispatchConfig& config,
                      const XattrCall& call, const char* path,
                      size_t path_length, bool* emulate) noexcept {
    if (emulate != nullptr) {
        *emulate = false;
    }
    bool matched = false;
    for (size_t index = 0; index < config.xattr_rule_count; ++index) {
        if (XattrRuleMatchesCall(config.xattr_rules[index], call, path,
                                 path_length)) {
            matched = true;
            if (emulate != nullptr &&
                (config.xattr_rules[index].flags &
                 kProcVirtualXattrRuleEmulate) != 0) {
                *emulate = true;
            }
        }
    }
    return matched;
}

void ZeroPending(ProcVirtualPending* pending) noexcept {
    memset(pending, 0, sizeof(*pending));
}

void ClearPendingUnchecked(ProcVirtualPendingTable* table,
                           uint32_t task_slot) noexcept {
    ProcVirtualPending& pending = table->entries[task_slot];
    if ((pending.flags & kProcVirtualPendingActive) != 0 &&
        table->active_count != 0) {
        --table->active_count;
    }
    ZeroPending(&pending);
    ++table->mutation_generation;
}

int InstallPending(ProcVirtualPendingTable* table,
                   const ProcVirtualDispatchConfig& config,
                   const ProcVirtualDispatchTask& task, int32_t syscall_number,
                   const uint64_t arguments[6], uint32_t flags, int32_t fd,
                   ProcVirtualNodeKind node, const char* path,
                   size_t path_length, uint32_t xattr_rule_index) noexcept {
    if (path_length >= kProcVirtualDispatchPathCapacity) {
        return ENAMETOOLONG;
    }
    ProcVirtualPending& pending = table->entries[task.task_slot];
    pending.flags = flags | kProcVirtualPendingActive;
    pending.task_slot = task.task_slot;
    pending.tgid = task.tgid;
    pending.tid = task.tid;
    pending.task_generation = task.generation;
    pending.config_generation = config.generation;
    pending.syscall_number = syscall_number;
    pending.fd = fd;
    pending.node = node;
    pending.xattr_rule_index = xattr_rule_index;
    pending.path_length = static_cast<uint32_t>(path_length);
    for (size_t index = 0; index < 6U; ++index) {
        pending.arguments[index] = arguments[index];
    }
    if (path_length != 0) {
        memcpy(pending.identity_path, path, path_length);
    }
    pending.identity_path[path_length] = '\0';
    if (config.getdents_replay_timeout_ns != 0) {
        pending.replay_deadline_ns =
                task.monotonic_time_ns >
                                UINT64_MAX - config.getdents_replay_timeout_ns
                        ? UINT64_MAX
                        : task.monotonic_time_ns +
                                  config.getdents_replay_timeout_ns;
    }
    ++table->active_count;
    ++table->mutation_generation;
    return 0;
}

uint32_t EffectiveMaxIov(const ProcVirtualDispatchConfig& config) noexcept {
    return config.max_iov_count == 0 ? kProcVirtualDispatchMaxIov
                                     : config.max_iov_count;
}

uint32_t EffectiveMaxReplays(const ProcVirtualDispatchConfig& config) noexcept {
    return config.max_getdents_replays == 0
                   ? kProcVirtualDispatchDefaultDirentReplays
                   : config.max_getdents_replays;
}

int ReadRemoteIovec(const ProcVirtualIo& io,
                    const ProcVirtualDispatchTask& task,
                    const ProcVirtualPending& pending, size_t index,
                    RemoteIovec64* vector) noexcept {
    const uintptr_t remote_vectors =
            static_cast<uintptr_t>(pending.arguments[1]);
    if (index > SIZE_MAX / sizeof(RemoteIovec64)) {
        return EOVERFLOW;
    }
    uintptr_t remote = 0;
    if (!AddAddress(remote_vectors, index * sizeof(RemoteIovec64), &remote)) {
        return EOVERFLOW;
    }
    return ReadRemote(io, task, remote, vector, sizeof(*vector));
}

int RequestedReadSize(const ProcVirtualDispatchConfig& config,
                      const ProcVirtualIo& io,
                      const ProcVirtualDispatchTask& task,
                      const ProcVirtualPending& pending,
                      size_t* requested_size) noexcept {
    *requested_size = 0;
    if (pending.syscall_number == __NR_read ||
        pending.syscall_number == __NR_pread64) {
        if (pending.arguments[2] > SIZE_MAX) {
            return EOVERFLOW;
        }
        *requested_size = static_cast<size_t>(pending.arguments[2]);
        return 0;
    }
    if (pending.syscall_number != __NR_readv) {
        return EINVAL;
    }
    const uint64_t count = pending.arguments[2];
    if (count > EffectiveMaxIov(config)) {
        return EINVAL;
    }
    size_t total = 0;
    for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
        RemoteIovec64 vector{};
        const int error = ReadRemoteIovec(io, task, pending, index, &vector);
        if (error != 0) {
            return error;
        }
        if (vector.length > SIZE_MAX ||
            (vector.length != 0 &&
             (vector.base == 0 ||
              vector.base > UINTPTR_MAX - (vector.length - 1U))) ||
            !AddSize(total, static_cast<size_t>(vector.length), &total)) {
            return EOVERFLOW;
        }
    }
    *requested_size = total;
    return 0;
}

int ScatterReadOutput(const ProcVirtualDispatchConfig& config,
                      const ProcVirtualIo& io,
                      const ProcVirtualDispatchTask& task,
                      const ProcVirtualPending& pending, const uint8_t* input,
                      size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    if (pending.syscall_number == __NR_read ||
        pending.syscall_number == __NR_pread64) {
        return WriteRemote(io, task,
                           static_cast<uintptr_t>(pending.arguments[1]), input,
                           size);
    }
    if (pending.syscall_number != __NR_readv) {
        return EINVAL;
    }
    const uint64_t count = pending.arguments[2];
    if (count > EffectiveMaxIov(config)) {
        return EINVAL;
    }
    size_t copied = 0;
    for (size_t index = 0; index < static_cast<size_t>(count) && copied < size;
         ++index) {
        RemoteIovec64 vector{};
        const int read_error =
                ReadRemoteIovec(io, task, pending, index, &vector);
        if (read_error != 0) {
            return read_error;
        }
        const size_t vector_size = static_cast<size_t>(vector.length);
        const size_t remaining = size - copied;
        const size_t chunk = vector_size < remaining ? vector_size : remaining;
        if (chunk != 0) {
            const int write_error =
                    WriteRemote(io, task, static_cast<uintptr_t>(vector.base),
                                input + copied, chunk);
            if (write_error != 0) {
                return write_error;
            }
            copied += chunk;
        }
    }
    return copied == size ? 0 : EPROTO;
}

int CommitVisibleResult(const ProcVirtualIo& io,
                        const ProcVirtualDispatchTask& task,
                        int64_t kernel_result, int64_t visible_result,
                        bool force_write,
                        ProcVirtualExitResult* result) noexcept {
    result->visible_result = visible_result;
    if (!force_write && visible_result == kernel_result) {
        return 0;
    }
    result->flags |= kProcVirtualExitWriteResult;
    if (io.write_syscall_result == nullptr) {
        return 0;
    }
    const int error = CallbackError(
            io.write_syscall_result(io.opaque, &task, visible_result));
    if (error == 0) {
        result->flags |= kProcVirtualExitResultWritten;
    }
    return error;
}

} // namespace

void InitProcVirtualPendingTable(ProcVirtualPendingTable* table) noexcept {
    if (table == nullptr) {
        return;
    }
    memset(table, 0, sizeof(*table));
    table->magic = kProcVirtualDispatchMagic;
    table->version = kProcVirtualDispatchVersion;
}

bool IsProcVirtualPendingTableInitialized(
        const ProcVirtualPendingTable* table) noexcept {
    return table != nullptr && table->magic == kProcVirtualDispatchMagic &&
           table->version == kProcVirtualDispatchVersion &&
           table->active_count <= kProcVirtualDispatchTaskCapacity;
}

bool ValidateProcVirtualPendingTable(
        const ProcVirtualPendingTable* table) noexcept {
    if (!IsProcVirtualPendingTableInitialized(table)) {
        return false;
    }
    uint32_t active = 0;
    for (uint32_t slot = 0; slot < kProcVirtualDispatchTaskCapacity; ++slot) {
        const ProcVirtualPending& pending = table->entries[slot];
        if ((pending.flags & kProcVirtualPendingActive) == 0) {
            const auto* bytes = reinterpret_cast<const uint8_t*>(&pending);
            for (size_t index = 0; index < sizeof(pending); ++index) {
                if (bytes[index] != 0) {
                    return false;
                }
            }
            continue;
        }
        constexpr uint32_t kOperationFlags =
                kProcVirtualPendingProcText | kProcVirtualPendingDirents |
                kProcVirtualPendingXattrGet | kProcVirtualPendingXattrList;
        constexpr uint32_t kKnownFlags = kProcVirtualPendingActive |
                                         kOperationFlags |
                                         kProcVirtualPendingEmulated;
        const uint32_t operation = pending.flags & kOperationFlags;
        if (pending.task_slot != slot || pending.tgid <= 0 ||
            pending.tid <= 0 || (pending.flags & ~kKnownFlags) != 0 ||
            operation == 0 || (operation & (operation - 1U)) != 0 ||
            pending.path_length >= kProcVirtualDispatchPathCapacity ||
            pending.identity_path[pending.path_length] != '\0' ||
            !BoundedBytes(pending.identity_path, pending.path_length) ||
            ((pending.flags & kProcVirtualPendingEmulated) != 0 &&
             operation != kProcVirtualPendingXattrGet &&
             operation != kProcVirtualPendingXattrList)) {
            return false;
        }
        if ((operation == kProcVirtualPendingProcText &&
             (!IsReadSyscall(pending.syscall_number) ||
              !IsProcTextNode(pending.node) || pending.fd < 0)) ||
            (operation == kProcVirtualPendingDirents &&
             (pending.syscall_number != __NR_getdents64 ||
              !IsProcDirectoryNode(pending.node) || pending.fd < 0))) {
            return false;
        }
        if (operation == kProcVirtualPendingXattrGet ||
            operation == kProcVirtualPendingXattrList) {
            const XattrCall call =
                    DecodeXattrCall(pending.syscall_number, pending.arguments);
            if (!call.valid ||
                (operation == kProcVirtualPendingXattrGet &&
                 (call.list ||
                  pending.xattr_rule_index == kProcVirtualInvalidRule)) ||
                (operation == kProcVirtualPendingXattrList &&
                 (!call.list ||
                  pending.xattr_rule_index != kProcVirtualInvalidRule))) {
                return false;
            }
        }
        ++active;
    }
    return active == table->active_count;
}

int ClearProcVirtualPending(ProcVirtualPendingTable* table,
                            uint32_t task_slot) noexcept {
    if (!IsProcVirtualPendingTableInitialized(table) ||
        task_slot >= kProcVirtualDispatchTaskCapacity) {
        return EINVAL;
    }
    ClearPendingUnchecked(table, task_slot);
    return 0;
}

int DispatchProcVirtualEntry(const ProcVirtualDispatchConfig& config,
                             const ProcVirtualIo& io,
                             ProcVirtualPendingTable* table,
                             const ProcVirtualDispatchTask& task,
                             int32_t syscall_number,
                             const uint64_t arguments[6],
                             ProcVirtualEntryResult* result) noexcept {
    if (result == nullptr || arguments == nullptr ||
        !IsProcVirtualPendingTableInitialized(table) ||
        task.task_slot >= kProcVirtualDispatchTaskCapacity || task.tgid <= 0 ||
        task.tid <= 0) {
        return EINVAL;
    }
    *result = {};
    result->pending_slot = kProcVirtualInvalidRule;
    const int config_error = ValidateConfig(config);
    if (config_error != 0) {
        return config_error;
    }
    ClearPendingUnchecked(table, task.task_slot);

    char identity[kProcVirtualDispatchPathCapacity]{};
    size_t identity_length = 0;
    if (IsReadSyscall(syscall_number)) {
        if (io.snapshot == nullptr) {
            return 0;
        }
        const int32_t fd = static_cast<int32_t>(arguments[0]);
        if (fd < 0) {
            return 0;
        }
        const int identity_error = ResolveIdentityPath(
                io, task, syscall_number, fd, kProcVirtualInvalidArgument, 0,
                identity, sizeof(identity), &identity_length);
        if (MissingIdentityError(identity_error)) {
            return 0;
        }
        if (identity_error != 0) {
            return identity_error;
        }
        ProcVirtualPath parsed{};
        const int parse_error = ParseProcVirtualPath(
                identity, identity_length, task.tgid, task.tid, &parsed);
        if (parse_error == ENOENT || !IsProcTextNode(parsed.kind)) {
            return 0;
        }
        if (parse_error != 0) {
            return parse_error;
        }
        const int install_error = InstallPending(
                table, config, task, syscall_number, arguments,
                kProcVirtualPendingProcText, fd, parsed.kind, identity,
                identity_length, kProcVirtualInvalidRule);
        if (install_error != 0) {
            return install_error;
        }
        result->flags = kProcVirtualEntryHandled | kProcVirtualEntryNeedsExit;
        result->node = parsed.kind;
        result->pending_slot = task.task_slot;
        return 0;
    }

    if (syscall_number == __NR_getdents64) {
        const int32_t fd = static_cast<int32_t>(arguments[0]);
        if (fd < 0) {
            return 0;
        }
        const int identity_error = ResolveIdentityPath(
                io, task, syscall_number, fd, kProcVirtualInvalidArgument, 0,
                identity, sizeof(identity), &identity_length);
        if (MissingIdentityError(identity_error)) {
            return 0;
        }
        if (identity_error != 0) {
            return identity_error;
        }
        ProcVirtualPath parsed{};
        const int parse_error = ParseProcVirtualPath(
                identity, identity_length, task.tgid, task.tid, &parsed);
        if (parse_error == ENOENT || !IsProcDirectoryNode(parsed.kind)) {
            return 0;
        }
        if (parse_error != 0) {
            return parse_error;
        }
        const int install_error = InstallPending(
                table, config, task, syscall_number, arguments,
                kProcVirtualPendingDirents, fd, parsed.kind, identity,
                identity_length, kProcVirtualInvalidRule);
        if (install_error != 0) {
            return install_error;
        }
        result->flags = kProcVirtualEntryHandled | kProcVirtualEntryNeedsExit;
        result->node = parsed.kind;
        result->pending_slot = task.task_slot;
        return 0;
    }

    const XattrCall xattr = DecodeXattrCall(syscall_number, arguments);
    if (!xattr.valid || config.xattr_rule_count == 0) {
        return 0;
    }
    const int identity_error = ResolveIdentityPath(
            io, task, syscall_number, xattr.fd_form ? xattr.fd : -1,
            xattr.path_argument_index, xattr.remote_path, identity,
            sizeof(identity), &identity_length);
    if (MissingIdentityError(identity_error)) {
        return 0;
    }
    if (identity_error != 0) {
        return identity_error;
    }

    uint32_t rule_index = kProcVirtualInvalidRule;
    uint32_t pending_flags = 0;
    uint32_t entry_flags =
            kProcVirtualEntryHandled | kProcVirtualEntryNeedsExit;
    if (xattr.list) {
        bool emulate = false;
        if (!HasXattrListRule(config, xattr, identity, identity_length,
                              &emulate)) {
            return 0;
        }
        pending_flags = kProcVirtualPendingXattrList;
        if (emulate) {
            pending_flags |= kProcVirtualPendingEmulated;
            entry_flags |= kProcVirtualEntrySuppress;
        }
    } else {
        char name[kProcVirtualDispatchXattrNameCapacity]{};
        size_t name_length = 0;
        const int name_error = ReadRemoteCString(
                io, task, xattr.remote_name, name, sizeof(name), &name_length);
        if (name_error != 0) {
            return name_error;
        }
        rule_index = SelectXattrGetRule(config, xattr, identity,
                                        identity_length, name, name_length);
        if (rule_index == kProcVirtualInvalidRule) {
            return 0;
        }
        pending_flags = kProcVirtualPendingXattrGet;
        if ((config.xattr_rules[rule_index].flags &
             kProcVirtualXattrRuleEmulate) != 0) {
            pending_flags |= kProcVirtualPendingEmulated;
            entry_flags |= kProcVirtualEntrySuppress;
        }
    }
    const int install_error = InstallPending(
            table, config, task, syscall_number, arguments, pending_flags,
            xattr.fd_form ? xattr.fd : -1, ProcVirtualNodeKind::kNone, identity,
            identity_length, rule_index);
    if (install_error != 0) {
        return install_error;
    }
    result->flags = entry_flags;
    result->node = ProcVirtualNodeKind::kNone;
    result->pending_slot = task.task_slot;
    return 0;
}

namespace {

int RequestSnapshot(const ProcVirtualDispatchConfig& config,
                    const ProcVirtualIo& io,
                    const ProcVirtualSnapshotRequest& request,
                    size_t* snapshot_size, uint64_t* logical_offset) noexcept {
    if (snapshot_size == nullptr || logical_offset == nullptr ||
        io.snapshot == nullptr || config.snapshot_buffer == nullptr ||
        config.snapshot_capacity == 0) {
        return io.snapshot == nullptr ? ENOSYS : ENOSPC;
    }
    *snapshot_size = 0;
    *logical_offset = 0;
    const int error = CallbackError(io.snapshot(
            io.opaque, &request, config.snapshot_buffer,
            config.snapshot_capacity, snapshot_size, logical_offset));
    if (error != 0) {
        return error;
    }
    return *snapshot_size <= config.snapshot_capacity ? 0 : EOVERFLOW;
}

int CompleteProcText(const ProcVirtualDispatchConfig& config,
                     const ProcVirtualIo& io,
                     const ProcVirtualDispatchTask& task,
                     const ProcVirtualPending& pending, int64_t kernel_result,
                     ProcVirtualExitResult* result) noexcept {
    if (kernel_result < 0 &&
        (pending.flags & kProcVirtualPendingEmulated) == 0) {
        return 0;
    }
    size_t requested_size = 0;
    int error = RequestedReadSize(config, io, task, pending, &requested_size);
    if (error != 0) {
        return error;
    }
    ProcVirtualSnapshotRequest request{};
    request.task = task;
    request.kind = ProcVirtualSnapshotKind::kProcText;
    request.node = pending.node;
    request.syscall_number = pending.syscall_number;
    request.fd = pending.fd;
    request.requested_offset = pending.syscall_number == __NR_pread64
                                       ? pending.arguments[3]
                                       : UINT64_MAX;
    request.requested_size = requested_size;
    request.kernel_result = kernel_result;
    request.identity_path = pending.identity_path;
    request.identity_path_length = pending.path_length;

    size_t snapshot_size = 0;
    uint64_t logical_offset = 0;
    error = RequestSnapshot(config, io, request, &snapshot_size,
                            &logical_offset);
    if (error != 0) {
        return error;
    }
    if (pending.syscall_number == __NR_pread64 &&
        logical_offset != pending.arguments[3]) {
        return EPROTO;
    }
    if (config.rewrite_buffer == nullptr || config.rewrite_capacity == 0) {
        return ENOSPC;
    }

    size_t rewritten_size = 0;
    ProcTextRewriteResult rewrite{};
    if (pending.node == ProcVirtualNodeKind::kMaps) {
        const ProcTextRewriteOptions options{
                config.hidden_ranges, config.hidden_range_count,
                config.reverse_rules, config.reverse_rule_count};
        error = RewriteProcMaps(config.snapshot_buffer, snapshot_size,
                                config.rewrite_buffer, config.rewrite_capacity,
                                options, &rewrite);
        rewritten_size = rewrite.output_size;
    } else if (pending.node == ProcVirtualNodeKind::kSmaps) {
        const ProcTextRewriteOptions options{
                config.hidden_ranges, config.hidden_range_count,
                config.reverse_rules, config.reverse_rule_count};
        error = RewriteProcSmaps(config.snapshot_buffer, snapshot_size,
                                 config.rewrite_buffer, config.rewrite_capacity,
                                 options, &rewrite);
        rewritten_size = rewrite.output_size;
    } else if (pending.node == ProcVirtualNodeKind::kSmapsRollup ||
               pending.node == ProcVirtualNodeKind::kAttrCurrent) {
        if (snapshot_size > config.rewrite_capacity) {
            return ENOSPC;
        }
        if (snapshot_size != 0) {
            memcpy(config.rewrite_buffer, config.snapshot_buffer,
                   snapshot_size);
        }
        rewritten_size = snapshot_size;
    } else {
        return EINVAL;
    }
    if (error != 0) {
        return error;
    }
    const size_t effective_offset =
            logical_offset > rewritten_size
                    ? rewritten_size
                    : static_cast<size_t>(logical_offset);
    const size_t available =
            rewritten_size - effective_offset;
    const size_t visible_size =
            requested_size < available ? requested_size : available;
    if (visible_size > static_cast<size_t>(INT64_MAX)) {
        return EOVERFLOW;
    }
    error = ScatterReadOutput(config, io, task, pending,
                              config.rewrite_buffer + effective_offset,
                              visible_size);
    if (error != 0) {
        return error;
    }
    result->bytes_read = snapshot_size;
    result->bytes_written = visible_size;
    result->mappings_seen = rewrite.mappings_seen;
    result->mappings_hidden = rewrite.mappings_hidden;
    result->paths_rewritten = rewrite.paths_rewritten;
    if (visible_size != 0 ||
        visible_size !=
                static_cast<size_t>(kernel_result < 0 ? 0 : kernel_result)) {
        result->flags |= kProcVirtualExitOutputPatched;
    }
    return CommitVisibleResult(
            io, task, kernel_result, static_cast<int64_t>(visible_size),
            (pending.flags & kProcVirtualPendingEmulated) != 0, result);
}

bool AppendUniqueFd(int32_t fd, int32_t* output, size_t capacity,
                    size_t* count) noexcept {
    for (size_t index = 0; index < *count; ++index) {
        if (output[index] == fd) {
            return true;
        }
    }
    if (*count >= capacity) {
        return false;
    }
    output[(*count)++] = fd;
    return true;
}

int SnapshotProtectedFds(const ProcVirtualDispatchConfig& config,
                         const ProcVirtualIo& io,
                         const ProcVirtualDispatchTask& task, int32_t* output,
                         size_t capacity, size_t* output_count) noexcept {
    *output_count = 0;
    for (size_t index = 0; index < config.protected_fd_count; ++index) {
        if (!AppendUniqueFd(config.protected_fds[index], output, capacity,
                            output_count)) {
            return ENOSPC;
        }
    }
    if (io.snapshot_protected_fds == nullptr) {
        return 0;
    }
    int32_t dynamic[kProcVirtualDispatchMaxProtectedFds]{};
    size_t dynamic_count = 0;
    const int error = CallbackError(io.snapshot_protected_fds(
            io.opaque, &task, dynamic, kProcVirtualDispatchMaxProtectedFds,
            &dynamic_count));
    if (error != 0) {
        return error;
    }
    if (dynamic_count > kProcVirtualDispatchMaxProtectedFds) {
        return EOVERFLOW;
    }
    for (size_t index = 0; index < dynamic_count; ++index) {
        if (!AppendUniqueFd(dynamic[index], output, capacity, output_count)) {
            return ENOSPC;
        }
    }
    return 0;
}

int CompleteDirents(const ProcVirtualDispatchConfig& config,
                    const ProcVirtualIo& io,
                    const ProcVirtualDispatchTask& task,
                    ProcVirtualPending* pending, int64_t kernel_result,
                    ProcVirtualExitResult* result) noexcept {
    if (kernel_result <= 0) {
        return 0;
    }
    if (static_cast<uint64_t>(kernel_result) > pending->arguments[2] ||
        static_cast<uint64_t>(kernel_result) > config.snapshot_capacity ||
        config.snapshot_buffer == nullptr) {
        return EOVERFLOW;
    }
    const size_t returned_size = static_cast<size_t>(kernel_result);
    int error =
            ReadRemote(io, task, static_cast<uintptr_t>(pending->arguments[1]),
                       config.snapshot_buffer, returned_size);
    if (error != 0) {
        return error;
    }
    int32_t protected_fds[kProcVirtualDispatchMaxProtectedFds]{};
    size_t protected_count = 0;
    error = SnapshotProtectedFds(config, io, task, protected_fds,
                                 kProcVirtualDispatchMaxProtectedFds,
                                 &protected_count);
    if (error != 0) {
        return error;
    }
    const ProcDirentFilterOptions options{
            pending->node,   config.tracer_pid,    protected_fds,
            protected_count, config.hidden_ranges, config.hidden_range_count};
    ProcDirentCompactResult compact{};
    error = CompactProcDirents64(config.snapshot_buffer, returned_size, options,
                                 &compact);
    if (error != 0) {
        return error;
    }
    result->bytes_read = returned_size;
    result->records_seen = compact.records_seen;
    result->records_hidden = compact.records_hidden;
    if (compact.all_hidden) {
        if (pending->replay_count >= EffectiveMaxReplays(config)) {
            return ELOOP;
        }
        if (pending->replay_deadline_ns != 0 && task.monotonic_time_ns != 0 &&
            task.monotonic_time_ns > pending->replay_deadline_ns) {
            return ETIMEDOUT;
        }
        ++pending->replay_count;
        result->flags |= kProcVirtualExitReplay;
        result->visible_result = 0;
        result->replay_syscall_number = pending->syscall_number;
        result->replay_count = pending->replay_count;
        result->instruction_rewind_bytes = 4U;
        for (size_t index = 0; index < 6U; ++index) {
            result->replay_arguments[index] = pending->arguments[index];
        }
        return 0;
    }
    error = WriteRemote(io, task, static_cast<uintptr_t>(pending->arguments[1]),
                        config.snapshot_buffer, compact.visible_size);
    if (error != 0) {
        return error;
    }
    result->bytes_written = compact.visible_size;
    if (compact.records_hidden != 0) {
        result->flags |= kProcVirtualExitOutputPatched;
    }
    return CommitVisibleResult(io, task, kernel_result,
                               static_cast<int64_t>(compact.visible_size),
                               false, result);
}

int CompleteXattrGet(const ProcVirtualDispatchConfig& config,
                     const ProcVirtualIo& io,
                     const ProcVirtualDispatchTask& task,
                     const ProcVirtualPending& pending, int64_t kernel_result,
                     ProcVirtualExitResult* result) noexcept {
    if (pending.xattr_rule_index >= config.xattr_rule_count) {
        return ESTALE;
    }
    if ((pending.flags & kProcVirtualPendingEmulated) == 0 &&
        kernel_result < 0 && kernel_result != -ENODATA &&
        kernel_result != -ERANGE && kernel_result != -ENOTSUP) {
        return 0;
    }
    const ProcVirtualXattrRule& rule =
            config.xattr_rules[pending.xattr_rule_index];
    const XattrCall call =
            DecodeXattrCall(pending.syscall_number, pending.arguments);
    if (!call.valid || call.list) {
        return EPROTO;
    }
    size_t result_size = 0;
    int error = ApplyXattrGetOverlay(rule.value, rule.value_size, nullptr, 0,
                                     &result_size);
    if (error != 0) {
        return error;
    }
    if (result_size > static_cast<size_t>(INT64_MAX)) {
        return EOVERFLOW;
    }
    int64_t visible_result = static_cast<int64_t>(result_size);
    if (call.output_capacity != 0 && call.output_capacity < result_size) {
        visible_result = -ERANGE;
    } else if (call.output_capacity != 0 && result_size != 0) {
        if (config.rewrite_buffer == nullptr ||
            config.rewrite_capacity < result_size) {
            return ENOSPC;
        }
        error = ApplyXattrGetOverlay(rule.value, rule.value_size,
                                     config.rewrite_buffer,
                                     config.rewrite_capacity, &result_size);
        if (error != 0) {
            return error;
        }
        error = WriteRemote(io, task, call.remote_output, config.rewrite_buffer,
                            result_size);
        if (error != 0) {
            return error;
        }
        result->bytes_written = result_size;
        result->flags |= kProcVirtualExitOutputPatched;
    }
    return CommitVisibleResult(
            io, task, kernel_result, visible_result,
            (pending.flags & kProcVirtualPendingEmulated) != 0, result);
}

int CompleteXattrList(const ProcVirtualDispatchConfig& config,
                      const ProcVirtualIo& io,
                      const ProcVirtualDispatchTask& task,
                      const ProcVirtualPending& pending, int64_t kernel_result,
                      ProcVirtualExitResult* result) noexcept {
    const bool emulated =
            (pending.flags & kProcVirtualPendingEmulated) != 0;
    if (kernel_result < 0 && !emulated) {
        return 0;
    }
    const XattrCall call =
            DecodeXattrCall(pending.syscall_number, pending.arguments);
    if (!call.valid || !call.list) {
        return EPROTO;
    }
    size_t native_size = kernel_result < 0
                                 ? 0U
                                 : static_cast<size_t>(kernel_result);
    if (emulated || (call.output_capacity == 0 && native_size != 0)) {
        ProcVirtualSnapshotRequest request{};
        request.task = task;
        request.kind = ProcVirtualSnapshotKind::kXattrList;
        request.node = ProcVirtualNodeKind::kNone;
        request.syscall_number = pending.syscall_number;
        request.fd = pending.fd;
        request.requested_size = call.output_capacity;
        request.kernel_result = kernel_result;
        request.identity_path = pending.identity_path;
        request.identity_path_length = pending.path_length;
        uint64_t logical_offset = 0;
        size_t snapshot_size = 0;
        const int snapshot_error = RequestSnapshot(
                config, io, request, &snapshot_size, &logical_offset);
        if (snapshot_error != 0) {
            return snapshot_error;
        }
        if (logical_offset != 0) {
            return EPROTO;
        }
        native_size = snapshot_size;
        result->bytes_read = native_size;
    } else if (call.output_capacity != 0) {
        if (native_size > call.output_capacity ||
            native_size > config.snapshot_capacity ||
            (native_size != 0 && config.snapshot_buffer == nullptr)) {
            return EOVERFLOW;
        }
        const int read_error = ReadRemote(io, task, call.remote_output,
                                          config.snapshot_buffer, native_size);
        if (read_error != 0) {
            return read_error;
        }
        result->bytes_read = native_size;
    } else if (native_size == 0) {
        // A successful zero-length size query proves that the backing list is
        // empty, so no provider round trip is needed.
    }
    if (config.rewrite_buffer == nullptr || config.rewrite_capacity == 0) {
        return ENOSPC;
    }

    const uint8_t* current_input = config.snapshot_buffer;
    size_t current_size = native_size;
    bool transformed = false;
    XattrListOverlayResult overlay{};
    for (size_t index = 0; index < config.xattr_rule_count; ++index) {
        const ProcVirtualXattrRule& rule = config.xattr_rules[index];
        if (!XattrRuleMatchesCall(rule, call, pending.identity_path,
                                  pending.path_length)) {
            continue;
        }
        const int overlay_error = ApplyXattrListOverlay(
                current_input, current_size, rule.name, rule.name_length,
                config.rewrite_buffer, config.rewrite_capacity, &overlay);
        if (overlay_error != 0) {
            return overlay_error == ERANGE ? ENOSPC : overlay_error;
        }
        current_input = config.rewrite_buffer;
        current_size = overlay.output_size;
        transformed = true;
    }
    if (!transformed || current_size > static_cast<size_t>(INT64_MAX)) {
        return !transformed ? EPROTO : EOVERFLOW;
    }
    result->xattr_names_seen = overlay.names_seen;
    result->xattr_names_emitted = overlay.names_emitted;

    int64_t visible_result = static_cast<int64_t>(current_size);
    if (call.output_capacity != 0 && call.output_capacity < current_size) {
        visible_result = -ERANGE;
    } else if (call.output_capacity != 0 && current_size != 0) {
        const int write_error =
                WriteRemote(io, task, call.remote_output, config.rewrite_buffer,
                            current_size);
        if (write_error != 0) {
            return write_error;
        }
        result->bytes_written = current_size;
        result->flags |= kProcVirtualExitOutputPatched;
    }
    return CommitVisibleResult(io, task, kernel_result, visible_result,
                               emulated, result);
}

} // namespace

int DispatchProcVirtualExit(const ProcVirtualDispatchConfig& config,
                            const ProcVirtualIo& io,
                            ProcVirtualPendingTable* table,
                            const ProcVirtualDispatchTask& task,
                            int64_t kernel_result,
                            ProcVirtualExitResult* result) noexcept {
    if (result == nullptr || !IsProcVirtualPendingTableInitialized(table) ||
        task.task_slot >= kProcVirtualDispatchTaskCapacity || task.tgid <= 0 ||
        task.tid <= 0) {
        return EINVAL;
    }
    *result = {};
    result->visible_result = kernel_result;
    const int config_error = ValidateConfig(config);
    if (config_error != 0) {
        return config_error;
    }
    ProcVirtualPending& pending = table->entries[task.task_slot];
    if ((pending.flags & kProcVirtualPendingActive) == 0) {
        return 0;
    }
    if (pending.task_slot != task.task_slot || pending.tgid != task.tgid ||
        pending.tid != task.tid || pending.task_generation != task.generation ||
        pending.config_generation != config.generation) {
        return ESTALE;
    }

    result->flags = kProcVirtualExitHandled;
    result->node = pending.node;
    int error = 0;
    if ((pending.flags & kProcVirtualPendingProcText) != 0) {
        error = CompleteProcText(config, io, task, pending, kernel_result,
                                 result);
    } else if ((pending.flags & kProcVirtualPendingDirents) != 0) {
        error = CompleteDirents(config, io, task, &pending, kernel_result,
                                result);
    } else if ((pending.flags & kProcVirtualPendingXattrGet) != 0) {
        error = CompleteXattrGet(config, io, task, pending, kernel_result,
                                 result);
    } else if ((pending.flags & kProcVirtualPendingXattrList) != 0) {
        error = CompleteXattrList(config, io, task, pending, kernel_result,
                                  result);
    } else {
        error = EPROTO;
    }
    if (error != 0) {
        ClearPendingUnchecked(table, task.task_slot);
        return error;
    }
    if ((result->flags & kProcVirtualExitReplay) == 0) {
        ClearPendingUnchecked(table, task.task_slot);
    } else {
        ++table->mutation_generation;
    }
    return 0;
}

} // namespace hookself::internal
