#include "proc_virtual_selftest.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "hookself/public_api.h"
#include "proc_virtual_dispatch.h"
#include "proc_virtual_resident_state.h"
#include "proc_virtual_view.h"

namespace hookself::internal {
namespace {

void Check(ProcVirtualSelfTestReport* report, bool condition,
           int32_t failure) noexcept {
    ++report->checks;
    if (!condition) {
        ++report->failures;
        if (report->first_failure == 0) {
            report->first_failure = failure;
        }
    }
}

bool Contains(const uint8_t* data, size_t size, const char* text) noexcept {
    size_t text_size = 0;
    while (text[text_size] != '\0') {
        ++text_size;
    }
    if (text_size > size) {
        return false;
    }
    for (size_t offset = 0; offset <= size - text_size; ++offset) {
        if (memcmp(data + offset, text, text_size) == 0) {
            return true;
        }
    }
    return false;
}

struct MockIo {
    const char* identity;
    const uint8_t* snapshot;
    size_t snapshot_size;
    int64_t written_result;
    uint32_t result_writes;
};

int MockRead(void*, int32_t, int32_t, uintptr_t address, void* output,
             size_t size) noexcept {
    if (address == 0 || output == nullptr) {
        return EFAULT;
    }
    memcpy(output, reinterpret_cast<const void*>(address), size);
    return 0;
}

int MockWrite(void*, int32_t, int32_t, uintptr_t address,
              const void* input, size_t size) noexcept {
    if (address == 0 || input == nullptr) {
        return EFAULT;
    }
    memcpy(reinterpret_cast<void*>(address), input, size);
    return 0;
}

int MockResolve(void* opaque, const ProcVirtualIdentityQuery*, char* output,
                size_t capacity, size_t* output_length) noexcept {
    auto* mock = static_cast<MockIo*>(opaque);
    const size_t length = strlen(mock->identity);
    if (length >= capacity) {
        return ENAMETOOLONG;
    }
    memcpy(output, mock->identity, length + 1U);
    *output_length = length;
    return 0;
}

int MockSnapshot(void* opaque, const ProcVirtualSnapshotRequest*,
                 uint8_t* output, size_t capacity, size_t* output_size,
                 uint64_t* logical_offset) noexcept {
    auto* mock = static_cast<MockIo*>(opaque);
    if (mock->snapshot_size > capacity) {
        return ENOSPC;
    }
    if (mock->snapshot_size != 0) {
        memcpy(output, mock->snapshot, mock->snapshot_size);
    }
    *output_size = mock->snapshot_size;
    *logical_offset = 0;
    return 0;
}

int MockProtected(void*, const ProcVirtualDispatchTask*, int32_t*, size_t,
                  size_t* output_count) noexcept {
    *output_count = 0;
    return 0;
}

int MockResult(void* opaque, const ProcVirtualDispatchTask*,
               int64_t result) noexcept {
    auto* mock = static_cast<MockIo*>(opaque);
    mock->written_result = result;
    ++mock->result_writes;
    return 0;
}

ProcVirtualIo MakeMockIo(MockIo* mock) noexcept {
    return {mock, MockRead, MockWrite, MockResolve, MockSnapshot,
            MockProtected, MockResult};
}

size_t AppendDirent(uint8_t* output, size_t capacity, uint64_t inode,
                    int64_t offset, const char* name) noexcept {
    const size_t name_size = strlen(name);
    const size_t record_size =
            (19U + name_size + 1U + 7U) & ~static_cast<size_t>(7U);
    if (record_size > capacity || record_size > UINT16_MAX) {
        return 0;
    }
    memset(output, 0, record_size);
    const uint16_t encoded_size = static_cast<uint16_t>(record_size);
    memcpy(output, &inode, sizeof(inode));
    memcpy(output + 8U, &offset, sizeof(offset));
    memcpy(output + 16U, &encoded_size, sizeof(encoded_size));
    output[18U] = 8U;
    memcpy(output + 19U, name, name_size + 1U);
    return record_size;
}

ProcVirtualDispatchConfig MakeConfig(
        ProcVirtualResidentState* state) noexcept {
    ProcVirtualDispatchConfig config{};
    config.generation = 7;
    config.tracer_pid = 321;
    config.max_iov_count = kProcVirtualDispatchMaxIov;
    config.max_getdents_replays = 4;
    config.getdents_replay_timeout_ns = 1000000000ULL;
    config.snapshot_buffer = state->snapshot_buffer;
    config.snapshot_capacity = sizeof(state->snapshot_buffer);
    config.rewrite_buffer = state->rewrite_buffer;
    config.rewrite_capacity = sizeof(state->rewrite_buffer);
    return config;
}

}  // namespace

ProcVirtualSelfTestReport RunProcVirtualSelfTest() noexcept {
    ProcVirtualSelfTestReport report{};

    constexpr char kMaps[] =
            "1000-2000 r-xp 00000000 00:00 0 /host/app/liba.so\n"
            "2000-3000 rw-p 00000000 00:00 0 /host/runtime/internal\n";
    const ProcVirtualAddressRange hidden[] = {{0x2800U, 0x100U}};
    const ProcReversePathRule reverse[] = {{
            "/host", 5U, "/guest", 6U, 10,
            kProcReversePathRuleVisible}};
    const ProcTextRewriteOptions rewrite_options{
            hidden, 1U, reverse, 1U};
    uint8_t rewritten[1024]{};
    ProcTextRewriteResult rewrite{};
    int error = RewriteProcMaps(
            reinterpret_cast<const uint8_t*>(kMaps), sizeof(kMaps) - 1U,
            rewritten, sizeof(rewritten), rewrite_options, &rewrite);
    Check(&report,
          error == 0 && rewrite.mappings_seen == 2U &&
                  rewrite.mappings_hidden == 1U &&
                  rewrite.paths_rewritten == 1U &&
                  Contains(rewritten, rewrite.output_size,
                           "/guest/app/liba.so") &&
                  !Contains(rewritten, rewrite.output_size, "internal"),
          8101);

    constexpr char kSmaps[] =
            "1000-2000 r-xp 00000000 00:00 0 /host/app/liba.so\n"
            "Size:                  4 kB\n"
            "Rss:                   4 kB\n"
            "2000-3000 rw-p 00000000 00:00 0 /host/runtime/internal\n"
            "Size:                  4 kB\n"
            "Rss:                   4 kB\n";
    memset(rewritten, 0, sizeof(rewritten));
    error = RewriteProcSmaps(
            reinterpret_cast<const uint8_t*>(kSmaps), sizeof(kSmaps) - 1U,
            rewritten, sizeof(rewritten), rewrite_options, &rewrite);
    Check(&report,
          error == 0 && rewrite.mappings_seen == 2U &&
                  rewrite.mappings_hidden == 1U &&
                  Contains(rewritten, rewrite.output_size,
                           "/guest/app/liba.so") &&
                  !Contains(rewritten, rewrite.output_size, "internal"),
          8102);

    void* memory = mmap(nullptr, sizeof(ProcVirtualResidentState),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Check(&report, memory != MAP_FAILED, 8103);
    if (memory == MAP_FAILED) {
        return report;
    }
    auto* state = static_cast<ProcVirtualResidentState*>(memory);
    InitProcVirtualResidentState(state);
    Check(&report, ValidateProcVirtualResidentState(state), 8104);

    uint64_t logical = UINT64_MAX;
    Check(&report,
          BeginProcVirtualSequentialRead(
                  state, 9, 3, "/proc/self/maps", 15U, 0, 64,
                  &logical) == 0 &&
                  logical == 0 &&
                  AdvanceProcVirtualSequentialRead(
                          state, 9, 3, "/proc/self/maps", 15U, 40) == 0 &&
                  BeginProcVirtualSequentialRead(
                          state, 9, 4, "/proc/self/maps", 15U, 64, 96,
                          &logical) == 0 &&
                  logical == 40 && ValidateProcVirtualResidentState(state),
          8105);

    ProcVirtualDispatchConfig config = MakeConfig(state);
    config.hidden_ranges = hidden;
    config.hidden_range_count = 1;
    config.reverse_rules = reverse;
    config.reverse_rule_count = 1;
    ProcVirtualDispatchTask task{5, 100, 101, 0, 11, 1000};
    uint8_t remote_output[1024]{};
    uint64_t read_arguments[6] = {
            7, reinterpret_cast<uintptr_t>(remote_output),
            sizeof(remote_output), 0, 0, 0};
    MockIo mock{"/proc/self/maps",
                reinterpret_cast<const uint8_t*>(kMaps),
                sizeof(kMaps) - 1U, 0, 0};
    ProcVirtualIo io = MakeMockIo(&mock);
    ProcVirtualEntryResult entry{};
    error = DispatchProcVirtualEntry(
            config, io, &state->pending, task, __NR_read, read_arguments,
            &entry);
    ProcVirtualExitResult exit{};
    if (error == 0) {
        error = DispatchProcVirtualExit(
                config, io, &state->pending, task, 64, &exit);
    }
    Check(&report,
          error == 0 &&
                  (entry.flags & kProcVirtualEntryHandled) != 0 &&
                  (exit.flags & kProcVirtualExitOutputPatched) != 0 &&
                  exit.mappings_hidden == 1U && mock.result_writes == 1U &&
                  mock.written_result ==
                          static_cast<int64_t>(exit.bytes_written) &&
                  Contains(remote_output, exit.bytes_written,
                           "/guest/app/liba.so") &&
                  !Contains(remote_output, exit.bytes_written, "internal"),
          8106);

    uint8_t dirents[256]{};
    size_t dirent_size = AppendDirent(
            dirents, sizeof(dirents), 1, 1, "321");
    dirent_size += AppendDirent(
            dirents + dirent_size, sizeof(dirents) - dirent_size, 2, 2,
            "999");
    mock.identity = "/proc";
    uint64_t dirent_arguments[6] = {
            8, reinterpret_cast<uintptr_t>(dirents), dirent_size, 0, 0, 0};
    error = DispatchProcVirtualEntry(
            config, io, &state->pending, task, __NR_getdents64,
            dirent_arguments, &entry);
    if (error == 0) {
        error = DispatchProcVirtualExit(
                config, io, &state->pending, task,
                static_cast<int64_t>(dirent_size), &exit);
    }
    Check(&report,
          error == 0 && exit.records_seen == 2U &&
                  exit.records_hidden == 1U && exit.bytes_written != 0 &&
                  !Contains(dirents, exit.bytes_written, "321") &&
                  Contains(dirents, exit.bytes_written, "999"),
          8107);

    memset(dirents, 0, sizeof(dirents));
    dirent_size = AppendDirent(dirents, sizeof(dirents), 3, 3, "321");
    dirent_arguments[2] = dirent_size;
    error = DispatchProcVirtualEntry(
            config, io, &state->pending, task, __NR_getdents64,
            dirent_arguments, &entry);
    if (error == 0) {
        error = DispatchProcVirtualExit(
                config, io, &state->pending, task,
                static_cast<int64_t>(dirent_size), &exit);
    }
    Check(&report,
          error == 0 && (exit.flags & kProcVirtualExitReplay) != 0 &&
                  exit.replay_count == 1U && exit.records_seen == 1U &&
                  state->pending.active_count == 1U,
          8108);
    (void)ClearProcVirtualPending(&state->pending, task.task_slot);

    static constexpr char kRoot[] = "/";
    static constexpr char kSelinux[] = "security.selinux";
    const uint8_t fake_label[] = "u:r:hookself_test:s0";
    const ProcVirtualXattrRule xattr_rule{
            kRoot, sizeof(kRoot) - 1U, kSelinux,
            sizeof(kSelinux) - 1U, fake_label, sizeof(fake_label), 100,
            kProcVirtualXattrRuleEmulate};
    config.xattr_rules = &xattr_rule;
    config.xattr_rule_count = 1;
    mock.identity = "/data/local/tmp/file";
    uint8_t xattr_output[128]{};
    uint64_t getxattr_arguments[6] = {
            reinterpret_cast<uintptr_t>(mock.identity),
            reinterpret_cast<uintptr_t>(kSelinux),
            reinterpret_cast<uintptr_t>(xattr_output), sizeof(xattr_output),
            0, 0};
    mock.result_writes = 0;
    error = DispatchProcVirtualEntry(
            config, io, &state->pending, task, __NR_getxattr,
            getxattr_arguments, &entry);
    if (error == 0) {
        error = DispatchProcVirtualExit(
                config, io, &state->pending, task, -ENOSYS, &exit);
    }
    Check(&report,
          error == 0 &&
                  (entry.flags & kProcVirtualEntrySuppress) != 0 &&
                  exit.visible_result == static_cast<int64_t>(
                                                 sizeof(fake_label)) &&
                  memcmp(xattr_output, fake_label, sizeof(fake_label)) == 0 &&
                  mock.result_writes == 1U,
          8109);

    const uint8_t backing_names[] = "user.test\0";
    mock.snapshot = backing_names;
    mock.snapshot_size = sizeof(backing_names) - 1U;
    memset(xattr_output, 0, sizeof(xattr_output));
    uint64_t listxattr_arguments[6] = {
            reinterpret_cast<uintptr_t>(mock.identity),
            reinterpret_cast<uintptr_t>(xattr_output), sizeof(xattr_output),
            0, 0, 0};
    mock.result_writes = 0;
    error = DispatchProcVirtualEntry(
            config, io, &state->pending, task, __NR_listxattr,
            listxattr_arguments, &entry);
    if (error == 0) {
        error = DispatchProcVirtualExit(
                config, io, &state->pending, task, -ENOSYS, &exit);
    }
    Check(&report,
          error == 0 &&
                  (entry.flags & kProcVirtualEntrySuppress) != 0 &&
                  Contains(xattr_output, exit.bytes_written, "user.test") &&
                  Contains(xattr_output, exit.bytes_written,
                           "security.selinux") &&
                  mock.result_writes == 1U,
          8110);
    Check(&report, ValidateProcVirtualResidentState(state), 8111);

    munmap(memory, sizeof(ProcVirtualResidentState));
    return report;
}

namespace {

int ReadSmokeSnapshot(const char* path, uint8_t* output, size_t capacity,
                      size_t* output_size) noexcept {
    *output_size = 0;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return errno;
    }
    int error = 0;
    while (*output_size < capacity) {
        const ssize_t count = read(
                fd, output + *output_size, capacity - *output_size);
        if (count > 0) {
            *output_size += static_cast<size_t>(count);
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        error = errno;
        break;
    }
    if (error == 0 && *output_size == capacity) {
        uint8_t extra = 0;
        const ssize_t count = read(fd, &extra, 1U);
        if (count > 0) {
            error = EOVERFLOW;
        }
    }
    close(fd);
    return error;
}

bool DirentSnapshotContainsPid(const uint8_t* data, size_t size,
                               int32_t pid) noexcept {
    char expected[16]{};
    size_t digits = 0;
    uint32_t value = static_cast<uint32_t>(pid);
    do {
        expected[digits++] = static_cast<char>('0' + value % 10U);
        value /= 10U;
    } while (value != 0 && digits < sizeof(expected));
    for (size_t left = 0, right = digits == 0 ? 0 : digits - 1U;
         left < right; ++left, --right) {
        const char temporary = expected[left];
        expected[left] = expected[right];
        expected[right] = temporary;
    }
    size_t offset = 0;
    while (offset < size) {
        if (size - offset < 20U) {
            return true;
        }
        uint16_t record_size = 0;
        memcpy(&record_size, data + offset + 16U, sizeof(record_size));
        if (record_size < 20U || record_size > size - offset) {
            return true;
        }
        const char* name = reinterpret_cast<const char*>(
                data + offset + 19U);
        const size_t name_capacity = record_size - 19U;
        size_t name_size = 0;
        while (name_size < name_capacity && name[name_size] != '\0') {
            ++name_size;
        }
        if (name_size == digits &&
            memcmp(name, expected, digits) == 0) {
            return true;
        }
        offset += record_size;
    }
    return false;
}

bool ProcDirectoryHidesTracer(int32_t tracer_pid) noexcept {
    const int fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    uint8_t buffer[4096]{};
    bool hidden = true;
    for (uint32_t iteration = 0; iteration < 4096U; ++iteration) {
        const long count = syscall(
                __NR_getdents64, fd, buffer, sizeof(buffer));
        if (count < 0) {
            hidden = false;
            break;
        }
        if (count == 0) {
            break;
        }
        if (DirentSnapshotContainsPid(
                    buffer, static_cast<size_t>(count), tracer_pid)) {
            hidden = false;
            break;
        }
    }
    close(fd);
    return hidden;
}

int32_t FindTracerPid(HookselfRuntime* runtime) noexcept {
    HookselfEvent events[32]{};
    const size_t count = hookself_read_events(
            runtime, events, sizeof(events) / sizeof(events[0]));
    for (size_t index = 0; index < count; ++index) {
        if (events[index].kind == HOOKSELF_EVENT_LIFECYCLE &&
            events[index].result > 0 &&
            events[index].result <= INT32_MAX) {
            return static_cast<int32_t>(events[index].result);
        }
    }
    return -1;
}

}  // namespace

ProcVirtualResidentSmokeReport RunProcVirtualResidentSmokeTest(
        const char* virtual_backing_dir) noexcept {
    ProcVirtualResidentSmokeReport report{};
    report.create_result = HOOKSELF_E_INTERNAL;
    report.start_result = HOOKSELF_E_INVALID_STATE;
    report.stop_result = HOOKSELF_E_INVALID_STATE;
    report.tracer_pid = -1;

    static constexpr uint8_t kFakeContext[] =
            "u:r:hookself_proc_virtual:s0";
    HookselfVirtualFile selinux{};
    selinux.struct_size = sizeof(selinux);
    selinux.file_id = 0x50564f53U;
    selinux.provider = HOOKSELF_VFILE_SELINUX_CONTEXT;
    selinux.mode = 0444;
    selinux.initial_content = kFakeContext;
    selinux.initial_content_size = sizeof(kFakeContext) - 1U;
    memcpy(selinux.guest_path, "/proc/self/attr/current",
           sizeof("/proc/self/attr/current"));

    HookselfConfig config{};
    hookself_default_config(&config);
    config.failure_mode = HOOKSELF_FAILURE_FAIL_CLOSED;
    config.flags |= HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW |
                    HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES;
    config.virtual_file_count = 1;
    config.virtual_files = &selinux;
    config.event_capacity = 128;
    const size_t backing_length = virtual_backing_dir == nullptr
            ? 0
            : strnlen(virtual_backing_dir,
                      sizeof(config.virtual_backing_dir));
    if (backing_length == 0 ||
        backing_length == sizeof(config.virtual_backing_dir)) {
        report.create_result = HOOKSELF_E_INVALID_ARGUMENT;
        return report;
    }
    memcpy(config.virtual_backing_dir, virtual_backing_dir,
           backing_length + 1U);

    HookselfRuntime* runtime = nullptr;
    report.create_result = hookself_create(&config, &runtime);
    if (report.create_result != HOOKSELF_OK || runtime == nullptr) {
        hookself_destroy(runtime);
        return report;
    }
    report.start_result = hookself_start(runtime);
    if (report.start_result != HOOKSELF_OK) {
        hookself_destroy(runtime);
        return report;
    }
    report.tracer_pid = FindTracerPid(runtime);

    void* memory = mmap(nullptr, kProcVirtualResidentBufferCapacity,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory != MAP_FAILED) {
        auto* snapshot = static_cast<uint8_t*>(memory);
        size_t snapshot_size = 0;
        const int maps_error = ReadSmokeSnapshot(
                "/proc/self/maps", snapshot,
                kProcVirtualResidentBufferCapacity, &snapshot_size);
        report.maps_hidden =
                maps_error == 0 &&
                        !Contains(snapshot, snapshot_size, "libhookself.so") &&
                        !Contains(snapshot, snapshot_size,
                                  "hookself-session")
                        ? 1
                        : 0;
        snapshot_size = 0;
        const int smaps_error = ReadSmokeSnapshot(
                "/proc/self/smaps", snapshot,
                kProcVirtualResidentBufferCapacity, &snapshot_size);
        report.smaps_hidden =
                smaps_error == 0 &&
                        Contains(snapshot, snapshot_size, "Rss:") &&
                        !Contains(snapshot, snapshot_size, "libhookself.so") &&
                        !Contains(snapshot, snapshot_size,
                                  "hookself-session")
                        ? 1
                        : 0;
        munmap(memory, kProcVirtualResidentBufferCapacity);
    }
    report.proc_dir_hidden =
            report.tracer_pid > 0 && ProcDirectoryHidesTracer(
                                               report.tracer_pid)
                    ? 1
                    : 0;

    char xattr_path[HOOKSELF_PATH_CAPACITY]{};
    const int xattr_path_size = snprintf(
            xattr_path, sizeof(xattr_path), "%s/proc_virtual_xattr_smoke-%d",
            virtual_backing_dir, static_cast<int>(getpid()));
    int smoke_fd = -1;
    int smoke_error = 0;
    if (xattr_path_size <= 0) {
        smoke_error = EINVAL;
    } else if (static_cast<size_t>(xattr_path_size) >= sizeof(xattr_path)) {
        smoke_error = ENAMETOOLONG;
    } else {
        errno = 0;
        smoke_fd = open(xattr_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        smoke_error = smoke_fd < 0 ? errno : 0;
    }
    report.xattr_open_result = smoke_fd;
    report.xattr_open_errno = smoke_error;
    if (smoke_fd >= 0) {
        close(smoke_fd);
        uint8_t value[128]{};
        errno = 0;
        const ssize_t value_size = getxattr(
                xattr_path, "security.selinux", value, sizeof(value));
        report.xattr_get_result = value_size;
        report.xattr_get_errno = value_size < 0 ? errno : 0;
        report.xattr_get_match =
                value_size >= static_cast<ssize_t>(
                                      sizeof(kFakeContext) - 1U) &&
                        memcmp(value, kFakeContext,
                               sizeof(kFakeContext) - 1U) == 0
                        ? 1
                        : 0;
        uint8_t names[1024]{};
        errno = 0;
        const ssize_t names_size = listxattr(
                xattr_path, reinterpret_cast<char*>(names), sizeof(names));
        report.xattr_list_result = names_size;
        report.xattr_list_errno = names_size < 0 ? errno : 0;
        report.xattr_list_match =
                names_size > 0 &&
                        Contains(names, static_cast<size_t>(names_size),
                                 "security.selinux")
                        ? 1
                        : 0;
        unlink(xattr_path);
    }

    report.stop_result = hookself_stop(runtime);
    HookselfStats stats{};
    stats.struct_size = sizeof(stats);
    if (hookself_get_stats(runtime, &stats) == HOOKSELF_OK) {
        report.fatal_code = stats.fatal_code;
        report.fatal_errno = stats.fatal_errno;
    }
    report.verdict =
            report.stop_result == HOOKSELF_OK && report.tracer_pid > 0 &&
                    report.maps_hidden != 0 && report.smaps_hidden != 0 &&
                    report.proc_dir_hidden != 0 &&
                    report.xattr_get_match != 0 &&
                    report.xattr_list_match != 0 &&
                    report.fatal_code == 0
                    ? 1
                    : 0;
    hookself_destroy(runtime);
    return report;
}

}  // namespace hookself::internal
