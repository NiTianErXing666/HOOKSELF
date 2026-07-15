#include "platform/procfs.h"

#include "platform/raw_syscall_arm64.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

namespace hookself {
namespace platform {
namespace {

struct LinuxDirent64 {
    uint64_t inode;
    int64_t offset;
    uint16_t record_length;
    uint8_t type;
    char name[1];
};

bool AppendPositiveDecimal(char* output, size_t capacity, size_t* length,
                           pid_t value) noexcept {
    char reversed[16];
    size_t count = 0;
    uint32_t current = static_cast<uint32_t>(value);
    do {
        reversed[count++] = static_cast<char>('0' + current % 10);
        current /= 10;
    } while (current != 0 && count < sizeof(reversed));

    if (*length + count >= capacity) {
        return false;
    }
    while (count > 0) {
        output[(*length)++] = reversed[--count];
    }
    output[*length] = '\0';
    return true;
}

bool BuildTaskDirectoryPath(pid_t pid,
                            char output[kTaskDirectoryPathCapacity]) noexcept {
    constexpr char prefix[] = "/proc/";
    constexpr char suffix[] = "/task";
    size_t length = 0;

    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
        output[length++] = prefix[i];
    }
    if (!AppendPositiveDecimal(output, kTaskDirectoryPathCapacity, &length, pid)) {
        return false;
    }
    if (length + sizeof(suffix) > kTaskDirectoryPathCapacity) {
        return false;
    }
    for (size_t i = 0; i < sizeof(suffix); ++i) {
        output[length++] = suffix[i];
    }
    return true;
}

bool BuildProcPidFilePath(pid_t pid, const char* suffix, size_t suffix_length,
                          char output[kTaskDirectoryPathCapacity]) noexcept {
    constexpr char prefix[] = "/proc/";
    size_t length = 0;

    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
        output[length++] = prefix[i];
    }
    if (!AppendPositiveDecimal(output, kTaskDirectoryPathCapacity, &length, pid)) {
        return false;
    }
    if (length + suffix_length + 1 > kTaskDirectoryPathCapacity) {
        return false;
    }
    for (size_t i = 0; i < suffix_length; ++i) {
        output[length++] = suffix[i];
    }
    output[length] = '\0';
    return true;
}

bool ParsePositiveTid(const char* text, size_t length, pid_t* result) noexcept {
    if (length == 0) {
        return false;
    }

    int64_t value = 0;
    for (size_t i = 0; i < length; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
        value = value * 10 + (text[i] - '0');
        if (value > INT32_MAX) {
            return false;
        }
    }
    if (value <= 0) {
        return false;
    }

    *result = static_cast<pid_t>(value);
    return true;
}

int CloseAndReturn(int fd, int error, size_t count, size_t* tid_count) noexcept {
    (void)RawClose(fd);
    *tid_count = count;
    return error;
}

int ReadProcFile(const char* path, char* output, size_t capacity,
                 size_t* output_length, bool* truncated) noexcept {
    const long open_result = RawOpenAt(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    const int open_error = RawError(open_result);
    if (open_error != 0) {
        return open_error;
    }
    const int fd = static_cast<int>(open_result);

    size_t length = 0;
    while (length < capacity) {
        const long read_result = RawRead(fd, output + length, capacity - length);
        const int read_error = RawError(read_result);
        if (read_error == EINTR) {
            continue;
        }
        if (read_error != 0) {
            (void)RawClose(fd);
            return read_error;
        }
        if (read_result == 0) {
            (void)RawClose(fd);
            *output_length = length;
            *truncated = false;
            return 0;
        }
        if (static_cast<size_t>(read_result) > capacity - length) {
            (void)RawClose(fd);
            return EIO;
        }
        length += static_cast<size_t>(read_result);
    }

    char extra = 0;
    for (;;) {
        const long read_result = RawRead(fd, &extra, 1);
        const int read_error = RawError(read_result);
        if (read_error == EINTR) {
            continue;
        }
        (void)RawClose(fd);
        if (read_error != 0) {
            return read_error;
        }
        *output_length = length;
        *truncated = read_result != 0;
        return 0;
    }
}

bool ParseUnsigned64(const char* text, size_t length, uint64_t* value) noexcept {
    if (length == 0) {
        return false;
    }

    uint64_t parsed = 0;
    for (size_t i = 0; i < length; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(text[i] - '0');
        if (parsed > (UINT64_MAX - digit) / 10) {
            return false;
        }
        parsed = parsed * 10 + digit;
    }
    *value = parsed;
    return true;
}

bool IsFieldSeparator(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

int ParseProcessStartTime(const char* data, size_t length, bool truncated,
                          uint64_t* start_time) noexcept {
    size_t final_parenthesis = length;
    for (size_t i = 0; i < length; ++i) {
        if (data[i] == ')') {
            final_parenthesis = i;
        }
    }
    if (final_parenthesis == length) {
        return truncated ? EOVERFLOW : EIO;
    }

    size_t cursor = final_parenthesis + 1;
    for (unsigned int field = 3; field <= 22; ++field) {
        while (cursor < length && IsFieldSeparator(data[cursor])) {
            ++cursor;
        }
        if (cursor == length) {
            return truncated ? EOVERFLOW : EIO;
        }

        const size_t field_start = cursor;
        while (cursor < length && !IsFieldSeparator(data[cursor])) {
            ++cursor;
        }
        if (field == 22) {
            uint64_t parsed = 0;
            if (!ParseUnsigned64(data + field_start, cursor - field_start, &parsed)) {
                return EIO;
            }
            *start_time = parsed;
            return 0;
        }
    }
    return EIO;
}

bool StartsWithTgid(const char* line, size_t length) noexcept {
    constexpr char prefix[] = "Tgid:";
    if (length < sizeof(prefix) - 1) {
        return false;
    }
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
        if (line[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

int ParseTaskTgid(const char* data, size_t length, bool truncated,
                  pid_t* tgid) noexcept {
    size_t line_start = 0;
    while (line_start < length) {
        size_t line_end = line_start;
        while (line_end < length && data[line_end] != '\n') {
            ++line_end;
        }

        if (StartsWithTgid(data + line_start, line_end - line_start)) {
            size_t cursor = line_start + sizeof("Tgid:") - 1;
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t')) {
                ++cursor;
            }
            const size_t value_start = cursor;
            while (cursor < line_end && data[cursor] >= '0' && data[cursor] <= '9') {
                ++cursor;
            }
            uint64_t parsed = 0;
            if (!ParseUnsigned64(data + value_start, cursor - value_start, &parsed) ||
                parsed == 0 || parsed > INT32_MAX) {
                return EIO;
            }
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t' ||
                    data[cursor] == '\r')) {
                ++cursor;
            }
            if (cursor != line_end) {
                return EIO;
            }
            *tgid = static_cast<pid_t>(parsed);
            return 0;
        }

        line_start = line_end < length ? line_end + 1 : length;
    }
    return truncated ? EOVERFLOW : EIO;
}

}  // namespace

int EnumerateTaskTids(pid_t target_pid, pid_t* tids, size_t capacity,
                      size_t* tid_count) noexcept {
    if (tid_count == nullptr) {
        return EINVAL;
    }
    *tid_count = 0;
    if (target_pid <= 0 || tids == nullptr || capacity == 0) {
        return EINVAL;
    }

    char path[kTaskDirectoryPathCapacity];
    if (!BuildTaskDirectoryPath(target_pid, path)) {
        return ENAMETOOLONG;
    }

    const long open_result = RawOpenAt(AT_FDCWD, path,
                                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const int open_error = RawError(open_result);
    if (open_error != 0) {
        return open_error;
    }
    const int fd = static_cast<int>(open_result);

    alignas(8) char buffer[kTaskDirectoryReadCapacity];
    size_t count = 0;
    for (;;) {
        const long read_result = RawGetdents64(fd, buffer, sizeof(buffer));
        if (read_result == 0) {
            (void)RawClose(fd);
            *tid_count = count;
            return 0;
        }
        const int read_error = RawError(read_result);
        if (read_error != 0) {
            return CloseAndReturn(fd, read_error, count, tid_count);
        }

        const size_t bytes = static_cast<size_t>(read_result);
        size_t offset = 0;
        while (offset < bytes) {
            const auto* entry = reinterpret_cast<const LinuxDirent64*>(buffer + offset);
            const size_t minimum_length = offsetof(LinuxDirent64, name) + 2;
            if (entry->record_length < minimum_length ||
                entry->record_length > bytes - offset) {
                return CloseAndReturn(fd, EIO, count, tid_count);
            }

            const size_t name_capacity =
                    entry->record_length - offsetof(LinuxDirent64, name);
            size_t name_length = 0;
            while (name_length < name_capacity && entry->name[name_length] != '\0') {
                ++name_length;
            }
            if (name_length == name_capacity) {
                return CloseAndReturn(fd, EIO, count, tid_count);
            }

            pid_t tid = 0;
            if (ParsePositiveTid(entry->name, name_length, &tid)) {
                if (count >= capacity) {
                    return CloseAndReturn(fd, EOVERFLOW, count, tid_count);
                }
                tids[count++] = tid;
            }
            offset += entry->record_length;
        }
    }
}

int ReadProcessStartTime(pid_t pid, uint64_t* start_time) noexcept {
    if (pid <= 0 || start_time == nullptr) {
        return EINVAL;
    }

    constexpr char suffix[] = "/stat";
    char path[kTaskDirectoryPathCapacity];
    if (!BuildProcPidFilePath(pid, suffix, sizeof(suffix) - 1, path)) {
        return ENAMETOOLONG;
    }

    char buffer[kProcMetadataReadCapacity];
    size_t length = 0;
    bool truncated = false;
    const int read_error = ReadProcFile(path, buffer, sizeof(buffer), &length, &truncated);
    if (read_error != 0) {
        return read_error;
    }
    return ParseProcessStartTime(buffer, length, truncated, start_time);
}

int ReadTaskTgid(pid_t tid, pid_t* tgid) noexcept {
    if (tid <= 0 || tgid == nullptr) {
        return EINVAL;
    }

    constexpr char suffix[] = "/status";
    char path[kTaskDirectoryPathCapacity];
    if (!BuildProcPidFilePath(tid, suffix, sizeof(suffix) - 1, path)) {
        return ENAMETOOLONG;
    }

    char buffer[kProcMetadataReadCapacity];
    size_t length = 0;
    bool truncated = false;
    const int read_error = ReadProcFile(path, buffer, sizeof(buffer), &length, &truncated);
    if (read_error != 0) {
        return read_error;
    }
    return ParseTaskTgid(buffer, length, truncated, tgid);
}

}  // namespace platform
}  // namespace hookself
