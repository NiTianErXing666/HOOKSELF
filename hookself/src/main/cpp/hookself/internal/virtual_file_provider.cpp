#include "virtual_file_provider.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hookself/public_api.h"

namespace hookself::internal {
namespace {

int ReadSnapshot(int fd, uint8_t* output, size_t capacity,
                 size_t* output_size) noexcept {
    if (fd < 0 || output == nullptr || capacity == 0 ||
        output_size == nullptr) {
        return EINVAL;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return errno;
    }
    size_t total = 0;
    while (total < capacity) {
        const ssize_t result = read(fd, output + total, capacity - total);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            return errno;
        }
        if (result == 0) {
            *output_size = total;
            return 0;
        }
        total += static_cast<size_t>(result);
    }
    uint8_t extra = 0;
    for (;;) {
        const ssize_t result = read(fd, &extra, 1);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            return errno;
        }
        if (result == 0) {
            *output_size = total;
            return 0;
        }
        return EFBIG;
    }
}

bool StartsWith(const uint8_t* data, size_t size,
                const char* prefix) noexcept {
    const size_t prefix_size = strlen(prefix);
    return size >= prefix_size &&
           memcmp(data, prefix, prefix_size) == 0;
}

bool Contains(const uint8_t* data, size_t size,
              const char* needle) noexcept {
    const size_t needle_size = strlen(needle);
    if (needle_size == 0 || needle_size > size) {
        return false;
    }
    for (size_t i = 0; i <= size - needle_size; ++i) {
        if (memcmp(data + i, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
}

bool MappingPath(const uint8_t* line, size_t line_size,
                 const uint8_t** path, size_t* path_size) noexcept {
    size_t offset = 0;
    for (int field = 0; field < 5; ++field) {
        while (offset < line_size &&
               (line[offset] == ' ' || line[offset] == '\t')) {
            ++offset;
        }
        const size_t start = offset;
        while (offset < line_size && line[offset] != ' ' &&
               line[offset] != '\t') {
            ++offset;
        }
        if (offset == start) {
            return false;
        }
    }
    while (offset < line_size &&
           (line[offset] == ' ' || line[offset] == '\t')) {
        ++offset;
    }
    *path = line + offset;
    *path_size = line_size - offset;
    return offset < line_size;
}

bool ParseHex(const uint8_t* data, size_t size, uintptr_t* value) noexcept {
    if (size == 0 || value == nullptr) {
        return false;
    }
    uintptr_t parsed = 0;
    for (size_t i = 0; i < size; ++i) {
        uint8_t digit = 0;
        if (data[i] >= '0' && data[i] <= '9') {
            digit = data[i] - '0';
        } else if (data[i] >= 'a' && data[i] <= 'f') {
            digit = data[i] - 'a' + 10U;
        } else if (data[i] >= 'A' && data[i] <= 'F') {
            digit = data[i] - 'A' + 10U;
        } else {
            return false;
        }
        if (parsed > (UINTPTR_MAX - digit) / 16U) {
            return false;
        }
        parsed = parsed * 16U + digit;
    }
    *value = parsed;
    return true;
}

bool MappingRange(const uint8_t* line, size_t line_size,
                  uintptr_t* start, uintptr_t* end) noexcept {
    size_t dash = 0;
    while (dash < line_size && line[dash] != '-') {
        ++dash;
    }
    if (dash == 0 || dash == line_size) {
        return false;
    }
    size_t range_end = dash + 1U;
    while (range_end < line_size && line[range_end] != ' ' &&
           line[range_end] != '\t') {
        ++range_end;
    }
    return ParseHex(line, dash, start) &&
           ParseHex(line + dash + 1U, range_end - dash - 1U, end) &&
           *start < *end;
}

bool OverlapsHiddenRange(uintptr_t start, uintptr_t end,
                         const VirtualFileHiddenRange* ranges,
                         size_t range_count) noexcept {
    for (size_t i = 0; i < range_count; ++i) {
        if (ranges[i].size == 0 ||
            ranges[i].start > UINTPTR_MAX - ranges[i].size) {
            continue;
        }
        const uintptr_t hidden_end = ranges[i].start + ranges[i].size;
        if (start < hidden_end && ranges[i].start < end) {
            return true;
        }
    }
    return false;
}

int RewriteTracerPid(uint8_t* data, size_t* size) noexcept {
    constexpr char kKey[] = "TracerPid:";
    constexpr char kReplacement[] = "TracerPid:\t0";
    size_t line_start = 0;
    size_t match_start = 0;
    size_t match_end = 0;
    uint32_t matches = 0;
    while (line_start < *size) {
        size_t line_end = line_start;
        while (line_end < *size && data[line_end] != '\n') {
            ++line_end;
        }
        if (StartsWith(data + line_start, line_end - line_start, kKey)) {
            match_start = line_start;
            match_end = line_end;
            ++matches;
        }
        line_start = line_end < *size ? line_end + 1U : line_end;
    }
    if (matches == 0) {
        return ENODATA;
    }
    if (matches != 1) {
        return EPROTO;
    }
    constexpr size_t kReplacementSize = sizeof(kReplacement) - 1U;
    const size_t old_size = match_end - match_start;
    if (old_size < kReplacementSize) {
        return EPROTO;
    }
    memcpy(data + match_start, kReplacement, kReplacementSize);
    if (old_size != kReplacementSize) {
        memmove(data + match_start + kReplacementSize,
                data + match_end, *size - match_end);
        *size -= old_size - kReplacementSize;
    }
    return 0;
}

void FilterInternalMappings(uint8_t* data, size_t* size,
                            const VirtualFileHiddenRange* hidden_ranges,
                            size_t hidden_range_count) noexcept {
    size_t read_offset = 0;
    size_t write_offset = 0;
    while (read_offset < *size) {
        size_t line_end = read_offset;
        while (line_end < *size && data[line_end] != '\n') {
            ++line_end;
        }
        const size_t record_end = line_end < *size ? line_end + 1U : line_end;
        const size_t line_size = line_end - read_offset;
        const uint8_t* path = nullptr;
        size_t path_size = 0;
        const bool has_path = MappingPath(
                data + read_offset, line_size, &path, &path_size);
        uintptr_t mapping_start = 0;
        uintptr_t mapping_end = 0;
        const bool has_range = MappingRange(
                data + read_offset, line_size,
                &mapping_start, &mapping_end);
        const bool hidden_by_range =
                has_range && OverlapsHiddenRange(
                                     mapping_start, mapping_end,
                                     hidden_ranges, hidden_range_count);
        const bool hidden_by_path = has_path &&
                (Contains(path, path_size, "hookself-session") ||
                 Contains(path, path_size, "hookself-vfile") ||
                 Contains(path, path_size, "libhookself.so"));
        const bool hidden = hidden_by_range || hidden_by_path;
        if (!hidden) {
            const size_t record_size = record_end - read_offset;
            if (write_offset != read_offset) {
                memmove(data + write_offset, data + read_offset, record_size);
            }
            write_offset += record_size;
        }
        read_offset = record_end;
    }
    *size = write_offset;
}

}  // namespace

int OpenVirtualFileProviderSource(int32_t provider, pid_t target_pid,
                                  int* source_fd) noexcept {
    if (target_pid <= 0 || source_fd == nullptr) {
        return EINVAL;
    }
    *source_fd = -1;
    char path[64]{};
    switch (provider) {
        case HOOKSELF_VFILE_PROC_STATUS:
            if (snprintf(path, sizeof(path), "/proc/%d/status", target_pid) <= 0) {
                return EIO;
            }
            break;
        case HOOKSELF_VFILE_PROC_MAPS:
            if (snprintf(path, sizeof(path), "/proc/%d/maps", target_pid) <= 0) {
                return EIO;
            }
            break;
        case HOOKSELF_VFILE_SELINUX_CONTEXT:
            if (snprintf(path, sizeof(path), "/proc/%d/attr/current",
                         target_pid) <= 0) {
                return EIO;
            }
            break;
        default:
            return EINVAL;
    }
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return errno;
    }
    *source_fd = fd;
    return 0;
}

int GenerateVirtualFileProviderSnapshot(
        int32_t provider, uint32_t flags, int source_fd,
        const uint8_t* configured_content, size_t configured_content_size,
        const VirtualFileHiddenRange* hidden_ranges,
        size_t hidden_range_count,
        uint8_t* output, size_t output_capacity,
        size_t* output_size) noexcept {
    if (output == nullptr || output_capacity == 0 || output_size == nullptr ||
        (hidden_range_count != 0 && hidden_ranges == nullptr) ||
        configured_content_size > output_capacity ||
        (configured_content_size != 0 && configured_content == nullptr)) {
        return EINVAL;
    }
    *output_size = 0;
    if (provider == HOOKSELF_VFILE_SELINUX_CONTEXT &&
        configured_content_size != 0) {
        memcpy(output, configured_content, configured_content_size);
        *output_size = configured_content_size;
        return 0;
    }
    int error = ReadSnapshot(source_fd, output, output_capacity, output_size);
    if (error != 0) {
        return error;
    }
    if (provider == HOOKSELF_VFILE_PROC_STATUS) {
        return RewriteTracerPid(output, output_size);
    }
    if (provider == HOOKSELF_VFILE_PROC_MAPS) {
        if ((flags & HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS) != 0) {
            FilterInternalMappings(output, output_size, hidden_ranges,
                                   hidden_range_count);
        }
        return 0;
    }
    return provider == HOOKSELF_VFILE_SELINUX_CONTEXT ? 0 : EINVAL;
}

}  // namespace hookself::internal
