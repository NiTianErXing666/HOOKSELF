#include "proc_virtual_view.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

namespace hookself::internal {
namespace {

constexpr size_t kLinuxDirent64InodeOffset = 0U;
constexpr size_t kLinuxDirent64OffsetOffset = 8U;
constexpr size_t kLinuxDirent64RecordLengthOffset = 16U;
constexpr size_t kLinuxDirent64TypeOffset = 18U;
constexpr size_t kLinuxDirent64NameOffset = 19U;
constexpr size_t kLinuxDirent64MinimumLength =
        kLinuxDirent64NameOffset + 1U;
constexpr size_t kLinuxDirent64Alignment = sizeof(uint64_t);
constexpr size_t kLinuxDirent64NameMax = 255U;
constexpr size_t kLinuxDirent64MaximumLength =
        (kLinuxDirent64NameOffset + kLinuxDirent64NameMax + 1U +
         kLinuxDirent64Alignment - 1U) &
        ~(kLinuxDirent64Alignment - 1U);

static_assert(kLinuxDirent64InodeOffset == 0U);
static_assert(kLinuxDirent64TypeOffset + 1U == kLinuxDirent64NameOffset);

bool BytesEqual(const char* left, size_t left_size, const char* right,
                size_t right_size) noexcept {
    return left_size == right_size &&
           (left_size == 0 || memcmp(left, right, left_size) == 0);
}

bool BytesEqual(const uint8_t* left, size_t left_size, const char* right,
                size_t right_size) noexcept {
    return left_size == right_size &&
           (left_size == 0 || memcmp(left, right, left_size) == 0);
}

bool ParseDecimal(const char* text, size_t size, bool allow_zero,
                  int32_t* value) noexcept {
    if (text == nullptr || value == nullptr || size == 0) {
        return false;
    }
    uint32_t parsed = 0;
    for (size_t index = 0; index < size; ++index) {
        if (text[index] < '0' || text[index] > '9') {
            return false;
        }
        const uint32_t digit = static_cast<uint32_t>(text[index] - '0');
        if (parsed > (static_cast<uint32_t>(INT32_MAX) - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0 && !allow_zero) {
        return false;
    }
    *value = static_cast<int32_t>(parsed);
    return true;
}

bool IsPositiveDecimal(const char* text, size_t size,
                       int32_t* value) noexcept {
    return ParseDecimal(text, size, false, value);
}

bool IsNonnegativeDecimal(const char* text, size_t size,
                          int32_t* value) noexcept {
    return ParseDecimal(text, size, true, value);
}

bool Component(const char* path, size_t path_length, size_t start,
               size_t* end) noexcept {
    if (path == nullptr || end == nullptr || start >= path_length ||
        path[start] == '/') {
        return false;
    }
    size_t cursor = start;
    while (cursor < path_length && path[cursor] != '/') {
        ++cursor;
    }
    if (cursor == start) {
        return false;
    }
    *end = cursor;
    return true;
}

bool DirectoryTail(const char* path, size_t path_length, size_t start,
                   const char* name, size_t name_length) noexcept {
    if (start > path_length || name_length > path_length - start ||
        memcmp(path + start, name, name_length) != 0) {
        return false;
    }
    const size_t end = start + name_length;
    return end == path_length ||
           (end + 1U == path_length && path[end] == '/');
}

bool FileTail(const char* path, size_t path_length, size_t start,
              const char* name, size_t name_length) noexcept {
    return start <= path_length && name_length == path_length - start &&
           memcmp(path + start, name, name_length) == 0;
}

bool AddSize(size_t left, size_t right, size_t* result) noexcept {
    if (result == nullptr || left > SIZE_MAX - right) {
        return false;
    }
    *result = left + right;
    return true;
}

bool IsCanonicalAbsolutePrefix(const char* path, size_t length) noexcept {
    if (path == nullptr || length == 0 || path[0] != '/' ||
        (length > 1 && path[length - 1U] == '/')) {
        return false;
    }
    if (length == 1) {
        return true;
    }
    size_t segment_start = 1;
    for (size_t index = 1; index <= length; ++index) {
        if (index != length && path[index] != '/') {
            if (path[index] == '\0') {
                return false;
            }
            continue;
        }
        const size_t segment_length = index - segment_start;
        if (segment_length == 0 ||
            (segment_length == 1 && path[segment_start] == '.') ||
            (segment_length == 2 && path[segment_start] == '.' &&
             path[segment_start + 1U] == '.')) {
            return false;
        }
        segment_start = index + 1U;
    }
    return true;
}

int ValidateRanges(const ProcVirtualAddressRange* ranges,
                   size_t count) noexcept {
    if (count != 0 && ranges == nullptr) {
        return EINVAL;
    }
    for (size_t index = 0; index < count; ++index) {
        if (ranges[index].size != 0 &&
            ranges[index].start > UINTPTR_MAX - ranges[index].size) {
            return EOVERFLOW;
        }
    }
    return 0;
}

int ValidateRewriteOptions(const ProcTextRewriteOptions& options) noexcept {
    int error = ValidateRanges(options.hidden_ranges,
                               options.hidden_range_count);
    if (error != 0) {
        return error;
    }
    if (options.reverse_rule_count != 0 &&
        options.reverse_rules == nullptr) {
        return EINVAL;
    }
    for (size_t index = 0; index < options.reverse_rule_count; ++index) {
        const ProcReversePathRule& rule = options.reverse_rules[index];
        if ((rule.flags & ~kProcReversePathRuleVisible) != 0 ||
            !IsCanonicalAbsolutePrefix(rule.host_prefix,
                                       rule.host_prefix_length) ||
            !IsCanonicalAbsolutePrefix(rule.guest_prefix,
                                       rule.guest_prefix_length)) {
            return EINVAL;
        }
    }
    return 0;
}

bool ParseHex(const uint8_t* text, size_t size, uintptr_t* value) noexcept {
    if (text == nullptr || value == nullptr || size == 0) {
        return false;
    }
    uintptr_t parsed = 0;
    for (size_t index = 0; index < size; ++index) {
        uint8_t digit = 0;
        if (text[index] >= '0' && text[index] <= '9') {
            digit = static_cast<uint8_t>(text[index] - '0');
        } else if (text[index] >= 'a' && text[index] <= 'f') {
            digit = static_cast<uint8_t>(text[index] - 'a' + 10U);
        } else if (text[index] >= 'A' && text[index] <= 'F') {
            digit = static_cast<uint8_t>(text[index] - 'A' + 10U);
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

bool IsSpace(uint8_t value) noexcept {
    return value == ' ' || value == '\t';
}

struct ParsedMapHeader {
    uintptr_t start;
    uintptr_t end;
    size_t path_offset;
    size_t path_size;
};

bool ParseMapHeader(const uint8_t* line, size_t line_size,
                    ParsedMapHeader* header) noexcept {
    if (line == nullptr || header == nullptr || line_size == 0) {
        return false;
    }
    size_t range_end = 0;
    while (range_end < line_size && !IsSpace(line[range_end])) {
        ++range_end;
    }
    size_t dash = 0;
    while (dash < range_end && line[dash] != '-') {
        ++dash;
    }
    if (dash == 0 || dash + 1U >= range_end) {
        return false;
    }
    uintptr_t mapping_start = 0;
    uintptr_t mapping_end = 0;
    if (!ParseHex(line, dash, &mapping_start) ||
        !ParseHex(line + dash + 1U, range_end - dash - 1U,
                  &mapping_end) ||
        mapping_start >= mapping_end) {
        return false;
    }

    size_t cursor = range_end;
    for (size_t field = 0; field < 4U; ++field) {
        while (cursor < line_size && IsSpace(line[cursor])) {
            ++cursor;
        }
        const size_t field_start = cursor;
        while (cursor < line_size && !IsSpace(line[cursor])) {
            ++cursor;
        }
        if (cursor == field_start) {
            return false;
        }
    }
    while (cursor < line_size && IsSpace(line[cursor])) {
        ++cursor;
    }
    header->start = mapping_start;
    header->end = mapping_end;
    header->path_offset = cursor;
    header->path_size = line_size - cursor;
    return true;
}

bool OverlapsHiddenRange(uintptr_t start, uintptr_t end,
                         const ProcVirtualAddressRange* ranges,
                         size_t count) noexcept {
    for (size_t index = 0; index < count; ++index) {
        if (ranges[index].size == 0) {
            continue;
        }
        const uintptr_t hidden_end = ranges[index].start + ranges[index].size;
        if (start < hidden_end && ranges[index].start < end) {
            return true;
        }
    }
    return false;
}

size_t VisiblePathLength(const uint8_t* path, size_t path_size) noexcept {
    constexpr char kDeletedSuffix[] = " (deleted)";
    constexpr size_t kDeletedSuffixLength = sizeof(kDeletedSuffix) - 1U;
    if (path_size >= kDeletedSuffixLength &&
        memcmp(path + path_size - kDeletedSuffixLength, kDeletedSuffix,
               kDeletedSuffixLength) == 0) {
        return path_size - kDeletedSuffixLength;
    }
    return path_size;
}

bool PrefixMatches(const uint8_t* path, size_t path_size,
                   const char* prefix, size_t prefix_size) noexcept {
    if (path == nullptr || prefix == nullptr || prefix_size > path_size ||
        memcmp(path, prefix, prefix_size) != 0) {
        return false;
    }
    return (prefix_size == 1U && prefix[0] == '/') ||
           prefix_size == path_size || path[prefix_size] == '/';
}

const ProcReversePathRule* SelectReverseRule(
        const uint8_t* path, size_t path_size,
        const ProcReversePathRule* rules, size_t rule_count) noexcept {
    if (path == nullptr || path_size == 0 || path[0] != '/') {
        return nullptr;
    }
    const size_t visible_size = VisiblePathLength(path, path_size);
    const ProcReversePathRule* selected = nullptr;
    for (size_t index = 0; index < rule_count; ++index) {
        const ProcReversePathRule& rule = rules[index];
        if ((rule.flags & kProcReversePathRuleVisible) == 0 ||
            !PrefixMatches(path, visible_size, rule.host_prefix,
                           rule.host_prefix_length)) {
            continue;
        }
        if (selected == nullptr ||
            rule.host_prefix_length > selected->host_prefix_length ||
            (rule.host_prefix_length == selected->host_prefix_length &&
             rule.priority > selected->priority)) {
            selected = &rule;
        }
    }
    return selected;
}

size_t TranslationSuffixOffset(const uint8_t* path, size_t path_size,
                               const ProcReversePathRule& rule) noexcept {
    const size_t visible_size = VisiblePathLength(path, path_size);
    if (rule.host_prefix_length == 1U && visible_size > 1U) {
        return 0;
    }
    return rule.host_prefix_length;
}

bool TranslatedPathSize(const uint8_t* path, size_t path_size,
                        const ProcReversePathRule& rule,
                        size_t* translated_size) noexcept {
    size_t suffix_offset = TranslationSuffixOffset(path, path_size, rule);
    if (suffix_offset > path_size) {
        return false;
    }
    if (rule.guest_prefix_length != 0 &&
        rule.guest_prefix[rule.guest_prefix_length - 1U] == '/' &&
        suffix_offset < path_size && path[suffix_offset] == '/') {
        ++suffix_offset;
    }
    return AddSize(rule.guest_prefix_length, path_size - suffix_offset,
                   translated_size);
}

void WriteTranslatedPath(const uint8_t* path, size_t path_size,
                         const ProcReversePathRule& rule,
                         uint8_t* output) noexcept {
    size_t suffix_offset = TranslationSuffixOffset(path, path_size, rule);
    if (rule.guest_prefix_length != 0 &&
        rule.guest_prefix[rule.guest_prefix_length - 1U] == '/' &&
        suffix_offset < path_size && path[suffix_offset] == '/') {
        ++suffix_offset;
    }
    memcpy(output, rule.guest_prefix, rule.guest_prefix_length);
    memcpy(output + rule.guest_prefix_length, path + suffix_offset,
           path_size - suffix_offset);
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

enum class ProcTextKind : uint32_t {
    kMaps,
    kSmaps,
};

int ProcessProcText(const uint8_t* input, size_t input_size, uint8_t* output,
                    const ProcTextRewriteOptions& options, ProcTextKind kind,
                    ProcTextRewriteResult* result) noexcept {
    ProcTextRewriteResult current{};
    size_t read_offset = 0;
    size_t write_offset = 0;
    bool have_smaps_mapping = false;
    bool current_smaps_hidden = false;
    while (read_offset < input_size) {
        size_t line_end = read_offset;
        while (line_end < input_size && input[line_end] != '\n') {
            ++line_end;
        }
        const size_t record_end = line_end < input_size
                                          ? line_end + 1U
                                          : line_end;
        const size_t line_size = line_end - read_offset;
        ParsedMapHeader header{};
        const bool mapping_header = ParseMapHeader(
                input + read_offset, line_size, &header);
        if (kind == ProcTextKind::kMaps && !mapping_header) {
            return EPROTO;
        }
        if (kind == ProcTextKind::kSmaps && !mapping_header &&
            !have_smaps_mapping) {
            return EPROTO;
        }

        bool hidden = false;
        const ProcReversePathRule* reverse_rule = nullptr;
        size_t translated_path_size = 0;
        if (mapping_header) {
            ++current.mappings_seen;
            hidden = OverlapsHiddenRange(
                    header.start, header.end, options.hidden_ranges,
                    options.hidden_range_count);
            if (hidden) {
                ++current.mappings_hidden;
            } else if (header.path_size != 0) {
                reverse_rule = SelectReverseRule(
                        input + read_offset + header.path_offset,
                        header.path_size, options.reverse_rules,
                        options.reverse_rule_count);
                if (reverse_rule != nullptr) {
                    if (!TranslatedPathSize(
                                input + read_offset + header.path_offset,
                                header.path_size, *reverse_rule,
                                &translated_path_size)) {
                        return EOVERFLOW;
                    }
                    ++current.paths_rewritten;
                }
            }
            if (kind == ProcTextKind::kSmaps) {
                have_smaps_mapping = true;
                current_smaps_hidden = hidden;
            }
        } else {
            hidden = current_smaps_hidden;
        }

        if (!hidden) {
            size_t output_record_size = record_end - read_offset;
            if (mapping_header && reverse_rule != nullptr) {
                const size_t newline_size = record_end - line_end;
                if (!AddSize(header.path_offset, translated_path_size,
                             &output_record_size) ||
                    !AddSize(output_record_size, newline_size,
                             &output_record_size)) {
                    return EOVERFLOW;
                }
            }
            size_t next_write = 0;
            if (!AddSize(write_offset, output_record_size, &next_write)) {
                return EOVERFLOW;
            }
            if (output != nullptr) {
                if (mapping_header && reverse_rule != nullptr) {
                    memcpy(output + write_offset, input + read_offset,
                           header.path_offset);
                    WriteTranslatedPath(
                            input + read_offset + header.path_offset,
                            header.path_size, *reverse_rule,
                            output + write_offset + header.path_offset);
                    if (record_end != line_end) {
                        output[next_write - 1U] = '\n';
                    }
                } else {
                    memcpy(output + write_offset, input + read_offset,
                           output_record_size);
                }
            }
            write_offset = next_write;
        }
        read_offset = record_end;
    }
    current.output_size = write_offset;
    *result = current;
    return 0;
}

int RewriteProcText(const uint8_t* input, size_t input_size, uint8_t* output,
                    size_t output_capacity,
                    const ProcTextRewriteOptions& options, ProcTextKind kind,
                    ProcTextRewriteResult* result) noexcept {
    if (result == nullptr || (input_size != 0 && input == nullptr)) {
        return EINVAL;
    }
    *result = {};
    const int options_error = ValidateRewriteOptions(options);
    if (options_error != 0) {
        return options_error;
    }
    ProcTextRewriteResult measured{};
    const int measure_error = ProcessProcText(
            input, input_size, nullptr, options, kind, &measured);
    if (measure_error != 0) {
        return measure_error;
    }
    *result = measured;
    if (measured.output_size > output_capacity) {
        return ENOSPC;
    }
    if (measured.output_size == 0) {
        return 0;
    }
    if (output == nullptr ||
        BuffersOverlap(input, input_size, output, measured.output_size)) {
        return EINVAL;
    }
    ProcTextRewriteResult written{};
    const int write_error = ProcessProcText(
            input, input_size, output, options, kind, &written);
    if (write_error != 0) {
        return write_error;
    }
    if (written.output_size != measured.output_size ||
        written.mappings_seen != measured.mappings_seen ||
        written.mappings_hidden != measured.mappings_hidden ||
        written.paths_rewritten != measured.paths_rewritten) {
        return EIO;
    }
    return 0;
}

uint16_t ReadUint16(const uint8_t* data) noexcept {
    uint16_t value = 0;
    memcpy(&value, data, sizeof(value));
    return value;
}

int64_t ReadInt64(const uint8_t* data) noexcept {
    int64_t value = 0;
    memcpy(&value, data, sizeof(value));
    return value;
}

bool ProtectedFd(int32_t fd, const int32_t* protected_fds,
                 size_t count) noexcept {
    for (size_t index = 0; index < count; ++index) {
        if (protected_fds[index] == fd) {
            return true;
        }
    }
    return false;
}

bool ParseMapFileName(const char* name, size_t name_size, uintptr_t* start,
                      uintptr_t* end) noexcept {
    if (name == nullptr || start == nullptr || end == nullptr ||
        name_size < 3U) {
        return false;
    }
    size_t dash = 0;
    while (dash < name_size && name[dash] != '-') {
        ++dash;
    }
    if (dash == 0 || dash + 1U >= name_size) {
        return false;
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(name);
    return ParseHex(bytes, dash, start) &&
           ParseHex(bytes + dash + 1U, name_size - dash - 1U, end) &&
           *start < *end;
}

bool HideDirent(const char* name, size_t name_size,
                const ProcDirentFilterOptions& options) noexcept {
    int32_t decimal = 0;
    switch (options.directory_kind) {
        case ProcVirtualNodeKind::kRootDirectory:
            return options.tracer_pid > 0 &&
                   IsPositiveDecimal(name, name_size, &decimal) &&
                   decimal == options.tracer_pid;
        case ProcVirtualNodeKind::kFdDirectory:
        case ProcVirtualNodeKind::kFdInfoDirectory:
            return IsNonnegativeDecimal(name, name_size, &decimal) &&
                   ProtectedFd(decimal, options.protected_fds,
                               options.protected_fd_count);
        case ProcVirtualNodeKind::kMapFilesDirectory: {
            uintptr_t start = 0;
            uintptr_t end = 0;
            return ParseMapFileName(name, name_size, &start, &end) &&
                   OverlapsHiddenRange(
                           start, end, options.hidden_map_ranges,
                           options.hidden_map_range_count);
        }
        default:
            return false;
    }
}

int ValidateDirentOptions(const ProcDirentFilterOptions& options) noexcept {
    if (options.directory_kind != ProcVirtualNodeKind::kRootDirectory &&
        options.directory_kind != ProcVirtualNodeKind::kFdDirectory &&
        options.directory_kind != ProcVirtualNodeKind::kFdInfoDirectory &&
        options.directory_kind != ProcVirtualNodeKind::kMapFilesDirectory) {
        return EINVAL;
    }
    if (options.protected_fd_count != 0 && options.protected_fds == nullptr) {
        return EINVAL;
    }
    return ValidateRanges(options.hidden_map_ranges,
                          options.hidden_map_range_count);
}

int ValidateXattrList(const uint8_t* input, size_t input_size,
                      size_t* names_seen) noexcept {
    if (names_seen == nullptr || (input_size != 0 && input == nullptr)) {
        return EINVAL;
    }
    *names_seen = 0;
    size_t cursor = 0;
    while (cursor < input_size) {
        const size_t start = cursor;
        while (cursor < input_size && input[cursor] != 0) {
            ++cursor;
        }
        const size_t name_size = cursor - start;
        if (cursor == input_size || name_size == 0 ||
            name_size > kProcVirtualXattrNameMax) {
            return EPROTO;
        }
        ++cursor;
        ++*names_seen;
    }
    return 0;
}

bool XattrNameSeenBefore(const uint8_t* input, size_t name_start,
                         const uint8_t* name, size_t name_size) noexcept {
    size_t cursor = 0;
    while (cursor < name_start) {
        const size_t earlier_start = cursor;
        while (cursor < name_start && input[cursor] != 0) {
            ++cursor;
        }
        const size_t earlier_size = cursor - earlier_start;
        if (earlier_size == name_size &&
            memcmp(input + earlier_start, name, name_size) == 0) {
            return true;
        }
        ++cursor;
    }
    return false;
}

bool XattrListContains(const uint8_t* input, size_t input_size,
                       const char* name, size_t name_size) noexcept {
    size_t cursor = 0;
    while (cursor < input_size) {
        const size_t start = cursor;
        while (cursor < input_size && input[cursor] != 0) {
            ++cursor;
        }
        if (BytesEqual(input + start, cursor - start, name, name_size)) {
            return true;
        }
        ++cursor;
    }
    return false;
}

}  // namespace

int ParseProcVirtualPath(const char* path, size_t path_length,
                         int32_t caller_tgid, int32_t caller_tid,
                         ProcVirtualPath* output) noexcept {
    if (output == nullptr || path == nullptr || path_length == 0) {
        return EINVAL;
    }
    *output = {};
    for (size_t index = 0; index < path_length; ++index) {
        if (path[index] == '\0') {
            return EINVAL;
        }
    }
    constexpr char kProc[] = "/proc";
    if (BytesEqual(path, path_length, kProc, sizeof(kProc) - 1U) ||
        BytesEqual(path, path_length, "/proc/", sizeof("/proc/") - 1U)) {
        output->kind = ProcVirtualNodeKind::kRootDirectory;
        return 0;
    }
    constexpr char kProcPrefix[] = "/proc/";
    if (path_length <= sizeof(kProcPrefix) - 1U ||
        memcmp(path, kProcPrefix, sizeof(kProcPrefix) - 1U) != 0) {
        return ENOENT;
    }

    size_t selector_start = sizeof(kProcPrefix) - 1U;
    size_t selector_end = 0;
    if (!Component(path, path_length, selector_start, &selector_end)) {
        return ENOENT;
    }
    if (BytesEqual(path + selector_start, selector_end - selector_start,
                   "self", sizeof("self") - 1U)) {
        if (caller_tgid <= 0) {
            return EINVAL;
        }
        output->subject_pid = caller_tgid;
        output->flags |= kProcVirtualPathSelfAlias;
    } else if (BytesEqual(path + selector_start,
                          selector_end - selector_start, "thread-self",
                          sizeof("thread-self") - 1U)) {
        if (caller_tgid <= 0 || caller_tid <= 0) {
            return EINVAL;
        }
        output->subject_pid = caller_tgid;
        output->subject_tid = caller_tid;
        output->flags |= kProcVirtualPathThreadSelfAlias;
    } else {
        int32_t selector = 0;
        if (!IsPositiveDecimal(path + selector_start,
                               selector_end - selector_start, &selector)) {
            return ENOENT;
        }
        output->subject_pid = selector;
        output->flags |= kProcVirtualPathNumericSelector;
    }
    if (selector_end >= path_length || path[selector_end] != '/') {
        return ENOENT;
    }

    size_t node_start = selector_end + 1U;
    size_t node_component_end = 0;
    if (!Component(path, path_length, node_start, &node_component_end)) {
        return ENOENT;
    }
    if (BytesEqual(path + node_start, node_component_end - node_start,
                   "task", sizeof("task") - 1U)) {
        if ((output->flags & kProcVirtualPathThreadSelfAlias) != 0 ||
            node_component_end >= path_length ||
            path[node_component_end] != '/') {
            return ENOENT;
        }
        const size_t tid_start = node_component_end + 1U;
        size_t tid_end = 0;
        int32_t tid = 0;
        if (!Component(path, path_length, tid_start, &tid_end) ||
            !IsPositiveDecimal(path + tid_start, tid_end - tid_start, &tid) ||
            tid_end >= path_length || path[tid_end] != '/') {
            return ENOENT;
        }
        output->subject_tid = tid;
        output->flags |= kProcVirtualPathExplicitTask;
        node_start = tid_end + 1U;
    }

    if (FileTail(path, path_length, node_start, "status",
                 sizeof("status") - 1U)) {
        output->kind = ProcVirtualNodeKind::kStatus;
    } else if (FileTail(path, path_length, node_start, "maps",
                        sizeof("maps") - 1U)) {
        output->kind = ProcVirtualNodeKind::kMaps;
    } else if (FileTail(path, path_length, node_start, "smaps",
                        sizeof("smaps") - 1U)) {
        output->kind = ProcVirtualNodeKind::kSmaps;
    } else if (FileTail(path, path_length, node_start, "smaps_rollup",
                        sizeof("smaps_rollup") - 1U)) {
        output->kind = ProcVirtualNodeKind::kSmapsRollup;
    } else if (FileTail(path, path_length, node_start, "attr/current",
                        sizeof("attr/current") - 1U)) {
        output->kind = ProcVirtualNodeKind::kAttrCurrent;
    } else if (DirectoryTail(path, path_length, node_start, "fd",
                             sizeof("fd") - 1U)) {
        output->kind = ProcVirtualNodeKind::kFdDirectory;
    } else if (DirectoryTail(path, path_length, node_start, "fdinfo",
                             sizeof("fdinfo") - 1U)) {
        output->kind = ProcVirtualNodeKind::kFdInfoDirectory;
    } else if (DirectoryTail(path, path_length, node_start, "map_files",
                             sizeof("map_files") - 1U)) {
        output->kind = ProcVirtualNodeKind::kMapFilesDirectory;
    } else {
        return ENOENT;
    }
    return 0;
}

int RewriteProcMaps(const uint8_t* input, size_t input_size, uint8_t* output,
                    size_t output_capacity,
                    const ProcTextRewriteOptions& options,
                    ProcTextRewriteResult* result) noexcept {
    return RewriteProcText(input, input_size, output, output_capacity, options,
                           ProcTextKind::kMaps, result);
}

int RewriteProcSmaps(const uint8_t* input, size_t input_size, uint8_t* output,
                     size_t output_capacity,
                     const ProcTextRewriteOptions& options,
                     ProcTextRewriteResult* result) noexcept {
    return RewriteProcText(input, input_size, output, output_capacity, options,
                           ProcTextKind::kSmaps, result);
}

int CompactProcDirents64(uint8_t* buffer, size_t buffer_size,
                         const ProcDirentFilterOptions& options,
                         ProcDirentCompactResult* result) noexcept {
    if (result == nullptr || (buffer_size != 0 && buffer == nullptr)) {
        return EINVAL;
    }
    *result = {};
    const int options_error = ValidateDirentOptions(options);
    if (options_error != 0) {
        return options_error;
    }

    size_t read_offset = 0;
    size_t write_offset = 0;
    while (read_offset < buffer_size) {
        const size_t remaining = buffer_size - read_offset;
        if (remaining < kLinuxDirent64MinimumLength) {
            return EPROTO;
        }
        const uint16_t record_length = ReadUint16(
                buffer + read_offset + kLinuxDirent64RecordLengthOffset);
        if (record_length < kLinuxDirent64MinimumLength ||
            record_length > kLinuxDirent64MaximumLength ||
            record_length > remaining ||
            record_length % kLinuxDirent64Alignment != 0) {
            return EPROTO;
        }
        const size_t name_capacity =
                record_length - kLinuxDirent64NameOffset;
        size_t name_size = 0;
        while (name_size < name_capacity &&
               buffer[read_offset + kLinuxDirent64NameOffset + name_size] !=
                       0) {
            ++name_size;
        }
        if (name_size == 0 || name_size == name_capacity ||
            name_size > kLinuxDirent64NameMax) {
            return EPROTO;
        }
        const int64_t d_off = ReadInt64(
                buffer + read_offset + kLinuxDirent64OffsetOffset);
        result->last_d_off = d_off;
        ++result->records_seen;
        const auto* name = reinterpret_cast<const char*>(
                buffer + read_offset + kLinuxDirent64NameOffset);
        const bool hidden = HideDirent(name, name_size, options);
        if (hidden) {
            ++result->records_hidden;
        } else {
            if (write_offset != read_offset) {
                memmove(buffer + write_offset, buffer + read_offset,
                        record_length);
            }
            write_offset += record_length;
            result->last_visible_d_off = d_off;
        }
        read_offset += record_length;
    }
    result->visible_size = write_offset;
    result->all_hidden = buffer_size != 0 && write_offset == 0;
    return 0;
}

int ApplyXattrGetOverlay(const uint8_t* value, size_t value_size,
                         uint8_t* output, size_t output_capacity,
                         size_t* result_size) noexcept {
    if (result_size == nullptr || (value_size != 0 && value == nullptr)) {
        return EINVAL;
    }
    *result_size = value_size;
    if (output_capacity == 0) {
        return 0;
    }
    if (output_capacity < value_size) {
        return ERANGE;
    }
    if (value_size == 0) {
        return 0;
    }
    if (output == nullptr) {
        return EFAULT;
    }
    memmove(output, value, value_size);
    return 0;
}

int ApplyXattrListOverlay(const uint8_t* input, size_t input_size,
                          const char* inject_name, size_t inject_name_length,
                          uint8_t* output, size_t output_capacity,
                          XattrListOverlayResult* result) noexcept {
    if (result == nullptr ||
        (inject_name_length != 0 && inject_name == nullptr) ||
        inject_name_length > kProcVirtualXattrNameMax) {
        return EINVAL;
    }
    *result = {};
    for (size_t index = 0; index < inject_name_length; ++index) {
        if (inject_name[index] == '\0') {
            return EINVAL;
        }
    }
    size_t names_seen = 0;
    const int validate_error = ValidateXattrList(
            input, input_size, &names_seen);
    if (validate_error != 0) {
        return validate_error;
    }

    size_t required_size = 0;
    size_t names_emitted = 0;
    size_t cursor = 0;
    while (cursor < input_size) {
        const size_t start = cursor;
        while (input[cursor] != 0) {
            ++cursor;
        }
        const size_t name_size = cursor - start;
        if (!XattrNameSeenBefore(input, start, input + start, name_size)) {
            if (!AddSize(required_size, name_size + 1U, &required_size)) {
                return EOVERFLOW;
            }
            ++names_emitted;
        }
        ++cursor;
    }
    const bool name_present = inject_name_length != 0 &&
            XattrListContains(input, input_size, inject_name,
                              inject_name_length);
    const bool inject = inject_name_length != 0 && !name_present;
    if (inject) {
        if (!AddSize(required_size, inject_name_length + 1U,
                     &required_size)) {
            return EOVERFLOW;
        }
        ++names_emitted;
    }
    result->output_size = required_size;
    result->names_seen = names_seen;
    result->names_emitted = names_emitted;
    result->injected = inject;

    if (output_capacity == 0) {
        return 0;
    }
    if (output_capacity < required_size) {
        return ERANGE;
    }
    if (required_size == 0) {
        return 0;
    }
    if (output == nullptr) {
        return EFAULT;
    }
    if (output != input &&
        BuffersOverlap(input, input_size, output, required_size)) {
        return EINVAL;
    }

    size_t write_offset = 0;
    cursor = 0;
    while (cursor < input_size) {
        const size_t start = cursor;
        while (input[cursor] != 0) {
            ++cursor;
        }
        const size_t name_size = cursor - start;
        if (!XattrListContains(
                    output, write_offset,
                    reinterpret_cast<const char*>(input + start),
                    name_size)) {
            memmove(output + write_offset, input + start, name_size);
            output[write_offset + name_size] = 0;
            write_offset += name_size + 1U;
        }
        ++cursor;
    }
    if (inject) {
        memcpy(output + write_offset, inject_name, inject_name_length);
        output[write_offset + inject_name_length] = 0;
        write_offset += inject_name_length + 1U;
    }
    return write_offset == required_size ? 0 : EIO;
}

}  // namespace hookself::internal
