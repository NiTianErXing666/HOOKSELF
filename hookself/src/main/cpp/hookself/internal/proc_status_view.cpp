#include "proc_status_view.h"

#include <cerrno>
#include <climits>

namespace hookself::internal {
namespace {

struct FieldValue {
    uint64_t value;
    size_t value_offset;
    size_t value_length;
    uint32_t matches;
};

bool PrefixEquals(const uint8_t* data, size_t size, size_t offset,
                  const char* prefix, size_t prefix_length) noexcept {
    if (offset > size || prefix_length > size - offset) {
        return false;
    }
    for (size_t i = 0; i < prefix_length; ++i) {
        if (data[offset + i] != static_cast<uint8_t>(prefix[i])) {
            return false;
        }
    }
    return true;
}

int FindDecimalField(const uint8_t* data, size_t size, const char* prefix,
                     size_t prefix_length, FieldValue* field) noexcept {
    if (data == nullptr || prefix == nullptr || field == nullptr) {
        return EINVAL;
    }
    *field = {};
    size_t line_start = 0;
    while (line_start < size) {
        size_t line_end = line_start;
        while (line_end < size && data[line_end] != '\n') {
            ++line_end;
        }
        if (PrefixEquals(data, line_end, line_start, prefix, prefix_length)) {
            size_t cursor = line_start + prefix_length;
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t')) {
                ++cursor;
            }
            const size_t value_offset = cursor;
            uint64_t value = 0;
            while (cursor < line_end && data[cursor] >= '0' &&
                   data[cursor] <= '9') {
                const uint32_t digit = data[cursor] - '0';
                if (value > (UINT64_MAX - digit) / 10U) {
                    return EOVERFLOW;
                }
                value = value * 10U + digit;
                ++cursor;
            }
            if (cursor == value_offset) {
                return EPROTO;
            }
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t' ||
                    data[cursor] == '\r')) {
                ++cursor;
            }
            if (cursor != line_end || ++field->matches != 1U) {
                return EPROTO;
            }
            field->value = value;
            field->value_offset = value_offset;
            field->value_length = cursor - value_offset;
            while (field->value_length != 0 &&
                   (data[field->value_offset + field->value_length - 1U] ==
                            ' ' ||
                    data[field->value_offset + field->value_length - 1U] ==
                            '\t' ||
                    data[field->value_offset + field->value_length - 1U] ==
                            '\r')) {
                --field->value_length;
            }
        }
        line_start = line_end < size ? line_end + 1U : size;
    }
    return field->matches == 1U ? 0 : EPROTO;
}

}  // namespace

int ParseProcStatusMetadata(const uint8_t* data, size_t size,
                            int32_t expected_tgid,
                            ProcStatusMetadata* metadata) noexcept {
    if (data == nullptr || size == 0 || expected_tgid <= 0 ||
        metadata == nullptr) {
        return EINVAL;
    }
    FieldValue tgid{};
    FieldValue pid{};
    FieldValue tracer{};
    int error = FindDecimalField(data, size, "Tgid:", 5U, &tgid);
    if (error == 0) {
        error = FindDecimalField(data, size, "Pid:", 4U, &pid);
    }
    if (error == 0) {
        error = FindDecimalField(data, size, "TracerPid:", 10U, &tracer);
    }
    if (error != 0) {
        return error;
    }
    if (tgid.value != static_cast<uint64_t>(expected_tgid) ||
        tgid.value > INT32_MAX || pid.value == 0 || pid.value > INT32_MAX ||
        tracer.value_length == 0 || tracer.value_length > UINT32_MAX) {
        return EPROTO;
    }
    metadata->tgid = static_cast<int32_t>(tgid.value);
    metadata->pid = static_cast<int32_t>(pid.value);
    metadata->tracer_value_offset = tracer.value_offset;
    metadata->tracer_value_length =
            static_cast<uint32_t>(tracer.value_length);
    return 0;
}

size_t RewriteTracerPidValue(uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0;
    }
    constexpr char kPrefix[] = "TracerPid:";
    constexpr size_t kPrefixLength = sizeof(kPrefix) - 1U;
    size_t rewritten = 0;
    for (size_t line_start = 0; line_start < size;) {
        size_t line_end = line_start;
        while (line_end < size && data[line_end] != '\n') {
            ++line_end;
        }
        const bool complete_line = line_end < size;
        if (complete_line &&
            PrefixEquals(data, line_end, line_start, kPrefix,
                         kPrefixLength)) {
            size_t cursor = line_start + kPrefixLength;
            while (cursor < line_end &&
                   (data[cursor] == ' ' || data[cursor] == '\t')) {
                ++cursor;
            }
            while (cursor < line_end && data[cursor] >= '0' &&
                   data[cursor] <= '9') {
                if (data[cursor] != '0') {
                    data[cursor] = '0';
                    ++rewritten;
                }
                ++cursor;
            }
        }
        line_start = complete_line ? line_end + 1U : size;
    }
    return rewritten;
}

bool TracerPidValueIsZero(const uint8_t* data, size_t size,
                          const ProcStatusMetadata& metadata) noexcept {
    if (data == nullptr || metadata.tracer_value_length == 0 ||
        metadata.tracer_value_offset > size ||
        metadata.tracer_value_length >
                size - static_cast<size_t>(metadata.tracer_value_offset)) {
        return false;
    }
    for (uint32_t i = 0; i < metadata.tracer_value_length; ++i) {
        if (data[metadata.tracer_value_offset + i] != '0') {
            return false;
        }
    }
    return true;
}

}  // namespace hookself::internal
