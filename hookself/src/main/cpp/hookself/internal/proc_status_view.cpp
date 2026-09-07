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

// 在 State 行值域内做等长替换："t (tracing stop)" → "S (sleeping)" + 尾部空格。
// 只处理完整行（行尾有 '\n'），避免跨 read 边界的半行被误改。
size_t RewriteProcStatusStateLine(uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0;
    }
    constexpr char kPrefix[] = "State:";
    constexpr size_t kPrefixLength = sizeof(kPrefix) - 1U;
    constexpr char kTracingStop[] = "(tracing stop)";
    constexpr size_t kTracingStopLength = sizeof(kTracingStop) - 1U;
    constexpr char kReplacement[] = "S (sleeping)";
    constexpr size_t kReplacementLength = sizeof(kReplacement) - 1U;
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
            const size_t value_start = cursor;
            const size_t value_length = line_end - value_start;
            if (value_length >= kReplacementLength &&
                data[cursor] == 't') {
                // 值格式 "t (tracing stop)"：'t' 与 '(' 之间可能有空格
                size_t paren = cursor + 1U;
                while (paren < line_end && data[paren] == ' ') {
                    ++paren;
                }
                if (paren < line_end &&
                    PrefixEquals(data, line_end, paren, kTracingStop,
                                 kTracingStopLength)) {
                    for (size_t i = 0; i < kReplacementLength; ++i) {
                        data[value_start + i] =
                                static_cast<uint8_t>(kReplacement[i]);
                    }
                    for (size_t i = kReplacementLength; i < value_length;
                         ++i) {
                        data[value_start + i] = ' ';
                    }
                    ++rewritten;
                }
            }
        }
        line_start = complete_line ? line_end + 1U : size;
    }
    return rewritten;
}

int ParseProcStatStateMetadata(const uint8_t* data, size_t size,
                               int32_t expected_pid,
                               ProcStatStateMetadata* metadata) noexcept {
    if (data == nullptr || size == 0 || expected_pid <= 0 ||
        metadata == nullptr) {
        return EINVAL;
    }
    *metadata = {};
    // 格式: "pid (comm) S ppid ..."，comm 可能含空格和括号
    size_t cursor = 0;
    uint64_t pid = 0;
    bool pid_present = false;
    while (cursor < size && data[cursor] >= '0' && data[cursor] <= '9') {
        const uint32_t digit = data[cursor] - '0';
        if (pid > (UINT64_MAX - digit) / 10U) {
            return EOVERFLOW;
        }
        pid = pid * 10U + digit;
        ++cursor;
        pid_present = true;
    }
    if (!pid_present || cursor == 0 || pid == 0 || pid > INT32_MAX ||
        cursor >= size || data[cursor] != ' ' ||
        static_cast<int32_t>(pid) != expected_pid) {
        return EPROTO;
    }
    ++cursor;  // 跳过 pid 后的空格
    if (cursor >= size || data[cursor] != '(') {
        return EPROTO;
    }
    // comm 取最后一个 ')'，与 /proc/stat 解析约定一致
    size_t rparen = 0;
    bool rparen_found = false;
    for (size_t i = cursor + 1U; i < size; ++i) {
        if (data[i] == ')') {
            rparen = i;
            rparen_found = true;
        }
    }
    if (!rparen_found || rparen + 1U >= size) {
        return EPROTO;
    }
    size_t state_cursor = rparen + 1U;
    while (state_cursor < size && data[state_cursor] == ' ') {
        ++state_cursor;
    }
    if (state_cursor >= size) {
        return EPROTO;
    }
    const uint8_t state = data[state_cursor];
    // State 字符后必须是空格或换行，防止把 comm 内部误判为字段
    const size_t next = state_cursor + 1U;
    if (next < size && data[next] != ' ' && data[next] != '\n') {
        return EPROTO;
    }
    metadata->pid = static_cast<int32_t>(pid);
    metadata->state_offset = state_cursor;
    if (state != 'S' && state != 'R' && state != 'D' && state != 't' &&
        state != 'T' && state != 'Z' && state != 'X' && state != 'x' &&
        state != 'I' && state != 'K' && state != 'W' && state != 'P') {
        return EPROTO;
    }
    return 0;
}

size_t RewriteProcStatStateTraced(uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0;
    }
    size_t rparen = 0;
    bool rparen_found = false;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == ')') {
            rparen = i;
            rparen_found = true;
        }
    }
    if (!rparen_found || rparen + 1U >= size) {
        return 0;
    }
    size_t state_cursor = rparen + 1U;
    while (state_cursor < size && data[state_cursor] == ' ') {
        ++state_cursor;
    }
    if (state_cursor < size && data[state_cursor] == 't') {
        const size_t next = state_cursor + 1U;
        if (next >= size || data[next] == ' ' || data[next] == '\n') {
            data[state_cursor] = 'S';
            return 1;
        }
    }
    return 0;
}

size_t RewriteProcWchanContent(uint8_t* data, size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0;
    }
    constexpr char kNeedle[] = "ptrace";
    constexpr size_t kNeedleLength = sizeof(kNeedle) - 1U;
    bool present = false;
    for (size_t i = 0; i + kNeedleLength <= size; ++i) {
        if (PrefixEquals(data, size, i, kNeedle, kNeedleLength)) {
            present = true;
            break;
        }
    }
    if (!present) {
        return 0;
    }
    // 标准值: "ptrace_stop" (11) → 真实内核符号 "wait_waking" (11)，'\n' 保留
    constexpr char kPtraceStop[] = "ptrace_stop";
    constexpr size_t kPtraceStopLength = sizeof(kPtraceStop) - 1U;
    constexpr char kWaitWaking[] = "wait_waking";
    if (size >= kPtraceStopLength &&
        PrefixEquals(data, size, 0, kPtraceStop, kPtraceStopLength)) {
        for (size_t i = 0; i < kPtraceStopLength; ++i) {
            data[i] = static_cast<uint8_t>(kWaitWaking[i]);
        }
        return 1;
    }
    // 变体: 含 "ptrace" 的未知符号 → 等长循环填充良性符号，长度不变
    constexpr char kBenign[] = "futex_wait";
    constexpr size_t kBenignLength = sizeof(kBenign) - 1U;
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(kBenign[i % kBenignLength]);
    }
    return 1;
}

}  // namespace hookself::internal
