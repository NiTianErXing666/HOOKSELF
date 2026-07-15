#include "path_policy.h"

#include <errno.h>

namespace hookself::path_policy {
namespace {

bool BoundedLength(const char* value, size_t capacity, size_t* length) {
    if (value == nullptr || capacity == 0) {
        return false;
    }
    for (size_t i = 0; i < capacity; ++i) {
        if (value[i] == '\0') {
            *length = i;
            return true;
        }
    }
    return false;
}

bool IsDotSegment(const char* path, size_t start, size_t end) {
    const size_t length = end - start;
    return (length == 1 && path[start] == '.') ||
           (length == 2 && path[start] == '.' && path[start + 1] == '.');
}

bool IsCanonicalAbsolute(const char* path, size_t length, bool is_rule_prefix) {
    if (length == 0 || path[0] != '/') {
        return false;
    }
    if (length == 1) {
        return true;
    }
    if (is_rule_prefix && length > 1 && path[length - 1] == '/') {
        return false;
    }
    size_t segment_start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && path[i] != '/') {
            continue;
        }
        if (i == segment_start) {
            if (i == length && !is_rule_prefix) {
                return true;
            }
            return false;
        }
        if (IsDotSegment(path, segment_start, i)) {
            return false;
        }
        segment_start = i + 1;
    }
    return true;
}

bool PrefixMatches(const char* input, size_t input_length,
                   const char* prefix, size_t prefix_length) {
    if (prefix_length > input_length) {
        return false;
    }
    for (size_t i = 0; i < prefix_length; ++i) {
        if (input[i] != prefix[i]) {
            return false;
        }
    }
    if (prefix_length == 1 && prefix[0] == '/') {
        return true;
    }
    return prefix_length == input_length || input[prefix_length] == '/';
}

bool CopyTranslated(const char* input, size_t input_length,
                    size_t guest_length, const char* host, size_t host_length,
                    char* output, size_t output_capacity, size_t* output_length) {
    size_t written = 0;
    for (size_t i = 0; i < host_length; ++i) {
        if (written + 1 >= output_capacity) {
            return false;
        }
        output[written++] = host[i];
    }

    size_t suffix_start = guest_length;
    bool add_separator = false;
    if (guest_length == 1) {
        suffix_start = 1;
        add_separator = suffix_start < input_length &&
                        !(host_length == 1 && host[0] == '/');
    } else if (suffix_start < input_length && host_length == 1 && host[0] == '/') {
        ++suffix_start;
    }
    if (add_separator) {
        if (written + 1 >= output_capacity) {
            return false;
        }
        output[written++] = '/';
    }
    for (size_t i = suffix_start; i < input_length; ++i) {
        if (written + 1 >= output_capacity) {
            return false;
        }
        output[written++] = input[i];
    }
    output[written] = '\0';
    *output_length = written;
    return true;
}

}  // namespace

Translation TranslateAbsolute(const char* input, size_t input_capacity,
                              const PrefixRule* rules, size_t rule_count,
                              char* output, size_t output_capacity) {
    Translation result{static_cast<int32_t>(Action::kInvalid), EINVAL, -1, 0, 0};
    if ((rules == nullptr && rule_count != 0) || rule_count > kMaxRules || output == nullptr ||
        output_capacity == 0) {
        return result;
    }

    size_t input_length = 0;
    if (!BoundedLength(input, input_capacity, &input_length)) {
        result.error = ENAMETOOLONG;
        return result;
    }
    result.input_length = static_cast<uint32_t>(input_length);
    if (!IsCanonicalAbsolute(input, input_length, false)) {
        result.error = ENOTSUP;
        return result;
    }

    const PrefixRule* selected = nullptr;
    size_t selected_guest_length = 0;
    size_t selected_host_length = 0;
    for (size_t i = 0; i < rule_count; ++i) {
        size_t guest_length = 0;
        size_t host_length = 0;
        if (!BoundedLength(rules[i].guest_prefix, sizeof(rules[i].guest_prefix),
                           &guest_length) ||
            !BoundedLength(rules[i].host_prefix, sizeof(rules[i].host_prefix),
                           &host_length) ||
            !IsCanonicalAbsolute(rules[i].guest_prefix, guest_length, true) ||
            !IsCanonicalAbsolute(rules[i].host_prefix, host_length, true)) {
            result.error = EINVAL;
            return result;
        }
        if (PrefixMatches(input, input_length, rules[i].guest_prefix, guest_length) &&
            (selected == nullptr || guest_length >= selected_guest_length)) {
            selected = &rules[i];
            selected_guest_length = guest_length;
            selected_host_length = host_length;
        }
    }

    if (selected == nullptr) {
        result.action = static_cast<int32_t>(Action::kPass);
        result.error = 0;
        return result;
    }

    size_t translated_length = 0;
    if (!CopyTranslated(input, input_length, selected_guest_length,
                        selected->host_prefix, selected_host_length,
                        output, output_capacity, &translated_length)) {
        result.error = ENAMETOOLONG;
        return result;
    }
    result.action = static_cast<int32_t>(Action::kRedirect);
    result.error = 0;
    result.rule_id = selected->id;
    result.output_length = static_cast<uint32_t>(translated_length);
    return result;
}

}  // namespace hookself::path_policy
