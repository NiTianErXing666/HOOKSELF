#pragma once

#include <cstddef>
#include <cstdint>

namespace hookself::path_policy {

constexpr size_t kPathCapacity = 512;
constexpr size_t kMaxRules = 16;

enum class Action : int32_t {
    kPass = 0,
    kRedirect = 1,
    kInvalid = 2,
};

struct PrefixRule {
    int32_t id;
    char guest_prefix[kPathCapacity];
    char host_prefix[kPathCapacity];
};

struct Translation {
    int32_t action;
    int32_t error;
    int32_t rule_id;
    uint32_t input_length;
    uint32_t output_length;
};

Translation TranslateAbsolute(const char* input, size_t input_capacity,
                              const PrefixRule* rules, size_t rule_count,
                              char* output, size_t output_capacity);

}  // namespace hookself::path_policy
