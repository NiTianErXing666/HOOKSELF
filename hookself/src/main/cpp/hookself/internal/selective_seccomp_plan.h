#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "hookself/public_api.h"
#include "internal/selective_seccomp_filter.h"

namespace hookself::internal {

constexpr uint32_t kSelectiveSeccompPlanSchemaVersion = 2U;
constexpr uint16_t kSelectiveSeccompUnifiedClassId = 0x4853U;  // "HS"

// Fully compiled, allocation-free input for the irreversible TSYNC commit.
// Rules are strictly sorted by syscall number and all use the unified class ID;
// the tracer must still verify the syscall number reported by the kernel.
struct SelectiveSeccompPlan {
    uint32_t schema_version;
    uint16_t rule_count;
    uint16_t class_id;
    uint64_t syscall_set_hash;
    SelectiveSeccompRule rules[kMaxSelectiveSeccompRules];
    SelectiveSeccompFilter filter;
};

static_assert(std::is_standard_layout_v<SelectiveSeccompPlan> &&
              std::is_trivially_copyable_v<SelectiveSeccompPlan>);

// Compiles every explicitly configured syscall together with the resident
// runtime's protected-FD, path-policy and ptrace/proc-view dependencies.
// HOOKSELF_CONFIG_OBSERVE_ALL is rejected because a selective allow-by-default
// filter cannot preserve its full-stream semantics.
//
// Returns 0 on success or a positive errno on failure. The output is cleared
// before validation and remains cleared on every failure.
int BuildSelectiveSeccompPlan(const HookselfConfig* config,
                              SelectiveSeccompPlan* output) noexcept;

// Binary-searches a successfully built plan. class_id is cleared on a miss.
bool FindSelectiveSeccompClass(const SelectiveSeccompPlan* plan,
                               int32_t syscall_number,
                               uint16_t* class_id) noexcept;

}  // namespace hookself::internal
