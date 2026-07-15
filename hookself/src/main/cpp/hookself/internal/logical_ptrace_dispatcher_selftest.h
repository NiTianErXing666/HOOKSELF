#pragma once

#include <cstdint>

namespace hookself::internal {

constexpr uint32_t kLogicalPtraceDispatcherSelfTestVersion = 1U;

struct LogicalPtraceDispatcherSelfTestReport {
    uint32_t version;
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
    uint32_t scenarios;
    uint32_t reserved;
};

LogicalPtraceDispatcherSelfTestReport
RunLogicalPtraceDispatcherSelfTest() noexcept;

}  // namespace hookself::internal
