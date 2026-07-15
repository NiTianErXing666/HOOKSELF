#pragma once

#include <cstdint>

namespace hookself::internal {

struct LogicalPtraceResidentStateSelfTestReport {
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
};

LogicalPtraceResidentStateSelfTestReport
RunLogicalPtraceResidentStateSelfTest() noexcept;

}  // namespace hookself::internal
