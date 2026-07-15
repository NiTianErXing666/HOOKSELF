#pragma once

#include <cstdint>

namespace hookself::internal {

struct FrameworkFacadeSelfTestReport {
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
};

FrameworkFacadeSelfTestReport RunFrameworkFacadeSelfTest();

}  // namespace hookself::internal
