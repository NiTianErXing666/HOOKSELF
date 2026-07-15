#pragma once

#include <cstdint>

namespace hookself::internal {

struct FrameworkSelfTestReport {
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
    int32_t chroot_path_result;
    int32_t chroot_path_first_failure;
};

FrameworkSelfTestReport RunFrameworkSelfTest(
        const char* virtual_backing_dir);

}  // namespace hookself::internal
