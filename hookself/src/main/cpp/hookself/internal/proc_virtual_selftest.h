#pragma once

#include <cstdint>

namespace hookself::internal {

struct ProcVirtualSelfTestReport {
    uint32_t checks;
    uint32_t failures;
    int32_t first_failure;
};

ProcVirtualSelfTestReport RunProcVirtualSelfTest() noexcept;

struct ProcVirtualResidentSmokeReport {
    int32_t verdict;
    int32_t create_result;
    int32_t start_result;
    int32_t stop_result;
    int32_t tracer_pid;
    int32_t maps_hidden;
    int32_t smaps_hidden;
    int32_t proc_dir_hidden;
    int32_t xattr_get_match;
    int32_t xattr_list_match;
    int32_t xattr_open_result;
    int32_t xattr_open_errno;
    int64_t xattr_get_result;
    int32_t xattr_get_errno;
    int64_t xattr_list_result;
    int32_t xattr_list_errno;
    int32_t fatal_code;
    int32_t fatal_errno;
};

ProcVirtualResidentSmokeReport RunProcVirtualResidentSmokeTest(
        const char* virtual_backing_dir) noexcept;

}  // namespace hookself::internal
