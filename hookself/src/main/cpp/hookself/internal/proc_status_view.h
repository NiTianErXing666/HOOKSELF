#pragma once

#include <cstddef>
#include <cstdint>

namespace hookself::internal {

struct ProcStatusMetadata {
    int32_t tgid;
    int32_t pid;
    uint64_t tracer_value_offset;
    uint32_t tracer_value_length;
};

int ParseProcStatusMetadata(const uint8_t* data, size_t size,
                            int32_t expected_tgid,
                            ProcStatusMetadata* metadata) noexcept;

size_t RewriteTracerPidValue(uint8_t* data, size_t size) noexcept;

bool TracerPidValueIsZero(const uint8_t* data, size_t size,
                          const ProcStatusMetadata& metadata) noexcept;

}  // namespace hookself::internal
