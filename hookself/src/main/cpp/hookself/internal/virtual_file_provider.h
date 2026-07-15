#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace hookself::internal {

struct VirtualFileHiddenRange {
    uintptr_t start;
    size_t size;
};

int OpenVirtualFileProviderSource(int32_t provider, pid_t target_pid,
                                  int* source_fd) noexcept;
int GenerateVirtualFileProviderSnapshot(
        int32_t provider, uint32_t flags, int source_fd,
        const uint8_t* configured_content, size_t configured_content_size,
        const VirtualFileHiddenRange* hidden_ranges,
        size_t hidden_range_count,
        uint8_t* output, size_t output_capacity,
        size_t* output_size) noexcept;

}  // namespace hookself::internal
