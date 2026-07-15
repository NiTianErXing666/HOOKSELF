#pragma once

#include <cstddef>
#include <cstdint>

#include "hookself/public_api.h"

namespace hookself::internal {

void RequestRuntimeDrainAbort(HookselfRuntime* runtime) noexcept;

int32_t PublishRuntimeVirtualFile(
        HookselfRuntime* runtime, uint32_t file_id, const uint8_t* content,
        size_t content_size, uint32_t* snapshot_published);

}  // namespace hookself::internal
