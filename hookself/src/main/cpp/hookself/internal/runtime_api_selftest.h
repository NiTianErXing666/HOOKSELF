#pragma once

#include <cstdint>

#include "hookself/public_api.h"

namespace hookself::internal {

// Consumes runtime when destroyed is set. Intended for the device self-test.
int32_t RunRuntimeApiBypassDestroyStress(HookselfRuntime* runtime,
                                         bool* destroyed) noexcept;

// Temporarily extends the resident protected-FD registry for deterministic
// device self-tests. The caller must unregister the descriptor before stop.
int32_t RegisterProtectedFdForSelfTest(HookselfRuntime* runtime,
                                       int32_t fd) noexcept;
int32_t UnregisterProtectedFdForSelfTest(HookselfRuntime* runtime,
                                         int32_t fd) noexcept;

// Executes one exact close through the internal provider bypass while keeping
// the test registration in place. The return value follows the raw syscall ABI.
int64_t CloseProtectedFdForSelfTest(HookselfRuntime* runtime,
                                    int32_t fd) noexcept;

uint32_t CloseRangeCapabilitiesForSelfTest(
        const HookselfRuntime* runtime) noexcept;

void SetVirtualPublishPostCommitFailureForSelfTest(bool enabled) noexcept;

}  // namespace hookself::internal
