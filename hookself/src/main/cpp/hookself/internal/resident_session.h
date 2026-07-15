#pragma once

#include <cstdint>
#include <sys/types.h>

#include "hookself/public_api.h"
#include "shared_abi.h"

namespace hookself::internal {

struct ResidentSessionController {
    pid_t tracer_pid = -1;
    int control_event_fd = -1;
    int status_read_fd = -1;
    int original_dumpable = -1;
    int ptracer_configured = 0;
    int logical_dumpable = -1;
    int logical_ptracer = 0;
    uint64_t logical_ptracer_start_time = 0;
    int ptrace_view_enabled = 0;
    int selective_committed = 0;
    int selective_passthrough = 0;
    FdObjectIdentity control_event_identity{};
    FdObjectIdentity status_read_identity{};
};

void InitializeResidentController(ResidentSessionController* controller) noexcept;

// Verifies that a protected descriptor number loses its protected view after
// the original object is closed and that number is reused by a new object.
int RunProtectedFdIdentitySelfTest() noexcept;
int RunCloseRangeCapabilityPolicySelfTest() noexcept;
// Returns the operating error for the first failed path check. When non-null,
// first_failure receives the stable self-test stage identifier for that check.
int RunChrootPathResolutionSelfTest(int32_t* first_failure) noexcept;

// Starts either the reversible full-ptrace backend or the fail-closed selective
// seccomp backend selected by config. Selective stop keeps a pass-through tracer
// resident because a committed seccomp filter cannot be removed.
int32_t StartResidentSession(const HookselfConfig& config,
                             SharedSessionMapping* mapping,
                             ResidentSessionController* controller,
                             const int32_t* protected_fds,
                             uint32_t protected_fd_count) noexcept;

int32_t StopResidentSession(SharedSessionMapping* mapping,
                            ResidentSessionController* controller,
                            uint32_t timeout_ms) noexcept;

// Used by destroy/error paths. Full-ptrace sessions are reaped; selective
// sessions first prove resident pass-through and restore the App-side ptrace
// state while retaining the tracer required by the irreversible filter.
void ForceDestroyResidentSession(SharedSessionMapping* mapping,
                                 ResidentSessionController* controller) noexcept;

// Freezes every traced task except the teardown owner after a selective
// session has entered pass-through. The control and status descriptors must
// remain open until this handshake completes.
int32_t BeginResidentTeardownFreeze(SharedSessionMapping* mapping,
                                    ResidentSessionController* controller,
                                    uint32_t timeout_ms) noexcept;

// Closes one exact protected descriptor for the registered teardown owner.
// The capability is published only for the duration of this close syscall.
int CloseResidentTeardownFd(SharedSessionMapping* mapping, int fd,
                            const FdObjectIdentity& identity) noexcept;

// Releases the frozen tasks after the exact-close path has reduced the
// protected descriptor registry to zero, then waits for shared-memory ack.
int32_t ReleaseResidentTeardown(SharedSessionMapping* mapping,
                                uint32_t timeout_ms) noexcept;

// Clears the selective teardown-owner capability after release is acknowledged
// and before the shared control mapping is released.
void FinishResidentTeardown(SharedSessionMapping* mapping) noexcept;

}  // namespace hookself::internal
