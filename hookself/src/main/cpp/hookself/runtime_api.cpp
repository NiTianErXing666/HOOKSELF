#include "hookself/public_api.h"

#include <android/log.h>
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <new>

#include "internal/event_ring.h"
#include "internal/resident_session.h"
#include "internal/runtime_facade_bridge.h"
#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
#include "internal/runtime_api_selftest.h"
#endif
#include "internal/shared_abi.h"
#include "internal/virtual_file_provider.h"
#include "internal/virtual_file_store.h"
#include "platform/procfs.h"
#include "platform/raw_syscall_arm64.h"

namespace {

#include "api/runtime/runtime_globals.inc"

}  // namespace

#include "api/runtime/runtime_context.inc"

namespace {
#include "api/runtime/guards.inc"
#include "api/runtime/virtual_files.inc"
#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
#include "api/runtime/runtime_selftest.inc"
#endif
}  // namespace

#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
namespace hookself::internal {
#include "api/runtime/runtime_selftest_public.inc"
}  // namespace hookself::internal
#endif

#include "api/runtime/lifecycle.inc"
#include "api/runtime/events.inc"
#include "api/runtime/virtual_file_public.inc"
