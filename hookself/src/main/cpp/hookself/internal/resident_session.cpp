#include "resident_session.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include <linux/openat2.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch/arm64_regs.h"
#include "event_ring.h"
#include "internal/logical_ptrace_resident_state.h"
#include "proc_status_view.h"
#include "proc_virtual_dispatch.h"
#include "proc_virtual_resident_state.h"
#include "selective_seccomp_plan.h"
#include "platform/procfs.h"
#include "platform/raw_syscall_arm64.h"
#include "tracer/close_range_replay.h"
#include "tracer/mount_syscall_state.h"
#include "tracer/path_state.h"
#include "tracer/remote_syscall_arm64.h"
#include "tracer/task_table.h"
#include "tracer/wait_decoder.h"

namespace hookself::internal {
#include "resident_session/task_lifecycle.inc"
#include "resident_session/path_resolver.inc"
#include "resident_session/syscall_rules.inc"
#include "resident_session/protected_fd.inc"
#include "resident_session/proc_status.inc"
#include "resident_session/proc_stat.inc"
#include "resident_session/proc_wchan.inc"
#include "resident_session/policy_application.inc"
#include "resident_session/path_redirect.inc"
#include "resident_session/proc_virtual.inc"
#include "resident_session/nested.inc"
#include "resident_session/syscall_dispatch.inc"
#include "resident_session/event_loop.inc"
#include "resident_session/selective.inc"
#include "resident_session/controller_support.inc"
#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
#include "resident_session/selftest.inc"
#endif
#include "resident_session/controller.inc"
}  // namespace hookself::internal
