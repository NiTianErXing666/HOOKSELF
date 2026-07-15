#include "path_state.h"

#include <errno.h>
#include <stddef.h>

namespace hookself::tracer {
#include "path_state/storage_validation.inc"
#include "path_state/task_fd.inc"
#include "path_state/mount_translation.inc"

}  // namespace hookself::tracer
