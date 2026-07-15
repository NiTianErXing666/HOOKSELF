#include "hookself/framework.h"

#include <pthread.h>

#include <cstddef>
#include <cstdint>
#include <new>

#include "internal/runtime_facade_bridge.h"

namespace {

#include "api/framework/state.inc"

}  // namespace

#include "api/framework/framework_context.inc"

namespace {
#include "api/framework/call_registry.inc"
#include "api/framework/rule_registry_helpers.inc"
#include "api/framework/runtime_lifecycle_helpers.inc"
}  // namespace

#include "api/framework/create_destroy_public.inc"
#include "api/framework/rule_public.inc"
#include "api/framework/runtime_public.inc"
#include "api/framework/service_forwarding_public.inc"
