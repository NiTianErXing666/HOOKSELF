#include <stdio.h>

#include "hookself/internal/selective_seccomp_plan.h"
#include "hookself/public_api.h"
#include "hookself/tracer/mount_syscall_state.h"

int main() {
    HookselfConfig config{};
    config.struct_size = sizeof(config);
    config.abi_version = HOOKSELF_ABI_VERSION;

    hookself::internal::SelectiveSeccompPlan plan{};
    if (hookself::internal::BuildSelectiveSeccompPlan(&config, &plan) != 0) {
        return 1;
    }
    if (plan.rule_count != 18U ||
        plan.filter.rule_count != plan.rule_count) {
        return 4;
    }
    const int32_t mount_syscalls[] = {
            hookself::tracer::kMountStateMount,
            hookself::tracer::kMountStateUmount2,
            hookself::tracer::kMountStatePivotRoot,
            hookself::tracer::kMountStateChroot,
            hookself::tracer::kMountStateOpenTree,
            hookself::tracer::kMountStateMoveMount,
            hookself::tracer::kMountStateMountSetattr,
    };
    for (int32_t syscall_number : mount_syscalls) {
        uint16_t class_id = 0;
        if (!hookself::internal::FindSelectiveSeccompClass(
                    &plan, syscall_number, &class_id) ||
            class_id != hookself::internal::kSelectiveSeccompUnifiedClassId) {
            return 2;
        }
    }
    for (uint16_t index = 1; index < plan.rule_count; ++index) {
        if (plan.rules[index - 1U].syscall_number >=
            plan.rules[index].syscall_number) {
            return 3;
        }
    }
    puts("mount_selective_harness: PASS");
    return 0;
}
