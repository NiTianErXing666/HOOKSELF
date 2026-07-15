#include <stdio.h>

#include "internal/logical_ptrace_dispatcher_selftest.h"
#include "internal/logical_ptrace_resident_state_selftest.h"

int main() {
    const hookself::internal::LogicalPtraceDispatcherSelfTestReport report =
            hookself::internal::RunLogicalPtraceDispatcherSelfTest();
    const hookself::internal::LogicalPtraceResidentStateSelfTestReport
            resident = hookself::internal::
                    RunLogicalPtraceResidentStateSelfTest();
    printf("logical_ptrace_dispatcher_harness: checks=%u failures=%u "
           "first=%d scenarios=%u\n",
           report.checks, report.failures, report.first_failure,
           report.scenarios);
    printf("logical_ptrace_resident_state: checks=%u failures=%u first=%d\n",
           resident.checks, resident.failures, resident.first_failure);
    return report.failures == 0U && resident.failures == 0U ? 0 : 1;
}
