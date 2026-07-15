#include <asm/unistd.h>

    .text
    .align 2
    .global hookself_runtime_bypass_gettid
    .hidden hookself_runtime_bypass_gettid
    .type hookself_runtime_bypass_gettid, %function
hookself_runtime_bypass_gettid:
    mov x8, #__NR_gettid

    .global hookself_runtime_bypass_gettid_svc
    .hidden hookself_runtime_bypass_gettid_svc
hookself_runtime_bypass_gettid_svc:
    svc #0

    .global hookself_runtime_bypass_gettid_after_svc
    .hidden hookself_runtime_bypass_gettid_after_svc
hookself_runtime_bypass_gettid_after_svc:
    ret
    .size hookself_runtime_bypass_gettid, .-hookself_runtime_bypass_gettid

    .section .note.GNU-stack,"",%progbits
