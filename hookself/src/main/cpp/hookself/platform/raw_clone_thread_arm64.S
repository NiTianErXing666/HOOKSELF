#include <asm/unistd.h>

    .text
    .p2align 2
    .global HookselfRawCloneThread
    .type HookselfRawCloneThread, %function
HookselfRawCloneThread:
    // x0=entry, x1=argument, x2=stack_top, x3=clone_flags.
    and x9, x2, #-16
    sub x9, x9, #16
    stp x0, x1, [x9]

    mov x0, x3
    mov x1, x9
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x8, #__NR_clone
    svc #0
    cbnz x0, 1f

    // The kernel switched SP to x9 in the child.
    ldp x9, x0, [sp]
    blr x9
    mov x8, #__NR_exit
    svc #0
    brk #0

1:
    ret
    .size HookselfRawCloneThread, .-HookselfRawCloneThread
