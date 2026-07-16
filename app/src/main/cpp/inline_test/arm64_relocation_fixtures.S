.text

.macro HOOKSELF_FIXTURE_BEGIN name
    .p2align 4
    .global \name
    .hidden \name
    .type \name, %function
\name:
.endm

.macro HOOKSELF_FIXTURE_END name
    .size \name, .-\name
.endm

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_plain
    add x0, x0, #7
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_plain

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_adr
    adr x0, hs_inline_fixture_adr_value
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_adr

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_adrp
    // A same-location expression is resolved by the assembler and cannot be
    // relaxed by the linker into ADR. It returns the original instruction page.
    adrp x0, .
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_adrp

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_literal_w
    ldr w0, hs_inline_fixture_literal_w_value
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_literal_w

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_literal_x
    ldr x0, hs_inline_fixture_literal_x_value
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_literal_x

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_ldrsw
    ldrsw x0, hs_inline_fixture_ldrsw_value
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_ldrsw

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_literal_s
    ldr s0, hs_inline_fixture_literal_s_value
    fmov w0, s0
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_literal_s

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_literal_d
    ldr d0, hs_inline_fixture_literal_d_value
    fmov x0, d0
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_literal_d

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_literal_q
    ldr q0, hs_inline_fixture_literal_q_value
    umov x0, v0.d[0]
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_literal_q

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_prfm
    prfm pldl1keep, hs_inline_fixture_literal_q_value
    mov x0, #0x5a
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_prfm

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_b
    b .Lfixture_b_taken
    mov x0, #0
.Lfixture_b_taken:
    add x0, x0, #9
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_b

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_bl
    bl .Lfixture_bl_helper
    br x19
HOOKSELF_FIXTURE_END hs_inline_fixture_bl

.Lfixture_bl_helper:
    mov x0, x30
    ret

// The BL fixture intentionally starts with BL, so this ABI-clean adapter keeps
// the caller return address outside x30 while the relocated function runs.
HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_invoke_bl
    stp x19, x30, [sp, #-16]!
    mov x16, x0
    mov x0, x1
    adr x19, .Lfixture_bl_return
    blr x16
    b .Lfixture_bl_return
.Lfixture_bl_return:
    ldp x19, x30, [sp], #16
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_invoke_bl

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_bcond
    b.eq .Lfixture_bcond_zero
    mov x0, #0x31
    ret
.Lfixture_bcond_zero:
    mov x0, #0x32
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_bcond

// BLR preserves NZCV, allowing B.cond to remain the target's first instruction.
HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_invoke_bcond
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x16, x0
    mov x0, x1
    cmp x0, #0
    blr x16
    ldp x29, x30, [sp], #16
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_invoke_bcond

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_cbz
    cbz x0, .Lfixture_cbz_taken
    mov x0, #0x41
    ret
.Lfixture_cbz_taken:
    mov x0, #0x42
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_cbz

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_cbnz
    cbnz x0, .Lfixture_cbnz_taken
    mov x0, #0x43
    ret
.Lfixture_cbnz_taken:
    mov x0, #0x44
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_cbnz

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_tbz
    tbz x0, #0, .Lfixture_tbz_taken
    mov x0, #0x51
    ret
.Lfixture_tbz_taken:
    mov x0, #0x52
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_tbz

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_tbnz
    tbnz x0, #0, .Lfixture_tbnz_taken
    mov x0, #0x53
    ret
.Lfixture_tbnz_taken:
    mov x0, #0x54
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_tbnz

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_bti
    .inst 0xd503245f // BTI C
    add x0, x0, #13
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_bti

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_paciasp
    .inst 0xd503233f // PACIASP
    add x0, x0, #15
    .inst 0xd50323bf // AUTIASP
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_paciasp

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_pacibsp
    .inst 0xd503237f // PACIBSP
    add x0, x0, #17
    .inst 0xd50323ff // AUTIBSP
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_pacibsp

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_convenience
    add x0, x0, #19
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_convenience

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_multi_a
    add x0, x0, #21
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_multi_a

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_multi_b
    add x0, x0, #23
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_multi_b

HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_concurrent
    add x0, x0, #3
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_concurrent

// Installation must reject an indirect call at the relocated entry. The test
// only inspects and installs this fixture; it never executes it.
HOOKSELF_FIXTURE_BEGIN hs_inline_fixture_unsupported_blr
    blr x0
    ret
HOOKSELF_FIXTURE_END hs_inline_fixture_unsupported_blr

.section .rodata.inline_hook_fixtures, "a", %progbits
.p2align 4

.global hs_inline_fixture_adr_value
.hidden hs_inline_fixture_adr_value
.type hs_inline_fixture_adr_value, %object
hs_inline_fixture_adr_value:
    .xword 0xa1a2a3a4a5a6a7a8
.size hs_inline_fixture_adr_value, 8

.p2align 2
.hidden hs_inline_fixture_literal_w_value
hs_inline_fixture_literal_w_value:
    .word 0x89abcdef

.p2align 3
.hidden hs_inline_fixture_literal_x_value
hs_inline_fixture_literal_x_value:
    .xword 0x0123456789abcdef

.p2align 2
.hidden hs_inline_fixture_ldrsw_value
hs_inline_fixture_ldrsw_value:
    .word 0xffed2979

.p2align 2
.hidden hs_inline_fixture_literal_s_value
hs_inline_fixture_literal_s_value:
    .word 0x3f9e0419

.p2align 3
.hidden hs_inline_fixture_literal_d_value
hs_inline_fixture_literal_d_value:
    .xword 0x400921fb54442d18

.p2align 4
.hidden hs_inline_fixture_literal_q_value
hs_inline_fixture_literal_q_value:
    .xword 0x1122334455667788
    .xword 0x99aabbccddeeff00

.section .note.GNU-stack, "", %progbits
