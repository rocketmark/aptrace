@ Added controls for the production p-code forward-use operation: shapes
@ whose correct answer is INCOMPLETE or UNSUPPORTED (never a silent
@ negative), plus two ABI controls. Same conventions as thumb_controls.s
@ (base 0, CB = 0x1001 = Thumb function at 0x1000); expectations in
@ controls.json.
@
@   clang -target thumbv7em-none-eabi -c thumb_negative.s -o /tmp/n.o
@   python3 extract_text.py /tmp/n.o thumb_negative.bin
        .syntax unified
        .cpu cortex-m4
        .thumb
        .text
        .equ CB, 0x1001

        .org 0x000                @ N1 computed jump, value live, no known targets
        .thumb_func
n1:     ldr r3, 9f
        bx r2
        .p2align 2
9:      .word CB

        .org 0x040                @ N2 no containing function (no function is created here)
n2:     ldr r3, 9f
        cbnz r3, 1f
        movs r0, #0
1:      bx lr
        .p2align 2
9:      .word CB

        .org 0x080                @ N3 compare then loop; run with a 2-step budget
        .thumb_func
n3:     ldr r2, 9f
        cmp r2, #0
        beq 2f
        movs r2, #0
1:      adds r2, #1
        cmp r2, #4
        bne 1b
2:      bx lr
        .p2align 2
9:      .word CB

        .org 0x0c0                @ N4 C6 shape, function body truncated before the store
        .thumb_func
n4:     ldr r3, 9f
        cmp r0, #0
        beq 1f
        movs r3, #0
1:      str r3, [r1]
        bx lr
        .p2align 2
9:      .word CB

        .org 0x100                @ N5 value reaches a user-defined p-code op (MSR MSP)
        .thumb_func
n5:     ldr r3, 9f
        msr msp, r3
        movs r3, #0
        bx lr
        .p2align 2
9:      .word CB

        .org 0x140                @ N6 two-register load: ambiguous origin unless a register is named
        .thumb_func
n6:     ldrd r2, r3, [r0]
        str r3, [r1]
        bx lr

        .org 0x180                @ N7 copy to a callee-saved register survives a call, then stored
        .thumb_func
n7:     push {r4, lr}
        ldr r3, 9f
        mov r4, r3
        movs r3, #0
        bl helper
        str r4, [r0]
        pop {r4, pc}
        .p2align 2
9:      .word CB

        .org 0x1c0                @ N8 copy to a call-clobbered non-argument register dies at a call
        .thumb_func
n8:     push {r4, lr}
        ldr r3, 9f
        mov ip, r3
        movs r3, #0
        bl helper
        str ip, [r0]
        pop {r4, pc}
        .p2align 2
9:      .word CB

        .org 0x800
        .thumb_func
helper: bx lr

        .org 0x1000
        .thumb_func
cb:     bx lr
