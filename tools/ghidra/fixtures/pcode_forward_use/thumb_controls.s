@ Controlled Thumb-2 pointer-use fixtures (Cortex-M, base 0).
@ Each case is a function at a fixed .org; its first instruction loads the
@ code pointer CB (0x1001 = Thumb function at 0x1000) into a register.
@ Expected classification of that loaded value is in expected.json.
        .syntax unified
        .cpu cortex-m4
        .thumb
        .text
        .equ CB, 0x1001

        .org 0x000                @ C1 compare_only (negative)
        .thumb_func
c1:     ldr r3, 9f
        cbnz r3, 1f
        movs r0, #0
        bx lr
1:      add r3, sp, #4
        movs r0, #1
        bx lr
        .p2align 2
9:      .word CB

        .org 0x040                @ C2 call_through (positive: control transfer)
        .thumb_func
c2:     ldr r3, 9f
        push {r4, lr}
        cbz r3, 1f
        blx r3
1:      pop {r4, pc}
        .p2align 2
9:      .word CB

        .org 0x080                @ C3 store (positive: memory store)
        .thumb_func
c3:     ldr r3, 9f
        str r3, [r0, #8]
        bx lr
        .p2align 2
9:      .word CB

        .org 0x0c0                @ C4 argument via move (positive: argument)
        .thumb_func
c4:     ldr r3, 9f
        push {r4, lr}
        mov r1, r3
        movs r3, #0
        bl helper
        pop {r4, pc}
        .p2align 2
9:      .word CB

        .org 0x100                @ C5 return value (positive: return)
        .thumb_func
c5:     ldr r3, 9f
        mov r0, r3
        bx lr
        .p2align 2
9:      .word CB

        .org 0x140                @ C6 join conceals a store on one path (positive)
        .thumb_func
c6:     ldr r3, 9f
        cmp r0, #0
        beq 1f
        movs r3, #0
1:      str r3, [r1]
        bx lr
        .p2align 2
9:      .word CB

        .org 0x180                @ C7 killed on both paths before a join (negative)
        .thumb_func
c7:     ldr r3, 9f
        cmp r0, #0
        beq 1f
        movs r3, #0
        b 2f
1:      movs r3, #1
2:      str r3, [r1]
        bx lr
        .p2align 2
9:      .word CB

        .org 0x1c0                @ C8 stack spill + reload + call (positive: control transfer)
        .thumb_func
c8:     push {lr}
        sub sp, #12
        ldr r3, 9f
        str r3, [sp, #4]
        movs r3, #0
        ldr r2, [sp, #4]
        blx r2
        add sp, #12
        pop {pc}
        .p2align 2
9:      .word CB

        .org 0x200                @ C9 IT-conditional redefinition (positive: store)
        .thumb_func
c9:     ldr r3, 9f
        cmp r0, #0
        it eq
        moveq r3, #0
        str r3, [r1]
        bx lr
        .p2align 2
9:      .word CB

        .org 0x240                @ C10 tail call with pointer argument (positive: argument)
        .thumb_func
c10:    ldr r0, 9f
        b.w helper
        .p2align 2
9:      .word CB

        .org 0x280                @ C11 compare then fall into a loop, never escapes (negative)
        .thumb_func
c11:    ldr r2, 9f
        cmp r2, #0
        beq 2f
        movs r2, #0
1:      adds r2, #1
        cmp r2, #4
        bne 1b
2:      bx lr
        .p2align 2
9:      .word CB

        .org 0x800
        .thumb_func
helper: bx lr

        .org 0x1000
        .thumb_func
cb:     bx lr
