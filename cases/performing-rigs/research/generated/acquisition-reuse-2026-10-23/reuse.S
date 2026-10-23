/* Simulation research only. NOT FOR HARDWARE DEPLOYMENT. */
.syntax unified
.cpu cortex-m4
.thumb
.text
.equ STATE, 0x2000531c
.equ INTERVAL, 50
.equ MAX_GAP, 20
.macro call_original address
 movw r12, #\address
 blx r12
.endm
.global poll_hook, accept_hook, program_hook, armed, qualified, commit
.global raw_hook, analog_hook, digital_hook, busy_hook, observation_update
.thumb_func
poll_hook:
 push {r0,r1,r2,r4,r5,r6,r7,r8,r9,r10,r11,lr}
 push {r0,r1}
 ldr r0,=STATE
 mov.w r1,#0
 str r1,[r0,#36] /* invalidate acquisition provenance at every poll */
 pop {r0,r1}
 ldr pc,=0x8e1d
.thumb_func
program_hook:
 push {r0-r3,r12,lr}
 ldr r0, =STATE
 movs r1, #0
 str r1, [r0]
 str r1, [r0,#8]
 str r1, [r0,#36]
 pop {r0-r3,r12,lr}
 ldr pc, =0xb2ff

/* r0: 0 both inactive, 3 both active, 1 raw-active/filter-inactive,
 * 2 raw-inactive/filter-active, 4 unsupported. Acquisitions are real helpers. */
.thumb_func
.Lfresh:
 push {r4-r7,r12,lr}
 ldr r7, =STATE
 ldr r0, =0x20001fc0
 ldrb r0,[r0]
 cmp r0,#2
 beq .Ldigital
 cmp r0,#1
 bne .Lunsupported
 call_original 0x42a5
 mov r5,r0
 movs r0,#59
 call_original 0xd1b5
 mov r4,r0
 ldr r0, =0x20000194
 ldr r0,[r0]
 cmp r0,#1
 beq .Lband1
 cmp r0,#2
 bne .Lunsupported
 movw r2,#250
 movw r3,#750
 b .Lband
.Lband1:
 movw r2,#200
 movw r3,#580
.Lband:
 movs r0,#0
 cmp r4,r2
 blt .Lraw_active
 cmp r4,r3
 ble .Lfiltered
.Lraw_active:
 orr r0,r0,#1
.Lfiltered:
 cmp r5,r2
 blt .Lfiltered_active
 cmp r5,r3
 ble .Lclassification_done
.Lfiltered_active:
 orr r0,r0,#2
 b .Lclassification_done
.Ldigital:
 movs r0,#57
 call_original 0xd3dd
 mov r4,r0
 mov r5,r0
 cmp r0,#0
 ite eq
 moveq r0,#3
 movne r0,#0
.Lclassification_done:
 str r4,[r7,#24]
 str r5,[r7,#28]
 pop {r4-r7,r12,pc}
.Lunsupported:
 movs r0,#4
 pop {r4-r7,r12,pc}
.ltorg

/* Actual ADC return inside native filter; six displaced bytes replayed.
 * No policy decision is made in this globally shared acquisition hook. */
.thumb_func
raw_hook:
 push {r0-r3,r12,lr}
 mrs r12,apsr
 ldr r1,=STATE
 str r0,[r1,#24]
 ldr r2,=0x200052ec
 ldr r2,[r2]
 str r2,[r1,#44]
 ldr r2,=0x20000194
 ldr r2,[r2]
 str r2,[r1,#48]
 mov.w r2,#1
 str r2,[r1,#36]
 msr apsr_nzcvq,r12
 pop {r0-r3,r12,lr}
 ldr r3,=0x20003118
 vmov s15,r0
 ldr pc,=0x42db
.ltorg

/* Analog policy observes only the original filter call at8e76. */
.thumb_func
analog_hook:
 push {r4,lr}
 call_original 0x42a5
 push {r0-r3,r12,lr}
 mrs r4,apsr
 ldr r1,=STATE
 str r0,[r1,#28]
 bl .Lpoll
 msr apsr_nzcvq,r4
 pop {r0-r3,r12,lr}
 pop {r4,lr}
 bx lr
.ltorg

/* Reuse the native digital acceptance read. */
.thumb_func
digital_hook:
 push {r4,lr}
 call_original 0xd3dd
 push {r0-r3,r12,lr}
 mrs r4,apsr
 bl .Lrecord_digital
 bl .Lpoll
 msr apsr_nzcvq,r4
 pop {r0-r3,r12,lr}
 pop {r4,lr}
 bx lr

/* Capture actual digitalRead return+time. Called with original R0 result. */
.thumb_func
.Lrecord_digital:
 ldr r1,=STATE
 str r0,[r1,#24]
 str r0,[r1,#28]
 ldr r2,=0x200052ec
 ldr r2,[r2]
 str r2,[r1,#44]
 ldr r2,=0x20000194
 ldr r2,[r2]
 str r2,[r1,#48]
 movs r2,#2
 str r2,[r1,#36]
 bx lr
.ltorg

/* A busy digital poll has no native acceptance read. Exactly one fallback
 * observation on its reject/return path maintains release arming while busy. */
.thumb_func
busy_hook:
 push {r0-r3,r12,lr}
 mrs r4,apsr /* original r4 will be restored by the original epilogue */
 ldr r0,=0x20001fc0
 ldrb r0,[r0]
 cmp r0,#2
 bne .Lbusy_done
 ldr r0,=STATE
 ldr r0,[r0,#36]
 cmp r0,#2
 beq .Lbusy_done
 movs r0,#57
 call_original 0xd3dd
 bl .Lrecord_digital
 bl .Lpoll
.Lbusy_done:
 msr apsr_nzcvq,r4
 pop {r0-r3,r12,lr}
 add sp,#12
 pop {r4-r11,pc}
.ltorg

/* Use only an acquisition in this poll, matching mode/X, age<=20.
 * Missing native ADC (cached filter return) is invalid, never time-advancing. */
.thumb_func
.Lobserved:
 push {r4-r7,r12,lr}
 ldr r7,=STATE
 ldr r0,[r7,#36]
 cmp r0,#1
 beq .Lobs_analog
 cmp r0,#2
 bne .Lunsupported
 ldr r1,=0x20001fc0
 ldrb r1,[r1]
 cmp r1,#2
 bne .Lunsupported
 b .Lobs_age
.Lobs_analog:
 ldr r1,=0x20001fc0
 ldrb r1,[r1]
 cmp r1,#1
 bne .Lunsupported
.Lobs_age:
 ldr r1,=0x20000194
 ldr r1,[r1]
 ldr r2,[r7,#48]
 cmp r1,r2
 bne .Lunsupported
 ldr r1,=0x200052ec
 ldr r1,[r1]
 ldr r2,[r7,#44]
 subs r1,r1,r2
 cmp r1,#MAX_GAP
 bhi .Lunsupported
 ldr r4,[r7,#24]
 ldr r5,[r7,#28]
 cmp r0,#2
 beq .Lobs_digital
 ldr r0,=0x20000194
 ldr r0,[r0]
 cmp r0,#1
 beq .Lband1
 cmp r0,#2
 bne .Lunsupported
 movw r2,#250
 movw r3,#750
 b .Lband
.Lobs_digital:
 cmp r4,#0
 ite eq
 moveq r0,#3
 movne r0,#0
 pop {r4-r7,r12,pc}
.ltorg

/* Original shared eligibility plus explicit setup-complete. */
.thumb_func
.Leligible:
 ldr r0,=0x20002524
 ldr r0,[r0]
 cbnz r0,.Lno
 ldr r0,=0x20001b38
 ldr r0,[r0]
 cmp r0,#123
 bne .Lno
 ldr r0,=0x200000d8
 ldrb r0,[r0]
 cmp r0,#9
 bne .Lno
 ldr r0,=0x20003120
 ldrb r0,[r0]
 cbnz r0,.Lno
 ldr r0,=0x20000060
 ldrb r0,[r0]
 cbnz r0,.Lno
 movs r0,#1
 bx lr
.Lno:
 movs r0,#0
 bx lr
.ltorg

/* Main-loop-only state: 0 need release, 1 releasing, 2 armed,
 * 3 active candidate, 4 qualified but unconsumed. */
.thumb_func
.Lpoll:
observation_update:
 push {r4-r8,lr}
 ldr r4,=STATE
 ldr r5,[r4,#44] /* time of actual acquisition, not filter-cache return */
 ldr r1,[r4,#32]
 subs r1,r5,r1
 cmp r1,#MAX_GAP
 bhi .Lcontext_reset
 ldr r1,=0x20001fc0
 ldrb r1,[r1]
 ldr r2,[r4,#8]
 cmp r1,r2
 bne .Lcontext_reset
 ldr r1,=0x20000194
 ldr r1,[r1]
 ldr r2,[r4,#12]
 cmp r1,r2
 bne .Lcontext_reset
 ldr r1,=0x20001b38
 ldr r1,[r1]
 ldr r2,[r4,#16]
 cmp r1,r2
 bne .Lcontext_reset
 ldr r1,=0x20003120
 ldrb r1,[r1]
 ldr r2,[r4,#20]
 cmp r1,r2
 beq .Lcontext_ok
.Lcontext_reset:
 movs r1,#0
 str r1,[r4]
 str r5,[r4,#4]
.Lcontext_ok:
 str r5,[r4,#32]
 ldr r1,=0x20001fc0
 ldrb r1,[r1]
 str r1,[r4,#8]
 ldr r1,=0x20000194
 ldr r1,[r1]
 str r1,[r4,#12]
 ldr r1,=0x20001b38
 ldr r1,[r1]
 str r1,[r4,#16]
 ldr r1,=0x20003120
 ldrb r1,[r1]
 str r1,[r4,#20]
 cbnz r1,.Lreset
 ldr r6,[r4]
 cmp r6,#4
 bhi .Lreset
 bl .Lobserved
 cmp r0,#0
 beq .Linactive
 cmp r0,#3
 beq .Lactive
 /* Raw-active with delayed filter may wait armed; never counts inactive. */
 cmp r0,#1
 bne .Lreset
 cmp r6,#2
 blo .Lreset
 movs r1,#2
 str r1,[r4]
 b .Lpoll_done
.Linactive:
 cmp r6,#2
 beq .Lpoll_done
 cmp r6,#1
 bne .Lbegin_release
 ldr r1,[r4,#4]
 subs r1,r5,r1
 cmp r1,#INTERVAL
 blo .Lpoll_done
armed:
 movs r1,#2
 str r1,[r4]
 b .Lpoll_done
.Lbegin_release:
 movs r1,#1
 str r1,[r4]
 str r5,[r4,#4]
 b .Lpoll_done
.Lactive:
 cmp r6,#2
 blo .Lreset
 bl .Leligible
 cmp r0,#0
 beq .Lreset
 cmp r6,#4
 beq .Lpoll_done
 cmp r6,#3
 bne .Lbegin_active
 ldr r1,[r4,#4]
 subs r1,r5,r1
 cmp r1,#INTERVAL
 blo .Lpoll_done
qualified:
 movs r1,#4
 str r1,[r4]
 b .Lpoll_done
.Lbegin_active:
 movs r1,#3
 str r1,[r4]
 str r5,[r4,#4]
 b .Lpoll_done
.Lreset:
 movs r1,#0
 str r1,[r4]
.Lpoll_done:
 pop {r4-r8,pc}
.ltorg

.thumb_func
accept_hook:
 push {r0-r12,lr}
 ldr r4,=STATE
 ldr r0,[r4]
 cmp r0,#4
 bne .Ldeny
 /* Reacquire before committing. No mid-motion cancellation is introduced. */
 bl .Lfresh
 cmp r0,#3
 bne .Linvalidate
 call_original 0xccd1
 ldr r1,[r4,#32]
 subs r0,r0,r1
 cmp r0,#MAX_GAP
 bhi .Linvalidate
 mrs r6,primask
 cpsid i
 bl .Leligible
 cmp r0,#0
 beq .Lmasked_deny
 ldr r0,=0x20001fc0
 ldrb r0,[r0]
 ldr r1,[r4,#8]
 cmp r0,r1
 bne .Lmasked_deny
 ldr r0,=0x20000194
 ldr r0,[r0]
 ldr r1,[r4,#12]
 cmp r0,r1
 bne .Lmasked_deny
commit:
 movs r0,#0
 str r0,[r4]
 ldr r0,[r4,#40]
 adds r0,#1
 str r0,[r4,#40]
 msr primask,r6
 pop {r0-r12,lr}
 /* Replay original displaced ldr/movs; return to its queue store. */
 ldr r3,=0x200025bc
 movs r2,#3
 ldr pc,=0x8f9d
.Lmasked_deny:
 msr primask,r6
.Linvalidate:
 movs r0,#0
 str r0,[r4]
.Ldeny:
 pop {r0-r12,lr}
 ldr pc,=0x9233
.ltorg
