# VVR trigger failures — matched original motor-output requests

2026-10-22. **The transient and held intentional-trigger controls produce
identical captured motor/control writes through14M original instructions.**
They select the same channel0 profile, request the same positive direction,
configure/enable TC0 and perform the same subsequent period updates. Driver
configuration requests also match, but occur before trigger acceptance. The
continuous runs do **not** deliver TC0 interrupts or show trigger-caused STEP
requests. A counter-forcing attempt is rejected as a trustworthy continuation.
This is a bounded output-request comparison, not proof of an equivalent physical
pulse train or movement.

[Reproducible packet](../../research/generated/vvr-motor-output-2026-10-22/README.md),
[chronological records](../../research/generated/vvr-motor-output-2026-10-22/timeline.json),
[comparison](../../research/generated/vvr-motor-output-2026-10-22/comparison.json),
[95 artifact checks](../../research/generated/vvr-motor-output-2026-10-22/checks.json).

## Scope, provenance and matched fixtures

This extends [VVR correlation](vvr-trigger-failure-correlation.md),
[Target3 output routes](motion-initiation-route-coverage.md),
[Target2 digital reachability](trigger-symbolic-reachability-target2.md),
[motor/reference state](motor-state-ownership-and-reference.md),
[bring-up](autopilot-bring-up-pass2.md),
[pin map](../hardware/firmware-pin-function-map.md) and
[driver reconciliation](../replacement/tmc5160-datasheet-reconciliation.md).
The original915 image is SHA-256
`0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`.
It is not hash-linked to Nathan's `Autopilot_firm05-08` archive. R39 alone
does not establish build identity; June/July beta behavior is not inferred from
this package. Primary VVR PDFs and their provenance remain unchanged.

Each main run starts at original reset0xcc24 with the same image, geometry,
PA02-selected digital mode2, blank modeled configuration, startup assumptions,
program and MC4 packet. The existing original Remote-built packet is
`+2,1,1,0,98,1,0,50,1000,500,0,0|`. MC4 is unchanged:
`MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|`.
It yields requested current1600 and microstep input0 after parsing; initial
boot uses400/16. No motor/program/reference/eligibility/output-state seed is
introduced. Packets enter the original RX ring, not actual RF.

| Run | Input assumptions only | Qualified read and first acceptance |
|---|---|---|
| `transient` | Initial PB05 HIGH; LOW before0x9228; HIGH at0x922c | Saved digitalRead0 while current GPIO already HIGH; acceptance12,098,773. Connection-like **hypothetical MCU history**, not Nathan's measured waveform. |
| `intentional` | Same initial HIGH and LOW before0x9228; remain LOW through the run | Saved digitalRead0; same acceptance12,098,773; input remains asserted when initiation occurs. No calibrated500ms pulse is claimed. |
| `unacquired` | HIGH before each0x9228; LOW after read at0x922c | Every observed qualified return is1; no acceptance or channel0 profile start through14M. This phase-locked synthetic history tests non-acquisition, not measured bounce timing. |

All main runs have the corrected `memory-hook-single-step` execution mode,
no native error, no code-watch cap and no dropped captured writes. The extra
log capacity needed by the negative control is observability only. Existing
Target2 actual-instruction SMT provides bounded guard/nonzero-read exclusions;
it is not an interrupt or output-equivalence theorem. No new symbolic query,
formal-model change, hardware action or framework implementation was needed.

## Chronological motor/control trace

Times below are executed instruction ordinals. The injected millisecond counter
advances once per4000 instructions; this is not a calibrated CPU, TC clock or
physical timebase. Both positive runs have the same ordinals and values.

| Stage | Observed original requests | Meaning and limits |
|---|---|---|
| Startup control outputs,7,236,451–7,236,548 | PORT group1 SET requests for PB17,PB16,PB06,PB07, respectively. | Existing control/reset names are provisional. Continuity did not establish these as MCU-controlled TMC DRV_ENN. These precede the trigger. |
| Driver boot initialization,9,501,047 onward | Four original0xae60 current-setter entries receive400; four0xb070 entries receive16. | Actual calls and serialized writes, not measured current or confirmed active driver state. |
| Startup motor probe,10,496,067 onward | Channel0 DIR HIGH; first PB10 STEP SET10,496,218 and CLR10,496,254; final ch0 startup CLR11,322,202. Each known STEP output receives96 HIGH/LOW pairs: PB10,PA08,PB12,PA10. | **These actual CPU write requests also occur in the negative control, before trigger acceptance.** They cannot be used as evidence of trigger-caused motion. No physical edges/current/movement is established. |
| MC4 driver application,11,878,184–12,050,312 and related serial requests | Current-setter inputs1600 and microstep-setter inputs0 for all four driver objects. Last selected GCONF/other register writes finish before acceptance. | Native MC4 processing, not just desired RAM. Driver current/microstep initialization is shared precondition, not a consequence of the trigger. |
| Qualified acquisition,12,098,771 |0x922c compares saved0; current input HIGH only in transient run. | Source history differs; accepted classification does not. |
| Reload/profile,12,098,773 onward |0x8f98→0x6e4c→0x4b64→0x6b50; channel0 state1/profile mode1, idle0, phase arm0. Record0 delta+500, start0, endpoint500. | Software coordinate units, not millimetres or physically established reference. Direct-G target cell is not this profile's endpoint authority;0x6fd8 is not required here. |
| Reload shared controls,12,117,143 /12,117,177 | PB30 SET and PB31 CLR requests. | Preserve as separate shared control requests; these are not the ch0 STEP/DIR pair or a proven TMC enable. |
| Profile direction,12,128,583–12,326,390 | Eleven PB11 OUTSET mask0x800 writes from the direction path0x54b8→0xd388. Input sign+1, channel0. | Requested DIR HIGH for the positive software move; no physical clockwise/connector identity is inferred. No corresponding post-boundary DIR writes in negative control. |
| Rate start,12,327,006 |0x6338 evaluator→0x5f8c;0x5570 initializes TC0. | Original application start logic, not a substituted helper call. |
| Timer initialization,12,327,022–12,327,046 | TC0 CTRLA0x600; WAVE offset0x0c=1; INTENSET offset0x09 receives0 then0x10; COUNT offset0x14=0. | Real CPU stores to modeled registers; peripheral side effects are not implemented by plain memory. |
| First ENABLE-containing store,12,327,091 | PC0x571c in the rate/prescaler path writes TC0 CTRLA0x602. | **Precedes the explicit0x5810 enable helper and first CC0 write.** Do not make0x5810 the unique enable boundary or infer a physical glitch/pulse from this ordering. |
| Initial period,12,327,119 | PC0x5c44 writes16-bit CC0 at0x4000381c=0x5563 (21859).0x5c4e then requests READSYNC. | Encoded period under current prescaler. No measured step frequency in Hz. |
| Explicit enable/live,12,327,145–12,327,152 |0x5810 clears COUNT; PC0x582c writes CTRLA0x602; original live byte becomes1 at0x5fa4. | Requested timer operation, not proof of interrupt delivery. |
| Continuing profile through14M | CC0/period arguments21859→18476→15821→13700→11978…;84 ch0 period calls plus2 auxiliary channel7 startup calls. Encoding later changes with prescaler selection. | Actual acceleration-related rate/period computation and stores. Counts cannot be compared as frequency across prescaler changes without clock/scaling interpretation. |
| End of bounded run | Channel/profile/live1; software position0; TC0 COUNT0, CTRLA0x102, CC0=40805. | Timer never counted autonomously; no TC0 handler0x607c or STEP emitter0x5898 entry. No completed physical trajectory is demonstrated. |

The corresponding0x6338/0x5c00 bodies are original instructions. Static helper
explanations are supported by the prior independent route work and selected
byte-identity checks between868/915. Direct915 queries confirm the shared
prescaler store and vector word0x41ec=`0x607d` (TC0 handler entry0x607c,
IRQ107). A vector entry plus software INTENSET is not evidence of delivery.

## Requested driver configuration and output equivalence

Captured PORT select and SERCOM5.DATA writes frame into **3258 complete logical
five-byte datagrams** in each positive run, with no overlapping selects,
unframed bytes or partial frames. The documentary grouping reuses the existing
case CS-boundary/low-byte method; it is not SPI simulation. All16,290 DATA
write requests and all29,236 captured CPU stores (including original PC,
instruction ordinal, value and previous bytes) are exactly equal between the
two positive runs. These captures cover TC0 registers0x40003800..1f, PORT
group0/1 CLR/SET/TGL windows, SERCOM5.DATA and selected existing RAM fields.
They are not an exhaustive all-register or all-pad observation.

For each of the four select/object paths, the last relevant pre-trigger writes
include:

| Register | Requested payload / field interpretation |
|---|---|
| GLOBALSCALER0x0b |0x00000085 (133). |
| IHOLD_IRUN0x10 |0x000f1714: IHOLD20, IRUN23, hold-delay15. |
| CHOPCONF0x6c |0x18408155: MRES8, INTPOL1, DEDGE0, TOFF5. Under valid external STEP/DIR mode, MRES8 requests full stepping; interpolation is separate. |

The microstep API's input0 is therefore meaningful encoding, not an unset
configuration. Current input1600 is consistent with the previously reconstructed
intended milliamp convention, but neither1600mA delivered nor the board's actual
current-sense resistor/mode/power-stage state is established. Boot400/16 is a
different earlier request. No driver register-write datagram occurs **after
trigger acceptance** through14M; periodic read-request traffic continues. There
is no demonstrated trigger-specific driver-enable/configuration transaction.
Read requests and zero-behavior modeled MMIO do not confirm a driver response.

| Compared boundary | Result |
|---|---|
| Recognition / acceptance | Same savedLOW and guards; only externally supplied current input level differs. |
| Program / profile / reference | Same record bytes, positive software distance500, start0/endpoint500, mode1 and phase0. |
| DIR / shared controls / timer | Same captured output sequence and period arguments; no meaningful output divergence through14M. |
| Driver configuration | Same requests, applied by original code before acceptance; driver electrical application unknown. |
| TC0 servicing / STEP after trigger | Not reached in either continuous run. Equality of absence in this incomplete peripheral model is **not** equality of a real pulse train. |
| Negative control | No acceptance/start, no post-boundary TC0 stores or ch0 DIR, no STEP-emitter entry. Shared startup STEP/configuration requests remain present. |

The baseline per-channel software delta is+1 and STEP divisor16. Prior isolated
Target3 STEP tests seeded divisor1; those samples cannot be relabeled as this
profile's continuous outputs. A natural service must satisfy the real divisor
and position conditions. OUT/PMUX/direction-register or unrelated routes outside
the selected windows are not exhaustively excluded by this comparison.

## Peripheral continuation attempts and stopping boundary

The documented direct CLI provides PC-forced external values and register
read-clear assumptions, but no TC tick→compare→pending→NVIC→exception→resume
schedule. `ConcreteMachine.deliver_interrupt()` exists as a narrow caller-driven
handler call. Its caller must supply pending state and explicitly resume; it
does not model priority/masking, EXC_RETURN or true nested-preemption timing.
Repository search found no existing validated continuous AutoPilot timer runner
exposing the missing schedule. Calling handlers repeatedly would fabricate a
sequence, so it was not done.

Two diagnostic `*-count-observation` runs tried supplying COUNT21858
(`0x5562`, below initial CC021859) at0x5fa6 after enable, using the same paired
trigger histories. This is a disclosed **force**, not observed timer counting.
It does not establish a credible peripheral continuation:

- COUNT is also read by the original profile's motion-feedback path before the
  anticipated period catch-up. The changed observation alters that path: native
  timer-disable and DIR reversal precede a later restart.
- CLI PC forces repeat on **every** hit. These runs enter0x5f8c38 times following
  only one trigger acceptance, and force COUNT again on each0x5fa6. Both paired
  results match, but this is not one elapsed-count event.
- Neither run enters TC0 handler0x607c or STEP emitter0x5898 or produces a
  post-accept STEP SET/CLR request. No clock, wrap/match/reset or NVIC consistency
  was established for those supplied observations.

These artifacts are retained as rejected continuation attempts. The38 starts
are **not** admitted as a Noxon misfire mechanism or a reproduction of Nathan's
repeated moves. No busy/phase/position values, instruction patches or replacement
STEP logic were introduced to force a positive outcome. No fabricated IRQ train
or new peripheral framework was built.

Time-based profile completion is supported separately by the previous868 VVR
continuation, which reaches terminal stage near52.25M and idle2; supplied native
W then reaches idle9 and another initiation under held active input. That run
has zero software-position progression/zero-distance return. It is neither a
completed STEP trajectory nor a matched915 transient/intentional completion
comparison. No new completion/re-arm equivalence is asserted here.

The existing VVR-003-like915 analog517→600 X1-positive/X2-negative witnesses
remain useful secondary acceptance/initiation controls. They were not recast as
observed STEP/DIR comparisons; no new analog campaign was needed to locate the
same peripheral boundary.

## Findings to share and next work

For Nathan: a modeled connection transient already accepted by this packaged
original firmware is treated like the held intentional trigger in the observed
motor-request path. Release before initiation does not withdraw the profile.
The same positive direction, timer configuration and rate updates are requested
without a fresh trigger at start. Driver setup is already requested beforehand.
This strengthens the software-authorization explanation of VVR-005, while the
physical insertion waveform and exact tested-build identity remain missing.
Do not claim the simulation reproduced the reported motor displacement or
proved identical driver electrical outputs.

**Capability gap — high for the requested end-to-end result:** a supported,
validated continuation must couple TC counting/prescaler/CC updates, compare
flags, IRQ enable/masking/vector delivery, original handler execution/resume and
software position with a consistent clock. Delivery must account for the first
ENABLE-containing store0x571c and subsequent CC0 write, rather than beginning
only after0x5fa6. Plain COUNT seeding and isolated
handler calls are insufficient. Existing code can observe the needed registers
and execute the handler, but the public validated scenario is absent. A narrowly
scoped APTrace development task could supply it; the operator did not implement
one. Symbolic reachability of a helper would not repair peripheral validity.

**New evidence needed:** hash-link Nathan's release; capture the insertion at
PB05 with mode/arming state and first STEP/DIR indication on the same program.
An intentional-trigger comparison on that wiring would distinguish whether
both failures reach the same physical output sequence. Driver-powered mode,
current application and actual displacement still need their independent
electrical evidence. No broad hardware survey or equipment list is required.

Nine direct native executions were made: three initial code-watch-cap results,
three main runs, two rejected counter runs, and one negative-control rerun to
remove write-log truncation. All process exits0/native error=null. Four capped
diagnostic snapshots and reproducible command recipes are preserved; claims use
the uncapped main captures.95/95 saved-artifact checks pass. No original binary,
apfw2, formal model, tool implementation, physical hardware, evidence ledger or
release grade changed.
