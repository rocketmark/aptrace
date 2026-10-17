# Replacement firmware bench verification

Readiness: software preparation can proceed; motor energization remains blocked by the items below. No electrical measurements were made in this investigation. No proposed GPIO level or current setting is approved by the firmware evidence alone.

## Existing evidence — do not repeat without a board-identity discrepancy

| Item | Classification | Evidence and limit |
|---|---|---|
| ATSAMD51J19A, four repeated motor stages, XLR-4 connectors | Already established by sufficient physical evidence for identity/layout | hardware-reference.md and board photos; no copper routing established |
| One legibly marked TMC5160A-TA and CSD88537ND | Already established by sufficient physical evidence for those component identities | REV 1 ...0101/0103 and documented marking matches; not legible identity on every channel |
| Two SN74CBTLV3257 muxes and A-side TMC routes | Already established by physical continuity record | New raw AutoPilot_Continuity_Bench_Sheet.md §3: distinct 0 Ω patterns, Mux1→TMC1/TMC3; Mux2→TMC2/TMC4. Do not repeat this full matrix without a board discrepancy |
| RJ45-side resistance paths | Already recorded physical evidence, limited network interpretation | Raw §4: Mux1→RJ45 #2/#4, Mux2→#1/#3, both B legs through diode/resistor networks; not powered source-selection behavior |
| Candidate mux control continuity | Already tested; direct connection not confirmed for measured pairs | Raw §2: S-to-PB16/PB17 about334.5kΩ; /OE-to-PB06/PB07 about324.9–325.6kΩ. Do not repeat the same candidate matrix as if untested |
| TMC1 mode/CFG/DRV_ENN straps | Already recorded physical evidence for TMC1 | Raw §5: SD_MODE/SPI_MODE→VCC I/O 0Ω; §7 CFG4/5/6→GNDANA 0Ω; §8 DRV_ENN→GNDANA (no resistance column). No powered safety or all-driver extrapolation |
| Reported serial/config-pin connections | Already recorded, narrative reconciliation required | Raw §6 upper table: CSN→MCU11/37/12/38 for TMC1–4, shared SCK→64, SDI→63, SDO→62. Summary incorrectly calls this table blank; reconcile rather than assuming no bus |
| PB10/PB11 MCU identity | Established firmware/package evidence, **not physical continuity** | pin-function map; MCU package pins 23/24; original package attribution is an indirect datasheet transcription |
| Actual control destinations/polarity, effective current, MCU STEP/DIR and XLR routing, reset states | Still missing physical evidence | Existing mux/TMC/RJ45/strap measurements do not close these particular relationships |

REV 1 contains mixed Remote and AutoPilot photos. Confirm the physical board revision/silkscreen (AutoPilot 52_PO_V01R04 in the documented photos) before transferring any result. Do not assume a folder name identifies the board.

## P0 — required before the first powered motor test

Perform passive routing/strap inspection with power removed first. Any powered verification needs a deliberately isolated, constrained bench setup defined by the responsible hardware engineer. This checklist specifies evidence to obtain, not unsubstantiated electrical limits.

| ID | Measurement / observable | Acceptance criterion | Decision unlocked |
|---|---|---|---|
| BENCH-01 | Trace the **missing MCU PB10/PB11 leg** to the already mapped mux/TMC network; then driver bridge → XLR | Reuse the recorded A→TMC matrix. Document intervening components and actual source-select truth table. Distinguish STEP/DIR; do not assume the MCU necessarily enters B1/B2 | Physical channel-0 connector assignment and internal source selection |
| BENCH-02 | PB06/PB07/PB16/PB17 actual destinations, any buffers, external pulls and polarities | Start from the recorded high-resistance candidate results, trace actual nets/intervening components. Do not repeat the old direct S,/OE hypothesis. Explain the four firmware control signals and powered truth table before assigning safety roles | Verified control/routing states; firmware startup, disable and enable levels |
| BENCH-03 | Remaining mux control/source behavior and shared-channel containment | Reuse two-device and RJ45 route measurements. Resolve B1/B2 source behavior and diode/resistor network effects under the engineer-approved powered setup; exclude unintended energization of other motors | Isolation of one channel and external-input interaction |
| BENCH-04 | Reconcile recorded TMC1 mode/CFG straps and populated serial-routing table with an authoritative **local** device mode truth table | Do not remeasure known TMC1 straps by default. Preserve raw HIGH/HIGH and LOW CFG readings without accepting the unsupported “no SPI” summary. Resolve actual mode/configuration expectations and missing current/microstep programming; verify other-driver differences only as needed | Decide whether replacement needs driver transactions and which initial state must be supplied |
| BENCH-05 | Current-sense resistors, bridge configuration, effective current limit and any programmable current state | Derive a documented effective limit from actual circuit/device settings and applicable local device evidence. Responsible engineering sets a first-test limit within motor/driver/power-stage ratings and demonstrates it. **No numeric limit can be supplied by current APTrace evidence** | Motor/power-stage compatibility and permissible energization/current settings |
| BENCH-06 | Actual DRV_ENN route/level, STEP, DIR and mux controls through power-up, reset assertion/release, bootloader interval and replacement startup | Show a defined, measured non-energizing condition until explicit authorization, and no unintended motor-input steps or other-channel enable. Where disconnecting a mux leaves a floating input, resolve pulls/latch state before accepting it | Reset/startup containment and safe electrical default; cannot be inferred from application HIGH writes |
| BENCH-07 | Physical motor connector winding mapping, cable identity and unused channel containment | Board/cable mapping agrees with the existing documented XLR pinout for the actual hardware; windings identified and other channels shown not to energize under the selected shared-control state | Attach one known-compatible motor to the verified channel |

BENCH-04/05 cannot be skipped because no SPI transaction was observed; serial routing is actually reported in raw §6. TMC1 grounded DRV_ENN is a strap observation, not assurance of a de-energized bridge. BENCH-06 may require a separate logic-only observation before motor power; inability to observe safely leaves first-motor testing blocked.

## P1 — required before broader functional testing

| ID | Observable | Acceptance criterion / unlocked decision |
|---|---|---|
| BENCH-08 | STEP high/low widths, DIR setup/hold at **driver inputs**, frequency, first/last pulse, STOP and reset during a bounded move | Compare with actual device requirements from available local datasheet evidence and explicit engineering timing requirements. Values are currently unknown; Unicorn instruction count is not an acceptance threshold. Establish latency/jitter bounds before relying on them |
| BENCH-09 | Direction polarity and physical rotation, one small bounded movement after P0 passes | Record HIGH/LOW→observed direction and actual step/microstep conversion; no inherited motor-1/channel-0 assumption |
| BENCH-10 | Driver diagnostics/fault route, thermal/current protection indication and recovery behavior | Determine whether firmware can observe faults; document a bounded stop/recovery policy and verify its electrical effect. No legacy fault-handling guarantee exists |
| BENCH-11 | Other motor channels during repeated enable/disable, USB STOP/disconnect, watchdog/reset and source selection | No unintended input steps or energization under the engineer-approved test conditions; confirm shared control behavior before adding motors |

## Later milestone / access limits

Full external RJ45 passthrough functionality, detailed legacy acceleration matching, TCC1/PB22 purpose, status LED identity and all-channel calibration are deferrable beyond the single-motor POC, **provided P0 routing shows they cannot interfere with it**. Two muxes are already established; no repeat device-count measurement is requested.

Remaining unperformed measurements are presently unresolved because this session has no physical board/probe access. That does not reclassify P0 items as optional. The source bench sheet is attributed to “Pin Testing” screenshots dated2026-09-21, while reconciliation is dated2026-10-17; actual measurement date/instrument settings are not independently established. Record future results with board revision, named points, instrument/setup, source datasheet or engineering requirement, observed data, uncertainty and implementation decision.

## Stop conditions

Stop before energization if any control net, current limit, package orientation, winding mapping or unused-channel state remains ambiguous; if the selected source is not verified; or if a reset/startup interval has an uncontrolled driver input. During an approved powered test, stop on unexpected current/heating, movement, pulses, fault indication or other-channel activity. Numeric stop thresholds must come from actual device/motor ratings, measurements and the approved bench design; none are invented here.

The firmware-observed all-HIGH startup state and legacy “disable” functions are comparison observations only. They do not waive any acceptance criterion above.
