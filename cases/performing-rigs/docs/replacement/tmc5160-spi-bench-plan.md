# Bounded TMC5160 SPI verification plan

Status: **blocked for powered testing until TMC-G0–G3 prerequisites are resolved and the responsible hardware engineer approves a non-energizing test setup**. This plan authorizes no physical test by itself. No voltage, clock, current or expected TMC register value is invented. Firmware-observed settings are not electrical acceptance limits.

## Existing measurements to retain

- Raw `AutoPilot_Continuity_Bench_Sheet.md` §6 upper table already reports four CSN package connections (TMC1→11, TMC2→37, TMC3→12, TMC4→38) and shared SCK64/SDI63/SDO62. Do not repeat the full continuity matrix merely because summary documents call its lower template blank.
- TMC1 SD_MODE21/SPI_MODE22→VCC I/O20 at0Ω, CFG4/5/6→GNDANA at0Ω, and DRV_ENN28→GNDANA are already reported in §§5/7/8. Other-device straps are not established by those TMC1 rows.
- Mux A→TMC and RJ45 resistance routes, and high-resistance tests of candidate S,/OE control pairs, already exist. Those mux paths are not evidence of components on SPI nets.
- Original firmware executes serial write/read requests. No repeat firmware discovery is needed as a prerequisite to electrical readback.

Before probing, reconcile board revision, device/connector label orientation and actual endpoints against the original annotated record if available. Record source ambiguities instead of treating every unpaired0Ω entry as a complete route. A targeted ambiguity check is appropriate; repeating settled measurements is not.

## Prerequisites — no board power yet

| Step / gap | Observable and action | Prerequisites/equipment | Acceptance / decision |
|---|---|---|---|
| P0 / G0 | Read authoritative local ATSAMD51J19A package/pinmux tables and associate measured package terminals with GPIOs | Correct package/revision documentation; existing bench sheet and legacy pin-table evidence | Every serial/select signal has a documented assignment and coherent SERCOM routing. Missing reference leaves actual pin drive blocked |
| P1 / G1 | Obtain correct TMC5160A-TA mode, supply and SPI/register chapters; decide what constitutes a valid read | Local primary documentation for the actual device | Record mode truth table, permitted power-domain conditions, framing/read pipeline, timing and electrical limits, and one readable register oracle. Exact address/content remains **unspecified until that document is available** |
| P2 / G2 | Hardware engineer defines a non-energizing logic-only configuration, including grounded DRV_ENN and all four channels | Circuit inspection, board/supply documentation, engineer review; suitable isolated/protected supplies and instruments selected by the engineer | No motor energization/current path or prohibited back-power condition, with shared-bus devices in defined states. Absence of STEP pulses is insufficient. If domains cannot be safely separated/contained, no logic-only test proceeds |

Keep power removed/discharged for any resistance/continuity work, as the original bench sheet specifies. This is not permission to assume removal of motor supply while powering logic is valid: that requires P1/P2 evidence.

## Minimum approved logic-only checks

| Step / gate | Missing observable / proposed measurement | Equipment/prerequisites | Acceptance criterion | Decision unlocked |
|---|---|---|---|---|
| P3 / before SPI | Rail-relative SD_MODE/SPI_MODE, CS idle and DRV_ENN states through logic power/reset | P0–P2; high-impedance measurement at identified device terminals and reset capture | Levels and sampling conditions satisfy the cited device requirements; no uncontrolled channel/output state. No numeric threshold can be specified from current local evidence | Actual mode eligibility for TMC1 and valid idle state |
| P4 / before SPI | Shared SCK/SDI/SDO line suitability and CS independence | P0–P3; inspect documented intervening circuitry, oscilloscope/logic analyzer with suitable probes; no motor power under approved setup | MCU can hold every CS inactive and select only TMC1; other CS lines remain inactive. No contention, prohibited loading/back-power or coupled selects. Receiver input/edge levels meet device limits | Permission for one-device communication |
| P5 / first SPI transaction | One data-sheet-defined read-only register exchange, with separate select transactions/read pipeline if required | P1 supplies exact request, address, clock, mode, frame boundaries and response oracle; P2–P4 pass | Capture clock, CS, MOSI and MISO at the device. Repeated response matches documented invariant/mask or approved oracle and reacts correctly to actual selection. All-zero/all-one/echo alone is **not** success | Demonstrated functional communication; no configuration write needed |
| P6 / isolation control | Repeat deselected control and inspect nonselected drivers' responses/CS states | Same approved logic-only setup; device documentation on output release | Only the selected driver drives the shared response as documented; no other driver is unintentionally selected. Do not infer isolation simply from four different MCU constants | Single-device use of shared bus |

The minimum register-level check is intentionally unresolved at its numeric fields. No local TMC5160A reference was found to authorize a particular identity/status register, expected value, frame timing or safe side effects. Do not substitute the legacy observed selector0x6f or literal bytes as the acceptance oracle. They are firmware observations whose register semantics still require the reference.

## Before motor energization

P7 / G5–G8: identify the sense-resistor/current path and actual selected-driver/connector mapping; derive first-test configuration/current limits from verified circuit and device/motor ratings. Read back only documented configuration/status values after establishing the actual reset/strap/write history. Establish chopper, current and microstep settings and a measured non-energizing state before enabling any bridge. Original firmware's temporary software argument400, microstep argument16 and raw register words are **not approved settings**.

Capture reset/startup/STOP/communication-fault behavior at the driver inputs and relevant power/current points; confirm other channels remain contained. Firmware GPIO “disable” labels do not satisfy this. A TMC1 ground strap on DRV_ENN requires particular review because software may lack direct control of that input. Use hardware-engineering-defined numeric limits and stop thresholds, not values inferred from a zero-behavior emulator.

## Stop conditions and deferred scope

Stop on unknown package orientation, supply-domain assumptions, ambiguous current path, unexplained CS coupling, missing MISO release, invalid power/logic levels, unexpected current/heating, movement or other-channel activity. Stop if readback only reproduces the transmitted data or a constant without the documented oracle. Stop if device documentation is missing for the proposed operation. Preserve the observation and return to the relevant gate rather than increasing voltage, clock or permissions by trial.

Defer full four-driver functional characterization, every diagnostic register, DIAG pin integration, exact legacy ramp reproduction and external-RJ45 functional testing until basic safe configuration is established. Nonselected-channel containment is **not deferrable** when those channels share the tested bus/power/control arrangement.

All results should record board revision, labeled driver/test points, actual instrument/setup, applicable data-sheet sections, waveforms/data, limits, uncertainty and decision unlocked. The minimum sequence is reference/engineering prerequisites → powered straps and idle → select/line isolation → one documented read → current/configuration/reset containment → first motor test. No additional full continuity survey or broad firmware census is requested.
