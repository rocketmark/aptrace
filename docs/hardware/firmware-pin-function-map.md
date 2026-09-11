# Hardware Pin ↔ Firmware Function Map (AutoPilot)

**Purpose**: chain UI/protocol action → firmware handler/state → MCU
peripheral/GPIO → MCU package pin → PCB observation → physical
connector/function, keeping a **separate confidence grade at each
layer**. This is a hardware-reconciliation pass, not new firmware
reverse engineering — every firmware-layer fact below already existed
in this project; what's new is the package-pin numbers, the PCB photo
inspection, and the explicit per-layer grading.

**Machine-readable companion (authoritative)**:
[`research/generated/firmware-pin-function-map.json`](../../research/generated/firmware-pin-function-map.json),
25 signals.

## Package and orientation

**Part**: ATSAMD51J19A-AU, TQFP-64 (10×10mm). Package-pin numbers were
cross-checked against the KiCad `MCU_Microchip_SAMD` symbol for
ATSAMD51J18/19/20A-A (TQFP-64), itself sourced from Microchip datasheet
DS60001507E — the full PDF exceeded this session's fetch size limit, so
the primary datasheet pinout table page was not independently
re-rendered; the KiCad symbol is treated as a faithful, attributed
transcription of it. Every firmware-side pin **index** (which entry of
the flash `g_APinDescription`-style table) was independently re-read
this session via `tools/ghidra/aptrace_ghidra.py dump` against
`firmware_autopilot868.bin` and cross-checked against every prior value
already on record — **all matched exactly, no discrepancy found**.

**MCU orientation in photos**: **not determined**. The Atmel-marked
ATSAMD51 package is visible in `IMG_3096.JPG`, but only two of its four
edges are in frame and no pin-1 corner marker was resolved at the
available resolution/angle. No claim in this document depends on which
package edge faces which board direction — only which general **board
region** (logic/control side vs. motor-driver side) a component sits
in relative to the MCU as a whole.

## Discrepancy flags

- **The `REV 1` photo subfolder does not show the AutoPilot.** It shows
  the **Remote/Mando** board (silkscreen `24_PO_V05R01`): Ai-Thinker
  Ra-01H radio module, rotary encoder with integrated push switch, LiPo
  pouch cell, buzzer — an exact match to `hardware-reference.md`'s
  *Remote* facts, not the AutoPilot's. The `REV 2` subfolder (silkscreen
  `52_PO_V01R04`) is the real AutoPilot board: visible `Atmel
  ATSAMD51J19A` marking, dual RJ45 jacks, a 3.5mm TRS jack, 4 XLR-4
  panel connectors, 4 repeated motor-driver channels. **Only `REV 2`
  photos were used as AutoPilot evidence in this pass**; this is
  reported rather than silently corrected in the folder.
- No discrepancy was found between the documented AutoPilot chip
  identity and the REV 2 photos — reported to make the validation check
  explicit.

## Compact map

| Signal | GPIO | Pkg pin | Firmware | Package | PCB | Physical |
|---|---|---:|---|---|---|---|
| STEP ch0 | PB10 | 23 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| STEP ch1 | PA08 | 17 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| STEP ch2 | PB12 | 25 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| STEP ch3 | PA10 | 19 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| DIR ch0 | PB11 | 24 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| DIR ch1 | PA09 | 18 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| DIR ch2 | PB13 | 26 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| DIR ch3 | PA11 | 20 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| Driver enable A | PB17 | 40 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| Driver enable B | PB16 | 39 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| Driver reset strobe A | PB06 | 9 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | UNKNOWN |
| Driver reset strobe B | PB07 | 10 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | UNKNOWN |
| Trigger digital/analog | PB05 | 6 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| Trigger boot arm-select | PA02 | 3 | PROVEN | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| Startup reference/input | PA22 | 43 | PROVEN | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| Completion/startup latch | PA23 | 44 | PROVEN | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| **Shared reload pulse A** | **PB30** | **59** | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | **UNKNOWN** |
| **Shared reload pulse B** | **PB31** | **60** | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | **UNKNOWN** |
| TCC1 aux pulse (unassigned 5th channel) | PB22 | 49 | PROVEN | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| Radio SPI CS | PA15 | 32 | PROVEN | PROVEN | TRACE_UNKNOWN | PROBABLE |
| Radio candidate (reset/DIO0?) A | PA16 | 35 | PROBABLE | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| Radio candidate (reset/DIO0?) B | PA17 | 36 | PROBABLE | PROVEN | TRACE_UNKNOWN | UNKNOWN |
| USB D- | PA24 | 45 | PROBABLE | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| USB D+ | PA25 | 46 | PROBABLE | PROVEN | NEIGHBORHOOD_ONLY | PROBABLE |
| External RJ45 STEP/DIR in | *unknown* | *unknown* | **UNKNOWN** | UNKNOWN | NEIGHBORHOOD_ONLY | UNKNOWN |

Full per-signal detail (firmware function/trigger, exact evidence refs,
PCB observations, remaining unknowns) is in the JSON companion — not
duplicated here.

## Priority question 1 — PB30/PB31

**Firmware** (already established, re-verified this pass): both pins
are driven by the one shared function `FUN_00006952`, reached from
*both* a real G/move-commit and an accepted Trigger's config-reload —
`PB30=HIGH, PB31=LOW`, **unconditionally**, identical every time
regardless of run-vs-idle state. This alone rules them out as a
state-dependent status signal by themselves.

**PCB**: the highest-value finding of this pass. `IMG_3096.JPG` shows a
pair of small SMD LEDs mounted immediately adjacent to each other, in
the board's **logic/control region** (between the main MCU and the
U3/U14 power-management ICs) — **not** in the motor-driver region on
the opposite side of the board. One is amber/yellow-tinted (consistent
with an unlit white-phosphor LED); the other is blue-tinted. This is
**suggestive** of the manual's documented single status LED
(WHITE=Standby / BLUE=Running) being implemented as two adjacent
single-color parts rather than one bi-color package — but **no copper
trace from package pin 59/60 to either LED footprint was followed or
resolved** at the available photo resolution.

**Result: UNRESOLVED, region-correlated only.** Per this pass's own
instruction, **no WHITE/BLUE color identity is assigned to PB30/PB31**.
The four candidate outcomes named in the task (status LED circuitry /
another on-board IC / external connector / unresolved multilayer
route) all remain open; the LED-pair observation is reported as a
plausible lead for a future, higher-resolution or continuity-tested
pass, not as a finding.

## Priority question 2 — PA22/PA23

Firmware semantics preserved exactly as documented: **PA22** gates the
startup reference/input routine and is later polled as a held-input
check (`loop_housekeeping_save_trigger__CUSTOM`); **PA23** is driven
LOW during that startup sequence and HIGH on its completion (and on
later, unrelated completion/halt events) — a one-shot latch, not a
repeating toggle (already established in a prior session; explicitly
**not** the status LED). Package pins re-verified this session: PA22 =
pin 43, PA23 = pin 44.

**No PCB component was confidently attributed to either pin.** A front
power button is a documented AutoPilot board-level fact and is a
plausible candidate for PA22's "held input" role, but this is a
plausibility note, not a traced or silkscreen-confirmed finding. Per
this pass's explicit scope, PA22's physical identity is **not**
resolved further.

## Motor result (STEP/DIR)

All 8 STEP+DIR package pins re-verified exactly against prior records
via fresh flash dumps this session (no discrepancy). PCB photos confirm
a motor-driver board region (4 repeated small-QFP/TI-H-bridge-marked
driver stages, large electrolytic capacitors, 4 XLR-4 panel connectors
— the REV 2 "left" board in `IMG_3098.JPG` shows the XLR jacks
mounted through the panel directly) on the side of the board opposite
the MCU/logic region. **No individual copper trace was followed from
any specific package pin to any specific XLR jack**, and — per explicit
instruction — **no logical-channel-to-physical-Motor-1..4 identity and
no DIR-polarity-to-physical-rotation identity is claimed.**

## Trigger result

**PB05** (digital read + ADC1 analog alias) and **PA02** (boot-time
arm-select) re-verified at pins 6 and 3. A 3.5mm TRS jack is visually
confirmed in the board's logic region (`IMG_3093.JPG`, `IMG_3101.JPG`),
near the MCU. This is a **region-level, not copper-traced**, match —
graded `PHYSICAL_FUNCTION_PROBABLE` for PB05 and left `UNKNOWN` for
PA02 (whose electrical relationship to the jack, vs. a separate
board strap, was not established). A plausible route toward the RJ45
external STEP/DIR interfaces is noted (2 RJ45 jacks visually confirmed
in the same region) but **not forced into a signal mapping** — no
firmware GPIO for that external-input path exists in current evidence
(already-documented gap, re-confirmed here, not re-investigated).

## Newly strengthened mappings

- All 18 previously-documented STEP/DIR/enable/disable/trigger/PA22/
  PA23/PB30/PB31 pin-table indices were **independently re-derived
  this session** via fresh flash dumps (not merely re-cited) and found
  to match every prior record exactly — a genuine, if unglamorous,
  strengthening (this project's own established replay-before-trust
  discipline).
- The analog and digital trigger aliases (`0x39`/`0x3b`) were confirmed
  this session to decode to the *same* physical pin (PB05), closing a
  small residual "are these really the same pin" gap.
- **PB30/PB31 → plausible LED-pair region** is new context this pass
  contributes (not previously photo-correlated anywhere in this
  project) — a lead, not a finding.

## Ruled-out mappings

- PB30/PB31 as a *repeating* WHITE/BLUE indicator: ruled out at the
  firmware layer (unconditional/state-independent pulse) in a prior
  session, reconfirmed structurally this pass.
- PA23 as the status LED: ruled out at the firmware layer (one-shot
  latch, not a toggle) in a prior session; not re-opened here.
- REV 1 photos as AutoPilot evidence: ruled out this pass (they are
  Remote-board photos).

## Unresolved high-value pins

PB30/PB31's real physical destination; PA22's physical component;
PB06/PB07's "reset strobe" characterization; the TCC1/PB22 5th-channel
pulse's purpose; the external RJ45 STEP/DIR input's entire firmware-side
mechanism; DIR polarity-to-rotation on all 4 channels; logical-channel
to physical-Motor-1..4 identity.

## Does this give concrete hardware sinks for a later bounded causal/SMT query?

**Yes, for the STEP/DIR/enable/disable/trigger/radio-CS signals** — all
have PROVEN firmware mechanism and PROVEN package pin, sufficient to
seed a bounded concrete (Unicorn) or symbolic query against a named
GPIO with known semantics.

**Not yet for PB30/PB31 or PA22/PA23** — the firmware side is proven,
but the *physical* sink each would need to correspond to (an LED, a
button, an external device) remains PCB-unresolved. A future pass would
need either higher-resolution/multi-angle photos with a resolved
component-to-pad continuity check, or a physical continuity/multimeter
measurement on real hardware, before a causal/SMT query against a named
physical outcome (e.g. "does the white LED turn on") would have a real
target to check against. The GPIO-level query ("does PB30 go HIGH") is
already answerable today; the physical-consequence query is not.

## See also

- [`docs/hardware/hardware-reference.md`](hardware-reference.md)
- [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md)
- [`docs/investigations/trigger-input.md`](../investigations/trigger-input.md)
- [`docs/replacement/autopilot-gap-audit.md`](../replacement/autopilot-gap-audit.md)
- [`research/generated/autopilot-replacement-gaps.json`](../../research/generated/autopilot-replacement-gaps.json)
