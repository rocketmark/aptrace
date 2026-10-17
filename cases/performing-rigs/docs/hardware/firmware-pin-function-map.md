# Hardware Pin ↔ Firmware Function Map (AutoPilot)

**Purpose**: chain UI/protocol action → firmware handler/state → MCU
peripheral/GPIO → MCU package pin → PCB observation → physical
connector/function, keeping a **separate confidence grade at each
layer**. This is a hardware-reconciliation pass, not new firmware
reverse engineering — every firmware-layer fact below already existed
in this project; what's new is the package-pin numbers, the PCB photo
inspection, and the explicit per-layer grading.

**Machine-readable companion (authoritative)**:
[`cases/performing-rigs/research/generated/firmware-pin-function-map.json`](../../research/generated/firmware-pin-function-map.json),
27 signals.

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

- **The `REV 1` photo subfolder is mixed, not exclusively Remote-board
  photos as this pass originally recorded.** The original file set
  (`...0042`-`...0074`) shows the **Remote/Mando** board (silkscreen
  `24_PO_V05R01`): Ai-Thinker Ra-01H radio module, rotary encoder with
  integrated push switch, LiPo pouch cell, buzzer — an exact match to
  `hardware-reference.md`'s *Remote* facts, not the AutoPilot's. A
  later-added file set in the SAME folder (`...0095` onward) shows the
  real **AutoPilot** board (silkscreen `52_PO_V01R04`, matching `REV 2`)
  — including the first legible, in-repo photo confirmation of a
  `TMC5160A-TA` motor-driver IC (`...0101.jpg`/`...0103.jpg`; see
  `hardware-reference.md`'s "Motor driver IC identity"). Check each
  file's own board identity; do not trust the folder name alone.
  `REV 2` (silkscreen `52_PO_V01R04`) remains the real AutoPilot board:
  visible `Atmel ATSAMD51J19A` marking, dual RJ45 jacks, a 3.5mm TRS
  jack, 4 XLR-4 panel connectors, 4 repeated motor-driver channels.
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
| Driver enable A *(name provisional — see "Firmware semantics" + "Continuity bench pass" below)* | PB17 | 40 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | TESTED — DIRECT CONNECTION NOT CONFIRMED¹ |
| Driver enable B *(name provisional — see "Firmware semantics" + "Continuity bench pass" below)* | PB16 | 39 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | TESTED — DIRECT CONNECTION NOT CONFIRMED¹ |
| Driver reset strobe A *(name provisional — see "Firmware semantics" + "Continuity bench pass" below)* | PB06 | 9 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | TESTED — DIRECT CONNECTION NOT CONFIRMED¹ |
| Driver reset strobe B *(name provisional — see "Firmware semantics" + "Continuity bench pass" below)* | PB07 | 10 | PROVEN | PROVEN | NEIGHBORHOOD_ONLY | TESTED — DIRECT CONNECTION NOT CONFIRMED¹ |
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
| Motor driver IC (chip identity: TMC5160A-TA) | n/a (not a GPIO) | n/a | n/a | n/a | **PROVEN — PCB PHOTO** | PROBABLE (1 of 4 channels) |
| Motor driver power stage (CSD88537ND, TI) | n/a (not a GPIO) | n/a | n/a | n/a | **PROVEN — PCB PHOTO + MARKING MATCH** | PROBABLE (power stage, not motor-control) |
| Motor bus mux candidate (SN74CBTLV3257, TI) | n/a (not traced) | n/a | n/a | n/a | **PROVEN — PCB PHOTO + MARKING MATCH** (identity only) | UNKNOWN (bus role not established) |
| Motor driver SPI/UART (SCK/SDI/SDO/CSN) | *unknown* | *unknown* | **UNKNOWN** | UNKNOWN | TRACE_UNKNOWN | UNKNOWN |

Full per-signal detail (firmware function/trigger, exact evidence refs,
PCB observations, remaining unknowns) is in the JSON companion — not
duplicated here.

¹ **New grade, introduced this pass**: `TESTED — DIRECT CONNECTION NOT
CONFIRMED`. Distinct from `UNCONFIRMED` (not yet tested) and from a
refutation (proven absent) — a real continuity measurement was taken
between these exact pins and came back inconsistent with a direct,
unbuffered trace, but does not rule out an indirect path (e.g. a
buffer/driver IC in between, or the wrong candidate GPIOs). See
"Continuity bench pass (2026-10-17)" under "Motor bus architecture —
mux hypothesis" below for the raw readings.

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
a motor-driver board region (4 repeated small-QFP/TI-CSD88537ND-marked
driver stages, large electrolytic capacitors, 4 XLR-4 panel connectors
— the REV 2 "left" board in `IMG_3098.JPG` shows the XLR jacks
mounted through the panel directly) on the side of the board opposite
the MCU/logic region. **No individual copper trace was followed from
any specific package pin to any specific XLR jack**, and — per explicit
instruction — **no logical-channel-to-physical-Motor-1..4 identity and
no DIR-polarity-to-physical-rotation identity is claimed.**

**Update (2026-10-17 continuity pass)**: a physical continuity check
(see "Continuity bench pass (2026-10-17)" under "Motor bus architecture
— mux hypothesis" below) traced each TMC5160 (1-4, as labeled on the
bench sheet) to its mux channel and to a specific RJ45 jack —
`PROVEN`. This is a **RJ45-jack identity**, not an **XLR-jack**
identity: the TMC5160 ↔ XLR-output-connector mapping, and the firmware
logical-channel (STEP0-3/DIR0-3) ↔ TMC1-4 mapping, remain exactly as
unestablished as stated above.

**Motor driver IC identity: `PROVEN — PCB PHOTO`.**
`cases/performing-rigs/research/AutoPilot Board Photos/REV 1/20260530_PerformingRigs_DatabaseImages_AutoPilot0101.jpg`
contains a clearly legible Trinamic-marked device — `TMC5160A-TA` /
`2512 A19TA` / `GERMANY` — direct PCB-photo confirmation that at least
one TMC5160A-TA is physically populated on the AutoPilot board.
`...0103.jpg` independently reconfirms the same device from a wider
view. **Not claimed**: which of the four motor channels this specific
chip belongs to (no legible reference designator or trace was in
frame), and that all four devices carry independently legible markings
— only one has been individually read; the other three are assumed
identical by board repetition, not confirmed. `...0106.jpg` additionally
shows a `CR9MICRO CRSS037N10N` power MOSFET near the connector/
power-stage area — recorded only as supporting power-stage evidence,
not as the motor-driver IC itself.

**Adjacent SOIC-8 parts identified: `PROVEN — PCB PHOTO + MANUFACTURER
MARKING MATCH`.** The small SOIC-8 parts previously recorded only as
"TI `8853x`-marked" are Texas Instruments **CSD88537ND** (dual 60 V
N-channel NexFET power MOSFET, SOIC-8) — marking `88537N` (TI's own
documented package/device marking for this exact part), with `26Z` and
`N9x4G4` recorded only as secondary package/lot/trace markings, not
independently decoded. **Architectural implication**: consistent with
the external N-channel MOSFET power stage the TMC5160A requires — a
power-stage component, not a second motor-control IC. Exact count of
CSD88537ND packages per channel and the complete bridge topology are
**not** inferred from a single photo.

**Adjacent 16-pin SSOP mux/demux identified: `PROVEN — PCB PHOTO +
MANUFACTURER MARKING MATCH`.** A 16-pin SSOP part in the same cluster
(`...0103.jpg`), marked `CL257` / `27M` / `AFRN64`, is Texas Instruments
**`SN74CBTLV3257`** — a low-voltage 4-bit 1-of-2 FET multiplexer/
demultiplexer, DBQ/SSOP-16 package (`CL257` is TI's documented top-side
marking, `SCDS040N`; `27M`/`AFRN64` are secondary lot/trace codes, not
independently decoded). TI's datasheet names "Motor drives" as an
application for this part. Pinout: `S`(1) select, `1B1/1B2/1A`,
`2B1/2B2/2A`, `3A/3B2/3B1`, `4A/4B2/4B1` (four independent 2:1 switch
channels), `GND`(8), `OE‾`(15), `VCC`(16) — all four channels share one
select (`S`) and one active-low enable (`OE‾`).

**Architectural implication (candidate, not proven)**: a shared-select
4-channel 2:1 mux is the kind of part used to time-share one physical
bus across two destinations with a single control bit — a plausible
mechanism for the still-open "is a config bus shared across all four
TMC5160s" question (see "Unresolved high-value pins" below). **Not
established**: no board signal has been traced to this chip's
`A`/`B1`/`B2`/`S`/`OE‾` pins. This is a candidate mechanism only, pending
a PCB continuity check.

**Update (2026-10-17 continuity pass)**: the PCB continuity check this
paragraph called for has now been run — see "Continuity bench pass
(2026-10-17)" below. It establishes the mux ↔ TMC5160 ↔ RJ45 chain as
`PROVEN` (not "a shared config bus," but STEP/DIR routing, matching the
architecture hypothesis below rather than the config-bus speculation in
this paragraph) and the TMC5160 mode-select/CFG-strap pins as `PROVEN`
standalone-consistent. It does **not** establish SCK/SDI/SDO/CSN
routing, logical-channel↔physical-XLR identity, or DIR-polarity↔
physical-rotation identity — those remain exactly as stated below.

No examined photo establishes SCK/SDI/SDO/CSN routing to the ATSAMD51,
logical-channel↔physical-XLR identity, or DIR-polarity↔physical-rotation
identity — **still true after the continuity pass**, which did not
probe any of these.

> The remaining high-value question is whether a live configuration
> interface exists between the ATSAMD51 and the TMC5160s, and if so how
> SCK/SDI/SDO/CSN are routed.

**Absence of visible bus traces in these photographs does not prove
standalone (pin-configured) mode** — it only means no such trace was
legible at the angles/resolution captured so far. The 2026-10-17
continuity pass now provides direct (not photo-based) support for
standalone mode via the `SD_MODE`/`SPI_MODE`/`CFG4-6` strap findings
above, but pins 13-16 (the actual CSN/SCK/SDI/SDO candidates) were not
measured and remain `UNKNOWN` — this is not yet fully closed either way.

## Firmware semantics of PB06/PB07/PB16/PB17 (`PROVEN` — Ghidra + Macaw cross-checked)

A narrowly-scoped follow-up pass characterized exactly what the firmware
writes to these four pins, superseding the earlier "~50ms pulse"/"holds
state" shorthand with precise write-site/value/ordering evidence.
**Tool trail**: existing DB/xref search (`census pin`, live-project
`xrefs`) located the write sites; **Macaw** (`aptrace macaw-census-expand`,
built from `external/macaw` per `docs/toolchain.md`) independently
discovered all three functions below as real, separate functions
reachable from `sketch_loop__CUSTOM` at the **exact same call-site
addresses** Ghidra found, and gave **byte-for-byte identical block-count
and size** for `FUN_000077f8`/`FUN_00007868` (10 blocks, 84 bytes each)
— independent structural confirmation of "symmetric," from a different
tool than the one that read the actual values. Ghidra decompile/disasm
supplied the values themselves (Macaw's CFG-level JSON does not expose
per-instruction register values). One self-caught error along the way:
a stale local JSON snapshot briefly suggested boot-time code doesn't
touch these pins at all — direct `disasm` and live-project `xrefs`
corrected that before it was reported (see "at boot" below).

RAM index cells (the pin-table-index byte each pin resolves through, via
the shared `digitalWrite_pulse_shared__STANDARD_LIBRARY` (`0xd388`)
helper — never a direct MMIO write):

| Pin | RAM cell |
|---|---|
| PB06 | `0x20000120` |
| PB07 | `0x20000121` |
| PB16 | `0x2000011f` |
| PB17 | `0x2000011e` |

**Exactly three functions write these pins anywhere in this firmware
image** (exhaustive per live-project `xrefs` on all four cells):

| Function | PB06 | PB07 | delay | PB17 | PB16 |
|---|---|---|---|---|---|
| `FUN_000077f8` (`0x77f8`) | HIGH | HIGH | 50ms | LOW | LOW |
| `FUN_00007868` (`0x7868`) | LOW | LOW | 50ms | LOW | LOW |
| `FUN_000077a0` (`0x77a0`) | *(not touched)* | *(not touched)* | 50ms | HIGH | HIGH |

(delay is `delay__STANDARD_LIBRARY(0x32)` — exactly 50 decimal,
milliseconds by construction, in all three functions; `delay()` is
already reference-confirmed byte-identical elsewhere in this project.)

**This corrects the earlier "byte-identical pulse" shorthand.** The two
disable functions are structurally identical (same literal addresses,
same delay, same call shape, same size/block-count) but **not
value-identical**: PB06/PB07 go HIGH in `0x77f8` and LOW in `0x7868` —
each function writes a single static value once, never both. A real
HIGH→LOW transition on PB06/PB07 only happens **across** separate calls
(e.g. `0x77f8` now, `0x7868` later), never inside one function body.
PB16/PB17 are always written together (never independently), always
*after* the 50ms delay that follows the PB06/PB07 write, and always to
the same value as each other.

**Callers** (all previously documented at a coarser grain; addresses
now exact and Macaw-cross-checked for the `sketch_loop` ones):
`sketch_loop__CUSTOM`'s three-way motor-connector-presence-poll branch
calls `0x77f8`/`0x7868`/`0x77a0` respectively at call sites `0x7918`/
`0x794c`/`0x7962`; `ascii_dispatcher__CUSTOM`'s ASCII `'J'` (0x4A) handler
reaches `0x77f8` or `0x7868` depending on three RAM flag bytes
(`0x8944`/`0x8948`/`0x894c`); the same dispatcher's `0xF0`/`0xE0`
manual-jog-frame handlers call `0x77a0` when a "was disabled" flag
(`0x8530`/`0x852c`) is set.

**Boot-time finding, fully characterized (follow-up pass, `FUN_00006968`
only, Ghidra disasm + independent Macaw CFG cross-check, zero
disagreements found).**

> **Strongest replacement-firmware statement**: `FUN_00006968` establishes
> PB16/PB17=HIGH and PB06/PB07=HIGH exactly once during `setup()`, before
> the four MCU STEP/DIR pairs are configured as outputs. This is the
> **deterministic vendor startup configuration** for those four control
> GPIOs. Its electrical safety meaning remains unproven pending
> continuity.

**Branch condition** (`0x69ae`-`0x69be`): a `millis()`-based unsigned
elapsed-time check, `(now − snapshot) ≥ 1800`, decompiled elsewhere as
`0x707 <` (same threshold, equivalent unsigned comparison). The snapshot
resets every time a status-check helper (`FUN_0000d3dc(1)`, meaning not
chased — out of scope) returns 0; otherwise the wait continues. **This
loop has no other exit** — confirmed independently by Macaw (59 blocks
for this function, exactly one `return` terminator in the whole
function, at `0x6b12`, reachable only through this branch).

**This is not merely a "startup timeout path."** The timeout is the
*only* exit from a boot-*blocking* polling loop — `FUN_00006968` cannot
return to its caller by any other route. That makes the four-pin
sequence below not an edge case but **an effectively mandatory startup
stage**: since this function has exactly one caller
(`sketch_setup__CUSTOM`/`setup()`, call site `0x9488`, confirmed
identically by Ghidra and Macaw), the sequence executes **exactly once
per boot, unconditionally, before `loop()` ever runs**, every boot,
without exception.

**STEP/DIR pins are directly proven untouched immediately before** this
sequence (a different, non-STEP/DIR set of pins — index `0`, `0x28`,
`0x32`, `0x31` — is configured instead) **and are configured `OUTPUT`
immediately after** (a 4-iteration loop, `0x6a68`-`0x6a82`, `pinMode`
only, no `digitalWrite` — direction is set, no level is driven).

**Ordered trace** (addresses exact):

```
0x69be  bcs 0x69d8                    -- elapsed >= 1800ms
0x69d8  pinMode+digitalWrite(idx0, LOW); pinMode+digitalWrite(idx0x28, LOW)
0x69f8  pinMode(idx0x32, OUTPUT); pinMode(idx0x31, OUTPUT)
0x6a08  load PB06/PB07/PB17/PB16 pointers
0x6a10  bl FUN_0000693c()             -- digitalWrite(idx0x32,HIGH); digitalWrite(idx0x31,HIGH)
0x6a14  pinMode+digitalWrite(idx8, HIGH)
0x6a24  pinMode(PB06,OUT); pinMode(PB07,OUT); pinMode(PB17,OUT); pinMode(PB16,OUT)
0x6a44  digitalWrite(PB17,HIGH); digitalWrite(PB16,HIGH); digitalWrite(PB06,HIGH); digitalWrite(PB07,HIGH)
0x6a68  loop x4: pinMode(STEP[i],OUTPUT); pinMode(DIR[i],OUTPUT)   -- no level driven
0x6a84+ TC0-TC3/TCC1 config, then a second unrelated 4-pin cluster (out of scope)
0x6b12  return                        -- sole exit of FUN_00006968
```

No `delay()` library call appears anywhere in this segment (pinMode/
digitalWrite calls are back-to-back). **Not connected to the runtime
state machine**: confirmed independently by both Ghidra (`callers` of
`0x77f8`/`0x7868`/`0x77a0` lists only `sketch_loop`/`ascii_dispatcher`)
and Macaw (zero call edges from `0x6968` to any of the three) — a
structurally distinct, one-time initialization, not a fourth path
through the disable/enable machinery documented above.

**Safe-initial-state classification: `STARTUP/HOMING STATE ONLY —
SAFETY SEMANTICS NOT PROVEN`.** Firmware evidence strongly supports this
being a *deliberate, deterministic, unconditional* startup value (sole
loop exit, always executed once, before STEP/DIR pins even become
outputs) — but "safe" is an electrical claim this pass cannot make:
whether HIGH means "mux outputs disabled/inert" or something else
entirely still depends on the unproven `/OE`/`S` polarity assumption
below. **Conditional interpretation only** (not firmware proof): *if*
PB06/PB07 are confirmed `/OE` (active-low) and PB16/PB17 are confirmed
`S`, this sequence reads as "disable both muxes, set both selects HIGH,
re-enable both muxes — all before STEP/DIR become outputs" — a
textbook glitch-free power-up sequence, contingent entirely on
continuity confirming that polarity.

**Explicit answers**:

- Does PB06 pulse HIGH then LOW, or LOW then HIGH? Neither, within one
  call — see correction above.
- Does PB07 behave identically to PB06? Yes, exactly, in every function.
- Do PB16/PB17 change before/during/after the PB06/PB07 write? **After**
  — always post-delay, in all three functions that touch them.
- PB16/PB17 and PB06/PB07: independent or A/B pairs? Always written
  together, same value, in every function — functionally pairs, no
  path writes one without the other.
- Exactly two structurally symmetric sequences? **Three functions
  total** — `0x77f8`/`0x7868` are the structurally-symmetric disable
  pair; `0x77a0` is a third, distinctly-shaped enable function that
  never touches PB06/PB07.

**What this does and does not resolve**: this is a complete firmware-side
account (write sites, values, ordering, boot behavior) — status
`PROVEN`. It does **not** resolve physical/electrical identity (mux
`S`/`OE‾` vs. TMC5160 `DRV_ENN` vs. something else) — that remains
`HIGH-CONFIDENCE INFERENCE`, unchanged, in the next section.

## Motor bus architecture — mux hypothesis (status: see "Continuity bench pass" below — partially `PROVEN`, partially downgraded)

**Two `SN74CBTLV3257` devices — device count: now `PROVEN`.** `...0103.jpg`
proved one device by PCB photo + TI marking match; a second legible photo
was never located (see below for that photo-only history). The
continuity bench pass (see "Continuity bench pass (2026-10-17)" below)
independently probed two physically distinct mux locations — labeled
"Mux 1" and "Mux 2" in `AutoPilot_Continuity_Bench_Sheet.md` — and
obtained **distinct 0 Ω continuity patterns**: Mux 1's channels land on
TMC1/TMC3, Mux 2's on TMC2/TMC4, with no overlap. Two electrically
independent devices are required to produce that pattern, so device
count is now `PROVEN` by continuity, independent of the photo gap.

**Photo-only history (superseded by the above, kept for record).** A
second device in the same repeated configuration was reported, but this
documentation pass **did not itself locate a second legible (or even
blurry-but-identifiable) photo of a second 16-pin SSOP part** —
`...0114.jpg`, `...0121.jpg` (REV 1) and `IMG_3094.JPG`, `IMG_3095.JPG`
(REV 2) were checked and show unrelated ICs (power-management parts near
the MCU logic region, not the motor-driver cluster). Per this document's
own evidence discipline (`hardware-reference.md`'s "Adjacent 16-pin SSOP
mux/demux"), the device count was graded `PROBABLE` by photo evidence
alone — now superseded by the `PROVEN` continuity finding above.

**The architectural hypothesis.** The two `SN74CBTLV3257` 4-channel 2:1
muxes select between MCU-generated STEP/DIR and externally-supplied
(RJ45) STEP/DIR, with their outputs feeding the four TMC5160 STEP/DIR
inputs:

```text
                   MCU STEP/DIR
                       \
                        SN74CBTLV3257
                       /              \
external RJ45 STEP/DIR                 TMC5160 STEP/DIR
```

Signal-count match (the basis for the inference, not proof of it):

```text
4 motors x 2 signals (STEP + DIR) = 8 switched signals
2 x SN74CBTLV3257 = 2 x 4 switched channels = 8 switched signals
```

One mux naturally handles 4 STEP/DIR signals (two motors); two muxes
cover all four motors. This would also explain why no firmware path has
been found consuming external RJ45 STEP/DIR pulses (see "Trigger
result" below and `cases/performing-rigs/docs/replacement/mapped-pin-causal-gap-audit.md`'s
"External RJ45 STEP/DIR" `INSUFFICIENT_SINK` finding): the external
pulses may bypass the ATSAMD51 entirely, switched electrically into the
TMC5160 STEP/DIR inputs by the mux rather than consumed by any GPIO/ISR.

**Status (pre-continuity): `HIGH-CONFIDENCE INFERENCE`, explicitly not
`PROVEN`.** Superseded in part by the continuity bench pass immediately
below — the A-side (mux-to-TMC) and B-side (mux-to-RJ45) legs of this
diagram are now `PROVEN`; the diagram's "MCU STEP/DIR" source arrow and
the `S`/`OE‾` GPIO identity below remain unconfirmed.

### Continuity bench pass (2026-10-17)

Source: [`AutoPilot_Continuity_Bench_Sheet.md`](AutoPilot_Continuity_Bench_Sheet.md)
(physical multimeter continuity/resistance measurements on a powered-off
board; raw readings preserved there, not retyped here beyond what's cited).

**Mux → TMC5160 → RJ45 chain: `PROVEN`.** Bench sheet §3 ("Mux outputs to
TMC5160 STEP/DIR") measured 0 Ω (clean continuity) at exactly one
TMC5160 per mux channel, with every other TMC5160 on that channel
reading ~480–570 KΩ (clearly not connected) — a clean, unambiguous
signature, unlike the §2 readings below. Bench sheet §4 ("Trace both
sides of each used mux channel") then found, for the same channels, both
`B1` and `B2` reaching a specific RJ45 jack through on-board ESD diodes
to `VCC I/O` plus a ~468–490 Ω series resistor. Combined:

| Mux | Channels (A pin) | TMC5160 (pin 17 STEP / pin 18 DIR) | RJ45 jack (via B1+B2) |
|---|---|---|---|
| Mux 1 | 1A (pin 4), 2A (pin 7) | TMC1: 1A→pin17, 2A→pin18 | RJ45 #2 |
| Mux 1 | 3A (pin 9), 4A (pin 12) | TMC3: 3A→pin18, 4A→pin17 | RJ45 #4 |
| Mux 2 | 1A (pin 4), 2A (pin 7) | TMC2: 1A→pin17, 2A→pin18 | RJ45 #1 |
| Mux 2 | 3A (pin 9), 4A (pin 12) | TMC4: 3A→pin18, 4A→pin17 | RJ45 #3 |

This proves, per mux channel: the `A` (common) pin is a direct (0 Ω)
connection to one specific TMC5160's STEP or DIR input, and **both**
`B1` and `B2` of that same channel reach the same external RJ45 jack
(through the board's input-protection network) — not two different
sources. **This resolves "which two motors belong to each
`SN74CBTLV3257`"** (Mux 1 = TMC1+TMC3, Mux 2 = TMC2+TMC4) and **gives a
PROVEN mux-channel ↔ RJ45-jack mapping**, previously open.

**What this does not establish.** No ATSAMD51 pin was found connected to
either `B1` or `B2` in this pass — the bench sheet's §4 instruction was
to check both the RJ45-side *and* the ATSAMD51-side probe points, but
only the RJ45-side connection was recorded as found. **Do not read this
as proof that no MCU-side leg exists** — it was not ruled out, it
simply wasn't the connection that was found/recorded. The architecture
diagram's "MCU STEP/DIR" source arrow, and which of `B1`/`B2` (if
either) is the MCU side, therefore **remain open, not confirmed and not
refuted**. The `HIGH-CONFIDENCE INFERENCE` that external RJ45 STEP/DIR
bypasses the ATSAMD51 entirely (no firmware sink found, "Trigger result"
below) is now also consistent with "both switched legs of the tested
channels land on the RJ45 side, not a traced MCU side" — real support,
not proof, since the MCU side of the mux was never probed.

**`S`/`OE‾` → PB16/PB17/PB06/PB07: `TESTED — DIRECT CONNECTION NOT
CONFIRMED`.** Bench sheet §2 measured mux pin 1 (`S`) and mux pin 15
(`/OE‾`), on **both** Mux 1 and Mux 2, against all four candidate
ATSAMD51 pins (PB16/PB17/PB06/PB07). Every reading came back in the
~325–335 KΩ range — no near-0 Ω reading anywhere, unlike the clean
TMC5160 result above. A real direct trace reads near 0 Ω regardless of
board power state; ~330 KΩ, identical across both physically distinct
muxes and all four candidate pins, is the signature of a generic
pull/leakage path, not a dedicated copper trace. **This is negative
evidence against a direct, unbuffered connection — it is not proof that
no control relationship exists.** An indirect path (e.g. through a
buffer/driver IC not yet identified, or the actual control pins being
different GPIOs entirely) is not ruled out. The firmware-side write
sequence to these four pins (see "Firmware semantics of
PB06/PB07/PB16/PB17" above) is **unaffected and remains `PROVEN`** —
only the physical `S`/`OE‾` identity is downgraded.

**TMC5160 mode/configuration-strap pins: `PROVEN`.** Bench sheet §5
measured TMC5160 pin 21 (`SD_MODE`) and pin 22 (`SPI_MODE`) both at 0 Ω
to `VCC I/O` (also shared with ATSAMD51 pins 8/21/34/48/56, which are
MCU supply pins, not GPIOs). Bench sheet §7 measured pins 23/24/25
(`ENCB_DCN_CFG4`/`ENCA_DCN_CFG5`/`ENCN_DCO_CFG6`) all at 0 Ω to `GNDANA`.
Both mode-select pins strapped HIGH and all three CFG pins strapped LOW
is the hard-wired configuration-strap pattern for the TMC5160A's
Step/Dir **standalone** interface mode (no SPI/UART), consistent with —
and now the first direct physical support for — the firmware-side
finding that the `MC` command's CURRENT and MICROSTEPPING fields have no
traced hardware effect. **Scope of this finding, explicitly bounded**:
this is a statement about which *digital configuration interface* is
selected. It says nothing about, and must not be read as establishing,
motor current magnitude, current-sense/IRUN-IHOLD scaling, or any safe
operating/current limit — those depend on the analog sense-resistor and
remaining strap network, which this pass did not measure.

**TMC5160 `DRV_ENN`: `PROVEN`, and this rules out one candidate
interpretation.** Bench sheet §8 measured TMC5160 pin 28 (`DRV_ENN`) at
0 Ω to `GNDANA` — hard-wired, not routed to any ATSAMD51 pin. This is a
physical fact about the strap only: it says nothing about whether the
driver stage is actually safely de-energized, actively driven, or
current-limited under any given condition — that remains a separate,
unestablished question. What it **does** settle is the candidate
interpretation already flagged as questionable above (point 4): **PB16/
PB17/PB06/PB07 cannot be wired to TMC5160 `DRV_ENN`**, on any of the four
TMC5160s — `DRV_ENN` has no MCU-side connection at all. Any documentation
elsewhere (including downstream, e.g. `apfw2`) that frames PB16/17/06/07
as a *driver-enable* control reaching `DRV_ENN` should be revisited; the
mux `S`/`OE‾` hypothesis and the `DRV_ENN` hypothesis were always
mutually exclusive candidates for the same four pins, and this pass
physically eliminates the `DRV_ENN` branch (it does not thereby prove
the `S`/`OE‾` branch — see "tested, not confirmed" above).

**Still `UNKNOWN`, not inferred from this pass.** Bench sheet §6 (CSN/
SCK/SDI/SDO — TMC5160 serial/config pins) and the DIAG0/DIAG1 rows of
§8 are blank templates in the bench sheet — no measurement was taken.
Per this document's standing discipline, **a blank field is not
evidence of absence**: these remain `UNKNOWN`, exactly as before this
pass, not reclassified based on the SD_MODE/SPI_MODE strap finding above
(which answers the *mode-select* question, not whether any serial lines
are additionally routed for diagnostics or OTP).

**PB16/PB17 and PB06/PB07 — revised interpretation.** The previous names
`Driver enable A/B` and `Driver reset strobe A/B` (compact map above) are
**provisional functional names, not proven electrical identities**.
Leading hypothesis (now `TESTED — DIRECT CONNECTION NOT CONFIRMED`, see
"Continuity bench pass" above — retained here for the reasoning, not as
a confirmed finding):

```text
PB16 / PB17  ->  hypothesized SN74CBTLV3257 source-select (S) lines
PB06 / PB07  ->  hypothesized SN74CBTLV3257 /OE lines
```

Status: `TESTED — DIRECT CONNECTION NOT CONFIRMED` (downgraded from
`HIGH-CONFIDENCE INFERENCE` by the bench pass above). Original reasoning
for the hypothesis, kept for record:

1. Two `SN74CBTLV3257`s require exactly 2x `S` + 2x `/OE` — matching the
   firmware's exactly-four unexplained paired motor-control GPIOs.
2. `/OE` is active-low on this part, so PB06/PB07 going HIGH in
   `0x77f8` would disconnect mux outputs immediately before PB16/PB17
   (the hypothesized `S` lines) change 50ms later — see "Firmware
   semantics of PB06/PB07/PB16/PB17" above for the exact, corrected
   per-function write table (PB06/PB07 are HIGH in `0x77f8`, LOW in
   `0x7868`, untouched in `0x77a0` — not a symmetric pulse in both
   disable sequences as earlier shorthand implied).
3. PB16/PB17 *hold* state after a transition (now exactly
   characterized: LOW after either disable function, HIGH after
   `0x77a0`'s enable path) — consistent with a persistent mux
   source-selection signal, not a momentary reset strobe.
4. Direct interpretation of PB16/PB17 as TMC5160 `DRV_ENN` is now
   physically ruled out, not merely questionable — see "Continuity bench
   pass" above (`DRV_ENN` is hard-strapped to `GNDANA`, no MCU
   connection on any of the four TMC5160s).

None of this reasoning is a continuity measurement of `S`/`OE‾`
themselves — points 1-3 are firmware/logical inference only, and the
bench pass's actual electrical test of `S`/`OE‾` came back
not-confirmed (above).

**Do not rename these pins in canonical tables** — the compact map
above keeps the old names with an explicit "name provisional" flag and
the new `TESTED — DIRECT CONNECTION NOT CONFIRMED` grade, rather than
renaming to `MOTOR_CTRL_A/B`/`MOTOR_STROBE_A/B` or asserting the
hypothesis is confirmed.

**Highest-value continuity tests — run this pass; see results above.**
Historical pre-pass plan, kept for record:

```text
For one mux:
  SN74CBTLV3257 pin 1  (S)    -> PB16 or PB17?         RUN — not confirmed (see above)
  SN74CBTLV3257 pin 15 (/OE)  -> PB06 or PB07?         RUN — not confirmed (see above)

Then for one switched channel:
  A/common -> TMC5160 STEP or DIR?                     RUN — PROVEN (see table above)
  B1       -> ATSAMD51 STEP/DIR?   (B1/B2 may be reversed)   NOT FOUND — see "What this does not establish"
  B2       -> external RJ45 STEP/DIR path?              RUN — PROVEN, both B1 and B2 (see table above)
```

Both muxes were measured, not just one — the pattern (one clean A→TMC
connection per channel; both B legs to the same RJ45; no clean `S`/`OE‾`
reading) held identically on Mux 1 and Mux 2.

**TMC5160 configuration mode directly at the device — also run this
pass.** Highest-value TMC5160A-TA pins (candidate numbers from the prior
plan; now measured against the real package):

```text
13 CSN_CFG3   14 SCK_CFG2   15 SDI_CFG1   16 SDO_CFG0    -- still UNKNOWN, blank in bench sheet
17 REFL_STEP  18 REFR_DIR                                -- PROVEN, see table above
21 SD_MODE    22 SPI_MODE                                -- PROVEN, strapped to VCC I/O
28 DRV_ENN                                                -- PROVEN, strapped to GNDANA
```

**TMC5160 configuration mode — mode-select pins now `PROVEN`; serial-bus
wiring (pins 13-16) still `UNKNOWN`.** The mux-architecture question and
the configuration-bus question remain logically independent, as before,
but the configuration-bus question is now partly answered directly at
the device rather than inferred from firmware absence-of-evidence:
`SD_MODE`/`SPI_MODE` are hard-strapped (see "Continuity bench pass"
above), consistent with standalone Step/Dir operation. This is now
**direct physical evidence**, not merely the absence of discovered SPI
traffic (`SERCOM2` confirmed as the radio SPI interface; `SERCOM5`
receives generic boot-time initialization but no traced transaction;
CURRENT and MICROSTEPPING command fields have no traced hardware
effect — all previously established, unchanged). **What remains
`UNKNOWN`**: pins 13-16 (`CSN_CFG3`/`SCK_CFG2`/`SDI_CFG1`/`SDO_CFG0`) and
`DIAG0`/`DIAG1` were not measured this pass (blank in the bench sheet) —
do not infer their absence from the mode-strap finding; a device can in
principle have mode pins strapped for standalone operation while still
exposing CFG-bus pins for diagnostics/OTP that this pass did not check.

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
- **Mux-channel ↔ TMC5160 ↔ RJ45-jack mapping** (2026-10-17 continuity
  bench pass, `AutoPilot_Continuity_Bench_Sheet.md`): `PROVEN`. See
  "Continuity bench pass (2026-10-17)" under "Motor bus architecture —
  mux hypothesis" above for the full table.
- **Two `SN74CBTLV3257` device count**: upgraded `PROBABLE` → `PROVEN`
  by the same pass (two electrically distinct continuity patterns, not
  just a second photo).
- **TMC5160 mode-select strapping (`SD_MODE`/`SPI_MODE`) and CFG4/5/6
  strapping**: `PROVEN` by the same pass — direct physical support for
  standalone Step/Dir operation, with no claim made about current
  magnitude or safety.
- **TMC5160 `DRV_ENN` strapping**: `PROVEN` by the same pass —
  hard-wired to `GNDANA`, not MCU-controlled.

## Ruled-out mappings

- PB30/PB31 as a *repeating* WHITE/BLUE indicator: ruled out at the
  firmware layer (unconditional/state-independent pulse) in a prior
  session, reconfirmed structurally this pass.
- PA23 as the status LED: ruled out at the firmware layer (one-shot
  latch, not a toggle) in a prior session; not re-opened here.
- REV 1 photos as AutoPilot evidence: **superseded** — this was true
  only of the original `...0042`-`...0074` file set (Remote-board
  photos); a later-added file set in the same folder (`...0095` onward)
  is real AutoPilot-board evidence, including the TMC5160A-TA chip-ID
  finding above.
- **PB16/PB17/PB06/PB07 as TMC5160 `DRV_ENN`**: ruled out physically by
  the 2026-10-17 continuity bench pass — `DRV_ENN` on all four TMC5160s
  is hard-strapped to `GNDANA`, no MCU connection exists to rule in.
  (This does not confirm the competing `S`/`OE‾` hypothesis for the same
  four pins — see "tested, not confirmed" below.)

## Unresolved high-value pins

PB30/PB31's real physical destination; PA22's physical component; the
TCC1/PB22 5th-channel pulse's purpose; the external RJ45 STEP/DIR
input's firmware-side consumption mechanism (still none found — the
2026-10-17 bench pass strengthens, but does not prove, that it bypasses
the MCU electrically via the mux); DIR polarity-to-rotation on all 4
channels; logical-channel (firmware STEP0-3/DIR0-3) to physical-TMC1..4
identity (the bench pass fixed TMC1..4 relative to each other and to
RJ45 #1-4, but not to the firmware's logical channel numbering or to
XLR jack numbering).

**`TESTED — DIRECT CONNECTION NOT CONFIRMED`** (2026-10-17 continuity
bench pass, downgraded from `HIGH-CONFIDENCE INFERENCE`): exact `S` and
`OE‾` GPIO assignments — PB16/PB17/PB06/PB07 showed no near-0 Ω
continuity to mux pin 1 (`S`) or pin 15 (`/OE‾`) on either mux. See
"Continuity bench pass (2026-10-17)" above for the readings; the
firmware-side write sequence to these four pins remains independently
`PROVEN`.

Resolved this pass (moved out of this list — see "Continuity bench
pass (2026-10-17)" above for citations):

- ~~Which two motors belong to each `SN74CBTLV3257`~~ — Mux 1 =
  TMC1+TMC3, Mux 2 = TMC2+TMC4.
- ~~Exact logical channel ↔ physical RJ45 jack~~ — Mux 1 channels 1A/2A
  (TMC1) ↔ RJ45 #2, 3A/4A (TMC3) ↔ RJ45 #4; Mux 2 channels 1A/2A
  (TMC2) ↔ RJ45 #1, 3A/4A (TMC4) ↔ RJ45 #3.
- ~~TMC5160 `DRV_ENN` wiring~~ — strapped to `GNDANA`, not MCU-routed.
- ~~TMC5160 SPI/UART/standalone mode-select~~ — `SD_MODE`/`SPI_MODE`
  strapped to `VCC I/O`, `CFG4/5/6` strapped to `GNDANA`; consistent
  with standalone Step/Dir operation (no claim made about current
  magnitude, scaling, or safety).

Still open, unaffected by this pass:

- Exact logical channel 0-3 (firmware STEP0-3/DIR0-3 GPIOs) ↔ physical
  TMC5160 package 1-4 identity.
- Exact logical channel ↔ physical XLR output-connector identity.
- DIR polarity ↔ actual motor rotation direction.
- `B1`/`B2` source polarity (which leg, if either, is MCU-internal) —
  **not resolved, not refuted**: both legs of every tested channel
  reached the RJ45 side; no ATSAMD51-side continuity was recorded for
  either leg (see "What this does not establish" above) — the MCU side
  of the mux was never probed.
- TMC5160 serial/config-bus wiring: `CSN_CFG3`/`SCK_CFG2`/`SDI_CFG1`/
  `SDO_CFG0` (pins 13-16) — blank in the bench sheet, still `UNKNOWN`.
- `DIAG0`/`DIAG1` wiring — blank in the bench sheet, still `UNKNOWN`.
- `REFL`/`REFR` use outside STEP/DIR mode.
- Exact current-sense/power-stage topology per motor (how many
  `CSD88537ND` packages per channel, exact bridge topology).

**TCC1/PB22 update** (TCC1/PB22 Boot Runtime Replay): concretely
confirmed TCC1 is genuinely enabled twice during boot, both times
inside the already-documented "dead" ADC-baseline function
(`FUN_00005d44`), not the reference-seek move itself. Its IRQ handler
never fired and `PORT.GROUP1.OUTTGL` was never written in a
450,000-instruction replay — but the AutoPilot boot recipe delivers
**zero** Cortex-M interrupts by construction (0 `interrupt_bridges`),
so this is `MODEL_GAP`, not evidence that real silicon stays silent.
See [`mapped-pin-causal-gap-audit.md`](../replacement/mapped-pin-causal-gap-audit.md)
for the full replay.

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

## Evidence status summary (motor hardware, current state)

```text
PROVEN
- TMC5160A-TA physically present (1 of 4 channels, PCB photo)
- CSD88537ND physically present (PCB photo + TI marking match)
- SN74CBTLV3257 physically present AND device count = 2 (PCB photo +
  TI marking match for identity; 2026-10-17 continuity pass for count —
  two electrically distinct 0 Ω patterns, see below)
- MCU STEP pin map (TC0-TC3 -> PB10/PA08/PB12/PA10, firmware + package)
- MCU DIR pin map (PB11/PA09/PB13/PA11, firmware + package)
- Mux channel -> TMC5160 chip + STEP/DIR pin, both muxes, all 8 switched
  signals (2026-10-17 continuity pass, §3 of the bench sheet): Mux 1 ->
  TMC1 (1A=STEP,2A=DIR) + TMC3 (3A=DIR,4A=STEP); Mux 2 -> TMC2
  (1A=STEP,2A=DIR) + TMC4 (3A=DIR,4A=STEP)
- Mux channel (both B1 and B2) -> RJ45 jack, both muxes (2026-10-17
  continuity pass, §4 of the bench sheet): Mux1/TMC1 channels -> RJ45
  #2; Mux1/TMC3 channels -> RJ45 #4; Mux2/TMC2 channels -> RJ45 #1;
  Mux2/TMC4 channels -> RJ45 #3 (each via on-board diodes to VCC I/O
  plus a ~468-490 ohm series resistor)
- TMC5160 SD_MODE + SPI_MODE strapped to VCC I/O, 0 ohm (2026-10-17
  continuity pass, §5) — mode-select only, no claim about current
  magnitude or safety
- TMC5160 CFG4/CFG5/CFG6 strapped to GNDANA, 0 ohm (2026-10-17
  continuity pass, §7)
- TMC5160 DRV_ENN strapped to GNDANA, 0 ohm, not MCU-routed (2026-10-17
  continuity pass, §8) — strap fact only, no claim about actual driver
  energization or safety

TESTED -- DIRECT CONNECTION NOT CONFIRMED (new grade, 2026-10-17 pass;
distinct from both PROVEN and UNKNOWN -- a real measurement was taken
and came back inconsistent with a direct trace, but an indirect/buffered
path is not ruled out)
- PB16/PB17 vs mux pin 1 (S): ~334.5 K ohm on both candidate pins, both
  muxes (bench sheet §2) -- no near-0 ohm reading
- PB06/PB07 vs mux pin 15 (/OE): ~325-335 K ohm on both candidate pins,
  both muxes (bench sheet §2) -- no near-0 ohm reading
- the firmware-side write sequence to these four pins is unaffected and
  remains PROVEN (see "Firmware semantics of PB06/PB07/PB16/PB17" above)

HIGH-CONFIDENCE INFERENCE (not PROVEN)
- internal MCU STEP/DIR and external RJ45 STEP/DIR are the two mux
  sources (the RJ45 side of this is now PROVEN per above; the MCU side
  was not probed this pass -- see "What this does not establish")
- external STEP/DIR may bypass the MCU datapath completely (consistent
  with, but not proven by, the above: both measured B-legs reached only
  RJ45, not a traced MCU pin)

UNKNOWN
- B1/B2 source polarity on the MCU side (no ATSAMD51-side continuity was
  recorded for either leg this pass)
- TMC5160 serial/config-bus wiring: CSN_CFG3/SCK_CFG2/SDI_CFG1/SDO_CFG0
  (pins 13-16) -- blank in the bench sheet, not measured
- DIAG0/DIAG1 wiring -- blank in the bench sheet, not measured
- physical channel ordering: firmware logical channel 0-3 (STEP0-3/
  DIR0-3 GPIOs) <-> physical TMC1-4 identity established by this pass;
  <-> physical XLR output-jack identity still open
- exact current-sense/power-stage topology per motor
```

## See also

- [`cases/performing-rigs/docs/hardware/AutoPilot_Continuity_Bench_Sheet.md`](AutoPilot_Continuity_Bench_Sheet.md) — raw measurements for the 2026-10-17 continuity pass cited throughout this document
- [`cases/performing-rigs/docs/hardware/hardware-reference.md`](hardware-reference.md)
- [`cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md)
- [`cases/performing-rigs/docs/investigations/trigger-input.md`](../investigations/trigger-input.md)
- [`cases/performing-rigs/docs/replacement/autopilot-gap-audit.md`](../replacement/autopilot-gap-audit.md)
- [`cases/performing-rigs/docs/replacement/mapped-pin-causal-gap-audit.md`](../replacement/mapped-pin-causal-gap-audit.md)
- [`cases/performing-rigs/research/generated/autopilot-replacement-gaps.json`](../../research/generated/autopilot-replacement-gaps.json)
