# Mapped-Pin Causal Gap Audit (AutoPilot)

Bounded causal-analysis pass over
[`docs/hardware/firmware-pin-function-map.md`](../hardware/firmware-pin-function-map.md).
Existing docs + bounded static tracing (Ghidra `callers`/`decompile`/
`dump`) — no SMT run. Does not reopen STEP/DIR or the Trigger-movement
causal question.

**Updated by a follow-up pass** (TCC1/PB22 Boot Runtime Replay): the
one concrete-replay recommendation this audit originally made (below)
was then executed, reusing the existing validated `AUTOPILOT_RECIPE`
boot recipe unmodified. The TCC1/PB22 section reflects the result.

**Machine-readable companion (authoritative)**:
[`research/generated/mapped-pin-causal-gap-audit.json`](../../research/generated/mapped-pin-causal-gap-audit.json).

## PB30 / PB31

**Role**: unconditional `PB30=HIGH, PB31=LOW` pulse in `FUN_00006952` —
takes no parameters, cannot vary its output.

**Upstream causes** — now 4, not 2: G/move-commit and accepted-Trigger
reload (already known), plus two found this pass: an already-armed
Auto-Mode move advancing to its next programmed segment
(`FUN_00006e68`, from `phase_ramp_state_machine__CUSTOM`'s phase-3
handling), and a boot-time PA22-HIGH read inside the startup
reference/input routine, checked immediately after PB30/PB31 are
configured as outputs and before the reference-seek timeout loop
starts. All four reach the identical, state-independent pulse.

**Physical meaning**: unknown (unchanged from the pin map — plausible
LED pair in the logic region, no copper traced; not re-investigated
here).

**Gap classification**: `CAUSAL_PATH_PROVEN` — firmware side now
fully closed. **Recommended next tool: none.** Having *more* producers
that all do the exact same thing makes this a *worse*, not better, SMT
target — there is no upstream ambiguity left to disambiguate.

## PB06 / PB07

**Role — corrected by a later Ghidra+Macaw cross-checked pass.** Not a
50ms HIGH pulse in both disable sequences: `FUN_000077f8` (`0x77f8`)
writes PB06=HIGH, PB07=HIGH, delays exactly 50ms (`delay(0x32)`), then
writes PB17=LOW, PB16=LOW; `FUN_00007868` (`0x7868`) instead writes
PB06=LOW, PB07=LOW, delays the same 50ms, then also writes PB17=LOW,
PB16=LOW. Each function writes PB06/PB07 to one static value, once —
the earlier "byte-identical...pulse" language conflated the two
functions' identical *structure* (same literal addresses, same delay,
same call shape — independently reconfirmed via Macaw: identical
84-byte size and identical 10-block CFG shape for both) with their
*values*, which differ. A third function, `FUN_000077a0` (`0x77a0`),
writes PB17=HIGH, PB16=HIGH after the same 50ms delay and **never
touches PB06/PB07 at all**. Full write-site/value/ordering table:
`firmware-pin-function-map.md`'s "Firmware semantics of
PB06/PB07/PB16/PB17".

**Boot-time finding, fully characterized (follow-up `FUN_00006968`-only
pass, Ghidra+Macaw cross-checked, no disagreements).**

> **Strongest replacement-firmware statement**: `FUN_00006968`
> establishes PB16/PB17=HIGH and PB06/PB07=HIGH exactly once during
> `setup()`, before the four MCU STEP/DIR pairs are configured as
> outputs. This is the **deterministic vendor startup configuration**
> for those four control GPIOs. Its electrical safety meaning remains
> unproven pending continuity.

Inside `FUN_00006968` (the startup reference/homing routine), a
`millis()`-based wait loop (`elapsed >= 1800`, snapshot reset by a status
check, `FUN_0000d3dc(1)`, not chased) has **no exit other than this
timeout** — confirmed independently by Macaw (59 blocks, exactly one
`return` terminator, reachable only through this branch). **This is not
merely a "startup timeout path"** — the timeout is the *only* exit from
a boot-*blocking* polling loop, so this is not an edge case but an
**effectively mandatory startup stage**: since `FUN_00006968` has exactly
one caller (`setup()`, confirmed identically by both tools), the
sequence runs **exactly once per boot, unconditionally, every boot,
without exception**. On that branch, all four pins are explicitly
configured `OUTPUT` and driven **HIGH** — PB06, PB07, PB16, and PB17
alike — with STEP/DIR pins directly proven untouched immediately before
and configured `OUTPUT` (direction only, no level) immediately after.
Not connected to `0x77f8`/`0x7868`/`0x77a0` (confirmed by both tools:
zero call edges either direction). Safety classification:
`STARTUP/HOMING STATE ONLY — SAFETY SEMANTICS NOT PROVEN` — this is
strongly evidenced as the vendor's deliberate startup value, but "safe"
remains an electrical claim, not a firmware one. Full ordered trace with
addresses: `firmware-pin-function-map.md`'s boot-time paragraph.

**Upstream causes** (unchanged, still accurate):

- `sketch_loop__CUSTOM`'s own motor-connector-presence poll — the
  firmware side of the manual's "auto-detects which of the four ports
  have a motor connected." A change in the aggregate connected/
  disconnected pattern drives disable or re-enable.
- **ASCII command `'J'` (0x4A)** — a previously-undocumented wire
  command that, under sub-conditions, reaches disable directly. Also:
  inbound `F0`/`E0` manual-jog frames can trigger **re-enable** when a
  "was disabled" flag is set.

**Physical meaning**: still not confirmed — this pass (and the later
one) establishes *exactly what* the firmware writes and *when*, not
what it does electrically. The mux-hypothesis pass
(`firmware-pin-function-map.md`) now has a specific candidate (`SN74CBTLV3257`
`/OE`/`S` lines), `HIGH-CONFIDENCE INFERENCE`, not proven.

**Gap classification**: `CAUSAL_PATH_PROVEN` for the firmware
write-site/value/ordering question (strengthened, not just re-affirmed,
by this later pass). **Recommended next tool: none** for the firmware
side — the remaining gap is physical (PCB continuity), not firmware.

## TCC1 / PB22

**Role**: `FUN_00005570(param_1)` is a per-peripheral configuration
function; cases 0–3 configure TC0–TC3's own EIC/PORT setup, **case 7
configures TCC1** (`CTRLA=0x100`, `PER=0x20000000`, `CC0=0x10000`).
All 5 calls (params 0,1,2,3,7) come **exclusively from
`FUN_00006968`**, the startup reference/input boot routine. The only
other path into `FUN_00005570` (via `FUN_00005f8c`) is always called
with a 0–3 channel argument, never 7 — **no live/wire command reaches
TCC1's own configuration.**

**Resolved this pass by concrete replay** (TCC1/PB22 Boot Runtime
Replay — see below): configuration is confirmed exactly as predicted
(instr 65062–65071). The real **ENABLE** writer is `FUN_00005d24`
(`CTRLA=0x102`), called *exclusively from inside `FUN_00005d44`* — the
already-documented "dead" 128-sample ADC-baseline boot function, **not
the reference-seek move** as the prior static-only pass inferred from
co-configuration timing. TCC1 was enabled and disabled twice, both
pairs entirely bracketing `FUN_00005d44`'s own execution (instr
251605–259661 and 263738–271782 of a 450,000-instruction replay), with
`FUN_0000434c` doing each disable (`CTRLA.ENABLE` cleared, PB22 driven
LOW).

**Across the full replay** (11 real main-loop iterations past steady
state): TCC1's IRQ handler (`0x60ec`) — **0 hits**. `PORT.GROUP1.OUTTGL`
(`0x4100809c`, the handler's own toggle register) — **never written,
not once**. But `AUTOPILOT_RECIPE` delivers **zero** real Cortex-M
interrupts by construction (`interrupt_bridges: []`, confirmed) — so
this null result is a property of the harness, not evidence that real
silicon stays silent.

**Physical meaning**: still unknown. The earlier "tied to the
reference-seek move" inference is superseded — TCC1's actual activity
brackets the ADC-baseline function instead, which is *already*
documented as functionally inert elsewhere, raising the possibility
this TCC1 usage is likewise dead code rather than merely unidentified.

**Gap classification**: `MODEL_GAP` — firmware genuinely requests
runtime behavior (real `CTRLA.ENABLE` writes, twice), but this harness
cannot determine whether real hardware would fire, because AutoPilot's
boot recipe models zero interrupt delivery. **Recommended next tool:
none for this recipe** — closing this would need a new,
evidence-bounded `interrupt_bridge` for IRQ93 (the same discipline
`MANDO_RECIPE`'s one DMAC bridge already established), which is a
harness change, out of this pass's bounded scope.

## External RJ45 STEP/DIR

The pin map exposes **no concrete GPIO/peripheral candidate**
(`gpio: null`, `package_pin: null`) — this was already a documented,
unresolved gap (EIC callback table confirmed dormant) before this pass,
not newly found here.

**Gap classification**: `INSUFFICIENT_SINK`. Per instruction, not
globally searched for — no pin to start from, none invented.

## Report

- **Candidates audited**: 4 (PB30/PB31, PB06/PB07, TCC1/PB22, external
  RJ45 STEP/DIR).
- **Causal paths closed this pass**: PB30/PB31 and PB06/PB07 (firmware
  side — both `CAUSAL_PATH_PROVEN`); TCC1/PB22's configuration and
  enable/disable lifecycle (firmware side — concretely proven by the
  follow-up boot replay), though its runtime-firing question landed on
  `MODEL_GAP`, not closed.
- **Good SMT candidates**: none, throughout. PB30/PB31 is a *worse* SMT
  target than before (4 identical producers, no ambiguity to solve
  for); the others have no sink, a resolved concrete question, or a
  harness limitation no query can get past.
- **Good concrete-replay candidates**: none remaining — TCC1/PB22 was
  the one candidate and it has now been run.
- **Insufficient-sink cases**: external RJ45 STEP/DIR input.
- **Newly discovered command/UI links**:
  - ASCII `'J'` → motor-driver disable.
  - Inbound `F0`/`E0` → motor-driver re-enable (conditional).
  - Motor-connector-presence poll (autonomous, not a wire command) →
    enable/disable.
  - Auto-Mode segment-advance and a boot-time PA22 read → the shared
    PB30/PB31 pulse (joining G-commit and Trigger-reload).
- **Remaining high-value unknowns**: PB30/PB31 and TCC1/PB22 physical
  destinations; whether TCC1 fires on real silicon (`MODEL_GAP`); full
  semantics of ASCII `'J'`; PB06/PB07's electrical identity; the
  external RJ45 STEP/DIR mechanism in its entirety.

**Recommended next causal query before LID**: none. Every candidate in
this audit's set now has either a proven firmware causal path, an
insufficient sink, or a gap that only PCB continuity measurement, real
hardware, or a new evidence-bounded interrupt bridge (a harness change,
not a query) could close. This candidate set is exhausted for
firmware-only causal work.
