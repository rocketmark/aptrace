# Mapped-Pin Causal Gap Audit (AutoPilot)

Bounded causal-analysis pass over
[`docs/hardware/firmware-pin-function-map.md`](../hardware/firmware-pin-function-map.md).
Existing docs + bounded static tracing (Ghidra `callers`/`decompile`/
`dump`) only — no Unicorn or SMT run this pass; recommended, not
executed, where warranted. Does not reopen STEP/DIR or the
Trigger-movement causal question.

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

**Role**: ~50ms HIGH pulse, only inside the two byte-identical
motor-driver disable sequences (`0x77f8`/`0x7868`), immediately before
enable (PB16/PB17) goes LOW.

**Upstream causes**, both newly traced this pass:

- `sketch_loop__CUSTOM`'s own motor-connector-presence poll — the
  firmware side of the manual's "auto-detects which of the four ports
  have a motor connected." A change in the aggregate connected/
  disconnected pattern drives disable or re-enable.
- **ASCII command `'J'` (0x4A)** — a previously-undocumented wire
  command that, under sub-conditions, reaches disable directly. Also:
  inbound `F0`/`E0` manual-jog frames can trigger **re-enable** when a
  "was disabled" flag is set.

**Physical meaning**: still not confirmed as reset vs. strobe — this
pass adds *when* it fires, not *what* it does electrically (needs the
driver IC's datasheet).

**Gap classification**: `CAUSAL_PATH_PROVEN`. **Recommended next
tool: none** — the causal question is closed by existing + bounded
static evidence; the remaining gap is a hardware-datasheet fact, not a
firmware one.

## TCC1 / PB22

**Role**: `FUN_00005570(param_1)` is a per-peripheral configuration
function; cases 0–3 configure TC0–TC3's own EIC/PORT setup, **case 7
configures TCC1** (`CTRLA=0x100`, `PER=0x20000000`, `CC0=0x10000`).
All 5 calls (params 0,1,2,3,7) come **exclusively from
`FUN_00006968`**, the startup reference/input boot routine — TCC1 is
configured once per boot, alongside the 4 real motor channels' own
timers, as part of the *same* reference-seek sequence. The only other
path into `FUN_00005570` (via `FUN_00005f8c`) is always called with a
0–3 channel argument in this pass's tracing, never 7 — **no live/wire
command was found that reaches TCC1's own configuration.**

`FUN_0000434c` explicitly **disables** TCC1 (clears `CTRLA.ENABLE`) and
drives PB22 LOW, from the power-button-held halt sequence — implying
TCC1 is expected to be actively running until explicitly silenced.

**Physical meaning**: unknown; functionally points toward "tied to the
boot-time reference-seek move" (synchronization/auxiliary timing) over
a per-command motion channel or external control — an inference from
co-configuration timing, not a proven identity.

**Gap classification**: `GOOD_CONCRETE_REPLAY_CANDIDATE`. Configuration
is now proven; whether TCC1 ever actually **fires at runtime** is not.

> **Recommended query**: reuse `boot-and-hardware-bringup.md`'s
> already-validated `AUTOPILOT_RECIPE` boot run unmodified, and watch
> `0x60ec` (TCC1's IRQ handler) plus the PB22 GPIO MMIO range through
> the *same already-reproduced* startup-reference window that run
> covers. No new harness code needed.

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
  side — both now `CAUSAL_PATH_PROVEN`).
- **Good SMT candidates**: none. PB30/PB31 is now a *worse* SMT target
  than before (4 identical producers, no ambiguity to solve for); the
  other candidates either have no sink or a cheaper concrete-replay
  path.
- **Good concrete-replay candidates**: TCC1/PB22's runtime-firing
  question (see above).
- **Insufficient-sink cases**: external RJ45 STEP/DIR input.
- **Newly discovered command/UI links**:
  - ASCII `'J'` → motor-driver disable.
  - Inbound `F0`/`E0` → motor-driver re-enable (conditional).
  - Motor-connector-presence poll (autonomous, not a wire command) →
    enable/disable.
  - Auto-Mode segment-advance and a boot-time PA22 read → the shared
    PB30/PB31 pulse (joining G-commit and Trigger-reload).
- **Remaining high-value unknowns**: PB30/PB31 and TCC1/PB22 physical
  destinations; full semantics of ASCII `'J'`; PB06/PB07's electrical
  identity; the external RJ45 STEP/DIR mechanism in its entirety.

**Recommended next causal query before LID**: run the TCC1/PB22
concrete-replay query above — the only candidate here with both a
precise, bounded sink and a genuinely open upstream-firing question,
answerable with zero new harness code.
