# Investigation: Can the PB05-Low Config-Reload Alone Cause Motor Motion?

**Question**: `trigger-input-symbolic-reachability.md` closed the
reachability question for the PB05-low path (`0x9226` → `0x8f98`):
firmware-reachable gate values exist, and `0x8f98` reloads the persisted
motor-target config. It does **not** itself issue a move. This slice:
determine exactly what live motor/config state changes as a consequence of
that reload, and whether continuing normal execution afterward ever
naturally reaches `motor_move_commit__CUSTOM`/`FUN_00006fd8`, the
rate/timer update machinery, or any other already-known motor-motion path
— closing the causal edge between "config reload" and "the reported
one-time motor trigger," one way or the other.

**Scope**: disassembly against the persistent `autopilot868` Ghidra cache
(the reload's own downstream code, `FUN_00006b50`/`0x6e4c`/`0x6952`, was
not previously traced past `0x8f98`'s own tail-jump), plus `ConcreteMachine`
(ROM Unicorn) execution reusing this project's own already-proven real
state: a genuine `'+'` mode=`0x62` bulk-push (byte-identical to
`plus-target-distance-roundtrip.md`'s own scenario), whose real side
effects already include gate 1 (`0x20001b38=0x7b`, per
`trigger-input-symbolic-reachability.md`) and a real, non-blank persisted
target (`500`) for channel 0 — not a fabricated distance. No Z3/Crucible
work this slice, per instruction; the solver-tooling finding
(`compact-ram-initialization.md`) is unrelated and not revisited.

## Result, in one paragraph

**The PB05-low reload cannot, by itself, cause the reported motor
trigger — proven, not just argued.** Disassembling the reload's own
downstream chain (`0x8f98` → `0x6e4c` → `FUN_00006b50` → `FUN_00006952`,
none previously traced past `0x8f98`) finds a real, substantial function
(`FUN_00006b50`, 686 bytes) that re-runs `config_loader__CUSTOM`'s bulk
load and then computes a full per-channel motion profile (velocity/period
arrays, a previously-uncharacterized "has a nonzero delta" flag
`0x2000310c[channel]`) for any channel whose reloaded config is valid —
but **never arms** `phase_ramp_state_machine__CUSTOM`'s own per-channel
mode byte (`0x20002318[channel]`), the *only* thing that function's
per-channel loop checks before ever calling `motor_move_commit__CUSTOM`.
An exhaustive xref search finds `0x20002318` has exactly 3 writers in the
whole image: the reload itself (writes `0`, i.e. idle), the state
machine's own internal self-transitions (once already armed), and exactly
one *other*, unrelated ASCII command handler (`0x865a`, disassembly-located
this slice, part of the `'W'` command family, gated on gate 2 — not gate 1
or PB05) that is the **sole** producer of the `0`→`1` (armed) transition
anywhere in this image. **Concretely confirmed**, reusing the real,
already-proven `'+'` push as the predecessor state (not a fabricated
target): PB05 LOW correctly reaches `0x8f98` (288 real memory writes
matching the bulk reload, a real PB30-high/PB31-low GPIO pulse, `channel0`'s
own busy flag set) while an identical-predecessor PB05-HIGH control touches
*none* of the watched state at all — a clean A/B pair — and **neither run,
nor a follow-up call simulating the next main-loop iteration, ever reaches
`motor_move_commit__CUSTOM`**. A separate, clearly-labeled control (**not**
part of the PB05 chain — the one disclosed, non-PB05 byte this slice
changes) confirms the state machine's own commit path is real and reachable
in general: independently forcing the missing arm byte **does** reach
`FUN_00006fd8` two calls later, proving the missing ingredient really is
the sole blocker, not some other silent precondition this harness can't
reach.

## Part 1 — The reload's own downstream chain, disassembled for the first time

`0x8f98`'s tail-jump (`b.w 0x00006e4c`) was previously only followed to its
own entry; this slice disassembles the whole chain:

```
0x8f98  *(0x200025bc+1) = 3                  ; status byte (already known)
0x8fa4  b.w 0x00006e4c                        ; tail-jump

0x6e4c  *0x200000d8 = 0                       ; gate 2 clear (already known)
0x6e54  bl 0x00004b64                          ; config_loader__CUSTOM's real
                                                ; bulk load (target-config-
                                                ; provenance.md) -- re-reads
                                                ; the persisted RAM buffer
                                                ; (0x20003145) into the live
                                                ; struct (0x20001b40), for real
0x6e5c  b.w 0x00006b50                         ; tail-jump

0x6b50  [686 bytes, NEW this slice -- see below]
0x6dfa  b.w 0x00006952                         ; tail-jump

0x6952  digitalWrite(0x31 /* PB30 */, 1)
        digitalWrite(0x32 /* PB31 */, 0)       ; real GPIO side effect,
                                                ; unconditional -- see Part 3
        [tail-calls into digitalWrite itself, which returns via the
         original caller's own LR -- the whole chain is a real function
         call, not a divergent branch]
```

**`FUN_00006b50`** (0x6b50–0x6dfa) does two things, per channel (0–3):

1. **Converts the current live position to a fixed-point double** and
   stores it, unconditionally, into a scratch array (`0x20000850`).
2. **If the channel's reloaded config is valid** (`+0x44 != 0` — true for
   any channel a real `'+'` push has touched, per
   `target-config-provenance.md`'s own blank-fill/`'+'`-push semantics):
   for each mode record (`0x48`-byte sub-array, same layout
   `target-config-provenance.md` already established) whose own delta
   field (`+0x00`) is nonzero, computes a full fixed-point motion profile
   — start/target/velocity arrays (`0x20002908`, `0x20000e90`,
   `0x200014d0`) and a millisecond period array (`0x200025e8`, `delta*1000`)
   — and sets `0x2000310c[channel] = 1`. **If invalid**, it instead zeroes
   those same arrays and leaves `0x2000310c[channel]` untouched.
3. **Unconditionally, for every channel whose config is valid**: records a
   timestamp (`FUN_0000ccdc`'s own return value) into `0x200030cc[channel]`,
   and **clears `0x20002318[channel] = 0`** (phase_ramp's own per-channel
   mode/arm byte) and **`0x20002014[channel] = 0`**.

Exhaustive xref checks (this project's standard method) on the four arrays
this function newly writes (`0x20002908`, `0x20000e90`, `0x200014d0`,
`0x200025e8`) find **no reader anywhere else in the image** — the same
"computed, never consumed" pattern this project has repeatedly found
elsewhere (the ADC baseline, `posA`/`posB`). `0x2000310c` is the one
exception: it has exactly one other reference, a read inside
`motor_move_commit__CUSTOM` itself (see Part 2) — but since that function
is never reached from this path (Part 3), that reader is never exercised
either.

**This closes trigger-input-concrete-path.md's own previously-open
question about `0x20002014[channel]`**: it now has a confirmed real
producer — this reload, which *clears* it, never sets it. (The one *other*
writer of `0x20002014`, at `0x80ec`, is a *different*, not-yet-fully-named
command that *invalidates* the whole config struct — out of this slice's
scope, named for completeness.)

## Part 2 — Why the reload can't arm a move: `0x20002318`'s one other producer

`phase_ramp_state_machine__CUSTOM`'s own per-channel loop (already
established, `0x8e26`–`0x8e66`) reads `0x20002318[channel]` once per
channel per call and dispatches on it: `0`→(idle, no-op unless a separate,
unrelated flag is set — Part "what this slice did not do"), `1`→calls
`FUN_00005274` then unconditionally advances to `2`, `2`→(if two further
idle-state bytes are clear) **computes a distance and calls
`motor_move_commit__CUSTOM`**, then advances to `3`. **This is the *only*
gate this whole subsystem checks before ever calling `FUN_00006fd8`.**

An exhaustive xref search for `0x20002318` finds exactly 3 writers in the
whole image:

| Writer | Value | Role |
|---|---|---|
| `0x6dda` (`FUN_00006b50`, the PB05-triggered reload — Part 1) | `0` | clears to idle |
| `0x8e5a` (`phase_ramp_state_machine__CUSTOM` itself) | `2`, `3`, `9`, ... | internal self-transitions, only reachable once already armed |
| **`0x865a`** (`ascii_dispatcher__CUSTOM`, disassembled this slice) | **`1`** | **the sole arm producer** |

`0x865a`'s own disassembly (`0x8648`–`0x866a`): for every channel whose
reloaded config is valid (`+0x44 != 0`) **and** currently idle
(`0x20002318[channel]==0`), sets `0x20002318[channel] = 1`. It is reached
from the top-level `'W'` command family (`0x84fc`→`0x85d8`,
`cmp r3,#0x57`), specifically the sub-case where the second wire byte is
**neither** `'0'` (→ `0x72ac`, a different handler) **nor** `'1'` (→ the
`0x8624`/gate-1-gated path below) — this slice did not pin down the exact
third wire byte(s) this falls through on (named, not chased, below).
**Crucially: this arming path is gated on `0x200000d8` (gate 2, checked
against `{0,1,2}` at `0x8630`–`0x863e`) — not gate 1, not PB05, not
anything the reload touches.** It is a structurally independent, unrelated
protocol command.

**A second, real, protocol-driven route into the *same* reload chain was
also found this slice** (not previously documented): `0x8624`
(`b.w 0x00006e4c`), reached from the `'W1'` sub-case of the same top-level
`'W'` dispatch, gated on gate 1 `==0x7b` (the *same* real `'+'`-push side
effect PB05 needs) **and** the per-channel device-state array all-zero.
This is a *second* way to trigger the identical reload — out of this
slice's scope (it is not PB05), named for completeness and for whichever
future slice wants to fully characterize the `'W'` command family.

## Part 3 — Concrete confirmation: `tools/unicorn/virtual_link.py pb05`

A new, reusable scenario, `run_pb05_reload_motion_check()`, reuses
`run_plus_target_distance_roundtrip`'s own real `'+'` delivery (Leg 1: the
exact wire bytes `"+1,1,1,0,98,1,0,0,0,500,0,0|"`, byte-identical to
`plus-target-distance-roundtrip.md`) — which, per
`trigger-input-symbolic-reachability.md`, is *also* the real producer of
gate 1. Gate 2 (`9`) is disclosed-seeded per that same investigation's own
already-closed provenance (an all-4-idle check inside this same function,
not re-derived live this slice). No motor target/distance value is
fabricated: the `500` reaching `motor_move_commit__CUSTOM`'s own doorstep
is the real Remote-built delta, carried forward exactly as
`plus-target-distance-roundtrip.md` already established is sound (`.carry()`,
not hand-patched bytes).

```
Leg 1 (real '+' push):    channel0 delta=500 target=500 dirty=1; gate1=0x7b
Leg 2 (PB05 LOW):         status byte -> 3 (0x8f98 reached); 288 real memory
                          writes matching config_loader__CUSTOM's bulk
                          reload; PHASE_MODE stays 0; 0x2000310c[0] -> 1;
                          real PB30-high/PB31-low GPIO pulse (2 MMIO writes);
                          clean return -- motor_move_commit__CUSTOM NOT reached
Leg 3 (PB05 HIGH, same predecessor state): status byte stays 0; ZERO of the
                          watched cells touched at all; clean return, no-op
                          (matches trigger-input-concrete-path.md Part 9's
                          own "ordinary return, no-op" finding exactly)
Leg 4 (a follow-up call, continuing from Leg 2's own resulting state,
       simulating the next main-loop iteration): PHASE_MODE still 0;
                          motor_move_commit__CUSTOM NOT reached
Control (NOT the PB05 chain -- PHASE_MODE[0] independently forced to 1):
       call 1: PHASE_MODE 1 -> 2 (the real self-transition)
       call 2: reaches motor_move_commit__CUSTOM for real
               (FUN_00006fd8(channel=0, const=0x32, distance=0, rate=0))
```

The control confirms the harness genuinely *can* reach
`motor_move_commit__CUSTOM` from this exact predecessor state — so Legs 2–4
never reaching it is a real finding about the PB05 path specifically, not a
harness limitation. (The control's own `distance=0`, rather than the real
`'+'`-pushed `500`, is a separate, genuine observation about how
`phase_ramp_state_machine__CUSTOM`'s own mode==2 branch selects which
target field to use — `struct+0x40`'s own selector byte, not touched by
either the reload or the `'+'` push — **not chased this slice**, since it
belongs to the synthetic control's own arming mechanism, not the PB05
causal chain this slice is scoped to.)

Full command: `tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py pb05`
(also included in `virtual_link.py all`).

## What this slice did not do

- Did not pin down the exact wire bytes for the `'W'`-command sub-case that
  reaches `0x865a` (the arm producer) — named its gating structure
  (`gate2 ∈ {0,1,2}`, third byte neither `'0'` nor `'1'`), not its full
  ASCII syntax.
- Did not characterize the `'W1'` command (`0x8624`) found in passing — a
  second, real, protocol-driven route into the identical reload chain,
  gated on gate 1 (not PB05) — out of scope, named for a future slice.
- Did not chase `0x80ec`'s own command identity (the other writer of
  `0x20002014`, a config-invalidation path).
- Did not chase why the *positive control*'s own `distance` comes out `0`
  rather than the real pushed `500` (a `struct+0x40` mode-selector detail,
  irrelevant to whether the PB05 path itself causes motion).
- Did not characterize PB30/PB31's own role — a real, confirmed GPIO pulse,
  shared between this reload and `motor_move_commit__CUSTOM`'s own real
  epilogue, but structurally distinct from any of the four channels' own
  step/DIR pins (`motor-timer-survey.md`/`pin-index-provenance.md` already
  named those separately, and this slice does not conflate the two).
- Did not chase the physical electrical cause of the jack transient itself,
  per explicit instruction.

## Confidence table

| Item | Status |
|---|---|
| `0x8f98`'s downstream chain (`0x6e4c`→`FUN_00006b50`→`FUN_00006952`) is a real config reload + motion-profile compute + GPIO pulse, ending in a clean return | **CONFIRMED** (full disassembly, not previously traced past `0x8f98`) |
| The reload writes `0x2000310c[channel]=1` for a channel with real nonzero delta, and computes velocity/period arrays with no other reader anywhere in the image | **CONFIRMED** (exhaustive xref) |
| The reload clears (never sets) `0x20002318[channel]` (phase_ramp's own arm byte) and `0x20002014[channel]` | **CONFIRMED** (disassembly + concrete) |
| `0x20002318`'s sole `0→1` (armed) producer is a different, unrelated command (`0x865a`), gated on gate 2, not PB05/gate 1 | **CONFIRMED** (exhaustive xref, 3 total writers found and individually attributed) |
| PB05 LOW (real predecessor state) reaches `0x8f98` and reruns the bulk reload for real | **CONFIRMED concretely** (Unicorn, 288 matching memory writes) |
| PB05 HIGH (identical predecessor state) touches none of the reload's own state | **CONFIRMED concretely** (Unicorn, 0 watched writes, matches the already-documented no-op path) |
| Neither the PB05-low reload nor a follow-up call ever reaches `motor_move_commit__CUSTOM` | **CONFIRMED concretely** (explicit `stop_at` on `0x00006fd8`, 3 separate calls) |
| The state machine's own commit path is real and reachable in general (not a harness limitation) | **CONFIRMED concretely** (the explicitly-labeled, non-PB05 control) |
| A second, protocol-driven (not PB05) route into the identical reload chain exists (`'W1'`, `0x8624`) | **CONFIRMED by disassembly**, not chased further |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by exhaustive xref)
for the reload's own structure and `0x20002318`'s complete producer list.
Level 2 (concrete, Unicorn, via a new reusable `virtual_link.py pb05`
regression) for the full PB05-dependent causal result, built entirely on
already-proven real state (a genuine `'+'` push, not a fabricated target).
No level-3 (solver-confirmed) claim is made or needed — this slice's
success criterion (prove or disprove the causal chain) does not depend on
Z3, per instruction.
