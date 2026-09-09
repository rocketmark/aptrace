# Investigation: A Concrete, End-to-End `'+'` -> Motor-Target -> `G` Mode-1 -> `FUN_00006fd8` Distance Round Trip

**Question**: `plus-command-remote-provenance.md` established, statically,
that a real Remote sender (`FUN_000049c4`) builds `'+'`, called from the
Auto-Mode configuration screen state machine and from a bulk config-push
path, and that `persistent-record-motor-target-mapping.md` established,
statically, that a real `'+'` write (mode `>50`) makes AutoPilot compute
and persist a motor target. Neither slice completed a concrete
confirmation: the first didn't need one, the second's concrete attempt
was blocked by a newly-discovered, very expensive boot-time `SERCOM`/
radio stall. This slice: close one concrete, end-to-end path from a real
Remote action through to a real, nonzero `FUN_00006fd8` move-commit
distance, using the Remote's own real packet builders throughout and the
project's existing `run_concrete.py`/`virtual_link.py` machinery — no new
execution framework, no full boot, no fabricated distance.

**Scope**: concrete Unicorn execution exclusively (the schema/provenance
questions were already answered statically in the two prior slices).
Every byte and value asserted below was produced by real, unmodified
firmware code; every seed is disclosed explicitly, with its evidence
tier stated.

## Result

**Closed.** `tools/unicorn/virtual_link.py plus` (also part of `... all`)
demonstrates, entirely with real firmware code:

```
Remote FUN_000049c4('+', confirm=1/1, channel=0, mode=0x62)
  -> real wire frame: "+1,1,1,0,98,1,0,0,0,500,0,0|"
  -> AutoPilot's real '+' handler (FUN_00008258 -> FUN_000046c8 ->
     FUN_00004ca8 -> FUN_000043f0)
  -> channel-0 record-0: delta(+0x0)=500, computed target(+0xc)=500,
     persisted-buffer dirty flag=1
  -> Remote's real G-request builder (0xb680), channel=0, type=1
  -> real wire frame: "G010|"
  -> AutoPilot's real G-mode-1 state machine (FUN_00007e2c)
  -> FUN_00006fd8(channel=0, const=0x1e, distance=500, rate=0)
  -> FUN_00006fd8's own real distance-threshold check takes the
     real-move branch (not the documented <=8 no-op): move-committed
     flag (0x20002524[0]) = 1
```

**`500` is the same number end to end** — the wire-supplied delta the
Remote's real code computed from a disclosed seed, unchanged through
every real intermediate computation, arriving at `FUN_00006fd8` as a
real, nonzero, threshold-crossing distance. This is the first time this
project has driven `FUN_00006fd8` past its `>8` real-move branch with a
value traceable to a Remote-side send, rather than `0` (mc4-transition.md)
or an unreachable state (persistent-record-motor-target-mapping.md).

## The chosen call site, and its label

Per `plus-command-remote-provenance.md`, only ONE of `'+'`'s four real
call sites uses a mode value (`0x62`) that crosses AutoPilot's own `>50`
compute+persist threshold: the **bulk "push all channels' stored
config" path**, inside the already-known `'S'`-handler (`FUN_0000c440`).
The three interactive Auto-Mode screen confirmations (`FUN_0000e670`,
modes `0` and `0x14`) write the delta field but do **not** themselves
advance it into a live target — that requires this separate, later
event. This scenario reproduces `FUN_0000c440`'s real call parameters
exactly (`confirm1=confirm2=1`, `param_4=0`, `mode=0x62`), **not** the
interactive-confirm call. Per this and the prior slice's own confidence
scale: this is **CONFIRMED Remote-generated** and **CONFIRMED reachable
from a real, disassembly-verified code path** (the `'S'`-handler's bulk
push), and **CONFIRMED, mechanically, as "the real path that actually
moves a delta into a live target"** — but it is explicitly **not** the
"user clicks confirm on segment A→B" story; that label remains
**PROBABLE**, exactly as the prior slice left it. The strongest honest
label for *this* scenario's own trigger is: **a confirmed, real
"AutoPilot config resync" event** (most plausibly fired on reconnect or
periodic status refresh, since it's driven by the `'S'` handler), not a
single, momentary Auto-Mode segment-save button press.

## What's real firmware output vs. disclosed harness input

| Value | Class | Where it comes from |
|---|---|---|
| `"+1,1,1,0,98,1,0,0,0,500,0,0\|"` (the exact wire bytes) | **Real firmware output** | `FUN_000049c4`, executed concretely, given the seed below |
| `500` (channel0 record0 delta) | **Real firmware output** | Copied by `FUN_000046c8` from the wire byte the Remote itself encoded |
| `500` (channel0 record0 computed target) | **Real firmware output** | `FUN_00004ca8`: `target = start(0) + delta(500)` |
| dirty flag `=1` | **Real firmware output** | `FUN_0000977c`'s own change-detection, exercised by `FUN_000043f0` |
| `"G010|"` (the exact wire bytes) | **Real firmware output** | `0xb680`, executed concretely, given the seed below |
| `distance=500` at `FUN_00006fd8` | **Real firmware output** | `FUN_00007e2c`: `distance = target(500) - live_position(0)` |
| move-committed flag `=1` | **Real firmware output** | `FUN_00006fd8`'s own real `if (8 < abs(distance))` branch |
| Remote record0 delta seed = `500` | **Disclosed harness input** | Stands in for "the user has already recorded a real A->B segment" — representative prior UI state, the same evidence tier as `REMOTE_G_WAKE_FLAG` elsewhere in this project |
| G-state-machine arm byte (`0x200025e1=2`) seeded directly | **Disclosed harness boundary** | The exact value a real `'G'` dispatch is independently confirmed (by disassembly, at `0x83de`) to set — bypassing the real MC4-unlocked main loop this state machine is normally driven from, not fabricating any value the state machine itself computes |
| Live position (`0x20002064[0]=0`) | **Disclosed, but not arbitrary** | Cold-RAM value; matches every prior slice's own finding that live position is genuinely `0` on a device that has never completed a real move |

**No motor-target RAM was ever hand-patched.** Every byte in
`AUTOPILOT_CH0_STRUCT` at the point `G` reads it was produced by the
real `'+'` delivery in the same investigation, carried forward into the
next process via `--seed-mem` with the exact bytes dumped from the
prior run — the same evidence tier as `nvm-param-and-full-roundtrip.md`'s
own "patch a firmware-image copy with the bytes a real prior run
produced" precedent, just crossing a RAM boundary instead of a flash
one.

## Concrete techniques this slice needed, and why

1. **`FUN_000049c4` does not itself call the TX wrapper.** Unlike every
   other Remote sender this project has captured (`0xba98`, `0xb680`,
   `0xc440`), `FUN_000049c4` only builds the frame into the shared
   outgoing buffer (`0x2000183c`) and returns; its real callers
   (`FUN_0000e670`, `FUN_0000c440`) separately hand it to `0x58a8` via
   the already-known ack/retry function (`0xb59c`). Confirmed by
   disassembly (its return, `0x4b32`, is reached without ever executing
   a `bl 0x58a8`) — `capture_tx_bytes`'s TX-wrapper-stop convention
   doesn't apply here, so this scenario stops at the function's own real
   return instead and reads the buffer directly.
2. **A 5th AAPCS argument on the stack, for a function entered directly.**
   `FUN_000049c4`'s `mode` parameter is its 5th argument, passed by the
   real caller on the stack at `[sp+0]`. Entering directly at the
   function (bypassing the real call) means this project's existing
   `run_concrete.py --sp` flag must be used to place a custom stack
   pointer with the value pre-seeded there — `run_concrete.py` already
   supported this; `virtual_link.py`'s own `run_concrete`/
   `capture_tx_bytes` wrappers did not expose it and now do (a minimal,
   backward-compatible parameter addition, not a new mechanism).
3. **`--reg` values are hex, not decimal.** A first attempt seeded
   `r0=28` (intending decimal 28, the real `'+'` frame's length) but
   `run_concrete.py`'s `--reg NAME=HEX` parses hex — `28` decoded as
   `0x28`=40, silently reading 12 bytes past the real frame and
   corrupting a real retransmission-dedup guard inside the `'+'` handler
   (`if (*DAT_00008548 == packet[param_1-1]) ...`), causing a spurious
   early return. Fixed by passing `0x1c` (28 in hex) — a harness-
   invocation bug, not a firmware finding, but worth recording precisely
   since it silently produced a *plausible-looking* early exit rather
   than a crash.
4. **`G`'s two digit fields are `(type, channel)` on the wire, not
   `(channel, type)`.** `g-ack-roundtrip.md`'s own `reg_seed=[("r0",0),
   ("r1",0)]` never distinguished order, since both were `0`. Setting
   `r1=1` (intending "type") produced `"G100|"` — decoding to
   channel-digit`='1'`, type-digit`='0'` — the *opposite* of intended.
   Corrected empirically (`r0=1, r1=0`) once the real wire bytes made the
   order observable; not previously wrong in `g-ack-roundtrip.md` itself
   (which never needed to distinguish them), so no correction to that
   doc is needed — recorded here as the first case that did.
5. **Reaching `FUN_00006fd8` needs the state machine called twice.**
   `FUN_00007e2c` is a plain, non-looping function with an internal
   `0`/`1`/`2` state byte (`0x200025e0`): one call resolves the real
   target from the config struct and advances state `0->1`; a second
   call (state `1`) is the one that actually calls `FUN_00006fd8`. Both
   calls read the `G` request's channel/type digits directly from the
   shared RX buffer, which only needs to be seeded once. This state
   machine is normally driven, once per call, by the real
   `FUN_000093fc` main loop — reachable only after `MC4`, which
   (per `persistent-record-motor-target-mapping.md`) currently costs an
   unresolved, very large instruction budget from a fresh boot. Entering
   `FUN_00007e2c` directly, twice, with its own real arm byte
   disclosed-seeded to the value a real `G` dispatch is confirmed to set,
   reaches the identical real code with none of that cost — a
   deliberate, disclosed harness boundary (see the table above), not a
   fabricated result.
6. **Entering a function directly with a fabricated `LR` needs a real,
   decodable return address, with the Thumb bit set.** `run_concrete.py`'s
   `--stop-at` hook only intercepts *after* Unicorn has already
   decoded the instruction at that address — pointing a synthetic `LR`
   at data (flash offset `0x4000`, the vector table) makes the real
   `pop {...,pc}`/`bx lr` land there and crash with `UC_ERR_INSN_INVALID`
   before the stop-at check ever fires; leaving out the Thumb bit
   (`0x8a34` instead of `0x8a35`) makes `bx lr` switch to ARM mode and
   crash the same way, even at an address containing perfectly valid
   Thumb code. Fixed by reusing this module's own already-proven,
   valid-Thumb-code entry point (`AUTOPILOT_RX_ENTRY`, with the Thumb bit
   set only in the register value, not the `--stop-at` argument) as a
   `RETURN_SENTINEL` — a reusable pattern now available to any future
   scenario that needs to enter a real function directly without a real
   caller.
7. **A real, uninitialized-display-object dereference**, distinct from
   the ones `g-ack-roundtrip.md` already named: `0xb216` (reached from
   the `'+'` handler's own unconditional display-refresh tail). Stubbed,
   same class and same justification as `AUTOPILOT_G_HANDLER_STUB_CALLS`
   — a real, but display-only, callee whose return value is unused by
   the code path this investigation cares about.

## The reusable regression fixture

`tools/unicorn/virtual_link.py`'s new `run_plus_target_distance_roundtrip()`
(CLI: `virtual_link.py plus`, also included in `virtual_link.py all`)
encodes the full five-leg chain above as one script, following this
project's existing convention (a real-frame-capture leg, a real-delivery
leg, asserted at every step) — not a new framework, an extension of the
same one `run_ampersand_roundtrip`/`run_g_ack_roundtrip`/
`run_s_roundtrip` already use. All five assertions (delta, target, dirty
flag, distance, move-committed flag) are checked against the literal
values a real, unmodified firmware execution produced.

## What this does not (yet) demonstrate

Per the task's own explicit scope, this slice stops at `FUN_00006fd8`'s
real move-commit decision. The **subsequent** phase-machine/ramp-timer/
ISR/GPIO chain (`FUN_00008e18`'s phase state machine ->
`FUN_00005274`/`FUN_00006338` -> the already-proven
`FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898` GPIO-pulse chain) is
**not re-verified this pass** — it is the same, already independently
concretely-proven mechanism `motor-timer-survey.md` and
`i-command-motor-chain.md` established on its own terms (real timer
ISRs, real GPIO toggles, all four channels). Closing the *remaining*
gap — chaining a real distance value like this slice's `500` all the
way through `FUN_00008e18`'s own phase machine into an observed GPIO
event in one continuous concrete run — was investigated briefly
(`FUN_00008e18` is a substantially larger, more stateful function than
`FUN_00007e2c`, with its own per-channel loop and multiple further
preconditions not yet resolved) and set aside as the next slice's target
rather than chased further here, per the task's own scope discipline.

## Channel/timer/GPIO identity, kept distinct

This slice only establishes the **logical channel** identity (channel
`0`, the value both the `'+'` and `G` frames carry and the value
`FUN_00006fd8` receives as its own `channel` argument). It makes **no
new claim** about which physical Motor 1-4 connector or which TCx timer
channel this logical channel `0` maps to — that mapping was already
established, independently, in `motor-timer-survey.md`/
`pin-index-provenance.md` (logical channel 0 -> TC0 -> PB10, per that
prior work) and is not re-derived or re-asserted here.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `FUN_000049c4` produces the exact real wire bytes for `mode=0x62`, `param_4=0`, given a disclosed record0-delta seed | **Confirmed concretely** |
| AutoPilot's real `'+'` handler computes `target=500` and dirties the buffer, given the real wire bytes | **Confirmed concretely** |
| `0xb680` produces the exact real `G010\|` bytes for `(type=1, channel=0)` | **Confirmed concretely** |
| AutoPilot's real `FUN_00007e2c`/`FUN_00006fd8` path receives `distance=500`, given the real, carried-forward channel-0 struct state | **Confirmed concretely** |
| `FUN_00006fd8` itself takes the real `>8` move branch (not the documented `<=8` no-op) for this distance | **Confirmed concretely** (move-committed flag observed) |
| This specific scenario's trigger is the `'S'`-handler's bulk config-push, not an interactive Auto-Mode segment-confirm button | **Confirmed** (disassembly-matched call parameters) |
| The manual-page/UI-label identity of *this* trigger (what user action causes an `'S'`-driven resync) | **PROBABLE at best** — most plausibly a reconnect/status-refresh event, not independently pinned to a specific manual page this slice |
| The phase-machine/timer/ISR/GPIO continuation for *this* specific distance value | **Not re-verified this slice** — relies on the already-independently-proven general mechanism from `motor-timer-survey.md`/`i-command-motor-chain.md`, not a fresh concrete trace from `500` all the way to a GPIO toggle |

## Evidence level

Level 2 (concrete, Unicorn) throughout, for every claim in the "Result"
and "What's real firmware output" sections — five real executions, each
asserted against the literal values produced, not decompiled or
inferred. Level 1 (static, disassembly-confirmed) for the "which call
site" and "which mode value" provenance claims, carried forward
unchanged from the prior two slices.

## Next step

Extend `FUN_00007e2c`'s direct-entry technique to `FUN_00008e18` (the
phase state machine), to chain this same `500`-distance scenario all the
way to a concretely observed GPIO pulse — the natural conclusion of the
"ideal acceptance result" this slice's task described, not reached this
pass due to `FUN_00008e18`'s own additional, not-yet-resolved
preconditions (a per-channel loop and further internal state this
investigation did not have time to trace to the same level of
confidence as `FUN_00007e2c`).
