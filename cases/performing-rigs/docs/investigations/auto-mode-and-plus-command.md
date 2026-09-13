# Auto Mode and the '+' Command — Current Model

`'+'` is a real, previously-undocumented Remote-to-AutoPilot protocol
command that persists a motor-target delta. This document consolidates
four investigations that together trace its full lifecycle: the Remote
boot/UI event that triggers a bulk `'+'` push, the real Remote-side
function that builds the `'+'` wire frame and every real UI path that
calls it, and a complete, concrete round trip from a real Remote `'+'`
send through AutoPilot's persistence to a real motor move-commit call.

## Current model

### The two real triggers for `FUN_0000c440`'s bulk push

`FUN_0000c440` is the Remote's own `'S'`-query function (sends `"S|"`,
waits for a `'P...'` response). Its tail bulk-pushes `'+'` (mode `0x62`)
for every channel with nonzero stored data, then unconditionally sends
`MC4`. This whole tail fires whenever a single, real, always-first
action inside the function — sending `"S|"` and receiving a clean
`'P'`-prefixed response within ~200 ticks — succeeds; the response's
actual value never matters, only its shape.

There are exactly four real callers of `FUN_0000c440` anywhere in the
compiled image (confirmed both by Ghidra's call graph and an independent
full-image Thumb-2 branch decoder), reducing to two real trigger events:

- **Primary — the Remote's own boot sequence.** `Reset_Handler ->
  FUN_00016900 -> FUN_0000fdf0` (a splash-screen/backlight-fade routine
  that also triple-broadcasts `"R0|"`) calls `FUN_0000c440(0)` **exactly
  once, unconditionally, per physical power-on**, immediately before the
  Remote's own `"&|"` firmware-version query and its main loop. Every
  branch on this path is unconditional; each function in the chain has a
  single, unique caller anywhere in the image.
- **Secondary — a radio-silence re-arm.** `FUN_00010ce4` (the Remote's
  inbound AutoPilot-byte dispatcher) calls `FUN_0000c440(0)` again when a
  byte in `['a','x']` or `'B'` arrives, but only while a "first sync
  done" latch (`0x20000fc9`) is `0`. That latch is set `1` on success and
  reset to `0` only by a genuine **~5000-tick (multi-second) gap in
  inbound radio activity** (measured against the last-RX-activity
  timestamp) — a real reconnect/link-loss re-arm, not a periodic timer.

**A cold boot alone sends zero `'+'` frames.** The bulk-push loop is
gated by a separate flag, `*0x20000fa0 != 0` ("has real programmed
data"), written only by interactive UI functions (`FUN_0000e670`, the
Auto-Mode screen state machine; `FUN_0000d218`, not traced further) —
**never by the boot sequence**. So a factory-fresh or freshly power-cycled
Remote's boot-time `FUN_0000c440(0)` call reaches the push loop with the
flag still `0` and sends nothing; only `MC4` is guaranteed on every real
trigger of this mechanism. The per-channel record array itself *is*
loaded from Remote-local flash storage earlier in the same boot sequence
— data can be genuinely present by push-loop time, but the loop is gated
on the separate flag, not on the data's presence.

A structurally distinct sibling exists and is **not** the same
mechanism: `FUN_0000b6f0`, called from the pump function `FUN_0000c340`
roughly every 250 ticks once first-sync is done and Quick Setup isn't
active, also bulk-pushes `'+'` for channels with data — but its own tail
calls `FUN_000049c4`-then-`FUN_00006800` and **never** sends `MC4`.
`FUN_0000c440`'s push+`MC4` combination and `FUN_0000b6f0`'s periodic
push are two genuinely different functions with different triggers and
different downstream effects; they are not conflated here.

### The real Remote-side `'+'` sender and its real UI callers

`FUN_000049c4` is the sole function anywhere in the Remote image that
writes the literal `'+'` byte into an outgoing frame (found by a
full-image scan for `movs r?,#0x2b`, not by decompiler naming). It builds
exactly the wire schema this project's AutoPilot-side analysis already
reconstructed independently: `'+'`, a units digit, `confirm1`,
`confirm2`, `channel`, a `mode` field, then per-record fields, a rolling
1–9 sequence digit, and `'|'`. Every real call site passes
**`confirm1 == confirm2`** — a real invariant this sender enforces, not
a coincidence of AutoPilot's own requirement. For the single-record
form, the delta is computed locally as `target_start(+0x10) -
target_computed(+0xc)` from the Remote's own per-channel-per-mode
struct — the identical `+0xc`/`+0x10` convention the AutoPilot side uses
— independent cross-confirmation that both firmwares agree on the same
struct layout.

**There are exactly four real `'+'` call sites in `FUN_0000e670`** (the
Auto-Mode configuration screen state machine), not three as an earlier,
decompile-only pass found — screen 5 has two mutually-exclusive branches
with identical arguments that were originally read as one:

| Site | Address | Screen | Gate | Args `(confirm1,confirm2,channel,param_4,mode)` |
|---|---|---|---|---|
| A | `0xf40c` | 5 | segment record still empty | `(1,1,ch,1,0x00)` |
| B | `0xf5a6` | 5 | no channel anywhere has data | `(1,1,ch,1,0x00)` |
| C | `0xf60c` | 10 | confirmed flag set | `(1,1,ch,2,0x14)` |
| D | `0xf68c` | 9 | confirmed flag set | `(1,1,ch,0,0x14)` |

**Screen 5 (A/B) is closed end to end**: the on-screen text (`"Click"` /
`"to rec A"`–`"to rec D"` / `"Long-click to end"`), the exact input
gesture, and the exact wire bytes are all CONFIRMED. The gesture is a
**short jog-wheel click**, not a long one — a long click ends recording
without sending `'+'`; the block that actually writes the recorded point
(the same `+0xc`/`+0x10` delta convention `FUN_000049c4` reads back out)
runs only on a short click.

Screens 9 and 10 (C/D) are confirmed to render `"RUNNING"` after a
successful send, but their **pre-send highlighted row label is only
PROBABLE** — extrapolated from the row-index arithmetic of the other
Auto-Mode screens (6→row 3 `SPEED`/`DURATION`, 7→`RAMP`, 8→`DELAY`,
9→`LOOP`), since screens 9/10 make no row-indexed render call of their
own to observe directly.

Cross-referencing the Remote's embedded UI strings against the user
manual's Auto Mode section (channels, A/B/C/D points, segment
parameters, persisted after power-off) gives a **PROBABLE — not
proven —** mapping: `'+'` at these interactive sites corresponds to the
user confirming/saving a programmed Auto Mode move segment. No string or
comment ties a specific packet to a specific manual page; this rests on
matching field structure, matching UI terminology, and the call sites'
position inside a confirmation-gated flow that also implements an
independently-confirmed "clear a stored segment" dialog.

### The critical distinction: interactive confirm screens vs. the bulk push that actually arms a target

**This is the load-bearing correction this cluster establishes, and it
must not be blurred:** the four interactive Auto-Mode `'+'` call sites in
`FUN_0000e670` (modes `0` and `0x14`) and the mechanism that actually
arms a drivable AutoPilot motor target are **not the same event.**
AutoPilot's `'+'` handler only crosses its compute+persist threshold for
mode values `>50`. The interactive Auto-Mode screens never send that mode
— they send `0` or `0x14`. The **only** real `'+'` call site that uses
`mode=0x62` (98), which is both `>50` and independently established as
the value that also drives AutoPilot's live-position resync, is the
**`'S'`-handler's bulk config-push tail** (`FUN_0000c440`, Part 1 above):
loop every channel with nonzero stored data, send `'+'` with
`confirm1=confirm2=1`, `param_4=0`, `mode=0x62`, wait for an ack, then
unconditionally send `MC4`.

The concrete round trip below (`auto-mode-and-plus-command.md`)
exercises exactly this bulk-push call, reproducing `FUN_0000c440`'s real
call parameters — **not** an interactive Auto-Mode segment-confirm call.
Clicking through the Auto-Mode UI screens writes delta fields into the
Remote's own local record and, once acked, may cause `FUN_0000e670` to
set the `0x20000fa0` "has real programmed data" flag consumed by the
bulk-push gate — but by itself it does **not** cross AutoPilot's
persist threshold. The manual/UI-label identity of what actually fires
the `'S'`-handler's bulk push (most plausibly a reconnect or periodic
status-refresh event, since it rides the `'S'` handler) stays PROBABLE,
exactly as the source investigations left it — it is not pinned to a
specific manual page or button press.

### The full concrete round trip

`'+'` (mode `0x62`, from the bulk-push path) → AutoPilot computes and
persists a channel target → Remote's real `'G'` request → AutoPilot's
real state machine resolves the target and calls `FUN_00006fd8`,
crossing its real move-commit threshold. See Evidence and Test/repro
below for the exact values.

## Evidence

**`FUN_0000c440`'s two trigger paths** (Part above): boot path
`Reset_Handler(0x16794) -> FUN_00016900 -> FUN_0000fdf0 -> FUN_0000c440(0)`,
unconditional, confirmed by full disassembly of all three functions
(zero conditional branches skip any hop, each function has a single
unique caller). Re-arm path: `FUN_00010ce4`'s `['a','x']`/`'B'` byte
dispatch, gated on `*0x20000fc9 == 0`, reset to `0` by
`FUN_00016840()` elapsed time vs. `*0x20001734` exceeding **~5000
ticks** with no has-ever-sent/Quick-Setup flags set. The bulk-push gate
itself: `cmp r4,#0; beq 0xc458` at `0xc9a4`–`0xc9a6`, where `r4` (`cVar24`)
is set purely by "did a clean `'P'`-response arrive within ~200 ticks,"
independent of the response's value. `MC4` (`FUN_00005a8c(4)`) is sent
from a single convergent instruction at `0xcb4a`, reached whether the
push loop completes, aborts on a failed ack, or is skipped entirely
(`*0x20000fa0 == 0`) — i.e. `MC4` is unconditional once `cVar24=1`,
regardless of the push loop's outcome.

**Sibling `FUN_0000b6f0`**, not conflated: called from `FUN_0000c340`
roughly every 250 ticks once `*0x20001810==0` (no Quick Setup),
`*0x20000fa0==0`\*, `FUN_00005450()!=0` (some channel has data), and
`*0x20000fc9!=0` (first sync already done, \*note: same flag
`FUN_0000c440`'s own loop requires nonzero — the two functions read it
with opposite polarity for their own separate gates). Confirmed by full
disassembly of its own tail that it never reaches `FUN_00005a8c(4)`.

**`FUN_000049c4`'s wire frame fields**: `buffer[0]='+'`; `buffer[1]`
= units digit; then `confirm1`, `confirm2`, `channel`, and a `mode`
field via the shared numeric encoder `FUN_000043b0`; for the
single-record form (`param_4==1`), four more fields including
`target_start(+0x10) - target_computed(+0xc)`. `confirm1==confirm2` at
every one of the four real call sites (all pass `1,1`). Observed mode
values: `0`, `0x14` (interactive `FUN_0000e670`), `0x62` (bulk push,
`FUN_0000c440`).

**The four real `'+'` call sites in `FUN_0000e670`** (screens and exact
gesture): table above. Screen 5's two sub-branches diverge on
`*0x20001099` (a "first point already taken" flag) and
`FUN_00005450()` ("does any channel have data"), both converging on the
identical `'+'` semantics and both landing on screen 10 afterward. A
representative captured screen-5 frame: `b'+1,1,1,2,0,1,0,50,0,0,0,0|'`.
Screens 9/10 representative frames (seeded channel 2, three segments):

```
C (screen 10, mode 0x14): b'+2,1,1,2,20,1,0,0,0,0,0,0|'
D (screen 9,  mode 0x14): b'+2,1,1,2,20,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'
```

For the identical seed, the bulk-push frame (mode `0x62`) is
byte-identical to site D except the mode digit:
`b'+2,1,1,2,98,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'` — a direct,
wire-level illustration of "same record data, different mode digit,
different AutoPilot-side consequence."

**The mode=0x62 threshold and the captured round-trip frame**: `mode=0x62`
(`0xcb0e: mov.w r11,#0x62`) is the fixed mode value `FUN_0000c440`'s bulk
push always uses, and is the one mode value confirmed (in prior,
AutoPilot-side work this cluster does not re-derive) to cross AutoPilot's
`>50` compute+persist threshold and also trigger its live-position
resync. The full concrete round trip's captured frame:

```
"+1,1,1,0,98,1,0,0,0,500,0,0|"
```

confirm1=1, confirm2=1, channel=0, mode=98(0x62), delta=500 — produced by
`FUN_000049c4` given a disclosed record0-delta seed of 500 (representing
"the user has already recorded a real A→B segment").

**The resulting distance=500 move-commit call**: AutoPilot's real `'+'`
handler chain (`FUN_00008258 -> FUN_000046c8 -> FUN_00004ca8 ->
FUN_000043f0`) computes channel-0 record-0 `delta(+0x0)=500`,
`target(+0xc)=500` (`start(0) + delta(500)`), and sets the
persisted-buffer dirty flag `=1`. The Remote's real G-request builder
(`0xb680`) then produces `"G010|"` (channel=0, type=1). AutoPilot's real
`FUN_00007e2c` state machine resolves `distance = target(500) -
live_position(0) = 500` and calls `FUN_00006fd8(channel=0, const=0x1e,
distance=500, rate=0)`, whose own real `if (8 < abs(distance))` check
takes the real-move branch — move-committed flag (`0x20002524[0]`) `=1`
— the opposite of the `distance=0` no-op result other investigations in
this project found for a cold/unconfigured device. **500 is the same
number, unmodified, through every real intermediate computation** — the
wire byte, the delta field, the computed target, and the distance
`FUN_00006fd8` receives.

## Test / repro

`tools/unicorn/virtual_link.py plus` (also included in `virtual_link.py
all`) demonstrates the full round trip above using both firmwares'
real, unmodified code — a real-frame-capture leg and a real-delivery leg
at each hop, exactly like this project's existing `run_ampersand_roundtrip`
/`run_g_ack_roundtrip`/`run_s_roundtrip` fixtures. All five assertions
(delta, target, dirty flag, distance, move-committed flag) are checked
against literal values a real firmware execution produced; no
motor-target RAM was hand-patched.

It uses two disclosed harness boundaries in place of a full real boot
(a fresh boot from `Reset_Handler` was not exercised end-to-end for this
scenario — see Open items):

1. **A representative Remote-side "already-recorded segment" seed.** The
   Remote's channel-0/record-0 delta field is seeded to `500`, standing
   in for a prior, real Auto-Mode UI session having already recorded that
   segment (the record itself, and what wrote it, was not re-derived —
   see Open items). This is the same evidence tier this project already
   uses elsewhere for representative prior UI state.
2. **Directly seeding `FUN_00007e2c`'s arm byte** (`0x200025e1=2`) to the
   exact value a real `'G'` dispatch is independently confirmed (by
   disassembly, at `0x83de`) to set. `FUN_00007e2c` is normally driven,
   once per call, from the real main loop only after `MC4` — reachable
   only past a very large, unresolved boot-time SERCOM/radio instruction
   cost. Seeding the arm byte directly reaches the identical real code
   the state machine would run, without fabricating any value the state
   machine itself computes.

## Open items

- **The exact manual/UI label correspondence for the screen-9/10 call
  sites** (C: screen 10, mode `0x14`; D: screen 9, mode `0x14`) stays
  **PROBABLE** — their pre-send highlighted row is extrapolated from
  the other Auto-Mode screens' row-index pattern, not directly observed;
  closing it needs tracing the highlight-cursor variable (`0x20000fae`)
  into the render function's own selection logic, or a concrete run
  through a real boot's row/cursor state.
- **What writes the Remote's own local per-channel record data before
  `'+'` sends it** is not directly confirmed — presumably the jog-wheel
  parameter screens (6–8) of `FUN_0000e670` itself, given the state
  machine directly reads and writes the same struct offsets, but this
  was not traced.
- **Concretely reaching `'+'`'s own dispatch from a genuinely fresh
  boot** remains blocked by a real, unresolved SERCOM/radio device-probe
  instruction cost between `MC4` and the main loop reaching `FUN_00007e2c`
  under its own normal drive — the round trip above enters that state
  machine directly instead, as a disclosed boundary.
- Also genuinely unresolved and not chased further in the source
  material: what clears `*0x20000fa0` after a real `'+'` push (so a
  later reconnect's bulk push would find it freshly cleared);
  `FUN_0000d218`'s own role as a second `0x20000fa0` writer; and a
  documented discrepancy between the screen-5 captured frame's `+0x14`
  field (`50`, observed on the wire) and the `+0x10 - +0xc` delta (`500`)
  one prior document attributed to that same branch — flagged, not
  reconciled.
