# Investigation: What Schedules the AutoPilot's `MT<...>|` Send

**Question**: `mc-command-remote-provenance.md` closed the Remote side of
Quick Setup end to end but left one edge open: *what causes the AutoPilot
firmware to execute the code that probes motor-connector presence and
sends `MT<b0><b1><b2><b3><x>|` to the Remote?* The enclosing region (flash
`0x7232`-`0x7514`) was unattributed in the Ghidra cache — no containing
function, no known caller. This slice closes that edge.

**Scope**: disassembly against the persistent `autopilot868` Ghidra cache,
an independent full-image Thumb-2 branch/call decoder (self-written this
slice, not trusted from Ghidra — see "Methodology" below), and concrete
execution (`ConcreteMachine`) to produce real `MT` frames from disclosed
connector-presence inputs. No AutoPilot-side or Remote-side conclusion
from any prior slice is revisited; this document only adds the missing
edge and the field-level detail that falls out of tracing it.

## Confidence scale

Same as `docs/ui/action-command-map.md`: **CONFIRMED** (disassembly and/or
concrete execution against real, unmodified firmware) / **PROBABLE** (a
real finding, but a specific interpretation rests on correlation rather
than proof) / **UNKNOWN**.

## Methodology note: why a second branch decoder

Ghidra's cached call-graph export (`callers`/`xrefs`) reports **zero**
callers for any address in the `0x7232`-`0x7514` region — not because
nothing calls in, but because every real entry into it is an unconditional
32-bit branch (`B.W`, Thumb-2 T4 encoding), not a `BL`/`BLX`. Ghidra's own
static analysis never built a function object here, so its call graph has
nothing to export for these addresses even though real control flow reaches
them. A from-scratch Thumb-2 decoder (`scan_all_branches.py`, this slice,
not persisted as a project tool — see "Tooling note" below) was written to
independently find every `B`/`Bcc`/`B.W`/`Bcc.W`/`BL`/`BLX` in the compiled
image whose target lands in a given address set. It was cross-validated
before being trusted: run against known targets (`0x7514`), it reproduced
exactly the two `BL` sites this project's own `containing()` output already
implied, with no false positives or omissions.

## Part 1 — Recovered control-flow structure

Ghidra's function-boundary model for this stretch of flash is misleading in
a specific, now-understood way: **`motor_move_commit__CUSTOM`
(`0x00006fd8`, size 602) is correctly bounded** — it genuinely ends with a
real `pop.w {r4,r5,r6,r7,r8,r9,r10,r11,pc}` at `0x7230` (disassembly-
confirmed) — but the region immediately following is not one function, not
dead code, and not part of `motor_move_commit`. It is **three separate,
Ghidra-unattributed regions**, recovered by disassembly and the independent
branch scan:

| Range | Content | Real entry mechanism |
|---|---|---|
| `0x6fd8`-`0x7230` | `motor_move_commit__CUSTOM` (Ghidra-named, correctly bounded) | (existing callers, unchanged) |
| `0x7232`-`~0x72ab` | `motor_move_commit`'s own literal pool (data — 2 bytes NOP + 2 bytes NOP.W padding, then pool words) | not code |
| `0x72ac`-`0x7319` | An unattributed "commit up to 4 channel moves" loop (two mutually exclusive branches, each 4 iterations, each calling `motor_move_commit` once per iteration — 8 real callers of `0x6fd8` total, previously showing in `callers 0x6fd8` output as "(unattributed — possibly a tail-jump target)") | `B.W` (tail-jump) from **`0x000085e6`, inside `ascii_dispatcher__CUSTOM` (`FUN_00008258`)** — a real but **entirely separate** command-dispatcher tail-call, structurally unrelated to `MT`. Named here only so it is not mistaken for part of the `MT` chain; not traced further this slice (out of scope: this document's question is the `MT` sender, not every occupant of this flash gap). |
| `0x731c`-`0x7333` | That routine's own literal pool | not code |
| `0x7334`-`0x74dd` | **The connector-presence-probe + `MT`-frame-builder function** — the actual subject of this investigation | `B.W` (tail-jump) from **`0x00007794`, inside `FUN_00007770`** |
| `0x74e2`-`0x74ed` | Guard-failure join stubs (`movs r0,#0; b <join>`) belonging to the builder function above | (internal to the function above) |
| `0x74f0`-`0x7513` | The builder function's own literal pool | not code |
| `0x7514`- | `lcd_status_refresh__THIRD_PARTY` (Ghidra-recognized, correctly bounded) | (existing callers, unchanged) |

**Exhaustive negative result** (independent branch scan across the *entire*
compiled image, every `B`/`Bcc`/`B.W`/`Bcc.W`/`BL`/`BLX` encoding, plus a
separate raw 32-bit-literal scan for these addresses appearing anywhere as
a possible function-pointer/jump-table entry): the **only** branch/call
instructions anywhere in the image targeting `0x7232`, `0x72ac`, `0x7334`,
or `0x7770` are:

```
0x00007794  B.W  -> 0x00007334   (inside FUN_00007770)
0x000085e6  B.W  -> 0x000072ac   (inside ascii_dispatcher__CUSTOM / FUN_00008258 -- unrelated sibling, see above)
0x000094b4  BL   -> 0x00007770   (inside sketch_setup__CUSTOM / FUN_00009464)
```

No indirect/table dispatch exists (no 32-bit word anywhere in the image
equals any of these addresses, ±the Thumb bit) — the entry into the
connector-probe/`MT`-builder chain is a single, static, two-hop path:
`sketch_setup()` → `BL FUN_00007770` → `B.W 0x7334`.

### `FUN_00007770` itself is branch-free (except its own fixed 4-count loop)

```asm
0x00007770  push {r3,r4,r5,r6,r7,lr}
0x00007772  ldr r5,[pool]              ; per-channel bookkeeping pointer A
0x00007774  ldr r7,[pool]              ; per-channel bookkeeping pointer B
0x00007776  movs r4,#0x0
loop (x4, channel index in r4):
  ...swap/copy A[i]<->B (LCD-bookkeeping, unrelated to MT)...
  0x00007784  bl 0x00007514            ; lcd_status_refresh(channel)
  ...
0x0000778e  bne <loop>
0x00007790  pop.w {r3,r4,r5,r6,r7,lr}  ; restores LR, does NOT pop PC
0x00007794  b.w 0x00007334             ; UNCONDITIONAL tail-jump, always taken
```

There is no branch anywhere in this function that skips the tail-jump —
every call reaches `0x7334`.

### `sketch_setup()`'s own call site is unconditional, straight-line code

Disassembling `sketch_setup__CUSTOM` (`FUN_00009464`, confirmed elsewhere
in this project's own toolchain-provenance work to be the AutoPilot
sketch's real `setup()`) from its entry through the call site:

```asm
0x00009464  push {r4,r5,r6,lr}
0x00009466..0x00009486  ... driver/buffer setup (no branches) ...
0x00009488  bl 0x00006968     ; the real startup reference/input routine
                               ; (PA22-adjacent -- NOT "homing", per this
                               ;  project's standing naming discipline)
0x0000948c  bl 0x0000610c     ; the real radio-ID device-probe boundary
                               ; (post-homing-radio-probe.md: on real
                               ;  hardware with no responding radio chip,
                               ;  this is an intentional infinite retry --
                               ;  everything after it, including this
                               ;  slice's own target, is unreached until
                               ;  that succeeds)
0x00009490  bl 0x00006190     ; per-channel init
0x00009494  bl 0x00004c20     ; boot-time config load
0x00009498  bl 0x00004328     ; writes "V01R39\0" (the &|-response buffer)
0x0000949c  bl 0x00005d44
0x000094a0..0x000094b2  ... flag clears, one state-byte write ...
0x000094b4  bl 0x00007770     ; <-- the call in question. UNCONDITIONAL.
0x000094b8  bl 0x0000ccd0     ; first read of the MC4-wait loop condition
0x000094be  ldrb r3,[0x20000060]   ; setup()'s already-documented internal
0x000094c0  cbz r3,0x000094e4      ; MC4-wait loop begins HERE
```

**Zero branches, zero conditionals, zero flag checks** exist anywhere
between `sketch_setup`'s entry and the `bl 0x00007770` call — every prior
instruction runs unconditionally, in sequence. The call happens exactly
once per invocation of `setup()`, immediately **before** `setup()`'s own
internal `MC4`-wait loop (`0x94be`-`0x94e2`, already documented by
`mc4-transition.md`) begins.

### `sketch_setup()` itself is called exactly once, ever

```
0x0000cdb2  BL  -> 0x00009464   (inside main__ADAFRUIT_CORE / FUN_0000cd90)
```

Confirmed two independent ways (Ghidra's call graph and the independent
branch scan, in full agreement, zero discrepancy): this is the **only**
branch or call instruction anywhere in the compiled image targeting
`sketch_setup`. This matches the already-established, toolchain-matched
Arduino `main()` idiom (`setup()` once, then `loop()` forever) — there is
no soft-reset/re-`setup()` mechanism anywhere in this image's static call
graph.

## Part 2 — The scheduling condition, closed

**AutoPilot sends `MT` when `setup()` executes** — which happens exactly
once per physical boot or MCU reset, unconditionally, as an ordinary
straight-line step of `setup()`, specifically **after** the startup
reference/input routine (`0x6968`) and the radio-ID device handshake
(`0x610c`) have both already completed, and **before** `setup()`'s own
internal `MC4`-wait loop begins.

This is not "most plausibly boot" (the prior slice's hedge) — it is
**CONFIRMED, exhaustively**: every instruction on the path from
`sketch_setup`'s first instruction to the `MT` frame's last written byte is
either unconditional straight-line code or an unconditionally-taken
tail-jump, and the entire compiled image contains no other branch, call, or
indirect-dispatch entry into any part of that path.

**One real precondition, inherited from earlier in the same `setup()` call,
not from this code itself**: reaching `0x94b4` at all requires `0x610c`'s
real radio-ID probe (called two instructions earlier, unconditionally, at
`0x948c`) to succeed. `post-homing-radio-probe.md` already established that
on real hardware with no responding SX127x-shaped device, that probe is an
intentional infinite retry loop — nothing after it, including the `MT`
chain, would ever run. This is a hardware/environment condition inherited
from an already-documented boundary, not a new branch discovered in the
`MT` code itself.

## Part 3 — Connector-probe → `MT`-field mapping

Four probes, each an indirect (vtable-style) call through a per-channel
object pointer:

```c
uint FUN_0000a970(int *obj) { return (call_through(obj, +0x10)() & 0x3fffffff) >> 29; }  // bit 29 -- "guard"
uint FUN_0000a982(int *obj) { return (call_through(obj, +0x10)() & 0x7fffffff) >> 30; }  // bit 30 -- "raw state"
```

Per channel:
```
if FUN_0000a970(obj) != 0:      digit = 0                    (guard failed)
else:                            digit = FUN_0000a982(obj) ^ 1
store digit into 0x20002018[slot]
```

**The result is a genuine 2-valued (boolean) quantity per channel**, not an
arbitrary 0-9 digit, despite `MT`'s wire grammar showing one ASCII-digit
field per channel — confirmed both by the disassembly (both paths only
ever produce `0` or `1` before the `+'0'` ASCII conversion) and concretely
(below).

**Slot ↔ probe-object mapping — CONFIRMED, and notably not naive A/B/C/D
order**:

| MT digit | RAM result slot | Probe object pointer | Literal pool source |
|---|---|---|---|
| `b0` | `0x20002018[0]` | `0x200020a0` ("object A") | `0x74f0` |
| `b1` | `0x20002018[1]` | `0x200021d8` ("object C") | `0x74fc` |
| `b2` | `0x20002018[2]` | `0x2000213c` ("object B") | `0x74f8` |
| `b3` | `0x20002018[3]` | `0x20002274` ("object D") | `0x7500` |

This mapping is confirmed both by disassembly (the probe order in the code
is A, then C, then B, then D — not A,B,C,D) and concretely, by seeding a
distinguishable presence pattern per object and reading back which wire
digit each landed in (Part 5).

**Interpretation — PROBABLE, consistent with the already-CONFIRMED Remote
side**: digit `0` = absent/not-connected (matches `mc-command-remote-
provenance.md`'s already-CONFIRMED finding that the Remote maps each `'0'`
digit to motor type `1`, "Not connected"); digit `1` = presence detected.
Per this project's standing conservatism about physical identity: **the
mapping from these four probe-object pointers to physical Motor 1-4 jacks,
or to any specific MCU GPIO pin, is not established by this slice** and is
not asserted — only the logical slot ↔ probe-object ↔ wire-digit
correspondence above is CONFIRMED. Do not conflate "probe object A" with
"Motor 1."

## Part 4 — The fifth field (`<x>`)

Bounded, per the task's own dataflow-cheapness test — this fell out
directly, no extra investigation needed:

```asm
0x000074ce  ldr r2,[0x00007510]   ; = 0x20001fc0
0x000074d0  ldrb r2,[r2,#0x0]     ; single byte, direct read
0x000074d2  adds r2,#0x30         ; ASCII digit
0x000074d4  strb r2,[r3,#0x6]     ; the 5th field, buf[6]
```

Cross-reference (from the same cached static export used throughout this
project): `0x20001fc0` is written by **`FUN_00006968`** — the same startup
reference/input routine that runs unconditionally, earlier, in this exact
same `setup()` call (see Part 1) — at exactly two sites, writing `1` (the
pin-check-succeeded path) or `2` (the timeout/failure path); also read by
`phase_ramp_state_machine__CUSTOM` elsewhere, confirming it is a real,
cross-subsystem status byte, not `MT`-exclusive.

**In practice, the fifth digit is always `'1'` or `'2'`**, never `'0'` —
by the time `FUN_00007770` reads it, `FUN_00006968` has unconditionally
already run and set it to one of those two values. This slice does not
further characterize what `1` vs. `2` means beyond "the startup
reference/input routine's own outcome" — deeper semantics of `FUN_00006968`
are out of scope here (already covered, and deliberately not renamed
"homing," by prior work).

## Part 5 — Concrete proof

`ConcreteMachine`, entering directly at `FUN_00007770` (the smallest
meaningful real boundary — its sole call site is already disassembly-
confirmed unconditional, the same methodology this project used for
`FUN_00005a8c`'s direct entry in `mc-command-remote-provenance.md`). Real
`.data` seeded from flash `0x25248` for `0x5f0` bytes (the same
`Reset_Handler`-startup-copy recipe used throughout this project's other
concrete captures).

**Disclosed harness inputs** (explicitly not firmware-produced this run):
- `stub_calls=[0xa9cc, 0xaa44, 0xd388, 0xcd50, 0xcd34, 0x7514]` — real
  GPIO pin-config/pulse/delay/display helpers, confirmed by the Part 3/4
  dataflow trace to have no effect on the output bytes.
- `stub_calls=[0xa970, 0xa982]` with `force_reg` at each of the 8 distinct
  per-channel return addresses — standing in for real connector GPIO/
  electrical state, exactly the license this task names explicitly
  ("connector GPIO inputs = harness-supplied external state").
- `seed_mem` at `0x20001fc0` (the 5th-field source) — standing in for
  `FUN_00006968`'s real output; that routine's own real execution was not
  re-run this pass (already independently disclosed/covered elsewhere in
  this project).

**Run 1 — mixed presence pattern** (object A present, C absent, B present,
D absent — i.e. `a970` forced to `0`/guard-passes for all four, `a982`
forced to `0,1,0,1` for A,C,B,D respectively):

```
stop_reason: reached stop address 0x000074de
probe result bytes (0x20002018[0..3]): b'\x01\x00\x01\x00'
MT frame buffer (0x20002548[0..8]):    b'MT10101|\x00'
```

Exactly matches the predicted slot mapping from Part 3 (A→b0=1, C→b1=0,
B→b2=1, D→b3=0), empirically confirming the disassembly-derived order, not
just asserting it.

**Run 2 — guard-failure control** (`a970` forced to `1`/guard-fails for all
four channels; `a982` forced to `0` for all four — which, if the guard did
*not* override it, would produce all `1`s):

```
stop_reason: reached stop address 0x000074de
MT frame buffer (0x20002548[0..8]):    b'MT00001|\x00'
```

Confirms the guard genuinely forces the digit to `0` regardless of the
second probe's own value, matching the disassembly exactly.

**The exact frame construction, byte for byte** (`0x74ac`-`0x74dc`, buffer
base `0x20002548`, resolved from the literal pool at `0x750c`):

```
buf[0] = 'M'                (0x4d)
buf[1] = 'T'                (0x54)
buf[2] = 0x20002018[0] + '0'
buf[3] = 0x20002018[1] + '0'
buf[4] = 0x20002018[2] + '0'
buf[5] = 0x20002018[3] + '0'
buf[6] = *0x20001fc0 + '0'
buf[7] = '|'                (0x7c)
buf[8] = 0x00
```

**Remote-side delivery — assessed, deferred as non-cheap this slice.** The
task licensed delivering the produced frame through the existing
virtual-link machinery "if cheap." `FUN_00010ce4` (the Remote's real
MT-reacting handler, per `mc-command-remote-provenance.md`) turns out, on
inspection this slice, to be a 792-byte general-purpose **per-character**
inbound radio-stream state machine (consuming bytes one at a time via
`FUN_0000b4f8()`/`FUN_0000583c()`, itself reached only from
`FUN_0000c340`, a "pump" function called from dozens of call sites across
nearly every Remote UI screen) — structurally different from, and a
materially larger undertaking than, this project's existing
whole-packet-buffer `REMOTE_*_ENTRY` anchors (`REMOTE_TX_ENTRY`,
`REMOTE_RX_ENTRY`, `REMOTE_S_ENTRY`, etc. in `tools/unicorn/
virtual_link.py`). Finding the real byte-source ring buffer and the exact
"MT" 2-character prefix match inside this state machine is a bounded but
separate investigation, not attempted this slice. This does **not** change
or cast doubt on `mc-command-remote-provenance.md`'s existing STATIC
(disassembly) confirmation that `FUN_00010ce4` sets the Quick-Setup flag
and opens the Choose-Type screen — that finding is unchanged and not
re-derived here.

## Part 6 — Lifecycle semantics

1. **When can AutoPilot send `MT`?** Exactly once per physical boot/MCU
   reset, as an unconditional step of `setup()`, after the startup
   reference/input routine and the radio-ID handshake both complete, and
   before `setup()`'s own internal `MC4`-wait loop begins.
2. **Exact condition**: none beyond "`setup()` is executing this
   instruction" — confirmed exhaustively branch-free from `setup()`'s
   entry through the frame's last byte, with the whole compiled image
   containing no alternate entry.
3. **Lifecycle class**: **one-shot, boot-only.** Not periodic (no timer/
   tick gates it), not edge/change-driven (no comparison against any prior
   probe result exists anywhere in the four probe blocks — each boot
   stores a fresh, unconditional read), not reconnect-driven (no code path
   anywhere re-enters `FUN_00007770` or `sketch_setup` after the initial
   boot call — confirmed exhaustively for both).
4. **Can it happen after normal runtime begins?** No. `loop()`
   (`FUN_000093fc`, already established elsewhere) and everything
   reachable from it are entirely disjoint, in the static call graph, from
   `sketch_setup`'s own call graph; nothing anywhere branches or calls back
   into `FUN_00007770`/`0x7334`/`0x72ac` once `setup()` has returned.
5. **Quick Setup is therefore**: **boot/setup-only.** It is not
   automatically re-enterable, not triggered by a motor being plugged in
   mid-session (the probe only ever runs once, at the exact moment
   `setup()` reaches it), and not reconnect-driven at the radio-link level.
   The Remote only ever sees Quick Setup opened in response to whichever
   connector-presence state existed at the AutoPilot's most recent
   physical power-on or reset.

## Confidence table

| Item | Status |
|---|---|
| Ghidra's function-boundary gap here is real (no function object covers `0x7232`-`0x7513`) and is explained: one literal pool, two unrelated tail-jumped routines, one more literal pool | **CONFIRMED** (disassembly) |
| Entry into the connector-probe/`MT`-builder routine is `B.W` (tail-jump) from `FUN_00007770` at `0x7794`, with no other entry anywhere in the image | **CONFIRMED** (exhaustive independent branch scan, cross-validated) |
| `FUN_00007770`'s tail-jump is unconditional (no branch skips it) | **CONFIRMED** (disassembly) |
| `FUN_00007770`'s sole call site (`0x94b4`, inside `sketch_setup`) is reached by unconditional, branch-free code from `setup()`'s entry | **CONFIRMED** (disassembly) |
| `sketch_setup()` is called exactly once anywhere in the image (`main()`, standard Arduino idiom) | **CONFIRMED** (Ghidra call graph + independent branch scan, agree) |
| The scheduling condition is therefore "unconditional, once, during `setup()`" | **CONFIRMED** |
| Real hardware must first pass the radio-ID handshake (`0x610c`) to ever reach this code | **CONFIRMED** (inherited from `post-homing-radio-probe.md`, not re-derived) |
| Four connector probes are a guarded 2-valued (boolean) read per channel, not an arbitrary digit | **CONFIRMED** (disassembly + concrete) |
| Slot↔probe-object mapping is A→b0, C→b1, B→b2, D→b3 (not naive order) | **CONFIRMED** (disassembly + concrete, both agree) |
| Digit `0`=absent / `1`=present matches the Remote's own `MT`-digit interpretation | **PROBABLE** (consistent with already-CONFIRMED Remote behavior, not independently re-proven here) |
| Probe-object pointers ↔ physical Motor 1-4 jacks / specific MCU GPIO pins | **UNKNOWN** — not attempted, per explicit scope discipline |
| 5th field (`<x>`) source is `0x20001fc0`, written by `FUN_00006968`, always `1` or `2` in practice | **CONFIRMED** (disassembly) for source/values; deeper semantics of `FUN_00006968` **UNKNOWN**, out of scope |
| Real `MT` frames concretely produced from disclosed connector-GPIO inputs, both the normal path and the guard-failure path | **CONFIRMED** (concrete, `ConcreteMachine`) |
| Remote-side delivery of the produced frame through `FUN_00010ce4`, concretely | **NOT ATTEMPTED** this slice — assessed as a materially larger, structurally different undertaking (per-character state machine, not whole-packet dispatch); precisely named as a follow-up, not silently skipped |
| Quick Setup is boot/setup-only, not reconnect- or change-driven | **CONFIRMED** (exhaustive: no re-entry path into `sketch_setup` or `FUN_00007770` exists anywhere in the image) |

## Remaining unknowns

1. Concretely deliver the produced `MT` frame through the Remote's real
   `FUN_0000c340`/`FUN_00010ce4` per-character inbound state machine (find
   its real ring-buffer/byte-source anchor, analogous to this project's
   existing `REMOTE_*_ENTRY` constants) to reconfirm the already-
   disassembly-CONFIRMED Quick-Setup-flag effect concretely, matching this
   project's evidentiary standard for the AutoPilot side achieved this
   slice.
2. The probe-object-pointer ↔ physical Motor N jack / MCU GPIO identity
   (deliberately not pursued — out of scope per this task's own
   conservatism instruction).
3. `FUN_00006968`'s own deeper semantics (what distinguishes its `1` vs.
   `2` outcome physically) — already out of scope for this project's
   naming discipline around that routine; not reopened here.
4. The unrelated sibling routine at `0x72ac`-`0x7319` (tail-jumped from
   `ascii_dispatcher__CUSTOM` at `0x85e6`) — identified and named so it
   isn't mistaken for part of the `MT` chain, but its own purpose (which
   ASCII command reaches it, and why) was not traced this slice.

## Tooling note

`scan_all_branches.py`/`scan_bl.py` (this slice's independent Thumb-2
branch decoder) were written ad hoc in the scratchpad, not added to
`tools/`, per the task's instruction not to turn this into a tooling
slice. They duplicate, in narrower form, the "independent full-image
BL/BLX decode" methodology `mc-command-remote-provenance.md` already used
once (also not persisted as a tool then). If a third investigation needs
this same capability, it is worth promoting to a real `tools/` script
instead of writing a fourth ad hoc copy — noted here, not acted on.
