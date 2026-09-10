# Investigation: Does the Remote's Reaction to T-Status Frames Bridge Back to Motion?

**Question**: `trigger-input-motion-causality.md` closed off the PB05-low
config-reload as a direct cause of motor motion — it never arms
`phase_ramp_state_machine__CUSTOM`'s own per-channel mode byte
(`0x20002318[channel]`), whose only real `0`→`1` producer anywhere in the
image is an unrelated AutoPilot-side command (`0x865a`, the `'W'` family).
That leaves one remaining firmware-only candidate bridge: the *other* real
consequence of a live PB05 read — the `"T<0 or 1023>,<1 or 0>,|"`
trigger-status frame AutoPilot sends to the Remote whenever reporting is
armed (`TR1|`). This slice: trace the Remote's real handling of that frame
end to end, and determine whether it can create a path back to the
AutoPilot that ends in the arm byte becoming `1`.

**Scope**: disassembly against the persistent `mando868` Ghidra cache
(the Remote's real inbound dispatcher, `FUN_00010ce4`, was already
partially characterized for its `'M'`/`'a'`-`'x'`/`'B'` branches by prior
slices — this one closes its previously-untraced plain `'T'` branch), plus
`ConcreteMachine` delivery of both real frame shapes into the Remote's
real inbound ring buffer. Per instruction, `'W'` is not reversed generically
— only as far as this slice's own trace actually reaches it (it doesn't).

## Result, in one paragraph

**The T-status path cannot be the missing bridge — proven, not inferred
from a timeout or absence.** The Remote's real per-byte inbound dispatcher
(`FUN_00010ce4`, already known from `mt-quick-setup-trigger.md`/
`bulk-push-trigger-provenance.md` for its `MT`/`'a'`-`'x'`/`'B'` branches)
has its own plain `'T'` case (`0x10f0a`–`0x10f32`, not previously traced):
it parses the two decimal fields exactly as the AutoPilot's own sender
builds them, stores them into two RAM cells (`0x200002e8`, `0x200027f8`)
plus a "received" flag (`0x200027f9`), and **returns immediately — no
call to anything resembling a send, anywhere in that branch**. An
exhaustive xref search for all three cells finds exactly one consumer in
the whole image: `FUN_0000fa10`, a real UI screen's own render loop, which
converts the first field into a scaled display value (`field1*3300/1023`
— `0` or `3300`) and redraws it in a color selected by the second field
(white/red) — **a pure telemetry readout, nothing else**. **Concretely
confirmed**, delivering both real frame shapes AutoPilot is confirmed to
send (`"T1023,0,|"`, `"T0,1,|"`) directly into the Remote's real inbound
ring buffer and running its real dispatcher (the one real-but-irrelevant
dependency in the way — the radio-driver ring-buffer refill step,
`FUN_0000b440` — stubbed, the same already-documented boundary this
project always stubs): both frames parse to the exact expected values,
both return cleanly, and **neither ever reaches the Remote's own real TX
wrapper (`0x58a8`)** — watched for explicitly via `stop_at`, not merely
assumed absent. Since the T-status path is the AutoPilot's *only* other
real consequence of a live PB05 read (mutually exclusive with the
config-reload path, gated by the same `TR0|`/`TR1|` toggle
`trigger-input-concrete-path.md` already established), **this closes the
firmware-only feedback-loop hypothesis entirely**: neither of PB05's two
real downstream paths — the reload, or the status broadcast — can arm
`phase_ramp_arm_byte`/reach `motor_move_commit__CUSTOM`.

## Part 1 — The Remote's real `'T'` branch, disassembled for the first time

`FUN_00010ce4`'s top-level dispatch (already known to check `'M'`/`0x4d`,
the `['a','x']` range, `'#'`/`'@'`, `'B'`, `'X'`) falls through, on anything
that isn't `'M'`, to a final `cmp r4,#0x54 ('T')` this slice traces for the
first time:

```asm
0x10f0a  cmp r4,#0x54 ('T')
0x10f0c  bne 0x10f5e              ; not 'T' -> drain-and-idle tail
0x10f0e  bl 0x583c                 ; consume the 'T' byte
0x10f12  movs r5,#0                ; field1 accumulator
0x10f16  bl 0xb4f8 / bl 0x583c     ; parse decimal digits into r5 (field1)
                                    ; until a non-digit (real MAC-style
                                    ; "peek availability, then consume" loop
                                    ; -- the same two helpers this project's
                                    ; existing REMOTE_RX_* constants already
                                    ; describe: FUN_0000583c reads
                                    ; 0x20001773[readptr++], FUN_0000b4f8
                                    ; computes writeptr-readptr)
0x10f1e  bl 0xb4f8 / bl 0x583c     ; parse field2 similarly, terminated by '|'
0x10f24  *0x200002e8 = field1      ; store
0x10f2a  *0x200027f8 = field2      ; store
0x10f30  *0x200027f9 = 1           ; "T received" flag
0x10f32  b 0x10e3a                 ; pop {r3,r4,r5,r6,r7,pc} -- plain return
```

**No `bl` to `FUN_0000c440` (the Remote's real request sender), `0x58a8`
(the TX wrapper), `0xb59c` (the ack/retry helper), or anything else that
could produce outbound bytes appears anywhere in this branch.** This is
disassembly-complete, not a sample — every instruction from the `'T'`
comparison to the branch's own return is accounted for above.

## Part 2 — The one real consumer: a display readout, not a command

Exhaustive xref search (this project's standard method) for all three
cells the `'T'` branch writes:

| Cell | Writer | Readers |
|---|---|---|
| `0x200002e8` (field1) | `FUN_00010ce4` only | `FUN_0000fa10` only |
| `0x200027f8` (field2) | `FUN_00010ce4` only | `FUN_0000fa10` only |
| `0x200027f9` (received flag) | `FUN_00010ce4` only | `FUN_0000fa10` only |

`FUN_0000fa10` (a real, 744-byte UI screen render/event loop, calling
`FUN_0000c340` — "the pump" — once per iteration, matching this project's
standard screen-loop shape) checks the flag once per loop pass
(`0xfbe0`–`0xfbe6`); if set, it clears the flag, reads field1, computes
`field1 * 3300 / 1023` (an exact 0↔3300 scaling — `1023`'s own role as a
10-bit-full-scale sentinel, already suspected in
`trigger-input-concrete-path.md`, is now explained: it's meant to read as
a voltage-style display value), and redraws that number on screen
(`FUN_00005d18`) in a color selected by field2 (`0xffff`/white if `0`,
`0xf800`/red otherwise — `FUN_00005d8c` sets the draw color immediately
before). **No call in this whole sequence sends anything** — `FUN_00005d8c`
and `FUN_00005d18` are display-draw primitives (set color, draw number at
a fixed `(x,y)`), not protocol functions. This is a real, previously
unidentified live trigger-status readout screen — which specific menu it
is was not chased further, per this slice's scope.

## Part 3 — Concrete confirmation: `tools/unicorn/virtual_link.py t-status`

A new, reusable scenario, `run_t_status_feedback_check()`, delivers both
real frame shapes directly into the Remote's real inbound ring buffer
(`0x20001773`, the same `REMOTE_RX_*` anchors this project's `S`/`G`/`&`
scenarios already use) and enters `FUN_00010ce4` for real. The one
real-but-irrelevant dependency in the way — `FUN_0000b440`, the radio
driver's own ring-buffer refill step (called from the peek helper,
touches an uninitialized driver object) — is stubbed, the same
already-documented boundary `mando-first-execution.md` established; it is
irrelevant here since the frame bytes are already placed in the ring
buffer directly, not awaiting a real radio receive.

```
"T1023,0,|"  -> field1=1023 field2=0 flag=1, readptr advances by exactly
                the frame's own length (9), clean return, TX wrapper NOT reached
"T0,1,|"     -> field1=0    field2=1 flag=1, readptr advances by exactly
                the frame's own length (6), clean return, TX wrapper NOT reached
```

Full command: `tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py t-status`
(also included in `virtual_link.py all`).

## Answering the task's five questions directly

1. **Where does the Remote parse/store the T frame?** `FUN_00010ce4`
   (`0x10f0a`–`0x10f32`), the same per-byte inbound dispatcher already
   known for `MT`/`'a'`-`'x'`/`'B'`.
2. **What state/UI/event changes does it cause?** Two RAM cells plus a
   flag are set, consumed exactly once by `FUN_0000fa10`'s own real
   screen-render loop to redraw a live, color-coded numeric readout — a
   real UI effect, nothing more.
3. **Does receiving T cause any outbound Remote command?** **No** —
   confirmed both by complete disassembly of the parsing branch (no send
   call anywhere in it) and concretely (real execution, explicit
   `stop_at` on the TX wrapper, never reached, for both real frame
   shapes).
4. **N/A** — since no outbound command exists, `'W'`-family handling,
   `phase_ramp_arm_byte`, and `motor_move_commit__CUSTOM` are unreachable
   from this path. Per instruction, `'W'` was not reversed generically;
   this slice's own trace never reaches it.
5. **Proven**: T only updates Remote state/display and sends nothing —
   the firmware feedback-loop hypothesis (PB05 → T-status → Remote
   reaction → command back → motion arm) is closed, negatively.

## What this slice did not do

- Did not identify which specific menu/screen `FUN_0000fa10` belongs to
  (a real UI screen, not otherwise characterized) — out of scope.
- Did not trace whether `FUN_0000fa10` itself sends `TR1|`/`TR0|` on
  screen entry/exit (plausible, given `TR1|`'s own already-established
  role as "arm trigger-status reporting," but that would be a
  *precondition* for T ever being sent, not a *consequence* of receiving
  it — not causally relevant to this slice's question, not chased).
- Did not reverse the `'W'` command family generically (`0x72ac`/`0x8624`/
  `0x865a`, named in `trigger-input-motion-causality.md`) — the T-handling
  path this slice traced never reaches any of it.

## Confidence table

| Item | Status |
|---|---|
| `FUN_00010ce4`'s plain `'T'` branch parses both real frame shapes and stores them, with no send call anywhere in the branch | **CONFIRMED** (complete disassembly) |
| The only consumer of the three storage cells anywhere in the image is `FUN_0000fa10`, a real UI screen's own render loop | **CONFIRMED** (exhaustive xref) |
| `FUN_0000fa10`'s own consumption is a pure display redraw (scaled value + color), no outbound call | **CONFIRMED** (disassembly) |
| Delivering both real T-frame shapes into the Remote's real inbound state reproduces the exact expected stored values | **CONFIRMED concretely** (Unicorn, real ring buffer, real dispatcher) |
| Neither delivery reaches the Remote's own TX wrapper | **CONFIRMED concretely** (explicit `stop_at`, not inferred) |
| The T-status path cannot bridge back to `phase_ramp_arm_byte`/`motor_move_commit__CUSTOM` | **CONFIRMED** — no outbound command exists to trace further |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by exhaustive xref)
for the parsing branch's completeness and the display-only consumer.
Level 2 (concrete, Unicorn, via a new reusable `virtual_link.py t-status`
regression) for the full real-frame delivery result. No level-3
(solver-confirmed) claim is made or needed.
