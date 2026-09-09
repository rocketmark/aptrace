# Investigation: The Real Trigger and Lifecycle of Remote `FUN_0000c440`'s Bulk `'+'`/`MC4` Push

**Question**: `plus-command-remote-provenance.md` and `mc-command-remote-
provenance.md` both found that `FUN_0000c440` — the same function that
builds the Remote's `S|` query — has a tail that bulk-pushes `'+'` (mode
`0x62`) for every channel with stored data, then sends `MC4`, but neither
slice traced *what calls `FUN_0000c440` and when*, beyond the hedge
"reconnect/status refresh, not proven." This slice closes that edge: the
real control-flow structure of `FUN_0000c440`, every real caller, the
exact predicate that reaches the bulk-push branch, and the lifecycle
semantics of the whole mechanism.

**Scope**: disassembly against the persistent `mando868` Ghidra cache, an
independent full-image Thumb-2 branch decoder (reused from the prior `MT`
scheduling slice, re-run against `firmware_mando868.bin`), and concrete
execution (`ConcreteMachine`) to produce real `'+'` and `MC4` frames from
a real `S -> P` exchange. No AutoPilot-side conclusion from any prior
slice is revisited.

## Confidence scale

Same as `docs/ui/action-command-map.md`: **CONFIRMED** / **PROBABLE** /
**UNKNOWN**.

## Result, in one paragraph

`FUN_0000c440`'s bulk-push-then-`MC4` tail is reached whenever a
**single, real, always-first action inside the function — sending `S|`
and getting a clean `'P...'` response within ~200 ticks — succeeds**;
this same gate is shared by every one of the function's four real
callers, regardless of the `param_1` value each passes. The **primary,
always-happens trigger is the Remote's own boot sequence**: `Reset_Handler`
→ `FUN_00016900` → `FUN_0000fdf0` (a splash-screen/backlight-fade
routine that also triple-broadcasts `"R0|"` and sends a wake preamble)
calls `FUN_0000c440(0)` **exactly once, unconditionally, per physical
power-on**, immediately before the Remote's own `"&|"` firmware-version
query and its main loop. A **secondary, conditional re-arm** exists:
`FUN_00010ce4` (the Remote's inbound AutoPilot-byte dispatcher, already
known from the `MT` scheduling slice) calls `FUN_0000c440(0)` again
whenever a byte in `['a','x']` or `'B'` arrives from the AutoPilot, but
only while a "first sync not yet done" latch is `0` — and that latch is
reset back to `0` only after a genuine ~5000-tick (multi-second) gap in
inbound radio activity. **The bulk-`'+'` loop itself only ever sends
anything if a separate "has real programmed data" flag is nonzero — set
exclusively by the interactive Auto-Mode UI, never by the boot sequence
itself** — so a factory-fresh boot's push loop is a real no-op; only
`MC4` is guaranteed. Concretely reproduced end to end this slice.

## Part 1 — `FUN_0000c440`'s real control-flow structure

`FUN_0000c440(param_1)` (`0xc440`-`0xcb50`, ~1580 bytes, one real Ghidra
function, no tail-jump artifacts at its own boundary) is **not** an `S`
handler with a bolted-on push tail — it is a single, linear transaction
function with two request/response rounds and a shared success flag:

```
FUN_0000c440(param_1):
  0xc44e-0xc456: if (retry_counter > 7 AND param_1==0): return 0   [rate-limit guard, param_1==0 only]
  0xc466-0xc47a: timestamp bookkeeping
  0xc47c: if (param_1==0): FUN_00005a14()        [wake preamble -- param_1==0 only]
  0xc480-0xc48c: drain any already-buffered inbound bytes
  0xc496-0xc498: FUN_000058a8(DAT_0000c660)       [sends "S|" -- ALWAYS, every param_1]
  0xc4a4-0xc4da: wait up to 200 ticks for a byte
  0xc4dc-0xc51c/0xc55e: parse loop -- consumes every available byte;
      cVar24 = 1 iff a byte arrived AND every byte seen was part of a
      clean 'P'-prefixed (or 'PN'-remap) response; ANY unexpected byte
      resets cVar24 = 0
  0xc4b2-0xc4b6: if (param_1 != 0): drain remainder, goto LAB_0000c9a4  [SKIPS the second round entirely]
  --- param_1==0 only, from here ---
  0xc4ba-0xc4c6: second send: "!0|" or "!1|" (selected by a stored flag)
  ... wait + parse an 11-field numeric CSV response (the already-known,
      untouched-here event-7/`!` 11-vs-10 field-count mismatch lives in
      this exact parse) ...
  0xc9a0: FUN_00005a50()                          [second wake-preamble idiom]
LAB_0000c9a4 (the shared tail, reached from BOTH param_1==0's fall-through
              and param_1!=0's goto):
  0xc9a4-0xc9a6: if (cVar24 == 0): return 0        [THE gate -- see Part 2]
  0xc9aa-0xc9ae: retry_counter = 0
  0xc9b0-0xc9b6: if (*0x20000fa0 == 0): goto 0xcb4a   [skip the whole push loop -- see Part 5]
  0xc9ba-0xc9da: count nonzero-data channels into cVar18 (confirm1)
  0xcb02-0xcb48: for channel in 0..(*0x20000260 - 1):
      if record[channel] != 0:
        FUN_000049c4(confirm1=cVar18, confirm2=cVar27, channel, param_4=0, mode=0x62)
        FUN_0000b59c()          [wait for ack]
        FUN_0000c340()          [pump]
        cVar27 += 1
        if ack failed: break
0xcb4a-0xcb4c: FUN_00005a8c(4)                     [MC4 -- UNCONDITIONAL once cVar24==1,
                                                     reached from EVERY exit of the block above]
```

Every address above is from direct disassembly, not decompiler
paraphrase — the decompile's variable names (`cVar24`, `cVar18`, `cVar27`,
etc.) are used here only as convenient labels, matched back to real
registers/addresses throughout.

## Part 2 — The exact bulk-push branch predicate

**`cmp r4,#0; beq 0xc458`** at `0xc9a4`-`0xc9a6` (`r4` = `cVar24`,
computed once, at `0xc484`/reset through the parse loop). This single
byte controls **both** whether the push loop runs at all **and** whether
`MC4` is ever sent — there is no separate gate for `MC4`. `cVar24` is
**not** a stored/persistent flag; it is a fresh local computed every call,
from this exact invocation's own `S -> P` round trip only.

**`cVar24 == 1` requires, in the same call**: a byte arrives within ~200
ticks of the `"S|"` send, **and** every byte the parse loop consumes
starts with `'P'` (or the `'PN'` state-remap form) — receiving *any*
other leading byte, or timing out, is a hard failure. **The specific
value carried in the `P` response does not matter** — `cVar24` does not
depend on `value0`/`value1`/`bool`, only on the response's shape. This is
disassembly-confirmed by walking every path through the parse loop: the
`else` arm (`FUN_0000583c(); cVar24='\0';`) fires on any non-`'P'` byte
regardless of value, and every `'P'`-prefixed path (including `'PN'`)
leaves `cVar24` untouched at `1`.

## Part 3 — Relation to the `S -> P...` exchange

Direct answers, per the task's own six questions:

1. **Does Remote send `S|` before the bulk branch?** Yes — it is the
   **very first action** of this exact same function call, not a
   separate, earlier transaction. `FUN_000058a8(DAT_0000c660)` at
   `0xc498` sends the literal `"S|"` (`DAT_0000c660` resolves to flash
   `0x1c58c`, confirmed in `s-p-roundtrip.md`) — this is the identical
   send `s-p-roundtrip.md` already captured and characterized.
2. **Does AutoPilot's `P...` response trigger it?** Yes, directly:
   receiving a clean `'P'`-response **is** `cVar24`, the sole gate for
   the entire bulk-push-then-`MC4` tail.
3. **Is it conditional on a particular `P`/state value?** **No** — see
   Part 2. Any of the response forms `s-p-roundtrip.md` characterized
   (`"P1,"`, `"P11,0,0,"`, or any other value in that shape) satisfies
   `cVar24` identically.
4. **Is the "don't downgrade" guard involved?** No — that guard
   (`s-p-roundtrip.md`: `if (value0 != 1 || stored_state > 6): store it`)
   only affects the Remote's separately-stored `state`/`value1`/`bool`
   fields; it does not touch `cVar24` or anything the bulk-push tail
   reads.
5. **Does the Remote compare local vs. AutoPilot state before pushing?**
   No — which channels get pushed is decided **purely locally**, by
   whether that channel's own stored record is nonzero (Part 5); the
   AutoPilot's reported state value is never consulted for that decision.
6. **Is `MC4` part of the same transaction?** Yes, unconditionally —
   confirmed by raw disassembly (Part 1): every exit from the push-loop
   region (loop completes naturally, an ack fails mid-loop, or the loop
   is skipped entirely because no channel has data) converges on the
   identical `0xcb4a: movs r0,#4; bl 0x00005a8c` instruction.

**Refinement to the prior framing**: `plus-command-remote-
provenance.md`/`mc-command-remote-provenance.md` described this as "the
`'S'`-handler bulk-push tail," which is accurate but incomplete — it is
specifically **the success tail of `FUN_0000c440`'s own `S -> P` round
trip**, not a separate feature bolted onto command handling. The `!0|`/
`!1|` second round (`param_1==0` only) is a real, parallel part of the
same function but is **not** on the causal path to the push/`MC4` tail —
confirmed by the `param_1 != 0` branch reaching the identical tail via
`goto` without ever executing it.

## Part 4 — Trigger provenance: every real caller, traced to a real event

### 4a. Ghidra's call graph vs. an independent full-image branch scan

`callers mando868 0xc440` returns exactly four sites (`0x1001e` in
`FUN_0000fdf0`; `0x10d52`, `0x10d64`, `0x10dfc`, all in `FUN_00010ce4`).
An independent, from-scratch Thumb-2 branch/call decoder (every `B`/
`Bcc`/`B.W`/`Bcc.W`/`BL`/`BLX` encoding, re-run against
`firmware_mando868.bin` — the same methodology validated in the prior
`MT`-scheduling slice) finds **exactly these same four, and no others**,
anywhere in the compiled image. No indirect/table dispatch exists either
(the same scan, extended to `0xfdf0`/`0x16900`/`0x16794`, below, finds
single, unique callers for each with zero ambiguity). This is exhaustive,
not "one way found to reach it" — satisfying Phase 8's requirement.

### 4b. The primary trigger: the Remote's own boot sequence

```
Reset_Handler (FUN_00016794, mando868 vector[1] @ flash 0x4004 = 0x16795)
  -- .data copy / .bss zero / FPU-enable convergence, all branches
     unconditional-eventual, standard Cortex-M CRT startup
  -> bl 0x16948 (SystemInit-equivalent)
  -> bl 0x16900                                              [UNCONDITIONAL]
     -- peripheral/clock/display init (0x16b40, 0x19630, 0x168fe, 0x157b0, 0x158d0)
     -> bl 0xfdf0                                            [UNCONDITIONAL]
        -- splash/backlight-fade animation (0xff->100->0xff brightness ramp)
        -- FUN_000058a8(DAT_000100dc) x3  ("R0|", confirmed by direct
           flash read at 0x1ca03: "R0|\0Reset limits..." -- an un-acked
           triple broadcast, the same idiom this project already
           documented for MC/wake-preamble sends)
        -- FUN_00005a50()  (wake preamble)
        -> FUN_0000c440(0)                                   <-- OUR TARGET
        -> FUN_0000ba98()  (the real "&|" firmware-version query, sent
           immediately AFTER)
     -- enters the real main loop (bl 0x42aa / bl 0x168f8, forever)
```

Every arrow above is a real, unconditional branch or call — confirmed by
disassembling `FUN_00016794` (104 bytes) and `FUN_00016900` (56 bytes) in
full: **zero conditional branches anywhere skip `bl 0xfdf0` or, within
`FUN_0000fdf0`, `bl 0xc440`**. `Reset_Handler` itself runs exactly once
per physical power-on or MCU reset (the standard ARM startup guarantee);
`FUN_00016900`/`FUN_0000fdf0` each have exactly one caller anywhere in
the image (confirmed by the same branch scan). **This closes the
question precisely: `FUN_0000c440(0)` is called exactly once,
unconditionally, per Remote power-on, as part of its own startup splash
sequence, immediately before its own firmware-version query.**

### 4c. The secondary trigger: specific inbound AutoPilot bytes, debounced to fire once

`FUN_00010ce4` (already established in `mt-quick-setup-trigger.md` as the
Remote's real per-character inbound-byte dispatcher, sole caller
`FUN_0000c340`, itself called from dozens of UI screens as a background
"pump") peeks the next buffered byte and dispatches on it. Two of its
branches reach `FUN_0000c440`:

- **`uVar17 - 0x61 < 0x18`** (the peeked byte is in `['a','x']`, 24
  possible ASCII values) consumes that byte, optionally a following
  digit `'0'`-`'2'`, then:
  - **call #1** (`0xc47c`... `0xc352`, i.e. `0xc47c`/`0xc47e`... — precisely
    `0x10d52: bl 0xc440`, `r0=0`), gated on **`*0x20000fc9 == 0`**
    ("first sync not yet latched done") **and** `*0x200001ac == 0` (a
    small toggle byte, also written by the other `FUN_0000c440` caller,
    `FUN_0000fdf0` — not chased further, out of scope);
  - **call #2** (`0x10d64: bl 0xc440`, `r0=0`), gated purely on
    **`*0x2000195c != 0`** ("pending retry" flag).
  - On failure (`FUN_0000c440` returns `0`), `*0x20000fc9` is reset back
    to `0` (0x10d88/0x10d98) — a real retry-until-success pattern.
  - **`*0x2000195c` has no writer anywhere in the image except these two
    call sites themselves** (set `=1` right before call #1, cleared `=0`
    on either call succeeding) — confirmed by an exhaustive xref scan.
    It is a purely local, single-attempt retry latch, not a recurring
    scheduler.
- **`uVar17 == 0x42`** (`'B'`) drains trailing bytes with short delays,
  then `0x10dfc: bl 0xc440` with **whatever raw byte value was last
  consumed by the drain** (0, if none were available) as `param_1` — not
  a fixed constant; a real, data-dependent argument. Not exercised
  concretely this slice (out of scope: the task's own `param_1 != 0`
  substitution in Part 6 already reaches the identical tail via a
  disassembly-confirmed-equivalent path).

**`*0x20000fc9` ("first sync done") is the true debounce**: written
`=1` on success at `0x10d48`/`0x10d9a`(no — see below)/`0x10ef6`, and
reset `=0` on failure (`0x10d88`, `0x10d98`) or by a real **link-timeout
watchdog** inside the same function's idle tail (`LAB_00010ff8`,
`0x11026`): if **no inbound byte has been processed for ~5000 ticks**
(`FUN_00016840()` elapsed vs. `*0x20001734`, the general last-RX-activity
timestamp) **and** neither the "has-ever-sent" flag (`0x20000fc8`) nor
the Quick-Setup-in-progress flag (`0x20001810`) is set, the Remote treats
this as a lost link and clears `*0x20000fc9` back to `0`. **This is the
mechanism's own real re-arm condition**: a genuine multi-second gap in
radio contact, followed by any fresh `['a','x']`-or-`'B'` byte from the
AutoPilot, can trigger `FUN_0000c440(0)` again, later in the same
session — precisely "Outcome A" from the task's list, not a vague
hypothesis.

A real, disassembly-confirmed cross-connection, not chased further: the
same latch (`0x20000fc9`) is **also** set to `1` unconditionally as part
of `FUN_00010ce4`'s separate `'M'`/`'T'` (i.e. `MT`) handling branch
(`0x10ef4`-`0x10ef6`, immediately before opening the Choose-Type screen,
`bl 0x10258`) — meaning receiving a real `MT` frame (`mt-quick-setup-
trigger.md`) also marks "first sync done," independent of ever calling
`FUN_0000c440`. Since the Remote's boot-time `FUN_0000c440(0)` call (4b)
happens very early in its own startup, well before the AutoPilot could
plausibly have sent `MT` yet, this does not threaten the primary
trigger's reliability — noted as a real, bounded fact, not investigated
further.

### 4d. A structurally distinct sibling, not the same mechanism

`FUN_0000c340` (the pump) has its own, separate periodic bulk-`'+'` push:
`FUN_0000b6f0`, called every time `FUN_0000c340` runs if **all** of:
`*0x20001810 == 0` (Quick Setup not in progress), `*0x20000fa0 == 0` (the
same "has real programmed data" flag `FUN_0000c440`'s own loop requires
`!= 0` — see Part 5), `FUN_00005450() != 0` (at least one channel has
real data), `*0x20000fc9 != 0` (first sync **already** done), and at
least `0xfa` (250) ticks have elapsed since its own last run. **This is
a real, recurring, roughly-every-250-tick mechanism — but it does
`FUN_000049c4`-then-`FUN_00006800`, never `FUN_00005a8c(4)` (`MC4`)** —
confirmed by full disassembly of `FUN_0000b6f0`'s own tail. **`FUN_0000c440`'s
bulk-push+`MC4` combination and `FUN_0000b6f0`'s periodic bulk-push are
two genuinely different functions with different trigger conditions and
different downstream effects** — satisfying Phase 8's "duplicate
implementation" check with a precise answer, not a vague one. Not
characterized further (its own `mode` argument is parameterized, not a
fixed `0x62`, and its own caller-context beyond `FUN_0000c340` was not
traced) — a bounded, named next step if ever needed, not part of this
slice's own target mechanism.

## Part 5 — What is actually being synchronized

**The bulk-push loop itself is separately gated**, independent of
`cVar24`: `*0x20000fa0 == 0` skips it entirely (straight to `MC4`,
`0xc9b6`). Exhaustive xref scan of `0x20000fa0`'s writers:

| Writer | Real role |
|---|---|
| `FUN_0000e670` (6 sites) | The interactive Auto-Mode configuration screen state machine (`plus-command-remote-provenance.md`'s already-known UI caller of `'+'`) |
| `FUN_0000d218` (2 sites) | A further UI-adjacent function, not traced this slice |
| `FUN_0000b6f0` (1 site) | Its own periodic-push tail (Part 4d) |

**Nothing in the boot sequence writes this flag.** This is the slice's
sharpest correction to the prior framing: **a factory-fresh or freshly
power-cycled Remote's boot-time `FUN_0000c440(0)` call reaches the push
loop with `*0x20000fa0 == 0` and sends zero `'+'` frames — only `MC4`
fires.** Real `'+'` sends from this mechanism require the user to have
interacted with the Auto-Mode UI (or reached `FUN_0000d218`) **since**
the flag was last cleared — this project did not trace `0x20000fa0`'s own
clear-side writer(s) this slice (a real, bounded UNKNOWN, not chased
further per scope).

**Separately, the per-channel record array itself (`0x20000b20`, stride
`0x120` bytes, bound `*0x20000260`) is loaded from the Remote's own
persisted (flash-backed) storage during the same boot sequence**, via
`FUN_000071d0` (reads sequential logical offsets through the shared
config-read accessor `FUN_00007188`, the same idiom this project's
AutoPilot-side persistence work already established), called from
`FUN_00007664`, called from `FUN_0000fdf0` **before** its own
`FUN_0000c440(0)` call (confirmed: `FUN_00007664()` appears earlier in
`FUN_0000fdf0`'s own body than the `'+'`/`&|`/`c440` tail). So: **the
record data can genuinely be real/persisted by the time the push loop
would check it — but the loop is gated on a separate flag that the boot
sequence never sets, not on the record data's own presence.** These are
two independent facts (data present vs. flag set), correctly kept
distinct per the task's own instruction not to conflate provenance
questions.

This directly answers "why is this bulk-push path the one that turns
Remote-side programmed state into a `G`-consumable AutoPilot target": it
is **not** because this path is special-cased for that purpose — it is
because `mode=0x62` (fixed, `0xcb0e: mov.w r11,#0x62`) is the one mode
value `persistent-record-motor-target-mapping.md`/`mc4-transition.md`
already established crosses the AutoPilot's own `>50` compute+persist
threshold. `FUN_0000c440`'s role is simply "the one real call site that
happens to use that mode value," confirmed unchanged from the prior
slices — not re-derived here.

## Part 6 — Concrete proof

`ConcreteMachine.call(0xc440, args=[...], ...)`, entering directly at
`FUN_0000c440` — the smallest meaningful real boundary, since its own
caller chain up through `Reset_Handler` is now disassembly-confirmed
unconditional and exhaustively unique (Part 4b/4a). No `.data` seed was
needed for this entry (matching `s-p-roundtrip.md`'s own precedent for
the same function).

**Leg 1** (reused unchanged, not re-derived): `capture_tx_bytes(MANDO_FW,
0xc440, 0x58a8, reg_seed=[("r0",0)], stub_calls=[0x5a14, 0xb440])` →
`b'S|\x00'`.

**Leg 2** (reused unchanged from `s-p-roundtrip.md`'s own machinery,
`AUTOPILOT_S_MODE` left at its cold-RAM default): AutoPilot's real `S`
handler + outbound dispatcher → `b'P1,\x00'`.

**Leg 3 — the new result**: `FUN_0000c440` entered directly with:

- `args=[1]` — a **disclosed substitution** for the real boot-time
  `param_1=0`. Justified precisely, not assumed: `param_1 != 0` skips
  *only* the separate `!0|`/`!1|` second round (Part 1/3), which does not
  influence `cVar24` or the push/`MC4` tail (confirmed by disassembly:
  the `goto LAB_0000c9a4` for `param_1 != 0` preserves `cVar24`
  unchanged) — and `param_1 != 0` is itself a real path (`FUN_00010ce4`'s
  `'B'`-branch caller, Part 4c), not fabricated. Avoids needing to
  fabricate a second, unrelated `!`-response merely to get past code this
  slice does not need (the event-7 field-count question stays untouched,
  per the task's own instruction).
- `stub_calls=[0x5a14, 0xb440, 0x58a8, 0xb59c, 0xc340]` — the wake
  preamble (unreached at `param_1=1` anyway), the radio-poll helper
  `0xb4f8` calls internally, the TX wrapper (so execution continues past
  every send instead of halting), the ack-wait (`FUN_0000b59c` — a real
  but not-yet-modeled retry primitive already characterized in
  `g-ack-roundtrip.md`; stubbing it is safe here since **either** ack
  outcome converges on the identical `MC4` send, confirmed by disassembly
  in Part 1), and the pump (`FUN_0000c340` — real but irrelevant
  background UI processing).
- `force_mem` at `0xc49c` (the instruction immediately after the real
  `"S|"` send's `bl 0x58a8` returns): injects the real, leg-2-produced
  `b'P1,'` bytes into the real RX ring buffer (`0x20001773`) and sets its
  write pointer (`0x200017d8`) — delivered at the exact point the real
  radio driver would have delivered it, not at function entry (which
  would be eaten by the earlier drain loop).
- `seed_mem`, disclosed explicitly: `0x20000fa0=1` ("has real programmed
  data" — stands in for a prior real Auto-Mode UI edit, per Part 5),
  `0x20000260=4` (channel count — stands in for the real `.data` value,
  bypassed since entry is past `Reset_Handler`'s own copy), `0x20000b20`
  (channel-0 record) `=500` (the **same** representative delta value
  `plus-target-distance-roundtrip.md` already used and proved end-to-end
  — reused, not a new arbitrary number).

**Result**:

```
returned cleanly: True   (real epilogue reached the call() trampoline)
cVar24 (r0) = 1
real '+' frame:  b'+1,1,1,0,98,1,0,0,0,500,0,0|'
real MC4 frame:  b'MC40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,|'
```

The `'+'` frame is **byte-identical** to `plus-target-distance-
roundtrip.md`'s own already-AutoPilot-delivered frame for the same
disclosed `delta=500` seed — confirming `confirm1=1` (one channel had
data), `confirm2=1` (first channel pushed), `channel=0`, `param_4=0`,
`mode=98`, matching Part 1's disassembly exactly. Since this is the
identical wire content already delivered into, and confirmed against,
real AutoPilot code in that prior slice (`target=500` computed and
persisted), **this slice does not re-deliver it** — per the task's own
instruction not to repeat that proof. The `MC4` frame is all-zero
per-channel fields, correctly reflecting cold AutoPilot-side motor
settings never having been configured in this scenario — its own
already-proven `setup()`-unlock effect (`mc4-transition.md`,
`mc-command-remote-provenance.md`) is unchanged and not re-run here.

## Part 7 — Does this explain the Auto Mode command stack?

**Only partially, and the task's own example sequence is explicitly not
what this slice proves.** What is actually shown:

```
Remote powers on
  -> Reset_Handler -> boot sequence -> FUN_0000c440(0)   [ALWAYS, once]
  -> real "S|" -> AutoPilot real "P..." -> cVar24=1
  -> IF *0x20000fa0 != 0 (i.e., the user had already used the Auto-Mode
     UI in a way that set it, in an EARLIER session before this exact
     power-cycle -- since RAM is cold at boot, this is almost never true
     on a literal cold boot): bulk-push whatever channels have real,
     persisted data
  -> MC4, always, once cVar24=1

Later in the SAME session (no reboot):
  user interacts with Auto-Mode UI (FUN_0000e670)
    -> sets *0x20000fa0 (real UI action, already characterized in
       plus-command-remote-provenance.md)
    -> [does NOT by itself call FUN_0000c440 or FUN_0000b6f0]
  FUN_0000c340's own periodic check (every ~250 ticks, once first-sync
  is done and Quick Setup isn't active)
    -> FUN_0000b6f0 (a DIFFERENT function -- pushes '+' but never MC4)

If radio contact is silent for ~5000 ticks, then resumes (any
['a','x']/'B' byte from AutoPilot):
    -> FUN_0000c440(0) again -> the same S/P-gated bulk-push+MC4 tail
```

**The task's own example ("record segment -> S/P sync -> bulk push+MC4
-> G/GO") is NOT proven by this slice as the real, single linear
workflow.** What IS proven: the bulk-push+`MC4` combination fires
**automatically, at boot, before any user interaction is possible**
(with an empty push in the fresh-boot case), and **can** fire again
after a real communication gap — it is fundamentally a **connection-
health-driven synchronization event**, not a direct consequence of any
specific button press. The *periodic*, UI-flag-driven half of "get
programmed data to the AutoPilot" runs through the structurally
different `FUN_0000b6f0` (Part 4d), which never sends `MC4`. **If the
product's real behavior is "program a segment, then later re-fetch/
re-verify it against AutoPilot's live state," the mechanism responsible
for the "re-fetch/verify" half is this boot-time-and-reconnect
`FUN_0000c440` path — the mechanism responsible for "get it there in the
first place during a live session" is the separate, `MC4`-free
`FUN_0000b6f0` path.** These are two real, distinct mechanisms serving
related but different purposes, not one linear pipeline.

## Confidence table

| Item | Status |
|---|---|
| `FUN_0000c440`'s real control-flow structure, both request/response rounds, and the shared `cVar24` gate | **CONFIRMED** (disassembly) |
| `cVar24` is set purely by "did a clean `'P'`-response arrive," independent of its value | **CONFIRMED** (disassembly, every path traced) |
| `MC4` is unconditional once `cVar24=1`, regardless of the push loop's own outcome | **CONFIRMED** (disassembly: single convergent instruction) |
| Exactly 4 real callers exist anywhere in the image, no indirect dispatch | **CONFIRMED** (Ghidra call graph + independent exhaustive branch scan, agree) |
| The primary trigger is `Reset_Handler` → `FUN_00016900` → `FUN_0000fdf0` → `FUN_0000c440(0)`, unconditional, once per boot | **CONFIRMED** (disassembly of all three functions, zero conditionals on the path; each has a single, unique real caller) |
| The secondary trigger (`FUN_00010ce4`, `['a','x']`/`'B'` inbound bytes) is real but debounced to fire successfully at most once between resets of `0x20000fc9` | **CONFIRMED** (disassembly; exhaustive xref scan of `0x20000fc9`/`0x2000195c`) |
| `0x20000fc9` is reset by a real ~5000-tick radio-silence timeout, re-arming the secondary trigger | **CONFIRMED** (disassembly) |
| The bulk-`'+'` loop itself additionally requires `0x20000fa0 != 0`, set only by interactive UI functions, never by the boot sequence | **CONFIRMED** (disassembly + exhaustive xref scan) — meaning a literal cold boot's push loop is empty in practice |
| The per-channel record array is loaded from Remote-local persisted storage before the boot-time `FUN_0000c440(0)` call | **CONFIRMED** (disassembly: real call order within `FUN_0000fdf0`) |
| `FUN_0000b6f0` is a structurally distinct, genuinely periodic sibling that never sends `MC4` | **CONFIRMED** (disassembly of its own gate and tail) |
| Real `'+'` (mode `0x62`) and `MC4` frames produced from `FUN_0000c440(1)` given a real `S->P` exchange and disclosed record/flag seeds | **CONFIRMED concretely** |
| `0x20000fa0`'s own clear-side writer(s) | **UNKNOWN** — not chased, bounded next step |
| `FUN_0000d218`'s own role as a second `0x20000fa0` setter | **UNKNOWN** — named, not traced |
| `FUN_00010ce4`'s `'B'`-branch call site's exact `param_1` value in real operation (data-dependent, not a fixed constant) | **UNKNOWN** by design — not concretely exercised (the `param_1=1` substitution in Part 6 is disassembly-equivalent, not this exact call site) |
| The task's own example "record -> sync -> push -> go" as one linear real workflow | **NOT SUPPORTED** — shown instead to be two distinct mechanisms (Part 7) |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by an independent
branch-decode methodology) for every structural/trigger-provenance claim.
Level 2 (concrete, Unicorn) for the produced `'+'`/`MC4` wire bytes and
the `cVar24=1` gate. No level-3 (solver-confirmed) claims made.

## Remaining bounded unknowns

1. What clears `0x20000fa0` after a real `'+'` push (so `FUN_0000b6f0`'s
   periodic check can become eligible again, and so a *second*
   `FUN_0000c440(0)` call after reconnect would find it `0` rather than
   still `1`) — not traced this slice.
2. `FUN_0000d218`'s own role and caller-context as a second setter of
   `0x20000fa0`.
3. `FUN_00010ce4`'s `'B'`-branch (`0x42`) real semantic meaning and its
   exact `param_1` value in real operation — only its structural
   equivalence to the `param_1=1` substitution used in Part 6 is
   established.
4. `FUN_0000b6f0`'s own further callers/preconditions beyond
   `FUN_0000c340`'s gate, and its own `mode` argument's real values.
