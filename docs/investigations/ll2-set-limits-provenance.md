# Investigation: `LL2|`'s Remote Sender, and the Full Set-Limits Sequence

**Question**: what exact user-visible Set Limits sequence produces `LL1|`
and `LL2|`, and how do the two joystick-positioned locations actually
become the AutoPilot's captured limit positions (`posA`/`posB`)?
`ll-limit-workflow.md` fully characterized the AutoPilot-side handler and
found `LL1`'s Remote sender (`manual-mode-wire-provenance.md`), but left
`LL2`'s sender **UNKNOWN** and the position-capture mechanism untraced.

**Scope**: static disassembly against the persistent `mando868` Ghidra
cache (`tools/ghidra/aptrace_ghidra.py`), plus concrete execution
(`ConcreteMachine`/`capture_tx_bytes`) for the real wire bytes. No fresh
Ghidra project, no hand-picked SP/LR, no fabricated packet content.

## Result, in one paragraph

**`LL2|`'s Remote sender is found, and it is the *same* function that
sends `LL1|`.** `FUN_0000de3c` — already established as the live-jog
engine shared with Manual Mode — sends `LL1|` three times as an entry
preamble, runs a jog phase, **resends `LL1|` again** (also three times)
once the user clicks and a real position-query round trip succeeds, runs
a second jog phase, then **sends `LL2|`** (three times, same idiom) once
the user clicks again and a second position-query succeeds. Both sends
are confirmed by disassembly (three independent literal-pool reads,
cross-checked against raw firmware bytes with no Ghidra involved) and by
concrete execution entering directly at each send site. **A previously
totally unknown mechanism is also found**: the "position-query" gate is a
real, undocumented use of the already-known `I9|`/`I1|` short forms
(`command-inventory.md` had flagged these as "used by a separate Remote
routine," sender unknown) — `FUN_0000b834` sends one of them, parses a
signed numeric response, and only if that succeeds does `FUN_0000de3c`
(re)send `LL1`/`LL2`. **The parsed position value itself is not
forwarded anywhere** — `LL1|`/`LL2|` are always sent as bare,
argument-less ASCII strings (confirmed at the sender, `FUN_000058a8`,
which takes only a string pointer), so no wire path exists from the
queried position to the AutoPilot's `posA`/`posB`. This is **Outcome
B**: the sender is fully found, but the position-capture path is real,
separate, and provably does not reach the AutoPilot's limit-storage
globals — a sharper, more complete version of `ll-limit-workflow.md`'s
existing negative result, not a contradiction of it.

## Confidence scale

Same as `docs/ui/action-command-map.md`: **CONFIRMED** / **PROBABLE** /
**UNKNOWN**.

---

## Phase 1 — AutoPilot-side `LL1`/`LL2` semantics (recap, unchanged)

Fully established in `ll-limit-workflow.md`; not re-derived here, only
summarized as the fixed target this slice's Remote-side findings must be
consistent with:

| Field | Value |
|---|---|
| Wire grammar | `LL1\|`, `LL2\|` — no arguments on either |
| Parser/handler | `FUN_000054e0` (shared `'L'`-family handler), reached from `FUN_00008258`'s top-level `'L'` branch, pre-`MC4` |
| RAM fields | `posA` (`0x20003114`), `posB` (`0x20002414`), `minDest` (`0x20002424`), `valid` (`0x20002458`) — all AutoPilot-image addresses |
| Samples current position? | **No** — neither instruction touches `0x20002064` (live position) |
| Clears/stages state? | `LL1` unconditionally zeros `posA`/`posB`/`valid` |
| Compares/reorders two positions? | `LL2` compares `posA`/`posB`; if they differ, orders them into `minDest`/`posB` and sets `valid=1`; if equal (including right after `LL1`), no-op |
| Hardware/MMIO effect | **None** — pure RAM bookkeeping, confirmed by disassembly and a live `--watch-mem-write` run |

Preserved verbatim: **no other code anywhere in the AutoPilot firmware
image writes `posA`/`posB` with a real value** (exhaustive literal-pool
scan). Field names (`posA`/`posB`) stay the neutral terms
`ll-limit-workflow.md` chose — this slice's findings do not license
renaming them "left/right limit."

---

## Phase 2 — The Remote-side `LL2` sender, found exhaustively

### Literal-string search (raw bytes, no Ghidra)

A plain byte scan of `research/firmware/originals/firmware_mando868.bin`
for `LL`, `LL1`, `LL2`, and bytewise `'L','L','2'` construction found
**exactly one** occurrence of each of `LL1` and `LL2` as a literal ASCII
run, and **no other** `LL` occurrence anywhere in the ~160KB image except
two unrelated substrings (`"...AR ALL\x00CLEAR..."`, `"...= NULL\x00SPICl..."`)
that are not commands:

```
flash 0x1ca83: "LL1|"   (surrounded by: "...are going to be set\x00LL1|\x00Use the joystick to...")
flash 0x1cb1e: "LL2|"   (surrounded by: "...Setting second\x00LL2|\x00No limits set...")
```

No table-driven or bytewise-constructed `'L','L','2'` variant exists
separately — both strings are ordinary compiled string literals, exactly
like `LL1|` already was.

### Xref search (Ghidra cached export)

```
$ tools/ghidra/aptrace_ghidra.py xrefs mando868 0x1cb1e
References TO 0x0001cb1e:
  0x0000e114 (FUN_0000de3c)  [PARAM]  label=DAT_0001cb1e
```

**Exactly one reference, in exactly one function — `FUN_0000de3c`, the
same function `manual-mode-wire-provenance.md` already proved sends
`LL1|` and hosts the shared binary-jog loop.** This was cross-checked by
reading the literal-pool slot directly (`tools/ghidra/aptrace_ghidra.py
literal mando868 0xe2b8` → `0x1cb1e`, matching the disassembly's
`ldr.w r8,[0xe2b8]` at `0xe10e` with zero Ghidra-labeling ambiguity).

**This search is exhaustive in the sense the task asked for**: a literal
byte scan of the whole image found the string exactly once; a
cross-reference scan of the whole image's data references found exactly
one instruction loading it; both converge on the same function, address,
and call. There is no other candidate sender anywhere in this firmware
image — **Outcome A/B, not Outcome C**: the sender exists, and it is not
hiding behind an indirect/table-driven/tail-jumped path (`FUN_0000de3c`
is reached by ordinary `bl`, and `0x58a8` is called with the pointer
value directly, not through a computed table).

### `LL1` is *also* sent a second time, from a second, separate literal

The same method applied to `LL1|`'s own string (`0x1ca83`) found **four**
references, not the one `manual-mode-wire-provenance.md` already
documented:

```
0x0000deb0, 0x0000debc, 0x0000dec8   -- the already-known entry preamble (3x)
0x0000e014                           -- a NEW, second real send, later in the
                                         same function
```

This is a genuine refinement, not a contradiction: `LL1|` is sent again,
later in `FUN_0000de3c`, under a specific real condition (Phase 3/5
below) — a fact the prior slice's "sends LL1| once on entry" summary
did not capture (it was accurate about the *entry* send but not
exhaustive about the whole function).

---

## Phase 3 — UI/state reconstruction, from real strings and real control flow

### Getting to the screen

```
FUN_0000e314  (reached from FUN_0000db34/FUN_0000d570, both part of the
               same "MANUAL MODE"-titled screen cluster (FUN_0000d988) --
               manual-mode-wire-provenance.md's own PIC-jump-shared-body
               finding)
  -> FUN_0000cb70()   -- screen-title renderer; its ONLY xref anywhere in
                          the image to "SET LIMITS" (flash 0x1c7d5)
  -> FUN_0000dd38()   -- populates a short row menu: row 0 = "Set limits"
                          or "Reset limits" (chosen by whether limits
                          already exist), row 1 = "Surpass limits",
                          row 2 = "Speed limit" (+ 2 more slots, not
                          decoded); waits for a click; on a specific row
                          selection, calls FUN_0000de3c
```

**Correcting `user-guide-workflows.md`'s own hedge**: section 11 had
placed `"SET LIMITS"` as a *possible* member of the trigger/relay
settings-screen family, based only on string-table proximity to
`"Pingpong mode"`/`"Relay contact"` — flagged there as exactly the kind
of unproven proximity inference this project warns against. **That
placement is now disproven**: `"SET LIMITS"` has exactly one real
code reference (`FUN_0000cb70`), and `FUN_0000cb70` is called from
exactly one place (`FUN_0000e314`, part of the Manual-Mode-cluster
screen family) — nothing in that call chain touches the trigger/relay
strings. The proximity in the flash string table is coincidental
layout, not a shared implementation. `I9|`/`I1|` (`command-inventory.md`'s
own "short forms, sender unknown") sit in the *same* nearby string run
as `"SET LIMITS"`/`"W1|"` purely by compiler string-pooling — this
slice found their real sender by code, not by that proximity (Phase 4).

Inside `FUN_0000e314`'s own body (702 bytes, only partially traced), the
literal `"Direction"` (flash `0x1cb98`) is written into row-slot `+0xc`
of a small local menu-row table, and a *separate* internal sub-state
check (`cmp r3,#5` at `0xe598`, gating a read of a distinct selector byte
at `[r6]`) decides: if that selector equals `1` or `8`, jump to
`FUN_0000dd38` (the Set-Limits sub-flow above); otherwise, toggle a
display flag (`0x20000fdc`) and continue the plain jog screen. **This
means Manual Mode's "Direction" row and Set Limits are literally two
rows of the *same* screen/menu**, not two independent implementations
that merely happen to share the jog primitive — a sharper version of
`manual-mode-wire-provenance.md`'s own "PROBABLE, not confirmed" hedge on
this exact point. The precise mapping of selector values `1`/`8` to
specific labeled rows in `FUN_0000e314`'s own menu was not fully
decoded this slice (bounded remaining unknown, see below) — but the
*shared-screen* structure is now disassembly-confirmed, not inferred.

### Real on-screen text, read directly from flash (no proximity guessing)

Every string below was resolved by dereferencing the exact literal-pool
slot each `FUN_00005c44` (row/line render) call in `FUN_0000de3c` uses —
not by nearby-string inference:

```
Entry screen (before LL1, unconditional, straight-line code):
  "Limit points for the"
  "cablecam movement"
  "are going to be set"
  "Click the knob"
  "to start"
    -> [wait for click]
    -> LL1|  LL1|  LL1|          (3x preamble, ~0x1e-tick spacing --
                                   the same "wake preamble" idiom this
                                   project already documented for MC/MT)

Phase 1 (conditional on a real EIC-quadrature-driven flag, see Phase 5):
  "Use the joystick to" / "Use the knob to"   (one of the two, by a mode flag)
  "move the cablecam"
  "Click the knob to"
  "confirm the"
  "limit point"
    -> [binary 0xF0/0xE0 jog stream, every tick, until click]
    -> on click:
  "Setting first"
  "limit..."
    -> I1| (or I9|, mode-dependent) -- real position query, Phase 4
    -> if it succeeds: LL1|  LL1|  LL1|   (resend, same 3x idiom)
    -> [wait for a second click, with an elapsed-time gesture check]

Phase 2 (same jog mechanism, same conditional prompt text reused):
    -> [binary 0xF0/0xE0 jog stream again, until click]
    -> on click:
  "Setting second"
  "limit..."
    -> I1| (or I9|) -- second real position query
    -> if it succeeds: LL2|  LL2|  LL2|   (3x idiom)
    -> [wait for a final click]

Outcome (selected by an internal 0/1/2 result code, not fully decoded --
see "Remaining unknowns"):
  "No limits set" / "Press knob to exit"     (one observed branch)
  -- OR --
  a different, not-yet-read branch at 0xe234 (see below)
```

This closes almost all of `user-guide-workflows.md` section 12's
`[firmware string]`/`[inferred]` hedges with a real, disassembly-proven
sequence — see the doc-update section below for the exact replacement
text. Two strings from the old hedge (`"Make sure that / the slider can /
move freely."`, `"Press knob to start" / "using the cablecam"`,
`"Detecting first/second limit..."`, `"Centering..."`, `"Finished!"`,
`"Limits successfully"`) were **not** found referenced anywhere inside
`FUN_0000de3c`, `FUN_0000dd38`, `FUN_0000cb70`, or `FUN_0000e314` by this
slice's search — they may belong to a different screen/step this slice
didn't reach (the un-traced `0xe234`/`0xe1ca`/`0xe1f4`/`0xe1fe` branches,
see "Remaining unknowns"), or may not be part of this exact flow at all.
Do not assume they belong here merely because the old doc listed them
under the same workflow number.

---

## Phase 4 — The position-capture data path (the central new finding)

### `FUN_0000b834`: a real, previously-unattributed position-query function

Disassembled in full (`0xb834`-`0xb92e`, 250 bytes). Decompiled shape:

```c
int FUN_0000b834(void) {
    // choose "I9|" (0x1c7e4) or "I1|" (0x1c7e8) by *0x200018e7
    // send it (FUN_000058a8 -- the real ASCII TX wrapper, same one every
    //   other simple command in this table uses)
    // wait up to ~1000-3000 ticks (growing +400 per retry, up to 6 tries)
    //   for a response byte that is '-' or a digit
    // parse a signed decimal number from it (FUN_0000b51c)
    // store the value at a fixed address (0x200027f0), return 1 on success
    // after 6 failed retries: set two RAM flags (an error/state pair,
    //   0x200019c3=9, 0x200002c8=0) and return 0
}
```

This is a real, general-purpose "ask the AutoPilot for its current
signed position and wait for the numeric answer" helper — the exact
mechanism `command-inventory.md`'s own "Lower-confidence" list flagged as
unexplained (`"I9| / I1| short forms — used by a separate Remote
routine, don't cleanly match the three-character I<channel><mode>
parser"`). **This closes that specific open item**: the routine is
`FUN_0000b834`, and its two callers (Phase 5) are exactly the two
"click to confirm a limit position" moments in `FUN_0000de3c`.

**Mode selector `*0x200018e7`** is the same byte `action-command-map.md`
already named (as an unresolved "4-row vs. 2-row motor-settings variant"
selector) — this slice adds a second, independent read site for it
(comparing against `0x1a`), a useful cross-link but not a semantic
resolution; that byte's real meaning stays an open item, unchanged.

### Where the query is called from, and what gates on it

```
FUN_0000de3c, after Phase-1's jog-and-click (0xe002-0xe030):
    FUN_0000591c(0); r0 = FUN_0000b834();
    if (r0 == 0) goto <skip to second-click wait, 0xe032>;
    // r0 != 0 (query succeeded):
    send "LL1|" three more times

FUN_0000de3c, after Phase-2's jog-and-click (0xe102-0xe130):
    FUN_0000591c(0); r0 = FUN_0000b834();
    if (r0 == 0) goto <skip to final wait, 0xe132>;
    // r0 != 0 (query succeeded):
    send "LL2|" three times
```

**Both call sites use the identical pattern**: query the AutoPilot's
current position, and only if a valid numeric response comes back,
(re)send the appropriate `LL` command. This answers acceptance question
6 precisely: **capture is neither automatic on click nor built into
`LL1`/`LL2` themselves — it is gated by a *separate, preceding* command
(`I9|`/`I1|`) whose success is a precondition for `LL1`/`LL2` being
(re)sent at all.**

### The captured value is not forwarded — a real, confirmed dead end

`FUN_0000b834`'s parsed value is stored at a **fixed** address,
`0x200027f0` (`DAT_0000b954`, not parameterized per call site — both
Phase-1 and Phase-2 calls write the *same* slot, so Phase 2's write
overwrites Phase 1's, with nothing observed to copy it out first). An
exhaustive xref search of `0x200027f0` across the whole Remote image
found exactly two writers: `FUN_0000b834` itself, and `FUN_000071d0` (a
wholly unrelated one-time NVM boot-config loader, coincidentally reusing
the same RAM slot as general scratch — confirmed by full decompile,
irrelevant to Set Limits). **No other function reads `0x200027f0`** —
`FUN_0000de3c` itself never reads it (only `FUN_0000b834`'s *return
code*, not its output value, is used).

Separately, `FUN_000058a8` (the real sender both `LL1|`/`LL2|` and
`I9|`/`I1|` go through) was decompiled in full:

```c
void FUN_000058a8(undefined4 param_1) {
    // wait for a minimum inter-send gap
    FUN_000117f4(radio, 0);
    FUN_00014bb6(radio, param_1);   // param_1 is a bare C-string pointer
    FUN_000113b0(radio, 0);
}
```

It takes **exactly one argument — a string pointer** — with no numeric
payload appended. Concretely confirmed (Phase 7): the exact bytes handed
to the TX wrapper are always `"LL1|\0"` or `"LL2|\0"`, never anything
longer.

**Conclusion (answers acceptance questions 5 and 7 directly)**: no
numeric position is included in any `LL` frame or companion command
reaching the wire; neither `LL1` nor `LL2` itself samples position (already
known from the AutoPilot side, and independently confirmed from the
Remote side: nothing computed by `FUN_0000b834` reaches `FUN_000058a8`'s
argument for the `LL1`/`LL2` sends). **The real, disassembly-traced
position-query mechanism exists, succeeds or fails as a real
precondition gate, and then its own result is thrown away before
`LL1`/`LL2` are sent.** This is a firmware-internal architectural gap,
not a harness limitation — the same class of finding as the blank
`0x12000` motor-target default (`target-config-provenance.md`) and the
"no producer for `posA`/`posB`" result (`ll-limit-workflow.md`), now
triangulated from a third, independent direction (the Remote's own query
mechanism) with the same conclusion.

### Answering Phase 4's six questions directly

1. Does the Remote request current position via `I`? **Yes — `I9|`/`I1|`,
   via `FUN_0000b834`, confirmed by disassembly and concretely.**
2. Does AutoPilot send position asynchronously? **No evidence found —
   this is a synchronous request/response, matching `I`'s already-known
   `event 15` response shape (`<signed-number>,`).**
3. Does the Remote maintain a local position mirror from jog traffic?
   Not established this slice — `FUN_0000b834`'s query is independent of
   the jog accumulator (`0x20001714`); no read of the accumulator by
   `FUN_0000b834` was found.
4. Does `LL1`/`LL2` itself sample position? **No** (already known from
   the AutoPilot side; independently reconfirmed here from the Remote
   side — nothing computed reaches the send).
5. Is a numeric position included in an `LL` response/companion command?
   **No — confirmed at the sender (`FUN_000058a8` takes only a bare
   string pointer).**
6. Is capture automatic on click, or via a preceding/following command?
   **Via a preceding command (`I9|`/`I1|`), but its result is discarded
   before `LL1`/`LL2` are sent — capture succeeds/fails as a gate, but
   does not populate anything `LL1`/`LL2` transmit.**

---

## Phase 5 — Relating `LL1`/`LL2` to the live-jog stream, precisely

The actual sequence, entirely disassembly-confirmed (addresses are real,
not illustrative):

```
FUN_0000de3c entry
  -> LL1| x3            (0xdeb0/0xdebc/0xdec8, ~30-tick spacing)
  -> [wait for a fresh click, with debounce]
  -> Phase-1 jog loop (0xdfa4-0xdfce): FUN_0000c340() [pump] ->
       (gated on 0x20001708==1) FUN_0000be94() [real 0xF0/0xE0 send] ->
       loop while wheel not clicked
  -> on click: screen text update ("Setting first" / "limit...")
  -> FUN_0000b834()  [I1|/I9| position query]
  -> if success: LL1| x3 again (0xe014, NEW finding -- see Phase 2)
  -> [wait for second click, elapsed-time gesture check]
  -> Phase-2 jog loop (0xe0a4-0xe0c6): structurally identical to Phase 1
  -> on click: screen text update ("Setting second" / "limit...")
  -> FUN_0000b834()  [I1|/I9| position query, again]
  -> if success: LL2| x3 (0xe114)
  -> [wait for final click; outcome branch, partially traced]
```

This confirms the task's proposed chain almost exactly, with one real
correction: **`LL1` is sent twice** (entry preamble, and again after
Phase 1's click+query succeed), not once, and **each `LL` send is
gated on a successful position query**, not sent unconditionally on
click.

### What `LL1`/`LL2` mean in this workflow (answers acceptance Q3/Q4)

Given the AutoPilot-side semantics (`LL1` = unconditional clear, `LL2` =
compare-and-validate) and this slice's Remote-side sequence:

- **`LL1` means "clear/(re-)prepare the limit-capture state"** — sent
  once at entry (before any positioning happens at all) and again after
  Phase 1's position is (ostensibly) confirmed, immediately before Phase
  2 begins. The second send is semantically odd if read as "the operator
  has just recorded point 1" — sending `LL1` again would erase it on the
  AutoPilot side (`ll-limit-workflow.md`'s disassembly is unconditional,
  no state-aware branch). **This is not smoothed over**: it is a real,
  concretely-confirmed firmware behavior that is *consistent with*, and
  helps explain, the already-established fact that no mechanism
  populates `posA`/`posB` with a real value — even if some other,
  unfound mechanism did write a real position into `posA` at Phase-1's
  click, this second `LL1` send would immediately clear it again before
  `LL2` ever runs. A plausible, unconfirmed reading: this is a "keep the
  link alive"/re-sync ping abusing the cheap `LL1` clear as a
  side-effect-free heartbeat (matching the 3x-no-ack "wake preamble"
  idiom this project has already documented for `MC`/`MT`), not a
  deliberate "re-clear" instruction — **inferred, not proven**.
- **`LL2` means "finalize/validate whatever `posA`/`posB` currently
  hold"** — sent once, at the very end, after Phase 2. Given the above,
  and given `ll-limit-workflow.md`'s exhaustive negative result, `posA`
  and `posB` are `0`/`0` (or whatever `LL1`'s last clear left them) at
  the moment `LL2` actually reaches the AutoPilot in this compiled
  firmware — so `LL2`'s own "values differ -> valid=1" branch is real
  but **not reachable via any traced real-world Set-Limits sequence**,
  matching the already-published "degenerate equal-values no-op" result
  in `ll-limit-workflow.md`.

---

## Phase 6 — Channel selection

**Negative result, checked directly rather than assumed**: Auto Mode's
known channel selector (`0x2000180c`, used by `'+'`/`G`) has **zero**
references anywhere in `FUN_0000de3c`, `FUN_0000dd38`, `FUN_0000cb70`,
`FUN_0000e314`, `FUN_0000d570`, `FUN_0000db34`, or `FUN_0000d988`
(exhaustive xref check) — **Set Limits does not reuse Auto Mode's
channel-selection mechanism.** The two RAM bytes `FUN_0000de3c` writes
immediately before each `FUN_0000be94()` call (`0x200001b8`, `0x200001d4`
— one set to `0`/`0x63` depending on the `0x20001708` gate) were checked
against `FUN_0000be94`'s and `FUN_0000bb38`'s own bodies and are **not**
read by either — they appear to be display/animation state, not
arguments to the frame builder. The real per-channel value inside the
binary jog frame comes from `FUN_0000bb38`'s own internal joystick-read
logic (a 772-byte function reading raw axis registers `0x37`/`0x38`),
**exactly the same unresolved source `manual-mode-wire-provenance.md`
already flagged as UNKNOWN** — this slice does not close it, and per the
task's own scope, does not chase it further here. **Inherited, not
re-derived, not newly broadened.**

---

## Phase 7 — Concrete proof

All captures below use this project's existing `capture_tx_bytes`
primitive (`tools/unicorn/virtual_link.py`, `REMOTE_TX_WRAPPER=0x58a8`),
entering directly at real, disassembly-confirmed addresses on the
**real, unmodified** `mando868` image — no fabricated packet bytes, no
hand-picked SP/LR.

```
0xdeb0 (LL1 preamble send)  -> 0x58a8: bytes=b'LL1|\x00'
0xe00e (post-phase-1 resend) -> 0x58a8: bytes=b'LL1|\x00'
0xe10e (LL2 send)            -> 0x58a8: bytes=b'LL2|\x00'
0xb834 (position query, cold RAM)         -> 0x58a8: bytes=b'I1|\x00'
0xb834 (position query, *0x200018e7=0x1a) -> 0x58a8: bytes=b'I9|\x00'
```

The first three needed no register seed or stubbing at all — each entry
point is a self-contained "load pointer from this function's own literal
pool, call the TX wrapper" pair, the smallest meaningful boundary for
proving each send (the same precedent this project already used for
`FUN_0000be94`). The `FUN_0000b834` captures needed three real-but-
irrelevant helper calls stubbed (`FUN_0001486c` — haptic; `FUN_0000b4f8`,
`FUN_0000583c` — an idle/exit-check pump pair inside its own retry-wait
loop; the real tick reader `FUN_00016840` was **not** stubbed, since
stubbing it stalls the elapsed-time comparison) and a larger instruction
budget (400,000) to let the real ~1000-3000-tick wait play out — a
disclosed, bounded harness accommodation, not a fabricated result; the
*command choice* (`I9|` vs `I1|`) and the *bytes themselves* are exactly
what the real, unmodified code computes from the seeded/cold mode byte.

This satisfies this slice's version of the task's "smaller concrete
boundary" allowance (Phase 7): the command-producing state (which
literal string gets loaded) and the position-source selector
(`*0x200018e7`) are both real; only the surrounding UI click/tick
machinery is bypassed by entering directly at each send site, exactly as
`manual-mode-wire-provenance.md` already did for `FUN_0000be94`. No
`posA`/`posB` value was hand-patched at any point — consistent with the
task's explicit instruction not to fake that value into existence.

---

## Phase 8 — Ordering/validation semantics (inherited, unchanged)

Carried forward verbatim from `ll-limit-workflow.md`, since this slice's
Remote-side tracing did not find any real sequence that changes `posA`/
`posB` away from `0`/`0` before `LL2` runs:

- `posA < posB`: not reachable in the traced real sequence (both are
  always `0` when `LL2` runs).
- `posA > posB`: same.
- `posA == posB` (including the always-true `0==0` case): `LL2` takes its
  documented no-op branch — no write to `minDest`, `valid` stays `0`.
- No margin/offset, no low/high normalization beyond the simple
  min/max reorder already documented; no explicit zero/negative-value
  restriction found.
- Validity flag: `0x20002458` (AutoPilot), `1` only when `posA != posB`
  at `LL2` time.

---

## Phase 9 — Persistence/lifecycle (inherited, unchanged)

`posA`/`posB`/`minDest`/`valid` are plain AutoPilot `.bss` RAM, cleared
by `Reset_Handler`'s bulk zero and by every `LL1` — **not** part of the
`0x12000`-backed persisted config struct (`nvm-param-and-full-
roundtrip.md`'s own persistence mechanism). They do **not** survive
AutoPilot reboot, do **not** survive `LL1`, and were never observed
touching NVM. Remote-side: `0x200027f0` (the discarded position-query
scratch value) is likewise plain RAM, reused as a boot-time NVM-load
scratch slot by an unrelated function (`FUN_000071d0`) — no persistence
role for Set Limits specifically.

---

## Confidence table

| Item | Status |
|---|---|
| `LL2\|`'s exact string address (`0x1cb1e`) and its exactly-one xref (`FUN_0000de3c` @ `0xe114`) | **CONFIRMED** (raw byte scan + Ghidra xref + direct literal-pool read, three independent methods agreeing) |
| `LL2` shares its sender with `LL1` (both inside `FUN_0000de3c`) | **CONFIRMED** (disassembly) |
| `LL1` is sent a second time, later in the same function, gated on a real position-query success | **CONFIRMED** (disassembly + concrete capture) |
| The exhaustive sender search found no other `LL2` candidate anywhere in the image (no bytewise/table-driven/indirect construction) | **CONFIRMED** (raw scan + xref scan both exhaustive over the whole image) |
| `FUN_0000b834` is the real sender of `I9\|`/`I1\|`, selected by `*0x200018e7`, parsing a signed numeric response | **CONFIRMED** (disassembly + concrete capture of both arms) |
| `FUN_0000b834`'s success/failure gates whether `LL1`(resend)/`LL2` are sent at all | **CONFIRMED** (disassembly) |
| The parsed position value is not forwarded to `LL1`/`LL2` or any other traced command | **CONFIRMED** (exhaustive xref of the storage slot `0x200027f0`; `FUN_000058a8`'s single-string-pointer signature) |
| `"SET LIMITS"` belongs to the Manual-Mode-cluster screen, not the trigger/relay settings family | **CONFIRMED** (single xref chain, disproving the prior proximity-based hedge) |
| Manual Mode's "Direction" row and Set Limits are two rows of the *same* screen (`FUN_0000e314`) | **CONFIRMED** structurally (both string writes and the routing branch are in the same function); **PROBABLE** for the exact row-index-to-label mapping (selector values `1`/`8`, not fully decoded) |
| Real on-screen text for the whole sequence (title, both positioning-phase prompts, both "Setting Nth limit..." transitions, "No limits set"/"Press knob to exit") | **CONFIRMED** (direct literal-pool reads, matched to specific render call sites) |
| The full outcome branch (success text, `"Process failed"`/`"Limits successfully"`, `"Centering..."`) | **UNKNOWN** — the `0xe234`/`0xe1ca`/`0xe1f4`/`0xe1fe` branches were not disassembled this slice |
| Channel selection for Set Limits' jog phases | **UNKNOWN**, inherited unchanged from `manual-mode-wire-provenance.md` — confirmed *not* to reuse Auto Mode's `0x2000180c` |
| AutoPilot-side `LL1`/`LL2` semantics, ordering/validation, persistence | **CONFIRMED**, inherited unchanged from `ll-limit-workflow.md` |

## Remaining bounded unknowns

1. **The exact outcome branch** after the second `LL2` send-or-skip:
   `FUN_0000de3c`'s own internal result code (`r4` ∈ observed range,
   with at least one branch showing `"No limits set"`/`"Press knob to
   exit"`) has at least one more, un-disassembled arm at `0xe234`
   (reached when the elapsed-time check's `r3` equals `5`) that likely
   contains `"Limits successfully"`/`"Process failed"` — not traced this
   slice.
2. **The exact row-selector values (`1`/`8`) inside `FUN_0000e314`** that
   route into the Set-Limits sub-flow versus the plain-jog "Direction"
   path — structurally confirmed as two rows of one screen, but the
   precise click gesture/menu-index producing each value was not traced
   to the same "displayed string -> input -> state" rigor this project
   holds other findings to.
3. **`FUN_0000bb38`'s exact channel/value source** for the binary jog
   frame — pre-existing, unchanged, not chased further per scope.
4. **Whether a real position ever *does* reach `posA`/`posB`** through
   some entirely different mechanism this project hasn't looked at yet
   (e.g., the `LH1`-`LH4` family sharing `FUN_000054e0`, explicitly
   out-of-scope for both this slice and `ll-limit-workflow.md`) — named,
   not started.

## Outcome classification

**Outcome B** (per the task's own framing): `LL2`'s sender is fully
found and closed; the position-capture mechanism (`I9|`/`I1|` via
`FUN_0000b834`) is real, separately characterized, and shown — not
assumed — not to converge with `LL1`/`LL2`'s own wire content. The two
paths (command-sending state machine, and position-query gate) are now
both concretely mapped and shown to run alongside each other without
the second ever feeding the first.

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by independent
raw-byte scan and Ghidra xref) for the sender identification and full
control-flow structure. Level 2 (concrete, Unicorn) for all five wire
captures in Phase 7. No solver/symbolic step used or needed.
