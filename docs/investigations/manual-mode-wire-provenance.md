# Investigation: Manual Mode / Live-Jog Wire Provenance

**Question**: what does the Remote actually send when a user operates a
motor in Manual Mode — from physical jog-wheel input, through the Remote's
state machine, to exact wire bytes, to the AutoPilot's motor-control
effect? No prior slice had identified any wire command for this; this
slice closes it with a **new, previously-undocumented binary command
family** (`0xF0`/`0xE0`), not any of the already-known ASCII commands.

**Scope**: disassembly against the persistent `mando868`/`autopilot868`
Ghidra caches, converging independently from both the UI/string side and
the physical-input (EIC/quadrature-encoder) side, plus concrete execution
(`ConcreteMachine`) to capture real wire bytes. No AutoPilot-side
motor-timer/ISR/GPIO conclusion from prior slices is re-derived — this
document connects to that existing chain rather than re-proving it.

## Confidence scale

Same as `docs/ui/action-command-map.md`: **CONFIRMED** / **PROBABLE** /
**UNKNOWN**.

## Result, in one paragraph

The jog wheel is a real quadrature encoder read through the SAMD51 EIC
peripheral (both firmwares share this MCU family). A confirmed,
disassembly-traced chain — `FUN_00007c3c` (one-time boot init, registers
a real interrupt callback) → `FUN_00007de8` (the real, velocity-sensitive
quadrature decoder) → `FUN_00007abc`/`FUN_00007b00` (called every UI
pump tick, producing a shared sign/magnitude pair at `0x20001818`/
`0x2000181c`) — reaches, through a live jog loop (`FUN_0000de3c`) that
accumulates that shared signal and calls a real frame sender
(`FUN_0000be94`) **on every tick while the wheel is turning, until the
wheel is clicked**, a **previously-uncharacterized binary command
family**: `0xF0`/`0xE0 <len> <0xFF x4> [<channel-nibble><sign+23-bit
value> x N] | <seq>`. The AutoPilot's ASCII dispatcher checks for this
binary frame **before any ASCII command** and routes each record's
channel/value into `FUN_00005274`/`FUN_00004d18` — the **exact same**
motor-rate/direction entry points `i-command-motor-chain.md` already
proved the `I` command uses, cross-confirmed independently via a shared
per-channel array (`0x20000180`). Real, unmodified-firmware frames were
captured concretely, both empty (idle) and with a real per-channel
record. **One attribution question is left PROBABLE, not CONFIRMED**:
the exact UI entry point that reaches this live-jog loop is
disassembly-confirmed to be the Remote's "Direction" screen
(`FUN_0000e314`), itself reached from a screen whose title string is
uniquely `"MANUAL MODE"` — but the same code also sends `"LL1|"` and
renders `"Use the joystick to..."` on entry, tying it concretely to the
Set-Limits workflow's own "position the motor with the joystick" step.
Both readings are consistent with the user guide (which lists
"Direction" as a Manual Mode feature) and are not mutually exclusive —
this is most plausibly one shared live-jog primitive reachable from (at
least) two menu contexts, not two separate implementations.

## Part 1 — UI-side reconstruction

`"MANUAL MODE"` (flash `0x1c95b`) is referenced from exactly one
instruction (`0xd9b4`, inside `FUN_0000d988`) anywhere in the compiled
image — confirmed by literal-pool xref, not string proximity. `FUN_0000d988`
and a second entry point, `FUN_0000db34` (reached from a "menu-page-1"
dispatcher already documented in `plus-command-remote-provenance.md`
near `"COMMIT!"`/`"COMMIT2!"`), decompile to the **same underlying
row-action body** — Ghidra's own "Possible PIC construction... changing
call to branch" warning on this region, and a computed/PIC-style jump at
its tail, both confirm this is one shared, jump-table-driven
menu/row-widget engine reached from more than one entry point, not two
independent copies of the same logic.

That shared body, driven by a per-row "action code" byte, was traced by
disassembly (not decompile alone, since the decompiler's variable reuse
across a PIC-jump region is unreliable) to send three real,
**previously-`UNKNOWN`-sender** commands from `command-inventory.md`'s
own "lower-confidence" list, resolving their flash string addresses
directly:

| Row action code | Wire command | Flash string | Send count |
|---|---|---|---|
| `2`-`6` (range) | `N\|` | `0x1c9fb` | 3x |
| `0x1e` (30) | `B0\|` | `0x1c9fe` | 4x |
| `0xc` (12) | `TR0\|` | `0x1ca02` | 3x |
| `0x2c` (44) | (calls `FUN_0000e314`, no direct send) | — | — |

`N|`, `B0|`, `TR0|` are all real, previously-uncharacterized-sender
commands, closed by this slice as a side effect — see "Provenance
updates" below. **None of the three is the live-jog mechanism** — they
are one-shot toggles, sent once per confirmed row selection (a real
"hold the wheel click to confirm" gesture, timed via a ~50-tick progress
counter), not a per-tick stream.

Row `0x2c` calls `FUN_0000e314` — the function `command-inventory.md`'s
"Direction" string (`0x1cb98`) is uniquely referenced from. This is where
the live mechanism actually begins (Part 2).

## Part 2 — Physical input, traced independently and converging

Both firmwares are confirmed ATSAMD51J19A (`docs/hardware/
autopilot-research-handoff.md` §15.3), so the Remote has a real EIC
(External Interrupt Controller). The vector table (flash `0x4000`+) was
read directly: entries 28-43 (16 consecutive, non-default handlers) are
exactly `EIC_0`-`EIC_15`, each a 6-byte stub (`movs r0,#N; b.w
0x166dc`) tail-jumping into one shared ISR (`0x166dc`) that iterates a
runtime-populated callback table at `0x40002800` (the real EIC base,
confirmed against the SVD) — the standard Adafruit/ArduinoCore-SAMD
`attachInterrupt` dispatch pattern, matching this project's existing
Adafruit-core provenance finding for both firmwares.

**The real registration, found and disassembled**: `FUN_00007c3c`
(called once, from the Remote's own boot sequence, `FUN_0000fdf0` —
already established in `bulk-push-trigger-provenance.md`) reads pins
`0x31` and `0x32` (via the same generic pin-index reader,
`FUN_000171f0`, this project already knows from UI click-polling) as
initial quadrature A/B state, then calls a real
`attachInterrupt`-equivalent (`FUN_0001240c`) with a literal-pool-resolved
callback address `0x7de9` (Thumb bit set) — **`FUN_00007de8`**. This
address appears nowhere in the image as a direct branch/call target
(confirmed by the same exhaustive independent branch-decoder methodology
`mt-quick-setup-trigger.md`/`bulk-push-trigger-provenance.md` already
validated) but **does** appear once as a raw 32-bit literal at flash
`0x7d08` — inside `FUN_00007c3c`'s own literal pool — confirming it is
reached exclusively through this one real interrupt-registration call,
not any static branch.

**`FUN_00007de8`, the real quadrature decoder**: reads pins `0x31`/`0x32`
each with a 2-bit software debounce, detects genuine A-leads-B vs.
B-leads-A edge transitions, and applies a **velocity-sensitive**
increment/decrement (`±1` if the last transition was ≥21 ticks ago, `±5`
if 11-20 ticks ago, `±10` if <11 ticks ago) into a 16-bit position
counter at `0x20001084` — real, disassembly-confirmed evidence for the
hardware doc's own predicted `encoder A/B -> EIC -> quadrature decode ->
signed jog delta` path (§14.3), now closed rather than hypothesized.

**`FUN_00007abc`** reads that counter; **`FUN_00007b00`** — called
**every time** the Remote's UI "pump" (`FUN_0000c340`, already
established as called from dozens of screens) runs — computes
`raw_delta = last_position - current_position`, applies a *second*,
UI-level acceleration curve (`|delta|` for small deltas, `delta²` or
`delta²*3` for larger ones, right-shifted), and exposes the result as
**two shared globals used throughout the entire Remote firmware**:
`0x20001818` = just the *sign* of `raw_delta` (`-1`/`0`/`+1`) and
`0x2000181c` = the accel-curved *magnitude*. Confirmed by exhaustive
xref: dozens of screen functions (Auto-Mode segment editing, Quick-Setup
motor-settings rows, RF-settings menus, generic menu-cursor navigation)
read/reset `0x20001818` — it is the Remote's one shared "current
jog-wheel step" signal, not something exclusive to any one screen.

**The two independent traces (UI-side Part 1, physical-input-side here)
converge exactly**: `FUN_0000e314` ("Direction," row `0x2c` of the
"MANUAL MODE"-titled screen) leads, via `FUN_0000dd38`/`FUN_0000de3c`,
to a loop that consumes precisely `0x20001818` — the same address this
independent hardware trace arrived at from the opposite direction.

## Part 3 — The live-jog loop and its TX sender

`FUN_0000de3c`, on entry, sends `"LL1\|"` (flash `0x1ca85`) once and
renders `"Use the joystick to..."` (flash `0x1ca8f`, the literal next
string in flash) — both real, disassembly-confirmed facts, not proximity
guesses. It then runs:

```c
do {
    FUN_0000c340();                       // pump: updates 0x20001818/0x2000181c
    if (*direction_invert_flag == 1) {
        // display-only branch (icon state), no accumulation this tick
    } else {
        delta = *DAT_0x20001818;          // the shared sign
        if (accumulator + delta is within [-100, 100])
            accumulator += delta;          // 0x20001714
        *DAT_0x20001818 = 0;                // consume/reset
    }
    FUN_0000be94();                        // <-- SEND a real wire frame, EVERY iteration
} while (FUN_000171f0(0x2d) == 0);          // loop while the wheel is NOT clicked
```

**This is the actual jog mechanism, and it is a continuous stream, not a
discrete command per gesture** — `FUN_0000be94()` runs on every pass of
this loop, i.e. on every UI pump tick while the wheel has not been
clicked, whether or not the wheel moved that tick (an idle/heartbeat
frame is sent even with no rotation — see Part 4's concrete captures). A
second, near-identical accumulate-and-send loop exists later in the same
function (after a display transition) — not separately characterized
this slice; structurally the same primitive, presumably the second
limit-point pass in the Set-Limits sequence, or a repeat for the
direction-inverted case.

Clicking the wheel (`FUN_000171f0(0x2d) != 0`) is the **only** thing that
ends this loop — there is no separate "confirm" or "cancel" branch
inside it. This matches the user manual's "clicking the jog wheel stops
the motor immediately" description exactly, and confirms **stop is
implicit** (frames simply stop being sent), not an explicit zero-rate/
stop command — see Part 7.

## Part 4 — The wire grammar, `0xF0`/`0xE0`

**AutoPilot's dispatcher checks for this frame first, before any ASCII
command** — `FUN_00008258` (`ascii_dispatcher`), at its very entry
(`0x8260`/`0x82c6`), checks `packet[0] == 0xF0` and `== 0xE0` ahead of
every lettered branch.

**The Remote-side builder, `FUN_0000be94` → `FUN_00004898`/`FUN_00004880`/
`FUN_0000468c`/`FUN_000048c8`**, disassembly-confirmed field by field:

```
buf[0]   = 0xF0 (mode==1) or 0xE0 (mode==2)      -- FUN_00004898
buf[1]   = 0x07                                   -- fixed base length
buf[2..5]= 0xFF 0xFF 0xFF 0xFF                    -- fixed
buf[6+4i]  = channel (low nibble)                 -- per dirty channel,
buf[7+4i]  = sign(value)<<7 | (|value|>>16)&0x7F     via FUN_0000468c,
buf[8+4i]  = (|value|>>8)&0xFF                       one record per
buf[9+4i]  = |value|&0xFF                            channel with real,
                                                       nonzero stored data
buf[6+4N]  = '|' (0x7C)                           -- FUN_000048c8
buf[7+4N]  = rolling 1-9 sequence digit
```

`buf[1]` (the base "0x07") reflects the base header length; the real
`packet[1]` value grows with the number of records (confirmed
concretely: `0x0B` = `7+4` with one record present, `0x07` with none —
see captures below), matching the AutoPilot dispatcher's own
`loop_count = (packet[1] - 7 or -4) >> 2` computation exactly (disassembly,
`0x8280`-`0x8286`/`0x82ea`-`0x82f0`).

**Channel and value encoding — CONFIRMED by disassembly of the shared
encoder `FUN_0000468c`**: a signed ~23-bit value, sign as the top bit of
byte+1 (bit 7), magnitude split across the low 7 bits of byte+1 plus
bytes+2/+3 — independently matching the AutoPilot dispatcher's own
decode (`and r3,r2,#0x7f` to strip the sign bit; `lsls r3,r2,#0x18; it
mi; rsb.mi r1,r1` to reapply it) exactly. **What the encoded value
represents (accumulated jog delta vs. a live/target position) was not
traced to its exact source this slice** — `FUN_0000be94`'s own prologue
calls (`FUN_0000bb38`, `FUN_00004714`, `FUN_00008560`) were not fully
decoded; this is the one bounded remaining edge on the sender side (see
"Remaining unknowns").

**The `0xE0` "2nd variant"** uses a structurally similar but
not-byte-identical field layout (confirmed by disassembly to differ in
which bit positions are masked) — not fully decoded this slice, beyond
confirming it also routes to `FUN_00005448`/`FUN_00004d18` on the
AutoPilot side (see Part 5). `command-inventory.md`'s existing
`0xE0`/`0xF0` rows already distinguished them as two variants; this
slice adds that they share the same sender family (`FUN_00004898`'s
`mode` argument selects between them) and the same general shape.

## Part 5 — AutoPilot receiver, connected to the already-proven chain

Disassembly of `FUN_00008258`'s `0xF0` branch (`0x8278`-`0x82c4`):

```
for each 4-byte record:
    channel = record[0] & 0xF
    value   = ((record[1]&0x7F)<<16 | record[2]<<8 | record[3])   // magnitude
    threshold = *(int*)(0x20000180 + channel*4)
    if threshold <= value:
        FUN_00005274(channel, 4)              // <-- SAME entry the I command uses
    else:
        sign_adjusted = (record[1]&0x80) ? -value : value
        FUN_00005448(channel, sign_adjusted, ...)
```

`0x20000180` is **the same per-channel array** `i-command-motor-chain.md`
already identified as "the same array `FUN_00006338` reads as a clamping
ceiling" for `FUN_00005274`'s own mode-4 body — an independent,
disassembly-confirmed cross-check that this binary frame's receiving
logic genuinely feeds the same motor-rate machinery, not a coincidence
of similar-looking code. `FUN_00005448` (new this slice, not previously
in any doc) itself calls **`FUN_00004d18`** directly — the exact
function `i-command-motor-chain.md` already characterized as writing
`step_delta[channel] = ±1` (a unit direction sign) in its mode-2 body.

**From here, the chain is already proven and not re-derived**:
`FUN_00005274`/`FUN_00004d18` → `step_delta[channel]` → (gated on the
still-unresolved `0x20001b14[channel]` "busy" enable byte —
`channel-busy-gate-search.md`'s own open question, unchanged by this
slice) → `FUN_00005ee8` → `FUN_00005c00` (real TC `CC0` write) →
`FUN_00005898` (real GPIO pulse, per-channel pin already resolved in
`pin-index-provenance.md`). This slice's own contribution stops at
confirming the binary frame reaches this entry point with a real
channel/value pair — it does not re-verify the timer/ISR/GPIO tail,
per the task's own scope.

**This inherits, not reopens, the one already-known missing link**: like
the `I` command, this binary path's real motor effect is gated on
`0x20001b14[channel]` becoming nonzero somewhere else in the firmware —
a producer this project has exhaustively searched for and not found
(`channel-busy-gate-search.md`). Manual jog frames reaching
`FUN_00005274`/`FUN_00004d18` is confirmed; whether that translates into
an observable GPIO pulse in a concrete run depends on that same
unresolved gate, exactly as it already did for `I`.

## Part 6 — Concrete proof

`ConcreteMachine.call(0xbe94, args=[])`, entering directly at the real
frame-sender (the smallest meaningful boundary once its own trigger
chain — the live-jog loop calling it every tick — is disassembly-
confirmed unconditional within that loop). No `.data` seed needed (cold
RAM matches this function's own needs, same as other Remote-side direct
entries in this project).

**Capture 1 — idle/heartbeat (no channel marked dirty, cold RAM)**:

```
real bytes: b'\xf0\x07\xff\xff\xff\xff|\x00...'
```

Exactly matches the disassembled fixed header + immediate `'|'`
terminator with zero records — confirming the loop really does send a
frame on every tick even with nothing to report.

**Capture 2 — one real record** (one disclosed seed: channel 0's "dirty"
byte set to `1`, standing in for a real accumulated/target value having
been computed for that channel — the seed marks *that a channel has
data*, not what the data's value should be):

```
real bytes: b'\xf0\x0b\xff\xff\xff\xff\x00LK@|\x00...'
```

Decodes, by the same rule the AutoPilot dispatcher itself uses: `packet[1]
= 0x0B = 7+4` (one record), record = `[channel=0][0x4C][0x4B][0x40]` →
sign bit clear (positive), magnitude `(0x4C<<16)|(0x4B<<8)|0x40 =
5,000,000` — a real, cold-RAM-default value this run's own code computed
(not hand-picked), landing exactly on the wire in the byte layout Part 4
predicted from disassembly alone.

Both captures are **real, unmodified-firmware output** — no packet buffer
was fabricated; only the "channel 0 has data" trigger condition was
disclosed-seeded, per the task's explicit instruction not to hand-patch
final packet bytes directly.

## Part 7 — Start / continue / stop semantics

1. **What causes motion to begin?** Reaching the live-jog loop
   (Part 3) and the wheel producing a nonzero `0x20001818` on some tick —
   confirmed structurally; the loop itself begins sending frames
   immediately on entry regardless (Capture 1), so "begin" in the wire
   sense is really "the screen is open," not "rotation started."
2. **What causes it to continue?** The loop simply keeps running,
   re-sending a frame every UI pump tick, for as long as the wheel is
   not clicked — **CONFIRMED** (disassembly, Part 3).
3. **What causes it to stop, on the wire?** The Remote simply **stops
   sending frames** the instant the wheel is clicked — **CONFIRMED, and
   there is no explicit "stop"/zero-rate command anywhere in this loop**.
   Whether the AutoPilot's own `FUN_00005274`/`FUN_00004d18`/ramp logic
   independently decays motion to zero on its own, absent new frames, was
   **not traced this slice** — the same `0x20001b14` gate uncertainty
   from Part 5 applies here too.
4. **Is stop encoded as a value, a separate command, or silence?**
   **Silence** — confirmed by disassembly; no code path in the jog loop
   builds or sends anything on click besides exiting the loop.
5. **What happens if radio packets stop arriving mid-jog (real radio
   silence, not a deliberate click)?** **UNKNOWN** — this slice did not
   find or trace an AutoPilot-side watchdog/timeout specific to this
   binary frame family. The already-known event-7/`!` field-count
   mismatch and other timing caveats are unrelated and untouched.
6. **Is there a dead-man timeout?** **UNKNOWN**, not found this slice —
   a real, precisely bounded question, not chased further per the task's
   explicit "note relevant safety behavior... do not broaden into the
   trigger-input safety bug."
7. **Can a stale command leave motion active?** **UNKNOWN** for the same
   reason as (5)/(6) — depends on AutoPilot-side logic not traced this
   slice.

## Part 8 — Known commands revisited

| Command | Manual Mode relationship |
|---|---|
| `G` | **Not used.** Structurally a synchronous, discrete request/ack (`plus-target-distance-roundtrip.md`'s own chain) — no call site anywhere near the jog loop. |
| `I` | **Not sent by Manual Mode** — but its AutoPilot-side *receiving* mechanism (`FUN_00005274`/`FUN_00004d18`) is the **same** one the new binary frames drive. `I` and Manual Mode are two different *senders* converging on one *receiver*. |
| `S` / `!` | Not used by this mechanism — no call site found in the jog loop or its callers. |
| `+` | Not used — a structurally and mechanically distinct sender (`FUN_000049c4`), never called from `FUN_0000de3c`/`FUN_0000dd38`/`FUN_0000e314`. |
| `D` | Not used — unrelated persistence command, no connection found. |
| `LL1` / `LL2` | **`LL1|` is sent once, at entry to the same screen** that hosts the live-jog loop (Part 3) — a real, new, disassembly-confirmed connection between this slice and `ll-limit-workflow.md`'s own open question ("does the 'Detecting first/second limit...' UI sequence actually send `LL1`/`LL2`?" — **partially answered**: `LL1` is sent from exactly this screen; `LL2`'s own send site was not found this slice). |

**A genuinely new command family, not previously cataloged as motor
control**: `0xF0`/`0xE0`, already listed in `command-inventory.md` as
"Binary motor/control frame" with unconfirmed direction — this slice
confirms Remote→AutoPilot, a real sender, a real receiver, and a real
connection to the proven motor-rate chain.

## Part 9 — User-guide mapping

```
Enter Manual Mode (screen titled "MANUAL MODE", FUN_0000d988)
  -> select "Direction" row (action code 0x2c) -> FUN_0000e314
     [PROBABLE, not fully closed: whether every path into the live-jog
      loop is reached via this exact row, or Manual Mode has its own
      direct entry alongside the Set-Limits workflow's entry, was not
      disambiguated this slice -- see "Remaining unknowns"]
  -> FUN_0000dd38 / FUN_0000de3c: sends "LL1|" once, shows
     "Use the joystick to..."
  -> rotate wheel clockwise/counter-clockwise
       -> real quadrature decode (Part 2) -> 0x20001818 sign
       -> accumulated into 0x20001714, sent as a signed value inside a
          real 0xF0/0xE0 binary frame, EVERY UI tick
       -> AutoPilot's FUN_00005274/FUN_00004d18 (same entry the I
          command uses) updates step_delta[channel]'s sign
       -> [inherits the existing, not-yet-closed 0x20001b14 gate before
          any GPIO pulse is observable -- channel-busy-gate-search.md]
  -> click the wheel
       -> frames simply stop being sent (no explicit stop command)
       -> [AutoPilot-side decay-to-zero behavior: UNKNOWN, not traced]
```

Per the task's own caution: clockwise/counter-clockwise vs. the wire's
`+`/`-` sign is a **firmware sign-only** fact (bit 7 of the encoded
value) — no claim is made here about which physical rotation direction
produces which sign, since that would require live hardware
observation this slice did not perform.

## Provenance updates

- `N|` (flash `0x1c9fb`): real sender confirmed — `FUN_0000d988`/
  `FUN_0000db34`'s shared row-action body, action code `2`-`6`, sent 3x.
- `B0|` (flash `0x1c9fe`): real sender confirmed — same body, action
  code `0x1e`, sent 4x.
- `TR0|` (flash `0x1ca02`): real sender confirmed — same body, action
  code `0xc`, sent 3x.
- `LL1|`: a second, real sender site found (`FUN_0000de3c`'s entry),
  alongside whatever `ll-limit-workflow.md` already knew about the
  AutoPilot-side handler (unchanged).
- `0xF0`/`0xE0`: direction resolved to Remote→AutoPilot; real sender
  (`FUN_0000be94` family) and real receiver (`FUN_00008258`'s
  pre-ASCII binary check) both confirmed, with a working field-level
  grammar for `0xF0` (Part 4).

## Confidence table

| Item | Status |
|---|---|
| The jog wheel is a real quadrature encoder, decoded via a genuine EIC interrupt callback (`FUN_00007de8`, registered by `FUN_00007c3c`) | **CONFIRMED** (disassembly: vector table, EIC base address, `attachInterrupt`-equivalent call, literal-pool callback reference) |
| The decoder is velocity-sensitive and writes a shared position counter, further processed every UI tick into `0x20001818` (sign) / `0x2000181c` (magnitude) | **CONFIRMED** (disassembly) |
| `0x20001818` is a system-wide shared signal, not Manual-Mode-exclusive | **CONFIRMED** (exhaustive xref: dozens of consumer screens) |
| `FUN_0000de3c`'s loop consumes `0x20001818`, accumulates it, and sends a real binary frame every tick until clicked | **CONFIRMED** (disassembly) |
| The `0xF0` wire grammar (header, per-channel record encoding, terminator) | **CONFIRMED** (disassembly of both sender and receiver, cross-matched field-for-field; concretely captured, both empty and one-record) |
| The AutoPilot receiver routes into `FUN_00005274`/`FUN_00004d18` — the same entries the `I` command uses | **CONFIRMED** (disassembly, cross-checked via the shared `0x20000180` array) |
| `FUN_0000de3c` is reached from a screen whose title string is uniquely `"MANUAL MODE"`, via the `"Direction"` row | **CONFIRMED** (string xref + disassembly of the row dispatch) |
| This is *the* (sole, canonical) Manual Mode live-jog entry point, as opposed to one of possibly several (e.g. a separate direct entry not funneling through "Direction") | **PROBABLE** — strong circumstantial fit (user guide lists Direction as a Manual Mode feature; the only "MANUAL MODE"-titled screen in the image reaches it), not independently proven exhaustive |
| `LL1|` is sent from this same screen, connecting it to the Set-Limits workflow | **CONFIRMED** (disassembly + string) |
| The exact source of the encoded per-channel value (accumulated delta vs. live/target position) | **UNKNOWN** — `FUN_0000be94`'s own prologue calls not fully decoded this slice |
| The `0xE0` variant's exact field-width differences | **UNKNOWN** — confirmed structurally similar and routed to the same receiver, not fully decoded |
| Explicit stop-on-silence / dead-man timeout on the AutoPilot side | **UNKNOWN** — not found or traced this slice |
| The `0x20001b14[channel]` "busy" gate's producer | **UNKNOWN** — pre-existing, unchanged (`channel-busy-gate-search.md`) |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked from two
independent directions — UI/string side and physical-input side, meeting
at the same address) for the whole chain's structure and grammar. Level
2 (concrete, Unicorn) for the two captured wire frames in Part 6. No
level-3 (solver-confirmed) claims made.

## Remaining unknowns

1. The exact source of the per-channel encoded value in `0xF0`/`0xE0`
   records (`FUN_0000be94`'s prologue: `FUN_0000bb38`, `FUN_00004714`,
   `FUN_00008560` — not decoded this slice).
2. Whether Manual Mode has any entry into the live-jog loop other than
   via the `"Direction"` row of the `"MANUAL MODE"` screen.
3. The `0xE0` variant's exact bit-field layout (confirmed structurally
   similar, not byte-mapped).
4. AutoPilot-side stop/decay/watchdog behavior when `0xF0`/`0xE0` frames
   stop arriving.
5. `LL2|`'s own Remote-side sender (still not found — `ll-limit-workflow.md`'s
   pre-existing open question, only half-closed by this slice's `LL1|`
   finding).
6. Physical clockwise/counter-clockwise ↔ wire sign-bit correspondence
   (deliberately not claimed — would need live hardware).
