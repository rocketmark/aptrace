# Investigation: `MC0`-`MC4` — Remote Sender Provenance and Quick Setup Mapping

**Question**: `mc4-transition.md` fully characterized `MC0`-`MC4` from the
AutoPilot receiving side — including `MC4`'s uniquely consequential role
as the sole instruction anywhere in the image that lets the sketch's
`setup()` exit its internal loop — but this project had **zero confirmed
Remote-side sender** for any of the five commands. This slice: determine
whether the Remote firmware actually generates `MC0`-`MC4`, and if so,
trace each one back to the specific user-visible Quick Setup action that
emits it.

**Scope**: static analysis (disassembly against the persistent `mando868`
Ghidra cache) plus concrete execution (`ConcreteMachine`) to confirm
argument values and capture real wire bytes. No AutoPilot-side conclusion
from `mc4-transition.md` or any other prior slice is revisited.

## Confidence scale

Same as [`docs/ui/action-command-map.md`](../ui/action-command-map.md):
**CONFIRMED** (disassembly and/or concrete execution against real,
unmodified firmware) / **HIGH** / **PROBABLE** (a real finding exists, but
the user-guide/manual-label mapping rests on circumstantial correlation)
/ **UNKNOWN**. A command's wire schema or call site being CONFIRMED does
not by itself make its exact user-guide action label CONFIRMED — the two
are graded separately throughout.

## Part 1 — The AutoPilot side, re-consolidated (unchanged from prior work)

All of the following is established in
[`mc4-transition.md`](mc4-transition.md) and
[`g-command-motor-subsystem-unlock.md`](g-command-motor-subsystem-unlock.md);
restated here only for reference, not re-derived.

### Wire grammar

- `MC<0-3><a>,<b>,<c>,<d>,|` — one channel, 4 signed-decimal
  comma-terminated fields.
- `MC4<a0>,<b0>,<c0>,<d0>,...,<a3>,<b3>,<c3>,<d3>,|` — all four channels,
  16 fields total (4 fields x 4 channels).

### Parser/handler

`FUN_00008258`'s `M`/`C` branch (`0x86f0`-`0x872a`): `packet[1]=='C'`,
then `packet[2]` selects per-channel (`'0'`-`'3'`) vs. all-four (`'4'`).
The per-channel form calls `FUN_00007a98(channel)` once; the all-four
form calls it for channels 0, 1, 2, 3 in sequence.

### Fields parsed / RAM state written

`FUN_00007a98(channel)` calls the shared numeric-field parser
`FUN_0000799c` 4 times, writing:

| Field | Destination | Transform |
|---|---|---|
| 1st | `0x2000006c[channel]` | `value * 0x50` (80 decimal) |
| 2nd | `0x200000dc[channel]` | raw |
| 3rd | `0x200000f0[channel]` | raw, except `1 -> 0` remap |
| 4th | `0x20000138[channel]` | raw |

Cross-reference (exhaustive literal-pool scan, per `mc4-transition.md`):

- `0x2000006c`/`0x200000f0` are also read by `FUN_00007514`/`FUN_00007770`
  (post-homing display/status) — **not** the locked motor subsystem.
- `0x200000dc` is also read by `FUN_00006190` (boot-time per-channel
  init) — **not** the locked motor subsystem.
- `0x20000138` is also read by `FUN_00007e2c` and `FUN_00008e18` — **the
  two functions at the heart of the locked motor subsystem** — used as
  an index into a secondary table (`DAT_00007e24` in `FUN_00007e2c`;
  `DAT_00009154`/`DAT_00009158` in `FUN_00008e18`'s "all channels"
  branch). Only this 4th field has any confirmed effect on the locked
  subsystem; the other three feed unrelated boot-time/display code.

**No AutoPilot-side field has been proven to correspond to a specific
named manual setting** (Current / Steps-per-second-max / Microstepping /
Return speed) — this remains a structural match at best (four numeric
fields, matching the manual's four per-motor settings in *count*) until
a specific transform or consumer ties one to a named quantity. `field 1
* 80` is suggestive of a unit conversion but has not been matched to any
of the manual's stated defaults (10,000 steps/s, microstep values
1-256, return speed default 25 max 99) closely enough to promote past
structural correlation. **Do not promote this to an exact field-name
mapping without independent proof** — none exists yet on the AutoPilot
side, and see Part 3 for whether this slice's Remote-side work changes
that.

### Persistence

None identified — `MC0`-`MC4`'s fields are not part of the `0x12000`
flash-backed persisted struct (`'+'`'s target/config struct); no code
path connecting `0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138` to
`FUN_0000977c`'s dirty-flag/persist mechanism has been found.

### Control-flow / state transition and downstream significance

**`MC4` is, precisely, the condition that lets `setup()` complete** —
not a generic "mode unlock." `FUN_00008258`'s `MC4` branch executes
`*0x20000060 = 0` at `0x8714`, and this is the **sole** instruction
anywhere in the compiled image that writes this address (confirmed by
exhaustive literal-pool scan, exactly two hits total: `0x8714`'s write
and `0x94ec`'s own read inside `FUN_00009464`, the sketch's `setup()`).
`FUN_00009464`'s internal loop (`0x94be`-`0x94e2`) exits exactly when
this byte is nonzero-checked-zero (`cbz`), returning to its caller
(`FUN_0000cd90`, i.e. `main()`), which then calls `FUN_000093fc` (the
sketch's real `loop()`) for the first time. Every later motor-control
function this project has traced (`FUN_00007e2c`, `FUN_00008e18`,
`FUN_00006338`, `FUN_00008a80`) is unreachable from a cold boot without
this exact transition having already happened. Per-channel `MC<0-3>`
does **not** touch `0x20000060` and has no equivalent unlock effect.

## Result

**Outcome A, for all five commands.** A single Remote function,
`FUN_00005a8c`, builds every `MC` frame in the image. It has exactly
three call sites, and the whole `MC` family maps cleanly onto the Quick
Setup / motor-settings screens — closed end to end (displayed string ->
input gesture -> state -> sender -> exact wire bytes) for `MC0`-`MC3` and
for one of `MC4`'s two call sites:

| Command | Remote sender | UI action |
|---|---|---|
| `MC0`-`MC3` | `FUN_00005a8c(page-0x32)` at `0x10cbe` in `FUN_00010698` | Clicking into, adjusting, and clicking out of one of the four numeric rows (`"CURRENT (mA)"`, `"STEPS/S MAX"`, `"MICRO-STEPPING"`, `"RETURN SPEED"`) on the `MOTOR <N>` settings page — **CONFIRMED** |
| `MC4` | `FUN_00005a8c(4)` at `0x1039e` in `FUN_00010258` | Clicking the `"Continue"` row on the `Motor <N>: Choose type` screen once all four motors have a type assigned — **CONFIRMED** |
| `MC4` (2nd path) | `FUN_00005a8c(4)` at `0xcb4c` in `FUN_0000c440` | The `'S'`-handler bulk-push tail (already known from `plus-command-remote-provenance.md`) — mechanism **CONFIRMED**, its own real-world trigger **UNKNOWN**, unchanged from before this slice and explicitly out of scope here |

A genuine surprise fell out along the way: **Quick Setup is
AutoPilot-initiated, not user-menu-initiated.** The only writer of the
Remote's "Quick Setup in progress" flag is the Remote's *inbound* radio
command handler, reacting to a real AutoPilot-built `MT<...>|` frame
derived from the AutoPilot's own per-connector motor-presence detection.
See Part 4.

## Part 2 — Remote-side sender search

### The sender is unique

Four independent full-image scans of `firmware_mando868.bin` (raw Thumb
immediate encodings for `'M'`/`'C'` in every encoding form the compiler
could plausibly use, adjacent raw byte pairs `4D 43` anywhere including
data/table regions, and 32-bit words equal to `0x434D`/`0x4D43`) find
**exactly one** real `"MC"`-frame builder: **`FUN_00005a8c`**
(`0x5a8c`-`0x5b76`, 236 bytes, one `int` parameter, a real Ghidra-recognized
function boundary, not a tail-jump artifact). Every other hit from any of
the four scans is independently accounted for as something else (an
`MLA` instruction encoding, bytes inside the unrelated UI strings
`"DMC32 inputs"`/`"MRMC/Other"`, or font/bitmap data) — there is no
second, differently-encoded `MC` builder anywhere in the image.

Header (`0x5a9e`-`0x5ab8`): `buf[0]='M'`, `buf[1]='C'`,
`buf[2]=param_1+'0'`, then `cmp r0,#4 / bne 0x5b32` selects one of two
branches.

### Exactly three callers, confirmed two independent ways

Both the Ghidra call graph and an independent full-image decode of every
`BL`/`BLX` instruction (self-computed target addresses, not trusted from
Ghidra — the same method reproduced the already-known 6 `'+'` call sites
and 55 `0x58a8` call sites correctly, confirming the decoder is sound)
agree: **`0xcb4c`** (in `FUN_0000c440`), **`0x1039e`** (in
`FUN_00010258`), **`0x10cbe`** (in `FUN_00010698`). A separate
address-taken check (no 32-bit word anywhere in the image equals
`0x5a8c`/`0x5a8d`) rules out an indirect/vtable call this project's
static graph could have missed.

### Path to the wire — a real mechanical difference from `'+'`

`FUN_00005a8c` calls the shared TX wrapper `FUN_000058a8` **directly,
three times in a row**, with **no ack/retry wait** in between:

```asm
0x00005b1e  bl 0x000058a8
0x00005b22  ldr r0,[0x00005b78]      ; = 0x2000183c (shared TX buffer)
0x00005b24  bl 0x000058a8
0x00005b28  pop.w {r3,r4,...,lr}
0x00005b2c  ldr r0,[0x00005b78]
0x00005b2e  b.w 0x000058a8
```

This is a genuinely different mechanism from `'+'`: `FUN_000049c4`
(`'+'`'s builder) never calls `0x58a8` at all — its *callers* separately
hand the buffer to `FUN_0000b59c`, which sends once and waits for an ack.
`FUN_00005a8c`'s fire-and-forget, triple-send pattern instead matches
this firmware's two wake-preamble senders (`FUN_00005a14`/`FUN_00005a50`)
— an established, not novel, idiom for un-acked broadcasts. **Any future
harness work with `MC` frames should expect no ack and up to three
identical transmissions per user action**, not the request/ack shape
every other characterized command in this project uses.

### The frame, including the previously-uncharacterized `param_1<4` branch

Literal pool (`0x5b78`-`0x5b90`) resolves four per-channel-array sources
(4 x `int32`, one array per field) plus a constant `24,000,000`:

| Field | Wire value | Source array | AutoPilot destination (per `mc4-transition.md`) |
|---|---|---|---|
| 1 | `A[ch] / 100` | `0x2000015c` | `0x2000006c[ch]` (`* 0x50` on receipt) |
| 2 | `24000000 / B[ch]` | `0x20000298` | `0x200000dc[ch]` (raw) |
| 3 | `C[ch]` (raw) | `0x200001e8` | `0x200000f0[ch]` (`1 -> 0` remap) |
| 4 | `D[ch]` (raw) | `0x20000284` | `0x20000138[ch]` (raw, table index) |

Both branches (`param_1==4`: loop channels 0-3; `param_1<4`: single
channel, same four fields) were disassembled and confirmed to emit
identical per-channel field content — `MC4` is exactly `MC0`'s +
`MC1`'s + `MC2`'s + `MC3`'s field content concatenated, not a separately
encoded quantity.

### The four arrays ARE the Remote's own settings-editor state — CONFIRMED

`FUN_00010698` (the motor-settings row editor, entered only when the
Remote's own page byte is `0x32`-`0x35`) edits these same four arrays
directly, at the same pool addresses, with real clamp ranges:

| Array | Remote UI row | Clamp / step | Real `.data` default (all 4 channels) |
|---|---|---|---|
| `0x2000015c` | `"CURRENT (mA)"` | 200-5000, step 50 | 2000 |
| `0x20000298` | `"STEPS/S MAX"` | 1000-20000, step 20 | 10000 |
| `0x200001e8` | `"MICRO-STEPPING"` | 1-256 | 1 |
| `0x20000284` | `"RETURN SPEED"` | 0-100 | 25 |

The `.data` defaults were read directly from the compiled image (the
same startup-copy mechanism `pin-index-provenance.md` already
established for a different array), not assumed. A second, independent
confirmation of field 2's meaning: `FUN_000042ac` (the Remote's own local
ramp-table rebuild, called immediately before every `MC` send) uses the
*identical* `24000000 / 0x20000298[ch]` formula on its own — i.e. the
Remote's own code, not just this reading of `FUN_00005a8c`, treats
`24,000,000` as a timer-clock constant and `0x20000298[ch]` as
steps-per-second.

**This makes the Remote-side field identity CONFIRMED** — the exact same
label string, editable row, and backing array are provably one object.
**It does NOT prove what these four numbers mean to the AutoPilot's own
motor driver** — the AutoPilot-side destinations
(`0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138`) remain only
structurally consistent (four fields in, four fields out, a plausible
`1->0` microstep-index remap) with carrying Current/Steps-per-second-max/
Microstepping/Return-speed through — this is graded **PROBABLE**, not
CONFIRMED, exactly per this project's standing discipline against
promoting a structural match to an exact field-name mapping. One
genuinely open tension worth naming plainly: `mc4-transition.md`
independently found `0x20000138[ch]` (field 4, the Remote's own
`"RETURN SPEED"` value) is used by the locked motor subsystem
(`FUN_00007e2c`/`FUN_00008e18`) **as a table index**, not as a speed
value read directly — a coherent possible design (a small number of
named speed profiles selected by index) but not something this slice
proves either way.

## Part 3 — Per-command summary

### `MC0` / `MC1` / `MC2` / `MC3`

- **AutoPilot receiver**: CONFIRMED, unchanged (Part 1); reconfirmed
  concretely this slice with a real Remote-produced `MC1` frame (see
  Part 5).
- **Remote sender**: **CONFIRMED** — `FUN_00005a8c`, called at `0x10cbe`
  in `FUN_00010698` with argument `uxtb(*0x200018e7 - 0x32)` (the page
  byte, `0x32`-`0x35` for motor settings pages 1-4, minus `0x32`).
- **Exact UI action**: **CONFIRMED**, full chain closed. On the
  `"MOTOR <N>"` settings page (`*0x200018e7` in `0x32`-`0x35`), the user
  clicks into one of the four numeric rows, adjusts it with the jog
  wheel, and clicks again to leave the row — that click-to-leave is what
  sends `MC<n>`. The label string, the row's backing array, the jog-wheel
  gesture (`FUN_000171f0(0x2d)`, a direct `PORT.IN` read of the jog-wheel
  button pin), and the resulting wire bytes were all independently
  confirmed by disassembly and concrete execution across all 16
  page x row combinations.
- **Exact bytes**: `MC1` at factory defaults: `b'MC120,2400,1,25,|'`
  (`MC0`/`MC2`/`MC3` identical but for the channel digit).
- **Preconditions**: the settings page must be open and the row must
  actually have been clicked into (`*0x200019c2 != 0`). No relation to
  `MC4`/setup-completion — this send can happen any number of times,
  independently, any time a motor's settings are adjusted, not just
  during first-time Quick Setup.
- **Persistent-state effect**: none identified on either side.
- **Evidence**: this document Part 2; disassembly `0x10698`-`0x10cc2`,
  `0x100f0`+pool `0x101ec`-`0x10254`, `0xd570`+pool `0xd7b4`; concrete
  captures in Part 5.
- **Missing edge**: none for the mechanism. Still open: what writes
  `*0x2000027d` (the byte selecting the 4-row vs. a 2-row settings-page
  variant) — no direct-literal writer found anywhere in the image.

### `MC4`

- **AutoPilot receiver**: CONFIRMED, unchanged (Part 1); reconfirmed
  concretely this slice with a real Remote-produced `MC4` frame,
  independently reproducing every field transform `mc4-transition.md`
  derived statically (see Part 5).
- **Remote sender**: **CONFIRMED**, two independent call sites:
  - `0x1039e` in `FUN_00010258` — literal `movs r0,#0x4`.
  - `0xcb4c` in `FUN_0000c440` — literal `movs r0,#0x4`, unconditional,
    already known from `plus-command-remote-provenance.md`.
- **Exact UI action** (`0x1039e`): **CONFIRMED**, full chain closed.
  Clicking the `"Continue"` row (the one and only `"Continue"` string in
  the entire Remote image) on the `"Motor <N>: Choose type"` screen,
  gated on all four bytes of the per-motor type array (`0x20001811`)
  being nonzero (a type, including `"Not connected"`, has been assigned
  to every motor). This same click clears the Quick-Setup-in-progress
  flag (`0x20001810`). Concretely exercised both ways: all four types
  set produces the real `MC4` frame; motor 4 left unset never reaches the
  send.
- **Exact UI action** (`0xcb4c`): **UNKNOWN** — the `'S'`-handler
  bulk-push tail's own real-world trigger remains the pre-existing open
  question recorded in `action-command-map.md`'s workflow 6, explicitly
  out of scope for this slice.
- **Exact bytes**: `b'MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|'`
  (16 comma-terminated fields) at factory defaults — matches
  `mc4-transition.md`'s grammar exactly.
- **Preconditions** (for `0x1039e`): all four motors must have an
  assigned type; cursor on the `"Continue"` row.
- **Persistent-state effect**: none identified on either side, beyond
  clearing the Quick-Setup-in-progress flag.
- **Evidence**: this document Part 2; disassembly `0x10258`-`0x103a2`
  plus its literal pool; concrete captures in Part 5.
- **Missing edge**: `0xcb4c`'s own real-world trigger (pre-existing,
  explicitly deferred).

## Part 4 — A correction to the Quick Setup entry condition, and the resulting command stack

**Quick Setup is triggered by the AutoPilot, not by a Remote menu
action.** The only writer anywhere in the Remote image of the
Quick-Setup-in-progress flag (`0x20001810`) is the Remote's own inbound
radio-command handler (`FUN_00010ce4`), reacting to a real, disassembly-
confirmed AutoPilot-built frame: **`MT<b0><b1><b2><b3><x>|`**, where
`b0`-`b3` are one digit each, built from four real GPIO motor-connector
presence probes (`FUN_0000a970`/`FUN_0000a982`, storing into
`0x20002018`) at AutoPilot flash `0x74ae`-`0x74d6`. The Remote turns each
`'0'` digit into per-motor type `1` (`"Not connected"`), sets
`0x20001810=1`, and opens the `"Motor <N>: Choose type"` screen
(`FUN_00010258`) automatically. **The AutoPilot-side function containing
this `MT` builder, and what schedules it, were not traced this slice**
(the enclosing region, flash `0x7232`-`0x7514`, is unattributed in the
current Ghidra cache) — this is a genuine, precisely-named gap, not
guessed at.

This means the Quick Setup workflow's real entry condition is **"the
AutoPilot has just detected its own motor-connector presence state and
told the Remote about it"** (most plausibly at power-on/boot, though this
slice did not trace the AutoPilot-side trigger closely enough to confirm
that precisely), not "the user opens a Quick Setup menu item" — no such
menu entry point was found or implied by any evidence gathered.

With that correction, the command stack this slice **can** support,
narrowly:

```
AutoPilot boot -- detects motor-connector presence (4 GPIO probes)
  -> AutoPilot sends MT<b0><b1><b2><b3><x>|             [AutoPilot-side trigger: UNKNOWN]
  -> Remote's inbound handler (FUN_00010ce4) sets Quick-Setup-in-progress,
     assigns type=1 ("Not connected") for any absent connector,
     opens "Motor <N>: Choose type"                      [CONFIRMED]

User assigns/changes a motor's type on the choose-type screen           [mechanism CONFIRMED;
                                                                          does not itself send MC]

User opens "MOTOR <N>" settings, adjusts a numeric row, clicks out
  -> Remote sends MC<n> (n = that motor's 0-based index)  [CONFIRMED, independent
                                                             of Quick Setup completion --
                                                             can fire any time this screen
                                                             is used, not just once per setup]

User returns to "Motor <N>: Choose type", all 4 motors now have a type,
clicks "Continue"
  -> Remote sends MC4 (all 4 channels' current settings)  [CONFIRMED]
  -> AutoPilot's MC4 handler clears 0x20000060            [CONFIRMED,
                                                             reconfirmed this slice with
                                                             a real Remote-produced frame]
  -> setup()'s internal loop can now exit -> loop() reachable
```

**Do not read this as "one `MC<n>` per motor, sent automatically as part
of finishing that motor's settings"** — the evidence shows `MC<n>` is
sent by *leaving an edited numeric row*, which can happen zero, one, or
many times per motor, independently of the choose-type screen's own
"Continue" gate. The two mechanisms (`MC0`-`MC3` from the settings
editor, `MC4` from the choose-type screen) are related only in that both
read/write the same four per-channel arrays — they are not one linear,
single-pass wizard the way the manual's own prose might suggest.

## Part 5 — Concrete proof

All runs use `ConcreteMachine` (no hand-picked SP/LR), `.data` seeded
from flash `0x25248` for `0x5f0` bytes — **exactly** the bytes the real
`Reset_Handler` copies at boot, not an arbitrary seed. Every other input
is called out explicitly as disclosed/harness-supplied.

**`FUN_00005a8c` called directly, real `.data` defaults, TX wrapper
stubbed** (`machine.call(0x5a8c, args=[n], stub_calls=[0x58a8])`), buffer
read back at `0x2000183c`:

```
param_1=0 -> b'MC020,2400,1,25,|'
param_1=1 -> b'MC120,2400,1,25,|'
param_1=2 -> b'MC220,2400,1,25,|'
param_1=3 -> b'MC320,2400,1,25,|'
param_1=4 -> b'MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|'
```

`stub_hits` confirms `0x58a8` entered exactly three times per call
(`0x5b1e`, `0x5b24`, `0x5b2e`), each with `r0=0x2000183c`.

**Field-to-array disambiguation**, seeding distinct per-channel probe
values (`A=[1100,1200,1300,1400]`, `B=[1000,2000,3000,4000]`,
`C=[2,4,8,16]`, `D=[31,32,33,34]`, disclosed, not `.data`-derived):

```
MC0 -> b'MC011,24000,2,31,|'
MC1 -> b'MC112,12000,4,32,|'
MC2 -> b'MC213,8000,8,33,|'
MC3 -> b'MC314,6000,16,34,|'
MC4 -> b'MC411,24000,2,31,12,12000,4,32,13,8000,8,33,14,6000,16,34,|'
```

Unambiguous: field1=`A/100`, field2=`24000000/B`, field3=`C`, field4=`D`,
and `MC4` emits channels 0,1,2,3 in that order.

**`FUN_00010698` exercised in context, all 16 page x row combinations**:
`run(entry=0x10698)`, seeded with the `.data` image, `0x2000027d=5`
(the 4-row settings variant), `0x200018e7=<page>`, `0x20000fae=<cursor>`,
`0x20000fad=0`, `0x20001818=0`. The one fabricated input, disclosed: a
`force_reg r0=1` at each row block's own post-`bl 0x171f0` compare —
standing in for the jog-wheel button being pressed, not firmware-produced.
Display/radio callees stubbed. Every one of the 16 `(page, cursor)`
combinations stopped at `0x10cbe` with the expected channel argument
(`page 0x32/0x33/0x34/0x35` -> `r0=0/1/2/3`, independent of which of the
4 numeric-row cursor positions was used); letting one run through
produced the real frame `b'MC120,2400,1,25,|'`. Negative controls
confirmed: cursor on the `"BACK"` row, or on the row-5 no-op, never sends
`MC` regardless of the Quick-Setup flag.

**`FUN_00010258` exercised in context**: `run(entry=0x10258)`, seeded
with the `.data` image, `0x2000027d=5`, `0x20001811=<four type bytes>`;
disclosed `force_reg r0=1` (button press) and `force_mem
0x20000fae:=5` (cursor on the `"Continue"` row). With all four types
set (`2,3,4,5`), the run reaches `0x103a2` with `r0=4` at the `0x1039e`
call and produces the real frame
`b'MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|'`. With motor
4 left unset (`2,3,4,0`), the gate at `0x10382` is reached but never
passed — no `MC4` send, the loop continues instead.

**Remote-originated `MC4` delivered against the AutoPilot's real
dispatcher**: taking the exact byte-for-byte frame the Remote produced
above (not fabricated) and seeding it into the AutoPilot's real packet
buffer, entering the real RX dispatcher call site (`0x8a34`), with
`0x20000060` seeded nonzero (disclosed cold-boot value) and the
already-documented uninitialized-driver-object calls stubbed:

```
stop: reached the confirmed post-dispatch exit (0x83ec)
0x8714 (the *0x20000060 = 0 write) reached: True
0x20000060 = 00
0x2000006c = (1600, 1600, 1600, 1600)   # field1 * 0x50  (20*80)
0x200000dc = (2400, 2400, 2400, 2400)   # field2 raw
0x200000f0 = (0, 0, 0, 0)               # field3 = 1, remapped 1->0
0x20000138 = (25, 25, 25, 25)           # field4 raw
```

The same harness given the Remote-produced `b'MC120,2400,1,25,|'`
(a single-channel frame) shows `0x8714` is **not** reached, `0x20000060`
stays `0x01`, and only channel 1's fields are written — confirming, with
a Remote-originated frame for the first time in this project, both that
`MC4` alone crosses the unlock and that `MC<0-3>` alone does not.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `FUN_00005a8c` is the sole `MC`-frame builder in the image | **CONFIRMED** (four independent full-image scans) |
| Exactly 3 call sites, no indirect dispatch | **CONFIRMED** (Ghidra graph + independent BL decode + address-taken scan, all agree) |
| Frame grammar, field order, both branches (`==4` and `<4`) | **CONFIRMED** (disassembly + concrete) |
| The four wire fields' Remote-side source arrays and their UI row identity | **CONFIRMED** (shared pool addresses, ranges, `.data` defaults, and an independent second consumer, `FUN_000042ac`, all agree) |
| Those Remote-side field identities carry over to what the AutoPilot's `0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138` mean to its own motor driver | **PROBABLE** — structurally consistent, not proven |
| `MC0`-`MC3` sender, exact UI action, and exact bytes | **CONFIRMED**, full chain closed |
| `MC4` sender at `0x1039e`, exact UI action (`"Continue"`), and exact bytes | **CONFIRMED**, full chain closed |
| `MC4` sender at `0xcb4c` (`'S'`-handler bulk push) | Mechanism **CONFIRMED**; its own UI/real-world trigger **UNKNOWN** (pre-existing, deferred) |
| A Remote-produced `MC4` frame clears the AutoPilot's `0x20000060`; a Remote-produced `MC1` frame does not | **CONFIRMED concretely** |
| `MC` frames are sent three times each, with no ack wait | **CONFIRMED** (disassembly + concrete stub-hit counts) |
| Quick Setup's real entry condition is an AutoPilot-initiated `MT<...>|` frame reacting to real connector-presence detection, not a Remote menu action | **CONFIRMED** (exhaustive writer scan on the Remote side; disassembly-confirmed builder on the AutoPilot side) |
| What schedules the AutoPilot's `MT` send | **UNKNOWN** — the enclosing function was not identified this slice |
| What writes `*0x2000027d` (4-row vs. 2-row settings-page variant selector) | **UNKNOWN** — no direct-literal writer found |

## Evidence level

Level 1 (static, disassembly-confirmed, cross-checked by independent
scan methods) for every sender-identity and frame-grammar claim; level 2
(concrete, Unicorn) for every captured wire-byte value and for the
Remote-produced-frame-against-real-AutoPilot-dispatcher result in Part 5.
No level-3 (solver-confirmed) claims made.

## Next step

Two precisely-named follow-ups, neither started this slice:

1. Identify the AutoPilot function containing the `MT<...>|` builder
   (flash `0x7232`-`0x7514`, currently unattributed in the Ghidra cache)
   and what schedules it — the natural next edge to close for the Quick
   Setup workflow, and plausibly related in kind to
   `action-command-map.md`'s own ranked question about what triggers the
   `'S'`-handler's bulk-push branch (both are AutoPilot-initiated events
   this project has not yet traced from the AutoPilot's own side).
2. Determine what writes `*0x2000027d` (the byte selecting the Remote's
   4-row vs. 2-row settings-page variant) — likely a product/hardware-
   variant identifier, not user-configurable, but not confirmed.
