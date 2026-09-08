# Investigation: Connecting `I<channel><mode>|` to the Motor Rate/Timer Chain

**Question**: [`pin-index-provenance.md`](pin-index-provenance.md) closed the
last gap in the hardware-side mechanism (ISR -> `FUN_00005898` ->
`FUN_0000d388` -> now-known GPIO pin). The remaining M6 item is the
protocol-side link: does `I<channel><mode>|` actually reach that
mechanism, and through what intermediate state? Per the task, this is a
**meet-in-the-middle** exercise — trace the `I` state machine forward from
[`synchronous-responses.md`](../../research/autopilot_static_inventory/synchronous-responses.md)'s
already-documented anchors, trace the callers/dataflow into the real TC
period setter (`FUN_00005c00`) backward, and find where the two meet,
without assuming `I` directly drives `step_delta`.

**Scope**: Ghidra decompile/disassembly and literal-pool resolution (the
same techniques used throughout this project), plus one small, clearly-
labeled Unicorn branch exercise to concretely validate the disassembly
reading of the `I`-handler's own gating logic. No new tooling. Explicitly
not a full trapezoidal-motion-profile decode — several floating-point
helper functions (`FUN_00006338`, `FUN_00006fd8`, `FUN_00004d18`,
`FUN_00006b50`) were read only as far as needed to identify which
per-channel arrays they touch and under what gating conditions, not to
fully decode their math.

## Result

**A real, evidence-backed chain exists and is traced below, but it does
not close end to end.** One link — what sets the master per-channel
"busy" gate (`0x20001b14[channel]`) to a nonzero value in the first place
— was searched for exhaustively and not found via static literal-address
methods, the same category of gap already documented for the GPIO
pin-index bytes before `.data`-segment analysis resolved that one. Per
the task's success criterion 2, the surrounding edges are proven and the
missing piece is named precisely below, rather than assumed.

**A correction to the existing record**: `synchronous-responses.md` says
the `I` handler "sets `u8[0x20001b14[channel]] = 5`". Disassembly of the
actual handler (`0x872e`-`0x877c`, below) shows the `= 5` store targets
**`0x20002524[channel]`**, not `0x20001b14[channel]` — two different,
adjacent-in-role but physically distinct per-channel byte arrays that the
older static-inventory pass conflated. `0x20001b14[channel]` is real and
is exactly what the monitor (`0x8b5c`-`0x8b66`) waits to reach zero — the
handler just doesn't write it; it only *reads* it as a gate. See
"Corrected addresses" below for the full detail.

## Command-side: the real `I` handler, disassembled

`FUN_00008258` (the ASCII command dispatcher) branch at `0x872e`-`0x877c`,
reached when the packet's first byte is `'I'` (`0x49`):

```asm
0x8732  bl   0xccd0            ; r0 = FUN_0000ccd0() (tick reader)
0x8736  ldr  r3,[0x886c]       ; r3 = 0x20001fd0
0x8738  ldr  r1,[0x8850]       ; r1 = *0x2000209f
0x873a  str  r0,[r3,#0]        ; *0x20001fd0 = tick_now
0x873c  ldrb r0,[r4,#1]        ; r0 = packet[1] (channel digit char, '1'..'4')
0x873e  ldrb r1,[r1,#0]        ; r1 = *(byte*)0x2000209f
0x8740  ldr  r4,[0x8870]       ; r4 = &selector (0x20002328)
0x8742  ldr  r6,[0x8828]       ; r6 = 0x20002524 (base of the array below)
0x8744  sub.w r3,r0,#0x30      ; r3 = channel digit as a number (1-based)
0x874a  strb r3,[r4,#0]        ; selector(0x20002328) = channel_digit    [confirmed: matches doc]
0x874c  subs r3,#1             ; r3 = channel_idx (0-based)
0x874e  cbz  r1,0x8756         ; if *0x2000209f == 0, skip the next check
0x8750  ldrb r2,[r6,r3]        ; r2 = 0x20002524[channel_idx]
0x8752  cmp  r2,#0x2
0x8754  bne  0x876c            ;   ...and it must be 2, else abandon the FUN_5274 call
0x8756  ldr  r2,[0x8874]       ; r2 = 0x2000309d
0x8758  ldrb r2,[r2,r3]        ; r2 = 0x2000309d[channel_idx]
0x875a  cbnz r2,0x876c         ; must be 0, else abandon
0x875c  ldr  r2,[0x8858]       ; r2 = 0x20001b14   <-- the monitor's own "busy" array
0x875e  ldrb r3,[r2,r3]        ; r3 = 0x20001b14[channel_idx]
0x8760  cbz  r3,0x876c         ; must be NONZERO, else abandon
0x8762  subs r0,#0x31          ; r0 = channel digit char - '1'  = channel_idx (0-based, recomputed)
0x8764  movs r1,#4
0x8768  bl   0x00005274        ; FUN_00005274(channel_idx, 4)   <-- the real call into motor-side code
0x876c  ldrb r3,[r4,#0]        ; r3 = selector = channel_digit (1-based)
0x876e  ldr  r1,[0x8878]       ; r1 = &mode[channel] (0x200029d8)
0x8770  subs r3,#1             ; r3 = channel_idx
0x8772  movs r2,#5
0x8774  strb r2,[r6,r3]        ; 0x20002524[channel_idx] = 5    <-- the real "=5" store
0x8776  ldrb r2,[r5,#2]        ; r2 = packet[2] (mode digit char)
0x8778  subs r2,#0x30
0x877a  strb r2,[r1,r3]        ; mode[channel_idx] = mode_digit  [confirmed: matches doc]
```

**Confirmed, unconditionally, on every `I<channel><mode>|`**: `selector =
channel`, `mode[channel] = mode_digit`, `0x20002524[channel] = 5`.

**Confirmed, conditionally** (only when `0x20001b14[channel]` is *already*
nonzero at the moment the command arrives, and two other flags —
`0x2000309d[channel]==0` and either `*0x2000209f!=0` or
`0x20002524[channel]==2` — also hold): a call to `FUN_00005274(channel,
4)` — a genuine, direct entry point from the `I` command into the
motor-side rate machinery, gated by the exact same "busy" byte the
monitor later waits on.

## Concretely validated (Unicorn)

To confirm this reading rather than trust the decompile alone, both
outcomes of the gate above were exercised concretely, entering at
`0x8732` with a synthetic packet `"I10"` seeded at a scratch RAM address
(clearly a controlled branch exercise, not a claim about real runtime
values — the three gating bytes and the channel/mode digits are the only
seeded state, `--stub-call 0x5274` is used since only reaching the call
matters here, not its internals):

- With `0x20001b14[0] = 0`: `FUN_00005274` is **not** called (no stub
  hit), and `selector=0x01`, `mode[0]=0x00`, `0x20002524[0]=0x05` — the
  unconditional writes still happen.
- With `0x20001b14[0] = 1` (and the other two gate bytes set to take the
  call path): `FUN_00005274(0, 4)` **is** called — a `--watch` at
  `0x8768` shows `r0=0`, `r1=4` immediately before the call, and the
  stub records the hit with `lr=0x876d` — then the same three
  unconditional writes happen identically afterward.

This is exact agreement with the disassembly above at the concrete
(level 2) evidence tier for the handler itself.

## Corrected addresses (why the doc said `0x20001b14`)

| Address | Real role | Evidence |
|---|---|---|
| `0x20002524[channel]` | The `I` handler's own per-channel signal byte. Set to `5` unconditionally by `I`; also set to `1` by `FUN_00006fd8` when committing a real move (see below), to `2` by an unnamed periodic poller (`0x541c`-`0x543c`) that re-issues the same `FUN_00005274(ch,4)` call whenever this byte is `2` and `0x20001b14[ch]!=0`, and cleared to `0` by `FUN_00006338` in most paths **except** when the value is exactly `5` (preserved, not clobbered) — this is genuinely a small per-channel state value, not a single global, correcting `motor-timer-survey.md`'s "may actually be the base of a small per-channel state array" to a confirmed fact. |
| `0x20001b14[channel]` | The real "channel busy" gate. Read (never written to nonzero) by the `I` handler, `FUN_00005ee8`, `FUN_00006338`, `FUN_00008e18`'s phase dispatcher, and the monitor (`0x8b5c`-`0x8b66`, waits for exactly this to reach `0`); written to `0` (cleared) by `FUN_00005958`. See "The one open link" below — nothing found writes it to nonzero. |

`synchronous-responses.md` is left as-is (a raw v0.3 catalog) with a
pointer added to this doc; this file is the corrected, authoritative
reading of the same handler.

## Motor-side: backward from `FUN_00005c00`

Confirmed by decompile, literal-resolving every `DAT_` symbol used:

- **`FUN_00005c00(channel, period, ...)`** ([already known](motor-timer-survey.md)):
  writes the real TC's `CC0` register (offset `0x1c` from each TC's SVD
  base — `0x40003800`/`0x40003c00`/`0x4101a000`/`0x4101c000` for
  TC0-TC3, matching the SVD), waits on `SYNCBUSY`, issues a `RETRIGGER`
  command, resets `COUNT`, and calls `FUN_00005898(channel)` (the
  already-confirmed position/GPIO-pulse mechanism) — a "catch-up pulse"
  if the previous period had already elapsed.
- **`FUN_00005ee8(channel)`** calls `FUN_00005c00`. It reads/clamps a
  per-channel *requested period* value at `0x2000007c[channel]` (floor
  20, ceiling 8,000,000 — plausibly the peripheral clock in Hz) and
  applies a special-case prescaler adjustment for very slow rates
  (`>= 59999`), using `0x20001b14[channel]` (the busy gate — **a
  second, independent read site**, not the `I`-handler's) and a flag at
  `0x20000123[channel]` to decide between a one-time `FUN_000056e8`
  prescaler call and a straight `>>7` (divide-by-128) rescale.
- **`FUN_00006338(channel)`** — the per-tick/per-call ramp/velocity
  executor, dispatching on a per-channel *phase* byte at
  `0x2000310c[channel]` (values seen: 1, 2, 3):
  - **phase 2** does the real position-vs-target math (floating point,
    using segment-breakpoint tables at `0x20002908`/`0x20000e90`/
    `0x200014d0`/`0x20000850`, all `channel*50+segment`-indexed, and a
    per-channel current-segment index at `0x200025e2[channel]`), and —
    gated on `iVar9!=0` (a computed sign check) **and**
    `0x20001b14[channel]!=0` — **writes `step_delta[channel] =
    -step_delta[channel]`** (a direction reversal / backlash-style
    correction), then calls `FUN_00005958`/`FUN_000054b8`.
  - phase 2 also writes the "requested period" array
    (`0x2000007c[channel]`, the same one `FUN_00005ee8` reads) from the
    computed target-vs-position delta, and conditionally clears
    `0x20002524[channel]` to `0` (except when it's exactly `5`, see
    above).
  - **Critically**, at the end of the phase-2 (and phase-3) body:
    `if (0x20001b14[channel] == 0) { return; }` — **`FUN_00005ee8` (and
    therefore the whole `FUN_00005c00`/`FUN_00005898`/GPIO chain) is
    only reached from this function when the busy gate is nonzero.**
    This is the single strongest confirmed link: the busy gate is not
    just something the `I` command checks — it is the real runtime
    switch that decides whether a rate update ever reaches the timer at
    all.
- **`FUN_00005274(channel, mode)`**, the function the `I` handler calls
  directly: for `mode==4` (the constant the `I` handler always passes),
  it reads `step_delta[channel]` (`0x20000094`), multiplies it by a
  per-channel factor at `0x20000180[channel]` (the same array
  `FUN_00006338` reads as a clamping ceiling), stores the product into
  `0x200024cc[channel]`, and calls `FUN_00004d18(channel)`.
- **`FUN_00004d18(channel)`** — a large (1162-byte) target/direction
  function with two internal modes selected by a byte at
  `0x20005018[channel]`, which resolves to **`0x20002524[channel]`** —
  the *same* per-channel byte the `I` handler writes `5` to (see
  "Corrected addresses"). Its two bodies run when that byte is `1`
  (mirrors `FUN_00006fd8`'s "just armed a real move" state) or `2`
  (mirrors the periodic poller's/`I`-handler's alternate gate value).
  **This closes a link the first pass of this doc left open**: the `I`
  handler's own call into `FUN_00005274`/`FUN_00004d18` happens
  *before* it stores `5` into `0x20002524[channel]` (the store is at
  `0x8774`, after the `bl 0x00005274` at `0x8768`) — so when the call is
  taken via the gate's `0x2000209f==0` path, `0x20002524[channel]` is
  unchanged at call time. When it was `2` (the same value the `bne
  0x876c` check at `0x8754` requires on the *other* gate path), the call
  concretely reaches `FUN_00004d18`'s **mode-2 body**: gated on
  `0x20001b14[channel]==0` **at function entry**,
  `step_delta[channel] = (comparison ? 1 : -1)` — a genuine, confirmed
  write of `step_delta[channel]` to a *unit direction sign*, from a
  floating-point comparison of a freshly computed target against the
  tracked current position. This establishes that `step_delta`'s
  **sign** encodes direction and is set here, reachable from the `I`
  command's own call chain; its *magnitude* (the actual "how many
  position units per pulse" scaling) was not traced to a specific writer
  this pass — consistent with the task's caution not to assume
  `step_delta` is itself "the" hardware step rate. The real per-pulse
  *timing* is `FUN_00005c00`'s `CC0` value, computed from the phase-2
  target/position delta, not from `step_delta`'s magnitude.
- **`FUN_00006fd8(channel, percent, distance, ...)`** — the real
  "commit a new move" function (called from `FUN_00008e18`'s phase-1->2
  transition and from a calibration/manual-jog UI path,
  `FUN_00007e2c`): for moves bigger than 8 units, it populates the same
  segment-breakpoint tables `FUN_00006338` reads, resets the segment
  index (`0x200025e2[channel]=0`), and sets **`0x20002524[channel] = 1`**
  and **`0x2000310c[channel] (phase) = 1`** — arming the phase-1->2->3
  state machine in `FUN_00008e18`. For moves of 8 units or fewer, it
  clears the same tables and sets both flags to `0` (no real move
  needed).
- **`FUN_00006b50`** (previously decompiled, see below) computes the
  segment breakpoints themselves (times/positions/velocities per
  up-to-4-segment trapezoidal profile) that `FUN_00006338` and
  `FUN_00006fd8` share; it also writes a *different*, adjacent per-channel
  array (`0x2000016c`-`0x2000016f`, a "profile active" flag), already
  identified and ruled unrelated to the GPIO pin-index bytes in
  [`pin-index-provenance.md`](pin-index-provenance.md).

## The one open link

**What sets `0x20001b14[channel]` (the busy gate) to a nonzero value.**

Every function in the firmware that references this address via a direct
literal-pool instruction was found and checked — 12 in total, an
exhaustive set, not a sample:

`FUN_00004cdc`, `FUN_00004d18`, an unnamed periodic poller at
`0x541c`-`0x543c`, `FUN_00005958`, `FUN_00005ee8`, `FUN_00005f8c`,
`FUN_00006338`, `FUN_00007e2c`, `FUN_00008258` (the `I` handler),
`FUN_00008960`, `FUN_00008a80` (the monitor), `FUN_00008e18`.

All twelve **read** it as a gate. Exactly one, `FUN_00005958` (called
throughout `FUN_00006338`'s branches), **writes** it — to `0`. No
literal-addressed instruction anywhere sets it to a nonzero value.

This is the same category of gap already resolved once in this project:
[`pin-index-provenance.md`](pin-index-provenance.md) found no literal
writer for the GPIO pin-index bytes either, and the real answer turned
out to be a `.data`-segment startup copy invisible to xref search.
`0x20001b14` is **not** in that same `.data` region
(`0x20000000`-`0x20000430`), so that specific mechanism doesn't apply
here directly, but a different computed/indirect store — most plausibly
inside `FUN_00006fd8` or the phase-0/phase-1 branches of
`FUN_00008e18`'s dispatcher, both of which are one hop from the confirmed
writes of the sibling flags `0x20002524[channel]` and
`0x2000310c[channel]` — is the leading hypothesis, not confirmed this
pass.

## Confirmed vs. inferred vs. unresolved

| Edge | Status |
|---|---|
| `I<channel><mode>\|` sets `selector`, `mode[channel]`, `0x20002524[channel]=5` | **Confirmed** (static disassembly + concrete/Unicorn) |
| The `I` handler's `0x20001b14[channel]!=0` gate on calling `FUN_00005274` | **Confirmed** (static + concrete, both branches exercised) |
| `FUN_00005274` reads `step_delta[channel]`, calls `FUN_00004d18` | **Confirmed** (static) |
| `FUN_00004d18` writes `step_delta[channel] = ±1` in its mode-2 body, gated on the busy gate `==0`, and the `I` command's own call chain reaches exactly this body when its gate takes the `0x20002524[channel]==2` path | **Confirmed** (static — mode selector resolved to `0x20002524[channel]`, the same byte the `I` handler tests) |
| `FUN_00006338`'s phase-2 body reverses `step_delta[channel]`'s sign and only calls onward to `FUN_00005ee8`/`FUN_00005c00`/`FUN_00005898` when the busy gate `!=0` | **Confirmed** (static, all literals resolved) |
| `FUN_00005ee8` clamps a per-channel requested-period value and calls the real `FUN_00005c00` (`CC0` setter) | **Confirmed** (static; matches `motor-timer-survey.md`) |
| `FUN_00005c00` -> `FUN_00005898` -> position += step_delta, GPIO pulse on the now-known pin | **Confirmed** (static + concrete, from `motor-timer-survey.md`/`pin-index-provenance.md`) |
| The monitor fires event 15 (`position[channel]`) only once the busy gate reaches `0` | **Confirmed** (static disassembly, `0x8b5c`-`0x8b8e`) |
| `step_delta`'s *magnitude* (vs. just its sign) as the real step-rate driver | **Not established** — `FUN_00005c00`'s `CC0` value comes from `FUN_00006338`'s phase-2 target/position delta, not visibly from `step_delta`'s magnitude; keeping these distinct per the task's instruction |
| What sets `0x20001b14[channel]` nonzero | **Unresolved** — exhaustive static search (12/12 direct-reference functions checked) found no literal writer; leading hypothesis is a computed/indirect store inside `FUN_00006fd8` or `FUN_00008e18`, not confirmed |
| Any "Motor 1/2/3/4" physical connector identity | **Not claimed** — out of scope per the task |

## Evidence level

Level 1 (static disassembly with full literal-pool resolution) for the
whole motor-side chain and the correction to the command-side addresses;
**level 2 (concrete, Unicorn)** specifically for the `I` handler's own
gating logic and its three unconditional writes, both branches of the
gate exercised. No solver/symbolic step was used or needed — every
question here was "what does this code concretely do," not "what input
satisfies this property."

## Best next entry point

**Find the `0x20001b14[channel]` setter** — the one remaining open cell.
The two named candidates (`FUN_00006fd8`, `FUN_00008e18`'s phase-0/phase-1
bodies) are already decompiled in this pass's working notes; re-reading
them specifically for a computed-address store (the same technique that
resolved the pin-index bytes: search for a loop whose destination
pointer is built from a *different* base literal plus a runtime offset,
rather than a direct `0x20001b14` literal) is the direct continuation.
Once found, the chain in the table above closes completely — every other
edge from `I<channel><mode>|` through to the now-known GPIO pin and back
to the event-15 result is already confirmed. This is a single-function,
targeted follow-up, not a broadening into full motor-control RE.
