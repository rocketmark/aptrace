# Investigation: `'+'` from the Remote's Side — Sender, Frame, and UI Provenance

**Question**: `persistent-record-motor-target-mapping.md` found the AutoPilot-side
`'+'` handler (a real, protocol-reachable writer of a wire-controlled,
unclamped motor-target delta into `0x20001b40`, persisted to flash
`0x12000`) but only characterized it from the receiving end. This slice:
trace `'+'` backward through the Remote (`mando`) firmware — who builds
it, the exact frame/field encoding, what UI/state machine calls it, and
what user-guide action most plausibly triggers it.

**Scope**: static analysis only (Ghidra disassembly + decompile + direct
literal-pool/data-reference resolution against `firmware_mando868.bin`,
the same discipline used throughout this project — no address taken on
decompiler naming alone). No concrete Unicorn execution: the goal is
provenance/schema, and every claim below is either a direct disassembly
fact or an explicit inference, graded per the task's confidence scale.

## Result

**`'+'` is confirmed, concretely (by disassembly, not inference), to be
Remote-generated** — a single function, `FUN_000049c4`, builds the exact
wire frame this project's AutoPilot-side analysis predicted, byte for
byte. It is called from **the Remote's Auto-Mode configuration screen
state machine** (`FUN_0000e670`), each call site gated behind a real
user confirmation wait, plus one bulk "push all channels' stored config"
call from the connection/handshake flow (`FUN_0000c440`, the already-
known `'S'` handler). Cross-referencing the Remote's own embedded UI
strings (`"TEST A-B"`, `"TEST B-C"`, `"TEST C-D"`, `"DURATION"`,
`"to rec C"`/`"to rec D"`, `"NO MOVEMENT"`, `"COMMIT!"`/`"COMMIT2!"`)
against the user manual's Auto Mode description (channels, A/B/C/D
points, segment parameters: duration, ramp, delay, loop; persisted after
power-off) gives a **probable** — not yet fully proven — mapping:
**`'+'` is sent when the user confirms/saves a programmed Auto Mode move
segment** (and, separately, when the Remote bulk-pushes previously
stored per-channel config after reconnecting).

## 1. Every Remote function that constructs or sends `'+'` — CONFIRMED

Found by pulling every direct and indirect caller of the shared TX
wrapper `FUN_000058a8` (22 direct callers) and its shared numeric-field
encoder `FUN_000043b0` (4 callers) from the Ghidra-exported call graph
(`research/runs/ghidra/firmware_mando868.json`), then disassembling each
candidate rather than trusting decompiler variable names. Two apparent
`0x2b` hits among the 22 direct `FUN_000058a8` callers
(`FUN_0000c10c`, `FUN_0000fdf0`) were checked and ruled out: both are
LCD pixel-coordinate/icon-index literals in unrelated USB-console and
splash-screen code, not the ASCII character `'+'`. A full-image
disassembly scan for the instruction `movs r?,#0x2b` (not just near
known TX call sites) found the real one:

**`FUN_000049c4`** (`0x000049cc`: `movs r3,#0x2b`) — the sole function in
this image that writes a literal `'+'` as the first byte of a buffer
later passed to `FUN_000058a8`. No other function does this anywhere in
the compiled image.

## 2. The exact wire frame/schema — CONFIRMED

Full disassembly/decompile of `FUN_000049c4(param_1, param_2, param_3,
param_4, param_5)`:

```c
buffer[0] = '+';
buffer[1] = (units_flag_true) ? '1' : '2';   // selects AutoPilot's
                                              // FUN_000046c8 vs FUN_00004910
buffer[2] = ',';  buffer[4] = ',';  buffer[6] = ',';  buffer[8] = ',';
buffer[3] = param_1 + '0';    // -> AutoPilot logical field "confirm1"
buffer[5] = param_2 + '0';    // -> AutoPilot logical field "confirm2"
buffer[7] = param_3 + '0';    // -> AutoPilot logical field "channel"
FUN_000043b0(param_5);        // -> AutoPilot logical field "mode" (multi-digit)
// then, selected by param_4:
//   == 1: append "1,0," (record count = 1, one reserved/padding field),
//         then 4 more FUN_000043b0 fields for a single record, including
//         a computed value target_start(+0x10) - target_computed(+0xc)
//         -- the exact record-offset convention this project's AutoPilot-
//         side analysis already established for the delta/target fields
//   == 2: a single-record variant reading a different per-record field
//         set (+0x14, +0x40, +0x20/+0x2c) from the Remote's own local
//         per-channel-per-mode struct
//   otherwise: loops over FUN_00004998(channel) segments (the Remote's
//         own "how many real segments does this channel have" count,
//         matching the manual's up-to-3 A->B/B->C/C->D structure),
//         appending a type digit plus 4 more fields per segment
// finally: a rolling 1-9 sequence digit, then '|', then NUL.
```

**This confirms, field for field, the schema
`persistent-record-motor-target-mapping.md` reconstructed purely from
the AutoPilot side**: `param_1`/`param_2` (the two "confirm" fields,
which the AutoPilot handler requires to be equal before it will write or
persist anything) are always called with **identical values** at every
call site found (see section 4) — not a coincidence, a real invariant
this sender enforces; `param_3` is the channel (0-3); `param_5` is the
mode; and the `param_4==1` branch's `target_start - target_computed`
computation is the Remote independently computing a delta from its own
locally tracked position/target state, using the identical `+0xc`/`+0x10`
field convention the AutoPilot side uses — strong, independent
corroboration that both sides agree on the same struct layout, not
merely that each side's analysis was self-consistent.

## 3. How channel, mode, delta, sequence are chosen — CONFIRMED (channel/mode/sequence), PROBABLE (delta semantics)

- **Channel** (`param_3`): passed directly by each caller — either a
  fixed/looped channel index (bulk-sync callers) or `*DAT_0000f638-1`/
  `*DAT_0000f8a4-1`/`*DAT_0000e938-1`-style "currently selected channel"
  globals in the Auto-Mode UI state machine (0-indexed from a 1-based
  UI selection).
- **Mode** (`param_5`): observed values are `0`, `0x14`(20), and `0x62`
  (98). `0x62` matches the AutoPilot-side mode that triggers *both* the
  live-position resync (`FUN_00004b24`) *and* the compute+persist branch
  (`FUN_00004ca8`/`FUN_000043f0`) — used only by the bulk "push stored
  config" caller (`FUN_0000c440`, see below). `0`/`0x14` are used by the
  interactive Auto-Mode UI callers; their exact significance on the
  AutoPilot side beyond ">50 triggers persist" was not re-derived this
  slice (out of this slice's scope, which is Remote-side provenance).
- **Sequence**: a rolling `1`-`9` digit (wrapping at `9` back to `1`),
  advanced on every call — an ordinary anti-duplicate/retry sequence
  number, the same pattern already established for other Remote-side
  commands (`I`, `G`) in earlier slices, not something this specific
  command invents.
- **Delta**: for `param_4==1`, computed locally as
  `target_start(+0x10) - target_computed(+0xc)` from the Remote's own
  per-channel-per-mode struct — i.e., **the Remote maintains its own
  local copy of position/target state and sends the AutoPilot the
  difference**, not a raw absolute position. This is a **probable**
  (not fully traced) reading: this slice did not trace what writes the
  Remote's own local struct in the first place (almost certainly the
  jog wheel / menu-entered values from the Auto-Mode screens
  themselves, given the state machine below directly reads and writes
  these same offsets) — that would be the natural next step for a
  Remote-side "how does the user set this value" investigation, not
  pursued further here per the task's scope.

## 4. What Remote state-machine/UI path calls it — CONFIRMED

Four call sites, two distinct real contexts:

### A. The Auto-Mode configuration screen state machine (`FUN_0000e670`)

A large (4290-byte) function implementing a numbered-screen state
machine on a menu-index variable (`*DAT_0000e920`, observed values
1-10), driven by the jog wheel (`FUN_000171f0(0x2d)` — an idle/rotation
poll already used this way elsewhere in this firmware) and a display-
update helper (`FUN_00006558`) that highlights/adjusts numeric fields at
struct offsets `+0x14`, `+0x1c`/`+0x20`, `+0x2c` of a per-channel-per-
mode record (the same `0x48`-byte-stride record family the AutoPilot
side uses) — consistent with three sequential "adjust a numeric segment
parameter" screens (indices 6, 7, 8 in the switch), followed by a
boolean-toggle screen (index 9, flipping a `+0x40` byte — a plausible
"loop yes/no" flag) and a final screen (index 10). Three real `'+'`
sends:

- **Screen 5**, gated behind `FUN_0000cd70(...)` (a real, blocking
  confirm/select wait — this project's convention for "wait for the
  user's jog-wheel click/selection") returning a specific accepted
  value, and a check that the segment's own record has nonzero data
  (`DAT_0000f640[...] != 0`): `FUN_000049c4(1, 1, channel, 1, 0)` — the
  "quick, single-record" form, `mode=0`.
- **Screen 9**, when a "confirmed" flag is set:
  `FUN_000049c4(1, 1, channel, 0, 0x14)` — the "loop over this channel's
  real segment count" form, `mode=20`.
- **Screen 10**, when a "confirmed" flag is set:
  `FUN_000049c4(1, 1, channel, 2, 0x14)` — the alternate single-record
  form, `mode=20`.

Every one of these three calls passes `param_1=param_2=1` — confirming,
independently of the AutoPilot side's own requirement, that a real
Remote sender always satisfies the "confirm1 == confirm2" invariant; it
is not a coincidence of this slice's frame reconstruction.

### B. A bulk "push stored config" call from the `'S'`-related handler (`FUN_0000c440`)

```asm
; loop channel 0..3, skip if this channel's stored record is all-zero
mov.w r11,#0x62        ; mode = 0x62 (98)
str.w r11,[sp,#0]
bl FUN_000049c4         ; (confirm1=r0, confirm2=r1, channel=r2, param_4=0, mode=0x62)
bl FUN_0000b59c          ; wait for the AutoPilot's ack (same retry/ack primitive as I/G)
...
bl FUN_00005a8c(4)       ; then also send MC4 for all channels
```

This is a **bulk resync**: for every channel with nonzero stored
segment data, send `'+'` (mode `0x62`, which on the AutoPilot side
triggers *both* the position resync and the compute+persist path), wait
for an ack, then also push `MC4`. Given `FUN_0000c440` is the already-
established `'S'` query handler, this reads as **"on reconnect/status
refresh, push this Remote's locally stored Auto-Mode config back to the
AutoPilot"** — a real, protocol-reachable path independent of the
interactive UI, and further confirmation that `'+'` is fundamentally a
config-push/save operation, not a one-off jog command.

A fourth caller, `FUN_0000b6f0`, is a smaller variant of the same
bulk-push-all-channels-with-nonzero-data pattern (iterates channels,
sends `'+'`, waits for `FUN_0000b59c`'s ack) — not traced to a specific
caller this slice, but structurally the same "push stored config"
family as (B).

## 5. What user-visible action most plausibly triggers it — PROBABLE

Cross-referencing the Remote's own embedded UI strings against the user
manual's Auto Mode description (`autopilot-research-handoff.md` section
6: channels M1-M4; points A/B/C/D; segments A->B, B->C, C->D; parameters
duration, ramp, delay, loop; direction of rotation recorded; persisted
after power-off):

| Remote string (address) | Likely role |
|---|---|
| `"TEST A-B"` / `"TEST B-C"` / `"TEST C-D"` (`0x1c54f`/`0x1c558`/`0x1c561`, all rendered by `FUN_00005474`) | Per-segment test/preview labels — matches the manual's `A -> B`, `B -> C`, `C -> D` segment naming exactly |
| `"DURATION"` (`0x1c546`, also `FUN_00005474`) | A parameter-adjustment screen label — matches the manual's "Duration" segment parameter |
| `"to rec C"` / `"to rec D"` (`0x1c576`/`0x1c57f`) | Point-recording prompts — "rec" strongly reads as "record [point]", matching the manual's "click sets a programmed point" |
| `"NO MOVEMENT"` (`0x1c56a`) | A real "this segment has no distance" state — matches `target-config-provenance.md`'s own finding that a zero/blank delta produces no real move |
| `"COMMIT!"` / `"COMMIT2!"` (`0x1c5e9`/`0x1c5f1`, both rendered by `FUN_00007f90`, called from `FUN_0000db34`'s menu-page-1 branch) | A save/confirm action label in the same general menu family — **not proven to be the literal screen text shown at any of the three `FUN_0000e670` `'+'`-sending call sites**, but the clearest "commit/save" terminology found anywhere in the image |
| `"Are you sure that / you want to clear / the selected movement?"` (`0x1c920`-`0x1c944`, rendered by `FUN_0000d0d4`) | The **clear**-segment confirmation (a different, already-distinguished dialog, called from the same `FUN_0000e670` screens right before the successful-clear paths) — evidence that this state machine already has one well-understood confirm-style dialog, making `FUN_0000cd70`'s similarly-shaped gate in front of the `'+'` sends a plausible sibling ("confirm and save," as opposed to "confirm and clear") |

**Most plausible user-guide action**: from the task's list, this is
**closest to "editing/confirming a stored position/segment as part of
Auto Mode programming"** — specifically, the step where the user
finishes adjusting a segment's parameters (duration/ramp/delay/loop, the
screens 6-9 immediately preceding the `'+'` sends) and confirms/saves it,
which the firmware then pushes to the AutoPilot and persists. It is
**not** a simple jog/manual-mode move (Manual Mode's real-time jog path
was already characterized in earlier slices via `MC`/`G`/`I`, and none of
those share `FUN_000049c4`), and it is **not** a "TEST" move by itself
(the `"TEST A-B"`-family strings are rendered by a different function,
`FUN_00005474`, not correlated to a `'+'` call site this slice found) —
though a TEST action may itself depend on a segment already having been
committed via `'+'` first, which this slice did not trace further.

## 6. Manual mapping confidence — PROBABLE, not CONFIRMED

No single string or code comment says "sending this packet corresponds
to page N of the manual." The mapping rests on: (a) matching field
structure (a wire-controlled delta plus percentage/rate/duration
fields, up to 3 records per channel — matching the manual's up-to-3-
segment, duration/ramp/delay/loop model almost exactly in shape), (b)
matching UI terminology (`A-B`/`B-C`/`C-D` segment names, `DURATION`,
`to rec C`/`D`), and (c) the call sites' position inside a real,
confirmation-gated screen-flow function that also implements the
already-independently-confirmed "clear a stored segment" dialog. This is
a strong circumstantial case, not a byte-exact proof — reported as
**PROBABLE**, per the task's explicit confidence scale.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `FUN_000049c4` is the sole Remote function that constructs `'+'` | **CONFIRMED** (full-image disassembly scan for the literal, not just near known TX call sites) |
| The frame schema (confirm1, confirm2, channel, mode, then per-record fields) matches the AutoPilot-side reconstruction field for field | **CONFIRMED** (direct disassembly + literal-pool resolution on both sides, cross-checked independently) |
| `confirm1 == confirm2` at every real call site | **CONFIRMED** (every caller passes `1, 1`) |
| The Remote independently computes a delta using the same `+0xc`/`+0x10` struct convention as the AutoPilot side | **CONFIRMED** (disassembly of the `param_4==1` branch) |
| `FUN_0000e670` (Auto-Mode screen state machine) is a real UI caller, gated behind a real confirmation wait | **CONFIRMED** (disassembly; `FUN_0000cd70`'s call sites are exclusively inside this function, exclusively guarding the `'+'` sends) |
| `FUN_0000c440` (`'S'` handler) bulk-pushes `'+'` for every channel with nonzero stored data, mode `0x62` | **CONFIRMED** (disassembly) |
| The specific user action is "confirm/save an Auto-Mode move segment," matching the manual's A/B/C/D + duration/ramp/delay/loop model | **PROBABLE** (strong circumstantial string/structure correlation, no byte-exact proof) |
| Which exact menu screen/label text is shown at each of the three `FUN_0000e670` `'+'`-send call sites | **UNRESOLVED** (the nearby strings found are in the same general area/function family, not proven to be the literal on-screen text at those exact points) |
| What produces the Remote's own local per-channel record data in the first place (before `'+'` sends it) | **UNRESOLVED**, not chased this slice (a natural next Remote-side provenance question) |
| Whether `'+'` is ever host/service/internal-only (never Remote-generated) | **RULED OUT** — a real, disassembly-confirmed Remote sender exists; this is not an internal-only or host-tool-only command |

## Provenance updates

No new AutoPilot-side functions to reclassify. On the Remote (`mando`)
side, worth recording for a future Remote-side provenance pass (not
performed this slice, since this project's existing
`function_classification.csv`/`ghidra_labels.tsv` are scoped to
`firmware_autopilot868.bin` only): `FUN_000049c4` (`'+'` frame builder),
`FUN_0000e670` (Auto-Mode screen state machine), `FUN_0000c440` (`'S'`
handler / bulk config push) are all genuinely custom, Noxon-specific
application logic — no Adafruit/Arduino-core signature found in any of
them.

## Evidence level

Level 1 (static) throughout — full disassembly and decompile of every
function named above, cross-checked against direct literal-pool/data-
reference resolution (not decompiler variable naming) for every address
that matters to the schema claim. No concrete (Unicorn) execution this
slice, per the task's own guidance to use it only if it could cheaply
confirm exact packet bytes — the disassembly-level confirmation was
already unambiguous enough not to need it.

## Next step

Two independent, narrow follow-ups, neither started this slice:

1. Trace what writes the Remote's own local per-channel-per-mode struct
   (the source of the `+0xc`/`+0x10` delta computation in
   `FUN_000049c4`'s `param_4==1` branch) — almost certainly the jog-
   wheel-driven screens 6-8 of `FUN_0000e670` themselves, but not
   directly confirmed this slice.
2. If exact manual-page correspondence is wanted, correlate
   `FUN_0000e670`'s screen-index transitions against the manual's own
   page-by-page Auto Mode walkthrough (pages 11-14) more precisely than
   this slice's string-based circumstantial case — likely needs either
   a concrete Unicorn run driving the jog wheel/button inputs and
   watching which screen text renders, or locating a font/string-table
   indirection this slice didn't chase.
