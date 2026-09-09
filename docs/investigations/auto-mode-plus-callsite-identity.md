# Investigation: `FUN_0000e670`'s Real `'+'` Call Sites — Screen Text, Input Gesture, and Wire Bytes

**Question**: `plus-command-remote-provenance.md` found three interactive
`'+'` call sites inside the Remote's Auto-Mode screen state machine
(`FUN_0000e670`), each gated behind a real confirmation wait, but left
UNRESOLVED which literal on-screen text is shown at each — the candidate
strings it found (`"TEST A-B"`-family, `"DURATION"`, `"to rec C"`/`"to
rec D"`) were only known to live in the same general function family
(`FUN_00005474`), not proven to be co-located with any specific call
site. This slice: separate the call sites precisely, trace each one's
screen-index gate backward to its render call, and — where the chain
permits — forward through the confirmation-wait primitive to the exact
wire bytes, closing the full chain the earlier slice could not.

**Scope**: static analysis (disassembly against the persistent
`mando868` Ghidra cache, `tools/ghidra/aptrace_ghidra.py`, no
re-import/re-analysis) plus concrete execution
(`tools/unicorn/concrete.py`'s `ConcreteMachine`, no hand-picked SP/LR)
to confirm argument values and capture real `'+'` frames. No firmware
behavior conclusion from any prior slice is revisited.

## Result

**There are four `'+'` call sites in `FUN_0000e670`, not three.** Screen
5 has two mutually-exclusive call sites with identical arguments — a
single decompiled block in the earlier, decompile-only pass, separated
here by disassembly. The full evidence chain (displayed string -> input
gesture -> state transition -> exact `'+'` bytes) is now **closed** for
both screen-5 sites; the other two (screens 9 and 10) are closed for
their post-send state but remain **PROBABLE**, not CONFIRMED, for their
pre-send highlighted screen text.

## 1. The four call sites — CONFIRMED

| Call site | Address | Screen index (`*0x200001a0`) | Gate | Arguments `(confirm1,confirm2,channel,param_4,mode)` |
|---|---|---|---|---|
| A | `0xf40c` | 5 | `*0x20001099 != 0` AND this channel/segment's record is still empty | `(1, 1, *0x2000180c-1, 1, 0x00)` |
| B | `0xf5a6` | 5 | `*0x20001099 == 0` AND no channel anywhere has recorded data (`FUN_00005450()==0`) | `(1, 1, *0x2000180c-1, 1, 0x00)` |
| C | `0xf60c` | 10 | `*0x20001099 != 0` | `(1, 1, *0x2000180c-1, 2, 0x14)` |
| D | `0xf68c` | 9 | `*0x20001099 != 0` AND `*0x20001905 == 0` | `(1, 1, *0x2000180c-1, 0, 0x14)` |

Screen-index dispatch is a linear compare chain on `*DAT_0000e920 =
*0x200001a0`, not a jump table:

```asm
0x0000e7c0  ldr r6,[r5,#0x0]        ; r6 = screen index
0x0000e7c2  cmp r6,#0x5
0x0000e7c4  bne.w 0x0000f5e8
0x0000e7c8  cmp r4,#0x0             ; long-press-exit flag must be 0
0x0000e7ca  bne.w 0x0000e68e
0x0000e7ce  <screen 5 body>
...
0x0000f5e8  cmp r6,#0xa             ; screen 10
0x0000f5ea  bne 0x0000f664
...
0x0000f664  cmp r6,#0x9             ; screen 9
0x0000f666  bne 0x0000f740
```

Screen 5's two sub-branches (`0xe806`-`0xe838`):

```asm
0x0000e806  ldr r2,[r6,#0x0]        ; channel  (r6 = 0x2000180c)
0x0000e808  ldrb r3,[r7,#0x0]       ; *0x20001099
0x0000e80a  subs r2,#0x1
0x0000e80c  uxtb r2,r2
0x0000e80e  strb.w r2,[r11,#0x0]    ; *0x200001d4 = channel-1
0x0000e812  cmp r3,#0x0
0x0000e814  beq.w 0x0000f462        ; *0x20001099 == 0  -> block B
0x0000e818  ldr.w r9,[0x0000e96c]   ; 0x20001904 (segment)
...
0x0000e836  cmp r2,#0x0
0x0000e838  beq.w 0x0000f328        ; segment record empty -> block A ('+' at 0xf40c)
0x0000e83c  bl 0x0000d0d4           ; else -> "Are you sure ... clear the selected movement?"
```

```asm
0x0000f462  bl 0x00005450           ; "does ANY of the 4 channels have recorded data?"
0x0000f466  cbz r0,0x0000f48a       ; no -> block B ('+' at 0xf5a6)
0x0000f468  bl 0x0000d0d4           ; yes -> the same clear-confirm dialog
```

`FUN_00005450` (30 bytes, base `0x20000b20`) returns `1` iff any of
`record[0..3][0]` (stride `0x120`) is nonzero, else `0`. Both A and B
reach the identical downstream point-recording dialog and both set
`*0x200001a0 := 10` (screen 5 -> screen 10) after the `'+'` send and its
ack — this document treats A and B as one user-visible action reached
two structurally different ways, not two different actions.

## 2. Screen 5 (call sites A/B) — the full chain, CONFIRMED

### Screen rendering

Both blocks call `FUN_00005474(0, 2)` before the confirmation wait (block
A: `0xf3ac`; block B: `0xf54c`) — and only there; no other path reaches
either `'+'` call without passing through this exact call:

```asm
0x0000f3a2  movs r0,#0x0
0x0000f3aa  movs r1,#0x2
0x0000f3ac  bl 0x00005474
```

`FUN_00005474(param_1, param_2)` never takes a string pointer. It fills
an 8-entry text-slot array at `0x200028a0`, indexed by a render-kind
array at `0x20001930`, from a RAM string table at `0x20000024` (stride
`0x78`), selected by `*0x20002694`:

```asm
0x0000579e  ldr r1,[0x00005824]    ; 0x20002694  (table index)
0x000057a0  ldr r0,[0x00005828]    ; 0x20000024  (table base)
0x000057a2  ldrb r1,[r1,#0x0]
0x000057a4  movs r5,#0x78
0x000057a6  mla r1,r5,r1,r0
```

`*0x20002694` is never written anywhere in the compiled image (a full
literal scan of `0x20002694` finds only read sites) and lies in the
`.bss` zero-fill range — confirmed `0` both statically and by concrete
execution (`ConcreteMachine.call(0x5474, args=[0,2], ...)`, `.data` image
seeded exactly as `Reset_Handler` copies it). Table entry 0 (flash
`0x2526c`) resolves the two selector-dependent slots this `param_2==2`
arm fills:

```asm
0x000057b6  ldr r0,[0x0000582c]    ; 0x20000a55  ("first point already taken" flag)
0x000057b8  ldrb r0,[r0,#0x0]
0x000057ba  cbz r0,0x000057c8      ; not yet taken -> keep table+0x40 ("to rec A")
0x000057bc  ldr r0,[0x00005830]    ; 0x20001904  (segment index, 1..3)
0x000057be  ldrb r0,[r0,#0x0]
0x000057c0  cmp r0,#0x3
0x000057c2  bne 0x000057dc
0x000057c4  ldr r1,[0x00005834]    ; 0x0001c576 = "to rec D"
0x000057c6  str r1,[r3,#0x18]      ; slot[6] :=
...
0x000057dc  cmp r0,#0x2
0x000057de  ite eq
0x000057e0  ldr.eq r1,[0x00005838] ; 0x0001c57f = "to rec C"
0x000057e2  ldr.ne r1,[r1,#0x48]   ; else table+0x48 = "to rec B"
```

Concretely dumping `0x200028a0` after the call confirms exactly:

```
flag=0 seg=1 :  slot[5]='Click' (0x1ceca)  slot[6]='to rec A' (0x1ced0)  slot[7]='Long-click to end' (0x1ced9)
flag=1 seg=1 :  slot[6]='to rec B' (0x1ceeb)
flag=1 seg=2 :  slot[6]='to rec C' (0x1c57f)
flag=1 seg=3 :  slot[6]='to rec D' (0x1c576)
```

`0x20000a55` (the "flag") and `0x20001904` (the "segment index") are
exactly the two variables the screen-5 blocks themselves manipulate —
e.g. block A clears the flag on entering screen 5
(`0xe7e0: strb.w r4,[r8,#0x0]`, `r8=0x20000a55`) and sets it `1` once the
recorded segment index exceeds 1.

**`FUN_0000e670` itself loads no string address anywhere in its own
body** — a full check of every data reference the function makes (690
total) into the `0x1c000`-`0x1d000` string range returns zero hits. Every
string reaches the screen through `FUN_00005474`'s own table lookup, not
a direct literal load in the caller — this is *why* the earlier,
decompile/xref-only pass could not close this chain: there was no direct
reference to find.

### Input gesture

`FUN_0000cd70` has exactly two call sites in the entire firmware image
(`0xf3d6`, `0xf570`), both immediately gating a `'+'` send. Its return
value:

```asm
0x0000cf54  mov r0,r4
```

`r4` is set to `1` at `0xceba` (button released within 400ms) or to `2`
at `0xce1e` (held past `cmp.w r0,#0x190` [400], after a two-pulse
haptic). The block that actually **writes the recorded point** into the
per-channel record (`0xcede`-`0xcf5c`: `record[+0x10]`, `record-0x48+0xc`,
`record-0x48+0x0 = position - record[+0x10]`) runs **only when `r4==1`**
(`0xceda: cmp r4,#0x1`) — the identical `+0xc`/`+0x10`/delta convention
`FUN_000049c4`'s own `param_4==1` branch reads back out. This proves,
concretely, that a **short click** is the real "record this point"
gesture (matching the manual's "click sets a programmed point" and the
on-screen `"Click"` text), and a **long click** is `"Long-click to end"`.

### Wire bytes

`ConcreteMachine.call(0x49c4, args=[1,1,channel,1,0], ...)` with a
disclosed representative per-channel record (the same evidence tier
`plus-target-distance-roundtrip.md` already uses) produces, for a seeded
channel-2/segment-2 scenario:

```
b'+1,1,1,2,0,1,0,50,0,0,0,0|'
```

### Verdict

**CONFIRMED**, end to end, for both screen-5 call sites: displayed
string -> input gesture -> state transition -> exact `'+'` wire bytes.
This is the first `'+'` call site in this project to close that full
chain rather than resting on string proximity.

## 3. Screens 9 (D) and 10 (C) — partially closed

Neither block loads a string address directly, and both reach
`FUN_0000b59c` (ack wait), then — on a successful ack — render
`"RUNNING"` (`0x1c918`, via `FUN_0000cfc8`):

```asm
; C -- 0xf60c
0x0000f610  bl 0x0000b59c
0x0000f614  cmp r0,#0x0
0x0000f616  beq.w 0x0000e68e
0x0000f61a  ldr r3,[0x0000f658]     ; 0x200018e7
0x0000f61c  movs r2,#0x9
0x0000f61e  strb r2,[r3,#0x0]
0x0000f620  bl 0x0000cfc8           ; -> "RUNNING"
```

**Post-send state: CONFIRMED.** Pre-send highlighted row: **PROBABLE**.
Screens 6/7/8/9 each make their own row-indexed `FUN_00006558` call with
a literal row argument, giving a clean `row = screen - 3` progression
(screen 6->row 3 `SPEED`/`DURATION`, 7->row 4 `RAMP`, 8->row 5 `DELAY`,
9->row 6 — the `LOOP` toggle, confirmed by label match against
`record[+0x40]`'s own YES/NO text). Extending that arithmetic gives
screen 10 -> row 7 (`"TEST A-B"`/`"TEST B-C"`/`"TEST C-D"`, by table
position) and (consistent with A/B being the recording dialog) screen 5
-> row 2 (`"REC A-B"`/`"CLEAR A-B"` family). **The missing edge is
exact**: screens 5 and 10 make no row-indexed `FUN_00006558` call of
their own, so this is an extrapolation from the other four screens'
pattern, not a direct observation the way screens 6-9 are. Closing it
needs either tracing the highlight-cursor variable (`0x20000fae`, set to
`screen-2` on menu entry) into `FUN_00005474`'s own highlight-selection
logic, or a concrete run with the row-count/cursor state a real boot
establishes — neither attempted this slice.

Real captured `'+'` frames (concrete, seeded channel 2, three segments):

```
C (0xf60c, screen 10): b'+2,1,1,2,20,1,0,0,0,0,0,0|'
D (0xf68c, screen 9):  b'+2,1,1,2,20,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'
```

For the identical seed, the reference bulk-push frame (mode `0x62`, per
`plus-command-remote-provenance.md`'s section 4B) is:

```
b'+2,1,1,2,98,3,1,50,0,500,9,0,60,0,600,0,0,0,0,700,0,0|'
```

**Byte-identical to site D except the mode field** (`0x14` vs `0x62`) —
a direct, visual confirmation of what "does not cross the persist
threshold" means at the wire level: the same record data, a different
mode digit, a different AutoPilot-side consequence.

## 4. Corrections to prior documents

- **`plus-command-remote-provenance.md`'s "three call sites" is
  superseded** — there are four; screen 5's two mutually-exclusive
  branches were collapsed into one by that slice's decompile-level
  reading.
- **`"NO MOVEMENT"` (`0x1c56a`) is rendered only in `FUN_00005474`'s "no
  channel anywhere has recorded data" branch** (`FUN_00005450()==0`,
  `param_2==1`) — not on any `'+'` call path, interactive or bulk-push.
  The earlier slice's listing of it as a candidate landmark near the
  `'+'` call sites is superseded by this more precise placement.
- **`"COMMIT!"`/`"COMMIT2!"` are definitively not shown at any of the
  four `'+'` call sites** — `FUN_0000e670` loads no string address at
  all, and `"COMMIT!"`'s own renderer (`FUN_00007f90`) is not reachable
  from any of these four blocks. Remove as candidates for this specific
  mapping; they remain real strings elsewhere in the same general menu
  family, per the earlier slice's own hedged framing.

## Open question carried forward

The `param_4==1` record-field-to-wire-position mapping deserves its own
pass: the captured call-site-A/B frame
(`b'+1,1,1,2,0,1,0,50,0,0,0,0|'`) shows the seeded `+0x14` value (`50`)
land on the wire but not the `+0x10 - +0xc` delta (`500`) that
`persistent-record-motor-target-mapping.md` attributes to that same
branch — a real, disassembly-answerable discrepancy between two of this
project's own documents, not reconciled this slice.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| Four `'+'` call sites exist (not three), with these exact addresses/gates/arguments | **CONFIRMED** (disassembly) |
| Screen-5 sites (A/B) render exactly `"Click"`/`"to rec A"`-`"to rec D"`/`"Long-click to end"` | **CONFIRMED** (disassembly + concrete) |
| A short jog-wheel click (not long) is the exact gesture that records the point | **CONFIRMED** (disassembly) |
| Screen-5 sites' exact `'+'` wire bytes for a representative seed | **CONFIRMED** (concrete) |
| Screens 9/10 render `"RUNNING"` after a successful send | **CONFIRMED** (disassembly) |
| Screens 9/10's pre-send highlighted row (`LOOP` row / `"TEST A-B"`-family) | **PROBABLE** — arithmetic extrapolation, not directly observed |
| `"NO MOVEMENT"` is a distinct, no-`'+'`-path menu state | **CONFIRMED** (disassembly) |
| `"COMMIT!"`/`"COMMIT2!"` are unrelated to any of the four call sites | **CONFIRMED** (disassembly) |
| The `param_4==1` delta-field wire position vs. `persistent-record-motor-target-mapping.md`'s claim | **UNRESOLVED**, flagged for a future pass |

## Evidence level

Level 1 (static, disassembly-confirmed) for every call-site/gate/render
claim; level 2 (concrete, Unicorn) for every wire-byte capture and the
`*0x20002694==0` claim. No level-3 (solver-confirmed) claims made.

## Next step

Close the one remaining PROBABLE edge (screens 9/10's highlighted row)
by tracing `0x20000fae`'s highlight-cursor value into `FUN_00005474`'s
selection logic, or by a concrete run through a real boot's row/cursor
state — see [`action-command-map.md`](../ui/action-command-map.md)'s
Part 5, item 6. Reconcile the `param_4==1` delta-position discrepancy
noted above as a separate, narrowly-scoped follow-up.
