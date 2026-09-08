# Investigation: `0x5274`/`0x5448` and the Dispatcher Loop's Exit Condition

**Question**: does the whole-function Crucible replay's non-termination
(see [`docs/project-status.md`](../project-status.md)'s "Current blocker")
actually depend on memory side effects `0x5274`/`0x5448` produce, as
hypothesized? Investigated statically with Ghidra, per
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md)'s decision
guidance (structure-recovery question -> Ghidra first, before Unicorn or
Crucible).

**Scope**: AutoPilot firmware only (`firmware_autopilot868.bin`). No Remote
firmware touched. No Crucible model changes, no lazy-CFG implementation, no
Unicorn execution in this pass — findings only.

**Method**: the existing headless pipeline
(`tools/ghidra/analyze_firmware.sh`, vector-table-seeded, `ARM:LE:32:Cortex`)
plus two additions used read-only against the same analysis:
- A new reusable script, `tools/ghidra/scripts/APTraceDecompileFunctions.java`
  (`-postScript`, dumps Ghidra's decompiler output for given addresses) —
  added because the existing export (`APTraceExportStaticAnalysis.java`)
  captures call edges and flat data references, but not conditionality,
  which decompiler output shows directly as `if` statements.
- Literal-pool pointer resolution done by reading the raw firmware bytes at
  known flash addresses (not instruction decoding — the flash addresses
  themselves came from Ghidra's own reference export; this just dereferences
  the one level of indirection Ghidra's flat reference list didn't resolve).

## The loop's actual structure (`0x827e`-`0x82c4`)

Full disassembly (Ghidra, Thumb, matches Macaw's decode at these addresses):

```
0x827e: ldrb  r3, [r5, #0x1]          ; r3 = buffer[1]              (r5 = fixed buffer base, 0x2000232a)
0x8280: subs  r2, r3, #0x7            ; r2 = r3 - 7
0x8282: it    mi
0x8284: sub.mi r2, r3, #0x4           ; if negative: r2 = r3 - 4
0x8286: cmp.w r6, r2, asr #0x2        ; compare r6 against r2/4 (arithmetic shift)
0x828a: bge.w 0x83ec                  ; EXIT the loop if r6 >= r2/4

0x828e: ldrb  r2, [r4, #0x7]          ; r2 = buffer[r4_offset+7]     (r4 slides: buffer base, +4 per iteration)
0x8290: ldrb  r1, [r4, #0x8]
0x8292: ldrb  r0, [r4, #0x6]
0x8294: and   r3, r2, #0x7f
0x8298: add.w r3, r1, r3, lsl #0x8
0x829c: and   r0, r0, #0xf            ; r0 = channel index (4 bits)
0x82a0: ldrb  r1, [r4, #0x9]
0x82a2: add.w r1, r1, r3, lsl #0x8    ; r1 = packed 3-byte target value from buffer[+7..+9]
0x82a6: ldr.w r3, [r7, r0, lsl #0x2]  ; r3 = TABLE[channel]           (r7 = 0x20000180, the shared table base)
0x82aa: cmp   r3, r1                  ; TABLE[channel] vs. target
0x82ac: bgt   0x82ba
0x82ae: movs  r1, #0x4                ; r1 = 4   (mode argument, fixed)
0x82b0: bl    0x5274                  ; FUN_00005274(r0=channel, r1=4, r2=?, r3=TABLE[channel])
0x82b4: adds  r6, #0x1                ; loop counter increment
0x82b6: adds  r4, #0x4                ; advance to next channel's 4-byte window
0x82b8: b     0x827e

0x82ba: lsls  r3, r2, #0x18           ; test sign bit of buffer[+7]
0x82bc: it    mi
0x82be: rsb.mi r1, r1                 ; negate target if buffer[+7]'s high bit was set
0x82c0: bl    0x5448                  ; FUN_00005448(r0=channel, r1=target(maybe negated), r2=?, r3=?)
0x82c4: b     0x82b4
```

**Loop semantics**: for each 4-byte channel record in the receive buffer
starting at buffer offset 6 (channel 0 = bytes 6-9, channel 1 = bytes 10-13,
...), compare the shared table's current value for that channel
(`TABLE[channel]`, `TABLE` = RAM `0x20000180`) against a packed target value
decoded from 3 of those bytes. If the table value is <= target, call
`0x5274(channel, 4, _, TABLE[channel])`; otherwise call
`0x5448(channel, ±target, _, _)`. Either way, increment the counter and
advance to the next channel.

**Exit condition**: `r6 >= (buffer[1]-adjusted) / 4`. `r6` starts at
whatever the dispatcher's own entry argument was (the caller's `R0`, `MOV
R6,R0` at `0x8262` — see
[`docs/investigations/trigger-input.md`](trigger-input.md)) and is
incremented by exactly 1 per iteration; nothing else in this address range
writes `r6`. `buffer[1]` is read fresh each iteration but is never written
anywhere in this range, so the threshold is effectively constant per call.
**Structurally, this is an ordinary bounded counting loop** — its exit
depends on two things only: the caller's initial `R6` value, and the one
buffer byte `buffer[1]`.

## `0x5274`: reads, writes, conditionality

Decompiled (Ghidra), with literal-pool constants resolved to their RAM
targets:

```c
void FUN_00005274(int channel, int mode, undefined4 param_3, int param_4)
{
  if (mode == 4) {
    // -- unconditional in this branch --
    *(int*)(0x200024cc + channel*4) = *(int*)(0x20000180 + channel*4)   // == TABLE[channel]
                                     * *(int*)(0x20000094 + channel*4);
    FUN_00004d18();
    *(byte*)(0x2000309d + channel) = 1;
  } else {
    // -- mode 2/3/other: a larger per-channel motion-profile computation --
    // (reads 0x20000090, 0x2000008c, 0x20002500, 0x2000012c, 0x20002524,
    //  and ~15 more per-channel arrays at 0x20001b20/0x20001b2c/0x20002004/
    //  0x20002534/0x20002938/0x20002310/0x20000170/0x20002400/0x2000231c/
    //  0x20001b18, indexed by channel*4; calls FUN_00004d18/0xdb08/0xde30/0xe1cc)
    // all writes in this branch are unconditional once the branch is taken;
    // the only internal conditionals select which *value* gets computed
    // (a formula choice gated on a byte at 0x20002524, and a mode==3
    //  adjustment to the target), not whether a write happens.
  }
}
```

**At the loop's call site (`0x82b0`), `mode` (R1) is hardcoded to `4`** —
so only the short branch above ever executes for this call site. `param_3`
(R2) is unused anywhere in the function; `param_4` (R3, = `TABLE[channel]`
at this call site) is only used in the `else` branch, which this call site
never takes. **Net effect of this call, at this call site**:

- Write: `0x200024cc[channel]` (4 bytes) = `TABLE[channel] * 0x20000094[channel]`
- Write: `0x2000309d[channel]` (1 byte) = `1`
- Calls `FUN_00004d18()` (see below)

Both writes are **unconditional** given this call site (mode is fixed to 4
here, and there's no further branching inside the `mode==4` arm).

`0x5274` is also called from five other sites (`0x7d3a`, `0x8320`, `0x84ee`,
`0x8768`, `0x8ac2`, `0x8e54`) with modes not yet checked — out of scope for
the loop-termination question, since only the `0x82b0` call site is inside
the loop.

## `0x5448`: reads, writes, conditionality

```c
void FUN_00005448(int channel, int target, undefined4 param_3, undefined4 param_4)
{
  *(byte*)(0x20000134 + channel) = 1;                    // unconditional
  *(int*)(0x200023d8 + channel*4) = FUN_0000ccd0();       // unconditional
  *(byte*)(0x20002524 + channel) = 2;                     // unconditional
  if (*(byte*)0x20003098 == '\n') {                       // CONDITIONAL
      *(byte*)0x20003098 = '\0';
  }
  if (*(int*)(0x200024cc + channel*4) != target) {        // CONDITIONAL
      *(int*)(0x200024cc + channel*4) = target;
      int iVar3 = *(int*)(0x20000094 + channel*4);
      if (iVar3*target - *(int*)(0x2000007c + channel*4) != 0) {
          FUN_00004d18(channel, iVar3, 0x20000094[channel], param_4);  // CONDITIONAL call
          return;                                          // early return
      }
  }
}
```

`param_3` (R2) is unused. `param_4` (R3) at the `0x82c0` call site is
leftover/incidental (the immediately preceding instruction, `lsls r3,r2,
#0x18`, sets R3 for an unrelated sign test — nothing deliberately loads a
4th argument) and only matters if the deep conditional call to
`FUN_00004d18` triggers, which itself is opaque to `0x5448`.

`FUN_0000ccd0` (called unconditionally above) is a 6-byte stub with **no
RAM writes** in Ghidra's export — almost certainly a trivial
read-a-tick-counter helper, not a hidden write path.

**Two conditional writes found**:
1. `0x20003098` reset to `0`, only if it currently holds `'\n'` (0x0A) —
   looks like a line/newline-processing flag, unrelated to per-channel state.
2. `0x200024cc[channel]` updated to `target`, only if it currently differs
   — **this is the same address `0x5274`'s `mode==4` branch writes**, so
   whichever of the two runs later for a given channel/iteration determines
   what ends up there.

## Shared callee: `FUN_00004d18`

Called from both functions above. Checked its data references (existing
export, no new decompile needed): its only RAM write is `0x200030c8`
(two sites, `0x4e94`/`0x517a`) — not the table (`0x20000180`), not the
buffer, and not any address either `0x5274` or `0x5448` write.

## Does the loop read anything `0x5274`/`0x5448` write? **No overlap found.**

The loop's own memory accesses (`0x827e`-`0x82c4`) are exactly: `buffer[1]`
(`0x2000232b`), the sliding 4-byte channel window (`0x20002330`-`0x20002337`
for channel 0, sliding by 4 per iteration), and `TABLE[channel]`
(`0x20000180 + channel*4`, **read only** — confirmed no write to this base
from either function or their shared callee).

`0x5274`/`0x5448`/`FUN_00004d18` write to: `0x200024cc`, `0x2000309d`,
`0x20000134`, `0x200023d8`, `0x20002524`, `0x20003098` (conditional),
`0x200030c8`. **None of these are read anywhere in the loop's own address
range.** This is a direct, addressed comparison, not an inference.

**Caveat**: this only checked `0x5274`, `0x5448`, and their two
directly-called helpers (`FUN_00004d18`, `FUN_0000ccd0`). The deeper
callees only reachable through `0x5274`'s `else` branch
(`FUN_0000db08`, `FUN_0000de30`, `FUN_0000e1cc` — never reached from the
loop's call site, since mode is fixed to 4 there) were not examined, since
they're outside what this call site can reach. Also not verified: whether
anything **outside** this loop iteration (e.g. a later call to `0x5274`
with a different mode, from one of its other 5 call sites) could write
`TABLE[]` before a *subsequent* dispatcher invocation — that's a
cross-invocation question, not relevant to one whole-function replay.

## Tool/evidence disagreement worth flagging

**This static finding is in tension with the previously-recorded dynamic
observation.** [`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)
records that a real whole-function Crucible run showed "R6 grows linearly
and unboundedly" for *both* tested concrete values of `buffer[1]` (`0x7c`
and `0x01`). But per the structural analysis above, `R6` is a simple
counter compared against a small, fixed threshold derived from `buffer[1]`
(e.g. `buffer[1]=0x7c` implies a threshold around `(124-7)/4 ≈ 29`) — it
should hit the `bge.w 0x83ec` exit within on the order of tens of
iterations, *not* grow unboundedly, regardless of what `0x5274`/`0x5448` do
to memory (confirmed above: they don't write anything the exit comparison
reads).

**This does not disprove the memory-side-effect hypothesis outright**, but
it does mean a second, simpler candidate explanation now has direct
structural support and hasn't been ruled out: **the loop's initial `R6`
value (seeded from the still-unresolved caller argument — see
[`trigger-input.md`](trigger-input.md)) may not have been the small,
realistic value assumed**, or the harness's register/memory setup for that
whole-function run may have left something upstream of `R6`/`buffer[1]`
symbolic or mis-seeded in a way that produces a huge or unbounded effective
threshold. **This needs a concrete check, not more static reading** — see
next steps.

## What Unicorn should capture next

Per [`docs/tooling/tool-selection.md`](../tooling/tool-selection.md) (concrete
execution is the right tool for "what does this code do from a known
state"), the next step is a concrete run seeded at the dispatcher's real
entry (`0x8259`) or directly at the loop (`0x827e`), capturing:

- **`R6`'s actual initial value** at loop entry, for a real `&`-packet run
  — this directly tests whether the "unbounded growth" claim reflects real
  firmware behavior or a harness-seeding artifact.
- **`buffer[1]`'s real value** for an actual `&|` packet, and the resulting
  `R2`/threshold computed at `0x8280`-`0x8286`.
- **`R7`** (should be `0x20000180`) and a few real entries of `TABLE[]` at
  that address, to see what a real device actually has there (this is
  runtime-populated RAM state static analysis cannot see at all).
- Step-count/iteration-count for a few full loop passes, to directly observe
  whether it terminates quickly (supporting the counter-seeding
  explanation) or genuinely runs long (supporting a memory-effect or other
  explanation not yet identified).
- Concrete values of `0x200024cc[channel]`, `0x2000309d[channel]`,
  `0x20002524[channel]`, `0x20003098` before and after a few iterations, to
  confirm the write pattern predicted above.

This is diagnostic capture, not the fix — no Crucible model changes should
follow until this concrete data is in hand.

## Open uncertainties

- The asymmetry in `0x5274`'s decompiled `mode==4` vs. `else` branch — the
  `else` branch's very first write renders as `*DAT_000053b8 = 1` (index 0
  only) while the `mode==4` branch explicitly indexes `puVar1[channel]` —
  worth a raw-disassembly double-check if this ever becomes load-bearing;
  not investigated further here since the loop's own call site only takes
  the `mode==4` (indexed) branch.
- `FUN_0000db08`, `FUN_0000de30`, `FUN_0000e1cc` (reachable only from
  `0x5274`'s `else` branch) were not examined — not reachable from the
  loop's call site, so not relevant to this specific question, but relevant
  if `0x5274` is ever called from one of its other 5 sites within the same
  replay.
- Where the loop's caller (`0x8a34 -> 0x8259`) actually sets `R0` (seeding
  `R6`) is still the unresolved question from
  [`trigger-input.md`](trigger-input.md) — this investigation makes that
  question more urgent, not less, since `R6`'s initial value now looks like
  the single most likely lever on loop length.
