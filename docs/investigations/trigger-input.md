# Investigation: What Triggers the Dispatcher, and With What Input?

Tracing the real caller into the AutoPilot protocol dispatcher (flash
`0x8258`) and how its input registers (R0, R4-R7) get established — asked
because the dispatcher's own entry code assumes several registers already
hold specific things (a buffer pointer, a table base, a caller-supplied
argument), and getting those wrong was the proximate cause of a long,
confusing debugging session (see
[`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)).

**Status**: resolved. R4/R5/R7's setup is understood and confirmed (they're
established by the dispatcher's *own* entry code, not by the caller). The
`0x801c` anomaly that originally blocked tracing R0 was cross-checked with
Ghidra and is a Macaw/dismantle decode limitation, not dead code — and R0's
real value at the call site was subsequently pinned down directly via
Unicorn (`R0 = 0`, from `*(byte*)0x20001fd4`), without needing to fully
resolve `0x801c`'s own computation. See the two "Update" sections below.

## The real call site

Seeding Macaw discovery at `0x8a35` (Thumb entry near the LoRa RX area, per
`research/autopilot_static_inventory/rf-boundaries.md`) reaches `0x8259` as
a properly call-classified function — a genuine `BL` with a matching return,
not a tail-jump:

```
0x8a34: BL 0x8259    ; call and return to 0x8a39
```

This confirms the dispatcher is invoked as an ordinary function call from
somewhere in the RX-processing path, which is what one would expect.

## R4, R5, R7: established by the dispatcher itself, not the caller

Within `0x8259`'s own entry sequence (before the indexed-lookup loop
discussed in [`parser-dispatch.md`](parser-dispatch.md)):

- `0x825c`: `LDR R4, [0x8528]` — loads the literal at flash `0x8528`, which
  is the RX packet buffer address `0x2000232a`.
- `0x8264`: `MOV R5, R4` — R5 is simply an alias of R4.
- `0x8278`: `LDR R7, [0x8534]` — loads a second literal, `0x20000180`.

None of these depend on anything the caller passed in — they're fixed
literals and a register copy, established fresh on every call. This part
is solid.

## R0/R6: does depend on the caller, and this is where it gets uncertain

`0x8262`: `MOV R6, R0` — R6 (used as the lookup loop's counter/search key)
is seeded directly from R0, the caller's argument.

Tracing backward from the call site to find what sets R0: `0x8a1b -> 0x896a
-> BL 0x801c -> CBZ R0` (i.e. R0 checked immediately after a call, strongly
suggesting R0 = that call's return value).

### The `0x801c` anomaly

**`0x801c` is lifted by Macaw as ARM (A32) mode code**: `BL_i_A1`, `BX_A1`,
and the semantics explicitly set `PSTATE_T => 0` (ARM mode, not Thumb).

**This is architecturally impossible on a Cortex-M4F.** M-profile Cortex-M
cores have no ARM execution state at all — they are Thumb-only. A real
ATSAMD51 chip cannot execute A32-encoded instructions; attempting to would
fault.

`0x801c`'s second block (`0x8020`) also hits a Macaw discovery "classify
failure" on an indirect `BX R11` — Macaw's own classifier could not
determine the jump target and gave up, which is a strong independent signal
that something is off about how this region is being interpreted.

**Two explanations are consistent with the evidence, and it hasn't been
determined which is correct:**

1. **A genuine Macaw/dismantle decode limitation** for this specific call
   site or byte pattern — e.g. the call target address computation produced
   the wrong value, or something about the surrounding bytes confused the
   Thumb/ARM mode-selection logic that normally uses the low bit of the
   target address (see
   [`docs/firmware/cortexm-assessment.md`](../firmware/cortexm-assessment.md)
   for how that mechanism is supposed to work).
2. **This is genuinely dead or unreachable code on real hardware** — e.g. a
   compatibility stub for a different chip variant, or padding/data bytes
   that happen to disassemble as plausible-looking instructions but are
   never actually executed by the real firmware.

**Practical consequence (as originally written)**: R0's "correct" value for
a real dispatcher call cannot be reliably derived from this trace. See the
update below for what's changed since.

## Update: Ghidra cross-check (2026-09-07)

Per [`docs/tooling/tool-selection.md`](../tooling/tool-selection.md)'s rule
to never trust a Macaw A32 lift on this target without cross-checking it,
`0x801c` was re-examined with `tools/ghidra/analyze_firmware.sh`, seeding
it as an extra function-start address. Ghidra's `ARM:LE:32:Cortex` language
is architecturally incapable of decoding A32 (its processor spec forces
Thumb mode across the whole address space) — so if this really were
unreachable/non-code, Ghidra would be expected to produce garbage or fail
to form a sensible function there. Instead it decoded a completely
ordinary, well-formed 54-byte Thumb function:

```
push {r3,lr}
ldr  r3,[0x8054]
ldrb r3,[r3,#0]
cbz  r3,0x802e
ldr  r0,[0x8058]
bl   0xb71a
uxtb r0,r0
pop  {r3,pc}
... (0x802e-0x8050: a second branch computing an elapsed-time-like value
     via two loaded counters, `cmp`/`it lt`/`add.lt r0,#0x64` -- a
     wraparound-safe subtraction pattern, i.e. "if the new count wrapped,
     add 100 back before subtracting" -- then calling one of two more
     helpers at 0xc93e/0x7fdc before falling through to the same
     `uxtb r0,r0; pop {r3,pc}` return.)
```

This function is called from **eight** real, cross-referenced sites in
Ghidra's own analysis, including `0x896a`, `0x897e`, `0x8986`, `0x8a28`,
`0x8a3c`, `0x8a54`, and `0x8b22` — all within the same caller region
(`FUN_00008960`) that contains the `0x8a34 -> 0x8258` call Macaw found
independently. This is strong, independent evidence that:

1. `0x801c` is real, reachable, ordinary Thumb code — not dead code, and
2. Macaw's A32 lift for this address was a genuine decode limitation, not
   a reflection of real firmware behavior.

**What this resolves**: the "is it dead code or a decode bug" question
(previously open item #11 in
[`docs/protocol/open-questions.md`](../protocol/open-questions.md)) —
resolved in favor of "decode bug."

**What this does not resolve**: R0's *exact numeric value* at the real
`0x8a34` call site. What's now known is that `0x801c` returns a small,
`uxtb`-truncated (i.e. single-byte-range) value that looks like an elapsed
tick/time count, not an arbitrary or complex control value — which
significantly narrows what the subsequent `CBZ R0` at the caller is
plausibly testing (a "has some time elapsed" style check), but doesn't pin
down the exact number without either fully modeling the two callees
(`0xb71a`, `0xc93e`/`0x7fdc`) or observing a real value via Unicorn/hardware.

## Update: R0 concretely resolved via Unicorn (2026-09-07)

Per the follow-up below, R0 turned out not to require modeling `0x801c`'s
full return-value computation at all. Tracing the actual `0x8a34` call site
in `FUN_00008960` (the UART/serial receive state machine that assembles
the packet into `0x2000232a` — confirmed by resolving its literal pool)
found `R0` there is simply `*(byte*)0x20001fd4`, loaded fresh at `0x8a2e`
(`ldrb r0,[r4,#0]`) just before the call — not the leftover return value of
the preceding `0x801c()` call as first assumed. `0x20001fd4` is never
written anywhere in `FUN_00008960`, so in the project's standard cold/zero
RAM convention it's `0`. Running `0x801c()` alone via Unicorn from cold RAM
separately (and concretely) confirmed *it* also returns `0` from that
state, for what it's worth — but it isn't actually what feeds R0 here.
**R0 = 0 at the real dispatcher call, demonstrated by tracing the actual
source instruction, not assumed.** Full trace:
[`docs/investigations/dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md).

This resolves this document's remaining open question. It also turned out
not to matter for the current milestone's blocker: the address R0 feeds
(`R6`, the `0x827e` loop's counter) is on a code path
(`buffer[0]==0xF0`) the real `&` command never reaches at all — see the
linked document.

## Open follow-ups

- Consider reporting the A32 misdecode upstream to GaloisInc/macaw or
  GaloisInc/dismantle with a minimal reproduction (the raw bytes at
  `0x801c` plus the expected Thumb decode above).
