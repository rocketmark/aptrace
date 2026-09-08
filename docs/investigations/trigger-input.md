# Investigation: What Triggers the Dispatcher, and With What Input?

Tracing the real caller into the AutoPilot protocol dispatcher (flash
`0x8258`) and how its input registers (R0, R4-R7) get established — asked
because the dispatcher's own entry code assumes several registers already
hold specific things (a buffer pointer, a table base, a caller-supplied
argument), and getting those wrong was the proximate cause of a long,
confusing debugging session (see
[`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)).

**Status**: partially resolved. R4/R5/R7's setup is understood and
confirmed (they're established by the dispatcher's *own* entry code, not by
the caller). R0's real value is not reliably known, because tracing it hit
a Macaw discovery anomaly (below) that undermines confidence in that
specific trace.

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

**Practical consequence**: R0's "correct" value for a real dispatcher call
cannot be reliably derived from this trace. Treat any conclusion drawn from
following execution through `0x801c` as unreliable until this is resolved.
Do not use this path as a source of ground truth for other investigations.

## Open follow-ups

- Determine which of the two `0x801c` explanations is correct — likely
  needs an independent disassembler (objdump/Capstone/Ghidra; see
  [`docs/project-status.md`](../project-status.md)'s tooling gaps) to
  cross-check Macaw's decode of the surrounding bytes.
- If it's a real decode limitation, consider reporting upstream to
  GaloisInc/macaw or GaloisInc/dismantle with a minimal reproduction.
- Independently of resolving the above, consider whether the dispatcher's
  behavior for the AutoPilot-only milestone
  ([`docs/project-status.md`](../project-status.md)) actually depends on
  R0's exact value, or whether a reasonable placeholder (e.g. `0`) is
  sufficient — this hasn't been definitively settled either way.
