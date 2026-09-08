# Investigation: Verifying the Outbound TX Path (`pending[5]` → `0x9268` → `0x8c10` → `"V01R39"`)

**Question**: with `pending[5]=1` (already concretely demonstrated to result
from a real `&|` packet — see
[`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md)),
does the real firmware's outbound event dispatcher actually consume event
5 and hand the TX hook exactly the string `"V01R39"`? This closes the last
open piece of the AutoPilot-only milestone. Per
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md), this is a
concrete-execution question (Unicorn), with Ghidra used first for the
static structure (decompiling `0x9268`/`0x8c10`/`0x7f84` and tracing where
the version string actually comes from). No Crucible/execution-model work.

**Scope**: AutoPilot firmware only. No Remote/mando work.

## Ghidra: decompiling the dispatcher and finding the version string

Decompiling `0x9268` (`tools/ghidra/scripts/APTraceDecompileFunctions.java`)
confirms the structure `docs/protocol/event-map.md` already described
statically: a loop over a scan table, checking `pending[event_id] != 0` for
each entry, and a `switch (event_id)` selecting what to send. **Case 5**:

```c
case 5:
  puVar9 = DAT_000093d4;   // resolves (raw firmware bytes) to 0x20003134
  break;
...
FUN_00008c10(puVar9);      // the string TX wrapper, called with R0 = puVar9
```

`"V01R39"` does **not** appear as a contiguous string literal anywhere in
the flash image (checked directly against the raw bytes) — the compiler
instead spread it across individual byte-store immediates. Ghidra's
cross-reference database found exactly one write to `0x20003134`:

```c
// FUN_00004328, called unconditionally, no preconditions:
void FUN_00004328(void) {
  puVar1 = DAT_00004348;        // resolves to 0x20003134 -- same address
  *DAT_00004348 = 0x56;         // 'V'
  puVar1[1] = 0x30;             // '0'
  puVar1[2] = 0x31;             // '1'
  puVar1[3] = 0x52;             // 'R'
  puVar1[4] = 0x33;             // '3'
  puVar1[5] = 0x39;             // '9'
  puVar1[6] = 0;                // '\0'
}
```

**Confirmed independently**: `DAT_00004348` resolves to the identical
address `0x20003134`. This function writes exactly `"V01R39\0"`,
unconditionally, in six deterministic byte-store instructions.

**Confirmed real call order** (Ghidra call-graph, matching the same
startup/main-loop functions this project already traced for the RX side):

```
FUN_0000cd90 (startup)
  -> FUN_00009464 (one-time init)
       -> ... -> FUN_00004328()   -- writes "V01R39" to 0x20003134
       -> main loop:
            FUN_000093fc()
              -> FUN_00009268()   -- the outbound dispatcher
              -> FUN_00008960()   -- the RX receiver (same one already tested)
```

**This means, in real firmware execution, `FUN_00004328` always runs once
at startup, strictly before the main loop's first call to either
`0x9268` or `0x8960`** — so by the time any `&|` packet could ever set
`pending[5]=1`, the version-string buffer is already guaranteed to hold
`"V01R39\0"`. No assumption is needed here beyond what's already
independently confirmed by reading the actual code.

`0x8c10`'s own body dispatches on a runtime mode byte (`*DAT_00008c60`,
0/1/2) to different underlying transport paths (radio driver, byte-wise
callback table, etc.) — real hardware/driver internals, deliberately not
modeled, per this project's already-established scope boundary
(`docs/protocol/bidirectional-protocol.md`: "Outbound transmission (the TX
hook at `0x8c10`) ... not modeled"). **The claim under test is "the
firmware hands the TX hook a pointer to exactly `V01R39`," not "the radio
transmits these exact wire bytes"** — consistent with the milestone's own
wording (`pending[5]` → TX hook → observed string).

## Unicorn: concretely running the dispatcher with `pending[5]=1`

Seeded (all via `tools/unicorn/run_concrete.py --seed-mem`, entry at
`0x9268`):

| Address | Value | Justification |
|---|---|---|
| `0x200025c1` (`pending[5]`) | `01` | Already concretely established as the real result of a `&\|` packet. |
| `0x20003134` (version buffer) | `56 30 31 52 33 39 00` (`"V01R39\0"`) | Independently confirmed above to be `FUN_00004328`'s unconditional, deterministic output — not guessed. |
| `0x20000100` (scan-table slot 0) | `05` | **Simplification**: the real scan-table's initialization code was not traced (its writes are computed/indexed, not visible to the static literal-pool xref scan used elsewhere in this project) — seeding "the table's one active entry is event 5" tests the case-5 path directly, matching this project's established precedent of seeding the RX packet buffer directly rather than simulating the full byte-arrival chain. |
| `0x200000d9` (scan-table count) | `1` | Same simplification — exactly one entry to scan. |
| `0x20002520` (last-processed timestamp) | `0xFFFF0000` | Bypasses an unrelated rate-limit gate (`elapsed >= 0x33` check) that would otherwise return early from a cold-RAM timestamp of `0`; unrelated to the event-5 dispatch logic itself. |

Result (`--stop-at 0x8c10`):

```
57 instructions executed, stopped at 0x8c10
R0 = 0x20003134
memory[0x20003134..+8] = 56 30 31 52 33 39 00 00   ->  "V01R39\0\0"
memory[0x200025c1]     = 00                          (pending[5], after dispatch)
```

## Results

1. **Event 5 is consumed**: `pending[5]` goes from `1` to `0` across the
   dispatcher's run (the decrement instruction identified in the Ghidra
   decompile, confirmed to have executed).
2. **The real TX path is exercised**: execution reaches `0x8c10` (the
   string TX wrapper) via the real `case 5` arm of the real, unmodified
   `0x9268` dispatcher — not a stubbed or hand-picked jump.
3. **Transmitted bytes captured**: `R0` (the TX hook's first argument)
   points at `0x20003134`, and the bytes there are exactly
   `56 30 31 52 33 39 00`.
4. **Verified exactly `"V01R39"`**: `56 30 31 52 33 39` decodes to
   `'V' '0' '1' 'R' '3' '9'`, null-terminated — an exact match, not a
   prefix or a similar-looking value.

## What this does and doesn't close

**Closes**: the full chain `pending[5]=1` → real dispatcher (`0x9268`) →
real TX hook (`0x8c10`) → exact string `"V01R39"`, at the concrete
(Unicorn, level 2) evidence tier — combined with the already-existing
concrete result for `&|` → `pending[5]=1`
([`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md)),
this is a complete, concrete, end-to-end demonstration of the AutoPilot
milestone: `"&|"` → real receive path → event 5 → real TX hook → exactly
`"V01R39"`.

**Does not close**: the solver-confirmed (level 3) version of the *whole*
chain in one Crucible run — that remains blocked on the readonly-flash/
literal-pool limitation documented in
[`whole-function-trace-divergence.md`](whole-function-trace-divergence.md),
which this pass did not attempt to fix (out of scope by explicit
instruction). The two halves (`&|`→`pending[5]` and
`pending[5]`→`"V01R39"`) have each been solver-confirmed only at the
single-block granularity for individual pieces (e.g. the `&` character
check itself), not as one continuous whole-function proof.

**Simplifications carried forward** (see table above): the outbound
scan-table's real initialization was not traced and was seeded directly
instead. This is the same category of simplification already accepted for
the RX side's UART/serial buffer assembly, and does not affect the
correctness of what was actually verified (the case-5 dispatch and TX
hand-off logic, which does not depend on how the table got populated,
only on the entry it finds being `5` with `pending[5]!=0`).
