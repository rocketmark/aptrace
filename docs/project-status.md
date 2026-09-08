# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it here.
Historical detail lives in linked docs, not here — this file stays short by
design.

Last updated: 2026-09-07.

**Before doing firmware-analysis work, read
[`docs/tooling/tool-selection.md`](tooling/tool-selection.md)** (short
version: [`CLAUDE.md`](../CLAUDE.md)) for which of Ghidra/Unicorn/Macaw/
Crucible to reach for.

## Current milestone

**Goal**: one complete AutoPilot-only transaction, verified through
APTrace's own pipeline:

```
wire command "&|"
    -> real receive/parser path (unmodified compiled firmware)
    -> event 5 scheduled
    -> outbound TX hook (0x8c10 / 0x7f84)
    -> observed string == "V01R39"
```

**Status: not yet complete** — see "Current blocker" below.

**Note on the command itself**: `&|` is the wire-level frame the Remote
transmits (`|` is the frame terminator). What's solver-confirmed so far is
narrower: the dispatcher's first-byte check requires exactly `0x26` ('&')
at flash `0x888c`. How the full `&|` frame gets from the receive buffer to
that single-byte check — i.e. the exact parser-visible representation — is
still part of the receive-path investigation (see "Corrected assumptions").

**Remote (`mando`) firmware**: substantial *static* research already exists
for it (`research/autopilot_static_inventory/`, `docs/protocol/`), covering
both sides of the protocol. What hasn't happened is any APTrace
execution/harness work — Ghidra, Macaw, Unicorn, or Crucible have not been
pointed at `firmware_mando868.bin`/`firmware_mando915.bin` yet, and
**must not be** until the AutoPilot-only milestone above is complete.

## Proven capabilities & findings

Demonstrated on real, unmodified firmware; safe to build on without
re-proving:

- **Target/platform**: Performing Rigs AutoPilot/Remote firmware on
  Microchip/Atmel **ATSAMD51 (Cortex-M4F)**, Arduino/Adafruit SAMD lineage,
  app image loaded at flash `0x4000`. Hashes:
  [`docs/firmware/firmware-inventory.md`](firmware/firmware-inventory.md).
  Layout/vector table: [`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md).
- **Macaw pipeline**: raw `.bin` loading (no ELF), vector-table parsing,
  Thumb-2 lifting (zero decode failures across ~1500 real instructions),
  and CFG discovery from arbitrary seeded entry points — used to seed the
  protocol dispatcher directly.
- **Crucible execution infrastructure works** at both granularities:
  single-block (`APTrace.SymbolicRunner.checkBranchModel`) and
  whole-function (`APTrace.ProtocolHarness.runPacketTransaction`) — i.e.
  the lift-to-Crucible-to-What4/Z3 machinery runs correctly in general.
  **This is distinct from the AutoPilot dispatcher replay specifically
  completing, which it does not yet — see "Current blocker."**
- **Solver-confirmed single-block protocol checks** (not hand-derived): a
  register holding the packet's first byte, checked against each command's
  real comparison instruction, reaches the correct handler exactly at that
  command's ASCII value:

  | Command | Solver-confirmed value | Check block |
  |---|---|---|
  | `&` | `0x26` | `0x888c` -> `0x8890` |
  | `G` | `0x47` | `0x83b2` -> `0x83b6` |
  | `!` | `0x21` | `0x87b2` -> `0x87b6` |
  | `S` | `0x53` | `0x87be` -> `0x87c2` |

  See [`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md).
- **The real caller into the protocol dispatch region**: `0x8a34 -> 0x8259`
  (Macaw-call-classified `BL`, not a tail-jump). See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **A real calling-convention bug, fixed**: the opaque function-call
  override used to clobber *every* register (including AAPCS callee-saved
  R4-R11), corrupting a loop's own counter/table-pointer state and
  producing a hang that looked like firmware complexity. Fixed to only
  substitute the genuinely caller-saved registers (R0-R3, R12). See
  [`docs/harness/execution-model.md`](harness/execution-model.md).
- **A reusable diagnostic**: `APTrace.ProtocolHarness.debugFeature`, a
  Crucible `ExecutionFeature` that logs the visited program location every
  N steps — turns an opaque hang into "stuck cycling through X, Y, Z."
  Reuse it whenever a whole-function run doesn't terminate as expected.
- **Ghidra headless static analysis** integrated
  (`tools/ghidra/analyze_firmware.sh`, Thumb-only `ARM:LE:32:Cortex`,
  vector-table entry seeding): 414 functions discovered on real firmware
  (vs. 204 unseeded), including the dispatcher region. See
  [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md).
- **Unicorn concrete execution** integrated (`tools/unicorn/run_concrete.py`,
  Cortex-M4 model): concretely running from `0x888c` with `r3=0x26`
  reproduces the solver-confirmed `&` -> `0x8890` branch exactly. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`tools/doctor.sh`** verifies Ghidra, Unicorn, and Macaw/Crucible/What4/Z3
  are all usable, including functional smoke tests.

## Corrected assumptions

- **The "flat parser chain" model of `0x8258` is not fully trusted.** The
  original static pass modeled the dispatcher as a simple if/else-if scan
  over the packet's leading byte. Symbolic execution found the real entry
  sequence runs through an indexed-lookup loop first (`0x827e`-`0x82c4`,
  reading `[R5+1]`, `[R4+6..9]`, indexing `[R7 + R0*4]`) inside one large
  (~340-block) Macaw-discovered unit. The individual character checks
  (table above) still hold; the overall shape does not. See
  [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **Macaw vs. Ghidra disagreement at `0x801c`, resolved.** Macaw lifted this
  address (on the path that sets up the dispatcher's R0 argument) as
  ARM/A32-mode code — architecturally impossible on Cortex-M4F. Ghidra's
  Thumb-only Cortex-M language (incapable of decoding A32 at all) instead
  decoded it as an ordinary, well-formed, 8-times-called Thumb function.
  **Conclusion: the A32 lift was a Macaw/dismantle decode limitation, not
  dead code.** R0's exact value at the dispatcher call site is still
  unconfirmed. See
  [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#tool-disagreements-investigate-dont-default)
  and [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).

## Current blocker

Whole-function Crucible replay of the AutoPilot dispatcher against a real
in-memory `&` packet **does not terminate**, even with the calling-convention
bug fixed. Full trail:
[`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md)
("Follow-up session").

**Hypothesis revised (2026-09-07) after a Ghidra deep-dive on `0x5274`/
`0x5448`.** The original hypothesis was that these two per-channel functions
have memory side effects the loop's exit condition depends on, and that
opaquely stubbing them (zero memory effects) breaks that dependency.
Decompiling both functions and resolving their actual RAM read/write
targets found: `0x5274` (at its loop call site, mode fixed to `4`) writes
`0x200024cc[channel]` and `0x2000309d[channel]`; `0x5448` writes
`0x20000134[channel]`, `0x200023d8[channel]`, `0x20002524[channel]`
unconditionally plus two conditional writes (`0x20003098`, and
`0x200024cc[channel]` again). **None of these overlap the loop's own reads**
— the loop only reads `buffer[1]`, a sliding 4-byte buffer window, and
`TABLE[channel]` at `0x20000180` (read-only; neither function writes to
`0x20000180`). Full breakdown:
[`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md).

This is now in tension with the memory-side-effect hypothesis rather than
confirming it. The loop's exit condition (`R6 >= buffer[1]-derived
threshold`) is structurally an ordinary bounded counter — it should
terminate in a small, finite number of iterations regardless of what
`0x5274`/`0x5448` do to memory. The previously-recorded observation that
"R6 grows linearly and unboundedly" for two different concrete `buffer[1]`
values is not yet explained by this structure. **New leading candidate**:
the loop's initial `R6` value (seeded from the dispatcher's still-unresolved
caller argument — [`docs/investigations/trigger-input.md`](investigations/trigger-input.md))
or another upstream register/memory-seeding choice in that whole-function
test may be the actual cause, not the opaque-callee memory model. Both
explanations remain open; a concrete Unicorn run (see "Next steps") is
needed to distinguish them before touching the Crucible model.

## Next steps

1. ~~**Ghidra**: statically determine what `0x5274`/`0x5448` actually write
   to memory.~~ **Done** — see
   [`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md).
   Result: no overlap found between what they write and what the loop
   reads, which redirects the next step below.
2. **Unicorn**: run the dispatcher loop concretely (seeded at `0x8259` or
   directly at `0x827e`) with a real `&|` packet, and capture: the actual
   initial `R6` value, `buffer[1]` and the resulting exit threshold, `R7`
   and real `TABLE[]` entries, iteration count to termination, and
   `0x200024cc`/`0x2000309d`/`0x20002524`/`0x20003098` before/after a few
   iterations. This directly tests whether the loop concretely terminates
   quickly (supporting a harness-seeding explanation) or genuinely runs long
   (pointing to something not yet identified) — see
   [`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md)'s
   "What Unicorn should capture next."
3. **Crucible**: adjust the harness's model based on (2) — this may now be
   a register/memory-seeding fix (how `R6`/`R0` is established at the
   dispatcher's true entry) rather than an opaque-callee memory-effect
   model. Only decide once (2) gives concrete data; the lazy real-CFG
   execution mechanism (`MS.LookupFunctionHandle`; see
   [`docs/harness/execution-model.md`](harness/execution-model.md)) remains
   the fallback if a genuine memory-effect dependency is still found.
4. Once the loop terminates: confirm `pending[5]` becomes 1 from a real
   `&` packet run through the *unmodified* whole dispatcher function.
5. Hook `0x8c10`/`0x7f84` and verify the emitted bytes equal `V01R39` —
   closes the AutoPilot milestone.
6. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only entry *reachability* is
   solver-verified for these three).
7. **Only after (1)-(5)**: begin Remote (`mando`) harness work per
   [`docs/harness/roadmap.md`](harness/roadmap.md), building on the
   existing static research rather than starting from nothing.

Do not resume the dispatcher experiment without following this order —
notably, do not jump to step 3 before 1-2. Fuller backlogs (protocol open
questions, tooling gaps like SVD/MMIO labeling) are tracked in
[`docs/protocol/open-questions.md`](protocol/open-questions.md) and
[`docs/tooling/tool-selection.md`](tooling/tool-selection.md), not
duplicated here.

## Tool architecture

APTrace orchestrates specialist tools rather than reimplementing them:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE / decompiler / xrefs / tables / MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb execution / state snapshots | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / machine-code lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |
| APTrace | orchestration, evidence model, scenarios, traces, UI | This repo |

See [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for when
to use which, and [`docs/architecture.md`](architecture.md) for rationale.
