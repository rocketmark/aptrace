# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it here.
Historical detail lives in linked docs, not here — this file stays short by
design.

Last updated: 2026-09-08.

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

**Status: COMPLETE at the concrete (Unicorn) evidence tier, end to end.**
As of 2026-09-07, every stage of the chain above has been independently,
concretely demonstrated against real, unmodified firmware, entering at
real call sites with the firmware establishing its own state (not
hand-picked to make the answer come out right):

1. `&|` → `pending[5]=1`: entering at the real caller (`0x8a34`) with a
   real `&|` packet, `pending[5]` becomes `1` in 46 instructions. See
   [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
2. `pending[5]=1` → TX hook → `"V01R39"`: the real, unmodified outbound
   dispatcher (`0x9268`) consumes event 5 and calls the real TX hook
   (`0x8c10`) with a pointer to a buffer holding exactly `"V01R39\0"` —
   independently confirmed to be what a real, unconditional startup
   routine (`FUN_00004328`) writes there before the main loop ever runs.
   See [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).

Per [`docs/tooling/tool-selection.md`](tooling/tool-selection.md)'s
evidence levels, this is **level 2** (concretely executed) across the
whole chain. A **level 3** (solver-confirmed, Crucible/What4/Z3) proof of
the *whole* chain in one run remains blocked by a known, deliberately
unfixed tooling gap — see "Tooling gaps," not a firmware blocker. Individual
pieces of the chain (e.g. the `&` character check itself) already have
independent level-3 confirmation.

**Note on the command itself**: `&|` is the wire-level frame the Remote
transmits (`|` is the frame terminator). The dispatcher's first-byte check
requires exactly `0x26` ('&') at flash `0x888c` — solver-confirmed
(level 3) — and the full `&|` frame reaching that check, and the full
onward path to `"V01R39"`, has now also been demonstrated concretely
(level 2, above).

**Remote (`mando`) firmware**: first concrete execution (2026-09-08), then
a full harness-driven virtual RF link (2026-09-08) closing roadmap M3
entirely at the concrete evidence tier. Ghidra's existing pipeline loads/
discovers Mando cleanly with zero platform-specific changes (563
functions; every previously-named Remote function of interest resolves
at its documented address). The complete `&|` -> `V01R39` round trip now
runs as **one harness-driven script** (`tools/unicorn/virtual_link.py`),
not two hand-run scenarios: Remote's real `0xba98` computes `"&|"` and
calls its real TX wrapper; the harness transfers those exact bytes (no
radio modeled) into AutoPilot's real RX buffer; AutoPilot's real
dispatcher schedules event 5 and its real outbound dispatcher builds
`"V01R39"`; the harness transfers those exact bytes into Remote's real RX
ring buffer; Remote's real collection loop captures exactly `"V01R39\0"`.
See [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md)
for the per-firmware proofs and the honest boundary found (both firmwares
gate real RF I/O behind an unmodeled driver layer — reaching past it
needed the `--stub-call` Unicorn capability, not full radio emulation),
and [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md)
for the round trip itself and the two reusable primitives
(`capture_tx_bytes`/`deliver_and_observe`) it's built from.

## Proven capabilities & findings

Demonstrated on real, unmodified firmware; safe to build on without
re-proving:

- **Target/platform**: Performing Rigs AutoPilot/Remote firmware on
  Microchip/Atmel **ATSAMD51J19A** (Cortex-M4F, 512KB flash, 192KB SRAM —
  exact part confirmed by physical board inspection, not inferred),
  Arduino/Adafruit SAMD lineage, app image loaded at flash `0x4000`.
  Hashes: [`docs/firmware/firmware-inventory.md`](firmware/firmware-inventory.md).
  Layout/vector table: [`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md).
  Hardware/board-level research:
  [`docs/hardware/autopilot-research-handoff.md`](hardware/autopilot-research-handoff.md).
- **Macaw pipeline**: raw `.bin` loading (no ELF), vector-table parsing,
  Thumb-2 lifting (zero decode failures across ~1500 real instructions),
  and CFG discovery from arbitrary seeded entry points — used to seed the
  protocol dispatcher directly.
- **Crucible execution infrastructure works** at both granularities:
  single-block (`APTrace.SymbolicRunner.checkBranchModel`) and
  whole-function (`APTrace.ProtocolHarness.runPacketTransaction`) — i.e.
  the lift-to-Crucible-to-What4/Z3 machinery runs correctly in general.
  **A whole-function solver-confirmed replay of the full `&`-command
  dispatcher specifically is still blocked by a known, documented, and
  deliberately unfixed tooling gap — see "Tooling gaps," not a claim
  about the firmware.**
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
- **`--watch`/`--watch-mem`** added to the Unicorn backend: records full
  register/memory state at multiple addresses across one run without
  halting (unlike `--stop-at`) — needed for a per-iteration loop trace. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **The real `&|` -> `pending[5]=1` transaction, concretely demonstrated**:
  entering at the real caller (`0x8a34`), letting the firmware establish
  its own entry state (not manually seeded), with a real `&|` packet in the
  buffer — `pending[5]` becomes `1` in 46 instructions. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
- **`tools/doctor.sh`** verifies Ghidra, Unicorn, and Macaw/Crucible/What4/Z3
  are all usable, including functional smoke tests.
- **`APTrace.ProtocolHarness.RichTraceConfig`/`runPacketTransactionTraced`**:
  a reusable, fine-grained (every-step, not sampled) execution trace for a
  bounded address range within a whole-function run, using the existing
  `Data.Macaw.Symbolic.Regs.simStateRegs` API to recover live register
  state. What found the readonly-flash root cause — see "Tooling gaps."
  See [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md).
- **The real `pending[5]=1` -> TX hook -> `"V01R39"` transaction, concretely
  demonstrated**: the real, unmodified outbound dispatcher (`0x9268`)
  consumes event 5 (`pending[5]` observed going `1` -> `0`) and calls the
  real TX hook (`0x8c10`) with a pointer to a buffer independently
  confirmed to hold exactly `"V01R39\0"` — written there unconditionally
  by a real startup routine (`FUN_00004328`), not seeded to force the
  answer. Combined with the `&|` -> `pending[5]=1` result above, this
  closes the full AutoPilot milestone at the concrete evidence tier. See
  [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).
- **Real ATSAMD51J19A peripheral/register naming for raw MMIO addresses**:
  [`tools/svd/resolve_mmio.py`](../tools/svd/resolve_mmio.py), backed by
  the real vendor SVD file, plus `run_concrete.py --log-mmio` to capture
  what a concrete run actually touches. Used to confirm the full
  `Reset_Handler` startup peripheral-init chain (clock tree, analog block,
  WDT, PORT, TC0-TC3, TCC1, USB), and one fully-resolved pin-level fact:
  **PB22 is toggled from a real timer interrupt handler (IRQ93/TCC1)** —
  a named GPIO tied to already-understood firmware behavior, matching the
  hardware doc's "4 motor-output channels." Also produced an honest
  negative result: the outbound TX path (`0x9268`→`0x8c10`) touches no
  MMIO directly — its real transport peripheral is gated behind a runtime
  driver-object pointer, not a literal address, and naming it is the next
  slice, not done here. See
  [`docs/investigations/samd51-peripheral-mapping.md`](investigations/samd51-peripheral-mapping.md).
- **First concrete Mando (Remote) execution**: Ghidra discovery clean with
  no platform-specific changes; both halves of the `&|` -> `V01R39`
  round trip confirmed from the Remote's own side via Unicorn (real TX
  construction and real RX capture, in two separate runs mirroring the
  AutoPilot milestone's own two-step structure). Required a new
  `run_concrete.py --stub-call` capability (the Unicorn-side equivalent of
  Crucible's existing opaque function-call override) to get past a real,
  not-yet-modeled radio/SPI driver dependency — the same class of boundary
  already found on the AutoPilot's TX path. See
  [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md).
- **A full, harness-driven virtual RF link, both firmwares, one round
  trip**: `tools/unicorn/virtual_link.py` runs the complete `&|` ->
  `V01R39` transaction end to end — Remote's real TX call, a harness-
  mediated byte transfer (no radio modeled), AutoPilot's real dispatch
  and response, a second harness-mediated transfer, Remote's real
  capture — asserting the exact bytes at every step. Built from two
  reusable primitives (`capture_tx_bytes`, `deliver_and_observe`) that
  don't hardcode transaction content, only the already-proven RF-boundary
  addresses, so the same script structure applies to future transactions
  (`G -> #`, `S -> P...`). This closes roadmap M3. See
  [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md).

## Corrected assumptions

- **The `0x827e`-`0x82c4` loop is not on the ASCII-command path at all —
  it's gated on `buffer[0]==0xF0`.** Two earlier passes (Ghidra-based
  decompilation, then a first symbolic-execution pass) both examined this
  loop under the assumption that it runs first for *every* packet,
  including `&`. Concrete execution found the dispatcher's actual first
  decision, at `0x8258`-`0x8266`, is `cmp buffer[0],#0xF0; bne <skip the
  loop>` — the loop is v0.1's own "binary motor/control frame" path
  (`0xF0`/`0xE0`), and ASCII commands branch straight past it into the
  character-comparison chain instead. **The loop is never entered for the
  `&` command the current milestone is about.** This supersedes the
  "flat parser chain" correction below it and the memory-side-effect
  blocker hypothesis that followed from it. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md)
  and [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **The "flat parser chain" model of `0x8258` is not fully trusted** (background,
  now refined by the point above). The original static pass modeled the
  dispatcher as a simple if/else-if scan over the packet's leading byte;
  the real shape is a `buffer[0]` gate into either the binary-frame loop or
  the ASCII chain. See
  [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **Macaw vs. Ghidra disagreement at `0x801c`, resolved.** Macaw lifted this
  address (on the path that sets up the dispatcher's R0 argument) as
  ARM/A32-mode code — architecturally impossible on Cortex-M4F. Ghidra's
  Thumb-only Cortex-M language (incapable of decoding A32 at all) instead
  decoded it as an ordinary, well-formed, 8-times-called Thumb function.
  **Conclusion: the A32 lift was a Macaw/dismantle decode limitation, not
  dead code.** R0's exact value at the dispatcher call site was
  subsequently pinned down directly via Unicorn: **R0 = 0**, traced to
  `*(byte*)0x20001fd4` at the real call site, a byte never written before
  that point from cold RAM. See
  [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#tool-disagreements-investigate-dont-default),
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md),
  and [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).

## Tooling gaps

**Not a firmware blocker — a known, documented, and deliberately unfixed
harness limitation.** A whole-function Crucible replay of the `&`-command
dispatcher gets stuck in the `0x827e` loop, taking the wrong branch at
`0x8266` despite `buffer[0]` being concretely `0x26`. This was fully
investigated and explained (not left as an open mystery):

- The `0x8266` branch itself, Macaw's lift of it, and `mkFunCFG`'s entry/
  branch-CFG wiring are all confirmed correct — isolating the exact block
  in Crucible (existing single-block machinery, extended with a small
  `bqMemoryBytes` addition to seed the buffer content) reproduces the
  correct, deterministic result for both `buffer[0]=0x26` and the `0xF0`
  control case. See
  [`docs/investigations/gate-block-crucible-isolation.md`](investigations/gate-block-crucible-isolation.md).
- **Root cause**: the dispatcher's buffer pointer is loaded from a literal
  pool in flash, and flash is `readonly` — `populateSegmentChunk` always
  populates readonly memory via solver assumptions, never as folded array
  literals, regardless of `ConcreteMutable`/`SymbolicMutable`. That's fine
  for a solver query, but plain Crucible execution has no solver in the
  loop for an ordinary `Br`, so the branch condition never folds to a
  concrete `Pred` and Crucible picks the wrong side. See
  [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md)
  and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#known-limitation-readonly-flash-and-plain-crucible-execution).

**Deliberately not fixed in this pass, and not planned unless needed**: no
general fix (baking all of flash into literals, redesigning
`populateSegmentChunk`) — that's a real execution-model change with no
current symbolic use case requiring it, now that the milestone below is
closed at the concrete evidence tier. Revisit only if a future
Crucible/What4/Z3 use case genuinely needs a whole-function proof through
a literal-pool-derived branch; the narrow fix (baking the *specific*
literal-pool words that target reads, the same store pattern already
proven for the packet buffer) would be the smallest starting point.

## Next steps

**Note**: a tooling-only detour (2026-09-08, ahead of a Galois meeting)
happened between the milestone above and this section — two clean repros
(Macaw's A32-on-Cortex-M mode selection, readonly-flash/plain-Crucible
divergence), an experimental `aptrace debug` (`crucible-debug`/
`crucible-macaw-debug`), an optional GREASE experiment, and a small MMIO-
diagnostics addition. See
[`docs/tooling/galois-premeeting.md`](tooling/galois-premeeting.md). It did
not touch the milestone/roadmap; roadmap M3 (the virtual RF link) closed
separately and immediately afterward, also on 2026-09-08.

1. **Exercise the next protocol transaction through the virtual link**
   (roadmap M4): `G -> #` (`0xb680`/`0xb59c` on the Remote side, event 17
   on the AutoPilot side) or `S -> P...` (`0xc440`, event 6) — both
   already statically mapped on both sides per
   `research/autopilot_static_inventory/protocol-bidirectional.md`, and
   both reachable with the same two primitives
   [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md)
   built (`capture_tx_bytes`/`deliver_and_observe`) — not a new
   technique. `G`'s Remote side involves a retry loop (`0xb59c`) that may
   need its own `--stub-call` treatment, not yet confirmed.
2. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only entry *reachability* is
   solver-verified for these three) — a smaller, parallel task, not a
   prerequisite for (1).
3. If a real symbolic use case for the readonly-flash gap above ever
   arises, apply the narrow fix described in "Tooling gaps" — not before.
4. **Hardware grounding, smaller follow-ups** (from
   [`docs/investigations/samd51-peripheral-mapping.md`](investigations/samd51-peripheral-mapping.md),
   not prerequisites for (1)): find the other three motor channels'
   ISR/pin pairs the same way PB22/TCC1 was found; name the TX path's real
   transport peripheral by tracing what populates the driver-object
   pointer `0x8c10` dispatches through; install `GhidraSVD` only if the
   standalone resolver stops being convenient enough for routine use.

The `0x827e` loop's own internal structure and its callees `0x5274`/`0x5448`
([`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md))
remain correctly documented and are relevant to future `0xF0`/`0xE0`
binary-frame work. Fuller backlogs (protocol open questions, remaining
tooling gaps like the still-not-installed `GhidraSVD` extension) are
tracked in [`docs/protocol/open-questions.md`](protocol/open-questions.md)
and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md), not
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
