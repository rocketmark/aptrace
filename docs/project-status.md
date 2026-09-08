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

**Status: concretely demonstrated end to end (Unicorn); not yet
solver-proven (Crucible)** — see "Current blocker" below. This is a real
milestone-status upgrade as of 2026-09-07: entering at the real caller
(`0x8a34`) with a real `&|` packet and letting the firmware establish its
own state, `pending[5]` was concretely observed to become `1` in 46
instructions. See
[`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
Per [`docs/tooling/tool-selection.md`](tooling/tool-selection.md)'s
evidence levels, this is level 2 (concretely executed, one input) — the
milestone still wants level 3 (solver-confirmed, Crucible/What4/Z3) for the
full transaction, which is what's blocked (see "Current blocker"). The TX
hook (`0x8c10`/`0x7f84` -> `"V01R39"`) has not yet been tested at either
level.

**Note on the command itself**: `&|` is the wire-level frame the Remote
transmits (`|` is the frame terminator). The dispatcher's first-byte check
requires exactly `0x26` ('&') at flash `0x888c` — solver-confirmed
(level 3) — and the full `&|` frame reaching that check has now also been
demonstrated concretely (level 2, above).

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

## Current blocker

**Reframed (2026-09-07).** The blocker is *not* the `0x827e` loop, and not
a memory-side-effect or register-seeding gap — those hypotheses are
superseded (see "Corrected assumptions"). Concretely executing the real
call path (`0x8a34 -> 0x8259`) with the *exact same nominal inputs*
`app/Main.hs`'s existing whole-function Crucible test already uses (`R0=0`,
packet buffer `= [0x26, 0x01, 0x00, 0x00]`) takes 46 instructions, never
enters the loop, and reaches `pending[5]=1` cleanly.

**The current blocker is that Crucible's whole-function replay of the
identical scenario does not do this** — it was observed getting stuck in
the `0x827e` loop with `R6` growing unboundedly
([`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md)).

**Narrowed further (2026-09-07): the `0x8266` branch itself is exonerated.**
Isolating exactly this block in Crucible (existing single-block machinery,
extended with a small `bqMemoryBytes` addition to seed the buffer content —
see [`docs/investigations/gate-block-crucible-isolation.md`](investigations/gate-block-crucible-isolation.md))
and seeding the identical concrete inputs reproduces the correct,
deterministic result: `buffer[0]=0x26` reaches `0x82c6` (skip-the-loop) and
cannot reach `0x8268`; `buffer[0]=0xF0` cannot reach `0x82c6`. Macaw's
lift of the `CMP`/conditional-branch pair is correct; Crucible's
single-block branch semantics are correct. Reading `mkFunCFG`'s source
also confirms its entry mechanically jumps to `discoveredFunAddr fn`
(address-matched, concretely: `0x8259`), and its generic `ParsedBranch`-to-
`Br` translation is unremarkable. **None of the "obvious" candidates from
the prior pass hold up** — the fault, if real, is somewhere else in the
~339-block whole-function graph, in something the isolated test and source
reading can't see; a finer-grained re-run of the actual whole-function test
is the next step, not yet done. See that document's "Smallest next
experiment" section.

## Next steps

1. ~~**Investigate why Crucible's whole-function CFG doesn't resolve the
   `0x8266` branch the way concrete execution does**~~ — the branch itself
   (isolated in Crucible) and `mkFunCFG`'s entry/`ParsedBranch` wiring
   (read and address-confirmed) are both exonerated; see
   [`gate-block-crucible-isolation.md`](investigations/gate-block-crucible-isolation.md).
   **Next**: re-run the actual whole-function test with much
   finer-grained tracing than `debugFeature`'s default (every 2000 steps)
   to find where in the ~339-block graph execution actually diverges —
   likely an aliasing-style hazard analogous to the one found (and fixed)
   in this pass's own isolated-block test, but located elsewhere. No model
   changes without that trace in hand.
2. Once (1) is understood and fixed: re-run the whole-function `&` test and
   confirm `pending[5]` becomes 1 **via Crucible/What4/Z3** (level 3
   evidence) — the concrete (level 2) result already exists, see "Proven
   capabilities & findings."
3. Hook `0x8c10`/`0x7f84` and verify the emitted bytes equal `V01R39` —
   this could reasonably be done concretely via Unicorn *first* (continuing
   past `0x83ec`), independently of (1)-(2), since it doesn't depend on the
   loop/CFG question at all. Closes the AutoPilot milestone once done at
   both evidence levels.
4. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only entry *reachability* is
   solver-verified for these three).
5. **Only after (1)-(3)**: begin Remote (`mando`) harness work per
   [`docs/harness/roadmap.md`](harness/roadmap.md), building on the
   existing static research rather than starting from nothing.

The `0x827e` loop's own internal structure and its callees `0x5274`/`0x5448`
([`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md))
remain correctly documented and are relevant to future `0xF0`/`0xE0`
binary-frame work — just not to steps (1)-(3) above. Fuller backlogs
(protocol open questions, tooling gaps like SVD/MMIO labeling) are tracked
in [`docs/protocol/open-questions.md`](protocol/open-questions.md) and
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
