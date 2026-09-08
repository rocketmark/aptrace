# Tool Selection

APTrace is a workbench: it orchestrates specialist tools rather than
reimplementing what they already do well. This document is the durable
reference for which tool to reach for, why, and what evidence each one
actually gives you. [`CLAUDE.md`](../../CLAUDE.md) has the short mandatory
version of the same rules; this is the reasoning behind them.

## The four backends and APTrace itself

| Tool | Role | Invoked via |
|---|---|---|
| **Ghidra** | Static RE: decompilation, cross-references, structure/table recovery, naming MMIO registers and globals | `tools/ghidra/analyze_firmware.sh` |
| **Unicorn** | Concrete Cortex-M/Thumb execution and state capture | `tools/unicorn/run_concrete.py` |
| **Macaw** | Independent machine-code CFG discovery and ARM/Thumb lifting | the `aptrace` CLI (`APTrace.FirmwareLoader`, `APTrace.VectorTable`) |
| **Crucible + What4 + Z3** | Targeted symbolic reachability and input solving | `APTrace.SymbolicRunner`, `APTrace.ProtocolHarness` |
| **APTrace** | Orchestration: evidence model, scenarios, traces, snapshots, (eventually) UI | this repo |

## Decision guidance

Ask what kind of question you actually have, in this order:

1. **"What is this code? What does it reference? What's this table/string/
   global?"** → **Ghidra.** This is structure recovery — decompiler output,
   cross-references, data typing. Don't try to answer this by staring at
   Macaw's pretty-printed IR or by writing a Crucible query; Ghidra's
   decompiler and xref database exist precisely for this and are far
   cheaper to query than either.

2. **"What does this code concretely do, starting from this known state?"**
   → **Unicorn.** If you can name a concrete entry point and concrete
   register/memory values, just run it. This is orders of magnitude cheaper
   than Crucible for the same question, because Crucible pays the cost of
   symbolic evaluation (path conditions, SMT encoding) whether or not
   anything is actually symbolic. **Do not use Crucible to approximate
   ordinary concrete execution when Unicorn (or Ghidra's emulator, if ever
   needed) can establish the same context/state more directly** — this is
   the single most important anti-pattern this document exists to name.

3. **"Do I trust Macaw's control-flow recovery here?"** → **Macaw itself,
   cross-checked against Ghidra.** Macaw's discovery is the project's
   ground-truth CFG source for the symbolic side (it's what Crucible
   actually executes), but it is not infallible — see "Tool disagreements"
   below for a concrete case where it produced an architecturally
   impossible result.

4. **"What input reaches this address / makes this condition true?"** →
   **Crucible + What4 + Z3**, and only once you already know *which* code
   region and *which* question, from steps 1-3. Symbolic execution is
   precise but expensive; it is the right tool for "solve for X," not for
   "find out what's here."

### Worked example from this project

The `&` command-byte check (flash `0x888c`) has now been established at
three different evidence levels, and the progression follows the order
above:

1. **Static (Ghidra / manual read)**: the instruction at `0x888c` is
   `cmp r3, #0x26`, branching to `0x8890` on equality.
2. **Concrete (Unicorn)**: seeding `r3 = 0x26` and running from `0x888c`
   concretely lands on `0x8890` after 3 instructions; seeding any other
   value lands on the fallthrough `0x889e`. See
   [`unicorn-backend.md`](unicorn-backend.md) for the exact commands.
3. **Symbolic (Crucible/What4/Z3)**: leaving `r3` symbolic and asking "is
   `0x8890` reachable" gets Z3 to *derive* `0x26` as the unique witness,
   rather than confirm a value already chosen — see
   [`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md).

All three agree. That agreement is itself the point: a static read alone is
a claim; concrete execution is a demonstration for one input; the solver
result is a proof over *all* inputs. Use the cheapest tool that gives you
the evidence level the question actually needs — don't reach for Z3 to
confirm something a two-line Unicorn run already settles, and don't stop at
a static read when the question is really "for all inputs."

## Evidence levels (weakest to strongest)

When recording a finding in `docs/`, say which of these it is:

1. **Static-only** — read from a disassembly/decompiler listing (Ghidra or
   Macaw's pretty-printer) with no execution. Cheap, but only as good as
   the reader's tracing and the decoder's correctness.
2. **Concretely executed** — actually run (Unicorn), for one specific
   concrete input/state. Proves "this happens for this input," not "only
   for this input" or "for all inputs."
3. **Solver-confirmed** — a Crucible/What4/Z3 query where the solver
   derived the value(s), and ideally both branch directions were checked.
   Proves a property over the full symbolic input space *of that specific
   query* (mind the soundness caveats in
   [`docs/harness/execution-model.md`](../harness/execution-model.md) about
   what's actually left symbolic).

`docs/project-status.md` and the investigation docs should make clear which
level a claim sits at — "confirmed" without qualification should mean level
3, not level 1.

## Tool disagreements: investigate, don't default

**Tool disagreements are signal.** When two backends disagree about the
same code, that is exactly the situation this multi-tool setup exists to
catch — resolve it before trusting either conclusion. Concrete case from
this project:

> Macaw lifted the region at flash `0x801c` as **ARM (A32) mode** code
> (`BL_i_A1`, `BX_A1`, `PSTATE_T => 0`). This is architecturally impossible
> on ATSAMD51 (Cortex-M4F) — M-profile Cortex-M cores have no ARM execution
> state at all; they are Thumb-only. See
> [`docs/investigations/trigger-input.md`](../investigations/trigger-input.md).

Ghidra's `ARM:LE:32:Cortex` language (`ARMCortex.pspec`) sets the `TMode`
context register to `1` (Thumb) **for the entire address space by
construction** — it is architecturally incapable of decoding A32 for this
target, matching real hardware. Running Ghidra against `0x801c` (seeded via
`tools/ghidra/analyze_firmware.sh`'s extra-seed-address argument) produced
a completely ordinary, well-formed Thumb function: a flag check, a
wraparound-safe elapsed-time computation (`cmp`/`it lt`/`add.lt #0x64`), and
two more calls — called from eight real, cross-referenced sites including
the same `0x8a34` caller Macaw found independently. **This is strong
evidence the A32 lift is a genuine Macaw/dismantle decode limitation for
this address, not dead/unreachable code** — updated in
`docs/investigations/trigger-input.md` and
`docs/protocol/open-questions.md`.

**The rule this generalizes to**: never trust Macaw's A32/ARM-mode
interpretation of anything on this Cortex-M4F target without cross-checking
it — the target cannot execute A32, so any A32 lift is by definition either
a Macaw bug for that address or a sign discovery was seeded wrong.
Ghidra's Cortex-M language, being Thumb-only by construction, is the
standard cross-check; a second opinion from an independent decoder is the
whole reason to keep more than one tool in the workbench.

## Anti-patterns

- **Using Crucible for concrete replay.** If nothing in the query is
  actually symbolic, you're paying SMT-solver overhead for a question
  Unicorn answers in milliseconds. (This project's own history has an
  example of *not* following this rule: `APTrace.ProtocolHarness`'s
  whole-function replay was, in effect, trying to concretely replay a
  packet transaction through Crucible — see
  [`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)
  for how that turned into a memory-side-effect modeling gap that a
  concrete Unicorn run would sidestep entirely.)
- **Reimplementing a mature tool's job.** Don't hand-write a disassembler,
  an xref database, or a peripheral register map when Ghidra/an SVD already
  has it. If a needed capability seems missing, the next section is where
  to look before writing new code.
- **Trusting a single tool's static read as if it were solver-confirmed.**
  See "Evidence levels" above — say which level a claim is at.
- **Silently working around a tool disagreement instead of recording it.**
  If Ghidra and Macaw disagree, that goes in the docs (with both readings)
  even if you don't have time to fully resolve it — see "Tool
  disagreements" above.

## SVD / MMIO labeling: mechanism identified, not yet wired up

**Goal**: label MMIO registers by real peripheral/field name (instead of
raw addresses like `0x40002000`) in both Ghidra and any future
Unicorn/Crucible MMIO modeling.

**A maintained mechanism exists and was confirmed reachable in this pass**:

- [`cmsis-svd/cmsis-svd-data`](https://github.com/cmsis-svd/cmsis-svd-data)
  (the community-maintained successor to `posborne/cmsis-svd-data`) ships
  real SVD files for the exact ATSAMD51 family under `data/Atmel/`:
  `ATSAMD51{G18A,G19A,J18A,J19A,J20A,N19A,N20A,P19A,P20A}.svd`.
- [`antoniovazquezblanco/GhidraSVD`](https://github.com/antoniovazquezblanco/GhidraSVD)
  is an actively maintained (releases as recent as 2026-08) Ghidra
  extension that loads an SVD file and labels/types the corresponding
  peripheral registers directly in a Ghidra program.

**Why this isn't wired up yet**: applying a specific SVD file requires
knowing the *exact* ATSAMD51 part number on the real board (G18A vs. J19A
vs. N20A, etc. — they differ in RAM/flash size and peripheral instance
counts). `docs/project-status.md` and `docs/firmware/firmware-layout.md`
currently confirm the family (ATSAMD51, Cortex-M4F) but not the exact part
number. Guessing wrong would silently mislabel MMIO registers, which is
worse than leaving them unlabeled — that's a real risk with SVD-based
labeling in general, not specific to this tool.

**Concrete next step** (not done in this pass): confirm the exact part
number (likely derivable from the Adafruit/Arduino board package identified
in `docs/firmware/firmware-layout.md`, or from RAM size — `0x30000` = 192KB
matches the *N19A/N20A/P19A/P20A* variants' 192KB SKUs, not the smaller
G/J variants — this is a real lead, just not chased down yet), install
GhidraSVD, and re-run `tools/ghidra/analyze_firmware.sh` with the matching
SVD applied.

## Reproducing the environment

See [`docs/toolchain.md`](../toolchain.md) for exact install/build steps for
all four backends, and run `tools/doctor.sh` to verify they're all usable.
