# Tool Selection

APTrace is a workbench: it orchestrates specialist tools rather than
reimplementing what they already do well. This document is the durable
reference for which tool to reach for, why, and what evidence each one
actually gives you. [`CLAUDE.md`](../../CLAUDE.md) has the short mandatory
version of the same rules; this is the reasoning behind them.

## The four backends and APTrace itself

| Tool | Role | Invoked via |
|---|---|---|
| **Ghidra** | Static RE: decompilation, cross-references, structure/table recovery, naming MMIO registers and globals | `tools/ghidra/aptrace_ghidra.py` (persistent per-firmware project cache; `analyze_firmware.sh` remains for a genuine one-shot query) |
| **Unicorn** | Concrete Cortex-M/Thumb execution and state capture | `tools/unicorn/run_concrete.py` (CLI) / `tools/unicorn/concrete.py`'s `ConcreteMachine` (reusable Python library — see `virtual_link.py`) |
| **Macaw** | Independent machine-code CFG discovery and ARM/Thumb lifting | the `aptrace` CLI (`APTrace.FirmwareLoader`, `APTrace.VectorTable`) |
| **Crucible + What4 + Z3** | Targeted symbolic reachability and input solving | `APTrace.SymbolicRunner`, `APTrace.ProtocolHarness` |
| **APTrace** | Orchestration: evidence model, scenarios, traces, snapshots, (eventually) UI | this repo |
| `crucible-debug` (experimental) | Interactive stepping/breakpoints/register inspection over a real Crucible run | `aptrace debug FIRMWARE.bin ENTRY_ADDR_HEX` — see `APTrace.DebugHarness` |
| GREASE (experimental, external) | Under-constrained symbolic execution as a cheap first-pass sweep, not a replacement for the targeted queries above | not vendored in this repo — see [`galois-premeeting.md`](galois-premeeting.md) |

The last two rows are additions at an explicitly **experimental** tier —
see [`galois-premeeting.md`](galois-premeeting.md) for what was tried, what
worked, and open questions for Galois. They do not change the hierarchy
below: Ghidra -> Unicorn -> Macaw/Crucible/What4 remains the load-bearing
path for any actual finding recorded in this project's docs.

## The execution order

For any firmware-analysis question, work through these in order — don't
skip ahead to a heavier tool because it feels more thorough:

```
Ghidra (static understanding)
    -> Unicorn (concrete observation)
        -> Crucible/What4/Z3 (symbolic proof)
```

1. **Ghidra first**: read the code, find the structure, name the
   addresses/constants involved. Cheap, and every later step depends on
   knowing *what* to point the next tool at.
2. **Unicorn second**: once you know the region and a concrete
   input/state, actually run it. This is where "what does this code do"
   gets answered for real, and it's the tier that catches harness-vs-
   firmware confusion (see "Harness rules" in `CLAUDE.md`) — if Crucible
   says one thing and Unicorn says another, Unicorn is presumed right
   until proven otherwise.
3. **Crucible/What4/Z3 last**: only once the question is genuinely "what
   input satisfies this," not "what does this input do" (already answered
   by step 2) or "what is this code" (already answered by step 1).

Macaw sits underneath all three, not as a fourth step: it's what lifts the
binary into the IR Crucible executes, and its own CFG/discovery output is
itself something to sanity-check with Ghidra (see "When Macaw is
authoritative vs. a cross-check" below), not to trust blindly at any tier.

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
   cross-checked against Ghidra.** Macaw's discovery is the CFG/IR
   consumed by APTrace's symbolic side (it's what Crucible actually
   executes), but it is not infallible — see "Tool disagreements" below
   for a concrete case where it produced an architecturally impossible
   result, and [`macaw-analysis.md`](macaw-analysis.md) for a second,
   subtler case (Macaw's own `ParsedCall` terminator routing several
   non-call Thumb shapes through the same constructor).

   **When Macaw is authoritative vs. when it's only a cross-check**: Macaw
   is the right, load-bearing tool for *lifting* (turning Thumb-2 bytes
   into Crucible-executable IR) and for *this project's own CFG*, since
   that's literally what gets executed downstream — there's no
   alternative for that job. It is **not** authoritative for claims about
   the binary's structure independent of that role: what counts as "one
   function," where a block boundary falls, how regions merge, and how a
   terminator is classified are products of Macaw's own discovery
   heuristics (see "Treat discovered function/CFG boundaries as
   heuristic, not ground truth" in `CLAUDE.md`) — Macaw remains
   load-bearing for the IR Crucible executes, but its discovered function
   boundaries, block partitioning, and terminator classification are not
   ground truth. Its ARM/Thumb decode itself has a known limitation (the
   `0x801c` A32 case below, now prevented in APTrace's own normal
   discovery path — see [`macaw-analysis.md`](macaw-analysis.md)'s
   "Cortex-M safety"). Use Ghidra to cross-check any of those *structural*
   claims before relying on them; use Macaw's own output directly only
   for what Crucible will actually execute.

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
   [`docs/investigations/protocol-harness-results.md`](../investigations/protocol-harness-results.md).

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

**Current status**: raw/stock Macaw (plain `ARM.arm_linux_info`, an
unnormalized entry address) still demonstrates this exact A32 failure —
that finding is preserved above as evidence that tool disagreements are
real and worth cross-checking, not smoothed over. APTrace's own normal
Cortex-M discovery path no longer hits it: every entry point is normalized
through `macawCortexMEntry` first, and discovery runs under
`armCortexMInfo` (which additionally forces `PSTATE_T=True` for two other
Thumb-state-loss cases Macaw's generic AArch32 backend has been observed
producing) — see [`macaw-analysis.md`](macaw-analysis.md)'s "Cortex-M
safety" for both fixes. The lesson this case established remains: analyzer
output must be cross-checked, not trusted by default. Macaw remains
load-bearing for the IR Crucible executes, but its discovered function
boundaries, block partitioning, and terminator classification are not
ground truth — see [`macaw-analysis.md`](macaw-analysis.md) for a second,
independently-found case of exactly that (Macaw's `ParsedCall` terminator
routing several non-call Thumb shapes through the same constructor).

## Known limitation: readonly flash and plain Crucible execution

**Solver assumptions are not the same as concrete runtime literals** (see
`CLAUDE.md`'s "Harness rules"). A value read from **readonly flash**
(e.g. a literal-pool pointer load) is populated into Crucible's memory
model via *solver assumptions*, not folded array literals —
`Data.Macaw.Symbolic.Memory.populateSegmentChunk` does this for every
readonly segment regardless of `ConcreteMutable`/`SymbolicMutable`, a
deliberate tradeoff (baking large concrete regions directly into the
array has crashed solvers in the past).

That's sound for a **solver query** — `checkBranchModel` and a
whole-function run's final reachability check both incorporate the
assumption set correctly. It is **not** sound for **plain Crucible
execution stepping through an ordinary branch** — there is no solver in
the loop to resolve an assumption-backed value into a concrete `Pred`, so
Crucible falls back to picking a side, which is not necessarily the one
the real concrete value implies. Confirmed concretely in this project: a
branch on a literal-pool-derived byte took the wrong successor during
whole-function execution despite the underlying byte being genuinely
concrete — see
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
for the full trace.

**Practical implication**: any whole-function Crucible target whose
control flow depends on a value read from flash (not just RAM) should be
expected to hit this until it's specifically fixed. It is a documented
gap, not a silent one — do not attempt a general fix (baking all flash
into literals, or redesigning `populateSegmentChunk`) without a real
symbolic use case that needs it; the narrow fix (baking the *specific*
literal-pool words a given target actually reads) is cheaper and
sufficient for now.

## Anti-patterns

- **Using Crucible for concrete replay.** If nothing in the query is
  actually symbolic, you're paying SMT-solver overhead for a question
  Unicorn answers in milliseconds. (This project's own history has an
  example of *not* following this rule: `APTrace.ProtocolHarness`'s
  whole-function replay was, in effect, trying to concretely replay a
  packet transaction through Crucible — see
  [`docs/investigations/protocol-harness-results.md`](../investigations/protocol-harness-results.md)
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

## SVD / MMIO labeling: standalone resolver wired up; GhidraSVD still not installed

**Goal**: label MMIO registers by real peripheral/field name (instead of
raw addresses like `0x40002000`) in Ghidra output, Unicorn traces, and any
future Crucible MMIO modeling.

**The part number is now confirmed**: `docs/hardware/hardware-reference.md`
identifies the AutoPilot's MCU directly (physical board inspection) as
**ATSAMD51J19A-AU** (Remote: -AF — same silicon, different
package/temperature grade). This confirmation did *not* come from the RAM-
size inference this section previously suggested ("`0x30000` = 192KB
matches the N19A/N20A/P19A/P20A variants... not the smaller G/J variants")
— that inference was wrong on its own terms: the confirmed J19A part does
have 192KB SRAM. Corrected here rather than left standing now that the
real part is known and this is directly load-bearing.

**Wired up in this pass**: the real SVD file
([`cmsis-svd/cmsis-svd-data`](https://github.com/cmsis-svd/cmsis-svd-data)'s
`data/Atmel/ATSAMD51J19A.svd`) is vendored at
[`tools/svd/ATSAMD51J19A.svd`](../../tools/svd/ATSAMD51J19A.svd), with a
small standalone resolver,
[`tools/svd/resolve_mmio.py`](../../tools/svd/resolve_mmio.py), that
parses it (stdlib XML, not a hand-rolled SVD format) and maps a raw
address to `PERIPHERAL.REGISTER` (handling repeated/union structures like
`PORT.GROUP0/1` and `TC.COUNT8/16/32`). `tools/unicorn/run_concrete.py
--log-mmio` records every MMIO access from a concrete run so it can be fed
through the same resolver. See
[`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md)
for a real worked example (startup peripheral survey, a first concretely-
named pin-mux fact, and an honest negative result for the outbound TX
path).

**Not done in this pass, and not required for anything above**: installing
[`antoniovazquezblanco/GhidraSVD`](https://github.com/antoniovazquezblanco/GhidraSVD)
so peripheral names appear directly inside Ghidra's own
listing/decompiler, rather than needing a separate resolver lookup. This
remains a reasonable future upgrade if the standalone resolver stops being
convenient enough (e.g. once heavy manual Ghidra browsing of
peripheral-heavy functions becomes routine) — not chased down here per
this project's "smallest useful slice" discipline.

## Standard-library/toolchain provenance: source-backed classification

**Goal**: separate high-confidence standard/platform/library code
(Reset_Handler's `.data`/`.bss` copy, SysTick/millis, SERCOM SWRST
self-clear, `digitalWrite`-shaped GPIO writes, memcpy/memset-shaped
loops...) from AutoPilot-specific application logic, so RE effort
focuses on the custom callers instead of repeatedly re-deriving known
infrastructure.

**Method, established in
[`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md)**:
identify the *exact* evidenced toolchain version first (this firmware
embeds its own build-path strings naming Adafruit `ArduinoCore-samd`
git tag `1.7.11` — see `docs/firmware/firmware-layout.md` — no need to
guess), fetch the real source for that exact tag from its public
repository, and compare structurally (control-flow shape, register/
field-access order) against functions this project has already
disassembled or decompiled. A `CONFIRMED_*` classification requires a
real structural match against fetched source; role-only or
cluster-level matches are labeled `LIKELY_*`, and anything without a
plausible library candidate is left `UNKNOWN` rather than guessed.
Recorded in a reusable CSV
([`research/provenance/function_classification.csv`](../../research/provenance/function_classification.csv))
and, optionally, applied into Ghidra's own database (renames + a
one-line provenance comment) via
[`tools/ghidra/scripts/APTraceApplyProvenance.java`](../../tools/ghidra/scripts/APTraceApplyProvenance.java),
reading a minimal companion TSV
([`research/provenance/ghidra_labels.tsv`](../../research/provenance/ghidra_labels.tsv)).
Purely cosmetic to Ghidra's database — no firmware behavior change, and
standard code is never removed from analysis or execution, only
labeled.

**Not a general framework**: this is a bounded, source-cited annotation
layer over functions this project actually encountered, not an attempt
to classify every function in every image, and not a heuristic
similarity-matcher (e.g. no FLIRT-style signature database was built or
used — every match here cites a specific fetched file and function).

## Reproducing the environment

See [`docs/toolchain.md`](../toolchain.md) for exact install/build steps for
all four backends, and run `tools/doctor.sh` to verify they're all usable.
