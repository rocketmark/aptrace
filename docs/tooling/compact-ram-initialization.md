# Compact RAM Zero-Initialization for Crucible/What4 Queries

**Status: implemented and measured.** Follow-up to
[`docs/investigations/trigger-input.md`](../investigations/trigger-input.md)'s
Part 6, which diagnosed (but deliberately did not fix) why that
investigation's narrowed PB05 reachability query produced a 41MB,
267,385-assertion SMT-LIB2 formula despite having only one genuine free
variable: ~73.5% of the assertions (196,615) were the entire RAM region
individually asserted `== 0`, one byte at a time. This note documents the
fix and the measured before/after impact on that exact query.

## Where the per-byte assertions came from

`APTrace.ProtocolHarness.runPacketTransactionTraced` builds its base memory
via `Data.Macaw.Symbolic.Memory.newGlobalMemory`, passing a
`MemoryModelContents` flag that controls how *writable* (non-readonly)
segments get populated into the single SMT array backing all of memory
(`globalMemoryBytes`). Before this change, that flag was `ConcreteMutable`.
Macaw-symbolic's own `populateSegmentChunk`
(`external/macaw/symbolic/src/Data/Macaw/Symbolic/Memory.hs`) handles
`ConcreteMutable` by asserting `globalMemoryBytes[addr] == byte` individually
for every byte in the segment — the same treatment it always gives
*readonly* segments (flash), but now also applied to the entire
0x20000000-0x2002FFFF RAM region (`ramSize = 0x30000`), regardless of
whether a given bounded query ever touches most of it.

Readonly (flash) segments are unaffected by this flag either way — they are
always populated with per-byte assumptions, a deliberate macaw-symbolic
tradeoff (baking large concrete regions directly into the array has crashed
solvers in the past; see `docs/tooling/tool-selection.md`'s own note on
this). **This slice does not touch flash encoding**, per its own scope.

## The fix

`APTrace.ProtocolHarness.runPacketTransactionTraced`
(`src/APTrace/ProtocolHarness.hs`) now:

1. Builds the base memory with `MSM.SymbolicMutable` instead of
   `MSM.ConcreteMutable`. Under `SymbolicMutable`, macaw-symbolic's own
   population code asserts **nothing** about a writable segment — it leaves
   that part of `globalMemoryBytes` totally unconstrained.
2. Immediately reasserts "every writable segment starts at zero" itself, as
   **one SMT constant-array store per segment** rather than one equality
   per byte: `WI.constantArray` builds an all-zero array literal, and
   `CLM.doArrayStore` writes it over the segment's address range in a
   single call — the exact same idiom this module already used (unchanged)
   to zero-fill the small malloc'd Crucible stack.
3. Determines each writable segment's base address and size **by
   inspecting `mem :: MM.Memory 32` itself**
   (`filter (not . Perm.isReadonly . MM.segmentFlags) (MM.memSegments mem)`),
   not from a hardcoded `0x20000000`/`0x30000` pair. This is the same
   `MM.Memory` `APTrace.FirmwareLoader.buildMemory` already built, so it
   stays correct for whatever firmware image and RAM layout a given run
   uses, and doesn't duplicate the address/size constants `app/Main.hs`
   already owns.

Net effect: byte-for-byte the same fact is asserted (every writable segment
starts at zero), at a fraction of the assertion count. Flash and the actual
packet-buffer/register logic are completely unchanged.

## Measured impact: the exact narrowed PB05 -> 0x8f98 query

Same query as `trigger-input.md`'s Part 5/6 ("Query
A": entry `0x9203`, both gate cells concrete, only PB05 free via the opaque
`digitalRead` override, stop at `0x8fa4`), same firmware
(`firmware_autopilot868.bin`), same solver-logging mechanism
(`aptrace trigger`'s `solverLogPath`), before vs. after this change:

| Metric | Before (per-byte RAM) | After (compact RAM) | Change |
|---|---|---|---|
| `.standalone.smt2` size | 41,260,653 bytes (~41.3 MB) | 10,786,066 bytes (~10.8 MB) | **-73.9%** |
| Lines | 802,222 | 212,377 | -73.5% |
| `(assert ...)` | 267,385 | 70,775 | **-73.5%** (~196,610 fewer — matches the diagnosed 196,615 RAM byte-assertions almost exactly) |
| `(define-fun ...)` | 534,810 | 141,585 | -73.5% |
| `(declare-fun ...)` | 2 (`globalMemoryBytes`, `opaque_r0`) | 3 (adds one fresh array for the RAM zero-overlay, constrained by a single `forall`-quantified equality — see below) | +1 |
| Solve time (online Z3, `checkWithAssumptionsAndModel`) | killed after ~9 minutes, **no answer** | **converged in 367.7s (~6.1 min)** | now terminates |
| Solver result | none (killed) | **`unknown`** | still not a reachability answer |

The remaining ~70,775 assertions are (as before) almost entirely flash's own
per-byte population, confirmed by inspecting the file directly: the surviving
assertions' addresses start at `(_ bv16384 32)` = `0x4000`, the flash load
base, not RAM. The RAM region contributes **zero** per-byte assertions now —
confirmed structurally, not just by construction: `grep` for
`(declare-fun ...)` shows exactly one new array (besides `globalMemoryBytes`
and `opaque_r0`), constrained by exactly one `(assert (forall ((a (_ BitVec
32))) ...))` equality whose guard is `0x20000000 <= a < 0x20000000 +
0x30000` — the whole RAM region, in one term, matching `ramBase`/`ramSize`
exactly.

A second query in the same investigation ("Query B": entry `0x91a3`, no
register overrides, stop at `0x91ce`, asking whether the TR1/armed `"T..."`
frame write is reachable) produced a comparably smaller `.standalone.smt2`
(~10.5 MB, same ~74% reduction) but **did not converge within an 18-minute
budget** even with the compact encoding — this investigation's own doc
never captured a solve-time number for Query B before this change (it was
explicitly skipped, "per instruction not to over-invest"), so there is no
prior number to compare against; it is reported here as a new, honestly
negative data point. **The compact-RAM fix does not, by itself, make every
query in this family solver-tractable.**

## Why "unknown" and not SAT/UNSAT

Z3 returning `unknown` rather than timing out or crashing is a real, useful
result in its own right (a bounded, terminating answer instead of an
open-ended hang), but it is **not** a reachability finding — no claim in
`trigger-input.md` changes because of it, and no new
solver-confirmed claim is made here either. The most plausible explanation,
**not independently verified this pass**: `CLM.doArrayStore`'s own encoding
of "overwrite this sub-range of a background array" produces a
`forall`-quantified equality (confirmed directly in the SMT-LIB2 output —
see above), and Z3's quantifier instantiation heuristics for the combined
`useNonlinearArithmetic`/`useSymbolicArrays` configuration this project's
`withZ3Backend` enables unconditionally may simply not be able to fully
resolve a quantified array theory alongside the rest of the query, whereas
the old quantifier-free (but 267K-assertion) encoding was slow but at least
stayed in a decidable fragment for long enough that it was never actually
*proven* undecidable-in-practice — it was killed externally instead, before
Z3 itself gave up. **Not chased further this slice**, consistent with this
project's practice of reporting a precisely-bounded, honestly negative
result rather than guessing at a fix. A concrete follow-up worth trying: a
quantifier-free constant-array encoding (if one exists in this What4/Crucible
version's API) or restricting the compact zero overlay to just the specific
sub-ranges a given bounded CFG can actually reach, rather than the whole RAM
segment.

## Regression check: no behavior change for concrete (non-symbolic) execution

There is no automated Haskell test suite for this harness (`aptrace.cabal`
has no `test-suite` stanza) — the project's own precedent for "regression"
on the Crucible/Haskell side is a direct before/after comparison, not a new
test file (a direct before/after comparison is this project's own
precedent for a Python-side regression too). Performed here: the
already-existing `aptrace protocol` command's whole-function check (`&|` ->
`pending[5]=1`, entering at the real caller `0x8a34`, matching
`protocol-pipeline.md`'s own scenario) was run against both the
committed baseline (`ConcreteMutable`, via `git stash`) and this change
(`SymbolicMutable` + compact overlay), same firmware, same inputs.

**Result: byte-for-byte identical trace up to the point of failure** — both
runs hit the exact same pre-existing, already-documented issue
(`docs/harness/execution-model.md`'s "Known architectural gap": a branch on
a *flash*-derived value doesn't resolve deterministically under plain
Crucible stepping, unrelated to RAM), aborting at the exact same step count
(300,000) and the exact same cycling block addresses (`0x82ac`-`0x82c4`).
Confirmed **not** a regression from this change — it reproduces identically
whether RAM is `ConcreteMutable` or the new compact `SymbolicMutable`+overlay
scheme, because the diverging branch's condition comes from flash, which
this slice left untouched. (The two runs' *outer* behavior differs
cosmetically — the baseline process hard-exits via `Exit.exitFailure`
propagating uncaught, while this change's run catches it via an `X.try`
wrapper and continues to the later `&`/`G`/`!`/`S` checks — but that wrapper
predates this slice, added for the trigger investigation's own `stopAtAddr`
early-stop feature, not introduced here.)

The single-block `&`/`G`/`!`/`S` solver-confirmed checks
(`APTrace.SymbolicRunner.checkBranchModel`) are unaffected by construction —
that module already used `SymbolicMutable` before this change and was not
touched — and were observed to still produce their exact expected values
(`0x26`, `0x47`, `0x21`, `0x53`) after this change.

## Evidence level

Level 1 (static/structural) for the SMT-LIB2 size/assertion-count comparison
and the encoding-correctness check (the single `forall`-guarded equality's
address range matches RAM exactly). Level 2-adjacent (direct before/after
process comparison, not a formal proof) for the regression check. No new
level-3 (solver-confirmed) reachability claim is made anywhere in this note.
