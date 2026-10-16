# Arrow: symbolic-execution

Bounded symbolic questions over Macaw-lifted code, using Crucible
simulation with What4/Z3. It covers four harnesses:
- the production `function_effects` operation, which runs the effects
  harness: raw accesses, calls and return terms, plus solver-derived guard,
  region, uniqueness and return-range facts;
- a single-block branch-reachability runner;
- a whole-function packet and gate harness;
- an experimental `crucible-debug` attachment.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/symbolic-execution/symbolic-execution-design.md

### EARS
- docs/intent/production/symbolic-execution/symbolic-execution-specs.md (prefix `PROD-SYM`; 46 specs: 45 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
- agent/tests/test_agent_v0.py, `function_effects` adapter only, against recorded or fake binary output (no Haskell run):
  - `test_function_effects_tool_rejects_paths_mmio_and_solver_arguments`
  - `test_effects_runner_validates_and_builds_only_bounded_argv`
  - `test_effects_evidence_keeps_raw_and_solver_facts_distinct`
  - `test_computed_control_transfer_marks_effects_bounded`
  - `test_effects_geometry_must_match_census_window`
  - `test_effects_timeout_is_bounded_and_cached`
- Adapter results consumed by other segments' tests: `test_claim_quality.py`, `test_followups.py`, `test_scenario_observation.py`.
- **No test exercises the Haskell harnesses** (`EffectsSpike`, `SymbolicRunner`, `ProtocolHarness`, `DebugHarness`). No framework or case test, test script or test suite references them. The case scenario commands that call `SymbolicRunner` and `ProtocolHarness` (`solve`, `protocol`, `trigger*`) are not tests.

### Code
- src/APTrace/EffectsSpike.hs: `runEffectsSpike`, used by both `function-effects` (production) and `effects-spike` (spike) in `app/Main.hs`
- src/APTrace/SymbolicRunner.hs: `checkBranchModel`, single-block branch reachability with one Z3 query
- src/APTrace/ProtocolHarness.hs: `runPacketTransaction`, `runPacketTransactionTraced`, `runGateReachability`
- src/APTrace/DebugHarness.hs: `runDebug`, an experimental `crucible-debug` prototype
- agent/src/aptrace_agent/function_effects.py: the `function_effects` agent adapter (`FunctionEffectsRunner`)
- Entry points: `app/Main.hs` (`function-effects`, `effects-spike`, `debug`; owned by target-loading). Case module `cases/performing-rigs/src/APTrace/Case/PerformingRigsScenarios.hs` (`solve`, `protocol`, `trigger`, `trigger-crosscheck`).

### Related docs
- docs/harness/execution-model.md, docs/tooling/compact-ram-initialization.md, docs/tooling/tool-selection.md
- docs/aptrace-agent-framework.md (Phase 2 "FunctionSummary" roadmap the spike came from)
- docs/spikes/architecture-evaluation.md §4.4, §8 step 5; docs/spikes/architecture-reconciliation.md §B, §F, §H
- docs/status.md "Available capabilities"

## Architecture

**Purpose:** answer bounded property questions over code paths, such as
which addresses a function can touch, under which guards, and whether a
return value is confined to a range. Results stay distinct from concrete
observations. CLAUDE.md assigns Crucible/What4/Z3 to "bounded symbolic
questions that need constraints or path reasoning", and warns against
using it to approximate concrete replay.

**Key components:**
1. **Effects harness** (`EffectsSpike.runEffectsSpike`):
   - discovers one function with plain Macaw `cfgFromAddrs`;
   - simulates it with Crucible: symbolic argument and input registers, a 4 KiB concrete stack, concrete flash, symbolic RAM and MMIO, opaque AAPCS calls and a step bound;
   - records every read, write and call, plus the return term;
   - runs one Z3 session of push/pop queries for guard status, region membership, address uniqueness and return range;
   - writes `<prefix>.raw.json`, then `<prefix>.enriched.json`.
2. **`function_effects` adapter**:
   - validates the request (a `FUN_` identity and at most 2 `r0`–`r3` specializations);
   - checks the image SHA-256 and the entry against an allow-list;
   - runs the Haskell binary with a 300-second timeout, caching outputs on disk and caching failures negatively;
   - interprets RAW and SOLVER facts separately.
3. **`SymbolicRunner.checkBranchModel`**: one Macaw block. Every register and all memory are symbolic, except caller-seeded pointers and concrete bytes. One query asks whether the PC can equal a target, with exclusions.
4. **`ProtocolHarness`**: whole-function runs with a compact zeroed-RAM overlay and concrete or symbolic packet bytes; optional tracing and SMT-LIB2 artifacts; gate reachability over named symbolic RAM cells. Only case scenario code calls it.
5. **`DebugHarness`**: one block under `crucible-debug` with a canned command script. A prototype.

## Spec Coverage

`[x]` means observed in source only. Tests are split into **adapter-only**
(recorded or fake binary output) and **harness** (executes Haskell). No
harness test exists. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Adapter-only test | Harness test |
|---|---|---|---|---|---|---|
| Harness and model assumptions | PROD-SYM-ASM-001 to 007 | 7 | 0 | 0 | 0 | 0 |
| RAW observations | PROD-SYM-RAW-001 to 006 | 6 | 0 | 0 | 1 | 0 |
| SOLVER conclusions | PROD-SYM-SOL-001 to 007 | 7 | 0 | 0 | 2 | 0 |
| Specialization assumptions | PROD-SYM-SPEC-001 to 003 | 3 | 0 | 0 | 2 | 0 |
| Incompleteness: discovery | PROD-SYM-DISC-001 | 1 | 0 | 0 | 0 | 0 |
| Incompleteness: simulation | PROD-SYM-SIM-001 to 002 | 2 | 0 | 0 | 1 | 0 |
| Incompleteness: process bound | PROD-SYM-PROC-001 | 1 | 0 | 0 | 1 | 0 |
| Incompleteness: solver failure or UNKNOWN | PROD-SYM-SOLX-001 | 1 | 0 | 0 | 0 | 0 |
| Incompleteness: skipped enrichment | PROD-SYM-ENR-001 to 005 | 5 | 0 | 0 | 0 | 0 |
| Grading divergence (observed) | PROD-SYM-GRD-001 | 1 | 0 | 0 | 0 | 0 |
| Identity and caching | PROD-SYM-ID-001 to 006 | 5 | 1 (ID-006) | 0 | 3 | 0 |
| Other harnesses | PROD-SYM-RUN-001 to 002, PH-001 to 003, DBG-001 | 6 | 0 | 0 | 0 | 0 |

**Summary:** 45 of 46 specs are observed in source. 1 is an approved-intent
gap: ID-006, binding results to the executing engine and toolchain. Its
mechanism is left to LLD Open Questions 1–2.

GRD-001 records an observed divergence: raw `status` drives the ledger grade
while adapter `coverage` can be bounded. It cross-references evidence-record
and is not an approved guarantee. ENR-004 records that the adapter shows a
concretely false RAW guard and an unqueried guard with the same label.

10 specs have an adapter-only test; none has a harness test. No `@spec`
annotations exist in code yet.

## Key Findings

1. **Spike code is the production path.**
   - `function-effects` and `effects-spike` both call `runEffectsSpike`. They differ only in constants: production uses the target MMIO window, no argument overrides, a 3,000-step bound and no parametric uniqueness queries; the spike uses a 200,000-step bound and always adds the `arg_r0 == 1` specialization (`app/Main.hs:46-57`).
   - The module calls itself an "EXPERIMENTAL vertical slice", "deliberately NOT the generic FunctionSummary abstraction" (`EffectsSpike.hs:9-14`).
   - Production output still carries `"spike": "aptrace-effects-spike-v1-raw"` and `"aptrace-effects-spike-v2"` (`:394, 633`).
2. **`function_effects` uses unrepaired Macaw discovery.** It calls plain `MD.cfgFromAddrs armCortexMInfo` on the single entry (`EffectsSpike.hs:151-156`), without `MacawExpand`'s normalization repair. `tool-selection.md` already records that it "fails early on functions it cannot classify (for example, an early `cbz`)". `status.md` does not list this limitation.
3. **No per-query solver timeout.**
   - None of the four harnesses sets one: `withZ3Backend` only extends the Z3 options (`EffectsSpike.hs:728-741`; same in `SymbolicRunner`, `ProtocolHarness`).
   - The only bounds on the production path are the adapter's 300-second subprocess timeout and the 3,000-step simulation bound.
   - Z3 `UNKNOWN` is kept three-valued, never read as SAT or UNSAT (`EffectsSpike.hs:429-430`).
4. **The ledger identity does not cover the analysis code.**
   - The ledger's declared inputs for `function_effects` are `census_db` and `svd` only (`agent/src/aptrace_agent/ledger/operations.py:35`). The Haskell binary and `EffectsSpike.hs` are not identity inputs.
   - The adapter's cache key is the first 16 hex characters of the firmware SHA-256, the entry and the specializations (`function_effects.py:166`). It excludes the binary, the step bound and the MMIO window.
   - Failures and timeouts are cached negatively, with no expiry (`:173-180, 202, 211`).
   - Provenance records an engine description string, the firmware SHA-256, absolute artifact paths, a `cached` flag and the MMIO window (`:217-226`). It records no Macaw, Crucible, What4 or Z3 versions and no binary hash.
5. **The harness model is fixed to Cortex-M, AAPCS and AArch32.**
   - Arguments: `r0`–`r3` become `arg_rN`, and `r4`–`r12`/`lr` become `in_*`.
   - Calls: opaque calls clobber `r0`–`r3`/`r12` and are assumed to have no memory effects.
   - Return: the value is read from `r0`, and the Thumb bit is cleared from PCs (`EffectsSpike.hs:211-212, 262-264, 294-299, 335`).
   - Types: every module uses AArch32 types.
   - The adapter allows specialization of `r0`–`r3` only (`function_effects.py:20`).
   - The raw document states its four harness assumptions (`EffectsSpike.hs:414-419`), and the adapter passes them through as `harness_assumptions`.
6. **RAW and SOLVER facts are kept separate.**
   - The adapter's docstring says RAW facts "hold for all inputs under the harness assumptions listed", and that SOLVER facts are proved over raw terms and "are not concrete runtime values" (`function_effects.py:50-58`).
   - Specialized facts carry their `arg_rN == V` assumption (`:300-317`).
   - Coverage is `bounded` when the raw status is not `complete*`, or when a computed transfer was modeled as an opaque call (`:322-337`).
7. **Solver enrichment is capped.** It covers the first access at each (kind, pc) site, at most 24 sites (`EffectsSpike.hs:579-582`). The raw output keeps every access, and accesses that were not enriched show guard `unqueried` in the adapter. Neither the raw nor the enriched document records how many sites were left out.
8. **When enrichment is skipped, the adapter re-runs every time.** If the Z3 smoke test fails, or the run is raw-only, `<prefix>.enriched.json` is not written (`EffectsSpike.hs:465-470`). The adapter treats a cache as present only when `enriched.json` exists (`function_effects.py:171`). A raw-only outcome is therefore re-run on every request, and its result carries no solver facts. *(Read from code.)*
9. **`ProtocolHarness` can terminate the whole process.** `debugFeature` calls `Exit.exitFailure` after 300,000 steps (`ProtocolHarness.hs:817-820`). A library function ends the whole process instead of returning a failure state.
10. **The harnesses differ in their memory models.**
    - `ProtocolHarness`'s packet runs use a compact zero overlay on RAM (`:13-40, 298-332`).
    - `SymbolicRunner` and `ProtocolHarness.runGateReachability` use plain `SymbolicMutable`, so RAM is unconstrained.
    - `EffectsSpike` keeps RAM and MMIO unconstrained symbolic.
    - `ProtocolHarness`'s own module comment explains why unconstrained RAM can let the solver "solve" a query by choosing a favorable initial value (`:30-37`). `compact-ram-initialization.md` states the general rule.
11. **Setup code is copied four times.** `withZ3Backend`, `resolvedPointer`/`globalPointer`, `concreteZeroVar` and `freshBV32` are duplicated across `SymbolicRunner`, `DebugHarness`, `EffectsSpike` and `ProtocolHarness`. The duplication is partly documented: `SymbolicRunner.hs:72-75` and `DebugHarness`'s "mirrors" comments.
12. **Some harnesses are reachable only through case commands.**
    - `SymbolicRunner.checkBranchModel` and `ProtocolHarness` are called only from case scenario code (`PerformingRigsScenarios.hs`: `solve`, `protocol`, `trigger*`).
    - `status.md` lists "Translate bounded Macaw regions into Crucible and ask What4/Z3 reachability and input-model questions" as a framework capability with no such qualifier.
    - `DebugHarness` is reachable only through the `debug` CLI command.
13. **Case data and missing docs.**
    - `DebugHarness` hardcodes `r3 = 0x26` (`:161`), although its comment says the module "carries no knowledge of any specific target" (`:96-99`).
    - It cites the nonexistent `docs/tooling/galois-premeeting.md` (`:16, 131, 189`).
    - `ProtocolHarness` comments name "the AutoPilot dispatcher", AutoPilot RAM geometry, "this investigation's own cells" and case investigation docs (`:17, 122-124, 321, 618-624`).
    - The production cache directory is case research state (`structural_wiring.py:112`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* The production cache under the case
research directory is written by design (`structural_wiring.py:112`), and no
test writes canonical state.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **The ledger identity and cache key omit the analysis code.** A changed Haskell binary or harness leaves the operation identity and cache key unchanged, and cached results, including negatively cached failures, can be reused. Continuity reuse is gated by the wrapper `ANALYSIS_VERSION` (1) (investigation/continuity). (Finding 4)
2. **No engine versions in provenance.** Macaw, Crucible, What4 and Z3 versions are not recorded, and there is no binary hash. (Finding 4)
3. **Unrepaired discovery.** Production `function_effects` runs on unrepaired discovery, so some functions are covered only partly or fail early. The cases that `tool-selection.md` documents are not reflected in `status.md`. (Finding 2)
4. **Unrecorded enrichment cap.** The number of sites left out of enrichment is not recorded. (Finding 7)
5. **Raw-only outcomes look solver-less and are never cached.** A failed smoke test leaves a result with no solver facts, re-run every time. (Finding 8)
6. **Unconstrained RAM in the gate and effects harnesses.** `ProtocolHarness`'s own comment names this soundness concern; whether it applies to the effects and gate questions is not established. (Finding 10)

### Architectural coupling
7. **Cortex-M, AAPCS and AArch32 hardcoded in harnesses and adapter.** (Finding 5)
8. **Case-only entry points for two harnesses.** `SymbolicRunner` and `ProtocolHarness` are reachable only through case scenario commands. (Finding 12)
9. **Case data in framework modules.** This includes `DebugHarness`'s `r3 = 0x26`, the case comments in `ProtocolHarness`, and the case cache directory. (Finding 13)

### Semantic inconsistencies
10. **Spike identifiers in production.** The production output carries spike identifiers, and the "EXPERIMENTAL" module docstring describes production code. (Finding 1)
11. **`status.md` overstates two capabilities.** It presents reachability questions as a framework capability, and omits `function_effects`'s unrepaired-discovery limitation. (Findings 2, 12)
12. **`DebugHarness` contradicts its "no target knowledge" comment.** (Finding 13)

### Maintenance debt
13. **Z3 and memory setup copied four times.** (Finding 11)
14. **A library function that exits the process** (`ProtocolHarness.debugFeature`). (Finding 9)
15. **Missing doc reference.** `docs/tooling/galois-premeeting.md` does not exist. (Finding 13)
16. **No tests for any Haskell harness.** (Tests)
