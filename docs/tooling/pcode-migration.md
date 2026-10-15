# Retiring Capstone Dataflow: P-code Migration Plan

**Status:** the plan only. Nothing listed here has been migrated. The first
p-code operation, [`pcode-forward-use.md`](pcode-forward-use.md), is the
foundation the plan builds on.

**Goal:** stop owning instruction semantics in Python. Python keeps the
APTrace policy layer: orchestration, shape and closing rules, evidence and
interpretation. Instruction-level and intraprocedural dataflow move onto
Ghidra p-code.

Fewer lines is not the measure of progress. A migration counts only when the
new path:

- reproduces the old results, or explains every difference;
- keeps the evidence schema and provenance;
- never turns an incomplete analysis into a negative.

## Rules for every migration step

1. **Side by side first.** The p-code version is a new analysis version and
   a new ledger operation identity. Historical records keep their identity
   and are never rewritten. The old path keeps running until the deletion
   condition holds.
2. **Deterministic comparison.** Both paths run over the same site corpus.
   Every disagreement is recorded in a comparison artifact and given one of
   these classes:
   - p-code more precise;
   - Python more precise;
   - scope or assumption difference;
   - one side incomplete;
   - correctness defect (state whose);
   - undetermined.

   Neither side is preferred by default.
3. **No ISA code in the p-code layer.** A step that needs an ISA-specific
   branch in the walker has found a design problem. Report it; do not patch
   around it. The static ISA-token check in
   [`test_pcode_forward_use.py`](../../tools/ghidra/test_pcode_forward_use.py)
   applies to every walker.
4. **Shared lineage is not corroboration.** Both paths read Ghidra's
   function and block boundaries. Agreement between them is a repeatability
   result for the semantics layer. It is not independent evidence (see
   [`../cross-engine-verification.md`](../cross-engine-verification.md)).
   Macaw stays the independent engine.
5. **Freeze.** No new Capstone-operand semantics are added to
   `tools/census/` while a module is scheduled here. Bug fixes are allowed.

## Inventory

The counts are lines, and ISA-specific references (`ARM_INS_/OP_/REG_/CC_`,
Capstone Thumb mode, mnemonic literals), at the time of writing.

### Migrate

| Module | Lines / ISA refs | Purpose and consumers | P-code replacement | Parity corpus | Deletion condition |
|---|---|---|---|---|---|
| `indirect_target.py`: `_reaching`, `_definition`, `_stack_argument`, the block-decode helpers | 703 / 32 | Backward reaching definitions of a branch register. Consumed by `callback_provenance.py`, the `indirect_call_target` agent operation and case dispatch investigations. | Backward p-code reaching definitions in the walker library. Stack-argument slots come from the cspec prototype model. Loads keep a `[base + disp (+ index << shift)]` record decomposed from p-code. | Every census register-indirect site with saved v2 output, plus fixture controls (Thumb and RV32) for joins, IT predication, `ldrd`, stack arguments and jump-table predecessors. | v3 matches v2 on every site, or each difference is classified and accepted, and one release runs both. |
| `callback_provenance.py`: `_next_use`, `caller_value` argument derivation | 672 / 14 | One-hop caller values. `_next_use` is the Capstone "what happens next" check on address-taken loads. | `_next_use` → `value_forward_use`. `caller_value` → the reaching-definitions walker at the call site. The closing rule (CLOSED/OPEN) stays in Python. | The recorded callback-provenance site set. | It runs on v3 reaching definitions plus `value_forward_use`, with recorded agreement. |
| `fnptr_resolve.py`: `trace_reg`, `_store_value`, `slot_writers` | 416 / 11 | RAM function-pointer slot recovery. `trace_reg` is a single-predecessor register trace that v3 reaching definitions subsume. | Reaching definitions plus p-code `STORE` address and value decomposition. `canonical_code_pointer` → Ghidra's normalized code address plus an APTrace validity check. | The census `function_pointers` and `indirect_edge_candidates` rows. | Slot and writer sets are equal on every case image. |
| `interproc_writes.py` | 168 / 2 | One-hop "callee writes through an argument". | Forward use of the incoming argument within the callee (`value_forward_use` with the entry's argument storage as origin), plus `STORE` decomposition. | Its existing tests and census rows. | Equal writer sets. |
| `indexed_writes.py` | 488 / 18 | Computed and indexed RAM stores that Ghidra's reference manager does not fold. It also hosts `_decode_block` and the register-resolution helpers other modules import. | P-code `STORE` address expressions plus constant propagation of the base. **Last** in order: the shared helpers have to go before their importers can drop them. | Census `memory_accesses` rows from this module. | No importer remains, and the rows are equal. |

### Retain (APTrace policy, orchestration or independence)

| Module | Why it stays |
|---|---|
| Shape classification in `indirect_target.py` (`_pattern`, vtable and object-table candidates, `vptr_installations`) | APTrace's interpretation of definitions. It consumes the def records; it does not produce them. |
| The closing rule and target-set policy in `callback_provenance.py`; `slot_dispatch.py` as a policy | These are APTrace evidence policies. `slot_dispatch`'s Thumb sweep is a pattern-matcher, so it is also deferred (below). |
| `capstone_sweep.py` | It exists to be **independent** of Ghidra's decoder, as a cross-check. Replacing it with Ghidra would remove the check. Keep it, re-moded per target. |
| `macaw_compare.py`, `reachability.py`, `components.py`, `reduce.py`, `db.py`, `build.py` | Census schema, reduction and comparison. They hold no instruction semantics. |

### Retire after the migrations above

- The duplicated AAPCS sets (`ARG_REGS`, `CALL_CLOBBERED`) in several modules.
  The cspec replaces them.
- Thumb-bit handling scattered across modules. It becomes one target
  pointer-tagging rule, supplied by the language through Ghidra.
- `indirect_resolve.decode_instruction` and the `_md()` Capstone handles in
  migrated modules.

### Case-localize (framework modules carrying Performing Rigs identity)

- `aptrace_census.py`, `build.py`, `reduce.py` and `dynamic_ingest.py`
  insert `cases/performing-rigs/config` or `cases/performing-rigs/scripts`
  into `sys.path`.
- `indirect_resolve.py` does the same at line ~189.
- `fingerprint.py` documents the case's image families as its ground truth.
- `tools/ghidra/aptrace_ghidra.py` imports `FIRMWARE_REGISTRY` and geometry
  from the case at import time.

These are the seams recorded in [`../case-boundary.md`](../case-boundary.md)
and the architecture evaluation §2. The p-code operation adds none: its
driver takes the target explicitly, and the case wiring lives in the
agent's application wiring. The fix is the target descriptor (architecture
evaluation §8 step 0). It is a separate cleanup.

### Defer (no evidence yet for a replacement)

| Module | Why deferred |
|---|---|
| `slot_dispatch.py` | A whole-image halfword sweep, deliberately independent of function boundaries. P-code needs decoded instructions, so a sweep has no direct p-code equivalent. Revisit with a "candidate decode" mode. |
| `fingerprint.py`, `reference_normalize.py` | Instruction-normalized hashing for library matching. The normalization is ISA-specific by design. P-code-based fingerprints are possible but are a different research question. |
| `raw_scan.py` | Platform seed recipe (vector table). It belongs to the target descriptor, not to dataflow. |

## First retirement candidate: `indirect_target` v3

This is still the best first candidate. It has the largest share of
ISA-specific code, it is the hub that `callback_provenance` and the
`indirect_call_target` operation consume, and it has a ready comparison
corpus.

The forward/backward duality check already ran over the grounding image's
full site set (see that case's `pcode-forward-use-v1` note). Every reaching
definition that v2 reports reaches its site in p-code: 95 of 95. That check
covers only one direction. What v2 might **miss** is unknown until a p-code
backward analysis exists, and that is what v3 tests.

The `callback_provenance` consumer change (closing a target set only on a
complete `NO_ESCAPE_WITHIN_SCOPE` for every address-taken load) is smaller,
but it retires almost no semantics: only `_next_use`. It changes case
classifications, so it should be its own milestone with its own assumptions
record. It can run before or after v3.

### Milestone: `indirect_target` v3 on p-code reaching definitions

Scope:

1. A generic backward reaching-definitions walker beside
   `APTracePcodeForwardUse.java`. It shares the varnode and calling-convention
   helpers, and it is batched: all sites in one invocation.
2. Normalized definition records with the same fields v2 emits (`def_addr`,
   `kind`: load / move / argument / call-result / constant; base, disp,
   index, shift, writeback; incomplete reasons).
3. `indirect_target.py` v3 consumes those records. Shape classification and
   candidate policy are unchanged. It is a new `ANALYSIS_VERSION`, and the
   agent operation version is bumped.
4. A deterministic comparison artifact, v2 vs v3, for every census
   register-indirect site.

Acceptance criteria:

- Fixtures: Thumb and RV32 controls for single and multiple definitions,
  joins, IT-conditional definitions, call clobbers, stack arguments, `ldrd`,
  literal and `movw`/`movt` constants, and a jump-table predecessor. They
  run with no ISA branch in the walker (static check).
- Real image: every site is compared, and each disagreement is classified
  (rule 2). None is silently resolved. The current spike evidence predicts
  that v3 is more complete wherever v2 hit a bound.
- Jump-table predecessors: v2 uses census case edges that APTrace itself
  resolved. v3 may take Ghidra's flow references, or it may take the census
  edges as an **explicitly recorded assumption**. Either way the choice is
  recorded in the result, and a missing predecessor is incomplete, never
  absent.
- Evidence: a new operation identity, and replay matches. Historical v1/v2
  records are unchanged and readable.
- Cost: all sites in one Ghidra invocation, under 10 s and under 1 GB on
  the development machine.
- Deletion: `_reaching`, `_definition`, `_stack_argument` and their
  Capstone decode helpers are deleted only after a full-corpus comparison
  with zero unexplained disagreements. `callback_provenance` is then moved
  onto v3 under its own version bump.

## Integration cost observed

Adding `value_forward_use` touched 10 existing agent modules plus one new
module:

- executor;
- investigator;
- ledger operations, semantics and wiring;
- controller;
- fact derivation;
- history;
- projection;
- structural wiring.

The tool name is enumerated by hand in five lists: controller structural
tools and sources, projection, investigator, and history versions. That
matches the architecture evaluation's estimate. An operation descriptor
(name, argument schema, inputs, analysis version, grade and limitation
policy, planner offering) would collapse most of this. It is recorded as
the separate cleanup in architecture evaluation §8 step 6, and it was not
started here.
