# Arrow: admission

The boundary between model output and the ledger. It covers:
- **Admission:** decides whether a parsed model claim proposal becomes a
  PROPOSED claim version or is rejected with diagnostics.
- **Candidate generation:** derives typed claim candidates deterministically
  from session evidence, so the planner can select them by id instead of
  writing relationships in prose.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/claims/claims-design.md (skeleton)

### LLD
- docs/intent/claims/admission/admission-design.md

### EARS
- docs/intent/claims/admission/admission-specs.md (prefix `CLAIMS-ADMIT`; 22 specs: 22 `[x]`, 0 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`, with fake sessions and executors.
- **test_claim_quality.py:**
  - entity rejection, access and absence, omission accountability;
  - historical reference note, scoped hypothesis;
  - USB/EIC controls;
  - bounded garbage.
- **test_claim_candidates.py:** about 20 tests:
  - identity independent of session numbering;
  - withheld facts;
  - no negative candidates;
  - historical support;
  - invalid evidence;
  - selection;
  - duplicates;
  - read-only preview.

  `test_19_canonical_case_ledger_preview_is_read_only_and_finds_no_access` reads the canonical case ledger.
- **test_call_relations.py:** correction round; candidates generate no call relations.
- **test_ledger_audit.py:** the claim contract and correction rounds (controller behavior).

### Code
- agent/src/aptrace_agent/research/admission.py
- agent/src/aptrace_agent/research/candidates.py

### Related docs
- docs/claim-admission.md, docs/claim-candidates.md, docs/claim-call-relations.md

## Architecture

**Purpose:** a model's proposal enters the ledger only if it is well-formed,
about real entities, supported by what it cites, and no stronger than its
evidence. Admission never verifies, and never rewrites
(`admission.py:1-37`).

**Key components:**
1. **`admit(proposal, session)`:** applies six rules:
   - **References:** at least one citation, every one a known session id.
   - **Entity identity.**
   - **Support:** typed semantics are checked with `verify_semantics`; untyped prose with the access and call-relation checks.
   - **Grade:** within `grade_ceiling`, and at most `PROBABLE` when untyped.
   - **Accountability:** follow-up evidence about named functions must be cited or its omission explained.
   - **Historical references:** reused evidence is noted.

   The output is a `ClaimAdmission` record (admitted or rejected, with diagnostics). A rejected first round gets one bounded correction round (`feedback`).
2. **`generate_candidates`:**
   - *Inputs:* typed facts from evidence graded `PROBABLE` or stronger, through the verifier's own fact readers.
   - *Extractors:* `MMIO_USER` and `ADDRESS_CONSTANT_LOADER` roles, and `RESOLVED_FUNCTION_POINTER`.
   - *Withheld facts:* conflicts, assumptions, insufficient grade, unknown entities, failed semantics.
   - *Identity:* content-derived ids `K-…` that are independent of session numbering.
   - *Ranking:* by objective entities and related signals.
3. **Selection:** `parse_selection` and `proposal_for`. The planner names `K-` ids. Each selected candidate becomes a proposal built only from the candidate record, and that proposal still passes `admit`.

## Spec Coverage

`[x]` means observed in source only. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Admission rules | CLAIMS-ADMIT-ADM-001 to 008 | 8 | 0 | 0 | 7 |
| Grade used and caps | CLAIMS-ADMIT-GRD-001 to 003 | 3 | 0 | 0 | 1 |
| Candidate extraction | CLAIMS-ADMIT-CAND-001 to 008 | 8 | 0 | 0 | 8 |
| Selection | CLAIMS-ADMIT-SEL-001 to 003 | 3 | 0 | 0 | 3 |

**Summary:** all 22 specs are observed in source, and none is an
approved-intent gap.
- *GRD-001:* admission recomputes grades with the current rules. It has no
  test.
- *GRD-002:* the strongest-artifact ceiling. Its admission-side test is
  related exercise only.

Both are recorded as observed behavior for the cross-segment register. 19
specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **Admission and the ledger can grade the same evidence differently.**
   - *Admission:* `_cited` computes the grade of each cited session observation with the current `evidence_grade` code (`admission.py:92-106`). So does candidate generation (`candidates.py:157-172`).
   - *Ledger:* verification phase B uses the grade stored on the ledger artifact at first recording (evidence-record X5).
   - *Consequence:* for historical evidence reused by reference, the two can differ after a grading change `[inferred]`.
2. **Typed claims are capped only by the ceiling.**
   - *Untyped claims:* capped at `PROBABLE` (`admission.py:69, 220-227`).
   - *Typed claims:* may be admitted up to the ceiling. That is the *strongest* cited artifact's grade (evidence-record CEIL-001), so `STRONG` or `EXACT` are possible.
   - *Producer grades that feed this:* `function_effects` raw-complete (`STRONG`) and census `EXACT`/`STRONG` edges (cross-segment X1, X2, X6).
3. **Effects access candidates do not check guard or coverage.**
   - *What is withheld:* an `MMIO_USER` candidate from `function_effects` is withheld only when the access was observed under specialization, or when no MMIO access has a concrete, input-independent address (`candidates.py:198-216`).
   - *What is not checked:* guard status (`unqueried`, `unsatisfiable`) and adapter coverage.
   - *Where coverage does appear:* bounded coverage is attached only as a limitation on *loader* candidates (`:219-244`).
4. **Pointer candidates inherit census confidence.** `RESOLVED_FUNCTION_POINTER` candidates come from census `resolved_indirect_edges`. They are offered when the supporting result's grade is `PROBABLE` or stronger. That grade is capped by the minimum edge confidence (evidence-record GRD-005). The scope text says "stores through computed pointers are not excluded" (`candidates.py:384-446`).
5. **No negative candidates exist.** Call-site relations, bounded effects observations and negative assertions are deliberately not extracted (`candidates.py:31-33`).
6. **Historical evidence is noted, not counted.** Citing reused evidence adds `HISTORICAL_REFERENCE`, "not new observations or independent corroboration" (`admission.py:229-241`). Candidate identity is content-based, so reuse and fresh execution give the same id (`candidates.py:35-40`).
7. **The planner can bypass admission only through the ledger CLI.** Inside the controller, every proposal (free or candidate-selected) passes `admit`. `ledger_cli propose`/`supersede` bypass it (evidence-record CLI-002).
8. **Some vocabulary and rendering are case- and runtime-specific.**
   - *Patterns:* SAM-style peripheral token regex (`candidates.py:84`) and the 32-bit `FUN_` pattern.
   - *Rendering:* candidates are rendered as plain sentences, as a workaround for local model-runtime `incomplete_tool_call` rejections (`candidates.py:671-673`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* The canonical-ledger candidate-preview
test asserts that it is read-only.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Admission uses the current grade; verification uses the stored grade** (Finding 1).
2. **Typed claims can reach `STRONG`/`EXACT` through the strongest-artifact ceiling and producer grades** (Finding 2; cross-segment X1, X2, X6).
3. **Effects `MMIO_USER` candidates ignore guard status and coverage** (Finding 3).

### Architectural coupling
4. **The modules sit in `research/` but make ledger-semantic decisions.** `recorder.py` imports `research.candidates` lazily (evidence-record).
5. **SAM peripheral regex and 32-bit function pattern** (Finding 8).

### Semantic inconsistencies
6. **Coverage applies to loader candidates only.** Bounded effects coverage limits loader candidates but not access candidates (Finding 3).

### Maintenance debt
7. **A rendering workaround tied to one model runtime** (Finding 8).
