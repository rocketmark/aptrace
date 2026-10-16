# Arrow: continuity

Research continuity across runs:
- **Historical operation reuse (`continuity-v1`):** a follow-up session can
  use an earlier run's identical, still-valid result by reference, instead
  of re-executing.
- **Follow-up candidate generation:** deterministic candidates are built from
  a recorded run's open-lead frontier, claim evidence gaps, audits,
  verification conditions and staleness.
- **Follow-up session seeding.**

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/investigation/investigation-design.md (skeleton)

### LLD
- docs/intent/investigation/continuity/continuity-design.md

### EARS
- docs/intent/investigation/continuity/continuity-specs.md (prefix `INV-CONT`; 16 specs: 16 `[x]`, 0 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`. They use fake executors and temporary ledgers.
- **test_continuity.py:**
  - reuse by reference; refusal for a different firmware, changed inputs, a changed analysis version, or invalidated or tampered evidence;
  - case search never reused;
  - seeding and preload;
  - free reuses and fallbacks;
  - original provenance kept.
- **test_followups.py:**
  - frontier re-derivation and refusal;
  - claim-gap scenarios (constant load, effects access, redundancy, audit requests, device identity, unavailable tools);
  - stable keys; idempotent creation;
  - preview writes nothing;
  - the work-item path;
  - seed bounds;
  - the CLI.

  `test_real_beads_followup_dedup_provenance_and_concurrency` uses the real Beads binary (work segment).
- **Per-tool historical-reuse tests:** `test_observed_call_arguments.py`, `test_scenario_observation.py`, `test_callback_provenance.py`, `test_value_forward_use.py`, `test_claim_candidates.py` (`test_8_incompatible_analysis_version_is_not_reused_as_candidate_support`).

### Code
- agent/src/aptrace_agent/research/history.py
- agent/src/aptrace_agent/research/followups.py

### Related docs
- docs/research-ledger.md, docs/work-store.md, docs/status.md

## Architecture

**Purpose:** let a follow-up investigation start from earlier research.
Reuse must not re-execute, must not count as new evidence, and must not
weaken identity (`history.py:1-40`). Follow-up generation decides which
unresolved questions are worth another bounded run, reading the ledger and
never writing it (`followups.py:1-40`).

**Key components:**
1. **`HistoricalOperations`:**
   - *Scope:* the source run, earlier runs with the same follow-up key, and cited evidence; at most 256 invocations.
   - *Lookup:* returns the newest reusable invocation, or the newest refusal reason. Seven ordered reuse requirements apply.
2. **`ContinuityTracker`:** per-session bookkeeping:
   - seeded leads, anchors, followed, failed, offered, preloaded;
   - free-reuse and fallback counters;
   - a `ContinuityRecord` written to the run.
3. **`FollowUpGenerator`:**
   - *Frontier:* re-derived from durable evidence, only under an equal context.
   - *Claim gaps:* from constant-load-only access, device identity, CHALLENGED/UNRESOLVED audits, unmet or unevaluable gate conditions and held checks, and STALE state.
   - *Lead groups.*
   - *Ranking:* categories 1–3.
   - *Keys:* stable candidate and question keys.
   - *Report:* redundancy, shortlist, deferred and suppressed lists.
4. **`seed_session`:**
   - registers seeded leads (at most 8), tagged questions and hypotheses;
   - attaches the tracker;
   - preloads cited reusable evidence as facts only.
5. **`continuity_review`:** read-only. It reports what a follow-up produced. The question always stays OPEN.

## Spec Coverage

`[x]` means observed in source only. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Historical reuse | INV-CONT-REUSE-001 to 006 | 6 | 0 | 0 | 4 |
| Session bookkeeping | INV-CONT-TRK-001 to 002 | 2 | 0 | 0 | 1 |
| Follow-up generation | INV-CONT-GEN-001 to 006 | 6 | 0 | 0 | 5 |
| Seeding and review | INV-CONT-SEED-001 to 002 | 2 | 0 | 0 | 1 |

**Summary:** all 16 specs are observed in source, and none is an
approved-intent gap.
- *REUSE-003:* version-gated reuse for five tools only. This is the
  documented limitation behind cross-segment X3 and X20. Its identity
  mechanism gap is EVREC-ID-009.
- *REUSE-004:* reuse ignores grade and claim state.

11 specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **Implementation changes without a version bump are reused.**
   - *What reuse checks:* firmware, input-artifact hashes, the operation key, evidence validity, blob integrity, and a declared `analysis_version` for five tools only. `current_analysis_versions` covers `function_effects`, `observed_call_arguments`, `indirect_call_target`, `callback_argument_provenance` and `value_forward_use` (`history.py:21-38, 71-80, 165-209`).
   - *The unversioned rest:* `census_*`, `function_facts`, `function_disassembly`, `callsite_context`, `pin_table_entry` and `structural_source_agreement` declare no version. Changed implementation code is reused whenever input hashes and arguments match.
   - *Documented:* "Tool code changes that do not bump a declared analysis version are not detected here" (`history.py:37-38`).
   - *Cached adapters:* for `function_effects`, the cache key also omits binary identity (symbolic-execution). A version bump is the only guard.
   - *Cross-segment:* X3, X20.
2. **Reuse keys on artifacts and ignores claim state.** Reuse refuses invalidated evidence (`EVIDENCE_VALID`). It does not consider:
   - the grade or limitations stored on the reused artifact;
   - the state of claims that cite it;
   - audits of those claims.

   The stored grade is the first-recorded one (evidence-record X5).
3. **A truncated history is not reported.** When the history exceeds 256 invocations it is truncated with a `truncated` flag, but that flag does not reach the `ContinuityRecord` (`history.py:112-125, 289-305`).
4. **Historical results are prior observations.** Reused results enter the session as aliases with `reused_from`. They are not re-recorded as the run's evidence (evidence-record REC-001). Admission notes them as "not new observations or independent corroboration" (claims/admission).
5. **The frontier depends on the current lead-derivation code.** The open-lead frontier is re-derived by replaying the *current* `LeadDeriver` over durable evidence. It is refused when the context differs; the recorded open-lead count is a cross-check (`followups.py:282-365`). A changed `LeadDeriver` changes the re-derived frontier under an equal context `[inferred]`.
6. **Contradictions produce only a note.** A CONTRADICTED verification gate condition yields a note, "revising the claim is an operator decision", not a candidate (`followups.py:572-573`).
7. **Some gap rules match wording.** Rules that match assertion prose (which claim a peripheral or function gap belongs to) are disclosed as pattern-matched in the candidate's priority basis (`followups.py:23-25`). Device-identity wording is blocked as needing hardware.
8. **Running a follow-up resolves nothing.** `continuity_review` always reports the question OPEN: "resolution is a ledger verification outcome" (`followups.py:995-1031`).
9. **Some outcomes cost one step.** In follow-up sessions, reuses beyond 4 cost one step. Fallback leads (at most 3) are taken on the planner's behalf (`history.py:62-68, 258-265`).
10. **Case vocabulary appears in candidates.** The constant-load and peripheral gap rules read census and effects fields. Device-identity and hardware-blocker codes are generic.

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* Follow-up generation and history only
read the ledger.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Unversioned tools are reused across implementation changes.** This is documented (Finding 1; cross-segment X3, X20).
2. **Reuse ignores stored grade, limitation semantics and claim or audit state** (Finding 2).
3. **History truncation is not recorded in the continuity record** (Finding 3).

### Architectural coupling
4. **`current_analysis_versions` hardcodes five tool modules.** A new versioned tool must be added by hand.
5. **Mutual import with session code.** `research.session` imports `research.history`, and `followups` imports `session`, `derivation` and `leads`.

### Semantic inconsistencies
6. **The frontier depends on current `LeadDeriver` code** under an equal context (Finding 5).

### Maintenance debt
7. **`followups.py` is 1,109 lines with about 25 rules.**
