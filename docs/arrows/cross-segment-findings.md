# Cross-Segment Findings Register

*Produced by `/map-codebase` (brownfield bootstrap) on 2026-10-16, from HEAD
`a6395d7`, after all 14 leaves were mapped.*

This register is for independent review. It is **not** an approval of the
architecture, and **no code was executed** during mapping.

**What each entry records:**
- a relationship in which one segment's output is interpreted, promoted,
  filtered, cached or reused by another;
- the source references;
- the producing and consuming components;
- the concern;
- the evidence level;
- the related specs and Open Questions (OQs);
- the *possible* downstream impact.

No entry asserts that an incorrect result has occurred. None was
demonstrated.

**Concern** values:
- identity
- provenance
- completeness
- correctness
- confidence-promotion
- independence
- canonical-state

**Evidence level** values:
- `observed`: read directly at the cited lines.
- `inferred`: follows from observed code; the full end-to-end chain was not
  executed.
- `contradicted`: source conflicts with project or module documentation.
- `unverified`: plausible, not established from the repository.

**Ranking.** Entries are ranked by potential impact, in this order:
1. evidence correctness and claim verification;
2. reproducibility;
3. canonical-state safety.

Within a tier, the order is by how many segments the chain crosses and how
close it gets to a VERIFIED or admitted claim.

**Relationships the review asked to track:**

| Requested relationship | Register entries |
|---|---|
| 1. Census STRONG → DEFINITELY_REACHABLE → callback ESTABLISHED | X1 |
| 2. Symbolic raw complete + bounded coverage → ledger STRONG | X2 |
| 3. Implementation changes not reflected in cache or ledger identity | X3, X7 |
| 4. Missing, truncated or failed results read as negatives | X22, X18 |
| 5. Shared-engine agreement mistaken for independent corroboration | X11, X15, X24 |
| 6. Promotion of grades into admitted or VERIFIED claims | X6, X10, X2, X4, X21, X14, X16 |
| 7. Historical evidence reuse after input or implementation change | X20, X5, X7 |

---

## Tier A: evidence correctness and claim verification

### X1. Census STRONG candidates → DEFINITELY_REACHABLE → callback ESTABLISHED, and census-scoped reachability claims
- **Chain:**
  1. *Census reachability:* `reachability.py` admits every EXACT or STRONG indirect candidate into the strong graph (`reachability.py:61-65, 122`), including STRONG table-scan and RAM function-pointer candidates. That yields `DEFINITELY_REACHABLE`. The module docstring defines the strong graph by site classification instead (census REACH-001/003/005, `contradicted`).
  2. *Callback provenance:* `callback_provenance` reports caller reachability `ESTABLISHED` from census `DEFINITELY_REACHABLE` (static-dataflow CB-004).
  3. *Claim checks:* `call_relations.check_reach` supports a reachability claim with no cited root, given census `DEFINITELY_REACHABLE` and wording that matches a census or static scope regex (`ledger/call_relations.py:571-593`; CLAIMS-SEM-REL-004).
- **Producer → consumer:** census → static-dataflow → claims/claim-semantics → admission and verification phase B.
- **Concern:** confidence-promotion, correctness.
- **Evidence level:** `contradicted` (census docstring vs code); the chain is `inferred`.
- **Specs and OQs:**
  - *Specs:* PROD-CENSUS-REACH-001/003/005, CP-002; PROD-DFLOW-CB-004; CLAIMS-SEM-REL-004.
  - *OQs:* census OQ1–2; static-dataflow OQ4; claim-semantics OQ2.
- **Possible impact:** a heuristic STRONG candidate can surface as "ESTABLISHED" caller reachability, and as an admitted census-scoped reachability statement. No test covers a STRONG table-scan candidate reaching `DEFINITELY_REACHABLE` (census arrow).

### X10. Census EXACT/STRONG resolved edges → categorical `ESTABLISHED_INDIRECT` edges and STRONG pointer candidates
- **Chain:**
  - *Call edges:* `extract_call_facts` maps census `resolved_indirect_edges` with EXACT or STRONG confidence to `ESTABLISHED_INDIRECT`, a categorical edge with no condition (`ledger/call_relations.py:332-341`).
  - *Pointer facts:* `extract_facts` builds pointer facts and roles from edges of any confidence (`ledger/claim_semantics.py:431-447`).
  - *Candidates:* the candidate generator offers `RESOLVED_FUNCTION_POINTER` at the ceiling grade (`research/candidates.py:384-446, 478-510`).
- **Producer → consumer:** census → claim-semantics → admission (candidates) → ledger claims.
- **Concern:** confidence-promotion.
- **Evidence level:** `observed`.
- **Specs and OQs:**
  - *Specs:* CLAIMS-SEM-EDGE-003, FACT-001; CLAIMS-ADMIT-CAND-004; EVREC-GRD-005.
  - *OQs:* claim-semantics OQ1, 3; admission OQ4; census OQ1–2.
- **Possible impact:** census heuristic confidence admits categorical indirect-call claims. Verification policy v1 has no contract for `RESOLVED_INDIRECT_CALL`, so such claims stay PROPOSED (X15).

### X6. Strongest-artifact grade ceiling, combined with status-keyed producer grades
- **Chain:**
  - *Ceiling:* `grade_ceiling` returns the maximum grade over supporting artifacts. BOUNDED counts as STRONG for `NO_KNOWN_PATH` (`ledger/semantics.py:489-509`).
  - *Who uses it:* admission (`research/admission.py:209-218`), candidate grading and verification phase B.
  - *Producer grades are status-keyed:* X2, X4, X10.
- **Producer → consumer:** every producer → evidence-record → admission and verification.
- **Concern:** confidence-promotion.
- **Evidence level:** `observed` (code-documented: "as strong as its strongest supporting derivation").
- **Specs and OQs:**
  - *Specs:* EVREC-CEIL-001; CLAIMS-ADMIT-GRD-002; CLAIMS-VERIFY-PH-003.
  - *OQs:* evidence-record OQ6–7; admission OQ2.
- **Possible impact:** a typed claim citing one STRONG artifact plus weaker ones can be admitted at STRONG.

### X2. `function_effects` raw `complete` with bounded adapter coverage → ledger STRONG
- **Chain:**
  - *Adapter:* coverage becomes `bounded: … computed control transfer(s)` when calls are opaque (`function_effects.py:319-337`).
  - *Grader:* grades STRONG whenever the raw status starts with `complete`. It adds `EFFECTS_BOUNDED` from the raw status only (`ledger/semantics.py:200-205, 311-312`).
- **Producer → consumer:** symbolic-execution → evidence-record → claim-semantics (MMIO roles), admission, candidates.
- **Concern:** confidence-promotion, completeness.
- **Evidence level:** `observed`.
- **Specs and OQs:**
  - *Specs:* PROD-SYM-GRD-001, SIM-002; EVREC-GRD-003.
  - *OQs:* symbolic-execution OQ4; evidence-record OQ7.
- **Possible impact:** effects evidence with unanalyzed computed transfers carries STRONG with no bounded limitation. Facts and candidates derived from it inherit that grade (X12).

### X12. Effects MMIO accesses → `MMIO_USER` roles and candidates, regardless of guard or solver-only region
- **Chain:**
  - *Roles:* any `function_effects` access whose region starts with `MMIO`, including `MMIO (solver)` and guard statuses `unqueried`, `unsatisfiable` or `conditional`, becomes an `MMIO_USER` role (`ledger/claim_semantics.py:528-537`).
  - *Candidates:* they withhold only specialized or input-dependent accesses (`research/candidates.py:198-216`).
  - *Shared label:* the adapter shows a concretely false RAW guard and an unqueried guard alike as `unqueried` (PROD-SYM-ENR-004).
- **Producer → consumer:** symbolic-execution → claim-semantics → admission (candidates).
- **Concern:** correctness, confidence-promotion.
- **Evidence level:** `observed` (no guard filter); the impact is `inferred`.
- **Specs and OQs:**
  - *Specs:* CLAIMS-SEM-FACT-004; CLAIMS-ADMIT-CAND-002; PROD-SYM-ENR-004.
  - *OQs:* claim-semantics OQ4; admission OQ3; symbolic-execution OQ3–4.
- **Possible impact:** an access recorded on a path the model rules out, or one only solver-placed in MMIO, could support an access role.

### X18. "Does not access" accepted on complete effects coverage while callees are opaque
- **Chain:**
  - *Absence rule:* `access_diagnostics` accepts a categorical absence when cited `function_effects` coverage is `complete` and no address is parametric (`ledger/claim_checks.py:207-251`).
  - *Call model:* the effects harness models calls as opaque, with no memory effects (PROD-SYM-ASM-004).
- **Producer → consumer:** symbolic-execution → claim-semantics → admission and verification.
- **Concern:** completeness (negative result).
- **Evidence level:** `inferred`.
- **Specs and OQs:** CLAIMS-SEM-PROSE-003; claim-semantics OQ5.
- **Possible impact:** an absence that holds only for the function's own direct accesses could be read as a whole-call-tree absence.

### X4. Bounded concrete observation with entries → STRONG → session fact PROVEN
- **Chain:**
  - *Grade:* `observed_call_arguments` with status `bounded…` and observed entries is graded STRONG. This is test-asserted (`ledger/semantics.py:208-221`; `test_observed_call_arguments.py::test_grades_and_limitations`).
  - *Session fact:* the derived fact is merged with `ClaimGrade.PROVEN` (`research/fact_derivation.py:447-482, 780-790`).
- **Producer → consumer:** concrete-execution → evidence-record and investigation/controller.
- **Concern:** confidence-promotion.
- **Evidence level:** `observed`. The fact text itself is scenario-scoped.
- **Specs and OQs:**
  - *Specs:* EVREC-GRD-004; INV-CTRL-FACT-001.
  - *OQs:* concrete-execution OQ13; controller OQ1–2.
- **Possible impact:** a truncated scenario's observation reads as STRONG in the ledger and PROVEN in the planner view.

### X21. Every derived session fact is PROVEN; the conclusion's `proven` bucket mixes evidence levels
- **Chain:**
  - *Facts:* `StateFactDeriver` grades all derived statements PROVEN, with the level only in the basis tag and the wording (`research/fact_derivation.py:769-799`). That includes may-escape static possibility, raw-symbolic results and concrete scenario facts.
  - *Conclusion:* `projection.conclusion` lists them under `proven` (`research/projection.py:543-578`).
- **Producer → consumer:** all producers → controller → CLI output and planner.
- **Concern:** confidence-promotion.
- **Evidence level:** `observed`. CLAUDE.md requires evidence levels to be kept distinct.
- **Specs and OQs:** INV-CTRL-FACT-001, FIN-006; controller OQ1.
- **Possible impact:** a planner or human reader sees heterogeneous evidence as "proven". These are session state, not ledger claims.

### X11. Ghidra seeded with census-derived function-pointer seeds, and census derived from Ghidra: seeded labels ignored
- **Chain:**
  - *Census → Ghidra:* census `fnptr-seeds` writes derived seeds that are fed into the Ghidra build (`tools/ghidra/aptrace_ghidra.py:125-148`).
  - *Ghidra → census:* the census is `derived_from` Ghidra (`structural_wiring.py:297-306`).
  - *Labels:* source agreement records per-observation `seeded` labels, but neither the gate, claim semantics nor grading reads them (no `seeded` reference in `ledger/`).
  - *Grade:* census + Ghidra suffices for AGREE and a STRONG agreement grade, with a `SOURCES_NOT_INDEPENDENT` limitation.
- **Producer → consumer:** census → target-loading → structural-discovery → claims/verification.
- **Concern:** independence.
- **Evidence level:** `observed`.
- **Specs and OQs:**
  - *Specs:* CLAIMS-VERIFY-GATE-005, SRC-003; EVREC-GRD-007.
  - *OQs:* verification OQ1, 3; structural-discovery OQ1, 4.
- **Possible impact:** circular agreement at derived-seed addresses. Today it cannot yield VERIFIED (X15), but it does yield STRONG agreement evidence and passes code-presence semantics.

### X24. `capstone_sweep` seeded from Ghidra discoveries, but documented as independent
- **Chain:** the sweep's roots include Ghidra function entries (`tools/census/build.py:225`). Its docstring says "completely independent".
- **Producer → consumer:** structural-discovery → census.
- **Concern:** independence.
- **Evidence level:** `contradicted`.
- **Specs and OQs:** structural-discovery OQ4; arrow drift.
- **Possible impact:** disagreement and agreement with Ghidra are not from an independent run.

### X15. No real structural source declares an independence envelope, so no production claim can newly reach VERIFIED
- **Chain:**
  - *Contracts:* policy v1 gives an evidence contract to `CODE_EXISTENCE` only.
  - *Envelope requirement:* the gate requires a lineage, firmware-SHA and engine-version envelope.
  - *Real sources:* census, Ghidra and Macaw declare none.
- **Producer → consumer:** structural-discovery and census → claims/verification.
- **Concern:** independence, provenance.
- **Evidence level:** `observed`, and documented (`docs/status.md:300-312`).
- **Specs and OQs:** CLAIMS-VERIFY-SRC-007 `[ ]`, POL-003; verification OQ1–2.
- **Possible impact:** fail-closed. VERIFIED is unreachable in production, and positive-control tests pass only with fake envelopes.

### X14. Coverage gap counts as a falsification attempt; a zero tool budget waives falsification
- **Chain:**
  - *Coverage gap:* `FALSIFYING_OUTCOMES` includes `executed:coverage_gap`, which covers a runner `KeyError`, `LookupError` or `FileNotFoundError` (`ledger/auditor.py:126-130, 1133-1136`).
  - *Zero budget:* `satisfied = successful > 0 or max_tool_requests == 0` (`:1182`).
  - *Phase D:* requires an audit SUPPORTED for VERIFIED.
- **Producer → consumer:** claims/audit → claims/verification.
- **Concern:** confidence-promotion.
- **Evidence level:** `contradicted` (the v0.4 docstring says failing requests do not count).
- **Specs and OQs:** CLAIMS-AUDIT-AUD-004, AUD-005; audit OQ1–2.
- **Possible impact:** a SUPPORTED verdict can follow an analysis that answered nothing. Policy v1 currently blocks VERIFIED anyway (X15).

### X16. A HOLD outcome demotes VERIFIED or BLOCKED versions to PROPOSED
- **Chain:** `_finish` maps HOLD to PROPOSED unless the current state is SUPERSEDED or STALE (`ledger/verifier.py:436-439, 469-477`).
- **Producer → consumer:** claims/verification → evidence-record (lifecycle).
- **Concern:** correctness (lifecycle).
- **Evidence level:** `observed`. VERIFIED → PROPOSED is test-asserted; BLOCKED → PROPOSED is untested for the same version.
- **Specs and OQs:** CLAIMS-VERIFY-OUT-002; verification OQ4.
- **Possible impact:** a block can be lifted by a later verification that only holds, unless the block reason recurs (a CHALLENGED audit always recurs).

### X13. Admission recomputes grades with the current rules; verification uses the stored artifact grade
- **Chain:**
  - *Admission and candidates:* `_cited` and `_graded` call `evidence_grade` on session results (`research/admission.py:92-106`; `research/candidates.py:157-172`).
  - *Verification:* phase B reads the grade stored on the ledger artifact at first recording (X5).
- **Producer → consumer:** evidence-record → admission and verification.
- **Concern:** confidence-promotion, identity.
- **Evidence level:** `inferred` (they diverge only after a grading change, or for reused historical evidence).
- **Specs and OQs:** CLAIMS-ADMIT-GRD-001; EVREC-ID-005; admission OQ1.
- **Possible impact:** admission and verification can disagree about the same evidence's grade.

---

## Tier B: reproducibility, identity and reuse

### X3. Implementation and engine changes are not reflected in operation, cache or ledger identity for most tools
- **Chain:**
  - *Operation keys:* hash declared input artifacts. Implementation source is included only for the Unicorn harness, the census dataflow tools and the p-code walker and driver (`ledger/operations.py:31-56`).
  - *No implementation identity:* `function_effects` (Haskell binary, vendored engines), the `census_*` readers, `function_facts`, the disassembly tools, `pin_table_entry` and `structural_source_agreement`.
  - *Effects cache key:* (firmware SHA-16, entry, specializations) only (`function_effects.py:166`).
  - *Runs:* record the git commit and dirty fingerprint, but not the vendored engine, Ghidra, Unicorn or Capstone versions.
- **Producer → consumer:** all producers → evidence-record → continuity and verification.
- **Concern:** identity, provenance.
- **Evidence level:** `observed`.
- **Specs and OQs:**
  - *Specs:* EVREC-ID-006, ID-009 `[ ]`; PROD-SYM-ID-002, ID-006 `[ ]`; PROD-CONC-ADP-006 `[ ]`; PROD-DISC-MACAW-009 `[ ]`; PROD-CENSUS-PROV-001/002 `[ ]`.
  - *OQs:* evidence-record OQ1; symbolic-execution OQ1–2; concrete-execution OQ1–2.
- **Possible impact:** results from different implementations share one identity. Cached failures persist across fixes.

### X20. Historical reuse after implementation change, for unversioned tools
- **Chain:**
  - *Version check:* `continuity-v1` checks a declared `analysis_version` for five tools only (`research/history.py:71-80, 202-206`).
  - *The other tools:* reused whenever inputs and arguments match.
  - *Documented:* "Tool code changes that do not bump a declared analysis version are not detected here" (`:37-38`).
- **Producer → consumer:** evidence-record → investigation/continuity → controller (session facts) → admission (`HISTORICAL_REFERENCE` note).
- **Concern:** identity.
- **Evidence level:** `observed` (documented limitation).
- **Specs and OQs:** INV-CONT-REUSE-003, REUSE-004; continuity OQ1–2.
- **Possible impact:** a follow-up reasons over results the current code would not produce.

### X7. Replay and verification phase C can match on a cached adapter result without re-execution
- **Chain:**
  - *Replay path:* `replay` goes through the same adapter.
  - *Cache hit:* `function_effects` serves its on-disk cache, and `provenance.cached` is stripped before hashing (`ledger/semantics.py:88-93`).
  - *Phase C:* reports "replay(s) identical".
- **Producer → consumer:** symbolic-execution → evidence-record → claims/verification.
- **Concern:** identity, independence (a re-run is not corroboration).
- **Evidence level:** `observed` for `function_effects`; other adapters were not checked.
- **Specs and OQs:** EVREC-OPS-005; CLAIMS-VERIFY-PH-005; evidence-record OQ5; verification OQ7.
- **Possible impact:** replay certifies cache consistency, not reproducibility.

### X5. Grades and limitations are frozen at first recording; grading semantics are unversioned
- **Chain:**
  - *First recording:* `record_invocation` writes an artifact's grade and limitations only for a new evidence id. Identical later results reuse it (`ledger/store.py:228-262`).
  - *Versioning:* artifacts carry no grading-semantics version.
- **Producer → consumer:** evidence-record → verification, continuity.
- **Concern:** identity.
- **Evidence level:** `inferred`.
- **Specs and OQs:** EVREC-ID-005; evidence-record OQ2.
- **Possible impact:** after a grading change, old and new evidence of the same content carry the old grade.

### X9. Missing context inputs are dropped silently; the context firmware hash is the expected hash
- **Chain:**
  - *Dropping:* `context_artifacts` drops missing files (`ledger_wiring.py:71`), so the operation key changes without a recorded reason.
  - *Firmware hash:* `firmware_sha256` is the configured expected hash (`:79-80`).
  - *Timing:* the context is computed when the run is recorded (`ledger_cli.py:528`).
- **Producer → consumer:** evidence-record wiring → all identities.
- **Concern:** identity.
- **Evidence level:** `observed`; the timing is `inferred`.
- **Specs and OQs:** EVREC-ID-008; evidence-record OQ3–4.
- **Possible impact:** a missing artifact gives a different identity that looks like a different operation.

### X22. Missing, truncated or failed analysis recorded inconsistently, so it could be read as a negative
Each of these is an incompleteness that is silent or only weakly recorded. These are possible paths for "missing = absent".

| Producer | Behavior | Specs / OQs | Level |
|---|---|---|---|
| target-loading | A cancelled or interrupted Ghidra build is cached `fresh` | PROD-TGT-GH-018 `[ ]`; target-loading OQ1 | observed |
| structural-discovery | A truncated Ghidra export has no marker | PROD-DISC-GEXP-010 `[ ]`; OQ2 | observed |
| structural-discovery | `GhidraIndex` drops unattributed call records uncounted | PROD-DISC-IDX-005 `[ ]` | observed |
| structural-discovery | `capstone_sweep` bounds are silent | PROD-DISC-SWEEP-004 `[ ]` | observed |
| census | Reduce scenario failures are printed only; hardware-snapshot failures are skipped | PROD-CENSUS-PROV-003 `[ ]`; census OQ7 | observed |
| static-dataflow | `interproc_writes` and `indexed_writes` drop cases silently; `DERIVATION_RECORD_TRUNCATED` is labeled "analysis unaffected" | static-dataflow OQ5–6 | observed |
| symbolic-execution | Enrichment cap and omitted sites are not counted; negative cache never expires; raw-only outcome re-runs | PROD-SYM-ENR-002, ID-003, ENR-005; OQ9–10 | observed |
| concrete-execution | MMIO and RAM logs are truncated silently; correlation ignores `dropped_writes` | PROD-CONC-REC-003, WW-004; OQ4, 7 | observed |
| controller | A lead is FOLLOWED even when the result status is a failure | INV-CTRL-SES-003; controller OQ3 | observed |
| continuity | History truncation is not in the continuity record | INV-CONT-TRK-002; OQ3 | observed |

- **Mitigations observed:**
  - `NO_KNOWN_PATH` is BOUNDED and never unreachability;
  - absence claims require scoped wording or complete coverage (but see X18);
  - concrete facts say "not thereby unreachable";
  - census bounded negatives disclose what is not excluded.
- **Possible impact:** an incomplete upstream result could be consumed as complete. No instance was demonstrated.

---

## Tier C: canonical-state safety

### X8 and X17. Permanent evidence invalidation from maintenance and verification
- **Chain:**
  - *`ledger_cli check`:* invalidates evidence whose blob is *missing* with reason "stored result hash mismatch" (`ledger_cli.py:337-356`). The store allows `blobs-large/` to stay out of version control (`store.py:61-63`). The verifier treats missing as unavailable.
  - *Verification phase C:* invalidates on replay mismatch in every mode, prechecks included (`verifier.py:282-321`).
  - *Default target:* both default to the canonical case ledger.
- **Concern:** canonical-state, correctness.
- **Evidence level:** `observed`. The failure path is `inferred`, not demonstrated.
- **Specs and OQs:**
  - *Specs:* EVREC-CLI-003 (contradicted in part); CLAIMS-VERIFY-PH-005.
  - *OQs:* evidence-record OQ10; verification OQ5–6.
- **Possible impact:** irreversible invalidation events in the canonical ledger, caused by checkout layout or environment differences.

### X19. Audits and investigations write to the canonical ledger by default
- **Chain:**
  - *Default:* every ledger CLI command, `research --ledger`, `followups` and `work` default to `cases/performing-rigs/research/ledger` (`ledger_wiring.py:34, 43-44`).
  - *Audits:* audit tool runs, and the census analyses they trigger, are recorded under the audit id (`ledger/auditor.py:564-580, 712-745`).
- **Concern:** canonical-state.
- **Evidence level:** `observed`.
- **Specs and OQs:** EVREC-CLI-001; CLAIMS-AUDIT-TOOL-004; INV-WORK-CLI-001; audit OQ3; work OQ2.
- **Possible impact:** experiments that omit `--ledger-dir` modify canonical research state (CLAUDE.md requires scratch copies).

### X23. "Read-only" paths that can write
| Path | Behavior | Specs / OQs |
|---|---|---|
| Census query connection | May run DDL and migrations (`tools/census/db.py:30-50, 70-75`) | census OQ9 |
| `macaw_compare` | Docstring says it never writes; its connection path may run DDL | structural-discovery OQ16 |
| `aptrace_ghidra decompile/disasm` | Writes output into the cache directory with the project opened read-only | target-loading OQ4 |
| `work reconcile` (no `--apply`) | Creates lock files | INV-WORK-LOCK-002; work OQ1 |

- **Concern:** canonical-state.
- **Evidence level:** `observed` or `inferred`, per segment.

### Must Fix: tests that might mutate canonical state
| Test | Canonical state | Spec |
|---|---|---|
| `tools/ghidra/test_aptrace_ghidra.py` | case Ghidra cache, including `meta.json` | PROD-TGT-TEST-001 `[ ]` |
| `tools/census/test_indexed_writes.py:377-381` | canonical census DB (write-capable connection) | PROD-DFLOW-TEST-001 `[ ]` |

Tests that read the canonical ledger in place were observed to use read-only
paths. They are recorded, not flagged:
- `test_verification_policy.py`;
- `test_call_relations.py`, which asserts its tree digest is unchanged;
- `test_work_handoff.py`;
- `test_claim_quality.py`;
- `test_claim_candidates.py`.
