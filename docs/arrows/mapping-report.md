# APTrace Brownfield Mapping — Consolidated Report

*Produced by `/map-codebase` on 2026-10-16 from HEAD `a6395d7` (branch
`feat/pcode-indirect-target`).*

This report is for independent review. **It does not approve the
architecture.**
- *Execution and changes:* no tests were run, and no source,
  canonical-research or work state was changed.
- *Conflicts:* conflicting semantics are recorded, not reconciled. No
  implementation was treated as authoritative.
- *Uncommitted:* everything produced here is untracked documentation under
  `docs/arrows/`, `docs/intent/` and `docs/high-level-design.md`.

**How to read spec status:**
- `[x]` means observed in source only. It is not "tested" and not
  "approved".
- `[ ]` means unmet *approved* intent (CLAUDE.md or docs/).
- `[D]` means a documented deliberate exclusion. None were found.

**Companion:** `docs/arrows/cross-segment-findings.md` (the ranked register,
X1–X24).

---

## 1. Completion report

All 14 leaves are MAPPED and registered in `docs/arrows/index.yaml`, with
inverse `blocks`/`blockedBy` links.

In the paths below, `A` = `docs/arrows/` and `I` = `docs/intent/`.

| Segment | Arrow | LLD | EARS specs | Status | Specs | `[x]` | `[ ]` | `[D]` | Test coverage summary |
|---|---|---|---|---|---|---|---|---|---|
| production/target-loading | `A/production/target-loading.md` | `I/production/target-loading/target-loading-design.md` | `…/target-loading-specs.md` | MAPPED | 46 | 44 | 2 | 0 | 15 test-asserted (6 in the case suite) |
| production/structural-discovery | `A/production/structural-discovery.md` | `I/production/structural-discovery/structural-discovery-design.md` | `…/structural-discovery-specs.md` | MAPPED | 58 | 53 | 5 | 0 | 25 test-asserted (18 case suite or case cache) |
| production/census | `A/production/census.md` | `I/production/census/census-design.md` | `…/census-specs.md` | MAPPED | 66 | 63 | 3 | 0 | 34 test-asserted (19 case-owned or case artifacts); no test of STRONG → DEFINITELY_REACHABLE |
| production/static-dataflow | `A/production/static-dataflow.md` | `I/production/static-dataflow/static-dataflow-design.md` | `…/static-dataflow-specs.md` | MAPPED | 50 | 49 | 1 | 0 | 37 test-asserted (6 need Ghidra; some need the case census) |
| production/symbolic-execution | `A/production/symbolic-execution.md` | `I/production/symbolic-execution/symbolic-execution-design.md` | `…/symbolic-execution-specs.md` | MAPPED | 46 | 45 | 1 | 0 | 10 adapter-only; **0 harness-executing** |
| production/concrete-execution | `A/production/concrete-execution.md` | `I/production/concrete-execution/concrete-execution-design.md` | `…/concrete-execution-specs.md` | MAPPED | 48 | 46 | 2 | 0 | 10 tool-script (synthetic image; checks fail only via script exit), 11 adapter-only, 12 case-script; the machine core is tested only by case scripts |
| evidence-record | `A/evidence-record.md` | `I/evidence-record/evidence-record-design.md` | `…/evidence-record-specs.md` | MAPPED | 52 | 51 | 1 | 0 | 28 test-asserted (fake executors); wiring and `check` untested |
| claims/claim-semantics | `A/claims/claim-semantics.md` | `I/claims/claim-semantics/claim-semantics-design.md` | `…/claim-semantics-specs.md` | MAPPED | 33 | 33 | 0 | 0 | 29 test-asserted; edge extraction tested on Thumb mnemonics only |
| claims/admission | `A/claims/admission.md` | `I/claims/admission/admission-design.md` | `…/admission-specs.md` | MAPPED | 22 | 22 | 0 | 0 | 19 test-asserted |
| claims/verification | `A/claims/verification.md` | `I/claims/verification/verification-design.md` | `…/verification-specs.md` | MAPPED | 29 | 28 | 1 | 0 | 22 test-asserted; positive controls rely on fake independence envelopes |
| claims/audit | `A/claims/audit.md` | `I/claims/audit/audit-design.md` | `…/audit-specs.md` | MAPPED | 23 | 22 | 1 | 0 | 18 test-asserted (scripted model) |
| investigation/controller | `A/investigation/controller.md` | `I/investigation/controller/controller-design.md` | `…/controller-specs.md` | MAPPED | 33 | 32 | 1 | 0 | 24 test-asserted (fake planner) |
| investigation/continuity | `A/investigation/continuity.md` | `I/investigation/continuity/continuity-design.md` | `…/continuity-specs.md` | MAPPED | 16 | 16 | 0 | 0 | 11 test-asserted |
| investigation/work | `A/investigation/work.md` | `I/investigation/work/work-design.md` | `…/work-specs.md` | MAPPED | 22 | 22 | 0 | 0 | 18 test-asserted (3 only via tests that need the real Beads CLI) |
| **Total** | | | | | **544** | **526** | **18** | **0** | No `@spec` annotations exist in code |

**Group nodes** (`production`, `claims`, `investigation`) are MAPPED. Their
sub-HLDs and `docs/high-level-design.md` are deliberately **skeletons**,
pending review of this report.

**Not done, by instruction:**
- Phase 6 of `/map-codebase`: the `update-lid` CLAUDE.md configuration and
  deleting the transient sweep reports in `docs/arrows/_map-codebase/`. The
  sweep reports are kept as review evidence.
- Committing or pushing.

---

## 2. Cross-segment findings, ranked

The full register, with chains, citations, specs and OQs, is in
`docs/arrows/cross-segment-findings.md`. In ranked order:

**Tier A: evidence correctness and claim verification**

| Rank | ID | Finding | Concern | Level |
|---|---|---|---|---|
| 1 | X1 | Census STRONG candidates → DEFINITELY_REACHABLE → callback ESTABLISHED, and census-scoped reachability claims | confidence-promotion | contradicted / inferred |
| 2 | X10 | Census EXACT/STRONG edges → categorical `ESTABLISHED_INDIRECT` edges and STRONG pointer candidates | confidence-promotion | observed |
| 3 | X6 | Strongest-artifact grade ceiling plus status-keyed producer grades | confidence-promotion | observed |
| 4 | X2 | `function_effects` raw complete with bounded coverage → STRONG | confidence-promotion, completeness | observed |
| 5 | X12 | Effects MMIO accesses → `MMIO_USER` regardless of guard or solver-only region | correctness | observed / inferred |
| 6 | X18 | "Does not access" accepted on complete coverage, though callees are opaque (direct-only absence) | completeness | inferred |
| 7 | X4 | Bounded concrete observation → STRONG → session PROVEN | confidence-promotion | observed |
| 8 | X21 | All session facts PROVEN; the `proven` conclusion mixes evidence levels | confidence-promotion | observed |
| 9 | X11 | Ghidra seeded from census `fnptr-seeds`, census derived from Ghidra; `seeded` ignored | independence | observed |
| 10 | X24 | `capstone_sweep` seeded from Ghidra, documented as independent | independence | contradicted |
| 11 | X15 | No real source declares an independence envelope, so no production claim can newly reach VERIFIED (fail-closed, documented) | independence | observed |
| 12 | X14 | A coverage gap counts as falsification; a zero budget waives it | confidence-promotion | contradicted |
| 13 | X16 | HOLD demotes VERIFIED or BLOCKED to PROPOSED | lifecycle correctness | observed |
| 14 | X13 | Admission recomputes grades; verification uses stored grades | identity | inferred |

**Tier B: reproducibility, identity and reuse**

| Rank | ID | Finding | Concern | Level |
|---|---|---|---|---|
| 15 | X3 | Implementation and engine changes absent from operation, cache and ledger identity for most tools | identity, provenance | observed |
| 16 | X20 | Historical reuse across implementation changes for unversioned tools (documented) | identity | observed |
| 17 | X7 | Replay and phase C match on a cached adapter result without re-execution | identity, independence | observed |
| 18 | X5 | Grades frozen at first recording; grading unversioned | identity | inferred |
| 19 | X9 | Missing context inputs dropped silently; expected rather than observed firmware hash | identity | observed |
| 20 | X22 | Ten silent or weakly recorded incompleteness paths (Ghidra build and export truncation, census reduce failures, sweep bounds, dataflow drops, enrichment cap, log caps, FOLLOWED on failure, history truncation) | completeness | observed |

**Tier C: canonical-state safety**

| Rank | ID | Finding | Concern | Level |
|---|---|---|---|---|
| 21 | X8/X17 | `check` turns a missing blob into permanent invalidation; verification invalidates in prechecks too | canonical-state | observed / inferred |
| 22 | X19 | Ledger, research, audit, follow-up and work commands default to the canonical case ledger | canonical-state | observed |
| 23 | X23 | Nominally read-only paths that can write: census DB connection DDL, `macaw_compare`, Ghidra `decompile`/`disasm`, `work reconcile` lock files | canonical-state | observed / inferred |
| 24 | (Must Fix) | Two tests that might mutate canonical state | canonical-state | observed |

---

## 3. Must Fix items and unmet approved requirements

Nothing below was implemented.

### Must Fix (committed requirements)
| Spec | Outcome required | Source |
|---|---|---|
| PROD-TGT-TEST-001 | The Ghidra backend regression test leaves the canonical case Ghidra cache, including `meta.json`, unchanged whether it passes, fails or is interrupted | `tools/ghidra/test_aptrace_ghidra.py:38, 120-136` |
| PROD-DFLOW-TEST-001 | Static-dataflow regression tests do not expose a canonical census database to schema changes or any other mutation | `tools/census/test_indexed_writes.py:377-381` |

Read-only versus scratch-copy is left as an implementation decision.

### All unmet approved requirements (`[ ]`, 18)
| Spec | Required outcome (abridged) | Intent source |
|---|---|---|
| PROD-TGT-GH-018 | Ghidra build incompleteness (cancel, failure, partial seeding) is distinguishable from a complete build | CLAUDE.md Evidence discipline |
| PROD-TGT-TEST-001 | Must Fix (above) | CLAUDE.md Protecting state |
| PROD-DISC-GEXP-010 | A truncated Ghidra export is distinguishable from a complete one | CLAUDE.md |
| PROD-DISC-MACAW-009 | Macaw observations are bindable to firmware SHA-256 and Macaw engine identity | CLAUDE.md |
| PROD-DISC-IDX-005 | Call records missing attribution are accounted for or disclosed | CLAUDE.md |
| PROD-DISC-WIRE-002 | Bytes consumed by disassembly, callsite and pin-table operations are established as the recorded firmware | CLAUDE.md |
| PROD-DISC-SWEEP-004 | An exhausted Capstone sweep bound is reported as incomplete coverage | CLAUDE.md |
| PROD-CENSUS-PROV-001 | Derived census tables are bindable to census code version and configuration | CLAUDE.md |
| PROD-CENSUS-PROV-002 | Concrete runs entering the census record engine identity and harness assumptions | CLAUDE.md |
| PROD-CENSUS-PROV-003 | Scenario replay or hardware-snapshot failures during reduction are recorded as incompleteness | CLAUDE.md |
| PROD-DFLOW-TEST-001 | Must Fix (above) | CLAUDE.md Protecting state |
| PROD-SYM-ID-006 | `function_effects` results are bindable to the harness binary and engine versions | CLAUDE.md |
| PROD-CONC-OBS-005 | The code and doc state whether the custom Thumb decoding fills an engine gap or is a cross-check | CLAUDE.md Static dataflow rules |
| PROD-CONC-ADP-006 | `observed_call_arguments` results are bindable to the concrete engine version | CLAUDE.md |
| EVREC-ID-009 | Every evidence artifact is bindable to implementation and engine identity (name, version, ISA/ABI configuration) | CLAUDE.md |
| CLAIMS-VERIFY-SRC-007 | Structural observations used for verification carry the minimal common envelope | `docs/cross-engine-verification.md` §2 [Required] |
| CLAIMS-AUDIT-MEAS-005 | AutoPilot benchmark content lives under the owning case | CLAUDE.md Framework/case boundary |
| INV-CTRL-CASE-001 | No firmware-specific function addresses in framework planner and reconciliation prompts | CLAUDE.md Framework/case boundary |

---

## 4. Conflicting or duplicated architectural semantics

Recorded, not reconciled.

**Conflicting definitions or documentation**
1. **Strong graph.** `reachability.py` docstring (by site classification)
   vs code (EXACT/STRONG candidates). Census REACH-001/003/005,
   *contradicted*.
2. **What drives the effects grade.** The ledger grades `function_effects`
   on the raw `status`. The absence check uses the adapter's `coverage`.
   *Two notions of completeness for one result:* X2, X18.
3. **Edge confidence.** Pointer facts ignore it; call edges map EXACT/STRONG
   to categorical (claim-semantics).
4. **Missing blob.** `check` treats it as corruption; the verifier treats it
   as unavailable; the store allows `blobs-large/` outside version control.
5. **Grade source.** Admission and candidates recompute; verification reads
   the stored grade.
6. **`DERIVATION_RECORD_TRUNCATED`.** The walker labels it "analysis
   unaffected"; the driver treats it as incompleteness; the doc omits it
   (static-dataflow PCW-005, PCD-007).
7. **"ESTABLISHED".** It names three different things:
   - callback caller reachability (from census `DEFINITELY_REACHABLE`);
   - indirect-target derivation status;
   - the `ESTABLISHED_INDIRECT` edge kind.
8. **"Independent".**
   - `capstone_sweep` is documented as "completely independent" but is
     seeded from Ghidra.
   - Macaw independence is qualified.
   - Source agreement counts census + Ghidra as AGREE.
9. **Falsification.** The auditor's v0.4 docstring says failing requests do
   not count; the code counts coverage gaps.
10. **Precheck phases.** The CLI help says "A-C" and the audit-v0.5 comment
    says "A-C"; the code runs P.
11. **SAMD51 defaults.** `docs/case-boundary.md` records them as a seam;
    `unicorn-backend.md` says the engine assigns no target meaning.
12. **Ghidra cache root.** `ghidra-backend.md` says the case supplies it;
    the code hardcodes it.
13. **Vector-table reading.** The seed script skips `0xFFFFFFFF` and does
    not low-bit-clear extra seeds; `VectorTable.hs` differs.
14. **Call-edge addressing.** `fnptr_resolve` uses block start;
    `macaw_compare` uses the instruction address.
15. **`completed`.** A watch-cap stop counts as the objective reached
    (concrete RUN-003).
16. **Run identity.** The write-log cap is per run, but the help says per
    range.
17. **`ExecutionContext`.** The docstring names 5 artifacts; the context
    carries about 20. `Claim.basis` documented values differ from the
    values used.
18. **Default work actor.** `aptrace` in the adapter vs `aptrace-agent` in
    the CLI.

**Vocabularies that coexist**

19. **Confidence and grade vocabularies.** Their mapping is undefined
    (census OQ2, EVREC OQ8):
    - census candidate confidence: EXACT, STRONG, WEAK;
    - ledger `EvidenceGrade`: EXACT … UNKNOWN;
    - session `ClaimGrade`: PROVEN, SUPPORTED;
    - `ClaimState`;
    - `AuditVerdict`;
    - candidate fact grades.
20. **Version axes.** A wrapper `ANALYSIS_VERSION` vs a tool or engine
    version (static-dataflow OQ9). Continuity checks five tools.
    `structural_source_agreement`, the census readers and the disassembly
    tools have none.

**Duplicated mechanisms**

21. **Strong-graph semantics:** `reachability.py` vs `census_graph.py`.
22. **ARM `r0`-literal parsing:** two diverging copies
    (`lead_generation.py` vs `fact_derivation.py`).
23. **Z3 and memory setup:** copied in four Haskell harnesses.
24. **AAPCS sets and Thumb handling:** across the Capstone modules, with
    inconsistent Capstone modes (`THUMB` vs `THUMB | MCLASS`).
25. **Structural tool list:** `investigator.py` vs
    `controller.STRUCTURAL_TOOLS`.
26. **Thumb bit-0 normalization:** cleared in the gate, in claim semantics
    and in effects-target naming; not cleared for discovery naked
    addresses.
27. **Per-tool registration:** `TOOL_INPUTS`, the `evidence_grade` and
    `evidence_limitations` if-chains, the fact-derivation map, the
    projection tool lists, `current_analysis_versions` and the executor
    dispatch. That is the "~10 modules" integration cost.

---

## 5. Deferred Open Questions by decision area

The notation is `segment OQn`. Abbreviations:
- **Production:** TGT target-loading, DISC structural-discovery, CEN census,
  DF static-dataflow, SYM symbolic-execution, CONC concrete-execution.
- **Evidence record:** EV.
- **Claims:** SEM claim-semantics, ADM admission, VER verification, AUD
  audit.
- **Investigation:** CTRL controller, CONT continuity, WORK work.

There are 166 deferred OQs in all, and each is listed once.

| Area | Open Questions |
|---|---|
| **A. Identity, versioning, invalidation, provenance** | TGT 2, 3, 10 · DISC 1, 3 · CEN 6, 8 · DF 2, 7, 9 · SYM 1, 2, 5, 13 · CONC 1, 2 · EV 1, 2, 3, 4, 5 · CONT 1, 4, 6 · VER 9 |
| **B. Completeness and incompleteness representation** | TGT 1 · DISC 2, 6 · CEN 7, 10, 11 · DF 5, 6, 8 · SYM 8, 9, 10, 14 · CONC 3, 4, 5, 6, 7 · SEM 5 · CTRL 3, 4 · CONT 3 |
| **C. Confidence, grading and promotion** | CEN 1, 2, 4 · DF 4 · SYM 3, 4, 6 · CONC 13 · EV 6, 7, 8, 9 · SEM 1, 2, 3, 4, 6 · ADM 1, 2, 3, 4, 5 · CTRL 1, 2 · CONT 2 |
| **D. Independence and corroboration** | DISC 4, 5, 7 · CEN 5 · VER 1, 2, 3 · AUD 1, 2, 4 |
| **E. Lifecycle and verification semantics** | EV 11 · VER 4, 5, 6, 7 · CONT 5 |
| **F. Canonical-state protection** | TGT 4, 14 · DISC 16 · CEN 9 · DF 14 · EV 10, 12 · AUD 3 · WORK 1, 2 |
| **G. ISA and architecture boundary** | TGT 8, 9, 11 · DISC 8, 9 · CEN 13 · DF 10 · SYM 12 · CONC 8, 9 · SEM 8 · VER 8 · CTRL 6 |
| **H. Framework/case boundary and wiring** | TGT 5, 6, 7 · DISC 10, 11 · CEN 12, 14 · SYM 11 · CONC 10 · EV 13 · SEM 9 · ADM 7 · AUD 5, 7 · CTRL 5, 10 · WORK 6 |
| **I. Engine roles, harness modeling and migration** | TGT 12 · DISC 13, 14 · CEN 16, 17 · DF 1, 3, 11, 12 · SYM 7 |
| **J. Model runtime and planner** | ADM 6, 8 · AUD 6, 8 · CTRL 8, 9, 11 · EV 14 |
| **K. Tests** | DF 13 · SYM 16 · CONC 14 |
| **L. Semantics, naming and maintenance** | TGT 13 · DISC 12, 15 · CEN 3, 15 · SYM 15 · CONC 11, 12, 15 · EV 15, 16 · SEM 7, 10 · CTRL 7 · WORK 3, 4, 5 |

Per-segment OQ totals:

| Segment | OQs |
|---|---|
| TGT | 14 |
| DISC | 16 |
| CEN | 17 |
| DF | 14 |
| SYM | 16 |
| CONC | 15 |
| EV | 16 |
| SEM | 10 |
| ADM | 8 |
| VER | 9 |
| AUD | 8 |
| CTRL | 11 |
| CONT | 6 |
| WORK | 6 |

---

## 6. End-to-end evidence lifecycle

Each stage is marked with what happens to information there:

| Marker | Meaning |
|---|---|
| **P** | promoted to a stronger statement or grade |
| **F** | filtered, capped or dropped |
| **C** | cached |
| **G** | graded |
| **A** | admitted |
| **V** | verified, with a lifecycle effect |
| **R** | reused |

| # | Stage | Component (segment) | Marks | What happens |
|---|---|---|---|---|
| 1 | Image and target load | `FirmwareLoader`, vector table, Thumb policy (TGT) | F | Vector entries filtered (`0xFFFFFFFF` handling differs); Thumb bit normalized |
| 2 | Ghidra project build | `aptrace_ghidra` (TGT) | **C**, P, F | Persistent project cached by `meta.json` identity; **derived seeds from census `fnptr-seeds` fed back (P)**; cancelled or failed builds cached `fresh` (F, X22) |
| 3 | Structural exports | Ghidra exports, Macaw census, `capstone_sweep` (DISC) | F, P | Truncated exports unmarked; unattributed calls dropped; sweep seeded from Ghidra; Macaw seeded from the vector table |
| 4 | Census build and reduce | `tools/census` (CEN) | **G**, **P**, F | Candidate confidence EXACT/STRONG/WEAK (G); a dynamic observation upgrades to EXACT (P); EXACT/STRONG enter the strong graph → `DEFINITELY_REACHABLE` (**P**, X1); scenario failures printed only (F) |
| 5 | Static dataflow | Capstone tools, p-code walker (DF) | **P**, F | `DEFINITELY_REACHABLE` → caller `ESTABLISHED` (**P**); silent drops; derivation-record truncation (F) |
| 6 | Symbolic effects | `EffectsSpike`, `function_effects` adapter (SYM) | **C**, F, P | On-disk cache and negative cache keyed without binary identity (**C**); enrichment capped at 24 sites (F); solver-proven region labeled `(solver)` (P) |
| 7 | Concrete observation | `ConcreteMachine`, `observed_call_arguments` (CONC) | F | Log caps (silent for MMIO and RAM); scenario-scoped observations; unobserved ≠ impossible |
| 8 | Dispatch to session | `EvidenceExecutor` → `EvidenceObservation E#` (EV, CTRL) | — | Planner summaries attached |
| 9 | Session facts and leads | `StateFactDeriver`, `LeadDeriver`, projection (CTRL) | **P**, F | **Every derived fact PROVEN** (P, X21); lead caps and invalid-target issues (F); character budgets (F) |
| 10 | Historical reuse | `HistoricalOperations` (CONT) | **R**, F | Aliased reuse when inputs, key, validity, integrity and the version (five tools only) match (**R**, X20); truncated history unrecorded |
| 11 | Claim proposal and admission | `admit` (ADM, SEM) | **A**, **G**, P | Grade recomputed with current rules (G, X13); typed claims capped at the strongest-artifact ceiling (P, X6); untyped ≤ PROBABLE; census edges → categorical (X10); effects roles unguarded (X12) |
| 12 | Candidates | `generate_candidates` (ADM) | G, F, P | Facts ≥ PROBABLE; ceiling grade; withheld facts recorded (F) |
| 13 | Recording | `record_investigation`, `ResearchLedger` (EV) | **G**, **C**, **R** | Evidence grade and limitations computed **once** per evidence id (G, X5); content-addressed blob (C); the identical operation and result reuse one artifact across runs (R) |
| 14 | Ledger claim | `propose_claim` (EV) | P | Limitations inherited mechanically; state PROPOSED |
| 15 | Verification A–C | `ClaimVerifier` (VER) | **V**, C | References, context, semantics, ceiling (stored grade); replay through the adapter, so it may be served from cache (C, X7); mismatch invalidates permanently, prechecks included (X17) |
| 16 | Verification P | Gate, fresh source agreement (VER) | **V**, G | Fresh agreement recorded as evidence (grade STRONG unless CONFLICT); envelope required; none real, so UNEVALUABLE (X15) |
| 17 | Audit | `ClaimAuditor`, pipeline (AUD) | — (verdict) | Model verdict recorded; falsification satisfied by success or a coverage gap (X14); tool runs recorded as ledger evidence (X19) |
| 18 | Verification D and transition | Verifier, store (VER, EV) | **V** | VERIFIED needs gate PASSED + audit SUPPORTED + VERIFIED dependencies; HOLD → PROPOSED (X16); BLOCKED or STALE propagate staleness |
| 19 | Maintenance | `ledger_cli check` (EV) | **V** (invalidation) | A missing or corrupt blob is invalidated, claims staled (X8) |
| 20 | Follow-ups | `FollowUpGenerator`, `seed_session` (CONT) | **R**, F | Frontier re-derived with current code; gaps from audits and gates; preload as facts (R) |
| 21 | Work | handoff and Beads (WORK) | — | No ledger writes; links runs; completion never changes claim state |
| 22 | Report | `report` (EV) | — | A fingerprint over events, claim keys and audit names |

**Where conclusions get stronger:**
- *Producer status → ledger grade:* stage 13.
- *Grade → claim ceiling:* stage 11 for admission, stage 15 for
  verification.
- *Census confidence → reachability and categorical edges:* stages 4, 5 and
  11.
- *Observation or result → session PROVEN:* stage 9.
- *Audit verdict → verification:* stage 18.

**Where information is reused:** stages 2, 6, 10, 13, 15 and 20.

---

## 7. Proposed architecture-audit order

**Decisions that block trustworthy verification.** Audit these first, in
order:
1. **Confidence and promotion semantics (area C).**
   - census OQ1–2 (strong-graph rule, the meaning of EXACT);
   - claim-semantics OQ1–3;
   - evidence-record OQ6–8;
   - admission OQ1–4;
   - static-dataflow OQ4.

   *Why first:* X1, X10, X6 and X2 decide what an admitted claim's grade
   means, and every later decision depends on that vocabulary.
2. **Independence and corroboration (area D).**
   - verification OQ1–3 (envelope supplier, seeded lineage, next contract);
   - structural-discovery OQ1, 4–5, 7;
   - census OQ5;
   - audit OQ1–2, 4.

   *Why:* this is the only path to VERIFIED (X15, X11, X24, X14).
3. **Identity and invalidation contract (area A).**
   - evidence-record OQ1–5;
   - symbolic-execution OQ1–2;
   - concrete-execution OQ1–2;
   - continuity OQ1;
   - static-dataflow OQ9.

   *Why:* replay, reuse and verification phase C are only as trustworthy as
   the identities they compare (X3, X7, X20, X5, X9). This also covers six
   `[ ]` provenance requirements:
   - EVREC-ID-009;
   - PROD-SYM-ID-006;
   - PROD-CONC-ADP-006;
   - PROD-DISC-MACAW-009;
   - PROD-CENSUS-PROV-001/002.
4. **Incompleteness representation (area B).**
   - target-loading OQ1;
   - structural-discovery OQ2;
   - census OQ7;
   - static-dataflow OQ5–6;
   - symbolic-execution OQ4, 9;
   - concrete-execution OQ4, 7;
   - claim-semantics OQ5.

   *Why:* negatives must never be built from incomplete results (X22, X18).
   This covers the `[ ]` GH-018, GEXP-010, IDX-005, SWEEP-004 and PROV-003.
5. **Lifecycle semantics (area E).** Verification OQ4–7: HOLD demotion,
   automatic invalidation, missing blob, replay bypass (X16, X17, X8).
6. **Session evidence levels.** Controller OQ1–2 (X21, X4). These do not
   affect ledger claims, but they shape what the planner and humans read as
   "proven".

**Canonical-state safety.** Low cost; do these early, in parallel with 1–3:
- the Must Fix items PROD-TGT-TEST-001 and PROD-DFLOW-TEST-001;
- then area F: evidence-record OQ10, 12; work OQ1–2; census OQ9;
  structural-discovery OQ16; target-loading OQ4; audit OQ3.

**Ordinary maintenance and boundary debt.** Does not block verification
trustworthiness:
- **G, ISA and architecture boundary:** do this before a second-ISA case
  exists.
- **H, framework/case boundary and wiring:** includes the `[ ]`
  INV-CTRL-CASE-001 and CLAIMS-AUDIT-MEAS-005, and the operation-descriptor
  milestone for item 27 in §4.
- **I, engine migration:** the p-code migration plan and harness retirement.
- **J, model runtime.**
- **K, tests:** add synthetic, framework-owned tests for the concrete
  machine and the symbolic harnesses.
- **L, naming, stale references, duplication:** items 21–26 in §4.
