# Arrow: evidence-record

The durable research ledger and the glue that feeds it. It covers:
- **Storage:** append-only, content-addressed records.
- **Identity:** operation, invocation, evidence and execution-context
  identity.
- **Evidence judgment:** per-tool evidence grading and mechanical limitation
  codes; the claim grade ceiling.
- **Lifecycle:** store-enforced claim lifecycle rules.
- **Operations:** operation execution and replay; recording a completed
  investigation.
- **Interfaces:** the ledger CLI and the Markdown report.
- **Application wiring:** the operation dispatcher (`executor.py`) and the
  case wiring (`ledger_wiring.py`, `structural_wiring.py`) that binds
  operations to inputs and evidence identity.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)

### LLD
- docs/intent/evidence-record/evidence-record-design.md

### EARS
- docs/intent/evidence-record/evidence-record-specs.md (prefix `EVREC`; 52 specs: 51 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`. Unless noted, they use a fake executor (`ledger_support.FakeExecutor`) and a temporary ledger. No analysis engine runs.
- **test_ledger.py:**
  - persistence and round-trip;
  - operation, invocation and evidence identity;
  - supersession, immutability, inherited limitations;
  - tamper staleness, dependency staleness, invalidation propagation;
  - report fingerprint, volatile metadata, the large-blob tier.
- **test_ledger_audit.py (evidence-record parts):**
  - VERIFIED transition ownership;
  - replay mismatch and input drift;
  - replay needs no model; case search is not replayable;
  - recorder mapping (`test_recorder_maps_session_evidence_and_keeps_unknown_references`).

  It also reads case benchmark fixtures under `cases/performing-rigs/research/benchmarks/ledger-v0`.
- **Per-tool grading and limitations:** `test_observed_call_arguments.py`, `test_callback_provenance.py`, `test_indirect_call_target.py`, `test_value_forward_use.py`, `test_source_agreement.py`, `test_agent_v0.py` (function_effects).
- **Historical identity forms:** `test_scenario_observation.py` (`test_effects_specialization_defaults_normalize_only_when_equivalent`, `test_historical_omitted_form_record_is_found_by_both_spellings`).
- **Canonical case ledger, read in place or copied:**
  - `test_audit_stability.py:248-268` copies it to tmp;
  - `test_verification_policy.py:639-653` opens it in place through read-only assessment;
  - `test_call_relations.py:511-534` opens it in place and asserts its tree digest is unchanged;
  - `test_work_handoff.py:143-157` reads `runs/` in place;
  - `test_claim_quality.py:296-310`.

  The code paths observed are reads. They are recorded as canonical-state touchpoints, not defects.
- **Not covered:** `executor.py` dispatch, `ledger_wiring.context_artifacts`, `structural_wiring` binding and `ledger_cli check` have no direct framework test.

### Code
- agent/src/aptrace_agent/ledger/{`__init__`, models, store, hashing, operations, semantics, recorder, report}.py
- agent/src/aptrace_agent/ledger_cli.py
- agent/src/aptrace_agent/ledger_wiring.py, structural_wiring.py (application and case wiring; recorded framework/case seams)
- agent/src/aptrace_agent/executor.py (operation dispatcher)
- agent/src/aptrace_agent/schemas.py

### Related docs
- docs/research-ledger.md, docs/claim-admission.md, docs/cross-engine-verification.md
- docs/case-boundary.md (its seam list does not include the agent wiring modules), docs/architecture.md, docs/status.md

## Architecture

**Purpose:** turn each typed APTrace operation into durable, reproducible,
judged evidence. That is:
- a record of what ran, on which inputs;
- the result, stored by content hash;
- a mechanical grade and limitations;
- a lifecycle that only APTrace code can move.

**Key components:**
1. **`ResearchLedger` (store.py):**
   - *Write-once records:* JSON records under a directory tree. A semantically equal rewrite is a no-op; a different one raises.
   - *Content-addressed blobs:* in two tiers, with results above 4 MiB going to `blobs-large/`.
   - *Event-folded claim state:* claim state is folded from `events.jsonl`.
   - *Policy-checked transitions:* only APTrace actors may append events, and VERIFIED needs a passing current-policy verification.
   - *Staleness:* propagates over `depends_on`.
2. **Identity:**
   - `operation_key` = digest(tool, canonical arguments, declared input-artifact hashes, firmware SHA-256);
   - `invocation_id` = digest(run, seq, operation key);
   - `evidence_id` = digest(operation key, result SHA-256);
   - `context_id` = digest(case, firmware key and SHA-256, all artifact hashes).

   `TOOL_INPUTS` declares which context artifacts enter each tool's key.
3. **Evidence semantics (semantics.py):**
   - one `evidence_grade` rule chain per tool (EXACT > STRONG > PROBABLE > BOUNDED > UNKNOWN);
   - `evidence_limitations` codes;
   - `grade_ceiling` for claims;
   - canonicalization of arguments (defaults) and results (volatile fields).
4. **`LedgerOperationRunner` (operations.py):**
   - runs an operation through the executor, records an invocation and evidence, and turns exceptions into error invocations;
   - `replay` re-runs a recorded invocation and compares result hashes, with input drift and a bounded diff.
5. **Recorder (recorder.py):** maps a completed session (E1…En) into durable invocations and evidence. It does not re-execute. It also records the planner's proposals, admission records and candidate selection.
6. **Application wiring:**
   - `executor.EvidenceExecutor` dispatches 14 tool names to case-bound readers and runners;
   - `ledger_wiring` binds the case name, ledger, report and work paths, and the context artifacts;
   - `structural_wiring` binds runners to case geometry, binaries, scripts and `*_INPUTS` source files.
7. **CLI and report:** `ledger_cli` (13 subcommands, defaulting to the case ledger); `report` renders Markdown with a ledger fingerprint.

## Spec Coverage

`[x]` means observed in source only. Tests use fake executors and temporary
ledgers unless marked canonical-read. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Storage and immutability | EVREC-STO-001 to 005 | 5 | 0 | 0 | 4 |
| Identity | EVREC-ID-001 to 009 | 8 | 1 (ID-009) | 0 | 5 |
| Evidence grade | EVREC-GRD-001 to 007 | 7 | 0 | 0 | 5 |
| Limitations | EVREC-LIM-001 to 004 | 4 | 0 | 0 | 2 |
| Grade ceiling | EVREC-CEIL-001 | 1 | 0 | 0 | 1 |
| Store-enforced lifecycle | EVREC-LIFE-001 to 006 | 6 | 0 | 0 | 5 |
| Operations and replay | EVREC-OPS-001 to 005 | 5 | 0 | 0 | 2 |
| Recording | EVREC-REC-001 to 005 | 5 | 0 | 0 | 2 |
| Application wiring | EVREC-WIRE-001 to 005 | 5 | 0 | 0 | 1 |
| CLI and report | EVREC-CLI-001 to 005 | 5 | 0 | 0 | 1 |

**Summary:** 51 of 52 specs are observed in source.
- **Approved-intent gap:** ID-009, making every evidence artifact bindable to
  its implementation and engine identity (CLAUDE.md "Evidence discipline").
  Its mechanism is in LLD Open Question 1.
- **Contradicted:** CLI-003 (missing blob treated as corruption) and CLI-004
  (stale precheck help).
- **Observed behavior, not approved guarantees:** GRD-003, GRD-004, GRD-005
  and CEIL-001 record grade rules (see the cross-segment register).

28 specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **The identity of an implementation is uneven across tools.**
   - *Source in the key:* `TOOL_INPUTS` hashes implementation source for the Unicorn harness, the census dataflow tools and the p-code walker and driver (`ledger/operations.py:31-56`; `structural_wiring.py:127-207`; `value_forward_use.py:42-46`).
   - *No implementation identity in the key:*
     - `function_effects` (the Haskell binary);
     - `census_*` readers (`census.py`, `census_graph.py`);
     - `function_facts` (`ghidra_index.py`);
     - `function_disassembly` and `callsite_context` (`disassembly.py`, Capstone);
     - `pin_table_entry`, which has an empty input tuple (`operations.py:54`).
   - *Run level:* each investigation run records the git commit, branch and a dirty fingerprint (`operations.py:75-102`; `models.py` `InvestigationRun.source`). Nothing records the vendored engines, the Haskell build, the Ghidra install, or Python package versions.
2. **Grade and limitations are frozen at the first recording.**
   - *First recording:* `record_invocation` writes an evidence artifact with its grade and limitations only when the `evidence_id` is new (`store.py:228-260`).
   - *Later recordings:* an identical operation with an identical result reuses the existing artifact, including its old grade and basis.
   - *Unversioned semantics:* the grading semantics carry no version identity on the artifact (`models.py:408-429`). A change to `evidence_grade` therefore affects only evidence first recorded after it `[inferred]`.
3. **The grade ceiling takes the strongest supporting artifact.** `grade_ceiling` returns the maximum grade over all supporting artifacts, documented as "as strong as its strongest supporting derivation". A `BOUNDED` artifact counts as `STRONG` for `NO_KNOWN_PATH` claims (`semantics.py:489-509`).
4. **Grades key on statuses the producer emits.** Recorded here with the producing segment; none is shown to have yielded a wrong claim.
   - *`function_effects`:* `complete*` → `STRONG` regardless of the adapter's bounded coverage (symbolic-execution PROD-SYM-GRD-001).
   - *`observed_call_arguments`:* status `ok` or `bounded…` with entries → `STRONG`, which is test-asserted (concrete-execution).
   - *Census results with resolved indirect edges:* the census edge-confidence minimum is applied, so `EXACT` or `STRONG` census candidates pass through (census Open Question 1).
   - *`function_disassembly`, `callsite_context`, `pin_table_entry`:* `EXACT`, "decoded from the hash-verified firmware image". Boundaries come from Ghidra and are heuristic (structural-discovery).
5. **Replay re-runs the operation, not necessarily the engine.**
   - *What it does:* `replay` calls the same executor path (`operations.py:198-246`).
   - *`function_effects`:* the adapter serves the on-disk cache when an enriched file exists, and `provenance.cached` is stripped before hashing so a cache hit "matches" (`semantics.py:88-99`; symbolic-execution LLD "Cache identity"). A replay match for a cached result therefore shows cache consistency, not re-execution.
   - *Other tools:* whether any other adapter caches is not established here.
6. **Missing artifacts silently change identity.**
   - *Dropping:* `context_artifacts` drops any input file that does not exist (`ledger_wiring.py:71`), so the operation key changes without a recorded reason.
   - *Hash source:* the context firmware SHA-256 is the configured expected hash, not a freshly computed one (`ledger_wiring.py:79-80`). Adapters that run subprocesses check the image themselves.
   - *Timing:* the context is computed when the run is recorded, after the session (`ledger_cli.py:528`) `[inferred]`.
7. **A missing blob means different things in different places.**
   - *`ledger_cli check`:* treats a missing blob like a hash mismatch. It permanently invalidates the evidence with reason "stored result hash mismatch" and stales the claims that cite it (`ledger_cli.py:337-356`).
   - *The verifier:* treats a missing blob as unavailable, which holds verification (claims/verification).
   - *The store:* says a case may keep `blobs-large/` out of version control (`store.py:61-63`).
   - *Consequence:* running `check` on such a checkout would invalidate large evidence in the default, canonical case ledger `[inferred failure path; not demonstrated]`.
8. **Claims can be written without admission.** `ledger_cli propose` and `supersede` write claim versions directly from JSON specs (`ledger_cli.py:256-270`). Verification still applies.
9. **Every ledger command defaults to the canonical case ledger.** `--ledger-dir` and `APTRACE_LEDGER_DIR` override it (`ledger_cli.py:33`; `ledger_wiring.py:43-44`).
10. **The framework is case-wired.**
    - `ledger_wiring` hardcodes `CASE_NAME = "performing-rigs"`, the case ledger, report and benchmark paths, and the SVD `ATSAMD51J19A.svd` (`ledger_wiring.py:31-40, 57`).
    - `structural_wiring` executes the case's `performing_rigs.py` for geometry on every call (`:35-60`).
    - `executor` builds only `performing_rigs_*` and `autopilot_*` readers (`executor.py:42-53`).
    - `semantics` special-cases the `virtual-link` scenario kind.
11. **Recorded configuration differs from the configuration used.** `record_research_run` records `execution_config` as constants (temperature 0.0, `max_tokens` 512, `local-omlx`), not values read from the controller (`ledger_cli.py:536`). `planner_version` is a digest of the controller and projection source (`recorder.py:65-68`).
12. **Records are immutable and history stays compatible.**
    - *Records:* frozen and `extra="forbid"`. Unset optional fields are omitted from serialization so older records stay byte-identical (`models.py:238-245, 359-367`; `schemas.py:88-95`).
    - *Keys:* `operation_keys` also yields the key over the recorded arguments, so records written before defaults were canonicalized still match (`store.py:190-200`).
13. **Concurrency is not handled.** Claim ids are allocated as the maximum existing id plus 1, event sequence numbers as the event count plus 1, and there is no locking (`store.py:316-319, 465-470`).
14. **The report fingerprint has a narrow scope.** It covers events, claim keys and audit file names, not evidence, runs or verifications (`store.py:673-680`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.*
- *Tests:* the tests that touch the canonical case ledger copy it, or use
  code paths observed to be read-only; `test_call_relations.py` asserts the
  tree digest is unchanged.
- *`ledger_cli check`:* it can modify the canonical ledger by design. It is
  an operator command, not a test, and is recorded below as an
  evidence-integrity risk.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Evidence identity omits implementation and engine identity for most tools** (Finding 1).
2. **Grades are frozen at first recording**, with no semantics version (Finding 2).
3. **A replay match can come from a cache hit** (`function_effects`), not a re-execution (Finding 5).
4. **Missing input files are dropped from the context**, which silently changes operation keys (Finding 6).
5. **`check` turns a missing blob into a permanent invalidation** in the canonical ledger by default (Finding 7).
6. **Grades and the ceiling can promote evidence** (cross-segment register).
   - *Ceiling:* the strongest-artifact ceiling (Finding 3).
   - *Producer statuses:* status-keyed producer grades (Finding 4).

### Architectural coupling
7. **Case-specific wiring at the framework root.** That covers the case name, paths, SVD part, geometry by executing case Python, and case-bound readers (Finding 10).
8. **Adding a tool means hand edits in several places:** `TOOL_INPUTS`, the `evidence_grade` and `evidence_limitations` if-chains, and the context artifacts.
9. **The ledger package imports `research`.** Specifically, `recorder.py:161` imports `research.candidates` lazily (claims and investigation cross-reference).

### Semantic inconsistencies
10. **Missing blob:** `check` treats it as corruption; the verifier treats it as unavailable (Finding 7).
11. **Recorded `execution_config` constants** vs the actual controller configuration (Finding 11).
12. **`ledger_cli` help says `--precheck` runs "Phases A-C only"**, but the precheck also runs P (`ledger_cli.py:78`; verification segment).
13. **`ExecutionContext` docstring** names five artifact kinds; the context carries about twenty (`models.py:96-101` vs `ledger_wiring.py:53-71`).

### Maintenance debt
14. **No locking** for claim ids or event sequence numbers (Finding 13).
15. **The report fingerprint has a narrow scope** (Finding 14).
16. **Glue has no direct tests:** `executor`, `ledger_wiring` and `structural_wiring`.
17. **`structural_wiring` re-executes case Python per call;** `REPO_ROOT` is duplicated.
