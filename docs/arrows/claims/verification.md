# Arrow: verification

The only component that moves claim state. It covers:
- the versioned verification policy (claim classes and evidence contracts);
- the phase-P policy gate (contradictions, structural conflicts,
  independent corroboration);
- the phased `ClaimVerifier`:
  - A, structural validity;
  - B, deterministic semantics;
  - C, replay and freshness;
  - P, policy;
  - D, dependencies and independent audit;
- the `structural_source_agreement` operation, which compares the census,
  Ghidra and Macaw at bounded addresses.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/claims/claims-design.md (skeleton)

### LLD
- docs/intent/claims/verification/verification-design.md

### EARS
- docs/intent/claims/verification/verification-specs.md (prefix `CLAIMS-VERIFY`; 29 specs: 28 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`, with fake executors and code sources (`ledger_support.FakeCodeSource`). Real sources declare no envelope; the tests supply one.
- **test_verification_policy.py:** 29 tests:
  - positive control;
  - material contradictions;
  - structural conflicts;
  - missing or same-lineage corroboration, derived sources, repeated runs;
  - envelope metadata;
  - mimicry;
  - comparison evidence reuse;
  - failed analysis;
  - classes without a contract;
  - gate non-bypass;
  - direct VERIFIED transition;
  - CLI parity;
  - policy identity;
  - historical decisions.

  `test_persisted_case_verifications_predate_the_policy` opens the canonical case ledger in place through read-only assessment.
- **test_ledger_audit.py (verifier parts):**
  - unknown evidence blocks;
  - replay mismatch → STALE;
  - drift holds;
  - ceiling blocks;
  - dropped limitations;
  - UNREACHABLE;
  - case benchmarks: USB, EIC (case fixtures);
  - CHALLENGED permanence.
- **test_claim_semantics.py:** phase B blocking before audit; valid `CODE_PRESENCE` → VERIFIED with an envelope; typed pointer held at P.
- **test_source_agreement.py:**
  - agreement classification;
  - file sources;
  - Ghidra index naming;
  - seeds in cache identity;
  - seeded USB targets. This one needs the case Ghidra cache.

### Code
- agent/src/aptrace_agent/ledger/policy.py
- agent/src/aptrace_agent/ledger/gate.py
- agent/src/aptrace_agent/ledger/verifier.py
- agent/src/aptrace_agent/source_agreement.py

### Related docs
- docs/cross-engine-verification.md, docs/research-ledger.md, docs/claim-admission.md, docs/status.md

## Architecture

**Purpose:** decide mechanically whether a claim version is VERIFIED,
BLOCKED, STALE or stays PROPOSED. An audit model's verdict is a
necessary input for VERIFIED, never a sufficient one. Missing corroboration
is never success (`policy.py:11-14`).

**Key components:**
1. **Policy** (`policy.py`):
   - *Identity:* id `aptrace-claim-verification`, version `1`, and a digest over the definition.
   - *Claim class:* computed from claim type and semantics only; the proposer never chooses it.
   - *Evidence contracts:* only `CODE_EXISTENCE` has one (`structural_source_agreement`, two disjoint lineages).
   - *Fail-closed:* every other class is UNEVALUABLE.
2. **Gate** (`gate.py`):
   - *Contradictions:* contradictory evidence is classified as CONTRADICTED, UNRESOLVED, UNEVALUABLE or NOT_MATERIAL.
   - *Structural conflicts:* a structural CONFLICT at a material address is CONTRADICTED.
   - *Corroboration:* code corroboration needs complete source envelopes, a matching firmware, not assisted, and disjoint lineage.
   - *Status precedence:* CONTRADICTED > UNRESOLVED/UNMET > UNEVALUABLE > PASSED.
3. **Verifier** (`verifier.py`):
   - *Phases:* A → B → C → P → D. A precheck stops after P.
   - *Outcome precedence:* BLOCK > STALE > HOLD (→ PROPOSED) > VERIFIED.
   - *Record:* every run writes a `VerificationRecord` with the policy identity.
   - *Ledger writes:* phase C can invalidate evidence. Phase P records a fresh source agreement as evidence.
4. **Source agreement** (`source_agreement.py`):
   - *Classification:* per address, CONFLICT, SOURCE_MISSING, BOUNDARY_DISAGREEMENT, PARTIAL_AGREEMENT or AGREE, over census DB, Ghidra export and Macaw census sources.
   - *Lineage:* `derived_from` and `seeded` are recorded per observation.
   - *Envelope:* passed through only when a source declares one.

## Spec Coverage

`[x]` means observed in source only. Tests marked *envelope-supplied* pass
only because fake sources declare an independence envelope that no real
source declares. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Policy | CLAIMS-VERIFY-POL-001 to 003 | 3 | 0 | 0 | 3 |
| Gate | CLAIMS-VERIFY-GATE-001 to 007 | 7 | 0 | 0 | 5 |
| Verifier phases | CLAIMS-VERIFY-PH-001 to 008 | 8 | 0 | 0 | 7 |
| Outcome and lifecycle | CLAIMS-VERIFY-OUT-001 to 004 | 4 | 0 | 0 | 4 |
| Source agreement | CLAIMS-VERIFY-SRC-001 to 007 | 6 | 1 (SRC-007) | 0 | 3 |

**Summary:** 28 of 29 specs are observed in source.
- **Approved-intent gap:** SRC-007, the minimal common envelope that
  `docs/cross-engine-verification.md` §2 marks [Required].
- **Observed, not approved:** OUT-002 (HOLD demotes VERIFIED or BLOCKED to
  PROPOSED) and GATE-005 (`seeded` ignored). Both are recorded for decision.
- **Contradicted:** PH-007 (CLI help).

22 specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **No production claim can newly reach VERIFIED under policy v1.**
   - *Contracts:* only `CODE_EXISTENCE` has an evidence contract.
   - *Envelopes:* it requires each source's independence envelope (`lineage`, `firmware_sha256`, `engine_version`). None of the three real sources declares one (`source_agreement.py:466-480`; `structural_wiring.py:297-323`).
   - *Status:* this is documented (`docs/status.md:300-312`; `docs/cross-engine-verification.md:355-358`) and fail-closed by design. The documented `[Required]` minimal common envelope is therefore unmet.
2. **A HOLD outcome moves a claim to PROPOSED from any current state other than SUPERSEDED or STALE**, including VERIFIED and BLOCKED (`verifier.py:436-439, 469-477`).
   - *Test:* `test_verification_policy.py` (`test_historical_verified_decisions_are_preserved_and_distinguished`) asserts VERIFIED → PROPOSED.
   - *Gap:* that a BLOCKED version can return to PROPOSED when a later verification only holds is not tested for the same version `[inferred]`.
3. **Verification writes to the ledger.**
   - *Phase C:* invalidates evidence on a hash mismatch or a replay mismatch, during prechecks too, and that stales other claims citing it (`verifier.py:258-321`).
   - *Phase P:* records a fresh `structural_source_agreement` invocation and evidence under a `VG` run (`:391-407`).
   - *Destination:* the CLI default ledger is the canonical case ledger (evidence-record CLI-001).
4. **A replay match can come from a cached adapter result.** For `function_effects`, phase C "deterministic replay … identical" can reflect an adapter cache hit rather than re-execution (evidence-record OPS-005; cross-segment X7).
5. **Without replay, drift holds.** With replay off, input-artifact drift is HOLD. A missing blob is HOLD, or re-derived when replay is on (`verifier.py:258-316`). Contrast with `ledger_cli check`, which invalidates on a missing blob (evidence-record X8).
6. **The source agreement does not record its own provenance.**
   - *Lineage:* census declares `derived_from ghidra`, and Macaw is seeded only from vector roots.
   - *Seeds:* the Ghidra project is seeded with census-derived function-pointer targets (`tools/ghidra/aptrace_ghidra.py:125-148`, written by `aptrace_census.py fnptr-seeds`). Observations carry a `seeded` label. Neither the gate nor claim semantics reads `seeded`.
   - *Version:* the operation has no `ANALYSIS_VERSION`, and its result has no provenance block.
   - *Grade:* status AGREE needs two recognizing sources, so census + Ghidra suffices for a STRONG agreement grade (evidence-record GRD-007), with a `SOURCES_NOT_INDEPENDENT` limitation.
   - *Cross-segment:* X11.
7. **Untyped claims are never VERIFIED.** They are class UNDETERMINED (except `NO_KNOWN_PATH` → BOUNDED_NEGATIVE and `PATH_EXISTS` → CONTROL_FLOW, which also lack contracts). Typed pointer, role, path and call claims have no contract either.
8. **Thumb normalization is applied to every address in the gate.** "The Thumb state bit is not part of an address" is applied regardless of ISA (`gate.py:60-62`). The `VECTOR_MAPPING` class is a Cortex-M concept.
9. **The gate asserts that only `CODE_EXISTENCE` reaches corroboration** (`gate.py:340`). A new evidence contract for another class would raise until this is extended.
10. **Phase D blocks on any earlier challenge.** It ignores diagnostic audits, and any CHALLENGED audit blocks the version permanently. A model verdict of SUPPORTED is required for VERIFIED (`verifier.py:356-373`; claims/audit).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* The canonical-ledger test uses read-only
assessment. Verification writes to the ledger by design, as an operator or
autonomous action, not a test.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Real structural sources declare no independence envelope.** This is an approved-intent gap: CLAIMS-VERIFY-SRC-007 `[ ]` (Finding 1).
2. **HOLD demotes VERIFIED or BLOCKED versions to PROPOSED** (Finding 2).
3. **A cache-served replay counts as an identical replay** (Finding 4; cross-segment X7).
4. **Seeded or derived observations are recorded but ignored by the gate and by code-presence checks** (Finding 6; cross-segment X11).
5. **Phase C invalidation is permanent and also runs during prechecks.** An environment-caused replay difference would invalidate evidence `[inferred; not demonstrated]` (Finding 3).

### Architectural coupling
6. **Thumb bit-0 normalization and the Cortex-M `VECTOR_MAPPING` class in the framework gate** (Finding 8).
7. **The source-agreement wiring hardcodes three case-bound sources** (`structural_wiring.py`).

### Semantic inconsistencies
8. **Missing blob:** HOLD in the verifier, invalidation in `ledger_cli check` (Finding 5; evidence-record CLI-003).
9. **`ledger_cli --precheck` help says A–C;** the precheck runs P.

### Maintenance debt
10. **The `CODE_EXISTENCE`-only assertion in the gate** (Finding 9).
11. **No `ANALYSIS_VERSION` on source agreement** (Finding 6).
