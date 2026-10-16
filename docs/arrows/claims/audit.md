# Arrow: audit

Model-facing adversarial review of one claim version, and the measurement
around it. It covers:
- the bounded auditor (`ClaimAuditor`) and its typed tool allowlist;
- the verification-gated audit pipeline;
- audit stability measurement;
- known-answer ledger benchmarks;
- the model-runtime determinism probe;
- the AutoPilot trigger-role benchmark description.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/claims/claims-design.md (skeleton)

### LLD
- docs/intent/claims/audit/audit-design.md

### EARS
- docs/intent/claims/audit/audit-specs.md (prefix `CLAIMS-AUDIT`; 23 specs: 22 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`. They use the scripted, OpenAI-shaped `ScriptedAuditModel` and fake executors. No model endpoint is called.
- **test_ledger_audit.py (audit parts):**
  - persistence;
  - a context without investigator reasoning;
  - verdict parsing;
  - toolbox rejections, rejection feedback;
  - budgets;
  - verdict before falsification;
  - coverage gap;
  - duplicates;
  - benchmarks (`usb-callback`, `eic-convergence`; case fixtures under `cases/performing-rigs/research/benchmarks/ledger-v0`).
- **test_audit_stability.py:**
  - compact provenance;
  - falsification counting;
  - fingerprint determinism and components;
  - immutable history;
  - the stability summary.

  `test_historical_stale_ghidra_audit_remains_readable` copies the canonical case ledger, without `blobs-large`, to tmp first.
- **test_claim_semantics.py:** semantic failure blocks before the audit model; diagnostic audits never count; fingerprint covers semantics; the `semantic-usb-eic` case benchmark.
- **test_runtime_probe.py:** request hashing and response comparison with no live runtime.

### Code
- agent/src/aptrace_agent/ledger/auditor.py
- agent/src/aptrace_agent/ledger/pipeline.py
- agent/src/aptrace_agent/ledger/stability.py
- agent/src/aptrace_agent/ledger/benchmark.py
- agent/src/aptrace_agent/runtime_probe.py
- agent/benchmarks/trigger-role.md (AutoPilot content; flagged for the case)

### Related docs
- docs/research-ledger.md (three authorities), docs/claim-admission.md, docs/status.md

## Architecture

**Purpose:** give a second model a bounded chance to falsify a claim with
typed APTrace analyses. The verdict is a recorded artifact that never
changes claim state. Verification phase D requires SUPPORTED for VERIFIED,
and blocks permanently on any CHALLENGED (`auditor.py:1-12`).

**Key components:**
1. **`ClaimAuditor`:**
   - *Context:* builds a compact context. It includes the claim, typed semantics and check summaries, grade, scope, assumptions, limitations, dependencies, compact evidence and structural agreement. It excludes the investigator's derivation.
   - *Tools:* offers an allowlist of typed tools whose arguments APTrace validates and executes through the ledger runner.
   - *Falsification:* enforces a falsification-before-verdict rule and decision and tool budgets.
   - *Record:* writes an `AuditRecord` with a ten-component input fingerprint.
2. **`audit_if_eligible`:** runs a verifier precheck. It calls the audit model only if phases C and P passed and the claim is not BLOCKED, STALE or SUPERSEDED. Otherwise it records a diagnostic audit, never counted, or skips.
3. **`stability_summary`:** groups audits by (claim version, input fingerprint). It reports verdict, tool-sequence and first-tool agreement, and a coverage-gap heuristic.
4. **`run_benchmark`:** runs fixture setup operations, proposes fixture claims, audits through the gate and verifies. It compares the outcome against a hidden `expected.json`.
5. **`runtime_probe`:** sends byte-identical chat requests and compares response hashes.

## Spec Coverage

`[x]` means observed in source only. Tests use a scripted model; no model
endpoint is called. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Audit loop and authority | CLAIMS-AUDIT-AUD-001 to 007 | 7 | 0 | 0 | 7 |
| Toolbox | CLAIMS-AUDIT-TOOL-001 to 005 | 5 | 0 | 0 | 5 |
| Audit records | CLAIMS-AUDIT-REC-001 to 004 | 4 | 0 | 0 | 2 |
| Gated pipeline | CLAIMS-AUDIT-PIPE-001 to 002 | 2 | 0 | 0 | 1 |
| Stability, benchmarks, probe | CLAIMS-AUDIT-MEAS-001 to 005 | 4 | 1 (MEAS-005) | 0 | 3 |

**Summary:** 22 of 23 specs are observed in source.
- **Approved-intent gap:** MEAS-005, AutoPilot benchmark content under
  `agent/`, against the CLAUDE.md case boundary.
- **Contradicted:** AUD-004, where coverage gaps count as falsification
  against the v0.4 docstring.

18 specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **A coverage gap counts as a successful falsification.**
   - *Rule:* `FALSIFYING_OUTCOMES` includes `executed:coverage_gap`, which covers a runner `KeyError`, `LookupError` or `FileNotFoundError` (`auditor.py:126-130, 1133-1136`). A verdict, including SUPPORTED, is accepted after an analysis that only reported a coverage gap.
   - *Docstring:* the module history says "only a successful new evidence operation satisfies the falsification requirement (rejected, duplicate, invalid, or failing requests do not)" (`:47-50`).
   - *Test:* `test_coverage_gap_counts_as_executed_but_is_not_contradictory` asserts the code's behavior.
   - *Classification:* recorded as `contradicted`, code vs docstring. Which is intended is undecided.
2. **A zero tool budget waives falsification.** `satisfied = counts["successful"] > 0 or max_tool_requests == 0` (`auditor.py:1182`). The CLI always sets the budget to at least 1 (`ledger_cli.py:119`). An API caller with a zero budget gets verdicts accepted with no falsification.
3. **Audit tool runs write to the ledger.** Every executed audit tool runs through `LedgerOperationRunner` under the audit id, and is recorded as invocations and evidence.
   - *Peripheral discovery:* `find_common_paths` can trigger a `census_peripheral_usage` run for an unanalyzed catalog peripheral (`auditor.py:564-580`).
   - *Source agreement:* recorded before the audit (`:939-952`).
   - *Destination:* the default ledger is the canonical case ledger (evidence-record CLI-001).
4. **The model and endpoint are runtime-specific.**
   - *Model:* the default audit model is `gemma-4-26b-a4b-it-4bit`, overridable through `APTRACE_REVIEW_MODEL`.
   - *Endpoint:* an OpenAI-compatible endpoint from `OMLX_BASE_URL` and `OMLX_API_KEY`, with a 240-second timeout. Prefill-memory rejections are retried after a sleep (`auditor.py:59, 911-937, 1029-1041`).
   - *Probe:* `runtime_probe.post` has no localhost restriction, unlike `model.py`.
5. **The auditor depends on controller internals.** It imports the private `research.controller._prefill_rejected` (`auditor.py:36`), and also `research.projection`. These form a ledger → research dependency.
6. **The toolbox carries case and ISA vocabulary:**
   - an `analyze_usb_interface` tool;
   - a hardcoded `USB` set;
   - the `TCC1` example;
   - "MCU peripheral";
   - `r0`/`r1` 32-bit argument ranges;
   - a "(Thumb bit cleared)" provenance note (`auditor.py:256-286, 453-674`).
7. **Benchmarks and fixtures are case-owned or case-shaped.**
   - *Framework benchmark runner:* hardcodes the `USB` set (`benchmark.py:128-131`).
   - *Fixtures:* the framework tests use case fixtures.
   - *`agent/benchmarks/trigger-role.md`:* entirely AutoPilot content (`FUN_0000d3dc`, PA22) under `agent/`, contrary to the CLAUDE.md case-boundary rule. No code references it.
8. **Fingerprints and history are compatible.** The input fingerprint has ten components and no timestamps. `_claim_identity` excludes `created_at`, and excludes semantics when there are none, so earlier fingerprints stay valid (`auditor.py:845-892`).
9. **Stability is a heuristic.** Its coverage-gap detection is a regex labeled "evaluator-side heuristic that never affects state" (`stability.py:22-29`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* The canonical-ledger audit test copies the
ledger first.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **A coverage gap satisfies falsification before a SUPPORTED verdict**, contradicting the v0.4 docstring (Finding 1).
2. **A zero tool budget waives falsification** (Finding 2).
3. **Audits write evidence to the default canonical ledger,** including peripheral analyses the audit triggered (Finding 3).

### Architectural coupling
4. **The auditor imports a private controller helper and the projection** (Finding 5).
5. **The toolbox and benchmark runner carry USB, SAM and Thumb vocabulary** (Finding 6).
6. **`trigger-role.md` (AutoPilot) sits under `agent/`.** This is an approved-intent gap: CLAIMS-AUDIT-MEAS-005 `[ ]` (Finding 7).

### Semantic inconsistencies
7. **Falsification counting:** the v0.4 docstring vs the code (Finding 1).
8. **The `audit-v0.5` docstring says phases "A-C"**; the pipeline requires C and P (`auditor.py:54-56` vs `pipeline.py:33-39`).

### Maintenance debt
9. **Model and runtime coupling:** the default model name, the oMLX environment, prefill retries; the probe has no localhost check (Finding 4).
10. **The stability coverage-gap heuristic** (Finding 9).
