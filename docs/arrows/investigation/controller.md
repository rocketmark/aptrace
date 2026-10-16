# Arrow: controller

APTrace's own investigator. It covers:
- **The research loop:** a bounded, model-directed loop (`ResearchController`)
  and its session plumbing: session state, evidence ids, the lead registry
  and lead following.
- **Derivation and presentation:** deterministic lead and fact derivation;
  the planner projection.
- **Case reconciliation.**
- **The one-shot path:** route, then execute, then synthesize.
- **Case search:** documentary search of the case.
- **Entry points:** the `aptrace-agent` CLI.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/investigation/investigation-design.md (the `investigation` sub-HLD; skeleton)

### LLD
- docs/intent/investigation/controller/controller-design.md

### EARS
- docs/intent/investigation/controller/controller-specs.md (prefix `INV-CTRL`; 33 specs: 32 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`, with fake planners, executors and reconcilers. No model endpoint is called, except where noted.
- **Loop:**
  - `test_research_controller.py` (termination, retries, discovery, reconciliation trigger);
  - `test_research_session.py`, `test_research_state.py`, `test_state_updates.py`;
  - `test_follow_lead.py`, `test_function_facts_flow.py`.
- **Leads:** `test_lead_derivation.py`, `test_lead_generation.py`, `test_discovery_leads.py`, `test_dynamic_leads.py`, `test_case_search_leads.py`, `test_outgoing_function_leads.py`.
- **Facts:** `test_fact_derivation.py` (pin table, callsite literal), plus the per-tool fact tests in `test_scenario_observation.py`, `test_value_forward_use.py` and `test_callback_provenance.py`.
- **Planner palette and gating:**
  - `test_agent_v0.py`, `test_census_planner.py`;
  - `test_scenario_observation.py` (palette);
  - `test_value_forward_use.py` (experimental opt-in: `test_value_trace_requires_explicit_opt_in`, `test_default_session_does_not_offer_value_trace`, `test_investigator_default_withholds_value_trace`, `test_cli_opt_in_is_explicit`).
- **Reconciliation, case search, router, CLI:** `test_reconciliation.py`, `test_case_evidence.py`, `test_router.py`, `test_autonomous_cli.py`.
- **Case data in fixtures:** `FUN_0000d3dc`, `FUN_00006968`, `PA22` and `TMC5160` appear as fixture strings. `test_case_evidence.py` searches the real case documents.

### Code
- agent/src/aptrace_agent/research/{`__init__`, controller, session, state, state_updates, evidence, leads, follow, derivation, lead_generation, fact_derivation, projection, reconciliation}.py
- agent/src/aptrace_agent/investigator.py, router.py, synthesizer.py, model.py, case_evidence.py, cli.py

### Related docs
- docs/aptrace-agent-framework.md, docs/codex-operator.md, docs/status.md, docs/claim-candidates.md, docs/tooling/pcode-forward-use.md

## Architecture

**Purpose:** APTrace owns evidence, provenance, execution, deduplication,
budgets and structural lead resolution. The model chooses direction,
proposes claims and hypotheses, and decides sufficiency
(`research/__init__.py:1-10`).

**Key components:**
1. **`ResearchSession`:**
   - deterministic plumbing with no model policy;
   - sequential evidence ids `E<n>` and opaque lead ids `L<n>`, whose tool and arguments the model never sees;
   - following a lead runs: execute, record, derive facts, derive leads;
   - historical reuse in follow-up sessions (investigation/continuity).
2. **`ResearchController.run`:**
   - **Palettes:** per-decision palettes (`follow_lead`, grounded structural tools under budgets, `finish`) and a discovery palette.
   - **Planner calls:** one tool call per response, validated deterministically, with one correction and prefill-rejection retries.
   - **Termination:** seven stop reasons.
   - **Claim contract (optional):** at finish, parsing, admission with one correction round, candidate selection, and terminal reconciliation.
3. **`StateFactDeriver`:** turns structurally explicit results into atomic state claims, each graded `PROVEN` with a basis tag, plus open questions.
4. **`LeadDeriver` and `lead_generation`:** turn results into validated leads and records generation issues.
5. **`PlannerProjection`:** a bounded, character-budgeted planner view, plus `conclusion()` with `proven`, `probable` and `open`.
6. **`CaseReconciler`:** model-assisted reconciliation of case-document searches with structural claims. It produces `SUPPORTED`, never `PROVEN`.
7. **Entry points:**
   - `investigator.run_autonomous_investigation` and `run_investigation` (one-shot: router, executor, synthesizer);
   - `cli.main` (`investigate`, `research`, ledger, work and follow-up commands).

## Spec Coverage

`[x]` means observed in source only. Tests use fake planners, executors and
reconcilers. No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Session plumbing | INV-CTRL-SES-001 to 004 | 4 | 0 | 0 | 4 |
| Fact derivation | INV-CTRL-FACT-001 to 003 | 3 | 0 | 0 | 3 |
| Lead derivation | INV-CTRL-LEAD-001 to 003 | 3 | 0 | 0 | 2 |
| Palette and gating | INV-CTRL-PAL-001 to 003 | 3 | 0 | 0 | 3 |
| Planner I/O and termination | INV-CTRL-LOOP-001 to 007 | 7 | 0 | 0 | 3 |
| Finish, claims, reconciliation | INV-CTRL-FIN-001 to 006 | 6 | 0 | 0 | 4 |
| Case and ISA content | INV-CTRL-CASE-001 to 004 | 3 | 1 (CASE-001) | 0 | 2 |
| Entry points | INV-CTRL-ENTRY-001 to 003 | 3 | 0 | 0 | 3 |

**Summary:** 32 of 33 specs are observed in source.
- **Approved-intent gap:** CASE-001, a firmware-specific address in a
  framework prompt.
- **Observed design behavior, not approved:**
  - FACT-001: uniform `PROVEN` for session facts;
  - FIN-006: the `proven` conclusion bucket;
  - SES-003: FOLLOWED regardless of status.

  These are recorded for decision.

24 specs have an asserting test. No `@spec` annotations exist.

## Key Findings

1. **Every derived session fact is graded `PROVEN`.**
   - *What it covers:* `StateFactDeriver` merges every derived statement with `ClaimGrade.PROVEN` (`research/fact_derivation.py:780-790`). That includes:
     - concrete scenario observations (`concrete-observed`);
     - raw-symbolic Crucible facts;
     - static-dataflow "may escape" statements;
     - census statements.
   - *Where the evidence level lives:* only in the basis tag and the wording.
   - *Conclusion:* `projection.conclusion` lists all of them under `proven` (`research/projection.py:543-578`).
   - *Vocabularies:* two grade vocabularies coexist, session `PROVEN`/`SUPPORTED` and ledger `EvidenceGrade`.
   - *Status:* these are session state, not ledger claims, and they do not pass admission. CLAUDE.md requires evidence levels to be kept distinct. This is recorded as an Open Question, not a defect. Cross-segment X4.
2. **A merge never downgrades.** A duplicate session claim becomes `PROVEN` if either copy is (`research/state_updates.py:53-69`), and the existing basis is kept.
3. **Experimental tools are gated.** `value_forward_use` is offered only when explicitly opted in, because admission cannot yet validate its value-flow assertions. Leads that would run it are hidden (`controller.py:48, 226-241, 273, 1452-1458`). This matches CLAUDE.md ("do not expose new unchecked tools there by default"), and is test-asserted.
4. **Case and ISA content sit in framework modules.**
   - *Reconciliation prompt:* `FUN_0000d3dc` is hardcoded: "Do not re-analyze FUN_0000d3dc" (`research/reconciliation.py:386`).
   - *Pin table:* "the Performing Rigs logical pin table" (`lead_generation.py:456`), and pin-table leads exported at package level.
   - *ARM `r0`-literal parsing:* duplicated in two diverging copies (`lead_generation.py:379-444`; `fact_derivation.py:21-101`).
   - *ARM in the planner:* `r0`/`r1` in the tool schema; "blx/bx register" text (`controller.py:447, 482`).
   - *Thumb bit:* cleared when naming effects call targets (`derivation.py:207-217`).
   - *Case search:* hardcoded case roots, and `pa##`/`pb##` boosts (`case_evidence.py:49-63, 295-305`).
5. **Reconciliation matches English templates.** `CaseReconciler` finds structural provenance by regex over the English templates of `fact_derivation`'s claims (`reconciliation.py:136-206`). A change to fact wording silently changes what reconciliation can support `[inferred]`.
6. **A returned failure counts as followed.**
   - *`LeadFollower`/`ResearchSession`:* a lead is marked FOLLOWED once the executor returns, without checking the result status (`follow.py:43-51`; `session.py:149`).
   - *Exceptions:* they propagate out of `run` (`controller.py:2082, 2129, 2137, 2142`).
7. **Planner I/O is shaped by the local runtime.**
   - *Claims as one string:* because "the local planner's tool-call output degenerates on nested arrays" (`controller.py:60-62`).
   - *Compact projection:* retries after an oMLX prefill rejection (`controller.py:160-172, 1183-1243`).
   - *Budgets:* projection budgets are in characters.
   - *Environment-driven:* planner logging can write full prompts to a JSONL file (`controller.py:1248-1269`).
   - *Endpoint check:* `model.py` refuses non-local endpoints. The controller's own planner client and the reconciler build OpenAI clients from the environment, with no such check (`controller.py:243-260`; `reconciliation.py:54-64`) `[observed]`.
8. **The structural tool list is duplicated.** `investigator.py:228-236` repeats `controller.STRUCTURAL_TOOLS` minus the experimental tools, rather than deriving from it.
9. **The one-shot path is unadmitted.** `run_investigation` produces free-text LLM synthesis with no claim admission (`synthesizer.py`). It is separate from the ledger path.
10. **The CLI records with the ledger only when asked.** `research --ledger` enables the claim contract and recording. Without `--ledger` there is no ledger recording and no claim contract (`cli.py:296-370`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.*

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Uniform `PROVEN` for session facts across evidence levels**, and a `proven` conclusion bucket (Finding 1; cross-segment X4).
2. **A lead is FOLLOWED regardless of the returned status** (Finding 6).
3. **Reconciliation's provenance depends on fact wording** (Finding 5).

### Architectural coupling
4. **AutoPilot function address in the framework reconciliation prompt.** This is an approved-intent gap: INV-CTRL-CASE-001 `[ ]` (Finding 4).
5. **Pin table, ARM `r0`-literal parsing, `r0`/`r1` and Thumb-bit naming, and SAM pin boosts in framework modules** (Finding 4).
6. **The structural tool list is duplicated in `investigator.py`** (Finding 8).
7. **The auditor imports the private `_prefill_rejected`** (claims/audit).

### Semantic inconsistencies
8. **Two diverging copies of `r0`-literal parsing** (Finding 4).
9. **`Claim.basis` documented values vs values used.** `static-table`, `disassembly` and `census-graph` are not listed (`state.py:30-35`).
10. **Endpoint locality is enforced only in `model.py`** (Finding 7).

### Maintenance debt
11. **`controller.py` is 2,155 lines,** with dead code (`_sanitize_claims` unused internally; the `origin` dead variable at `:1480`).
12. **Runtime-specific workarounds** (Finding 7).
13. **Case-flavored fixture strings in framework tests.**
