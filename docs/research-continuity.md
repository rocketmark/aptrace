# Research Continuity: Using Prior Operations in Follow-up Investigations

> APTrace must use the work it has already performed to make better research
> decisions, without confusing reused evidence with newly established facts.

A follow-up investigation (created with `aptrace-agent followups`, see
[`spikes/investigation-continuity.md`](spikes/investigation-continuity.md))
starts from an earlier run. Without continuity, the ResearchController
judged "already run" from the current session only. It therefore re-executed
the source run's analyses and ranked the follow-up's own leads last.
Continuity fixes that deterministically inside the existing controller. It
adds no planner, scheduler, or cache.

Code: `agent/src/aptrace_agent/research/history.py`, plus small changes to
`research/session.py`, `research/controller.py`, `research/projection.py`,
and `ledger/recorder.py`. It is active only when a follow-up session is
seeded with history (`seed_session(..., history=...)`), which the
`research --ledger --work-item` path does for follow-up items. Standalone
research is unchanged.

## Three kinds of research state

| Kind | Where | Counted as this run's evidence |
|---|---|---|
| historical analysis | `ToolInvocation` + evidence of the source run, earlier attempts at the same follow-up, and the candidate's cited evidence (`HistoricalOperations`, ≤ 256 invocations) | never |
| current-session analysis | the session `EvidenceLedger` (`E1, E2, …`) | only entries the session executed |
| pending leads | `ResearchState.leads`; follow-up leads carry `origin = "followup:<key>"` | — |

A historical result used in the session gets a session alias (`E3`) whose
`EvidenceObservation.reused_from` names the original evidence id. The
planner can see and cite it, and the projection marks it `(E3=prior)`.

The recorder treats the alias differently from executed evidence:

- It writes **no** `ToolInvocation` for it.
- It does **not** add it to `InvestigationRun.evidence_ids`.
- It maps references to `E3` (claims, lead sources) to the original evidence
  id.

The reuse itself is recorded in `InvestigationRun.continuity.reused`, with
the original invocation, evidence, source run, operation key, trigger, and
step.

## When a historical result may be reused

`HistoricalOperations.lookup(tool, arguments)` finds historical invocations
with the same tool and canonical arguments. Approximate or text matching is
never used. It then checks the following, in order; the first failure is
the recorded refusal reason:

1. the tool is deterministic and replay-verifiable (`DETERMINISTIC_TOOLS`;
   case-document search reads mutable prose and is always re-executed);
2. the historical invocation succeeded and its evidence exists;
3. same firmware sha256 and firmware key;
4. identical input-artifact hashes for that tool (`TOOL_INPUTS`), so the
   ledger's `operation_key` recomputed under the current context equals the
   recorded one (`census_db` drift refuses census reuse but not Ghidra-only
   tools);
5. evidence `VALID` (not invalidated by `aptrace-agent check`);
6. the result blob is present and passes its content-hash check;
7. for tools that declare an analysis version (`function_effects`
   `provenance.analysis_version`), the current version.

Reusable results are used and never re-executed. Re-running a compatible
deterministic operation cannot add information. Deeper analysis is a
*different* operation (for example, function effects with `r0` specialized),
which has a different identity and runs normally.

An incompatible historical result does not block execution: the operation
runs, and the refusal and its reason are recorded in
`continuity.refused`. A lead is satisfied by history only when its own
operation is identical. Inspecting a function never resolves a call-site
lead into it.

## Controller policy (continuity-v1)

| Rule | Effect |
|---|---|
| **No rerun** | `ResearchSession.follow_lead` (the single execution point) checks history first; a compatible result is used by reference |
| **Prerequisites** | the candidate's cited, reusable prior results are preloaded as references: facts only, no derived leads (the seeded leads are the frontier), no step |
| **Seeded leads first** | open follow-up leads rank first, are always in the visible lead set, render with `[follow-up]`, and the decision prompt gains rule `0)` while any is open |
| **Discovery gating** | `analyze_peripheral` / `analyze_usb_interface` are withheld while follow-up leads are open; a request for one is rejected with that reason |
| **Executed caps** | the per-run caps on census, path and effects analyses count executed analyses only |
| **Planner failure** | when the planner produces no valid decision after its correction (`planner_contract_exhausted`), APTrace follows the top open follow-up lead (`fallback_lead`, at most 3) instead of ending the run; when none is left, a run that did work still gets the bounded final-claims request before it ends |

The planner still chooses among follow-up leads, other leads, effects,
paths, and finishing. Nothing forces an execution order except the bounded
fallback.

## Budget

- An executed action charges one step (`max_steps`).
- A reuse charges nothing for the first 4 reuses (`max_free_reuses`) and
  one step after that, still without executing anything. Decisions are
  therefore at most `max_steps + max_free_reuses`, and a planner that keeps
  asking for prior analyses cannot loop.
- A request for an analysis already in the session, executed or reused, is
  rejected deterministically. It is retried without that tool, and the tool
  is withheld for two decisions (existing behaviour).
- Fallback steps are charged like any other action.

Every follow-up run records the budget in `continuity.budget`:
`max_steps`, `steps_charged`, `decisions`, `free_reuses`, `fallbacks`.

## Seeded-lead tracking

`continuity.seeded_leads` gives each follow-up lead one outcome, using the
existing lead lifecycle (`OPEN` / `FOLLOWED`) plus what the tracker
observed:

| Outcome | Meaning |
|---|---|
| `executed` | followed; the operation ran in this run |
| `reused` | followed; satisfied by a compatible historical result |
| `attempted-failed` | followed; the tool raised |
| `offered` | shown to the planner, never followed |
| `not-offered` | never shown |

These are mechanical outcomes. Whether an executed lead *answered* the
follow-up question is not decided by the controller. That is a claim, and
claims are verified as before.

## Provenance guarantees

- Original invocations, evidence, and blobs are never rewritten.
- A run's `invocation_ids` and `evidence_ids` contain only what it
  executed.
- Reused results are listed separately, with the original ids.
- Claims citing a reused alias cite the original evidence id; verification
  semantics are unchanged.
- `ToolInvocation.input_evidence_ids` names only durable evidence that
  existed before the invocation.

## Limitations

- Tool implementation changes without a declared analysis version are not
  detected at reuse time. `aptrace-agent replay` detects them by hash.
- History is bounded to the source run, earlier attempts at the same
  follow-up, and cited evidence. Other runs' identical operations are not
  consulted.
- Preloading adds the cited prior facts to the planner state. The
  projection's total budget still bounds it.
- The fallback follows the planner-ranked top follow-up lead. It does not
  judge which lead is most informative.
