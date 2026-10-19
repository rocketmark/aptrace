# Objective-bounded investigation v1: remote-to-motor comparison

On 2026-10-19 the framework gained objective-bounded research runs. The
contracts are in
[`docs/objective-bounded-investigation.md`](../../../../docs/objective-bounded-investigation.md).
This page compares them with the two failed autonomous runs recorded in the
[APTrace assessment](remote-to-motor-aptrace-assessment.md). It is a record
of agent behaviour. **No firmware conclusion here is new, and nothing was
promoted.**

- **Regression references (unchanged, SHA-256 prefix):**
  - `research/runs/agent/remote-to-motor-2026-10-17.json` (`c1b35f96ed177d59`)
  - `research/runs/agent/remote-to-motor-focused-2026-10-19.json` (`9ddc76e2f61d0fcb`)
- **Objective specs:** [`research/objectives/`](../../research/objectives/).
  They restate each run's verbatim question and add relations taken from the
  operator [causal graph](../../research/generated/remote-to-motor-causal-graph.json).
- **Live runs:** [`research/runs/agent/objective-bounded-v1/`](../../research/runs/agent/objective-bounded-v1/).

## What caused the observed failures

| Observation | Cause | Status |
|---|---|---|
| Objective constraints lost | The planner's prose objective was clipped silently at 640 characters (`ProjectionBudget.objective`). Run 1's objective has 1,017 characters, so the planner never saw "avoid broad census", "do not infer full end-to-end execution", the Gemma instruction or the cessation question. | **Confirmed** from the artifact and the code. |
| Eight steps on PORT inventory | 1. Rule 1 of the decision prompt said "a subsystem the objective names is not under ALREADY RUN: analyze it", and the objective names STEP/DIR/GPIO. 2. Census-derived leads rank first (`_STRUCTURAL_SOURCES`). 3. No objective-named function was offered as a lead. 4. Nothing measured progress. The trajectory: discovery search, `analyze_peripheral(PORT)`, a duplicate PORT request, then five `function_facts`/`function_disassembly` calls on PORT users. | **Confirmed** from the trajectory and planner requests. That the clipped constraint contributed is **plausible, not provable**: the clipped text was never shown to the model. |
| `vl-ampersand` chosen for an F0 jog question | The scenario note collapsed all eleven virtual-link scenarios into `vl-*: short protocol slices…`, and the enum lists them alphabetically, `vl-ampersand` first. Nothing tied a scenario to the objective. | **Confirmed** from the code and the request; there is no planner prompt log. Why Qwen picked that particular entry is **hypothesis** (first enum value). |
| Effects timeout re-requested | After the 300 s timeout (E3), Qwen asked for the same analysis again in the next request. The duplicate guard dropped it silently. Nothing told the planner the analysis had failed. | **Confirmed** (request 2 has no decision; the tool was withheld). |
| Budget exhausted, empty conclusion | No progress test and no stall stop. The final conclusion lists only derived facts and planner open questions. Run 2 ended with empty proven, probable and open lists. | **Confirmed.** |
| Gemma never reviewed | `_reconcile_terminal` requires non-discovery case search. | **Confirmed**, and out of scope here (no Gemma changes). |

## Replaying the original choices (deterministic)

`test/test_objective_bounded_regression.py` re-issues Qwen's recorded choices.
Function facts come from the real, freshness-checked Ghidra index. Every other
operation is answered only from the saved results. An unsaved operation gets
an explicit replay failure, never an invented result.

| Original choice | Under objective-v1 |
|---|---|
| Run 1: discovery search | Withheld: endpoint leads exist and discovery is off. Rejected with a reason; the correction follows an endpoint. |
| Run 1: `analyze_peripheral(PORT)` | Not offered. No peripheral is named by the question or terms. Rejected and recorded. |
| Run 1: PORT-user crawl (`FUN_0000d388`, …) | Those leads are never derived. The census did not run, and they are more than one hop from an endpoint. |
| Run 2: `function_effects(FUN_00005448)` | Runs once. Recorded `failed` with "not absence of effects", shown as `FAILED (do not repeat)` and as an R3 blocker. |
| Run 2: repeated effects request | Rejected as a duplicate; the timeout stays visible. |
| Run 2: `observe(FUN_00005448, vl-ampersand)` | Rejected: "no established relevance … relevant scenarios: vl-manual-f0e0". The scenario enum offers only `vl-manual-f0e0`, matched on the terms `f0` and `manual`. |
| Both: budget end | Run 2's replay stops with `objective_stalled` after three low-value steps, with a REPLAN notice before the stop. Both runs emit `objective_report`: per-relation level, blockers, what is missing, and "composition: not attempted". |

Applying the tracker afterwards to the original evidence shows how little each
run established about the declared relations:

| Run | Relations |
|---|---|
| Run 1 | All six relations UNRESOLVED. |
| Run 2 | R1 and R2 STATIC (seed facts); R3 UNRESOLVED; the timeout and the failed ampersand observation recorded as blockers. |

## Bounded live Qwen runs

The planner was `Qwen3-Coder-30B-A3B-Instruct-4bit` through local oMLX, at
temperature 0. Each run reproduced its original command and budget, adding
`--objective-file`. Run 1 used `--ledger` with a scratch `--ledger-dir`; the
canonical ledger was untouched. The `-v0` artifacts are the first attempt. The
final-code runs followed two fixes that v0 motivated (described under "What v0
changed").

### Focused follow-up: `--function FUN_00005448 --max-steps 4`, 13 s

| | Original 2026-10-19 | Live (final code) |
|---|---|---|
| Steps | effects (timeout), observe under **vl-ampersand** (failed), facts `0x4d18`, facts `0xe0fc` | 1. observe `FUN_00005448` under **vl-manual-f0e0**; 2. observe `FUN_00004d18` under **vl-manual-f0e0**; 3. effects `FUN_00005448` (cached timeout); 4. callsite `FUN_00005448@0x5496` |
| Rejected or repeated | effects repeated (silent) | effects repeated (rejected as a duplicate); no unrelated scenario requested |
| Relations | none tracked | **R1 OBSERVED** (E3: `FUN_00008258` observed calling `0x5448`, r0=0, 2 entries, vl-manual-f0e0 harness assumptions); **R2 STATIC**, blocked: `FUN_00004d18` not entered under vl-manual-f0e0 (E4), so a scenario-coverage gap; **R3 UNRESOLVED**, blocked: effects timeout (E5), so a capability gap |
| End | `step_budget_exhausted`, empty conclusion | `step_budget_exhausted` with `objective_report`; R2 and R3 recorded as open questions |

R2's blocker is consistent with the causal graph: the operator's `0x4d18`
entry (E09) came from a separate seeded RX run, not from this scenario. **R1 is scenario-scoped concrete evidence under
seeded virtual-link state. It is not natural command reception.**

### Original objective: `--max-steps 8 --ledger`, 41 s

| | Original 2026-10-17 | Live (final code) |
|---|---|---|
| Steps | search, PORT census, 5 PORT-user facts/disassembly, facts `0x77a0` | facts `0x5898`, facts `0x5448`, observe `0x5448`@F0, observe `0x5898`@F0, effects `0x5448` (cached timeout), facts `0x607c`, `0x5c00`, `0x5ee8` |
| Steps on unrelated inventory | 7 of 8 | **0 of 8**. Every step targets a relation endpoint. |
| Relations | none tracked (retroactively all UNRESOLVED) | **R1 OBSERVED**; **R2, R4 STATIC**; **R3 UNRESOLVED** (effects timeout); **R5 UNRESOLVED** (no direct Ghidra call edge `0x607c`→`0x5898`, so it needs a path capability; `0x5898` not entered under F0); **R0 UNRESOLVED** (`mando868:0xbe94`, other image, so it needs a multi-image capability) |
| Proposed claims | C10–C13: PORT structural roles | one PROBABLE BEHAVIOR claim, "FUN_00005448 observed under vl-manual-f0e0" (scratch ledger; admission unchanged) |
| Final reason (Qwen) | n/a | "concrete evidence is missing to confirm causal relationships … No complete end-to-end path can be confirmed" |

### What v0 changed

- **TC0 inventory from a label.** The first live run of the original objective
  spent step 1 on a TC0 census, because R5's *label* says "TC0 handler".
  Candidate selection then offered six TC0 MMIO-user claims, and Qwen selected
  all six. This is the same failure shape as C10–C13.
- **The fixes.**
  - Relation labels no longer request peripheral inventory.
  - In a focused run, claim candidates are offered only for relevant
    functions. The rest are recorded as `CANDIDATE_OUTSIDE_OBJECTIVE`.
- **Earlier refinements.** The focused v0 run led to these, before the final
  runs:
  - Effects blockers are attributed only to the edge they bear on.
  - Each relation shows the operation it needs.
- **Wording only.** After the final runs, the missing-evidence text now names
  scenario-coverage gaps and single-edge (path) gaps. The reports above were
  recomputed from the saved evidence with the final tracker. That computation
  is deterministic, and the levels are identical.

## Did the agent stay on the F0 objective?

Yes, within what the contracts enforce:

- No step went to inventory, an unrelated scenario, or an off-objective lead.
- Both runs found the one relevant scenario.
- The F0 observation produced the only concrete edge.
- Both runs ended with a defensible unresolved report.

Qwen still made avoidable choices:

- It requested a known-timed-out analysis while "FAILED (do not repeat)" was
  displayed (caught as a duplicate).
- It spent steps on facts and callsites that changed no relation.
- It proposed a vague observation claim.

## Remaining capabilities for reliable autonomous causal investigation

1. **Path relations.** A relation is one call edge, so R5 (TC0 ISR to STEP
   helper) cannot be STATIC. This needs `find_common_paths`-style path
   evidence per relation.
2. **Scenario coverage.** No registered scenario enters `0x4d18` or `0x5898`.
   This needs the caller-grounded witness and carried-state scenarios already
   listed in the assessment (RX→`0x5448`→`0x4d18`, TC0 IRQ delivery,
   jog→click/silence).
3. **Address endpoints.** The busy gate `0x20001b14` can be related only by
   completed symbolic effects, and those time out for `0x5448`. This needs
   bounded effects (specialization or callee summaries) or watched-field links
   to the observation tool.
4. **Multi-image relations.** R0 (Remote sender → AutoPilot RX) needs a
   two-image scenario or composition capability.
5. **Composition.** Per-edge levels need a scope-preserving, weakest-link
   composition and its verification before any end-to-end claim. Neither
   exists, by design.
6. **Terminal review.** The Gemma review path still never runs for these runs,
   and the model residency problem (HTTP 507) remains.
7. **Report persistence.** The ledger records the objective spec, but the
   per-relation report lives only in the run artifact.
8. **Relevance-aware claim semantics.** An admitted claim can still be
   uninformative ("observed under …"). Admission checks support, not
   usefulness.
