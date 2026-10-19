# Terminal Review v1: remote-to-motor comparison and live results

On 2026-10-19 the framework gained a deterministic terminal assessment for
every focused run, adversarial review by Gemma, and sequential oMLX model
residency. The design is in
[`docs/terminal-review.md`](../../../../docs/terminal-review.md). This page
is a record of agent and runtime behavior.

**No firmware conclusion here is new, nothing was promoted, and no claim
state changed.** Gemma's criticism is advisory, and it is reported here
separately from what APTrace established.

- **Regression references.** These are unchanged. Their SHA-256 values are
  pinned in `test/test_terminal_review_regression.py`.
  - `research/runs/agent/remote-to-motor-2026-10-17.json` (`c1b35f96ed177d59`)
  - `research/runs/agent/remote-to-motor-focused-2026-10-19.json` (`9ddc76e2f61d0fcb`)
  - `research/runs/agent/objective-bounded-v1/live-{focused,drift}-2026-10-19.json`
  - `research/ledger/audits/A-20261019T133615-906232.json` (`ac8ff6aeee851050`, the HTTP 507 audit)
- **New live material.**
  [`research/runs/terminal-review-v1/`](../../research/runs/terminal-review-v1/)
  holds the run artifacts, their logs, and the write-once review store
  `reviews/`.
- **F0/ISR review fixture.**
  [`scripts/terminal_review_f0_isr.py`](../../scripts/terminal_review_f0_isr.py).

## Causes

| Observation | Cause | Status |
|---|---|---|
| Both autonomous runs skipped Gemma | `ResearchController._reconcile_terminal` runs the only review path, case reconciliation, and only after a non-discovery `search_case_evidence`. Focused runs do no such search. | **Confirmed** from the code. The replay shows `reconciled: False` with no case search. |
| Diagnostic audit failed with HTTP 507 | oMLX evicts only *idle* models before a load (`engine_pool._find_lru_victim` skips models with active requests). The server log at 09:36:15 shows the 507 for Gemma ("current: 16.80GB, model: 15.26GB", ceiling 19.00 GB). A Qwen completion that was in flight then finished at 09:36:41 after 43.4 s. Qwen therefore could not be evicted. | **Confirmed** from the oMLX log and source. Which process issued that Qwen request is **not established**. |
| An errored focused run would leave no report | Exceptions in the controller loop propagated out of `run` (INV-CTRL-LOOP-005). | **Confirmed** from the code. It is now handled for focused runs only (INV-CTRL-TR-002). |

## Comparison with the original runs (deterministic, no model)

| Run | Original | Under Terminal Review v1 |
|---|---|---|
| Run 1, 2026-10-17 (drift) | `step_budget_exhausted`. Gemma never ran. No relation report. | The assessment is recomputed from the saved artifact (`assessment_from_artifact` with the case spec). All six relations are UNRESOLVED, as the objective-v1 comparison recorded. The replay under objective-v1 is assessed too. It keeps R0's multi-image gap as a stated limitation and records the rejected discovery search and PORT census. |
| Run 2, 2026-10-19 (focused) | `step_budget_exhausted`, empty conclusion, Gemma never ran. | The replay stops `stalled`. R1 and R2 are STATIC and R3 is UNRESOLVED. The 300 s effects timeout is a failed operation and an R3 blocker. The `vl-ampersand` request is a rejected operation. The run had no case evidence and no claim proposals, and it is still eligible for review: a scripted review completes. |
| objective-bounded-v1 live runs | `objective_report` only, Gemma never ran. | Assessed from the artifacts alone, with relation levels identical to the saved report and a reproducible hash. In the focused run, R1 (OBSERVED, `vl-manual-f0e0`, 5 harness assumptions) and R2 (STATIC) are reported as a join whose continuity is not validated. |

## Live end-to-end test (Qwen → unload → Gemma → unload → Qwen)

Models and settings are unchanged:

- planner: `Qwen3-Coder-30B-A3B-Instruct-4bit`;
- reviewer: `gemma-4-26b-a4b-it-4bit` (oMLX 0.7.0; context 40,000, model
  `max_tokens` 2,048; review request at temperature 0.0, `max_tokens` 2,000);
- memory: ceiling 19.00 GB (custom), not raised.

Run 1 reproduced the focused follow-up:

```
aptrace-agent research --objective-file research/objectives/remote-to-motor-focused-2026-10-19.objective.json \
  --function FUN_00005448 --max-steps 4 --output .../live-focused-2026-10-19.json --review-dir .../reviews
```

No `--ledger` was used, and the canonical ledger is untouched. The
function-effects cache listing was byte-identical before and after the live
runs.

| Step | Run 1 (focused, `TR-78cf8cd5aece72d3`) | F0/ISR package (`TR-995b2d4e91725afe`, via `terminal-review retry`) |
|---|---|---|
| Planner residency | Qwen already the only model (verified) | n/a (review only) |
| Investigation | 4 steps, `step_budget_exhausted`. R1 OBSERVED, R2 STATIC, R3 UNRESOLVED. Same levels as the objective-v1 live run. | not rerun |
| Assessment, package, artifact | persisted before any model switch. The artifact records the review as `pending`. | persisted by the fixture script |
| Idle check | 0 active and 0 waiting requests. The last Qwen completion ended at 13:16:44.780. | idle |
| Qwen unload | 13:16:44.805, 1.09 s, 16.17 GB freed, verified from `/v1/models/status` | 13:17:54.8, verified |
| Gemma load | 8.05 s (14.84 GB actual), verified as the only resident model. **No 507.** | 13:18:03, verified, no 507 |
| Review | 6,616 prompt tokens, 943 completion tokens, 30.1 s, `finish_reason=stop`. `completed` on the first response. | 5,899 prompt tokens, 932 completion tokens, 27.6 s. `completed`. |
| Gemma unload | 1.57 s, 15.21 GB freed, verified | verified |
| Qwen restore | 5.57 s, verified loaded | 13:18:38, verified |

**Subsequent investigation on the restored planner.** A second focused run
(`--max-steps 2 --review skip`) executed two observation steps on the
restored Qwen. Its review is recorded as `skipped` by explicit policy
(`TR-32d9854c1803ed0e`).

**Failure path, live.** A retry with `--review-model no-such-model` (scratch
store) returned `unavailable` / `model_not_served`. No other model was
substituted, no residency changed, and Qwen remained resident. Log:
`live-unserved-model-2026-10-19.log`.

## What Gemma challenged, and how far it holds

Each finding below is the reviewer's, and none is an APTrace result. The
assessment column is my reading against the package; it is not a new
finding.

### Run 1 (focused follow-up)

| Reviewer finding | Assessment |
|---|---|
| R2 rests on a static edge that the only scenario did not exercise (E4). | Correct, but already stated in the assessment (R2 STATIC; E4 is a scenario-coverage blocker). "Phantom edge" overstates it, and it is filed under the wrong category (composition). |
| E3 and E5 lack state continuity, so R3 is speculative. | Weak. E5 is a timed-out symbolic analysis, not an execution that carries state. R3 is UNRESOLVED for that reason already. |
| R3 relates a function to an address without the instruction. Test: find the store to `0x20001b14`. | A useful, concrete test. It matches the capability gap the assessment names. |
| R2 status uses "not entered" as unreachability. | **Incorrect.** The assessment says "not thereby unreachable". The accompanying test (the inputs that take the branch at `0x5496` toward `0x4d18`) is still useful. |
| Omitted question: what loop causes the 300 s effects timeout. | Useful. It is the precondition for any symbolic R3 evidence. |

**Missed.** The reviewer did not challenge R1's OBSERVED scope: seeded
virtual-link state, not natural reception. That is the main overstatement
risk in this run.

### F0 motion state + ISR STEP (acceptance test 5)

| Reviewer finding | Assessment |
|---|---|
| `scope_mismatch` R2,R5 (E1,E2): joining the command segment with the separately triggered ISR segment ignores that the command might not trigger the ISR. Test: check whether E1 produces the timer state needed to trigger E2. | **This is the requested challenge.** The test is the right one, and the mechanical check (`requests_connection_validation`) passes on the saved attempt. |
| `peripheral_timer_interrupt_assumption` R6 (E2): a direct handler call is not TC0 IRQ delivery. Test: interrupt-triggered execution. | Correct and important. It matches the causal graph's E13 and the R6 capability gap. |
| `missing_prerequisite_or_state_continuity` R7: identify the state that R2/R3 must set to enable R4/R6. | Relevant. It is the busy-gate precondition (E11). |
| `static_as_execution` R4,R6: the static edge is treated as a functional link. | Attributes an inference the assessment does not make (R4 is labeled "static possibility, not execution"). Recorded as a hypothesis. |
| Confidence "overstated" | Not well supported: the package makes no end-to-end claim. |

**Missed.** The reviewer did not use the package's most concrete continuity
evidence. Both segments independently seed `0x20000094`, and the F0 segment
ends with motion state that the ISR segment never consumed. Both facts are in
the harness assumptions.

In both reviews, every finding was correctly a hypothesis or a suggested
test. Gemma claimed no demonstrated contradiction. Its `verdict`-style output
had no effect: the parser records unknown fields, and nothing reads them.

## What changed for this case

- Focused remote-to-motor runs now end with a persisted deterministic
  assessment and an explicit review status, whatever their stop reason.
- Gemma reviews them after Qwen is unloaded, with each step verified. The
  diagnostic audit's 507 path, Gemma loading while Qwen is busy, is replaced
  by a bounded idle wait that ends in a reported `server_busy` failure.

## Remaining capability gaps

1. **Case reconciliation residency.** Reconciliation still calls Gemma
   without residency management. Focused runs do not trigger it.
2. **Composition.** The joins and segments state what is missing. Causal
   trace composition, the carried-state scenarios (RX → `0x5448` → `0x4d18`)
   and TC0 IRQ delivery remain unimplemented, as in the objective-v1 record.
3. **Review substance.** APTrace checks the reviewer's references and kinds,
   not whether a finding is right. Run 1 shows a reviewer error (the
   unreachability finding) that passes every mechanical check.
4. **Review depth.** The review is one request with no analysis requests.
   Routing a reviewer's suggested tests into follow-up work items would be
   the next step.
