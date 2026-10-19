# Critic Validation v1: Gemma's remote-to-motor criticism, validated

On 2026-10-19 the framework gained deterministic validation of terminal
review findings, execution-state continuity checks, follow-up question
proposals and a v2 review package and template. The design is in
[`docs/critic-validation.md`](../../../../docs/critic-validation.md). This
page records what that validation decides for this case.

**No firmware conclusion here is new. No claim, grade, relation level or
ledger record changed.** Each classification is about the reviewer's
proposition regarding APTrace's record, not about the firmware.

- **Regression references.** These are unchanged. The test checks their file
  hashes before and after validation:
  - `research/runs/terminal-review-v1/reviews/TR-78cf8cd5aece72d3` (focused
    run 1, Gemma attempt `RA-20261019T171644-f41a47`);
  - `research/runs/terminal-review-v1/reviews/TR-995b2d4e91725afe` (F0/ISR
    fixture, Gemma attempt `RA-20261019T171754-640213`).
- **New material.**
  [`research/runs/critic-validation-v1/`](../../research/runs/critic-validation-v1/):
  - `TR-*.validation.{json,txt}`: validations of the two saved attempts,
    written with `terminal-review validate --output`, so the saved store was
    not written;
  - `reviews/TR-6c12702daeb42174`: a live Gemma review of the rebuilt v2
    F0/ISR package, with `.log` (console) and `.show.log` (final report).
- **Tests.** [`test/test_critic_validation_regression.py`](../../test/test_critic_validation_regression.py).

Both saved assessments are `terminal-assessment-v1`. They kept no
structured execution state, so their continuity is recomputed from the
harness-assumption strings. The validation record discloses this
(`continuity_source`). The rebuilt fixture
([`scripts/terminal_review_f0_isr.py`](../../scripts/terminal_review_f0_isr.py))
now emits `legs` (fresh, seeds) and the artifacts' `final_memory`. Its v2
assessment carries the structured state.

## Before and after: the three known review problems

| Known problem | Before (Terminal Review v1) | After (Critic Validation v1) |
|---|---|---|
| **False criticism.** Run 1, `unsupported_negative` R2/E4: "uses the absence of execution … A 'not entered' result is not evidence of unreachability." | Passed every mechanical check. Only a manual reading found it wrong. | **CONTRADICTED.** The refuting records are R2's level (STATIC, positive), R2's blocker E4 ("FUN_00004d18 not entered under scenario vl-manual-f0e0 (not thereby unreachable)"), the session claim citing E4 with the same qualifier, and the framework limitation that blockers are never evidence of absence. Its suggested test (inputs for the branch at `0x5496`) produces no follow-up. The same test reaches R2 through the omitted question that cites E6. |
| **Valid criticism.** F0/ISR, `scope_mismatch` R2,R5/E1,E2: joining the command segment and the ISR segment ignores that the command might not trigger the ISR. | Recorded as a hypothesis; a case-specific test helper checked that it cited both sides. | **SUPPORTED.** The connection check cites the unvalidated joins R2→R7→R4→R6→R5, R7 and R6 UNRESOLVED, and R4 STATIC. The state-continuity check cites C1. The finding also implies that APTrace joined the segments; the record refutes that (`composition.attempted: false`), so it is flagged as a mischaracterization and the gap is kept. Whether the firmware's command activates the timer remains **unresolved**, and it becomes follow-up FQ-491c114e58e2. |
| **Missed issue.** Both segments independently seed `0x20000094`. | Not raised by Gemma; noticed manually. | **Detected by APTrace**, with no reviewer involved: C1 `independently_supplied_state` (E1, E2, `0x20000094`, 4 bytes, `establishes_continuity: false`). It is reported as "not raised by the reviewer". In the v2 assessment, C2 `prior_state_not_carried` also records that E1's end state (for example `0x200024cc` and `0x20001b14`) is not carried into E2's fresh start. E1's `final_memory` is a snapshot, not a write log, so none of it is called *produced*. |

### Every saved finding

Run 1 (`TR-78cf8cd5aece72d3`):

| # | Category, targets | Classification | Basis |
|---|---|---|---|
| 0 | unjustified_composition R2 (E1, E4) | SUPPORTED, mischaracterization | R2 is STATIC. The record does not compose anything. The gap is already an APTrace requirement. |
| 1 | missing_prerequisite_or_state_continuity R2,R3 (E3, E5) | SUPPORTED | R2 is STATIC and R3 UNRESOLVED. The continuity part is **UNGROUNDED**: E5 is a timed-out symbolic analysis and carries no state. R2 and R3 are siblings, not a chain. |
| 2 | scope_mismatch R3 (E5) | SUPPORTED, mischaracterization | R3 is UNRESOLVED. No scope was applied to another. |
| 3 | unsupported_negative R2 (E4) | **CONTRADICTED** | see above |
| 4, 5 | omitted questions (E6 branch; E5 timeout loop) | UNRESOLVED | firmware questions |

F0/ISR (`TR-995b2d4e91725afe`):

| # | Category, targets | Classification | Basis |
|---|---|---|---|
| 0 | unjustified_composition R7 (E1, E3) | SUPPORTED, mischaracterization | R7 is UNRESOLVED |
| 1 | static_as_execution R4,R6 (E3, E2) | **CONTRADICTED** | R4 is reported as "static possibility, not execution", R6 is UNRESOLVED, and no join is validated |
| 2 | missing_prerequisite_or_state_continuity R7 (E1) | SUPPORTED | R7 is UNRESOLVED |
| 3 | peripheral_timer_interrupt_assumption R6 (E2) | SUPPORTED | E2's harness assumption "Direct AAPCS handler call is not IRQ delivery", and the R6 capability gap |
| 4 | scope_mismatch R2,R5 (E1, E2) | SUPPORTED, mischaracterization | see above |
| 5–7 | omitted questions | UNRESOLVED | firmware questions |
| — | confidence "overstated" | **CONTRADICTED** | no composition, no admitted claim, no end-to-end conclusion |

These agree with the manual reading in
[`terminal-review-v1.md`](terminal-review-v1.md), with one refinement. The
run-1 continuity finding was judged "weak" there. It is now split: its
continuity part has no target, and its relation gap is real but already
recorded. No finding was UNGROUNDED, and no citation was fabricated. The
regression test also checks that fabricated ids (`R8`, `E9`) and an absent
quote are rejected.

## Follow-up question proposals

From F0/ISR, four proposals (none executed):

- **FQ-491c114e58e2** [connection]. Does one execution carry FUN_00005448
  through FUN_00005898 (R2 → R7 → R4 → R6 → R5)?
  - Sources: finding 4, omitted questions 5 and 7, and APTrace C1.
  - Missing: R7's caller-grounded activation, R4's concrete call, R6's
    timer/IRQ model (capability gap), and the three unvalidated joins.
  - Condition: `0x20000094` must be produced or carried, not seeded.
  - Operations: a case scenario that runs through the chain in one execution
    (`requires_registered_scenario`), then `observe_call_arguments`. R6 is a
    `capability_gap`.
  - Limitation: the segments' coverage says that MMIO is plain memory, with
    no peripheral or interrupt model.
- **R3** [relation]: busy gate. From omitted question 6, which names
  `0x20001b14`. Candidates: `analyze_function_effects(FUN_00005448)` (none
  completed in the fixture), or `observed_call_arguments` with `watch` on
  `0x20001b14`, an executor option that needs an operator request.
- **R7** [relation]. From findings 0 and 2. Candidates:
  `observe_call_arguments` (scenario tried: `rx-f0-direct-seed`) and
  `analyze_function_effects`.
- **R6** [assumption]. From finding 3. Does R6 hold without E2's harness
  assumptions? It is a capability gap.

From run 1, two proposals:

- **R2** [relation]. A scenario that enters FUN_00004d18. `vl-manual-f0e0`
  was already tried. The earlier `analyze_function_effects` attempt, E5,
  timed out.
- **R3** [relation]. The busy-gate store. The effects analysis was
  attempted (E5 timeout); a repeat needs a different bound. Alternative:
  watch `0x20001b14` under a scenario that enters FUN_00005448.

These are precise enough to scope the next investigation: each names the
relations, the missing evidence, the scenario prerequisites and the
capability gaps. They are not executable plans. The connection question in
particular needs a new case scenario and, for R6, a timer and interrupt
capability that APTrace does not have.

## Review-package integrity

- The two saved v1 packages were 13,596 and 12,652 characters, so no
  reduction applied. Their only missing material item is the continuity
  concern, which v1 did not represent.
- Had the v1 package been reduced, "first 3 harness assumptions per scope"
  would have dropped E1's seed of `0x20000094`: it is E1's 4th assumption.
  The integrity check names that loss, and the regression test asserts it.
- The rebuilt v2 package is 16,230 characters with no reduction. Forced
  down to 4,000 characters, every reduction applies, and the seed, the
  "not IRQ delivery" qualifier, the scope states and C1/C2 all remain.

## Live Gemma review under template v2

`TR-6c12702daeb42174`, from the rebuilt v2 fixture package, run with
`terminal-review retry --review-dir research/runs/critic-validation-v1/reviews`.
No ledger was used.

Sequential residency worked as before. Each step was verified:

| Step | Time |
|---|---|
| Qwen unload | 1.31 s |
| Gemma load | 9.41 s; no 507 |
| Review | 8,387 prompt tokens, 1,088 completion tokens, 40.0 s, `finish_reason=stop`, completed on the first response |
| Gemma unload | 2.97 s |
| Qwen restore | 6.49 s, verified loaded |

Gemma used every v2 grounding field. Each of the 4 findings stated a
`defect` and `targets` (including `R7->R4`, `C1`, `C2`), and one quoted
package text: R4's relation label. There were no rejected citations.

Validation: SUPPORTED 3, CONTRADICTED 1 (static_as_execution R4: the quoted
label is the objective's question, not a conclusion), UNRESOLVED 3 (omitted
questions). Gemma cited C1 and C2, but the v2 package showed it those
concerns, so this is **not** independent detection. The live store's
`validations/` file was regenerated once by the final code. The first one
had been written minutes earlier by development code that over-widened
concern targets.

## Remaining limitations to evaluate in real investigations

1. **Characterization checks depend on structure and APTrace's qualifiers.**
   A negatively worded planner hypothesis without a qualifier makes a
   refutation UNRESOLVED. Real autonomous runs, with richer planner state,
   will show how often this happens.
2. **Gap support is coarse.** Any non-OBSERVED relation supports a "not
   established" criticism. Most SUPPORTED gaps here were already APTrace
   requirements (`already_recorded`). The reviewer's distinct value was the
   framing, not new gaps.
3. **Continuity is address-range only.** It needs write logs to call state
   produced; no current scenario runner records them, and none records
   `carried_from`. Registers, peripheral and interrupt state, and legs
   within a scenario are not compared.
4. **v1 records are parsed from text.** The run-1 scenario seeds were
   counted but not located (`unknown`).
5. **Reviewer independence.** Now that the package shows the continuity
   concerns, a reviewer that repeats them is not corroboration. Measuring
   independent detection would need a package variant without them.
6. **Proposals are not routed** to `followups-v1` or work items, and the
   connection proposal depends on scenario authoring and a timer/IRQ
   capability, not on an existing operation.
