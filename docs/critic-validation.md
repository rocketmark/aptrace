# Critic Validation (critic-validation-v1)

Terminal review ([`terminal-review.md`](terminal-review.md)) gives every
focused run an adversarial critic. Before this milestone APTrace checked
only that a criticism was well-formed. A finding could pass every check and
still be wrong, such as a claim that APTrace treated an unentered function as
unreachable when the record says the opposite.

Critic validation decides, mechanically and without another model, which
criticisms APTrace's own record supports. It keeps three things separate:

| Question | Decided by |
|---|---|
| Did the review complete? | Review status (`completed`, `failed`, ...) |
| Is the criticism of the investigation correct? | Critic validation (this document) |
| Does the firmware behave as claimed? | Evidence, admission and verification. Never the critic or its validation. |

| Part | Code | Tests |
|---|---|---|
| Validation, follow-ups | `agent/src/aptrace_agent/research/critic.py` | `agent/tests/test_critic_validation.py` |
| State continuity | `agent/src/aptrace_agent/research/continuity.py` | same |
| Package v2, template v2, persistence, report | `agent/src/aptrace_agent/research/review.py` | same, plus `test_terminal_review.py` |
| Assessment v2 (scope state, continuity) | `agent/src/aptrace_agent/research/terminal.py` | same |
| CLI | `aptrace-agent terminal-review validate TR-... [--attempt RA-...] [--json] [--output FILE]` | same |

## What a finding is

A finding is a **proposition about the investigation record**, not about
firmware. It says either that the record lacks something ("nothing connects
the command segment to the ISR segment") or that the record concluded
something it should not have ("a not-entered function was treated as
unreachable"). APTrace's record is complete for that question: the
assessment holds every relation level, blocker, scope, join, segment,
session claim, hypothesis and admission decision of the run. That is why a
characterization of the investigation can be refuted mechanically, while a
claim about firmware cannot.

Validation always reads the **full persisted assessment**, never the
reduced package. A package reduction can therefore hide context from the
reviewer, but it cannot weaken validation.

## Grounding

Template v2 (`terminal-review-v2`) asks for these fields in every finding:

| Field | Meaning |
|---|---|
| `relations`, `evidence_ids` | Package relation and evidence ids, as before |
| `targets` | Ids from the package's `targets` index: joins `R1->R2`, segments `S1`, continuity concerns `C1` (relation and evidence ids are also accepted) |
| `defect` | `missing_evidence`, `incorrect_inference`, `unsupported_assumption`, `contradiction` or `firmware_hypothesis` |
| `quote` | The exact package text challenged, for an `incorrect_inference` |
| `checkable` | The reviewer's own opinion; recorded, never trusted |
| `resolving_evidence` | What would establish or refute the finding |

v1 responses lack these fields and still validate: the defect then comes
from the category (table below), and the targets from the cited ids.

Grounding rules:

- A cited id that is not in both the package and the assessment is
  **rejected**. It is listed in `rejected_citations` and never used as
  support.
- A `quote` that is not a substring of the package content is also
  rejected.
- A finding with no valid relation or evidence target, or with no
  identifiable defect (an unknown category and no valid `defect`), is
  **UNGROUNDED**.
- Joins, segments and concerns resolve to the relations they contain.
  Evidence resolves to the relations it *establishes*, or to the relations it
  blocks when it establishes none.
- Omitted questions are validated as `omitted_question` findings. Their
  ids, and any relation endpoint (an address before a function name) that
  the text names, are pattern-extracted. This is disclosed in the record.

## Classifications

| Class | Meaning |
|---|---|
| `SUPPORTED` | APTrace's record establishes the criticism. |
| `CONTRADICTED` | A **positive** record refutes it: a relation level with its meaning, a blocker recorded as incompleteness, an explicit APTrace scope qualifier, a carried-forward link, or two relations established by one execution. |
| `UNRESOLVED` | Grounded and plausible, but the record neither establishes nor refutes it. Every claim about firmware behavior lands here. |
| `UNGROUNDED` | No valid target, or no identifiable defect. |

A missing record never refutes. "No contradiction is recorded between E1
and E2" leaves a demonstrated-contradiction finding UNRESOLVED, not
CONTRADICTED. An OBSERVED relation leaves an unspecific
"not established" criticism UNRESOLVED. A characterization check returns
CONTRADICTED only after it has inspected every place the record could hold
the alleged conclusion. A free-text statement that might hold it makes the
result UNRESOLVED.

## Routing and checks

| Category (v1) | Defect | Checks |
|---|---|---|
| `unsupported_relationship` | missing_evidence | relation gap |
| `missing_prerequisite_or_state_continuity` | missing_evidence | connection, state continuity, conditional relation gap |
| `unjustified_composition` | missing_evidence | connection or relation gap; characterization: composition |
| `scope_mismatch` | missing_evidence | connection or conditional relation gap; characterization: scope |
| `peripheral_timer_interrupt_assumption` | unsupported_assumption | scope assumptions, relation capability gaps |
| `static_as_execution` | incorrect_inference | static presented as execution |
| `unsupported_negative` | incorrect_inference | negative conclusion |
| `overstated_confidence` | incorrect_inference | stated confidence |
| `contradictory_evidence` | contradiction | recorded contradictions, tensions |
| `counterexample_or_falsification`, `omitted_question` | firmware_hypothesis | none (UNRESOLVED) |

A valid reviewer `defect` overrides the category's defect. The category
still chooses which characterization check applies.

The checks:

- **Relation gap.** If the relation is below OBSERVED, the gap is SUPPORTED,
  citing its level and `evidence_needed`. If it is OBSERVED, a scope-type
  criticism is SUPPORTED by the scope's harness assumptions, because the
  observation holds only under them. Otherwise the result is UNRESOLVED.
- **Connection** (two or more chained relations, or two execution segments).
  This is SUPPORTED when the joins along the chain are unvalidated (which in
  objective-v1 is always), citing the intermediate levels and any continuity
  concern. It is CONTRADICTED when one execution establishes every relation.
  Parallel relations (siblings with no join path) get relation gaps instead.
- **State continuity.** SUPPORTED by a concern between the cited segments
  and CONTRADICTED by a carried-forward pair. Evidence with no execution
  state (static or symbolic results) makes this part UNGROUNDED.
- **Negative conclusion.** The record holds relation levels (never
  negative), blockers (incompleteness by INV-CTRL-OBJ-004), and statements
  that cite the evidence. A negative-worded statement without an APTrace
  qualifier ("not thereby", "not excluded", "not absence", ...) makes the
  check UNRESOLVED. Otherwise it is CONTRADICTED.
- **Static presented as execution.** SUPPORTED when an OBSERVED level rests
  on evidence that has no execution scope, a statement presents static-only
  evidence as execution, or a join is validated. Otherwise CONTRADICTED.
- **Composition / scope characterization.** SUPPORTED when a statement spans
  separately established segments or scenarios, or composition was
  attempted. Otherwise CONTRADICTED.
- **Stated confidence.** CONTRADICTED when the assessment states no
  end-to-end conclusion (no composition, no admitted claim). UNRESOLVED when
  admitted proposals exist, because their grades are admission's business.

A `missing_evidence` finding whose characterization is CONTRADICTED but
whose gap is SUPPORTED is kept as SUPPORTED with
`mischaracterizes_investigation: true`. Example: "the investigation joined
two segments" next to a real gap between them. The gap is the useful part.
`already_recorded` says whether APTrace already lists that gap as an
evidence requirement.

The validation also reports:

- APTrace continuity concerns the reviewer did not raise
  (`not_raised_by_reviewer`). A finding raises a concern only by citing it
  or by naming one of its addresses; citing both segments is listed as
  related, not as raised.
- The reviewer's top-level `confidence`, checked when it says `overstated`.

## Execution-state continuity

`research/continuity.py` (`state-continuity-v1`) classifies each concrete
execution segment's state from metadata the evidence already has:

| Class | Source |
|---|---|
| supplied | `legs[].seeds` (address, length), register seeds, forced values: harness inputs |
| produced | Recorded writes only (`ram_log` writes, `mem_write_hits`) |
| end_state | `final_memory` snapshot addresses the segment did not supply. A snapshot does not say whether execution or the initial image put the value there, so it is never called produced. |
| carried | `carried_from` evidence ids (no current runner records this) |
| unknown | Seeds counted but not located, writes not logged, initial state not identified |

Assessment v2 stores each scope's normalized `state` and the composition's
`continuity`. A v1 assessment kept only rendered harness assumptions. For
it, the same analysis parses APTrace's own strings ("seeded N byte(s) at
ADDR", "N seeded range(s)", "fresh") and is labeled
`harness_assumption_text`.

For each pair of segments the analysis reports:

| Pair | Reported as |
|---|---|
| The same registered scenario under the same registry hash | `same_registered_scenario` (a replay of one harness state; no concern) |
| A `carried_from` link | `carried` (no concern) |
| Overlapping supplied ranges | `independently_supplied_state` |
| The later segment supplies what the earlier produced or recorded at its end | `supplied_over_prior_state` |
| The earlier segment produced or recorded end state, and the later one starts fresh without carrying it | `prior_state_not_carried` |

Every concern has `establishes_continuity: false` and a precise
`requirement`. This detects unsupported continuity. It does not compose
executions, does not transfer state, and does not compare legs within one
scenario.

## Follow-up questions

SUPPORTED and UNRESOLVED findings, and APTrace's own continuity concerns,
become at most 8 question **proposals**. Each has `status: proposal` and
`executable: false`, and nothing runs them. Findings on the same challenge
merge:

- **connection**: the chain of relations between the targets, along joins;
  a sub-chain folds into its containing chain;
- **relation**: one non-OBSERVED relation;
- **assumption**: an OBSERVED relation, or an `unsupported_assumption`.

Each proposal records:

- **challenged:** the relations, their levels, the endpoints and the execution
  segments.
- **missing_evidence:** APTrace-derived. It comes from the relations'
  `evidence_needed`, the unvalidated joins, and the concern requirements.
- **candidate_operations:** existing operations with their prerequisites:
  - `observe_call_arguments` (needs a registered scenario that enters the
    source; the scenarios already tried are named);
  - `analyze_function_effects` (marked as attempted when a prior attempt
    failed);
  - `observed_call_arguments` with `watch` for an address endpoint (an
    executor option the planner palette does not offer);
  - `requires_registered_scenario` for a connection;
  - `capability_gap` items copied from the record.
- **conditions:** for example, that the shared addresses must be produced or
  carried rather than seeded, the scenarios already tried, and that remaining
  harness assumptions stay disclosed.
- **expected_evidence:** the level and scope that would resolve the question.
- **limitations:** the capability gaps, the coverage text of the segments,
  the unknown state, and the continuity check's own limits.
- **reviewer_tests:** labeled as reviewer text. They are not APTrace
  requirements.

They are deliberately not `followups-v1` candidates
([`research-continuity.md`](research-continuity.md)), which are derived from
ledger runs and claims and can become work items. Routing critic proposals
into that path is a later step.

## Review-package integrity

The 24,000-character package v1 could drop material:

- The reduction to "first 3 harness assumptions" drops E1's seed of
  `0x20000094` in the F0/ISR package, because that seed is its 4th
  assumption.
- The fixed caps on rejected operations, hypotheses and questions were not
  recorded.
- The package carried no structured state and no continuity concern.

Package v2 (`terminal-review-package-v2`):

- **Never reduces** relation levels, blockers, evidence needed, scope
  states, continuity concerns, segment boundaries, joins, tensions,
  contradictions, limitations, or any evidence id, tool, status or result
  hash.
- Its harness-assumption reduction keeps the first 3 assumptions, plus every
  assumption that names a shared address or carries a qualifier ("not", "no",
  "without", "direct call", "fresh").
- Records every omission in `bounds.omitted`: the item, how much was dropped
  and kept, or which evidence lost its summary. This includes assumptions
  beyond `terminal.MAX_ASSUMPTIONS` that the assessment itself did not keep.
- Adds a `targets` index and compact per-scope `state`.

`review.package_integrity(assessment, package)` lists any material item a
package lacks, for v1 and v2 packages. The two saved v1 packages of the
first case were not reduced at all. The only material item they lack is the
continuity concern, which v1 did not have.

The reduction order otherwise stays as it was: trajectory, then evidence
prose, then lists. This is not a context-management redesign. A package
that cannot reach its bound is still sent, with `within_bound: false`.

## Persistence and authority

After a completed attempt, `TerminalReviewer.run` writes
`<store>/<TR>/validations/<RA>.json` (write-once). A validation failure is
recorded there and never changes the review status. `TerminalReviewStore.validate`
and the CLI `validate` action recompute from the persisted assessment,
package and attempt. They are deterministic (`validation_sha256`), work on
historical v1 attempts, and **never write the store**. `--output` writes a
separate file.

The final report gains a fifth section between the criticism and the
evidence requirements: **CRITIC VALIDATION**. The follow-up proposals are
listed under the unresolved evidence requirements.

Validation changes no evidence, relation level, claim, grade or admission
decision. It reads no ledger and writes no ledger. A SUPPORTED criticism
promotes nothing, and a CONTRADICTED one demotes nothing. Review records,
including validations, are not `AuditRecord`s.

## Limitations

- **Characterization checks inspect structure and APTrace's own qualifiers.**
  A planner hypothesis worded negatively without a qualifier blocks a
  refutation (UNRESOLVED), even when it is harmless.
- **Gap checks are coarse.** Any non-OBSERVED relation supports a "not
  established" criticism. The check does not know which level the reviewer
  required.
- **Continuity is address-range only.** It does not compare registers,
  peripheral state, interrupt state or legs within one scenario. Produced
  state needs a write log, and current registered-scenario results record
  none. Seeds in v1 records are parsed from text.
- **Endpoint naming in omitted questions is pattern-matched**, and so is the
  extraction of hex addresses in "raised" detection.
- **The reviewer now sees APTrace's continuity concerns.** A v2 review that
  cites `C1` is repeating APTrace, not detecting the issue independently.
- **Proposals are not executed or routed** to work items, and their
  candidate operations are suggestions with stated prerequisites, not
  plans.
