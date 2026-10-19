# Objective-Bounded Investigation (objective-v1)

An objective-bounded research run tells the `ResearchController` which
relationships it is investigating. The controller keeps that objective whole
for every planner request. It withholds operations that have no connection to
the objective. After each step it judges progress mechanically, and it stops
with an explicit unresolved-relation report when steps stop paying off.

Code: `agent/src/aptrace_agent/research/objective.py`, wired into
`research/controller.py`. Tests: `agent/tests/test_objective_bounded.py`
(synthetic). Each case keeps its own replay tests. The first is the Performing
Rigs remote-to-motor replay.

The mode is **opt-in**. A run with no declared relations behaves exactly as
before. The only exception is that a clipped prose objective now says it was
clipped.

## Why

An autonomous run in the first case drifted. Qwen was asked a narrow causal
question and spent its budget on peripheral inventory. A follow-up run chose
an unrelated concrete scenario and re-requested an analysis that had timed
out. Both runs ended with `step_budget_exhausted` and no statement of what
stayed unresolved. The investigated causes were:

- **Clipped objective.** The planner saw only the first 640 characters of the
  objective, and the clip was silent.
- **Prompt rule.** The rule "a subsystem the objective names: analyze it",
  combined with lead ranking that puts census-derived leads first, rewarded
  breadth.
- **Scenario note.** The note collapsed every virtual-link scenario into one
  line. The planner had no basis for choosing between them.
- **No memory of failures.** Nothing recorded a failed or timed-out operation,
  and nothing measured progress.

## Use

```
aptrace-agent research --objective-file OBJECTIVE.json [--relation SRC->DST[:label]] [--constraint TEXT] ...
```

The objective file is a JSON `ObjectiveSpec`. Only `question` is required.
Firmware-specific specs live in the owning case, for example
`cases/<case>/research/objectives/`.

| Field | Meaning |
|---|---|
| `question` | The full natural-language objective, at most 1,200 characters. It is never clipped in a focused run. |
| `firmware` | The image the endpoints belong to. A relation may override it per endpoint with `source_firmware` or `target_firmware`. |
| `relations` | At most 8 entries `{id, source, target, label}`. Each endpoint is `FUN_xxxxxxxx` or a `0x` address. |
| `constraints` | At most 8 lines of at most 240 characters each. They are shown to the planner word for word. |
| `terms` | Extra relevance vocabulary, such as subsystem or scenario words. |
| `scenarios` | Registered scenarios the operator declares relevant. This is recorded as an operator assertion, not as evidence. |
| `allow_broad_discovery` | Allows peripheral inventory and case discovery that the objective does not name. Defaults to false. |
| `replan_after`, `stall_limit` | Consecutive low-value steps before a replan notice, and before the run stops. Defaults are 2 and 3. |

`research --ledger` records the declared spec in the run's `execution_config`.
The terminal report is written to the run artifact as `objective_report`.

## Contract 1: the objective

APTrace holds the objective, not the planner. Every planner request starts
with a block that APTrace renders from the spec and the recorded evidence:

- the full `question` and every constraint;
- one line per relation with its **per-edge evidence level**, the evidence
  ids, the latest blocker, and what it **needs**: the operation that could
  raise its level, or the capability gap when that operation already failed;
- endpoints that are not functions in the loaded image;
- the relevant functions and relevant scenarios;
- operations that failed, and requests rejected as unrelated;
- the budget: steps used, steps left, consecutive steps without progress, and
  the replan and stop thresholds;
- what counts as progress.

### Endpoint resolution

Endpoints are resolved once, at the start of the run:

| Endpoint | Resolves to |
|---|---|
| A function entry in the loaded image | `function` |
| A `0x` address that is not a function entry | `address` (data or MMIO) |
| An endpoint declared for another image | `other-image`. It is never checked against the loaded image, so the same address in two images cannot be confused. |

Every function endpoint that has no `function_facts` yet is offered as an
objective lead.

### Relation levels

A relation's level is recomputed from all recorded evidence on every request.
Each level is evidence about one edge only:

| Level | Source |
|---|---|
| `UNRESOLVED` | No supporting evidence. |
| `STATIC` | A `function_facts` call edge between the two functions. This comes from Ghidra's call graph, with heuristic function boundaries. |
| `SYMBOLIC` | Completed `function_effects` showing a call to the target, or an access to an address endpoint, with its guard. |
| `OBSERVED` | `observed_call_arguments` of the target in which the source is the observed caller. It is scoped to that scenario and its harness assumptions. |

### Blockers

These results are recorded as **blockers**, never as negative evidence:

- a failed or timed-out analysis;
- bounded coverage;
- a target that was not entered in a scenario;
- a target that was entered without a call from the source.

**APTrace never composes relations into a path.** Per-edge levels are not an
end-to-end causal result. Composition, and verification of it, is a separate
capability that does not exist yet.

## Contract 2: relevance

Relevance decides only whether an operation may run. It never creates a claim
and is not evidence.

### Sources of relevance

- **Functions.** The relevant functions are the relation endpoints plus
  functions one static call hop from an endpoint in recorded `function_facts`.
  The bound is fixed: relevance does not spread with every followed lead.
- **Scenarios.** A registered scenario is relevant when any of these holds:
  - the objective declares it;
  - it is among the best lexical matches between the objective vocabulary and
    the scenario's own registry metadata (its id, its runner, and an optional
    `topics` list);
  - recorded evidence shows it entering an endpoint.

  Tokens shared by more than half of the registered scenarios, such as a common
  prefix or runner verb, are ignored. No case names appear in framework code.
- **Peripherals.** A peripheral's census or inventory is relevant only when the
  question or `terms` name the peripheral, or broad discovery is allowed.
  Relation labels describe edges. They count for scenario matching, but they
  do not request inventory.

### Enforcement

- **Palette.** Unrelated leads are not offered. The peripheral and scenario
  enums are narrowed to relevant values, and a tool with no relevant value is
  withheld.
- **Parse.** A request for a withheld or unrelated operation is rejected. The
  planner is told why, and the rejection is recorded. The planner's single
  existing correction applies.
- **Lead inheritance.** A lead without a function target, such as a pin-table
  entry or a case search, is relevant only when its source evidence came from a
  relevant operation.
- **Claim candidates.** Under the claim contract, only candidates whose subject
  is a relevant function are offered for selection. The rest are recorded as
  withheld with `CANDIDATE_OUTSIDE_OBJECTIVE`. This limits the scope of
  selection only: admission and the candidate generator are unchanged.
- **No relevant operation.** If no relevant lead or tool remains, the run stops
  with `objective_no_relevant_operation` before any planner call. Case
  discovery does not run in a focused run unless `allow_broad_discovery` is
  set, because relations, not lexical search, define the targets.

## Contract 3: progress and termination

After each executed step APTrace assigns one outcome:

| Outcome | Rule |
|---|---|
| `failed` | The result status is a failure, a timeout or `*_unavailable`. |
| `strengthened` | A relation's level rose. |
| `blocker` | The result added a new blocker to a relation. |
| `relevant_partial` | The operation was relevant, but no relation changed. |
| `no_progress` | The operation was not connected to the objective. |

Only `strengthened` and `blocker` reset the counter of consecutive low-value
steps. When the counter reaches `replan_after`, the next request carries a
`REPLAN` notice. When it reaches `stall_limit`, the run stops with
`objective_stalled`. The existing termination paths, including the step
budget and the planner's `finish`, are unchanged.

Every focused termination produces `objective_report`, which contains:

- the per-relation levels, evidence, blockers and *missing* evidence or
  capability;
- the unresolved relation ids, and whether all relations reached a level;
- the step outcomes and the rejections;
- the explanation of the stop.

Each unresolved relation is also merged into the session's open questions,
with source `objective`. Under the claim contract, the final-claims request
tells the planner not to claim a composed path. Admission is unchanged and
still decides what is admitted.

## Limitations

- **Single-edge relations.** A relation is one call or access edge. A
  multi-hop relation stays `UNRESOLVED` statically, even when a path exists.
  Path relations need `find_common_paths` integration or a composition
  capability.
- **Address endpoints.** Only symbolic access evidence relates an address
  endpoint. Watched-field observation is not yet linked.
- **Lexical scenario relevance.** It depends on the registry naming scenarios
  meaningfully. A scenario with an uninformative id and runner needs `topics`
  or an explicit declaration.
- **One image.** One run investigates one image. Cross-image relations are
  reported as needing a multi-image capability.
- **Report persistence.** The ledger records the spec, not the report. The
  report lives in the run artifact.
- **Model behavior.** These contracts bound what Qwen can execute and make the
  state visible to it. They do not make its choices or its prose correct.
