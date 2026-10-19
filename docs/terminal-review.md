# Terminal Review (terminal-review-v1)

Every focused (objective-bounded) research run ends with a **deterministic
terminal assessment**. A review model then challenges it in an **adversarial
terminal review**, when that model can be made available. The two never
merge:

- The assessment is what APTrace established through its tools and evidence
  rules. It needs no model.
- The review is advisory criticism. It never changes evidence, relation
  levels, claim state or admission.

The review runs through **sequential model residency**. The planner and the
reviewer do not fit under the oMLX memory ceiling together, so APTrace
unloads one model and verifies the unload before it loads the other.

| Part | Code | Tests |
|---|---|---|
| Assessment | `agent/src/aptrace_agent/research/terminal.py` | `agent/tests/test_terminal_review.py` |
| Review, store, report | `agent/src/aptrace_agent/research/review.py` | same |
| Residency | `agent/src/aptrace_agent/omlx.py` | same (simulated oMLX) |
| Wiring | `research/controller.py` (`_assess_terminal`), `cli.py` | same, plus each case's replay |

## Why

Two failures in the first case motivated the milestone (case record:
`cases/performing-rigs/docs/investigations/terminal-review-v1.md`):

1. **The review never ran.** The only review path was case reconciliation,
   and it runs only after a non-discovery case-evidence search
   (`ResearchController._reconcile_terminal`). Focused runs do no such
   search, so nothing ever reviewed them, including runs with meaningful
   partial results.
2. **HTTP 507.** A separate diagnostic audit failed because the server could
   not load the reviewer. oMLX evicts the least recently used *idle* model
   before a load, but it never evicts a model that has an in-flight request
   (`engine_pool._find_lru_victim`). The server log shows that a planner
   request was generating when the audit request arrived. That cause is
   **confirmed** from the oMLX log and source.

A third gap was found during this work: an exception raised in the
controller loop, such as a planner transport failure, propagated out of
`run`. The run then left no report at all.

## 1. Deterministic terminal assessment

`ResearchController._result` builds `ResearchRunResult.terminal_assessment`
for every focused run, whatever its stop reason:

| stop_reason | category |
|---|---|
| `planner_finished` | `completed` |
| `step_budget_exhausted` | `budget_exhausted` |
| `objective_stalled` | `stalled` |
| `objective_no_relevant_operation` | `no_relevant_operation` |
| `planner_prefill_exhausted`, `planner_contract_exhausted` | `planner_failure` |
| `investigation_error` | `error` (with `{type, message}`) |

`investigation_error` is new, and it exists only in focused runs. An exception
raised in the loop ends the run with that stop reason, the error is recorded,
and the run still gets its report and assessment. An unfocused run lets the
exception propagate, as before (INV-CTRL-LOOP-005).

Contents (`terminal-assessment-v1`):

- **The objective:** the question, constraints, relations, terms and
  declared scenarios.
- **Termination:** the reason, its explanation, the budget, any error, and
  the count of analysis failures.
- **Per relation:** objective-v1's level, unchanged, with its meaning stated,
  plus the evidence, the blockers, the evidence needed, and the execution
  scope of every cited concrete or symbolic result. A scope gives the
  scenario, the engine, firmware and registry hashes, entry conditions,
  coverage, and up to 12 harness assumptions with their total.
- **Composition:** always `attempted: false`. The assessment adds two
  descriptions:
  - **joins:** adjacent relations, where one relation's target is the next
    one's source. Each join lists the evidence that established each side
    and has continuity `not validated`.
  - **segments:** groups of evidenced relations connected by shared
    endpoints. When there is more than one segment, the assessment says that
    nothing recorded connects them.
- **Tensions:** relations that have both positive evidence and blockers.
  This is never a contradiction verdict.
- **Operations:** the trajectory, every evidence item with its status, a
  bounded summary and its result SHA-256, and the failed and rejected
  operations.
- **Limitations:** the framework's fixed limitations, plus every capability
  gap that a relation's missing evidence names.
- **Session state:** open questions, planner hypotheses (untyped, at most
  `PROBABLE`), contradictions, session claims, and every admission decision.
  Admitted proposals are `PROPOSED`.

It is deterministic. The same inputs give the same assessment and the same
`assessment_sha256`. The assessment carries no timestamps.

What it does not do:

- It is not a second evidence grade.
- It does not check claims.
- It does not compose relations. Joins and segments state that a composition
  is missing.

`terminal.assessment_from_artifact` rebuilds the assessment from a saved
`research --output` artifact without rerunning anything. An older artifact
that has no `objective_report` also needs its objective spec; the report is
then recomputed from the saved evidence by the objective-v1 tracker.

## 2. Review eligibility and the package

Every focused run is eligible for review. The case-evidence condition does
not apply. The review runs on:

- completed runs;
- stalled and budget-exhausted runs;
- errored runs;
- runs with failed analyses;
- runs without admissible claims;
- runs with only static evidence.

Case reconciliation is unchanged and separate: it still runs only after
non-discovery case searches.

The **package** (`terminal-review-package-v1`) is built from the assessment
alone and is bounded to 24,000 rendered characters. When the package is over
the bound, the reductions apply in this order:

1. drop the trajectory;
2. clip evidence summaries;
3. drop evidence arguments;
4. cut open questions;
5. cut harness assumptions to 3 per scope;
6. drop the summaries.

Evidence ids, tools, statuses and result hashes always remain. The package
records:

- every reduction it applied;
- `assessment_sha256` and its own `package_sha256`;
- links to the investigation: the ledger run id, the artifact, the objective
  file and the planner model.

The **prompt** (`terminal-review-v1`) asks the reviewer to challenge the
investigation, not to summarize it, under the eleven headings of the
milestone:

1. unsupported relationships;
2. static reachability presented as execution;
3. missing prerequisites or state continuity;
4. unjustified composition of separate traces;
5. peripheral, timer or interrupt assumptions;
6. contradictions;
7. scope mismatches;
8. unsupported negatives;
9. overstated confidence;
10. counterexamples and falsification tests;
11. omitted questions.

Each finding must be one of three kinds:

- `demonstrated_contradiction`: it must cite package evidence;
- `hypothesis`;
- `suggested_test`.

The reviewer cannot run tools.

**APTrace's mechanical checks** apply to each parsed finding:

- References to relations or evidence that the package does not contain are
  flagged.
- A "contradiction" that cites no package evidence is reported as a
  hypothesis (`effective_kind`).
- Unknown categories are flagged.
- Extra top-level fields, such as a `verdict`, are recorded as
  `ignored_fields` and have no effect.

A malformed response gets one correction round, as in reconciliation.

## 3. Sequential model residency

`omlx.ModelResidency` uses only oMLX's own lifecycle endpoints. Their
behavior was read from the server source (`omlx/server.py`,
`omlx/engine_pool.py`, oMLX 0.7.0):

| Endpoint | Used for |
|---|---|
| `GET /api/status` | Active and waiting requests, loaded models, memory |
| `GET /v1/models/status` | Per model: `loaded`, `is_loading`, `pinned`, `estimated_size`, `max_context_window`. For the pool: `final_ceiling`, `current_model_memory` |
| `POST /v1/models/{id}/unload` | Immediate unload. **It aborts in-flight requests.** |
| `POST /v1/models/{id}/load` | Blocking load. Returns `507` on memory admission failure, `404` for an unknown model, `409` when busy |

`acquire(model)` makes `model` the only resident model:

1. Read both status endpoints.
2. If the model is not served, fail with `model_not_served`. No other model
   is ever substituted.
3. If another resident model is pinned, fail with `pinned_model_resident`.
   APTrace never changes pins or memory settings.
4. For each other loaded model:
   1. wait until the server has no active, waiting or loading work (at most
      180 s, else `server_busy`);
   2. unload it;
   3. re-read the status until the model is reported unloaded (else
      `unload_unverified` after the bounded attempts).
5. Wait until the status shows headroom under the ceiling for the model's
   estimated size (else `insufficient_memory`).
6. Wait for idle, then load the model. A `507`, a `409` or a timeout is
   retried once after a settle wait. Then re-read the status until the model
   is reported loaded and no other model is resident (`load_unverified`,
   `unexpected_residency`).

`release(model)` waits for idle, unloads the model, and verifies that it is
gone. Each transition returns a record with these fields:

- the status snapshot before;
- every action, with its result and elapsed time;
- every wait, with its poll count and outcome;
- the status snapshot after;
- the error, if any.

The residency layer never waits indefinitely.

Lifecycle in `aptrace-agent research` for a focused run:

1. Acquire the planner (`APTRACE_MODEL`). A failure is reported, and the
   run's own planner calls then decide what happens.
2. Run the bounded investigation.
3. Persist the assessment and the package, then write the `--output`
   artifact. The artifact records the review as `pending`, with a pointer to
   the store. It is not rewritten after the review.
4. Acquire the reviewer (`APTRACE_REVIEW_MODEL`, default
   `gemma-4-26b-a4b-it-4bit`). This unloads the planner.
5. Review, then persist the attempt.
6. Release the reviewer, then restore the planner, unless
   `--no-restore-planner` is given. The restore is persisted as its own
   record, so its failure never changes the review status.

The lifecycle belongs to APTrace's infrastructure. The planner never
requests it.

## 4. Persistence, status and retry

The store holds write-once JSON files. A rewrite with different content is
refused with `LedgerImmutableError`. Layout:

```
<store>/<TR-id>/assessment.json        {investigation_id, assessment_sha256, links, assessment}
<store>/<TR-id>/package.json           the review input, with package_sha256
<store>/<TR-id>/attempts/<RA-id>.json  one per attempt
<store>/<TR-id>/residency/<RA-id>-restore.json
```

The store location:

- `--review-dir`, when given;
- otherwise `<ledger>/terminal-reviews` with `--ledger`;
- otherwise `<output>.terminal-review`.

A run with none of these has its assessment in the artifact only, and its
review status is `unavailable` (`no_review_store`).

The terminal-reviews directory is not part of the ledger's claim, event or
audit state. `ResearchLedger.fingerprint` and claim verification never read
it.

Each attempt records:

- its sequence number and `retry_of`;
- the package and assessment hashes, and the template version;
- the model: its id and source, the generation parameters, the oMLX
  per-model settings, the context window as served, and the server version;
- every residency record;
- every request hash and every raw response, with its finish reason and
  usage;
- the parsed review;
- the error (stage, kind, detail), any correction notes, and links.

| Status | Meaning |
|---|---|
| `pending` | The package is persisted and no attempt has finished (includes a process that died mid-review). |
| `completed` | A schema-valid review was parsed. This does not mean the conclusions are correct. |
| `unavailable` | The reviewer could not be made resident or reached: endpoint down, model not served, server busy, `507`/insufficient memory, pinned or unexpected residency. |
| `failed` | The reviewer ran but produced no valid review: timeout, HTTP error, prefill rejection, or a malformed response after one correction. |
| `skipped` | Explicit policy, `research --review skip`, recorded with its reason. |

The latest attempt's status is the investigation's review status.

A review failure has these limits:

- It never erases or changes the assessment, the artifact, the evidence or
  the ledger.
- It never counts as a review.
- It never needs the planner to recover.

**Retry:** `aptrace-agent terminal-review retry TR-... [--review-dir DIR]`.

- It loads the persisted package and checks the package hash, the assessment
  hash and their link. A mismatch is an error, never a silent rebuild.
- It runs a new attempt with `retry_of` set.
- It never reruns the investigation or the planner.

`terminal-review show` prints the report. `list` lists the reviews.
`prepare --artifact RUN.json` assesses and packages a saved run.

## 5. The final report

`review.render_final_report` prints four separate sections:

1. **Deterministic investigation result:** the assessment, with relation
   levels, scopes, blockers, joins, segments, failures, rejections and claim
   proposals.
2. **Adversarial criticism:** findings grouped by their effective kind, each
   with APTrace's checks; the omitted questions; and the reviewer's view of
   the stated confidence.
3. **Unresolved evidence requirements:** first the deterministic ones, from
   the relations, joins and segments. The reviewer's suggested tests follow,
   labeled as not yet APTrace requirements.
4. **Review availability:** the status, the attempts, the model and any
   error. When the review did not complete, the report says that the review
   step is missing and that the deterministic result stands on its own
   evidence.

## Authority

The reviewer has no authority. The following stay with APTrace's
deterministic rules, and the review changes none of them:

- claim admission (`research/admission.py`);
- verification (`ledger/verifier.py`, policy gates);
- LID semantic checks;
- relation levels.

Review agreement does not promote a claim or raise a grade. Review records
are not `AuditRecord`s, so verification never reads them.

## Limitations

- **Case reconciliation residency.** Case reconciliation still calls the
  review model without residency management. It relies on oMLX evicting an
  idle planner. Wrapping it is a small follow-up.
- **Race with other clients.** The idle check and the unload are two calls.
  Another client can start a request between them, and that request would be
  aborted. APTrace cannot lock the server.
- **Headroom check.** The pre-load check uses the status-reported model
  memory. oMLX's own admission also considers live process memory, so a
  `507` can still happen. It is then retried once and reported.
- **Mechanical checks only.** The checks validate references and kinds, not
  the substance of a finding. A completed review can still be wrong or
  shallow.
- **One review per assessment.** There is no multi-round dialogue, and the
  reviewer cannot request APTrace analyses during terminal review. The
  claim auditor (`ledger/auditor.py`) is the path that can.
