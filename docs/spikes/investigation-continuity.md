# Spike: Investigation Continuity

> APTrace should not merely remember what it discovered. It should use that
> knowledge to determine what question is worth investigating next.

## Question

Can APTrace take a completed, bounded investigation and do three things
from durable records alone, without a frontier model re-reading a report?

- Produce a small, ranked, deduplicated set of follow-up investigations.
- Persist a selected follow-up as Beads work.
- Run it through the existing research path with bounded prior context.

The same questions were asked of a real case run. The results are in
[`cases/performing-rigs/research/continuity-spike.md`](../../cases/performing-rigs/research/continuity-spike.md).

## Verdict: PARTIAL (mechanism works; the live planner does not yet exploit it)

What works:

- Deterministic candidate generation, consolidation and ranking.
- Preview without writes.
- Deduplicated Beads persistence, including concurrent creation and a
  reopened store.
- Seeded follow-up execution through `research --ledger --work-item`.
- Recorded context provenance.
- Claim state that is never changed by follow-up work.

All of these are covered by deterministic fixtures. They were also
exercised on a real run, with real firmware tools and live Qwen.

What does not yet work: the live local planner used little of the seeded
context. In the measured run it followed 2 of 6 seeded leads. It spent most
of its budget re-running analyses the source run had already recorded,
because the controller only treats *session* evidence as "already run".
That is the recommended next step ([Next milestone](#next-milestone)).

## What existed, and what was reused

| Need | Existing structure | Used as |
|---|---|---|
| open leads | `ResearchState.leads` + `LeadRegistry`, **in memory only** | re-derived (below) |
| lead derivation | `LeadDeriver` (deterministic, validated) | replayed over durable evidence |
| leads' durable inputs | `ToolInvocation` (seq order, `session_evidence_id`) + blobs | replay input |
| open-lead count | `InvestigationRun.planner_requests[-1].open_leads` | cross-check |
| unverified claims | `ClaimVersion` + lifecycle fold (`ledger.state`) | claim sources |
| audit challenges | `AuditRecord.challenges`, `follow_up_requests` (`suggested_tool`) | audit source |
| verifier diagnostics | `VerificationRecord.checks`, `gate.conditions` | verification source |
| analyses already done | `ToolInvocation.operation_key` | redundancy check |
| follow-up dedup | explicit Beads id + `DuplicateWork` (`followup_for_audit`) | same pattern |
| provenance links | `create_work(discovered_from=)`, `InvestigationRun.parent_run_id` (unused until now) | linkage |
| execution | `handoff.run_investigation` → `research --ledger --work-item` | unchanged path |
| bounded planner context | `PlannerProjection` (`OPEN` section renders hypotheses / open questions; objective ≤ 640 chars; ≤ 6 leads) | seeding seam; **no controller change** |

**Open leads are not durable.** A run records the leads it followed (in
`trajectory`) and the open-lead *count*, but not the frontier itself.
Instead of adding a second representation, the generator replays the
existing `LeadDeriver` over the run's durable observations, in invocation
order. Executed actions are subtracted. It runs only when the run's
`context_id` equals the current one, so the replay reads the same inputs;
otherwise it reports the frontier as unavailable. The recorded count is
checked, and any mismatch is disclosed. On the case run, the replay
reproduced the recorded 25 exactly.

## How candidates are identified

Code: `agent/src/aptrace_agent/research/followups.py` (reads the ledger,
never writes it, and does not import `work/`).

The generator considers only the claim versions the run proposed whose
state is `PROPOSED` or `STALE`. `VERIFIED`, `BLOCKED` and `SUPERSEDED`
claims are reported and skipped.

| Source | Rule (structured fields) | Evidence level of the rule |
|---|---|---|
| peripheral-access gap | Applies when the claim names function F, peripheral P (whose census usage it cites) and an access verb. Census shows only literal-pool constant loads for F (`mmio_site_count` 0), and no `function_effects` for F has an `MMIO` access. Parametric addresses (e.g. `addr<-r0`) are reported. | pattern-matched (claim prose) over structured results |
| device identity | The claim carries `STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY` and device-identity wording. Produces a **blocked** candidate: hardware routing is required. | pattern-matched |
| audit | The latest non-diagnostic `CHALLENGED`/`UNRESOLVED` audit's `follow_up_requests` (or its challenges). A `suggested_tool` outside APTrace's operations makes that request **blocked**. | recorded |
| verification | Latest verification not `VERIFIED`: gate conditions `UNMET`/`UNEVALUABLE`/`UNRESOLVED` and held checks. `CONTRADICTED` gets no follow-up, because revising the claim is an operator decision. | recorded |
| staleness | Claim state `STALE` (reason from the lifecycle event). | recorded |
| lead group | Re-derived open leads, grouped by *anchor*: the subject of the lead's first source evidence (function, `peripheral:X`, `query:X`). | re-derived |

Consolidation:

- One claim candidate merges every executable gap of that claim version.
- It absorbs lead groups anchored at the gap's functions or their direct
  call neighbours (from the run's `function_facts`).
- It also absorbs individual leads that target the gap functions.
- The remaining groups become lead-group candidates.

## How candidates are ranked

Candidates are ranked by ordered category, not a confidence score:

| Rank | When |
|---|---|
| 1 | executable evidence gap, `CHALLENGED` audit, or unmet/unevaluable verification condition on an unverified claim of the run |
| 2 | `STALE` claim or `UNRESOLVED` audit; lead group whose anchor appears in firmware-derived evidence supporting a run claim |
| 3 | lead group linked only through documentary evidence, or not linked to any claim |

Ties are broken in this order:

1. Relationships addressed (claims + consolidated leads), descending.
2. Firmware-derived before documentary.
3. Candidate key.

The shortlist defaults to 3 (`--limit`). Beyond it, candidates are
*deferred*. Redundant and blocked candidates are *suppressed*, each with its
reason. Every candidate states its basis in `priority_basis`. If no rule
applies, the report says so instead of inventing a ranking.

## Deduplication identity

- `question_key = H(case, firmware, category, claim_id | anchor)`. This is
  the question itself. It survives evidence changes and does not depend on
  the run, so the same anchor left open by two runs is one question.
- `key = H(question_key, evidence basis)`. The basis covers:
  - claim version and state, gap codes and details, sorted evidence ids,
    audit and verification ids, and `context_id`, for claims;
  - sorted lead actions and `context_id`, for lead groups.
- Objective text is not part of either key, so rewording an objective does
  not create new work.
- The Beads id is `<prefix>-fq<key[:10]>`.
  - A repeat create returns the existing item, open or closed. A closed
    item is never reopened or recreated.
  - A concurrent create loses to `DuplicateWork` and returns the winner's
    item.
  - A changed basis gives a new key and a new item. Its
    `aptrace_prior_followups` lists earlier items with the same
    `question_key`.
- Ledger-side redundancy works without Beads:
  - A lead whose `operation_key` is already recorded (under current inputs)
    is not seeded; it is listed as already performed.
  - A lead group whose analyses were all recorded is suppressed as
    `redundant`.
  - A candidate whose key a recorded follow-up run already carries is
    suppressed, with that run's seeded-lead coverage and stop reason.

## Provenance

| Direction | Record |
|---|---|
| work → source | Beads item metadata: `aptrace_followup_key`, `aptrace_followup_question`, `aptrace_source_run`, `aptrace_claim_versions`, `aptrace_audit_ids`, `aptrace_verification_ids`, `aptrace_evidence_ids`; dependency `discovered-from` the source run's work item; `aptrace_related_work` for an audit follow-up item of the same audit |
| run → source | `InvestigationRun.parent_run_id` (source run), `InvestigationRun.followup` (`FollowUpProvenance`) |
| invocation → source evidence | a seeded lead keeps its durable source ids, so `ToolInvocation.input_evidence_ids` of the follow-up run names the source run's evidence |
| work ↔ run | existing exact link (`work_item_id`, `aptrace_run_ids`) |

Beads holds ids and the specific objective, nothing else from the ledger.
The bounded context is re-assembled from the ledger when the item runs. If
the candidate no longer derives (its basis or inputs changed), `research
--work-item` refuses and leaves the item unchanged.

## Context passed to the follow-up

`seed_session` adds the following, and nothing is replayed into the
session's evidence ledger:

| Item | Bound | Seen by the planner as |
|---|---|---|
| objective (specific question, prior run, consolidated leads) | 640 chars (projection objective budget) | `OBJECTIVE` |
| prior claim as unverified hypothesis | 200 chars | `PH1[hypothesis] [prior Cn:vm PROPOSED, unverified] …` |
| gap / audit / verification details | ≤ 3 × 200 chars | `PQ1..3[open]` |
| seeded leads (executable, validated) | ≤ 8 | `LEADS` (the controller still shows ≤ 6) |
| prior evidence | ids only | — (recorded in provenance) |

The projection clips the `OPEN` section further (260 chars, 130 per item).
On the live case run, follow-up planner prompts stayed at 1.7–3.0 k chars
(≤ 2.0 k tokens). That is the same scale as the source run (1.0 k tokens),
not a transcript.

## Failure and recovery

| Situation | Behaviour |
|---|---|
| inputs changed since the run | frontier `unavailable`; only claim candidates; disclosed |
| no deriver wired | same, disclosed |
| recorded and re-derived counts differ | disclosed as `MISMATCH` |
| candidate blocked or redundant | `--create` refuses (`FollowUpRefused`) |
| work store unavailable at preview | annotations say so; preview still runs |
| source work item not in the store | created without `discovered-from`; note |
| concurrent creation / lock contention | one item; losers get the item or `WorkStoreUnavailable` |
| candidate no longer derives at run time | `research --work-item` refuses before claiming |
| follow-up run interrupted | existing reconciliation (unchanged) |

A related fix was found during the live run and made in the recorder. A
lead's sources could grow after it was followed, when a later observation
re-derived the same lead. The recorder then wrote that later *session* id
(e.g. `E7`) into the earlier invocation's `input_evidence_ids`. Inputs are
now only earlier session observations or durable ledger evidence.

## Limitations

- **The frontier is re-derived, not recorded.** It depends on the
  `LeadDeriver` code and on unchanged inputs. A run recorded before a
  deriver change could re-derive differently; only the count check would
  notice.
- **The gap rule is narrow.** Only peripheral-access assertions are
  checked, and claim-to-gap matching reads assertion prose. Claims with
  typed semantics are not yet used for gap detection.
- **The live planner repeats prior analyses.** The controller's
  `ALREADY RUN` and analysis palette are session-scoped, and its rule 1
  asks for any named subsystem not under `ALREADY RUN`. Listing prior
  analyses in the objective (n = 1) did not prevent repetition, and that
  run ended early on `planner_contract_exhausted`. The variant was
  reverted.
- **An inconclusive follow-up suppresses its question.** Once a follow-up
  run exists for a key, the question is `redundant` until its evidence
  basis changes or an operator reruns the item. The suppression states how
  many seeded leads were followed.
- **Ranking uses categories, not utility.** It does not estimate which
  tool can answer a question beyond "is an APTrace operation".
- **A follow-up's new evidence does not enter the original claim's basis.**
  Re-evaluating the originating question is an explicit verification or
  audit step.

## Remaining operator decisions

- Which shortlist candidate to create (`--select`); nothing is created by
  default.
- When to run, rerun (`--rerun`) and complete a follow-up item.
- Whether a follow-up answered its question: verify or audit the claims, or
  supersede the original claim.
- Blocked candidates (hardware, unavailable tools): gather the external
  evidence or drop the question.
- Contradicted claims: revise or supersede.

## Next milestone

Make the follow-up planner see the source run's analyses as already run.
At session seeding, put the prior analyses the candidate cites (durable
`operation_key`s) into the projection's `ALREADY RUN` / `INSPECTED`
sections and the controller's analysed-peripheral filter. Do this as
referenced prior analyses, not replayed observations. Then measure
seeded-lead uptake and repeated operations on the case follow-up across
several live runs before changing anything else.

The second step is to record the open-lead frontier on new runs, so
continuity no longer depends on re-derivation.

## Reproducing

```bash
cd agent
uv run pytest -q tests/test_followups.py      # scenarios A-F, CLI, real bd (skips without bd)
uv run aptrace-agent followups <run-id>        # preview
uv run aptrace-agent followups <run-id> --create --select 1
uv run aptrace-agent research --ledger --work-item <apt-fq...>
```
