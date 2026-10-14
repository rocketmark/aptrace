# Claim Candidates: Deterministic Evidence-to-Claim Selection

> APTrace should mechanically express the facts its tools establish. The
> planner decides which of them matter. It never writes their identifiers,
> provenance or evidentiary strength.

[Claim admission](claim-admission.md) blocks malformed and overstated
proposals. It cannot help a planner that can't express a typed claim at
all. The planner's claim line (`GRADE [TYPE] E#,E# assertion`) carries no
typed semantics, so a local planner's claims are untyped hypotheses capped
at `PROBABLE`. In practice, they are often rejected.

Candidate generation separates three steps:

1. **Extraction:** APTrace derives typed facts from session evidence using
   fixed rules.
2. **Selection:** the planner names candidate ids. That is all it can do.
3. **Admission and verification:** a selected candidate becomes a proposal
   and goes through the unchanged admission. The verifier is also
   unchanged.

Code:

- `agent/src/aptrace_agent/research/candidates.py`: generation, ranking,
  selection parsing, equivalence lookup, and the read-only run preview.
- `ResearchController._select_candidates` / `_request_candidate_selection`:
  the selection request after the final-claims phase.
- `ledger/recorder.py`: the equivalence guard at claim creation.
- Records: `ClaimCandidate`, `CandidateWithheld`, `CandidateSelection`
  (`InvestigationRun.candidate_selection`), and
  `ClaimAdmission.candidate_id`.

## Supported candidates

Each extractor reads the structured facts the verifier itself uses
(`claim_semantics.extract_facts`). As a result, a candidate cannot claim a
role or relation that phase B would not find.

| Extractor | Typed semantics | Evidence and rule |
|---|---|---|
| `peripheral-role` | `FUNCTION_ROLE … MMIO_USER`, claim type `BEHAVIOR` | One of the following: a census constant-address MMIO site; a USB-inventory register user; or a `function_effects` access in the MMIO region. A `function_effects` access must be at a concrete address that depends on no input, in an analysis with no argument specialization. |
| `peripheral-role` | `FUNCTION_ROLE … ADDRESS_CONSTANT_LOADER`, claim type `STRUCTURE` | A census entry with constant loads, where no source records an MMIO access for that function, including an access attributed to no peripheral. |
| `resolved-pointer` | `RESOLVED_FUNCTION_POINTER`, claim type `RESOLUTION` | Census `resolved_indirect` edges for one slot. Their fields are merged, and the candidate is withheld if they disagree. |

### Withheld facts

Facts the generator finds but does not offer are recorded as
`CandidateWithheld`, each with a code:

| Code | Meaning |
|---|---|
| `ACCESS_UNDER_ASSUMPTION` | An MMIO access was observed only under an argument specialization (a harness assumption), or at an input-dependent address. `FUNCTION_ROLE` cannot state the condition. |
| `ROLE_CONFLICT` | The census lists a function for its address constants only, but other evidence records an MMIO access in it. A loader fact would misstate this. |
| `POINTER_CONFLICT` | Edges for one slot disagree. |
| `ENTITY_UNKNOWN` / `PERIPHERAL_UNKNOWN` | The fact names a function the firmware index does not know, or an unknown peripheral. |
| `GRADE_INSUFFICIENT` | No supporting evidence is graded `PROBABLE` or stronger. Bounded, failed and ungraded results support no candidate. |
| `SEMANTICS_UNSUPPORTED` | Defensive check: the verifier's own semantics check failed on the candidate's support. |

### Not extracted

There are no candidates for the following:

- **Call-site relations ("A calls B").** No typed predicate exists.
- **Bounded effects observations** ("no MMIO site observed", "address
  depends on r0"). No typed predicate exists. These observations appear as
  limitations of related candidates instead.
- **Negative assertions of any kind**, including `NO_KNOWN_PATH`.
- **Common-path relations.** These were deferred: they need set-scope
  attribution, which `_side_scopes` marks with notes.

Representing any of these would require a typed-semantics extension (see
[Limitations](#limitations)). Prose cannot carry them.

## What a candidate holds

`ClaimCandidate` is a frozen record. It has no claim id and no lifecycle
state.

- `candidate_id`: `K-` followed by 12 hex characters of a SHA-256 digest
  over:
  - the generator version (`candidates-v1`);
  - the claim type, semantics and grade;
  - the sorted *content identities* of the supporting evidence (tool,
    canonical arguments, and canonical result; volatile fields removed).

  Session numbering and model text never enter the digest. A historical
  result reused by reference and a fresh identical execution give the same
  id. The firmware identity enters through the results' own provenance.
- `semantics`, `claim_type`, `grade`: `grade` is `grade_ceiling` over the
  supporting evidence, the same function admission applies.
- `assertion`: generated from the semantics and evidence fields. It is
  presentation only.
- `scope`, `assumptions`, `limitations`:
  - `scope` names the analysis kind, for example "static census
    references", or "symbolic function-effects analysis without argument
    specialization, not solver-confirmed".
  - `assumptions` holds the effects harness assumptions.
  - `limitations` holds what the fact does not establish. For example, a
    loader candidate states that it neither establishes nor excludes a
    register access, and repeats any input-dependent addresses that the
    function's effects analysis records.
- `supporting_evidence_ids`: session ids. `durable_evidence_ids` holds the
  durable ids and is filled at recording; historical evidence keeps its
  original id. `prior_evidence_ids` lists reused support.
- `considered`: followed seeded-lead evidence about the candidate's
  functions that is not support, mapped to a deterministic reason. Either
  the evidence "limits, does not support" the fact, or it "does not
  establish this fact and records no conflicting role or pointer fact for
  it". Conflicts are withheld by construction, so the second statement is
  true. These reasons become the proposal's omission explanations for
  admission rule 7.
- `seeded_leads`: the seeded leads whose evidence supports the candidate
  or was considered.
- `existing_claims`: equivalent claims already in the ledger, when the
  session can read the ledger.

## Ranking and the bound

Candidates are sorted by:

1. names a function from the objective;
2. its role's peripheral is named in the objective;
3. it has a seeded-lead contribution;
4. not already recorded;
5. kind: access, then pointer, then loader;
6. candidate id.

The controller offers the top `max_claim_candidates`. The default is 0
(off) for the controller. On the CLI, `research --ledger
--claim-candidates N` defaults to 5. Valid candidates beyond the limit are
recorded in `CandidateSelection.omitted`, and the prompt states how many
were not shown.

The selection request is the objective plus the candidate list. It
includes no research state. On the measured case it was about 2 KB, well
inside the local planner's prefill envelope (see [status](status.md)).

## Selection

The selection is one request with one tool: `select_claims(selected:
string, reason?)`. A single string matches the local planner's reliable
output form.

- Only `K-…` tokens are read, and each must equal an offered id exactly.
  Nothing is reinterpreted: case changes and truncations are invalid.
- An unknown id is recorded as a rejected selection with
  `CANDIDATE_UNKNOWN`. A valid id that was not offered is rejected with
  `CANDIDATE_NOT_OFFERED`. Prose with no id is also recorded as invalid.
- Each selected id is resolved against the immutable record.
  `proposal_for(candidate)` builds the proposal from that record alone.
  Any other argument in the tool call is ignored, so the model cannot
  change semantics, grade, scope, evidence or text.
- The proposal passes `admission.admit` unchanged. Every rule applies,
  including grade ceilings, typed-semantics consistency and
  accountability. There is no correction round, because a candidate cannot
  be corrected.

Free-form claims are unaffected. The `finish` claim line and its one
correction round run first, exactly as before. Their admitted proposals and
any selected candidates are recorded side by side. The `round` field
distinguishes them, and `candidate_id` is set only on candidate-derived
records.

## Duplicates

Two claim versions are **equivalent** when their typed semantics are equal
(`ClaimSemantics` equality) and the existing version is not `SUPERSEDED`.
Typed semantics are what verification checks, so equal semantics assert
the same fact.

- **At recording (authoritative).** For a candidate-derived proposal, the
  recorder looks for equivalent claims, from any run or created earlier in
  this one. If one exists, no claim version is created. The admission
  record becomes `decision: duplicate`, with a `CLAIM_EQUIVALENT_EXISTS`
  note listing the existing keys and states.
- **At selection (informational).** In a follow-up session, which can read
  the ledger through its history, existing equivalents are shown next to
  the candidate and rank it lower.

Existing claims are never merged, superseded or rewritten. Free-form
proposals keep their previous behaviour: possible duplicates are reported
by work reconciliation and never merged. The ledger can already contain
equivalent claims recorded before this check existed. Those are left as
they are.

## Grade, lifecycle and verification

- A candidate's grade is never above `grade_ceiling` of its support.
  Admission re-checks this.
- Candidate generation writes nothing. An admitted candidate is a
  `PROPOSED` claim version, `proposed_by: candidate-selection:<model>`, with
  the candidate id in `derivation`. Nothing is verified because it was
  machine-generated.
- Verification is unchanged:
  - `ADDRESS_CONSTANT_LOADER` has no verification-policy class, so it is
    held `UNDETERMINED`.
  - `MMIO_USER` is `MEMORY_ACCESS`, and `RESOLVED_FUNCTION_POINTER` is
    `RESOLVED_INDIRECT_CALL`.
  - Under policy v1, all of them stay `PROPOSED` until an independent
    corroboration contract exists.
- Reused historical evidence is cited by its original id. Admission notes
  it as `HISTORICAL_REFERENCE`, and it never adds corroboration.

## Read-only preview

```
aptrace-agent candidates <run-id> [--limit N] [--json]
```

This regenerates candidates from a recorded run's valid, intact evidence:
its own evidence and the evidence it reused, under durable ids. It lists
equivalent existing claims and withheld facts, and writes nothing.

## Compatibility

`candidate_selection` and `ClaimAdmission.candidate_id` are omitted from
serialized records when unset. Earlier runs and admission records load and
serialize byte-for-byte as before. `decision: duplicate` is a new value of
an existing string field.

## Limitations

- Only three typed facts are extracted. Call-site relations, bounded
  effects observations, and accesses that hold only under an argument
  specialization need typed predicates before they can be candidates. For
  example:
  - an `EFFECTS_OBSERVATION` predicate scoped to one analysis operation;
  - a `FUNCTION_ROLE` with a condition on specialized inputs.
- Contradiction handling is limited to the conflicts the extractors define
  (role conflict, pointer disagreement). Other structured observations
  that limit a candidate are attached as limitations, not evaluated.
- The equivalence check uses exact typed semantics. A claim that states
  the same fact without semantics, or with different optional fields (for
  example a pointer claim without `registration_caller`), is not detected
  as equivalent.
- Relevance ranking is lexical: functions and peripherals named in the
  objective, plus seeded-lead contribution.
- The local runtime's tool-call parsing is sensitive to how the candidate
  list is worded. In replays of one recorded selection request, a
  bracketed annotation such as `[already recorded: Cn:v1 PROPOSED]`, and
  some plain variants, made the runtime reject the model's tool call
  (`incomplete_tool_call`) on every attempt. The current wording ("Already
  recorded as claim Cn:v1 in state PROPOSED.") succeeded in those replays.
  The controller's single correction retry is the fallback, and a failed
  selection is recorded as `planner-failed`, with no claim.
- An `ADDRESS_CONSTANT_LOADER` fact is a static structural fact. It is
  useful as a corrected statement of what the evidence shows. It answers
  no behavioural question.
