# Claim Admission and Evidence Accountability

> APTrace should be able to say "we do not know" precisely and durably,
> rather than turning incomplete evidence into an unjustifiably strong
> firmware claim.

The research planner proposes claims when it finishes. Until this change,
every proposal that matched the claim-line format became a `PROPOSED`
claim version, whatever it named or asserted. Lines that did not match
were dropped without a record.

Admission is the boundary between a model proposal and the ledger. It
reuses the verifier's own semantics and grade functions, and it is not a
second validation system.

Code:

- `agent/src/aptrace_agent/research/admission.py`: the admission decision.
- `ledger/claim_checks.py`: shared checks and stable diagnostic codes.
- The controller's `_accept_claims` path.
- One fix in `ledger/claim_semantics.py`.

## Three separate decisions

| Decision | Where | Outcome |
|---|---|---|
| **admission**: well-formed, real entities, supported at its grade? | `research/admission.py`, at the controller's claim boundary | admitted → `PROPOSED` claim version; rejected or unparseable → recorded on the run only |
| **evidentiary support** of typed claims | `claim_semantics.verify_semantics` (same function as verification phase B) | consistent / mismatch per field |
| **verification** | `ClaimVerifier` (phases A–D, policy gate) | `VERIFIED` / `BLOCKED` / `STALE` / held `PROPOSED` |

An admitted claim is only `PROPOSED`. Admission never verifies, and a
grade is never a lifecycle state.

## Admission rules

Every diagnostic has a stable code and a severity (`reject` / `note`).
Pattern-matched applicability is marked `basis: pattern-matched`.

| # | Rule | Codes |
|---|---|---|
| 1 | Parse: one `GRADE [TYPE] E#,E# assertion` line, or a structured claim | `CLAIM_UNPARSEABLE` |
| 2 | References: at least one, each naming session evidence | `EVIDENCE_MISSING`, `EVIDENCE_REFERENCE_UNKNOWN` |
| 3 | Entity identity (below) | `ENTITY_MALFORMED`, `ENTITY_SESSION_REFERENCE`, `ENTITY_UNKNOWN`, `PERIPHERAL_UNKNOWN` |
| 4 | Typed semantics, when given: valid, and consistent with the cited evidence | `SEMANTICS_INVALID`, `SEMANTICS_INCONSISTENT` |
| 5 | Untyped prose about peripheral access: an asserted access needs an access in the evidence; an asserted absence needs complete effects evidence with no input-dependent addresses, or wording that limits it to the recorded analysis | `ACCESS_NOT_ESTABLISHED`, `ABSENCE_NOT_ESTABLISHED`, `ABSENCE_SCOPED` (note) |
| 5b | Call relations (calls, dispatches, reachability, call absence; prose or typed `CALL_RELATION`): supported by cited edges at the asserted kind and scope ([`claim-call-relations.md`](claim-call-relations.md)) | `CALL_*`, e.g. `CALL_RELATION_UNSUPPORTED`, `CALL_CONDITION_OMITTED`, `CALL_SCOPE_EXCEEDED`; `CALL_RELATION_CHECKED` (note) |
| 6 | Grade: at most the cited evidence's ceiling (`grade_ceiling`). Untyped claims are hypotheses nothing checks mechanically, so they are at most `PROBABLE` | `GRADE_ABOVE_CEILING`, `UNTYPED_GRADE` |
| 7 | Accountability in follow-up sessions: evidence of executed or reused follow-up leads about a function the claim names is cited, or its omission is explained (`[omit E#: reason]`) | `EVIDENCE_OMITTED`, `OMISSION_EXPLAINED` (note) |
| 8 | Historical evidence cited by its session alias resolves to the original evidence id; it is a prior observation, not independent corroboration | `HISTORICAL_REFERENCE` (note) |

A proposal is admitted only when it has no `reject` diagnostic. Nothing is
rewritten: an untyped `STRONG` claim is rejected, not downgraded. An
explained omission satisfies rule 7 only; it never overrides rules 3–6.

### Entity identity

- **`ENTITY_MALFORMED`.** Identifier-shaped tokens must be canonical:
  `FUN_` plus 8 lowercase hex digits, or a `0x` address. `E0000b4b4`,
  `FUN_b4b4`, and a bare `0000b4b4` are reported, never reinterpreted.
- **`ENTITY_SESSION_REFERENCE`.** Session evidence ids (`E10`) belong in the
  citation list, not the assertion. The recorder maps citations to durable
  ids, so an id inside the prose would be meaningless in the stored claim.
- **`ENTITY_UNKNOWN`.** `FUN_` names must resolve through the session's
  FunctionFacts reader (the Ghidra index) when one is wired.
- **`PERIPHERAL_UNKNOWN`.** Numbered peripheral names (`SERCOM0`, `TCC1`)
  must be among the census peripherals the controller was given.

Claims that name no function, such as set and path claims, are not
required to name one.

The verifier's phase B applies the canonical-identifier and session-id
checks (`entity_identity`, BLOCK) to every claim, including
operator-proposed ones, and the call-relation rule (`call_relations`, BLOCK)
to untyped ones. No persisted claim is affected.

## Constant load is not an access (typed-fact fix)

Typed `FUNCTION_ROLE … MMIO_USER` claims were checked against census facts
that assigned `MMIO_USER` to every function the census lists for a
peripheral. That includes functions listed only because they load the
peripheral's base address from a literal pool. As a result, a typed claim
of register access could be "consistent" with evidence showing
`mmio_site_count: 0`.

`extract_facts` now assigns:

- `MMIO_USER` for a census constant-address MMIO site, or a
  `function_effects` access in the MMIO region (peripheral from the
  register name);
- `ADDRESS_CONSTANT_LOADER`, a new role, for census entries with constant
  loads and no MMIO site.

A mistaken access claim gets
`ENTITY_ROLE_MISMATCH … ADDRESS_CONSTANT_LOADER, not MMIO_USER`. The new
role has no verification-policy class, so it is held `UNDETERMINED`. No
persisted claim uses `MMIO_USER`.

Typed semantics keep the distinctions the evidence supports:

| Distinction | Typed representation |
|---|---|
| address constant loading | `ADDRESS_CONSTANT_LOADER` |
| peripheral register access | `MMIO_USER` |
| reachability | `PATH_RELATION` |
| resolved pointer writer and target | `RESOLVED_FUNCTION_POINTER` |
| call, tail transfer, indirect target (established or conditional), observed dispatch | `CALL_RELATION` |

Pointer propagation, plain memory read and write, and concrete
caller-supplied values have **no** typed predicate. Claims about them are
untyped hypotheses, and rules 5–6 apply.

## Bounded handling of model output

- **One correction round.** After rule-1–8 rejections, the controller makes
  one finish-only `claim-correction` request. The request shows the
  rejected proposals and their diagnostics, capped at 900 chars, with a
  concrete line example. Its proposals are admitted by the same rules.
  There is no second correction, and no path bypasses admission.
- **Records.** Every proposal of both rounds is in
  `InvestigationRun.claim_admission` (`ClaimAdmission`): round, original
  text, decision, session and durable evidence ids, omissions,
  diagnostics, and the claim version when admitted.
- **No admitted claim is a valid outcome.** A run may end without one. Its
  evidence is recorded either way.
- **Compatibility.** Runs recorded earlier have no `claim_admission` field,
  and their claims are unchanged.

## Limitations

- Rules 5 and 7 decide *applicability* from assertion wording: function
  and peripheral names, access verbs, negation, and qualifying words. A
  claim worded outside those patterns is not checked by them, but it is
  still capped at `PROBABLE` as untyped.
- The planner's claim line cannot carry typed semantics. Structured claims
  (dicts) can, but the local planner emits lines, so its claims are untyped
  hypotheses. Typed claims the evidence establishes mechanically reach
  admission as selected candidates instead
  ([`claim-candidates.md`](claim-candidates.md)); they pass these same
  rules.
- Accountability covers follow-up sessions, through their seeded leads.
  Standalone runs have no lead-relevance record to check against.
- Unknown-function checks need a FunctionFacts reader. Without one, only
  malformed and session-id tokens are caught.
