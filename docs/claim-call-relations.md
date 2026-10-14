# Call-Relation Admission

> APTrace may record uncertainty about a possible call relationship. It
> must never turn that uncertainty into an established edge because a
> model asserted one.

A claim that one function calls, dispatches to, reaches, or never calls
another is checked against the call edges in the evidence it cites.

Before this check, a prose claim was capped at `PROBABLE`, but nothing
compared the relation it stated with the evidence. A claim "`A` calls `B`"
was admitted when it cited one result showing `A` calling some other
function and another result listing **no** callers of `B`. Every
identifier was valid and every citation resolved, so admission passed.

Code:

- `agent/src/aptrace_agent/ledger/call_relations.py`: edge extraction, the
  matcher, and the prose classifier.
- `ledger/claim_semantics.py`: the typed `CALL_RELATION` predicate.
- `ledger/claim_checks.py`: the `CALL_*` diagnostic codes.
- Wiring:
  - `research/admission.py`;
  - `ledger/verifier.py` (phase B);
  - `ledger/policy.py` and `ledger/gate.py` (claim class, material
    addresses).

## Edge kinds

Edges come only from structured result fields:

| Kind | Meaning | Evidence |
|---|---|---|
| `DIRECT_CALL` | a call instruction to a specific function | `function_facts` callers/callees (Ghidra call references); decoded `BL`/`BLX` immediates in `function_disassembly` or `callsite_context`; static call sites listed by `observed_call_arguments` |
| `TAIL_TRANSFER` | a branch that leaves the source function | decoded `B`, `B.W`, `B<c>`(`.W`) immediates outside the decoded function's extent (`function_disassembly`) |
| `ESTABLISHED_INDIRECT` | an indirect transfer with a statically established target | `indirect_call_target` with `STATICALLY_ESTABLISHED` and an `ESTABLISHED` derivation; census `resolved_indirect` edges of `EXACT`/`STRONG` confidence |
| `POTENTIAL_INDIRECT` | a target an indirect transfer can take under a stated condition | every other `indirect_call_target` candidate, with its basis (for example "IF the receiver's vptr is V") and the addresses that condition names: vtable, table entry, slot |
| `OBSERVED_DISPATCH` | a transfer concretely taken in one scenario | `observed_call_arguments` call sites with hits, labeled with the result's scenario |

Not edges:

- a function named in a result;
- a table entry or a function pointer;
- a missing edge.

An indirect site with no derived target is recorded as **unresolved**.

A dynamically observed site has no static caller. The source of its edge is
taken only from other cited evidence that places the site's instruction in
a function: an indirect-target result's containing function, or a decoded
instruction address.

## What an assertion needs

| Assertion | Supported by | Otherwise |
|---|---|---|
| categorical edge: "A calls B" | a static edge: direct, tail or established indirect | `CALL_CONDITION_OMITTED` if only a potential edge exists; `CALL_SCOPE_EXCEEDED` if only an observation exists |
| possible edge: "A can call B" | a static or observed edge, or a potential edge whose condition the claim restates: conditional wording plus at least one address the condition names | `CALL_CONDITION_OMITTED` |
| observed edge: "A was observed calling B during S" | an observed dispatch in a scenario the claim names | `CALL_SCOPE_EXCEEDED` (another scenario); `CALL_RELATION_UNSUPPORTED` (static edges only) |
| "always", "every execution", "unconditionally" | nothing | `CALL_SCOPE_EXCEEDED` |
| reachability: "A reaches B" | a path of cited edges from A, at most 8 edges, each edge within the claim's scope | `CALL_REACHABILITY_UNSUPPORTED` |
| reachability of B alone: "B is reachable" | an observed entry of B in a scenario the claim names, or census `DEFINITELY_REACHABLE` stated as the census's static result | `CALL_REACHABILITY_UNSUPPORTED` |
| absence: "A never calls B", "B has no callers" | stated as a property of the recorded analysis ("no recorded caller") | `CALL_ABSENCE_NOT_ESTABLISHED`; also raised when a cited edge contradicts the absence |

When no edge connects the claim's endpoints, the diagnostic names the
nearest evidence instead:

| Code | When |
|---|---|
| `CALL_SITE_MISMATCH` | the edge exists at another site |
| `CALL_TARGET_MISMATCH` | the named site goes elsewhere, or a cited result enumerates the source's direct calls without the target |
| `CALL_TARGET_UNRESOLVED` | the named site, or an indirect site of the source, has no derived target |
| `CALL_SOURCE_MISMATCH` | cited edges reach the target only from other functions |
| `CALL_RELATION_UNSUPPORTED` | anything else; the detail lists what the cited evidence does show about both endpoints |

Other rules:

- **Disjunctions.** Each target in "calls B or C" must be supported.
- **Nothing is rewritten.** A categorical claim is rejected even when a
  conditional form of it would have been admitted. The rejection names the
  omitted condition or scope.
- **Grade.** A relation may be no stronger than the evidence supporting its
  edge. Other, stronger citations do not raise it. A breach is
  `GRADE_ABOVE_CEILING`.

Every check is `reject` except three notes:

- `CALL_RELATION_CHECKED`: the supporting kind and evidence;
- `CALL_ABSENCE_SCOPED`;
- `CALL_RELATION_UNCHECKED`: call wording without identifiable endpoints.

Every diagnostic records:

- the relation as `value` (for example `FUN_A -> FUN_B at 0x…`);
- the evidence ids;
- `basis: pattern-matched` for prose, `structured` for typed claims.

Rejected proposals keep their original text on
`InvestigationRun.claim_admission`, like every admission rejection.

## Typed relations

```json
{"predicate": "CALL_RELATION",
 "call": {"source": "FUN_…", "target": "0x…", "kind": "POTENTIAL_INDIRECT",
          "site": "0x…", "conditions": ["receiver vptr 0x…"], "scenario": null}}
```

- **Kinds.** `kind` is one of the five edge kinds.
- **Required fields.**
  - `POTENTIAL_INDIRECT` needs `conditions`.
  - `OBSERVED_DISPATCH` needs `scenario`.
- **Matching.** A typed relation must match an evidence edge of a
  supporting kind:
  - `POTENTIAL_INDIRECT` is also satisfied by an established indirect edge;
  - every other kind needs its own kind.
- **Kind mismatch.** A wrong kind is `CALL_KIND_MISMATCH`, for example a
  tail branch claimed as `DIRECT_CALL`.
- **Diagnostic codes.** Typed failures carry the same `CALL_*` code as
  prose (`SemanticCheck.diagnostic`). Admission reports that code instead
  of `SEMANTICS_INCONSISTENT`.
- **Policy class.**
  - Direct, tail and observed relations are `CONTROL_FLOW`.
  - Indirect relations are `RESOLVED_INDIRECT_CALL`.
  - Neither class has an evidence contract, so such claims stay
    `PROPOSED`.

No candidate extractor generates `CALL_RELATION` yet.

## Where it applies

- **Admission.** One shared boundary covers:
  - free-form proposals;
  - the correction round (its proposals pass the same `admit`);
  - selected candidates.

  Prose claims get `call_diagnostics`. Typed claims get the same matcher
  through `verify_semantics`.
- **Verification phase B.**
  - Untyped claims get a `call_relations` check (BLOCK).
  - Typed relations get `claim_semantics` and `call_relation_grade`.

  Older persisted claims load unchanged. Re-verifying a historical
  unsupported claim would block it, so recognizing one is reported, not
  applied to its lifecycle.

## Prose forms

The classifier works per clause. Clauses split at `;`, `.`,
parentheses, "but", "while", "though", and ", which". Endpoints are
`FUN_xxxxxxxx` names or `0x` addresses.

| Form | Example | Reads as |
|---|---|---|
| active | `A calls B`, `A can call B or C`, `A tail-calls B at 0x…`, `A dispatches to the thunk at 0x…`, `A invokes B`, `A was observed calling B during boot` | edge A→B (and A→C) |
| subject site | `A's indirect call at 0xS may dispatch to B`, `the call at 0xS in A calls B` | edge A→B at S |
| passive | `B is called by A`, `B is called from 0xS`, `B is a potential target of the indirect call at 0xS in A` | edge A→B |
| reach | `A reaches B`, `B is reachable from A`, `B is reachable` | path, or B from a root |
| absence | `A does not call B`, `A never calls B`, `B is not called by A`, `B has no callers` | absence |

The classifier reads modality and scope from the clause:

- **Modality:**
  - "can", "may", "if", "when", "potential" make the claim *possible*;
  - "observed", "during", "scenario" make it *observed*;
  - everything else is *categorical*.
- **Universal scope:** "always", "every execution", "unconditionally",
  "whenever".
- **Hedged clauses** are not assertions and are not checked: "whether",
  "not established", "undetermined", "unclear".
- **Unrelated words.** "Callback", "caller", "call site" and "call graph"
  are nouns, never verbs. A claim containing them is not a call claim.

**Not classified** (`CALL_RELATION_UNCHECKED`, or no call check):

- an endpoint that is not an entity: "the handler calls B", "A calls a
  vtable method";
- an endpoint that is the object of a preposition: "the pointer written by
  A is invoked from …";
- a relative-pronoun subject: "B is called by A, which is called by C"
  checks A→B only;
- bare hex without `0x` or `FUN_` ("c5cc calls c7c0");
- multi-hop edge claims such as "A calls B via C", which are checked as
  A→B;
- unreachability wording, which is covered only by `NO_KNOWN_PATH`'s
  absolute-negative guard.

An unclassified claim stays an untyped hypothesis. Admission caps it at
`PROBABLE`, and the `CALL_RELATION_UNCHECKED` note records that its call
wording was not checked.

## Limitations

- **Call graph.** `function_facts` edges are Ghidra call references over
  heuristic boundaries. They do not distinguish `BL` from a tail call
  Ghidra marked as a call. Only decoded instructions establish
  `TAIL_TRANSFER`.
- **Path checks.** Reachability is checked only over *cited* edges. A
  static path shows that call instructions connect the functions, not that
  each instruction executes.
- **Census reachability** comes from census roots. Claims may use it only
  stated as the census's result. The census and case analyses can
  disagree; such disagreements are evidence, not settled here.
- **Conditions** are matched by address: the vtable, slot or store the
  condition names. A condition stated without its address is not
  recognized as retained.
- **Prose coverage.** The classifier is deliberately small. A wording
  outside its forms is not checked, only capped.
