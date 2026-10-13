# Research Ledger, Adversarial Audit, and Verification

APTrace treats findings as versioned, executable research artifacts. The
ledger is canonical; Markdown reports are generated views of it.

Cross-engine corroboration requirements for promotion (independent discovery,
deterministic comparison, discrepancy retention, claim-class verification
policy) are defined in
[`cross-engine-verification.md`](cross-engine-verification.md). They extend
the verification described here. A first safety gate (verification policy v1,
phase P) is enforced; most cross-engine capabilities are not yet built, so
most claim classes cannot reach `VERIFIED` today. See
[Verification](#verification).

## Three layers, three authorities

| Layer | Who | May | May not |
|---|---|---|---|
| Investigation | research model (planner) | choose analyses, propose claims | mark anything verified |
| Adversarial audit | audit model | challenge one claim version, request typed analyses, record a verdict | change claim state |
| Verification and knowledge management | APTrace | execute operations, validate references, replay, track versions and dependencies, move claims between states | — |

Code: `agent/src/aptrace_agent/ledger/`. Application wiring (case identity,
ledger location, input artifacts) is in `aptrace_agent/ledger_wiring.py`.

## Store

An append-only, content-addressed directory owned by the case:

```
runs/<run_id>.json                 InvestigationRun (investigation, benchmark-setup)
invocations/<invocation_id>.json   ToolInvocation
evidence/<evidence_id>.json        EvidenceArtifact metadata
blobs/<sha[:2]>/<sha>.json         structured results (content-addressed)
blobs-large/<sha[:2]>/<sha>.json   results above 4 MB (may be untracked)
claims/<claim_id>/v<N>.json        ClaimVersion
audits/<audit_id>.json             AuditRecord
verifications/<id>.json            VerificationRecord
events.jsonl                       lifecycle events (append-only)
```

Every JSON record is written once; rewriting different content raises.
An `InvestigationRun` may carry `work_item_id`, an opaque reference to the
work item it was executed for ([`work-store.md`](work-store.md)). It is set
at recording, and it is absent from standalone and older runs.
A follow-up run also carries `followup` (`FollowUpProvenance`): the
candidate key, source run, cited claim/audit/verification/evidence ids, the
seeded leads, and the bounded text the planner was given; `parent_run_id`
names the source run ([`spikes/investigation-continuity.md`](spikes/investigation-continuity.md)).
Prior claims in that context are unverified hypotheses, never evidence.
Its `continuity` record lists historical results the run used by reference
(original invocation and evidence ids; no new invocation or evidence is
written for them), refused reuse with reasons, seeded-lead outcomes, and
the step budget ([`research-continuity.md`](research-continuity.md)).
Current claim and evidence state is folded from `events.jsonl` and never
stored on a record, so history is never rewritten.

## Identity and replay

- **ExecutionContext**: case, firmware key and sha256, and sha256 of each
  input artifact (census database, Ghidra export, Ghidra project cache
  identity, SVD, generated Ghidra seeds, Macaw census). Generated artifacts
  are referenced by content hash only. The Ghidra export is the seeded
  persistent-project export the census is built from; the agent refuses a
  cache whose identity (firmware, build scripts, generated seeds) is stale.
- **ToolInvocation**: a typed operation (`tool` + validated `arguments`)
  plus the input-artifact hashes that operation reads. `operation_key` is
  equal for every execution of the same operation on the same inputs. No
  shell command is ever persisted; replay re-executes the typed operation
  through the same `EvidenceExecutor`.
- **EvidenceArtifact**: id derived from `operation_key` and the result hash,
  so identical results are one artifact across runs. Each artifact records a
  mechanical grade and the limitations its result carries.

Results are hashed in **evidence form**: volatile execution metadata that
differs between identical analyses (FunctionEffects `provenance.cached`) is
removed first. Results above 4 MB are stored under `blobs-large/`, which a
case may keep out of version control; the tracked evidence record keeps the
hash, and replay re-derives and re-verifies an absent large result.

Case-document search is recorded but not replay-verifiable: it reads mutable
prose.

## Grades and states are independent

Evidence grade (`EXACT > STRONG > PROBABLE > BOUNDED > UNKNOWN`) uses
classifications the producing analyses already emit: census confidence,
`PathStatus` (`NO_KNOWN_PATH` is `BOUNDED`), and FunctionEffects coverage
status. Claim lifecycle state is separate and owned by APTrace:

`PROPOSED`, `VERIFIED`, `BLOCKED`, `STALE`, `SUPERSEDED`.

`STRONG + PROPOSED` and `STRONG + VERIFIED` are both valid.

## Claims

A ClaimVersion (`C42:v1`) records subject, assertion, type, proposed grade,
scope, assumptions, limitations, supporting and contradictory evidence ids,
version-pinned dependencies, derivation, proposer, and run. Changing a claim
writes `C42:v2` with `supersedes: C42:v1`; v1 becomes `SUPERSEDED` and is
never modified.

Limitations carried by supporting evidence are **inherited mechanically**
when a version is written, so a proposer cannot drop them.

### Typed semantics

A claim version may carry `semantics`: a structured predicate that is
**authoritative for verification** (the prose assertion is presentation).
Code: `ledger/claim_semantics.py`. Only predicates current evidence
establishes mechanically exist:

| Predicate | Fields |
|---|---|
| `RESOLVED_FUNCTION_POINTER` | `slot`, and any of `writer`, `writer_instruction`, `registration_caller`, `registration_callsite`, `raw_pointer`, `canonical_target`, `forwarding_target`, `indirect_site`, `indirect_caller` |
| `FUNCTION_ROLE` | `function`, `role` (`WRITER`, `CALLBACK_TARGET`, `FORWARDING_TARGET`, `REGISTRATION_CALLER`, `INDIRECT_CALLER`, `INTERRUPT_VECTOR_HANDLER`, `MMIO_USER`), optional `slot`/`peripheral` context |
| `PATH_RELATION` | `status` (`KNOWN_COMMON_PATH`/`NO_KNOWN_PATH`), typed `left`/`right` set scopes |
| `CODE_PRESENCE` | `address`, optional `function_entry` (the containing function's entry); checked against structural source-agreement evidence |

Set scopes are `KIND:NAME` with kinds `PERIPHERAL_MMIO_USAGE`,
`INTERFACE_INVENTORY` (MMIO register users plus IRQ vector handlers, e.g. the
USB inventory set), `IRQ_ROOT_SET`, `INTERRUPT_DISPATCH_SET`, `FUNCTION_SET`.
Common-path evidence is typed from its set labels and the supporting
evidence that produced each set (members are cross-checked); a label APTrace
cannot attribute is `UNATTRIBUTED`. No analysis currently produces
`INTERRUPT_DISPATCH_SET`, and no derivation makes different kinds equivalent.

Semantic checks report `ENTITY_ROLE_MISMATCH` (the claimed entity holds a
different role in the evidence), `RELATION_MISMATCH` (wrong value, swapped
endpoints, non-Thumb-canonical target, wrong path status),
`RELATION_UNSUPPORTED` (the evidence does not establish the field),
`SCOPE_MISMATCH`, and `PREDICATE_TYPE_MISMATCH`, each with the claimed
entity/role, the evidence role, and the evidence id.

## Structural source agreement

`structural_source_agreement` is a recorded, replayable operation over a
bounded set of code addresses. For each address it asks every code-discovery
source (census database, Ghidra export, Macaw census) whether it recognizes
code there and in which function, extent, and blocks, and classifies:

| Status | Meaning for a claim |
|---|---|
| `AGREE` | consistent |
| `PARTIAL_AGREEMENT` | consistent; one source covers a subset, or lacks the code (`<SOURCE>_COVERAGE_GAP`) |
| `SOURCE_MISSING` | fewer than two sources have code there: a **coverage gap**, never negative firmware evidence |
| `BOUNDARY_DISAGREEMENT` | sources see code but disagree on function start/extent: structural, **not** a contradiction of the claim |
| `CONFLICT` | a source affirmatively classifies the address as non-code while another decodes code: contradictory structural evidence |

Agreement is structural consistency, not semantic proof, and sources are not
necessarily independent: each observation records what it is derived from
(the census function table is derived from the same Ghidra project). Macaw
discovery is seeded only from vector-table roots, so code reached only
through resolved pointers is a Macaw coverage gap. Code:
`aptrace_agent/source_agreement.py`.

The verification-policy gate (phase P, below) records source agreement for
a typed claim's asserted code addresses before any audit and evaluates it
mechanically: a `CONFLICT` at an address the claim asserts is code blocks
the claim; a function-start disagreement where the claim asserts the
containing function is an unresolved discrepancy that holds it; conflicts
elsewhere are recorded as not material. The audit model still receives
source agreement as context. Agreement counts as independent corroboration
only when each source declares an independence envelope (`lineage`,
`firmware_sha256`, `engine_version`; optional `assisted`) and two sources
with disjoint lineages agree. No current source declares one, so real
source agreement does not satisfy corroboration yet. See
[`cross-engine-verification.md`](cross-engine-verification.md).

## Audit

The auditor sees one claim version: assertion, grade, scope, assumptions,
limitations, dependencies, and compact deterministic evidence summaries. It
never sees the investigator's transcript or derivation. It answers in JSON:
a typed analysis request, or a verdict (`SUPPORTED`, `CHALLENGED`,
`UNRESOLVED`) with a required `scope_check`, reasoning, challenges, evidence
inspected, limitations, and follow-up requests.

Since `audit-v0.4` the compact evidence includes the structured provenance
of resolved RAM function pointers (consumer site, slot, writer and store
instruction, registration callsite and its function, raw and canonical
pointer, forwarding target, edge grade), and APTrace records structural
source agreement for the code addresses that evidence names and shows it
with its coverage gaps.

APTrace enforces the contract: a decision and analysis budget, one format
correction per decision, duplicate-request rejection (including requests
that repeat supporting evidence), at least one **successful** falsification
analysis before a verdict, and a tool allowlist. Only a request that passes
validation, is not a duplicate, and is executed with a structured result or
a legitimate coverage-gap result (the source lacks the entity) counts;
duplicate, invalid, unavailable-tool, over-budget, and malformed requests and
harness errors do not. A verdict given without any successful analysis is
recorded as `UNRESOLVED` (synthesized) with the model's verdict kept in
`model_verdict`. Every step records its outcome
(`rejected:<kind>`, `executed:success|coverage_gap|tool_error`,
`parse_failure`, `verdict_rejected`). Each allowed tool maps to one existing
APTrace operation with APTrace-validated arguments: evidence inspection,
function facts and disassembly, peripheral census, USB inventory, common
paths (sets: analyzed peripherals, evidence functions, or `IRQ:<PREFIX>`
interrupt-vector handlers), function effects, evidence replay, and
(optionally) case-document search. Tool failures are reported to the model
as coverage gaps, not firmware evidence. Every step, raw response, request,
result reference, and token count is persisted in the AuditRecord.

Every audit records an **audit-input fingerprint** (`AI-…`): a hash of the
claim version, supporting/contradictory evidence ids and result hashes,
limitations, the exact compact projection, the source-agreement evidence,
the template (version, system prompt, response format), model id,
generation parameters, tool surface, and budget, with per-component hashes
so a change can be attributed. It contains no timestamps or ids, so audits
intended to be identical share it. Audits before `audit-v0.4` have none.
`aptrace-agent audit-repeat C7:v1 --repeat N` measures auditor stability on
one fingerprint (measurement only; verification still uses the rule below).

## Verification

Verification runs in phases. A failure in A or B skips the later phases; a
failure in C skips P and D. A failure in P is final for promotion. D still
reads recorded audits and dependencies, so a CHALLENGED audit still blocks,
but no audit verdict can override P:

- **A structural:** evidence references, supporting evidence present, same
  firmware/case, dependency references exist.
- **B deterministic semantics:** typed semantics (when present), grade
  ceiling, inherited limitations, bounded-negative wording.
- **C replay/freshness:** stored hashes, evidence validity, deterministic replay.
- **P verification policy:** contradictory evidence, structural conflicts,
  and independent corroboration for the claim's class, under the versioned
  policy (`ledger/policy.py`, `ledger/gate.py`).
- **D audit:** dependencies verified, latest non-diagnostic audit.

`precheck` runs A-C and P and never advances a claim. The normal audit pipeline
(`ledger/pipeline.py`, used by `audit`, `audit-repeat`, and benchmarks) is
precheck → audit model only if A-C and P passed → full verification, so the
audit model is never consulted about a claim APTrace already knows is
invalid or cannot meet its verification policy. A
`--diagnostic` audit of an ineligible claim is recorded with
`diagnostic: true` and never used by verification. Each VerificationRecord
stores its mode, per-phase results, semantic-check results, and whether the
audit was skipped.

`VERIFIED` means *consistent with the currently recorded evidence and
APTrace's deterministic checks, after an independent audit returned
SUPPORTED*. It is not a proof of semantic truth. "Independent audit" means the
auditor is separated from the investigator's transcript and derivation; it is
not independent engine corroboration, and the two never substitute for each
other.

Every verification record names the policy it applied (`policy`: id,
version, digest of the canonical definition) and, once phase P runs, the
gate result (`gate`: claim class, status, conditions with evidence ids).
Records written before the policy have `policy: null`; they are never
rewritten. `aptrace-agent policy-status` reports, read-only, which policy
each `VERIFIED` decision applied and how the current policy assesses the
recorded evidence. A new `verify` of such a claim applies the current
policy and appends its own record and event. None of the checks below is
relaxed by the policy. Checks:

| Check | Fail → |
|---|---|
| evidence references resolve; at least one supporting reference | BLOCKED |
| evidence from the claim's firmware and case | BLOCKED |
| stored result hash matches; evidence not invalidated | STALE |
| deterministic replay reproduces the result hash | STALE |
| dependency references exist | BLOCKED |
| dependencies are VERIFIED | stays PROPOSED |
| proposed grade ≤ strongest supporting derivation | BLOCKED |
| inherited limitations present | BLOCKED |
| no unreachability claim; no absolute-negative wording over `NO_KNOWN_PATH` | BLOCKED |
| verification policy gate (P): no typed assertion contradicted by contradictory evidence or a structural `CONFLICT` | BLOCKED |
| verification policy gate (P): no unresolved potentially material contradiction or discrepancy; required independent corroboration present and evaluable; claim class determinable | stays PROPOSED, conditions named |
| latest audit of this exact version SUPPORTED | none/UNRESOLVED: PROPOSED; CHALLENGED: BLOCKED |

The gate's result is `PASSED`, `BLOCKED` (a typed assertion is
contradicted), `HELD` (a required kind of support is missing, or a
potentially material contradiction or discrepancy is unresolved), or
`UNEVALUABLE` (the requirement cannot be evaluated, for example because no
evidence contract exists for the class or independence metadata is
missing). Each condition records its code, status, evidence ids, and the
typed field or address concerned. A held or unevaluable claim may still be
correct. It stays `PROPOSED` and can be re-verified when new evidence
exists. `ledger.transition(..., VERIFIED)` is refused unless it cites a full
verification of that exact version, under the current policy, whose gate
passed.

Any CHALLENGED audit blocks that version permanently; a later SUPPORTED
audit does not override it. A challenge is answered with a new claim
version, which gets its own audit.

## Staleness

Deterministic, no model. Superseded, stale, or blocked claim versions make
their transitive dependents `STALE`. Invalidated evidence (changed stored
hash, or a replay that changes the result) makes every claim relying on it
`STALE`, then their dependents. Generated reports embed the ledger
fingerprint; `aptrace-agent report --check` detects a stale report. Stale
claims are not repaired automatically.

## Commands

```sh
aptrace-agent research --ledger "<objective>"   # record run, evidence, claim proposals
aptrace-agent research --ledger --work-item ID  # same, for a Beads work item (work-store.md)
aptrace-agent claims                            # current state of every claim version
aptrace-agent policy-status [C2:v2 ...]         # read-only: policy of VERIFIED decisions vs current policy
aptrace-agent propose spec.json                 # record a PROPOSED claim from a spec
aptrace-agent audit C7                          # adversarial audit (latest version)
aptrace-agent audit-repeat C7:v1 --repeat 10    # repeated identical audits; stability summary
aptrace-agent verify C7:v1 [--precheck]         # phased deterministic verification (+ replay)
aptrace-agent supersede C7:v1 change.json       # next claim version (prior kept, SUPERSEDED)
aptrace-agent runtime-probe [--audit-id A-...]  # byte-identical requests to the audit-model runtime
aptrace-agent replay TI-...|EV-...              # model-free replay of one invocation
aptrace-agent check                             # re-hash evidence; stale affected claims
aptrace-agent report [--check]                  # generated Markdown view
aptrace-agent benchmark <name>...               # known-answer audit/verify benchmarks
```

`--ledger` turns on the planner's finish claim contract: one scalar string,
one claim per line, `GRADE [TYPE] E#,E# assertion`, with one finish-only
request after the step budget. APTrace translates session evidence ids to
durable ids and keeps unknown references verbatim so verification rejects
them. Benchmark fixtures live in the case; expected outcomes are in a
separate evaluator-only file.
