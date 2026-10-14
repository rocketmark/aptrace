# Independent Discovery and Cross-Engine Verification

This is the canonical statement of how APTrace uses multiple analysis engines
to verify firmware-derived claims. It is **normative**: future engine, ledger,
verification, and agent work must conform to it. Other documents refer here
rather than restating these rules.

Most of what follows is not yet implemented. A first safety gate
(verification policy v1, [below](#verification-policy-v1-safety-gate)) is
enforced. Every requirement is tagged:

| Tag | Meaning |
|---|---|
| **[Implemented]** | Exists in the repository today and behaves as described. |
| **[Partial]** | A precursor exists but does not meet the requirement. |
| **[Required]** | A binding requirement with no implementation yet. |
| **[Proposed]** | One acceptable way to meet a requirement. It is not binding. |

Current implementation status is summarized in
[Implementation status](#implementation-status) and in [`status.md`](status.md).
Ledger mechanics (records, lifecycle, phases A–D) are defined in
[`research-ledger.md`](research-ledger.md). This document adds to them. It
does not redefine them.

## Guiding invariant

> **APTrace must not promote an applicable firmware-derived claim to
> `VERIFIED` without satisfying its defined independent-evidence
> requirements, deterministic comparison policy, and resolution of material
> contradictions.**
>
> The absence of required corroboration must remain visible as an unresolved
> verification condition. It is never silently treated as success.

Independent analysis is a required verification capability, not an optional
optimization and not agent behavior. Not every exploratory query must invoke
several engines. However, a claim subject to cross-engine verification cannot
satisfy its verification policy without the required independent evidence and
comparison.

Multi-engine agreement is never sufficient by itself for `VERIFIED`. All
existing phase A–D checks, including the independent audit, still apply.

## Terms

- **Engine.** An analysis implementation that produces observations about
  firmware: for example a static discovery/lifting tool, a decompiler-based
  static analyzer, a concrete emulator, or a symbolic executor. Engines are
  identified by name, version, and configuration, never by the operation
  that wraps them.
- **Derived source.** A view computed from one engine's output, such as a
  database built from a static export. It shares that engine's lineage and
  is not an engine for independence purposes.
- **Discovery run.** One bounded execution of one engine over one firmware
  artifact under one target configuration.
- **Observation.** One structured fact a discovery run emits, of a declared
  kind such as "code at address", "function entry", "CFG edge", "call edge",
  or "memory access". Observations live in native artifacts. They are not
  translated into a universal schema.
- **Lineage.** The set of engines whose *generated findings* contributed to
  an observation, directly or transitively. This includes seeds, boundaries,
  resolved targets, names, labels, and anything derived from them.
- **Target configuration.** The externally grounded or explicitly assumed
  facts a run is given: architecture and instruction-set mode, load address,
  memory map, discovery-root policy, and execution-mode assumptions.
- **Independent observation.** An observation produced in a discovery run
  that received no other engine's generated findings.
- **Assisted observation.** An observation produced after any cross-engine
  finding was introduced, for example during reconciliation.
- **Comparison record.** The deterministic result of comparing compatible
  observations from two or more runs.
- **Discrepancy.** A retained comparison outcome that is not agreement.
- **Verification policy.** The APTrace-owned, versioned rule set that states,
  for a claim class, what evidence and comparison promotion requires.

The ledger already uses "independent audit" for the audit model's separation
from the investigator's transcript ([`research-ledger.md`](research-ledger.md)).
That is *auditor* independence. This document is about *engine* independence.
They are different requirements, and one never substitutes for the other.

## The four stages

```text
 immutable firmware (sha256) + target configuration (shared, externally grounded)
            |                         |                         |
            v                         v                         v
   engine A discovery        engine B discovery        engine C discovery     1. independent discovery
   (bounded scope)           (bounded scope)           (bounded scope)           no cross-engine findings
            |                         |                         |
            +------------+------------+-------------------------+
                         v
              deterministic comparison                                        2. typed comparison records
     AGREE / DISAGREE / COVERAGE_GAP / INCOMPARABLE / UNAVAILABLE
                         |
                         v
          discrepancies retained in the ledger
                         |
                         v
          reconciliation (hints allowed; results ASSISTED)                    3. never overwrites stage 1/2
                         |
                         v
   claim verification: phases A-C, corroboration policy, D (audit)            4. APTrace decides promotion
```

### 1. Independent discovery

**[Required]** An independent discovery run must have:

- **The same immutable firmware artifact**, identified by content digest.
  The run's result must carry or be mechanically bound to that digest. A file
  path or image size is not enough.
- **An explicit target configuration** recorded with the run: architecture
  and instruction-set mode, load address, memory map, discovery-root policy,
  and execution-mode assumptions. Configurations of runs being compared must
  be equal on every field material to the observation kind. A difference is
  recorded and makes the observations incomparable or scope-restricted. It is
  never treated as disagreement.
- **A bounded scope**, such as address ranges, roots, function sets, and
  step, time, or memory budgets. Hitting a bound is recorded.
- **Separately recorded engine identity**: engine name, version, build or
  configuration identity, and invocation, plus the result.

**[Required]** Inputs to an independent run are restricted:

| May be shared | Must not cross into an independent run |
|---|---|
| firmware bytes (by digest) | another engine's function list, entries, or boundaries |
| architecture facts from the ISA/architecture specification (for example how a vector table is laid out) | another engine's resolved indirect targets or seeds derived from them |
| case-asserted geometry and memory map, recorded as a harness assumption | another engine's CFG, call graph, names, or labels |
| vendor documentation pinned by digest (for example an SVD) | any value derived from the above, however indirectly |

The test for any input: did an analysis engine generate it from these
firmware bytes? If so, it carries that engine's lineage. A run that receives
it is not independent of that engine.

**[Required]** Independence is evaluated per observation, by lineage, not by
counting tool invocations:

- Re-running the same engine is a repeatability check, not corroboration.
- A derived source shares its engine's lineage. For example, a census
  database built from a static export can never corroborate that export.
- Two observations corroborate each other only if their lineages are
  disjoint.
- An engine that seeds itself from its own earlier findings, or from a
  resolver over its own output, stays within its own lineage. The seeds must
  still be recorded.

**[Required]** Once a cross-engine hint is introduced, every result of that
run, and everything derived from it, is **assisted**. It must record which
hints it received and their evidence references. Assisted evidence may
support a discrepancy's resolution. It never satisfies an independence
requirement.

Sequential execution is acceptable and may be preferable on constrained
hosts. Independence is a property of the information flow, not of timing or
concurrency.

### 2. Deterministic comparison

**[Required]** Comparison is a deterministic, replayable APTrace operation
over structured observations. It never runs over model-generated summaries.
Its outputs are ledger evidence, like any other operation result. It
distinguishes at least:

| Outcome | Meaning |
|---|---|
| `AGREE` | Comparable observations match at the declared granularity (possibly one a declared subset of the other). |
| `DISAGREE` | Comparable observations differ. The record states the nature of the difference (for example boundary, edge set, or affirmative code/non-code conflict). |
| `COVERAGE_GAP` | An engine was able and in scope, but has no observation there. This is not negative evidence about the firmware. |
| `INCOMPARABLE` | Configurations, scope, or representation semantics do not permit comparison at the required granularity. |
| `UNAVAILABLE` | The engine was absent, failed, timed out, hit a bound, or does not support the observation kind. The cause is recorded. |

**[Required]** Comparison is defined per observation kind, and only where the
engines' semantics are compatible. Each comparison type declares its
granularity and every normalization it applies. Normalizations are mechanical
and disclosed. Two examples:

- canonicalizing the Thumb state bit in addresses;
- containment matching when one engine reports a call at block start and
  another reports it at the call instruction.

Function counts alone are never evidence of agreement. Equal counts with
different address sets are disagreement.

| Observation kind | Comparable granularity | Notes |
|---|---|---|
| code coverage | byte or instruction address | Whole-image heuristic discovery and root-seeded discovery are comparable only over a common root or reachability scope. |
| instruction decode | address, length, mnemonic and operands | Must agree on instruction-set mode first. |
| basic-block boundaries | block start/end set | |
| function entry and extent | entry address; block set | Boundaries are heuristic in every engine. A boundary disagreement does not contradict a claim that depends only on the code being present. |
| CFG edges | (source block, target, edge kind) | Edge-kind vocabularies differ, so the mapping is declared per engine pair. |
| call edges | (call site, callee), direct vs resolved-indirect kept apart | A resolved indirect edge is compared only against an engine that resolves indirect transfers. Otherwise the outcome is `UNAVAILABLE`. |
| memory and MMIO accesses | (instruction or function, address or address term, width, direction) | Constant-address accesses are comparable. A parametric access is comparable only after an explicit, recorded specialization. |

**[Required]** Native artifacts are preserved and content-addressed. The
framework adds only:

- a **minimal common envelope**: firmware digest, target-configuration
  identity, scope, engine identity, lineage, independent/assisted marker,
  observation kind, and evidence reference;
- **typed comparison records** per observation kind.

It does not force native representations into a lossy universal schema.

### 3. Discrepancies and reconciliation

**[Required]** A material discrepancy is a retained ledger record. It holds:

- the specific conflicting observations and their originating evidence ids;
- the scope and target configuration of each side;
- the nature of the disagreement, as typed by the comparison;
- its relevance to the claims or investigation it touches;
- its resolution status.

**[Required]** Reconciliation never overwrites or erases independent
observations, comparison records, or the discrepancy itself. A resolution is
a separate, immutable record that cites evidence, in the ledger's
append-only style. Its resolution state, like claim state, is folded from
events. Resolution is decided mechanically from cited evidence:

- **Representational difference.** A declared normalization, applied
  deterministically, makes the observations agree.
- **Scope difference.** The disagreement lies outside one engine's declared
  scope, for example code reached only through a transfer that the engine's
  root policy does not follow. The scope difference becomes a recorded
  coverage limitation, not agreement.
- **Demonstrated error.** Concrete evidence shows one observation is wrong:
  for example exact decode from the hash-verified bytes, concrete execution,
  or a solver result under stated assumptions. The losing observation stays
  in the ledger, marked as refuted by that evidence.
- **Unresolved.** The default.

A model may propose an explanation or an analysis. It cannot mark a
discrepancy resolved. A resolution does not turn the dissenting engine's
observation into corroboration.

**[Required]** An unresolved discrepancy can be turned into a bounded
investigation task. The task references the discrepancy id. See
[Ledger and task tracking](#ledger-and-task-tracking).

### 4. Claim verification

**[Partial]** Each claim class has a verification policy. A claim's class
is determined mechanically from its typed semantics and claim type. It is
never chosen by the proposer to lower requirements. A firmware-derived claim
whose class cannot be determined mechanically does not satisfy any
cross-engine policy. It remains with an explicit unmet condition.

**[Partial]** Policy evaluation is a mechanical verification step that
checks:

1. each required kind of support is present, from observations of the
   required independence;
2. the comparison records covering the claim's material assertions exist,
   are deterministic and replay-verified, and report `AGREE` (or an outcome
   the policy explicitly permits);
3. no discrepancy material to the claim is unresolved, and
   `contradictory_evidence_ids` have been evaluated rather than only
   resolved as references;
4. every unmet condition is listed by name, such as missing corroboration,
   `UNAVAILABLE` engine, `COVERAGE_GAP`, `INCOMPARABLE` scope, or unresolved
   discrepancy.

A claim with any unmet condition is not `VERIFIED`. Unmet conditions are
shown wherever claim state is shown (`claims`, reports, verification
records).

**[Implemented]** Policies are versioned. Every verification record names the
policy version it applied. A policy change requires re-verification. It does
not rewrite earlier records.

**[Implemented, as phase P]** Evaluate policy as a new phase between C (replay/freshness)
and D (audit). Comparison evidence is then replay-verified before it counts,
and the audit model is not consulted about a claim that cannot meet its
policy. This matches how `precheck` already gates the audit. Severities could
map as follows:

| Condition | Severity |
|---|---|
| missing or unavailable corroboration, coverage gap | `hold`: stays `PROPOSED`, condition visible |
| material unresolved discrepancy | `hold` |
| affirmative contradiction of a typed assertion (for example a `CONFLICT` at an address the claim asserts is code) | `block` |

This adds no new lifecycle state.

### Verification policy v1 (safety gate)

**[Implemented]** `aptrace-claim-verification` v1 (`agent/src/aptrace_agent/ledger/policy.py`,
`ledger/gate.py`) is phase P of the verifier. It is a bounded safety gate,
not the full architecture above. What it enforces:

- **Claim class** is computed from typed semantics and claim type only.
  An unmapped shape is `UNDETERMINED`, which is unevaluable.
- **Contradictory evidence** is evaluated, not only resolved. Each
  reference is checked for firmware/case identity and validity, then
  classified against the typed assertion:
  - `CONTRADICTED` (blocks): a fact for the same pointer slot with a
    different value for a claimed field; a common-path result over exactly
    the claimed scopes with the opposite status; or a structural `CONFLICT`
    at an asserted code address.
  - `UNRESOLVED` (holds): the evidence names a claimed entity but no typed
    fact classifies it, or the claim is untyped or set-scoped.
  - `NOT_MATERIAL`: it names none of the claim's typed entities.
  - `UNEVALUABLE`: foreign, invalidated, or unreadable evidence.
- **Structural conflicts.** The gate records `structural_source_agreement`
  for the typed claim's asserted code addresses before any audit. It also
  evaluates supporting agreement evidence and agreement evidence recorded by
  audits of the version. A `CONFLICT` at an asserted code address blocks the
  claim. A function-start disagreement where the claim asserts the
  containing function holds it. A conflict elsewhere is recorded
  `NOT_MATERIAL`. A conflict on a claim without typed code assertions holds
  it as unresolved. A failed or truncated agreement run is `UNEVALUABLE`.
- **Independent corroboration** is required for the class. Only
  `CODE_EXISTENCE` (`CODE_PRESENCE` semantics) has an evidence contract
  today: two observations at the address (and, where asserted, at the same
  function entry) from sources with disjoint lineages. Every counted source
  must declare `lineage`, `firmware_sha256` equal to the claim's firmware,
  and `engine_version`. A source's `derived_from` engine is added to its
  lineage. `assisted` sources never count. Re-runs and derived sources share
  a lineage and never count. Missing envelope fields make the requirement
  `UNEVALUABLE`. Absent or same-lineage observations make it `UNMET`.
- **Gate status** is `PASSED`, `BLOCKED` (contradicted), `HELD`
  (unmet/unresolved), or `UNEVALUABLE`. It is recorded on the verification
  record with every condition, its evidence ids, and the policy identity
  (id, version, digest of the canonical definition). Only `BLOCKED` changes
  the lifecycle state to `BLOCKED`; the other failures leave the claim
  `PROPOSED`.
- **Ordering and authority.** The audit pipeline consults the audit model
  only after phases A–C and P pass. In full verification, phase D still
  reads recorded audits, so a CHALLENGED audit still blocks. No verdict
  overrides P. The ledger refuses a `VERIFIED` transition that does not cite
  a full verification of that exact version, under the current policy, with
  a passing gate.
- **Historical decisions.** A record without `policy` predates the policy
  and is never rewritten. `aptrace-agent policy-status` and the generated
  report show, read-only, a `VERIFIED` decision's policy beside a
  current-policy assessment of the recorded evidence. Re-verification happens
  only when someone runs `verify`. There is no bulk re-verification.

Claim classes that **cannot reach `VERIFIED` under v1**, because no ledger
operation produces the required evidence (gate `UNEVALUABLE`,
`NO_EVIDENCE_CONTRACT` or `CLAIM_CLASS_UNDETERMINED`):

| Class (v1 name) | Typical claims | Missing prerequisite |
|---|---|---|
| `RESOLVED_INDIRECT_CALL` | `RESOLVED_FUNCTION_POINTER`; pointer-derived `FUNCTION_ROLE` (writer, callback, forwarding, registration, indirect caller) | an independent resolver, concrete transfer observation (Unicorn in the ledger), or a solver result as ledger evidence |
| `CONTROL_FLOW` | `PATH_EXISTS`; `PATH_RELATION` `KNOWN_COMMON_PATH` | a second engine's path/edge evidence and a typed edge comparison |
| `BOUNDED_NEGATIVE` | `NO_KNOWN_PATH` | a second engine's bounded path analysis |
| `MEMORY_ACCESS` | `FUNCTION_ROLE` `MMIO_USER` | a constant-address access comparison across engines |
| `VECTOR_MAPPING` | `FUNCTION_ROLE` `INTERRUPT_VECTOR_HANDLER` | independent vector-table slot/handler agreement |
| `UNDETERMINED` | untyped `RESOLUTION`, `BEHAVIOR`, `STRUCTURE`, `OTHER` | typed semantics |

`CODE_EXISTENCE` claims built on today's real sources are also
`UNEVALUABLE`, because the census, Ghidra, and Macaw sources declare no
independence envelope. The Macaw census does not yet record a firmware
digest or engine version. Runtime-behavior, formal-property,
peripheral-interpretation, direct-call, and physical-hardware classes have
no mechanical mapping in v1 and are `UNDETERMINED`.

### Claim classes

The table states what corroboration *means* for each class. Exact thresholds
belong to the versioned policy. "Independent static" means observations from
at least two engines with disjoint lineages, compared at the stated
granularity.

| Claim class | Cross-engine corroboration | Other required support | What agreement does *not* establish |
|---|---|---|---|
| Code/function existence | Independent static agreement on code at the asserted addresses. Function-entry agreement only when the claim asserts the entry. | — | That the code is reachable at runtime, or the function's extent. |
| Call relationship (direct) | Independent static agreement on (call site, callee). | — | That the call executes on any particular path. |
| Call relationship (resolved indirect) | An independent engine that resolves the same transfer. If no available engine supports it, record `UNAVAILABLE`. | Or concrete execution that observes the transfer, or a solver result under stated assumptions. One of these is required when no independent static resolution exists. | That every runtime value of the slot is covered. |
| Control-flow relationship | Independent static agreement on the asserted edges or paths, within a common scope. | — | Feasibility of the path. |
| Bounded negative (`NO_KNOWN_PATH`) | Each engine's own bound is recorded. Agreement is two bounded absences, never unreachability. | — | Unreachability. The existing bounded-negative rules are unchanged. |
| Dataflow / memory access | Independent agreement on constant-address accesses. Parametric accesses only after recorded specialization. | Concrete execution for runtime values. | The values written or read at runtime. |
| Peripheral/register interpretation | Corroboration applies to the *access* (above). | Vendor documentation pinned by digest for the register meaning. | Device identity or board wiring. Structural usage stays structural. |
| Runtime behavior | Static corroboration of the code involved is supporting, not sufficient. | Concrete execution or hardware evidence, with every harness assumption recorded. | Behavior outside the modeled environment and inputs. |
| Formal property | Not applicable to the property itself. | Solver-confirmed under explicit, recorded assumptions and bounds. | The property outside those assumptions. |
| Physical hardware connectivity | **Not applicable.** No firmware engine observes it. | Hardware measurement with recorded provenance. | Anything about firmware behavior. |

Not-applicable is a policy entry with a stated reason. It is never an
inference from missing evidence. When a policy permits an alternative to
cross-engine corroboration, such as concrete execution for a resolved
indirect call, that alternative must actually be present. When an
alternative is unsupported, the claim stays unverified. The other choice is
to narrow the claim in a new claim version, to a scope or strength whose
policy it meets.

## Kinds of support

Support kind is recorded alongside evidence grade and claim state. It is not
a replacement for either. It answers *how* something is known. It is not a
single ladder: kinds 4 and 5 are different in kind from kind 3, and none
implies another.

| Kind | Meaning | Typical source |
|---|---|---|
| 1. Candidate discovery | Proposed, heuristic, or single-pass and unchecked. | Agent or model proposal, pattern match, lead. |
| 2. Mechanically supported observation | Deterministic, replayable output of one engine lineage. | One static engine or derived source. |
| 3. Independently corroborated observation | Two or more disjoint lineages agree in a comparison record, with no material unresolved discrepancy. | Comparison over independent discovery runs. |
| 4. Experimentally demonstrated behavior | Observed under concrete inputs and a recorded environment model. | Concrete emulation; hardware. |
| 5. Formally verified property | Holds for all inputs within explicit assumptions and bounds. | Solver-confirmed symbolic execution. |

Mapping to the evidence levels required by [`../CLAUDE.md`](../CLAUDE.md):

- kinds 1–3 are *static* (1 may be *probable/pattern-matched*);
- kind 4 is *concrete*;
- kind 5 is *solver-confirmed*;
- *unknown/bounded* applies at any kind.

Static-analysis agreement is corroboration, not proof. It says nothing about
runtime behavior or hardware effects. Each kind keeps its own assumptions and
limitations, and they are inherited mechanically, as ledger limitations
already are.

## Agent autonomy within deterministic boundaries

**[Required]**

- The agent chooses questions, tools, engines to run, and which
  discrepancies to pursue.
- The agent cannot waive, weaken, or reclassify a verification requirement.
  Policy selection, independence and lineage marking, comparison, and
  promotion eligibility are computed by APTrace.
- No planner- or auditor-facing operation may set an independence marker,
  claim class, policy version, or discrepancy resolution.
- A convincing single-engine result, a SUPPORTED audit, or a model's
  explanation of a discrepancy does not satisfy a policy requirement.

## Ledger and task tracking

| Concern | Owner | Notes |
|---|---|---|
| observations (native results) | ledger evidence | content-addressed, replayable, unchanged by reconciliation |
| comparison records | ledger evidence | output of a deterministic comparison operation |
| discrepancies and their resolutions | ledger records plus events **[Required]** | immutable; status folded from events |
| claims, policy evaluation, promotion | ledger and verifier | `VERIFIED` only via the verifier |
| contradictions on a claim | `contradictory_evidence_ids` plus material discrepancies | both evaluated in verification **[Required]** |
| discrepancy investigation tasks | work store ([`work-store.md`](work-store.md)) | reference discrepancy and evidence ids. They are never evidence, never resolve a discrepancy, and closing one never changes claim or discrepancy state. |

This extends the existing boundary: Beads remembers what to do, and the
ledger remembers what was learned and how it is known.

## Implementation status

As of this document's introduction. Update [`status.md`](status.md) when this
changes.

| Requirement | Status | What exists |
|---|---|---|
| Firmware identity by digest | **[Implemented]** for ledger evidence. **[Partial]** for engine outputs. | `ExecutionContext.firmware_sha256`, and the verifier rejects foreign firmware. Ghidra cache identity includes the firmware digest and load configuration. The Macaw census result records path, size, flash base, and RAM geometry, but no firmware digest. Its ledger source checks only image size. |
| Independent discovery by construction | **[Partial]** | `APTrace.MacawCensus` is seeded only from vector-table roots and never consults Ghidra, Capstone, or census data. Ghidra is seeded from the vector table plus derived function-pointer seeds. Those seeds are produced by a resolver over the Ghidra-derived census, so they stay within the Ghidra lineage. They are recorded in the Ghidra cache identity. |
| Lineage / independence marking | **[Partial]** | `SourceObservation.derived_from` (one level, per source) and `seeded`. Limitation `AGREEMENT_SOURCES_NOT_INDEPENDENT`. Source agreement passes through a declared per-source envelope (`lineage`, `firmware_sha256`, `engine_version`, `assisted`) that policy v1 consumes, but no real source declares one yet. There is no per-observation transitive lineage. |
| Target configuration record | **[Missing]** | Geometry is supplied per tool by the case. No comparable configuration identity exists across engines. |
| Engine identity and version | **[Partial]** | Ghidra version is in cache identity. Input artifacts are hashed per invocation. Macaw/macaw-symbolic versions are not recorded on evidence. |
| Deterministic comparison: code presence, function extent, blocks | **[Partial]** | `structural_source_agreement` is a recorded, replayable operation over up to 16 addresses. Phase P records it for a typed claim's asserted code before any audit and gates on a material `CONFLICT`. It classifies `AGREE`, `PARTIAL_AGREEMENT`, `BOUNDARY_DISAGREEMENT`, `SOURCE_MISSING`, and `CONFLICT`, and keeps coverage gaps distinct from negative evidence. Of its three sources, census and Ghidra share a lineage, so it compares at most two independent lineages. |
| Comparison: functions and calls over a common root set | **[Partial]** | `tools/census/macaw_compare.py` applies a same-root fairness rule and disclosed call-site containment. It is standalone and not a ledger operation. |
| Comparison: CFG edges, memory/MMIO accesses, indirect resolutions | **[Missing]** | — |
| `INCOMPARABLE` / `UNAVAILABLE` outcomes | **[Partial]** | Unavailable sources and Macaw `discovery_error` are reported as `<SOURCE>_UNAVAILABLE` gaps inside `SOURCE_MISSING`. There is no separate incomparable outcome and no recorded timeout or bound cause. |
| Discrepancy records and resolution lifecycle | **[Missing]** | Agreement results are evidence, but discrepancies are not first-class records. Phase P treats every material discrepancy as unresolved, because no resolution record exists. |
| Verification policy per claim class | **[Partial]** | Policy v1 is phase P (see [above](#verification-policy-v1-safety-gate)). The class is computed mechanically, the policy is versioned and recorded on every verification, and the gate runs before the audit model. Only `CODE_EXISTENCE` has an evidence contract. Every other class is held as `UNEVALUABLE`. |
| Contradictory evidence evaluated in verification | **[Partial]** | Phase P classifies each reference against typed assertions (pointer fields, path status over identical scopes, structural `CONFLICT` at asserted code). Anything else that names a claimed entity is `UNRESOLVED` and holds the claim. Untyped claims cannot be classified. |
| Concrete and solver evidence in the ledger | **[Partial]** | `function_effects` (Macaw + Crucible + Z3) is a ledger operation. Unicorn concrete execution is one only as `observed_call_arguments` (caller-grounded argument values and in-function MMIO accesses over a case scenario); general concrete runs are not. No operation compares Crucible's access model with concrete accesses. |
| Work items separate from evidence | **[Implemented]** | `work/` has no ledger write path. Closing an item never changes claim state. |

## Open design questions

These need implementation evidence to settle. They do not leave the
requirements above open.

- **Correlated components.** Engines may share a loader, decoder, or ISA
  semantics source. Which shared components make two lineages correlated
  enough not to count as independent? Settling this needs measured
  disagreement data across engine pairs.
- **Common scope under different root policies.** Root-seeded and
  whole-image heuristic discovery overlap only partly. How do we get
  independent coverage of code reached only through resolved indirect
  transfers, when the only current resolver is in one engine's lineage? The
  resolver's targets cannot seed another engine's independent run.
- **Materiality mapping.** For each typed claim predicate, which comparison
  records and discrepancies are material? This must be computed mechanically
  from the predicate's entities and scope.
- **Discrepancy record shape.** Should a discrepancy be a dedicated ledger
  record type, or comparison evidence plus lifecycle events? Either way it
  must meet the retention and immutability requirements.
- **Policy representation.** v1 is a data table in code. Its identity is the
  id, the version, and a sha256 over the canonical definition. Whether later
  policies should be versioned files under the ledger is open.
- **Transition of existing `VERIFIED` claims.** Claims verified before the
  policy existed have verification records with `policy: null`, which
  identifies them mechanically. Policy v1 does not bulk re-verify them. It
  reports them read-only (`policy-status`, the report), and any explicit
  `verify` applies the current policy. Whether to bulk re-verify later is
  still open.

## Acceptance criteria

The implementation is accepted when known-answer tests and ledger benchmarks
show the following. Fixtures are case-owned, and expected outcomes stay in
separate evaluator-only files, as for existing ledger benchmarks.

**Independent discovery**

- A run that receives another engine's seeds, boundaries, or resolved
  targets, directly or through a derived artifact, is marked assisted.
- Two runs of one engine, or an engine plus its derived source, never
  satisfy an independence requirement.
- Runs over different firmware digests are refused for comparison.
- A target-configuration mismatch (for example load base) yields
  `INCOMPARABLE`, not `DISAGREE`.

**Deterministic comparison**

- Replaying a comparison reproduces its result hash.
- Input order does not change the result.
- Equal function counts with different address sets yield `DISAGREE`.
- Fixtures covering agreement, subset agreement, boundary disagreement,
  affirmative conflict, coverage gap, engine failure, timeout, and
  unsupported kind each produce the expected typed outcome.

**Discrepancy retention**

- After reconciliation and resolution, the original observations,
  comparison record, and discrepancy hash-match their pre-reconciliation
  state.
- The resolution is a separate record citing its evidence.
- A model-proposed resolution with no qualifying evidence leaves the
  discrepancy unresolved.

**Verification gating**

- A claim in a corroboration-required class does not reach `VERIFIED` with
  single-lineage evidence and a SUPPORTED audit. Its verification record
  names the unmet condition.
- An unavailable or timed-out required engine leaves the claim unverified,
  with that cause named.
- Assisted-only corroboration does not satisfy the requirement.
- A material unresolved discrepancy prevents `VERIFIED`. An affirmative
  contradiction of a typed assertion blocks.
- Two agreeing independent lineages without a SUPPORTED audit do not reach
  `VERIFIED`.
- A not-applicable class, such as a physical measurement, records the policy
  entry that made corroboration inapplicable.
- A claim whose class cannot be determined mechanically does not satisfy a
  cross-engine policy.
- Verification records name the policy version.

**Agent boundary**

- No planner or auditor tool can set independence, class, policy, or
  resolution.
- Closing a discrepancy work item changes no claim or discrepancy state.
