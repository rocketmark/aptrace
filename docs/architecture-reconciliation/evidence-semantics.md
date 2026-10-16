# Architecture Reconciliation, Phase 1: Evidence Semantics and Confidence Promotion

*Design analysis, 2026-10-16, at HEAD `3c21469` (`main`). It is for
independent review. It does not approve anything, and nothing in it is
implemented.*

- **Scope.** How the evidentiary meaning of an observation is kept, or lost,
  as it moves from the producing engines through census, static dataflow,
  symbolic and concrete execution, the evidence ledger, claim semantics,
  admission, verification and audit.
- **Method.** The source was read directly. The mapping documents
  (`docs/arrows/`, `docs/intent/`) were used as an inventory, and are
  corrected in §2.7 where the code disagrees with them. No code, tests or
  engines were run. No mapping documents, LLDs, EARS specs, source or tests
  were changed.
- **Not in scope.** Each of these gets its own later phase: independence and
  corroboration, identity and replay, completeness representation in each
  producer, and claim lifecycle. This document names their dependencies on
  evidence semantics and stops there.

**Labels used throughout**

| Label | Meaning |
|---|---|
| **OBSERVED** | Read directly in source at the cited lines. Not executed. |
| **INFERRED** | Follows from observed code. The end-to-end behavior was not executed or demonstrated. |
| **PROPOSED** | A design proposal in this document. Not approved. |
| **DECISION REQUIRED** | A choice this document cannot make. It needs an owner's approval. |

**Path abbreviations:** `A/` = `agent/src/aptrace_agent/`, `C/` =
`tools/census/`, `E/` = `src/APTrace/EffectsSpike.hs`.

**No incorrect firmware result is claimed anywhere in this document.** Every
risk below is a path by which a downstream statement *can* be stronger than
its evidence. None was demonstrated on real firmware.

---

## 1. Executive summary

**The question.** Can derived evidence silently gain certainty,
completeness, independence or authority just by passing through another
processing stage?

**The answer, from the code: yes, at specific and enumerable points.** There
are five root causes. (OBSERVED unless marked otherwise.)

1. **One ordinal grade is asked to carry many dimensions.**
   - `EvidenceGrade` (`EXACT > STRONG > PROBABLE > BOUNDED > UNKNOWN`) is
     the only mechanical strength signal that admission and verification
     read.
   - It folds together several independent things: observation mode,
     interpretation confidence, completeness, polarity, and the conditions
     a result holds under.
   - It is assigned **per artifact**, from **producer status strings**. But
     one artifact holds facts of very different strength. For example:
     - a census result can hold both a Ghidra-direct edge and a flash
       table-scan edge;
     - an effects result can hold both an always-true access and an access
       behind an unsatisfiable guard.
2. **The census confidence vocabulary is also the ledger grade
   vocabulary.**
   - `EvidenceGrade`'s own docstring says "EXACT and STRONG are the census
     confidence vocabulary" (`A/ledger/models.py:22-31`).
   - So a census `STRONG` table-scan candidate is graded as STRONG by the
     ledger. The same candidate also produces:
     - census `DEFINITELY_REACHABLE`;
     - callback-provenance `ESTABLISHED`;
     - a categorical `ESTABLISHED_INDIRECT` call edge, in the
       function-pointer case.

   Each of these is a renaming step. None of them adds evidence.
3. **Fact extraction drops the qualifiers that limited a fact.** Examples:
   - guard status and solver-only regions on effects accesses;
   - the edge basis behind a census path or reachability status;
   - the closed-world condition on a resolved function pointer.

   Limitations are kept only as *disclosure text*. They never act as
   *constraints* on what a claim may assert.
4. **The claim ceiling does not check what actually supports the claim.**
   - For `FUNCTION_ROLE`, `RESOLVED_FUNCTION_POINTER`, `PATH_RELATION` and
     `CODE_PRESENCE`, the ceiling is the maximum grade over *every* cited
     artifact. It is not the grade of the artifact that matched the
     predicate.
   - Call relations do bind the ceiling to the matching edges. But they
     take the maximum over a path, not its weakest link.
5. **Session facts are uniformly `PROVEN`.** That includes solver results
   over a `partial` simulation, and concrete observations from one scenario.

**What fails closed today.** Verification policy v1 gives an evidence
contract only to `CODE_EXISTENCE`, and no production source declares an
independence envelope (X15). So none of these promotions can currently
produce a `VERIFIED` claim. They do produce:
- admitted `PROPOSED` claims at grades above their basis;
- STRONG candidates;
- `PROVEN` planner facts.

**INFERRED, and the most important point for sequencing:** the masking ends
as soon as any policy class (`MEMORY_ACCESS`, `RESOLVED_INDIRECT_CALL`,
`CONTROL_FLOW`) gets an evidence contract.

**Not every increase is a defect.** Several transitions are justified once
the claim's polarity is known (§3.3):
- A truncated concrete observation can still establish that a value *was*
  observed.
- A complete raw simulation with opaque computed calls can still establish a
  direct access by an always-true path.
- `NO_KNOWN_PATH` may support a `NO_KNOWN_PATH` claim at the strength of its
  graph.

These are wrong only when the same grade is reused for universal or negative
statements.

**The proposed invariant needs one refinement** (PROPOSED, §4.1). As
written, it would also forbid legitimate strengthening (new independent
evidence, a discharged condition). The refined form:

> **No transformation may strengthen any evidence facet unless it cites the
> additional evidence that justifies the strengthening.
> Representation-only transformations are facet-monotone: they may preserve
> or weaken, never strengthen.**

**Recommended approach** (PROPOSED, §5): a **hybrid**.
- Producer-native results stay as they are, preserved and
  content-addressed.
- A small set of **per-fact qualifiers** is added:
  - mode;
  - interpretation;
  - polarity;
  - scope and completeness;
  - coded conditions;
  - lineage.
- The qualifiers are computed by **versioned per-tool readers** at the
  existing ledger boundary.
- A few targeted producer additions cover facts the readers cannot recover
  from native output.
- **Consumer rules** are enforced in admission, candidates and verification
  phase B. They bind the grade to facts, apply weakest-link and polarity
  rules, and treat conditions as constraints.
- `EvidenceGrade` stays as the output vocabulary. It becomes a *derived
  per-fact summary*, not a producer-status lookup.
- This matches the normative "minimal common envelope; no lossy universal
  schema" rule in `docs/cross-engine-verification.md` §2.

**Twelve decisions need approval** (§6). The most consequential:
- **D3:** the ceiling rule.
- **D4, D5:** whether census heuristic confidence can ever yield a
  categorical or "definite" downstream statement.
- **D6:** effects guard and region policy.
- **D12:** a sequencing rule. No new verification-policy evidence contract
  until the claim ceiling and condition rules are enforced.

**Acceptance criteria** (§7): eleven synthetic, fixture-based tests, each
with pass and fail cases. They cover the six requested scenarios, plus
ceiling binding, representation invariance, fnptr closed-world handling and
session-fact levels.

---

## 2. Current-state evidence-promotion traces

Each trace is a sequence of transitions. For every transition the table
gives:
- producer and consumer;
- code;
- input and output;
- the rule;
- what is preserved (**P**), discarded (**D**) or reinterpreted (**R**);
- whether new evidence is added;
- what depends on it downstream.

### 2.1 Trace T1: census STRONG candidate → `DEFINITELY_REACHABLE` → callback `ESTABLISHED` → reachability claim

| # | Producer → consumer | Code | Input → output | Rule | P / D / R | New evidence? | Downstream |
|---|---|---|---|---|---|---|---|
| 1a | census reduce (table scan) | `C/reduce.py:117-142`; `C/indirect_resolve.py:105-151` | unresolved `tbb/tbh` or `ldr pc` site → `indirect_edge_candidates` rows, `source=flash-table-scan` | `confidence = "STRONG" if fid is not None else "WEAK"`, where `fid = func_ranges.containing(target)`: the target lies **inside** any Ghidra function range, not necessarily at an entry | **R:** "plausible table entry inside a heuristic function range" becomes `STRONG`. **P:** `source` column. The site classification `FINITE_CANDIDATE_SET` is kept in a separate table | No. The candidate is a byte-pattern scan | 1c, 1d, census graph |
| 1b | census reduce (RAM fnptr) | `C/fnptr_resolve.py:368-372, 43`; `C/reduce.py:150-167` | slot loads and known constant stores → candidate `source=ram-fnptr-constant-store` | `STRONG` iff every *known* writer stores one agreeing code pointer. The module documents why it is never `EXACT`: computed-pointer stores are invisible | **P:** writer provenance in `resolved_function_pointers`. **R:** a closed-world-over-known-writers conclusion becomes `STRONG` | No | 1c, 1d, X10 (T2) |
| 1c | census reduce → roots | `C/reachability.py:61-65` | every `EXACT`/`STRONG` candidate address → a root of kind `confirmed-indirect-target`, justified as "resolved (static or dynamic) target of a real indirect call/jump" | Candidate confidence alone. **The call site's own reachability is not consulted.** | **R:** a table-scan entry is described as "resolved". **D:** the candidate source | No | 1d |
| 1d | census reduce → reachability | `C/reachability.py:113-168` | Ghidra resolved direct edges ∪ `EXACT`/`STRONG` indirect candidates → BFS → `DEFINITELY_REACHABLE` | Strong graph = confidence filter (`:122`). The module docstring says the strong graph is site classification `STATICALLY_RESOLVED`/`DYNAMICALLY_OBSERVED` (`:19-24`) | **D:** which edge kinds the path used. **R:** "reachable from a vector **or from any EXACT/STRONG candidate target**" becomes "DEFINITELY" | No | 1e, 1f, census_graph |
| 1e | census → static dataflow (callback provenance) | `C/callback_provenance.py:69, 446-459` | census status → `caller_reachability`/`target_reachability` `{status: ESTABLISHED, census: DEFINITELY_REACHABLE}` | Fixed rename map `_REACH` | **P:** the raw `census` field is kept alongside. **R:** a third use of the word "ESTABLISHED" | No | **No agent consumer.** `grep` finds no reader of `caller_reachability`/`target_reachability`/`entry_reachability` under `A/` (OBSERVED). It reaches the stored blob and any human or auditor who reads it |
| 1f | census → agent census tools → claim checks | `A/ledger/call_relations.py:343-348, 576-604` | `functions[].reachability.status` in any `census_*` result → `facts.census_reach` → `check_reach` | A rootless reachability assertion is CHECKED if census says `DEFINITELY_REACHABLE` **and** the wording matches `_CENSUS_SCOPE_RE` (`census|static…|call graph|…`) | **P:** scope by wording. **D:** edge basis. **R:** the scope regex treats "statically reachable" as matching | No | Untyped prose claims (capped at PROBABLE by `A/research/admission.py:69, 225-233`). No typed reachability predicate exists |
| 1g | census → ledger grade (common paths) | `A/ledger/semantics.py:183-195`; `A/census_graph.py:276-286, 509` | `KNOWN_COMMON_PATH` over the same strong graph (EXACT/STRONG candidates) → `STRONG` | `_min_grade(STRONG, edge)`. Only `resolved_indirect_edges` lower it, and those are fnptr-only (`:412`) | **D:** whether a path used a table-scan edge (paths list function names only). **R:** the limitation text says the graph has "statically resolved or dynamically observed indirect targets" (`:144-147`), which is inaccurate for table-scan candidates | No | typed `PATH_RELATION` claims at STRONG |

**Demonstrated (OBSERVED) vs inferred.**
- *OBSERVED:* the confidence filter, the root rule, the rename and the
  inaccurate limitation text are all in source.
- *INFERRED:* that a real image contains a function reached *only* through a
  table-scan or fnptr candidate. The mapping notes no test covers this.
- *INFERRED, needs targeted testing:* for TBB/TBH, `scan_halfword_table`
  stops only when a target leaves the image (up to 64 entries,
  `C/indirect_resolve.py:131-151`). A table shorter than 64 entries can
  therefore yield entries past its end. Any of those that lands inside a
  Ghidra function becomes `STRONG`. This applies only to TBB/TBH sites that
  Ghidra left unresolved.

### 2.2 Trace T2: census EXACT/STRONG resolved edge → categorical call relation and pointer candidate

| # | Producer → consumer | Code | Input → output | Rule | P / D / R | New evidence? | Downstream |
|---|---|---|---|---|---|---|---|
| 2a | census DB → `census_*` result | `A/census_graph.py:395-449` | **only** `source='ram-fnptr-constant-store' AND confidence='STRONG'` candidates joined to their store provenance → `resolved_indirect_edges` | SQL filter (`:412`) | **P:** slot, store, writer, raw value, forwarding. **D:** table-scan and dynamic candidates never appear here | No | 2b, 2c, 2d |
| 2b | result → ledger artifact | `A/ledger/semantics.py:149-158, 280-281` | edges → grade `min(STRONG, edge)` = STRONG; limitation `COMPUTED_POINTER_WRITES_NOT_EXCLUDED` | Census confidence string parsed *as* `EvidenceGrade` | **R:** census `STRONG` *is* ledger `STRONG`. **P:** the closed-world caveat, as limitation **text** | No | 2c, 2d |
| 2c | artifact → call facts | `A/ledger/call_relations.py:331-341` | edge → `CallEdge(kind=ESTABLISHED_INDIRECT, conditions=())` for EXACT/STRONG | Confidence alone | **D:** the closed-world condition. It survives only as an artifact limitation. **R:** a heuristic conclusion becomes a *categorical* edge | No | typed/untyped `CALL_RELATION` (policy class `RESOLVED_INDIRECT_CALL`) |
| 2d | artifact → pointer facts → candidates | `A/ledger/claim_semantics.py:476-497`; `A/research/candidates.py:384-446, 478-510` | edge → `PointerFact` + five roles → `RESOLVED_FUNCTION_POINTER` candidate at `grade_ceiling` = STRONG | Any confidence (CLAIMS-SEM-FACT-001). This is moot today because only STRONG reaches results (2a) | **P:** the candidate's `scope` text keeps "stores through computed pointers are not excluded". **D:** as a predicate condition | No | candidates, claims |

**Contrast: a correctly scoped producer** (OBSERVED, `C/indirect_target.py:594`;
`A/ledger/call_relations.py:189-216`). `indirect_call_target` yields
`ESTABLISHED_INDIRECT` only when:
- every reaching definition is `STATICALLY_ESTABLISHED`, and
- the definition set is `complete`.

Otherwise it yields `POTENTIAL_INDIRECT`, with conditions the claim must
restate. That is the pattern the fnptr path lacks.

### 2.3 Trace T3: symbolic raw `complete` + bounded adapter coverage → ledger STRONG

| # | Producer → consumer | Code | Input → output | Rule | P / D / R | New evidence? | Downstream |
|---|---|---|---|---|---|---|---|
| 3a | EffectsSpike (Crucible) | `E:414-418` | raw `status`, accesses, calls, plus `assumptions` (opaque calls clobber `r0-r3/r12` and have **no memory effects**; RAM and MMIO unconstrained; step bound) | Engine | **P:** assumption list | Primary observation | 3b |
| 3b | adapter | `A/function_effects.py:320-337` | raw `status` + calls without a concrete target → `coverage = "bounded: …computed control transfer(s)…"` | Adapter adds a completeness facet | **P:** raw status. **Adds:** a second completeness notion | Interpretation only | 3c, 3e |
| 3c | adapter result → ledger grade | `A/ledger/semantics.py:200-206, 311-312` | `status.startswith("complete")` → `STRONG` ("symbolic extraction, not solver-confirmed"). `EFFECTS_COVERAGE_BOUNDED` only when the *raw* status is not complete | Keyed on raw status, not on `coverage` (PROD-SYM-GRD-001, EVREC-GRD-003) | **D:** adapter `coverage` for grading and limitation. **R:** "complete raw run of the simulated part" becomes STRONG with no bounded disclosure | No | 3d, candidates, admission |
| 3d | artifact → claim limitations | `A/ledger/semantics.py:471-486`; verifier `limitations_preserved` (`A/ledger/verifier.py:230-233`) | Limitation codes are inherited and checked | Mechanical | **P:** whatever 3c attached. 3c attaches nothing for bounded coverage | No | claim disclosure |
| 3e | adapter result → absence check | `A/ledger/claim_checks.py:207-251` | "does not access" is accepted when `coverage == "complete"` and no parametric address | Uses adapter `coverage` (the stricter notion) | **D:** that direct callees are opaque (PROD-SYM-ASM-004). "Complete" covers the function's own body only | No | untyped claims, capped at PROBABLE |

**Assessment.**
- *OBSERVED:* one result carries two completeness notions, and grading uses
  the weaker one.
- *INFERRED and justified:* an existential statement about the function's
  *own* direct access on an always-true path is not weakened by unsimulated
  code behind a computed transfer.
- *INFERRED as a defect:* the claim carries no disclosure that part of the
  function body was not simulated. And no mechanism stops a universal
  statement ("F's accesses are X and Y") from resting on it.

### 2.4 Trace T4: symbolic MMIO access with infeasible, unknown or unqueried guard → claim roles

| # | Producer → consumer | Code | Input → output | Rule | P / D / R | New evidence? | Downstream |
|---|---|---|---|---|---|---|---|
| 4a | EffectsSpike solver enrichment | `E:520-535, 576-597` | guard → `always-true` / `unsatisfiable` / `conditional` / `unknown`, for the first access at each `(kind, pc)`, **at most 24 sites** | Solver over common assumptions (the opaque-call / no-memory-effect model) | **P:** method and queries. **D:** count of sites not enriched (SYM OQ9) | Solver result *under the model* | 4b |
| 4b | EffectsSpike region membership | `E:555-575` | parametric address → first region with UNSAT(`guard ∧ outside`) → `proven` | Solver | **INFERRED:** if the guard is itself unsatisfiable, the query is UNSAT vacuously, and the first region checked (`FLASH`) is "proven". This does not create an MMIO role, because FLASH is first. It is a vacuous proof under inconsistent premises. Needs a targeted test | Solver | 4c |
| 4c | adapter | `A/function_effects.py:290-297` | `region = "<R> (solver)"` when only solver-proven. `guard = solver status`, else `"always"` if the RAW guard is concretely true, else `"unqueried"` | Display mapping | **R:** a RAW-concretely-**false** guard and a never-queried guard both become `unqueried` (PROD-SYM-ENR-004). **R:** two spellings of always: `always` (RAW) vs `always-true` (solver) | No | 4d, 4e |
| 4d | artifact → role facts | `A/ledger/claim_semantics.py:528-537` | every access with `region.startswith("MMIO")` → `MMIO_USER` role, whatever the guard (CLAIMS-SEM-FACT-004) | String prefix | **D:** guard, solver-only region marker, specialization | No | typed `FUNCTION_ROLE` claims at admission and verification |
| 4e | role facts → candidates | `A/research/candidates.py:198-216, 318-333` | withhold if specialized, or if no concrete input-independent access exists. Otherwise offer `MMIO_USER` | Specialization and parametric filters only (CLAIMS-ADMIT-CAND-002) | **R:** any guard not equal to `always-true` produces the limitation "conditional on input-derived guards". That covers `unsatisfiable`, `unknown`, `unqueried`, and also the RAW `always` (a conservative mislabel) | No | planner candidates |

**Assessment.**
- *OBSERVED:* no guard filter at 4d or 4e.
- *INFERRED:*
  - an access the model rules out (`unsatisfiable`), or one beyond the
    enrichment cap whose RAW guard is concretely false, can support "F
    accesses PERIPH registers";
  - a model-proposed typed `FUNCTION_ROLE` claim reaches the same result
    without passing candidate filtering at all.
- **A key nuance for the contract** (INFERRED, from `E:415`): `unsatisfiable`
  is relative to a model in which callees have *no memory effects*. A
  guard reading RAM after a call can be unsatisfiable in the model and
  satisfiable on hardware. So an unsatisfiable-guard access:
  - must **not** support a positive role;
  - must **not** be treated as evidence of absence either.

  It is "infeasible under model M". That is a conditional, not a fact.

### 2.5 Trace T5: evidence grades → admission → verification eligibility

| # | Producer → consumer | Code | Input → output | Rule | P / D / R | New evidence? | Downstream |
|---|---|---|---|---|---|---|---|
| 5a | session result → grade (admission, candidates) | `A/research/admission.py:92-106`; `A/research/candidates.py:158-176` | `evidence_grade(tool, result)` recomputed with current code | Current rules | **R:** the grade can differ from the stored artifact grade (X13) | No | 5b |
| 5b | grades → ceiling | `A/ledger/semantics.py:489-509`; `A/research/admission.py:208-218`; `A/ledger/verifier.py:219-228` | `max` grade over **all** cited artifacts. `BOUNDED` counts as STRONG for `NO_KNOWN_PATH` | "As strong as its strongest supporting derivation" | **D:** which artifact supplied the matched fact. `verify_semantics` records it (`SemanticCheck.evidence_id`, e.g. `A/ledger/claim_semantics.py:649-652`), but the ceiling ignores it | No | admission, phase B |
| 5c | call relations → ceiling | `A/ledger/call_relations.py:897-920` | max over the evidence ids **on the matched path** | Fact-bound, but `max` | **R:** a path whose edges come from STRONG and PROBABLE artifacts is capped at STRONG (weakest link not applied) | No | typed and untyped call claims |
| 5d | untyped cap | `A/research/admission.py:225-233` | untyped claim ≤ PROBABLE | Fixed | **P:** a strong safety net for prose (T1-f, T3-e) | — | — |
| 5e | stored artifact grade → phase B | `A/ledger/store.py:237-262`; `A/ledger/verifier.py:219-228` | grade frozen at first recording; phase B uses the stored grade | First-write wins (X5) | **R:** admission and verification can disagree (X13) | No | lifecycle |
| 5f | claim class → corroboration | `A/ledger/policy.py:52-89`; `A/ledger/gate.py:155-164, 380-425` | only `CODE_EXISTENCE` has an evidence contract; envelopes absent → UNEVALUABLE (X15) | Fail-closed | **P:** no VERIFIED from 5b/5c promotions *today* | — | VERIFIED unreachable in production |
| 5g | session facts | `A/research/fact_derivation.py:597-649, 769-799`; `A/research/projection.py:543-578` | every derived statement → `ClaimGrade.PROVEN` + basis tag | Uniform | **R:** examples: `return_bit_valued == "proven"` → "F return value is always 0 or 1" for statuses `partial` and `bounded: step limit` (`:600, 634-635`); single-scenario observations; may-escape possibilities | No | planner, CLI conclusion |

**Concrete instance of 5b** (OBSERVED by code reading, not executed). Take a
typed `FUNCTION_ROLE MMIO_USER` claim at STRONG that cites:
- **E1:** a `function_effects` result with status `partial`. That is graded
  BOUNDED, and its accesses still yield roles.
- **E2:** an unrelated `census_common_paths` result graded STRONG.

What happens:
- `check_function_role` matches the role on E1.
- `grade_ceiling` returns STRONG from E2.
- Admission accepts, and phase B accepts.
- Candidate generation would not offer this: it drops support below
  PROBABLE (`A/research/candidates.py:479-484`). But admission of a
  model-proposed typed claim has no such filter.

### 2.6 Trace T6 (supporting): concrete observation → STRONG → session PROVEN

The source is `A/ledger/semantics.py:208-221, 332-399` and
`A/research/fact_derivation.py:447-482`. An `observed_call_arguments` result
with status `ok` or `bounded…`, and with entries observed, is graded STRONG.
It carries these limitations:
- `HARNESS_ASSUMPTIONS`;
- `OBSERVED_CONTEXTS_ONLY`;
- `SCENARIO_SPECIFIC`;
- `OBSERVATION_TRUNCATED`;
- others as applicable.

The session fact text is scenario-scoped ("other scenarios and values are
not excluded").

*Assessment (INFERRED):* this is justified for an **existential**,
scenario-scoped statement, because truncation cannot un-observe a value. The
grade is wrong only if it is reused for a universal statement. The real gap
is that the scenario is a *limitation*, not a *structured condition*, so
nothing mechanical requires a claim to name it. `OBSERVED_DISPATCH` is the
exception: it requires a scenario (`A/ledger/claim_semantics.py:262-263`).

### 2.7 Corrections and additions to the mapping register

The mapping is accurate as an inventory. Reading the source directly changes
these points:

| Register entry | Correction or addition | Level |
|---|---|---|
| X1 step 2 | Callback-provenance `ESTABLISHED` reachability has **no agent consumer**. The claim-level path is `census_*` `functions[].reachability` → `check_reach` (T1-f), and it applies to *untyped* claims only, which are capped at PROBABLE. The rename is a terminology risk with low current mechanical impact | OBSERVED |
| X1 (new aspect) | `EXACT`/`STRONG` candidate *targets* become reachability **roots** whatever their call site's reachability (`C/reachability.py:61-65`). `DEFINITELY_REACHABLE` therefore means "reachable from a vector or from a resolved indirect target", not "reachable from reset". The root rule is documented in the module docstring (`:9-17`), so this is a policy and terminology question, not a contradiction | OBSERVED |
| X10 | Table-scan and dynamic candidates never reach `resolved_indirect_edges` (SQL filter `A/census_graph.py:412`). Only STRONG fnptr edges become `ESTABLISHED_INDIRECT`. Table-scan candidates reach claims through census graph **paths** and **reachability statuses** (T1-d, T1-g), where the edge basis is not reported | OBSERVED |
| X6 | Call relations already bind the ceiling to the matched edges (T5-c), but take `max` along a path. X6 applies fully to `FUNCTION_ROLE`, `RESOLVED_FUNCTION_POINTER`, `PATH_RELATION` and `CODE_PRESENCE` | OBSERVED |
| X18 | The absence check uses adapter `coverage`, which already accounts for computed transfers. The remaining gap is direct-call opacity. Absence claims are untyped, so the consequence is an admitted PROBABLE hypothesis, not a STRONG claim | OBSERVED |
| X12 | An unsatisfiable guard is model-relative (callees have no memory effect). Excluding such accesses is necessary, but it does not produce negative evidence (T4 nuance) | INFERRED |
| X2 | Positive existential direct-access facts are justified at STRONG. The defect is the missing completeness disclosure, plus the absence of polarity in the grade | INFERRED |
| new | Producer-declared result `limitations` lists are **not** inherited. Examples: `census_graph._LIMITATIONS` (`A/census_graph.py:144-151`) and the callback-provenance `LIMITATIONS` (`C/callback_provenance.py:74-…`). The ledger re-derives its own limitation set per tool (`A/ledger/semantics.py:274-468`). Any producer caveat not mirrored there is lost | OBSERVED |
| new | Vacuous solver region proof under an unsatisfiable guard (T4-b) | INFERRED |
| new | Session fact "return value is always 0 or 1" from `partial` / step-limited simulation (T5-g). Whether the return term covers unexplored paths is not established | INFERRED |
| new | TBB/TBH scan bound (T1, last bullet) | INFERRED |
| new | The adapter's RAW `always` is treated as conditional by the candidate limitation text. This is conservative, and a vocabulary mismatch | OBSERVED |

---

## 3. Architectural conflicts and evidence-integrity risks

### 3.1 Diagnosis: eight promotion mechanisms

Each mechanism is a place where a downstream representation can assert more
than its input. They are listed by mechanism, not by finding, because the
contract in §4 targets mechanisms.

| ID | Mechanism | Where (examples) | Findings |
|---|---|---|---|
| M1 | **Vocabulary aliasing.** A producer label is reused as, or renamed to, a stronger-sounding consumer label | census `STRONG` ≡ ledger `STRONG` (`A/ledger/models.py:26`); `DEFINITELY_REACHABLE`; `ESTABLISHED` ×3; session `PROVEN` | X1, X10, X21 |
| M2 | **Artifact-level grade keyed on one status string.** Facts of mixed strength inside one artifact share a grade | `A/ledger/semantics.py:161-271` | X2, X4, X6 |
| M3 | **Qualifier loss at fact extraction.** Guard, region basis, edge basis, edge confidence and specialization are dropped when a fact is formed | `A/ledger/claim_semantics.py:476-546`; `A/ledger/call_relations.py:331-341` | X10, X12 |
| M4 | **Unbound ceiling.** A claim's grade is bounded by any cited artifact, not by the supporting fact | `A/ledger/semantics.py:489-509` | X6 |
| M5 | **Max instead of min along a chain** | `A/ledger/call_relations.py:897-899` | new |
| M6 | **Conditions demoted to disclosures.** A condition under which a fact holds is kept as limitation text, so a categorical claim still passes | fnptr closed-world; scenario scope; harness model | X10, X4 |
| M7 | **Producer caveats not propagated.** Result-level `limitations` are not inherited; the ledger re-derives a subset | `A/ledger/semantics.py:274-468` | new |
| M8 | **Completeness notion chosen per consumer.** The same result is "complete" for grading and "bounded" for absence | T3 | X2, X18 |

The proposed invariant ("no gain by passing through a stage") is broken by
M1, M3, M4, M5, M6 and M7. M2 and M8 break it only when combined with a
claim of the wrong polarity. That is why polarity has to become explicit.

### 3.2 Trust boundaries and their classification

Classification key:
- **IC:** a demonstrable implementation contradiction (code vs its own
  documentation or approved intent).
- **AP:** an explicitly approved, or code-documented, policy that is
  potentially inadequate.
- **MP:** a missing policy decision.
- **DT:** a documentation or terminology mismatch.
- **TT:** a possible issue requiring targeted testing.

| # | Boundary | Stronger downstream assertion | Class | What would justify the transition |
|---|---|---|---|---|
| B1 | Census strong-graph membership (T1-d) | Table-scan / fnptr candidate → "DEFINITELY" reachable | **IC** (docstring `:19-24` vs code `:122`) + **MP** (census OQ1) | Either a site classified `STATICALLY_RESOLVED`/`DYNAMICALLY_OBSERVED`, or a status that names its edge bases so consumers can apply their own rule |
| B2 | Reachability roots (T1-c) | Any EXACT/STRONG candidate target is a root, whatever the site's reachability | **AP** (docstring `:9-17`) + **DT** ("DEFINITELY") | Requiring the site's containing function to be reachable; or naming the status "reachable from vectors or resolved targets" |
| B3 | Callback `ESTABLISHED` rename (T1-e) | census status → "ESTABLISHED" | **DT** (no consumer) | Nothing. The raw `census` field already carries the meaning |
| B4 | `census_graph` limitation text (T1-g) | Graph described as "statically resolved or dynamically observed" | **IC** (text vs SQL `:279`) | Accurate text, or a graph that matches the text |
| B5 | Census `STRONG` → ledger `STRONG` (T2-b) | A heuristic candidate is graded like an established derivation | **AP** (`EvidenceGrade` docstring) + **MP** (EV OQ8, CEN OQ2) | An explicit, versioned per-basis mapping (§4.5) |
| B6 | fnptr STRONG → `ESTABLISHED_INDIRECT` (T2-c) | Closed-world-over-known-writers → categorical edge | **MP** (SEM OQ1) | Discharging the closed-world condition (for example, evidence that no computed-pointer store can reach the slot), or concrete observation, scoped to its scenario |
| B7 | Effects raw `complete` → STRONG with no bounded disclosure (T3-c) | Partially simulated body graded as if fully simulated | **IC** with the adapter's own `coverage` contract (`A/function_effects.py:62-66`) + **MP** (EV OQ7) | For existential direct facts: already justified. For universal or negative statements: complete coverage over the claimed scope |
| B8 | Effects access → `MMIO_USER` whatever the guard (T4-d) | Infeasible-under-model or unqueried access → positive role | **MP** (SEM OQ4, ADM OQ3) + **TT** (raw-false vs unqueried) | Guard `always`/`always-true`; or a conditional predicate that states the guard |
| B9 | Solver-only region `"MMIO (solver)"` → role (T4-c/d) | Model-relative region proof → unconditional role | **MP** (SYM OQ3) | A claim that carries the harness-model condition; or a concrete-address corroboration |
| B10 | Vacuous region proof (T4-b) | "proven" region under an unsatisfiable guard | **TT** | The region query is evaluated only when the guard is satisfiable |
| B11 | Typed claim ceiling over all cited artifacts (T5-b) | Grade borrowed from an unrelated artifact | **AP** (EVREC-CEIL-001, code-documented) — potentially inadequate | The ceiling taken from the artifacts the semantic check matched |
| B12 | Path ceiling `max` (T5-c) | A chain as strong as its strongest edge | **MP** (implicit; not documented as intended) | Weakest link (`min`) |
| B13 | Absence on `coverage == complete` (T3-e) | Own-body absence read as call-tree absence | **MP** (SEM OQ5) + **DT** ("does not access") | Wording scoped to "own code, callees opaque", or callee coverage |
| B14 | Bounded concrete observation → STRONG (T6) | Truncated scenario → STRONG | **Justified** for existential, scenario-scoped facts; **MP** for whether the scenario is a structured condition (EV OQ9, CONC OQ13) | The claim states its scenario as a structured condition |
| B15 | Session facts `PROVEN` (T5-g) | Possibility, scenario observation or model-relative solver result → "proven" | **DT** + **MP** (CTRL OQ1–2). The "always 0 or 1" over partial simulation is **TT** | Session levels that mirror the observation mode and completeness |
| B16 | `NO_KNOWN_PATH` BOUNDED → STRONG for `NO_KNOWN_PATH` claims (`A/ledger/semantics.py:503-504`) | — | **Justified**: a same-scope restatement, with absolute negatives blocked (`A/ledger/verifier.py:235-245`) | (already) |
| B17 | Producer result `limitations` not inherited (M7) | Caveats lost | **MP** | Inherit them, or map them to codes, by an explicit per-tool reader |
| B18 | Admission recomputes grade; verification uses the stored grade (X13) | Two grades for one evidence id | **MP** (ADM OQ1, EV OQ2) | Versioned readers, with the version recorded on decisions (identity phase) |

### 3.3 Transitions that are justified, and why

The invariant should not be applied as "grades may never rise". These
derived conclusions add information through reasoning that is already
recorded:

- **`indirect_call_target` STATICALLY_ESTABLISHED** (`C/indirect_target.py:594`).
  A deterministic rule over a *complete* definition set within a declared
  intraprocedural scope. Justified, with heuristic block boundaries
  disclosed.
- **`value_forward_use`** (`A/ledger/semantics.py:249-259`).
  - ESCAPE is PROBABLE ("sound over-approximation", a may-flow).
  - NO_ESCAPE requires `complete` and is BOUNDED.

  Polarity and completeness are already built into the grade. This is the
  model to generalize.
- **`callback_argument_provenance` CLOSED.** STRONG only with a closed
  caller set and constrained values. Otherwise PROBABLE, with
  `CALLER_SET_OPEN`.
- **Concrete existential observations** (B14), and **effects direct
  accesses on always-true paths** (B7, existential half).
- **Candidate generation's `ACCESS_UNDER_ASSUMPTION` and
  `POINTER_CONFLICT` withholding.** This is a precedent for enforcing rules
  at the consumer boundary. The gap is that admission and verification do
  not apply the same rules to model-proposed typed claims.

---

## 4. Proposed minimal evidence semantics contract (PROPOSED)

### 4.1 Invariant, refined

> **ESC-0.** A transformation of evidence is either *representation-only*
> or *evidential*.
> - A **representation-only** transformation (renaming, re-encoding,
>   extraction, caching, replay, historical reuse, summarization, session
>   projection) must be **facet-monotone**. Each facet in §4.2 of its output
>   is equal to, or weaker than, that facet of its inputs.
> - An **evidential** transformation may strengthen a facet only by
>   **citing additional evidence**, recorded in its lineage, of a kind
>   listed in §4.6.
>
> Passing through a stage, agreement between derived sources, re-execution,
> cache hits, model confidence and wording are never additional evidence.

Why the original wording is not sufficient:
- *Too strict:* it would forbid strengthening a conditional fact when a
  grounding observation discharges the condition (§4.6, J3).
- *Too loose:* it does not name **polarity**. A transformation that keeps
  the grade but changes "∃ an access" into "these are all the accesses"
  gains nothing nominal and still overstates.

### 4.2 Evidence dimensions: what must be distinct

| Facet | Values (minimal) | Mechanically represented? | Who sets it | Who must check it |
|---|---|---|---|---|
| **mode** (how observed) | `static-structural`, `static-dataflow`, `concrete-harness`, `symbolic-raw`, `solver`, `documentary` | **Yes** (per fact) | per-tool reader (from tool identity; mostly constant per tool) | candidates, admission, phase B, session projection, gate (phase 2) |
| **interpretation** (how the meaning was derived) | `direct` (engine-reported or decoded from verified bytes), `derived-complete` (deterministic rule over a complete input set within scope), `heuristic` (pattern, scan, boundary, or closed-world over *known* items) | **Yes** (per fact) | reader. Producer additions where native output lacks it (§4.3) | ceiling (§4.5) |
| **polarity** | `exists`, `forall` (universal or negative within a scope) | **Yes**, on facts *and* claims | reader (fact); claim predicate or type (claim) | admission, phase B |
| **scope** | structured scope id: `function-body`, `function-body+callees(opaque)`, `census-graph(hops=N)`, `scenario(S)`, `image`, … | **Yes** (id + parameters) | reader | admission, phase B (claim scope ⊆ fact scope) |
| **completeness over scope** | `complete`, `bounded(reasons…)`, `failed`, `n/a` (for existential facts) | **Yes** | reader, from native completeness fields. Analysis completeness is kept separate from explanation completeness (DF OQ6) | admission, phase B for `forall` claims |
| **conditions** | coded set: `HARNESS_MODEL(id)`, `SPECIALIZATION(r=v)`, `GUARD(status)`, `CLOSED_WORLD(kind)`, `SCENARIO(S)`, `RECEIVER(vptr)`, … | **Yes**: codes and parameters | reader | admission, phase B (claim must carry them, §4.4 R3) |
| **lineage** | evidence ids + engine lineage + `seeded`/`assisted` flags | **Yes**: evidence ids now. Engine lineage is phase 2 | reader; `derived_from` already exists for source agreement (`A/ledger/gate.py:155-164`) | gate (phase 2); ESC-0 audits |
| **implementation identity** | analysis, version, engine, configuration | Hook only here (phase 3) | operation / identity layer | replay, continuity |
| **confidence in interpretation** | — | **No separate field.** It is the output of the mapping in §4.5 (`EvidenceGrade`) | computed | — |
| **detailed reasons, bounds, frontiers, query logs, guard methods** | native | **No.** Kept producer-specific in the content-addressed result | producer | humans, auditors |
| **heuristic function boundaries and similar universal caveats** | limitation codes | Disclosure only, as today | reader | `limitations_preserved` (existing) |

The six distinctions the review asked to keep apart, and how the facets keep
them apart:

| Pair | Distinguished by |
|---|---|
| Exact observation vs correct interpretation | `mode` + `interpretation` (`direct` observation of a table word vs `heuristic` reading of it as a dispatch target) |
| Possible target vs established relationship | `interpretation` (`heuristic` / `CLOSED_WORLD` condition) + edge kind (`POTENTIAL_INDIRECT` vs `ESTABLISHED_INDIRECT`) |
| Path observed vs path proven reachable | `mode=concrete-harness` + `SCENARIO(S)` condition (exists) vs a static `derived-complete` path from a stated root |
| Simulated behavior vs firmware behavior | `HARNESS_MODEL(id)` condition. It is never discharged by agreement with another simulation under the same model |
| Solver proof under assumptions vs independent corroboration | `mode=solver` + `HARNESS_MODEL`/`SPECIALIZATION` conditions vs a lineage-disjoint observation (phase 2) |
| Absence within a bounded search vs proof of absence | `polarity=forall` + `scope` + `completeness`. "Proof of absence" exists only as `forall` + `complete` over a scope, and only for that scope |

### 4.3 Producer obligations

The rule is: native results stay native, and producers add only what a
reader cannot recover. Every evidence-producing tool must make these five
things recoverable, **per fact** where facts differ in strength:

1. **What kind of fact it is**, and its **interpretation basis** where one
   result mixes bases.
2. **The scope** the analysis covered, and **completeness over that scope**.
   Bounds hit, failures and truncation are explicit fields. They are never
   only implied by absence or printed to a log.
3. **Conditions** the fact holds under: harness and solver model,
   specializations, guards, closed-world assumptions, scenario.
4. **The inputs it derived from** (lineage), including other engines'
   outputs and seeds.
5. **Caveats as codes**, not only as prose in a result `limitations` list
   (M7).

Concrete producer additions needed for the demonstrated gaps (PROPOSED). All
are additive. None rewrites history.

| Producer | Addition | Reason |
|---|---|---|
| census `indirect_edge_candidates` → `census_*` results | Per candidate: `basis` ∈ {`ghidra-resolved`, `dynamic-observed:S`, `flash-table-scan`, `ram-fnptr-closed-world`}. Per reachability status: the set of edge bases its shortest strong path used, and the root kind. Per common path: the edge bases used | B1, B2, B5, T1-g. Without it no consumer can tell a table scan from a Ghidra edge |
| `function_effects` adapter | Distinguish RAW-concrete-false from never-queried (`raw-false` vs `unqueried`). Record the enrichment-omitted count. Use one spelling for "always". Mark solver-region proofs as model-relative. Skip or flag region queries when the guard is unsatisfiable | B8, B9, B10; SYM OQ3, 4, 9 |
| `function_effects` session derivation | Carry `status`/`coverage` into any solver statement (for example "return ∈ {0,1} over the simulated paths of a partial run") | B15 |
| static-dataflow (Capstone) | None required for this phase. Bug-fix-level only, per the CLAUDE.md freeze. Their `LIMITATIONS` are mapped by the reader instead | M7; freeze rule |
| p-code `value_forward_use` | Already conforms. Keep analysis completeness separate from explanation completeness (DF OQ6) | — |
| concrete `observed_call_arguments` | Scenario as a structured condition (it is already in the result); `bounded` reasons as codes | B14 |

### 4.4 Consumer obligations

These rules apply wherever evidence becomes a fact, a candidate, a claim
decision or a session statement: in candidates, admission, phase B, and the
session projection.

- **R1. Fact-bound strength.** The ceiling for a claim is computed only from
  the facts the semantic check *matched*: the `SemanticCheck.evidence_id`s,
  or the call path's edges. Citing other evidence never raises it.
- **R2. Combination.**
  - A conjunction or chain takes the weakest link. That means `min` over the
    facts it needs, the union of their conditions, and `complete` only if
    every link is.
  - `max` is allowed only across *alternatives that each independently
    support the entire assertion*. This is the legitimate reading of today's
    "strongest supporting derivation".
- **R3. Conditions are constraints.**
  - A fact with conditions supports a claim only if the claim carries the
    same coded conditions: typed `conditions`/`scenario`/`assumptions`.
  - A predicate that cannot state a condition (today: `FUNCTION_ROLE`,
    `RESOLVED_FUNCTION_POINTER`) cannot be supported by a conditional fact.
    That generalizes candidates' `ACCESS_UNDER_ASSUMPTION` to admission and
    verification.
- **R4. Polarity.**
  - A `forall`/negative claim needs a `forall` fact with
    `completeness=complete` over a scope that contains the claim's scope.
    Otherwise it is at most BOUNDED, and must be worded and typed as
    scope-limited.
  - An `exists` claim may rest on a fact from a bounded-completeness run.
- **R5. No aliasing.** Producer labels (`EXACT`, `STRONG`,
  `DEFINITELY_REACHABLE`, `ESTABLISHED`, `proven`, `always-true`) are never
  read as ledger grades or claim kinds. A versioned per-tool reader
  translates them (§4.5). A consumer that uses a producer label must name
  the producer's meaning.
- **R6. No silent drop.** A consumer either preserves a facet or rejects or
  withholds with a coded reason. Producer-declared caveats are mapped to
  codes or inherited verbatim (M7).
- **R7. Session levels.** Planner-visible facts carry their mode,
  conditions and completeness. A single uniform `PROVEN` is retired or
  redefined (D9).
- **R8. Fail closed on unknown facets.** If a reader cannot determine a
  facet (an unknown tool, an old result shape), the fact supports nothing
  stronger than PROBABLE `exists`, and never a `forall` claim.

### 4.5 Grade as a derived summary (keeps the existing vocabulary)

`EvidenceGrade` stays as the claim-facing vocabulary, so ledger records and
docs stay compatible. It becomes the output of one versioned mapping, applied
**per fact** together with the claim's polarity:

| Fact facets (after R2 combination) | Max grade for an `exists` claim | Max grade for a `forall` claim |
|---|---|---|
| `direct`, `static-structural` decoded from hash-verified bytes, no conditions | EXACT | BOUNDED unless `complete` over scope, then STRONG |
| `direct` or `derived-complete`, conditions all stated in the claim | STRONG | STRONG if `complete` over the claim scope, else BOUNDED |
| any `heuristic` interpretation, or `CLOSED_WORLD` not discharged | PROBABLE | BOUNDED at most |
| conditions present but not stated in the claim | rejected (R3) | rejected |
| `failed`, unknown facets | UNKNOWN (supports nothing) | UNKNOWN |
| `documentary` | PROBABLE (as today) | not supporting |

The table is illustrative. **The exact cells are a decision (D2).** What
matters structurally:
- the grade is computed, never copied from a producer label;
- the mapping is versioned, and its version is recorded wherever a grade is
  used to decide something (this links to the identity phase and X13).

Today's stored artifact grade stays as a historical field. It is not
rewritten.

### 4.6 Justified increases in confidence

Only these strengthen a facet, and each must appear in lineage:

| ID | Mechanism | What it may strengthen | What it may not |
|---|---|---|---|
| J1 | Independent corroboration under the phase-2 lineage rules (disjoint lineage, not assisted) | The claim's **corroboration status** at the gate | Either observation's own interpretation or completeness |
| J2 | A completeness result over a declared scope | `forall` within that scope (bounded negative → scoped negative) | Scope beyond the analyzed one |
| J3 | Discharging a condition with evidence. Examples: an observed caller value grounds a specialization; a concrete dispatch grounds a receiver condition; an analysis excludes computed-pointer stores to a slot | Removes that condition, **replacing it with the discharging evidence's own conditions**. For example, a scenario-observed grounding yields a `SCENARIO(S)` condition, not an unconditional fact | Conditions it does not address |
| J4 | Deterministic re-derivation from exact inputs (decode from verified bytes) | `interpretation=direct` for the decoded fact | The meaning attributed to it (for example "is a dispatch table") |

Never a justification:
- re-running the same operation;
- a cache hit;
- historical reuse;
- census + Ghidra agreement when census derives from Ghidra;
- a solver re-proving a raw fact under the same harness model;
- model confidence;
- a wording regex;
- the number of cited artifacts.

### 4.7 Propagation of uncertainty and incompleteness

- **Facts → claim.** R1 + R2. Conditions are unioned; limitations are
  unioned (existing, EVREC-LIM-004); completeness is the conjunction.
- **Result → derived census structures.** A census status computed over
  mixed-basis edges carries the *set* of bases it used, so a consumer can
  apply R2 to it.
  - **DECISION REQUIRED (D4):** keep the current statuses and add bases, or
    change the statuses.
- **Producer failure.**
  - `failed`, `firmware_unavailable` and timeout facts are `failed`.
    `failed` never supports `forall`, and never makes a lead FOLLOWED as if
    answered (CTRL OQ3).
  - Silent drops (X22) are out of scope here. They are recorded as phase
    "completeness" inputs.

### 4.8 Bounded negative evidence

A negative or universal fact is represented as the tuple:

> (`polarity=forall`, `scope`, `completeness`, `bound`, `frontier/open
> reasons`, `conditions`)

This is the shape `NO_KNOWN_PATH`, `NO_ESCAPE_WITHIN_SCOPE` and
callback `CLOSED`/`OPEN` already approximate.

Rules:
- It supports only a claim of the same polarity whose scope is contained in
  its own.
- It never supports `UNREACHABLE` (existing,
  `A/ledger/verifier.py:235-236`).
- A `bounded` completeness keeps the claim BOUNDED and scope-worded. The
  existing `NO_KNOWN_PATH` rule is consistent with this.
- An **unsatisfiable-under-model guard is not negative evidence about
  firmware** (T4 nuance). It is a conditional `forall` under
  `HARNESS_MODEL`.

### 4.9 Conditional and specialized symbolic conclusions

- Every solver-mode fact carries:
  - `HARNESS_MODEL(effects-v1: opaque calls without memory effects, RAM and
    MMIO unconstrained, read-only segments concrete, step bound N)`;
  - its own `SPECIALIZATION` and `GUARD` conditions.

  Today's `assumptions` list in the raw result is the source.
- **Specialization is hypothetical until discharged by J3.** A specialized
  fact supports only a claim that carries the specialization as a
  structured condition.
  - Today: `HYPOTHETICAL_SPECIALIZATION` is a limitation (disclosure),
    `ACCESS_UNDER_ASSUMPTION` withholds in candidates only, and admission and
    phase B accept an unconditional `FUNCTION_ROLE` (INFERRED from
    T4-d + T5-b).
  - Proposed: admission and phase B reject it (R3).
- **Guard policy (PROPOSED, D6):**

  | Guard | Supports an unconditional `exists` access? |
  |---|---|
  | `always` / `always-true` | Yes |
  | `conditional` | Only a conditional claim |
  | `unknown`, `unqueried` | No; withheld as "not established" |
  | `unsatisfiable`, `raw-false` | No; withheld as "infeasible under model". Neither positive nor negative |

- **Solver-only region membership** is a conditional fact. It supports an
  unconditional role only together with corroborating evidence of a
  concrete address.

### 4.10 Not representing solver assumptions as firmware facts

- Values that come from a specialization, a solver model or a harness seed
  are never rendered as concrete runtime literals:
  - not in claim text generated by candidates;
  - not in session facts;
  - not in fact extraction.

  They carry their condition codes.
- **Harness assumptions** (the scenario recipe, a seeded RAM, the boot
  recipe) are kept apart from **firmware-produced state**, as CLAUDE.md
  requires. Concrete facts carry `HARNESS_MODEL` + `SCENARIO`, and a
  re-run under the same scenario never discharges them (EVREC-LIM-002
  already says so in prose).
- The policy text "a solver result under recorded assumptions" as
  corroboration for `RESOLVED_INDIRECT_CALL` (`A/ledger/policy.py:57-60`)
  should be read under J1 and §4.9. The solver result corroborates only:
  - when its conditions are compatible with the claim's scope; and
  - when its lineage is disjoint from the claim's supporting lineage.

  **DECISION REQUIRED (D11).**

### 4.11 Derived conclusions keep their lineage

- Every fact records the evidence ids it was read from. `SemanticCheck`,
  `CallEdge` and `RoleFact` already hold an `evidence_id`; R1 starts using
  them for the ceiling.
- A derived census status records the edge bases and root kinds it rests on
  (§4.3).
- Session facts keep their evidence ids (they already do) and add mode and
  conditions (R7).
- Phase 2 builds engine-level lineage and the `seeded`/`assisted` handling
  on these ids.

---

## 5. Alternatives and tradeoffs

### A. Producer-native formats; semantics enforced at consumer boundaries only

Producers do not change. Per-tool readers in the ledger layer interpret
native fields, and consumers enforce R1–R8.

### B. Shared typed evidence envelope or IR emitted by every producer

Every producer (Python census, Ghidra scripts, Haskell harnesses, Unicorn
tools) emits facts in a common typed schema with facet fields. Consumers read
only the envelope.

### C (hybrid). Native results + versioned per-tool fact readers + minimal targeted producer additions + consumer rules

This is A, plus:
- the small producer additions in §4.3, for facts native output cannot
  recover (census basis, effects guard distinctions);
- per-fact qualifiers computed by versioned readers, located where the
  `evidence_grade` and `evidence_limitations` if-chains are today. These
  readers are natural members of the planned operation descriptor.

### Evaluation

| Criterion | A: consumer-only | B: shared envelope / IR | C: hybrid (recommended) |
|---|---|---|---|
| **Existing ledger records** | Fully compatible. Facets are re-derived from stored blobs by a versioned reader | Historical artifacts lack the envelope, so a legacy reader is needed anyway (it ends up being A) | Compatible. Old blobs lack the census basis, so readers fail closed to `heuristic` (R8) for affected facts |
| **Migration cost** | Low. Concentrated in `A/ledger/semantics.py`, `claim_semantics.py`, `call_relations.py`, `admission.py`, `candidates.py`, `verifier.py`, `fact_derivation.py` | High. It touches census SQL and exports, four Haskell harnesses, Ghidra Java, Unicorn scripts, and every adapter. It conflicts with the Capstone freeze and the p-code migration plan | Low–moderate: A, plus census candidate basis (schema + `census_graph` export), effects adapter labels, one enrichment count |
| **Auditability** | Medium. Semantics live in readers, so a reader must be read to know what a fact means | High in principle. One schema to inspect | High. Facets are explicit per fact in decision records. Native evidence is still preserved for audit |
| **Deterministic enforcement** | Good where native output has the information. **Impossible** for the census basis (not in results) | Good | Good |
| **Impact on producers** | None. But it cannot close B1, B5 or B8 fully | Every producer, and it forces early vocabulary unification across engines | Two producers (census export, effects adapter), additively |
| **Fit with approved docs** | Partial | Conflicts with `cross-engine-verification.md` §2 ("does not force native representations into a lossy universal schema") | Matches §2's "minimal common envelope + typed comparison records" pattern |
| **Fit with p-code migration** | Neutral | The new p-code analyses would need to emit the envelope before their parity comparison. That couples two milestones | p-code analyses get a reader like any producer. A new analysis version gets a new reader version |
| **Risk** | Reader drift (M7 recurs) | Lossy normalization; large blast radius | Reader drift, mitigated by reader versioning and fixture tests (§7, T8) |

**Recommendation (PROPOSED, not a decision): C.**
- B's benefits are mostly obtainable from per-fact readers, at a fraction of
  the cost.
- A alone cannot recover the census edge basis, which is the root of X1 and
  X10.
- If the operation-descriptor milestone proceeds, the reader should become
  part of each operation's descriptor. That reduces the ~10-module
  registration cost instead of adding to it.

---

## 6. Recommended design decisions requiring approval

Each item is **DECISION REQUIRED**. The recommendation is a proposal.

| ID | Decision | Options | Recommendation | Unblocks |
|---|---|---|---|---|
| D1 | Adopt ESC-0 (refined invariant, §4.1) as a framework rule | adopt / adopt original wording / defer | Adopt the refined form | everything below |
| D2 | What `EvidenceGrade` means: a per-fact derived summary under a versioned mapping (§4.5) vs the current per-artifact producer-status lookup | derived per-fact / keep per-artifact + patches | Derived per-fact. Approve the mapping cells separately | EV OQ6–8; ADM OQ2 |
| D3 | Ceiling rule | (a) current max over cited; (b) fact-bound max; (c) fact-bound + weakest link for chains + max over independently sufficient alternatives | (c) | X6, B11, B12; EVREC-CEIL-001 |
| D4 | Census reachability semantics | (a) restrict the strong graph to `STATICALLY_RESOLVED`/`DYNAMICALLY_OBSERVED` sites (match the docstring); (b) keep the graph, report edge bases + root kind with each status, and let consumers apply R2; (c) rename the statuses | (b), plus fix the docstring and the `census_graph` text. Decide root-rule wording (B2) separately | CEN OQ1, 3, 16; DF OQ4; SEM OQ2 |
| D5 | Can a census fnptr `STRONG` (closed-world) edge be `ESTABLISHED_INDIRECT`? | yes (status quo) / `POTENTIAL_INDIRECT` with a `CLOSED_WORLD(slot)` condition / a new conditional-established kind | `POTENTIAL_INDIRECT` with the condition, until J3 discharge exists | SEM OQ1, 3; ADM OQ4; X10 |
| D6 | Effects guard and region policy (§4.9 table) | as proposed / stricter (always-true only) / status quo | As proposed | SEM OQ4; ADM OQ3; SYM OQ3–4 |
| D7 | Effects completeness for grading and absence | key on `coverage`; "does not access" = own-body only unless callee coverage is cited | Key on `coverage` for `forall`; keep STRONG for `exists` direct facts; attach `EFFECTS_COVERAGE_BOUNDED` whenever coverage ≠ complete | X2, X18; EV OQ7; SEM OQ5 |
| D8 | Concrete observation grading | status quo / polarity-restricted STRONG + scenario as a structured condition | Polarity-restricted, with the scenario structured | CONC OQ13; EV OQ9 |
| D9 | Session-fact levels | keep `PROVEN` (redefine as "mechanically restated") / replace with mode-based levels | Replace, with levels that mirror mode and completeness; the conclusion groups by level | CTRL OQ1–2; X21 |
| D10 | Representing conditions on claims | reuse `ClaimVersion.assumptions` with coded entries / a new `conditions` field / typed per-predicate fields | Coded entries in a new structured field. `assumptions` stays prose for operators | EV OQ9; SEM OQ6 |
| D11 | When a solver result counts as corroboration | as policy text / only under J1 + compatible conditions | J1 + compatible conditions (phase 2 confirms) | VER OQ2 |
| D12 | **Sequencing:** no new verification-policy evidence contract (`MEMORY_ACCESS`, `RESOLVED_INDIRECT_CALL`, `CONTROL_FLOW`) until D3, D5 and D6 are enforced in admission and phase B | adopt / do not | Adopt | Keeps the X15 fail-closed property from turning into a promotion path |

---

## 7. Proposed acceptance criteria and tests (not implemented, not run)

**General requirements.** All tests are framework-owned and synthetic:
- fixture results, or a synthetic census DB / synthetic image;
- no case firmware;
- they run against a scratch ledger.

Each test states the expected behavior **under the proposed contract**. Where
current behavior differs, that is noted (INFERRED from code reading). Each
test has a pass control and a fail case.

### T1. STRONG table-scan candidate that is not independently established

- **Fixture.** A synthetic census DB:
  - `reset → F1` (Ghidra direct);
  - F1 contains an unresolved `ldr pc` whose nearest literal table yields a
    Thumb pointer inside F2 (`source=flash-table-scan`);
  - F3 is reached only by a Ghidra direct edge from F1.
- **Expected:**
  - F2's reachability record carries `bases={flash-table-scan}`;
  - F3's carries `bases={ghidra-direct}`;
  - a rootless claim "F2 is statically reachable" citing the census is
    admitted only as conditional / ≤ PROBABLE;
  - the same claim for F3 is admitted at the mapped grade;
  - a typed `PATH_RELATION` whose only path uses the F1→F2 edge is ≤
    PROBABLE.
- **Fail case (must be rejected):** STRONG claim about F2.
- **Root variant.** The site lives in an unreachable F4. Its target must not
  be reported as reachable from reset (D4/B2 wording).
- **Current behavior:** F2 `DEFINITELY_REACHABLE`, common path STRONG.

### T2. Symbolically observed MMIO access behind an infeasible guard

- **Fixture.** A `function_effects` result: complete, one MMIO access at a
  concrete address.
- **Variants:**
  - (a) guard `unsatisfiable`;
  - (b) RAW guard concretely false, beyond the enrichment cap (`raw-false`
    after §4.3; `unqueried` today);
  - (c) `unknown`;
  - (d) control: `always-true`;
  - (e) control: `conditional` with a conditional claim.
- **Expected:**
  - (a)–(c): no unconditional `MMIO_USER` fact. The candidate is withheld
    with a coded reason. A typed `FUNCTION_ROLE` claim is rejected at
    admission and at phase B.
  - A claim "F does not access PERIPH" citing (a) is also **not** supported
    by it. It is not negative evidence.
  - (d): admitted.
  - (e): admitted only with the guard condition.
- **Current behavior:** (a)–(c) yield `MMIO_USER`.

### T3. Complete raw simulation with opaque computed calls and bounded coverage

- **Fixture.** Raw `status=complete`; one call with no concrete target, so
  `coverage=bounded: computed…`; one always-true MMIO access.
- **Expected:**
  - the artifact carries `EFFECTS_COVERAGE_BOUNDED` (or the completeness
    facet);
  - an `exists` role claim is admitted at STRONG, with the limitation
    inherited;
  - a `forall` claim ("F's only MMIO accesses are …", or "F does not access
    PERIPH2") is rejected unless scope-worded, and then ≤ BOUNDED.
- **Second fixture.** `coverage=complete` with opaque **direct** calls. "F
  does not access PERIPH2" is accepted only with the own-code / callees-opaque
  scope.

### T4. A bounded search that finds no result

- **Fixtures:**
  - `census_common_paths` `NO_KNOWN_PATH` with `hop_limited=true` and a
    non-empty frontier;
  - `value_forward_use` `NO_ESCAPE_WITHIN_SCOPE` with `complete=false`;
  - `function_effects` `status=failed`;
  - `observed_call_arguments` with the function not entered.
- **Expected:**
  - `NO_KNOWN_PATH` claim scoped to the census and its hop bound is
    admitted;
  - "unreachable" / `UNREACHABLE` is blocked;
  - the incomplete forward use supports nothing negative (UNKNOWN);
  - the failed effects result supports no absence;
  - "not entered" supports only "not entered under scenario S within N
    instructions".
- **Fail case:** any of these cited for an unscoped negative.

### T5. Conditional solver fact with an ungrounded argument specialization

- **Fixture.** `function_effects` with `specialize={r0: 0x20001000}`, and a
  specialized fact: access to an MMIO register.
- **Expected:**
  - an unconditional `FUNCTION_ROLE MMIO_USER` is rejected at **admission
    and phase B**, not only in candidates;
  - a claim carrying `SPECIALIZATION(r0=0x20001000)` is admitted as
    hypothetical (grade per D2).
- **Grounding variant.** Add an `observed_call_arguments` fixture showing
  `r0=0x20001000` at a call site in scenario S.
  - The claim may drop `SPECIALIZATION`, but must then carry `SCENARIO(S)`
    (J3).
  - Lineage lists both evidence ids.
  - An unconditional claim is still rejected.

### T6. A correct derived fact whose lineage comes entirely from one engine

- **Fixture.** A `CODE_PRESENCE` claim at an address that really is code in
  the synthetic image. Support: `structural_source_agreement` with census
  (`derived_from: ghidra`) + Ghidra.
- **Expected:**
  - semantics consistent; grade within ceiling; admitted;
  - the gate reports corroboration UNMET (single lineage);
  - the claim does not reach VERIFIED;
  - the agreement artifact's grade is not raised by the second, derived
    source.
- **Control:** the same with a lineage-disjoint source carrying a full
  envelope → corroboration SATISFIED. Phase-2 envelope rules apply.
- **What this asserts:** correctness of the fact never substitutes for
  independence.

### T7. Ceiling binding and weakest link

- **Fixtures:**
  - (a) `FUNCTION_ROLE` matched only by a `partial` effects result (BOUNDED),
    plus an unrelated STRONG census artifact;
  - (b) a call path A→B (decoded BL in a PROBABLE callback-provenance
    artifact) → C (STRONG census edge);
  - (c) control: two artifacts each independently establishing the same role.
- **Expected:**
  - (a): STRONG rejected (currently admitted, INFERRED);
  - (b): the chain is capped by its weakest *fact*. Note that the decoded
    BL itself is a `direct` fact; the artifact's PROBABLE grade is about its
    provenance conclusion. The test checks that fact-level, not
    artifact-level, strength is used;
  - (c): max of the two.

### T8. Representation-only transformations are facet-monotone (property test)

- **Method.** For each per-tool reader, compute facets for one fixture
  result:
  - fresh;
  - from the ledger blob;
  - via the adapter cache hit (`provenance.cached=true`);
  - via historical reuse (`reused_from`);
  - after replay.
- **Expected:**
  - identical facets in every case;
  - no corroboration or lineage added;
  - the reader version recorded.
- **Fail case:** any facet differs.

### T9. Session facts carry level and scope

- **Fixture.** An effects result with `status=partial` and
  `return_bit_valued=proven`.
- **Expected:**
  - the session statement includes solver mode, the harness model and the
    partial coverage;
  - it is not grouped as `proven`;
  - no "always" wording without scope.
- **Fail case:** today's "return value is always 0 or 1" under `PROVEN`.

### T10. fnptr closed-world condition

- **Fixture.** A census `resolved_indirect_edges` entry (STRONG fnptr) with
  limitation `COMPUTED_POINTER_WRITES_NOT_EXCLUDED`.
- **Expected (per D5):**
  - typed `CALL_RELATION ESTABLISHED_INDIRECT` rejected;
  - `POTENTIAL_INDIRECT` with condition `CLOSED_WORLD(slot 0x…)` admitted;
  - the `RESOLVED_FUNCTION_POINTER` candidate is offered with the condition
    (or withheld, if the predicate cannot state it).

### T11. No vocabulary aliasing

- **Fixture.** A census candidate `EXACT` with `source=dynamic-observed:S`.
- **Expected:**
  - the derived fact carries `mode=concrete-harness` and `SCENARIO(S)`;
  - a static categorical claim from it is rejected;
  - an observed-dispatch claim naming S is admitted.
- **Second fixture.** Ghidra-resolved `EXACT` → `direct` static. Both
  labels are `EXACT`, and the reader output differs.

**Stopping condition for the contract milestone** (PROPOSED). T1–T11 pass on
synthetic fixtures. At least the census-basis and effects-guard tests also
pass on a second-ISA synthetic fixture where the producer supports one (p-code
`value_forward_use` already does). And no existing ledger record is
rewritten.

---

## 8. Impacted leaf LLDs, EARS specs and Open Questions

No document listed here was modified. These are the places a later,
approved change would touch.

| Segment (LLD) | Specs affected | OQs this phase would answer or constrain |
|---|---|---|
| production/census (`docs/intent/production/census/census-design.md`) | PROD-CENSUS-REACH-001, -003, -005 (root and strong-graph rule, status meaning); CP-002 (graph semantics in results); new: candidate `basis` export | OQ1, OQ2, OQ4 (dynamic scope), OQ16 (one strong-graph definition) |
| production/static-dataflow | PROD-DFLOW-CB-004 (`ESTABLISHED` rename) | OQ4; OQ6 (analysis vs explanation completeness feeds §4.2) |
| production/symbolic-execution | PROD-SYM-GRD-001, ENR-004, ASM-004 (as `HARNESS_MODEL` condition); new: raw-false label, enrichment-omitted count, guard-gated region query | OQ3, OQ4, OQ9; OQ5 (undisclosed assumptions enter `HARNESS_MODEL`) |
| production/concrete-execution | (grading via EVREC-GRD-004) | OQ13 |
| evidence-record (`docs/intent/evidence-record/evidence-record-design.md`) | EVREC-GRD-003, -004, -005, -007; EVREC-CEIL-001; EVREC-LIM-001, -004 (producer caveats, M7); EVREC-ID-005 (stored vs recomputed grade, via reader version) | OQ2 (grading versioning, overlapping the identity phase), OQ6, OQ7, OQ8, OQ9 |
| claims/claim-semantics | CLAIMS-SEM-FACT-001, -004; EDGE-003; REL-004; PROSE-003 | OQ1–OQ6 |
| claims/admission | CLAIMS-ADMIT-GRD-001, -002; CAND-002, -004 | OQ1–OQ5 |
| claims/verification | CLAIMS-VERIFY-PH-003 (ceiling in phase B); POL-003 / class contracts (D12 sequencing); GATE-005 (lineage hook) | OQ2 (sequencing only); OQ1, OQ3 deferred to phase 2 |
| claims/audit | none directly. The auditor sees facets in the projection | AUD OQ1–2 stay with phase 2 |
| investigation/controller | INV-CTRL-FACT-001; FIN-006 | OQ1, OQ2, OQ3 (failed → FOLLOWED) |
| investigation/continuity | INV-CONT-REUSE-003/004 (reader version on reuse; T8) | OQ1, OQ2 (overlaps the identity phase) |
| `docs/research-ledger.md` "Grades and states are independent"; `docs/claim-admission.md` rule 6; `docs/claim-candidates.md` grade section | Would need revision after D2/D3 | — |

---

## 9. Explicit unresolved questions

These are not answered here. Several overlap the later phases.

1. **Mapping cells (D2).** What grade does each facet combination get?
   - In particular: may `heuristic` + `exists` ever exceed PROBABLE?
   - Should `derived-complete` within a heuristic function boundary be
     STRONG? Today's analogues are `indirect_call_target` and closed
     callback provenance.
2. **Census root rule (B2).** Should a statically resolved indirect target
   be a root when its site's function is not itself reachable? Or should it
   be reachable only through its site?
3. **Discharging `CLOSED_WORLD` for a slot (J3).**
   - What evidence suffices?
   - Is there an engine capability for it (a p-code memory-flow analysis is
     not yet implemented: `value_forward_use` follows no memory flow), or
     does it stay conditional indefinitely?
4. **Harness-model identity.** How is `HARNESS_MODEL(id)` named and
   versioned, so that two results can be compared for "same model"? This
   overlaps the identity phase (SYM OQ1, 5, 6).
5. **Polarity for existing typed predicates.**
   - `PATH_RELATION KNOWN_COMMON_PATH` is `exists`. `NO_KNOWN_PATH` is
     `forall`-bounded.
   - Should `RESOLVED_FUNCTION_POINTER` be treated as `forall`? It
     implicitly asserts "the slot holds this target", which is a statement
     about all writers.
6. **Typed absence.** Should there be a typed absence predicate (for
   example a `NO_ACCESS` role with explicit scope)? Or should absence stay
   an untyped hypothesis capped at PROBABLE?
7. **Historical claims after D2/D3.** Re-verification under the new rules
   may HOLD or BLOCK claims admitted under the old ones. How is that
   presented without rewriting history? This overlaps the lifecycle phase
   (VER OQ4, X16).
8. **Reader drift control.** Is a per-reader fixture corpus (T8) enough?
   Or must reader versions be bound into operation identity (the identity
   phase)?
9. **Explanation vs analysis completeness** (DF OQ6). Does
   `DERIVATION_RECORD_TRUNCATED` affect the `completeness` facet, or only an
   explanation facet?
10. **Session-fact vocabulary (D9).** Should session levels reuse
    `EvidenceGrade` with mode tags, or a distinct vocabulary? How does the
    planner prompt render them without character-budget loss?
11. **Unsatisfiable-under-model accesses.** Are they surfaced as their own
    "infeasible under model" open question, to drive a concrete check? Or
    are they only withheld?
12. **Scope containment.** Can claim scope ⊆ fact scope be decided
    mechanically for every scope kind? Or does scope remain partly
    pattern-matched (SEM OQ6) for some claim forms?
13. **Seeded and derived inputs.** Do `seeded` observations, and Ghidra
    runs seeded from census `fnptr-seeds`, need a facet in this phase (for
    example `interpretation` downgraded at seeded addresses)? Or is lineage
    in phase 2 enough? (X11, X24.)
