# Arrow: claim-semantics

The typed claim vocabulary and the mechanical reading of evidence it is
checked against. It covers:
- predicates, roles, set kinds and call-edge kinds;
- fact extraction from structured evidence results (pointer, role and path
  facts; call edges, unresolved sites, enumerations, reachability);
- deterministic checks of typed bodies;
- the shared prose checks (entity identity, peripheral access and absence,
  call relations through a pattern parser).

Admission, verification and candidate generation all use it. It owns no
lifecycle decision.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton); docs/intent/claims/claims-design.md (the `claims` sub-HLD; skeleton)

### LLD
- docs/intent/claims/claim-semantics/claim-semantics-design.md

### EARS
- docs/intent/claims/claim-semantics/claim-semantics-specs.md (prefix `CLAIMS-SEM`; 33 specs: 33 `[x]`, 0 `[ ]`, 0 `[D]`)

### Tests
All in `agent/tests/`. They use synthetic or fake evidence documents; no engine runs.
- **test_claim_semantics.py:**
  - serialization and normalization;
  - entity roles, pointer relations, set scopes, unattributed members;
  - path status;
  - it also covers verification, audit gating and a case benchmark fixture.
- **test_call_relations.py:** about 30 tests of edge extraction, kinds, conditions, observed dispatch, reachability, absence and parser forms, on a synthetic Thumb disassembly.
  - Its synthetic disassembly uses ARM mnemonics only (`:51-58`).
  - `test_20_persisted_records_load_and_call_diagnostics_only_report` reads the canonical case ledger in place and asserts its tree digest is unchanged.
- **test_claim_quality.py:**
  - entity diagnostics;
  - access from a constant load, typed `MMIO_USER`;
  - effects access;
  - categorical absence with symbolic `r0`.

  It is shared with admission. `test_j_persisted_records_load_unchanged_and_carry_no_malformed_identifiers` is a canonical read.
- **Case data used by framework tests:**
  - AutoPilot addresses in `ledger_support.py`;
  - `test_call_relations.py:531` asserts case claim `C9:v1` gives `CALL_REACHABILITY_UNSUPPORTED`.

### Code
- agent/src/aptrace_agent/ledger/claim_semantics.py
- agent/src/aptrace_agent/ledger/claim_checks.py
- agent/src/aptrace_agent/ledger/call_relations.py

### Related docs
- docs/claim-admission.md, docs/claim-call-relations.md, docs/claim-candidates.md, docs/research-ledger.md

## Architecture

**Purpose:** let APTrace decide mechanically whether a claim stays within
what the cited evidence's structured fields establish. Prose is
presentation; a typed body is what is checked (`claim_semantics.py:1-12`).

**Key components:**
1. **Typed bodies:**
   - **`ClaimSemantics`:** one predicate with exactly one body. The predicates are `RESOLVED_FUNCTION_POINTER`, `FUNCTION_ROLE`, `PATH_RELATION`, `CODE_PRESENCE` and `CALL_RELATION`.
   - **Normalization:** addresses normalize to `0x%08x` and functions to `FUN_%08x`.
   - **Claim types:** a compatibility table maps predicates to claim types.
2. **`extract_facts`:** reads facts from evidence results.
   - *Pointer facts and roles:* from any result's `resolved_indirect_edges`.
   - *USB roles:* from `census_usb_inventory`.
   - *Peripheral roles:* `MMIO_USER` vs `ADDRESS_CONSTANT_LOADER` from `census_peripheral_usage`.
   - *Effects roles:* `MMIO_USER` from `function_effects` accesses in an `MMIO*` region.
   - *Path facts:* from `census_common_paths`.
   - *Registration caller:* the census containing function in structural agreement.
3. **`extract_call_facts`:** builds edges of five kinds, plus unresolved sites, enumerations, concrete entries and census reachability:
   - `DIRECT_CALL`;
   - `TAIL_TRANSFER`;
   - `ESTABLISHED_INDIRECT`;
   - `POTENTIAL_INDIRECT`, with conditions;
   - `OBSERVED_DISPATCH`, with a scenario.
4. **Checks:**
   - `check_resolved_pointer`, `check_function_role`, `check_path` and `check_code_presence`;
   - `check_edge`, `check_reach` and `check_absence`;
   - `typed_call_checks` and the prose `call_diagnostics`;
   - `entity_diagnostics` and `access_diagnostics`.
5. **Prose parser:** `parse_assertions` is a regex and token parser for edge, reach and absence assertions. Clauses it cannot classify are noted `CALL_RELATION_UNCHECKED`.

## Spec Coverage

`[x]` means observed in source only. Tests use synthetic or fake evidence.
No tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Asserting test |
|---|---|---|---|---|---|
| Vocabulary | CLAIMS-SEM-VOC-001 to 005 | 5 | 0 | 0 | 4 |
| Fact extraction | CLAIMS-SEM-FACT-001 to 006 | 6 | 0 | 0 | 6 |
| Call-edge extraction | CLAIMS-SEM-EDGE-001 to 006 | 6 | 0 | 0 | 4 |
| Typed checks | CLAIMS-SEM-CHK-001 to 004 | 4 | 0 | 0 | 4 |
| Call-relation requirements | CLAIMS-SEM-REL-001 to 007 | 7 | 0 | 0 | 7 |
| Prose checks | CLAIMS-SEM-PROSE-001 to 005 | 5 | 0 | 0 | 4 |

**Summary:** all 33 specs are observed in source, and none is an
approved-intent gap. The open decisions concern whether the evidence these
rules accept is sufficient:
- EDGE-003: census confidence → categorical edge;
- REL-004: census reachability;
- FACT-004: unguarded effects roles;
- PROSE-003: direct-only absence.

29 specs have an asserting test. Edge extraction is tested on Thumb
mnemonics only. No `@spec` annotations exist.

## Key Findings

1. **Census confidence becomes categorical call edges.** A census `resolved_indirect_edges` entry with `EXACT` or `STRONG` confidence becomes an `ESTABLISHED_INDIRECT` edge: categorical, with no condition. Weaker confidence becomes `POTENTIAL_INDIRECT` (`call_relations.py:332-341`). Census promotes `STRONG` table-scan and function-pointer candidates into its strong graph (census Open Question 1). That census confidence is therefore what admits a categorical indirect-call claim. Cross-segment X1, X10.
2. **Census reachability supports rootless reachability claims.** A census `DEFINITELY_REACHABLE` status supports a reachability claim with no cited root, when the wording matches a census or static scope regex (`call_relations.py:571-593`). The census docstring and code disagree on what feeds `DEFINITELY_REACHABLE` (census `REACH-001/003/005`, contradicted). Cross-segment X1.
3. **Pointer facts ignore edge confidence.** `extract_facts` creates pointer facts and roles from every `resolved_indirect_edges` entry, whatever its confidence (`claim_semantics.py:431-447`). The grade ceiling applies separately (evidence-record).
4. **Effects accesses become `MMIO_USER` roles.**
   - *Rule:* a `function_effects` access whose region starts with `MMIO` yields an `MMIO_USER` role, with the peripheral taken from the SVD register name (`claim_semantics.py:528-537`).
   - *Included:* solver-derived regions (`MMIO (solver)`), and accesses whose guard is `unqueried`, `conditional` or `unsatisfiable`.
   - *Status:* no guard filter is applied. Whether an access on an unsatisfiable or unqueried path should establish a role is not decided (symbolic-execution Open Question 4).
5. **Absence of access is direct-only.**
   - *Rule:* `access_diagnostics` accepts a categorical "does not access" claim when cited `function_effects` coverage is `complete` and no access address is parametric (`claim_checks.py:207-251`).
   - *Effects call model:* calls are opaque, with no memory effects (PROD-SYM-ASM-004). Complete coverage therefore excludes direct accesses only.
   - *Status:* whether "does not access" means direct access only is not stated `[inferred]`.
6. **Reading and scope are pattern-based.** Which claims the access rules apply to, absence scoping, census scoping and observed-scenario naming are all decided from assertion wording by regex (`claim_checks.py:20-26`; `call_relations.py:571, 620-624`). The diagnostics are marked `pattern-matched`. A wording change can move a claim between "scoped" and "categorical" `[inferred]`.
7. **ISA, case and peripheral vocabulary are in framework code:**
   - ARM and Thumb mnemonics (`bl`, `blx`, `b<cond>`) in edge extraction (`call_relations.py:152-186, 710-713`);
   - Thumb bit-0 "canonical target" checks (`claim_semantics.py:626-635`);
   - 32-bit address formatting;
   - SAM-style peripheral names and `USB`/`EIC` literals (`claim_checks.py:95, 174`);
   - `USB` for `census_usb_inventory` (`claim_semantics.py:458, 508`);
   - the source name `census` (`claim_semantics.py:420`).
8. **Two set kinds and one claim type have no producer.** `INTERRUPT_DISPATCH_SET` and claim type `UNREACHABLE` are declared, and documented as produced by no current analysis (`claim_semantics.py:45-47`; `models.py:49-62`).
9. **Observed call sites become static edges.**
   - *`DIRECT_CALL`:* every Ghidra static call site the concrete operation lists (`OBSERVED` or `UNOBSERVED` with a caller) becomes a `DIRECT_CALL` edge (`call_relations.py:256-277`).
   - *`OBSERVED_DISPATCH`:* only reached sites become `OBSERVED_DISPATCH`.
   - *Sites with no source:* dynamic edges without a source are attributed through instruction ownership from other cited evidence, which uses heuristic boundaries.

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* The canonical-ledger test reads in place
and asserts the tree digest is unchanged.

### Confirmed defects
*None demonstrated by execution.*

### Evidence-integrity risks
1. **Census `EXACT`/`STRONG` → `ESTABLISHED_INDIRECT`**, and census `DEFINITELY_REACHABLE` → a supported reachability claim (Findings 1–2; cross-segment X1, X10).
2. **`MMIO_USER` roles from effects accesses regardless of guard or solver origin** (Finding 4).
3. **A complete-coverage absence check over an opaque-callee model** (Finding 5).
4. **Pattern-matched scoping decides between categorical and scoped readings** (Finding 6).

### Architectural coupling
5. **ISA, case and peripheral literals in framework claim code** (Finding 7). CLAUDE.md requires p-code walkers to carry no ISA tokens; these modules are not p-code walkers, but the same boundary question applies.
6. **The ledger's claim code imports from `census_graph` and reads the source name `census`.**

### Semantic inconsistencies
7. **Declared vocabulary with no producer** (Finding 8).
8. **Two treatments of edge confidence.** Pointer facts ignore it; call edges map it (Findings 1, 3).

### Maintenance debt
9. **A 1,036-line regex parser** with no ISA-neutral edge source.
10. **Framework tests rely on case data:** AutoPilot addresses and the case claim `C9:v1`.
