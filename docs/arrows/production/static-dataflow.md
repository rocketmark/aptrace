# Arrow: static-dataflow

Instruction-level and intraprocedural static dataflow over firmware code.
Two implementations exist side by side:
- **the p-code path:** a Ghidra raw p-code forward-use walker with its APTrace
  driver and the `value_forward_use` operation;
- **the legacy Capstone-operand path:** backward reaching definitions for
  indirect-call targets, one-hop callback provenance, RAM function-pointer
  slots, indexed and interprocedural writes, and slot-dispatch sweeps, with
  their agent adapters.

The planned migration from the second to the first is owned by this segment.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been
verified against code (no audit has run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/static-dataflow/static-dataflow-design.md

### EARS
- docs/intent/production/static-dataflow/static-dataflow-specs.md (prefix `PROD-DFLOW`; 50 specs: 49 `[x]`, 1 `[ ]`, 0 `[D]`)

### Tests
- **p-code:**
  - tools/ghidra/test_pcode_forward_use.py: exact expectations for 11 Thumb and 7 RV32 controls plus Thumb/RV32 negatives and budget suites (`controls.json`); spike parity; byte-identical determinism; project-mode source immutability; request validation; verdict policy; a static ISA-token check over walker and driver
  - Fixtures: tools/ghidra/fixtures/pcode_forward_use/ (`thumb_controls.s`, `thumb_negative.s`, `rv32_controls.py`, `rv32_negative.py`, `.bin` images, `controls.json`, `APTracePcodeForwardUseTestSeed.java`, `extract_text.py`)
- **Capstone dataflow** (hand-encoded Thumb fixtures and scratch DBs, except where noted):
  - tools/census/test_indirect_target.py, test_callback_provenance.py, test_fnptr_resolve.py (one real-census check, read-only URI)
  - tools/census/test_indexed_writes.py (one real-census check, through the schema-ensuring connection; see Must Fix), test_interproc_writes.py, test_slot_dispatch.py
- **Agent adapters:**
  - agent/tests/test_value_forward_use.py (recorded driver outputs in agent/tests/data/value_forward_use_fixtures.json; end-to-end Ghidra test skips without Ghidra)
  - agent/tests/test_indirect_call_target.py, agent/tests/test_callback_provenance.py (real-tool checks need the case census)
- **Case-owned**, outside framework scope:
  - cases/performing-rigs/test/test_value_forward_use.py
  - cases/performing-rigs/test/test_callback_provenance.py
  - cases/performing-rigs/test/test_indirect_dispatch.py

### Code
- **p-code path:**
  - tools/ghidra/scripts/APTracePcodeForwardUse.java: the walker. Forward may-flow of one instruction-defined value; reports uses, kills, derivation and incompleteness, but no verdict.
  - tools/ghidra/pcode_forward_use.py: the driver. Target binding, scratch project copy, validation, engine identity check, verdict policy, measurement.
  - agent/src/aptrace_agent/value_forward_use.py: the `value_forward_use` adapter, plus `census_code_pointer_loads`.
- **Capstone-operand path:**
  - tools/census/indirect_target.py (v2): backward reaching definitions for a register-indirect branch; shape and candidate classification; vptr installations
  - tools/census/callback_provenance.py (v1): one-hop caller-argument provenance; CLOSED/OPEN target set
  - tools/census/fnptr_resolve.py (no version constant): RAM function-pointer slot resolution; runs inside `census reduce`
  - tools/census/indexed_writes.py (no version constant): indexed RAM stores; also the shared register resolver other modules import
  - tools/census/interproc_writes.py (no version constant): one-hop "callee writes through an argument"
  - tools/census/slot_dispatch.py (v2): whole-image Thumb pattern sweep for slot dispatch
- **Agent adapters for the Capstone path:**
  - agent/src/aptrace_agent/indirect_target.py (`indirect_call_target` v1)
  - agent/src/aptrace_agent/callback_provenance.py (`callback_argument_provenance` v1)

### Related docs
- docs/tooling/pcode-forward-use.md, docs/tooling/pcode-migration.md, docs/tooling/tool-selection.md
- docs/spikes/architecture-evaluation.md §1, §4, §8–9; CLAUDE.md "Static dataflow and custom Python"

## Architecture

**Purpose:** answer bounded questions about where a value comes from and
where it goes inside a function, as structured, completeness-aware evidence.
CLAUDE.md makes Ghidra p-code the preferred foundation and freezes new
Capstone-operand semantics. The Capstone modules remain the only backward
reaching-definitions implementation until each is migrated side by side.

**Key components:**
1. **p-code walker:** an ISA-free Java walker that takes calling convention, stack pointer and argument storage from the program's language and cspec. It is two-phase: a fixpoint, then recording. It emits incompleteness codes and assumptions.
2. **p-code driver:** owns the APTrace policy. Verdicts are ESCAPE, NO_ESCAPE_WITHIN_SCOPE, INCOMPLETE or UNSUPPORTED. It adds precision labels, copies the project to scratch, checks engine identity, and keeps measurement outside the deterministic result.
3. **Capstone reaching definitions:** `indirect_target` is the hub; `callback_provenance` and `fnptr_resolve` consume it. `indexed_writes` hosts the shared register resolver used by `fnptr_resolve`, `interproc_writes`, `indirect_target` and `callback_provenance`.
4. **Agent adapters:** each validates the request against an APTrace-owned allow-list (a census register-indirect site, or a hex origin plus an optional register). Each checks the image SHA-256, runs the tool as a subprocess with a timeout, and maps failures to statuses.

## Spec Coverage

`[x]` means observed in source only. "Test-asserted" counts specs with a test
assertion; no tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Test-asserted |
|---|---|---|---|---|---|
| p-code walker | PROD-DFLOW-PCW-001 to 007 | 7 | 0 | 0 | 5 (4 need Ghidra) |
| p-code driver | PROD-DFLOW-PCD-001 to 011 | 11 | 0 | 0 | 7 (2 need Ghidra) |
| `value_forward_use` adapter | PROD-DFLOW-VFU-001 to 006 | 6 | 0 | 0 | 6 |
| `indirect_target` | PROD-DFLOW-IT-001 to 006 | 6 | 0 | 0 | 6 |
| Callback provenance | PROD-DFLOW-CB-001 to 005 | 5 | 0 | 0 | 4 |
| Function-pointer resolution | PROD-DFLOW-FP-001 to 003 | 3 | 0 | 0 | 2 |
| Indexed writes | PROD-DFLOW-IW-001 to 002 | 2 | 0 | 0 | 1 |
| Interprocedural writes | PROD-DFLOW-IPW-001 to 003 | 3 | 0 | 0 | 2 |
| Slot-dispatch sweep | PROD-DFLOW-SD-001 | 1 | 0 | 0 | 1 |
| Shared register resolver | PROD-DFLOW-RES-001 to 002 | 2 | 0 | 0 | 0 |
| Capstone-path adapters | PROD-DFLOW-ADP-001 to 003 | 3 | 0 | 0 | 3 |
| Canonical state protection | PROD-DFLOW-TEST-001 | 0 | 1 | 0 | n/a |

**Summary:** 49 of 50 specs are observed in source. 1 is an approved-intent
gap: TEST-001, canonical census isolation in regression tests (the Must Fix).

Resolver behavior is recorded as observed, with no demonstrated real-world
error:
- RES-001: over-broad definition, leading to incomplete provenance;
- RES-002 and IPW-003: missing call-clobber handling, a possible source of
  false-positive provenance.

PCW-005 and PCD-007 record the `DERIVATION_RECORD_TRUNCATED` handling with
the analysis-versus-explanation completeness question left open. CB-004
records the census DEFINITELY_REACHABLE → ESTABLISHED mapping.

37 specs have a test assertion; 6 need Ghidra and a few more need the case
census. No `@spec` annotations exist in code yet.

## Key Findings

1. **Migration status, judged by what is implemented.**
   - `value_forward_use` is the only implemented p-code operation.
   - No p-code backward reaching-definitions walker exists, and no `indirect_target` v3 module exists.
   - Every Capstone module in `docs/tooling/pcode-migration.md`'s "Migrate" table is still the implementation in use. That doc itself says "Nothing listed here has been migrated".
2. **The p-code path is ISA-free by test.**
   - `test_pcode_forward_use.py:238-258` statically checks the walker and driver for ISA tokens.
   - The adapter takes language, cspec and base from the Ghidra cache `meta.json` (`value_forward_use.py:182-186`).
   - RV32 coverage is synthetic only (`pcode-forward-use.md` "Not established").
3. **`DERIVATION_RECORD_TRUNCATED` makes a result incomplete although its own detail says otherwise.** The walker emits it as an incompleteness entry whose detail reads "analysis unaffected" (`APTracePcodeForwardUse.java:724`). The driver sets `complete = not r["incomplete"]` (`pcode_forward_use.py:341`), so such a result can never be NO_ESCAPE_WITHIN_SCOPE. `pcode-forward-use.md`'s code table omits the code. *(Read from code; the conservative direction.)*
4. **The driver's identity check skips the load base.** It compares the program SHA-256, language and cspec, but not the target base against the program's image base (`pcode_forward_use.py:301-310`).
5. **The timeout re-check can misreport.** `_run_measured` re-checks the deadline after the process has already exited (`pcode_forward_use.py:215-216`). A run that ends just before the deadline can be returned as exit -1 with a timeout note. The adapter's own subprocess timeout is separate (`value_forward_use.py:156-158, 191-196`). *(Inferred; not executed.)*
6. **Fixed-ISA semantics in the Capstone modules.**
   - AAPCS register sets (`ARG_REGS`, `CALL_CLOBBERED`) are duplicated across modules (`indirect_target.py:82-83`; `fnptr_resolve.py:57-58`; `interproc_writes.py:34`).
   - Thumb encodings are hand-decoded in `callback_provenance` and `slot_dispatch`.
   - Cortex-M specifics: BLX-imm is UNDEFINED, INVSTATE on an even target (`callback_provenance.py:112, 240`; INVSTATE noted at `:28`).
   - Capstone mode differs: `THUMB | MCLASS` in `slot_dispatch` versus `THUMB` elsewhere.
   - These are the modules CLAUDE.md freezes for new semantics.
7. **The shared register resolver's definition test is broader than its docstring.**
   - `indexed_writes._reg_written_by` documents "a small set of def shapes". It returns the first operand's register for any instruction whose first operand is a register, so `str`, `cmp` and `tst` count as definitions. It never treats a call as clobbering `r0`–`r3` (`indexed_writes.py:145-154`).
   - `fnptr_resolve` adds its own call-clobber and chain-crosses-call guards (`fnptr_resolve.py:109-124`). `interproc_writes._reg_traces_to_argument` does not (`interproc_writes.py:42-69`).
   - No test covers an intervening call clobbering an argument register in `interproc_writes`.
   - *(Read from code; effect on real results not demonstrated.)*
8. **Some Capstone results are dropped without a completeness signal.**
   - `interproc_writes` drops unresolved cases by design, so a missing writer has no completeness signal (`interproc_writes.py:151-152`). It also needs `edges.from_addr` to equal the call instruction exactly (`:139`).
   - `indexed_writes` drops a constant index that lands outside the array (`indexed_writes.py:442`) and excludes unattributed blocks without saying so (`:402-404`).
   - `slot_dispatch` documents itself as pattern-matched, records no image hash, and stops its loop at `len(image) - 4` (`slot_dispatch.py:16-19, 75`).
9. **Callback provenance inherits census reachability wording.** `callback_provenance._REACH` maps census `DEFINITELY_REACHABLE` to `ESTABLISHED`, POSSIBLY_REACHABLE to `CONDITIONAL` and NO_KNOWN_PATH to `UNRESOLVED` (`callback_provenance.py:69`). Census DEFINITELY_REACHABLE can rest on STRONG table-scan candidates (census Open Question 1), so "ESTABLISHED" caller reachability inherits that promotion.
10. **Incompleteness detection relies on reason text.** `callback_provenance` detects incompleteness by string prefixes (`"block limit"`, `"work budget"`, `"bound"`; `:585, 604-605`). The modules import each other's private `_`-prefixed helpers (`callback_provenance.py:51-54`; `fnptr_resolve.py` from `indexed_writes`, `interproc_writes`).
11. **Two version axes, and some modules have none.**
    - Agent wrappers carry their own versions (`indirect_call_target` v1, `callback_argument_provenance` v1, `value_forward_use` v1). The tools report theirs: `indirect_target` v2, `callback_provenance` v1 with `site_analysis`, `pcode_forward_use` v1.
    - `fnptr_resolve`, `indexed_writes` and `interproc_writes` have no version constant; `fnptr_resolve` has only a `SOURCE` string (`fnptr_resolve.py:62`).
12. **Adapters check identity and isolate state.**
    - Every adapter checks the image SHA-256 before running and returns `firmware_unavailable` on mismatch.
    - A returned document naming another firmware, site or origin raises `RuntimeError` rather than returning a status.
    - The census CLIs for `indirect_target` and `callback_provenance` open the DB read-only (`indirect_target.py:681`).
    - The p-code driver never opens the source Ghidra project: it works on a scratch copy, and a test checks the source is byte-identical afterward.
13. **Contradicting docs about call-site addressing.** `fnptr_resolve.py:250-252` says Ghidra call edges are keyed by block start. `macaw_compare.py:58-59` says by exact instruction address. `test_fnptr_resolve.py` covers both forms.
14. **The spike-parity test checks expectations, not engine output.** `test_spike_parity` compares spike ground truth with the manifest's expected escape kinds. Engine agreement is checked only by `test_controls` (`test_pcode_forward_use.py:101-117`).

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
1. **Regression tests must not expose canonical census databases to schema changes or other mutations.**
   - **Observed:** `tools/census/test_indexed_writes.py:377-381` (`test_real_known_indexed_write`) opens `census_db.DEFAULT_DB_PATH`, the canonical case census, through `census_db.connect(..., create=False)`. That connection path runs schema DDL and column migrations and commits (census `PROD-CENSUS-STORE-002`).
   - **Rule:** CLAUDE.md "Protecting research and repository state" applies to any operation that *might* modify canonical research state. An actual mutation does not need to be demonstrated.
   - **Open:** read-only access (as `test_fnptr_resolve.py:224` already uses) versus a scratch copy is an implementation decision, left to the fix.

### Confirmed defects
*None demonstrated by execution.* Source/documentation contradictions are listed under Semantic inconsistencies.

### Evidence-integrity risks
2. **Results without versions.** `fnptr_resolve`, `indexed_writes` and `interproc_writes` results carry no analysis version. `fnptr_resolve` rows feed census reachability and derived Ghidra seeds. (Finding 11)
3. **Over-broad definitions and missing clobber checks.** The shared resolver treats non-defining instructions as definitions, and `interproc_writes` has no call-clobber guard, so a clobbered argument register could be read as the incoming argument. *(Inferred.)* (Finding 7)
4. **Silent drops in `interproc_writes` and `indexed_writes`.** Unresolved writers, out-of-range indices and unattributed blocks are dropped without any completeness signal. (Finding 8)
5. **Caller reachability labeled "ESTABLISHED".** `callback_provenance` labels caller reachability "ESTABLISHED" from census DEFINITELY_REACHABLE, which can rest on table-scan candidates. (Finding 9)
6. **Reason-text coupling.** Incompleteness detection depends on reason-text prefixes. (Finding 10)
7. **Incomplete identity check in the driver.** The p-code driver's identity check omits the load base. (Finding 4)

### Architectural coupling
8. **AAPCS, Thumb and Cortex-M semantics hardcoded in the Capstone modules.** This is current state under CLAUDE.md's freeze. (Finding 6)
9. **Private-helper imports across modules.** (Finding 10)
10. **Agent adapters bound to case artifacts** through structural wiring (evidence-record segment): the case census, the Unicorn venv, the Ghidra project path.

### Semantic inconsistencies
11. **`DERIVATION_RECORD_TRUNCATED`.** It is emitted as incompleteness while its detail says "analysis unaffected", and it is missing from the doc's code table. (Finding 3)
12. **The `_reg_written_by` docstring contradicts its code.** (Finding 7)
13. **Call-edge addressing granularity.** `fnptr_resolve` and `macaw_compare` contradict each other. (Finding 13)
14. **Timeout misreport.** The driver timeout re-check can misreport a just-finished run. *(Inferred.)* (Finding 5)
15. **Two version axes per operation** without a stated rule. (Finding 11)

### Maintenance debt
16. **Duplicated resolver logic.** AAPCS sets and Thumb-bit handling are duplicated, and the Capstone modes are inconsistent. (Finding 6)
17. **Repeated image scans.** `indirect_target._Ctx` scans the whole image for code-pointer words on every call (`indirect_target.py:185-186`).
18. **The spike-parity test is weaker than its name.** It checks expectations, not engine output. (Finding 14)
19. **The migration plan's deletion conditions are unmet**, as expected while no migration step is implemented. (Finding 1)
