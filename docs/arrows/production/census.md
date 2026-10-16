# Arrow: census

The mechanical firmware census. It ingests Ghidra structure, raw byte scans,
a Capstone cross-check and concrete (Unicorn) observations into one SQLite
database. It reduces that evidence into indirect-edge resolutions,
reachability, components, fingerprints, reference matches, a residual queue
and a hardware snapshot. It exposes it through a query CLI and three
read-only agent readers.

## Status

**MAPPED**: mapped 2026-10-16 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/census/census-design.md

### EARS
- docs/intent/production/census/census-specs.md (prefix `PROD-CENSUS`; 66 specs: 63 `[x]`, 3 `[ ]`, 0 `[D]`)

### Tests
- tools/census/test_census.py: address helpers, SVD pin resolution (through the case `pins` module), synthetic raw vector and function-pointer scans, schema creation and idempotent replace, a real build into a temporary DB (needs case Ghidra cache)
- agent/tests/test_census.py: `CensusReader` (synthetic DBs): MMIO and constant-load attribution, hostile input, limit clamping, missing/stale/absent census, reduction overlay, read-only and deterministic queries, research-layer claims and leads
- agent/tests/test_resolved_indirect.py: `CensusGraph` resolved RAM function-pointer edges (synthetic); real USB inventory and EIC↔USB common paths (need case census)
- agent/tests/test_agent_v0.py: `CensusGraph.common_paths` ranking and statuses, USB descriptor scan, real-case USB inventory (needs case census); shares the file with controller tests (investigation segment)
- Case-owned, outside framework scope, but exercising framework census modules:
  - cases/performing-rigs/test/test_reduce.py: reachability, indirect decode and table scans, fingerprints, components, pins, boot recipes, reference library and match, residual priority, hardware contract, firmware diff
  - cases/performing-rigs/test/test_target_irq_count.py: full-length vector scan, high-IRQ roots
  - cases/performing-rigs/test/test_indirect_dispatch.py

### Code
- tools/census/aptrace_census.py: census CLI (30 subcommands; build/reduce delegate, most others are inline SQL)
- tools/census/db.py: connection, schema ensure, column migrations, per-firmware clear/replace
- tools/census/schema.sql: all census tables
- tools/census/build.py: base evidence layer (Ghidra ingest, raw scans, Capstone sweep, SVD/pin resolution, scan warnings)
- tools/census/raw_scan.py: ARMv7-M vector table and function-pointer candidate scans over raw bytes
- tools/census/reduce.py: closure-reduction orchestrator (10 steps)
- tools/census/indirect_resolve.py: indirect-flow shape decode, table scans, scenario-corpus watch replay
- tools/census/reachability.py: roots and strong/weak reachability
- tools/census/components.py, features.py: union-find components; per-function feature rows
- tools/census/fingerprint.py, reference_normalize.py, reference_match.py: cross-image fingerprints; reference-corpus matching and confirmation
- tools/census/residual_priority.py: residual queue definition and priority score
- tools/census/firmware_diff.py: mechanical two-image diff
- tools/census/semantic_packets.py: JSONL evidence packets for model-based classification
- tools/census/dynamic_ingest.py: Unicorn coverage ingest
- tools/census/hardware_snapshot.py: register and pin state from the boot capture
- tools/census/state_map.py: per-slot RAM-array evidence and Unicorn dispatcher probe
- agent/src/aptrace_agent/census.py: `census_peripheral_usage` reader, plus Performing Rigs wiring (SVD, AutoPilot census)
- agent/src/aptrace_agent/census_graph.py: `census_common_paths` and shared graph queries
- agent/src/aptrace_agent/interface_inventory.py: `census_usb_inventory`

Owned by other segments but called by the census: `capstone_sweep.py` and
`macaw_compare.py` (structural-discovery); `indirect_target.py`,
`callback_provenance.py`, `fnptr_resolve.py`, `indexed_writes.py`,
`interproc_writes.py` and `slot_dispatch.py` (static-dataflow).
`fnptr_resolve` runs inside `census reduce`; `indexed_writes` and
`interproc_writes` run inside `state-map`.

### Case inputs consumed (not owned here)
- Imported through `sys.path` from `cases/performing-rigs/config/`: `pins`, `boot_recipes`, `reference_library`, `hardware_contract`
- Imported through `sys.path` from `cases/performing-rigs/scripts/`: `reference_corpus`, `virtual_link`, `dynamic_export`
- Executed by the agent through `importlib`: `cases/performing-rigs/config/svd/resolve_mmio.py`
- Data: the SVD `ATSAMD51J19A.svd`; firmware `originals/` and `SHA256SUMS.txt`; the provenance CSV and case docs (semantic packets)
- The canonical DB at `cases/performing-rigs/research/runs/census/census.sqlite3`

### Related docs
- docs/tooling/census.md (40 lines; most detail has moved to the case's census-results.md)
- docs/spikes/architecture-reconciliation.md §F; docs/tooling/pcode-migration.md

## Architecture

**Purpose:** turn engine output and raw-byte facts into one queryable,
firmware-scoped evidence store with mechanical, disclosed derivations. The
census is the main input of the agent's structural operations and of
several static-dataflow analyses.

**Key components:**
1. **Store** (`db.py`, `schema.sql`): one SQLite file, with rows scoped by `firmware_id`. A static rebuild clears per-firmware rows in child-first order. A reduce clears only reduction tables.
2. **Base layer** (`build.py`, `raw_scan.py`): Ghidra exports transcribed into tables, raw vector-table and function-pointer scans, the Capstone sweep, SVD/pin resolution, and `scan_warnings` for disagreements.
3. **Reduction layer** (`reduce.py` and its steps): fingerprints, a boot capture (Unicorn, through case recipes), reference confirmation, indirect-edge classification with scenario-corpus replay, reachability, features, components, hardware snapshot, residual priority, hardware contract.
4. **Query surfaces** (`aptrace_census.py`, `firmware_diff.py`, `semantic_packets.py`, `state_map.py`): a CLI with inline SQL; diff, export and array-mapping tools.
5. **Agent readers** (`census.py`, `census_graph.py`, `interface_inventory.py`): read-only (`mode=ro`) bounded operations. Each checks the census's firmware SHA-256 against an expected value before answering.

## Spec Coverage

`[x]` means observed in source only. "Test-asserted" counts specs with a test
assertion; no tests were run during mapping. Candidate confidence (CONF),
edge-resolution classification (RES) and reachability status (REACH) are
distinct properties with explicit dependencies between them.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Test-asserted |
|---|---|---|---|---|---|
| Store and lifecycle | PROD-CENSUS-STORE-001 to 007 | 7 | 0 | 0 | 2 |
| Base evidence layer | PROD-CENSUS-BUILD-001 to 006 | 6 | 0 | 0 | 3 (2 need case cache) |
| Raw scans | PROD-CENSUS-RAW-001 to 002 | 2 | 0 | 0 | 2 |
| Dynamic ingest | PROD-CENSUS-DYN-001 to 002 | 2 | 0 | 0 | 0 |
| Candidate confidence | PROD-CENSUS-CONF-001 to 005 | 5 | 0 | 0 | 0 (1 related exercise, case) |
| Edge-resolution classification | PROD-CENSUS-RES-001 to 004 | 4 | 0 | 0 | 2 (case) |
| Reachability status | PROD-CENSUS-REACH-001 to 006 | 6 | 0 | 0 | 4 (case) |
| Fingerprints and reference | PROD-CENSUS-FP-001 to 004 | 4 | 0 | 0 | 3 (case) |
| Other reduction outputs | PROD-CENSUS-RED-001 to 007 | 7 | 0 | 0 | 4 (case) |
| Query and export | PROD-CENSUS-QRY-001 to 006 | 6 | 0 | 0 | 2 (1 case) |
| Peripheral usage reader | PROD-CENSUS-PU-001 to 007 | 7 | 0 | 0 | 6 |
| Common-paths reader | PROD-CENSUS-CP-001 to 004 | 4 | 0 | 0 | 3 (1 needs case census) |
| USB inventory reader | PROD-CENSUS-USB-001 to 003 | 3 | 0 | 0 | 3 (2 need case census) |
| Provenance and incompleteness | PROD-CENSUS-PROV-001 to 003 | 0 | 3 | 0 | 0 |

**Summary:** 63 of 66 specs are observed in source. 3 are approved-intent
gaps (PROV-001 to 003: derived-table provenance, concrete-run engine and
harness identity, recorded reduction incompleteness). Each states the
required outcome only.

Six `[x]` specs are tagged `contradicted`, because the behavior conflicts
with the module's own documentation: REACH-001, REACH-003, REACH-005,
REACH-006, CP-002 and QRY-006. They describe current behavior, not approved
intent.

34 specs have a test assertion; 19 of those are case-owned or need case
artifacts. No test covers a STRONG table-scan or RAM-function-pointer
candidate reaching DEFINITELY_REACHABLE. No `@spec` annotations exist in
code yet.

## Key Findings

1. **Reachability's "strong" graph is wider than its own documentation.**
   - `reachability.py:19-24` says the strong graph uses resolved direct edges plus indirect edges classified STATICALLY_RESOLVED or DYNAMICALLY_OBSERVED.
   - The code admits every indirect candidate with confidence EXACT or STRONG (`reachability.py:122`). That includes:
     - `flash-table-scan` candidates of FINITE_CANDIDATE_SET sites, which get STRONG whenever the target lies inside a known function (`reduce.py:135-143`);
     - `ram-fnptr-constant-store` candidates graded STRONG (`reduce.py:156-171`).
   - The same candidates also become reachability roots of kind `confirmed-indirect-target` (`reachability.py:61-65`).
   - Effect: functions reached only through table-scan candidates can be reported DEFINITELY_REACHABLE.
   - `census_graph.py:268-285` copies these edge semantics, and its evidence limitation text repeats the narrower documented definition (`census_graph.py:139-146`).
   - The case test covers only a WEAK table-scan candidate (`cases/performing-rigs/test/test_reduce.py:88-138`).
2. **Nearest-root fields are filled only for roots.** `nearest_root_addr`/`nearest_root_kind` are looked up by the function's own id among root rows (`reachability.py:155-177`). Non-root functions always get null, while the comment above describes a nearest-root computation (`:149-154`).
3. **"Read-only" connections may change the database schema.** `db.connect(create=False)` still runs `executescript(schema.sql)` and `ALTER TABLE` column migrations on every connect (`db.py:30-50, 70-75`). The query CLI, `reduce`, `macaw_compare` and a static-dataflow test all use it. On a current-schema database these statements should not change content; whether any run has altered a database has not been established. Only the agent readers and two dataflow CLIs open the file with `mode=ro` (`census.py:256-264`; `census_graph.py:211`; `interface_inventory.py:210`).
4. **Ghidra and dynamic results are labeled EXACT.**
   - A computed edge Ghidra resolved becomes STATICALLY_RESOLVED with candidate confidence `EXACT` (`reduce.py:106-114`).
   - A value observed at a watched register during boot or scenario replay becomes DYNAMICALLY_OBSERVED with confidence `EXACT` (`reduce.py:192-213`).
   - A Ghidra thunk flag becomes an `EXACT` fingerprint match (`fingerprint.py:145-151`).
5. **Capstone-sweep edges share the census `edges` table.** They are stored as `resolved=1, source='capstone-sweep'` (`build.py:229-236`).
   - Reachability, `census_graph`, `components` and `fingerprint` filter on `source LIKE 'ghidra%'`.
   - `features`, `residual_priority`, `interproc_writes` and `semantic_packets` do not filter, so their counts and joins include sweep edges.
6. **Concrete execution runs inside the static census.** `reduce` runs a Unicorn boot capture through case `boot_recipes`, then a full scenario-corpus replay. The replay monkeypatches `ConcreteMachine.run` (`reduce.py:257-288`; `indirect_resolve.py:172-231`). Its results feed indirect classification and reachability. A scenario exception is printed and partial data kept (`indirect_resolve.py:224-227`). Engine version and harness assumptions are not recorded per dynamic run (`dynamic_ingest.py:89-96`). Only `hardware_snapshot_runs.assumptions_json` records boot assumptions.
7. **No analysis version or run record for build or reduce.**
   - The `firmware` row records path, SHA-256 (taken from Ghidra `meta.json`), geometry, `ghidra_version` and `built_at` (`build.py:85-104`).
   - Reduction tables carry no analysis version.
   - There is no schema-version table; columns are migrated by a hand-maintained list (`db.py:58-67`).
8. **Failure paths found by reading code and schema (not executed).**
   - `clear_firmware_data` does not clear `state_map_*` tables, but `state_map_indexed_writers.from_function_id` and `state_map_interproc_writers.caller/callee_function_id` reference `functions(id)` with foreign keys on (`db.py:36, 89-114`; `schema.sql:891-943`). A static rebuild after a state-map run could therefore fail or leave dangling rows.
   - `hardware_snapshot.compute` inserts `boot_method = None` when no recipe exists (`hardware_snapshot.py:150, 163-168`) into a `NOT NULL` column (`schema.sql:560`).
9. **Agent readers check identity before answering.**
   - `CensusReader` opens read-only and refuses a census whose firmware SHA-256 differs from the expected one (`census_stale`). It verifies the image hash before its flash scan (`census.py:440-458, 316-347`).
   - The expected SHA-256 comes from the case's `SHA256SUMS.txt`, not from hashing the image (`census.py:826-831, 854-883`).
   - Negative statuses keep two outcomes apart, NO_MATCHING_ACCESSES and NO_CODE_REFERENCES, and carry an explicit limitation that absence is "bounded to these two static methods" (`census.py:165-175, 657-675`).
10. **Case wiring inside framework modules.**
    - `sys.path` imports of case `config/` and `scripts/` modules (`build.py:35, 40`; `reduce.py:60-77`; `dynamic_ingest.py:18-20`; `aptrace_census.py:60-61`; `indirect_resolve.py:186-192`).
    - `DEFAULT_DB_PATH` under the case (`db.py:20`).
    - The SAMD51 SVD hardwired through `pins._samd51_map()` (`build.py:246`; `reduce.py:304`).
    - Four AutoPilot/Mando firmware keys matched by substring (`dynamic_ingest.py:62-63`).
    - SAMD peripheral names (`hardware_snapshot.py:38-39`; `residual_priority.py:35, 210`).
    - A grouping constant tuned on `mando868` (`components.py:21-28, 60-67`).
    - Hardcoded MMIO geometry in `state_map.probe_dispatcher` (`:363-364`).
    - In the agent: `performing_rigs_census()`, which executes the case `resolve_mmio.py` (`census.py:809-886`); an ATSAMD51 diagnostic string (`:413`); USB board and vendor words in the string filter (`interface_inventory.py:26`).
11. **ARMv7-M architecture semantics are built in.**
    - Vector layout and the reset/IRQ split in `raw_scan.py:13-71` and `reachability.py:48-59`.
    - IRQ = index − 16 in `census_graph.py:350-356` and `interface_inventory.py:183-199`.
    - TBB/TBH base = site + 4 (`reduce.py:118-119`).
    - Thumb-bit handling throughout.
12. **Docs, comments and code have drifted.**
    - `docs/tooling/census.md` is 40 lines. Module docstrings cite sections it no longer has.
    - `schema.sql:10` cites a nonexistent `tools/census/cli.py`.
    - Schema comments omit `RESOLVED_RAM_FUNCTION_POINTER` and `ram-fnptr-constant-store` (`schema.sql:374, 394`), and list `writer_status` values no code produces (`schema.sql:864-871`).
    - The `state_map.probe_dispatcher` docstring says it writes `0xFF`, but the code writes `0x01` (`state_map.py:337` vs `:371`).
    - The structural tolerance differs: `max(1, 10%)` in `fingerprint.py:181`, `max(2, 10%)` in `reference_match.py:127`.

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* A test that opens the canonical census
through the schema-ensuring connection (`tools/census/test_indexed_writes.py:377-381`)
belongs to static-dataflow and is assessed there.

### Confirmed defects
*Established by reading code against its own unambiguous documentation, not
by execution. Which side, the code or the documentation, states the intended
behavior is undecided (LLD Open Questions).*
1. **The reachability strong-graph definition contradicts the code.** The docstring says STATICALLY_RESOLVED/DYNAMICALLY_OBSERVED only. The code admits all EXACT/STRONG candidates, including STRONG table-scan and RAM-function-pointer candidates (`reachability.py:19-24` vs `:61-65, 122`). (Finding 1)
2. **The nearest-root comment contradicts the code.** The comment describes a nearest-root computation, but the code fills the fields for root functions only (`reachability.py:149-154` vs `:155-177`). (Finding 2)
3. **The dispatcher probe's documented seed value contradicts the code.** The docstring says `0xFF`, the code writes `0x01` (`state_map.py:337` vs `:371`). (Finding 12)

### Evidence-integrity risks
4. **DEFINITELY_REACHABLE can rest on table-scan candidates.** The same graph semantics, and the narrower limitation text, propagate into `census_common_paths` evidence (`census_graph.py:139-146, 268-285`). (Finding 1)
5. **EXACT labels on engine output and dynamic observations.** Ghidra-resolved edges, Ghidra thunk flags and single dynamic observations are labeled EXACT. CLAUDE.md says Ghidra output is evidence, not truth. (Finding 4)
6. **Mixed edge sources.** Capstone-sweep edges are mixed into consumers that do not filter by source. (Finding 5)
7. **Unversioned concrete evidence.** Concrete observations enter static reduction without per-run engine or harness identity, and scenario failures are only printed. (Finding 6)
8. **No version on build or reduce output.** Derived tables cannot be tied to the code version that produced them. (Finding 7)
9. **"Read-only" connections may run DDL and migrations.** An actual mutation has not been demonstrated. (Finding 3)
10. **Unrecorded skips in `hardware_snapshot`.** It silently skips unreadable regions through broad `except` clauses (`hardware_snapshot.py:49, 99, 111, 118`).
11. **Packets carry no identity.** `semantic_packets` output has no firmware SHA-256, analysis version or generation provenance (`semantic_packets.py:89-198`).

### Architectural coupling
12. **Case imports and paths in framework modules.** Case `config/` and `scripts/` modules are imported through `sys.path`; the default DB path, firmware keys, provenance CSV and docs paths are hardcoded. (Finding 10)
13. **Hardwired device data.** The SAMD51 SVD, SAMD peripheral names, the mando868-tuned constant and the state-map MMIO geometry are built into framework code. (Finding 10)
14. **Agent-side case wiring.** `performing_rigs_census()` and the SVD loader live inside `census.py`; the USB vendor words live inside `interface_inventory.py`. (Finding 10)
15. **ARMv7-M semantics with no declared ISA boundary.** (Finding 11)

### Semantic inconsistencies
16. **Rebuild may fail after a state-map run.** `clear_firmware_data` omits `state_map_*` tables that reference `functions` (foreign keys on). This is inferred from code and schema and was not executed. (Finding 8)
17. **NULL `boot_method` into a NOT NULL column.** `hardware_snapshot` can insert one when no recipe exists. Inferred, not executed. (Finding 8)
18. **The strong-graph definition is duplicated** between `reachability.py` and `census_graph.py`. (Findings 1, 5)
19. **Stale doc, schema and comment references; differing structural tolerances.** (Finding 12)

### Maintenance debt
20. **A large CLI built from inline SQL.** `aptrace_census.py` has 30 subcommands, and its docstring calls the query commands "read-only".
21. **Per-row queries in graph and feature builds.** `census_graph.owner` runs one query per address (`census_graph.py:250-264`), and `features` runs several queries per function.
22. **Hand-maintained migrations and child-first table lists.** `db.py:58-67, 89-127` must be kept in sync with `schema.sql` by hand.
