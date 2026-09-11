-- APTrace census: deterministic SQLite evidence database.
--
-- Every row is a mechanically-collected fact plus its provenance
-- (`source`), never a semantic interpretation -- see
-- docs/tooling/census.md for the full design rationale and
-- tools/census/build.py for what populates each table. Addresses are
-- always stored as plain integers (SQLite INTEGER, i.e. a real 64-bit
-- signed int -- every address here fits well within that range), never
-- as hex strings, so range queries (`to_addr BETWEEN ? AND ?`) work
-- directly; tools/census/cli.py is responsible for hex<->int formatting
-- at the boundary.

PRAGMA foreign_keys = ON;

-- One row per firmware image this database has ever ingested a census
-- for. `key` matches tools/ghidra/aptrace_ghidra.py's FIRMWARE_REGISTRY
-- keys (e.g. 'autopilot868') -- the census reuses that registry rather
-- than inventing a second one.
CREATE TABLE IF NOT EXISTS firmware (
    id            INTEGER PRIMARY KEY,
    key           TEXT UNIQUE NOT NULL,
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    flash_base    INTEGER NOT NULL,
    size_bytes    INTEGER NOT NULL,
    ram_base      INTEGER NOT NULL,
    ram_size      INTEGER NOT NULL,
    mmio_base     INTEGER NOT NULL,
    mmio_size     INTEGER NOT NULL,
    ghidra_version TEXT,
    built_at      TEXT NOT NULL   -- ISO-8601 UTC timestamp of this census build
);

-- Ghidra's function table (APTraceExportStaticAnalysis.java's
-- "functions"). The executable/function-region inventory.
CREATE TABLE IF NOT EXISTS functions (
    id            INTEGER PRIMARY KEY,
    firmware_id   INTEGER NOT NULL REFERENCES firmware(id),
    entry         INTEGER NOT NULL,
    name          TEXT NOT NULL,
    size          INTEGER NOT NULL,
    thunk         INTEGER NOT NULL,  -- 0/1
    external      INTEGER NOT NULL,  -- 0/1
    source        TEXT NOT NULL,
    UNIQUE(firmware_id, entry)
);
CREATE INDEX IF NOT EXISTS idx_functions_fw ON functions(firmware_id);

-- Ghidra's own basic-block model (APTraceExportCensus.java).
CREATE TABLE IF NOT EXISTS basic_blocks (
    id            INTEGER PRIMARY KEY,
    firmware_id   INTEGER NOT NULL REFERENCES firmware(id),
    start_addr    INTEGER NOT NULL,
    end_addr      INTEGER NOT NULL,  -- inclusive last byte address of the block
    function_id   INTEGER REFERENCES functions(id),  -- NULL: block not attributed to any known function
    source        TEXT NOT NULL,
    UNIQUE(firmware_id, start_addr)
);
CREATE INDEX IF NOT EXISTS idx_blocks_fw ON basic_blocks(firmware_id);
CREATE INDEX IF NOT EXISTS idx_blocks_function ON basic_blocks(function_id);
CREATE INDEX IF NOT EXISTS idx_blocks_range ON basic_blocks(firmware_id, start_addr, end_addr);

-- Direct control-flow/call edges, resolved and unresolved alike (an
-- unresolved indirect edge has to_addr NULL, resolved=0) --
-- APTraceExportCensus.java (Ghidra basic-block model + a per-instruction
-- scan for computed flow with no resolved reference) and
-- tools/census/capstone_sweep.py (an independent cross-check).
CREATE TABLE IF NOT EXISTS edges (
    id                INTEGER PRIMARY KEY,
    firmware_id       INTEGER NOT NULL REFERENCES firmware(id),
    from_addr         INTEGER NOT NULL,
    to_addr           INTEGER,           -- NULL if unresolved
    kind              TEXT NOT NULL,     -- fallthrough / branch / cbranch / call / computed-call / computed-jump / *-unresolved
    resolved          INTEGER NOT NULL,  -- 0/1
    from_function_id  INTEGER REFERENCES functions(id),
    to_function_id    INTEGER REFERENCES functions(id),
    source            TEXT NOT NULL      -- ghidra-basicblockmodel / ghidra-instrscan / capstone-sweep
);
CREATE INDEX IF NOT EXISTS idx_edges_fw ON edges(firmware_id);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(firmware_id, from_addr);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(firmware_id, to_addr);
CREATE INDEX IF NOT EXISTS idx_edges_resolved ON edges(firmware_id, resolved);

-- The ARMv7-M vector table: 16 system exception slots + N IRQ slots,
-- read directly from the firmware's own flash bytes (tools/census/raw_scan.py)
-- -- independent of Ghidra's own seeding (which consumes the same table
-- but only to plant function starts, not to keep a queryable record).
CREATE TABLE IF NOT EXISTS vectors (
    id                        INTEGER PRIMARY KEY,
    firmware_id                INTEGER NOT NULL REFERENCES firmware(id),
    vector_index                INTEGER NOT NULL,  -- 0 = initial SP; 1-15 = system exceptions; 16+ = IRQ (index-16)
    raw_value                   INTEGER NOT NULL,   -- exact little-endian word from flash (Thumb bit intact)
    target_addr                 INTEGER,            -- raw_value with the Thumb bit stripped; NULL for vector 0 or an empty slot
    name                         TEXT,               -- standard ARMv7-M system exception name (index<16 only); NULL for IRQs
    is_irq                       INTEGER NOT NULL,   -- 0/1
    landed_in_known_function    INTEGER,            -- 0/1/NULL(vector 0/empty): does target_addr equal a functions.entry?
    source                       TEXT NOT NULL,
    UNIQUE(firmware_id, vector_index)
);
CREATE INDEX IF NOT EXISTS idx_vectors_fw ON vectors(firmware_id);

-- Candidate function pointers: 4-byte-aligned flash words, outside any
-- known function body, whose value (Thumb bit stripped) equals a known
-- function's entry point. A *candidate*, not an assertion -- flagged
-- explicitly as evidence, not as "this is a real function-pointer
-- table/callback slot" (tools/census/raw_scan.py).
CREATE TABLE IF NOT EXISTS function_pointers (
    id                       INTEGER PRIMARY KEY,
    firmware_id               INTEGER NOT NULL REFERENCES firmware(id),
    location_addr              INTEGER NOT NULL,  -- flash address the candidate word was found at
    raw_value                   INTEGER NOT NULL,
    target_addr                 INTEGER NOT NULL,  -- raw_value with the Thumb bit stripped
    matches_known_function     INTEGER NOT NULL,  -- 0/1: does target_addr equal a functions.entry?
    source                       TEXT NOT NULL,
    UNIQUE(firmware_id, location_addr)
);
CREATE INDEX IF NOT EXISTS idx_funcptrs_fw ON function_pointers(firmware_id);
CREATE INDEX IF NOT EXISTS idx_funcptrs_target ON function_pointers(firmware_id, target_addr);

-- RAM reads/writes with a statically-resolved target address (Ghidra's
-- own reference manager, from the same instruction pass as `edges`'
-- unresolved-indirect scan -- APTraceExportCensus.java).
CREATE TABLE IF NOT EXISTS memory_accesses (
    id                  INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    from_addr             INTEGER NOT NULL,
    from_function_id      INTEGER REFERENCES functions(id),
    to_addr               INTEGER NOT NULL,
    width                  INTEGER,   -- bytes; NULL if not a single-fixed-width load/store (e.g. LDM/STM/PUSH/POP)
    direction              TEXT NOT NULL,  -- READ / WRITE / DATA
    source                 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memacc_fw ON memory_accesses(firmware_id);
CREATE INDEX IF NOT EXISTS idx_memacc_to ON memory_accesses(firmware_id, to_addr);
CREATE INDEX IF NOT EXISTS idx_memacc_from ON memory_accesses(firmware_id, from_addr);

-- MMIO reads/writes with a statically-resolved target address, same
-- source pass as memory_accesses but landing in the MMIO window instead
-- of RAM. `peripheral`/`register_name` are filled in by resolving
-- `to_addr` through tools/svd/resolve_mmio.py's Samd51Map -- NULL means
-- the SVD has no peripheral covering that address (a real finding, kept
-- visible rather than hidden -- see scan_warnings).
CREATE TABLE IF NOT EXISTS mmio_accesses (
    id                  INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    from_addr             INTEGER NOT NULL,
    from_function_id      INTEGER REFERENCES functions(id),
    to_addr               INTEGER NOT NULL,
    width                  INTEGER,
    direction              TEXT NOT NULL,
    peripheral             TEXT,     -- e.g. "PORT", NULL if unresolved
    register_name          TEXT,     -- e.g. "GROUP1.OUTSET", NULL if unresolved or not register-exact
    resolution_note         TEXT,     -- e.g. "byte offset into register" / "unlisted offset"
    source                  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mmioacc_fw ON mmio_accesses(firmware_id);
CREATE INDEX IF NOT EXISTS idx_mmioacc_to ON mmio_accesses(firmware_id, to_addr);
CREATE INDEX IF NOT EXISTS idx_mmioacc_peripheral ON mmio_accesses(firmware_id, peripheral);

-- Flash/literal/data references from code -- reused directly from
-- APTraceExportStaticAnalysis.java's existing "dataReferences" export
-- (memory_accesses/mmio_accesses above cover RAM/MMIO; this table is
-- what's left: flash constants, literal pools, string addresses, etc).
CREATE TABLE IF NOT EXISTS literal_refs (
    id                  INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    from_addr             INTEGER NOT NULL,
    from_function_id      INTEGER REFERENCES functions(id),
    to_addr               INTEGER NOT NULL,
    to_label               TEXT,
    ref_type                TEXT,
    source                  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_literalrefs_fw ON literal_refs(firmware_id);
CREATE INDEX IF NOT EXISTS idx_literalrefs_to ON literal_refs(firmware_id, to_addr);

-- Defined strings (APTraceExportStaticAnalysis.java's "strings").
CREATE TABLE IF NOT EXISTS strings (
    id            INTEGER PRIMARY KEY,
    firmware_id    INTEGER NOT NULL REFERENCES firmware(id),
    addr            INTEGER NOT NULL,
    length          INTEGER NOT NULL,
    data_type       TEXT,
    value           TEXT NOT NULL,
    source          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_strings_fw ON strings(firmware_id);

-- SAMD51 peripherals actually referenced by this firmware image (a
-- filtered view of the SVD map -- only peripherals with at least one
-- mmio_accesses row, so this table answers "which peripherals are
-- actually used" directly, not "which peripherals exist on the chip").
CREATE TABLE IF NOT EXISTS peripherals (
    id                INTEGER PRIMARY KEY,
    firmware_id        INTEGER NOT NULL REFERENCES firmware(id),
    name                TEXT NOT NULL,
    base_addr           INTEGER NOT NULL,
    size                 INTEGER NOT NULL,
    access_count         INTEGER NOT NULL DEFAULT 0,  -- count of mmio_accesses rows resolving to this peripheral
    source                TEXT NOT NULL,
    UNIQUE(firmware_id, name)
);
CREATE INDEX IF NOT EXISTS idx_peripherals_fw ON peripherals(firmware_id);

-- Per-pin mechanical evidence (PORT/PINCFG/PMUX accesses). Deliberately
-- has NO "connector"/"board silkscreen" identity field -- see
-- docs/tooling/census.md's "pin evidence" section: PA08 and a physical
-- connector name are different evidence classes, and only a curated
-- annotation source (not this scanner) may ever join them.
CREATE TABLE IF NOT EXISTS pins (
    id                INTEGER PRIMARY KEY,
    firmware_id        INTEGER NOT NULL REFERENCES firmware(id),
    pin_name             TEXT NOT NULL,   -- e.g. 'PA08'
    group_index           INTEGER NOT NULL, -- 0=PORTA(GROUP0), 1=PORTB(GROUP1), ...
    pin_index              INTEGER NOT NULL, -- 0-31 within the group
    evidence_kind           TEXT NOT NULL,   -- pincfg / pmux / port-bitmask-peephole / port-register-generic
    from_addr                INTEGER NOT NULL,
    from_function_id         INTEGER REFERENCES functions(id),
    mmio_addr                 INTEGER NOT NULL,
    register_name             TEXT,
    confidence                 TEXT NOT NULL,  -- exact (array-index-derived) / heuristic (peephole bitmask scan)
    source                     TEXT NOT NULL,
    UNIQUE(firmware_id, pin_name, evidence_kind, from_addr, mmio_addr)
);
CREATE INDEX IF NOT EXISTS idx_pins_fw ON pins(firmware_id);
CREATE INDEX IF NOT EXISTS idx_pins_name ON pins(firmware_id, pin_name);

-- One row per ingested Unicorn scenario leg (a single ConcreteMachine.run()
-- call captured while replaying tools/unicorn/virtual_link.py's scenario
-- corpus -- see tools/census/dynamic_ingest.py).
CREATE TABLE IF NOT EXISTS dynamic_runs (
    id                     INTEGER PRIMARY KEY,
    firmware_id             INTEGER NOT NULL REFERENCES firmware(id),
    scenario                 TEXT NOT NULL,   -- e.g. 'g_ack_roundtrip'
    leg_label                 TEXT,            -- machine.run(..., label=...) if the scenario set one
    leg_index                  INTEGER NOT NULL, -- 0-based order within the scenario's own capture sequence
    entry                       INTEGER,
    stop_reason                 TEXT,
    error                        TEXT,
    instructions_executed       INTEGER,
    ran_at                       TEXT NOT NULL,   -- ISO-8601 UTC
    source_file                  TEXT NOT NULL    -- coverage-export JSON path this run came from
);
CREATE INDEX IF NOT EXISTS idx_dynruns_fw ON dynamic_runs(firmware_id);
CREATE INDEX IF NOT EXISTS idx_dynruns_scenario ON dynamic_runs(firmware_id, scenario);

-- Every unique PC visited during one dynamic run (ConcreteMachine.run(...,
-- collect_coverage=True)'s visited_pcs), joined against functions/
-- basic_blocks by address at ingest time.
CREATE TABLE IF NOT EXISTS dynamic_coverage (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    pc                    INTEGER NOT NULL,
    function_id            INTEGER REFERENCES functions(id),
    basic_block_id          INTEGER REFERENCES basic_blocks(id)
);
CREATE INDEX IF NOT EXISTS idx_dyncov_run ON dynamic_coverage(dynamic_run_id);
CREATE INDEX IF NOT EXISTS idx_dyncov_pc ON dynamic_coverage(firmware_id, pc);
CREATE INDEX IF NOT EXISTS idx_dyncov_function ON dynamic_coverage(function_id);

-- Every RAM access logged during one dynamic run (ConcreteMachine.run(...,
-- log_ram=True)'s ram_log).
CREATE TABLE IF NOT EXISTS dynamic_memory (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    addr                  INTEGER NOT NULL,
    width                  INTEGER,
    direction              TEXT NOT NULL,  -- read / write
    pc                      INTEGER,
    value                   TEXT   -- hex string, write only (NULL for reads)
);
CREATE INDEX IF NOT EXISTS idx_dynmem_run ON dynamic_memory(dynamic_run_id);
CREATE INDEX IF NOT EXISTS idx_dynmem_addr ON dynamic_memory(firmware_id, addr);

-- Every MMIO access logged during one dynamic run (log_mmio=True's
-- mmio_log), resolved through the SVD the same way mmio_accesses is.
CREATE TABLE IF NOT EXISTS dynamic_mmio (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    addr                  INTEGER NOT NULL,
    width                  INTEGER,
    direction              TEXT NOT NULL,
    pc                      INTEGER,
    value                   TEXT,
    peripheral              TEXT,
    register_name            TEXT
);
CREATE INDEX IF NOT EXISTS idx_dynmmio_run ON dynamic_mmio(dynamic_run_id);
CREATE INDEX IF NOT EXISTS idx_dynmmio_addr ON dynamic_mmio(firmware_id, addr);

-- TX/RX byte captures opportunistically available on a dynamic run (only
-- when the scenario itself requested dump_mem/dump_reg_pointee that
-- happens to be a TX/RX buffer -- recorded as-is, not synthesized).
CREATE TABLE IF NOT EXISTS dynamic_tx_rx (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    direction              TEXT NOT NULL,  -- TX / RX
    data_hex                TEXT NOT NULL,
    note                     TEXT
);
CREATE INDEX IF NOT EXISTS idx_dyntxrx_run ON dynamic_tx_rx(dynamic_run_id);

-- Every disagreement/anomaly the census itself finds -- reported, never
-- hidden. See docs/tooling/census.md's "Exhaustiveness / validation"
-- section for the full list of categories this is populated with.
CREATE TABLE IF NOT EXISTS scan_warnings (
    id            INTEGER PRIMARY KEY,
    firmware_id    INTEGER NOT NULL REFERENCES firmware(id),
    category        TEXT NOT NULL,
    addr             INTEGER,
    detail           TEXT NOT NULL,
    source           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_warnings_fw ON scan_warnings(firmware_id);
CREATE INDEX IF NOT EXISTS idx_warnings_category ON scan_warnings(firmware_id, category);

-- ===========================================================================
-- Closure-reduction layer (tools/census/reduce.py and friends). Built ON
-- TOP of the tables above -- never a parallel evidence model. See
-- docs/tooling/census.md's "Closure reduction" section for the full
-- design writeup: reachability, indirect-edge resolution, library/
-- platform fingerprinting, function feature records, component
-- grouping, and the hardware-init snapshot.
-- ===========================================================================

-- Mechanically-justified reachability roots: the reset vector, every
-- populated system/IRQ vector, and any address that resolved control
-- flow (static or dynamic) actually treats as an indirect-call/jump
-- target -- deliberately NOT every function_pointers candidate (see
-- tools/census/reachability.py's module docstring for why a raw
-- flash-word match is not, by itself, a root).
CREATE TABLE IF NOT EXISTS reachability_roots (
    id             INTEGER PRIMARY KEY,
    firmware_id     INTEGER NOT NULL REFERENCES firmware(id),
    addr             INTEGER NOT NULL,
    function_id       INTEGER REFERENCES functions(id),
    root_kind         TEXT NOT NULL,  -- reset-vector / system-vector / irq-vector / confirmed-indirect-target
    justification      TEXT NOT NULL,
    source              TEXT NOT NULL,
    UNIQUE(firmware_id, addr, root_kind)
);
CREATE INDEX IF NOT EXISTS idx_roots_fw ON reachability_roots(firmware_id);

-- One row per known function: its reachability status from the roots
-- above, over the (edges UNION indirect_edge_candidates) graph.
CREATE TABLE IF NOT EXISTS function_reachability (
    id                     INTEGER PRIMARY KEY,
    firmware_id             INTEGER NOT NULL REFERENCES firmware(id),
    function_id              INTEGER NOT NULL REFERENCES functions(id),
    status                    TEXT NOT NULL,  -- DEFINITELY_REACHABLE / POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT / NO_KNOWN_PATH
    nearest_root_addr          INTEGER,
    nearest_root_kind           TEXT,
    hops                         INTEGER,
    source                        TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_reach_fw ON function_reachability(firmware_id);
CREATE INDEX IF NOT EXISTS idx_reach_status ON function_reachability(firmware_id, status);

-- One row per unique indirect-flow instruction address (whether
-- Ghidra already resolved it or not) -- the unified classification
-- tools/census/indirect_resolve.py computes.
CREATE TABLE IF NOT EXISTS indirect_edge_resolutions (
    id                  INTEGER PRIMARY KEY,
    firmware_id           INTEGER NOT NULL REFERENCES firmware(id),
    from_addr              INTEGER NOT NULL,
    from_function_id        INTEGER REFERENCES functions(id),
    instr_mnemonic            TEXT,
    instr_shape                TEXT,   -- reg-indirect / mem-indirect / table-branch / unknown
    classification              TEXT NOT NULL,  -- STATICALLY_RESOLVED / DYNAMICALLY_OBSERVED / FINITE_CANDIDATE_SET / UNRESOLVED
    note                          TEXT,
    source                         TEXT NOT NULL,
    UNIQUE(firmware_id, from_addr)
);
CREATE INDEX IF NOT EXISTS idx_indedge_fw ON indirect_edge_resolutions(firmware_id);
CREATE INDEX IF NOT EXISTS idx_indedge_class ON indirect_edge_resolutions(firmware_id, classification);

-- Every candidate target found for an indirect-flow instruction, from
-- every method that found one -- never deduplicated away, so a
-- disagreement between methods stays visible (see
-- indirect_edge_resolutions.classification for the single summary
-- label; this table is the full detail behind it).
CREATE TABLE IF NOT EXISTS indirect_edge_candidates (
    id                     INTEGER PRIMARY KEY,
    firmware_id             INTEGER NOT NULL REFERENCES firmware(id),
    from_addr                INTEGER NOT NULL,
    candidate_addr             INTEGER NOT NULL,
    candidate_function_id        INTEGER REFERENCES functions(id),
    confidence                     TEXT NOT NULL,  -- EXACT / STRONG / WEAK
    source                          TEXT NOT NULL   -- ghidra-basicblockmodel / capstone-sweep / dynamic-observed:<scenario> / flash-table-scan
);
CREATE INDEX IF NOT EXISTS idx_indcand_fw ON indirect_edge_candidates(firmware_id);
CREATE INDEX IF NOT EXISTS idx_indcand_from ON indirect_edge_candidates(firmware_id, from_addr);

-- Deterministic per-function fingerprints (tools/census/fingerprint.py)
-- -- used to cross-check the SAME function across the other firmware
-- images already in this database, never against an externally-
-- vendored reference library (none is vendored here).
CREATE TABLE IF NOT EXISTS function_fingerprints (
    id                 INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    function_id           INTEGER NOT NULL REFERENCES functions(id),
    exact_hash              TEXT NOT NULL,  -- sha256 of the function's raw instruction bytes
    normalized_hash          TEXT,          -- sha256 of a (mnemonic, operand-shape) token sequence -- ignores concrete immediates/addresses
    byte_size                  INTEGER NOT NULL,
    block_count                  INTEGER NOT NULL,
    edge_count                     INTEGER NOT NULL,
    callee_count                     INTEGER NOT NULL,
    source                             TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_fp_exact ON function_fingerprints(exact_hash);
CREATE INDEX IF NOT EXISTS idx_fp_norm ON function_fingerprints(normalized_hash);

-- The library/platform-plumbing verdict for one function, always with
-- a `method` naming exactly which deterministic signal produced it.
-- Never set by intuition/naming -- see docs/tooling/census.md.
CREATE TABLE IF NOT EXISTS library_matches (
    id                    INTEGER PRIMARY KEY,
    firmware_id             INTEGER NOT NULL REFERENCES firmware(id),
    function_id              INTEGER NOT NULL REFERENCES functions(id),
    confidence                 TEXT NOT NULL,  -- EXACT / STRONG_MATCH / POSSIBLE_MATCH / NO_MATCH -- cross-image evidence ONLY, never "library truth" by itself
    method                       TEXT NOT NULL,  -- exact-byte-hash[-same-product] / ghidra-thunk / normalized-instruction-hash[-same-product] / structural-similarity[-same-product]
    matched_firmware_key           TEXT,
    matched_function_id              INTEGER REFERENCES functions(id),
    matched_function_name              TEXT,
    -- A cross-image fingerprint match (however strong) proves "shared
    -- code between OUR OWN products", not "confirmed external library".
    -- reference_source_confirmed=1 is a stronger, separate, curated fact:
    -- this function was structurally matched against REAL, FETCHED
    -- upstream source (see tools/census/reference_library.py and
    -- docs/investigations/boot-and-hardware-bringup.md's CONFIRMED
    -- tier) -- the only thing this reducer treats as actual "library
    -- truth" for residual-exclusion purposes.
    reference_source_confirmed          INTEGER NOT NULL DEFAULT 0,
    reference_source_citation             TEXT,
    source                                  TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_libmatch_fw ON library_matches(firmware_id);
CREATE INDEX IF NOT EXISTS idx_libmatch_conf ON library_matches(firmware_id, confidence);

-- One materialized, purely-structural feature row per function --
-- counts and small evidence lists only, NEVER a semantic field (no
-- "meaning"/"purpose" column -- see docs/tooling/census.md). The
-- underlying detail (which peripheral, which caller, ...) remains
-- queryable from the tables it was aggregated from; this table exists
-- for cheap, single-row-per-function lookups.
CREATE TABLE IF NOT EXISTS function_features (
    id                      INTEGER PRIMARY KEY,
    firmware_id               INTEGER NOT NULL REFERENCES firmware(id),
    function_id                INTEGER NOT NULL REFERENCES functions(id),
    n_callers                    INTEGER NOT NULL,
    n_callees                      INTEGER NOT NULL,
    n_basic_blocks                   INTEGER NOT NULL,
    n_ram_reads                        INTEGER NOT NULL,
    n_ram_writes                         INTEGER NOT NULL,
    n_mmio_reads                           INTEGER NOT NULL,
    n_mmio_writes                            INTEGER NOT NULL,
    n_literal_refs                             INTEGER NOT NULL,
    n_strings                                    INTEGER NOT NULL,
    n_pins                                         INTEGER NOT NULL,
    n_indirect_edges_from                            INTEGER NOT NULL,
    is_irq_handler                                     INTEGER NOT NULL DEFAULT 0,
    irq_vector_index                                     INTEGER,
    n_dynamic_runs                                         INTEGER NOT NULL,
    n_dynamic_scenarios                                      INTEGER NOT NULL,
    peripherals_json                                           TEXT,
    pins_json                                                    TEXT,
    scenarios_json                                                 TEXT,
    reachability_status                                              TEXT,
    library_confidence                                                 TEXT,
    source                                                               TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_features_fw ON function_features(firmware_id);

-- Deterministic component grouping (tools/census/components.py) --
-- connected components of a relatedness graph over reachable
-- functions (call edges to low-fan-in callees, SCC membership, shared
-- MMIO peripheral/RAM address/pin, dynamic co-execution). Stable
-- small-integer IDs per firmware (see components.py for the exact
-- tie-break rule); never a semantic name.
CREATE TABLE IF NOT EXISTS components (
    id                 INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    component_index        INTEGER NOT NULL,
    n_functions               INTEGER NOT NULL,
    peripherals_json           TEXT,
    pins_json                    TEXT,
    ram_addrs_json                 TEXT,
    scenarios_json                   TEXT,
    strings_json                       TEXT,  -- distinct string values referenced by any member (rule 8 below)
    source                             TEXT NOT NULL,
    UNIQUE(firmware_id, component_index)
);
CREATE INDEX IF NOT EXISTS idx_components_fw ON components(firmware_id);

CREATE TABLE IF NOT EXISTS component_members (
    id             INTEGER PRIMARY KEY,
    firmware_id      INTEGER NOT NULL REFERENCES firmware(id),
    component_id       INTEGER NOT NULL REFERENCES components(id),
    function_id           INTEGER NOT NULL REFERENCES functions(id),
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_compmembers_fw ON component_members(firmware_id);
CREATE INDEX IF NOT EXISTS idx_compmembers_component ON component_members(component_id);

-- Hardware-init snapshot (tools/census/hardware_snapshot.py). One
-- `hardware_snapshot_runs` row records HOW the snapshot was taken
-- (`boot_method`: 'established-recipe' reuses a previously-published,
-- human-confirmed boot-to-steady-state recipe verbatim;
-- 'cold-run-bounded' is a from-Reset_Handler run with NO disclosed
-- hardware assumptions, bounded by an instruction cap, for a firmware
-- image with no established recipe -- `completed_init=0` in that case
-- is not a failure, it is the honest, expected result and must not be
-- hidden) -- see docs/tooling/census.md's "Hardware-init snapshot"
-- section.
CREATE TABLE IF NOT EXISTS hardware_snapshot_runs (
    id                  INTEGER PRIMARY KEY,
    firmware_id           INTEGER NOT NULL REFERENCES firmware(id),
    boot_method             TEXT NOT NULL,
    -- Three-way status, distinct from the boolean completed_init below:
    --   complete           -- reached the recipe's own defined steady-state criterion
    --   partial-justified  -- reached at least one real named milestone via
    --                         cited, provenance-tagged assumptions, then
    --                         stalled at a documented, evidence-backed point
    --   blocked            -- stalled with no citable evidence to justify
    --                         a model for the blocking condition
    init_status              TEXT,
    stop_addr                 INTEGER,
    instructions_executed       INTEGER,
    stop_reason                   TEXT,
    completed_init                  INTEGER NOT NULL,  -- 0/1 -- see note above
    notes                             TEXT,
    -- JSON list of every environmental/model assumption applied to reach
    -- this run's stop point: [{kind, addr, detail, citation}, ...] --
    -- see tools/census/boot_recipes.py. Never hidden -- this is the
    -- complete, auditable list of what was disclosed to get this far.
    assumptions_json                   TEXT,
    ran_at                                TEXT NOT NULL,
    UNIQUE(firmware_id)
);

CREATE TABLE IF NOT EXISTS hardware_snapshot (
    id             INTEGER PRIMARY KEY,
    firmware_id      INTEGER NOT NULL REFERENCES firmware(id),
    addr               INTEGER NOT NULL,
    peripheral            TEXT,
    register_name           TEXT,
    width                      INTEGER NOT NULL,
    raw_value                    TEXT NOT NULL,  -- hex string, exactly `width` bytes, little-endian as read
    source                          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hwsnap_fw ON hardware_snapshot(firmware_id);
CREATE INDEX IF NOT EXISTS idx_hwsnap_peripheral ON hardware_snapshot(firmware_id, peripheral);

-- PORT state decoded per-pin from hardware_snapshot's raw PORT bytes --
-- MCU pin/mux/register state ONLY (direction, output/input level,
-- PINCFG raw byte, PMUX enable bit + raw nibble). Deliberately carries
-- NO physical-connector identity column -- see
-- docs/tooling/census.md's "Pin/peripheral evidence" section; a
-- curated annotation source, not this table, is the only legitimate
-- place to join a pin to a connector name.
CREATE TABLE IF NOT EXISTS pin_snapshot (
    id             INTEGER PRIMARY KEY,
    firmware_id      INTEGER NOT NULL REFERENCES firmware(id),
    pin_name           TEXT NOT NULL,
    group_index           INTEGER NOT NULL,
    pin_index               INTEGER NOT NULL,
    direction                  TEXT,     -- 'IN' / 'OUT' / NULL if not determinable
    output_value                  INTEGER,  -- 0/1/NULL
    input_value                      INTEGER,  -- 0/1/NULL
    pincfg_raw                          INTEGER,
    pmuxen                                 INTEGER,  -- 0/1/NULL -- PINCFG.PMUXEN bit
    pmux_nibble                               INTEGER,  -- 0-15/NULL -- raw PMUX field value (see census.md for what this does/doesn't mean)
    source                                       TEXT NOT NULL,
    UNIQUE(firmware_id, pin_name)
);
CREATE INDEX IF NOT EXISTS idx_pinsnap_fw ON pin_snapshot(firmware_id);

-- ===========================================================================
-- Residual-prioritization / hardware-contract layer (tools/census/
-- residual_priority.py, hardware_contract.py, firmware_diff.py). Built ON
-- TOP of everything above -- purely a deterministic re-aggregation of
-- already-collected evidence, never a new evidence-collection pass. See
-- docs/tooling/census.md's "Residual prioritization" and "Hardware
-- contract" sections.
-- ===========================================================================

-- One row per RESIDUAL function (see residual_priority.residual_function_ids
-- -- same definition `aptrace_census.py residual` reports): a deterministic
-- priority score plus the FULL list of individual signals that produced it
-- (reasons_json: [{signal, points, description, evidence}, ...]) -- never
-- collapsed to just the number. Purely a re-weighting of evidence already
-- in function_features/edges/mmio_accesses/etc; no new fact is collected
-- here. See residual_priority.py's module docstring for the fixed signal
-- table.
CREATE TABLE IF NOT EXISTS residual_priority (
    id                INTEGER PRIMARY KEY,
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    function_id           INTEGER NOT NULL REFERENCES functions(id),
    score                    INTEGER NOT NULL,
    tier                       TEXT NOT NULL,  -- HIGH / MEDIUM / LOW -- see residual_priority.tier_for
    reasons_json                 TEXT NOT NULL,
    source                          TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_respri_fw ON residual_priority(firmware_id);
CREATE INDEX IF NOT EXISTS idx_respri_tier ON residual_priority(firmware_id, tier);

-- One deterministic, machine-readable hardware-contract JSON document per
-- firmware image (tools/census/hardware_contract.py), regenerated every
-- `census reduce` from the SAME hardware_snapshot/mmio_accesses/vectors/
-- pins/components evidence already persisted above -- never a second
-- Unicorn run, never a new fact. Kept as one row so `census diff` can
-- compare two firmware images' contracts directly without re-deriving
-- them, and so the contract is inspectable/exportable without
-- recomputation. See hardware_contract.py's module docstring for the
-- exact JSON shape (every field ships its raw register value alongside
-- any decoded field, and is explicitly null/omitted rather than guessed
-- when evidence is missing).
CREATE TABLE IF NOT EXISTS hardware_contract_runs (
    id                INTEGER PRIMARY KEY,
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    contract_json         TEXT NOT NULL,
    generated_at            TEXT NOT NULL,
    UNIQUE(firmware_id)
);

-- ===========================================================================
-- Reference-source fingerprinting layer (tools/census/reference_corpus.py
-- + reference_match.py). Independent of any one firmware image -- these
-- five tables hold the mechanically-fetched-and-built reference corpus
-- (packages/build-variants/symbols) and, per firmware, the match result
-- against it. See docs/tooling/census.md's "Reference-source
-- fingerprinting" section for the full design writeup.
-- ===========================================================================

-- One row per fetched corpus package (the core itself, the pinned
-- toolchain, CMSIS, CMSIS-Atmel) -- always with a citable reason it
-- belongs in the corpus (`relevance`) and exactly how it was
-- mechanically discovered (`discovered_via`) -- see
-- reference_corpus.py's module docstring. Never a "looks useful"
-- addition.
CREATE TABLE IF NOT EXISTS reference_packages (
    id                INTEGER PRIMARY KEY,
    pkg_key             TEXT UNIQUE NOT NULL,
    name                  TEXT NOT NULL,
    version                 TEXT NOT NULL,
    kind                      TEXT NOT NULL,  -- git / archive
    repo_url                    TEXT,
    ref                           TEXT,          -- requested tag/branch (git only)
    resolved_commit                 TEXT,          -- resolved commit hash (git only)
    archive_url                       TEXT,
    archive_sha256                      TEXT,
    license                               TEXT NOT NULL,
    relevance                              TEXT NOT NULL,
    discovered_via                           TEXT NOT NULL,
    fetched_at                                 TEXT NOT NULL
);

-- One row per compiled reference build configuration -- the EXACT
-- toolchain/board/flags applied (see reference_corpus.py's module
-- docstring for the evidence behind each). `confidence_note` discloses
-- any setting that is a board DEFAULT rather than independently
-- confirmed from the firmware (never silently treated as fact).
CREATE TABLE IF NOT EXISTS reference_build_variants (
    id                INTEGER PRIMARY KEY,
    variant_key         TEXT UNIQUE NOT NULL,
    board                 TEXT,
    mcu                     TEXT NOT NULL,
    toolchain_name            TEXT NOT NULL,
    toolchain_version           TEXT NOT NULL,
    optimize                      TEXT NOT NULL,
    f_cpu                           TEXT,
    cflags                            TEXT NOT NULL,
    cxxflags                            TEXT NOT NULL,
    confidence_note                       TEXT,
    built_at                                TEXT NOT NULL
);

-- One row per source file this build variant attempted to compile --
-- 'ok' or 'failed' with the real compiler error, never silently
-- dropped. See `aptrace_census.py reference-corpus build`'s own
-- summary output.
CREATE TABLE IF NOT EXISTS reference_build_files (
    id                INTEGER PRIMARY KEY,
    build_variant_id    INTEGER NOT NULL REFERENCES reference_build_variants(id),
    package_id            INTEGER NOT NULL REFERENCES reference_packages(id),
    source_file             TEXT NOT NULL,
    status                     TEXT NOT NULL,  -- ok / failed
    error                        TEXT,
    UNIQUE(build_variant_id, source_file)
);

-- One row per compiled reference function/symbol -- the actual corpus
-- `reference_match.py` compares firmware functions against. Four
-- fingerprints, most to least strict (see reference_normalize.py's
-- module docstring for exactly what each masks):
-- exact_hash (raw code bytes, literal pool excluded) / exact_instr_hash
-- (verbatim decoded-instruction sequence) / reloc_norm_hash (relocation-
-- derived operands masked, using this symbol's OWN real ELF relocation
-- records -- ground truth, not a heuristic) / pcrel_norm_hash
-- (reloc_norm_hash plus PC-relative-load offsets masked).
CREATE TABLE IF NOT EXISTS reference_symbols (
    id                INTEGER PRIMARY KEY,
    build_variant_id    INTEGER NOT NULL REFERENCES reference_build_variants(id),
    package_id            INTEGER NOT NULL REFERENCES reference_packages(id),
    source_file             TEXT NOT NULL,
    symbol                     TEXT NOT NULL,
    byte_size                    INTEGER NOT NULL,
    exact_hash                     TEXT NOT NULL,
    exact_instr_hash                 TEXT NOT NULL,
    reloc_norm_hash                    TEXT NOT NULL,
    pcrel_norm_hash                      TEXT NOT NULL,
    n_instructions                         INTEGER NOT NULL,
    n_branches                               INTEGER NOT NULL,
    raw_bytes_hex                              TEXT NOT NULL,
    UNIQUE(build_variant_id, source_file, symbol)
);
CREATE INDEX IF NOT EXISTS idx_refsym_exact ON reference_symbols(exact_hash);
CREATE INDEX IF NOT EXISTS idx_refsym_exact_instr ON reference_symbols(exact_instr_hash);
CREATE INDEX IF NOT EXISTS idx_refsym_reloc ON reference_symbols(reloc_norm_hash);
CREATE INDEX IF NOT EXISTS idx_refsym_pcrel ON reference_symbols(pcrel_norm_hash);

-- Every candidate reference symbol found for a firmware function, at
-- EVERY tier that matched (never deduplicated away -- an ambiguous
-- match, e.g. two distinct reference symbols both EXACT_BYTES-matching
-- the same tiny firmware function, stays fully visible here rather
-- than one being silently chosen -- see reference_matches.is_ambiguous).
CREATE TABLE IF NOT EXISTS reference_match_candidates (
    id                INTEGER PRIMARY KEY,
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    function_id           INTEGER NOT NULL REFERENCES functions(id),
    reference_symbol_id     INTEGER NOT NULL REFERENCES reference_symbols(id),
    tier                       TEXT NOT NULL,  -- EXACT_BYTES/EXACT_INSTRUCTIONS/RELOCATION_NORMALIZED/PC_RELATIVE_NORMALIZED/STRONG_STRUCTURAL
    detail                       TEXT,
    source                         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refmatchcand_fw ON reference_match_candidates(firmware_id);
CREATE INDEX IF NOT EXISTS idx_refmatchcand_func ON reference_match_candidates(firmware_id, function_id);

-- One row per firmware function: its SINGLE best-tier summary
-- classification. `reference_source_confirmed=1` ONLY for a
-- non-ambiguous match at EXACT_BYTES/EXACT_INSTRUCTIONS/
-- RELOCATION_NORMALIZED/PC_RELATIVE_NORMALIZED -- STRONG_STRUCTURAL and
-- NO_MATCH NEVER set it (see docs/tooling/census.md's evidence rule).
-- An ambiguous best-tier match (>1 distinct reference symbol at the
-- SAME best tier) sets is_ambiguous=1, reference_symbol_id=NULL,
-- reference_source_confirmed=0 -- reported, never silently resolved by
-- picking one.
CREATE TABLE IF NOT EXISTS reference_matches (
    id                INTEGER PRIMARY KEY,
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    function_id           INTEGER NOT NULL REFERENCES functions(id),
    tier                     TEXT NOT NULL,
    is_ambiguous               INTEGER NOT NULL DEFAULT 0,
    reference_symbol_id          INTEGER REFERENCES reference_symbols(id),
    reference_source_confirmed     INTEGER NOT NULL DEFAULT 0,
    detail                           TEXT,
    source                             TEXT NOT NULL,
    UNIQUE(firmware_id, function_id)
);
CREATE INDEX IF NOT EXISTS idx_refmatch_fw ON reference_matches(firmware_id);
CREATE INDEX IF NOT EXISTS idx_refmatch_tier ON reference_matches(firmware_id, tier);

-- ===========================================================================
-- Generic indexed state/event array mapper (tools/census/state_map.py).
-- One run = one (firmware, base, count, width) array description (e.g.
-- AutoPilot's pending[] event-scheduling array, base=0x200025bc,
-- count=18, width=1) -- reusable for ANY other indexed state array in
-- ANY firmware, not specific to any one protocol/array. Every fact
-- underneath is pulled mechanically from the evidence tables ABOVE
-- (memory_accesses, function_reachability, dynamic_memory,
-- indirect_edge_resolutions) -- this layer never collects a new static
-- fact of its own; it only re-slices existing evidence per array slot.
-- No semantic interpretation ("is this real/dormant/motor-related") is
-- stored here -- see docs/tooling/census.md's evidence rule.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS state_map_runs (
    id                INTEGER PRIMARY KEY,
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    base                  INTEGER NOT NULL,
    count                   INTEGER NOT NULL,
    width                    INTEGER NOT NULL,
    label                      TEXT,
    dispatcher_entry            INTEGER,  -- NULL if no dispatcher probe was requested
    ran_at                        TEXT NOT NULL,
    source                          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_statemap_runs_fw ON state_map_runs(firmware_id);

-- One row per slot (0..count-1) of one state_map_runs run. JSON columns
-- hold the full, un-collapsed list of matching evidence rows (never just
-- a count) so a later reader can see exactly which instructions/
-- functions/scenarios produced each verdict.
CREATE TABLE IF NOT EXISTS state_map_slots (
    id                       INTEGER PRIMARY KEY,
    run_id                     INTEGER NOT NULL REFERENCES state_map_runs(id),
    firmware_id                  INTEGER NOT NULL REFERENCES firmware(id),
    slot_index                     INTEGER NOT NULL,
    addr                              INTEGER NOT NULL,
    static_writers_json                 TEXT NOT NULL,  -- [{from_addr, from_function, reachability}, ...]
    static_readers_json                   TEXT NOT NULL,  -- [{from_addr, from_function, reachability}, ...]
    dynamic_writers_json                    TEXT NOT NULL,  -- [{scenario, leg_label, pc, value_hex}, ...]
    dynamic_readers_json                      TEXT NOT NULL,  -- [{scenario, leg_label, pc}, ...]
    unresolved_indirect_json                    TEXT NOT NULL,  -- [{from_addr, from_function}, ...] -- UNRESOLVED
                                                                    -- indirect edges inside a writer/reader's
                                                                    -- OWN function (disclosed caveat, not a
                                                                    -- claim that edge produces this write)
    has_static_writer                             INTEGER NOT NULL,  -- 0/1
    has_dynamic_writer                              INTEGER NOT NULL,  -- 0/1
    unresolved_producer                               INTEGER NOT NULL,  -- 0/1: NO_KNOWN_WRITER (no static,
                                                                             -- dynamic, indexed, or interprocedural
                                                                             -- writer found at all)
    indexed_writers_json                                TEXT,  -- [{from_addr, classification, ...}, ...] --
                                                                   -- state_map_indexed_writers rows touching
                                                                   -- this slot (see that table); NULL if no
                                                                   -- computed-write scan was run for this array
    interproc_writers_json                                TEXT,  -- [{callsite_from_addr, classification, ...},
                                                                     -- ...] -- state_map_interproc_writers rows
                                                                     -- touching this slot; NULL if no
                                                                     -- interprocedural scan was run
    writer_status                                         TEXT,  -- DIRECT_WRITER / INDEXED_WRITER_EXACT_SLOT /
                                                                     -- INTERPROC_EXACT_WRITER /
                                                                     -- INDEXED_WRITER_FINITE_SLOT_SET /
                                                                     -- INTERPROC_FINITE_WRITER_SET /
                                                                     -- INDEXED_WRITER_RANGE /
                                                                     -- INTERPROC_RANGE_WRITER /
                                                                     -- UNKNOWN_COMPUTED_WRITE /
                                                                     -- UNKNOWN_ALIASED_WRITE / NO_KNOWN_WRITER --
                                                                     -- the single strongest classification found
                                                                     -- for this slot, in that precedence order;
                                                                     -- NULL if no computed-write/interprocedural
                                                                     -- scan was run (has_static_writer/
                                                                     -- has_dynamic_writer/unresolved_producer
                                                                     -- above remain valid either way)
    source                                              TEXT NOT NULL,
    UNIQUE(run_id, slot_index)
);
CREATE INDEX IF NOT EXISTS idx_statemap_slots_run ON state_map_slots(run_id);
CREATE INDEX IF NOT EXISTS idx_statemap_slots_unresolved ON state_map_slots(run_id, unresolved_producer);

-- One row per candidate register-indexed ("computed") store instruction
-- found by tools/census/indexed_writes.py's whole-image scan, whose
-- resolved base address falls inside the mapped array -- see that
-- module's docstring for the exact, bounded classification method.
-- Every candidate a scan finds is kept (never deduplicated away), one
-- row per (run, from_addr) -- multiple instructions can legitimately
-- write into the same array.
CREATE TABLE IF NOT EXISTS state_map_indexed_writers (
    id                       INTEGER PRIMARY KEY,
    run_id                     INTEGER NOT NULL REFERENCES state_map_runs(id),
    firmware_id                  INTEGER NOT NULL REFERENCES firmware(id),
    from_addr                      INTEGER NOT NULL,
    from_function_id                 INTEGER REFERENCES functions(id),
    mnemonic                           TEXT NOT NULL,
    access_width                         INTEGER NOT NULL,
    base_reg                               TEXT,
    index_reg                                TEXT,
    scale                                      INTEGER,
    disp                                         INTEGER,
    resolved_base_addr                             INTEGER NOT NULL,
    classification                                   TEXT NOT NULL,  -- INDEXED_WRITER_EXACT_SLOT /
                                                                         -- INDEXED_WRITER_FINITE_SLOT_SET /
                                                                         -- INDEXED_WRITER_RANGE /
                                                                         -- UNKNOWN_COMPUTED_WRITE
    slots_json                                         TEXT NOT NULL,  -- concrete affected slot indices;
                                                                          -- [] for UNKNOWN_COMPUTED_WRITE
    applies_to_all_slots                                 INTEGER NOT NULL DEFAULT 0,  -- 1 for
                                                                                        -- UNKNOWN_COMPUTED_WRITE:
                                                                                        -- bound not determined,
                                                                                        -- so every slot in the
                                                                                        -- array is a possible
                                                                                        -- target, disclosed
                                                                                        -- rather than guessed
    derivation_json                                        TEXT NOT NULL,  -- the full mechanical trace: every
                                                                               -- instruction consulted to resolve
                                                                               -- base/index, and why the bound
                                                                               -- search stopped where it did
    source                                                    TEXT NOT NULL,
    UNIQUE(run_id, from_addr)
);
CREATE INDEX IF NOT EXISTS idx_statemap_indexed_run ON state_map_indexed_writers(run_id);
CREATE INDEX IF NOT EXISTS idx_statemap_indexed_class ON state_map_indexed_writers(run_id, classification);

-- One row per (callsite, callee-effect) pair found by tools/census/
-- interproc_writes.py's minimal, bounded ONE-call-edge-hop scan -- a
-- write that happens through a pointer PASSED AS AN ARGUMENT into
-- another function, invisible to both memory_accesses (the destination
-- is a register, not a literal, at the write site) and
-- state_map_indexed_writers (the write is in a DIFFERENT function than
-- the one holding the array's address). The scan only ever produces
-- INTERPROC_EXACT_WRITER (a concrete argument value, or argument+
-- constant, that lands inside the array) -- an unresolved argument is
-- dropped, never recorded as a guess. See that module's docstring.
CREATE TABLE IF NOT EXISTS state_map_interproc_writers (
    id                       INTEGER PRIMARY KEY,
    run_id                     INTEGER NOT NULL REFERENCES state_map_runs(id),
    firmware_id                  INTEGER NOT NULL REFERENCES firmware(id),
    callsite_from_addr             INTEGER NOT NULL,  -- the real `bl`/`blx` instruction address
    caller_function_id               INTEGER REFERENCES functions(id),
    callee_function_id                 INTEGER REFERENCES functions(id),
    effect_from_addr                     INTEGER NOT NULL,  -- the store address INSIDE the callee
    classification                         TEXT NOT NULL,  -- always INTERPROC_EXACT_WRITER
    slots_json                               TEXT NOT NULL,  -- concrete affected slot index, as a 1-element list
    applies_to_all_slots                       INTEGER NOT NULL DEFAULT 0,  -- always 0 in this minimal pass
    derivation_json                              TEXT NOT NULL,  -- {effect:{...}, argument_resolution:{...},
                                                                     -- resolved_pointer, touched_addr} -- never
                                                                     -- just the final label
    source                                         TEXT NOT NULL,
    UNIQUE(run_id, callsite_from_addr, effect_from_addr)
);
CREATE INDEX IF NOT EXISTS idx_statemap_interproc_run ON state_map_interproc_writers(run_id);

-- One row per slot's OPTIONAL generic dispatcher probe (only populated
-- when state_map_runs.dispatcher_entry is set) -- a single reusable
-- probe (tools/census/state_map.py:probe_dispatcher) iterates every
-- slot mechanically (mark slot N active, run the real dispatcher
-- function, see what real code path it takes), never a per-slot
-- hand-authored test and never a seeded semantic source value.
CREATE TABLE IF NOT EXISTS state_map_dispatcher_probes (
    id                       INTEGER PRIMARY KEY,
    run_id                     INTEGER NOT NULL REFERENCES state_map_runs(id),
    firmware_id                  INTEGER NOT NULL REFERENCES firmware(id),
    slot_index                     INTEGER NOT NULL,
    outcome                           TEXT NOT NULL,  -- string_tx / byte_tx / clean_return / other / error
    stop_reason                         TEXT,
    tx_wrapper_addr                       INTEGER,
    output_hex                              TEXT,     -- raw bytes captured at the TX-wrapper stop, if reached
    output_depends_on_unresolved_source       INTEGER NOT NULL DEFAULT 0,  -- 1 if output_hex is all-zero/empty
                                                                              -- while reaching a real TX call --
                                                                              -- i.e. the dispatcher DID take a
                                                                              -- real output path, but this probe
                                                                              -- supplied no source value for it
    instructions_executed                       INTEGER,
    source                                        TEXT NOT NULL,
    UNIQUE(run_id, slot_index)
);
CREATE INDEX IF NOT EXISTS idx_statemap_probes_run ON state_map_dispatcher_probes(run_id);
