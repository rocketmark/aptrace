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
CREATE TABLE firmware (
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
CREATE TABLE functions (
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
CREATE INDEX idx_functions_fw ON functions(firmware_id);

-- Ghidra's own basic-block model (APTraceExportCensus.java).
CREATE TABLE basic_blocks (
    id            INTEGER PRIMARY KEY,
    firmware_id   INTEGER NOT NULL REFERENCES firmware(id),
    start_addr    INTEGER NOT NULL,
    end_addr      INTEGER NOT NULL,  -- inclusive last byte address of the block
    function_id   INTEGER REFERENCES functions(id),  -- NULL: block not attributed to any known function
    source        TEXT NOT NULL,
    UNIQUE(firmware_id, start_addr)
);
CREATE INDEX idx_blocks_fw ON basic_blocks(firmware_id);
CREATE INDEX idx_blocks_function ON basic_blocks(function_id);
CREATE INDEX idx_blocks_range ON basic_blocks(firmware_id, start_addr, end_addr);

-- Direct control-flow/call edges, resolved and unresolved alike (an
-- unresolved indirect edge has to_addr NULL, resolved=0) --
-- APTraceExportCensus.java (Ghidra basic-block model + a per-instruction
-- scan for computed flow with no resolved reference) and
-- tools/census/capstone_sweep.py (an independent cross-check).
CREATE TABLE edges (
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
CREATE INDEX idx_edges_fw ON edges(firmware_id);
CREATE INDEX idx_edges_from ON edges(firmware_id, from_addr);
CREATE INDEX idx_edges_to ON edges(firmware_id, to_addr);
CREATE INDEX idx_edges_resolved ON edges(firmware_id, resolved);

-- The ARMv7-M vector table: 16 system exception slots + N IRQ slots,
-- read directly from the firmware's own flash bytes (tools/census/raw_scan.py)
-- -- independent of Ghidra's own seeding (which consumes the same table
-- but only to plant function starts, not to keep a queryable record).
CREATE TABLE vectors (
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
CREATE INDEX idx_vectors_fw ON vectors(firmware_id);

-- Candidate function pointers: 4-byte-aligned flash words, outside any
-- known function body, whose value (Thumb bit stripped) equals a known
-- function's entry point. A *candidate*, not an assertion -- flagged
-- explicitly as evidence, not as "this is a real function-pointer
-- table/callback slot" (tools/census/raw_scan.py).
CREATE TABLE function_pointers (
    id                       INTEGER PRIMARY KEY,
    firmware_id               INTEGER NOT NULL REFERENCES firmware(id),
    location_addr              INTEGER NOT NULL,  -- flash address the candidate word was found at
    raw_value                   INTEGER NOT NULL,
    target_addr                 INTEGER NOT NULL,  -- raw_value with the Thumb bit stripped
    matches_known_function     INTEGER NOT NULL,  -- 0/1: does target_addr equal a functions.entry?
    source                       TEXT NOT NULL,
    UNIQUE(firmware_id, location_addr)
);
CREATE INDEX idx_funcptrs_fw ON function_pointers(firmware_id);
CREATE INDEX idx_funcptrs_target ON function_pointers(firmware_id, target_addr);

-- RAM reads/writes with a statically-resolved target address (Ghidra's
-- own reference manager, from the same instruction pass as `edges`'
-- unresolved-indirect scan -- APTraceExportCensus.java).
CREATE TABLE memory_accesses (
    id                  INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    from_addr             INTEGER NOT NULL,
    from_function_id      INTEGER REFERENCES functions(id),
    to_addr               INTEGER NOT NULL,
    width                  INTEGER,   -- bytes; NULL if not a single-fixed-width load/store (e.g. LDM/STM/PUSH/POP)
    direction              TEXT NOT NULL,  -- READ / WRITE / DATA
    source                 TEXT NOT NULL
);
CREATE INDEX idx_memacc_fw ON memory_accesses(firmware_id);
CREATE INDEX idx_memacc_to ON memory_accesses(firmware_id, to_addr);
CREATE INDEX idx_memacc_from ON memory_accesses(firmware_id, from_addr);

-- MMIO reads/writes with a statically-resolved target address, same
-- source pass as memory_accesses but landing in the MMIO window instead
-- of RAM. `peripheral`/`register_name` are filled in by resolving
-- `to_addr` through tools/svd/resolve_mmio.py's Samd51Map -- NULL means
-- the SVD has no peripheral covering that address (a real finding, kept
-- visible rather than hidden -- see scan_warnings).
CREATE TABLE mmio_accesses (
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
CREATE INDEX idx_mmioacc_fw ON mmio_accesses(firmware_id);
CREATE INDEX idx_mmioacc_to ON mmio_accesses(firmware_id, to_addr);
CREATE INDEX idx_mmioacc_peripheral ON mmio_accesses(firmware_id, peripheral);

-- Flash/literal/data references from code -- reused directly from
-- APTraceExportStaticAnalysis.java's existing "dataReferences" export
-- (memory_accesses/mmio_accesses above cover RAM/MMIO; this table is
-- what's left: flash constants, literal pools, string addresses, etc).
CREATE TABLE literal_refs (
    id                  INTEGER PRIMARY KEY,
    firmware_id          INTEGER NOT NULL REFERENCES firmware(id),
    from_addr             INTEGER NOT NULL,
    from_function_id      INTEGER REFERENCES functions(id),
    to_addr               INTEGER NOT NULL,
    to_label               TEXT,
    ref_type                TEXT,
    source                  TEXT NOT NULL
);
CREATE INDEX idx_literalrefs_fw ON literal_refs(firmware_id);
CREATE INDEX idx_literalrefs_to ON literal_refs(firmware_id, to_addr);

-- Defined strings (APTraceExportStaticAnalysis.java's "strings").
CREATE TABLE strings (
    id            INTEGER PRIMARY KEY,
    firmware_id    INTEGER NOT NULL REFERENCES firmware(id),
    addr            INTEGER NOT NULL,
    length          INTEGER NOT NULL,
    data_type       TEXT,
    value           TEXT NOT NULL,
    source          TEXT NOT NULL
);
CREATE INDEX idx_strings_fw ON strings(firmware_id);

-- SAMD51 peripherals actually referenced by this firmware image (a
-- filtered view of the SVD map -- only peripherals with at least one
-- mmio_accesses row, so this table answers "which peripherals are
-- actually used" directly, not "which peripherals exist on the chip").
CREATE TABLE peripherals (
    id                INTEGER PRIMARY KEY,
    firmware_id        INTEGER NOT NULL REFERENCES firmware(id),
    name                TEXT NOT NULL,
    base_addr           INTEGER NOT NULL,
    size                 INTEGER NOT NULL,
    access_count         INTEGER NOT NULL DEFAULT 0,  -- count of mmio_accesses rows resolving to this peripheral
    source                TEXT NOT NULL,
    UNIQUE(firmware_id, name)
);
CREATE INDEX idx_peripherals_fw ON peripherals(firmware_id);

-- Per-pin mechanical evidence (PORT/PINCFG/PMUX accesses). Deliberately
-- has NO "connector"/"board silkscreen" identity field -- see
-- docs/tooling/census.md's "pin evidence" section: PA08 and a physical
-- connector name are different evidence classes, and only a curated
-- annotation source (not this scanner) may ever join them.
CREATE TABLE pins (
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
CREATE INDEX idx_pins_fw ON pins(firmware_id);
CREATE INDEX idx_pins_name ON pins(firmware_id, pin_name);

-- One row per ingested Unicorn scenario leg (a single ConcreteMachine.run()
-- call captured while replaying tools/unicorn/virtual_link.py's scenario
-- corpus -- see tools/census/dynamic_ingest.py).
CREATE TABLE dynamic_runs (
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
CREATE INDEX idx_dynruns_fw ON dynamic_runs(firmware_id);
CREATE INDEX idx_dynruns_scenario ON dynamic_runs(firmware_id, scenario);

-- Every unique PC visited during one dynamic run (ConcreteMachine.run(...,
-- collect_coverage=True)'s visited_pcs), joined against functions/
-- basic_blocks by address at ingest time.
CREATE TABLE dynamic_coverage (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    pc                    INTEGER NOT NULL,
    function_id            INTEGER REFERENCES functions(id),
    basic_block_id          INTEGER REFERENCES basic_blocks(id)
);
CREATE INDEX idx_dyncov_run ON dynamic_coverage(dynamic_run_id);
CREATE INDEX idx_dyncov_pc ON dynamic_coverage(firmware_id, pc);
CREATE INDEX idx_dyncov_function ON dynamic_coverage(function_id);

-- Every RAM access logged during one dynamic run (ConcreteMachine.run(...,
-- log_ram=True)'s ram_log).
CREATE TABLE dynamic_memory (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    addr                  INTEGER NOT NULL,
    width                  INTEGER,
    direction              TEXT NOT NULL,  -- read / write
    pc                      INTEGER,
    value                   TEXT   -- hex string, write only (NULL for reads)
);
CREATE INDEX idx_dynmem_run ON dynamic_memory(dynamic_run_id);
CREATE INDEX idx_dynmem_addr ON dynamic_memory(firmware_id, addr);

-- Every MMIO access logged during one dynamic run (log_mmio=True's
-- mmio_log), resolved through the SVD the same way mmio_accesses is.
CREATE TABLE dynamic_mmio (
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
CREATE INDEX idx_dynmmio_run ON dynamic_mmio(dynamic_run_id);
CREATE INDEX idx_dynmmio_addr ON dynamic_mmio(firmware_id, addr);

-- TX/RX byte captures opportunistically available on a dynamic run (only
-- when the scenario itself requested dump_mem/dump_reg_pointee that
-- happens to be a TX/RX buffer -- recorded as-is, not synthesized).
CREATE TABLE dynamic_tx_rx (
    id                INTEGER PRIMARY KEY,
    dynamic_run_id     INTEGER NOT NULL REFERENCES dynamic_runs(id),
    firmware_id         INTEGER NOT NULL REFERENCES firmware(id),
    direction              TEXT NOT NULL,  -- TX / RX
    data_hex                TEXT NOT NULL,
    note                     TEXT
);
CREATE INDEX idx_dyntxrx_run ON dynamic_tx_rx(dynamic_run_id);

-- Every disagreement/anomaly the census itself finds -- reported, never
-- hidden. See docs/tooling/census.md's "Exhaustiveness / validation"
-- section for the full list of categories this is populated with.
CREATE TABLE scan_warnings (
    id            INTEGER PRIMARY KEY,
    firmware_id    INTEGER NOT NULL REFERENCES firmware(id),
    category        TEXT NOT NULL,
    addr             INTEGER,
    detail           TEXT NOT NULL,
    source           TEXT NOT NULL
);
CREATE INDEX idx_warnings_fw ON scan_warnings(firmware_id);
CREATE INDEX idx_warnings_category ON scan_warnings(firmware_id, category);
