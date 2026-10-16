# Sweep 5: census tooling (`tools/census/`)

Read-only reconnaissance. Scope: every source file under `tools/census/` (27 non-test files: 26 `.py` plus `schema.sql`; 8 `test_*.py` files) and `docs/tooling/census.md`. `__pycache__/*.pyc` files exist in the directory and are compiled bytecode, so they were not read. The directory has no `__init__.py`. Modules import each other as flat top-level modules through `sys.path.insert(0, HERE)`.

Abbreviations used below:
- **CSD**: Capstone-operand dataflow (ARM/Thumb-specific instruction interpretation in Python).
- **XC**: independent cross-check.
- **NORM**: engine-output normalization or ingest.

Classification follows the CLAUDE.md rule that `tools/census/` holds about 2,800 lines of ARM-specific Capstone dataflow.

```yaml
- path: docs/tooling/census.md
  purpose: Short framework-level description of the census layer (40 lines).
  exports: n/a
  dependencies: refers to cases/performing-rigs/docs/investigations/census-results.md for history and recipes
  data_shapes: n/a
  side_effects: none
  role: documentation
  observations:
    - Says firmware registries, boot recipes, hardware interpretations, roots and run databases are case inputs, "not the census engine" (census.md:19-21). Code contradicts this in many places (see db.py, build.py, reduce.py, dynamic_ingest.py).
    - Many module docstrings point at census.md sections that no longer exist in this 40-line file: "Closure reduction" (aptrace_census.py:16), "Residual prioritization" (residual_priority.py:2, aptrace_census.py:668), "868 vs 915 diff" (firmware_diff.py:11), "Reference-source fingerprinting" (reference_normalize.py:41), "Hardware-init snapshot" (schema.sql:555), "pin evidence" (schema.sql:207), "Exhaustiveness / validation" (schema.sql:308), "state-map section" (indexed_writes.py:11). The content appears to have moved to the case doc named at census.md:38-40.

- path: tools/census/aptrace_census.py
  purpose: Census CLI. `build`/`reduce` delegate to pipelines; most other subcommands are SQL queries that print text.
  exports: hexaddr, hx, cmd_* (30 subcommands, see the subcommand map), main(argv)
  dependencies: db (census_db); lazy imports: build, reduce, residual_priority, dynamic_ingest, firmware_diff, reference_corpus (case script), reference_match, semantic_packets, state_map, fnptr_resolve, aptrace_ghidra (tools/ghidra). sys.path adds cases/performing-rigs/config and cases/performing-rigs/scripts (lines 60-61), which is a case import seam in a framework module.
  data_shapes: reads nearly every census table; `hardware-contract` and `diff --json` emit JSON; `fnptr-seeds` writes a seed JSON doc {firmware_key, firmware_sha256, source, seeds:[{addr, role, consumer_site, slot_addr, raw_value}]} (lines 986-989)
  side_effects: the docstring calls the query commands "read-only" (lines 8-9), but every one calls census_db.connect(create=False), which still runs executescript(schema.sql) plus ALTER TABLE column migrations (db.py:37,48,74). Writes the DB through build/reduce/ingest-dynamic/reference-corpus/reference-match/state-map. Writes files through hardware-contract --out (line 782), semantic-packets --output, and fnptr-seeds (ghidra.seed_file, lines 984-992). reduce and state-map --dispatcher-entry run Unicorn.
  role: CLI / query surface / orchestration entry
  observations:
    - Usage examples are all AutoPilot-specific: autopilot868, 0x8258, 0x20001b14, TC1, PB05, base 0x200025bc count 18 (lines 20-51).
    - --db default help names cases/performing-rigs/research/runs/census/census.sqlite3 (line 1014).
    - The 'peripheral' help says "named SAMD51 peripheral" (line 1047), and the 'diff' help says "e.g. 868 vs 915" (line 1103).
    - cmd_summary encodes an evidence rule: cross-image fingerprint matches are never treated as library truth, and only reference_source_confirmed is subtracted from the residual (lines 178-199).
    - cmd_summary's indirect-edge count line prints RESOLVED_RAM_FUNCTION_POINTER (line 164), but the --classification help omits it (line 1061).
    - The pin "no evidence" message names PORT DIR/OUT/IN bitmask registers (lines 390-392), which is SAMD-specific vocabulary.
    - cmd_reference_match and cmd_fnptr_seeds read firmware bytes through ghidra.firmware_info (the case firmware registry), not the DB's firmware.path (lines 855, 970).
    - cmd_fnptr_seeds writes STRONG-only resolutions as derived Ghidra seeds, so one analysis's output feeds a later Ghidra build (lines 959-993).
    - No analysis-version identifiers appear on any printed output.

- path: tools/census/db.py
  purpose: SQLite connection, schema ensure, column migrations, per-firmware clear/replace helpers.
  exports: HERE, REPO_ROOT, SCHEMA_PATH, DEFAULT_DB_PATH, connect(db_path, create), get_firmware_id, clear_reduction_data, clear_firmware_data, replace_firmware_rows, _ensure_schema, _ensure_columns, _COLUMN_MIGRATIONS, _TABLES_CHILD_FIRST, _REDUCTION_TABLES_CHILD_FIRST
  dependencies: sqlite3, pathlib
  data_shapes: all census tables
  side_effects: creates parent dirs (line 33); runs schema DDL and ALTER TABLE on every connect, including create=False (lines 37, 48, 74); DELETEs in clear_* and replace_firmware_rows
  role: schema / persistence helper
  observations:
    - DEFAULT_DB_PATH is hardcoded to the case: cases/performing-rigs/research/runs/census/census.sqlite3 (line 20). This is a framework-to-case path seam.
    - create=False only refuses a missing file. It still mutates an existing DB through DDL and migrations (lines 30-37).
    - Hand-maintained column migrations (lines 58-67) instead of a schema version.
    - _TABLES_CHILD_FIRST omits every state_map_* table (lines 89-114). state_map_indexed_writers.from_function_id and state_map_interproc_writers.caller/callee_function_id REFERENCE functions(id) (schema.sql:896,942-943), and PRAGMA foreign_keys=ON (line 36). A static rebuild after a state-map run could therefore hit an FK violation, or leave stale rows. This is inferred from code and was not executed.
    - The comments name residual_priority.py and hardware_contract.py as tools/census modules (line 97), but hardware_contract.py lives in cases/performing-rigs/config/.

- path: tools/census/build.py
  purpose: Builds the base evidence layer for one firmware. Steps: Ghidra export ingest, raw vector and function-pointer scan, Capstone sweep cross-check, SVD/pin resolution, scan_warnings.
  exports: FunctionRanges (class, .containing(addr)), build(key, db_path, verbose, ghidra_build), _compute_warnings, main
  dependencies: db, raw_scan, capstone_sweep, aptrace_ghidra (tools/ghidra: build, ensure_fresh, firmware_info, _load_static_export, _load_census_export, read_meta, CENSUS_RAM_BASE/SIZE, CENSUS_MMIO_BASE/SIZE, NUM_EXTERNAL_IRQ), `pins` from cases/performing-rigs/config (resolve_mmio_addr, port_pin_evidence, _samd51_map). This is a case import (sys.path line 35, import line 40).
  data_shapes: consumes Ghidra static_export.json (functions, dataReferences, strings, program.memoryBlocks) and census_export.json (basicBlocks, edges, memoryAccesses, mmioAccesses). Writes firmware, functions, basic_blocks, edges, memory_accesses, mmio_accesses, literal_refs, strings, vectors, function_pointers, peripherals, pins, scan_warnings.
  side_effects: may invoke a Ghidra build (line 74); DB writes; clear_firmware_data also wipes dynamic coverage and every reduction table (line 107)
  role: census ingest (NORM of Ghidra output, plus raw scan and an XC)
  observations:
    - Firmware identity is recorded as path, sha256 (from Ghidra meta), flash_base, size, RAM/MMIO windows, ghidra_version and built_at (lines 90-94). No census build version or script hash is recorded.
    - RAM/MMIO windows come from aptrace_ghidra.CENSUS_* constants (lines 83-84).
    - Peripherals and pins are resolved only through pins_mod._samd51_map(), so the SAMD51 SVD is hardwired (lines 157, 246, 259). scan_warnings text says "any SAMD51 peripheral in the SVD" (line 326).
    - Stack-space dataReferences ("0xStack[-0x48]") are silently skipped, with the reason given in a comment (lines 170-184).
    - Capstone-sweep edges are inserted with resolved=1 and source='capstone-sweep' into the same edges table as Ghidra edges (lines 231-236). Downstream queries that do not filter on source mix the two (see features.py, residual_priority.py, interproc_writes.py, fnptr_resolve.py).
    - scan_warnings categories: capstone-target-not-in-ghidra-coverage, vector-outside-known-function, mmio-unresolved, exec-bytes-unowned (lines 283-356). The stated authority rule is "Ghidra remains the authority" (line 289).
    - The step logs are numbered [1/6]..[6/6], but [1/6] only prints when ghidra_build is set (line 73).

- path: tools/census/raw_scan.py
  purpose: Ghidra-independent raw byte scans: the ARMv7-M vector table, plus function-pointer candidates outside function bodies.
  exports: SYSTEM_VECTOR_NAMES, read_vectors(firmware_path, flash_base, *, num_irq, known_function_entries), scan_function_pointer_candidates(...)
  dependencies: struct only
  data_shapes: returns dicts {vector_index, raw_value, target_addr, name, is_irq, landed_in_known_function} and {location_addr, raw_value, target_addr, matches_known_function}
  side_effects: reads the firmware file
  role: raw scan / XC leg (ARMv7-M architecture-specific, device-independent)
  observations:
    - ARMv7-M vector layout is hardcoded (lines 13-25). num_irq deliberately has no default, so it is target config (lines 35-38).
    - The vector table is read at file offset 0, which assumes the table sits at the image start (line 52).
    - Function-pointer candidates require the Thumb bit and value-1 equal to a known entry; the result is labeled as a candidate, not an assertion (lines 80-87).
    - in_any_function uses a linear scan (lines 97-105).

- path: tools/census/capstone_sweep.py
  purpose: Independent Capstone Thumb linear sweep from seeds, following direct branch and call targets, used to cross-check Ghidra block coverage.
  exports: MAX_TOTAL_INSTRUCTIONS=400000, MAX_INSTRUCTIONS_PER_SEED=4000, UNCONDITIONAL_TERMINATORS, _is_return_like, sweep(firmware_bytes, flash_base, seed_addrs) -> (edges, discovered)
  dependencies: capstone (CS_ARCH_ARM, CS_MODE_THUMB, ARM_OP_IMM)
  data_shapes: edges (from, to, kind in branch/cbranch/call); set of decoded addresses
  side_effects: none
  role: independent cross-check (XC), explicitly "not a second authority" (lines 3-9). It is the exemplar named in CLAUDE.md.
  observations:
    - Thumb mnemonic tables are hardcoded (line 27). The set includes the odd entry "table branch byte".
    - is_cond_branch = startswith("b") and not in {b, b.w, bl, blx} (line 89). That test also matches bx, bic, bfi, bfc and bkpt, so those are labeled "cbranch" when they carry an immediate last operand (for example bkpt #imm, if in range), and stop detection relies on _is_return_like. A `bx rN` other than lr does not stop the linear run, because "bx" makes is_cond_branch True and so fails the terminator test at line 102. Any `pop` stops the run, even without pc.
    - Bounded by instruction caps. The caller sees no completeness/truncation flag: hitting MAX_TOTAL_INSTRUCTIONS is silent (lines 65, 72).
    - Seeds are Ghidra function entries plus vector targets (build.py:225), so the sweep is not fully independent of Ghidra's discovery: it shares Ghidra's seed set.

- path: tools/census/callback_provenance.py
  purpose: One-hop provenance of a register-indirect target that derives from an incoming argument. Enumerates direct transfers into the entry, computes each caller's argument reaching-defs, and classifies them.
  exports: ANALYSIS="callback_provenance", ANALYSIS_VERSION=1, MAX_CALLERS=16, MAX_BLOCKS=128, MAX_DEFS=16, MAX_TARGETS=16, MAX_WORK=4096, MAX_PATH_BLOCKS=512, STATUSES, LIMITATIONS, direct_transfers, caller_value, static_path, trace_callback_argument(conn, firmware_key, image, site, ...), argument_sites, main (CLI --site/--all-argument-sites/--max-*)
  dependencies: capstone.arm_const; fnptr_resolve (canonical_code_pointer); indirect_target (resolve_indirect_call, _Ctx, _reaching, _flatten, _shape, _targets, _written, _is_call, _sp_delta, _region, _hexify, _CAPSTONE_NAMES, MAX_DEPTH); indexed_writes (_read_flash_word, ARM_REG_INVALID); slot_dispatch (_bl_target, _t4_target, _wide_branch_target); db (main only)
  data_shapes: reads firmware, basic_blocks, edges, functions, literal_refs, indirect_edge_candidates, indirect_edge_resolutions, function_reachability, dynamic_runs, dynamic_coverage. Returns deterministic JSON {analysis, analysis_version, site_analysis, firmware_key, firmware_sha256, site, bounds, limitations, argument_origins[{callers[{value_status, components, conditions, ...}], address_taken, census_only_edges, ...}], candidate_targets, non_callable_values, next_hops, caller_value_statuses, provenance_status, target_set CLOSED/OPEN, open_reasons, incomplete_reasons, work, recorded_coverage}
  side_effects: CLI opens the DB with SQLite read-only URI mode=ro (line 657); prints JSON
  role: static dataflow analysis (CSD, ARM/Thumb-specific). An agent wrapper exists at agent/src/aptrace_agent/callback_provenance.py (not in scope).
  observations:
    - Hand-decoded Thumb encodings: 16-bit B/B<c> (lines 100-108), BLX imm (111-115), MOVW/MOVT T3 (158-163), and a halfword sweep over the whole image for transfers (118-139).
    - Cortex-M semantics are hardcoded: BLX imm is UNDEFINED on M-profile (line 240), and INVSTATE on an even target (line 317).
    - AAPCS r0-r3 and stack-argument modeling (lines 275-299, 377-388).
    - Value statuses: CONCRETE, FINITE_TARGET_SET, FORWARDED_ARGUMENT, MEMORY_DEPENDENT, UNKNOWN (line 66). Site-level states: provenance_status (worst caller status, or NOT_APPLICABLE), target_set CLOSED/OPEN, open_reasons, incomplete_reasons (bound hits). Pointer validity values: NULL, VALID_THUMB_CODE_POINTER, OUTSIDE_IMAGE, THUMB_BIT_CLEAR, DOES_NOT_DECODE (lines 302-325).
    - Verifies the image sha256 against the census (lines 483-484).
    - The LIMITATIONS tuple is explicit (lines 74-87) and is carried into the output.
    - Imports private helpers (underscore names) from three sibling modules: tight coupling.
    - incomplete-reason detection is string-prefix based ("block limit", "work budget", "bound") (lines 585, 604).
    - _sweep_transfers has a docstring only on the function. Each _address_taken call scans the whole image (lines 193-215).

- path: tools/census/components.py
  purpose: Deterministic union-find grouping of reachable functions over call, resource, dynamic and string relations.
  exports: CALL_UNION_MAX_CALLERS=3, CALL_UNION_MAX_CALLEES=3, RESOURCE_UNION_MAX_OWNERS=8, DSU, _union_low_fan_in_owners, _sccs (iterative Tarjan), compute(conn, firmware_id)
  dependencies: json; db.replace_firmware_rows (lazy)
  data_shapes: reads function_reachability, edges, mmio_accesses, memory_accesses, pins, dynamic_coverage, literal_refs, strings, functions. Writes components (peripherals_json, pins_json, ram_addrs_json, scenarios_json, strings_json) and component_members.
  side_effects: DB writes
  role: closure reduction (aggregation over existing evidence; no instruction semantics)
  observations:
    - RESOURCE_UNION_MAX_OWNERS=8 was tuned against "mando868's own real distribution" (lines 21-28, 60-67), a case-derived constant in a framework module.
    - Rule 6 (dynamic co-execution) has no fan-in bound: all functions in one dynamic_run are unioned (lines 219-228). This contrasts with the bounded resource rules.
    - Call graph restricted to source LIKE 'ghidra%' (line 170).
    - Component IDs are stable only for a fixed evidence state, which is disclosed (lines 48-54).

- path: tools/census/dynamic_ingest.py
  purpose: Ingests dynamic_export.py coverage JSON (scenario legs) into the dynamic_* tables.
  exports: _function_id_for_pc, _basic_block_id_for_pc, ingest_file(conn, path, firmware_key_filter), ingest_dir, main
  dependencies: db; `pins` from cases/performing-rigs/config (case import, lines 18-20) for resolve_mmio_addr
  data_shapes: consumes {scenario, legs:[{firmware, label, snapshot{entry, stop_reason, error, instructions_executed, visited_pcs, ram_log, mmio_log}, tx_rx}]}. Writes dynamic_runs, dynamic_coverage, dynamic_memory, dynamic_mmio, dynamic_tx_rx.
  side_effects: DB writes; deletes the prior (firmware, scenario) rows first
  role: census ingest (NORM of Unicorn output)
  observations:
    - Hardcoded firmware keys ("autopilot868","autopilot915","mando868","mando915") are used to map leg filename stems to keys (lines 62-63). This is a case-specific seam.
    - Silently skips firmware that has no static census (lines 70-73).
    - No harness assumptions, engine version or capture-script identity is recorded per run, only source_file and ran_at (lines 89-96).

- path: tools/census/features.py
  purpose: Materialized per-function structural counts.
  exports: compute(conn, firmware_id)
  dependencies: json; db.replace_firmware_rows
  data_shapes: writes function_features (n_callers, n_callees, n_basic_blocks, n_ram_reads/writes, n_mmio_reads/writes, n_literal_refs, n_strings, n_pins, n_indirect_edges_from, is_irq_handler, irq_vector_index, n_dynamic_runs/scenarios, peripherals_json, pins_json, scenarios_json, reachability_status, library_confidence)
  side_effects: DB writes
  role: closure reduction (aggregation)
  observations:
    - n_callers and n_callees count edges of every source, including capstone-sweep (no source filter, lines 34-39). fingerprint.py counts edges with source LIKE 'ghidra%' only (fingerprint.py:64-65). The two filters are inconsistent.
    - Issues several queries per function (lines 31-76). Performance only.

- path: tools/census/fingerprint.py
  purpose: Cross-image function fingerprints (exact byte hash, normalized Capstone token hash, structural) and library_matches tiers.
  exports: _normalize_op_str, _md, compute_fingerprints, _family, compute_matches, recompute_all_matches
  dependencies: capstone (ARM THUMB), hashlib, re; db.replace_firmware_rows
  data_shapes: writes function_fingerprints and library_matches (EXACT / STRONG_MATCH / POSSIBLE_MATCH / NO_MATCH; method names with a -same-product suffix; reference_source_confirmed carried forward)
  side_effects: DB writes; recompute_all_matches rewrites library_matches for every fingerprinted firmware in the DB
  role: cross-image comparison (Capstone mnemonic/op_str text normalization; ARM-specific decode, not dataflow)
  observations:
    - The docstring is case-specific: it names autopilot868/915 and mando868/915, and "Arduino-core/CMSIS" (lines 3-12, 92-104).
    - _family strips trailing digits to define "same product" (lines 92-108). This is a naming-convention heuristic tied to the case's firmware keys.
    - The thunk flag yields confidence EXACT with method ghidra-thunk (lines 145-151), so a Ghidra classification is recorded as an EXACT match.
    - Normalization is regex-based over Capstone op_str text (lines 44-51).
    - The comment notes that reference_source_confirmed is preserved across recompute (lines 202-218).

- path: tools/census/firmware_diff.py
  purpose: Mechanical diff between two reduced firmware images: hardware registers, MMIO sites, pin config, fingerprint-paired residual priority, strings, literal-ref counts.
  exports: _fw_pair, _hw_register_diff, _mmio_site_diff, _pin_config_diff, _fingerprint_pairing, _residual_diff, _string_diff, _hardware_relevant_constant_diff, diff_firmwares(conn, key_a, key_b)
  dependencies: db
  data_shapes: reads hardware_snapshot, mmio_accesses, pin_snapshot, function_fingerprints, functions, residual_priority, strings, function_features. Returns a JSON dict with counts and a note.
  side_effects: none (read-only queries)
  role: cross-firmware comparison (aggregation)
  observations:
    - Framed as "868-vs-915" (line 1) and references boot_recipes.py's sibling remap (lines 8-9, 71).
    - _fingerprint_pairing maps exact_hash to one function. Byte-identical duplicates inside one image collapse silently to the last row (lines 72-77).

- path: tools/census/fnptr_resolve.py
  purpose: Resolves unresolved register-indirect sites whose target is loaded from one constant RAM slot whose known writers store constants. Also canonicalizes Thumb pointers and follows forwarding stubs.
  exports: MAX_TRACE_HOPS=8, MAX_FORWARD_HOPS=3, MAX_FORWARD_SETUP=2, ARG_REGS, CALL_CLOBBERED, SOURCE="ram-fnptr-constant-store", trace_reg, slot_load_at_site, slot_writers, canonical_code_pointer, follow_forwarding, resolve_function_pointers, seed_targets, _direct_call_instructions, _store_value
  dependencies: capstone.arm_const; indexed_writes (private helpers); interproc_writes (_reg_traces_to_argument); indirect_resolve.decode_instruction (lazy)
  data_shapes: reads edges, functions, basic_blocks, memory_accesses, function_pointers. Returns rows matching resolved_function_pointers (consumer_site, slot_addr, store_addr, derivation intraprocedural-constant/callsite-argument, value_kind constant/unresolved, raw_value, thumb_bit, canonical_target, terminal_target, forwarding_json, confidence STRONG/WEAK, provenance_json)
  side_effects: none (the caller persists results)
  role: static dataflow analysis (CSD, ARM/Thumb-specific)
  observations:
    - No ANALYSIS/ANALYSIS_VERSION constant. Identity is only the SOURCE string (line 62).
    - AAPCS call-clobber set r0-r3/r12 (line 58).
    - The Capstone alias remap {"r9":"sb",...} is applied inline (line 355), the inverse of indirect_resolve's normalization.
    - Docstring (lines 250-252): "Ghidra's block model reports the containing BLOCK start, the Capstone sweep the instruction itself" for call edges. macaw_compare.py:58-59 says the opposite: Ghidra's edges.from_addr for a call is the exact instruction address. The two modules disagree about the data they share.
    - Confidence is STRONG only when every known writer is a constant code pointer and all agree, otherwise WEAK. EXACT is never used, and the docstring explains why (lines 38-43, 369-372).
    - Writer-set incompleteness is surfaced as an extra unresolved row when the writer has non-call entries or is pointed to from flash (lines 233-244).
    - slot_writers has a missing space in its signature (`conn,firmware_id`, line 271); cosmetic.

- path: tools/census/hardware_snapshot.py
  purpose: Persists MCU register and pin state from an already-run boot capture (Unicorn machine).
  exports: PERIPHERAL_PREFIXES, dump_registers, decode_pins, compute(conn, firmware_id, firmware_key, machine, result, recipe, init_status, svd_map, verbose, delivery_log)
  dependencies: datetime, json; db.replace_firmware_rows; reads machine.uc.mem_read (Unicorn)
  data_shapes: writes hardware_snapshot_runs (boot_method, init_status, completed_init, notes, assumptions_json), hardware_snapshot (addr, peripheral, register_name, width, raw_value hex), pin_snapshot
  side_effects: DB writes
  role: concrete-state normalization (NORM of Unicorn state, SAMD-specific decode)
  observations:
    - SAMD51 peripheral names are hardcoded (PORT, ADC, TC, TCC, SERCOM, EIC, DMAC, NVMCTRL, USB, WDT, GCLK, OSCCTRL, OSC32KCTRL, MCLK) (lines 38-39).
    - The PORT decode assumes the SAMD register layout GROUPn.DIR/OUT/IN/PINCFGn/PMUXn, the PMUXEN bit at 1, and pin naming P{A+g}{nn} (lines 89-133).
    - The docstring references cases/performing-rigs/config/boot_recipes.py (lines 3, 158), and a citation string hardcodes that case path (line 158).
    - Records assumptions and interrupt deliveries into assumptions_json (lines 151-159). This is the census's main harness-assumption record.
    - compute() can insert boot_method=None when recipe is None (lines 150, 168), but schema.sql declares boot_method TEXT NOT NULL (schema.sql:560). That would raise a constraint error. Inferred from code, not executed.
    - Broad except clauses silently skip unreadable regions, so incompleteness is not recorded (lines 49, 99, 111, 118).

- path: tools/census/indexed_writes.py
  purpose: Finds register-indexed stores into a given RAM array and classifies their slot coverage. Also hosts the shared same-block and cross-block register resolvers that other modules reuse.
  exports: MAX_CHAIN_DEPTH=4, MAX_FINITE_CANDIDATES=8, MAX_CROSS_BLOCK_HOPS=8, _md, _access_width, _decode_block, _mem_operand, _store_candidate, _literal_pool_target, _read_flash_word, _reg_written_by, _resolve_reg_value, _resolve_reg_across_blocks, _block_for_addr, _direct_predecessors, _bound_index_cross_block, _match_cmp_beq, _match_cmp_range_guard, _find_init_in_predecessors_of, find_computed_writers(conn, firmware_id, firmware_bytes, flash_base, base, count, width); re-exports ARM_REG_INVALID
  dependencies: capstone (ARM THUMB, arm_const), struct
  data_shapes: reads basic_blocks and edges. Returns [{from_addr, from_function_id, mnemonic, access_width, base_reg, index_reg, scale, disp, resolved_base_addr, classification INDEXED_WRITER_EXACT_SLOT/FINITE_SLOT_SET/RANGE/UNKNOWN_COMPUTED_WRITE, slots, applies_to_all_slots, derivation}]
  side_effects: none
  role: static dataflow analysis (CSD, ARM/Thumb-specific); shared resolver library for fnptr_resolve, interproc_writes, indirect_target and callback_provenance
  observations:
    - T1 LDR-literal PC-relative rule (lines 128-135), plus Thumb mnemonics and condition suffixes (lines 64-69, 364-369).
    - The _reg_written_by docstring says it returns a register only for a small set of definition shapes. The code returns operands[0].reg for any instruction whose first operand is a register, so str/cmp/tst count as definitions, and the local variable `m` is unused (lines 145-154). Effect: _resolve_reg_value reports "unknown: unrecognized def" when it meets a store or compare of the register, and calls (operand 0 is an immediate) are never seen as clobbers. fnptr_resolve adds its own call-clobber check; interproc_writes does not.
    - find_computed_writers accepts only a "literal" base and rejects an "imm" base (line 416).
    - Incompleteness is represented through UNKNOWN_COMPUTED_WRITE + applies_to_all_slots=True (lines 475-476), keeping derivation_json. A constant index that lands outside the array is dropped (`continue`, line 442) rather than recorded.
    - _bound_index_cross_block recognizes exactly two shapes: equality fan-in and a single guard plus init (lines 288-336).
    - Bases are found by a whole-image scan of every attributed basic block (lines 402-404). Unattributed blocks (function_id IS NULL) are excluded and that exclusion is not reported.

- path: tools/census/indirect_resolve.py
  purpose: Decodes indirect-flow instruction shapes and scans candidate tables. Its dynamic_candidates function replays the case scenario corpus with watched registers.
  exports: MAX_TABLE_ENTRIES=64, _md, _CAPSTONE_REG_ALIASES, _canonical_reg_name, decode_instruction(firmware_bytes, flash_base, addr) -> (mnemonic, shape reg-indirect/table-branch/mem-indirect/unknown, reg), scan_pointer_table, scan_halfword_table, nearby_literal_table_base, dynamic_candidates(firmware_key, from_addrs_with_regs, verbose)
  dependencies: capstone; dynamic_candidates imports concrete (tools/unicorn) plus virtual_link and dynamic_export from cases/performing-rigs/scripts (lines 186-192, a case import in a framework module)
  data_shapes: candidate lists; dynamic hits {from_addr: [(value, scenario)]}
  side_effects: dynamic_candidates monkeypatches concrete.ConcreteMachine.run globally while each scenario runs (lines 198-229) and executes Unicorn scenarios
  role: instruction-shape classification (Capstone operand checks, ARM-specific); table scan; concrete-execution observation harness
  observations:
    - The classification driver is not in this file. It lives in reduce.resolve_indirect_edges. The module docstring (lines 1-38) describes tiers that reduce.py assigns.
    - The comment cites "Mando868 has a real `bx sl`" (lines 57-62).
    - Table stopping rule: the first word that does not look like a pointer (pointer tables) or a target outside the image (TBB/TBH). Table length is a heuristic (lines 105-151).
    - A scenario exception is swallowed and partial watch data is kept (lines 224-227). The scenario failure is only printed, never recorded in the DB.
    - The candidate table base for mem-indirect is the nearest preceding literal ref in the same block, a heuristic (lines 154-169).

- path: tools/census/indirect_target.py
  purpose: Intraprocedural backward reaching definitions for the branch register of a register-indirect site, plus shape classification and candidate targets. Also detects vptr installations.
  exports: ANALYSIS="indirect_target", ANALYSIS_VERSION=2, MAX_BLOCKS=64, MAX_DEPTH=3, MAX_TABLE_ENTRIES=64, ARG_REGS, CALL_CLOBBERED, INTRA_KINDS, TABLE_SHAPES, _CAPSTONE_NAMES, LIMITATIONS, _Ctx, _reaching, _definition, _load, _sp_delta, _stack_argument, _flatten, _origin, _shape, _targets, resolve_indirect_call(conn, firmware_key, image, site, vtables, max_blocks, max_depth), _hexify, vptr_installations, main (CLI --site/--vtable/--installations/--vtables-from-installations/--all-register-indirect)
  dependencies: capstone.arm_const (ARM_INS_* ids); fnptr_resolve (canonical_code_pointer, slot_writers); indexed_writes (private helpers); indirect_resolve (decode_instruction, scan_pointer_table); db (main)
  data_shapes: reads firmware, basic_blocks, edges, functions, indirect_edge_resolutions, indirect_edge_candidates, memory_accesses (through slot_writers). Returns JSON {analysis, analysis_version, firmware_key, firmware_sha256, site, bounds, vtables_supplied, limitations, mnemonic, instruction_shape, target_reg, containing_block/function, function_attributed, derivation_status ESTABLISHED/PARTIAL/UNKNOWN/NOT_APPLICABLE, pattern(s), reaching_definitions, candidate_targets, resolution_status STATICALLY_ESTABLISHED/CONDITIONALLY_POSSIBLE/UNRESOLVED}
  side_effects: CLI opens the DB with mode=ro (line 681)
  role: static dataflow analysis (CSD, ARM/Thumb-specific). This is the only backward reaching-definitions implementation. Per CLAUDE.md, v3 (p-code) is the planned replacement, and the agent wraps it at agent/src/aptrace_agent/indirect_target.py.
  observations:
    - The version comment documents what v2 changed (lines 73-76).
    - Thumb/ARM semantics: ARM_INS_POP/LDM/LDMDB/LDRD/MOV/MOVT/ADR/ADD/SUB handling (lines 229-271); the ADR PC alignment rule (lines 248, 256-257); prologue SP-delta modeling of push/vpush/sub sp (lines 307-320); the AAPCS stack-argument offset (lines 323-346); IT-conditional definitions via insn.cc (lines 106-107, 372).
    - A movw workaround for Capstone versions that report the id as MOV (line 245).
    - Definition kinds that mark a result incomplete: unknown, incomplete (block limit / work budget / depth limit), block-live-in, indirect-entry (lines 384-417).
    - _pointer_targets marks every aligned Thumb-looking flash word as an indirect entry, which makes derivations PARTIAL wherever such a word exists. This is conservative (lines 159-174).
    - _Ctx computes pointer_targets with a full image scan for every call to resolve_indirect_call (lines 185-186). argument_sites and callback_provenance call it once per site.
    - LIMITATIONS are carried into the output (lines 89-99).
    - The sha256 image check refuses a mismatched image (lines 561-562).

- path: tools/census/interproc_writes.py
  purpose: One-hop interprocedural write recovery: a caller passes a resolvable pointer as r0-r3, and the callee stores at arg+const.
  exports: ARG_REGS, MAX_ARG_TRACE_HOPS=8, _arg_index, _reg_traces_to_argument, summarize_function_arg_writes, find_interproc_writers(conn, firmware_id, firmware_bytes, flash_base, base, count, width)
  dependencies: indexed_writes (private helpers)
  data_shapes: reads edges, functions, basic_blocks. Returns [{callsite_from_addr, caller_function_id, callee_function_id, effect_from_addr, classification INTERPROC_EXACT_WRITER, slots, applies_to_all_slots False, derivation}]
  side_effects: none
  role: static dataflow analysis (CSD, ARM-specific)
  observations:
    - _reg_traces_to_argument relies on _resolve_reg_value returning "not_found" and has no call-clobber check (lines 56-58). Because indexed_writes._reg_written_by does not treat bl as defining r0-r3, an argument register clobbered by an intervening call is still treated as the live-in argument. fnptr_resolve guards this case separately (fnptr_resolve.py:109-111, 123-124).
    - The call-edge query has no source filter, so Ghidra and capstone-sweep call edges are both used (lines 116-119). call_idx must equal edges.from_addr exactly (line 139), so any edge whose from_addr is a block start rather than the instruction yields nothing (silently `continue`).
    - An unresolved result is dropped with no record (lines 151-152), as designed ("report nothing"). A negative result therefore carries no completeness signal.

- path: tools/census/macaw_compare.py
  purpose: Standalone comparison of the Ghidra census DB against `aptrace macaw-census` JSON: inventory, same-root reachability, calls, blocks/bytes, CFG edges, Macaw unresolved cases.
  exports: hx, maddr, load_macaw_census, check_firmware_match, whole_inventory, macaw_root_addrs, ghidra_vector_target_addrs, report_root_fairness, ghidra_function_id_by_entry, ghidra_resolved_static_adjacency, bfs, ghidra_same_root_functions, compare_functions_same_root, macaw_calls_by_caller, find_macaw_call, ghidra_calls_in_reachable_set, group_ghidra_calls_by_macaw_call, compare_calls, merge_ranges, range_len, subtract_ranges, intersect_ranges, ghidra_blocks_by_function, macaw_blocks_by_function, compare_block_coverage, _GHIDRA_NONCALL_KINDS, _MACAW_JUMP_KINDS, macaw_block_size_map, macaw_edges_by_function, ghidra_noncall_edges_in_reachable_set, compare_cfg_edges, macaw_normalized_edges_by_function, genuine_disagreements, compare_call_return_vs_fallthrough, analyze_macaw_indirect_calls, macaw_normalized_lookup, analyze_macaw_classify_failures, build_report, print_report, report_to_jsonable, fmt_*, main (CLI firmware macaw_json [--db] [--json])
  dependencies: db; consumes Macaw census JSON produced by src/APTrace/MacawCensus.hs / MacawExpand.hs (fields firmware, roots, functions, basic_blocks, edges, calls, incomplete_or_unresolved_terminators, normalized_terminators, discovery_error)
  data_shapes: reads functions, basic_blocks, edges (source LIKE 'ghidra%'), vectors. Outputs a text or JSON report.
  side_effects: the docstring says "never writes to the database" (lines 6-7), but census_db.connect(create=False) still runs schema DDL and migrations (line 1235; db.py:37). Prints to stdout and stderr.
  role: cross-engine comparison (Ghidra vs Macaw), on the side of keeping the two independent
  observations:
    - The fairness rule is documented: Macaw is seeded only from vector roots, and Part B recomputes Ghidra reachability from Macaw's roots (lines 15-54). Root asymmetry is disclosed, not widened (lines 168-184).
    - Firmware identity check covers only flash_base, ram_base and ram_size, warning only, with no sha256 comparison (lines 105-125). The output has no analysis version and no Macaw or Ghidra version.
    - "Both unresolved" is counted inside exact_agreement, with a sub-flag (lines 341-373), and printed as "Exact agreement (concrete or both-unresolved)" (line 960). Treating "both unknown" as agreement mixes agreement with shared incompleteness.
    - Call-site matching is by containment in the Macaw block range (lines 56-69, 284-288), and Ghidra's multi-target call rows are grouped (lines 309-338).
    - The fallthrough-inclusion special case for normalized terminators is documented with the case investigation "0x4b64/0x4ba2" (lines 852-862), and "flash 0x635e" is cited (lines 316, 713). These are firmware-specific references in the comments.
    - classify_failure is described as a "believed CBZ/CBNZ classifier limitation" in the printed label (line 1076).
    - The default DB help names the case path (line 1231).

- path: tools/census/reachability.py
  purpose: Function reachability from vector roots and confirmed indirect targets over strong and weak graphs.
  exports: _SYSTEM_VECTOR_ROOT_KIND, compute_roots, _indirect_adjacency, compute(conn, firmware_id, func_ranges)
  dependencies: collections; db.replace_firmware_rows
  data_shapes: reads vectors, indirect_edge_candidates, functions, edges, reachability_roots. Writes reachability_roots (reset-vector/irq-vector/system-vector/confirmed-indirect-target) and function_reachability (DEFINITELY_REACHABLE / POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT / NO_KNOWN_PATH, nearest_root_addr/kind, hops)
  side_effects: DB writes
  role: closure reduction (graph reachability)
  observations:
    - The docstring says NO_KNOWN_PATH is not a claim of unreachability (lines 30-32). This matches the evidence discipline.
    - Strong vs weak graphs. The docstring says the strong graph uses only STATICALLY_RESOLVED/DYNAMICALLY_OBSERVED indirect edges (lines 21-24). The code filters on candidate confidence IN ('EXACT','STRONG') (line 122). reduce.py assigns confidence STRONG to flash-table-scan candidates of FINITE_CANDIDATE_SET sites whenever the target lies in a known function (reduce.py:141), and fnptr_resolve emits STRONG. So FINITE_CANDIDATE_SET table-scan targets reach DEFINITELY_REACHABLE, and compute_roots also makes them roots of kind "confirmed-indirect-target" (lines 61-65). The documented and actual behavior diverge.
    - nearest_root_addr/kind is filled only for functions that are themselves roots: root_addr_kind is keyed by root function_id and looked up by fid (lines 149-174). The comment describes a nearest-root computation that is not performed.
    - The direct graph uses every Ghidra edge kind, including fallthrough and branch, not only calls (lines 114-120).
    - Indirect candidate_function_id comes from FunctionRanges.containing (in reduce.py), so a candidate in the middle of a function body counts as reaching that function.
    - The ARMv7-M vector semantics (vector[1] reset, index>15 IRQ) are hardcoded (lines 51-59).

- path: tools/census/reduce.py
  purpose: Closure-reduction orchestrator: fingerprint, boot capture, reference confirmation, indirect resolution, reachability, features, components, hardware snapshot, residual priority, hardware contract.
  exports: resolve_indirect_edges(conn, firmware_id, firmware_key, firmware_bytes, flash_base, func_ranges, boot_result, verbose), reduce_firmware(key, db_path, verbose), main
  dependencies: db, indirect_resolve, fnptr_resolve, reachability, fingerprint, features, components, hardware_snapshot, residual_priority, reference_match, build.FunctionRanges, aptrace_ghidra. Case imports: boot_recipes, reference_library, hardware_contract, pins (cases/performing-rigs/config), plus the scripts dir on sys.path (lines 60-61, 71-72, 74, 76).
  data_shapes: writes indirect_edge_resolutions (STATICALLY_RESOLVED / DYNAMICALLY_OBSERVED / RESOLVED_RAM_FUNCTION_POINTER / FINITE_CANDIDATE_SET / UNRESOLVED), indirect_edge_candidates (EXACT/STRONG/WEAK; sources: the edge source, flash-table-scan, ram-fnptr-constant-store, dynamic-observed:<scenario>), resolved_function_pointers, and through submodules all reduction tables; ingests the boot dynamic run
  side_effects: DB writes (clear_reduction_data first, line 234); runs a Unicorn boot capture and a full scenario-corpus replay; may write a boot export JSON (via boot_recipes)
  role: closure-reduction orchestration; mixes static and concrete evidence
  observations:
    - The docstring names the "cited AutoPilot recipe", the "Mando recipe" and a case doc (lines 8-18).
    - A Ghidra-resolved computed edge becomes STATICALLY_RESOLVED with candidate confidence EXACT (lines 106-114). Ghidra output is labeled EXACT.
    - TBB/TBH base is assumed to be from_addr+4, "32-bit instructions" (line 119). A flash-table-scan candidate is STRONG if it lands in a known function, else WEAK (line 141).
    - A dynamic observation upgrades the classification to DYNAMICALLY_OBSERVED. Values without the Thumb bit or outside flash are silently skipped (lines 193-213).
    - fnptr upgrade applies only to UNRESOLVED sites (lines 159-164).
    - SVD access is hardwired to pins_mod._samd51_map() (line 304).
    - No analysis version or run record is written for the reduce pass as a whole.

- path: tools/census/reference_match.py
  purpose: Matches firmware functions against the fetched-and-built reference corpus, tiered EXACT_BYTES through STRONG_STRUCTURAL, and feeds confirmations into library_matches.
  exports: TIER_ORDER, CONFIRMABLE_TIERS, STRUCTURAL_SIZE_TOLERANCE=0.10, MAX_CANDIDATES_PER_FUNCTION=50, function_fingerprint, compute(conn, firmware_id, firmware_bytes, flash_base, verbose), apply_to_library_matches
  dependencies: reference_normalize; db.replace_firmware_rows. Corpus built by cases/performing-rigs/scripts/reference_corpus.py (case).
  data_shapes: reads functions, reference_symbols, reference_packages, reference_build_variants. Writes reference_matches (tier, is_ambiguous, reference_symbol_id, reference_source_confirmed, detail) and reference_match_candidates; inserts or updates library_matches.
  side_effects: DB writes
  role: reference-source matching (Capstone text normalization; ARM-specific decode)
  observations:
    - The evidence rule is implemented: confirmation requires a confirmable tier and a non-ambiguous match (lines 29-35, 147-148). STRONG_STRUCTURAL never confirms.
    - Structural tolerance is max(2, 10%) here (line 127), versus max(1, 10%) in fingerprint.py:181. The tolerances differ.
    - The citation string hardcodes "arm-none-eabi-gcc" (line 203).
    - apply_to_library_matches inserts confidence "EXACT", method "reference-source-confirmed" rows (lines 208-214).

- path: tools/census/reference_normalize.py
  purpose: Shared instruction normalization and the four hashes used by both the reference corpus and firmware-side matching.
  exports: _BRANCH_CALL_MNEM, _BRANCH_MNEM, md, trim_trailing_padding, decode_code_bytes, reloc_mask, pcrel_mask, fingerprint_instructions
  dependencies: capstone (ARM THUMB), hashlib, re
  data_shapes: {exact_instr_hash, reloc_norm_hash, pcrel_norm_hash, n_instructions, n_branches}
  side_effects: none
  role: normalization library (Thumb-specific mnemonic tables)
  observations:
    - The docstring says exact_hash excludes the trailing literal pool via `code_only_instructions` (lines 9-11). No such function exists in this file. Decoding stops only at the first undecodable byte (lines 80-87), so a literal pool that decodes as instructions is included.
    - _BRANCH_MNEM is a hand list and incomplete (for example bvs.n, bvc.n, b<cc>.w for most conditions, bhs/blo variants) (lines 49-54). Missing branches are neither masked nor counted.
    - The firmware side masks by heuristic and the reference side by ELF relocations. The asymmetry is disclosed (lines 32-41).
    - The trim_trailing_padding comment cites `millis()` from the case corpus (lines 70-73).

- path: tools/census/residual_priority.py
  purpose: Defines the residual queue (the single source of truth) and a fixed, disclosed-signal priority score with HIGH/MEDIUM/LOW tiers.
  exports: POSITIVE_SIGNALS, NEGATIVE_SIGNALS, HIGH_THRESHOLD=5, MEDIUM_THRESHOLD=1, TIER_LABELS, tier_for, residual_function_ids(conn, firmware_id), compute(conn, firmware_id)
  dependencies: json; db.replace_firmware_rows
  data_shapes: reads function_reachability, library_matches, dynamic_coverage, function_features, edges, dynamic_tx_rx, dynamic_memory, memory_accesses, indirect_edge_resolutions, indirect_edge_candidates, component_members. Writes residual_priority (score, tier, reasons_json [{signal, points, description, evidence}]).
  side_effects: DB writes
  role: closure reduction (scoring)
  observations:
    - The NVMCTRL peripheral name is hardcoded for the nvm_access signal (lines 35, 210), which is SAMD-specific.
    - The call-adjacency query has no source filter, so capstone-sweep call edges are included (lines 115-118).
    - The score is labeled a "PRIORITY ORDERING HINT ... not a correctness claim" (lines 15-19).
    - A function with a missing features row gets an honest zero score (lines 184-190).

- path: tools/census/semantic_packets.py
  purpose: Exports compact per-residual-function evidence packets as JSONL for a semantic (LLM) classification pass.
  exports: MAX_LIST=10, PROVENANCE_CSV, DOCS_DIR, _capped, _load_provenance_csv, _build_docs_index, build_packets, export_packets
  dependencies: db, residual_priority, csv, re
  data_shapes: JSONL records {function_id, address, name, component, priority_tier/score, reachability, size, n_basic_blocks, callers/callees/ram_writes/ram_reads {values, total, truncated}, peripherals, pins, strings, strings_truncated, protocol_ram_overlap, cross_image_library_match, provenance_csv, docs_mentions}
  side_effects: writes the output JSONL (lines 191-198)
  role: export / handoff to model-based classification
  observations:
    - Hardcoded case paths: PROVENANCE_CSV at cases/performing-rigs/research/provenance/function_classification.csv and DOCS_DIR at cases/performing-rigs/docs (lines 34-35). The docstring says `docs/**/*.md` (line 16), but the code searches the case docs dir.
    - Packets carry no firmware sha256, analysis version or generation provenance.
    - The callers/callees queries have no source filter (lines 139-144).

- path: tools/census/slot_dispatch.py
  purpose: Whole-image halfword pattern sweep for `ldr rX,[rY,#off] ... bx/blx rX` dispatch sites at given slot offsets, plus BL, B.W, B<c>.W and pointer words to given targets.
  exports: _LOAD regex, _md (THUMB|MCLASS), _bl_target, _t4_target, _wide_branch_target, sweep(image, base, offsets, targets, window=6), main (CLI IMAGE --base --offset --target --window)
  dependencies: capstone, re, json
  data_shapes: {analysis "slot_dispatch_sweep", analysis_version 2, basis, offsets, targets, window, dispatch_sites, direct_calls, direct_branches, thumb_pointer_words}
  side_effects: reads the image file (CLI)
  role: pattern scan (Thumb encoding decode plus op_str regex; ARM-specific). Not dataflow. Its encoding helpers are reused by callback_provenance.
  observations:
    - Uses CS_MODE_THUMB | CS_MODE_MCLASS (line 35). Every other module uses CS_MODE_THUMB only, so Capstone modes are inconsistent across the census.
    - Register redefinition is detected by op_str text prefix (`nxt.op_str.startswith(reg + ",")`), excluding str/cmp/tst (line 106). This text heuristic misses writebacks and multi-register writes.
    - The _LOAD regex allows only r\d+|ip|lr names (line 31), so sb/sl/fp bases are not matched.
    - The loop bound `len(image) - 4` skips the final halfword positions (line 75).
    - The docstring states that the result is pattern-matched and not evidence of unreachability (lines 16-19). The JSON carries no image hash.

- path: tools/census/state_map.py
  purpose: Per-slot evidence for a base/count/width RAM array, from static, dynamic, indexed and interprocedural writers. Optionally probes a dispatcher with Unicorn.
  exports: WRITER_STATUS_PRECEDENCE, _static_access_rows, _dynamic_access_rows, _run_indexed_write_scan, _run_interproc_write_scan, build_state_map(conn, firmware_key, base, count, width, label, dispatcher_entry, source, include_indexed_writers, include_interproc_writers), _parse_extra_seed, probe_dispatcher(...), summary_rows
  dependencies: db; lazily aptrace_ghidra (firmware_info), indexed_writes, interproc_writes, concrete.ConcreteMachine (tools/unicorn)
  data_shapes: writes state_map_runs, state_map_slots, state_map_indexed_writers, state_map_interproc_writers, state_map_dispatcher_probes (outcome string_tx/byte_tx/clean_return/other/error, output_hex, output_depends_on_unresolved_source)
  side_effects: DB inserts (appends a new run each time; never replaces); Unicorn execution in probe_dispatcher
  role: reusable array evidence re-slice plus concrete probe (orchestration over CSD modules and Unicorn)
  observations:
    - The docstring example is AutoPilot's pending[] array (base 0x200025bc, count 18) (lines 4-5). It claims to be generic (lines 25-27).
    - The probe_dispatcher docstring says it writes "a single 0xFF-filled `width`-byte value" (line 337). The code writes b"\x01" + zeros (line 371). Docstring and code disagree.
    - probe_dispatcher hardcodes mmio_base=0x40000000 and mmio_size=0x4000000 instead of reading the DB firmware row (line 364).
    - Static slot matching is exact on to_addr == slot addr (lines 76-85), so a wider access that overlaps a slot from another start address is missed.
    - The writer_status precedence omits INTERPROC_FINITE_WRITER_SET, INTERPROC_RANGE_WRITER and UNKNOWN_ALIASED_WRITE, which schema.sql lists (schema.sql:864-871). No code produces those values.
    - unresolved_producer semantics depend on whether the scans ran (lines 294-296), which is disclosed.
    - Harness assumptions (extra_seed, index_addr) are not persisted in state_map_runs, which has no column for them; only the probe rows are stored.

- path: tools/census/schema.sql
  purpose: SQLite DDL for the census DB. All CREATE ... IF NOT EXISTS.
  exports: |
    Tables. Base layer: firmware, functions, basic_blocks, edges, vectors, function_pointers, memory_accesses, mmio_accesses, literal_refs, strings, peripherals, pins, dynamic_runs, dynamic_coverage, dynamic_memory, dynamic_mmio, dynamic_tx_rx, scan_warnings.
    Reduction layer: reachability_roots, function_reachability, indirect_edge_resolutions, indirect_edge_candidates, resolved_function_pointers, function_fingerprints, library_matches, function_features, components, component_members, hardware_snapshot_runs, hardware_snapshot, pin_snapshot.
    Residual/contract layer: residual_priority, hardware_contract_runs.
    Reference corpus: reference_packages, reference_build_variants, reference_build_files, reference_symbols, reference_match_candidates, reference_matches.
    State map: state_map_runs, state_map_slots, state_map_indexed_writers, state_map_interproc_writers, state_map_dispatcher_probes.
    No views. Indexes on most firmware_id and address columns.
  dependencies: n/a
  data_shapes: as listed; addresses are INTEGER; JSON stored as TEXT columns
  side_effects: executed on every db.connect
  role: schema
  observations:
    - References a nonexistent tools/census/cli.py (line 10).
    - vectors is described as "The ARMv7-M vector table" (line 84), mmio_accesses resolves through "cases/performing-rigs/config/svd/resolve_mmio.py's Samd51Map" (line 140), and peripherals as "SAMD51 peripherals" (line 189). Device and case specifics are baked into the framework schema comments.
    - The indirect_edge_resolutions.classification comment omits RESOLVED_RAM_FUNCTION_POINTER (line 374), and the indirect_edge_candidates.source comment omits ram-fnptr-constant-store (line 394), though resolved_function_pointers names it (line 405).
    - hardware_snapshot_runs.boot_method is NOT NULL (line 560), but hardware_snapshot.py can pass NULL.
    - There is no schema version table, and no analysis-version column on any reduction table.
    - The state_map_slots.writer_status comment lists values no code produces (lines 864-871).
    - The comments cite case paths (boot_recipes.py, reference_library.py, boot-and-hardware-bringup.md, reference_corpus.py) (lines 469-470, 576, 651, 670) and AutoPilot's pending[] array (line 809).

- path: tools/census/test_census.py
  purpose: Plain-assert regression tests for CLI helpers, SVD/pin resolution, raw vector and function-pointer scans (synthetic), DB schema and idempotent replace, plus real autopilot868 facts.
  behaviors_covered: hexaddr/hx; PINCFG and PMUX pin evidence through the case pins module; vector table bounds and Thumb clearing; function-pointer candidate filtering; schema table creation; replace semantics; get_firmware_id error; a real build into a temp DB checking >300 functions, 0x8258 named ascii_dispatcher__CUSTOM, vector count, PORT referenced, >80% MMIO resolved, unresolved edges present
  observations: imports the case pins module (line 27); the real-firmware test is skipped when the Ghidra cache is not fresh (lines 198-202); it builds into a temp DB, not the canonical one (lines 204-206).

- path: tools/census/test_indexed_writes.py
  purpose: Tests for indexed_writes on hand-encoded, Capstone-verified Thumb fixtures, plus one real-DB check. Also provides shared encoders and scratch-DB helpers for the other tests.
  behaviors_covered: an immediate-offset store is not a candidate; base/index/width extraction; EXACT_SLOT with a scaled index; UNKNOWN with no predecessors (applies_to_all, derivation kept); FINITE_SLOT_SET equality fan-in; RANGE init+guard; an unconstrained predecessor stays UNKNOWN; a base outside the array is dropped; on the real autopilot868 DB, 0x8774 `strb r2,[r6,r3]` into 0x20002524 is UNKNOWN_COMPUTED_WRITE
  observations: the real test opens the canonical case DB through census_db.connect(create=False), which runs schema DDL and migrations on canonical state (lines 377-381). Hardcoded AutoPilot addresses (lines 399-411).

- path: tools/census/test_interproc_writes.py
  purpose: Tests for interproc_writes on synthetic fixtures.
  behaviors_covered: helper(*ptr) gives slot 0; ptr+K folded at the callsite gives slot 4; an unresolved callsite pointer gives no claim
  observations: provides the bl() encoder reused by other tests. No test covers a call clobbering the argument register (the gap noted under interproc_writes.py).

- path: tools/census/test_fnptr_resolve.py
  purpose: Tests for fnptr_resolve on synthetic consumer/setter/init scenarios, plus a real autopilot868 USB slot check.
  behaviors_covered: callsite-argument resolution with both instruction-level and block-start call edges; raw vs canonical Thumb value; STRONG confidence; intraprocedural constant; memory-loaded and call-clobbered arguments stay unresolved with a reason; an even constant gives no target; forwarding hop plus constant args; hop limit; real slot 0x200052e8 from site 0xcc1a, store 0xccc6, callsite 0xbcda, raw 0xc725 forwarding to 0xc5cc; post-seeding checks
  observations: the real test opens the canonical DB read-only by URI (line 224). Hardcoded AutoPilot addresses and the case firmware path (lines 219-260).

- path: tools/census/test_indirect_target.py
  purpose: Tests for indirect_target v2 on a synthetic image and scratch DB.
  behaviors_covered: constant target; vtable slot 8 and 7 shapes and receivers; candidates only against supplied vtables (CONDITIONALLY_POSSIBLE); join receivers; code-pointer-entered block makes the result PARTIAL; entry-block stack argument 5; object-field; callback argument; IT-conditional defs; call clobber; call result; writeback base; LDRD first and second destinations; flash vs RAM constant slot; non-indirect site gives NOT_APPLICABLE; site outside blocks; sha mismatch refused; block and depth bounds reported incomplete; provenance keys; determinism; vptr_installations
  observations: synthetic only. No second ISA and no p-code comparison.

- path: tools/census/test_callback_provenance.py
  purpose: Tests for callback_provenance and the indirect_target v2 behaviors it relies on.
  behaviors_covered: stack argument after prologue; spill stays unresolved; jump-table case edges as predecessors; jump-table words excluded from pointer_targets; analysis_version==2 asserted; caller enumeration (BL, B.W, B<c>.W, 16-bit B); CONCRETE, FINITE_TARGET_SET, FORWARDED_ARGUMENT, MEMORY_DEPENDENT, UNKNOWN; THUMB_BIT_CLEAR and NULL validity; BLX-imm as an invalid transfer; caller set OPEN for address-taken, MOVW and census-only edges; CLOSED set; caller, work, target and def bounds; provenance; determinism; sha refusal
  observations: synthetic only. A case-level test of the same name exists at cases/performing-rigs/test/test_callback_provenance.py (out of scope).

- path: tools/census/test_macaw_compare.py
  purpose: Tests for how macaw_compare handles normalized_terminators.
  behaviors_covered: normalized edges are kept apart from base edges with the distinct kind "macaw-normalized"; normalized classify_failure is excluded from the unresolved analysis while unnormalized ones are still analyzed; cbranch+fallthrough agreement for normalized two-way branches (reproduces the old bug, then checks the fix)
  observations: scratch DB from the real schema. Only the normalized-terminator paths are covered; calls and blocks comparison are untested here.

- path: tools/census/test_slot_dispatch.py
  purpose: Tests for slot_dispatch.sweep on a hand-assembled image.
  behaviors_covered: slot 8 tail dispatch; slot 7 through an unrelated instruction; a redefined load is excluded; BL target; B.W and B<c>.W tail branches; aligned Thumb pointer word
  observations: synthetic only.
```

### Analysis classification summary

| Module | Class | Version identity | Completeness / incompleteness states |
|---|---|---|---|
| indirect_target.py | CSD (backward reaching defs) | ANALYSIS indirect_target v2 (lines 72-76) | derivation_status ESTABLISHED/PARTIAL/UNKNOWN/NOT_APPLICABLE; resolution_status STATICALLY_ESTABLISHED/CONDITIONALLY_POSSIBLE/UNRESOLVED; incomplete defs (block limit, work budget, depth limit), block-live-in, indirect-entry; LIMITATIONS |
| callback_provenance.py | CSD (one-hop caller args) | callback_provenance v1 (lines 56-57) | per caller CONCRETE/FINITE_TARGET_SET/FORWARDED_ARGUMENT/MEMORY_DEPENDENT/UNKNOWN; target_set CLOSED/OPEN; open_reasons; incomplete_reasons; NOT_APPLICABLE; LIMITATIONS |
| fnptr_resolve.py | CSD (slot load and store constants) | SOURCE string only (line 62) | value_kind constant/unresolved with reason; confidence STRONG/WEAK; extra unresolved row for an incomplete caller set; forwarding "stopped" reason |
| indexed_writes.py | CSD (indexed stores; shared resolver) | none | EXACT_SLOT/FINITE_SLOT_SET/RANGE/UNKNOWN_COMPUTED_WRITE + applies_to_all_slots; resolver kinds imm/literal/not_found/unknown with reason |
| interproc_writes.py | CSD (one-hop arg writes) | none | INTERPROC_EXACT_WRITER only; an unresolved result is dropped silently |
| capstone_sweep.py | XC | none | none surfaced (silent instruction caps) |
| raw_scan.py | raw scan / XC leg | none | `landed_in_known_function`/`matches_known_function` flags |
| slot_dispatch.py | Thumb pattern scan | slot_dispatch_sweep v2 (lines 110-111) | none (pattern-matched; caveat in docstring only) |
| indirect_resolve.py | shape decode + table scan + concrete observation harness | none | shape `unknown`; scenario exceptions printed only |
| fingerprint.py / reference_normalize.py / reference_match.py | Capstone-text normalization for matching | none | tiers; is_ambiguous; NO_MATCH "no decodable instructions" |
| build.py / dynamic_ingest.py / hardware_snapshot.py | NORM (Ghidra, Unicorn) | ghidra_version recorded in the firmware row only | scan_warnings categories; init_status complete/partial-justified/blocked; assumptions_json |
| macaw_compare.py | cross-engine comparison | none | categories including both_unresolved (counted inside exact_agreement); no_ghidra_evidence |
| reachability / components / features / residual_priority / firmware_diff / semantic_packets / state_map | aggregation over the DB | none | NO_KNOWN_PATH (not a negative proof); NO_KNOWN_WRITER; truncated flags in packets |

## Census subcommand map

All subcommands are defined in `aptrace_census.py` main() (lines 1011-1172).

| Subcommand | Handler | Implementing module(s) |
|---|---|---|
| build | cmd_build (75) | build.build |
| reduce | cmd_reduce (80) | reduce.reduce_firmware |
| summary | cmd_summary (87) | inline SQL + residual_priority.residual_function_ids |
| function | cmd_function (240) | inline SQL |
| callers | cmd_callers (274) | inline SQL |
| callees | cmd_callees (291) | inline SQL |
| readers | cmd_readers (323) | inline SQL (_mem_access_rows) |
| writers | cmd_writers (337) | inline SQL |
| peripheral | cmd_peripheral (353) | inline SQL |
| pin | cmd_pin (377) | inline SQL |
| uncovered | cmd_uncovered (397) | inline SQL |
| indirect-edges | cmd_indirect_edges (411) | inline SQL |
| warnings | cmd_warnings (455) | inline SQL |
| ingest-dynamic | cmd_ingest_dynamic (474) | dynamic_ingest.ingest_dir / ingest_file |
| reachable | cmd_reachable (488) | inline SQL |
| residual | cmd_residual (506) | residual_priority.residual_function_ids + SQL |
| components | cmd_components (542) | inline SQL |
| library-matches | cmd_library_matches (565) | inline SQL |
| hardware-snapshot | cmd_hardware_snapshot (585) | inline SQL |
| residual-ranked | cmd_residual_ranked (630) | inline SQL + residual_priority.TIER_LABELS |
| residual-components | cmd_residual_components (672) | inline SQL + residual_priority.tier_for/TIER_LABELS |
| hardware-contract | cmd_hardware_contract (771) | inline SQL (contract produced by cases/performing-rigs/config/hardware_contract.py during reduce) |
| diff | cmd_diff (788) | firmware_diff.diff_firmwares |
| reference-corpus fetch/build | cmd_reference_corpus (837) | cases/performing-rigs/scripts/reference_corpus.py (case module) |
| reference-match | cmd_reference_match (848) | reference_match.compute (+ aptrace_ghidra.firmware_info) |
| reference-matches | cmd_reference_matches (860) | inline SQL |
| reference-unmatched | cmd_reference_unmatched (996) | inline SQL |
| semantic-packets | cmd_semantic_packets (904) | semantic_packets.export_packets |
| state-map | cmd_state_map (913) | state_map.build_state_map, probe_dispatcher, summary_rows |
| fnptr-seeds | cmd_fnptr_seeds (959) | fnptr_resolve.resolve_function_pointers, seed_targets (+ aptrace_ghidra.seed_file) |

Standalone CLIs not wired into aptrace_census.py: `build.py` main (359), `reduce.py` main (323), `dynamic_ingest.py` main (145), `indirect_target.py` main (664, read-only URI), `callback_provenance.py` main (641, read-only URI), `macaw_compare.py` main (1227), `slot_dispatch.py` main (123, image-only, no DB).

## Observed behaviors

- The census DB is one SQLite file with rows scoped by firmware_id. The default path is inside the Performing Rigs case (db.py:20).
- Every connection runs the full schema DDL and the column migrations, including connections opened "read-only" with create=False (db.py:37,48-50,70-75).
- Only indirect_target.py and callback_provenance.py open the DB with SQLite mode=ro (indirect_target.py:681, callback_provenance.py:657); test_fnptr_resolve.py does too (test_fnptr_resolve.py:224).
- A static rebuild deletes every per-firmware row in child-first order, including dynamic coverage and reduction tables (db.py:139-152; build.py:107).
- Reduce clears only reduction-layer tables before recomputing (db.py:130-136; reduce.py:234).
- The child-first delete lists omit state_map_* tables even though those tables reference functions(id) (db.py:89-114; schema.sql:896,942-943).
- Per-table writes use delete-then-insert per firmware (db.py:155-171).
- Ghidra static_export/census_export JSON is normalized into functions/basic_blocks/edges/memory_accesses/mmio_accesses/literal_refs/strings (build.py:110-199).
- Ghidra stack-space data references are dropped (build.py:170-184).
- The vector table is read from raw bytes at offset 0 with ARMv7-M layout and a caller-supplied IRQ count (raw_scan.py:28-71; build.py:203).
- Flash words outside function bodies are scanned for Thumb pointers to known entries (raw_scan.py:74-124).
- The Capstone Thumb sweep from Ghidra entries and vector targets produces edges inserted as resolved=1, source 'capstone-sweep' (capstone_sweep.py:39-108; build.py:224-237).
- Disagreements are recorded as scan_warnings: capstone target outside Ghidra blocks, vector outside known function, unresolved MMIO, unowned executable bytes (build.py:283-356).
- MMIO addresses are resolved and PORT pin evidence is derived through the case SAMD51 SVD module (build.py:157,246-268; dynamic_ingest.py:118).
- Dynamic coverage JSON legs are ingested per (firmware, scenario), with idempotent replace (dynamic_ingest.py:49-133).
- Leg firmware keys are inferred by substring match against four hardcoded AutoPilot and Mando keys (dynamic_ingest.py:62-63).
- Indirect-flow sites are classified as STATICALLY_RESOLVED (Ghidra resolved, candidates EXACT), FINITE_CANDIDATE_SET (TBB/TBH or nearby literal table scan, STRONG/WEAK), RESOLVED_RAM_FUNCTION_POINTER (fnptr), DYNAMICALLY_OBSERVED (watch hits) or UNRESOLVED (reduce.py:86-224).
- Register-indirect sites are watched during a full replay of the case scenario corpus by monkeypatching ConcreteMachine.run (indirect_resolve.py:172-231).
- Watched registers are also observed during the boot capture (reduce.py:258-272,180-184).
- Reachability is computed by BFS over Ghidra edges plus indirect candidates. EXACT/STRONG gives DEFINITELY_REACHABLE; any confidence gives POSSIBLY_REACHABLE; otherwise NO_KNOWN_PATH (reachability.py:108-184).
- EXACT/STRONG indirect candidates become reachability roots (reachability.py:61-65).
- The strong reachability graph includes flash-table-scan candidates labeled STRONG (reduce.py:141; reachability.py:122).
- nearest_root fields are populated only for root functions (reachability.py:155-174).
- Cross-image fingerprints: exact byte hash, normalized Capstone token hash, structural similarity, with a same-product suffix from trailing-digit stripping (fingerprint.py:59-237).
- Fingerprinting any firmware recomputes library_matches for all fingerprinted firmware and carries reference confirmations forward (fingerprint.py:202-237; reduce.py:248-249).
- Reference-corpus matching is tiered. Confirmation is set only for non-ambiguous exact or normalized tiers and is propagated into library_matches (reference_match.py:81-226).
- Firmware-side relocation masking is heuristic; reference-side masking uses ELF relocations (reference_normalize.py:32-41,90-106).
- Per-function structural feature rows are aggregated from the base tables (features.py:14-93).
- Reachable functions are grouped by union-find over SCCs, low-fan-in calls, shared peripheral/RAM/pin/string (owner cap 8), common low-fan-out caller, and unbounded dynamic co-execution (components.py:151-302).
- Peripheral registers and per-pin PORT state are persisted from the already-run boot machine, together with disclosed assumptions and interrupt deliveries (hardware_snapshot.py:141-184).
- The residual queue is defined once: reachable, not reference-confirmed, never dynamically covered (residual_priority.py:77-89).
- Residual functions are scored with fixed positive and negative signals; each reason is recorded with its evidence (residual_priority.py:30-269).
- Two reduced firmware images are diffed by registers, MMIO site sets, pin fields, fingerprint-paired residual priority, strings and literal-ref counts (firmware_diff.py:147-179).
- Capped JSONL evidence packets are exported per residual function, joined with a case provenance CSV and case-doc address mentions (semantic_packets.py:89-198).
- State map: per-slot static, dynamic, indexed and interprocedural writer evidence for an arbitrary RAM array, with a writer_status precedence (state_map.py:240-321).
- An optional Unicorn dispatcher probe marks each slot, runs from the dispatcher entry, and records the TX-wrapper stop and output bytes (state_map.py:333-422).
- Register-indexed stores into an array are classified EXACT, FINITE, RANGE or UNKNOWN by bounded same-block and two-hop predecessor patterns (indexed_writes.py:392-488).
- Same-block register resolution covers mov imm, PC-literal ldr, add/sub imm and mov reg chains up to depth 4 (indexed_writes.py:157-206).
- Cross-block resolution accepts a value only when all predecessors agree (indexed_writes.py:212-259).
- The shared resolver treats any instruction with a register first operand as a definition of that register, and does not treat calls as clobbers (indexed_writes.py:145-154).
- One-hop interprocedural writer recovery: callee stores at arg+K, caller argument resolved to a literal; unresolved cases are dropped (interproc_writes.py:107-168).
- Interprocedural argument tracing has no call-clobber check (interproc_writes.py:42-69).
- RAM function-pointer slots are resolved from the consumer load, Ghidra WRITE refs, and constant stored values (intraprocedural, or a callsite argument through a direct bl). Results are graded STRONG/WEAK (fnptr_resolve.py:341-395).
- Thumb pointers are canonicalized while the raw word is kept (fnptr_resolve.py:284-295).
- Unconditional branch forwarding stubs are followed for up to 3 hops, each with up to 2 constant argument loads (fnptr_resolve.py:298-338).
- STRONG fnptr resolutions are written as derived Ghidra seed files for the next Ghidra build (aptrace_census.py:959-993; fnptr_resolve.py:403-415).
- Backward reaching definitions for a reg-indirect branch register are bounded by max_blocks, max_depth and optional work, and are classified into a dataflow pattern with candidate targets and status (indirect_target.py:349-612).
- Every aligned Thumb-looking flash word and every indirect candidate is treated as an indirect block entry, except jump-table words and cases (indirect_target.py:140-174,384-390).
- AAPCS stack arguments are detected only in the entry block from prologue SP deltas (indirect_target.py:307-346).
- vptr installation stores are detected as a flash constant starting a run of at least 2 Thumb pointers stored to [rB,#k] (indirect_target.py:629-661).
- vtable-slot candidates are computed only against caller-supplied vtables and labeled conditional (indirect_target.py:537-548).
- One-hop callback provenance: halfword-sweep direct transfers into the argument entry, verified against census-decoded instructions and cross-checked with census edges (callback_provenance.py:118-270).
- Callback provenance classifies each caller's argument value and declares the target set CLOSED only under complete conditions (callback_provenance.py:476-626).
- Address-taken detection covers flash words, MOVW/MOVT pairs and indirect candidates (callback_provenance.py:186-221).
- Static CFG path existence is checked with a 512-block bound, returning True/False/None (callback_provenance.py:426-443).
- Recorded dynamic coverage per pc by scenario is attached to callback provenance output (callback_provenance.py:461-471,623-625).
- Firmware image sha256 is checked against the census row before analysis; a mismatch is refused (indirect_target.py:561-562; callback_provenance.py:483-484).
- slot_dispatch pattern sweep: every halfword for ldr-slot then bx/blx dispatch within a window, plus BL, B.W, B<c>.W and pointer words to given targets (slot_dispatch.py:70-120).
- Ghidra and Macaw are compared on whole inventory, same-root Ghidra BFS from Macaw's vector roots, calls by block containment, byte coverage, CFG edges, and Macaw's unresolved calls and classify_failures (macaw_compare.py:832-881).
- In macaw_compare, the firmware match check compares only load parameters, not a hash (macaw_compare.py:105-125).
- The query CLI prints mechanical counts and lists. summary encodes the "fingerprint match is not library truth" rule (aptrace_census.py:87-235).
- Framework modules import case modules via sys.path: pins, boot_recipes, reference_library, hardware_contract (config); reference_corpus, virtual_link, dynamic_export (scripts) (aptrace_census.py:60-61; build.py:35,40; dynamic_ingest.py:18-20; reduce.py:60-61,71-76; indirect_resolve.py:189-192).
- Case-specific literals in framework code: four firmware keys (dynamic_ingest.py:62), the case DB path (db.py:20), the provenance CSV and docs paths (semantic_packets.py:34-35), MMIO window constants (state_map.py:364), SAMD51 peripheral names (hardware_snapshot.py:38-39; residual_priority.py:210), and a tuning constant derived from mando868 (components.py:60-67).
- Tests use hand-encoded Thumb fixtures verified against Capstone, plus scratch DBs from the real schema. Real-firmware checks against autopilot868 are skipped when the canonical artifacts are absent (test_census.py:196-249; test_indexed_writes.py:375-415; test_fnptr_resolve.py:217-260).
- test_indexed_writes' real-DB check opens the canonical case DB through the schema-mutating connect (test_indexed_writes.py:377-381).
