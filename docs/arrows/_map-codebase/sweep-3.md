# Sweep 3 — agent-side analysis operations and investigator

Scope: `agent/src/aptrace_agent/` (22 listed modules) and `agent/tests/` (14 listed
test files + `tests/data/`). Every listed file was read in full. Paths are relative
to the repo root. Line numbers are from the working tree on branch
`feat/pcode-indirect-target` (2026-10-15).

Context reads outside scope (for the operation registry only, not reported per
file): `agent/src/aptrace_agent/research/controller.py` lines 28-50, 1340-1420,
1880-1960 (planner action names and the experimental gate), `grep` for which
modules reference each executor tool name, and `ls` of a few case paths named by
the wiring.

---

## Source modules

```yaml
- path: agent/src/aptrace_agent/__init__.py
  purpose: Package marker.
  exports: none (file is empty, 0 lines)
  dependencies: none
  data_shapes: none
  side_effects: none
  role: package init
  observations: Empty; nothing re-exported at package level.

- path: agent/src/aptrace_agent/call_observation.py
  purpose: Adapter for the observed_call_arguments operation — concrete Unicorn replay of one registered case scenario reporting which argument values reach one function through which call sites.
  exports:
    - constants ANALYSIS_NAME="observed_call_arguments", ANALYSIS_VERSION=2, TIMEOUT_SECONDS=300, DEFAULT_SCENARIO="boot", MAX_WATCH_FIELDS=8, MAX_WATCH_BYTES=16, CALLER_GROUNDED="CALLER_GROUNDED_CONCRETE", SCENARIO_KINDS
    - ObservationInputError(ValueError)
    - pydantic ArgumentValue, CallSiteObservation, ObservedCallArguments
    - validate_request(function) -> (name, entry)
    - validate_scenario(scenario, supported) -> str
    - validate_watch(watch, ram) -> list[dict]
    - ObservedCallArgumentsRunner (supported_scenarios, scenario_note, observe)
    - planner_summary(result) -> str
  dependencies: stdlib hashlib/json/re/subprocess; pydantic. No aptrace imports. Subprocess target is injected (`python`, `script`) — in production structural_wiring binds tools/unicorn/.venv python + cases/performing-rigs/scripts/observe_call_arguments.py (case script). Provenance string names tools/unicorn/concrete.py.
  data_shapes:
    - consumes harness JSON doc: {status, scenario, firmware_sha256, scenario_config{kind, registry_sha256}, scenario_failure, recipe{reference_key,gaps,assumptions}, run{instructions_executed,...}, legs[{leg,entry,fresh,observed,seeds,reg_seed,stub_calls,forced}], observation{analysis,analysis_version,observed_entries,call_sites[{call_site,call_kind,hits,arguments{reg:[{value,region,count,pointee_word,pointee_word_region}]}}]}, mmio_in_extent{extent,access_count,accesses,log_truncated}, watched_fields{fields[...],complete,dropped_writes}, correlation[...]}
    - produces ObservedCallArguments{status, function, entry, basis, scenario, scenario_config, scenario_failure, observed_entries, call_sites[CallSiteObservation{call_site,caller,status OBSERVED|UNOBSERVED|DYNAMIC_ONLY,call_kind,static_target_match,hits,arguments}], mmio_in_function, run, legs, watched_fields, correlation, harness_assumptions, coverage, provenance, planner_summary}
    - argv: [python, script, --firmware-key K, --entry 0x.., --scenario S, (--extent a:b), (--watch addr:size[@base])*]
  side_effects: reads firmware image (hash check); subprocess.run with 300 s timeout (default runner).
  role: analysis operation adapter (concrete execution, Unicorn)
  observations:
    - Operation identity ANALYSIS_NAME/VERSION at :34-35 (v2 = scenario-aware).
    - Function identity regex FUN_([0-9a-f]{8}) at :46 — lowercase only, 32-bit address assumption.
    - Default RAM window (0x20000000, 0x30000) at :232 — SAMD51-specific default in framework-ish code; production passes the case window.
    - SCENARIO_KINDS :49-52 hardcodes the case's two registry kinds ("boot-recipe", "virtual-link") with case-specific descriptions.
    - _short_register :55-64 assumes SVD alias naming "SERCOM2.I2CM.CTRLA/..." (ATSAMD51 style).
    - static_target_match := call_kind == "BL" at :364 — ARM/Thumb mnemonic baked into interpretation.
    - Planner summary only renders r0 (:454, :485) — ARM AAPCS first-arg register hardcoded.
    - Static callers come from Ghidra export (heuristic); DYNAMIC_ONLY when a reached site is not in that list (:362).
    - Legacy compatibility: doc without scenario registry treated as boot-recipe (:389-390).
    - Firmware/scenario mismatch in returned doc raises RuntimeError (:300-304) rather than returning a status.
    - Engine string in provenance hardcodes "tools/unicorn/concrete.py" (:311).

- path: agent/src/aptrace_agent/callback_provenance.py
  purpose: Adapter for callback_argument_provenance — one-hop caller-argument provenance for one census register-indirect site whose target is an incoming argument.
  exports: ANALYSIS_NAME="callback_argument_provenance", ANALYSIS_VERSION=1, TIMEOUT_SECONDS=120, STATIC_ONE_HOP="STATIC_ONE_HOP_CALLER_ARGUMENT"; CallbackProvenance (pydantic); CallbackProvenanceRunner(.sites, .trace); planner_summary; re-exports IndirectTargetInputError (__all__ :36).
  dependencies: aptrace_agent.indirect_target (IndirectTargetInputError, census_register_indirect_sites, validate_site); stdlib hashlib/json/subprocess; pydantic. Production subprocess target is tools/census/callback_provenance.py (bound in structural_wiring).
  data_shapes:
    - argv [python, script, firmware_key, --db, db, --site 0x........]
    - consumes stdout {"sites":[{site, firmware_sha256, instruction, target_register, containing_function, site_pattern, site_derivation_status, provenance_status, target_set, argument_origins, candidate_targets, non_callable_values, next_hops, caller_value_statuses, open_reasons, incomplete_reasons, recorded_coverage, limitations, analysis, analysis_version, site_analysis, bounds, work}]}
    - produces CallbackProvenance{status, site, basis, ..., provenance{analysis, analysis_version, engine{...}, firmware_sha256, callers, blocks}}
  side_effects: reads firmware image; opens census sqlite read-only (via census_register_indirect_sites) to enumerate allowed sites; subprocess 120 s.
  role: analysis operation adapter (Capstone/census static dataflow)
  observations:
    - Docstring :9 explicitly "constants are checked as Cortex-M Thumb code pointers"; provenance :165-167 names "direct BL/B.W/B<c>.W/B transfers decoded by a halfword sweep" — ARM Thumb-specific backing tool.
    - Site allow-list = census reg-indirect sites; cached once per runner (:96-100).
    - Engine sub-identity carries site_analysis (indirect_target version) from the tool (:161-163).
    - Value statuses CONCRETE / FINITE_TARGET_SET / FORWARDED_ARGUMENT / MEMORY_DEPENDENT / UNKNOWN; target set CLOSED only if no other entry known (docstring :7-12).
    - Backed by legacy Capstone-operand dataflow in tools/census/ (per CLAUDE.md, migration target).

- path: agent/src/aptrace_agent/case_evidence.py
  purpose: Bounded read-only lexical search over the Performing Rigs case docs/research files (search_case_evidence).
  exports: CaseEvidenceMatch, CaseEvidenceSearchResult (pydantic); CaseEvidenceSearch(.search); performing_rigs_case_evidence().
  dependencies: stdlib re, pathlib; pydantic. No case-code import, but hardcodes case paths.
  data_shapes: search(query, max_results 1..20) -> {query, matches[{source (repo-relative), line, kind investigation|generated_evidence|workflow|provenance|status|roadmap|documentation, excerpt, score}], files_scanned, truncated}
  side_effects: filesystem reads (rglob) under allowed case roots; none written.
  role: case-evidence search tool (non-firmware evidence)
  observations:
    - Class docstring :26 "Bounded read-only search over Performing Rigs evidence"; case root hardcoded cases/performing-rigs at :49-51; allowed roots :53-63 (docs, research/generated, research/workflows, research/provenance, status.md, roadmap.md).
    - repo_root default via parents[3] (:46).
    - Scoring boosts :295-305 terms starting fun_/0x and regex p[ab]\d{2} — SAMD port-pin naming (PA/PB) and Ghidra FUN_ naming baked in.
    - Bounds: MAX_FILE_BYTES 5 MB, MAX_QUERY_TERMS 12, MAX_EXCERPT_CHARS 1400, CONTEXT_LINES 2; nearby duplicate collapse :373-392.
    - Symlink escape guarded via resolve + _inside_case_root (:170-173).
    - No provenance block or analysis version in the result.

- path: agent/src/aptrace_agent/census.py
  purpose: Read-only bounded census reader for census_peripheral_usage (per-peripheral MMIO sites, flash address constants, reachability/component overlay) plus Performing Rigs application wiring (SVD loader, AutoPilot census reader).
  exports:
    - ANALYSIS_NAME="census_peripheral_usage", ANALYSIS_VERSION=1, DEFAULT_LIMIT=25, MAX_LIMIT=50, MAX_SITES_PER_FUNCTION=8, MAX_REFS_PER_CONSTANT=8, MAX_WARNINGS=10
    - CensusStatus, ReductionStatus (StrEnum); PeripheralRange (dataclass)
    - pydantic CensusProvenance, MmioSite, ConstantLoad, Reachability, ComponentMembership, PeripheralFunction, UnattributedSite, AddressConstant, CensusWarning, PeripheralUsage
    - clamp_limit, normalize_peripheral
    - CensusReader(.available_peripherals, .peripheral_usage)
    - PERFORMING_RIGS_CASE (Path), performing_rigs_svd(), performing_rigs_census()
  dependencies: stdlib bisect/hashlib/importlib.util/re/sqlite3/struct; pydantic. Dynamically loads case code: cases/performing-rigs/config/svd/resolve_mmio.py via importlib (:812-823, :848) and instantiates module.Samd51Map(ATSAMD51J19A.svd) (:849). Reads census sqlite produced by tools/census/.
  data_shapes:
    - sqlite tables read: firmware, mmio_accesses, functions, literal_refs, basic_blocks, function_reachability, hardware_snapshot_runs, component_members, components, scan_warnings.
    - PeripheralUsage{status, peripheral, diagnostic, peripheral_base/size, totals, functions[PeripheralFunction], functions_truncated, unattributed_sites, address_constants, warnings, warnings_total, limitations, provenance CensusProvenance}
  side_effects: sqlite read-only URI (?mode=ro); reads firmware image and SHA256SUMS.txt; exec of a case Python module at import-time-of-call.
  role: analysis operation adapter (census reader) + case wiring
  observations:
    - Framework/case seam: "Performing Rigs application wiring" section :809-886 lives inside a framework-named module; hardcodes firmware_key "autopilot868" (:874), db path cases/performing-rigs/research/runs/census/census.sqlite3 (:876), image research/firmware/originals/firmware_autopilot868.bin (:878), SVD ATSAMD51J19A.svd (:838).
    - Diagnostic string :413 "peripheral is not a known ATSAMD51 SVD peripheral" — device name in generic reader.
    - Flash word scan :338-343 assumes 4-byte aligned little-endian words ("<I").
    - SVD singleton global :839-851.
    - Status semantics: NO_CODE_REFERENCES vs NO_MATCHING_ACCESSES, explicit "absence bounded to two static methods" limitation (:165-175).
    - Image hash checked before flash scan; scan status recorded in provenance.flash_word_scan.
    - performing_rigs_census imported by executor, structural_wiring and several tests.

- path: agent/src/aptrace_agent/census_graph.py
  purpose: Read-only bounded call-graph questions over the census (census_common_paths): convergence of two function sets, shared RAM state, unresolved frontier, resolved RAM function-pointer edges; helper queries for other readers.
  exports: ANALYSIS_NAME="census_common_paths", ANALYSIS_VERSION=1; bounds MAX_SET_SIZE=16, MAX_HOPS=8, MAX_COMMON=8, MAX_SHARED_STATE=6, MAX_FRONTIER=6, MAX_PATH=6, SHARED_UTILITY_FAN_IN=8; PathStatus; pydantic SetMember, Convergence, SharedState, UnresolvedSite, ResolvedIndirectEdge, CommonPathResult; RESOLVED_INDIRECT_LIMITATION, NO_KNOWN_PATH_LIMITATION; CensusGraph(.function_entry, .common_paths, .downstream, .resolved_indirect_edges, .dispatch_sites, .containing_function, .unresolved_sites, .member, .census_name).
  dependencies: stdlib collections/re/sqlite3/dataclasses; pydantic. Reads census sqlite (tools/census schema). No case import.
  data_shapes:
    - sqlite tables read: firmware, functions, basic_blocks, edges, indirect_edge_candidates, indirect_edge_resolutions, resolved_function_pointers, function_reachability, reachability_roots, vectors, memory_accesses.
    - internal _Graph dataclass (adjacency, fan_in, unresolved, reachability, root_reach, ram_access, dispatch, resolved_indirect).
    - CommonPathResult{status KNOWN_COMMON_PATH|SHARED_UTILITIES_ONLY|NO_KNOWN_PATH|CENSUS_UNAVAILABLE|NO_RESOLVABLE_INPUT, left/right members, unknown_inputs, explored_*, hop_limited, common[Convergence], shared_state, frontier, resolved_indirect_edges, limitations, provenance, planner_summary}
  side_effects: sqlite read-only; graph cached per instance ("loaded once per process").
  role: analysis operation adapter (census graph reader) + shared graph service for usb inventory/effects/observation wiring
  observations:
    - Edge semantics comment :268 "Same edge semantics as tools/census/reachability.py's strong graph" — duplicated logic with a tools/ module (two implementations of the strong graph).
    - Strong edges: edges.resolved=1 AND source LIKE 'ghidra%' plus indirect candidates EXACT/STRONG (:269-285).
    - Vector root labeling :350-356: irq = vector_index - 16 — Cortex-M exception-vector layout assumption.
    - `_resolved_indirect` tolerates older census without resolved_function_pointers (sqlite3.OperationalError → empty) :416-417.
    - containing_function :632-644 is a linear scan over all functions.
    - owner() :250-264 runs a per-address SQL query (N+1 pattern) during build.
    - No UNREACHABLE status by design; NO_KNOWN_PATH explicitly not proof (limitations :139-152).
    - Shared-state channel requires a WRITE on at least one side (:755).

- path: agent/src/aptrace_agent/disassembly.py
  purpose: function_disassembly — decode a Ghidra-bounded function with Capstone in ARM M-class Thumb mode.
  exports: ThumbFunctionDisassembler(.function_disassembly); autopilot_disassembler().
  dependencies: capstone (Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB); aptrace_agent.ghidra_index (GhidraIndex, autopilot_ghidra_index); aptrace_agent.schemas (FunctionDisassembly, Instruction).
  data_shapes: FunctionDisassembly{name, entry, size, architecture, mode, bounds_source, decoder, bytes_requested, bytes_decoded, complete, instructions[Instruction{address,size,bytes_hex,mnemonic,operands}]}
  side_effects: reads entire firmware image at construction; autopilot_ghidra_index checks Ghidra cache freshness (may import tools/ghidra/aptrace_ghidra).
  role: analysis operation (local Capstone decode)
  observations:
    - Hardcoded ISA: Capstone ARM Thumb|MCLASS (:37-40); result labels architecture="ARM Cortex-M4F", mode="Thumb/Thumb-2 M-class" (:92-93) regardless of input.
    - autopilot_disassembler :103-123 hardcodes cases/performing-rigs/research/firmware/vendor-package/firmware_autopilot868.bin and flash_base=0x4000. This is a different path from census.py (research/firmware/originals/...). In this checkout vendor-package/*.bin is gitignored (.gitignore:13) and absent, so autopilot_disassembler() raises FileNotFoundError (:116-117) — EvidenceExecutor() construction depends on it.
    - No firmware hash check on the image (unlike every other adapter); no provenance/version in result.
    - `complete` only means decoded byte count equals requested; Capstone linear sweep stops at first undecodable byte.

- path: agent/src/aptrace_agent/executor.py
  purpose: EvidenceExecutor — deterministic dispatch of named evidence operations to their readers/runners; also executes the one-shot InvestigationPlan.
  exports: EvidenceExecutor(.execute_operation(tool, arguments, evidence_id), .execute(objective, plan), lazy properties value_forward_use, callback_provenance, indirect_targets, observed_calls, effects; attributes ghidra, disassembler, callsite_reader, pin_table_reader, case_evidence, census, graph, usb, source_agreement).
  dependencies: aptrace_agent.case_evidence.performing_rigs_case_evidence; census.performing_rigs_census; disassembly.autopilot_disassembler; planner_summary from call_observation/function_effects/callback_provenance/indirect_target; structural_wiring.performing_rigs_* (function_effects, callback_provenance, indirect_targets, observed_calls, graph, source_agreement, usb_inventory, value_forward_use); ghidra_index.autopilot_ghidra_index; investigation_tools.performing_rigs_callsite_context/pin_table; schemas.
  data_shapes: EvidenceObservation{id, tool, arguments, result dict}; EvidenceBundle{objective, observations}.
  side_effects: constructor eagerly builds Ghidra index (cache freshness check), disassembler (reads image), callsite reader (a second disassembler + second Ghidra index), pin table reader, case evidence, census reader (loads SVD via case module), graph, USB reader, source agreement closure. Lazy members spawn subprocess runners on use. verbose prints to stdout.
  role: operation dispatcher (application wiring)
  observations:
    - Tool names handled (if/elif :112-236): function_facts, function_disassembly, callsite_context, pin_table_entry, search_case_evidence, census_peripheral_usage, census_common_paths, census_usb_inventory, structural_source_agreement, function_effects, observed_call_arguments, indirect_call_target, callback_argument_provenance, value_forward_use; else ValueError.
    - Entirely single-case wired: every reader is a performing_rigs_*/autopilot_* factory (:43-53); no firmware/case parameter.
    - performing_rigs_callsite_context() constructs its own autopilot_disassembler(), so the image and Ghidra index are loaded twice (:44-47).
    - Planner summaries are attached by the executor for four tools (:204, :213, :218, :223) but value_forward_use attaches its own inside the runner and structural_source_agreement returns a dict with planner_summary.
    - callsite_context before/after default 8 here; pin_table_entry index int().
    - execute() only runs function_facts and function_disassembly from the plan (:263-322); evidence ids E1.. local.
    - census_peripheral_usage uses model_dump(mode="json"); function_facts/disassembly use plain model_dump().

- path: agent/src/aptrace_agent/function_effects.py
  purpose: Adapter for function_effects — Macaw discovery + Crucible simulation (RAW) plus What4/Z3 queries (SOLVER) over one function via the Haskell `aptrace function-effects` binary, with on-disk cache.
  exports: ANALYSIS_NAME="function_effects", ANALYSIS_VERSION=1, MAX_SPECIALIZATIONS=2, TIMEOUT_SECONDS=300, SPECIALIZABLE=("r0","r1","r2","r3"); EffectsInputError; pydantic AccessFact, SpecializedFact, FunctionEffectsResult; validate_request; FunctionEffectsRunner(.analyze); planner_summary.
  dependencies: stdlib hashlib/json/re/subprocess; pydantic. Production binary: external/macaw/dist-newstyle/.../aptrace (bound in structural_wiring; override APTRACE_HASKELL_BIN).
  data_shapes:
    - argv [binary, "function-effects", image, 0xENTRY, (rN=0x..)*, out=PREFIX]
    - reads PREFIX.raw.json {status, macaw_blocks, counts, inputs_referenced, regions[{region,base,size}], accesses[{kind,pc,width_bytes,address{concrete,expr,free_vars},served_from_concrete_readonly,is_stack_block,guard}], calls[{pc,target_concrete,args_concrete}], return_r0, assumptions}
    - reads PREFIX.enriched.json {solver_derived_facts{accesses[{index, region_membership_under_guard, guard_status, specializations[{additional_assumption, address_uniqueness, guard_status}]}], return_r0{bit_valued}}, query_log}
    - writes PREFIX.failed.json {status, summary} on timeout/failure
    - FunctionEffectsResult{status, function, entry, coverage complete|bounded:..., specialize, blocks, inputs_used, reads, writes, calls, accesses[AccessFact], return_depends_on, return_bit_valued, specialized[SpecializedFact], harness_assumptions, raw, solver, provenance, planner_summary}
  side_effects: reads image; creates cache dir; subprocess 300 s; writes failed-cache marker files; binary writes raw/enriched files into the cache.
  role: analysis operation adapter (Macaw/Crucible/What4)
  observations:
    - ARM-specific: SPECIALIZABLE r0..r3 (:20), return value "return_r0" (:319-320); "arg_"/"in_" free-var prefixes stripped (:266).
    - Negative caching: a failed/timeout result is cached forever per (sha16, entry, specs) key (:173-180) — "deterministic" assumption; cache key does not include binary identity.
    - Cache key uses only first 16 hex chars of firmware sha (:166).
    - MMIO window from raw output must equal configured census geometry else RuntimeError (:259-262).
    - Coverage becomes "bounded" when computed control transfers are modeled as opaque calls (:331-337).
    - Production cache dir is cases/performing-rigs/research/runs/function_effects (case research state written by an agent run).
    - Provenance records raw/enriched artifact paths (absolute local paths) :222-223.

- path: agent/src/aptrace_agent/ghidra_index.py
  purpose: In-memory index of a Ghidra static export (function_facts: callers/callees, entry, size) and the Ghidra-cache freshness gate.
  exports: DEFAULT_MAX_EDGES=25; RejectedCallEdge (dataclass); GhidraIndex(.rejected_edges, .function_facts); AUTOPILOT_GHIDRA_KEY="autopilot868"; GhidraCacheStale; ghidra_cache_identity(key); ghidra_cache_paths(key); autopilot_ghidra_index().
  dependencies: aptrace_agent.schemas (CallSite, FunctionFacts); sys.path injection + import of tools/ghidra/aptrace_ghidra (:229-239) using its cache_status, read_meta, firmware_info, sha256_of, BUILD_SCRIPTS, SCRIPTS_DIR, _file_identity_hash (private), seed_file, cache_dir.
  data_shapes:
    - consumes static_export.json (walked generically for dicts with name/entry, size/thunk, fromFunction/toFunction/from)
    - FunctionFacts{name, entry, size, callers[CallSite], callees[CallSite], unique_caller_count, callsite_count, unique_callee_count, outgoing_callsite_count, callers_truncated, callees_truncated}
    - cache meta dict (firmware_sha256, script_sha256:*, derived_seeds_sha256, processor, cspec, load_base, ...)
  side_effects: reads JSON export; mutates sys.path; calls into tools/ghidra cache_status (may invoke analyzeHeadless discovery; catches SystemExit when not installed).
  role: Ghidra structural reader + cache identity gate
  observations:
    - Generic recursive _walk over the whole export (:39-47) — any dict with matching keys becomes a function/edge record.
    - Labeled functions canonicalized to FUN_<entry> (:62-70); FUN_ names use 8-hex-digit format.
    - Edges whose call site lies outside the caller's [entry, entry+size) are rejected and recorded (:97-111) — heuristic boundary filter.
    - ghidra_cache_identity :242-280 reimplements part of cache_status when Ghidra not installed, reaching into private ag._file_identity_hash — tight coupling to tools/ghidra internals.
    - Stale cache refused with remediation hint "run tools/ghidra/aptrace_ghidra.py rebuild {key}" (:276-277).
    - Default key "autopilot868" (:222) used by default args everywhere.
    - Docstring :298-299: legacy one-shot export under research/runs/ghidra/ no longer read.

- path: agent/src/aptrace_agent/indirect_target.py
  purpose: Adapter for indirect_call_target — static intraprocedural reaching-definitions shape for one census register-indirect site, with vtable candidates from constructor vptr installations.
  exports: ANALYSIS_NAME="indirect_call_target", ANALYSIS_VERSION=1, TIMEOUT_SECONDS=120, STATIC_DERIVATION="STATIC_INTRAPROCEDURAL_DERIVATION"; IndirectTargetInputError; IndirectCallTarget (pydantic); validate_site; census_register_indirect_sites(db, key); IndirectTargetRunner(.sites, .resolve); planner_summary.
  dependencies: stdlib hashlib/json/re/sqlite3/subprocess; pydantic. Production script tools/census/indirect_target.py (+ fnptr_resolve, indexed_writes, indirect_resolve as declared inputs in structural_wiring).
  data_shapes:
    - argv [python, script, key, --db, db, --site 0x........, --vtables-from-installations]
    - consumes {"sites":[{site, firmware_sha256, mnemonic, target_reg, containing_function, pattern, derivation_status, resolution_status, patterns[...], candidate_targets[{target,is_code_pointer,vtable,basis,...}], vtables_supplied, limitations, analysis, analysis_version, bounds}]}
    - produces IndirectCallTarget{status, site, basis, instruction, target_register, containing_function, pattern, derivation_status, resolution_status, patterns, candidate_targets, vtables_considered, limitations, provenance, planner_summary}
  side_effects: sqlite read-only (site list, query instr_shape='reg-indirect'); reads image; subprocess 120 s.
  role: analysis operation adapter (legacy Capstone census dataflow)
  observations:
    - Wrapper version 1 while the backing tool reports its own version (test doc uses analysis_version 1; callback test uses site_analysis indirect_target v2) — two version axes, wrapper and engine.
    - Site regex :34 accepts 1-8 hex digits with optional 0x (32-bit addresses).
    - census_register_indirect_sites uses f"file:{db_path}?mode=ro" (:79) — unlike census.py's resolve().as_uri() form; a path with special URI chars would differ.
    - Planner summary :239 "r{arg}" if arg < 4 else stack — AAPCS r0-r3 argument convention baked in.
    - Patterns vtable-slot/object-table-slot/object-field/argument/constant-slot/indexed-table (:229-246).
    - Branch name feat/pcode-indirect-target and CLAUDE.md mark this path for p-code v3 replacement; no p-code variant present in this module.

- path: agent/src/aptrace_agent/interface_inventory.py
  purpose: census_usb_inventory — bounded structural USB inventory from census, SVD interrupts, image vector table, flash descriptor scan and census strings.
  exports: ANALYSIS_NAME="census_usb_inventory", ANALYSIS_VERSION=1, DOWNSTREAM_HOPS=4, MAX_LISTED=6; pydantic IrqVector, RegisterUser, DescriptorCandidate, StringCandidate, DispatchCandidate, UsbInventory; scan_usb_descriptors(data, flash_base); UsbInventoryReader(.vector_handlers, .inventory).
  dependencies: aptrace_agent.census.CensusReader; aptrace_agent.census_graph (CensusGraph, MAX_HOPS, ResolvedIndirectEdge); stdlib hashlib/re/sqlite3/struct; pydantic.
  data_shapes: UsbInventory{status, register_users, unattributed_sites, irq_vectors[IrqVector{irq,name,handler,census_function_at_entry,inside_census_function,in_census_vector_table}], census_vector_coverage, descriptors, strings, downstream_total, dispatch_candidates, irq_reachable_total, irq_reachable, resolved_indirect_edges, unresolved_total, unresolved_examples, functions, limitations, provenance, planner_summary}; interrupts Mapping[int, (name, owner_peripheral)].
  side_effects: sqlite read-only; reads and hashes firmware image (twice per inventory: vector_handlers and descriptors each call _image()).
  role: analysis operation adapter (structural inventory) + vector-handler helper used by wiring
  observations:
    - Cortex-M vector table layout: NMI slot at word 2 as "default handler" (:183), IRQ slot at 4*(16+irq) (:187), Thumb bit cleared (raw & ~1) (:197) — ISA/arch-specific.
    - vector_handlers assumes the image begins with the vector table (offset 0 == flash_base); also used by structural_wiring to allow function_effects/observation entries.
    - _USB_STRING_RE :26 includes "adafruit|arduino|metro" — board/vendor-specific lexical filter (case knowledge in framework module).
    - Peripheral name defaults to "USB" (:157); `_reg` strips "DEVICE." SVD view (:362-364) — SAMD51 USB register naming.
    - Fixed limit=25 on the underlying peripheral_usage (:202).
    - No USB-specific abstraction for other interfaces despite module name "interface_inventory".

- path: agent/src/aptrace_agent/investigation_tools.py
  purpose: callsite_context (bounded instruction window around an exact address) and pin_table_entry (decoder for an Arduino-style pin-description table) plus case factories.
  exports: CallsiteContext, PinTableEntry (pydantic); CallsiteContextReader(MAX_CONTEXT=16; .context); PinTableReader(MAX_INDEX=127; .entry); performing_rigs_callsite_context(); performing_rigs_pin_table().
  dependencies: aptrace_agent.disassembly.autopilot_disassembler; aptrace_agent.schemas.Instruction; pydantic.
  data_shapes: CallsiteContext{function,address,before,after,instructions[Instruction]}; PinTableEntry{index, table_address, file_offset, raw_hex, group, bit, field_8, gpio PXnn}.
  side_effects: reads firmware image on each pin entry; disassembler construction reads image + Ghidra index.
  role: analysis operations (instruction context; case-specific table decoder)
  observations:
    - PinTableReader docstring :137-145 names FUN_0000d3dc and fields "established by disassembly" — an AutoPilot finding encoded in framework module.
    - performing_rigs_pin_table :257-280 hardcodes vendor-package/firmware_autopilot868.bin path, flash_base 0x4000, table_base 0x14284, stride 0x18 — firmware addresses/geometry in root agent code (CLAUDE.md says these belong in the case). Same vendor-package path absent in checkout.
    - _gpio_name :233-247 maps group 0..25 → PA..PZ — SAMD port naming.
    - No firmware hash check, no provenance in either result.

- path: agent/src/aptrace_agent/investigator.py
  purpose: Entry points for the deterministic one-shot investigation (route → execute → synthesize) and for the autonomous ResearchController-driven investigation.
  exports: InvestigationRun, AutonomousInvestigationRun (dataclasses); run_investigation(question, verbose); run_autonomous_investigation(objective, seed_function, max_steps=12, planner_model, review_model, controller, executor, claim_contract, claim_candidates, followup, history, experimental_tools).
  dependencies: aptrace_agent.executor.EvidenceExecutor; investigation_tools.performing_rigs_callsite_context; aptrace_agent.research (LeadDeriver, LeadFollower, LeadRegistry, ResearchController, ResearchRunResult, ResearchSession, ResearchState); research.followups (FollowUpCandidate, seed_session); research.history.HistoricalOperations; router.route_question; schemas; synthesizer.synthesize; value_forward_use.census_code_pointer_loads.
  data_shapes: InvestigationRun{question, plan, evidence, answer, routing, synthesis_usage}; AutonomousInvestigationRun{objective, seed_function, result, state, evidence tuple, continuity}.
  side_effects: constructs EvidenceExecutor (see executor); synthesize() makes a local LLM call; ResearchController makes planner/review LLM calls; verbose prints.
  role: orchestration entry point (application wiring of controller + executor)
  observations:
    - Default structural_tools tuple hardcoded :228-236: usb_inventory, common_paths, function_effects, observed_call_arguments, indirect_call_target, callback_argument_provenance, *experimental_tools. value_forward_use is only added via experimental_tools and passed again as experimental_tools= (:237) — the opt-in gate (commit 1bdeaef). This list duplicates controller.STRUCTURAL_TOOLS minus EXPERIMENTAL_STRUCTURAL_TOOLS instead of deriving from it.
    - hasattr(executor, ...) guards :239-256 let fake executors omit capabilities.
    - value_origins = census_code_pointer_loads(db, key) computed eagerly from census even when value_forward_use is not opted in (:253-257).
    - Seed function path records function_facts + function_disassembly directly via executor (:191-214).
    - LeadDeriver gets a fresh performing_rigs_callsite_context() (third disassembler/Ghidra index instance) (:182-184).
    - run_investigation raises ValueError when router returns None (:66-70).

- path: agent/src/aptrace_agent/model.py
  purpose: Builds the pydantic-ai OpenAI-compatible chat model for the local endpoint.
  exports: DEFAULT_BASE_URL="http://127.0.0.1:8000/v1", DEFAULT_MODEL="Qwen3-Coder-30B-A3B-Instruct-3bit"; build_model().
  dependencies: openai.AsyncOpenAI; pydantic_ai.models.openai.OpenAIChatModel; pydantic_ai.profiles.openai.OpenAIModelProfile; pydantic_ai.providers.openai.OpenAIProvider; os env.
  data_shapes: env OMLX_BASE_URL, APTRACE_MODEL, OMLX_API_KEY (required).
  side_effects: none at build (client creation only); network at use.
  role: model client
  observations:
    - Refuses non-local endpoints (hostname must be 127.0.0.1/localhost) :24-28.
    - max_retries=0, timeout 120 s; strict tool definitions disabled; single system message; no max_completion_tokens (oMLX quirks).
    - Used only by synthesizer here (research controller uses its own planner client — out of scope).

- path: agent/src/aptrace_agent/router.py
  purpose: Deterministic keyword router from a natural-language question to an InvestigationPlan of function_facts / function_disassembly.
  exports: FUNCTION_RE; route_question(question) -> InvestigationPlan | None.
  dependencies: aptrace_agent.schemas (FunctionDisassemblyArgs, FunctionFactsArgs, InvestigationPlan); re.
  data_shapes: InvestigationPlan (max 3 per list — validation error if >3 functions named).
  side_effects: none
  role: planner (deterministic, one-shot)
  observations:
    - Phrase lists :34-106; incoming, outgoing and metadata queries all map to the same function_facts plan.
    - FUN_ regex case-insensitive here (:12) while other modules require lowercase hex; a mixed-case FUN_ name would route but fail lookup.
    - More than 3 FUN_ names would raise pydantic ValidationError (max_length=3 in schemas) rather than return None.

- path: agent/src/aptrace_agent/runtime_probe.py
  purpose: Model-runtime determinism probe — sends byte-identical chat-completion requests and records whether responses are byte-identical.
  exports: CURRENT="current", EXPLICIT_GREEDY="explicit_greedy", GREEDY_PARAMETERS; build_request; request_bytes; sha256; ProbeCall (dataclass); post(base_url, api_key, body, timeout); run_probe(payload, repeat, send).
  dependencies: stdlib hashlib/json/time/urllib.request/urllib.error/collections.Counter/dataclasses.
  data_shapes: probe result {request_sha256, request_bytes, generation, model, repeat, answered, errors, distinct_responses, byte_identical, modal_response_share, calls[ProbeCall]}.
  side_effects: network POST to {base_url}/chat/completions in post() (no local-only check, unlike model.py).
  role: model-runtime diagnostic
  observations:
    - Comment :24 says CURRENT mirrors "ClaimAuditor.generation()" — implicit coupling to ledger/auditor generation params (temperature 0 only).
    - post() has no localhost restriction (model.py does); caller supplies URL.
    - Not referenced by executor/investigator; presumably wired from a CLI (out of scope).

- path: agent/src/aptrace_agent/schemas.py
  purpose: Shared pydantic schemas for function facts, disassembly, plans and evidence observations.
  exports: CallSite, FunctionFacts, Instruction, FunctionDisassembly, FunctionFactsArgs, FunctionDisassemblyArgs, InvestigationPlan, EvidenceObservation, EvidenceBundle.
  dependencies: pydantic (BaseModel, Field, SerializerFunctionWrapHandler, model_serializer).
  data_shapes: EvidenceObservation{id, tool, arguments, result, reused_from?}; reused_from omitted from serialization when None (:88-95) to keep historical serialized forms unchanged.
  side_effects: none
  role: schema
  observations:
    - InvestigationPlan "Created by APTrace code, never by the model" (:62-66); max_length=3 per list.
    - EvidenceObservation.result is an untyped dict — per-tool shapes are not schema-validated at this layer.

- path: agent/src/aptrace_agent/source_agreement.py
  purpose: structural_source_agreement — compares independent code-discovery sources (census DB, Ghidra export, Macaw census) at bounded addresses and classifies agreement.
  exports: AgreementStatus, EvidenceRelation (StrEnum); RELATION map; AGREEMENT_SEMANTICS; SourceObservation, StructuralSourceAgreement (frozen, extra=forbid); CodeSource Protocol; hx; classify(address, observations); MAX_BLOCKS=64; CensusDbSource, GhidraExportSource, MacawCensusSource; parse_addresses(values, limit=16); ENVELOPE_FIELDS; source_agreement(sources, addresses) -> dict.
  dependencies: stdlib json/sqlite3/enum/pathlib/typing.Protocol; pydantic. Reads census sqlite, Ghidra static_export.json + census_export.json, Macaw `aptrace macaw-census` JSON.
  data_shapes: result dict {status "ok", agreements[StructuralSourceAgreement{address, observations[SourceObservation], recognizing_sources, function_start_agreement, function_range_agreement, block_agreement, status, relation, coverage_gaps, disagreement}], status_counts, sources[{source, version, derived_from, (lineage, firmware_sha256, engine_version, assisted)}], semantics, planner_summary}.
  side_effects: file/sqlite reads only.
  role: cross-source verification operation (used by ledger verification, not offered to planner)
  observations:
    - Independence envelope ENVELOPE_FIELDS :470 (lineage, firmware_sha256, engine_version, assisted) emitted only when a source declares it; none of the three concrete sources here declares them (no lineage/firmware_sha256 attributes), so production output lacks envelope fields.
    - Census source declares derived_from ghidra (set in wiring) — agreement between census and ghidra is not independent; docstring :23-24 says so.
    - Macaw source: discovery seeded only from vector-table roots (:425); refuses a census built for a different image size (:406-407) — size, not hash, is the identity check.
    - Census DB source has no firmware hash check (only key lookup) :260.
    - GhidraExportSource.observe falls back to block membership when no function extent contains the address (:355-360).
    - No ANALYSIS_NAME/VERSION constant in this module; result has no provenance.analysis_version.
    - Off-by-one conventions: census end_addr inclusive (+1 applied :305), ghidra block end inclusive (+1 :375), macaw size-based exclusive.

- path: agent/src/aptrace_agent/structural_wiring.py
  purpose: Performing Rigs application wiring for structural actions — binds census, SVD, firmware, geometry, Haskell binary, Unicorn interpreter/scripts, census tools, Ghidra project and caches to each runner.
  exports: performing_rigs_graph, performing_rigs_usb_inventory, performing_rigs_function_effects, performing_rigs_observation_scenarios, performing_rigs_observed_calls, performing_rigs_callback_provenance, performing_rigs_indirect_targets, performing_rigs_value_forward_use, performing_rigs_source_agreement, macaw_census_path, ghidra_seeds_path; constants REPO_ROOT, UNICORN_PYTHON, OBSERVE_CALLS_SCRIPT, OBSERVATION_SCENARIOS, OBSERVATION_INPUTS, CENSUS_TOOLS, INDIRECT_TARGET_INPUTS, CALLBACK_PROVENANCE_INPUTS, MACAW_CENSUS_DIR, GHIDRA_SEEDS_DIR.
  dependencies: census (PERFORMING_RIGS_CASE, CensusReader, performing_rigs_svd); census_graph.CensusGraph; call_observation.ObservedCallArgumentsRunner; function_effects.FunctionEffectsRunner; callback_provenance.CallbackProvenanceRunner; indirect_target.IndirectTargetRunner; interface_inventory.UsbInventoryReader; value_forward_use (VALUE_FORWARD_USE_INPUTS, ValueForwardUseRunner); lazy imports ghidra_index (ghidra_cache_identity, ghidra_cache_paths), ledger.hashing.file_sha256, source_agreement. Dynamically executes case module cases/performing-rigs/config/performing_rigs.py via importlib (:35-46) for CENSUS_MMIO_*/CENSUS_RAM_*. Binds subprocess targets: tools/unicorn/.venv/bin/python3 + cases/performing-rigs/scripts/observe_call_arguments.py; sys.executable + tools/census/indirect_target.py and tools/census/callback_provenance.py; external/macaw/dist-newstyle/.../aptrace (or APTRACE_HASKELL_BIN); sys.executable + tools/ghidra/pcode_forward_use.py.
  data_shapes: *_INPUTS dicts name→Path (consumed by ledger operations for input-artifact identity hashing); observation_scenarios.json {"scenarios": {id: {kind, firmware_keys, ...}}}.
  side_effects: importlib exec of case config; reads JSON registry; Ghidra cache identity check (may raise GhidraCacheStale); file hashing in source agreement on each call.
  role: application wiring (case ↔ framework seam)
  observations:
    - Module is case wiring but lives at framework root; it is the main recorded seam (docstring :1-8).
    - _case_geometry re-imports performing_rigs.py on every call (_case_mmio_window and _case_ram_window each exec it) :49-60.
    - _analysis_binary picks the lexicographically last glob match (:69-74) — newest ghc version by sort, not by build time; returns /nonexistent/aptrace when absent.
    - REPO_ROOT and _REPO_ROOT duplicated (:32, :119); `import json` repeated inside performing_rigs_source_agreement (:277) though imported at top.
    - function_effects and observed_calls both allow entries = census functions ∪ vector handlers (:104-105, :154-155).
    - observed_calls: static call sites and extent from GhidraIndex.function_facts(max_edges=10_000) (:159).
    - value_forward_use: project dir = Ghidra cache meta parent, project_name "aptrace", program = image file name (:244-253); refuses stale cache.
    - Source agreement seeds: vector handlers → "vector-table", ghidra_seeds JSON → "derived-seed:<role>" (:291-296).
    - OBSERVATION_INPUTS include case files boot_recipes.py, observation_scenarios.json, observe_call_arguments.py, virtual_link.py plus tools/unicorn/concrete.py and call_observation.py (:127-134).
    - Function-effects cache dir is case research state (:112).

- path: agent/src/aptrace_agent/synthesizer.py
  purpose: Single-shot LLM synthesis of an answer from an EvidenceBundle (one-shot investigation path).
  exports: synthesize(bundle) -> (answer, usage); private _synthesizer() lru_cache.
  dependencies: pydantic_ai (Agent, UsageLimits); aptrace_agent.model.build_model; schemas.EvidenceBundle.
  data_shapes: prompt = objective + full bundle JSON.
  side_effects: local LLM call (request_limit=1, per_request_input_tokens_limit=4000).
  role: model client (synthesis)
  observations:
    - Lazy construction so model-free commands don't need the endpoint (:12-14).
    - Free-text output; no claim admission on this path (only used by run_investigation).
    - Whole bundle JSON inlined — 4000-token input cap can be exceeded by large disassembly payloads (failure, not truncation).

- path: agent/src/aptrace_agent/value_forward_use.py
  purpose: Adapter for value_forward_use — Ghidra raw p-code forward use of one instruction-defined value inside its containing function, via tools/ghidra/pcode_forward_use.py.
  exports: ANALYSIS_NAME="value_forward_use", ANALYSIS_VERSION=1, TIMEOUT_SECONDS=300, STATIC_PCODE="STATIC_PCODE_FORWARD_USE"; VALUE_FORWARD_USE_INPUTS {pcode_forward_use_walker: tools/ghidra/scripts/APTracePcodeForwardUse.java, pcode_forward_use_driver: tools/ghidra/pcode_forward_use.py, ghidra_headless_locator: tools/ghidra/headless.py}; LIMITATIONS; ValueForwardUseInputError; ValueForwardUse (pydantic); validate_origin; census_code_pointer_loads(db, key); ValueForwardUseRunner(.trace); planner_summary.
  dependencies: aptrace_agent.ledger.hashing.file_sha256; stdlib json/re/sqlite3/subprocess; pydantic. Subprocess into tools/ghidra/pcode_forward_use.py (which runs Ghidra headless).
  data_shapes:
    - argv [python, driver, "project", image, --sha256, --language <meta.processor>, --cspec <meta.cspec>, --base <meta.load_base>, --project-dir, --project-name, --program, --project-identity <sha of meta.json>, --origin 0x........[:reg], --max-steps 20000]
    - consumes {result{status, engine{name, version, language_id, compiler_spec_id, calling_convention, argument_storage, ...}, program, target{image_sha256}, walker, analysis, analysis_version, walker_sha256, driver_sha256, bounds, results[{origin_address, verdict, complete, escape_kinds, origin_instruction, tracked, origin_value, scope, uses, kills, derivation, incomplete, precision, assumptions, unsupported, work}]}} or {status:"invalid_request", error} with rc 2
    - ValueForwardUse{status ok|unsupported|failed|firmware_unavailable|project_unavailable|engine_unavailable|bounded..., origin, requested_register, basis, verdict NO_ESCAPE_WITHIN_SCOPE|ESCAPE|INCOMPLETE|UNSUPPORTED, complete, escape_kinds, ..., limitations, provenance, planner_summary}
  side_effects: sqlite read-only (code-pointer loads); file hashing; subprocess 300 s (driver copies project to scratch workspace per invocation per docstring :125-127).
  role: analysis operation adapter (Ghidra p-code; the only p-code operation)
  observations:
    - ISA-neutral: language/cspec/base come from the Ghidra cache meta (:182-186); no ISA tokens in adapter or planner summary.
    - census_code_pointer_loads :102-117 selects origins = READ literal refs to flash words that census matches as known-function pointers — feeds controller value_origins.
    - Escape kinds CONTROL_TRANSFER/ARGUMENT/STORE/RETURN_VALUE vs local COMPARE/DEREFERENCE_LOAD/DEREFERENCE_STORE/DEAD (:293-294).
    - Experimental-only for the planner (gate lives in research/controller.py EXPERIMENTAL_STRUCTURAL_TOOLS); the adapter itself is ungated.
    - Firmware hash via file_sha256 (returns None on missing file → mismatch path).
    - Double version axes: wrapper value_forward_use v1, engine pcode_forward_use v1 in provenance.
    - LIMITATIONS :51-58 state MEMORY_ESCAPE over-approximates (stack spills), compare-only = one bit flows, heuristic Ghidra bodies.
```

---

## Test modules

```yaml
- path: agent/tests/test_agent_v0.py
  purpose: Deterministic "Agent v0" tests — planner projection bounds, census-first controller behavior, function_effects runner, census graph common paths, USB descriptor scan and inventory, duplicate/prefill handling. No live model.
  covers: research.projection (PlannerProjection, ProjectionBudget, conclusion), ResearchController decision palette/prompt/compaction/prefill retry/duplicate withholding, FunctionEffectsRunner (validate_request, argv binding, caching, timeout negative cache, MMIO-geometry mismatch, computed-transfer coverage), census_graph.CensusGraph.common_paths (ranking, shared utilities, frontier, NO_RESOLVABLE_INPUT), interface_inventory.scan_usb_descriptors, real-census USB inventory.
  observations:
    - Builds synthetic census DBs from tools/census/schema.sql (:39, :596-653).
    - Real-case tests :729-777 call performing_rigs_census()/performing_rigs_usb_inventory and skip if census/image absent; assert AutoPilot specifics (IRQ 80-83 handlers FUN_0000cc14/ccb6/ccba/ccbe).
    - Planner action names exercised: analyze_peripheral, analyze_usb_interface, find_common_paths, analyze_function_effects, follow_lead, search_case_evidence, finish.
    - Asserts effects tool schema exposes only {function, r0, r1} (:446).
    - Size/plateau thresholds hardcoded (e.g. <7000, <8000 bytes).

- path: agent/tests/test_callback_provenance.py
  purpose: callback_argument_provenance runner, grading/limitations, call-relation extraction, admission, ledger identity/replay/reuse, planner action gating.
  covers: CallbackProvenanceRunner (site allow-list, argv, failure statuses, mismatch refusal), planner_summary, ledger.semantics evidence_grade/evidence_limitations (ONE_HOP, POTENTIAL_TARGET, DISPATCH_NOT_REACHABILITY, CALLER_SET_OPEN, PROVENANCE_BOUNDED), ledger.call_relations.extract_call_facts (DIRECT_CALL vs POTENTIAL_INDIRECT, never ESTABLISHED_INDIRECT), research.admission.admit, ledger.operations DETERMINISTIC_TOOLS/TOOL_INPUTS, HistoricalOperations reuse refusal on input/version drift, controller trace_callback_argument palette/cap (max_callback_traces), fact_derivation._callback_provenance_facts.
  observations:
    - Recorded doc shaped like real 0xee60 result (AutoPilot addresses 0xe8a8/0xec48/0xe882).
    - Real tool test :415-431 runs tools/census/callback_provenance.py on the case census when present.
    - Imports shared helpers from ledger_support and test_research_controller (FakePlannerClient, FakeReconciler).

- path: agent/tests/test_case_evidence.py
  purpose: CaseEvidenceSearch behavior over a synthetic case tree.
  covers: search finds files under allowed roots, excludes files outside the case root, rejects max_results out of range, collapses nearby duplicates.
  observations: Synthetic tree must be laid out as cases/performing-rigs/... because the class hardcodes that path.

- path: agent/tests/test_census.py
  purpose: CensusReader.peripheral_usage correctness, bounds, failure statuses, read-only behavior; provenance flowing into research layer claims/leads.
  covers: census.CensusReader (MMIO sites, address constants, unattributed sites, warnings, limit clamping, census_missing/stale, reduction overlay, missing image, no_matching_accesses, no_code_references, determinism, ro connection, available_peripherals), research LeadFollower/LeadDeriver claim and lead derivation from census results (PROVEN grade, derivation issues).
  observations: Hostile peripheral names (SQL/path) yield unknown_peripheral; DB bytes unchanged. Synthetic catalog uses SAMD51-like addresses.

- path: agent/tests/test_census_planner.py
  purpose: Controller offers census analysis (analyze_peripheral) with an enum of validated peripherals and rejects planner-supplied paths/SQL/limits.
  covers: ResearchController discovery/decision palettes, structural analysis guidance ordering, max_structural_analyses budget, no-census fallback to search_case_evidence, reanalysis retry without the tool.
  observations: Planner extra args (db_path, sql, limit, firmware "mando868") are dropped; executor sees {peripheral, limit:25} only.

- path: agent/tests/test_indirect_call_target.py
  purpose: indirect_call_target runner, grading/limitations, admission, ledger identity/replay/reuse, planner action resolve_indirect_call.
  covers: IndirectTargetRunner/validate_site/planner_summary, evidence_grade (never promote potential target; STRONG only for ESTABLISHED+STATICALLY_ESTABLISHED), limitations (POTENTIAL_TARGET, DISPATCH_NOT_REACHABILITY, INTRAPROCEDURAL, DERIVATION_PARTIAL), admit rejects PATH_EXISTS/UNREACHABLE, TOOL_INPUTS first entry census_db, HistoricalOperations refusal on indirect_target_tool change, controller palette/cap (max_indirect_targets), fact_derivation._indirect_target_facts.
  observations: Real tool test :299-314 on the case census asserts ≥56 reg-indirect sites and the slot-7 vtable thunk at 0xc74c (AutoPilot specifics).

- path: agent/tests/test_investigation_tools.py
  purpose: CallsiteContextReader and PinTableReader unit tests.
  covers: exact-boundary context window, non-boundary rejection, pin-table decode (group/bit/field_8/gpio PA22, address/offset), out-of-range entry rejection.
  observations: Uses fake disassembler and synthetic image; the case factory performing_rigs_pin_table is not exercised.

- path: agent/tests/test_observed_call_arguments.py
  purpose: observed_call_arguments (v1 boot-recipe shape) interpretation, grading/limitations, failure handling, ledger identity/replay/reuse.
  covers: ObservedCallArgumentsRunner OBSERVED/UNOBSERVED/DYNAMIC_ONLY classification, argv tail, planner_summary; evidence_grade for observed vs function_effects specialization (HYPOTHETICAL_SPECIALIZATION, not caller-grounded); limitations HARNESS_ASSUMPTIONS/OBSERVED_CONTEXTS_ONLY/UNOBSERVED_CALL_SITES/OBSERVATION_TRUNCATED; failure statuses (timeout, rc≠0, non-JSON, hash mismatch, missing interpreter); ledger operation_key changes with boot_recipe input; HistoricalOperations analysis-version gate.
  observations: Exports fixtures (IMAGE, IMAGE_SHA, OBSERVATION_ARTIFACTS, FakeHarness, harness_doc, value) reused by test_scenario_observation.

- path: agent/tests/test_resolved_indirect.py
  purpose: Resolved RAM function-pointer edges in the census graph are a distinct edge kind with provenance and do not close other frontiers.
  covers: CensusGraph.downstream, common_paths, resolved_indirect_edges, unresolved_sites (STRONG vs WEAK candidates); real-case USB inventory includes recovered callback body FUN_0000c5cc and edge 0xcc1a; real EIC↔USB common paths stays NO_KNOWN_PATH.
  observations: Real tests depend on case census built with fnptr-seeded Ghidra; skip otherwise. Uses EIC IRQ range 12..27 (SAMD51 numbering) :158.

- path: agent/tests/test_router.py
  purpose: Router routes an incoming-call question and refuses a complex question.
  covers: router.route_question.
  observations: Two tests only; disassembly/metadata/outgoing branches untested here.

- path: agent/tests/test_runtime_probe.py
  purpose: Runtime-probe request hashing and response comparison without a live runtime.
  covers: build_request (CURRENT vs EXPLICIT_GREEDY), request_bytes canonical ordering, run_probe distinct_responses/byte_identical/cached_tokens/generation.
  observations: Numbered "# 24", "# 25" comments refer to an external test plan.

- path: agent/tests/test_scenario_observation.py
  purpose: observed_call_arguments v2 — scenario and watch validation, scenario identity in the ledger, scenario limitations, planner action observe_call_arguments, claim boundaries, canonical argument defaults.
  covers: validate_scenario/validate_watch, virtual-link leg assumptions, BOUNDED grade for unentered, limitations SCENARIO_SPECIFIC/NON_BOOTED_STATE/SCENARIO_FAILED/EXECUTION_BUDGET/WATCH_ABSENCE/WRITE_LOG_TRUNCATED, correlation register naming, scenario-distinct operation keys and reuse, canonical_arguments for function_effects specialize defaults (omitted == {} == None) and legacy key compatibility, FollowUpGenerator performed keys, controller palette (scenario enum, no watch parameter for planner, max_observations cap), admission rejects negatives from finite scenario coverage, scenario_note text, projection.summarize_observation digest, fact_derivation._observation_facts.
  observations: Scenario ids vl-plus/vl-t-status and mando868 firmware key are case-specific; planner cannot pass `watch` (only programmatic callers can) :386.

- path: agent/tests/test_source_agreement.py
  purpose: Structural source agreement classification and file sources; Ghidra index label canonicalization; seeded Ghidra cache identity.
  covers: source_agreement/classify (AGREE, PARTIAL_AGREEMENT, BOUNDARY_DISAGREEMENT, SOURCE_MISSING, CONFLICT; relations), evidence_grade/limitations for structural_source_agreement (SOURCE_AGREEMENT_IS_STRUCTURAL, AGREEMENT_SOURCES_NOT_INDEPENDENT; CONFLICT→UNKNOWN), GhidraExportSource/MacawCensusSource from files (size mismatch → unavailable), GhidraIndex label → FUN_ canonicalization, ghidra_cache_identity staleness on seed change (monkeypatches ag.SEEDS_ROOT), autopilot_ghidra_index recognizing seeded USB targets.
  observations: Cache tests skip unless cases/performing-rigs/research/runs/ghidra_cache/autopilot868/meta.json and ghidra_seeds exist; assert AutoPilot seed set {FUN_0000c724, FUN_0000c5cc}.

- path: agent/tests/test_value_forward_use.py
  purpose: value_forward_use runner, grading/limitations, ledger identity/replay/reuse, planner trace_value_use action and the experimental opt-in gate across controller, investigator and CLI.
  covers: validate_origin/register rejection; argv bound from project identity (language/cspec/base); verdicts NO_ESCAPE_WITHIN_SCOPE (BOUNDED), ESCAPE (PROBABLE), INCOMPLETE/UNSUPPORTED (UNKNOWN); failure statuses (timeout, rc, engine_unavailable, invalid_request→exception, project_unavailable, firmware_unavailable, mismatched image/origin); RV32 fixture proves architecture comes from project; TOOL_INPUTS disjoint from Capstone tools; HistoricalOperations refusal per input; controller gate: ValueError without opt-in, "not experimental" error for non-experimental names, default session neither offers nor executes trace_value_use nor shows its leads; investigator default withholds; CLI --experimental-tool choices; planner cannot widen (register, max_steps, project); cap (max_value_traces); fact_derivation._value_forward_use_facts; end-to-end Ghidra test on fixture project (skipped without Ghidra) checks project unchanged.
  observations: Planner-facing description must contain no ISA tokens (ldr/blx/thumb/r3) :284. Uses tests/data/value_forward_use_fixtures.json and tools/ghidra/fixtures/pcode_forward_use/*.bin.
```

### agent/tests/data

```yaml
- path: agent/tests/data/value_forward_use_fixtures.json
  purpose: Recorded outputs of tools/ghidra/pcode_forward_use.py over the framework's own p-code fixtures, used in place of the driver subprocess.
  contents: 20,605 bytes; top-level keys C1_compare_only, C4_argument_via_move, N1_computed_jump, N6_ambiguous_origin, R1_compare_only; each {doc: {result: {analysis "pcode_forward_use", analysis_version 1, bounds{max_steps 20000}, driver_sha256, engine{name ghidra, version 12.1.3, language_id, compiler_spec_id, calling_convention, argument_storage, return_storage, unaffected_storage, pointer_size, program_counter, stack_pointer, low_bit_code_mode,...}, functions_created, program, results[{verdict,...}], status, target, walker, walker_sha256}}, image}.
  verdicts/images: C1 NO_ESCAPE_WITHIN_SCOPE (thumb_controls.bin, ARM:LE:32:Cortex); C4 ESCAPE (thumb_controls.bin); N1 INCOMPLETE (thumb_negative.bin); N6 UNSUPPORTED (thumb_negative.bin); R1 NO_ESCAPE_WITHIN_SCOPE (rv32_controls.bin, RISCV:LE:32:default).
  observations: Embeds driver/walker sha256 values; a change to the driver/walker does not invalidate these recordings automatically.
```

Other files in `agent/tests/` not in scope but present: `ledger_support.py` (FIRMWARE constant, FakeCodeSource, CODE, FakeExecutor, MutableContext, stack(), irq_handlers) and `work_support.py`, plus ~30 other test_*.py files.

---

## Observed behaviors

- Every subprocess-backed adapter validates the request against an APTrace-owned allow-list before building argv: function FUN_ identity + census/vector-handler entry (call_observation.py:115-121, :256-257; function_effects.py:84-114, :153-154), census reg-indirect site (indirect_target.py:59-72; callback_provenance.py:103), hex origin + register-name regex (value_forward_use.py:90-99).
- Every subprocess-backed adapter checks the firmware image sha256 before running and returns status firmware_unavailable on mismatch (call_observation.py:260-265; callback_provenance.py:106-111; function_effects.py:159-164; indirect_target.py:132-137; value_forward_use.py:172-175).
- Returned documents naming a different firmware hash or a different site/origin/scenario raise RuntimeError instead of returning a status (call_observation.py:300-304; callback_provenance.py:133-137; indirect_target.py:161-165; value_forward_use.py:218-224; function_effects.py:259-262 for MMIO geometry).
- Timeouts become status "bounded: timeout Ns" with "nothing concluded" summaries (call_observation.py:284-287; callback_provenance.py:117-120; function_effects.py:195-203; indirect_target.py:144-147; value_forward_use.py:193-196).
- Non-zero exit becomes status "failed" with the last stderr line (call_observation.py:289-292; callback_provenance.py:122-125; function_effects.py:205-212; indirect_target.py:149-152; value_forward_use.py:206-209).
- function_effects caches raw/enriched engine artifacts and negatively caches failures/timeouts per (sha16, entry, specialization) (function_effects.py:166-180, :202, :211).
- value_forward_use takes language, compiler spec and load base from the Ghidra cache meta, not from code (value_forward_use.py:182-186).
- value_forward_use raises ValueForwardUseInputError when the driver exits 2 with invalid_request (value_forward_use.py:203-204).
- observed_call_arguments classifies call sites OBSERVED / UNOBSERVED / DYNAMIC_ONLY against Ghidra static callers (call_observation.py:339-372).
- observed_call_arguments derives harness assumptions from the boot recipe or from executed virtual-link legs (call_observation.py:401-415).
- observed_call_arguments validates up to 8 non-overlapping RAM watch fields of 1..16 bytes with optional object base (call_observation.py:133-188).
- Census reader opens sqlite with ?mode=ro and refuses stale census (hash mismatch → census_stale) (census.py:256-265, :454-458).
- Census reader scans aligned flash words for peripheral-range constants only for a hash-verified image (census.py:316-347).
- Census reader overlays reachability/components only if the census is reduced (census.py:274-299, :615-626).
- Census graph strong edges = Ghidra resolved edges + EXACT/STRONG indirect candidates + STRONG RAM function-pointer candidates; WEAK not used (census_graph.py:269-285, :406-415).
- Census graph ranks common descendants with fan-in ≥8 as shared utilities last (census_graph.py:530-538).
- Census graph reports unresolved indirect sites in the explored region as frontier; NO_KNOWN_PATH never reported as unreachable (census_graph.py:567-578, :866-867).
- Census graph shared-state channel needs a WRITE on one side (census_graph.py:755-756).
- USB inventory reads IRQ handlers from the image's own vector table, omitting empty and default (NMI-slot) handlers (interface_inventory.py:173-199).
- USB inventory scans flash for standard USB 2.0 device/configuration descriptor byte patterns (interface_inventory.py:118-145).
- Source agreement classifies per address: CONFLICT only if a source affirmatively marks non-code; <2 recognizing sources → SOURCE_MISSING; nested blocks → PARTIAL_AGREEMENT (source_agreement.py:149-228).
- Source agreement accepts 1..16 unique addresses (source_agreement.py:446-462).
- Ghidra index rejects call edges whose site lies outside the caller's extent (ghidra_index.py:97-111, :133-167).
- Ghidra index canonicalizes labeled functions to FUN_<entry> (ghidra_index.py:62-70).
- Ghidra cache freshness check refuses stale/unbuilt caches with GhidraCacheStale; works without analyzeHeadless by recomputing expected identity (ghidra_index.py:242-280).
- Disassembler decodes Ghidra-bounded byte ranges with Capstone Thumb M-class; complete = all bytes decoded (disassembly.py:42-100).
- Callsite context requires an exact instruction boundary and windows ≤16 (investigation_tools.py:37-100).
- Pin table decoder reads 0x18-byte rows at 0x14284 and names PA..PZ pins (investigation_tools.py:163-247, :275-280).
- Case evidence search scores lexical windows, boosts fun_/0x/pa##/pb## terms, collapses nearby hits, and stays inside the case root (case_evidence.py:65-151, :264-307, :373-392).
- Router maps keyword phrases + FUN_ names to function_facts/function_disassembly plans; returns None otherwise (router.py:19-108).
- One-shot investigation: route → EvidenceExecutor.execute → LLM synthesize (investigator.py:52-120; synthesizer.py:32-50).
- Autonomous investigation builds a ResearchSession and ResearchController with a fixed default structural tool list and experimental opt-in (investigator.py:123-282).
- Planner-facing summaries are generated mechanically and attached to results (executor.py:204, :213, :218, :223; value_forward_use.py:262).
- Model client refuses non-localhost endpoints and requires OMLX_API_KEY (model.py:16-28).
- Runtime probe hashes the exact request bytes and compares response hashes across repeats (runtime_probe.py:91-143).
- EvidenceObservation omits reused_from when unset to keep historical serialization stable (schemas.py:88-95).
- Case geometry (MMIO/RAM windows) is read by exec'ing the case's performing_rigs.py (structural_wiring.py:35-60).
- SVD is loaded by exec'ing the case's resolve_mmio.py and instantiating Samd51Map (census.py:812-851).

---

## Operation registry

Executor tool names (the evidence/ledger identities) are dispatched in
`agent/src/aptrace_agent/executor.py:105-236`. Planner action names are declared
in `agent/src/aptrace_agent/research/controller.py` (out of scope; mapping read at
:1355-1357 and :1880-1960). Planner-visible structural tool keys are
`STRUCTURAL_TOOLS` (controller.py:35-43) and the experimental gate is
`EXPERIMENTAL_STRUCTURAL_TOOLS = ("value_forward_use",)` (controller.py:48).

| Executor tool (ledger identity) | Adapter / declared | Planner action name | Backing engine / script | Version | Gating |
|---|---|---|---|---|---|
| `function_facts` | ghidra_index.GhidraIndex.function_facts; executor.py:112 | follow_lead (leads); seed in investigator.py:192 | Ghidra static export (tools/ghidra cache `static_export.json`) | none | always; Ghidra cache must be fresh |
| `function_disassembly` | disassembly.ThumbFunctionDisassembler; executor.py:119 | follow_lead; router plan | Capstone ARM Thumb M-class (local) over Ghidra bounds | none | always |
| `callsite_context` | investigation_tools.CallsiteContextReader; executor.py:128 | follow_lead (callsite leads) | Capstone via disassembler | none | always; ≤16 before/after |
| `pin_table_entry` | investigation_tools.PinTableReader; executor.py:144 | follow_lead (derived leads) | raw image bytes (case table 0x14284) | none | always; index 0..127 |
| `search_case_evidence` | case_evidence.CaseEvidenceSearch; executor.py:152 | search_case_evidence (discovery) | filesystem lexical search of cases/performing-rigs | none | always; max_results 1..20 |
| `census_peripheral_usage` | census.CensusReader.peripheral_usage; executor.py:166 | analyze_peripheral (controller action "analyze") | census sqlite (tools/census) + image flash scan + case SVD | census_peripheral_usage v1 | offered when census_peripherals non-empty; enum of available peripherals; limit fixed 25 by controller |
| `census_common_paths` | census_graph.CensusGraph.common_paths; executor.py:177 | find_common_paths (action "common_paths") | census sqlite strong graph | census_common_paths v1 | structural_tools contains "common_paths" |
| `census_usb_inventory` | interface_inventory.UsbInventoryReader.inventory; executor.py:190 | analyze_usb_interface (action "usb_inventory") | census + SVD interrupts + image vector table + descriptor scan | census_usb_inventory v1 | structural_tools contains "usb_inventory"; once per session (test_agent_v0:783) |
| `structural_source_agreement` | source_agreement.source_agreement via structural_wiring.performing_rigs_source_agreement; executor.py:196 | not a planner action (referenced from ledger semantics/policy/gate/auditor only) | census DB, Ghidra export, Macaw `aptrace macaw-census` JSON | no version constant | used by ledger verification path |
| `function_effects` | function_effects.FunctionEffectsRunner.analyze; executor.py:199 | analyze_function_effects (action "effects") | Haskell `aptrace function-effects` (Macaw + Crucible + What4/Z3) from external/macaw/dist-newstyle | function_effects v1 | structural_tools contains "function_effects"; planner params {function, r0, r1} only |
| `observed_call_arguments` | call_observation.ObservedCallArgumentsRunner.observe; executor.py:207 | observe_call_arguments (action "observation") | Unicorn: tools/unicorn/.venv python + cases/performing-rigs/scripts/observe_call_arguments.py (tools/unicorn/concrete.py, call_observation.py) | observed_call_arguments v2 | structural_tools contains it AND observation_scenarios non-empty; planner params {function, scenario}; watch only programmatic; cap max_observations |
| `indirect_call_target` | indirect_target.IndirectTargetRunner.resolve; executor.py:216 | resolve_indirect_call (action "indirect_target") | tools/census/indirect_target.py (Capstone reaching-defs; fnptr_resolve, indexed_writes, indirect_resolve) | indirect_call_target v1 (engine reports its own) | structural_tools contains it AND indirect_sites non-empty; sites must be in evidence; cap max_indirect_targets |
| `callback_argument_provenance` | callback_provenance.CallbackProvenanceRunner.trace; executor.py:221 | trace_callback_argument (action "callback_provenance") | tools/census/callback_provenance.py (+ slot_dispatch, indirect_target inputs) | callback_argument_provenance v1 | structural_tools contains it AND "indirect_call_target" AND indirect_sites; cap max_callback_traces (2 default per test) |
| `value_forward_use` | value_forward_use.ValueForwardUseRunner.trace; executor.py:226 | trace_value_use (action "value_forward_use") | tools/ghidra/pcode_forward_use.py → Ghidra headless + scripts/APTracePcodeForwardUse.java (raw p-code) | value_forward_use v1 (engine pcode_forward_use v1) | EXPERIMENTAL: offered only when named in experimental_tools (investigator.py:235-237; controller.py:48, :231-236 raises ValueError otherwise; CLI --experimental-tool); also needs value_origins; cap max_value_traces; planner param {origin} only |

Non-evidence capabilities in scope:

- `route_question` (router.py:19) — deterministic one-shot planner producing function_facts/function_disassembly plans; no gate.
- `synthesize` (synthesizer.py:32) — local LLM synthesis; requires OMLX_API_KEY and localhost endpoint (model.py).
- `run_probe` / `post` (runtime_probe.py:76-143) — model-runtime determinism probe; not wired into the executor.
- `ghidra_cache_identity` (ghidra_index.py:242) — freshness gate used by function_facts index, value_forward_use wiring and source agreement.
- `census_code_pointer_loads` (value_forward_use.py:102) and `census_register_indirect_sites` (indirect_target.py:75) — census queries that produce the planner's allowed origin/site enums.

Ledger identity inputs per tool are declared in `ledger/operations.py` TOOL_INPUTS (out of scope); the path dicts feeding it here are `OBSERVATION_INPUTS`, `INDIRECT_TARGET_INPUTS`, `CALLBACK_PROVENANCE_INPUTS` (structural_wiring.py:127-207) and `VALUE_FORWARD_USE_INPUTS` (value_forward_use.py:42-46).
