# Sweep 6 — Ghidra, Unicorn and misc tools

Scope: `tools/ghidra/` (Python, shell, Java scripts, p-code fixtures), `tools/unicorn/` (excluding `.venv/` and `__pycache__/`), `tools/vector_scan.py`, `tools/doctor.sh`. Context docs: `docs/tooling/ghidra-backend.md`, `unicorn-backend.md`, `pcode-forward-use.md`, `pcode-migration.md`.

Files read in full: 27 source/test/doc files, plus `controls.json` (parsed in full). Four `.bin` fixtures were listed, not read.

## Per-file entries

```yaml
- path: tools/ghidra/aptrace_ghidra.py
  purpose: Persistent-project Ghidra backend. One cached, analyzed project per firmware key; queries reopen it read-only or are answered from cached JSON exports.
  exports:
    functions: resolve_headless, sha256_of, firmware_info, cache_dir, seed_file, derived_seeds, _file_identity_hash, expected_identity, read_meta, cache_status, _run_headless, build, ensure_fresh, _query_via_process, decompile, disasm, _load_static_export, _load_census_export, _norm_addr, callers, xrefs, containing, symbol, literal, dump, status, main
    constants: REPO_ROOT, SCRIPTS_DIR, CACHE_ROOT, ANALYSIS_VERSION=1, PROCESSOR="ARM:LE:32:Cortex", CSPEC="default", SEED_VECTOR_WORDS, SEEDS_ROOT, BUILD_SCRIPTS; re-exports CENSUS_RAM_BASE/SIZE, CENSUS_MMIO_BASE/SIZE, FIRMWARE_REGISTRY, NUM_EXTERNAL_IRQ, ghidra_version
    CLI subcommands: build FW | rebuild FW | decompile FW ADDR... | disasm FW START END | callers FW ADDR | xrefs FW ADDR | containing FW ADDR | symbol FW NAME_OR_ADDR | literal FW ADDR [--width 1|2|4|8] [--count N] | dump FW ADDR [--length N] | status [FW]
  dependencies: stdlib (argparse, hashlib, json, re [unused], shutil, struct, subprocess, sys, pathlib); headless.find_headless/ghidra_version; **case import** `performing_rigs` from cases/performing-rigs/config via sys.path insert (L82-86); external analyzeHeadless; Ghidra scripts APTraceSeedVectorTable, APTraceApplyProvenance, APTraceExportStaticAnalysis, APTraceExportCensus, APTraceDecompileFunctions, APTraceDisassembleRange.
  data_shapes:
    produces: <cache>/<key>/meta.json (identity dict, L174-195), static_export.json, census_export.json, _last_decompile.txt, _last_disasm.txt; Ghidra project "aptrace" in the cache dir.
    consumes: case FIRMWARE_REGISTRY entries (rel_path, base, labels_tsv); ghidra_seeds/<key>.json {firmware_sha256, seeds:[{addr}]} (L138-149); provenance TSV.
  side_effects: Writes and deletes (shutil.rmtree L250) under cases/performing-rigs/research/runs/ghidra_cache/<key>/. Subprocess analyzeHeadless. Query outputs are written into the cache dir even for -readOnly queries (L317, L325). Exits the process via sys.exit on errors.
  role: engine adapter / headless driver (project lifecycle + cached query layer)
  observations:
    - L63 CACHE_ROOT is hardcoded under cases/performing-rigs. It is not supplied by a case, although ghidra-backend.md L9-10 says "A case supplies ... cache root".
    - L74 PROCESSOR = "ARM:LE:32:Cortex" and L75 CSPEC = "default" are hardcoded. Language is not per firmware.
    - L82-86 framework module imports case config at import time (recorded seam per pcode-migration.md L89-90).
    - L91 SEED_VECTOR_WORDS = 15 + NUM_EXTERNAL_IRQ is ARMv7-M vector-table geometry.
    - L171-195 cache identity contains firmware sha256, path, load base, processor, cspec, ghidra_version (path-derived, best-effort, can be "unknown"), ANALYSIS_VERSION, seed_vector_words, sha256 of 4 build scripts, provenance TSV sha (or "missing"), derived seeds sha (only when present).
    - L213 staleness is strict dict equality of meta vs expected. Stale caches are refused (L295-297) rather than reused.
    - L218 `_run_headless` parameter readonly_process is unused.
    - L264 derived seeds are passed as a positional pre-script arg (may be empty string).
    - L265 `-analysisTimeoutPerFile 300`. A timeout during auto-analysis is not recorded in meta and not surfaced as incompleteness.
    - L281 meta is recomputed after the build, not captured before it. A script edit made during the build would be recorded as the post-edit hash.
    - L284-285 opens JSON without context managers.
    - L356 callers: "no callers found" is printed when the cached export has none. It is presented as a plain negative with no completeness qualifier (the export covers only Ghidra-discovered references).
    - L386-408 containing() uses entry+getNumAddresses() as a contiguous range. It is a heuristic for non-contiguous bodies, but it does flag "PAST this function's own recorded size".
    - L389-390 docstring references persistent-record-motor-target-mapping.md (case investigation).
    - L466-474 status prints only 3 identity fields.
    - L48 docstring references cases/performing-rigs/docs/investigations/toolchain-cleanup.md, which does not exist in the repo.
    - Docstring usage examples use case keys autopilot868/mando868 and case addresses.

- path: tools/ghidra/headless.py
  purpose: Locate analyzeHeadless and derive the Ghidra version from its resolved path.
  exports: find_headless() -> Path|None; ghidra_version(headless_path) -> str
  dependencies: os, re, shutil, subprocess, pathlib; external `brew`.
  data_shapes: none
  side_effects: subprocess `brew --prefix ghidra` (L27)
  role: engine locator (shared by aptrace_ghidra.py and pcode_forward_use.py)
  observations:
    - L5 "Imports no case module" (true).
    - L17-31 search order: PATH, $GHIDRA_HOME/support, Homebrew libexec.
    - L42-44 version is a regex over the resolved path `ghidra/<ver>/`. It returns "unknown" for non-Homebrew layouts, so the engine version is only best-effort here. The p-code walker records Application.getApplicationVersion() separately.

- path: tools/ghidra/pcode_forward_use.py
  purpose: APTrace-side driver for the p-code forward-use operation. Handles target binding, scratch isolation, request validation, engine identity checks and the verdict policy.
  exports:
    constants: ANALYSIS="pcode_forward_use", ANALYSIS_VERSION=1, SCRIPTS_DIR, WALKER_SCRIPT, DEFAULT_MAX_STEPS=20000, MAX_MAX_STEPS=200000, MAX_ORIGINS=256, TIMEOUT_SECONDS=300, ESCAPE_KINDS, LOCAL_KINDS, verdicts NO_ESCAPE/ESCAPE/INCOMPLETE/UNSUPPORTED
    classes: ForwardUseError, GhidraProject(directory,name,program,identity), FunctionSpec(entry,body), Target(image,image_sha256,language_id,compiler_spec_id,base,project,functions,disassemble; describe()), Origin(address,register), Measurement(wall_seconds,peak_rss_bytes,walker_seconds,extra)
    functions: sha256_file, implementation_identity, _validate, _run_measured, run_forward_use(target, origins, *, max_steps, scratch_root, timeout) -> (doc, Measurement), _check_identity, _engine_unavailable, classify, _parse_function, _parse_origin, main
    CLI: `pcode_forward_use.py {import|project} IMAGE --sha256 --language --cspec --base [--function ENTRY[:LO-HI,...]]... [--disassemble ADDR]... [--project-dir --project-name --program --project-identity] --origin ADDR[:REG]... [--max-steps N] [--scratch DIR]`; prints {"result","measurement"} JSON, exit 2 + {"status":"invalid_request"} on ForwardUseError.
  dependencies: stdlib only; headless.find_headless/ghidra_version; Ghidra script APTracePcodeForwardUse.java. No case import.
  data_shapes:
    produces (request.json to walker): {origins:[{address,register}], max_steps, functions?:[{entry, body?}], disassemble?:[addr]}
    consumes (output.json from walker): {walker, walker_version, engine{...}, program{...}, functions_created, max_steps, results[...], timing_analysis_ms, complete_output}
    result doc: {analysis, analysis_version, walker_sha256, driver_sha256, target{image_sha256, language_id, compiler_spec_id, base, mode, project_identity|functions/disassemble/auto_analysis:false}, bounds{max_steps}, status ok|engine_unavailable, engine, program, walker{name,version}, functions_created?, results[ {walker fields..., verdict, complete, escape_kinds, precision[], unsupported?} ]}
  side_effects: Temp dir (aptrace-pcode-*) under scratch_root. In project mode it copies <name>.gpr and <name>.rep into scratch (L264-271) and the source project is never opened. In import mode it uses `-deleteProject`. Subprocess analyzeHeadless. os.wait4 polling.
  role: p-code analysis driver / verdict policy
  observations:
    - Code is ISA-free. The test enforces this via ISA_TOKENS (test_pcode_forward_use.py L238-258).
    - L159-167 implementation identity records the walker and driver sha256.
    - L170-188 validation covers origin count, step bounds, image sha256 vs target, origin inside [base, base+size), no function creation in project mode, and that the .gpr exists.
    - L241-244 a missing engine yields status "engine_unavailable" with per-origin UNSUPPORTED/ENGINE_UNAVAILABLE.
    - L281 ghidra_install_version is put in measurement.extra (non-deterministic section). The deterministic engine version comes from the walker.
    - L287-288 a truncated walker output (no complete_output) raises.
    - L301-310 the identity check covers program executable_sha256, language_id and compiler_spec_id. It does **not** compare the target base with program image_base.
    - L215 timeout detection re-checks perf_counter after the measurement. A process that exits normally just before the deadline can be reported as a timeout (exit -1). The code is only used in an error message, and output.json still governs.
    - L337-339 an unknown walker use kind raises RuntimeError.
    - L341 complete = not r["incomplete"]. Any incomplete code, including the walker's DERIVATION_RECORD_TRUNCATED (which the walker's detail says leaves the analysis unaffected), makes the result non-complete.
    - L346-362 precision labels MEMORY_FLOW_NOT_FOLLOWED (with regions; stack hint) and ARGUMENT_BY_STORAGE.

- path: tools/ghidra/analyze_firmware.sh
  purpose: One-shot headless import + vector-table seeding + auto-analysis + static export JSON (throwaway project).
  exports: CLI `analyze_firmware.sh FIRMWARE.bin [LOAD_ADDR_HEX=0x4000] [OUT_JSON] [EXTRA_SEED_ADDRS]`; env SEED_VECTOR_WORDS, GHIDRA_HOME.
  dependencies: bash, analyzeHeadless, brew (optional), python3 importing aptrace_ghidra (which imports case config) to compute SEED_VECTOR_WORDS (L47); scripts APTraceSeedVectorTable.java, APTraceExportStaticAnalysis.java.
  data_shapes: produces static-analysis JSON (APTraceExportStaticAnalysis schema)
  side_effects: mktemp project dir (removed by trap), mkdir of output dir; default output under cases/performing-rigs/research/runs/ghidra/<basename>.json (L43).
  role: legacy/alternate headless driver
  observations:
    - L7-10, L82 hardcodes ARM:LE:32:Cortex. The comment cites the case's 0x801c anomaly (trigger-input.md).
    - L37 default load 0x4000 ("AutoPilot/Remote images' flash base"). This is a case-specific default in a root tool.
    - L47 depends transitively on the case config via aptrace_ghidra import.
    - It does not run APTraceExportCensus or APTraceApplyProvenance and records no identity or engine version. Its headless-resolution logic duplicates headless.py and doctor.sh.

- path: tools/ghidra/scripts/APTraceApplyProvenance.java
  purpose: Post-script that renames functions and sets comments from a human-reviewed provenance TSV.
  exports: Ghidra script args `<labels.tsv>` (columns address, name, classification; header row skipped)
  dependencies: GhidraScript, Address, Function, SourceType; java.io.
  data_shapes: consumes TSV; prints "applied N, skipped M"
  side_effects: mutates the program (function names USER_DEFINED, comments). It is persisted in the build project.
  role: engine adapter (labeling)
  observations:
    - L78-80 the comment string embeds case paths (standard-library-provenance.md, function_classification.csv). Case-specific text is written into Ghidra comments by a root script.
    - L9 and L79 reference cases/performing-rigs/docs/investigations/standard-library-provenance.md, which does not exist in the repo.
    - L72-76 a missing function at a TSV address is skipped with a printout (not recorded in any export).
    - L2-4 mention "Adafruit-core/toolchain/library code" (case/platform-specific framing).

- path: tools/ghidra/scripts/APTraceDecompileFunctions.java
  purpose: Dump decompiler C for listed function entries.
  exports: script args `<output.txt> <hexAddr1>[,<hexAddr2>...]`
  dependencies: DecompInterface, DecompileResults, ConsoleTaskMonitor, Function.
  data_shapes: produces text file (header per function: name, entry, size, params, callingConvention; C or "(decompilation failed: ...)")
  side_effects: writes output file
  role: engine adapter (query)
  observations: L59 60 s decompile timeout per function. L50 "No function at" is reported in the text. Records no engine version. Hex-only address parsing.

- path: tools/ghidra/scripts/APTraceDisassembleRange.java
  purpose: Per-instruction listing (address, Ghidra instruction text) for an inclusive address range.
  exports: script args `<output.txt> <hexStartAddr> <hexEndAddrInclusive>`
  dependencies: GhidraScript, InstructionIterator.
  data_shapes: text lines "0x%08x  <insn>"
  side_effects: writes output file
  role: engine adapter (query)
  observations: Lists only already-defined instructions (undefined bytes are silently skipped; no gap marker). L44 uses a fixed 8-hex-digit format.

- path: tools/ghidra/scripts/APTraceExportCensus.java
  purpose: Export basic blocks, block CFG edges (resolved + unresolved computed), and RAM/MMIO data references for tools/census/.
  exports: script args `<output.json> <ramBaseHex> <ramSizeHex> <mmioBaseHex> <mmioSizeHex>`
  dependencies: BasicBlockModel, CodeBlock(Reference)Iterator, FlowType, ReferenceManager, RefType, Listing.
  data_shapes: produces {basicBlocks:[{start,end,functionEntry,functionName}], edges:[{from,to,kind,resolved,fromFunctionEntry,toFunctionEntry,source:"ghidra-basicblockmodel"|"ghidra-instrscan"}], memoryAccesses:[{from,fromFunctionEntry,to,width,direction,source:"ghidra-refmgr"}], mmioAccesses:[same]}
  side_effects: writes output file
  role: engine adapter (census export)
  observations:
    - L106-128 widthFromMnemonic uses ARM/Thumb mnemonic prefixes (ldrsb/strb/ldrb/ldrh/ldrd/ldr/str/vldr/vstr). This is ISA token logic in a root Ghidra script (returns null otherwise).
    - L13-15 the docstring names SAMD51 and the case's resolve_mmio.py.
    - L166, L178, L213 on monitor.isCancelled() the export breaks and still writes a well-formed but truncated JSON with no completeness marker.
    - L183-189 cross-space destinations are skipped silently.
    - L221 computed flows without a resolved destination are emitted as "<kind>-unresolved", resolved:false (explicit incompleteness).
    - Records no engine version, language or program identity (relies on meta.json).
    - The JSON writer is hand-rolled and duplicated with APTraceExportStaticAnalysis.

- path: tools/ghidra/scripts/APTraceExportStaticAnalysis.java
  purpose: Export program metadata, functions, call edges, data references and defined strings.
  exports: script args `<output.json>`
  dependencies: Listing, ReferenceManager, Language, CompilerSpec, MemoryBlock, StringDataInstance, SymbolTable.
  data_shapes: produces {program:{name,languageId,compilerSpecId,imageBase,memoryBlocks[{name,start,end,execute,write}]}, functions:[{name,entry,size,thunk,external}], calls:[{from,fromFunction,to,toFunction}], dataReferences:[{from,fromFunction,to,toLabel,refType}], strings:[{address,length,dataType,value}]}
  side_effects: writes output file
  role: engine adapter (static export)
  observations: Records language and cspec but not the Ghidra version. L145 `cu` is computed and unused. L168 strings loop honors cancellation without a completeness flag. `size` = getNumAddresses (non-contiguous bodies are flattened). ISA-neutral.

- path: tools/ghidra/scripts/APTracePcodeForwardUse.java
  purpose: Ghidra p-code walker for forward use of one value defined by one instruction. It reports uses, kills, derivation and incompleteness, with no verdict.
  exports: script args `<request.json> <output.json>`; WALKER="aptrace-pcode-forward-use", WALKER_VERSION=1, DEFAULT_MAX_STEPS=20000, MAX_PCODE_STATES=4096, MAX_DERIVATION_STEPS=512
  dependencies: Gson (bundled with Ghidra), DisassembleCommand, CreateFunctionCmd, PseudoDisassembler, Application, Language/CompilerSpec/PrototypeModel/VariableStorage, PcodeOp, Varnode, MemoryBlock.
  data_shapes:
    output: {walker, walker_version, engine{name:"ghidra", version, language_id, language_version, compiler_spec_id, calling_convention, pointer_size, low_bit_code_mode, program_counter, stack_pointer, argument_storage[], return_storage, unaffected_storage[]}, program{executable_sha256, image_base, memory_blocks[{name,start,end,permissions,initialized}], function_count}, functions_created[{entry,created,body}], max_steps, results[ {origin_address, origin_instruction, tracked{storage,varnode}, origin_value{kind constant|load|computed, value?, code_address?, function_at_code_address?, source_address?, size?, source_block?...}, scope{kind function|none, function_entry, function_name, body, body_bytes}, status analyzed|unsupported, unsupported_code/detail, uses[{kind,address,instruction,pcode_op,detail,via[],store_target?|callee?}], kills[{address,instruction,storage,by}], derivation[{address,instruction,pcode_index,pcode_op,from[],to}], incomplete[{code,address,detail}], assumptions[], work{steps,max_steps,instructions,budget_exhausted}} ], timing_analysis_ms, complete_output:true}
  side_effects: In import mode it mutates the program (disassemble, create functions L101-110, L169-195); the driver discards it via -deleteProject. Writes output.json.
  role: p-code analysis (walker)
  observations:
    - No ISA tokens in code. L83-92 semantics come from currentProgram language/cspec: default calling convention, potential input register storage, unaffected list, return location for a pointer type, cspec stack pointer, language PC.
    - L141 records PseudoDisassembler.hasLowBitCodeModeInAddrValues, and L358 uses getNormalizedDisassemblyAddress. Thumb-bit handling is delegated to Ghidra.
    - L272-285 default origin storage is pointer-sized registers written, excluding PC/SP. Non-pointer-sized outputs are not candidates (an assumption, reported as NO_VALUE_OUTPUT/AMBIGUOUS_VALUE_OUTPUT).
    - L445-447 delay-slot instructions give DELAY_SLOT_UNSUPPORTED.
    - L405-409 BUDGET_EXHAUSTED. Phase 2 (L419-430) then records from partial fixpoint states.
    - L425-427 NO_INSTRUCTION incomplete is emitted only in phase 2. Phase 1 skips null instructions (L414).
    - L460-462 PCODE_PATH_BOUND; L466 PCODE_BRANCH_OUT_OF_RANGE.
    - L486-497 BRANCHIND with no flows while live gives COMPUTED_FLOW_UNRESOLVED. With flows, the assumption "computed-jump targets are Ghidra's flow references".
    - L498-519 CALL/CALLIND produce ARGUMENT use via cspec argument storage, call clobber of registers outside the unaffected list (L605-614), and a no-return callee ends the path (assumption).
    - L520-527 RETURN produces CONTROL_TRANSFER if the value is the return target, RETURN_VALUE if it is in return storage, and ENDS_AT_RETURN otherwise.
    - L538-551 CALLOTHER gives UNMODELED use + UNMODELED_OPERATION incomplete. The output is still written and propagated as carrying the value.
    - L564-566 predicates (L779-790) consume the value as COMPARE. Other ops propagate (may-flow through all data ops).
    - L582-589 direct writes to a memory-space varnode give a STORE use.
    - L617-644 exit(): leaving the body to a function entry gives ARGUMENT or TAIL_TRANSFER (assumption: tail call); leaving to a non-entry gives FLOW_LEAVES_FUNCTION. With no containing function (body null), only transfers to function entries count as leaving, so the walk is otherwise unbounded except by the budget.
    - L651-676 store target classification is stack (cspec SP + const offset), absolute, or computed, using only intra-instruction p-code.
    - L723-726 DERIVATION_RECORD_TRUNCATED is emitted as an incompleteness entry although its detail says "analysis unaffected". pcode-forward-use.md's code table does not list it.
    - L860-866 output arrays are sorted for determinism. timing_analysis_ms is separated (popped by the driver).

- path: tools/ghidra/scripts/APTraceSeedVectorTable.java
  purpose: Pre-script that seeds function starts from the ARMv7-M vector table, plus extra addresses.
  exports: script args `[numVectors] [extraHexAddrs]` (numVectors is required: 15 + IRQ count)
  dependencies: GhidraScript disassemble/createFunction, Memory, MemoryBlock.
  data_shapes: none (console output)
  side_effects: mutates the program (disassembly + functions) before auto-analysis
  role: engine adapter (platform seed recipe)
  observations:
    - Cortex-M specific by design: L60-71 word 0 = SP skipped, Thumb bit cleared (raw & ~1), 0 and 0xFFFFFFFF skipped, and only targets inside block 0 are kept (L57 uses only getBlocks()[0]).
    - L84-85 extra seed addresses are NOT low-bit-cleared (the doc example "0x8259" is odd).
    - L42-44 a seeding failure is printed and skipped (not recorded).
    - L5-9 "unseeded run found only 204 functions ... 0x8000-0x9700" is case-specific evidence in a root script. The referenced docs/harness/protocol-harness-results.md does not exist (now at cases/performing-rigs/docs/investigations/protocol-harness-results.md).
    - L11-13 references tools/vector_scan.py and the Haskell APTrace.VectorTable as the validated structure.

- path: tools/ghidra/test_aptrace_ghidra.py
  purpose: Regression checks for the persistent cache (build/fresh, query cost, cached queries, staleness detection).
  behaviors covered: build+fresh status; decompile under 8 s after build; cached callers under 1 s; symbol/containing/literal against real case firmware (mando868 0x49c4, 0x58a8, 0x49c0 -> 0x20000b20); a modified build script gives stale; a modified provenance TSV changes identity (autopilot868); a tampered meta.json gives stale and ensure_fresh exits.
  observations:
    - Runs against real case firmware and the canonical case cache. It is not isolated: L38 builds the real cache and L120-136 overwrites the real meta.json (restored without try/finally, so a crash between L124 and L136 leaves a tampered cache).
    - L82 timing thresholds are flake-prone. No synthetic or second-ISA controls.

- path: tools/ghidra/test_pcode_forward_use.py
  purpose: Acceptance coverage for pcode_forward_use.py.
  behaviors covered:
    - fixture sha256 pins (L262-265)
    - verdict policy unit tests (L214-232): complete → NO_ESCAPE, incomplete → INCOMPLETE, an escape stands under incompleteness, stack store → MEMORY_FLOW_NOT_FOLLOWED, unknown kind raises, unsupported mapping
    - static ISA-neutrality check over the walker and driver with comments/strings stripped (L238-258)
    - request validation and the engine-unavailable path (L185-211)
    - controls.json exact expectations across 6 suites: Thumb (11), RV32 (7), Thumb negatives, Thumb budget, RV32 negatives, RV32 budget (L73-98), plus the invariant that NO_ESCAPE implies complete (L95)
    - spike parity (L101-117)
    - determinism: byte-identical canonical docs, no path/timing data (L120-127)
    - project mode on a scratch copy, source tree byte-identical, no lock files, function creation refused, auto-analyzed boundaries never yield a new NO_ESCAPE (L144-182)
  observations:
    - L114 test_spike_parity compares the spike's ground truth to the manifest's *expected* escape_kinds (`o["escape_kinds"]`), not to engine output. It checks that the fixture expectations are consistent with the spike. Engine agreement comes only via test_controls.
    - L240 the ISA_TOKENS regex covers ARM/RISC-V/MIPS/x86 names. Python `str` is exempted.
    - L270 a missing Ghidra returns exit 1 after the static checks.
    - L135-141 builds fixture projects with the test seed pre-script. The subprocess result is not checked (relies on the later .gpr existence check).

- path: tools/ghidra/fixtures/pcode_forward_use/APTracePcodeForwardUseTestSeed.java
  purpose: Test-only pre-script. Disassembles and creates functions at the given entries so a fixture becomes an analyzed project.
  observations: args `<entry>[,<entry>...]`. Body specs like "0xc0:0xc0-0xc7" would fail Long.decode, but project mode only uses suite 0 (thumb_controls), which has plain entries.

- path: tools/ghidra/fixtures/pcode_forward_use/extract_text.py
  purpose: Copy .text of a 32-bit LE ELF object to a raw image. Refuses .rel*text relocations.
  observations: Position-fixed fixtures via .org; build recipe in thumb_negative.s L7-8 (clang thumbv7em).

- path: tools/ghidra/fixtures/pcode_forward_use/rv32_controls.py
  purpose: Hand-encoded RV32I controls R1-R7 (compare-only, call-through, store, argument via move, return, join one-path store, join both killed). Each loads 0x1000 via auipc+lw into a5. Tracked definition at case+4.
  observations: RV32 is the second-ISA control. There is no RISC-V assembler (hand-encoded). Exports encoders used by rv32_negative.py.

- path: tools/ghidra/fixtures/pcode_forward_use/rv32_negative.py
  purpose: RV32 negatives Q1 computed jump, Q2 no function, Q3 loop (budget 2), Q4 truncated body.

- path: tools/ghidra/fixtures/pcode_forward_use/thumb_controls.s
  purpose: Thumb-2 controls C1-C11 (compare-only, blx call-through, store, argument via mov, return, one-path store at join, both-killed join, stack spill+reload+blx, IT-conditional redefinition, tail call with pointer arg, compare-then-loop). CB=0x1001.
  observations: L4 says expectations are in "expected.json". That is the spike file (docs/spikes/architecture-evaluation/experiments/fixtures/expected.json); this directory uses controls.json.

- path: tools/ghidra/fixtures/pcode_forward_use/thumb_negative.s
  purpose: Thumb negatives N1 computed jump bx r2, N2 no function, N3 loop (budget), N4 truncated body, N5 MSR MSP (CALLOTHER), N6 ldrd ambiguous / named r3 / named r2, N7 callee-saved r4 survives bl, N8 ip dies at bl.

- path: tools/ghidra/fixtures/pcode_forward_use/controls.json
  purpose: Exact expectations manifest. 6 suites with image, sha256, language (ARM:LE:32:Cortex/default; RISCV:LE:32:default/gcc), base 0, functions (some with explicit bodies), disassemble seeds, optional max_steps. Origins carry case, origin[:reg], verdict, escape_kinds, incomplete, unsupported, precision, spike_escapes and assessment.
  observations: Notable assessments: C2/R2 sound over-approximation (ARGUMENT_ESCAPE added), C8 sound but imprecise (spill = MEMORY_ESCAPE + MEMORY_FLOW_NOT_FOLLOWED; the reload and blx are not tracked), N8 ABI-dependent.

- fixtures (binary, listed only): thumb_controls.bin (4098 B), thumb_negative.bin (4098 B), rv32_controls.bin (4100 B), rv32_negative.bin (4100 B)

- path: tools/unicorn/concrete.py
  purpose: Reusable Unicorn Cortex-M/Thumb concrete-execution library (ConcreteMachine) with run/call/interrupt delivery, dirty-page reset, and structured results.
  exports:
    constants: REG_BY_NAME (r0-r12, sp, lr, pc, cpsr), NAME_BY_REG, PAGE, DEFAULT_TRACE_LAST=64, PPB_BASE/PPB_SIZE, HARNESS_BASE=0x2FFF0000, HARNESS_SIZE, TRAMPOLINE_BYTES=b"\xfe\xe7"
    functions: align_down, align_up, _ranges_excluding
    classes: Carried(addr,data,source); RunResult(error_free, completed, stopped_at, expect_stop, reg, mem, reg_pointee, carry, to_dict); ConcreteExecutionError(result); CallResult(result, returned, r0-r3, signed); ConcreteMachine(firmware_path, flash_base=0x4000, ram_base=0x20000000, ram_size=0x30000, mmio_base=0x40000000, mmio_size=0x100000, extra_maps, track_dirty) with reset, rebuild, run(...many kwargs...), call(entry,args,...), deliver_interrupt(handler_entry,...)
  dependencies: unicorn (Uc, UC_ARCH_ARM, UC_MODE_THUMB|UC_MODE_MCLASS, hooks, UC_CPU_ARM_CORTEX_M4), unicorn.arm_const, collections.
  data_shapes: RunResult.to_dict {firmware(path), entry, instructions_executed, stop_reason, error, error_free, completed, requested_stop_at, registers, memory, reg_pointee, recent_pcs, visited_pcs, ram_log, applied_seeds[{addr,len,tag}], watch_hits[{hit,instruction,address,registers,memory,reg_pointee?}], mmio_log, stub_hits, mem_write_hits[{range,instruction,pc,lr,address,size,value,previous}], mem_write_dropped, fake_ticks_applied, mmio_force_bits_applied, mmio_clear_bits_applied, force_reg_hits, force_mem_hits}
  side_effects: reads the firmware file; optional stderr trace. Otherwise in-memory.
  role: concrete execution harness
  observations:
    - Architecture-fixed: L432-433 ARM Thumb|MCLASS, Cortex-M4 model. L71-77 ARM register set. L583 the Thumb bit is forced on entry. L689-693 stub = PC:=LR. L894-963 AAPCS call (r0-r3 + stack args, 8-byte alignment). L997 r0-r3/r12 saved for interrupts.
    - Target-specific defaults and commentary: L380-381 defaults are the SAMD51 geometry (flash 0x4000, RAM 192 KB). L88-109 and L393-399 justify HARNESS_BASE by ATSAMD51J19A RAM. unicorn-backend.md L4-6 says it "maps caller-supplied ... geometry without assigning target-specific meaning", but the defaults embed it.
    - Provenance: to_dict records the firmware *path* only, with no firmware hash, Unicorn version, CPU model, memory map or flash base. reg_seed values (L589-593), sp, stub_calls list, stop_at semantics, and the MMIO "zero-behavior" model are not recorded in the result. applied_seeds, force_*_hits, fake_ticks/mmio bit counts are recorded (assumption disclosure is partial).
    - L203-213 completeness split error_free/completed. With no stop_at, a watch-hit cap stop (L696-699) counts as completed.
    - L509-516 reset refuses when track_dirty=False after a run. L520-522 reset zeroes only REG_BY_NAME registers. Other CPU state (CONTROL, PRIMASK, FPU, NVIC internals) is not reset, so isolation is partial for CPU state.
    - L790-807 documents an empirical Unicorn reentrancy hazard (log_ram hooks on addresses hook_code writes) and works around it by splitting ranges.
    - L42-43, L108, L183 reference cases/performing-rigs/docs/investigations/toolchain-cleanup.md, which does not exist. L5 and L360 reference the case's virtual_link.py.
    - L712-714 unmapped access gives stop_reason + UcError. L716-738 MMIO/RAM logs are capped (overflow silently stops logging, with no dropped counter, unlike mem_write_dropped).

- path: tools/unicorn/run_concrete.py
  purpose: CLI over ConcreteMachine.run/call that emits RunResult JSON.
  exports: parse_hexaddr, parse_value, parse_reg_value, parse_addr_bytes, parse_addr_len, parse_reg_len, parse_addr_reg_hexvalue, parse_addr_addr_bytes, parse_addr_hexmask, build_argparser, main. Flags: --firmware (req), --flash-base, --ram-base, --ram-size, --mmio-base, --mmio-size, --entry | --call, --arg*, --sp, --reg*, --seed-mem*, --map-page*, --stop-at*, --max-instructions, --trace, --trace-every, --trace-last, --dump-mem*, --dump-reg-pointee*, --watch*, --watch-mem*, --max-watch-hits, --log-mmio, --max-mmio-log, --log-ram, --max-ram-log, --collect-coverage, --watch-mem-write*, --max-mem-write-log, --fake-tick*, --stub-call*, --mmio-force-bits*, --mmio-clear-bits*, --force-reg*, --force-mem*, --out
  dependencies: concrete (ConcreteMachine, DEFAULT_TRACE_LAST, REG_BY_NAME), argparse, json.
  data_shapes: RunResult.to_dict JSON, plus a "call" block {function, args, returned, return_registers} in --call mode.
  side_effects: optional --out file write; stderr
  role: concrete execution CLI
  observations:
    - Addresses are always parsed as hex (L69-73). Sizes for --ram-size/--mmio-size also go through parse_hexaddr (L176-178), while --map-page/--dump-mem lengths use int(,0).
    - L134 the --sp help text ("top of RAM, minus a small reserved trampoline page") is stale. concrete.py moved the trampoline out of RAM (L102-110).
    - L216-228 in --call mode, --stop-at values are parsed but never passed (stop_at is not in common_kwargs). They are silently ignored.
    - L126-130 defaults are ATSAMD51 geometry. L20, L30 examples use case firmware paths. L137 help references the SAMD51 NVM calibration row.
    - L180 track_dirty=False. Exit 1 on Unicorn error.

- path: tools/unicorn/call_observation.py
  purpose: Deterministic post-processing of concrete-run watch hits and write hits into call-site argument observations, watched-field store events, and call/field correlation.
  exports: ANALYSIS_VERSION=2, ARGUMENT_REGISTERS, Region, region_of, bl_target, classify_return_address, summarize_entry_observations, store_addressing, summarize_watched_writes, correlate_calls_with_fields
  dependencies: stdlib; optional capstone (imported lazily in store_addressing, L202-206).
  data_shapes:
    entry summary: {analysis:"call_observation", analysis_version, entry, observed_entries, call_sites[{call_site, call_kind BL|BLX_REG|OTHER, decoded_target, target_register?, note?, return_address, hits, first_instruction, arguments{reg:[{value, region, pointee_bytes?, pointee_word?, pointee_word_region?, count}]}}]}
    watched writes: {analysis:"watched_writes", analysis_version, fields[{name,address,size,object_base?,events[{leg,instruction,pc,function,address,width,previous,new,changed,first_write,addressing{form base+imm|base+reg|multiple|other|undecoded, instruction?, base_register?, offset?, base_value?, index_register?, object_relative?}}], writes, value_changing_writes, initialization, changed_after_initialization, final_bytes}], dropped_writes, complete}
    correlation: list of {call_site, call_kind, register, value, value_region, pointee_words[{word,region}], field, calls, first_call, last_call, calls_before_initialization, calls_after_a_later_change, field_state}
  side_effects: none (pure)
  role: concrete-observation analysis
  observations:
    - ISA-specific Python decoding: L65-79 Thumb-2 BL T1 immediate decode, L96 16-bit `blx rm` mask 0xFF87==0x4780, L208 Capstone CS_MODE_THUMB|MCLASS, L218 ARM mnemonics (stm, push, strd, strexd, str).
    - Capstone-operand semantics (store addressing form) sit outside tools/census/. CLAUDE.md's freeze rule targets tools/census/ only. The file does not say whether this is a demonstrated gap or a cross-check.
    - When Capstone is absent, store_addressing returns form "undecoded". The capstone presence/version is not recorded in the output.
    - L328 complete = dropped==0 for watched writes. correlate_calls_with_fields carries no analysis_version or completeness field and ignores `dropped_writes`.
    - L9-12, L34-35 explicit "not observed is not impossible" disclosure.

- path: tools/unicorn/test_call_observation.py
  purpose: Regression for call_observation and run(watch_reg_pointee / watch_mem_write) on a hand-assembled Thumb image, round-trip-verified with Capstone.
  behaviors covered: BL decoder forward/backward/non-BL; RAM caller BL attribution and pointee capture with no MMIO log; constant-only load is not an MMIO access; MMIO dereference logged; BLX_REG attribution; pointee capture fires no MMIO hook; tail branch gives OTHER; unmapped pointee gives None; order independence; watched writes (init base+imm object_relative, base+reg indexed, byte store width 1, previous/new, initialization, final bytes, unwritten field); call/field correlation states; write-log truncation gives complete false; write watch is passive (same instructions/registers/memory).
  observations: Thumb only (no second ISA). Requires capstone at import (L21) although call_observation treats it as optional. Uses the venv interpreter. The image is synthetic, with no case data.

- path: tools/unicorn/requirements.txt
  purpose: Pins unicorn==2.1.4 and capstone==5.0.9.
  observations: L2 says capstone is "optional: static disassembly cross-check in trigger_mitigation_prototype.py only" (a case script, cases/performing-rigs/scripts/). That is stale: call_observation.store_addressing and test_call_observation.py also use it, and the test requires it.

- path: tools/vector_scan.py
  purpose: Score candidate Cortex-M vector tables in a raw image and dump the best one.
  exports: read_words, score_candidate, dump_table, main. CLI `vector_scan.py FIRMWARE [--flash-base 0x0] [--flash-size 0x100000] [--ram-base 0x20000000] [--ram-size 0x30000] [--num-irq 32] [--scan] [--scan-limit 0x1000]`
  dependencies: argparse, struct, sys
  data_shapes: text output; exit 1 if no candidate scores >= 4
  side_effects: none
  role: platform seed / prototype tool
  observations:
    - Cortex-M specific: L20-38 handler names and reserved indices; L72-83 Thumb-bit checks. The heuristic scoring threshold is hardcoded at 4 (L159).
    - L4-6 "Standalone Python prototype (Step 4 of the APTrace spike)".
    - L9 docstring usage shows `--flash-base 0x4000`, but L131 defaults to 0x0. L137 ram-size default is SAMD51 "ATSAMD51x20/x19". L138 num-irq default is 32, unrelated to the case's SVD-derived NUM_EXTERNAL_IRQ.
    - Overlaps APTraceSeedVectorTable.java, the case's raw_scan.py (pcode-migration.md L104) and the Haskell APTrace.VectorTable.

- path: tools/doctor.sh
  purpose: Environment check for Ghidra headless, the Unicorn venv/version, and Macaw/Z3/GHC prerequisites.
  exports: CLI, no args; exit 0/1
  dependencies: analyzeHeadless, brew, tools/ghidra/analyze_firmware.sh, python3, tools/unicorn/.venv, run_concrete.py, z3, ghc, cabal, external/macaw/cabal.project
  data_shapes: console
  side_effects: writes /tmp/aptrace_ghidra_doctor.log and /tmp/aptrace_unicorn_doctor.log; mktemp output JSON (removed); runs a full headless analysis of the case firmware if present.
  role: environment doctor
  observations:
    - L2 says "four analysis backends", but L5-7 and the body check three.
    - L17 hardcodes the case firmware path (firmware_autopilot868.bin). L79-82 functional checks use case addresses 0x888c/0x8890 and the "solver-confirmed '&' branch".
    - L72 asserts unicorn.__version__ == '2.1.4' (consistent with requirements). Headless resolution is a third copy of the same logic. It does not exercise pcode_forward_use or the persistent cache.

- path: docs/tooling/ghidra-backend.md (context)
  purpose: Short description of aptrace_ghidra.py. Says the case supplies registry, base, labels and cache root; cache identity; stale rejection.
  observations: The cache root is hardcoded in the module (aptrace_ghidra.py L63), not supplied by the case. Language/cspec are hardcoded constants and are not "load configuration" supplied per firmware.

- path: docs/tooling/unicorn-backend.md (context)
  purpose: Describes concrete.py, run_concrete.py, call_observation.py, and the observed_call_arguments agent operation.
  observations: Lists addressing forms base+imm/base+reg/multiple; the code also emits "other" and "undecoded". The "caller-supplied geometry" claim is undercut by SAMD51 defaults.

- path: docs/tooling/pcode-forward-use.md (context)
  purpose: Spec of the forward-use walker, driver, verdict policy, incompleteness codes, evidence identity, grades, hosting and measurements.
  observations: Incompleteness code table L138-147 omits DERIVATION_RECORD_TRUNCATED (emitted at walker L724). Unsupported codes (NO_INSTRUCTION, UNKNOWN_REGISTER, REGISTER_NOT_WRITTEN, NO_VALUE_OUTPUT, AMBIGUOUS_VALUE_OUTPUT) are not enumerated. Otherwise consistent with code (verdict policy, bounds 20000/200000/256/300 s, scratch copy, identity fields).

- path: docs/tooling/pcode-migration.md (context)
  purpose: Plan to retire Capstone dataflow in tools/census/ in favor of p-code. Inventory, rules, indirect_target v3 milestone, integration cost.
  observations: L89-90 records the aptrace_ghidra.py case import as a seam. It does not mention analyze_firmware.sh's transitive case dependency, the ARM mnemonic width logic in APTraceExportCensus.java, or Capstone use in tools/unicorn/call_observation.py.
```

## Observed behaviors

- Persistent Ghidra project per firmware key under a case-owned cache root: tools/ghidra/aptrace_ghidra.py:63, :123, :230-287.
- Cache identity hashing (firmware sha, base, processor, cspec, Ghidra version, analysis version, seed words, build-script hashes, provenance TSV hash, derived-seeds hash): aptrace_ghidra.py:171-195.
- Strict stale-cache refusal (missing/stale/fresh tri-state; exit on stale query): aptrace_ghidra.py:206-215, :290-297.
- Rebuild deletes the cache dir and prints the identity diff: aptrace_ghidra.py:241-250.
- Build pipeline is import -> preScript seed vector table -> auto-analysis (300 s timeout) -> optional provenance labels -> static export -> census export: aptrace_ghidra.py:256-279.
- Derived seeds file bound to firmware sha (refused on mismatch): aptrace_ghidra.py:138-149.
- Read-only reopened queries (-process -noanalysis -readOnly) for decompile/disasm: aptrace_ghidra.py:300-328.
- Cached-JSON queries answered without Ghidra (callers, xrefs, containing, symbol): aptrace_ghidra.py:350-425.
- Raw firmware reads without Ghidra (literal, dump) using the registered load base: aptrace_ghidra.py:428-463.
- Framework module imports case config at import time: aptrace_ghidra.py:82-86. analyze_firmware.sh:47 inherits it.
- Hardcoded Cortex-M language and cspec in the persistent backend and the one-shot script: aptrace_ghidra.py:74-75; analyze_firmware.sh:82-83.
- Ghidra headless discovery (PATH, GHIDRA_HOME, Homebrew), triplicated: headless.py:17-31; analyze_firmware.sh:49-67; doctor.sh:25-40.
- Ghidra version from the resolved install path (best-effort, may be "unknown"): headless.py:34-44.
- ARMv7-M vector-table function seeding (Thumb bit cleared for vectors; extras unmasked; block 0 only): APTraceSeedVectorTable.java:56-87.
- Provenance-label application (rename + comment with case paths): APTraceApplyProvenance.java:45-82.
- Static export of functions/calls/dataRefs/strings with language/cspec but no engine version: APTraceExportStaticAnalysis.java:88-187.
- Census export of basic blocks, resolved CFG edges, explicitly unresolved computed edges, RAM/MMIO refs by caller-supplied windows: APTraceExportCensus.java:155-272.
- Access width from ARM/Thumb mnemonic prefixes (ISA token logic in a root script): APTraceExportCensus.java:113-128.
- Cancellation truncates exports silently with no completeness marker: APTraceExportCensus.java:166,178,213; APTraceExportStaticAnalysis.java:168.
- Decompile per function with 60 s timeout and explicit failure text: APTraceDecompileFunctions.java:59-64.
- Range disassembly of defined instructions only: APTraceDisassembleRange.java:38-45.
- p-code forward-use walker: two-phase may-dataflow fixpoint and recording pass: APTracePcodeForwardUse.java:394-431.
- Intra-instruction p-code path forking with a path-state bound: APTracePcodeForwardUse.java:443-576.
- Calling convention and stack pointer taken from cspec and language (no ISA tokens): APTracePcodeForwardUse.java:83-92.
- Engine/program identity recorded in the walker output (version, language id/version, cspec, convention, storage, pointer size, low-bit code mode, exe sha256, blocks): APTracePcodeForwardUse.java:132-167.
- Origin selection (named register or the single pointer-sized non-PC/SP output) with unsupported codes: APTracePcodeForwardUse.java:199-225, :272-285.
- Image-time origin value with code-address normalization via Ghidra: APTracePcodeForwardUse.java:288-365.
- Incompleteness codes emitted: NO_CONTAINING_FUNCTION :396; BUDGET_EXHAUSTED :407; NO_INSTRUCTION :426; DELAY_SLOT_UNSUPPORTED :446; PCODE_PATH_BOUND :461; PCODE_BRANCH_OUT_OF_RANGE :466; COMPUTED_FLOW_UNRESOLVED :490; UNMODELED_OPERATION :545; FLOW_LEAVES_FUNCTION :636; DERIVATION_RECORD_TRUNCATED :724.
- Assumptions recorded: computed-jump targets from flow refs :493; no-return ends path :514; tail call under default convention :634.
- Store target classification (stack/absolute/computed) from intra-instruction p-code: APTracePcodeForwardUse.java:651-676.
- Deterministic sorted output; timing separated: APTracePcodeForwardUse.java:122-124, :860-866; pcode_forward_use.py:289.
- Driver: explicit target, validation, import vs project modes, scratch copy of the project, single invocation for all origins: pcode_forward_use.py:170-298.
- Driver engine identity check (exe sha256, language, cspec; base not checked): pcode_forward_use.py:301-310.
- Engine unavailable gives an explicit UNSUPPORTED document: pcode_forward_use.py:241-244, :313-321.
- Verdict policy ESCAPE / NO_ESCAPE_WITHIN_SCOPE / INCOMPLETE / UNSUPPORTED, with unknown kinds raising: pcode_forward_use.py:324-363.
- Precision labels MEMORY_FLOW_NOT_FOLLOWED and ARGUMENT_BY_STORAGE: pcode_forward_use.py:346-362.
- Peak RSS and wall-time measurement via wait4, outside the deterministic result: pcode_forward_use.py:191-217.
- Static ISA-neutrality test over walker and driver: test_pcode_forward_use.py:238-258.
- Thumb + RV32 controls and negative controls with exact expectations: controls.json; test_pcode_forward_use.py:73-98.
- Determinism test (byte-identical, no path/timing leakage): test_pcode_forward_use.py:120-127.
- Project-mode source-immutability test and the auto-analysis "never a new NO_ESCAPE" test: test_pcode_forward_use.py:144-182.
- Persistent-cache tests run against real case firmware and mutate the canonical cache meta.json: test_aptrace_ghidra.py:38, :120-136.
- Unicorn Cortex-M4 Thumb machine with flash/RAM/MMIO/PPB/extra maps and a harness-only trampoline page: concrete.py:411-457.
- Dirty-page tracking and pristine-snapshot reset; refusal to reset a non-tracking machine after a run: concrete.py:459-522.
- run() with seeds (tagged seed / carried), stubs, stop/watch, watch memory and register pointees, fake tick, MMIO force/clear bits, force reg/mem, MMIO/RAM logs, write watchpoints, coverage, recent-PC ring: concrete.py:534-890.
- error_free vs completed result semantics: concrete.py:203-213.
- Carry-forward of firmware-produced bytes distinguished from seeds: concrete.py:154-168, :250-261, :596-606.
- AAPCS direct call with stack args and trampoline return detection: concrete.py:894-963.
- Narrow interrupt delivery (nested AAPCS call, r0-r3/r12 restored): concrete.py:967-1003.
- Hook reentrancy workaround for log_ram vs internal writes: concrete.py:790-807; _ranges_excluding :132-151.
- Result provenance lacks firmware hash, Unicorn version, memory map and reg_seed disclosure: concrete.py:263-300.
- CLI numeric conventions (addresses hex, values int(,0), masks hex): run_concrete.py:69-120.
- CLI silently ignores --stop-at in --call mode: run_concrete.py:203-228.
- Thumb BL/BLX call-site attribution from LR: call_observation.py:65-101.
- Per-call-site argument observation with region and pointee classification: call_observation.py:113-183.
- Watched-field store events with Capstone-derived addressing form and completeness from dropped count: call_observation.py:195-329.
- Call/field correlation with field_state classification: call_observation.py:332-413.
- Synthetic Thumb regression of call observation, watch passivity and truncation: test_call_observation.py:156-314.
- Cortex-M vector-table candidate scoring and dump: vector_scan.py:52-174.
- Environment doctor running case-firmware functional checks: doctor.sh:41-89.

### Doc/code disagreements and stale references

- ghidra-backend.md:9-10 says the case supplies the cache root. Code hardcodes it at aptrace_ghidra.py:63.
- pcode-forward-use.md:138-147 omits DERIVATION_RECORD_TRUNCATED. The walker emits it as an incompleteness entry (APTracePcodeForwardUse.java:724), and the driver therefore marks the result non-complete (pcode_forward_use.py:341), even though the walker text says "analysis unaffected".
- unicorn-backend.md:3-6 says the engine has no target-specific meaning. concrete.py:380-381 defaults and :88-110 commentary are SAMD51-specific.
- unicorn-backend.md:31-33 lists three addressing forms. call_observation.py also emits "other" (:224) and "undecoded" (:206, :213, :286).
- run_concrete.py:134 --sp help describes the trampoline as in RAM. concrete.py:102-110 places it outside RAM.
- requirements.txt:2 says capstone is used only by a case script. call_observation.py:202-208 and test_call_observation.py:21 also use it.
- vector_scan.py:9 usage implies --flash-base 0x4000. The default is 0x0 (:131).
- doctor.sh:2 says "four analysis backends". Three are checked.
- thumb_controls.s:4 points to expected.json. The local manifest is controls.json; expected.json lives in docs/spikes/architecture-evaluation/experiments/fixtures/.
- test_pcode_forward_use.py:101-117 "spike parity" compares the spike ground truth with the manifest's expected escapes, not with engine output.
- Missing referenced files:
  - cases/performing-rigs/docs/investigations/toolchain-cleanup.md (cited at aptrace_ghidra.py:48; concrete.py:43, :108, :183)
  - cases/performing-rigs/docs/investigations/standard-library-provenance.md (APTraceApplyProvenance.java:9, :79)
  - docs/harness/protocol-harness-results.md (APTraceSeedVectorTable.java:9). It now exists under cases/performing-rigs/docs/investigations/.
- pcode-migration.md:82-96 "Case-localize" lists aptrace_ghidra.py but not analyze_firmware.sh's transitive case import (:47), case-default paths in analyze_firmware.sh:37,43 and doctor.sh:17, or the ARM mnemonic logic in APTraceExportCensus.java:113-128.
