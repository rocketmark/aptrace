# Arrow: structural-discovery

Recovering a firmware image's static structure (functions, basic blocks,
control-flow and call edges, data references, strings) from Ghidra and,
independently, from Macaw. Also covers serving that structure as
function facts and disassembly, and the cross-engine and cross-decoder
comparisons over it.

## Status

**MAPPED**: mapped 2026-10-15 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/structural-discovery/structural-discovery-design.md

### EARS
- docs/intent/production/structural-discovery/structural-discovery-specs.md (prefix `PROD-DISC`; 58 specs: 53 `[x]`, 5 `[ ]`, 0 `[D]`)

### Tests
- tools/census/test_macaw_compare.py: normalized-terminator handling in the Ghidra/Macaw comparison
- agent/tests/test_investigation_tools.py: call-site context boundary rules; pin-table decode on a synthetic image
- agent/tests/test_source_agreement.py: `GhidraIndex` label canonicalization (`:149`); seeds included in cache identity (`:186`); seeded USB targets recognized (`:209`, needs case cache)
- agent/tests/test_function_facts_flow.py: `function_facts` over the real AutoPilot export; out-of-range caller edges retained as rejected (needs case cache)
- Case-owned, outside framework scope: cases/performing-rigs/test/Main.hs tests 6–8 and 11–29 (Macaw census canonical addresses, determinism, unresolved preservation, calls, refinement, normalization, expansion)

### Code
- tools/ghidra/scripts/APTraceExportStaticAnalysis.java: program metadata, functions, call edges, data references, strings
- tools/ghidra/scripts/APTraceExportCensus.java: basic blocks, block CFG edges (resolved and unresolved computed), RAM/MMIO data references
- tools/ghidra/scripts/APTraceDecompileFunctions.java: decompiler C per function (cross-check use)
- tools/ghidra/scripts/APTraceDisassembleRange.java: Ghidra listing for an address range
- src/APTrace/MacawCensus.hs: vector-root-only Macaw discovery census (JSON)
- src/APTrace/MacawExpand.hs: normalization fixpoint fed back into Macaw's incremental discovery
- src/APTrace/MacawIsaClassify.hs: APTrace ISA-level relabeling of Macaw `ParsedCall` terminators
- src/APTrace/MacawNormalize.hs: nested-mux identity recovering two-way targets from `classify_failure`
- src/APTrace/MacawRefinement.hs: experimental macaw-refinement plumbing (not wired to the CLI)
- agent/src/aptrace_agent/ghidra_index.py: in-memory index of the Ghidra static export (`function_facts`); agent-side cache-identity gate
- agent/src/aptrace_agent/disassembly.py: `function_disassembly`, Capstone Thumb decode over Ghidra bounds
- agent/src/aptrace_agent/investigation_tools.py: `callsite_context`; `pin_table_entry` (case-specific decoder)
- tools/census/capstone_sweep.py: Capstone Thumb branch-target sweep cross-checking Ghidra block coverage
- tools/census/macaw_compare.py: Ghidra-census vs Macaw-census comparison report

### Case inputs consumed (not owned here)
- `cases/performing-rigs/research/firmware/vendor-package/firmware_autopilot868.bin` (disassembler and pin table; gitignored, absent in this checkout)
- Case pin-table geometry (`0x14284`, stride `0x18`) hardcoded in `investigation_tools.py`

### Related docs
- docs/tooling/macaw-analysis.md, docs/tooling/tool-selection.md, docs/cross-engine-verification.md
- docs/spikes/architecture-evaluation.md §4.4; docs/spikes/architecture-reconciliation.md §B, §F

## Architecture

**Purpose:** produce static structure from two engines with different
lineage. Ghidra is the primary structural source (CLAUDE.md engine table).
Macaw is an independent lifter seeded only from the vector table. The
segment also exposes Ghidra's structure to the agent as `function_facts`,
`function_disassembly` and `callsite_context`, and compares structure
across sources (Ghidra vs Macaw, Ghidra vs a Capstone sweep).

**Key components:**
1. **Ghidra exports** (`APTraceExportStaticAnalysis`, `APTraceExportCensus`): build-time JSON exports written into the persistent Ghidra cache. Their identity comes from target-loading's `meta.json`.
2. **Macaw census family** (`MacawCensus`, `MacawExpand`, `MacawNormalize`, `MacawIsaClassify`): vector-root-only discovery, plus APTrace-owned normalization, expansion and reclassification layers. Each layer carries its own provenance tag.
3. **Agent structural readers** (`GhidraIndex`, `ThumbFunctionDisassembler`, `CallsiteContextReader`): bounded, read-only structural operations over the Ghidra export and raw image bytes.
4. **Cross-checks** (`capstone_sweep`, `macaw_compare`): disagreement reporting. Neither is an authority.
5. **Experimental** (`MacawRefinement`, `APTraceDecompileFunctions`): refinement plumbing, not wired to the CLI; decompiler output used only as a cross-check.

## Spec Coverage

`[x]` means observed in source only. "Test-asserted" counts specs with a test
assertion; no tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Test-asserted |
|---|---|---|---|---|---|
| Ghidra exports | PROD-DISC-GEXP-001 to 012 | 11 | 1 (GEXP-010) | 0 | 1 |
| Macaw census | PROD-DISC-MACAW-001 to 009 | 8 | 1 (MACAW-009) | 0 | 6 (case suite) |
| Normalization | PROD-DISC-NORM-001 to 003 | 3 | 0 | 0 | 3 (case suite) |
| Expansion | PROD-DISC-EXPAND-001 to 003 | 3 | 0 | 0 | 2 (case suite) |
| ISA classification | PROD-DISC-ISA-001 to 002 | 2 | 0 | 0 | 2 (case suite; no direct-`BL` case) |
| Refinement | PROD-DISC-REFINE-001 | 1 | 0 | 0 | 1 (case suite) |
| Ghidra index | PROD-DISC-IDX-001 to 007 | 6 | 1 (IDX-005) | 0 | 4 |
| Cache-identity gate | PROD-DISC-CACHE-001 to 002 | 2 | 0 | 0 | 1 (needs case cache) |
| Disassembly | PROD-DISC-DIS-001 to 003 | 3 | 0 | 0 | 0 |
| Call-site context | PROD-DISC-CTX-001 to 002 | 2 | 0 | 0 | 2 |
| Pin table | PROD-DISC-PIN-001 to 002 | 2 | 0 | 0 | 2 |
| Reader wiring | PROD-DISC-WIRE-001 to 002 | 1 | 1 (WIRE-002) | 0 | 0 |
| Capstone sweep | PROD-DISC-SWEEP-001 to 004 | 3 | 1 (SWEEP-004) | 0 | 0 |
| Ghidra-vs-Macaw comparison | PROD-DISC-CMP-001 to 006 | 6 | 0 | 0 | 1 |

**Summary:** 53 of 58 specs are observed in source. The 5 gaps are
approved-intent gaps. Each states the required outcome and leaves the
mechanism open:
- GEXP-010: truncated exports distinguishable;
- MACAW-009: Macaw observations bindable to firmware SHA-256 and engine;
- IDX-005: missing attribution disclosed;
- WIRE-002: firmware association established;
- SWEEP-004: exhausted bounds reported.

25 specs have a test assertion; 18 of those live in the case suite or need
the case cache. No `@spec` annotations exist in code yet.

## Key Findings

1. **`MacawIsaClassify` gives direct `BL` calls the `true_indirect_call` label.** The kind rule is `"BL" isPrefixOf mnem` plus a return address gives `TrueIndirectCall` (`MacawIsaClassify.hs:140`). `MacawCensus.callClassificationOf` applies it to every `ParsedCall`, not only Macaw's `kind = "indirect"` calls (`MacawCensus.hs:556-570`), so direct `BL` immediates get the label. The documentation is ambiguous:
   - the module was motivated by the 48 `kind = "indirect"` sites (`:6-14`);
   - the constructor's documentation reads "register-indirect (or PC-relative) call" (`:48-51`), which could cover a direct `BL`;
   - the emitted text `true_indirect_call` does not cover it.

   `docs/spikes/architecture-reconciliation.md` §F treats this as a defect and reports it at 1,206 of 1,229 sites; that count was not re-measured here.
2. **Neither engine's output records engine identity.**
   - The Macaw census identifies firmware only by path and size, with no digest or engine version (`MacawCensus.hs:656-663`).
   - The Ghidra static export records language, cspec and image base but no Ghidra version (`APTraceExportStaticAnalysis.java:92-109`).
   - The census export records no program identity at all.
   - Both Ghidra exports rely on target-loading's `meta.json` for identity.
3. **Cancelled exports are silently truncated.** On `monitor.isCancelled()` the Ghidra exports stop iterating but still write well-formed JSON with no completeness marker (`APTraceExportCensus.java:166, 178, 213`; `APTraceExportStaticAnalysis.java:168`).
4. **`capstone_sweep` is seeded from Ghidra's discovery output.** Seeds are Ghidra's known function entries plus vector targets (`tools/census/build.py:225`). Its docstring calls it "completely independent" while also saying "walking from the same roots" (`capstone_sweep.py:5-8`). It also:
   - hits its instruction caps silently (`:65, 72`);
   - treats any `b*` mnemonic other than `b`/`b.w`/`bl`/`blx` as a conditional branch, which includes `bx`, `bic` and `bkpt` (`:89`);
   - uses `CS_MODE_THUMB` without `MCLASS`, unlike `disassembly.py:37-40`.
5. **The agent's cache-identity fallback skips two inputs.** When Ghidra is not installed, `ghidra_cache_identity` re-checks the firmware SHA-256, build scripts and an existing derived-seeds file (`ghidra_index.py:254-271`). It does **not** recompute the provenance-TSV hash. It also does not notice a derived-seeds file that was deleted, because the old hash carries over from `meta`. *(Inferred from code, not executed.)* It reaches into a private `aptrace_ghidra` helper (`:266`).
6. **`GhidraIndex` drops some call records without accounting for them.** It indexes any JSON dict with matching keys (`ghidra_index.py:39-70`). Call edges outside the caller's `[entry, entry+size)` range are kept as `rejected_edges` (`:97-111, 133-167`), and a case test asserts five such edges on the real export. Call records with a null `fromFunction` or `toFunction` are skipped with no record (`:79-84`). Function `size` is Ghidra's `getNumAddresses()` (`APTraceExportStaticAnalysis.java:118`), so the range check is a heuristic for non-contiguous bodies.
7. **`function_disassembly` is fixed to one ISA and one case image.**
   - The decoder is always Capstone ARM Thumb M-class, and results are always labeled `ARM Cortex-M4F` (`disassembly.py:37-40, 92-93`).
   - The image is not hash-checked and the result carries no provenance or version.
   - `complete` only means decoded bytes equal requested bytes (`:98`).
   - `autopilot_disassembler()` reads `vendor-package/firmware_autopilot868.bin` (`:103-123`). That path is gitignored and absent in this checkout. The census reads `originals/`.
8. **A case-specific decoder lives in framework code.** `PinTableReader` decodes an Arduino-style pin table "used by FUN_0000d3dc", with PA–PZ naming (`investigation_tools.py:135-247`). Its factory hardcodes table base `0x14284`, stride `0x18` and flash base `0x4000` (`:257-280`). It has no hash check and no provenance.
9. **`macaw_compare` counts shared incompleteness as agreement and checks identity weakly.**
   - Calls both tools leave unresolved are counted inside `exact_agreement` and printed as "Exact agreement (concrete or both-unresolved)" (`macaw_compare.py:341-373, 960`).
   - The firmware identity check compares only flash base and RAM parameters, warns only, and never compares a hash (`:105-125`).
   - Its docstring says it "never writes to the database", but it opens the census through a connection path that may run schema DDL and migrations (`:1235`; that path belongs to the census segment). An actual mutation has not been demonstrated (LLD Open Question 16).
10. **Macaw discovery failures are captured, not thrown.** A Macaw exception becomes `discovery_error` with every list empty (`MacawCensus.hs:337-363`). Expansion aborts loudly beyond 100 rounds rather than truncating (`MacawExpand.hs:106-130`).
11. **`MacawRefinement` is not wired and has never refined a block.** Its own documentation says "no block has yet refined successfully" (`MacawRefinement.hs:13-19`). It depends on a vendored compatibility patch that `architecture-reconciliation.md` §B reports as lost (case test 16).
12. **Root and adjacent code uses ISA mnemonics.** `APTraceExportCensus.widthFromMnemonic` uses ARM/Thumb mnemonic prefixes (`:113-128`). `MacawIsaClassify` matches mnemonic text produced by macaw-aarch32 (`:129-145`).
13. **Case data in framework comments.** AutoPilot audit counts appear in `MacawIsaClassify.hs:7-14`, `MacawNormalize.hs:25-26` and `MacawExpand.hs:94-97`, and investigation addresses in `macaw_compare.py:316, 713, 852-862`. `MacawNormalize.hs:25` cites an elided `docs/tooling/...` path.

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
*None identified in this segment.* (The only Must Fix for the Ghidra cache is in target-loading.)

### Confirmed defects
*None confirmed.* The `true_indirect_call` labeling (Finding 1) is reported as
a defect by `architecture-reconciliation.md` §F. Its own documentation is
ambiguous, so it is listed under Semantic inconsistencies until the intended
meaning is decided (LLD Open Question).

### Evidence-integrity risks
1. **No engine identity on structural evidence.** The Macaw census has no firmware digest or engine version. The Ghidra exports have no engine version. Consumers cannot tie structural evidence to an exact engine without going back to `meta.json`, which the Macaw census has no counterpart for. (Finding 2)
2. **Truncated exports look complete.** A cancelled Ghidra export cannot be told apart from a complete one. (Finding 3)
3. **A cross-check seeded from the authority.** `capstone_sweep` runs from Ghidra's own function entries, so disagreement with Ghidra is not evidence from an independent run (CLAUDE.md "Evidence discipline": do not pass one engine's findings into another's independent run). (Finding 4)
4. **Shared incompleteness reported as agreement.** `macaw_compare` counts both-unresolved calls under `exact_agreement` and checks firmware identity by parameters only. (Finding 9)
5. **Stale-cache detection gap without Ghidra.** The agent-side identity fallback does not recompute the provenance-TSV hash and does not notice a deleted derived-seeds file. (Finding 5)
6. **Unaccounted and unverified agent readers.**
   - `GhidraIndex` drops call records with null function attribution without recording them. (Finding 6)
   - `function_disassembly` and `pin_table_entry` read the image without a hash check and return no provenance. (Findings 7–8)

### Architectural coupling
7. `function_disassembly`, `callsite_context` and `pin_table_entry` are bound to the case image path and geometry (`disassembly.py:103-123`; `investigation_tools.py:250-280`). (Findings 7–8)
8. A case-specific pin-table decoder sits in a framework module. (Finding 8)
9. `ghidra_index` depends on private `aptrace_ghidra` internals (`ghidra_index.py:229-239, 266`). (Finding 5)

### Semantic inconsistencies
10. **`true_indirect_call` applies to direct `BL` calls.** The label is emitted for every `BL*` `ParsedCall` with a return address, including direct `BL` immediates. It contradicts its name, and whether it contradicts its documented meaning depends on how "(or PC-relative)" is read (`MacawIsaClassify.hs:48-51, 140`; `MacawCensus.hs:556-570`). (Finding 1)
11. **Capstone modes and branch classification differ across decoders.** `capstone_sweep` uses `THUMB` and `disassembly.py` uses `THUMB|MCLASS`. `capstone_sweep`'s conditional-branch test also matches non-branch mnemonics. (Finding 4)
12. **`capstone_sweep` is described as independent but is not.** Its docstring says "completely independent decoder" while its seeds are Ghidra entries. (Finding 4)
13. **`macaw_compare` claims no database writes, but its connection path may run schema DDL or migrations.** No actual mutation has been demonstrated, so this is not classified as a defect. (Finding 9; LLD Open Question 16)

### Maintenance debt
14. **Duplicated implementations.**
    - The JSON writer is duplicated between the two Ghidra export scripts.
    - `canonicalWord` is duplicated in `MacawNormalize.segOffToCanonicalWord`, which the code documents as avoiding an import cycle.
15. **Experimental and unused modules.** `MacawRefinement` is not wired to the CLI and its compatibility patch is reported lost. (Finding 11)
16. **Case data in comments.** Case-specific counts and addresses appear in framework comments, and one doc path is elided. (Finding 13)
