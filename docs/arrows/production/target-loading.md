# Arrow: target-loading

Turning a raw firmware image and its target configuration into analyzable
engine inputs: memory layout, vector-table code roots, Thumb execution-state
policy, and the persistent Ghidra project with its cache identity.

## Status

**MAPPED**: mapped 2026-10-15 by `/map-codebase` from HEAD `a6395d7`. The
structure is known. Specs have not been verified against code (no audit has
run).

## References

### HLD
- docs/high-level-design.md (skeleton; written after all leaves)
- docs/intent/production/production-design.md (the `production` sub-HLD; skeleton)

### LLD
- docs/intent/production/target-loading/target-loading-design.md

### EARS
- docs/intent/production/target-loading/target-loading-specs.md (prefix `PROD-TGT`; 46 specs: 44 `[x]`, 2 `[ ]`, 0 `[D]`)

### Tests
- tools/ghidra/test_aptrace_ghidra.py: cache build/fresh, stale detection, cached queries (runs against real case firmware and the canonical cache)
- Case-owned, outside framework scope: cases/performing-rigs/test/test_target_irq_count.py (checks Python and Haskell IRQ counts agree)

### Code
- src/APTrace/FirmwareLoader.hs: raw image to Macaw memory, Cortex-M Thumb policy (`macawCortexMEntry`, `armCortexMInfo`)
- src/APTrace/VectorTable.hs: ARMv7-M vector-table parse
- tools/ghidra/aptrace_ghidra.py: persistent Ghidra project per firmware key, cache identity, cached query CLI
- tools/ghidra/headless.py: `analyzeHeadless` locator and best-effort Ghidra version
- tools/ghidra/analyze_firmware.sh: one-shot throwaway-project import and static export (older path)
- tools/ghidra/scripts/APTraceSeedVectorTable.java: vector-table function seeding pre-script
- tools/ghidra/scripts/APTraceApplyProvenance.java: human-reviewed label application post-script
- tools/vector_scan.py: vector-table candidate scoring prototype
- tools/doctor.sh: environment check for Ghidra, Unicorn and the Haskell toolchain
- app/Main.hs: Haskell CLI entry; supplies target geometry to every command
- aptrace.cabal: Haskell package manifest (library includes case modules)

### Case inputs consumed (not owned here)
- cases/performing-rigs/config/performing_rigs.py: `FIRMWARE_REGISTRY`, census RAM/MMIO windows, `NUM_EXTERNAL_IRQ` (derived from the SVD)
- cases/performing-rigs/src/APTrace/Case/PerformingRigs.hs: `ramBase`, `ramSize`, `numIrq`, `defaultFlashBase`, `mmioWindow`

### Related docs
- docs/tooling/ghidra-backend.md
- docs/case-boundary.md (records several of this segment's seams)
- docs/toolchain.md

## Architecture

**Purpose:** give every engine the same view of one firmware image: where it
loads, where RAM and MMIO are, which addresses are code roots, and that
Cortex-M code is always Thumb. Also own the identity of the persistent Ghidra
analysis, so later structural evidence is tied to an exact image, toolchain
and script set.

**Key components:**
1. **Macaw memory builder** (`FirmwareLoader.buildMemory`, `buildMemoryWithMMIO`): builds flash, zeroed RAM and optional MMIO segments from the raw bytes, without ELF.
2. **Thumb execution-state policy** (`macawCortexMEntry`, `armCortexMInfo`): forces the Thumb bit on code roots and pins PSTATE_T during Macaw discovery.
3. **Vector-table readers** (`VectorTable.parseVectorTable`, `APTraceSeedVectorTable.java`, `vector_scan.py`): three independent ARMv7-M readers. The census's `raw_scan.py` is a fourth, owned by the census segment.
4. **Persistent Ghidra project** (`aptrace_ghidra.build`, `cache_status`, `ensure_fresh`): one analyzed project per firmware key. Freshness is strict equality between `meta.json` and the expected identity.
5. **Geometry wiring** (`app/Main.hs`, the case `performing_rigs.py`): supplies the case target configuration to the framework commands.

## Spec Coverage

`[x]` means observed in source only. "Test-asserted" counts specs with a test
assertion; no tests were run during mapping.

| Category | Spec IDs | Implemented `[x]` | Gaps `[ ]` | Deferred `[D]` | Test-asserted |
|---|---|---|---|---|---|
| Memory image | PROD-TGT-MEM-001 to 004 | 4 | 0 | 0 | 0 |
| Thumb policy | PROD-TGT-THUMB-001 to 004 | 4 | 0 | 0 | 4 (case suite) |
| Vector table | PROD-TGT-VEC-001 to 010 | 10 | 0 | 0 | 0 |
| Ghidra project and identity | PROD-TGT-GH-001 to 018 | 17 | 1 (GH-018) | 0 | 9 |
| One-shot export | PROD-TGT-ONESHOT-001 to 002 | 2 | 0 | 0 | 0 |
| Target configuration | PROD-TGT-CFG-001 to 005 | 5 | 0 | 0 | 2 (case suite) |
| Environment check | PROD-TGT-ENV-001 to 002 | 2 | 0 | 0 | 0 |
| Test isolation | PROD-TGT-TEST-001 | 0 | 1 (TEST-001) | 0 | n/a |

**Summary:** 44 of 46 specs are observed in source. 2 are approved-intent
gaps: GH-018 (build incompleteness made distinguishable) and TEST-001
(canonical cache isolation). 15 specs have a test assertion; 6 of those live
in the case suite. No `@spec` annotations exist in code yet.

## Key Findings

1. **The cache root is hardcoded to the case.** `aptrace_ghidra.py:63` hardcodes the cache root under `cases/performing-rigs/research/runs/ghidra_cache`. `docs/tooling/ghidra-backend.md` says the case supplies it. *(Inferred from code.)*
2. **The Ghidra language is a module constant.** `PROCESSOR = "ARM:LE:32:Cortex"` and `CSPEC = "default"` (`aptrace_ghidra.py:74-75`) apply to every firmware key instead of coming from per-image target configuration. `analyze_firmware.sh:82-83` repeats them.
3. **Framework code imports case config at import time.** `aptrace_ghidra.py:82-86` inserts `cases/performing-rigs/config` on `sys.path` and imports `performing_rigs`. `analyze_firmware.sh:47` inherits this. It is a recorded seam (case-boundary.md).
4. **All Haskell commands get case geometry.** `app/Main.hs:18` imports `APTrace.Case.PerformingRigs`. Only the flash base can be overridden on the command line (`Main.hs:34-59`), and only for some commands.
5. **The case is compiled into the framework library.** `aptrace.cabal:19-22` lists `cases/performing-rigs/src` in the library's `hs-source-dirs`. The only Haskell test suite is the case's (`aptrace.cabal:74`).
6. **Cache identity is recorded, but parts are best-effort.** The identity records firmware SHA-256, load base, processor/cspec, Ghidra version, analysis version, seed-vector count, the four build-script hashes, provenance TSV and derived seeds (`aptrace_ghidra.py:171-195`). However:
   - the Ghidra version is parsed from the install path and can be `"unknown"` (`headless.py:34-44`);
   - the identity is computed after the build finishes (`aptrace_ghidra.py:281`), not captured before it.
7. **Computing the identity exits when Ghidra is absent.** `expected_identity` calls `resolve_headless()` (`aptrace_ghidra.py:173`), which calls `sys.exit` when Ghidra is missing. The structural-discovery segment's `ghidra_index.ghidra_cache_identity` re-implements part of this to work without Ghidra.
8. **Headless lookup exists three times.** It is in `headless.py:17-31`, `analyze_firmware.sh:49-67` and `doctor.sh:25-40`.
9. **Vector-table reading exists four times.** It is in `VectorTable.hs`, `APTraceSeedVectorTable.java`, `vector_scan.py` and the census's `raw_scan.py`. They also differ:
   - the seed script skips `0xFFFFFFFF` words and the Haskell parser does not;
   - extra seed addresses are not low-bit-cleared (`APTraceSeedVectorTable.java:84-85`).
10. **Seeding and labeling failures are printed, not recorded.** They are console-only and do not reach `meta.json` or any export (`APTraceSeedVectorTable.java:42-44`, `APTraceApplyProvenance.java:72-76`). An auto-analysis timeout (`-analysisTimeoutPerFile 300`) is not surfaced either.
11. **Case data in root code and comments.** Examples:
    - `doctor.sh:17` hardcodes the case firmware path;
    - `doctor.sh:79-82` hardcodes case addresses;
    - `analyze_firmware.sh:37` defaults to load base 0x4000;
    - `FirmwareLoader.hs:144-161` cites AutoPilot addresses;
    - `APTraceApplyProvenance.java:78-80` writes case paths into Ghidra comments;
    - several comments cite case docs that no longer exist (see the LLD Open Questions).
12. **The test overwrites canonical case state.** `test_aptrace_ghidra.py:120-136` overwrites the real `meta.json` with no try/finally.

## Work Required

*Brownfield initial mapping. Items are classified by kind, with source
references. Only Must Fix is a committed requirement. The other categories
record observations for flesh-out; they are not implementation requirements
until a design decision adopts them (see the LLD Open Questions).*

### Must Fix
1. **Canonical cache mutated by a test.** `tools/ghidra/test_aptrace_ghidra.py:120-136` overwrites the canonical case cache's `meta.json` and restores it without try/finally. A failure between those lines leaves canonical state tampered with. (Finding 12)

### Confirmed defects
No defect in this segment's production behavior has been confirmed by
execution. Finding 12 is the only confirmed defect, and it is in a test (Must
Fix above).

### Evidence-integrity risks
2. **The cache cannot tell a clean build from a degraded one.** A Ghidra project can be cached as `fresh` after a build in which:
   - vector or extra seeds failed to seed (`APTraceSeedVectorTable.java:42-44`);
   - provenance labels were skipped (`APTraceApplyProvenance.java:72-76`);
   - auto-analysis hit `-analysisTimeoutPerFile 300` (`aptrace_ghidra.py:265`).

   None of these outcomes reaches `meta.json` or the exports, so downstream consumers (census build, `function_facts`, p-code, source agreement) cannot distinguish successful analysis, known incompleteness, failure, and unknown completeness. (Finding 10; LLD Open Question.)
3. **Engine identity is best-effort.** The Ghidra version can be recorded as `"unknown"` (`headless.py:34-44`), and the identity is computed after the build instead of being captured before it (`aptrace_ghidra.py:281`). (Finding 6)

### Architectural coupling
4. The cache root is hardcoded under the case (`aptrace_ghidra.py:63`). (Finding 1)
5. Language and cspec are module constants rather than target configuration (`aptrace_ghidra.py:74-75`; `analyze_firmware.sh:82-83`). (Finding 2)
6. Framework code imports case config at import time (`aptrace_ghidra.py:82-86`; `analyze_firmware.sh:47`). (Finding 3)
7. All Haskell commands use case geometry, and the case is compiled into the framework library (`app/Main.hs:18`; `aptrace.cabal:19-22,74`). (Findings 4–5)
8. Case paths and addresses appear in root tool defaults and comments (`doctor.sh:17,79-82`; `analyze_firmware.sh:37`; `FirmwareLoader.hs:144-161`; `APTraceApplyProvenance.java:78-80`). (Finding 11)

### Semantic inconsistencies
9. The vector-table readers disagree on edge cases:
   - `0xFFFFFFFF` words are skipped by the seed script but not by `VectorTable.hs`;
   - extra seeds are not low-bit-cleared (`APTraceSeedVectorTable.java:84-85`).

   (Finding 9)
10. `ghidra-backend.md` says the case supplies the cache root, but the code hardcodes it. (Finding 1)
11. The identity is computed only with Ghidra installed (`aptrace_ghidra.py:173`), while `ghidra_index.ghidra_cache_identity` re-implements it to work without Ghidra. The two can drift. (Finding 7)

### Maintenance debt
12. The headless locator is triplicated (`headless.py:17-31`; `analyze_firmware.sh:49-67`; `doctor.sh:25-40`). (Finding 8)
13. Vector-table reading is implemented four times. (Finding 9)
14. Stale doc references and wording (see the LLD).
