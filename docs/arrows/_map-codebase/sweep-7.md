# Sweep 7 — Haskell code and root framework docs

Read-only reconnaissance. Every file in scope was read in full except
`cabal.project.freeze` (see scope issues). Line numbers refer to the files as
of branch `feat/pcode-indirect-target` (HEAD a6395d7).

## Scope issues

- `cabal.project.freeze` is a **dangling symlink** to
  `cabal.project.freeze.ghc-9.6.7`, which does not exist in the working tree.
  The symlink is untracked (`git ls-files` empty). There is no `cabal.project`
  at root. The real project and freeze live in `external/macaw/`
  (`cabal.project` with `packages: ../../.`; `cabal.project.freeze.ghc-9.6.7`),
  which I skimmed instead — see "Freeze file note" after Part A.
- Docs referenced from code that do not exist: `docs/tooling/galois-premeeting.md`
  (cited by `src/APTrace/DebugHarness.hs:16,131,189`). `docs/tooling/unicorn-backend.md`
  does exist (not in scope).

---

## Part A — Code

```yaml
- path: aptrace.cabal
  purpose: Cabal package description for the Haskell side (library, `aptrace` executable, `aptrace-test` suite).
  exports:
    library exposed-modules (8-20): APTrace.VectorTable, FirmwareLoader, SymbolicRunner, ProtocolHarness,
      DebugHarness, MacawCensus, MacawExpand, MacawIsaClassify, MacawNormalize, MacawRefinement, EffectsSpike,
      APTrace.Case.PerformingRigs, APTrace.Case.PerformingRigsScenarios
    executable aptrace (56-69): main-is app/Main.hs
    test-suite aptrace-test (71-87): main-is cases/performing-rigs/test/Main.hs
  dependencies: base, aeson, asl-translator, bytestring, binary, bv-sized, containers, crucible, crucible-debug,
    crucible-llvm, crucible-macaw-debug, crucible-syntax, exceptions, lumberjack, macaw-base, macaw-aarch32,
    macaw-aarch32-symbolic, macaw-loader, macaw-refinement, macaw-symbolic, microlens, mtl, parameterized-utils,
    prettyprinter, semmc-aarch32, text, time, unliftio-core, vector, what4 (25-54). No version bounds anywhere.
  data_shapes: n/a
  side_effects: n/a
  role: build manifest
  observations:
    - synopsis line 4 "Bare-metal Cortex-M firmware analysis and symbolic execution" — package identity is Cortex-M.
    - lines 19-20, 22: case modules (APTrace.Case.PerformingRigs, PerformingRigsScenarios) are compiled INTO the
      framework library via `hs-source-dirs: src, cases/performing-rigs/src`. The framework library and the case
      are one compilation unit; the case is not a separate package.
    - line 74: the only test suite lives under cases/performing-rigs/test — no framework-level Haskell tests.
    - Only ARM backends (macaw-aarch32, macaw-aarch32-symbolic, semmc-aarch32, asl-translator) are dependencies;
      no other Macaw architecture (x86, PPC, RISC-V) is pulled in.

- path: cabal.project.freeze
  purpose: (intended) pinned dependency versions.
  exports: n/a
  dependencies: root file is a dangling, untracked symlink -> cabal.project.freeze.ghc-9.6.7 (missing at root); real freeze is external/macaw/cabal.project.freeze.ghc-9.6.7 (see Freeze file note)
  data_shapes: n/a
  side_effects: n/a
  role: build pinning
  observations:
    - Symlink target missing; GHC 9.6.7 is implied by the target name only.

- path: app/Main.hs
  purpose: Single CLI entry for the Haskell `aptrace` executable; dispatches subcommands, wiring case constants into framework modules.
  exports:
    module Main (main). CLI subcommands (lines 33-60):
      - `aptrace FIRMWARE.bin [FLASH_BASE_HEX]` -> `run` (58-59, 102-121): parse vector table, Macaw discovery from all handlers, pretty-print functions.
      - `solve FIRMWARE.bin [FLASH_BASE_HEX]` -> case `runSolve` (34-35)
      - `explore FIRMWARE.bin [FLASH_BASE_HEX] ENTRY_ADDR_HEX` -> `runExplore` (36-37, 128-141): seed one entry, dump reached functions.
      - `protocol FIRMWARE.bin` -> case `runProtocol` (38)
      - `trigger FIRMWARE.bin` -> case `runTrigger` (39)
      - `trigger-crosscheck FIRMWARE.bin` -> case `runTriggerCrossCheck` (40)
      - `debug FIRMWARE.bin ENTRY_ADDR_HEX` -> `DebugHarness.runDebug` (41)
      - `macaw-census FIRMWARE.bin [FLASH_BASE_HEX]` -> `MacawCensus.runMacawCensus` (42-43)
      - `macaw-census-expand FIRMWARE.bin [FLASH_BASE_HEX]` -> `MacawExpand.runMacawCensusExpand` (44-45)
      - `effects-spike FIRMWARE.bin ENTRY [rN=HEX] [mmio=BASE:SIZE] [--raw-only] [out=PREFIX]` -> `runEffectsSpike` with hardcoded spec [(0,1)], step bound 200000, parametricUniq True (46-51)
      - `function-effects FIRMWARE.bin ENTRY [rN=HEX ...] out=PREFIX` -> `runEffectsSpike` with target mmioWindow, no overrides, step bound 3000, parametricUniq False, rawOnly False (52-57)
    internal: parseSpikeOpts (67-73), parseEffectsOpts (78-87), parseHexWord (89-97), run, runExplore.
  dependencies: APTrace.Case.PerformingRigs (ramBase, ramSize, numIrq, defaultFlashBase, mmioWindow) line 18;
    APTrace.Case.PerformingRigsScenarios (runSolve, runProtocol, runTrigger, runTriggerCrossCheck) lines 19-20;
    APTrace.DebugHarness, EffectsSpike, FirmwareLoader, MacawCensus, MacawExpand, VectorTable; Data.Macaw.Discovery.
  data_shapes: stdout text (run/explore pretty-print); delegates JSON output to census/expand/effects modules.
  side_effects: reads firmware file; invoked commands write JSON files / spawn Z3.
  role: application wiring (explicit case wiring at app level)
  observations:
    - line 18-20: application imports case modules directly — every subcommand, even generic ones (macaw-census,
      function-effects), uses Performing Rigs geometry (ramBase/ramSize/numIrq/defaultFlashBase/mmioWindow).
      Only flash base is overridable by CLI; RAM/IRQ/MMIO are not.
    - line 50-51: "Spike-only: preserves the original hardcoded arg_r0 == 1 specialization" — effects-spike always
      queries arg_r0 == 1.
    - line 53-57: function-effects described as "Production entry for the agent's bounded function-effects action";
      shares implementation with the spike (runEffectsSpike) with different constants (step bound 3000 vs 200000).
    - line 41: `debug` takes no flash-base override (defaultFlashBase fixed).
    - line 64-66: mmio= option documented as "scaffolding to be removed".
    - line 99: run described as "Step 5/6 demo".

- path: src/APTrace/VectorTable.hs
  purpose: Parse the ARMv7-M vector table at offset 0 of a firmware image.
  exports: VectorEntry(..) {veIndex, veName, veRawAddr}, parseVectorTable :: Int -> ByteString -> [VectorEntry]
  dependencies: bytestring, binary (Data.Binary.Get)
  data_shapes: consumes raw firmware bytes; produces list of non-zero entries (index>0).
  side_effects: none (pure; runGet will throw on short input — line 58 reads 16+numIrq words unconditionally)
  role: firmware loader (Cortex-M vector table)
  observations:
    - Entirely ARMv7-M specific: system handler names (27-34), "IRQn_Handler" naming (39), 16 fixed system slots (57).
    - numIrq is caller-supplied (47); no hardcoded device.
    - Comment (21-24): Thumb bit is preserved raw for Macaw.

- path: src/APTrace/FirmwareLoader.hs
  purpose: Build a Macaw `Memory 32` directly from a raw (non-ELF) image; owns Cortex-M Thumb-state policy for Macaw discovery.
  exports: buildMemory, buildMemoryWithMMIO, resolveEntry, resolveEntries, macawCortexMEntry, armCortexMInfo (19-26)
  dependencies: Data.Macaw.ARM, ARMReg, ARM.Arch, ARM.Eval, AbsDomain.AbsState, Architecture.Info, CFG, Discovery,
    Memory, Memory.Permissions; Language.ASL.Globals (asl-translator); APTrace.VectorTable.
  data_shapes: ByteString firmware + flash base + RAM base/size (+ MMIO base/size) -> MM.Memory 32.
  side_effects: none (pure)
  role: firmware loader / Macaw architecture configuration
  observations:
    - 6-10: exists because macaw-loader-aarch32 is ELF-only.
    - 57-59: RAM modeled as all-zero at start (documented simplification).
    - 137-138: macawCortexMEntry = addr .|. 1 — Thumb bit forced for every code root.
    - 140-183: armCortexMInfo overrides arm_linux_info's mkInitialAbsState (PSTATE_T := 1) and
      extractBlockPrecond (fallback bpPSTATE_T = True). Haddock cites traces against `firmware_autopilot868.bin`
      and AutoPilot addresses 0xcd90, 0xcdd8, 0xcc24, 0xcb94, 0xcb8e (144-161) — case-specific evidence in a
      framework module's documentation.
    - 140: "Cortex-M4F-specific" — module is the single Cortex-M policy owner; no architecture abstraction.
    - buildMemoryWithMMIO (89-105) appears unused by in-scope callers (EffectsSpike has its own addMmioSegment).

- path: src/APTrace/SymbolicRunner.hs
  purpose: Symbolically execute one isolated Macaw basic block and ask Z3 whether a given branch target is reachable, returning a model for an observed register.
  exports: BranchQuery(..) {bqPointerOverrides, bqMemoryBytes, bqTargetAddr, bqObserveReg, bqExcludeObserved},
    BranchResult(..) (Unreachable | Reachable Integer | SolverError String), checkBranchModel, reportResult (24-29)
  dependencies: macaw-base (CFG, Discovery.ParsedContents, Memory, Types), macaw-symbolic (+ Memory),
    macaw-aarch32-symbolic, Data.Macaw.ARM.ARMReg, SemMC.Architecture.AArch32, crucible, crucible-llvm,
    what4 (Expr, Interface, Online, SMTLib2, SatResult, Solver.Z3, ProgramLoc, Config, ProblemFeatures).
  data_shapes: in BranchQuery; out BranchResult; reportResult prints SAT/UNSAT lines to stdout (299-303).
  side_effects: spawns Z3 online solver process (225-234); stdout.
  role: symbolic runner (block-level Crucible/What4)
  observations:
    - 15-23: designed for "the target block in our demonstration firmware" polling loop.
    - Memory SymbolicMutable (182) — RAM/MMIO unconstrained; all registers fresh symbolic (197, 277-293).
    - 72-75: withZ3Backend copied from macaw-refinement's private Solver module; also duplicated verbatim in
      EffectsSpike.hs:728-741 and ProtocolHarness.hs:942-955.
    - resolvedPointer duplicated in SymbolicRunner/DebugHarness/EffectsSpike(globalPointer)/ProtocolHarness.
    - 241-244: writeConcreteByte deliberately duplicated to avoid coupling to ProtocolHarness.
    - AArch32-only types throughout (ARM.AArch32, AR.ARMReg).
    - 298: reportResult "Shared by every CLI investigation command ... framework- and case-specific alike".

- path: src/APTrace/DebugHarness.hs
  purpose: Experimental attachment of Galois crucible-debug + crucible-macaw-debug to one discovered block, driven by a canned command script.
  exports: runDebug :: FilePath -> Word32 -> Word32 -> Word32 -> Word32 -> IO () (31-33)
  dependencies: crucible-debug (Lang.Crucible.Debug), crucible-macaw-debug (Data.Macaw.Symbolic.Debug),
    crucible-syntax, crucible-llvm, macaw-symbolic, macaw-aarch32-symbolic, what4; APTrace.FirmwareLoader.
  data_shapes: stdout/stderr debugger output only.
  side_effects: reads firmware; debugger I/O on stdin/stdout; no solver process.
  role: spike / prototype harness
  observations:
    - 9-30: "Experimental ... pre-meeting prototype, not a stable feature"; refers to docs/tooling/galois-premeeting.md (missing).
    - 91-92: Haddock names "the AutoPilot `&` command check at flash 0x888c, r3=0x26".
    - 161: hardcoded r3 = 0x26 seed (AutoPilot-specific concrete value) inside framework module, despite comment
      at 96-99 claiming "this module carries no knowledge of any specific target".
    - 195-203: canned script (mregister r3, step, step, mregister r3 _pc, continue, quit).
    - 205-207, 221-232: concreteZeroVar/resolvedPointer duplicated.

- path: src/APTrace/EffectsSpike.hs
  purpose: Bounded whole-function Crucible simulation that records every memory access, call and return term as raw JSON, then enriches with Z3-derived facts (uniqueness, guard status, region membership).
  exports: MmioRange (type), runEffectsSpike (34-37). runEffectsSpike args (131-144): path, flashBase, ramBase,
    ramSize, mmio ranges, entry, arg overrides, solver specializations, step bound, parametricUniq, rawOnly, outPrefix.
  dependencies: aeson, time, macaw-base (CFG, Discovery, Discovery.State, Memory, Permissions), macaw-symbolic
    (+Memory), macaw-aarch32-symbolic, ARMReg, semmc-aarch32, crucible (Simulator, EvalStmt, GlobalState), crucible-llvm,
    what4 (Expr.Builder, Online, SMTWriter, Solver.Z3, Symbol...); APTrace.FirmwareLoader.
  data_shapes:
    - writes `<prefix>.raw.json` (420): {spike:"aptrace-effects-spike-v1-raw", entry, arg_overrides, arg_specializations,
      regions[{region,base,size}], status, macaw_blocks, crucible_steps, counts{reads,writes,calls,backend_assumptions},
      runtime_s{discovery,cfg_and_setup,simulation}, inputs_referenced, accesses[{kind,pc,width_bytes,
      served_from_concrete_readonly,alloc_block,is_stack_block,address{concrete,expr,free_vars},guard{...}}],
      calls[{pc,target_concrete,target_expr,args_concrete,args_expr,guard_expr}], return_r0{concrete,expr,free_vars},
      assumptions[4 strings]} (393-419).
    - writes `<prefix>.enriched.json` (631-644): {spike:"aptrace-effects-spike-v2", raw_effects, solver_derived_facts
      {accesses[{index,kind,pc,region_membership_under_guard,address_uniqueness_under_guard,guard_status,specializations}],
      return_r0{uniqueness,bit_valued,specializations}} | {error}, solver_session{processes,common_assumptions_asserted_once,
      per_query_isolation,smoke_test,queries,shutdown,enrichment_s}, query_log[{n,type,source,additional_assumptions,result,runtime_s}]}.
    - stderr "[effects-spike]" timing log lines (746-756).
  side_effects: reads firmware; writes two JSON files; one Z3 online process (425-426) with push/pop per query; stderr.
  role: spike that also serves as the production `function-effects` agent action (via Main.hs:52-57)
  observations:
    - 9-14: "EXPERIMENTAL vertical slice (Phase 2 spike of docs/aptrace-agent-framework.md) ... deliberately NOT the generic FunctionSummary abstraction".
    - spike identifier strings "aptrace-effects-spike-v1-raw"/"-v2" (394, 633) remain in production function-effects output.
    - 415-418: assumptions list declares "Cortex-M Thumb, AAPCS opaque calls (clobber r0-r3/r12, no memory effects)".
    - Hardcoded ABI: args r0-r3 named arg_rN, r4-r12/lr named in_* (294-299); opaque call clobbers r0-r3,r12 (262-264); return in r0 (335).
    - 211-212: Thumb bit cleared from PC location (`.&. complement 1`) — ARM/Thumb-specific.
    - 284-288: 4096-byte concrete stack; 318-321: step bound via exception StepLimit; status strings "complete",
      "partial (some paths aborted)", "failed: ...", "bounded: timeout", "bounded: step limit N" (331-340).
    - 429-430: three-valued SAT/UNSAT/UNKNOWN; UNKNOWN never collapsed.
    - 451-463: Z3 smoke test before enrichment; enrichment skipped if fails.
    - 579-582: enrichment capped at first access per (kind,pc) site, max 24 sites; raw list keeps all.
    - 513-519: parametric terms not queried unless parametricUniq.
    - withZ3Backend/concreteZeroVar/globalPointer duplicated (699-741).
    - No engine-version/firmware-hash provenance recorded in JSON (only entry, regions, assumptions).

- path: src/APTrace/MacawCensus.hs
  purpose: Deterministic, vector-table-seeded Macaw static-discovery census emitted as one JSON line.
  exports: types FirmwareMeta, RootInfo, FunctionInfo, BlockInfo, EdgeInfo, UnresolvedInfo, CallInfo, NormalizedInfo,
    NormalizedTransferInfo, CallClassificationInfo, CensusResult, RootBuildResult; functions normalizeRoots,
    discoverCensus, buildDiscoveryState, buildRootInfo, summarizeDiscoveryState, censusToValue, canonicalWord,
    runMacawCensus (13-37).
  dependencies: aeson, vector, macaw-base (Discovery, ParsedContents, CFG, Memory), Data.Macaw.ARM; APTrace.FirmwareLoader,
    APTrace.MacawIsaClassify, APTrace.MacawNormalize, APTrace.VectorTable.
  data_shapes: stdout JSON (746-759, 790): {firmware{path,size_bytes,flash_base,ram_base,ram_size}, roots[{names,macaw_addr,
    canonical_addr,resolved}], discovery_error, functions[{entry,is_root,block_count}], basic_blocks[{function_entry,
    block_start,size,terminator_kind}], edges[{function_entry,source,target,kind}], incomplete_or_unresolved_terminators
    [{function_entry,block_start,kind,detail}], calls[{caller,call_site,callee,raw_target,kind}], normalized_terminators
    [{...,targets,provenance}], normalized_transfers[{...,semantic_kind,targets,provenance}], call_classifications
    [{function_entry,block_start,instruction_addr,instruction,macaw_terminator,semantic_kind,return_addr,provenance}]}.
  side_effects: reads firmware; stdout.
  role: Macaw discovery (independent evidence producer)
  observations:
    - 4-12: "independent Macaw evidence producer: no Ghidra, no Capstone, no existing census data" — designed for cross-engine comparison.
    - 337-343: discovery wrapped in try; exception -> discovery_error with all lists empty (explicit failure state).
    - 742-745: determinism relies on aeson's pinned `+ordered-keymap` build and explicit sorts (418-432).
    - Call kinds direct/unmapped/indirect kept distinct (125-165).
    - 769-772: "this module carries no knowledge of any specific target; app/Main.hs supplies the Performing Rigs AutoPilot/Remote values".
    - Types fixed to ARM.ARM (411, 446, 450...) — Macaw-ARM-specific, not arch-polymorphic.
    - JSON has no engine version / firmware hash; firmware identified by path and size only (656-663).
    - 198-204: NormalizedTransferInfo doc notes audited finding "all of them are ... CBZ/CBNZ" (firmware-derived finding in framework doc comment).

- path: src/APTrace/MacawExpand.hs
  purpose: Fixpoint that feeds MacawNormalize-recovered classify_failure targets back into Macaw's own incremental intraprocedural discovery and reports expanded census.
  exports: RoundInfo(..), ExpansionResult(..), expandWithNormalization, coverageStats, CoverageStats(..), runMacawCensusExpand, resolutionValue (38-47)
  dependencies: aeson (+KeyMap), macaw-base (Discovery addDiscoveredFunctionBlockTargets, analyzeDiscoveredFunctions,
    discoveredClassifyFailureResolutions), Data.Macaw.ARM; APTrace.FirmwareLoader, MacawCensus, MacawNormalize, VectorTable.
  data_shapes: stdout JSON = census object (same keys as macaw-census, describing expanded state) unioned with
    {base{functions,blocks,byte_coverage}, expanded{...}, normalization_rounds, rounds[{round,resolutions[{function_entry,
    block_start,targets,provenance}]}], residual_classify_failures[{function_entry,block_start}]} (330-342).
  side_effects: reads firmware; stdout.
  role: Macaw discovery (expansion)
  observations:
    - 94-107: maxRounds = 100; exceeding it calls `error` (128-130) — loud failure rather than truncation.
    - 95-97: comment cites "the original 72 base-state classify_failure blocks ... on autopilot868" — case fact in framework comment.
    - 284-285: output designed to be consumed by `tools/census/macaw_compare.py`.
    - 288-291: geometry caller-supplied; Performing Rigs values via Main.hs.

- path: src/APTrace/MacawIsaClassify.hs
  purpose: APTrace-owned reinterpretation of Macaw ParsedCall terminators into ISA-level semantic kinds using Macaw's own InstructionStart mnemonic text plus mret.
  exports: SemanticKind(..) (TrueIndirectCall|TailCall|ConditionalBranch|TableBranch|ComputedJump|Ambiguous), semanticKindText,
    aptraceIsaClassificationProvenance (= "aptrace-isa-classification"), IsaClassification(..), classifyParsedCall (26-32)
  dependencies: text, Data.Macaw.ARM, Data.Macaw.CFG, Data.Macaw.Memory.
  data_shapes: pure; consumed by MacawCensus call_classifications.
  side_effects: none
  role: Macaw discovery interpretation layer (ISA-specific)
  observations:
    - 4-14: motivation is a firmware-specific audit ("on this firmware ... all 48 kind=indirect ParsedCall sites ... 23 genuine ... 25 ...").
    - 139-145: classification by ARM/Thumb mnemonic prefix text (BL, BX, CBZ/CBNZ, TBB/TBH, LDR with "Rt 15") —
      string matching on disassembler output; explicitly AArch32-specific.
    - 129-131: depends on macaw-aarch32 Disassemble.hs output format "<addr>: <mnemonic> (<operand fields>)".
    - 140: "BL" prefix also matches any BL* mnemonic (BLX etc.) by design; non-BL mnemonics starting with "BL" would also match.
    - Provenance tag distinct from base Macaw evidence (84-88).

- path: src/APTrace/MacawNormalize.hs
  purpose: One architecture-independent Boolean identity (nested mux with identical condition collapses) applied to classify_failure curIP values to recover two-way branch targets.
  exports: macawNormalizedProvenance (= "macaw-normalized"), normalizeIP, normalizeIPSegOff, segOffToCanonicalWord (32-37)
  dependencies: Data.Macaw.ARM, Data.Macaw.CFG, Data.Macaw.Memory, Data.Macaw.Types; APTrace.FirmwareLoader (resolveEntry).
  data_shapes: pure; recovered targets as MemSegmentOff / Word32.
  side_effects: none
  role: Macaw discovery normalization
  observations:
    - 3-19: the identity itself is architecture-independent, but types are fixed to ARM.ARM (61-64, 81, 106, 121).
    - 25-26: comment references "docs/tooling/..." (elided path) and "the 72 classify_failure blocks this addresses 49 of" — case figure.
    - 87-96: segOffToCanonicalWord duplicates MacawCensus.canonicalWord to avoid an import cycle (documented).
    - Only accepts concrete mapped targets (104-115); declines otherwise.

- path: src/APTrace/MacawRefinement.hs
  purpose: Plumbing to invoke vendored macaw-refinement's SMT ClassifyFailure resolution on a single function of an existing discovery state.
  exports: refineFunctionAt (34-36)
  dependencies: macaw-refinement (Data.Macaw.Refinement), macaw-loader (BinaryLoader, BinaryLoader.Raw), Memory.LoadCommon,
    lumberjack, mtl, unliftio-core, exceptions, crucible-llvm MemModel, macaw-aarch32-symbolic.
  data_shapes: returns (DiscoveryState ARM, RefinementInfo ARM); logs pretty-printed RefinementLog to stderr (77).
  side_effects: Z3 solver via macaw-refinement (config solver=Z3, parallelismFactor 1, timeoutSeconds 60; 124-128); stderr.
  role: spike / experimental refinement
  observations:
    - 13-19: "exists only to experiment with, and regression-test ... no block has yet refined successfully ... does not feed into MacawCensus".
    - 15-17: depends on a "compatibility-patch" in vendored macaw-refinement for an AArch32 register-state gap.
    - Not wired into app/Main.hs; only user is cases/performing-rigs/test/Main.hs.
    - 84-94: builds LoadedBinary via RawBin instance without calling loadBinary.

- path: src/APTrace/ProtocolHarness.hs
  purpose: Whole-function Crucible/What4 harness: run a Macaw function with a controlled (concrete or symbolic) memory buffer and ask reachability of a target byte value; also bounded "gate" reachability over named symbolic RAM cells.
  exports: PacketByte(..) (Concrete Word8 | Symbolic), PacketResult(..) (ConcreteResult | Reachable [(Int,Integer)] | Unreachable | HarnessError),
    runPacketTransaction, RichTraceConfig(..) {rtLoAddr, rtHiAddr, rtWatchMem, rtMaxHits}, runPacketTransactionTraced,
    GateVar(..) {gvLabel, gvAddr, gvWidth}, GateResult(..) (GateSat | GateUnsat | GateError), runGateReachability (42-51)
  dependencies: macaw-base, macaw-symbolic (+Memory, +Regs), macaw-aarch32-symbolic, ARMReg, semmc-aarch32, crucible
    (EvalStmt, ExecutionTree, GlobalState), crucible-llvm, what4 (Online, SMTLib2, Solver.Z3). No APTrace imports.
    Used by case module cases/performing-rigs/src/APTrace/Case/PerformingRigsScenarios.hs:38-39.
  data_shapes: optional solver-observability files `<base>.<tag>.standalone.smt2` and `<base>.<tag>.interaction.smt2`
    (tag = stop|final|gate) (793-805); stderr [timing]/[trace]/[rich-trace]/[opaque_call] lines.
  side_effects: Z3 processes (424, 471, 664); file writes (smt2); stderr; `Exit.exitFailure` kills the process after
    300000 steps in debugFeature (817-820).
  role: symbolic harness (whole function)
  observations:
    - 17, 188, 209, 258, 541, 768: comments point to cases/performing-rigs/docs/investigations/* as the authority for behavior.
    - 122-124: "expected to be the AutoPilot dispatcher".
    - 298-332: compact RAM zero overlay via one constant-array store per writable segment, bounds read from Memory
      (not hardcoded; 317-321 mention "0x20000000/0x30000 AutoPilot RAM" as the example).
    - 249-289: AAPCS opaque call override clobbers r0-r3, r12; logs r4/r6/r7 every 200 calls (270-275) — debug print with
      specific registers.
    - 350-360: all registers concrete zero (ASL bookkeeping globals) except IP/SP/overrides.
    - 176-190: early-stop address soundness depends on caller placement (documented assumption).
    - 589-604: runGateReachability uses unsupportedFunctionCalls — throws if a call is reached (deliberate).
    - 618-624: comment "all seven of this investigation's own cells" — case-specific.
    - 925-938: freshSymVar defined but not used in this module (only mentioned in comment).
    - 817-820: hard process exit on step cap inside a library function — not a structured failure state.
    - Duplicated helpers: withZ3Backend, resolvedPointer, concreteZeroVar, freshBV32.
```

### Freeze file note (cabal.project.freeze)

The root `cabal.project.freeze` is an untracked, dangling symlink. The real
build project is `external/macaw/cabal.project` (`import: cabal.project.dist`,
`packages: ../../.`, i.e. it includes the APTrace root), with freezes
`external/macaw/cabal.project.freeze.ghc-{9.6.7,9.8.4,9.10.2}`. Skimmed the
9.6.7 freeze (320 lines): `aeson ==2.2.4.1` with `aeson +ordered-keymap`
(lines 17-18, which `MacawCensus.censusToValue` relies on for key order),
`lumberjack ==1.0.3.0`, `parameterized-utils ==2.3.0.0`, `index-state:
hackage.haskell.org 2026-05-05T14:12:12Z` (line 320). Galois packages
(macaw-*, crucible-*, what4, semmc, asl-translator) are not in the freeze —
they are local packages of the vendored `external/macaw` checkout (submodules),
so their versions are pinned only by that checkout's commits, which are not
tracked by the APTrace repository (see architecture-reconciliation.md §D).

---

## Part B — Root docs

```yaml
- path: README.md
  covers: repository overview, framework/case layering, capabilities, layout, quick start, doc index
  kind: overview
  key_claims:
    - (intro, 3-6) "reusable firmware-analysis workbench for bare-metal Cortex-M images"
    - (8-19) two layers: framework at root, cases under cases/; Performing Rigs is "a consumer of APTrace, not the definition"
    - (Capabilities 21-28) raw Cortex-M loading, Ghidra, Macaw CFG + Thumb lifting, Unicorn, Crucible/What4/Z3, census
    - (Repository layout 36-44) lists app/, src/APTrace/, tools/, docs/, test/ "framework tests", cases/performing-rigs/
    - (Quick start 54-59) cd external/macaw; git submodule update; cd ../..; cabal build aptrace
  code_referenced: app/, src/APTrace/, tools/ghidra/test_aptrace_ghidra.py, cases/performing-rigs/test/test_concrete.py, tools/doctor.sh, external/macaw
  observations:
    - root `test/` does not exist (verified: `ls test` fails); Haskell tests live in cases/performing-rigs/test.
    - Quick start builds from repo root after `cd ../..`; toolchain.md builds inside external/macaw (contradiction; also noted in architecture-reconciliation §D).
    - No mention of agent/ (Python agent, ledger) — the largest subsystem per status.md.
    - Cortex-M framing contradicts CLAUDE.md's multi-architecture target (CLAUDE.md acknowledges current state as Cortex-M-specific).

- path: AGENTS.md
  covers: Codex operator role pointer
  kind: operator guide
  key_claims:
    - operator, not developer (3); answer questions using existing APTrace capabilities (5-7)
    - avoid replacing missing functionality with independent scripts/tools (11-12); gaps are findings (14-15)
    - every substantive investigation reports answer, evidence, execution, gaps, next work (17-19)
  code_referenced: docs/codex-operator.md
  observations: none; thin pointer to codex-operator.md.

- path: CLAUDE.md
  covers: development instructions for Claude Code — goal, framework/case boundary, engine ownership, p-code dataflow rules, evidence discipline, claim safety, repository protection
  kind: methodology / development rules (normative)
  key_claims: (see Documented intent below; sections "What we are building", "Framework/case boundary", "Analysis-engine ownership", "Static dataflow and custom Python", "Developing APTrace, not substituting for it", "Analysis discipline", "Evidence discipline", "Model output and claims", "Protecting research and repository state")
  code_referenced: tools/census/ (indirect_target, callback_provenance, fnptr_resolve), capstone_sweep.py, value_forward_use, ResearchController, trace_value_use, docs/*
  observations:
    - Explicitly says "Today most layers are still Cortex-M/Thumb-specific and single-case wired ... Treat that as current state to reduce" — reconciles with README/architecture.md framing only by declaring them current state.
    - "existing case imports are recorded seams" — matches case-boundary.md.
    - "Wiring an operation into the agent currently touches about ten modules" — matches architecture-evaluation §6.5 (12 modules) / reconciliation (~10).

- path: docs/README.md
  covers: framework documentation index
  kind: index
  key_claims: Start-here list (architecture, status, adding-a-case, case-boundary, toolchain, aptrace-agent-framework "roadmap", research-ledger, cross-engine-verification, work-store, spikes/beads-work-store); Tooling list (tool-selection, ghidra-backend, pcode-forward-use, pcode-migration, unicorn-backend, macaw-analysis, census, compact-ram-initialization, harness/execution-model)
  code_referenced: none
  observations:
    - Not indexed: claim-admission.md, claim-call-relations.md, claim-candidates.md, research-continuity.md, codex-operator.md, spikes/architecture-evaluation.md, spikes/architecture-reconciliation.md, spikes/investigation-continuity.md.
    - Describes aptrace-agent-framework.md as "roadmap for the Galois-first binary map" — that roadmap's engine primacy is contradicted by decision B (architecture-evaluation.md).

- path: docs/adding-a-case.md
  covers: how to add a case; ownership rule
  kind: methodology (normative)
  key_claims:
    - (intro) case under cases/<name>/, minimum a README
    - (Ownership rule) framework owns mechanisms (loaders, engines, discovery, normalization, evidence schemas, backend interfaces); case owns recipes (firmware registries, geometry, addresses, scenarios, device models, experiments, evidence); case may depend on framework, not reverse; application may wire explicitly
    - (Documentation and evidence) "could it exist unchanged if the target never existed?" test; no root research/
  code_referenced: none
  observations: consistent with CLAUDE.md.

- path: docs/aptrace-agent-framework.md
  covers: roadmap for Galois-first whole-binary behavioral map, local-model labeling, job-2 tool surface
  kind: design / roadmap
  key_claims:
    - (Recalibration, 8-14) Agent v0 un-parks the controller; phases pursued when needed, not as gates
    - (Jobs to be done) map binary; research mapped binary; patch (out of scope)
    - (Design principles) coverage drives job 1 via deterministic batch pipeline; "Galois tools produce the facts", Ghidra optional for map building but cross-engine corroboration still required; local models label, don't establish facts; every record carries status complete/bounded/failed(reason) and provenance; all pipeline code is framework code
    - (Starting point table) Macaw census "never ingested", SymbolicRunner single-block; agent wired to one case; controller parked
    - (Phase 1) ingest macaw-census into census DB with source column; coverage ledger; macaw-refinement for indirect transfers
    - (Phase 2) APTrace.FunctionSummary module + `aptrace summarize`; MMIO fresh symbolic; log loads/stores; callee summaries or flagged havoc; bound loops; leaves-first
    - (Phase 3-5) function_effects table, whole-program facts, Qwen/Gemma labeling with deterministic validator, MCP server, GREASE eval
    - (Job 3) Renovate/PATE evaluation
  code_referenced: tools/census/, APTrace.MacawCensus, APTrace.SymbolicRunner, agent/, agent/benchmarks/trigger-role.md, APTrace.FunctionSummary (does not exist), aptrace summarize (does not exist)
  observations:
    - Phase 0 "controller parked" vs Recalibration "un-parked as Agent v0" — internal tension within the doc.
    - "Ghidra becomes optional ... not the critical path" and Macaw as "primary census source" contradict decision B (architecture-evaluation.md §7, tool-selection.md, CLAUDE.md engine table). architecture-reconciliation §C/§K flags it as never reconciled.
    - "Documentation drift" risk (186-187) says tool-selection names Ghidra primary, to update when Phase 1 lands — now tool-selection intentionally names Ghidra primary per decision B.
    - Phase 2 spike = EffectsSpike.hs, which became production function-effects without the FunctionSummary abstraction.
    - Names case benchmark path in a root doc (114) as "for the current case".

- path: docs/architecture.md
  covers: component model, verification architecture summary, dependency direction, layout
  kind: design (overview)
  key_claims:
    - (intro) "workbench for analyzing raw bare-metal Cortex-M firmware"
    - (Component model) FirmwareLoader from caller-supplied geometry; VectorTable; APTrace.Macaw* discovery/normalization/classification/expansion/refinement; SymbolicRunner/ProtocolHarness bounded Crucible; tools/ghidra, tools/unicorn, tools/census
    - (Verification architecture) four stages: independent discovery, deterministic comparison, reconciliation, claim verification; agreement never sufficient
    - (Framework and case dependency direction) case -> framework only; application may wire
    - (Repository layout) lists test/ "reusable framework tests"
  code_referenced: APTrace.FirmwareLoader, VectorTable, Macaw*, SymbolicRunner, ProtocolHarness, tools/*
  observations:
    - Diagram omits agent/, ledger, census-as-store, p-code, function_effects/EffectsSpike, DebugHarness.
    - Lists nonexistent test/.
    - Cortex-M framing vs CLAUDE.md goal.
    - Lists MacawRefinement as a discovery capability; reconciliation reports it broken (test 16 fails, patch lost), and its own Haddock says no block refined.

- path: docs/case-boundary.md
  covers: intentional framework/case coupling seams
  kind: status / design
  key_claims:
    - (Intentional current seams) app/Main.hs imports case modules; aptrace.cabal includes cases/performing-rigs/src and case test dir; tools/ghidra/aptrace_ghidra.py loads case firmware registry and cache; census CLI/build/reducer import case recipes; tools/doctor.sh uses case firmware as optional fixture; ConcreteMachine/run_concrete.py keep case flash/RAM defaults
    - (Deferred extraction) on a second case, explicit case selection at CLI and injection of registries etc.; second Cabal package only when needed
  code_referenced: app/Main.hs, aptrace.cabal, tools/ghidra/aptrace_ghidra.py, tools/census/, tools/doctor.sh, ConcreteMachine, run_concrete.py
  observations:
    - Does not list agent-side case wiring (executor.py autopilot_ghidra_index, performing_rigs_census, ATSAMD51 SVD path; "34 framework files name the case") that architecture-evaluation.md §2 reports as "case-specific wiring inside the framework agent".
    - Does not list case-specific constants/comments inside framework Haskell modules (DebugHarness r3=0x26 at :161; AutoPilot addresses in FirmwareLoader Haddock).

- path: docs/claim-admission.md
  covers: deterministic admission of planner claim proposals into the ledger
  kind: design (normative + status)
  key_claims:
    - (intro) admission reuses verifier semantics; not a second validation system
    - (Three separate decisions) admission -> PROPOSED; evidentiary support via verify_semantics; verification via ClaimVerifier phases; admission never verifies
    - (Admission rules 1-8) parse; evidence references; entity identity; typed semantics consistency; untyped peripheral access/absence; call relations (5b); grade ceiling, untyped <= PROBABLE; follow-up accountability; historical references are not corroboration
    - admitted only with no reject diagnostic; nothing rewritten (untyped STRONG rejected, not downgraded)
    - (Entity identity) FUN_ + 8 lowercase hex or 0x address; session ids not in assertion; FUN_ resolves via FunctionFacts reader; numbered peripherals among census peripherals
    - (Constant load is not an access) MMIO_USER requires actual access; ADDRESS_CONSTANT_LOADER new role (UNDETERMINED class)
    - (Bounded handling) one correction round; all proposals recorded in InvestigationRun.claim_admission; no admitted claim is valid outcome
    - (Limitations) applicability by wording; planner line can't carry typed semantics
  code_referenced: agent/src/aptrace_agent/research/admission.py, ledger/claim_checks.py, ledger/claim_semantics.py, controller _accept_claims
  observations:
    - Peripheral examples SERCOM0, TCC1 (SAMD peripheral names) in a root doc — illustrative, case-flavored.
    - FUN_ + 8 hex digit identity is Ghidra-naming and 32-bit-address specific.

- path: docs/claim-call-relations.md
  covers: checking call/dispatch/reach/absence assertions against cited call edges
  kind: design (normative + status)
  key_claims:
    - (Edge kinds) DIRECT_CALL, TAIL_TRANSFER, ESTABLISHED_INDIRECT, POTENTIAL_INDIRECT (always conditional), OBSERVED_DISPATCH; edges only from structured result fields; named functions, table entries, pointers, missing edges are not edges; unresolved sites recorded as unresolved
    - (What an assertion needs) categorical needs static edge; possible needs condition restated with address; observed needs scenario; universal wording never supported; reachability via <=8 cited edges; absence only scoped to recorded analysis
    - (Other rules) disjunctions each supported; nothing rewritten; grade no stronger than edge evidence
    - (Typed relations) CALL_RELATION predicate; kinds; POTENTIAL_INDIRECT needs conditions, OBSERVED_DISPATCH needs scenario; policy classes CONTROL_FLOW / RESOLVED_INDIRECT_CALL without evidence contract -> stay PROPOSED; no candidate extractor yet
    - (Where it applies) admission and verification phase B; historical claims not re-lifecycled
    - (Prose forms) small classifier; unclassified -> CALL_RELATION_UNCHECKED, capped PROBABLE
  code_referenced: agent/src/aptrace_agent/ledger/call_relations.py, claim_semantics.py, claim_checks.py, research/admission.py, ledger/verifier.py, ledger/policy.py, ledger/gate.py
  observations:
    - Edge evidence definitions name ARM/Thumb mnemonics (BL/BLX immediates, B, B.W, B<c>) — ISA-specific vocabulary in framework admission semantics.

- path: docs/claim-candidates.md
  covers: deterministic evidence-to-claim candidate extraction and planner selection by id
  kind: design (normative + status)
  key_claims:
    - (intro) extraction by fixed rules; planner only selects ids; admission and verification unchanged
    - (Supported candidates) peripheral-role MMIO_USER (BEHAVIOR), ADDRESS_CONSTANT_LOADER (STRUCTURE), resolved-pointer RESOLVED_FUNCTION_POINTER (RESOLUTION)
    - (Withheld facts) ACCESS_UNDER_ASSUMPTION, ROLE_CONFLICT, POINTER_CONFLICT, ENTITY/PERIPHERAL_UNKNOWN, GRADE_INSUFFICIENT, SEMANTICS_UNSUPPORTED
    - (Not extracted) call-site relations, bounded effects observations, negatives, common paths
    - (What a candidate holds) K- + 12 hex SHA-256 over generator version, type, semantics, grade, sorted evidence content identities
    - (Ranking) lexical/objective-based; default 0 for controller, 5 on CLI
    - (Selection) select_claims(selected: string); exact id match; model cannot change semantics
    - (Duplicates) equivalence by typed semantics; recorder authoritative; never merged
    - (Grade, lifecycle) admitted candidate is PROPOSED; under policy v1 stays PROPOSED
  code_referenced: agent/src/aptrace_agent/research/candidates.py, ResearchController._select_candidates/_request_candidate_selection, ledger/recorder.py
  observations: "No typed predicate exists" for call-site relations here vs claim-call-relations.md which defines typed CALL_RELATION (but notes no candidate extractor) — wording tension; status.md resolves it ("call relations have one (CALL_RELATION) but no candidate extractor").

- path: docs/codex-operator.md
  covers: full operator methodology for Codex
  kind: operator guide
  key_claims:
    - (Role/Core philosophy) operate APTrace, don't develop it; success = effective use, accurate distinction of findings, clear gaps, preserving APTrace as the evidence mechanism
    - (Executing investigations) six steps; prefer documented workflows
    - (Tool and workflow selection) engines are implementation details; existing internal script is not automatically an approved interface
    - (Handling missing capabilities) eight gap categories; don't conceal gaps
    - (Source code) preserve implementation; development requires explicit role change
    - (Evidence discipline) six evidence distinctions
    - (Required end-of-run report) 5 sections incl. capability-gap report with gap/impact/evidence/cause/needed/priority
  code_referenced: none specific
  observations: not indexed in docs/README.md.

- path: docs/cross-engine-verification.md
  covers: normative independent-discovery and cross-engine verification requirements; policy v1
  kind: design (normative) + status
  key_claims: (see Documented intent) Guiding invariant; Terms (engine, derived source, lineage, independent vs assisted, target configuration); four stages; input restrictions table; per-observation lineage; comparison outcomes AGREE/DISAGREE/COVERAGE_GAP/INCOMPARABLE/UNAVAILABLE; per-kind granularity; native artifacts + minimal envelope; discrepancies retained, reconciliation never overwrites; claim class computed mechanically; policy versioned; phase P; policy v1 details (CODE_EXISTENCE only contract); claim class table; kinds of support 1-5; agent autonomy limits; implementation status table; acceptance criteria
  code_referenced: agent/src/aptrace_agent/ledger/policy.py, ledger/gate.py, APTrace.MacawCensus, tools/census/macaw_compare.py, ExecutionContext.firmware_sha256, SourceObservation.derived_from, structural_source_agreement, function_effects, observed_call_arguments, work/
  observations:
    - Implementation status confirms code observation: Macaw census records path/size/flash/RAM but no firmware digest; Macaw/macaw-symbolic versions not recorded (MacawCensus.hs:656-663; EffectsSpike JSON has neither).
    - Status table lists "Target configuration record: [Missing]" — tags used elsewhere are Implemented/Partial/Required/Proposed; "Missing" is not one of the four declared tags.
    - "Thumb state bit" canonicalization given as an example normalization (178) — ISA example, acceptable.
    - No rule for rooted Macaw runs seeded from census addresses (gap noted by reconciliation §K).

- path: docs/harness/execution-model.md
  covers: Crucible/What4/Z3 harness model and correctness rules
  kind: methodology
  key_claims:
    - query supplies memory image, target function/block, pointer/register overrides, bounded overlays, symbolic inputs, property; large RAM compact
    - (Correctness rules) seed stack/pointers explicitly; keep solver assumptions distinct from concrete literals; don't infer behavior from divergent harness; validate against Unicorn; prefer isolated/understood regions over whole-function replay
  code_referenced: APTrace.SymbolicRunner, APTrace.ProtocolHarness, cases/performing-rigs/docs/investigations/symbolic-harness-results.md
  observations: does not mention EffectsSpike/function-effects (the only harness exposed to the agent) or DebugHarness.

- path: docs/research-continuity.md
  covers: reuse of prior operations in follow-up investigations (continuity-v1)
  kind: design + status
  key_claims:
    - (Three kinds of state) historical (never counted as this run's evidence), current-session, pending leads; reused alias maps to original evidence id; no ToolInvocation written for reuse
    - (When reusable) same tool + canonical args; deterministic tool; succeeded; same firmware sha256/key; identical input hashes; evidence VALID; blob hash ok; current analysis version
    - (Controller policy) no rerun; prerequisites preloaded; seeded leads first; discovery gating; caps count executed only; planner-failure fallback (<=3)
    - (Budget) reuse free for first 4 then one step
    - (Provenance guarantees) originals never rewritten; reused listed separately
    - (Limitations) tool changes without analysis version undetected at reuse
  code_referenced: agent/src/aptrace_agent/research/history.py, session.py, controller.py, projection.py, ledger/recorder.py
  observations: not indexed in docs/README.md.

- path: docs/research-ledger.md
  covers: research ledger store, identity/replay, grades/states, claims, typed semantics, structural source agreement, audit, verification phases, staleness, CLI
  kind: design (normative) + operator reference
  key_claims: (see Documented intent) three layers/authorities; append-only content-addressed store under the case; ExecutionContext/ToolInvocation/EvidenceArtifact identity; evidence-form hashing; grades vs lifecycle states; ClaimVersion supersession; inherited limitations; typed predicates (RESOLVED_FUNCTION_POINTER, FUNCTION_ROLE, PATH_RELATION, CODE_PRESENCE); structural source agreement statuses; audit contract (falsification requirement, fingerprint); verification phases A, B, C, P, D; VERIFIED meaning; CHALLENGED permanent; staleness propagation; commands
  code_referenced: agent/src/aptrace_agent/ledger/, ledger_wiring.py, claim_semantics.py, source_agreement.py, ledger/pipeline.py, policy.py, gate.py
  observations:
    - RELATION_MISMATCH includes "non-Thumb-canonical target" — ISA-specific notion in typed semantics.
    - Typed predicate table omits CALL_RELATION (defined in claim-call-relations.md) and ADDRESS_CONSTANT_LOADER role (claim-admission.md) — table lags later docs.
    - ExecutionContext input artifacts include "Macaw census" by hash; status says Macaw census has no firmware digest.

- path: docs/status.md
  covers: framework capability status and limitations
  kind: status
  key_claims:
    - (Available capabilities) raw Cortex-M loading + vector table; Macaw discovery + semantic classification; Ghidra projects; Unicorn Thumb concrete execution; Crucible/What4/Z3 reachability and input-model questions; census DB; function-effects (geometry from case, caller supplies entry + rN=); observed_call_arguments; argument-default operation identities; slot_dispatch; indirect_target v1/v2 (detailed); value_forward_use p-code (11 Thumb + 7 RV32 controls, opt-in trace_value_use); callback_provenance; fnptr_resolve; Agent v0; ledger; Beads work; follow-ups; continuity; admission; call relations; candidates
    - (Current limitations) not general MCU simulator; heuristic boundaries; dataflow split p-code vs Capstone (ARM-only backward RD); admission doesn't check value-flow; symbolic best for targeted regions; caller-grounded scope; function effects don't resolve tbb/tbh (bounded); indirect-target intraprocedural; fnptr STRONG never EXACT; common-path NO_KNOWN_PATH; planner prefill limit; verification mechanical; policy v1 only CODE_EXISTENCE and no real source declares envelope; Qwen tool-call limits; work items manual; follow-up limits; case selection explicit
  code_referenced: tools/unicorn/call_observation.py, ConcreteMachine, ledger/semantics.py, tools/census/slot_dispatch.py, indirect_target.py, tools/ghidra/pcode_forward_use.py, callback_provenance.py, fnptr_resolve.py, agent/, macaw_compare.py
  observations:
    - "Translate bounded Macaw regions into Crucible and ask What4/Z3 reachability and input-model questions" listed as a capability, but runGateReachability/SymbolicRunner are reachable only via case CLIs (solve/protocol/trigger in PerformingRigsScenarios via Main.hs:34-40); flagged by reconciliation §C/§K.
    - function-effects limitation lists only tbb/tbh; code confirms it uses unrepaired discovery (EffectsSpike.hs:153 calls MD.cfgFromAddrs directly, no MacawExpand), and early-cbz failure is documented in tool-selection.md and architecture-evaluation §4.4 but not in status.md.
    - Agent v0 action list (179-184) omits later actions (observe_call_arguments, resolve_indirect_call, trace_callback_argument, trace_value_use, select_claims) though some are described elsewhere in the doc.
    - Names case claim ids C2:v2, C5:v1 (311) in a root doc.
    - Lists Macaw "semantic classification layer"; reconciliation found BL-prefix rule mislabels direct BL as true_indirect_call (confirmed in MacawIsaClassify.hs:140).

- path: docs/toolchain.md
  covers: build and dev environment
  kind: operator guide
  key_claims:
    - (Haskell build) inside external/macaw: submodule update; `ln -sf cabal.project.freeze.ghc-9.6.7 cabal.project.freeze`; cabal build aptrace; cabal test aptrace-test; GHC 9.6.7; Z3 on PATH
    - (Python and Ghidra) tools/unicorn/.venv from requirements; analyzeHeadless or GHIDRA_HOME; tools/doctor.sh
    - case-specific notes in cases/performing-rigs/docs/investigations/toolchain-case-notes.md
  code_referenced: external/macaw, tools/unicorn/requirements.txt, tools/doctor.sh
  observations:
    - The ln -sf step is meant to run inside external/macaw; the root `cabal.project.freeze` symlink (untracked, dangling) looks like this step run in the wrong directory.
    - Omits agent env (uv), local model server, Beads bd 1.3.1, Ghidra/Z3 versions, vendored engine commits (reconciliation §D).

- path: docs/work-store.md
  covers: optional Beads-backed work items and hand-off to the ledger
  kind: design + operator guide
  key_claims:
    - (Who owns what) Beads = work; APTrace = knowledge; work/ has no ledger write path; ledger/ and research/ don't import work/; closing work never changes claim or discrepancy state
    - (Link) InvestigationRun.work_item_id exact; aptrace_run_ids + link basis; heuristic matches only reported
    - (Setup) bd 1.3.1, store outside git tree, BEADS_DIR, DO_NOT_TRACK=1
    - (Running) seven-step research --work-item procedure; completion explicit
    - (Reconciliation) states ready/active/link-runs/awaiting-completion/interrupted/claimed-by-other/operator-review/conflict/completed; only repair is linking
    - (Ownership) Beads claim + host-local flock + attempt marker; lease expiry releases nothing; APTrace never runs reclaim/heartbeat
    - (Backup) bd backup sync; export lacks history
    - (Not yet automated) list
  code_referenced: agent/src/aptrace_agent/work/, work_cli.py, ledger_wiring.work_dir, handoff.followup_for_audit
  observations: examples use ~/.aptrace/work/performing-rigs and a USB_OTHER objective — case names in root operator examples.

- path: docs/tooling/tool-selection.md
  covers: engine selection and ownership
  kind: methodology (normative)
  key_claims:
    - (table) Ghidra structure; Ghidra p-code dataflow; Unicorn known input; Macaw independent lifter; Crucible+What4+Z3 bounded property
    - (Engine ownership, decision B) Ghidra primary structural + p-code dataflow; decompiler cross-check only; Macaw independence, needs MacawExpand repair; Crucible function_effects uses unrepaired discovery and fails early on cbz; Unicorn Thumb/M hard-coded; APTrace engine-neutral envelope
    - (Custom instruction analysis) ~2,800 lines Capstone ARM; new analyses p-code first; Python resolvers stay until parity; custom interpretation only for engine gap or cross-check (capstone_sweep.py)
    - (Operating rules) Macaw: Cortex-M is Thumb-only, investigate A32; symbolic only after region/property bounded; disagreements -> first divergence; agent chooses tool, not corroboration
  code_referenced: pcode-forward-use.md, pcode-migration.md, MacawExpand, function_effects, capstone_sweep.py, tools/census/
  observations:
    - Consistent with code: EffectsSpike uses MD.cfgFromAddrs without MacawExpand.
    - "Use Macaw ... Cortex-M is Thumb-only" operating rule is platform-specific in a root methodology doc.

- path: docs/tooling/macaw-analysis.md
  covers: Macaw discovery/normalization/comparison
  kind: methodology / status
  key_claims:
    - Macaw as independent Cortex-M discovery/lifting; seeds normalized Thumb entries; preserves unresolved transfers; iteratively feeds recovered targets back
    - separates machine-level meaning of ambiguous transfers from call assumptions; normalized evidence records provenance
    - modules MacawCensus, MacawExpand, MacawIsaClassify, MacawNormalize, MacawRefinement; geometry and roots are caller inputs
    - macaw-census independent by construction (vector roots only); seeding from another engine -> assisted; no firmware digest, toolchain version not recorded
  code_referenced: APTrace.MacawCensus, MacawExpand, MacawIsaClassify, MacawNormalize, MacawRefinement, cases/.../macaw-analysis-results.md
  observations:
    - Omits rooted `explore`, MacawRefinement's non-functional state, and the BL true_indirect_call mislabel (reconciliation §K).
    - Matches code: MacawCensus seeds only from vector table (MacawCensus.hs:268-278); geometry params passed from Main.hs.

- path: docs/tooling/compact-ram-initialization.md
  covers: compact representation of default RAM in symbolic queries
  kind: methodology
  key_claims: don't materialize every RAM byte; preserve byte semantics; explicit overlay precedence; separate concrete init from symbolic vars/assumptions; validate against concrete execution
  code_referenced: cases/performing-rigs/docs/investigations/compact-ram-initialization.md
  observations: implemented in ProtocolHarness.hs:298-332 (one constant-array store per writable segment); not applied in EffectsSpike (RAM unconstrained symbolic) or SymbolicRunner.

- path: docs/spikes/architecture-evaluation.md
  covers: engine ownership evaluation; decision B
  kind: spike (verdict PARTIAL, decision B)
  key_claims:
    - (Decision B) instruction-level/intraprocedural dataflow -> Ghidra p-code behind APTrace adapter; Python for interpretation/policy/evidence; Macaw independent + Crucible front end; Crucible bounded; Unicorn concrete; stop Capstone semantics
    - (§1) Python/Capstone is an undocumented fifth engine (~2,800 lines); EffectsSpike over upstream Macaw without MacawExpand
    - (§2) analysis core ISA-coupled unmarked; 34 framework files name the case; SVD lookup mechanism lives in case (inverted)
    - (§3) engine comparison table
    - (§4) controls: raw p-code passes 11 Thumb + 7 RV32 after one generic fix; Capstone v1 missed 4; decompiler heuristic; real image agreement; missing function attribution must be INCOMPLETE
    - (§4.4) upstream Macaw recovers 1 block (cbz); with MacawExpand 66 blocks/10 rounds/47 resolutions; macaw-aarch32 lacks RegisterUse; function-effects failed after 1 block
    - (§5) RISC-V portability table
    - (§6) risks incl. production symbolic path diverges from repaired discovery; 12-module integration cost; case wiring in agent
    - (§7) ownership table; engine identity in operation record; shared derivation-step record; completeness enum
    - (§8) migration steps 0-6 (target descriptor; pilot; freeze; indirect_target v3; rebase; function_effects on MacawExpand; operation descriptors)
    - (§9) pilot pointer_forward_use acceptance criteria; (§10) established vs not
  code_referenced: tools/census/*.py modules, APTraceExportCensus.java, aptrace_ghidra.py, APTraceSeedVectorTable.java, raw_scan.py, FirmwareLoader.armCortexMInfo, macawCortexMEntry, concrete.py, call_observation.py, EffectsSpike.hs, SymbolicRunner.hs, agent executor.py etc., resolve_mmio.py, experiments/*
  observations:
    - "Branch spike/architecture-evaluation; nothing is committed" (20) is stale — commit 5d383b5 exists in history.
    - Code confirms §1 row: EffectsSpike.hs:153 uses plain cfgFromAddrs.
    - Pilot named pointer_forward_use; implemented operation is value_forward_use (naming drift, per status.md/CLAUDE.md).

- path: docs/spikes/architecture-reconciliation.md
  covers: provenance of original design vs current capability; gaps; recommended milestone (invocation paths + path feasibility)
  kind: spike (verdict PARTIALLY ALIGNED)
  key_claims:
    - (§A) timeline: Galois-first feasibility spike; reachability as purpose; tool hierarchy Ghidra -> Unicorn -> Macaw/Crucible; cbz classify failure; Macaw census; agent; Galois-first roadmap again; ledger; target-centered Python resolvers; decision B
    - (§A.2) Macaw roles: Crucible front end, reachability with Crucible, independent discovery, (never implemented) primary census source
    - (§B) current implementation per engine with run evidence; Macaw expand 263 functions/3,521 blocks; macaw-refinement non-functional (patch lost, test 16 fails); function_effects unrepaired, no per-query solver timeout; runGateReachability case-only
    - (§C) capability provenance table; forgotten decisions (agent-framework not reconciled; step 5 not done; runGateReachability in case script; agent uses base census)
    - (§D) toolchain table; contradictions (README build path, root test/, architecture.md framing, census.md flow, status.md reachability claim, engine identity unrecorded, vendored Macaw gitignored)
    - (§F) defects: MacawIsaClassify BL-prefix labels direct BL as true_indirect_call (1,206/1,229); refinement patch lost; no digest/versions; DEFINITELY_REACHABLE reads stronger than evidence; four Crucible harnesses with copied setup
    - (§G) reconciled ownership; rooted Macaw runs from census addresses are assisted
    - (§H) milestone invocation_paths + path-feasibility + witness replay; prerequisite fixes; grades; acceptance criteria; non-goals
    - (§K) documentation update list
  code_referenced: EffectsSpike.hs:153, ProtocolHarness.runGateReachability, MacawExpand.expandWithNormalization, MacawIsaClassify, MacawRefinement, controller.py:35, source_agreement.py:382, function_effects.py:195-201, census_graph._Graph, slot_dispatch, ConcreteMachine.call
  observations:
    - Code confirms: MacawIsaClassify.hs:140 `"BL" isPrefixOf mnem` with mret Just -> TrueIndirectCall regardless of immediate/register form; four harnesses each duplicate withZ3Backend/resolvedPointer/concreteZeroVar.
    - Not indexed in docs/README.md. References untracked `pcode-migration-baseline/migration-interruption.md` (matches git status: untracked cases/performing-rigs/research/runs/pcode-migration-baseline/).
    - Contains case addresses/function ids (FUN_0000b4b4, c7c0, SERCOM0, mando868) in a root spike doc.

- path: docs/spikes/beads-work-store.md
  covers: Beads evaluation as long-horizon work store
  kind: spike (ADOPT WITH CONDITIONS)
  key_claims:
    - bd 1.3.1 embedded Dolt; boundary rules (ledger/research don't import work/; no ledger write path in work/; ids only in aptrace_* metadata; BEADS_DIR, DO_NOT_TRACK=1; refuse git tree; version pin)
    - safety findings (telemetry default, bd init git commit, .gitignore append, ~/.dolt config)
    - experiments A-J results; J (workflows) PARTIAL: Beads cannot branch on audit verdict
    - conditions: exact run correlation, restart policy, heartbeat, backups, pin/isolate, follow-up key policy
  code_referenced: agent/src/aptrace_agent/work/{store,beads,handoff}.py, agent/tests/test_work_beads.py, agent/scripts/beads-spike.sh, controller.py, investigator.py, ledger/*
  observations: describes spike-time design (heuristic orphan link, `link-orphan-run`, close on completion); production work-store.md supersedes with exact work_item_id link and explicit completion — the spike doc says so at the top.

- path: docs/spikes/investigation-continuity.md
  covers: follow-up candidate generation, persistence, seeded execution
  kind: spike (PARTIAL)
  key_claims:
    - mechanism works deterministically; live planner followed 2/6 seeded leads, re-ran prior analyses
    - open leads not durable; re-derived by replaying LeadDeriver when context_id matches
    - candidate sources (peripheral-access gap, device identity, audit, verification, staleness, lead group); consolidation; category ranking; dedup keys question_key/key; Beads id <prefix>-fq<key[:10]>
    - provenance; bounded context; failure/recovery table; recorder fix for input_evidence_ids
    - next milestone implemented as continuity-v1
  code_referenced: agent/src/aptrace_agent/research/followups.py, ResearchState.leads, LeadRegistry, LeadDeriver, PlannerProjection, seed_session, handoff.run_investigation
  observations: not indexed in docs/README.md; "STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY" limitation referenced.

- path: docs/spikes/architecture-evaluation/experiments/ (listed only)
  covers: spike experiment artifacts
  kind: spike artifacts
  files:
    - fixtures/expected.json, fixtures/extract_text.py, fixtures/rv32_controls.bin, fixtures/rv32_controls.py, fixtures/thumb_controls.bin, fixtures/thumb_controls.s
    - ghidra/PointerUseProbe.java
    - macaw/DumpBlocks.hs
    - python/capstone_forward_use.py, python/capstone_forward_use_v1.py, python/unicorn_ea54.py
    - results/ghidra_rv32_controls.json, results/ghidra_thumb_controls.json, results/python_v1_thumb_controls.txt, results/python_v2_thumb_controls.json
  observations: `unicorn_ea54.py` name suggests a case address; contents not read (list-only scope).
```

---

## Observed behaviors

Haskell code, with file:line.

- Single CLI `aptrace` dispatches by literal arg patterns; generic and case commands share one entry (app/Main.hs:33-60).
- All commands receive Performing Rigs geometry (`ramBase` 0x20000000, `ramSize` 0x30000, `numIrq`, `defaultFlashBase`, `mmioWindow`) from `APTrace.Case.PerformingRigs` (app/Main.hs:18, 34-59); only flash base is CLI-overridable, and only for run/solve/explore/macaw-census/macaw-census-expand.
- `function-effects` and `effects-spike` both call `runEffectsSpike`; production differs only by constants: target MMIO window, no arg overrides, step bound 3000, no parametric uniqueness queries (app/Main.hs:51, 57).
- `effects-spike` always adds the solver specialization arg_r0 == 1 (app/Main.hs:50-51).
- Library compiles case modules into itself (aptrace.cabal:19-22); test suite is case-only (aptrace.cabal:74).
- Vector table parsing reads 16+numIrq little-endian words, skips index 0 and zero words, names entries by ARMv7-M conventions (VectorTable.hs:27-58).
- Memory image: flash RX segment + zero RAM RW segment in region 0; optional MMIO RW segment (FirmwareLoader.hs:60-105).
- Every code root gets the Thumb bit forced (`.|. 1`) before Macaw discovery (FirmwareLoader.hs:137-138, 193; MacawCensus.hs:277; DebugHarness.hs:106; EffectsSpike.hs:151; Main.hs:135).
- `armCortexMInfo` forces PSTATE_T=1 in initial abstract state and defaults a failed block precondition to Thumb (FirmwareLoader.hs:172-183).
- Macaw census: vector-root-only discovery, exception captured into `discovery_error` with empty lists (MacawCensus.hs:344-363); deterministic sorted JSON on stdout (418-432, 746-759, 790); no digest/engine version in output (656-663).
- Calls classified direct/unmapped/indirect from Macaw curIP (MacawCensus.hs:639-648); every ParsedCall also gets an APTrace ISA classification (556-571).
- ISA classification by mnemonic-prefix text from Macaw InstructionStart; any "BL*" with return -> true_indirect_call, including direct BL immediates (MacawIsaClassify.hs:132-145).
- Normalization accepts only the nested-identical-condition mux identity with concrete mapped targets (MacawNormalize.hs:106-115); provenance "macaw-normalized" (51-52).
- Expansion fixpoint feeds recovered targets via `addDiscoveredFunctionBlockTargets`, then `analyzeDiscoveredFunctions`; aborts with `error` beyond 100 rounds (MacawExpand.hs:106-134, 170-187); emits expanded census + base/expanded coverage + rounds + residual classify failures (292-346).
- `refineFunctionAt` runs macaw-refinement with Z3, parallelism 1, 60 s timeout, scoped to one function; not wired to CLI (MacawRefinement.hs:107-133).
- SymbolicRunner: single-block CFG, SymbolicMutable memory, all registers fresh symbolic, optional concrete byte writes, one Z3 query for PC == target plus exclusions; three-valued result (SymbolicRunner.hs:152-239).
- DebugHarness: single block under crucible-debug with canned script, registers concrete zero except hardcoded r3 = 0x26 (DebugHarness.hs:160-163, 195-203).
- EffectsSpike: whole-function simulation; r0-r3 `arg_rN`, r4-r12/lr `in_*` symbolic; 4 KiB concrete stack; flash reads served concretely through `concreteUnmutatedGlobalRead`; writes observed via validity hook; opaque AAPCS call override clobbers r0-r3/r12 and records target/args/guard; step bound via exception (EffectsSpike.hs:203-340).
- EffectsSpike writes `<prefix>.raw.json` then `<prefix>.enriched.json`; one Z3 process with push/pop frames, smoke test gate, three-valued outcomes, enrichment capped to first access per (kind,pc), max 24 sites; enrichment failures recorded as `{error}` not thrown (EffectsSpike.hs:420-646).
- EffectsSpike uses upstream Macaw discovery, not MacawExpand (EffectsSpike.hs:153-156).
- No per-query solver timeout in EffectsSpike, SymbolicRunner or ProtocolHarness (no timeout configuration in any withZ3Backend; EffectsSpike.hs:728-741).
- ProtocolHarness: whole-function run with all registers concrete zero, compact zero overlay per writable segment, concrete zeroed 4 KiB stack, packet buffer concrete/symbolic bytes, AAPCS opaque calls; optional range trace, early-stop address query, SMT-LIB2 log artifacts (ProtocolHarness.hs:226-497, 793-805).
- `runGateReachability`: plain SymbolicMutable RAM (no overlay), unsupported function calls (throws on any call), stop-at-block query with not-equal exclusions; reports GateSat/GateUnsat/GateError (ProtocolHarness.hs:555-696).
- ProtocolHarness `debugFeature` calls `Exit.exitFailure` after 300000 steps — process-terminating from a library (ProtocolHarness.hs:817-820).
- `withZ3Backend`, `resolvedPointer`/`globalPointer`, `concreteZeroVar`, `freshBV32`, `BackendData` are duplicated across SymbolicRunner, DebugHarness, EffectsSpike, ProtocolHarness (e.g. SymbolicRunner.hs:76-91, EffectsSpike.hs:699-741, ProtocolHarness.hs:892-955, DebugHarness.hs:85, 208-232).
- All symbolic modules are fixed to AArch32 types (`ARM.AArch32`, `AR.ARMReg`), all discovery modules to `ARM.ARM`.
- Case-specific content in framework Haskell: AutoPilot addresses and firmware name in FirmwareLoader Haddock (FirmwareLoader.hs:144-161); AutoPilot `&` check 0x888c and r3=0x26 in DebugHarness (91-92, 161); "72 classify_failure ... autopilot868" in MacawExpand (95-97); "72 ... 49 of" in MacawNormalize (25-26); "48 indirect ... 23 ... 25" in MacawIsaClassify (7-14); "AutoPilot dispatcher", "0x20000000/0x30000 AutoPilot RAM", "seven of this investigation's own cells", and case investigation doc paths in ProtocolHarness (17, 122-123, 188, 209, 258, 321, 541, 620, 768).
- Comment references to nonexistent `docs/tooling/galois-premeeting.md` (DebugHarness.hs:16, 131, 189) and elided `docs/tooling/...` (MacawNormalize.hs:25).

## Documented intent

Flat list of normative rules and stated intent, with doc:section.

- APTrace is a reusable, autonomous, evidence-driven firmware investigation platform across devices, manufacturers, architectures; AutoPilot is the first case, not the architectural target — CLAUDE.md: What we are building.
- Cortex-M/Thumb specificity and single-case wiring are current state to reduce, not extend — CLAUDE.md: What we are building.
- Favor reusable capabilities with explicit firmware/platform configuration; architecture-aware but device-independent; deterministic evidence; controller-usable; remove duplicated tooling — CLAUDE.md: What we are building.
- Framework owns mechanisms (loaders, engines, Macaw/Ghidra/Unicorn integration, census, schemas, methodology); cases own identities, hashes, geometry, addresses, recipes, scenarios, evidence, findings, status — CLAUDE.md: Framework/case boundary; adding-a-case.md: Ownership rule.
- Case code may import framework; framework libraries must not import a case; explicit application wiring is acceptable; existing imports are recorded seams; no new ones — CLAUDE.md: Framework/case boundary; architecture.md: Framework and case dependency direction; adding-a-case.md: Ownership rule.
- No root `research/` directory — CLAUDE.md: Framework/case boundary; adding-a-case.md: Documentation and evidence.
- Root doc test: could it exist unchanged if the case never existed? — CLAUDE.md: Framework/case boundary; adding-a-case.md: Documentation and evidence.
- Engine ownership defaults: Ghidra structural discovery + p-code dataflow; Macaw independent lifting and Crucible front end; Crucible/What4/Z3 bounded symbolic questions; Unicorn concrete execution; APTrace orchestration/evidence/claims — CLAUDE.md: Analysis-engine ownership; tool-selection.md: Engine ownership; architecture-evaluation.md: Decision B, §7.
- Don't use symbolic execution to approximate ordinary concrete replay; don't reimplement mature engine capability without a demonstrated gap — CLAUDE.md: Analysis-engine ownership; tool-selection.md: Operating rules.
- New static analyses build on p-code; no new Capstone-operand semantics in tools/census/ (bug fixes allowed) — CLAUDE.md: Static dataflow; tool-selection.md: Custom instruction analysis; architecture-evaluation.md §8 step 2.
- Custom instruction interpretation only for a demonstrated engine gap or as an independent cross-check, stated in code and doc — CLAUDE.md: Static dataflow; tool-selection.md.
- Migrate side by side; replacement is a new analysis version and operation identity; retire only after deterministic comparison classifying every disagreement; historical identities stay valid — CLAUDE.md: Static dataflow; architecture-evaluation.md §8 step 3.
- p-code walkers contain no ISA tokens; needing one is a design finding — CLAUDE.md: Static dataflow; architecture-evaluation.md §9.
- Ghidra output is evidence, not truth; Ghidra-derived agreement is repeatability, not corroboration — CLAUDE.md: Static dataflow; tool-selection.md: Custom instruction analysis.
- Prefer making APTrace more capable over manual re-investigation; new capabilities should be bounded operations with structured I/O, firmware/arch identity, determinism, provenance, completeness/failure states, replay compatibility, controller integration — CLAUDE.md: Developing APTrace.
- Single-question tools stay case-local experiments — CLAUDE.md: Developing APTrace.
- Tool disagreements are evidence; harness failure is not firmware behavior until cross-checked; solver assumptions are not runtime literals; reproduce, find first divergence, fix narrowest layer; boundaries heuristic; escalate tracing gradually — CLAUDE.md: Analysis discipline; tool-selection.md: Operating rules; harness/execution-model.md: Correctness rules.
- Every conclusion discloses evidence level (static possibility vs established, conditional, concrete under harness, symbolic, reachability, unknown) and separates harness assumptions from firmware state — CLAUDE.md: Evidence discipline; cross-engine-verification.md: Kinds of support.
- A missing result is not evidence of impossibility; negatives complete only with established scope and self-reported completeness; incompleteness kinds never "no result" — CLAUDE.md: Evidence discipline; architecture-evaluation.md §4.3, §7 Evidence normalization.
- Every evidence-producing capability records engine name/version, ISA/ABI, configuration, firmware/source hashes, assumptions, limitations, replay info — CLAUDE.md: Evidence discipline; architecture-evaluation.md §7 Evidence normalization.
- Don't pass one engine's findings into another's independent run; derived sources and re-runs aren't corroboration; agreement is not proof — CLAUDE.md: Evidence discipline; cross-engine-verification.md §1.
- No firmware-derived claim reaches VERIFIED without independent-evidence requirements, deterministic comparison, and resolution of material contradictions; absence of corroboration stays visible — cross-engine-verification.md: Guiding invariant.
- Independent run requires same firmware digest (path/size insufficient), explicit target configuration, bounded scope, recorded engine identity — cross-engine-verification.md §1.
- Independence evaluated per observation by lineage; any cross-engine hint makes results assisted — cross-engine-verification.md §1.
- Comparison is deterministic, replayable, over structured observations, outcomes AGREE/DISAGREE/COVERAGE_GAP/INCOMPARABLE/UNAVAILABLE; normalizations mechanical and disclosed; function counts never evidence of agreement — cross-engine-verification.md §2.
- Native artifacts preserved and content-addressed; only a minimal common envelope plus typed comparison records — cross-engine-verification.md §2.
- Discrepancies retained; reconciliation never overwrites; resolution separate immutable record; model cannot resolve — cross-engine-verification.md §3.
- Claim class determined mechanically; policies versioned; policy evaluated as phase P before audit — cross-engine-verification.md §4; research-ledger.md: Verification.
- Agent cannot waive/weaken/reclassify verification requirements; no planner/auditor tool sets independence, class, policy or resolution — cross-engine-verification.md: Agent autonomy; acceptance criteria.
- Rooted Macaw runs seeded from census addresses are assisted, never independent corroboration — architecture-reconciliation.md §G (proposed addition to cross-engine-verification.md, §K).
- Correct tool selection is not evidence of correct conclusion; deterministic admission/verification decide; prefer structured mechanically derived claims; hypotheses capped at PROBABLE; close admission gaps before exposing new tools; never weaken admission — CLAUDE.md: Model output and claims.
- Admission: no reject diagnostic or not admitted; nothing rewritten; untyped claims at most PROBABLE; grade ≤ evidence ceiling; one correction round; all proposals recorded — claim-admission.md: Admission rules, Bounded handling.
- MMIO_USER requires an actual access; constant loads are ADDRESS_CONSTANT_LOADER — claim-admission.md: Constant load is not an access.
- Call relations: edges only from structured fields; categorical needs static edge; potential edges always conditional; observed scoped to scenario; absence only scoped to recorded analysis; never universal — claim-call-relations.md: Edge kinds, What an assertion needs.
- Candidates: extraction by fixed rules; planner selects ids only; model cannot alter semantics/grade/scope/evidence; equivalent typed semantics create no new version; nothing merged — claim-candidates.md: Selection, Duplicates.
- Ledger is canonical and append-only; records written once; state folded from events; reports are generated views — research-ledger.md: intro, Store.
- Investigation proposes, audit challenges, APTrace alone moves claim state — research-ledger.md: Three layers.
- Limitations inherited mechanically; CHALLENGED audit blocks a version permanently; VERIFIED means consistent with recorded evidence plus SUPPORTED independent audit, not semantic proof — research-ledger.md: Claims, Verification.
- Historical evidence and claim records never rewritten; changed analysis is a new version — CLAUDE.md: Protecting research; research-continuity.md: Provenance guarantees.
- Reused historical results are references, never this run's evidence or corroboration; reuse only on exact operation identity and validity checks — research-continuity.md: When a historical result may be reused.
- Beads owns work, APTrace owns knowledge; work/ has no ledger write path; closing work never changes claim or discrepancy state; heuristic run matches never linked — work-store.md: Who owns what, link; cross-engine-verification.md: Ledger and task tracking.
- Run experiments on scratch copies of ledgers, census DBs, Ghidra projects, case records, Beads state; preserve unrelated changes; no commit/push/claim change unless asked; no broad changes under guise of documentation — CLAUDE.md: Protecting research and repository state.
- Operators (Codex) operate, not develop; don't replace missing capability with scripts; report capability gaps in a structured end-of-run report — AGENTS.md; codex-operator.md: Handling missing capabilities, Required end-of-run report.
- Symbolic harness: seed stack/pointers explicitly; keep assumptions distinct from literals; don't infer from divergent harness; validate against Unicorn; prefer isolated regions — harness/execution-model.md: Correctness rules.
- Large RAM represented compactly; overlays explicit; validate against concrete execution — compact-ram-initialization.md.
- Macaw census is independent by construction (vector roots only); Cortex-M is Thumb-only, investigate any A32 — macaw-analysis.md; tool-selection.md: Operating rules.
- Map-building roadmap: records carry complete/bounded/failed(reason) status and provenance; local models label but never establish facts; model agreement is not engine corroboration; all pipeline code is framework code — aptrace-agent-framework.md: Design principles (engine primacy portion superseded per architecture-reconciliation.md §K).
- Case selection explicit at CLI on a second case; inject registries/roots/SVD/boot/hardware builders; second Cabal package only when a real case needs it — case-boundary.md: Deferred extraction; status.md: Current limitations.
- Planned migration: target descriptor (config only), freeze Capstone, indirect_target v3 on p-code, rebase callback_provenance/fnptr_resolve, point function_effects at MacawExpand, operation descriptors — architecture-evaluation.md §8.
- Recommended next milestone: invocation_paths + path_feasibility + witness replay with per-query solver timeouts, typed guards, engine identities on evidence, function_effects on repaired discovery; no complete-enumeration claim while frontier non-empty; empty path set with frontier is NO_KNOWN_PATH — architecture-reconciliation.md §G, §H.
