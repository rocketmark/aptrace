{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
-- | Runs a *whole* Macaw-discovered function (not just one block, contrast
-- 'APTrace.SymbolicRunner') via 'MS.mkFunCFG', with a chosen memory region
-- (e.g. an RX packet buffer) treated as controlled memory: either concrete
-- bytes (to reproduce a known transaction) or fresh symbolic bytes (to ask
-- What4/Z3 what byte pattern reaches a given outcome).
--
-- Current status, blockers, and the diagnostic technique ('debugFeature')
-- are documented in docs/harness/execution-model.md and
-- docs/harness/protocol-harness-results.md -- see those before changing
-- this module's call-handling or memory-model behavior.
--
-- Memory model: the base memory uses @SymbolicMutable@ content (Macaw-
-- symbolic's own population code then asserts nothing at all about RAM),
-- immediately followed by one explicit, compact overlay that reasserts
-- "every writable segment starts at zero" as a single SMT constant-array
-- store per segment -- not per byte. This produces the exact same
-- semantics the previous @ConcreteMutable@ setup did (all RAM, including
-- the pending-event array, starts at a known concrete value -- zero,
-- matching 'APTrace.FirmwareLoader.buildMemory'\'s zero-filled RAM), at a
-- fraction of the assertion count: @ConcreteMutable@ made Macaw-symbolic
-- assert @globalMemoryBytes[addr] == 0@ individually, once per byte, for
-- the *entire* RAM region regardless of whether a given query ever
-- touches most of it (~196,615 assertions for this project's own
-- 0x30000-byte RAM -- see
-- docs/tooling/compact-ram-initialization.md). This still matters for
-- soundness exactly as before: if the pending-event array were left
-- symbolic (as with plain @SymbolicMutable@, used in
-- 'APTrace.SymbolicRunner', which has no such overlay), the solver could
-- "solve" a query by simply picking a favorable *initial* value for that
-- memory rather than actually deriving it from real code execution. Only
-- the packet buffer itself is made symbolic, by directly overwriting
-- those specific bytes with fresh constants after the base memory
-- (including this zero overlay) is built.
module APTrace.ProtocolHarness
  ( PacketByte(..)
  , PacketResult(..)
  , runPacketTransaction
  , RichTraceConfig(..)
  , runPacketTransactionTraced
  , GateVar(..)
  , GateResult(..)
  , runGateReachability
  ) where

import qualified Control.Exception as X
import           Control.Monad ( foldM, when )
import           Control.Monad.IO.Class ( liftIO )
import           Data.IORef
import           Data.Maybe ( isNothing )
import           Data.Proxy ( Proxy(..) )
import qualified Data.Time.Clock as CT
import qualified System.Exit as Exit
import qualified Data.BitVector.Sized as BV
import qualified Data.Parameterized.Context as Ctx
import qualified Data.Word as W

import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery.State as MDS
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Memory.Permissions as Perm
import qualified Data.Macaw.Symbolic as MS
import qualified Data.Macaw.Symbolic.Memory as MSM
import qualified Data.Macaw.Symbolic.Regs as MSR
import qualified Data.Macaw.AArch32.Symbolic ()
import qualified Data.Macaw.ARM.ARMReg as AR
import qualified Data.Macaw.Types as MT
import qualified SemMC.Architecture.AArch32 as ARM

import qualified Lang.Crucible.Backend as CB
import qualified Lang.Crucible.Backend.Simple as CBS
import qualified Lang.Crucible.CFG.Core as CC
import qualified Lang.Crucible.FunctionHandle as CFH
import qualified Lang.Crucible.LLVM.DataLayout as LDL
import qualified Lang.Crucible.LLVM.Intrinsics as CLI
import qualified Lang.Crucible.LLVM.MemModel as CLM
import qualified Lang.Crucible.Simulator as CS
import qualified Lang.Crucible.Simulator.EvalStmt as CSE
import qualified Lang.Crucible.Simulator.ExecutionTree as CSET
import qualified Lang.Crucible.Simulator.GlobalState as CSG
import           Lens.Micro ( (^.) )

import           Data.Bits ( (.|.) )
import qualified Data.Parameterized.Nonce as PN
import qualified Numeric
import qualified System.IO as IO
import qualified What4.Config as WC
import qualified What4.FunctionName as WF
import qualified What4.Expr as WE
import qualified What4.Interface as WI
import qualified What4.ProblemFeatures as WPF
import qualified What4.ProgramLoc as WPL
import qualified What4.Protocol.Online as WPO
import qualified What4.Protocol.SMTLib2 as WPS
import qualified What4.SatResult as WSR
import qualified What4.Solver.Z3 as WSZ

-- | One byte of the RX packet buffer: a fixed concrete value, or symbolic
-- (unconstrained, to be solved for).
data PacketByte = Concrete W.Word8 | Symbolic
  deriving (Show)

data PacketResult
  = ConcreteResult Integer
    -- ^ Every packet byte was concrete; this is the resulting value actually
    -- observed at the target address (no solver involved).
  | Reachable [(Int, Integer)]
    -- ^ Some packet bytes were symbolic; the solver found a model reaching
    -- the target value. One entry per symbolic byte, in buffer order.
  | Unreachable
    -- ^ No assignment of the symbolic bytes reaches the target value.
  | HarnessError String
  deriving (Show)

-- | Run 'fn' (expected to be the AutoPilot dispatcher, or any whole,
-- loop-free Macaw function) with the given buffer bytes written at
-- 'bufAddr', then check whether 'targetValue' is a reachable value of the
-- byte at 'observeAddr' after the function returns.
runPacketTransaction
  :: MM.Memory 32
  -> MDS.DiscoveryFunInfo ARM.AArch32 ids
  -> W.Word32          -- ^ packet buffer address
  -> [PacketByte]       -- ^ buffer contents, in order starting at 'bufAddr'
  -> W.Word32          -- ^ address to read back after execution
  -> Integer            -- ^ target value to search/check for at 'observeAddr'
  -> IO PacketResult
runPacketTransaction mem fn bufAddr bufBytes observeAddr targetValue =
  runPacketTransactionTraced mem fn bufAddr bufBytes observeAddr targetValue Nothing [] Nothing Nothing

-- | Bounded, per-step tracing for 'runPacketTransactionTraced' -- unlike
-- 'debugFeature' (which only samples every 2000 steps, far too coarse to
-- see which successor a specific branch took), this fires on *every* step
-- whose current PC falls within ['rtLoAddr', 'rtHiAddr'], recording R0-R7,
-- SP, and (if 'rtWatchMem' is set) one watched memory byte. Reusable for
-- any investigation that needs a fine-grained trace of a specific region
-- rather than the whole run -- not tied to the dispatcher specifically.
data RichTraceConfig = RichTraceConfig
  { rtLoAddr   :: W.Word32
  , rtHiAddr   :: W.Word32
  , rtWatchMem :: Maybe W.Word32
  , rtMaxHits  :: Int
    -- ^ Safety cap: stop *recording* (not stop the run) after this many
    -- in-range hits, so a genuine infinite loop in-range doesn't flood
    -- stderr.
  }

-- | Like 'runPacketTransaction', but with an optional 'RichTraceConfig'
-- for fine-grained tracing of a specific address range, and a list of
-- register overrides applied *after* IP/SP are set (before the run
-- starts) -- for entering 'fn' at a real, already-independently-confirmed
-- (disassembly and/or concrete-Unicorn) mid-function point whose live
-- registers hold known addresses, rather than only 'fn'\'s own true
-- entry (where every register legitimately starts at zero). Mirrors
-- 'APTrace.SymbolicRunner.BranchQuery'\'s 'bqPointerOverrides' -- same
-- register-to-address seeding, same justification (a register standing
-- in for a pointer this code will dereference, established by real
-- prior execution this harness does not itself re-derive). An empty
-- list reproduces the original entry-only behavior exactly.
runPacketTransactionTraced
  :: MM.Memory 32
  -> MDS.DiscoveryFunInfo ARM.AArch32 ids
  -> W.Word32
  -> [PacketByte]
  -> W.Word32
  -> Integer
  -> Maybe RichTraceConfig
  -> [(AR.ARMReg (MT.BVType 32), W.Word32)]
  -> Maybe W.Word32
     -- ^ Optional early-stop address: the *first* time execution reaches
     -- this PC, answer the same reachability question
     -- 'runPacketTransactionTraced' would normally only ask once the whole
     -- function returns -- using the real path condition accumulated so
     -- far -- and keep that answer even if the run is later killed by an
     -- exception (e.g. a real ARM instruction this Macaw version's
     -- semantics table has no lifting for, encountered on some entirely
     -- unrelated downstream code this query never needed). Sound only
     -- when the stop address has no other, later-reached predecessor
     -- edge whose path condition would also need accounting for -- true
     -- by construction whenever it is the unique final write before an
     -- unconditional jump/call, as in this module's own trigger-input use
     -- (see docs/investigations/trigger-input-symbolic-reachability.md).
     -- 'Nothing' reproduces the original run-to-completion behavior
     -- exactly.
  -> Maybe FilePath
     -- ^ Optional solver-observability path, 'Nothing' by default
     -- (identical behavior to before this parameter existed). When
     -- @Just base@: (1) opens @base ++ ".interaction.smt2"@ and passes it
     -- as the online solver's own @LogData@-equivalent log handle (the
     -- second argument of 'WPO.startSolverProcess', already present in
     -- the online-solver API this module already uses -- previously
     -- always 'Nothing' here) -- the *exact* SMT-LIB2 sent to and
     -- received from Z3, incrementally, so it can be inspected even
     -- while a long-running query is still in flight; (2) additionally
     -- writes a standalone @base ++ ".standalone.smt2"@ via
     -- 'WSZ.writeZ3SMT2File', asserting the same @[assumptions,
     -- reachedPred]@ list the online check itself queries, so the
     -- problem can be replayed or measured (asserts/declarations, file
     -- size) with a plain @z3 file.smt2@ outside this harness entirely,
     -- without needing the online run to finish. Purely observational --
     -- changes no query semantics, only what gets written to disk
     -- alongside it. See
     -- docs/investigations/trigger-input-symbolic-reachability.md for
     -- why this was added (a query that would not converge in a
     -- practical time budget, with nothing on disk to show what was
     -- actually being asked).
  -> IO PacketResult
runPacketTransactionTraced mem fn bufAddr bufBytes observeAddr targetValue traceCfg regOverrides stopAtAddr solverLogPath
  | Just archVals <- MS.archVals (Proxy @ARM.AArch32) Nothing =
      withZ3Backend (run archVals)
  | otherwise = pure (HarnessError "no ArchVals for AArch32")
  where
    run :: forall solver t st fs
         . (WPO.OnlineSolver solver, CB.IsSymBackend (WE.ExprBuilder t st fs) (CBS.SimpleBackend t st fs))
        => MS.ArchVals ARM.AArch32
        -> Proxy solver
        -> WPF.ProblemFeatures
        -> CBS.SimpleBackend t st fs
        -> IO PacketResult
    run archVals _proxy problemFeatures bak = do
      let sym = CB.backendGetSym bak
      let ?recordLLVMAnnotation = \_ _ _ -> pure ()
      let ?processMacawAssert = MSM.defaultProcessMacawAssertion
      let ?memOpts = CLM.defaultMemOptions
      let ?ptrWidth = WI.knownNat @32
      halloc <- CFH.newHandleAllocator
      t0 <- CT.getCurrentTime
      IO.hPutStrLn IO.stderr "  [timing] starting mkFunCFG..."
      someCfg <- MS.mkFunCFG (MS.archFunctions archVals) halloc
                   (WF.functionNameFromText "target") posFn fn
      t1 <- CT.getCurrentTime
      IO.hPutStrLn IO.stderr ("  [timing] mkFunCFG took " ++ show (CT.diffUTCTime t1 t0))
      case someCfg of
        CC.SomeCFG cfg ->
          MS.withArchEval archVals sym $ \archEvalFns -> do
            memVar <- CLM.mkMemVar "aptrace:llvm_memory" halloc
            (baseMem, memPtrTable) <-
              -- SymbolicMutable, not ConcreteMutable: see the RAM
              -- compact-zero overlay right below for why, and
              -- docs/tooling/compact-ram-initialization.md for the
              -- ~196,615-assert-per-query cost this replaces.
              MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.SymbolicMutable mem
            -- Every call we might encounter (e.g. a per-channel helper called
            -- from inside a loop we don't want to inline) is treated as an
            -- opaque black box -- but a *calling-convention-respecting* one.
            -- AAPCS makes R0-R3/R12 and the condition flags caller-saved
            -- (undefined after a call) while R4-R11/SP are callee-saved (a
            -- well-behaved function preserves them). Our first attempt at
            -- this clobbered *every* register, including whatever loop
            -- counter or table pointer the caller was using in R4-R11 --
            -- which corrupted ordinary bounded loops into apparently-infinite
            -- ones (see docs/harness/protocol-harness-results.md). Only
            -- clobber the registers a real call is actually allowed to.
            let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
            callCounter <- newIORef (0 :: Int)
            opaqueCallHandle <- CFH.mkHandle' halloc (WF.functionNameFromText "opaque_call")
                                  (Ctx.singleton (CC.StructRepr regTypes)) (CC.StructRepr regTypes)
            let opaqueCallOverride = CS.mkOverride' (WF.functionNameFromText "opaque_call") (CC.StructRepr regTypes) $ do
                  CS.RegMap argsAssign <- CS.getOverrideArgs
                  let incoming = CS.RegEntry (CC.StructRepr regTypes) (CS.regValue (argsAssign Ctx.! Ctx.baseIndex))
                  ovSym <- CS.getSymInterface
                  liftIO $ do
                    n <- atomicModifyIORef' callCounter (\c -> (c + 1, c + 1))
                    when (n `mod` 200 == 0) $ do
                      let CLM.LLVMPointer _ r6off = CS.regValue (MS.lookupReg archVals incoming AR.r6)
                          CLM.LLVMPointer _ r4off = CS.regValue (MS.lookupReg archVals incoming AR.r4)
                          CLM.LLVMPointer _ r7off = CS.regValue (MS.lookupReg archVals incoming AR.r7)
                      IO.hPutStrLn IO.stderr ("  [opaque_call] #" ++ show n ++ " R6=" ++ show (WI.asBV r6off)
                                               ++ " R4=" ++ show (WI.asBV r4off) ++ " R7=" ++ show (WI.asBV r7off))
                    v0  <- freshBV32 ovSym "opaque_r0"
                    v1  <- freshBV32 ovSym "opaque_r1"
                    v2  <- freshBV32 ovSym "opaque_r2"
                    v3  <- freshBV32 ovSym "opaque_r3"
                    v12 <- freshBV32 ovSym "opaque_r12"
                    let s1 = MS.updateReg archVals incoming AR.r0 v0
                        s2 = MS.updateReg archVals s1 AR.r1 v1
                        s3 = MS.updateReg archVals s2 AR.r2 v2
                        s4 = MS.updateReg archVals s3 AR.r3 v3
                        s5 = MS.updateReg archVals s4 AR.ip v12
                    pure (CS.regValue s5)
                fnBindings = CS.FnBindings
                  (CFH.insertHandleMap opaqueCallHandle (CS.UseOverride opaqueCallOverride) CFH.emptyHandleMap)
                lookupFn = MS.LookupFunctionHandle $ \st _mem _regs -> pure (opaqueCallHandle, st)

            let mmConf0 = MSM.memModelConfig bak memPtrTable
                globalMap = MS.globalMemMap mmConf0
                mmConf = mmConf0
                  { MS.lookupFunctionHandle = lookupFn
                  , MS.lookupSyscallHandle = MS.unsupportedSyscalls "aptrace"
                  }

            -- Compact RAM zero-initialization. 'newGlobalMemory' above was
            -- built with SymbolicMutable specifically so every writable
            -- segment (RAM; this harness's own callers never build an MMIO
            -- segment) gets NO per-byte assertions from Macaw's own
            -- memory-population code (which -- for ConcreteMutable, as
            -- this module used to pass -- asserts
            -- 'globalMemoryBytes[addr] == 0' individually, once per byte,
            -- for the *entire* RAM region regardless of whether this run
            -- ever touches most of it: ~196,615 assertions for this
            -- project's own 0x30000-byte RAM, over 70% of a real query's
            -- total assertion count -- see
            -- docs/tooling/compact-ram-initialization.md). SymbolicMutable
            -- alone would leave RAM bytes totally unconstrained, which is
            -- NOT sound for this module's purposes (see the module header
            -- on why concrete zero RAM matters) -- so the exact same "RAM
            -- starts at zero" fact is reasserted here, just as ONE genuine
            -- SMT constant-array term per writable segment instead of one
            -- equality per byte, using this module's own pre-existing
            -- stack-zeroing technique (proven below, not new). Segment
            -- bounds are read directly from 'mem' itself (the same
            -- 'MM.Memory' 'APTrace.FirmwareLoader.buildMemory' built) --
            -- not a hardcoded address/size pair -- so this stays correct
            -- for any firmware image this harness is pointed at, not just
            -- this project's own 0x20000000/0x30000 AutoPilot RAM.
            let writableSegs = filter (not . Perm.isReadonly . MM.segmentFlags) (MM.memSegments mem)
            ramZeroedMem <- foldM
              (\curMem seg -> do
                 let segBase = fromIntegral (MM.memWordValue (MM.segmentOffset seg)) :: W.Word32
                     segSize = MM.memWordValue (MM.segmentSize seg)
                 segZeroArr <- WI.constantArray sym (Ctx.singleton WI.knownRepr) =<< WI.bvLit sym (WI.knownNat @8) (BV.zero WI.knownNat)
                 segSizeBV <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger segSize))
                 segPtr <- resolvedPointer bak globalMap curMem segBase
                 CLM.doArrayStore bak curMem segPtr LDL.noAlignment segZeroArr segSizeBV)
              baseMem
              writableSegs

            -- A small concrete stack: this function pushes/pops registers.
            stackSize <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 4096)
            (stackBase, mem1) <- CLM.doMalloc bak CLM.StackAlloc CLM.Mutable "aptrace_stack" ramZeroedMem stackSize LDL.noAlignment
            zeroArr <- WI.constantArray sym (Ctx.singleton WI.knownRepr) =<< WI.bvLit sym (WI.knownNat @8) (BV.zero WI.knownNat)
            mem2 <- CLM.doArrayStore bak mem1 stackBase LDL.noAlignment zeroArr stackSize
            initSP <- CLM.ptrAdd sym WI.knownRepr stackBase stackSize

            (mem3, symBytes) <- writeBuffer bak globalMap mem2 bufAddr bufBytes

            let ext = MS.macawExtensions archEvalFns memVar mmConf
            let simCtx = CS.initSimContext bak CLI.llvmIntrinsicTypes halloc IO.stderr
                           fnBindings ext MS.MacawSimulatorState
            let globalState = CSG.insertGlobal memVar mem3 CS.emptyGlobals

            entryPtr <- resolvedPointer bak globalMap mem3 (fromIntegral entryAddr)

            -- Every register starts at a concrete default (0 / false), not
            -- symbolic. This matters: many ARM "registers" in this model are
            -- really ASL bookkeeping globals (PSTATE_IT, __UndefinedBehavior,
            -- __UnpredictableBehavior, ...) that can themselves drive
            -- conditional branches throughout the *semantics* of ordinary
            -- instructions, unrelated to our packet input. Leaving them
            -- symbolic (as 'freshSymVar' does, which is correct for
            -- 'APTrace.SymbolicRunner''s single-block queries) turns every
            -- such branch into a real fork, and running the whole 300+ block
            -- dispatcher that way explodes. Only the packet buffer memory is
            -- meant to be the symbolic input here.
            let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
            regVals <- Ctx.traverseWithIndex (concreteZeroVar sym) regTypes
            let regStruct0 = CS.RegEntry (CC.StructRepr regTypes) regVals
                regStruct1 = MS.updateReg archVals regStruct0 MC.ip_reg entryPtr
                regStruct2 = MS.updateReg archVals regStruct1 MC.sp_reg initSP
            regStruct3 <- foldM
              (\struct (reg, val) -> do
                 pointerVal <- resolvedPointer bak globalMap mem3 val
                 pure (MS.updateReg archVals struct reg pointerVal))
              regStruct2
              regOverrides
            let initRegs = CS.RegMap (Ctx.singleton regStruct3)

            let retTy = CFH.handleReturnType (CC.cfgHandle cfg)
            let simulation = CS.regValue <$> CS.callCFG cfg initRegs
            let initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                              (CS.runOverrideSim retTy simulation)
            t2 <- CT.getCurrentTime
            IO.hPutStrLn IO.stderr "  [timing] starting executeCrucible..."
            stepCounter <- newIORef (0 :: Int)
            richFeatures <- case traceCfg of
              Nothing -> pure []
              Just cfg -> do
                hitsRef <- newIORef (0 :: Int)
                pure [richTraceFeature bak archVals memVar globalMap cfg hitsRef]
            stopResultRef <- newIORef Nothing
            let stopAddressFeature addr = CSE.ExecutionFeature $ \execState ->
                  case CSET.execStateSimState execState of
                    Just (CSET.SomeSimState st) | addrOfState (st ^. CSET.stateLocation) == Just addr -> do
                      already <- readIORef stopResultRef
                      when (isNothing already) $ do
                        let globals = st ^. CSET.stateGlobals
                        case CSG.lookupGlobal memVar globals of
                          Nothing -> writeIORef stopResultRef (Just (HarnessError "stop-address memory global not found"))
                          Just curMem -> do
                            observePtr <- resolvedPointer bak globalMap curMem observeAddr
                            CLM.LLVMPointer _ observedVal <-
                              CLM.doLoad bak curMem observePtr (CLM.bitvectorType 1)
                                (CLM.LLVMPointerRepr (WI.knownNat @8)) LDL.noAlignment
                            r <- case WI.asBV observedVal of
                              -- Genuinely concrete (the common case when
                              -- nothing symbolic can have reached this
                              -- exact byte yet) -- report directly, no
                              -- solver needed.
                              Just bv -> pure (ConcreteResult (BV.asUnsigned bv))
                              -- Symbolic even though 'anySymbolic' (this
                              -- query's own seeded buffer) said otherwise:
                              -- a real, calling-convention-opaque call
                              -- upstream (e.g. a branch gated on an opaque
                              -- millis()/digitalRead() return) can still
                              -- make Crucible represent this address's
                              -- value as an ITE over that call's fresh
                              -- symbolic result, with no buffer byte of
                              -- ours involved at all. Fall back to the
                              -- same solver check either way -- correct
                              -- in both cases, just occasionally doing
                              -- more work than strictly needed when the
                              -- value happens to already be concrete.
                              Nothing -> do
                                assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
                                targetLit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr targetValue)
                                reachedPred <- WI.bvEq sym observedVal targetLit
                                mLogHandle <- writeSolverLogArtifacts sym solverLogPath "stop" [assumptions, reachedPred]
                                (solverHandle :: WPO.SolverProcess t solver) <- WPO.startSolverProcess problemFeatures mLogHandle sym
                                msat <- WPO.checkWithAssumptionsAndModel solverHandle "stop-address reachability"
                                          [assumptions, reachedPred]
                                result <- case msat of
                                  WSR.Sat evalFn -> do
                                    models <- mapM (\(i, bv) -> (,) i . BV.asUnsigned <$> WE.groundEval evalFn bv) symBytes
                                    pure (Reachable models)
                                  WSR.Unsat {} -> pure Unreachable
                                  WSR.Unknown -> pure (HarnessError "solver returned unknown at the stop address")
                                _ <- WPO.shutdownSolverProcess solverHandle
                                maybe (pure ()) IO.hClose mLogHandle
                                pure result
                            writeIORef stopResultRef (Just r)
                      pure CSE.ExecutionFeatureNoChange
                    _ -> pure CSE.ExecutionFeatureNoChange
                addrOfState (Just loc) = case WPL.plSourceLoc loc of
                  WPL.BinaryPos _ a -> Just (fromIntegral a :: W.Word32)
                  _ -> Nothing
                addrOfState Nothing = Nothing
            let stopFeatures = case stopAtAddr of
                  Nothing -> []
                  Just addr -> [stopAddressFeature addr]
            execOutcome <- X.try @X.SomeException
              (CS.executeCrucible (debugFeature stepCounter : richFeatures ++ stopFeatures) initState)
            t3 <- CT.getCurrentTime
            IO.hPutStrLn IO.stderr ("  [timing] executeCrucible took " ++ show (CT.diffUTCTime t3 t2))
            earlyResult <- readIORef stopResultRef
            let finishResult execRes = case execRes of
                  CS.FinishedResult _ res -> do
                    let globals = res ^. CS.partialValue . CS.gpGlobals
                    case CSG.lookupGlobal memVar globals of
                      Nothing -> pure (HarnessError "final memory global not found")
                      Just finalMem -> do
                        observePtr <- resolvedPointer bak globalMap finalMem observeAddr
                        CLM.LLVMPointer _ observedVal <-
                          CLM.doLoad bak finalMem observePtr (CLM.bitvectorType 1)
                            (CLM.LLVMPointerRepr (WI.knownNat @8)) LDL.noAlignment
                        case WI.asBV observedVal of
                          Just bv -> pure (ConcreteResult (BV.asUnsigned bv))
                          -- See the identical fallback in 'stopAddressFeature'
                          -- above for why this can't just be an error when
                          -- 'anySymbolic' is False.
                          Nothing -> do
                            assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
                            targetLit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr targetValue)
                            reachedPred <- WI.bvEq sym observedVal targetLit
                            mLogHandle <- writeSolverLogArtifacts sym solverLogPath "final" [assumptions, reachedPred]
                            (solverHandle :: WPO.SolverProcess t solver) <- WPO.startSolverProcess problemFeatures mLogHandle sym
                            msat <- WPO.checkWithAssumptionsAndModel solverHandle "packet reachability"
                                      [assumptions, reachedPred]
                            result <- case msat of
                              WSR.Sat evalFn -> do
                                models <- mapM (\(i, bv) -> (,) i . BV.asUnsigned <$> WE.groundEval evalFn bv) symBytes
                                pure (Reachable models)
                              WSR.Unsat {} -> pure Unreachable
                              WSR.Unknown -> pure (HarnessError "solver returned unknown")
                            _ <- WPO.shutdownSolverProcess solverHandle
                            maybe (pure ()) IO.hClose mLogHandle
                            pure result
                  CS.AbortedResult {} -> pure (HarnessError "simulation aborted")
                  CS.TimeoutResult {} -> pure (HarnessError "simulation timed out")
            case (earlyResult, execOutcome) of
              -- The early-stop feature already answered the question from
              -- the real path condition at the moment the target address
              -- was reached -- keep that answer regardless of what (if
              -- anything) happened afterward, including a crash on
              -- unrelated, downstream, unmodeled code.
              (Just r, _) -> pure r
              (Nothing, Left e) ->
                pure (HarnessError ("execution raised an exception before reaching the stop address (if one was set) or finishing: " ++ show (e :: X.SomeException)))
              (Nothing, Right execRes) -> finishResult execRes
      where
        entryAddr = MM.memWordToUnsigned (MM.addrOffset (MM.segoffAddr (MDS.discoveredFunAddr fn)))
        posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

-- | One symbolic RAM cell to solve for in 'runGateReachability': a
-- human-readable label (for reporting only), its concrete address, and its
-- width in bytes (this module's own two real uses are 1 and 4). Left
-- unwritten by 'runGateReachability' (no per-byte seeding, unlike
-- 'PacketByte') -- the base memory is plain @SymbolicMutable@ with no
-- zero-overlay at all, so every 'GateVar' address is already a fresh,
-- unconstrained free variable by construction, with no extra machinery
-- needed to make it so.
data GateVar = GateVar
  { gvLabel :: String
  , gvAddr  :: W.Word32
  , gvWidth :: Int  -- ^ 1 or 4 bytes, little-endian (matches 'CLM.doLoad'\'s own convention)
  } deriving (Show)

data GateResult
  = GateSat [(String, Integer)]
    -- ^ One ground value per 'GateVar', in the order given, from a real
    -- solver model.
  | GateUnsat
  | GateError String
  deriving (Show)

-- | A loaded 'GateVar'\'s own symbolic value, before it is ever written to
-- (there is no writer -- this module only reads). Two widths, matching
-- 'GateVar'\'s own two real uses; not a general-width facility.
data GateVal sym = GateVal8 (WI.SymBV sym 8) | GateVal32 (WI.SymBV sym 32)

-- | Symbolically execute a small, whole, loop-free, call-free-up-to-its-
-- own-stop-point Macaw-discovered function (built via 'MS.mkFunCFG' from a
-- re-seeded entry, exactly as 'runPacketTransactionTraced' already does),
-- with a bounded set of concrete pointer registers ('regOverrides') and a
-- bounded set of named symbolic RAM cells ('gateVars') -- everything else
-- (every other register, every other byte of RAM) is either a concrete
-- zero default (registers, matching 'runPacketTransactionTraced'\'s own
-- posture) or fully free/unconstrained (memory), with **no RAM
-- zero-initialization overlay at all**. This is deliberately leaner than
-- 'runPacketTransactionTraced': that overlay exists to make "the
-- pending-event array starts at zero" sound for a whole-firmware-state
-- replay, at a real, measured cost (docs/tooling/compact-ram-
-- initialization.md) -- a bounded gate check that only ever reads
-- 'gateVars' and nothing else in RAM has no use for it, and dropping it is
-- exactly the "avoid the earlier solver failure mode" this function exists
-- for (see docs/investigations/trigger-input-symbolic-crosscheck.md).
--
-- Stops the *first* time execution reaches 'stopAtAddr' (same block-
-- granular convention 'runPacketTransactionTraced'\'s own 'stopAtAddr'
-- established -- must be a real Macaw block-start address, not an
-- arbitrary mid-block instruction address) and asks the solver whether
-- that point is reachable at all, given the real path condition
-- accumulated so far *plus* 'extraNotEqual' (zero or more additional
-- "this 'GateVar' must not equal this value" constraints, by label --
-- for a Query-B-style negative check: the same run, the same stop point,
-- one guard's own known-good value excluded). An empty 'extraNotEqual'
-- asks the plain positive reachability question. On 'GateSat', reports a
-- real solver-produced ground value for every 'GateVar', not just the
-- ones named in 'extraNotEqual'.
runGateReachability
  :: MM.Memory 32
  -> MDS.DiscoveryFunInfo ARM.AArch32 ids
  -> [(AR.ARMReg (MT.BVType 32), W.Word32)]  -- ^ regOverrides (concrete pointers only)
  -> [GateVar]
  -> W.Word32                                 -- ^ stopAtAddr
  -> [(String, Integer)]                       -- ^ extraNotEqual, by 'gvLabel'
  -> Maybe FilePath                            -- ^ optional solver-observability base path (see 'writeSolverLogArtifacts')
  -> IO GateResult
runGateReachability mem fn regOverrides gateVars stopAtAddr extraNotEqual solverLogPath
  | Just archVals <- MS.archVals (Proxy @ARM.AArch32) Nothing =
      withZ3Backend (run archVals)
  | otherwise = pure (GateError "no ArchVals for AArch32")
  where
    run :: forall solver t st fs
         . (WPO.OnlineSolver solver, CB.IsSymBackend (WE.ExprBuilder t st fs) (CBS.SimpleBackend t st fs))
        => MS.ArchVals ARM.AArch32
        -> Proxy solver
        -> WPF.ProblemFeatures
        -> CBS.SimpleBackend t st fs
        -> IO GateResult
    run archVals _proxy problemFeatures bak = do
      let sym = CB.backendGetSym bak
      let ?recordLLVMAnnotation = \_ _ _ -> pure ()
      let ?processMacawAssert = MSM.defaultProcessMacawAssertion
      let ?memOpts = CLM.defaultMemOptions
      let ?ptrWidth = WI.knownNat @32
      halloc <- CFH.newHandleAllocator
      someCfg <- MS.mkFunCFG (MS.archFunctions archVals) halloc
                   (WF.functionNameFromText "gate") posFn fn
      case someCfg of
        CC.SomeCFG cfg ->
          MS.withArchEval archVals sym $ \archEvalFns -> do
            memVar <- CLM.mkMemVar "aptrace:llvm_memory" halloc
            -- Plain SymbolicMutable, no zero overlay -- see the module
            -- comment above for why that is sound and deliberate here.
            (baseMem, memPtrTable) <-
              MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.SymbolicMutable mem
            let mmConf = (MSM.memModelConfig bak memPtrTable)
                  { MS.lookupFunctionHandle = MS.unsupportedFunctionCalls "aptrace"
                    -- Sound only because 'stopAtAddr' is expected to fire
                    -- before any call in 'fn' actually executes -- true by
                    -- construction for this module's own trigger-gate use
                    -- (the stop point is the block immediately preceding
                    -- the region's one real call). If 'stopAtAddr' is
                    -- placed *after* a real call, this throws instead of
                    -- silently fabricating a return value -- a deliberate
                    -- failure mode, not a gap to work around here.
                  , MS.lookupSyscallHandle = MS.unsupportedSyscalls "aptrace"
                  }
                globalMap = MS.globalMemMap mmConf

            -- A small concrete stack, exactly as 'runPacketTransactionTraced'
            -- provides -- cheap, and this module makes no claim that 'fn'
            -- never pushes/pops (ASL side-conditions can reference SP even
            -- without an explicit push), so it stays for safety even though
            -- this module's own current callers never need it.
            stackSize <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 4096)
            (stackBase, mem1) <- CLM.doMalloc bak CLM.StackAlloc CLM.Mutable "aptrace_stack" baseMem stackSize LDL.noAlignment
            zeroArr <- WI.constantArray sym (Ctx.singleton WI.knownRepr) =<< WI.bvLit sym (WI.knownNat @8) (BV.zero WI.knownNat)
            mem2 <- CLM.doArrayStore bak mem1 stackBase LDL.noAlignment zeroArr stackSize
            initSP <- CLM.ptrAdd sym WI.knownRepr stackBase stackSize

            -- Read every GateVar's own (fresh, never-written) symbolic
            -- value *before* running -- since nothing in this module's own
            -- bounded region ever writes to a GateVar address (all seven
            -- of this investigation's own cells are read-only guards),
            -- this is the exact same underlying array expression the
            -- block's own real load instructions will read during
            -- execution, not a separate/aliased one.
            gateVals <- mapM (\gv -> (,) (gvLabel gv) <$> readGateVar bak globalMap mem2 gv) gateVars

            entryPtr <- resolvedPointer bak globalMap mem2 (fromIntegral entryAddr)
            let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
            regVals <- Ctx.traverseWithIndex (concreteZeroVar sym) regTypes
            let regStruct0 = CS.RegEntry (CC.StructRepr regTypes) regVals
                regStruct1 = MS.updateReg archVals regStruct0 MC.ip_reg entryPtr
                regStruct2 = MS.updateReg archVals regStruct1 MC.sp_reg initSP
            regStruct3 <- foldM
              (\struct (reg, val) -> do
                 pointerVal <- resolvedPointer bak globalMap mem2 val
                 pure (MS.updateReg archVals struct reg pointerVal))
              regStruct2
              regOverrides
            let initRegs = CS.RegMap (Ctx.singleton regStruct3)

            let ext = MS.macawExtensions archEvalFns memVar mmConf
            let simCtx = CS.initSimContext bak CLI.llvmIntrinsicTypes halloc IO.stderr
                           (CS.FnBindings CFH.emptyHandleMap) ext MS.MacawSimulatorState
            let globalState = CSG.insertGlobal memVar mem2 CS.emptyGlobals
            let retTy = CFH.handleReturnType (CC.cfgHandle cfg)
            let simulation = CS.regValue <$> CS.callCFG cfg initRegs
            let initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                              (CS.runOverrideSim retTy simulation)

            stepCounter <- newIORef (0 :: Int)
            stopResultRef <- newIORef Nothing
            let stopAddressFeature = CSE.ExecutionFeature $ \execState ->
                  case CSET.execStateSimState execState of
                    Just (CSET.SomeSimState st) | addrOfState (st ^. CSET.stateLocation) == Just stopAtAddr -> do
                      already <- readIORef stopResultRef
                      when (isNothing already) $ do
                        assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
                        extraPreds <- mapM
                          (\(label, notVal) -> case lookup label gateVals of
                             Just gv -> notEqualPred sym gv notVal
                             Nothing -> fail ("runGateReachability: unknown GateVar label in extraNotEqual: " ++ label))
                          extraNotEqual
                        mLogHandle <- writeSolverLogArtifacts sym solverLogPath "gate" (assumptions : extraPreds)
                        (solverHandle :: WPO.SolverProcess t solver) <- WPO.startSolverProcess problemFeatures mLogHandle sym
                        msat <- WPO.checkWithAssumptionsAndModel solverHandle "gate reachability"
                                  (assumptions : extraPreds)
                        r <- case msat of
                          WSR.Sat evalFn -> do
                            vs <- mapM (\(label, gv) -> (,) label <$> groundGateVal evalFn gv) gateVals
                            pure (GateSat vs)
                          WSR.Unsat {} -> pure GateUnsat
                          WSR.Unknown -> pure (GateError "solver returned unknown")
                        _ <- WPO.shutdownSolverProcess solverHandle
                        maybe (pure ()) IO.hClose mLogHandle
                        writeIORef stopResultRef (Just r)
                      pure CSE.ExecutionFeatureNoChange
                    _ -> pure CSE.ExecutionFeatureNoChange
                addrOfState (Just loc) = case WPL.plSourceLoc loc of
                  WPL.BinaryPos _ a -> Just (fromIntegral a :: W.Word32)
                  _ -> Nothing
                addrOfState Nothing = Nothing

            execOutcome <- X.try @X.SomeException
              (CS.executeCrucible [debugFeature stepCounter, stopAddressFeature] initState)
            earlyResult <- readIORef stopResultRef
            case (earlyResult, execOutcome) of
              (Just r, _) -> pure r
              (Nothing, Left e) ->
                pure (GateError ("execution raised an exception before reaching stopAtAddr: " ++ show (e :: X.SomeException)))
              (Nothing, Right (CS.FinishedResult {})) ->
                pure (GateError "run finished without ever reaching stopAtAddr on any path")
              (Nothing, Right (CS.AbortedResult {})) -> pure (GateError "simulation aborted before reaching stopAtAddr")
              (Nothing, Right (CS.TimeoutResult {})) -> pure (GateError "simulation timed out before reaching stopAtAddr")
      where
        entryAddr = MM.memWordToUnsigned (MM.addrOffset (MM.segoffAddr (MDS.discoveredFunAddr fn)))
        posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

-- | Read one 'GateVar'\'s own current symbolic (or concrete, if somehow
-- already determined) value out of 'mem', without writing anything.
readGateVar
  :: ( CB.IsSymBackend (WE.ExprBuilder t st fs) bak
     , CLM.HasLLVMAnn (WE.ExprBuilder t st fs)
     , CLM.HasPtrWidth 32
     , ?memOpts :: CLM.MemOptions
     )
  => bak
  -> MS.GlobalMap (WE.ExprBuilder t st fs) CLM.Mem 32
  -> CLM.MemImpl (WE.ExprBuilder t st fs)
  -> GateVar
  -> IO (GateVal (WE.ExprBuilder t st fs))
readGateVar bak globalMap mem gv = do
  ptr <- resolvedPointer bak globalMap mem (gvAddr gv)
  case gvWidth gv of
    1 -> do
      CLM.LLVMPointer _ bv <- CLM.doLoad bak mem ptr (CLM.bitvectorType 1) (CLM.LLVMPointerRepr (WI.knownNat @8)) LDL.noAlignment
      pure (GateVal8 bv)
    4 -> do
      CLM.LLVMPointer _ bv <- CLM.doLoad bak mem ptr (CLM.bitvectorType 4) (CLM.LLVMPointerRepr (WI.knownNat @32)) LDL.noAlignment
      pure (GateVal32 bv)
    w -> fail ("readGateVar: unsupported width " ++ show w ++ " for " ++ gvLabel gv)

groundGateVal :: WE.GroundEvalFn t -> GateVal (WE.ExprBuilder t st fs) -> IO Integer
groundGateVal evalFn (GateVal8 bv) = BV.asUnsigned <$> WE.groundEval evalFn bv
groundGateVal evalFn (GateVal32 bv) = BV.asUnsigned <$> WE.groundEval evalFn bv

notEqualPred :: (CB.IsSymInterface sym) => sym -> GateVal sym -> Integer -> IO (WI.Pred sym)
notEqualPred sym (GateVal8 bv) v = do
  lit <- WI.bvLit sym (WI.knownNat @8) (BV.mkBV WI.knownRepr v)
  WI.notPred sym =<< WI.bvEq sym bv lit
notEqualPred sym (GateVal32 bv) v = do
  lit <- WI.bvLit sym (WI.knownNat @32) (BV.mkBV WI.knownRepr v)
  WI.notPred sym =<< WI.bvEq sym bv lit

-- | Write 'bufBytes' starting at 'bufAddr' into 'mem', returning the updated
-- memory and, for each symbolic byte, its index (0-based, from 'bufAddr')
-- and the underlying fresh 'WI.SymBV' (for later model extraction).
writeBuffer
  :: ( CB.IsSymBackend (WE.ExprBuilder t st fs) bak
     , CLM.HasLLVMAnn (WE.ExprBuilder t st fs)
     , CLM.HasPtrWidth 32
     , ?memOpts :: CLM.MemOptions
     )
  => bak
  -> MS.GlobalMap (WE.ExprBuilder t st fs) CLM.Mem 32
  -> CLM.MemImpl (WE.ExprBuilder t st fs)
  -> W.Word32
  -> [PacketByte]
  -> IO (CLM.MemImpl (WE.ExprBuilder t st fs), [(Int, WI.SymBV (WE.ExprBuilder t st fs) 8)])
writeBuffer bak globalMap = go 0
  where
    sym = CB.backendGetSym bak
    go _ mem _addr [] = pure (mem, [])
    go i mem addr (b:bs) = do
      bv <- case b of
              Concrete w -> WI.bvLit sym (WI.knownNat @8) (BV.mkBV WI.knownNat (fromIntegral w))
              Symbolic -> case WI.userSymbol ("pkt_byte_" ++ show i) of
                Right symbol -> WI.freshConstant sym symbol (WI.BaseBVRepr (WI.knownNat @8))
                Left err -> fail (show err)
      ptr <- resolvedPointer bak globalMap mem addr
      val <- CLM.llvmPointer_bv sym bv
      mem' <- CLM.doStore bak mem ptr (CLM.LLVMPointerRepr (WI.knownNat @8)) (CLM.bitvectorType 1) LDL.noAlignment val
      (mem'', rest) <- go (i + 1) mem' (addr + 1) bs
      let here = case b of
                   Symbolic -> [(i, bv)]
                   Concrete _ -> []
      pure (mem'', here ++ rest)

-- | Solver observability, per docs/investigations/trigger-input-
-- symbolic-reachability.md's own request: when 'Nothing', does nothing
-- and returns 'Nothing' (the online solver process then gets no log
-- handle, exactly as before this was added). When @Just base@:
--
--   1. Writes a standalone @base ++ \".\" ++ tag ++ \".standalone.smt2\"@
--      via 'WSZ.writeZ3SMT2File', asserting exactly the predicates the
--      caller is about to hand the online solver -- a complete,
--      independently-replayable SMT-LIB2 problem (@z3 -smt2
--      that-file.smt2@ reproduces the exact query this harness is
--      asking, with no need for the online run to ever finish).
--   2. Opens (but does not close -- the caller does, once the solver
--      process it feeds has been shut down) @base ++ \".\" ++ tag ++
--      \".interaction.smt2\"@ for the online solver's own raw,
--      incremental SMT-LIB2 interaction log (the second argument of
--      'WPO.startSolverProcess', which this module always passed
--      'Nothing' for before this existed) -- readable while a
--      long-running query is still in flight, unlike the standalone
--      file above (which is complete but static, written once up front).
--
-- 'tag' distinguishes the two call sites in this module ("stop" for the
-- early-stop-address check, "final" for the ordinary end-of-run check)
-- so a query that somehow exercises both doesn't overwrite one log with
-- the other. Purely observational: never changes what gets asserted,
-- only what gets additionally written to disk alongside it.
writeSolverLogArtifacts
  :: WE.ExprBuilder t st fs
  -> Maybe FilePath
  -> String
  -> [WE.BoolExpr t]
  -> IO (Maybe IO.Handle)
writeSolverLogArtifacts _sym Nothing _tag _preds = pure Nothing
writeSolverLogArtifacts sym (Just base) tag preds = do
  IO.withFile (base ++ "." ++ tag ++ ".standalone.smt2") IO.WriteMode $ \h ->
    WSZ.writeZ3SMT2File sym h preds
  logHandle <- IO.openFile (base ++ "." ++ tag ++ ".interaction.smt2") IO.WriteMode
  IO.hSetBuffering logHandle IO.LineBuffering
  pure (Just logHandle)

-- | Diagnostic-only: logs the visited program location every 2000 steps and
-- force-aborts after a step cap, so a genuine infinite loop shows up as a
-- clear "stuck at address X" trace instead of an unbounded hang.
debugFeature :: IORef Int -> CSE.ExecutionFeature p sym ext rtp
debugFeature counterRef = CSE.ExecutionFeature $ \execState -> do
  n <- atomicModifyIORef' counterRef (\m -> (m + 1, m + 1))
  case CSET.execStateSimState execState of
    Just (CSET.SomeSimState st) -> do
      when (n `mod` 2000 == 0) $
        IO.hPutStrLn IO.stderr ("  [trace] step " ++ show n ++ " at " ++ show (st ^. CSET.stateLocation))
      if n > 300000
        then do
          IO.hPutStrLn IO.stderr ("  [trace] step limit exceeded at " ++ show (st ^. CSET.stateLocation) ++ ", aborting")
          Exit.exitFailure
        else pure CSE.ExecutionFeatureNoChange
    Nothing -> pure CSE.ExecutionFeatureNoChange

-- | See 'RichTraceConfig'. Fires on every step; only prints while the
-- current PC is in range, and stops printing (without aborting the run)
-- once 'rtMaxHits' in-range hits have been recorded.
richTraceFeature
  :: ( CB.IsSymBackend (WE.ExprBuilder t st fs) bak
     , CLM.HasLLVMAnn (WE.ExprBuilder t st fs)
     , CLM.HasPtrWidth 32
     , ?memOpts :: CLM.MemOptions
     )
  => bak
  -> MS.ArchVals ARM.AArch32
  -> CS.GlobalVar CLM.Mem
  -> MS.GlobalMap (WE.ExprBuilder t st fs) CLM.Mem 32
  -> RichTraceConfig
  -> IORef Int
  -> CSE.ExecutionFeature p (WE.ExprBuilder t st fs) ext rtp
richTraceFeature bak archVals memVar globalMap cfg hitsRef =
  CSE.ExecutionFeature $ \execState ->
    case CSET.execStateSimState execState of
      Nothing -> pure CSE.ExecutionFeatureNoChange
      Just (CSET.SomeSimState st) ->
        case addrOfLoc (st ^. CSET.stateLocation) of
          Just addr | rtLoAddr cfg <= addr && addr <= rtHiAddr cfg -> do
            n <- atomicModifyIORef' hitsRef (\c -> (c + 1, c + 1))
            when (n <= rtMaxHits cfg) $ do
              let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
              regsLine <- case MSR.simStateRegs (MS.archFunctions archVals) st of
                Just rawRegs -> do
                  let regsEntry = CS.RegEntry (CC.StructRepr regTypes) rawRegs
                      regHex r = let CLM.LLVMPointer _ off = CS.regValue (MS.lookupReg archVals regsEntry r)
                                 in case WI.asBV off of
                                      Just bv -> "0x" ++ Numeric.showHex (BV.asUnsigned bv) ""
                                      Nothing -> "<sym:" ++ show (WI.printSymExpr off) ++ ">"
                  pure (unwords [ nm ++ "=" ++ regHex r | (nm, r) <- namedRegs ])
                Nothing -> pure "(no register struct available here)"
              memLine <- case rtWatchMem cfg of
                Nothing -> pure ""
                Just wa -> do
                  let globals = st ^. CSET.stateGlobals
                  case CSG.lookupGlobal memVar globals of
                    Nothing -> pure "  buffer[0]=<no memory global>"
                    Just mem -> do
                      ptr <- resolvedPointer bak globalMap mem wa
                      CLM.LLVMPointer _ byteOff <-
                        CLM.doLoad bak mem ptr (CLM.bitvectorType 1)
                          (CLM.LLVMPointerRepr (WI.knownNat @8)) LDL.noAlignment
                      pure ("  buffer[0]=" ++ case WI.asBV byteOff of
                              Just bv -> "0x" ++ Numeric.showHex (BV.asUnsigned bv) ""
                              Nothing -> "<sym:" ++ show (WI.printSymExpr byteOff) ++ ">")
              IO.hPutStrLn IO.stderr
                ("  [rich-trace] #" ++ show n ++ " pc=0x" ++ Numeric.showHex addr ""
                 ++ "  " ++ regsLine ++ memLine)
            pure CSE.ExecutionFeatureNoChange
          _ -> pure CSE.ExecutionFeatureNoChange
  where
    addrOfLoc (Just loc) = case WPL.plSourceLoc loc of
      WPL.BinaryPos _ a -> Just (fromIntegral a :: W.Word32)
      _ -> Nothing
    addrOfLoc Nothing = Nothing
    namedRegs =
      [ ("r0", AR.r0), ("r1", AR.r1), ("r2", AR.r2), ("r3", AR.r3)
      , ("r4", AR.r4), ("r5", AR.r5), ("r6", AR.r6), ("r7", AR.r7)
      , ("sp", AR.sp)
      ]

-- | A fresh, uniquely-named 32-bit symbolic register value, with no
-- dependency on a Crucible context index (used by the opaque-call override,
-- which only clobbers a fixed, small set of named registers).
freshBV32 :: (CB.IsSymInterface sym) => sym -> String -> IO (CS.RegValue sym (CLM.LLVMPointerType 32))
freshBV32 sym nm = case WI.userSymbol nm of
  Right symbol -> CLM.llvmPointer_bv sym =<< WI.freshConstant sym symbol (WI.BaseBVRepr (WI.knownNat @32))
  Left err -> fail (show err)

resolvedPointer
  :: (CB.IsSymBackend (WE.ExprBuilder t st fs) bak)
  => bak
  -> MS.GlobalMap (WE.ExprBuilder t st fs) CLM.Mem 32
  -> CLM.MemImpl (WE.ExprBuilder t st fs)
  -> W.Word32
  -> IO (CLM.LLVMPtr (WE.ExprBuilder t st fs) 32)
resolvedPointer bak globalMap memImpl addr = do
  let sym = CB.backendGetSym bak
  base <- WI.natLit sym 0
  off <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger addr))
  MS.applyGlobalMap globalMap bak memImpl base off

-- | Like 'freshSymVar', but every register gets a concrete default (0 for
-- bitvectors, False for booleans) instead of a fresh symbolic constant.
concreteZeroVar
  :: (CB.IsSymInterface sym)
  => sym
  -> Ctx.Index ctx tp
  -> CC.TypeRepr tp
  -> IO (CS.RegValue' sym tp)
concreteZeroVar _sym _idx (CC.StructRepr Ctx.Empty) = pure (CS.RV Ctx.empty)
concreteZeroVar sym _idx tp =
  CS.RV <$> case tp of
    CLM.LLVMPointerRepr w -> CLM.llvmPointer_bv sym =<< WI.bvLit sym w (BV.zero w)
    CC.BoolRepr -> pure (WI.falsePred sym)
    _ -> fail ("unsupported register type: " ++ show tp)

freshSymVar
  :: (CB.IsSymInterface sym)
  => sym
  -> Ctx.Index ctx tp
  -> CC.TypeRepr tp
  -> IO (CS.RegValue' sym tp)
freshSymVar _sym _idx (CC.StructRepr Ctx.Empty) = pure (CS.RV Ctx.empty)
freshSymVar sym idx tp =
  CS.RV <$> case WI.userSymbol ("reg" ++ show (Ctx.indexVal idx)) of
    Right symbol -> case tp of
      CLM.LLVMPointerRepr w -> CLM.llvmPointer_bv sym =<< WI.freshConstant sym symbol (WI.BaseBVRepr w)
      CC.BoolRepr -> WI.freshConstant sym symbol WI.BaseBoolRepr
      _ -> fail ("unsupported register type: " ++ show tp)
    Left err -> fail (show err)

data BackendData t = BackendData

withZ3Backend
  :: (forall t st fs
       . (CB.IsSymBackend (WE.ExprBuilder t st fs) (CBS.SimpleBackend t st fs))
      => Proxy (WPS.Writer WSZ.Z3)
      -> WPF.ProblemFeatures
      -> CBS.SimpleBackend t st fs
      -> IO a)
  -> IO a
withZ3Backend k = do
  sym <- WE.newExprBuilder WE.FloatUninterpretedRepr BackendData PN.globalNonceGenerator
  bak <- CBS.newSimpleBackend sym
  WC.extendConfig WSZ.z3Options (WI.getConfiguration sym)
  let features = WPF.useBitvectors .|. WPF.useSymbolicArrays .|. WPF.useStructs .|. WPF.useNonlinearArithmetic
  k (Proxy @(WPS.Writer WSZ.Z3)) features bak
