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
-- STATUS: this does NOT currently work for the AutoPilot inbound-packet
-- dispatcher (flash 0x8258) it was written for. Seeding it at its real entry
-- and running the whole ~340-block merged function hangs -- real execution
-- goes through what looks like a hash-table/lookup-table probe (reading
-- registers R4-R7, whose correct initial values we haven't traced yet)
-- before reaching the character-dispatch logic, not a simple loop-free
-- if/else-if chain as originally assumed. See
-- research/notes/protocol-harness-results.md for the full diagnosis
-- (including the step-tracing 'ExecutionFeature' technique used to find
-- this) and for the workaround actually used instead (targeting individual
-- known blocks directly via 'APTrace.SymbolicRunner.checkBranchModel').
-- This module is kept because the technique is sound and reusable in
-- general (and its debug-tracing helper is useful for diagnosing *why* a
-- whole-function run hangs) -- just not yet successfully applied here.
--
-- Memory model: the base memory uses @ConcreteMutable@ content (all RAM,
-- including the pending-event array, starts at a known concrete value --
-- zero, matching 'APTrace.FirmwareLoader.buildMemory'\'s zero-filled RAM).
-- This matters for soundness: if the pending-event array were symbolic
-- (as with @SymbolicMutable@, used in 'APTrace.SymbolicRunner'), the solver
-- could "solve" a query by simply picking a favorable *initial* value for
-- that memory rather than actually deriving it from real code execution.
-- Only the packet buffer itself is made symbolic, by directly overwriting
-- those specific bytes with fresh constants after the base memory is built.
module APTrace.ProtocolHarness
  ( PacketByte(..)
  , PacketResult(..)
  , runPacketTransaction
  ) where

import           Control.Monad ( when )
import           Control.Monad.IO.Class ( liftIO )
import           Data.IORef
import           Data.Proxy ( Proxy(..) )
import qualified Data.Time.Clock as CT
import qualified System.Exit as Exit
import qualified Data.BitVector.Sized as BV
import qualified Data.Parameterized.Context as Ctx
import qualified Data.Word as W

import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery.State as MDS
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Symbolic as MS
import qualified Data.Macaw.Symbolic.Memory as MSM
import qualified Data.Macaw.AArch32.Symbolic ()
import qualified Data.Macaw.ARM.ARMReg as AR
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
runPacketTransaction mem fn bufAddr bufBytes observeAddr targetValue
  | Just archVals <- MS.archVals (Proxy @ARM.AArch32) Nothing =
      withZ3Backend (run archVals)
  | otherwise = pure (HarnessError "no ArchVals for AArch32")
  where
    anySymbolic = any isSymbolic bufBytes
    isSymbolic Symbolic = True
    isSymbolic _ = False

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
              MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.ConcreteMutable mem
            -- Every call we might encounter (e.g. a per-channel helper called
            -- from inside a loop we don't want to inline) is treated as an
            -- opaque black box -- but a *calling-convention-respecting* one.
            -- AAPCS makes R0-R3/R12 and the condition flags caller-saved
            -- (undefined after a call) while R4-R11/SP are callee-saved (a
            -- well-behaved function preserves them). Our first attempt at
            -- this clobbered *every* register, including whatever loop
            -- counter or table pointer the caller was using in R4-R11 --
            -- which corrupted ordinary bounded loops into apparently-infinite
            -- ones (see research/notes/protocol-harness-results.md). Only
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

            -- A small concrete stack: this function pushes/pops registers.
            stackSize <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 4096)
            (stackBase, mem1) <- CLM.doMalloc bak CLM.StackAlloc CLM.Mutable "aptrace_stack" baseMem stackSize LDL.noAlignment
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
                initRegs = CS.RegMap (Ctx.singleton regStruct2)

            let retTy = CFH.handleReturnType (CC.cfgHandle cfg)
            let simulation = CS.regValue <$> CS.callCFG cfg initRegs
            let initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                              (CS.runOverrideSim retTy simulation)
            t2 <- CT.getCurrentTime
            IO.hPutStrLn IO.stderr "  [timing] starting executeCrucible..."
            stepCounter <- newIORef (0 :: Int)
            execRes <- CS.executeCrucible [debugFeature stepCounter] initState
            t3 <- CT.getCurrentTime
            IO.hPutStrLn IO.stderr ("  [timing] executeCrucible took " ++ show (CT.diffUTCTime t3 t2))
            case execRes of
              CS.FinishedResult _ res -> do
                let globals = res ^. CS.partialValue . CS.gpGlobals
                case CSG.lookupGlobal memVar globals of
                  Nothing -> pure (HarnessError "final memory global not found")
                  Just finalMem -> do
                    observePtr <- resolvedPointer bak globalMap finalMem observeAddr
                    CLM.LLVMPointer _ observedVal <-
                      CLM.doLoad bak finalMem observePtr (CLM.bitvectorType 1)
                        (CLM.LLVMPointerRepr (WI.knownNat @8)) LDL.noAlignment
                    if not anySymbolic
                      then case WI.asBV observedVal of
                             Just bv -> pure (ConcreteResult (BV.asUnsigned bv))
                             Nothing -> pure (HarnessError "expected a concrete result but got a symbolic one")
                      else do
                        assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
                        targetLit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr targetValue)
                        reachedPred <- WI.bvEq sym observedVal targetLit
                        (solverHandle :: WPO.SolverProcess t solver) <- WPO.startSolverProcess problemFeatures Nothing sym
                        msat <- WPO.checkWithAssumptionsAndModel solverHandle "packet reachability"
                                  [assumptions, reachedPred]
                        result <- case msat of
                          WSR.Sat evalFn -> do
                            models <- mapM (\(i, bv) -> (,) i . BV.asUnsigned <$> WE.groundEval evalFn bv) symBytes
                            pure (Reachable models)
                          WSR.Unsat {} -> pure Unreachable
                          WSR.Unknown -> pure (HarnessError "solver returned unknown")
                        _ <- WPO.shutdownSolverProcess solverHandle
                        pure result
              CS.AbortedResult {} -> pure (HarnessError "simulation aborted")
              CS.TimeoutResult {} -> pure (HarnessError "simulation timed out")
      where
        entryAddr = MM.memWordToUnsigned (MM.addrOffset (MM.segoffAddr (MDS.discoveredFunAddr fn)))
        posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

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
