{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
-- | EXPERIMENTAL vertical slice (Phase 2 spike of
-- docs/aptrace-agent-framework.md): can the existing Macaw/Crucible stack
-- mechanically recover a single function's memory/return effects, with no
-- function-specific hints?
--
-- This is deliberately NOT the generic @FunctionSummary@ abstraction. It
-- runs one Macaw-discovered function via 'MS.mkFunCFG' (the same path
-- 'APTrace.ProtocolHarness' already uses) with:
--
--   * argument registers r0-r3 and r4-r12/lr as fresh named symbols
--     (or concrete, per caller-supplied overrides), SP a small concrete
--     stack, every other (ASL bookkeeping) register concrete zero;
--   * read-only (flash) memory concrete, all writable memory (RAM and the
--     caller-supplied MMIO ranges) unconstrained symbolic
--     ('MSM.SymbolicMutable');
--   * two macaw-symbolic 'MS.MemModelConfig' hooks used purely as
--     observation points: 'MS.concreteUnmutatedGlobalRead' (called on every
--     read, with width and resolved pointer, before the read happens) and
--     'MS.mkGlobalPointerValidityAssertion' (called on every write);
--   * an opaque call override that records target and r0-r3;
--   * a generic step bound.
--
-- It prints raw JSON describing every observed access (address term, width,
-- region, path condition), calls, and the return value term, so a human can
-- score the result. Nothing here knows anything about the target function.
module APTrace.EffectsSpike
  ( MmioRange
  , runEffectsSpike
  ) where

import qualified Control.Exception as X
import           Control.Monad ( foldM, forM, when )
import           Control.Monad.IO.Class ( liftIO )
import qualified Data.Aeson as A
import           Data.Bits ( complement, shiftL, (.&.), (.|.) )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy.Char8 as BSL
import           Data.Functor.Identity ( runIdentity )
import           Data.IORef
import           Data.List ( nub, sort )
import qualified Data.Map as Map
import           Data.Maybe ( catMaybes )
import           Data.Parameterized.Some ( Some(..) )
import           Data.Proxy ( Proxy(..) )
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Time.Clock as CT
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( showHex )
import qualified System.IO as IO

import qualified Data.BitVector.Sized as BV
import qualified Data.Parameterized.Context as Ctx
import qualified Data.Parameterized.NatRepr as NR
import qualified Data.Parameterized.Nonce as PN

import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.State as MDS
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Memory.Permissions as Perm
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
import qualified Lang.Crucible.Simulator.GlobalState as CSG
import qualified What4.Config as WC
import qualified What4.Expr as WE
import qualified What4.Expr.Builder as WEB
import qualified What4.FunctionName as WF
import qualified What4.Interface as WI
import qualified What4.ProblemFeatures as WPF
import qualified What4.ProgramLoc as WPL
import qualified What4.Protocol.Online as WPO
import qualified What4.Protocol.SMTLib2 as WPS
import qualified What4.SatResult as WSR
import qualified What4.Symbol as WS
import qualified What4.Protocol.SMTWriter as WSW
import qualified What4.Solver.Z3 as WSZ

import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, macawCortexMEntry, armCortexMInfo )

-- | A caller-supplied MMIO address range (base, size), e.g. derived from an
-- SVD's peripheral address blocks. Target geometry, not function knowledge.
type MmioRange = (Word32, Word32)

-- | One observed memory access, captured at the moment it happened.
data Access sym = Access
  { acKind  :: String                 -- ^ "read" / "write"
  , acPc    :: Maybe Word32           -- ^ instruction address (from the current program location)
  , acWidth :: Maybe Integer          -- ^ bytes (reads only; the write hook does not carry it)
  , acBlock :: Maybe Integer          -- ^ LLVM allocation block, if concrete
  , acAddr  :: WI.SymBV sym 32        -- ^ address offset term
  , acGuard :: WI.Pred sym            -- ^ path condition when the access happened
  , acServedConcrete :: Bool          -- ^ read satisfied from concrete read-only bytes
  }

data Call sym = Call
  { clPc     :: Maybe Word32
  , clTarget :: WI.SymBV sym 32
  , clArgs   :: [WI.SymBV sym 32]
  , clGuard  :: WI.Pred sym
  }

data StepLimit = StepLimit Int deriving Show
instance X.Exception StepLimit

runEffectsSpike
  :: FilePath
  -> Word32             -- ^ flash base
  -> Word32             -- ^ RAM base
  -> Word32             -- ^ RAM size
  -> [MmioRange]        -- ^ MMIO ranges (target geometry)
  -> Word32             -- ^ function entry
  -> [(Int, Word32)]    -- ^ concrete overrides for argument registers r0-r3
  -> Int                -- ^ generic step bound
  -> Bool               -- ^ raw only: skip solver enrichment
  -> FilePath           -- ^ output prefix (.raw.json / .enriched.json)
  -> IO ()
runEffectsSpike path flashBase ramBase ramSize mmio entryRaw argOverrides stepBound rawOnly outPrefix = do
  bytes <- BS.readFile path
  mem <- either fail pure $ do
    m0 <- buildMemory bytes flashBase ramBase ramSize
    foldM addMmioSegment m0 mmio
  entryOff <- maybe (fail "entry not in mapped memory") pure
                (resolveEntry mem (macawCortexMEntry entryRaw))
  tDisc0 <- CT.getCurrentTime
  let discState = MD.cfgFromAddrs armCortexMInfo mem
                    (Map.singleton entryOff (BSC.pack "target")) [entryOff] []
  Some fn <- timed "discovery" $ maybe (fail "function not discovered") pure
               (Map.lookup entryOff (discState ^. MD.funInfo))
  nBlocks <- X.evaluate (Map.size (fn ^. MD.parsedBlocks))
  tDisc1 <- CT.getCurrentTime
  case MS.archVals (Proxy @ARM.AArch32) Nothing of
    Nothing -> fail "no ArchVals for AArch32"
    Just archVals -> withZ3Backend $ \proxy features bak ->
      simulate archVals proxy features bak mem fn nBlocks (BS.length bytes)
        (realToFrac (CT.diffUTCTime tDisc1 tDisc0) :: Double)
  where
    simulate
      :: forall solver t st fs ids
       . (WPO.OnlineSolver solver, CB.IsSymBackend (WE.ExprBuilder t st fs) (CBS.SimpleBackend t st fs))
      => MS.ArchVals ARM.AArch32
      -> Proxy solver
      -> WPF.ProblemFeatures
      -> CBS.SimpleBackend t st fs
      -> MM.Memory 32
      -> MDS.DiscoveryFunInfo ARM.AArch32 ids
      -> Int
      -> Int
      -> Double
      -> IO ()
    simulate archVals _ features bak mem fn nBlocks flashLen discSecs = do
      let sym = CB.backendGetSym bak
      let ?recordLLVMAnnotation = \_ _ _ -> pure ()
      let ?processMacawAssert = MSM.defaultProcessMacawAssertion
      let ?memOpts = CLM.defaultMemOptions
      let ?ptrWidth = WI.knownNat @32
      t0 <- CT.getCurrentTime
      halloc <- CFH.newHandleAllocator
      CC.SomeCFG cfg <- timed "mkFunCFG" $ MS.mkFunCFG (MS.archFunctions archVals) halloc
                          (WF.functionNameFromText "target") posFn fn
      accessesRef <- newIORef ([] :: [Access (WE.ExprBuilder t st fs)])
      callsRef <- newIORef ([] :: [Call (WE.ExprBuilder t st fs)])
      -- Conjuncts of the path condition that existed before simulation
      -- (e.g. macaw-symbolic's per-byte read-only-memory equalities). A
      -- recorded guard is the path condition minus these, so it holds only
      -- what the function's own control flow added.
      baseRef <- newIORef Set.empty
      let isPos WEB.Positive = True
          isPos WEB.Negative = False
          relGuard = do
            pc <- CB.getPathCondition bak
            base <- readIORef baseRef
            let keep = [ (e, isPos p) | (e, p) <- WEB.asConjunction pc, not (Set.member (e, isPos p) base) ]
            foldM (\acc (e, pos) -> WI.andPred sym acc =<< (if pos then pure e else WI.notPred sym e))
                  (WI.truePred sym) keep
      MS.withArchEval archVals sym $ \archEvalFns -> do
        memVar <- CLM.mkMemVar "aptrace:llvm_memory" halloc
        (baseMem, memPtrTable) <- timed "crucible setup: global memory" $
          MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.SymbolicMutable mem

        let currentPc = do
              loc <- WI.getCurrentProgramLoc sym
              pure $ case WPL.plSourceLoc loc of
                -- Canonical instruction address: clear the Thumb bit.
                WPL.BinaryPos _ a -> Just (fromIntegral a .&. complement 1)
                _ -> Nothing
            blockOf (CLM.LLVMPointer blk _) = toInteger <$> WI.asNat blk
            record acc = modifyIORef' accessesRef (acc :)

            -- Observation hook 1: every read, with width, before it happens.
            -- Also serves concrete bytes for concrete addresses in read-only
            -- segments (the "flash is concrete/immutable" assumption).
            readHook :: MS.ConcreteUnmutatedGlobalRead p (WE.ExprBuilder t st fs) 32
            readHook _ memRep ptr@(CLM.LLVMPointer _ off) = do
              pc <- currentPc
              guardP <- relGuard
              served <- concreteReadOnly sym mem memRep off
              let served' = case served of { Just _ -> True; Nothing -> False }
              record Access { acKind = "read", acPc = pc
                            , acWidth = Just (toInteger (MC.memReprBytes memRep))
                            , acBlock = blockOf ptr, acAddr = off, acGuard = guardP
                            , acServedConcrete = served' }
              pure served

        let mmConf0 = MSM.memModelConfig bak memPtrTable
            defaultValidity = MS.mkGlobalPointerValidityAssertion mmConf0
            -- Observation hook 2: every write (and, for completeness, the
            -- reads that reach the full memory model; those are skipped
            -- here because hook 1 already logged them).
            validityHook s use@(MS.PointerUse _ tag) cond ptrEntry = do
              when (tag == MS.PointerWrite) $ do
                let ptr@(CLM.LLVMPointer _ off) = CS.regValue ptrEntry
                pc <- currentPc
                guardP <- relGuard
                guard' <- case cond of
                  Nothing -> pure guardP
                  Just c -> WI.andPred sym guardP (CS.regValue c)
                record Access { acKind = "write", acPc = pc, acWidth = Nothing
                              , acBlock = blockOf ptr, acAddr = off, acGuard = guard'
                              , acServedConcrete = False }
              defaultValidity s use cond ptrEntry

        -- Opaque, AAPCS-respecting call: clobber r0-r3/r12, record target
        -- and arguments. No memory effects (a known limitation).
        let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
        opaqueHandle <- CFH.mkHandle' halloc (WF.functionNameFromText "opaque_call")
                          (Ctx.singleton (CC.StructRepr regTypes)) (CC.StructRepr regTypes)
        callCounter <- newIORef (0 :: Int)
        let opaqueOverride = CS.mkOverride' (WF.functionNameFromText "opaque_call") (CC.StructRepr regTypes) $ do
              CS.RegMap args <- CS.getOverrideArgs
              let incoming = CS.RegEntry (CC.StructRepr regTypes) (CS.regValue (args Ctx.! Ctx.baseIndex))
              ovSym <- CS.getSymInterface
              liftIO $ do
                n <- atomicModifyIORef' callCounter (\c -> (c + 1, c + 1))
                vs <- mapM (\r -> freshBV32 ovSym ("call" ++ show n ++ "_" ++ r)) ["r0", "r1", "r2", "r3", "r12"]
                let clobbered = foldl (\s (reg, v) -> MS.updateReg archVals s reg v) incoming
                                  (zip [AR.r0, AR.r1, AR.r2, AR.r3, AR.ip] vs)
                pure (CS.regValue clobbered)
            lookupFn = MS.LookupFunctionHandle $ \st _ regs -> do
              let entry = CS.RegEntry (CC.StructRepr regTypes) regs
                  bvOf r = let CLM.LLVMPointer _ o = CS.regValue (MS.lookupReg archVals entry r) in o
              pc <- currentPc
              guardP <- relGuard
              modifyIORef' callsRef (Call pc (bvOf MC.ip_reg) (map bvOf [AR.r0, AR.r1, AR.r2, AR.r3]) guardP :)
              pure (opaqueHandle, st)
            fnBindings = CS.FnBindings
              (CFH.insertHandleMap opaqueHandle (CS.UseOverride opaqueOverride) CFH.emptyHandleMap)

        let mmConf = mmConf0
              { MS.lookupFunctionHandle = lookupFn
              , MS.lookupSyscallHandle = MS.unsupportedSyscalls "aptrace-effects-spike"
              , MS.concreteUnmutatedGlobalRead = readHook
              , MS.mkGlobalPointerValidityAssertion = validityHook
              }

        -- Small concrete stack (its own allocation block).
        stackSize <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 4096)
        (stackBase, mem1) <- CLM.doMalloc bak CLM.StackAlloc CLM.Mutable "aptrace_stack"
                               baseMem stackSize LDL.noAlignment
        initSP <- CLM.ptrAdd sym WI.knownRepr stackBase stackSize
        let stackBlock = blockOf stackBase

        entryPtr <- globalPointer bak (MS.globalMemMap mmConf) mem1 (fromIntegral entryAddr)
        regVals <- Ctx.traverseWithIndex (concreteZeroVar sym) regTypes
        let regs0 = CS.RegEntry (CC.StructRepr regTypes) regVals
            regs1 = MS.updateReg archVals (MS.updateReg archVals regs0 MC.ip_reg entryPtr) MC.sp_reg initSP
            inputs = [ ("arg_r0", AR.r0, Just 0), ("arg_r1", AR.r1, Just 1)
                     , ("arg_r2", AR.r2, Just 2), ("arg_r3", AR.r3, Just 3)
                     , ("in_r4", AR.r4, Nothing), ("in_r5", AR.r5, Nothing), ("in_r6", AR.r6, Nothing)
                     , ("in_r7", AR.r7, Nothing), ("in_r8", AR.r8, Nothing), ("in_r9", AR.r9, Nothing)
                     , ("in_r10", AR.r10, Nothing), ("in_r11", AR.r11, Nothing)
                     , ("in_r12", AR.ip, Nothing), ("in_lr", AR.lr, Nothing) ]
        (regs2, inputTerms) <- foldM
          (\(s, acc) (nm, reg, argIx) -> do
             v <- case argIx >>= (`lookup` argOverrides) of
                    Just c -> CLM.llvmPointer_bv sym =<< WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger c))
                    Nothing -> freshBV32 sym nm
             let CLM.LLVMPointer _ vOff = v
             pure (MS.updateReg archVals s reg v, acc ++ [(nm, vOff)]))
          (regs1, []) inputs

        let ext = MS.macawExtensions archEvalFns memVar mmConf
            simCtx = CS.initSimContext bak CLI.llvmIntrinsicTypes halloc IO.stderr
                       fnBindings ext MS.MacawSimulatorState
            globalState = CSG.insertGlobal memVar mem1 CS.emptyGlobals
            retTy = CFH.handleReturnType (CC.cfgHandle cfg)
            simulation = CS.regValue <$> CS.callCFG cfg (CS.RegMap (Ctx.singleton regs2))
            initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                          (CS.runOverrideSim retTy simulation)
        steps <- newIORef (0 :: Int)
        let boundFeature = CSE.ExecutionFeature $ \_ -> do
              n <- atomicModifyIORef' steps (\m -> (m + 1, m + 1))
              when (n > stepBound) $ X.throwIO (StepLimit n)
              pure CSE.ExecutionFeatureNoChange
        basePC <- CB.getPathCondition bak
        let baseConj = [ (e, isPos p) | (e, p) <- WEB.asConjunction basePC ]
        writeIORef baseRef (Set.fromList baseConj)
        logLine ("base path-condition conjuncts excluded from guards: " ++ show (length baseConj))
        tSim0 <- CT.getCurrentTime
        outcome <- timed "crucible simulation" $ X.try (CS.executeCrucible [boundFeature] initState)
        tSim1 <- CT.getCurrentTime
        nSteps <- readIORef steps

        (status, retTerm) <- case outcome of
          Left (e :: X.SomeException) -> pure ("failed: " ++ show e, Nothing)
          Right (CS.FinishedResult _ res) -> do
            let finalRegs = res ^. CS.partialValue . CS.gpValue
                CLM.LLVMPointer _ r0 = CS.regValue (MS.lookupReg archVals finalRegs AR.r0)
                partial = case res of { CS.TotalRes _ -> "complete"; CS.PartialRes {} -> "partial (some paths aborted)" }
            pure (partial, Just r0)
          Right (CS.AbortedResult _ _) -> pure ("failed: all paths aborted", Nothing)
          Right (CS.TimeoutResult _) -> pure ("bounded: timeout", Nothing)
        let status' = if nSteps > stepBound then "bounded: step limit " ++ show stepBound else status

        let freeVars :: WI.SymExpr (WE.ExprBuilder t st fs) tp -> [String]
            freeVars e = sort [ T.unpack (WS.solverSymbolAsText (WE.bvarName v))
                              | Some v <- Set.toList (WI.exprUninterpConstants sym e) ]
            showE :: WI.SymExpr (WE.ExprBuilder t st fs) tp -> String
            showE = show . WI.printSymExpr
            -- Solver-free facts only: a term is reported concrete iff What4
            -- already folded it to a literal.
            concreteOf e = hex . BV.asUnsigned <$> WI.asBV e

        accesses <- reverse <$> readIORef accessesRef
        calls <- reverse <$> readIORef callsRef
        assumptionList <- CB.flattenAssumptions sym =<< CB.collectAssumptions bak
        let nReads = length [ () | a <- accesses, acKind a == "read" ]
            nWrites = length [ () | a <- accesses, acKind a == "write" ]
        logLine ("observed: reads=" ++ show nReads ++ " writes=" ++ show nWrites
                 ++ " calls=" ++ show (length calls) ++ " crucible_steps=" ++ show nSteps
                 ++ " backend_assumptions=" ++ show (length assumptionList))

        let rawAccess acc = A.object
              [ "kind" A..= acKind acc
              , "pc" A..= fmap hex (acPc acc)
              , "width_bytes" A..= acWidth acc
              , "served_from_concrete_readonly" A..= acServedConcrete acc
              , "alloc_block" A..= acBlock acc
              , "is_stack_block" A..= (acBlock acc /= Nothing && acBlock acc == stackBlock)
              , "address" A..= A.object
                  [ "concrete" A..= concreteOf (acAddr acc)
                  , "expr" A..= showE (acAddr acc)
                  , "free_vars" A..= freeVars (acAddr acc) ]
              , "guard" A..= A.object
                  [ "concrete" A..= WI.asConstantPred (acGuard acc)
                  , "expr" A..= showE (acGuard acc)
                  , "free_vars" A..= freeVars (acGuard acc) ]
              ]
            rawCall c = A.object
              [ "pc" A..= fmap hex (clPc c)
              , "target_concrete" A..= concreteOf (clTarget c)
              , "target_expr" A..= showE (clTarget c)
              , "args_concrete" A..= map concreteOf (clArgs c)
              , "args_expr" A..= map showE (clArgs c)
              , "guard_expr" A..= showE (clGuard c) ]
            rawReturn = case retTerm of
              Nothing -> A.Null
              Just r -> A.object
                [ "concrete" A..= concreteOf r
                , "expr" A..= showE r
                , "free_vars" A..= freeVars r ]
            allVars = nub $ concat $
              [ freeVars (acAddr a) ++ freeVars (acGuard a) | a <- accesses ] ++
              [ concatMap freeVars (clArgs c) | c <- calls ] ++
              [ maybe [] freeVars retTerm ]
            rawDoc = A.object
              [ "spike" A..= ("aptrace-effects-spike-v1-raw" :: String)
              , "entry" A..= hex entryRaw
              , "arg_overrides" A..= [ ("r" ++ show i, hex v) | (i, v) <- argOverrides ]
              , "status" A..= status'
              , "macaw_blocks" A..= nBlocks
              , "crucible_steps" A..= nSteps
              , "counts" A..= A.object
                  [ "reads" A..= nReads, "writes" A..= nWrites, "calls" A..= length calls
                  , "backend_assumptions" A..= length assumptionList ]
              , "runtime_s" A..= A.object
                  [ "discovery" A..= discSecs
                  , "cfg_and_setup" A..= (realToFrac (CT.diffUTCTime tSim0 t0) :: Double)
                  , "simulation" A..= (realToFrac (CT.diffUTCTime tSim1 tSim0) :: Double) ]
              , "inputs_referenced" A..= allVars
              , "accesses" A..= map rawAccess accesses
              , "calls" A..= map rawCall calls
              , "return_r0" A..= rawReturn
              , "assumptions" A..=
                  [ "Cortex-M Thumb, AAPCS opaque calls (clobber r0-r3/r12, no memory effects)"
                  , "read-only segments concrete; RAM and MMIO ranges unconstrained symbolic"
                  , "non-GPR (ASL bookkeeping) registers concrete zero"
                  , "generic step bound " ++ show stepBound :: String ]
              ]
        timed "raw-effect serialization" $ BSL.writeFile (outPrefix ++ ".raw.json") (A.encode rawDoc)
        logLine ("raw effects written to " ++ outPrefix ++ ".raw.json")

        -- ---- Solver enrichment: ONE Z3 process, common assumptions
        -- asserted once, one push/pop frame per proof query. ----
        proc' :: WPO.SolverProcess t solver <- timed "solver initialization" $
          WPO.startSolverProcess features Nothing sym
        queryCount <- newIORef (0 :: Int)
        queryLog <- newIORef ([] :: [A.Value])
        let -- Three-valued outcome; UNKNOWN is never read as SAT or UNSAT.
            satKind r = case r of { WSR.Sat _ -> "SAT"; WSR.Unsat _ -> "UNSAT"; WSR.Unknown -> "UNKNOWN" } :: String
            query :: String -> String -> [String] -> [WI.Pred (WE.ExprBuilder t st fs)]
                  -> (WSR.SatResult (WE.GroundEvalFn t) () -> IO a) -> IO (String, a)
            query qType source extra preds k = do
              n <- atomicModifyIORef' queryCount (\c -> (c + 1, c + 1))
              q0 <- CT.getCurrentTime
              (kind, r) <- WPO.inNewFrame proc' $ do
                mapM_ (WSW.assume (WPO.solverConn proc')) preds
                res <- WPO.checkAndGetModel proc' (qType ++ ": " ++ source)
                r <- k res
                pure (satKind res, r)
              q1 <- CT.getCurrentTime
              let secs = realToFrac (CT.diffUTCTime q1 q0) :: Double
              modifyIORef' queryLog (A.object
                [ "n" A..= n, "type" A..= qType, "source" A..= source
                , "additional_assumptions" A..= extra, "result" A..= kind, "runtime_s" A..= secs ] :)
              logLine ("solver query #" ++ show n ++ " [" ++ qType ++ " | " ++ source
                       ++ (if null extra then "" else " | assuming " ++ unwords extra)
                       ++ "] -> " ++ kind ++ " in " ++ show secs ++ "s")
              pure (kind, r)

        -- Smoke test through the exact same path, before any real query.
        smokeOk <- timed "z3 smoke test" $ do
          x <- WI.freshConstant sym (WI.safeSymbol "smoke_x") (WI.BaseBVRepr (WI.knownNat @32))
          one <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 1)
          two <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 2)
          x1 <- WI.bvEq sym x one
          x2 <- WI.bvEq sym x two
          (_, okSat) <- query "smoke" "x==1" [] [x1] $ \r -> case r of
            WSR.Sat ev -> (== 1) . BV.asUnsigned <$> WE.groundEval ev x
            _ -> pure False
          (k2, _) <- query "smoke" "x==1 && x==2" [] [x1, x2] $ \_ -> pure ()
          pure (okSat && k2 == "UNSAT")
        logLine ("z3 smoke test: " ++ (if smokeOk then "PASS" else "FAIL"))

        if rawOnly || not smokeOk
          then do
            logLine (if rawOnly then "raw-only: skipping enrichment" else "smoke test failed: skipping enrichment")
            _ <- WPO.shutdownSolverProcess proc'
            pure ()
          else do
            assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
            timed "assert common assumptions once" $
              WSW.assume (WPO.solverConn proc') assumptions
            tEnrich0 <- CT.getCurrentTime
            argEqs <- forM [ (nm, v) | (nm, v) <- inputTerms, nm == "arg_r0" ] $ \(nm, v) -> do
              lit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr 1)
              eqP <- WI.bvEq sym v lit
              pure (nm ++ " == 0x1", eqP)
            enrichOutcome <- X.try $ timed "solver enrichment" $ do
              let -- unique(v) / non-unique(witnesses) / unknown, under the given preds.
                  uniqueness source extra preds e = case WI.asBV e of
                    Just bv -> pure (A.object [ "outcome" A..= ("unique" :: String)
                                              , "value" A..= hex (BV.asUnsigned bv)
                                              , "method" A..= ("concrete term (no solver)" :: String) ])
                    Nothing -> do
                      (k1, mv) <- query "uniqueness: model" source extra preds $ \r -> case r of
                        WSR.Sat ev -> Just . BV.asUnsigned <$> WE.groundEval ev e
                        _ -> pure Nothing
                      case mv of
                        Nothing -> pure (A.object [ "outcome" A..= (if k1 == "UNSAT" then "no value (guard infeasible)" else "unknown" :: String)
                                                  , "model_query" A..= k1 ])
                        Just v -> do
                          lit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr v)
                          other <- WI.notPred sym =<< WI.bvEq sym e lit
                          (k2, mv2) <- query "uniqueness: other value?" source extra (preds ++ [other]) $ \r -> case r of
                            WSR.Sat ev -> Just . BV.asUnsigned <$> WE.groundEval ev e
                            _ -> pure Nothing
                          pure $ case k2 of
                            "UNSAT" -> A.object [ "outcome" A..= ("unique" :: String), "value" A..= hex v
                                                , "method" A..= ("solver: model + UNSAT for any other value" :: String) ]
                            "SAT" -> A.object [ "outcome" A..= ("non-unique" :: String)
                                              , "witnesses" A..= map hex (v : maybe [] pure mv2) ]
                            _ -> A.object [ "outcome" A..= ("unknown" :: String), "witnesses" A..= [hex v] ]
                  -- satisfiable? always true? (three-valued)
                  guardStatus source extra preds g = case WI.asConstantPred g of
                    Just True -> pure (A.object [ "status" A..= ("always-true" :: String), "method" A..= ("concrete term (no solver)" :: String) ])
                    Just False -> pure (A.object [ "status" A..= ("unsatisfiable" :: String), "method" A..= ("concrete term (no solver)" :: String) ])
                    Nothing -> do
                      notG <- WI.notPred sym g
                      (canTrue, _) <- query "guard: satisfiable?" source extra (preds ++ [g]) $ \_ -> pure ()
                      (canFalse, _) <- query "guard: refutable?" source extra (preds ++ [notG]) $ \_ -> pure ()
                      let status = case (canTrue, canFalse) of
                            ("UNSAT", _) -> "unsatisfiable"
                            ("SAT", "UNSAT") -> "always-true"
                            ("SAT", "SAT") -> "conditional"
                            _ -> "unknown" :: String
                      pure (A.object [ "status" A..= status, "satisfiable_query" A..= canTrue
                                     , "refutable_query" A..= canFalse ])
                  inRange e lo sz = do
                    loL <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger lo))
                    hiL <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger lo + toInteger sz))
                    a <- WI.bvUle sym loL e
                    b <- WI.bvUlt sym e hiL
                    WI.andPred sym a b
                  -- Per mapped region: proven (never outside), disproven
                  -- (never inside), possible, or unknown. Stops at the first
                  -- proven region; every checked region is reported.
                  regions source acc
                    | acBlock acc /= Nothing && acBlock acc == stackBlock =
                        pure [A.object [ "region" A..= ("STACK" :: String), "membership" A..= ("proven" :: String)
                                       , "method" A..= ("allocation block (no solver)" :: String) ]]
                    | Just bv <- WI.asBV (acAddr acc) =
                        let v = BV.asUnsigned bv
                        in pure [ A.object [ "region" A..= nm, "base" A..= hex lo, "size" A..= hex sz
                                           , "membership" A..= ("proven" :: String)
                                           , "method" A..= ("concrete address (no solver)" :: String) ]
                                | (nm, lo, sz) <- namedRegions flashLen
                                , toInteger lo <= v, v < toInteger lo + toInteger sz ]
                    | otherwise = go (namedRegions flashLen)
                    where
                      go [] = pure []
                      go ((nm, lo, sz) : rest) = do
                        inside <- inRange (acAddr acc) lo sz
                        outside <- WI.notPred sym inside
                        let src = source ++ " in " ++ nm ++ " " ++ hex lo ++ "+" ++ hex sz
                        (kOut, _) <- query "region: proven member?" src [] [acGuard acc, outside] $ \_ -> pure ()
                        if kOut == "UNSAT"
                          then pure [A.object [ "region" A..= nm, "base" A..= hex lo, "size" A..= hex sz
                                              , "membership" A..= ("proven" :: String) ]]
                          else do
                            (kIn, _) <- query "region: possible member?" src [] [acGuard acc, inside] $ \_ -> pure ()
                            let m = case (kOut, kIn) of
                                  (_, "UNSAT") -> "disproven"
                                  ("SAT", "SAT") -> "possible (not proven)"
                                  _ -> "unknown" :: String
                            restJ <- go rest
                            pure (A.object [ "region" A..= nm, "base" A..= hex lo, "size" A..= hex sz
                                           , "membership" A..= m ] : restJ)
              accJson <- forM (zip [(1 :: Int) ..] accesses) $ \(i, acc) -> do
                let src = "access " ++ show i ++ " " ++ acKind acc ++ maybe "" (\p -> " @" ++ hex p) (acPc acc)
                regionJ <- regions (src ++ " address") acc
                uniqJ <- uniqueness (src ++ " address") [] [acGuard acc] (acAddr acc)
                guardJ <- guardStatus (src ++ " guard") [] [] (acGuard acc)
                specJ <- forM argEqs $ \(desc, eqP) -> do
                  su <- uniqueness (src ++ " address") [desc] [eqP, acGuard acc] (acAddr acc)
                  sg <- guardStatus (src ++ " guard") [desc] [eqP] (acGuard acc)
                  pure (A.object [ "additional_assumption" A..= desc
                                 , "address_uniqueness" A..= su, "guard_status" A..= sg ])
                pure $ A.object
                  [ "index" A..= i, "kind" A..= acKind acc, "pc" A..= fmap hex (acPc acc)
                  , "region_membership_under_guard" A..= regionJ
                  , "address_uniqueness_under_guard" A..= uniqJ
                  , "guard_status" A..= guardJ
                  , "specializations" A..= specJ ]
              retJ <- case retTerm of
                Nothing -> pure A.Null
                Just r -> do
                  u <- uniqueness "return r0" [] [] r
                  specs <- forM argEqs $ \(desc, eqP) -> do
                    su <- uniqueness "return r0" [desc] [eqP] r
                    pure (A.object [ "additional_assumption" A..= desc, "uniqueness" A..= su ])
                  pure (A.object [ "uniqueness" A..= u, "specializations" A..= specs ])
              pure (accJson, retJ)
            tEnrich1 <- CT.getCurrentTime
            nQueries <- readIORef queryCount
            qlog <- reverse <$> readIORef queryLog
            shutdownRes <- X.try (WPO.shutdownSolverProcess proc')
            let shutdownDesc = case shutdownRes of
                  Left (e :: X.SomeException) -> "exception: " ++ show e
                  Right (ec, _) -> show ec
            logLine ("z3 session shutdown: " ++ shutdownDesc)
            enriched <- case enrichOutcome of
              Left (e :: X.SomeException) -> do
                logLine ("enrichment FAILED: " ++ show e)
                pure (A.object [ "error" A..= show e ])
              Right (accJson, retJ) -> pure $ A.object
                [ "accesses" A..= accJson, "return_r0" A..= retJ ]
            timed "final enrichment serialization" $
              BSL.writeFile (outPrefix ++ ".enriched.json") $ A.encode $ A.object
                [ "spike" A..= ("aptrace-effects-spike-v2" :: String)
                , "raw_effects" A..= rawDoc
                , "solver_derived_facts" A..= enriched
                , "solver_session" A..= A.object
                    [ "processes" A..= (1 :: Int)
                    , "common_assumptions_asserted_once" A..= True
                    , "per_query_isolation" A..= ("push/pop frame" :: String)
                    , "smoke_test" A..= smokeOk
                    , "queries" A..= nQueries
                    , "shutdown" A..= shutdownDesc
                    , "enrichment_s" A..= (realToFrac (CT.diffUTCTime tEnrich1 tEnrich0) :: Double) ]
                , "query_log" A..= qlog ]
            logLine ("solver queries: " ++ show nQueries ++ "; enriched effects written to "
                     ++ outPrefix ++ ".enriched.json")
      where
        entryAddr = MM.memWordToUnsigned (MM.addrOffset (MM.segoffAddr (MDS.discoveredFunAddr fn)))
        posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

    namedRegions :: Int -> [(String, Word32, Word32)]
    namedRegions flashLen =
      [ ("FLASH", flashBase, fromIntegral flashLen)
      , ("RAM", ramBase, ramSize) ] ++
      [ ("MMIO", b, s) | (b, s) <- mmio ]

-- | Add one zero-filled, writable segment for an MMIO range. Under
-- 'MSM.SymbolicMutable' its contents are unconstrained symbolic.
addMmioSegment :: MM.Memory 32 -> MmioRange -> Either String (MM.Memory 32)
addMmioSegment m (base, size) =
  let seg :: MM.MemSegment 32
      seg = runIdentity $
        MM.memSegment Map.empty 0 0 Nothing (MM.memWord (fromIntegral base))
                      (Perm.read .|. Perm.write) BS.empty (fromIntegral size)
  in either (const (Left ("MMIO range overlaps: 0x" ++ showHex base ""))) Right
       (MM.insertMemSegment seg m)

-- | If the offset is concrete and lies entirely within a read-only
-- segment, return the concrete little-endian value from the image.
concreteReadOnly
  :: (CB.IsSymInterface sym)
  => sym
  -> MM.Memory 32
  -> MC.MemRepr ty
  -> WI.SymBV sym 32
  -> IO (Maybe (CS.RegValue sym (MS.ToCrucibleType ty)))
concreteReadOnly sym mem memRep off = case (memRep, WI.asBV off) of
  (MC.BVMemRepr nBytes endian, Just bv) -> do
    let addr = BV.asUnsigned bv
        cnt = NR.natValue nBytes
    case MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral addr)) of
      Just so | Perm.isReadonly (MM.segmentFlags (MM.segoffSegment so)) ->
        case MM.readByteString mem (MM.segoffAddr so) (fromIntegral cnt) of
          Right bs | BS.length bs == fromIntegral cnt -> do
            let ordered = case endian of
                  MC.LittleEndian -> reverse (BS.unpack bs)
                  MC.BigEndian -> BS.unpack bs
                val = foldl (\acc b -> (acc `shiftL` 8) .|. toInteger b) 0 ordered
                bits = NR.natMultiply (NR.knownNat @8) nBytes
            case NR.isPosNat bits of
              Just NR.LeqProof -> do
                lit <- WI.bvLit sym bits (BV.mkBV bits val)
                Just <$> CLM.llvmPointer_bv sym lit
              Nothing -> pure Nothing
          _ -> pure Nothing
      _ -> pure Nothing
  _ -> pure Nothing

globalPointer
  :: (CB.IsSymBackend (WE.ExprBuilder t st fs) bak)
  => bak
  -> MS.GlobalMap (WE.ExprBuilder t st fs) CLM.Mem 32
  -> CLM.MemImpl (WE.ExprBuilder t st fs)
  -> Word32
  -> IO (CLM.LLVMPtr (WE.ExprBuilder t st fs) 32)
globalPointer bak globalMap memImpl addr = do
  let sym = CB.backendGetSym bak
  base <- WI.natLit sym 0
  off <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger addr))
  MS.applyGlobalMap globalMap bak memImpl base off

freshBV32 :: (CB.IsSymInterface sym) => sym -> String -> IO (CS.RegValue sym (CLM.LLVMPointerType 32))
freshBV32 sym nm = case WI.userSymbol nm of
  Right s -> CLM.llvmPointer_bv sym =<< WI.freshConstant sym s (WI.BaseBVRepr (WI.knownNat @32))
  Left err -> fail (show err)

concreteZeroVar
  :: (CB.IsSymInterface sym)
  => sym -> Ctx.Index ctx tp -> CC.TypeRepr tp -> IO (CS.RegValue' sym tp)
concreteZeroVar _ _ (CC.StructRepr Ctx.Empty) = pure (CS.RV Ctx.empty)
concreteZeroVar sym _ tp = CS.RV <$> case tp of
  CLM.LLVMPointerRepr w -> CLM.llvmPointer_bv sym =<< WI.bvLit sym w (BV.zero w)
  CC.BoolRepr -> pure (WI.falsePred sym)
  _ -> fail ("unsupported register type: " ++ show tp)

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

hex :: (Integral a) => a -> String
hex n = "0x" ++ showHex (toInteger n) ""

logLine :: String -> IO ()
logLine msg = IO.hPutStrLn IO.stderr ("[effects-spike] " ++ msg) >> IO.hFlush IO.stderr

timed :: String -> IO a -> IO a
timed label act = do
  logLine (label ++ ": start")
  t0 <- CT.getCurrentTime
  r <- act
  t1 <- CT.getCurrentTime
  logLine (label ++ ": done in " ++ show (CT.diffUTCTime t1 t0))
  pure r
