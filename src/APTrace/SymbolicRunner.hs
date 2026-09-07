{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
-- | Symbolically executes a single, isolated Macaw basic block (a
-- 'MDP.ParsedBlock') with a chosen register seeded to a concrete
-- memory-mapped-peripheral address, and everything else -- including all of
-- RAM and the MMIO region itself -- left fully symbolic (via
-- @Data.Macaw.Symbolic.Memory@'s @SymbolicMutable@ content mode).
--
-- We work at the level of a single block, not the whole containing function,
-- because the target block in our demonstration firmware is the body of a
-- polling loop with a symbolic exit condition; Crucible's default
-- 'CS.executeCrucible' has no built-in loop-invariant inference, so
-- simulating the whole function/loop risks not terminating. A single block
-- ending in a conditional branch has no such issue: 'MS.mkParsedBlockCFG'
-- turns the block's terminator into a Crucible return, so simulating it
-- always finishes, and the returned "PC" register value directly tells us
-- which branch is reachable under which conditions.
module APTrace.SymbolicRunner
  ( BranchQuery(..)
  , BranchResult(..)
  , checkBranchModel
  ) where

import           Data.Proxy ( Proxy(..) )
import qualified Data.BitVector.Sized as BV
import qualified Data.Parameterized.Context as Ctx
import qualified Data.Word as W

import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Symbolic as MS
import qualified Data.Macaw.Symbolic.Memory as MSM
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
import qualified Lang.Crucible.Simulator.GlobalState as CSG
import           Lens.Micro ( (^.) )

import           Data.Bits ( (.|.) )
import qualified Data.Parameterized.Nonce as PN
import qualified System.IO as IO
import qualified What4.Config as WC
import qualified What4.Expr as WE
import qualified What4.Interface as WI
import qualified What4.ProblemFeatures as WPF
import qualified What4.ProgramLoc as WPL
import qualified What4.Protocol.Online as WPO
import qualified What4.Protocol.SMTLib2 as WPS
import qualified What4.SatResult as WSR
import qualified What4.Solver.Z3 as WSZ

-- | Minimal What4/Z3 online-solver backend setup. This mirrors
-- @Data.Macaw.Refinement.Solver.withNewBackend@'s Z3 case (that module is
-- private to the @macaw-refinement@ package, so it isn't reusable directly);
-- we only need the Z3 path, not its CVC4/Yices alternatives.
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

-- | Which of a block's two branch targets to check reachability for, and
-- what to seed a chosen "pointer" register to before running the block (so
-- that a memory access through it lands at a fixed, known MMIO address
-- rather than an arbitrary symbolic one).
data BranchQuery = BranchQuery
  { bqPointerOverride :: Maybe (AR.ARMReg (MT.BVType 32), W.Word32)
    -- ^ Optionally seed one register to a concrete value before running the
    -- block (e.g. the register holding the base address of a peripheral this
    -- block dereferences). 'Nothing' leaves every register fresh/symbolic,
    -- which is what you want when the register itself is the thing you're
    -- asking the solver to find a value for.
  , bqTargetAddr  :: W.Word32
    -- ^ The (even, Thumb-bit-cleared) instruction address we're asking
    -- "is this branch target reachable, and under what value?"
  , bqObserveReg  :: AR.ARMReg (MT.BVType 32)
    -- ^ Register whose final symbolic value we ask the solver to produce a
    -- concrete model for (typically the register just loaded from memory
    -- immediately before the branch, or the register the branch condition
    -- itself was computed from).
  }

data BranchResult
  = Unreachable
  | Reachable Integer  -- ^ A concrete value for 'bqObserveReg' that reaches 'bqTargetAddr'
  | SolverError String

instance Show BranchResult where
  show Unreachable = "unreachable"
  show (Reachable v) = "reachable, model: 0x" ++ showHexInteger v
  show (SolverError e) = "solver error: " ++ e

showHexInteger :: Integer -> String
showHexInteger n
  | n < 16 = [digit n]
  | otherwise = showHexInteger (n `div` 16) ++ [digit (n `mod` 16)]
  where digit d = "0123456789abcdef" !! fromIntegral d

-- | Symbolically execute 'block' in isolation and ask the solver whether
-- 'bqTargetAddr' is a reachable value of the ending program counter, given a
-- concrete seed for one register and everything else (registers, RAM, MMIO)
-- symbolic.
checkBranchModel
  :: MM.Memory 32
  -> MDP.ParsedBlock ARM.AArch32 ids
  -> BranchQuery
  -> IO BranchResult
checkBranchModel mem block q
  | Just archVals <- MS.archVals (Proxy @ARM.AArch32) Nothing =
      withZ3Backend (run archVals)
  | otherwise = pure (SolverError "no ArchVals for AArch32")
  where
    run :: forall solver t st fs
         . (WPO.OnlineSolver solver, CB.IsSymBackend (WE.ExprBuilder t st fs) (CBS.SimpleBackend t st fs))
        => MS.ArchVals ARM.AArch32
        -> Proxy solver
        -> WPF.ProblemFeatures
        -> CBS.SimpleBackend t st fs
        -> IO BranchResult
    run archVals _proxy problemFeatures bak = do
      let sym = CB.backendGetSym bak
      let ?recordLLVMAnnotation = \_ _ _ -> pure ()
      let ?processMacawAssert = MSM.defaultProcessMacawAssertion
      let ?memOpts = CLM.defaultMemOptions
      halloc <- CFH.newHandleAllocator
      someCfg <- MS.mkParsedBlockCFG (MS.archFunctions archVals) halloc posFn block
      case someCfg of
        CC.SomeCFG cfg ->
          MS.withArchEval archVals sym $ \archEvalFns -> do
            memVar <- CLM.mkMemVar "aptrace:llvm_memory" halloc
            (initialMem, memPtrTable) <-
              MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.SymbolicMutable mem
            let mmConf = (MSM.memModelConfig bak memPtrTable)
                  { MS.lookupFunctionHandle = MS.unsupportedFunctionCalls "aptrace"
                  , MS.lookupSyscallHandle = MS.unsupportedSyscalls "aptrace"
                  }
            let ext = MS.macawExtensions archEvalFns memVar mmConf
            let simCtx = CS.initSimContext bak CLI.llvmIntrinsicTypes halloc IO.stderr
                           (CS.FnBindings CFH.emptyHandleMap) ext MS.MacawSimulatorState
            let globalState = CSG.insertGlobal memVar initialMem CS.emptyGlobals

            let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
            regVals <- Ctx.traverseWithIndex (freshSymVar sym) regTypes
            let regStruct0 = CS.RegEntry (CC.StructRepr regTypes) regVals
            regStruct1 <- case bqPointerOverride q of
              Nothing -> pure regStruct0
              Just (reg, val) -> do
                pointerVal <- resolvedPointer bak (MS.globalMemMap mmConf) initialMem val
                pure (MS.updateReg archVals regStruct0 reg pointerVal)
            let initRegs = CS.RegMap (Ctx.singleton regStruct1)

            let retTy = CFH.handleReturnType (CC.cfgHandle cfg)
            let simulation = CS.regValue <$> CS.callCFG cfg initRegs
            let initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                              (CS.runOverrideSim retTy simulation)
            execRes <- CS.executeCrucible [] initState
            case execRes of
              CS.FinishedResult _ res -> do
                let finalRegs = res ^. CS.partialValue . CS.gpValue
                let CLM.LLVMPointer _ pcOff  = CS.regValue (MS.lookupReg archVals finalRegs MC.ip_reg)
                let CLM.LLVMPointer _ obsOff = CS.regValue (MS.lookupReg archVals finalRegs (bqObserveReg q))
                assumptions <- CB.assumptionsPred sym =<< CB.collectAssumptions bak
                targetLit <- WI.bvLit sym WI.knownRepr (BV.mkBV WI.knownRepr (toInteger (bqTargetAddr q)))
                reachedPred <- WI.bvEq sym pcOff targetLit
                (solverHandle :: WPO.SolverProcess t solver) <- WPO.startSolverProcess problemFeatures Nothing sym
                msat <- WPO.checkWithAssumptionsAndModel solverHandle "branch reachability"
                          [assumptions, reachedPred]
                result <- case msat of
                  WSR.Sat evalFn -> do
                    v <- WE.groundEval evalFn obsOff
                    pure (Reachable (BV.asUnsigned v))
                  WSR.Unsat {} -> pure Unreachable
                  WSR.Unknown -> pure (SolverError "solver returned unknown")
                _ <- WPO.shutdownSolverProcess solverHandle
                pure result
              CS.AbortedResult {} -> pure (SolverError "simulation aborted")
              CS.TimeoutResult {} -> pure (SolverError "simulation timed out")
      where
        posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

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

freshSymVar
  :: (CB.IsSymInterface sym)
  => sym
  -> Ctx.Index ctx tp
  -> CC.TypeRepr tp
  -> IO (CS.RegValue' sym tp)
-- The ARM backend has one placeholder "dummy" register (ARMDummyReg, used
-- for ASL globals whose type is an empty struct); it carries no information,
-- so it needs no symbolic value, just the unique empty assignment.
freshSymVar _sym _idx (CC.StructRepr Ctx.Empty) = pure (CS.RV Ctx.empty)
freshSymVar sym idx tp =
  CS.RV <$> case WI.userSymbol ("reg" ++ show (Ctx.indexVal idx)) of
    Right symbol -> case tp of
      CLM.LLVMPointerRepr w -> CLM.llvmPointer_bv sym =<< WI.freshConstant sym symbol (WI.BaseBVRepr w)
      CC.BoolRepr -> WI.freshConstant sym symbol WI.BaseBoolRepr
      _ -> fail ("unsupported register type: " ++ show tp)
    Left err -> fail (show err)
