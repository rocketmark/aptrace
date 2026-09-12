{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
-- | Experimental: attach Galois' @crucible-debug@ (an interactive Crucible
-- debugger, distributed as a reusable 'CS.ExecutionFeature') plus
-- @crucible-macaw-debug@ (its macaw-specific extension: @mregister@,
-- @mmemory@, @mtrace@, @mglobals@ commands) to one of APTrace's own,
-- already-understood Crucible blocks.
--
-- This is a pre-meeting prototype, not a stable feature: see
-- docs/tooling/galois-premeeting.md for what worked, what's a known
-- simplification, and the exact questions this raised for Galois. It
-- deliberately does NOT reuse/modify 'APTrace.SymbolicRunner' or
-- 'APTrace.ProtocolHarness' -- both use the fixed
-- @Data.Macaw.Symbolic.MacawSimulatorState@ personality type, and
-- @crucible-debug@'s 'Dbg.debugger' feature requires the simulator's
-- personality to satisfy 'Dbg.HasContext' (a lens onto a
-- @Lang.Crucible.Debug.Context@ value carrying breakpoints, I/O streams,
-- and instruction-trace history). Retrofitting that onto the existing
-- harnesses would mean threading a new personality type through both
-- modules; this module instead runs a small, separate simulation whose
-- personality *is* a 'Dbg.Context' directly (which trivially satisfies
-- 'Dbg.HasContext' via @instance HasContext (Context cExt sym ext t) ...@),
-- the smaller-footprint option consistent with this project's
-- "don't restructure for one experiment" discipline.
module APTrace.DebugHarness
  ( runDebug
  ) where

import           Control.Applicative ( empty )
import           Data.Proxy ( Proxy(..) )
import qualified Data.BitVector.Sized as BV
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import qualified Data.Parameterized.Context as Ctx
import qualified Data.Parameterized.Map as MapF
import           Data.Parameterized.Some ( Some(..) )
import qualified Data.Text as Text
import qualified Data.Word as W
import           System.Exit ( die )
import qualified System.IO as IO

import qualified Data.Macaw.AArch32.Symbolic ()
import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.ARMReg as AR
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Symbolic as MS
import qualified Data.Macaw.Symbolic.Debug as MDebug
import qualified Data.Macaw.Symbolic.Memory as MSM
import qualified SemMC.Architecture.AArch32 as ARM

import qualified Lang.Crucible.Backend as CB
import qualified Lang.Crucible.Backend.Simple as CBS
import qualified Lang.Crucible.CFG.Core as CC
import qualified Lang.Crucible.Debug as Dbg
import qualified Lang.Crucible.FunctionHandle as CFH
import qualified Lang.Crucible.LLVM.DataLayout as LDL
import qualified Lang.Crucible.LLVM.Intrinsics as CLI
import qualified Lang.Crucible.LLVM.MemModel as CLM
import qualified Lang.Crucible.Pretty as CPretty
import qualified Lang.Crucible.Simulator as CS
import qualified Lang.Crucible.Simulator.GlobalState as CSG
import qualified Lang.Crucible.Syntax.Concrete as CSyn
import           Lens.Micro ( (^.) )

import qualified Data.Parameterized.Nonce as PN
import qualified What4.Expr as WE
import qualified What4.Interface as WI
import qualified What4.ProgramLoc as WPL

import           APTrace.FirmwareLoader ( buildMemory, resolveEntry, macawCortexMEntry )

-- | Minimal What4 backend "user state" placeholder -- mirrors
-- 'APTrace.SymbolicRunner.BackendData' (kept local there too; What4's
-- 'WE.newExprBuilder' needs some @st@ type, and this project's existing
-- Crucible modules don't use it for anything).
data BackendData t = BackendData

-- | Attach an interactive @crucible-debug@ session to a single already-
-- discovered Macaw block, entering with the same concrete seed this
-- project has already independently confirmed with Unicorn
-- (@docs/tooling/unicorn-backend.md@) and solver-confirmed with
-- 'APTrace.SymbolicRunner.checkBranchModel' (the AutoPilot @&@ command
-- check at flash 0x888c, @r3=0x26@). Runs a small, fixed script of debugger
-- commands (register inspection, single-stepping, then continuing to
-- completion) so the output is deterministic and reproducible without
-- requiring a live interactive terminal.
runDebug :: FilePath -> W.Word32 -> W.Word32 -> IO ()
runDebug path flashBase entryRaw = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase 0x20000000 0x30000 of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let entryAddr = macawCortexMEntry entryRaw
      entry <- maybe (die "could not resolve entry address") pure (resolveEntry mem entryAddr)
      let addrSymMap = Map.singleton entry "target"
          discState = MD.cfgFromAddrs ARM.arm_linux_info mem addrSymMap [entry] []
          funs = discState ^. MD.funInfo
      case Map.lookup entry funs of
        Nothing -> die "target function was not discovered"
        Just (Some fn) ->
          case MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral entryAddr)) of
            Nothing -> die "could not resolve block address"
            Just off -> case Map.lookup off (fn ^. MD.parsedBlocks) of
              Nothing -> die "target block not found in discovered function"
              Just block -> runBlockUnderDebugger mem block

runBlockUnderDebugger :: MM.Memory 32 -> MDP.ParsedBlock ARM.AArch32 ids -> IO ()
runBlockUnderDebugger mem block
  | Just archVals <- MS.archVals (Proxy @ARM.AArch32) Nothing = do
      sym <- WE.newExprBuilder WE.FloatUninterpretedRepr BackendData PN.globalNonceGenerator
      bak <- CBS.newSimpleBackend sym
      let ?recordLLVMAnnotation = \_ _ _ -> pure ()
      let ?processMacawAssert = MSM.defaultProcessMacawAssertion
      let ?memOpts = CLM.defaultMemOptions
      let ?ptrWidth = WI.knownNat @32
      -- No macaw-syntax extensions registered (no interactive 'load'/'call'
      -- of extra .cbl snippets in this prototype) -- see
      -- docs/tooling/galois-premeeting.md's debugger section for why this
      -- is a documented simplification: Data.Macaw.Symbolic.Syntax's
      -- 'machineCodeParserHooks' exists and could be wired in if that
      -- capability is wanted later.
      let ?parserHooks = CSyn.ParserHooks empty empty :: CSyn.ParserHooks (MS.MacawExt ARM.AArch32)
      halloc <- CFH.newHandleAllocator
      someCfg <- MS.mkParsedBlockCFG (MS.archFunctions archVals) halloc posFn block
      case someCfg of
        CC.SomeCFG cfg ->
          MS.withArchEval archVals sym $ \archEvalFns -> do
            memVar <- CLM.mkMemVar "aptrace:llvm_memory" halloc
            (memAfterBuild, memPtrTable) <-
              MSM.newGlobalMemory (Proxy @ARM.AArch32) bak LDL.LittleEndian MSM.SymbolicMutable mem
            let mmConf = (MSM.memModelConfig bak memPtrTable)
                  { MS.lookupFunctionHandle = MS.unsupportedFunctionCalls "aptrace"
                  , MS.lookupSyscallHandle = MS.unsupportedSyscalls "aptrace"
                  }
            let ext = MS.macawExtensions archEvalFns memVar mmConf
            let retTy = CFH.handleReturnType (CC.cfgHandle cfg)

            let cmdExt = MDebug.macawCommandExt archVals
                iFns = CPretty.IntrinsicPrinters MapF.empty
            inputs0 <- Dbg.defaultDebuggerInputs cmdExt
            let stmts = [ s | Right s <- map (Dbg.parse cmdExt) cannedScript ]
            inputs <- Dbg.prepend stmts inputs0
            let outputs = Dbg.defaultDebuggerOutputs
            ctx0 <- Dbg.initCtx cmdExt iFns inputs outputs retTy

            let regTypes = MS.crucArchRegTypes (MS.archFunctions archVals)
            regVals <- Ctx.traverseWithIndex (concreteZeroVar sym) regTypes
            r3Ptr <- resolvedPointer bak (MS.globalMemMap mmConf) memAfterBuild 0x26
            let regStruct0 = CS.RegEntry (CC.StructRepr regTypes) regVals
                regStruct1 = MS.updateReg archVals regStruct0 AR.r3 r3Ptr
                initRegs = CS.RegMap (Ctx.singleton regStruct1)

            let simCtx = CS.initSimContext bak CLI.llvmIntrinsicTypes halloc IO.stderr
                           (CS.FnBindings CFH.emptyHandleMap) ext ctx0
            let globalState = CSG.insertGlobal memVar memAfterBuild CS.emptyGlobals
            let simulation = CS.regValue <$> CS.callCFG cfg initRegs
            let initState = CS.InitialState simCtx globalState CS.defaultAbortHandler retTy
                              (CS.runOverrideSim retTy simulation)
            let extImpl = MDebug.macawExtImpl iFns memVar archVals Nothing
            execRes <- CS.executeCrucible [Dbg.debugger extImpl] initState
            case execRes of
              CS.FinishedResult {} -> putStrLn "\n[aptrace debug] simulation finished"
              CS.AbortedResult {}  -> putStrLn "\n[aptrace debug] simulation aborted"
              CS.TimeoutResult {}  -> putStrLn "\n[aptrace debug] simulation timed out"
  | otherwise = die "no ArchVals for AArch32"
  where
    posFn addr = WPL.BinaryPos "aptrace" (maybe 0 fromIntegral (MC.segoffAsAbsoluteAddr addr))

-- | The fixed demonstration script: show the seeded register, single-step
-- through the block's few instructions, print it again, then run to
-- completion. Real interactive use would replace this with a live terminal
-- (crucible-debug's own default input source, still used as the fallback
-- once this canned script is exhausted).
-- | Ends with an explicit @quit@: without it, once the script is
-- exhausted the debugger falls back to its real input source
-- (interactive stdin) -- see docs/tooling/galois-premeeting.md's debugger
-- section for what happened when this ran with stdin redirected from
-- @/dev/null@ instead of ending on @quit@ (an infinite "No command given"
-- loop on repeated EOF, not a graceful exit -- a real integration
-- question for Galois, not something this prototype works around beyond
-- avoiding it here).
cannedScript :: [Text.Text]
cannedScript =
  [ "mregister r3"
  , "step"
  , "step"
  , "mregister r3 _pc"
  , "continue"
  , "quit"
  ]

-- | Mirrors 'APTrace.ProtocolHarness.concreteZeroVar' (not exported there;
-- kept local here too, same "small, self-contained module" precedent as
-- 'APTrace.SymbolicRunner.writeConcreteByte').
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
