{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Minimal APTrace-local plumbing to invoke the vendored @macaw-refinement@
-- library's SMT-based 'MDP.ClassifyFailure' resolution
-- ('Refine.cfgFromAddrsAndStateWith') against an already-computed AArch32
-- 'MD.DiscoveryState', scoped to a single function at a time.
--
-- This exists only to experiment with, and regression-test, refinement on
-- specific, already-known @classify_failure@ blocks (the CBZ\/CBNZ
-- investigation -- see @Data.Macaw.Refinement.SymbolicExecution@'s
-- compatibility-patch comment for the AArch32 register-state gap this
-- depends on). It does not feed into 'APTrace.MacawCensus': no block has yet
-- refined successfully, so there is nothing yet to mark with @macaw-refined@
-- provenance, and no census output is changed by this module.
--
-- @macaw-refinement@'s own 'Refine.RefinementContext' is deliberately opaque
-- outside its package (constructor and fields unexported) -- its only
-- exported constructor, 'Refine.defaultRefinementContext', requires a
-- 'MBL.LoadedBinary'. Rather than go through an ELF loader (this firmware
-- has none -- see 'APTrace.FirmwareLoader'), 'mkLoadedBinary' wraps our own
-- directly-built 'MM.Memory' using macaw-loader's own generic, already
-- fully-general @BinaryLoader arch 'MBL.RawBin'@ instance
-- (@Data.Macaw.BinaryLoader.Raw@): that instance's 'MBL.loadBinary' is never
-- called (it would re-derive memory from raw bytes at a single fixed base
-- with execute-only permissions, discarding our flash\/RAM\/permission
-- layout); only its @ArchBinaryData@\/@BinaryFormatData@ type-family
-- solutions (both @()@) are needed to construct the 'MBL.LoadedBinary'
-- record directly from our own memory image.
module APTrace.MacawRefinement
  ( refineFunctionAt
  ) where

import qualified Control.Monad.Catch as X
import           Control.Monad.IO.Class ( MonadIO, liftIO )
import qualified Control.Monad.IO.Unlift as MU
import qualified Control.Monad.Reader as MR
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import           Data.Word ( Word32 )
import           Lens.Micro ( (&), (%~) )
import qualified Lang.Crucible.LLVM.MemModel as LLVM
import qualified Lumberjack as LJ
import qualified Prettyprinter as PP
import qualified System.IO as IO

import           Data.Macaw.AArch32.Symbolic ()
import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.BinaryLoader as MBL
import           Data.Macaw.BinaryLoader.Raw ()
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Memory.LoadCommon as LC
import qualified Data.Macaw.Refinement as Refine

-- | The 'MR.ReaderT'-over-'IO' monad @macaw-refinement@'s own
-- @tools\/run-refinement.hs@ uses to satisfy 'LJ.HasLog'; refinement log
-- messages are written to stderr, matching every other diagnostic output in
-- this project.
newtype Refine a = Refine { runRefine_ :: MR.ReaderT Env IO a }
  deriving ( Functor, Applicative, Monad
           , MU.MonadUnliftIO, MonadIO, X.MonadThrow
           , MR.MonadReader Env )

newtype Env = Env { logger :: LJ.LogAction Refine (Refine.RefinementLog ARM.ARM) }

instance LJ.HasLog (Refine.RefinementLog ARM.ARM) Refine where
  getLogAction = MR.asks logger

runRefine :: Refine a -> IO a
runRefine a = MR.runReaderT (runRefine_ a) env0
  where
    doLog msg = liftIO $ IO.hPutStrLn IO.stderr (show (PP.pretty msg))
    env0 = Env (LJ.LogAction doLog)

-- | See the module-level Haddock: wraps our own memory image as a
-- 'MBL.LoadedBinary' via macaw-loader's generic raw-binary instance, purely
-- so 'Refine.defaultRefinementContext' -- the only exported way to build a
-- 'Refine.RefinementContext' -- can be used unmodified.
mkLoadedBinary :: BS.ByteString -> MM.Memory 32 -> MBL.LoadedBinary ARM.ARM MBL.RawBin
mkLoadedBinary flashBytes mem = MBL.LoadedBinary
  { MBL.memoryImage = mem
  , MBL.memoryEndianness = MM.LittleEndian
  , MBL.archBinaryData = ()
  , MBL.binaryFormatData = ()
  , MBL.loadDiagnostics = []
  , MBL.binaryRepr = MBL.RawBinary
  , MBL.originalBinary = MBL.RawBin { MBL.rawContents = flashBytes, MBL.rawEndianess = MM.LittleEndian }
  , MBL.loadOptions = LC.defaultLoadOptions
  }

-- | Attempt @macaw-refinement@'s SMT-based unknown-transfer resolution
-- against exactly one already-discovered function, identified by its
-- canonical (even) entry address. Scoping to one function keeps an
-- experiment or regression test fast and its result attributable, rather
-- than re-running refinement's parallel, per-function search across an
-- entire firmware's worth of functions.
--
-- Never consults Ghidra, Capstone, or any other evidence source: every
-- candidate model comes only from Crucible\/What4 symbolic execution of the
-- given 'MD.DiscoveryState' (Macaw's own lifted semantics), seeded from the
-- given memory image and firmware bytes.
refineFunctionAt
  :: BS.ByteString
  -- ^ Raw firmware bytes (flash contents), as read from disk -- passed
  -- straight through into the 'MBL.RawBin' wrapper; never touched.
  -> MM.Memory 32
  -> MD.DiscoveryState ARM.ARM
  -- ^ An already-computed discovery state (e.g. from the same
  -- vector-table-seeded discovery 'APTrace.MacawCensus' uses).
  -> Word32
  -- ^ The canonical entry address of the one function to attempt refinement
  -- on.
  -> IO (MD.DiscoveryState ARM.ARM, Refine.RefinementInfo ARM.ARM)
refineFunctionAt flashBytes mem discState targetEntry = do
  let keep k _ = case MM.asAbsoluteAddr (MM.segoffAddr (MM.clearSegmentOffLeastBit k)) of
        Just w  -> MM.memWordValue w == fromIntegral targetEntry
        Nothing -> False
      scoped = discState & MD.funInfo %~ Map.filterWithKey keep
      cfg = Refine.defaultRefinementConfig
              { Refine.solver = Refine.Z3
              , Refine.parallelismFactor = 1
              , Refine.timeoutSeconds = 60
              }
      loadedBin = mkLoadedBinary flashBytes mem
      memOpts = LLVM.defaultMemOptions
  ctx <- Refine.defaultRefinementContext cfg loadedBin
  let ?memOpts = memOpts
  runRefine (Refine.cfgFromAddrsAndStateWith ctx scoped [] [])
