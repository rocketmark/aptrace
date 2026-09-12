{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
-- | Reintegrates 'APTrace.MacawNormalize'\'s recovered @classify_failure@
-- targets into Macaw's own discovery using Macaw's own incremental,
-- intraprocedural API
-- (@Data.Macaw.Discovery.addDiscoveredFunctionBlockTargets@), so that
-- recovered branch targets are explored as continuations of the function
-- that already owns them -- never seeded as new top-level functions the
-- way a one-off @cfgFromAddrs@-with-extra-roots experiment would (that
-- experiment inflates function count, since every address handed to
-- @cfgFromAddrs@\/@markAddrsAsFunction@ is unconditionally treated as a
-- fresh function entry, regardless of whether it is really just an
-- ordinary intra-function branch target another path already reaches).
--
-- 'addDiscoveredFunctionBlockTargets' re-runs discovery for exactly one,
-- already-known function, additionally supplying it a list of @(block
-- address, resolved targets)@ pairs. Internally
-- (@Data.Macaw.Discovery.useExternalTargets@), when the normal classifier
-- chain fails on a block whose address appears in that list, Macaw adds
-- the supplied targets to that function's own exploration frontier
-- ('Jmp.IntraJumpTarget') and continues discovering from them as part of
-- the very same function -- function identity and ownership stay entirely
-- Macaw-derived; APTrace supplies only the resolved intraprocedural jump
-- targets, exactly as the API is documented to expect. Note that the
-- block's own 'MDP.ClassifyFailure' terminator is /not/ rewritten by this
-- (that is simply how this Macaw API represents "resolved via external
-- information" -- see 'discoveredClassifyFailureResolutions' below): the
-- classify_failure itself remains fully auditable in the expanded state
-- exactly as it was in the base state.
--
-- 'MD.discoveredClassifyFailureResolutions' -- the same field
-- macaw-refinement's own @Data.Macaw.Refinement.UnknownTransfer@ uses for
-- exactly this purpose -- records, per function, every @(block, targets)@
-- pair already supplied to it, so re-running this module's fixpoint over
-- an already-expanded state never re-applies (or re-derives) the same
-- resolution twice.
module APTrace.MacawExpand
  ( RoundInfo(..)
  , ExpansionResult(..)
  , expandWithNormalization
  , coverageStats
  , CoverageStats(..)
    -- * CLI entry point
  , runMacawCensusExpand
  , resolutionValue
  ) where

import           Data.Aeson ( Value(..), encode, object, (.=) )
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as BSLC
import           Data.List ( foldl', sort )
import qualified Data.Map as Map
import qualified Data.Set as Set
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( showHex )
import           System.Exit ( die )
import qualified System.IO as IO

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM
import           Data.Parameterized.Some ( Some(..) )

import           APTrace.FirmwareLoader ( buildMemory )
import           APTrace.MacawCensus
  ( CensusResult(..), FirmwareMeta(..), RootBuildResult(..)
  , buildDiscoveryState, buildRootInfo, censusToValue, normalizeRoots, summarizeDiscoveryState )
import qualified APTrace.MacawNormalize as Normalize
import           APTrace.VectorTable ( parseVectorTable )

-- | One completed round of the fixpoint: every @(function, block, targets)@
-- resolution newly discovered and fed into Macaw during that round (via
-- one or more calls to 'MD.addDiscoveredFunctionBlockTargets' -- one per
-- function that had at least one new resolution).
data RoundInfo = RoundInfo
  { riRound       :: !Int
  , riResolutions :: ![(Word32, Word32, [Word32])]
    -- ^ (function_entry, block_start, targets), all canonical words.
  } deriving (Eq, Show)

data ExpansionResult = ExpansionResult
  { erExpandedState :: !(MD.DiscoveryState ARM.ARM)
  , erRounds        :: ![RoundInfo]
    -- ^ One entry per round that made progress, in order; empty means the
    -- base state was already a fixpoint (no normalizable classify_failure
    -- at all).
  }

-- | An upper bound on fixpoint rounds. Not derived from the original 72
-- base-state classify_failure blocks: normalization can (and on
-- @autopilot868@, does) expose entirely new code with its own further
-- classify_failures, so the round count is not bounded by any fixed count
-- observed before expansion starts. What does bound it is that each round
-- either makes strictly positive progress (at least one block gains a
-- resolution it didn't have before, and a resolved block is never
-- revisited -- see 'MD.discoveredClassifyFailureResolutions') or the
-- fixpoint stops; 100 is simply a generously large ceiling on plausible
-- rounds for a single firmware image, so hitting it means the process is
-- not actually converging and must be reported loudly rather than
-- silently truncated.
maxRounds :: Int
maxRounds = 100

-- | Starting from an already-computed, vector-root-only Macaw
-- 'MD.DiscoveryState' (see 'APTrace.MacawCensus.buildDiscoveryState'),
-- repeatedly: find every @ClassifyFailure@ block not yet given a
-- resolution (per that function's own 'MD.discoveredClassifyFailureResolutions'),
-- attempt 'Normalize.normalizeIPSegOff' on each, and feed every successful
-- one back into its owning function via
-- 'MD.addDiscoveredFunctionBlockTargets' -- then let Macaw's own
-- 'MD.analyzeDiscoveredFunctions' explore anything newly reachable
-- (including entirely new functions Macaw itself identifies from the
-- newly-explored code, e.g. an ordinary call target) before checking for
-- more. Stops at the first round that finds no new resolutions anywhere
-- (a deterministic fixpoint, since normalization is a pure function of
-- Macaw's own already-lifted IR and never revisits an
-- already-resolved block).
expandWithNormalization :: MM.Memory 32 -> MD.DiscoveryState ARM.ARM -> ExpansionResult
expandWithNormalization mem base = go base 1 []
  where
    go state n acc
      | n > maxRounds =
          error ("APTrace.MacawExpand.expandWithNormalization: did not converge within "
                   ++ show maxRounds ++ " rounds -- this should be impossible for a bounded "
                   ++ "number of classify_failure blocks; aborting rather than truncating.")
      | otherwise =
          case applyOneRound mem state of
            (_, [])     -> ExpansionResult state (reverse acc)
            (state', rs) -> go state' (n + 1) (RoundInfo n rs : acc)

-- | Every function with at least one new, successfully-normalized
-- @classify_failure@ this round, paired with the full (old ++ new)
-- resolution list 'MD.addDiscoveredFunctionBlockTargets' expects (it
-- replaces, rather than merges with, whatever resolution list the
-- function previously had, so the old entries -- read back from Macaw's
-- own bookkeeping -- must always be included).
collectCandidates
  :: MM.Memory 32
  -> MD.DiscoveryState ARM.ARM
  -> [(Some (MD.DiscoveryFunInfo ARM.ARM), [(MM.MemSegmentOff 32, [MM.MemSegmentOff 32])])]
collectCandidates mem state =
  [ (sfn, newForFn)
  | sfn@(Some fn) <- Map.elems (state ^. MD.funInfo)
  , let already = Set.fromList (map fst (MD.discoveredClassifyFailureResolutions fn))
  , let newForFn =
          [ (MDP.pblockAddr b, targets)
          | b <- Map.elems (fn ^. MD.parsedBlocks)
          , not (Set.member (MDP.pblockAddr b) already)
          , MDP.ClassifyFailure regs _ <- [MDP.pblockTermStmt b]
          , Just targets <- [Normalize.normalizeIPSegOff mem (regs ^. MC.boundValue MC.ip_reg)]
          ]
  , not (null newForFn)
  ]

-- | Apply every candidate found against the given state (each function's
-- 'MD.addDiscoveredFunctionBlockTargets' call folded through the state in
-- turn -- safe to use a function handle captured at the start of the round
-- throughout the fold, since that call only ever reads that handle's
-- address and explore-reason, both of which never change), then run
-- 'MD.analyzeDiscoveredFunctions' once so any genuinely new function Macaw
-- itself now identifies (e.g. an ordinary call target in newly-explored
-- code) is fully analyzed before the next round looks for more
-- classify_failures. Returns the updated state and every resolution that
-- was newly applied this round, for reporting.
applyOneRound
  :: MM.Memory 32
  -> MD.DiscoveryState ARM.ARM
  -> (MD.DiscoveryState ARM.ARM, [(Word32, Word32, [Word32])])
applyOneRound mem state0 =
  let candidates = collectCandidates mem state0
      apply st (Some fn, newForFn) =
        let full = MD.discoveredClassifyFailureResolutions fn ++ newForFn
        in MD.addDiscoveredFunctionBlockTargets st fn full
      state1 = foldl' apply state0 candidates
      state2 = MD.analyzeDiscoveredFunctions state1
      canon = Normalize.segOffToCanonicalWord
      rows =
        [ (canon (MD.discoveredFunAddr fn), canon blk, map canon targets)
        | (Some fn, newForFn) <- candidates
        , (blk, targets) <- newForFn
        ]
  in (state2, sort rows)

-- | Function/block count and total (deduplicated, union-of-ranges) byte
-- coverage for a 'MD.DiscoveryState' -- used to report base vs. expanded
-- coverage without needing to materialize or diff the full block lists.
-- Block counts follow the same per-function-context convention as
-- 'APTrace.MacawCensus.crBlocks' (a block reached from two different
-- functions counts twice); byte coverage merges ranges first, so the same
-- physical bytes are never double-counted regardless of how many function
-- contexts reach them.
data CoverageStats = CoverageStats
  { csFunctions    :: !Int
  , csBlocks       :: !Int
  , csByteCoverage :: !Int
  } deriving (Eq, Show)

coverageStats :: MD.DiscoveryState ARM.ARM -> CoverageStats
coverageStats state =
  let funs = Map.elems (state ^. MD.funInfo)
      blockRanges =
        [ (start, start + fromIntegral (MDP.blockSize b))
        | Some fn <- funs
        , b <- Map.elems (fn ^. MD.parsedBlocks)
        , let start = Normalize.segOffToCanonicalWord (MDP.pblockAddr b)
        ]
      ranges = mergeRanges blockRanges
  in CoverageStats
       { csFunctions = length funs
       , csBlocks = length blockRanges
       , csByteCoverage = sum [ fromIntegral (hi - lo) | (lo, hi) <- ranges ]
       }

-- | Half-open @[lo,hi)@ range union, used only by 'coverageStats'.
mergeRanges :: [(Word32, Word32)] -> [(Word32, Word32)]
mergeRanges = go . sort
  where
    go [] = []
    go [r] = [r]
    go ((l1, h1) : (l2, h2) : rest)
      | l2 <= h1  = go ((l1, max h1 h2) : rest)
      | otherwise = (l1, h1) : go ((l2, h2) : rest)

------------------------------------------------------------------------
-- Residual classify_failure accounting

-- | Every @classify_failure@ block remaining in the final expanded state
-- that was /never/ given a resolution (in any round) -- i.e. Macaw's own
-- 'MD.discoveredClassifyFailureResolutions' for its owning function does
-- not mention it. This is computed fresh from the final state, so it is
-- correct regardless of how many rounds it took to reach it -- never a
-- simple "72 minus round 1" count.
residualClassifyFailures :: MD.DiscoveryState ARM.ARM -> [(Word32, Word32)]
residualClassifyFailures state =
  sort
    [ (canon (MD.discoveredFunAddr fn), canon (MDP.pblockAddr b))
    | Some fn <- Map.elems (state ^. MD.funInfo)
    , let already = Set.fromList (map fst (MD.discoveredClassifyFailureResolutions fn))
    , b <- Map.elems (fn ^. MD.parsedBlocks)
    , MDP.ClassifyFailure{} <- [MDP.pblockTermStmt b]
    , not (Set.member (MDP.pblockAddr b) already)
    ]
  where
    canon = Normalize.segOffToCanonicalWord

------------------------------------------------------------------------
-- CLI entry point

-- Matches every other harness in this project (see app/Main.hs's own
-- ramBase/ramSize/numIrq, and APTrace.MacawCensus's identical constants).
ramBase :: Word32
ramBase = 0x20000000

ramSize :: Word32
ramSize = 0x30000

numIrq :: Int
numIrq = 40

hexStr :: Word32 -> String
hexStr w = "0x" ++ showHex w ""

resolutionValue :: (Word32, Word32, [Word32]) -> Value
resolutionValue (fn, blk, targets) = object
  [ "function_entry" .= hexStr fn
  , "block_start"    .= hexStr blk
  , "targets"        .= map hexStr targets
  , "provenance"     .= Normalize.macawNormalizedProvenance
  ]

coverageValue :: CoverageStats -> Value
coverageValue cs = object
  [ "functions"      .= csFunctions cs
  , "blocks"         .= csBlocks cs
  , "byte_coverage"  .= csByteCoverage cs
  ]

-- | @aptrace macaw-census-expand FIRMWARE.bin [FLASH_BASE]@ -- build the
-- same vector-root-only base discovery state @aptrace macaw-census@ does
-- (via 'buildRootInfo'\/'buildDiscoveryState', the very functions
-- @discoverCensus@ itself is built from -- no separate address-resolution
-- or canonicalization logic here), then run 'expandWithNormalization' to a
-- fixpoint.
--
-- The output's core fields (@functions@, @basic_blocks@, @edges@,
-- @calls@, @incomplete_or_unresolved_terminators@,
-- @normalized_terminators@) are exactly what @aptrace macaw-census@ itself
-- emits -- built via the very same 'summarizeDiscoveryState'\/'censusToValue'
-- this module's base census uses -- but describing the FINAL EXPANDED
-- state, not the base one, so @tools/census/macaw_compare.py@ can consume
-- this file exactly as it already consumes a plain @macaw-census@ one.
-- Base-vs-expanded coverage is reported alongside as small summary
-- metadata (@base@\/@expanded@), not a second copy of the whole graph.
runMacawCensusExpand :: FilePath -> Word32 -> IO ()
runMacawCensusExpand path flashBase = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let rb = buildRootInfo mem (normalizeRoots (parseVectorTable numIrq bytes))
          baseState = buildDiscoveryState mem (rbAddrSymMap rb) (rbEntryList rb)
          baseStats = coverageStats baseState

          result = expandWithNormalization mem baseState
          expandedState = erExpandedState result
          expandedStats = coverageStats expandedState

          residual = residualClassifyFailures expandedState

          fm = FirmwareMeta
                 { fmPath = path
                 , fmSizeBytes = BS.length bytes
                 , fmFlashBase = flashBase
                 , fmRamBase = ramBase
                 , fmRamSize = ramSize
                 }
          -- The final expanded state's own functions/basic_blocks/edges/
          -- calls/unresolved-terminators/normalized-terminators, via the
          -- same summarization discoverCensus uses -- with crRoots set to
          -- the firmware's own vector-table roots (unaffected by
          -- expansion) rather than 'summarizeDiscoveryState's default
          -- empty list.
          expandedCensus = (summarizeDiscoveryState mem (rbRootCanonSet rb) expandedState)
                             { crRoots = rbRootInfos rb }
          graphValue = censusToValue fm expandedCensus

          roundValue r = object
            [ "round"       .= riRound r
            , "resolutions" .= map resolutionValue (riResolutions r)
            ]

          extras = object
            [ "base" .= coverageValue baseStats
            , "expanded" .= coverageValue expandedStats
            , "normalization_rounds" .= length (erRounds result)
            , "rounds" .= map roundValue (erRounds result)
            , "residual_classify_failures" .=
                [ object [ "function_entry" .= hexStr fn, "block_start" .= hexStr blk ]
                | (fn, blk) <- residual
                ]
            ]

          out = case (graphValue, extras) of
            (Object g, Object e) -> Object (KM.union g e)
            _ -> error "runMacawCensusExpand: censusToValue/extras did not produce JSON objects"

      IO.hSetBuffering IO.stdout IO.LineBuffering
      BSLC.putStrLn (encode out)
