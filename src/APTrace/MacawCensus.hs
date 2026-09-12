{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
-- | A standalone, deterministic census of what Macaw's own static discovery
-- finds in a Cortex-M firmware image, seeded /only/ from the firmware's own
-- vector table (see 'normalizeRoots' / 'runMacawCensus'). This is an
-- independent Macaw evidence producer: no Ghidra, no Capstone, no existing
-- census data, and no symbolic execution feed into it, so its output can
-- later be compared against those sources without circularity.
--
-- Phase 1 only: this module has no dependency on (and no effect on) the
-- existing Python/SQLite census.
module APTrace.MacawCensus
  ( -- * Types
    FirmwareMeta(..)
  , RootInfo(..)
  , FunctionInfo(..)
  , BlockInfo(..)
  , EdgeInfo(..)
  , UnresolvedInfo(..)
  , CallInfo(..)
  , CensusResult(..)
    -- * Pipeline
  , normalizeRoots
  , discoverCensus
  , censusToValue
  , canonicalWord
    -- * CLI entry point
  , runMacawCensus
  ) where

import           Control.Exception ( SomeException, evaluate, try )
import           Data.Aeson ( Value, encode, object, (.=) )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy.Char8 as BSLC
import           Data.List ( intercalate, sort, sortOn )
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Vector as V
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

import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, macawCortexMEntry, armCortexMInfo )
import           APTrace.VectorTable ( VectorEntry(..), parseVectorTable )

-- Fixed for the AutoPilot/Mando firmware family, matching every other
-- harness in this project (see app/Main.hs's own ramBase/ramSize/numIrq).
ramBase :: Word32
ramBase = 0x20000000

ramSize :: Word32
ramSize = 0x30000

numIrq :: Int
numIrq = 40

------------------------------------------------------------------------
-- Types

data FirmwareMeta = FirmwareMeta
  { fmPath      :: !FilePath
  , fmSizeBytes :: !Int
  , fmFlashBase :: !Word32
  , fmRamBase   :: !Word32
  , fmRamSize   :: !Word32
  } deriving (Eq, Show)

-- | One deduplicated, Cortex-M-normalized vector-table target.
data RootInfo = RootInfo
  { riNames         :: ![String]
    -- ^ Every vector-table handler name sharing this target address
    -- (e.g. several unused IRQs sharing one @Default_Handler@).
  , riMacawAddr     :: !Word32
    -- ^ The address actually handed to 'MD.cfgFromAddrs' (post-
    -- 'macawCortexMEntry' normalization; always Thumb-tagged).
  , riCanonicalAddr :: !(Maybe Word32)
    -- ^ The canonical (even) instruction address, if the root resolved
    -- into mapped memory.
  , riResolved      :: !Bool
  } deriving (Eq, Show)

data FunctionInfo = FunctionInfo
  { fiEntry      :: !Word32
    -- ^ Canonical entry address (never the odd Thumb-tagged form).
  , fiIsRoot     :: !Bool
    -- ^ True if this function's entry is one of the seeded vector-table
    -- roots, false if Macaw reached it transitively (e.g. a called helper).
  , fiBlockCount :: !Int
  } deriving (Eq, Show)

data BlockInfo = BlockInfo
  { biFunctionEntry :: !Word32
  , biBlockStart    :: !Word32
  , biSize          :: !Int
  , biTermKind      :: !String
  } deriving (Eq, Show)

data EdgeInfo = EdgeInfo
  { eiFunctionEntry :: !Word32
  , eiSource        :: !Word32
  , eiTarget        :: !Word32
    -- ^ Only ever emitted when Macaw's own terminator AST gives a concrete
    -- target; see 'UnresolvedInfo' for the "target not known" case.
  , eiKind          :: !String
  } deriving (Eq, Show)

data UnresolvedInfo = UnresolvedInfo
  { uiFunctionEntry :: !Word32
  , uiBlockStart    :: !Word32
  , uiKind          :: !String
  , uiDetail        :: ![String]
  } deriving (Eq, Show)

-- | One @caller function -> call site -> callee function@ relationship,
-- distinct from the CFG-successor 'EdgeInfo' (whose @call_return@ edge
-- points at the *return continuation*, never the callee). Emitted for
-- every 'MDP.ParsedCall' terminator Macaw discovers, call or tail call.
--
-- 'ciKind' distinguishes three cases Macaw's own call-target value
-- ('MC.curIP') can be in -- deliberately kept separate rather than
-- collapsing the latter two into one "unknown callee" bucket, so a later
-- Ghidra comparison can tell "Macaw doesn't know" from "Macaw has an
-- address, but it's outside APTrace's firmware image":
--
--  * @"direct"@ -- 'MC.valueAsMemAddr' gives a concrete absolute address,
--    and it resolves into the firmware memory image. 'ciCallee' is that
--    address, canonicalized.
--  * @"unmapped"@ -- 'MC.valueAsMemAddr' gives a concrete absolute
--    address, but it does /not/ resolve into the firmware memory image
--    (out of the mapped flash\/RAM ranges). 'ciCallee' is still that
--    address -- preserved exactly as Macaw computed it, /not/
--    canonicalized (there is no basis to assume it's even a real
--    instruction address, let alone Thumb-tagged, for a target outside
--    the image), so it can still be inspected or cross-checked later.
--  * @"indirect"@ -- Macaw cannot reduce 'MC.curIP' to a concrete address
--    at all (a genuinely register-indirect call). 'ciCallee' is 'Nothing'.
data CallInfo = CallInfo
  { ciCaller   :: !Word32
    -- ^ Canonical entry of the function containing the call site.
  , ciCallSite :: !Word32
    -- ^ Canonical address of the block ending in the call.
  , ciCallee   :: !(Maybe Word32)
    -- ^ 'Just' for @"direct"@ (canonicalized, resolved) and @"unmapped"@
    -- (raw, unresolved -- see 'ciKind'); 'Nothing' only for @"indirect"@.
  , ciKind     :: !String
    -- ^ @"direct"@, @"unmapped"@, or @"indirect"@ -- see above.
  } deriving (Eq, Show)

data CensusResult = CensusResult
  { crRoots           :: ![RootInfo]
  , crDiscoveryError  :: !(Maybe String)
    -- ^ Set only if Macaw's discovery pass itself raised an exception
    -- (e.g. an unhandled decode case) -- see 'discoverCensus'. When set,
    -- 'crFunctions'/'crBlocks'/'crEdges'/'crUnresolved'/'crCalls' are empty.
  , crFunctions       :: ![FunctionInfo]
  , crBlocks          :: ![BlockInfo]
  , crEdges           :: ![EdgeInfo]
  , crUnresolved      :: ![UnresolvedInfo]
  , crCalls           :: ![CallInfo]
  } deriving (Eq, Show)

------------------------------------------------------------------------
-- Discovery roots: vector table only, deduplicated and Cortex-M-normalized

-- | Group a firmware's vector-table entries by their Macaw discovery-root
-- address (every raw table value normalized through 'macawCortexMEntry'
-- first, so an even and an odd encoding of "the same" target collapse into
-- one root), sorted ascending by that address. This -- and only this -- is
-- the discovery-root source for 'discoverCensus': no Ghidra, no Capstone,
-- no existing census data, no manual lists.
normalizeRoots :: [VectorEntry] -> [(Word32, [String])]
normalizeRoots entries =
  let grouped = Map.fromListWith (++)
                  [ (macawCortexMEntry (veRawAddr e), [veName e]) | e <- entries ]
  in [ (addr, sort names) | (addr, names) <- Map.toAscList grouped ]

------------------------------------------------------------------------
-- Canonical addresses

-- | The canonical (even) Cortex-M instruction address for a resolved Macaw
-- address -- strips the internal Thumb-state bit via Macaw's own
-- 'MM.clearSegmentOffLeastBit' (the same operation macaw-aarch32's own
-- disassembler uses to compute the real byte address to decode from), so
-- this module never re-implements that bit test itself. Never expose the
-- odd, Thumb-tagged form as a function/block identity in output.
canonicalWord :: MM.MemSegmentOff 32 -> Word32
canonicalWord so =
  case MM.asAbsoluteAddr (MM.segoffAddr (MM.clearSegmentOffLeastBit so)) of
    Just w  -> fromIntegral (MM.memWordValue w)
    Nothing -> error "canonicalWord: expected an absolute address"

------------------------------------------------------------------------
-- Discovery

-- | An intermediate, plain-Haskell (never Macaw's own GADT-heavy AST)
-- summary of one discovery pass, with strict fields throughout so that
-- forcing a list's spine (see 'forceElems') also forces every element's
-- scalar fields -- which is what actually exercises Macaw's decode/
-- classification logic on each block's terminator. This is what lets
-- 'discoverCensus' catch a Macaw decode exception before it escapes into
-- pure code the caller might inspect later, lazily, outside the 'try'.
data Core = Core
  { coreFunctions  :: ![FunctionInfo]
  , coreBlocks     :: ![BlockInfo]
  , coreEdges      :: ![EdgeInfo]
  , coreUnresolved :: ![UnresolvedInfo]
  , coreCalls      :: ![CallInfo]
  }

forceElems :: [a] -> [a]
forceElems xs = foldr seq () xs `seq` xs

forceCore :: Core -> Core
forceCore c = Core
  { coreFunctions  = forceElems (coreFunctions c)
  , coreBlocks     = forceElems (coreBlocks c)
  , coreEdges      = forceElems (coreEdges c)
  , coreUnresolved = forceElems (coreUnresolved c)
  , coreCalls      = forceElems (coreCalls c)
  }

-- | Run Macaw's own static discovery ('MD.cfgFromAddrs') from the given
-- (already deduplicated/normalized) roots and summarize exactly what it
-- found. Never seeds from anything but the given roots, never invokes
-- Crucible/What4/Z3, and never consults Ghidra/Capstone/the existing
-- census.
--
-- Wrapped in 'try': macaw-aarch32's decode/classification tables are known
-- to be incomplete for some real instruction encodings (see
-- @docs/tooling/tool-selection.md@), and an unhandled case can raise a
-- plain Haskell exception rather than returning a 'MDP.ClassifyFailure'.
-- If that happens, 'crDiscoveryError' carries the exception text and every
-- other list in the result is empty, rather than the whole command
-- crashing with no output at all.
discoverCensus :: MM.Memory 32 -> [(Word32, [String])] -> IO CensusResult
discoverCensus mem rootGroups = do
  let resolvedRoots =
        [ (addr, off, names)
        | (addr, names) <- rootGroups
        , Just off <- [resolveEntry mem addr]
        ]
      unresolvedRoots =
        [ (addr, names) | (addr, names) <- rootGroups, Nothing <- [resolveEntry mem addr] ]
      rootCanon (_, off, _) = canonicalWord off
      rootCanonSet = Set.fromList (map rootCanon resolvedRoots)
      addrSymMap = Map.fromList
        [ (off, BSC.pack (intercalate "|" names)) | (_, off, names) <- resolvedRoots ]
      entryList = [ off | (_, off, _) <- resolvedRoots ]
      rootInfos =
        sortOn riMacawAddr $
          [ RootInfo names addr Nothing False | (addr, names) <- unresolvedRoots ]
          ++ [ RootInfo names addr (Just (canonicalWord off)) True
             | (addr, off, names) <- resolvedRoots
             ]

  attempt <- try (evaluate (forceCore (buildCore mem addrSymMap entryList rootCanonSet)))
               :: IO (Either SomeException Core)
  pure $ case attempt of
    Left ex ->
      CensusResult
        { crRoots = rootInfos
        , crDiscoveryError = Just (show ex)
        , crFunctions = []
        , crBlocks = []
        , crEdges = []
        , crUnresolved = []
        , crCalls = []
        }
    Right core ->
      CensusResult
        { crRoots = rootInfos
        , crDiscoveryError = Nothing
        , crFunctions = sortOn fiEntry (coreFunctions core)
        , crBlocks = sortOn (\b -> (biFunctionEntry b, biBlockStart b)) (coreBlocks core)
        , crEdges = sortOn (\e -> (eiFunctionEntry e, eiSource e, eiTarget e, eiKind e))
                      (coreEdges core)
        , crUnresolved = sortOn (\u -> (uiFunctionEntry u, uiBlockStart u)) (coreUnresolved core)
        , crCalls = sortOn (\c -> (ciCaller c, ciCallSite c, ciCallee c)) (coreCalls core)
        }

buildCore :: MM.Memory 32 -> MD.AddrSymMap 32 -> [MM.MemSegmentOff 32] -> Set.Set Word32 -> Core
buildCore mem addrSymMap entryList rootCanonSet =
  let discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap entryList []
      funs = Map.elems (discState ^. MD.funInfo)
      perFunction = map (summarizeFunction mem rootCanonSet) funs
  in Core
       { coreFunctions  = map (\(f, _, _, _, _) -> f) perFunction
       , coreBlocks     = concatMap (\(_, bs, _, _, _) -> bs) perFunction
       , coreEdges      = concatMap (\(_, _, es, _, _) -> es) perFunction
       , coreUnresolved = concatMap (\(_, _, _, us, _) -> us) perFunction
       , coreCalls      = concatMap (\(_, _, _, _, cs) -> cs) perFunction
       }

summarizeFunction
  :: MM.Memory 32
  -> Set.Set Word32
  -> Some (MD.DiscoveryFunInfo ARM.ARM)
  -> (FunctionInfo, [BlockInfo], [EdgeInfo], [UnresolvedInfo], [CallInfo])
summarizeFunction mem rootCanonSet (Some fn) =
  let entryCanon = canonicalWord (MD.discoveredFunAddr fn)
      blocks = Map.elems (fn ^. MD.parsedBlocks)
      blockInfos =
        [ BlockInfo entryCanon (canonicalWord (MDP.pblockAddr b)) (MDP.blockSize b)
            (termKindName (MDP.pblockTermStmt b))
        | b <- blocks
        ]
      edgeInfos =
        concat
          [ edgesOf entryCanon (canonicalWord (MDP.pblockAddr b)) (MDP.pblockTermStmt b)
          | b <- blocks
          ]
      unresolvedInfos =
        [ u
        | b <- blocks
        , Just u <- [unresolvedOf entryCanon (canonicalWord (MDP.pblockAddr b)) (MDP.pblockTermStmt b)]
        ]
      callInfos =
        concat
          [ callsOf mem entryCanon (canonicalWord (MDP.pblockAddr b)) (MDP.pblockTermStmt b)
          | b <- blocks
          ]
      fnInfo = FunctionInfo entryCanon (entryCanon `Set.member` rootCanonSet) (length blocks)
  in (fnInfo, blockInfos, edgeInfos, unresolvedInfos, callInfos)

-- | Name Macaw's own terminator classification -- one word per
-- 'MDP.ParsedTermStmt' constructor, nothing inferred beyond that.
termKindName :: MDP.ParsedTermStmt ARM.ARM ids -> String
termKindName t = case t of
  MDP.ParsedCall _ (Just _)  -> "call"
  MDP.ParsedCall _ Nothing   -> "tail_call"
  MDP.PLTStub{}              -> "plt_stub"
  MDP.ParsedJump{}           -> "jump"
  MDP.ParsedBranch{}         -> "branch"
  MDP.ParsedLookupTable{}    -> "lookup_table"
  MDP.ParsedReturn{}         -> "return"
  MDP.ParsedArchTermStmt{}   -> "arch_term_stmt"
  MDP.ParsedTranslateError{} -> "translate_error"
  MDP.ClassifyFailure{}      -> "classify_failure"

-- | Every successor edge Macaw's own terminator AST gives a concrete
-- target for -- mirrors 'MDP.parsedTermSucc' exactly (same cases, same
-- targets) but keeps each edge's specific kind instead of flattening them
-- into one address list. A terminator with no known target (classify
-- failure, translate error) or no successor at all (return, tail call,
-- PLT stub) contributes no edges here; see 'unresolvedOf' for the former.
edgesOf :: Word32 -> Word32 -> MDP.ParsedTermStmt ARM.ARM ids -> [EdgeInfo]
edgesOf funcEntry src t = case t of
  MDP.ParsedCall _ (Just ret)           -> [mk "call_return" ret]
  MDP.ParsedCall _ Nothing              -> []
  MDP.PLTStub{}                         -> []
  MDP.ParsedJump _ tgt                  -> [mk "jump" tgt]
  MDP.ParsedBranch _ _ tAddr fAddr      -> [mk "branch_true" tAddr, mk "branch_false" fAddr]
  MDP.ParsedLookupTable _ _ _ v         -> [ mk "lookup_table" a | a <- V.toList v ]
  MDP.ParsedReturn{}                    -> []
  MDP.ParsedArchTermStmt _ _ (Just ret) -> [mk "arch_term_stmt" ret]
  MDP.ParsedArchTermStmt _ _ Nothing    -> []
  MDP.ParsedTranslateError{}            -> []
  MDP.ClassifyFailure{}                 -> []
  where
    mk kind tgt = EdgeInfo
      { eiFunctionEntry = funcEntry
      , eiSource = src
      , eiTarget = canonicalWord tgt
      , eiKind = kind
      }

-- | The two cases where Macaw explicitly could not classify a block's
-- terminator at all (as opposed to classifying it as, say, a genuine
-- no-successor return). Recorded verbatim -- Macaw's own classify-failure
-- reason strings / translate-error message -- never guessed at.
unresolvedOf :: Word32 -> Word32 -> MDP.ParsedTermStmt ARM.ARM ids -> Maybe UnresolvedInfo
unresolvedOf funcEntry src t = case t of
  MDP.ParsedTranslateError msg  -> Just (UnresolvedInfo funcEntry src "translate_error" [Text.unpack msg])
  MDP.ClassifyFailure _ reasons -> Just (UnresolvedInfo funcEntry src "classify_failure" reasons)
  _                              -> Nothing

-- | The @caller -> call site -> callee@ relation for one block's
-- terminator, if it's a call (ordinary or tail) -- 'MDP.ParsedCall'.
-- Every other terminator kind (jump, branch, lookup table, PLT stub --
-- 'MDP.PLTStub' is itself documented as a tail-call variant, not a plain
-- call -- return, arch term stmt, translate error, classify failure)
-- contributes nothing here; this never guesses a call from anything but
-- Macaw's own classified 'MDP.ParsedCall'.
--
-- The callee comes from the *same* register state 'MDP.parsedTermSucc'
-- reads for the call's return successor -- 'MDP.ParsedCall'\'s own
-- 'MC.RegState' -- read at the instruction-pointer register ('MC.curIP').
-- Never inferred from disassembly text. Classified into exactly the three
-- cases 'CallInfo' documents (@direct@\/@unmapped@\/@indirect@); a call is
-- always emitted, never dropped, regardless of which case it falls into.
callsOf :: MM.Memory 32 -> Word32 -> Word32 -> MDP.ParsedTermStmt ARM.ARM ids -> [CallInfo]
callsOf mem funcEntry src t = case t of
  MDP.ParsedCall regs _ -> [ classify (regs ^. MC.curIP) ]
    where
      classify ipVal = case MC.valueAsMemAddr ipVal >>= MM.asAbsoluteAddr of
        Nothing -> CallInfo funcEntry src Nothing "indirect"
        Just w  -> case resolveEntry mem (fromIntegral (MM.memWordValue w)) of
          Nothing  -> CallInfo funcEntry src (Just (fromIntegral (MM.memWordValue w))) "unmapped"
          Just off -> CallInfo funcEntry src (Just (canonicalWord off)) "direct"
  _ -> []

------------------------------------------------------------------------
-- JSON

hexStr :: Word32 -> String
hexStr w = "0x" ++ showHex w ""

firmwareMetaValue :: FirmwareMeta -> Value
firmwareMetaValue fm = object
  [ "path"       .= fmPath fm
  , "size_bytes" .= fmSizeBytes fm
  , "flash_base" .= hexStr (fmFlashBase fm)
  , "ram_base"   .= hexStr (fmRamBase fm)
  , "ram_size"   .= hexStr (fmRamSize fm)
  ]

rootValue :: RootInfo -> Value
rootValue r = object
  [ "names"          .= riNames r
  , "macaw_addr"     .= hexStr (riMacawAddr r)
  , "canonical_addr" .= fmap hexStr (riCanonicalAddr r)
  , "resolved"       .= riResolved r
  ]

functionValue :: FunctionInfo -> Value
functionValue f = object
  [ "entry"       .= hexStr (fiEntry f)
  , "is_root"     .= fiIsRoot f
  , "block_count" .= fiBlockCount f
  ]

blockValue :: BlockInfo -> Value
blockValue b = object
  [ "function_entry"  .= hexStr (biFunctionEntry b)
  , "block_start"     .= hexStr (biBlockStart b)
  , "size"            .= biSize b
  , "terminator_kind" .= biTermKind b
  ]

edgeValue :: EdgeInfo -> Value
edgeValue e = object
  [ "function_entry" .= hexStr (eiFunctionEntry e)
  , "source"         .= hexStr (eiSource e)
  , "target"         .= hexStr (eiTarget e)
  , "kind"           .= eiKind e
  ]

unresolvedValue :: UnresolvedInfo -> Value
unresolvedValue u = object
  [ "function_entry" .= hexStr (uiFunctionEntry u)
  , "block_start"    .= hexStr (uiBlockStart u)
  , "kind"           .= uiKind u
  , "detail"         .= uiDetail u
  ]

callValue :: CallInfo -> Value
callValue c = object
  [ "caller"    .= hexStr (ciCaller c)
  , "call_site" .= hexStr (ciCallSite c)
  , "callee"    .= fmap hexStr (ciCallee c)
  , "kind"      .= ciKind c
  ]

-- | The full, deterministic census document. Field order within each
-- object is fixed by this function (aeson's pinned @+ordered-keymap@
-- build preserves it); array order is fixed by the sorts already applied
-- in 'discoverCensus'.
censusToValue :: FirmwareMeta -> CensusResult -> Value
censusToValue fm cr = object
  [ "firmware"  .= firmwareMetaValue fm
  , "roots"     .= map rootValue (crRoots cr)
  , "discovery_error" .= crDiscoveryError cr
  , "functions" .= map functionValue (crFunctions cr)
  , "basic_blocks" .= map blockValue (crBlocks cr)
  , "edges"     .= map edgeValue (crEdges cr)
  , "incomplete_or_unresolved_terminators" .= map unresolvedValue (crUnresolved cr)
  , "calls"     .= map callValue (crCalls cr)
  ]

------------------------------------------------------------------------
-- CLI entry point

-- | @aptrace macaw-census FIRMWARE.bin [FLASH_BASE]@ -- read the firmware,
-- seed Macaw discovery from its vector table only (deduplicated,
-- normalized through 'macawCortexMEntry'), and print the resulting census
-- as one line of deterministic JSON on stdout.
runMacawCensus :: FilePath -> Word32 -> IO ()
runMacawCensus path flashBase = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let entries = parseVectorTable numIrq bytes
          roots = normalizeRoots entries
      census <- discoverCensus mem roots
      let fm = FirmwareMeta
                 { fmPath = path
                 , fmSizeBytes = BS.length bytes
                 , fmFlashBase = flashBase
                 , fmRamBase = ramBase
                 , fmRamSize = ramSize
                 }
      IO.hSetBuffering IO.stdout IO.LineBuffering
      BSLC.putStrLn (encode (censusToValue fm census))
