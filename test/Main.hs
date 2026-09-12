{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Regression tests for the Cortex-M execution-address policy
-- ('APTrace.FirmwareLoader.macawCortexMEntry'). Macaw's AArch32 backend
-- derives a discovery root's Thumb-vs-A32 decode mode purely from the low
-- bit of the address handed to it, and Cortex-M has no A32 execution state
-- at all -- see that function's Haddock for the full mechanism.
module Main (main) where

import           Control.Exception ( SomeException, try )
import           Data.Aeson ( encode )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy.Char8 as BSLC
import           Data.List ( isInfixOf, sortOn )
import qualified Data.Map as Map
import qualified Data.Set as Set
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( showHex )
import           System.Exit ( exitFailure )
import           System.IO ( hPutStrLn, stderr )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.Arch as ARMArch
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Refinement as Refine
import qualified Data.Macaw.Types as MT
import qualified Data.Parameterized.Nonce as PN
import           Data.Parameterized.Some ( Some(..) )
import qualified Prettyprinter as PP

import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, macawCortexMEntry, armCortexMInfo )
import           APTrace.MacawCensus
  ( CensusResult(..), CallInfo(..), EdgeInfo(..), FirmwareMeta(..)
  , FunctionInfo(..), NormalizedInfo(..), RootBuildResult(..), UnresolvedInfo(..)
  , buildDiscoveryState, buildRootInfo, canonicalWord, censusToValue, discoverCensus
  , normalizeRoots, summarizeDiscoveryState )
import           APTrace.MacawExpand
  ( ExpansionResult(..), expandWithNormalization, resolutionValue )
import qualified APTrace.MacawNormalize as Normalize
import           APTrace.MacawRefinement ( refineFunctionAt )
import           APTrace.VectorTable ( VectorEntry(..), parseVectorTable )

main :: IO ()
main = do
  results <- sequence
    [ test "1. even canonical code address becomes a Thumb Macaw seed"
        (macawCortexMEntry 0x801c == 0x801d)
    , test "2. odd Thumb function pointer normalizes to itself (idempotent)"
        (macawCortexMEntry 0x952d == 0x952d)
    , dataAddressUnmodified
    , realFirmwareRepro
    , vectorRootsDedupNormalized
    , censusAddressesAreCanonical
    , censusOutputDeterministic
    , censusPreservesUnresolvedTerminator
    , directCallCalleeIsThumb
    , postCallContinuationIsThumb
    , noA32DecodeErrorsInFullCensus
    , knownDirectCallsAreEmitted
    , callReturnEdgeStaysSeparateFromCallRelation
    , unresolvedCallIsPreserved
    , callOutputIsDeterministic
    , refinementInitializesEmptyStructRegister
    , nestedSameConditionMuxSimplifies
    , nestedDifferentConditionMuxDoesNotSimplify
    , realCase0x44ecRecoversTwoTargets
    , recoveredEvidenceIsMarkedMacawNormalized
    , memoryDerivedFailureRemainsUnresolved
    , expansionFeedsExistingFunctionNotNewFunction
    , fullFirmwareFixpointExpansion
    , summarizeDiscoveryStateMatchesDiscoverCensus
    ]
  if and results
    then putStrLn "All tests passed."
    else exitFailure

test :: String -> Bool -> IO Bool
test name ok = do
  putStrLn ((if ok then "PASS: " else "FAIL: ") ++ name)
  pure ok

-- | 3. A plain data/RAM address, resolved the way every non-code address
-- actually is elsewhere in this codebase (via 'resolveEntry' alone, never
-- 'macawCortexMEntry') must come back byte-for-byte unchanged -- confirming
-- the Thumb-bit policy is applied only where APTrace intentionally treats
-- an address as code, not globally.
dataAddressUnmodified :: IO Bool
dataAddressUnmodified = do
  let ramBase = 0x20000000 :: Word32
  case buildMemory (BS.replicate 4 0) 0x8000 ramBase 0x1000 of
    Left err -> test "3. non-code/data address is left unmodified" False
                  <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
    Right mem -> case resolveEntry mem ramBase of
      Nothing  -> test "3. non-code/data address is left unmodified" False
      Just off -> test "3. non-code/data address is left unmodified"
                    (segOffAddrWord off == ramBase)

segOffAddrWord :: MM.MemSegmentOff 32 -> Word32
segOffAddrWord so =
  case MM.asAbsoluteAddr (MM.segoffAddr so) of
    Just w  -> fromIntegral (MM.memWordValue w)
    Nothing -> error "segOffAddrWord: expected an absolute address"

-- | 4. The real, previously-documented repro
-- (@docs/tooling/tool-selection.md@'s flash @0x801c@ case): seeding Macaw
-- discovery directly at the raw, even address decodes it as A32
-- (@BL_i_A1@, @PSTATE_T => 0@); routing the same address through
-- 'macawCortexMEntry' first (as every normal APTrace discovery seed now
-- does) decodes the identical bytes as Thumb (@PUSH_T1@/@LDR_l_T1@/...).
-- Skips, rather than fails, if the proprietary firmware isn't present
-- locally -- matching this project's existing convention for this fixture
-- (see @tools/doctor.sh@).
realFirmwareRepro :: IO Bool
realFirmwareRepro = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 4. real-firmware 0x801c repro (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "4. real-firmware 0x801c repro" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        evenHasA1 <- decodeContainsA1 mem rawAddr
        oddHasA1  <- decodeContainsA1 mem (macawCortexMEntry rawAddr)
        r1 <- test "4a. raw even 0x801c reproduces the known A32 misdecode (unnormalized)"
                evenHasA1
        r2 <- test "4b. macawCortexMEntry-normalized 0x801c decodes as Thumb"
                (not oddHasA1)
        pure (r1 && r2)
  where
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32
    rawAddr      = 0x801c :: Word32

-- | Seed Macaw discovery at the given raw address and report whether the
-- discovered function's own pretty-printed IR mentions an A32-only
-- instruction form (dismantle's "_A1"/"_A2"/... suffix, as opposed to
-- Thumb's "_T1"/"_T2"/...) -- the same textual signature
-- @docs/tooling/tool-selection.md@ used to originally identify this bug
-- (@BL_i_A1@, @BX_A1@).
decodeContainsA1 :: MM.Memory 32 -> Word32 -> IO Bool
decodeContainsA1 mem addr =
  case resolveEntry mem addr of
    Nothing -> error ("decodeContainsA1: could not resolve 0x" ++ showHex addr "")
    Just entry ->
      let discState = MD.cfgFromAddrs ARM.arm_linux_info mem
                        (Map.singleton entry (BSC.pack "repro")) [entry] []
          funs = discState ^. MD.funInfo
      in case Map.lookup entry funs of
           Nothing -> error ("decodeContainsA1: 0x" ++ showHex addr "" ++ " was not discovered")
           Just (Some fn) -> pure ("_A1" `isInfixOf` show (PP.pretty fn))

-- | 5. Two vector-table entries whose raw values are byte-different but
-- represent the same Cortex-M target (one already Thumb-tagged, one not)
-- must collapse into a single root group, and a genuinely different target
-- must not -- exercising 'APTrace.MacawCensus.normalizeRoots' directly, no
-- firmware needed.
vectorRootsDedupNormalized :: IO Bool
vectorRootsDedupNormalized =
  let entries =
        [ VectorEntry 1 "Reset_Handler"   0x8001 -- already Thumb-tagged
        , VectorEntry 3 "Default_Handler" 0x9000 -- a distinct target
        , VectorEntry 4 "Spurious_A"      0x8000 -- same target as #1, even encoding
        , VectorEntry 5 "Spurious_B"      0x8001 -- same target as #1, exact duplicate
        ]
      grouped = normalizeRoots entries
      expected =
        [ (0x8001, ["Reset_Handler", "Spurious_A", "Spurious_B"])
        , (0x9001, ["Default_Handler"])
        ]
  in test "5. vector roots are deduplicated and normalized through macawCortexMEntry"
       (grouped == expected)

-- | A tiny, hand-assembled Thumb function -- @nop; bx lr@ -- used by tests
-- 6 and 7 so they don't need the proprietary AutoPilot firmware.
tinyThumbProgram :: BS.ByteString
tinyThumbProgram = BS.pack [0xC0, 0x46, 0x70, 0x47]

-- | 6. A census seeded at an even canonical code address must report that
-- function's identity as the canonical (even) address, never the odd
-- Thumb-tagged Macaw-internal one.
censusAddressesAreCanonical :: IO Bool
censusAddressesAreCanonical = do
  let entryRaw = 0x8000 :: Word32
  case buildMemory tinyThumbProgram entryRaw 0x20000000 0x1000 of
    Left err -> test "6. census output addresses are canonical (no Thumb-tag identities)" False
                  <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
    Right mem -> do
      census <- discoverCensus mem [(macawCortexMEntry entryRaw, ["synthetic"])]
      test "6. census output addresses are canonical (no Thumb-tag identities)"
        (case crFunctions census of
           [fi] -> fiEntry fi == entryRaw
           _    -> False)

-- | 7. Running the same census twice over the same input must produce
-- byte-identical JSON -- both list ordering (sorted by address, per
-- 'discoverCensus') and content must be deterministic.
censusOutputDeterministic :: IO Bool
censusOutputDeterministic = do
  let entryRaw = 0x8000 :: Word32
  case buildMemory tinyThumbProgram entryRaw 0x20000000 0x1000 of
    Left err -> test "7. census output ordering/content is deterministic across runs" False
                  <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
    Right mem -> do
      let fm = FirmwareMeta "synthetic" (BS.length tinyThumbProgram) entryRaw 0x20000000 0x1000
          roots = [(macawCortexMEntry entryRaw, ["synthetic"])]
      c1 <- discoverCensus mem roots
      c2 <- discoverCensus mem roots
      test "7. census output ordering/content is deterministic across runs"
        (encode (censusToValue fm c1) == encode (censusToValue fm c2))

-- | 8. A genuine, already-documented Macaw classify failure (every branch
-- in @phase_ramp_state_machine__CUSTOM@ / flash @0x8e18@ is a narrow
-- @CBZ_T1@/@CBNZ_T1@ this Macaw version's branch classifier cannot
-- recognize -- see @app/Main.hs@'s @runTrigger@ docstring, "Confirmed
-- exhaustively for this function (4/4 classify failures are CBZ_T1)") must
-- show up in 'crUnresolved' rather than being silently dropped. Skips if
-- the proprietary firmware isn't present locally.
censusPreservesUnresolvedTerminator :: IO Bool
censusPreservesUnresolvedTerminator = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 8. unresolved-terminator preservation (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "8. unresolved terminators are preserved, not dropped" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry 0x8e18, ["phase_ramp_state_machine"])]
        test "8. unresolved terminators are preserved, not dropped"
          (not (null (crUnresolved census)))
  where
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | Look up the precondition of one specific block, by canonical address,
-- within one specific function, by canonical entry -- shared by tests 9/10.
precondAt :: MD.DiscoveryState ARM.ARM -> Word32 -> Word32 -> [Either String ARMArch.ARMBlockPrecond]
precondAt discState fnEntry blkAddr =
  [ MDP.pblockPrecond b
  | Some fn <- Map.elems (discState ^. MD.funInfo)
  , canonicalWord (MD.discoveredFunAddr fn) == fnEntry
  , b <- Map.elems (fn ^. MD.parsedBlocks)
  , canonicalWord (MDP.pblockAddr b) == blkAddr
  ]

-- | 9. The real, previously-misclassified direct-call target confirmed by
-- the prior investigation: @0xcc24@ (a normal, already-Thumb root) calls
-- @0xcd90@ via a plain Thumb @BL@ -- an ordinary, /even/ instruction
-- address, not a Thumb-bit-tagged pointer. Under stock
-- 'ARM.arm_linux_info' this decodes as A32 (@PSTATE_T=False@); under
-- 'armCortexMInfo' it must resolve to @PSTATE_T=True@. Skips if the
-- firmware isn't present locally.
directCallCalleeIsThumb :: IO Bool
directCallCalleeIsThumb = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 9. direct-call callee 0xcd90 resolves PSTATE_T=True (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "9. direct-call callee 0xcd90 resolves PSTATE_T=True" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> case resolveEntry mem (macawCortexMEntry callerAddr) of
        Nothing -> test "9. direct-call callee 0xcd90 resolves PSTATE_T=True" False
        Just entry ->
          let discState = MD.cfgFromAddrs armCortexMInfo mem
                            (Map.singleton entry (BSC.pack "caller")) [entry] []
          in test "9. direct-call callee 0xcd90 resolves PSTATE_T=True"
               (precondAt discState calleeAddr calleeAddr
                  == [Right (ARMArch.ARMBlockPrecond True)])
  where
    callerAddr   = 0xcc24 :: Word32
    calleeAddr   = 0xcd90 :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 10. The real, previously-@TopV@ post-call continuation confirmed by the
-- prior investigation: stub function @0xcbb0@ (@IRQ12_Handler@) calls a
-- shared subroutine at @0xcb8e@ and continues at @0xcb94@; under stock
-- 'ARM.arm_linux_info' the post-call abstract-state transfer can't fold
-- @PSTATE_T@ to a precise value there (@Left "TopV where PSTATE_T
-- expected"@); under 'armCortexMInfo' it must resolve to @PSTATE_T=True@
-- instead of failing. Skips if the firmware isn't present locally.
postCallContinuationIsThumb :: IO Bool
postCallContinuationIsThumb = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 10. post-call continuation 0xcb94 resolves PSTATE_T=True (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "10. post-call continuation 0xcb94 resolves PSTATE_T=True" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> case resolveEntry mem (macawCortexMEntry stubEntry) of
        Nothing -> test "10. post-call continuation 0xcb94 resolves PSTATE_T=True" False
        Just entry ->
          let discState = MD.cfgFromAddrs armCortexMInfo mem
                            (Map.singleton entry (BSC.pack "stub")) [entry] []
          in test "10. post-call continuation 0xcb94 resolves PSTATE_T=True"
               (precondAt discState stubEntry continuationAddr
                  == [Right (ARMArch.ARMBlockPrecond True)])
  where
    stubEntry        = 0xcbb0 :: Word32
    continuationAddr = 0xcb94 :: Word32
    firmwarePath     = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase        = 0x4000 :: Word32
    ramBase          = 0x20000000 :: Word32
    ramSize          = 0x30000 :: Word32

-- | 11. Across the /normal/, full vector-table-rooted discovery path (the
-- same one @aptrace macaw-census@ runs), no unresolved terminator's detail
-- text should ever mention an A32-only decode -- confirming 'armCortexMInfo'
-- is actually wired into the real discovery path, not just reachable in
-- isolation. (This does not assert the residual unresolved set is empty --
-- a real, pre-existing, differently-caused classifier limitation
-- ("IP is not a mux", narrow @CBZ_T1@/@CBNZ_T1@ branches) remains and is
-- out of this fix's scope.) Skips if the firmware isn't present locally.
noA32DecodeErrorsInFullCensus :: IO Bool
noA32DecodeErrorsInFullCensus = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 11. no A32 decode errors in the full vector-table census (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "11. no A32 decode errors in the full vector-table census" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        let roots = normalizeRoots (parseVectorTable 40 bytes)
        census <- discoverCensus mem roots
        let allDetail = concatMap uiDetail (crUnresolved census)
        test "11. no A32 decode errors in the full vector-table census"
          (not (any ("A32" `isInfixOf`) allDetail))
  where
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 12. The two calls verified directly against Macaw's own call-target
-- resolution -- NOT the stale call-site address from the earlier,
-- pre-'armCortexMInfo' investigation (that investigation reported
-- @0xcc52 -> 0xcdd8@; fixing the Cortex-M architecture policy changed
-- Macaw's own block splitting in @0xcc24@, and the real call site for
-- @0xcdd8@ is now @0xcc42@ -- re-verified directly from 'crCalls' before
-- writing this, the same "verify, don't assume" lesson as the earlier
-- @0xcde8@ vs @0xcdd8@ correction). @0xcc24@ calls @0xcd90@ from call site
-- @0xcc5c@ and @0xcdd8@ from call site @0xcc42@ -- both direct, both
-- canonical. Skips if the firmware isn't present locally.
knownDirectCallsAreEmitted :: IO Bool
knownDirectCallsAreEmitted = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 12. known direct calls are emitted (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "12. known direct calls are emitted" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry callerAddr, ["caller"])]
        let calls = crCalls census
        test "12. known direct calls are emitted with canonical caller/callee addresses"
          (CallInfo callerAddr 0xcc5c (Just 0xcd90) Nothing "direct" `elem` calls
             && CallInfo callerAddr 0xcc42 (Just 0xcdd8) Nothing "direct" `elem` calls)
  where
    callerAddr   = 0xcc24 :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 13. The @call_return@ CFG edge (source = call site, target = return
-- continuation) must remain a distinct fact from the new @caller ->
-- callee@ relation for the *same* call site: for @0xcc5c@'s call to
-- @0xcd90@, the edge target is the return address @0xcc60@ -- never the
-- callee -- while 'crCalls' separately records the callee for that same
-- call site. Skips if the firmware isn't present locally.
callReturnEdgeStaysSeparateFromCallRelation :: IO Bool
callReturnEdgeStaysSeparateFromCallRelation = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 13. call_return edge stays separate from the call relation (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "13. call_return edge stays separate from the call relation" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry callerAddr, ["caller"])]
        let callReturnTargets =
              [ eiTarget e
              | e <- crEdges census
              , eiFunctionEntry e == callerAddr, eiSource e == callSite, eiKind e == "call_return"
              ]
            callCallees =
              [ ciCallee c
              | c <- crCalls census
              , ciCaller c == callerAddr, ciCallSite c == callSite
              ]
        test "13. call_return edge stays separate from the call relation"
          (callReturnTargets == [0xcc60] && callCallees == [Just 0xcd90])
  where
    callerAddr   = 0xcc24 :: Word32
    callSite     = 0xcc5c :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 14. A real, register-indirect call whose target Macaw's own
-- call-target value doesn't reduce to a concrete address (@0xa03c@,
-- called into as its own root, whose entry block itself ends in the
-- indirect call) must still appear in 'crCalls' -- with @callee=Nothing@,
-- @kind="indirect"@ -- rather than being dropped. Skips if the firmware
-- isn't present locally.
unresolvedCallIsPreserved :: IO Bool
unresolvedCallIsPreserved = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 14. unresolved call is preserved (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "14. unresolved call is preserved, not dropped" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry entryAddr, ["indirect_caller"])]
        test "14. unresolved call is preserved, not dropped"
          (CallInfo entryAddr entryAddr Nothing Nothing "indirect" `elem` crCalls census)
  where
    entryAddr    = 0xa03c :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 15. Running the same census twice must produce a byte-identical
-- @calls@ list -- both content and the @caller, call_site, callee@ sort
-- order. Skips if the firmware isn't present locally.
callOutputIsDeterministic :: IO Bool
callOutputIsDeterministic = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 15. call output ordering is deterministic (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "15. call output ordering is deterministic" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        let roots = normalizeRoots (parseVectorTable 40 bytes)
        c1 <- discoverCensus mem roots
        c2 <- discoverCensus mem roots
        let isSorted cs = cs == sortOn (\c -> (ciCaller c, ciCallSite c, ciCallee c)) cs
        test "15. call output ordering is deterministic"
          (crCalls c1 == crCalls c2 && isSorted (crCalls c1))
  where
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 16. AArch32/Cortex-M compatibility-patch regression: vendored
-- @macaw-refinement@'s own 'Data.Macaw.Refinement.SymbolicExecution.freshSymVar'
-- previously had no case for AArch32's ASL-derived unit-typed pseudo-register
-- (an empty struct, visible in a block's abstract state as @() => ()_0@) and
-- failed /every/ AArch32 refinement attempt with @user error (unsupported
-- variable type: StructRepr [])@ before any SMT solving was even attempted
-- -- see that module's compatibility-patch comment. This proves refinement
-- now gets past register-state construction for a real @classify_failure@
-- block (flash @0x44ec@, a Thumb @CBZ_T1@) without throwing that error, even
-- though this particular block still does not fully refine: a separate,
-- independent gap (missing ASL semantics for a VFP instruction elsewhere in
-- the block, @MissingSemanticsForT32Instruction VLDR_l_T1_S@) is expected
-- and must show up recorded in the result, not silently hidden. Skips if
-- the firmware isn't present locally.
refinementInitializesEmptyStructRegister :: IO Bool
refinementInitializesEmptyStructRegister = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 16. AArch32 refinement initializes the empty-struct register without throwing (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "16. AArch32 refinement initializes the empty-struct register without throwing" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> case resolveEntry mem (macawCortexMEntry targetEntry) of
        Nothing -> test "16. AArch32 refinement initializes the empty-struct register without throwing" False
        Just off -> do
          let discState = MD.cfgFromAddrs armCortexMInfo mem
                            (Map.singleton off (BSC.pack "target")) [off] []
          outcome <- try (refineFunctionAt bytes mem discState targetEntry)
                       :: IO (Either SomeException (MD.DiscoveryState ARM.ARM, Refine.RefinementInfo ARM.ARM))
          case outcome of
            Left ex ->
              test "16. AArch32 refinement initializes the empty-struct register without throwing" False
                <* hPutStrLn stderr ("  (refinement threw: " ++ show ex ++ ")")
            Right (_, info) ->
              let msgs = map snd (Refine.refinementErrors info)
                  mentionsStructGap = any (\m -> "unsupported variable type" `isInfixOf` m
                                                    || "StructRepr" `isInfixOf` m) msgs
              in test "16. AArch32 refinement initializes the empty-struct register without throwing"
                   (not mentionsStructGap)
  where
    targetEntry  = 0x44ec :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

------------------------------------------------------------------------
-- APTrace.MacawNormalize: the one algebraic identity
-- mux(c, mux(c,A,B), C) -> mux(c,A,C), applied only to classify_failure
-- curIP expressions. Tests 17/18 build small, synthetic, hand-assembled
-- Macaw IR values directly (no firmware, no discovery) to exercise
-- 'Normalize.normalizeIP' in isolation; tests 19/20/21 use the real,
-- already-documented firmware cases.

-- | A fresh, otherwise-meaningless Bool-typed assignment -- stands in for
-- "some condition Macaw computed"; 'Normalize.normalizeIP' never inspects
-- a condition's own right-hand side, only its identity, so its actual rhs
-- (here, 'MC.SetUndefined') is irrelevant.
mkCond :: PN.NonceGenerator IO ids
       -> IO (MC.Value ARM.ARM ids MT.BoolType)
mkCond gen = do
  n <- PN.freshNonce gen
  pure (MC.AssignedValue (MC.Assignment (MC.AssignId n) (MC.SetUndefined MT.BoolTypeRepr)))

-- | A concrete literal code address, exactly as it appears in Macaw's own
-- lifted IR for a direct branch target ('MC.RelocatableValue').
mkLitAddr :: Word32 -> MC.Value ARM.ARM ids (MT.BVType 32)
mkLitAddr w = MC.RelocatableValue MM.Addr32 (MM.absoluteAddr (MM.memWord (fromIntegral w)))

-- | A fresh Mux assignment -- 'MC.valueAsApp' (which 'Normalize.normalizeIP'
-- uses internally) recovers exactly this shape back out.
mkMux :: PN.NonceGenerator IO ids
      -> MC.Value ARM.ARM ids MT.BoolType
      -> MC.Value ARM.ARM ids (MT.BVType 32)
      -> MC.Value ARM.ARM ids (MT.BVType 32)
      -> IO (MC.Value ARM.ARM ids (MT.BVType 32))
mkMux gen c t f = do
  n <- PN.freshNonce gen
  pure (MC.AssignedValue
          (MC.Assignment (MC.AssignId n) (MC.EvalApp (MC.Mux (MT.BVTypeRepr MT.n32) c t f))))

-- | A tiny synthetic memory covering exactly the literal addresses tests
-- 17/18 use as branch targets -- large enough to hold three well-separated
-- addresses, nothing more.
synthMem :: Either String (MM.Memory 32)
synthMem = buildMemory (BS.replicate 0x100 0) 0x1000 0x20000000 0x100

-- | 17. The one supported identity, in isolation: @mux(c, mux(c,A,B), C)@
-- with the *same* condition value @c@ in both mux positions (by identity --
-- literally the same 'MC.Value', not merely two conditions that happen to
-- read the same) must normalize to exactly @[A, C]@, dropping the
-- unreachable @B@ branch entirely.
nestedSameConditionMuxSimplifies :: IO Bool
nestedSameConditionMuxSimplifies =
  case synthMem of
    Left err -> test "17. mux(c, mux(c,A,B), C) simplifies to [A,C]" False
                  <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
    Right mem -> PN.withIONonceGenerator $ \gen -> do
      c <- mkCond gen
      let a = mkLitAddr 0x1000
          b = mkLitAddr 0x1010
          bigC = mkLitAddr 0x1020
      inner <- mkMux gen c a b
      outer <- mkMux gen c inner bigC
      test "17. mux(c, mux(c,A,B), C) simplifies to [A,C]"
        (Normalize.normalizeIP mem outer == Just [0x1000, 0x1020])

-- | 18. The same shape, but the inner mux's condition is a *different*
-- value from the outer one -- the identity does not apply (it is only
-- valid when both conditions are identical), so this must be left
-- unresolved (@Nothing@), never guessed at.
nestedDifferentConditionMuxDoesNotSimplify :: IO Bool
nestedDifferentConditionMuxDoesNotSimplify =
  case synthMem of
    Left err -> test "18. different conditions do not simplify" False
                  <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
    Right mem -> PN.withIONonceGenerator $ \gen -> do
      c1 <- mkCond gen
      c2 <- mkCond gen
      let a = mkLitAddr 0x1000
          b = mkLitAddr 0x1010
          bigC = mkLitAddr 0x1020
      inner <- mkMux gen c2 a b
      outer <- mkMux gen c1 inner bigC
      test "18. different conditions do not simplify"
        (Normalize.normalizeIP mem outer == Nothing)

-- | 19. The real, already-documented @0x44ec@ CBZ_T1 case (a whole,
-- single-block function whose only terminator is exactly this shape --
-- see @APTrace.MacawNormalize@'s Haddock): seeding discovery at @0x44ec@
-- alone must produce a 'NormalizedInfo' recovering its real two targets,
-- @0x457e@ and @0x453e@. Skips if the firmware isn't present locally.
realCase0x44ecRecoversTwoTargets :: IO Bool
realCase0x44ecRecoversTwoTargets = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 19. real case 0x44ec recovers its two targets (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "19. real case 0x44ec recovers its two targets" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry targetEntry, ["target"])]
        test "19. real case 0x44ec recovers its two targets"
          (case crNormalized census of
             [n] -> niFunctionEntry n == targetEntry && niBlockStart n == targetEntry
                      && niTargets n == [0x457e, 0x453e]
             _   -> False)
  where
    targetEntry  = 0x44ec :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 20. Every 'NormalizedInfo' the census emits must carry the
-- @macaw-normalized@ provenance tag -- never left blank, never relabeled as
-- ordinary @macaw-base@ evidence. Reuses the same @0x44ec@ fixture as
-- test 19. Skips if the firmware isn't present locally.
recoveredEvidenceIsMarkedMacawNormalized :: IO Bool
recoveredEvidenceIsMarkedMacawNormalized = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 20. recovered evidence is marked macaw-normalized (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "20. recovered evidence is marked macaw-normalized" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem [(macawCortexMEntry targetEntry, ["target"])]
        test "20. recovered evidence is marked macaw-normalized"
          (not (null (crNormalized census))
             && all ((== Normalize.macawNormalizedProvenance) . niProvenance) (crNormalized census))
  where
    targetEntry  = 0x44ec :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 21. A real memory-derived classify_failure -- @0x978c@ / target
-- @0x97a0@ (@mux(c, loop_target, stack_loaded_value)@ -- one branch is a
-- plain memory read, not a concrete address; see @APTrace.MacawNormalize@'s
-- Haddock) -- must remain unresolved: normalization must not fire, so no
-- 'NormalizedInfo' is emitted for it, and the original classify_failure
-- must still be present in 'crUnresolved'. Skips if the firmware isn't
-- present locally.
memoryDerivedFailureRemainsUnresolved :: IO Bool
memoryDerivedFailureRemainsUnresolved = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 21. memory-derived failure remains unresolved (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "21. memory-derived failure remains unresolved" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        census <- discoverCensus mem (normalizeRoots (parseVectorTable 40 bytes))
        let stillUnresolved =
              any (\u -> uiFunctionEntry u == fnEntry && uiBlockStart u == blkStart
                           && uiKind u == "classify_failure")
                  (crUnresolved census)
            notNormalized =
              not (any (\n -> niFunctionEntry n == fnEntry && niBlockStart n == blkStart)
                       (crNormalized census))
        test "21. memory-derived failure remains unresolved"
          (stillUnresolved && notNormalized)
  where
    fnEntry      = 0x97a0 :: Word32
    blkStart     = 0x978c :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

------------------------------------------------------------------------
-- APTrace.MacawExpand: reintegrating normalization via Macaw's own
-- 'MD.addDiscoveredFunctionBlockTargets', never as new 'cfgFromAddrs'
-- roots.

-- | 22. The real @0x44ec@ case, scoped to just that one function: after
-- 'expandWithNormalization', its two recovered targets (@0x457e@,
-- @0x453e@) must NOT appear as new, independent function entries -- only
-- as new blocks reachable from within @0x44ec@'s own, pre-existing
-- function. This is the central distinction this integration exists to
-- get right (a one-off @cfgFromAddrs@-with-extra-roots experiment gets it
-- wrong, inflating function count). Skips if the firmware isn't present
-- locally.
expansionFeedsExistingFunctionNotNewFunction :: IO Bool
expansionFeedsExistingFunctionNotNewFunction = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 22. expansion feeds the existing function, not a new one (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "22. expansion feeds the existing function, not a new one" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> case resolveEntry mem (macawCortexMEntry targetEntry) of
        Nothing -> test "22. expansion feeds the existing function, not a new one" False
        Just off -> do
          let baseState = buildDiscoveryState mem (Map.singleton off (BSC.pack "target")) [off]
              canonFnAddrs s = [ canonicalWord (MD.discoveredFunAddr fn) | Some fn <- Map.elems (s ^. MD.funInfo) ]
              baseBlockCount =
                sum [ Map.size (fn ^. MD.parsedBlocks) | Some fn <- Map.elems (baseState ^. MD.funInfo) ]

              result = expandWithNormalization mem baseState
              expState = erExpandedState result
              expFnAddrs = canonFnAddrs expState

              matchesTarget (Some fn) = canonicalWord (MD.discoveredFunAddr fn) == targetEntry
              targetFnBlocks state =
                case filter matchesTarget (Map.elems (state ^. MD.funInfo)) of
                  (Some fn : _) -> Just [ canonicalWord (MDP.pblockAddr b) | b <- Map.elems (fn ^. MD.parsedBlocks) ]
                  []            -> Nothing

          r1 <- test "22a. recovered targets 0x457e/0x453e are not created as new function entries"
                  (0x457e `notElem` expFnAddrs && 0x453e `notElem` expFnAddrs)
          r2 <- test "22b. recovered targets become new blocks within the existing 0x44ec function"
                  (case targetFnBlocks expState of
                     Just blks -> 0x457e `elem` blks && 0x453e `elem` blks
                                    && length blks > baseBlockCount
                     Nothing   -> False)
          r3 <- test "22c. recovered evidence is rendered with macaw-normalized provenance"
                  ("macaw-normalized" `isInfixOf`
                     BSLC.unpack (encode (resolutionValue (targetEntry, targetEntry, [0x457e, 0x453e]))))
          pure (r1 && r2 && r3)
  where
    targetEntry  = 0x44ec :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 23. The full, vector-table-seeded fixpoint on the real firmware:
-- normalization exposes new code, which itself contains further
-- same-shape @classify_failure@s, so the fixpoint must run more than one
-- round (23a); every one of the base run's 23 originally non-normalizable
-- failures must still be present, unresolved, in the final state -- never
-- force-resolved just because the block was revisited in a later round
-- (23b); and running the fixpoint again over its own already-expanded
-- output must find nothing further to do (23c), confirming this is a
-- genuine, stable fixpoint. Skips if the firmware isn't present locally.
fullFirmwareFixpointExpansion :: IO Bool
fullFirmwareFixpointExpansion = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 23. full-firmware fixpoint expansion (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "23. full-firmware fixpoint expansion" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        let rootGroups = normalizeRoots (parseVectorTable 40 bytes)
        baseCensus <- discoverCensus mem rootGroups
        let originalNormalized =
              Set.fromList [ (niFunctionEntry n, niBlockStart n) | n <- crNormalized baseCensus ]
            originalClassifyFailures =
              Set.fromList [ (uiFunctionEntry u, uiBlockStart u)
                            | u <- crUnresolved baseCensus, uiKind u == "classify_failure" ]
            originalResidual = originalClassifyFailures `Set.difference` originalNormalized

            rb = buildRootInfo mem rootGroups
            baseState = buildDiscoveryState mem (rbAddrSymMap rb) (rbEntryList rb)
            result = expandWithNormalization mem baseState

        r1 <- test "23a. the fixpoint discovers second-round-or-later normalizable failures"
                (length (erRounds result) > 1)

        let residualOf state =
              Set.fromList
                [ (canonicalWord (MD.discoveredFunAddr fn), canonicalWord (MDP.pblockAddr b))
                | Some fn <- Map.elems (state ^. MD.funInfo)
                , let already = Set.fromList (map fst (MD.discoveredClassifyFailureResolutions fn))
                , b <- Map.elems (fn ^. MD.parsedBlocks)
                , MDP.ClassifyFailure{} <- [MDP.pblockTermStmt b]
                , not (Set.member (MDP.pblockAddr b) already)
                ]
            finalResidual = residualOf (erExpandedState result)

        r2 <- test "23b. the original 23 non-normalizable failures are not force-resolved"
                (originalResidual `Set.isSubsetOf` finalResidual)

        let result2 = expandWithNormalization mem (erExpandedState result)
        r3 <- test "23c. repeating the completed expansion finds no further changes"
                (null (erRounds result2))

        -- 23d/23e: the same 'summarizeDiscoveryState' the CLI's
        -- macaw-census-expand output is built from (see
        -- APTrace.MacawExpand.runMacawCensusExpand) must describe the
        -- FINAL EXPANDED graph -- strictly more functions/blocks/calls
        -- than the base graph, never a second copy of the base one -- and
        -- every one of its normalized-terminator entries must still carry
        -- macaw-normalized provenance once round-tripped through the same
        -- 'censusToValue' JSON encoding the CLI uses.
        let expandedCensus = summarizeDiscoveryState mem (rbRootCanonSet rb) (erExpandedState result)
        r4 <- test "23d. the expanded census reflects the final expanded graph, not the base one"
                (length (crFunctions expandedCensus) > length (crFunctions baseCensus)
                   && length (crBlocks expandedCensus) > length (crBlocks baseCensus)
                   && length (crCalls expandedCensus) > length (crCalls baseCensus)
                   && not (null (crNormalized expandedCensus)))

        let fm = FirmwareMeta firmwarePath (BS.length bytes) flashBase ramBase ramSize
            encoded = BSLC.unpack (encode (censusToValue fm expandedCensus))
        r5 <- test "23e. normalized_terminators round-tripped through censusToValue keep their provenance"
                ("macaw-normalized" `isInfixOf` encoded
                   && length (crNormalized expandedCensus) >= 100)

        pure (r1 && r2 && r3 && r4 && r5)
  where
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32

-- | 24. A fast, single-function-scoped check that 'summarizeDiscoveryState'
-- (the new, reusable summarization entry point 'discoverCensus' itself is
-- now built from -- see 'APTrace.MacawCensus.coreToCensusResult') produces
-- exactly the same 'CensusResult' as the existing 'discoverCensus' path,
-- for the identical discovery state -- i.e. this is a genuine refactor
-- (one summarization implementation reused two ways), not a second,
-- independent one. 'crRoots' is set explicitly since
-- 'summarizeDiscoveryState' always returns it empty (a discovery state
-- carries no root-group list of its own). Skips if the firmware isn't
-- present locally.
summarizeDiscoveryStateMatchesDiscoverCensus :: IO Bool
summarizeDiscoveryStateMatchesDiscoverCensus = do
  readResult <- try (BS.readFile firmwarePath) :: IO (Either SomeException BS.ByteString)
  case readResult of
    Left _ -> do
      hPutStrLn stderr
        ("SKIP: 24. summarizeDiscoveryState matches discoverCensus (firmware not present at "
          ++ firmwarePath ++ ")")
      pure True
    Right bytes -> case buildMemory bytes flashBase ramBase ramSize of
      Left err -> test "24. summarizeDiscoveryState matches discoverCensus" False
                    <* hPutStrLn stderr ("  (setup failed: " ++ err ++ ")")
      Right mem -> do
        let rootGroups = [(macawCortexMEntry targetEntry, ["target"])]
            rb = buildRootInfo mem rootGroups
            discState = buildDiscoveryState mem (rbAddrSymMap rb) (rbEntryList rb)
            viaSummarize = (summarizeDiscoveryState mem (rbRootCanonSet rb) discState)
                             { crRoots = rbRootInfos rb }
        viaDiscoverCensus <- discoverCensus mem rootGroups
        test "24. summarizeDiscoveryState matches discoverCensus for the same discovery state"
          (viaSummarize == viaDiscoverCensus)
  where
    targetEntry  = 0x44ec :: Word32
    firmwarePath = "Autopilot_firm/firmware_autopilot868.bin"
    flashBase    = 0x4000 :: Word32
    ramBase      = 0x20000000 :: Word32
    ramSize      = 0x30000 :: Word32
