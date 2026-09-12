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
import           Data.List ( isInfixOf )
import qualified Data.Map as Map
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( showHex )
import           System.Exit ( exitFailure )
import           System.IO ( hPutStrLn, stderr )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.Arch as ARMArch
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM
import           Data.Parameterized.Some ( Some(..) )
import qualified Prettyprinter as PP

import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, macawCortexMEntry, armCortexMInfo )
import           APTrace.MacawCensus
  ( CensusResult(..), FirmwareMeta(..), FunctionInfo(..), UnresolvedInfo(..)
  , canonicalWord, censusToValue, discoverCensus, normalizeRoots )
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
