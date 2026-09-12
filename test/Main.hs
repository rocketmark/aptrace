{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Regression tests for the Cortex-M execution-address policy
-- ('APTrace.FirmwareLoader.macawCortexMEntry'). Macaw's AArch32 backend
-- derives a discovery root's Thumb-vs-A32 decode mode purely from the low
-- bit of the address handed to it, and Cortex-M has no A32 execution state
-- at all -- see that function's Haddock for the full mechanism.
module Main (main) where

import           Control.Exception ( SomeException, try )
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
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Memory as MM
import           Data.Parameterized.Some ( Some(..) )
import qualified Prettyprinter as PP

import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, macawCortexMEntry )

main :: IO ()
main = do
  results <- sequence
    [ test "1. even canonical code address becomes a Thumb Macaw seed"
        (macawCortexMEntry 0x801c == 0x801d)
    , test "2. odd Thumb function pointer normalizes to itself (idempotent)"
        (macawCortexMEntry 0x952d == 0x952d)
    , dataAddressUnmodified
    , realFirmwareRepro
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
