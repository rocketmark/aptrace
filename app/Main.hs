{-# LANGUAGE DataKinds #-}
module Main (main) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Map as Map
import           Data.Parameterized.Some ( Some(..) )
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( readHex, showHex )
import qualified Prettyprinter as PP
import           System.Environment ( getArgs )
import           System.Exit ( die )
import qualified System.IO as IO

import qualified Data.Macaw.Discovery as MD

import           APTrace.Case.PerformingRigs ( ramBase, ramSize, numIrq, defaultFlashBase )
import           APTrace.Case.PerformingRigsScenarios
  ( runSolve, runProtocol, runTrigger, runTriggerCrossCheck )
import           APTrace.DebugHarness ( runDebug )
import           APTrace.FirmwareLoader
  ( buildMemory, resolveEntry, resolveEntries, macawCortexMEntry, armCortexMInfo )
import           APTrace.MacawCensus ( runMacawCensus )
import           APTrace.MacawExpand ( runMacawCensusExpand )
import           APTrace.VectorTable ( parseVectorTable )

main :: IO ()
main = do
  IO.hSetBuffering IO.stdout IO.LineBuffering
  args <- getArgs
  case args of
    ["solve", path]                    -> runSolve path defaultFlashBase
    ["solve", path, flashBaseS]        -> runSolve path (parseHexWord flashBaseS)
    ["explore", path, entryS]          -> runExplore path defaultFlashBase (parseHexWord entryS)
    ["explore", path, flashBaseS, entryS] -> runExplore path (parseHexWord flashBaseS) (parseHexWord entryS)
    ["protocol", path]                 -> runProtocol path defaultFlashBase
    ["trigger", path]                  -> runTrigger path defaultFlashBase
    ["trigger-crosscheck", path]       -> runTriggerCrossCheck path defaultFlashBase
    ["debug", path, entryS]            -> runDebug path defaultFlashBase ramBase ramSize (parseHexWord entryS)
    ["macaw-census", path]              -> runMacawCensus path defaultFlashBase ramBase ramSize numIrq
    ["macaw-census", path, flashBaseS]  -> runMacawCensus path (parseHexWord flashBaseS) ramBase ramSize numIrq
    ["macaw-census-expand", path]             -> runMacawCensusExpand path defaultFlashBase ramBase ramSize numIrq
    ["macaw-census-expand", path, flashBaseS] -> runMacawCensusExpand path (parseHexWord flashBaseS) ramBase ramSize numIrq
    [path]                      -> run path defaultFlashBase
    [path, flashBaseS]          -> run path (parseHexWord flashBaseS)
    _ -> die "usage: aptrace FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace solve FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace explore FIRMWARE.bin [FLASH_BASE_HEX] ENTRY_ADDR_HEX\n       aptrace protocol FIRMWARE.bin\n       aptrace trigger FIRMWARE.bin\n       aptrace trigger-crosscheck FIRMWARE.bin\n       aptrace debug FIRMWARE.bin ENTRY_ADDR_HEX  (experimental, crucible-debug prototype)\n       aptrace macaw-census FIRMWARE.bin [FLASH_BASE_HEX]  (standalone Macaw static-discovery census, phase 1)\n       aptrace macaw-census-expand FIRMWARE.bin [FLASH_BASE_HEX]  (macaw-normalized classify_failure recovery, fed back into Macaw's own incremental discovery)"

parseHexWord :: String -> Word32
parseHexWord s =
  let s' = case s of
             ('0':'x':rest) -> rest
             ('0':'X':rest) -> rest
             _              -> s
  in case readHex s' of
       [(w, "")] -> w
       _         -> error ("not a hex address: " ++ s)

-- | @aptrace FIRMWARE.bin [FLASH_BASE]@ -- Step 5/6 demo: parse the vector
-- table, run Macaw code discovery from every handler, and dump the
-- recovered functions.
run :: FilePath -> Word32 -> IO ()
run path flashBase = do
  bytes <- BS.readFile path
  putStrLn (path ++ ": " ++ show (BS.length bytes) ++ " bytes, flash base 0x"
            ++ showHex flashBase "")
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let entries = parseVectorTable numIrq bytes
      putStrLn (show (length entries) ++ " non-empty vector table entries:")
      mapM_ (putStrLn . ("  " ++) . show) entries

      let (addrSymMap, entryAddrs) = resolveEntries mem entries
      putStrLn ("\nRunning Macaw code discovery from " ++ show (length entryAddrs)
                ++ " entry points...")
      let discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap entryAddrs []
          funs = discState ^. MD.funInfo

      putStrLn ("\nDiscovered " ++ show (Map.size funs) ++ " function(s):\n")
      mapM_ (\(Some info) -> print (PP.pretty info)) (Map.elems funs)

-- | @aptrace explore FIRMWARE.bin [FLASH_BASE] ENTRY_ADDR_HEX@ -- seed a single,
-- arbitrary entry point (e.g. a function known from static analysis but not
-- reachable from the vector table in Macaw's own transitive discovery) and
-- dump every function reached from it. Investigation tool, not a stable CLI
-- surface yet.
runExplore :: FilePath -> Word32 -> Word32 -> IO ()
runExplore path flashBase entryRaw = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      entry <- maybe (die "could not resolve entry address") pure
                 (resolveEntry mem (macawCortexMEntry entryRaw))
      let addrSymMap = Map.singleton entry (BSC.pack "target")
          discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap [entry] []
          funs = discState ^. MD.funInfo
      putStrLn ("Discovered " ++ show (Map.size funs) ++ " function(s) from 0x"
                ++ showHex entryRaw "" ++ ":\n")
      mapM_ (\(Some info) -> print (PP.pretty info)) (Map.elems funs)
