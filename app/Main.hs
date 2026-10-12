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

import           APTrace.Case.PerformingRigs ( ramBase, ramSize, numIrq, defaultFlashBase, mmioWindow )
import           APTrace.Case.PerformingRigsScenarios
  ( runSolve, runProtocol, runTrigger, runTriggerCrossCheck )
import           APTrace.DebugHarness ( runDebug )
import           APTrace.EffectsSpike ( runEffectsSpike )
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
    ("effects-spike" : path : entryS : opts) ->
      let (argOvs, mmio) = parseSpikeOpts [ o | o <- opts, o /= "--raw-only", take 4 o /= "out=" ]
          rawOnly = "--raw-only" `elem` opts
          outPrefix = last ("effects-spike" : [ drop 4 o | o <- opts, take 4 o == "out=" ])
      -- Spike-only: preserves the original hardcoded arg_r0 == 1 specialization.
      in runEffectsSpike path defaultFlashBase ramBase ramSize mmio (parseHexWord entryS) argOvs [(0, 1)] 200000 True rawOnly outPrefix
    ("function-effects" : path : entryS : opts) ->
      -- Production entry for the agent's bounded function-effects action.
      -- Geometry (flash/RAM/MMIO) is the target's own; the only caller
      -- inputs are the entry, solver specializations and the output prefix.
      let (specs, outPrefix) = parseEffectsOpts opts
      in runEffectsSpike path defaultFlashBase ramBase ramSize [mmioWindow] (parseHexWord entryS) [] specs 3000 False False outPrefix
    [path]                      -> run path defaultFlashBase
    [path, flashBaseS]          -> run path (parseHexWord flashBaseS)
    _ -> die "usage: aptrace FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace solve FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace explore FIRMWARE.bin [FLASH_BASE_HEX] ENTRY_ADDR_HEX\n       aptrace protocol FIRMWARE.bin\n       aptrace trigger FIRMWARE.bin\n       aptrace trigger-crosscheck FIRMWARE.bin\n       aptrace debug FIRMWARE.bin ENTRY_ADDR_HEX  (experimental, crucible-debug prototype)\n       aptrace macaw-census FIRMWARE.bin [FLASH_BASE_HEX]  (standalone Macaw static-discovery census, phase 1)\n       aptrace macaw-census-expand FIRMWARE.bin [FLASH_BASE_HEX]  (macaw-normalized classify_failure recovery, fed back into Macaw's own incremental discovery)\n       aptrace function-effects FIRMWARE.bin ENTRY_ADDR_HEX [rN=HEX ...] out=PREFIX  (raw + solver-derived function effects; target geometry)\n       aptrace effects-spike FIRMWARE.bin ENTRY_ADDR_HEX [rN=HEX] [mmio=BASE:SIZE] [--raw-only] [out=PREFIX]  (SPIKE ONLY)"

-- | @effects-spike@ options: @rN=HEX@ (N in 0..3) concrete argument
-- overrides, and @mmio=BASE:SIZE@ MMIO ranges. Also @--raw-only@ and
-- @out=PREFIX@ (handled by the caller). Experimental spike CLI only: MMIO
-- ranges belong to the target configuration, not to callers, and this
-- option is scaffolding to be removed.
parseSpikeOpts :: [String] -> ([(Int, Word32)], [(Word32, Word32)])
parseSpikeOpts = foldr step ([], [])
  where
    step opt (argOvs, mmio) = case break (== '=') opt of
      ('r' : n, '=' : v) | n `elem` ["0", "1", "2", "3"] -> ((read n, parseHexWord v) : argOvs, mmio)
      ("mmio", '=' : range) | (b, ':' : s) <- break (== ':') range -> (argOvs, (parseHexWord b, parseHexWord s) : mmio)
      _ -> error ("bad effects-spike option: " ++ opt)

-- | @function-effects@ options: @rN=HEX@ (N in 0..3) solver
-- specializations @arg_rN == HEX@, and @out=PREFIX@ (required). No MMIO or
-- solver options: those belong to the target and to APTrace.
parseEffectsOpts :: [String] -> ([(Int, Word32)], FilePath)
parseEffectsOpts opts = (foldr step [] opts, outPrefix)
  where
    outPrefix = case [ drop 4 o | o <- opts, take 4 o == "out=" ] of
      [p] -> p
      _ -> error "function-effects requires exactly one out=PREFIX"
    step opt specs = case break (== '=') opt of
      ('r' : n, '=' : v) | n `elem` ["0", "1", "2", "3"] -> (read n, parseHexWord v) : specs
      ("out", _) -> specs
      _ -> error ("bad function-effects option: " ++ opt)

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
