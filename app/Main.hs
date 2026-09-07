{-# LANGUAGE DataKinds #-}
module Main (main) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.Maybe ( mapMaybe )
import qualified Data.Map as Map
import           Data.Parameterized.Some ( Some(..) )
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( readHex, showHex )
import qualified Prettyprinter as PP
import           System.Environment ( getArgs )
import           System.Exit ( die )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.ARMReg as AR
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM

import           APTrace.FirmwareLoader
  ( buildMemory, buildMemoryWithMMIO, resolveEntry )
import           APTrace.SymbolicRunner
  ( BranchQuery(..), BranchResult(..), checkBranchModel )
import           APTrace.VectorTable ( VectorEntry(..), parseVectorTable )

-- Fixed for the AutoPilot/Mando firmware family (ATSAMD51, 192KB RAM);
-- not yet exposed as CLI flags -- see the plan's Step 5 "not over-designing
-- the CLI yet" guidance.
ramBase :: Word32
ramBase = 0x20000000

ramSize :: Word32
ramSize = 0x30000

numIrq :: Int
numIrq = 40

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["solve", path]                    -> runSolve path 0x4000
    ["solve", path, flashBaseS]        -> runSolve path (parseHexWord flashBaseS)
    ["explore", path, entryS]          -> runExplore path 0x4000 (parseHexWord entryS)
    ["explore", path, flashBaseS, entryS] -> runExplore path (parseHexWord flashBaseS) (parseHexWord entryS)
    ["protocol", path]                 -> runProtocol path 0x4000
    [path]                      -> run path 0x4000
    [path, flashBaseS]          -> run path (parseHexWord flashBaseS)
    _ -> die "usage: aptrace FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace solve FIRMWARE.bin [FLASH_BASE_HEX]\n       aptrace explore FIRMWARE.bin [FLASH_BASE_HEX] ENTRY_ADDR_HEX\n       aptrace protocol FIRMWARE.bin"

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
      let discState = MD.cfgFromAddrs ARM.arm_linux_info mem addrSymMap entryAddrs []
          funs = discState ^. MD.funInfo

      putStrLn ("\nDiscovered " ++ show (Map.size funs) ++ " function(s):\n")
      mapM_ (\(Some info) -> print (PP.pretty info)) (Map.elems funs)

resolveEntries :: MM.Memory 32 -> [VectorEntry] -> (MD.AddrSymMap 32, [MM.MemSegmentOff 32])
resolveEntries mem entries =
  let resolved = mapMaybe (\e -> (,) (veName e) <$> resolveEntry mem (veRawAddr e)) entries
      addrSymMap = Map.fromList [ (addr, BSC.pack name) | (name, addr) <- resolved ]
  in (addrSymMap, map snd resolved)

-- | @aptrace solve FIRMWARE.bin [FLASH_BASE]@ -- Steps 7-9 demo.
--
-- This is deliberately hardcoded to one real, already-discovered function in
-- the AutoPilot firmware family, @IRQ10_Handler@: it clears a bit in an MMIO
-- register at 0x40002000, then polls a status word at 0x40002008 in a loop
-- (@while (status == 0) {}@-shaped), branching to 0x953c once the status
-- becomes non-zero. See research/notes/symbolic-execution-results.md for how
-- these addresses were found (a real firmware literal-pool load, confirmed
-- by hand-decoding the firmware bytes).
--
-- We seed R3 (the register holding the peripheral base pointer, invariant
-- across loop iterations) concretely, symbolically execute *only* the loop
-- body block in isolation (see 'APTrace.SymbolicRunner' for why), and ask
-- the solver for a model of R2 (the loaded status word) that reaches each of
-- the block's two branch targets.
runSolve :: FilePath -> Word32 -> IO ()
runSolve path flashBase = do
  bytes <- BS.readFile path
  let mmioBase = 0x40002000 :: Word32
      mmioSize = 0x400       :: Word32
      funcEntryRaw = 0x952d  :: Word32  -- IRQ10_Handler, Thumb bit set
      loopBlockAddr = 0x9536 :: Word32  -- loop body: load status, compare, branch
      exitAddr = 0x953c      :: Word32  -- falls out of the loop
      loopAddr = 0x9536      :: Word32  -- branches back to the top of the loop
  case buildMemoryWithMMIO bytes flashBase ramBase ramSize mmioBase mmioSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let entries = parseVectorTable numIrq bytes
          (addrSymMap, entryAddrs) = resolveEntries mem entries
          discState = MD.cfgFromAddrs ARM.arm_linux_info mem addrSymMap entryAddrs []
          funs = discState ^. MD.funInfo

      funcEntry <- maybe (die "could not resolve function entry address") pure
                     (resolveEntry mem funcEntryRaw)
      Some funInfo <- maybe (die "target function was not discovered") pure
                        (Map.lookup funcEntry funs)
      loopBlockOff <- maybe (die "could not resolve loop block address") pure
                        (MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral loopBlockAddr)))
      block <- maybe (die "target block not found in discovered function") pure
                 (Map.lookup loopBlockOff (funInfo ^. MD.parsedBlocks))

      putStrLn ("Function @ 0x" ++ showHex funcEntryRaw "" ++ ", loop block @ 0x"
                ++ showHex loopBlockAddr "")
      putStrLn ("MMIO region: 0x" ++ showHex mmioBase "" ++ " - 0x"
                ++ showHex (mmioBase + mmioSize) "" ++ " (fully symbolic)")
      putStrLn ("Seeding R3 = 0x" ++ showHex mmioBase "" ++ " (peripheral base pointer)\n")

      putStrLn ("Query 1: is exit block 0x" ++ showHex exitAddr "" ++ " reachable?")
      exitResult <- checkBranchModel mem block
        BranchQuery { bqPointerOverride = Just (AR.r3, mmioBase)
                    , bqTargetAddr = exitAddr, bqObserveReg = AR.r2 }
      reportResult "R2 (status word @ 0x40002008)" exitResult

      putStrLn ("\nQuery 2: is loop-continuation 0x" ++ showHex loopAddr "" ++ " reachable?")
      loopResult <- checkBranchModel mem block
        BranchQuery { bqPointerOverride = Just (AR.r3, mmioBase)
                    , bqTargetAddr = loopAddr, bqObserveReg = AR.r2 }
      reportResult "R2 (status word @ 0x40002008)" loopResult

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
      entry <- maybe (die "could not resolve entry address") pure (resolveEntry mem entryRaw)
      let addrSymMap = Map.singleton entry (BSC.pack "target")
          discState = MD.cfgFromAddrs ARM.arm_linux_info mem addrSymMap [entry] []
          funs = discState ^. MD.funInfo
      putStrLn ("Discovered " ++ show (Map.size funs) ++ " function(s) from 0x"
                ++ showHex entryRaw "" ++ ":\n")
      mapM_ (\(Some info) -> print (PP.pretty info)) (Map.elems funs)

-- | @aptrace protocol FIRMWARE.bin@ -- protocol-harness-roadmap M2/M3 demo.
--
-- Seeds the AutoPilot inbound packet dispatcher directly at Thumb entry
-- 0x8259 (flash 0x8258 -- the main parser named throughout
-- research/autopilot_static_inventory), models the RX packet buffer at RAM
-- 0x2000232a (found by reading the literal-pool pointer the dispatcher's
-- entry block loads).
--
-- IMPORTANT CORRECTION vs. the first version of this command: seeding
-- discovery at the dispatcher's true entry (0x8259) and running the whole
-- ~340-block merged function via 'Data.Macaw.Symbolic.mkFunCFG' does NOT
-- work -- it hangs. Diagnosis (see research/notes/protocol-harness-results.md
-- for the full trace): the entry sequence does not simply read the packet's
-- first byte and walk an if/else-if chain of character comparisons the way
-- research/autopilot_static_inventory/parser-dispatch.md describes; real
-- execution first goes through what looks like a hash-table/lookup-table
-- based command lookup (reading through registers R4-R7, which we don't yet
-- know how to seed correctly), and with those registers defaulted to zero
-- that mechanism loops forever dereferencing near-null memory.
--
-- We sidestep that unresolved mechanism for now: block 0x888c (part of the
-- SAME already-discovered function) is confirmed by direct inspection to be
-- exactly "if R3 == '&' (0x26), goto 0x8890" -- i.e. R3 already holds the
-- packet's first byte by the time control reaches here, however it got
-- there. Block 0x8890 (the '&' handler) unconditionally writes 1 to
-- pending[5] (RAM 0x200025bc + 5) and returns -- no further branching. So
-- "PC reaches 0x8890" is an exact proxy for "event 5 gets scheduled", and we
-- can test it with 'APTrace.SymbolicRunner.checkBranchModel' -- the same
-- single-block technique already proven safe and fast for the Steps 7-9 MMIO
-- demo, seeding R3 directly instead of modeling the packet buffer as memory.
runProtocol :: FilePath -> Word32 -> IO ()
runProtocol path flashBase = do
  bytes <- BS.readFile path
  let dispatcherEntry  = 0x8259 :: Word32  -- Thumb entry for flash 0x8258
      ampersandCheck    = 0x888c :: Word32 -- "if R3 == '&', goto 0x8890"
      ampersandHandler  = 0x8890 :: Word32 -- writes pending[5]=1, then returns
      fallthroughTarget = 0x889e :: Word32 -- "not '&', check next command"
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      entry <- maybe (die "could not resolve dispatcher entry address") pure
                 (resolveEntry mem dispatcherEntry)
      let addrSymMap = Map.singleton entry (BSC.pack "dispatcher")
          discState = MD.cfgFromAddrs ARM.arm_linux_info mem addrSymMap [entry] []
          funs = discState ^. MD.funInfo
      Some fn <- maybe (die "dispatcher was not discovered") pure (Map.lookup entry funs)
      checkOff <- maybe (die "could not resolve '&' check address") pure
                    (MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral ampersandCheck)))
      block <- maybe (die "'&' check block not found in discovered function") pure
                 (Map.lookup checkOff (fn ^. MD.parsedBlocks))

      putStrLn ("Dispatcher @ 0x" ++ showHex dispatcherEntry ""
                ++ ", '&' check @ 0x" ++ showHex ampersandCheck ""
                ++ " (\"if R3 == '&', goto 0x" ++ showHex ampersandHandler "" ++ "\")\n")

      putStrLn "Test 1: concrete R3 = '&' (0x26)"
      r1 <- checkBranchModel mem block
        BranchQuery { bqPointerOverride = Just (AR.r3, 0x26)
                    , bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3 }
      reportResult "R3" r1

      putStrLn "\nTest 2: R3 left fully symbolic -- what value reaches the '&' handler?"
      r2 <- checkBranchModel mem block
        BranchQuery { bqPointerOverride = Nothing
                    , bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3 }
      reportResult "R3" r2

      putStrLn "\nTest 3: R3 left fully symbolic -- what value takes the fallthrough (not '&') path?"
      r3 <- checkBranchModel mem block
        BranchQuery { bqPointerOverride = Nothing
                    , bqTargetAddr = fallthroughTarget, bqObserveReg = AR.r3 }
      reportResult "R3" r3

      -- Same technique, same dispatcher, three more single-character command
      -- checks found the same way (grep the lifted IR for "CMP ... Rn 3, imm8
      -- <ascii>", confirm the true-branch target by inspection):
      --   'G' (0x47): check @ 0x83b2 -> handler 0x83b6 (G<dd><seq>| request, event 17)
      --   '!' (0x21): check @ 0x87b2 -> handler 0x87b6 (bulk CSV query, event 7)
      --   'S' (0x53): check @ 0x87be -> handler 0x87c2 (state/config query, event 6)
      mapM_ (runSingleCharCheck mem fn)
        [ ("G", 0x83b2, 0x83b6, 0x47)
        , ("!", 0x87b2, 0x87b6, 0x21)
        , ("S", 0x87be, 0x87c2, 0x53)
        ]

-- | Ask the solver what value of R3 reaches a given single-character
-- command's handler, within the already-discovered dispatcher function 'fn'.
runSingleCharCheck :: MM.Memory 32 -> MD.DiscoveryFunInfo ARM.ARM ids
                   -> (String, Word32, Word32, Integer) -> IO ()
runSingleCharCheck mem fn (label, checkAddr, handlerAddr, expected) = do
  putStrLn ("\n'" ++ label ++ "' check @ 0x" ++ showHex checkAddr ""
            ++ " -> handler 0x" ++ showHex handlerAddr "")
  case MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral checkAddr)) of
    Nothing -> putStrLn "  error: could not resolve check address"
    Just off -> case Map.lookup off (fn ^. MD.parsedBlocks) of
      Nothing -> putStrLn "  error: check block not found"
      Just block -> do
        r <- checkBranchModel mem block
          BranchQuery { bqPointerOverride = Nothing
                      , bqTargetAddr = handlerAddr, bqObserveReg = AR.r3 }
        reportResult "R3" r
        case r of
          Reachable v | v == expected -> putStrLn "  (matches expected ASCII value)"
          Reachable _ -> putStrLn "  (WARNING: does not match expected ASCII value)"
          _ -> pure ()

reportResult :: String -> BranchResult -> IO ()
reportResult label res = case res of
  Unreachable -> putStrLn "  UNSAT: no model -- this branch is not reachable."
  Reachable v -> putStrLn ("  SAT: reachable when " ++ label ++ " = 0x" ++ showHex v "")
  SolverError e -> putStrLn ("  error: " ++ e)
