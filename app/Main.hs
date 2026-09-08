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
import qualified System.IO as IO

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.ARMReg as AR
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM

import           APTrace.FirmwareLoader
  ( buildMemory, buildMemoryWithMMIO, resolveEntry )
import           APTrace.ProtocolHarness ( PacketByte(..) )
import qualified APTrace.ProtocolHarness as PH
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
  IO.hSetBuffering IO.stdout IO.LineBuffering
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
-- becomes non-zero. See docs/harness/symbolic-execution-results.md for how
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
        BranchQuery { bqPointerOverrides = [(AR.r3, mmioBase)]
                    , bqTargetAddr = exitAddr, bqObserveReg = AR.r2 }
      reportResult "R2 (status word @ 0x40002008)" exitResult

      putStrLn ("\nQuery 2: is loop-continuation 0x" ++ showHex loopAddr "" ++ " reachable?")
      loopResult <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = [(AR.r3, mmioBase)]
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

-- | @aptrace protocol FIRMWARE.bin@ -- targets the AutoPilot inbound packet
-- dispatcher directly at Thumb entry 0x8259 (flash 0x8258), modeling the RX
-- packet buffer at RAM 0x2000232a.
--
-- Runs single-block checks (via 'APTrace.SymbolicRunner.checkBranchModel')
-- against known character-comparison blocks rather than the whole merged
-- ~340-block function, because whole-function replay does not yet
-- terminate -- see docs/investigations/parser-dispatch.md for why entry
-- isn't a simple character chain, and docs/project-status.md for the
-- current blocker on the whole-function version of this test.
runProtocol :: FilePath -> Word32 -> IO ()
runProtocol path flashBase = do
  bytes <- BS.readFile path
  let dispatcherEntry  = 0x8259 :: Word32  -- Thumb entry for flash 0x8258
      ampersandCheck    = 0x888c :: Word32 -- "if R3 == '&', goto 0x8890"
      ampersandHandler  = 0x8890 :: Word32 -- writes pending[5]=1, then returns
      fallthroughTarget = 0x889e :: Word32 -- "not '&', check next command"
      bufAddr           = 0x2000232a :: Word32  -- RX packet buffer (literal @ flash 0x8528)
      pendingBase       = 0x200025bc :: Word32  -- pending-event array base (literal @ flash 0x893c)
      event5Addr        = pendingBase + 5
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

      -- Diagnostic: the whole-function run (Test 0 below) was hanging with
      -- R6 growing without bound. Rather than hand-deriving the ARM CMP/ASR
      -- flag arithmetic at 0x8286 (error-prone), ask Z3 directly what
      -- buffer[1] value makes the loop's own exit block (0x83ec, a real
      -- confirmed `return`) reachable from a single pass of the loop body
      -- (0x827e), versus what value keeps it looping (0x828e).
      loopBodyOff <- maybe (die "could not resolve loop body address") pure
                       (MM.resolveAbsoluteAddr mem (MM.memWord 0x827e))
      loopBody <- maybe (die "loop body block not found") pure
                    (Map.lookup loopBodyOff (fn ^. MD.parsedBlocks))
      putStrLn "Loop probe: block 0x827e, R4=R5=bufAddr, R6=0, R7=0x20000180 -- what is buffer[1] when the loop exits vs. continues?"
      lp1 <- checkBranchModel mem loopBody
        BranchQuery { bqPointerOverrides = [(AR.r4, bufAddr), (AR.r5, bufAddr), (AR.r6, 0), (AR.r7, 0x20000180)]
                    , bqTargetAddr = 0x83ec, bqObserveReg = AR.r3 }
      putStr "  exit (0x83ec): " >> reportResult "buffer[1]" lp1
      lp2 <- checkBranchModel mem loopBody
        BranchQuery { bqPointerOverrides = [(AR.r4, bufAddr), (AR.r5, bufAddr), (AR.r6, 0), (AR.r7, 0x20000180)]
                    , bqTargetAddr = 0x828e, bqObserveReg = AR.r3 }
      putStr "  continue (0x828e): " >> reportResult "buffer[1]" lp2

      -- The '|' is the wire-protocol frame terminator consumed by the LoRa
      -- assembly loop (0x8960 per research/autopilot_static_inventory);
      -- rf-boundaries.md says the buffer gets NUL-terminated once assembled,
      -- so it's very unlikely '|' itself is ever stored at buffer[1]. The
      -- loop probe above confirms buffer[1]=1 exits this pre-check loop
      -- immediately (R6=0); our formula predicts buffer[1]=0 does too (both
      -- give a negative (buf[1]-7), satisfying the observed exit condition).
      putStrLn "\nTest 0: whole dispatcher function, buffer[1]=0x01 (Z3-confirmed exit witness above)"
      let realPacket = [Concrete 0x26, Concrete 0x01, Concrete 0x00, Concrete 0x00]
      r0 <- PH.runPacketTransaction mem fn bufAddr realPacket event5Addr 1
      case r0 of
        PH.ConcreteResult 1 -> putStrLn "  PASS: pending[5] = 1 (event 5 scheduled) via the real parser path"
        PH.ConcreteResult v -> putStrLn ("  FAIL: pending[5] = 0x" ++ showHex v "" ++ " (expected 1)")
        other -> putStrLn ("  error: " ++ show other)

      putStrLn "\nTest 1: concrete R3 = '&' (0x26)"
      r1 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = [(AR.r3, 0x26)]
                    , bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3 }
      reportResult "R3" r1

      putStrLn "\nTest 2: R3 left fully symbolic -- what value reaches the '&' handler?"
      r2 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = []
                    , bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3 }
      reportResult "R3" r2

      putStrLn "\nTest 3: R3 left fully symbolic -- what value takes the fallthrough (not '&') path?"
      r3 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = []
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
          BranchQuery { bqPointerOverrides = []
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
