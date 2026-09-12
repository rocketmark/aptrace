{-# LANGUAGE DataKinds #-}
-- | Performing Rigs AutoPilot-specific investigation scenarios: bounded
-- symbolic-execution queries against real, hardcoded addresses this
-- project's own reverse-engineering found in the AutoPilot firmware's
-- @IRQ10_Handler@ MMIO poll, its inbound-packet dispatcher, and its PB05
-- trigger-input region. Moved out of @app/Main.hs@ verbatim (behavior
-- unchanged) so that reusable Macaw/Crucible framework code stays free of
-- Performing Rigs case knowledge -- see @docs/architecture.md@'s
-- framework/case split. This module may depend on framework modules;
-- framework modules must not depend on this one.
module APTrace.Case.PerformingRigsScenarios
  ( runSolve
  , runProtocol
  , runTrigger
  , runTriggerCrossCheck
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Map as Map
import           Data.Parameterized.Some ( Some(..) )
import           Data.Word ( Word32 )
import           Lens.Micro ( (^.) )
import           Numeric ( showHex )
import qualified Prettyprinter as PP
import           System.Exit ( die )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.ARMReg as AR
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Discovery.ParsedContents as MDP
import qualified Data.Macaw.Memory as MM

import           APTrace.Case.PerformingRigs ( ramBase, ramSize, numIrq )
import           APTrace.FirmwareLoader
  ( buildMemory, buildMemoryWithMMIO, resolveEntry, resolveEntries
  , macawCortexMEntry, armCortexMInfo )
import           APTrace.ProtocolHarness ( PacketByte(..) )
import qualified APTrace.ProtocolHarness as PH
import           APTrace.SymbolicRunner
  ( BranchQuery(..), BranchResult(..), checkBranchModel, reportResult )
import           APTrace.VectorTable ( parseVectorTable )

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
          discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap entryAddrs []
          funs = discState ^. MD.funInfo

      funcEntry <- maybe (die "could not resolve function entry address") pure
                     (resolveEntry mem (macawCortexMEntry funcEntryRaw))
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
                    , bqMemoryBytes = [], bqTargetAddr = exitAddr, bqObserveReg = AR.r2, bqExcludeObserved = [] }
      reportResult "R2 (status word @ 0x40002008)" exitResult

      putStrLn ("\nQuery 2: is loop-continuation 0x" ++ showHex loopAddr "" ++ " reachable?")
      loopResult <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = [(AR.r3, mmioBase)]
                    , bqMemoryBytes = [], bqTargetAddr = loopAddr, bqObserveReg = AR.r2, bqExcludeObserved = [] }
      reportResult "R2 (status word @ 0x40002008)" loopResult


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
                 (resolveEntry mem (macawCortexMEntry dispatcherEntry))
      let addrSymMap = Map.singleton entry (BSC.pack "dispatcher")
          discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap [entry] []
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
                    , bqMemoryBytes = [], bqTargetAddr = 0x83ec, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      putStr "  exit (0x83ec): " >> reportResult "buffer[1]" lp1
      lp2 <- checkBranchModel mem loopBody
        BranchQuery { bqPointerOverrides = [(AR.r4, bufAddr), (AR.r5, bufAddr), (AR.r6, 0), (AR.r7, 0x20000180)]
                    , bqMemoryBytes = [], bqTargetAddr = 0x828e, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      putStr "  continue (0x828e): " >> reportResult "buffer[1]" lp2

      -- Isolate the dispatcher's real first decision (0x8258-0x8266, per
      -- docs/investigations/dispatcher-loop-concrete-trace.md) in Crucible,
      -- using the existing single-block machinery plus 'bqMemoryBytes' (a
      -- small addition: 'BranchQuery' previously could only seed pointer
      -- *registers*, not the memory they point at, which this block's
      -- buffer[0] load needs). This is the block Unicorn found gates entry
      -- to the 0x827e loop (concretely, buffer[0]=0x26 skips it; the
      -- whole-function Crucible run, given the same nominal inputs, was
      -- observed getting stuck inside it instead -- see project-status.md's
      -- "Current blocker"). 'entry' is this block's own address, since it's
      -- the function's discovered entry block.
      gateBlock <- maybe (die "gate block (function entry) not found") pure
                     (Map.lookup entry (fn ^. MD.parsedBlocks))
      putStrLn "\nGate block (0x8258-0x8266) -- Macaw's parsed IR:"
      print (PP.pretty gateBlock)
      case MDP.pblockTermStmt gateBlock of
        MDP.ParsedBranch _regs cond trueAddr falseAddr -> do
          putStrLn "\nDecoded terminator: ParsedBranch"
          putStrLn ("  condition : " ++ show (PP.pretty cond))
          putStrLn ("  trueAddr  : " ++ show trueAddr)
          putStrLn ("  falseAddr : " ++ show falseAddr)
        other -> putStrLn ("\nUnexpected terminator (not ParsedBranch): " ++ show other)
      putStrLn ("\ndiscoveredFunAddr fn = " ++ show (MD.discoveredFunAddr fn)
                ++ "  (our resolved entry = " ++ show entry
                ++ ", match: " ++ show (MD.discoveredFunAddr fn == entry) ++ ")")

      -- SP must be seeded concretely: this block's first instruction is
      -- `push {r4,r5,r6,r7,r8,r9,r10,lr}` (writes [SP-32..SP-1]). Left
      -- symbolic (the default for anything not in bqPointerOverrides), the
      -- solver is free to pick SP so that push aliases and overwrites our
      -- seeded buffer[0] byte with a fresh symbolic register's low byte --
      -- which is exactly what happened on the first attempt here (both
      -- targets came back "reachable" with an unconstrained-looking R3).
      -- Seeding SP to a concrete, buffer-disjoint value (top of RAM, same
      -- convention Unicorn/ProtocolHarness already use) removes the hazard.
      let stackTop = ramBase + ramSize :: Word32
      putStrLn "\nTest G1: seed buffer[0] = 0x26 ('&'), SP = top of RAM -- is 0x82c6 (skip-the-loop path) reachable?"
      g1 <- checkBranchModel mem gateBlock
        BranchQuery { bqPointerOverrides = [(AR.sp, stackTop)], bqMemoryBytes = [(bufAddr, 0x26)]
                    , bqTargetAddr = 0x82c6, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3 (buffer[0])" g1
      putStrLn "Test G2: seed buffer[0] = 0x26, SP = top of RAM -- is 0x8268 (enter-the-loop path) reachable?"
      g2 <- checkBranchModel mem gateBlock
        BranchQuery { bqPointerOverrides = [(AR.sp, stackTop)], bqMemoryBytes = [(bufAddr, 0x26)]
                    , bqTargetAddr = 0x8268, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3 (buffer[0])" g2

      putStrLn "\nTest G3 (control): seed buffer[0] = 0xF0, SP = top of RAM -- is 0x82c6 reachable?"
      g3 <- checkBranchModel mem gateBlock
        BranchQuery { bqPointerOverrides = [(AR.sp, stackTop)], bqMemoryBytes = [(bufAddr, 0xF0)]
                    , bqTargetAddr = 0x82c6, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3 (buffer[0])" g3
      putStrLn "Test G4 (control): seed buffer[0] = 0xF0, SP = top of RAM -- is 0x8268 reachable?"
      g4 <- checkBranchModel mem gateBlock
        BranchQuery { bqPointerOverrides = [(AR.sp, stackTop)], bqMemoryBytes = [(bufAddr, 0xF0)]
                    , bqTargetAddr = 0x8268, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3 (buffer[0])" g4

      -- The '|' is the wire-protocol frame terminator consumed by the LoRa
      -- assembly loop (0x8960 per research/autopilot_static_inventory);
      -- rf-boundaries.md says the buffer gets NUL-terminated once assembled,
      -- so it's very unlikely '|' itself is ever stored at buffer[1]. The
      -- loop probe above confirms buffer[1]=1 exits this pre-check loop
      -- immediately (R6=0); our formula predicts buffer[1]=0 does too (both
      -- give a negative (buf[1]-7), satisfying the observed exit condition).
      putStrLn "\nTest 0: whole dispatcher function, buffer[1]=0x01 (Z3-confirmed exit witness above)"
      putStrLn "  (rich-trace enabled: 0x8258-0x8900, watching buffer[0] -- see docs/investigations/whole-function-trace-divergence.md)"
      let realPacket = [Concrete 0x26, Concrete 0x01, Concrete 0x00, Concrete 0x00]
          traceCfg = PH.RichTraceConfig
            { PH.rtLoAddr = 0x8258, PH.rtHiAddr = 0x8900
            , PH.rtWatchMem = Just bufAddr, PH.rtMaxHits = 500
            }
      r0 <- PH.runPacketTransactionTraced mem fn bufAddr realPacket event5Addr 1 (Just traceCfg) [] Nothing Nothing
      case r0 of
        PH.ConcreteResult 1 -> putStrLn "  PASS: pending[5] = 1 (event 5 scheduled) via the real parser path"
        PH.ConcreteResult v -> putStrLn ("  FAIL: pending[5] = 0x" ++ showHex v "" ++ " (expected 1)")
        other -> putStrLn ("  error: " ++ show other)

      putStrLn "\nTest 1: concrete R3 = '&' (0x26)"
      r1 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = [(AR.r3, 0x26)]
                    , bqMemoryBytes = [], bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3" r1

      putStrLn "\nTest 2: R3 left fully symbolic -- what value reaches the '&' handler?"
      r2 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = []
                    , bqMemoryBytes = [], bqTargetAddr = ampersandHandler, bqObserveReg = AR.r3, bqExcludeObserved = [] }
      reportResult "R3" r2

      putStrLn "\nTest 3: R3 left fully symbolic -- what value takes the fallthrough (not '&') path?"
      r3 <- checkBranchModel mem block
        BranchQuery { bqPointerOverrides = []
                    , bqMemoryBytes = [], bqTargetAddr = fallthroughTarget, bqObserveReg = AR.r3, bqExcludeObserved = [] }
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

-- | @aptrace trigger FIRMWARE.bin@ -- bounded symbolic reachability for the
-- AutoPilot's PB05 trigger-poll region, inside @phase_ramp_state_machine__
-- CUSTOM@ (@FUN_00008e18@), per
-- docs/investigations/trigger-input-symbolic-reachability.md.
--
-- Macaw's automatic whole-function discovery from the region's *own* real
-- entry (0x8e18) cannot reach any of this region's interesting code: every
-- one of the digital arm's real branches is a narrow @CBZ_T1@/@CBNZ_T1@
-- instruction, and this Macaw version's ARM branch classifier fails to
-- recognize the (semantically correct, just redundantly double-nested)
-- mux shape its own ASL lifting produces for that instruction family --
-- "IP is not a mux", cascading through every other classifier, leaving the
-- block a 'ClassifyFailure' with no successor edges recorded. Confirmed
-- exhaustively for this function (4/4 classify failures are CBZ_T1) via
-- @aptrace explore@. This is a genuine, narrow Macaw discovery gap, not a
-- Ghidra disagreement: Ghidra's own disassembly, and the prior slice's
-- concrete Unicorn execution, already independently and exactly establish
-- both of each CBZ's real successor addresses.
--
-- Workaround, not a Macaw patch: since each CBZ's two successors are
-- already independently proven (disassembly + concrete execution, not
-- assumed), this seeds Macaw discovery directly at each successor instead
-- of trying to cross the CBZ automatically -- two separate, cleanly
-- (re-)discovered whole-function regions, each confirmed classify-failure
-- clean over the addresses this query actually touches (the only
-- remaining failures are downstream, past the observed addresses, in the
-- shared config-reload continuation this query never needs to reach):
--
--   0x9203 -- the TR0/disarmed four-way idle-state gate, the second
--            digitalRead(PB05), and the 0x8f98 config-reload write.
--   0x91a3 -- the TR1/armed continuation that builds and sends the real
--            "T..." status frame.
--
-- Registers r5/r6 (the per-channel device-state array base and the
-- TR-enable byte's own address) are seeded via 'PH.runPacketTransactionTraced'\'s
-- register-override list to the real values Ghidra's disassembly resolves
-- them to at each of these real predecessor points -- not fabricated;
-- see the investigation doc for the exact literal-pool loads this
-- reproduces. PB05 itself is never seeded: it is read through a real
-- @bl digitalRead@ call, which this harness's existing opaque-call
-- override always treats as a calling-convention-respecting black box
-- (fresh symbolic R0-R3/R12) -- so PB05's value is already a free
-- variable the solver can pick, with no special-casing needed.
runTrigger :: FilePath -> Word32 -> IO ()
runTrigger path flashBase = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      let deviceStateArray = 0x20002524 :: Word32  -- r5 @ 0x9203: per-channel device-state, [0..3] must be 0
          trEnableAddr     = 0x20003120 :: Word32  -- r6 @ both entries: the TR0|/TR1| enable byte
          gateCell2Addr    = 0x200000d8 :: Word32  -- ldrb-checked == 9 before the second digitalRead
          gateCell1Addr    = 0x20001b38 :: Word32  -- ldr(4)-checked == 0x7b before the second digitalRead
          statusByteAddr   = 0x200025bc :: Word32  -- +1 becomes 3 at 0x8f98 (the config-reload write)
          txBufBase        = 0x20002548 :: Word32  -- becomes 'T' (0x54) once the T-frame is being built

      putStrLn "=== Query A: entry 0x9203 (TR0/disarmed four-way gate -> second digitalRead(PB05) -> 0x8f98) ==="
      -- Macaw's own discovery from this entry eventually reaches a real ARM
      -- VFP/NEON instruction (VSTMDB_T1) downstream, past the unconditional
      -- jump at 0x8fa4 into 0x6e4c, that this Macaw version's semantics
      -- table has no lifting for at all -- a genuine, unrelated gap (this
      -- query never needs anything past 0x8f98's own write). Seeding 0x6e4c
      -- as a second, simultaneous known-function entry does NOT avoid this:
      -- Macaw's classifier treats a direct `B.W` by its own instruction
      -- form (an ordinary intra-function jump) regardless of whether the
      -- target is independently known, so it still gets inlined. The real
      -- fix is the 'stopAtAddr' early-stop below: reaching 0x8f9e (right
      -- after the write at 0x8f9c completes) answers this query's actual
      -- question before Macaw's execution ever reaches the unmodeled
      -- instruction, and the resulting exception (caught, not crashing the
      -- process) is simply ignored once that answer is already in hand.
      -- Observed cost, both queries in this function, this Macaw/Crucible/
      -- Z3 version: the model builds correctly (mkFunCFG in ~10-20ms,
      -- executeCrucible reaches the target address and hands the online
      -- Z3 process a well-formed query), but the SAT check itself did not
      -- converge within a practical session time budget (killed after
      -- 17+ minutes for this query, 4+ for Query B below) -- likely the
      -- symbolic-array memory model plus the accumulated ASL side-
      -- condition state from a real, multi-instruction run, not a flaw in
      -- the query's own logic. See
      -- docs/investigations/trigger-input-symbolic-reachability.md for
      -- the full accounting; this slice's actual answer to both queries
      -- came from direct provenance tracing (Ghidra) plus a concrete
      -- Unicorn replay using the real values that tracing found, not from
      -- this solver call completing.
      entryA <- maybe (die "could not resolve 0x9203 entry") pure
                  (resolveEntry mem (macawCortexMEntry 0x9203))
      let addrSymMapA = Map.singleton entryA (BSC.pack "trigger_gate")
          discA = MD.cfgFromAddrs armCortexMInfo mem addrSymMapA [entryA] []
          funsA = discA ^. MD.funInfo
      case Map.lookup entryA funsA of
        Nothing -> putStrLn "  error: 0x9203 region was not discovered by Macaw"
        Just (Some fnA) -> do
          -- Narrowed per instruction: gate provenance is now closed (both
          -- cells traced to real firmware producers -- see the
          -- investigation doc), so both are seeded CONCRETE at their real
          -- values here instead of symbolic. The only remaining free
          -- variable is PB05 itself, via the existing opaque-call
          -- override on `bl digitalRead` -- no buffer symbolism at all.
          let (bufLoA, bufBytesA) = sparseBuffer gateCell2Addr (gateCell1Addr + 4)
                [ (gateCell2Addr, Concrete 9)
                , (gateCell1Addr,     Concrete 0x7b), (gateCell1Addr + 1, Concrete 0)
                , (gateCell1Addr + 2, Concrete 0),    (gateCell1Addr + 3, Concrete 0)
                ]
              regOverridesA = [(AR.r5, deviceStateArray), (AR.r6, trEnableAddr)]
          putStrLn ("  gate cell 2 (0x" ++ showHex gateCell2Addr "" ++ ") = 9 and gate cell 1 (0x"
                    ++ showHex gateCell1Addr "" ++ ") = 0x7b, both CONCRETE (real, provenance-traced values); "
                    ++ "only PB05 (via the opaque digitalRead call) is free; r5=0x"
                    ++ showHex deviceStateArray "" ++ ", r6=0x" ++ showHex trEnableAddr "" ++ " seeded")
          -- Stop once execution reaches 0x8fa4 -- the next *macaw-block*
          -- boundary after 0x8f98 (Crucible/macaw-symbolic's own location
          -- tracking is per discovered-block, not per-ARM-instruction, so
          -- an address mid-block such as 0x8f9e -- right after the real
          -- write at 0x8f9c -- never registers as a distinct location; a
          -- rich-trace run confirmed this empirically). By the time 0x8fa4
          -- is reached, the whole 0x8f98 block, including its write, has
          -- already executed -- well before the unconditional jump into
          -- the unmodeled-VSTMDB continuation this query never needs.
          -- Solver-observability path: writes /tmp/aptrace_trigger_A.stop.*
          -- (standalone .smt2 immediately, plus an incremental online-
          -- interaction log) so the actual query can be inspected without
          -- waiting for -- or instead of -- the online check converging.
          resA <- PH.runPacketTransactionTraced mem fnA bufLoA bufBytesA (statusByteAddr + 1) 3 Nothing
                    regOverridesA (Just 0x8fa4) (Just "/tmp/aptrace_trigger_A")
          reportPacket "0x8f98 config-reload write (0x200025bc+1 == 3)" bufLoA resA

      putStrLn "\n=== Query B: entry 0x91a3 (TR1/armed -- does reaching the 'T' write depend on PB05 or the gate cells?) ==="
      entryB <- maybe (die "could not resolve 0x91a3 entry") pure
                  (resolveEntry mem (macawCortexMEntry 0x91a3))
      let addrSymMapB = Map.singleton entryB (BSC.pack "trigger_report")
          discB = MD.cfgFromAddrs armCortexMInfo mem addrSymMapB [entryB] []
          funsB = discB ^. MD.funInfo
      case Map.lookup entryB funsB of
        Nothing -> putStrLn "  error: 0x91a3 region was not discovered by Macaw"
        Just (Some fnB) -> do
          -- No register overrides at all: every register this arm touches
          -- before the 'T' write (r4, r7, r8) is a fresh literal-pool load
          -- or immediate, confirmed by disassembly -- unlike Query A, this
          -- entry needs nothing seeded. The write itself is at 0x91c4, but
          -- (per Query A's own note on block-granular location tracking)
          -- the next address that registers as its own location is 0x91ce
          -- -- right after the digitalRead(PB05) call at 0x91ca returns,
          -- which is irrelevant to *whether* the write happened; by 0x91ce
          -- it already has.
          putStrLn "  no buffer bytes and no register overrides seeded -- this arm's own registers are all fresh literal loads"
          resB <- PH.runPacketTransactionTraced mem fnB txBufBase [] txBufBase 0x54 Nothing [] (Just 0x91ce)
                    (Just "/tmp/aptrace_trigger_B")
          reportPacket "'T' buffer write (0x20002548 == 0x54)" txBufBase resB

-- | @aptrace trigger-crosscheck FIRMWARE.bin@ -- a deliberately small,
-- targeted Crucible/What4/Z3 cross-check of the exact trigger gate
-- Unicorn has already isolated (trigger-input-concrete-path.md /
-- trigger-input-motion-causality.md), per
-- docs/investigations/trigger-input-symbolic-crosscheck.md. Unlike
-- 'runTrigger' above (which enters the *whole* re-seeded
-- @phase_ramp_state_machine__CUSTOM@ region and stops deep inside it,
-- the approach already found not to converge for this Macaw/Crucible/Z3
-- version), this targets only the seven-guard gate block chain
-- (0x9202-0x9224) plus one single-block check at the post-call
-- continuation (0x922c) -- both deliberately small, loop-free, and
-- (until their own respective stop points) call-free.
--
-- Query A/B use the new 'PH.runGateReachability' (no RAM zero-overlay,
-- since nothing in this bounded region needs "the rest of RAM starts at
-- zero" to be sound -- every address this query ever touches is one of
-- the seven named 'PH.GateVar's, explicitly and deliberately left free).
-- Query C reuses the existing, unmodified single-block
-- 'checkBranchModel' unchanged -- 0x922c is already a real Macaw
-- block-start address in the same re-seeded discovery, so no new
-- capability is needed there at all.
runTriggerCrossCheck :: FilePath -> Word32 -> IO ()
runTriggerCrossCheck path flashBase = do
  bytes <- BS.readFile path
  case buildMemory bytes flashBase ramBase ramSize of
    Left err -> die ("failed to build memory image: " ++ err)
    Right mem -> do
      -- Every address below is a real, already-provenance-traced RAM cell
      -- or literal-pool pointer from trigger-input-symbolic-
      -- reachability.md / trigger-input-concrete-path.md -- not derived
      -- fresh this pass. r5/r6 are seeded concrete (the pointers
      -- themselves); everything they point at is left symbolic.
      let deviceStateArray = 0x20002524 :: Word32  -- r5 @ 0x9203: per-channel device-state array base
          trEnableAddr     = 0x20003120 :: Word32  -- r6 @ 0x9222: the TR0|/TR1| enable byte's own address
          state32Addr      = 0x20001b38 :: Word32  -- loaded via the flash literal @ 0x9260; must == 0x7b
          state8Addr       = 0x200000d8 :: Word32  -- loaded via the flash literal @ 0x9264; must == 0x09
          entryRaw         = 0x9203 :: Word32      -- Thumb bit set -- see FirmwareLoader.macawCortexMEntry
          stopAddr         = 0x9226 :: Word32      -- the real Macaw block-start address immediately
                                                     -- preceding the "bl 0xd3dc" at 0x9228 -- reaching it
                                                     -- is this project's own established proxy for "0x9228
                                                     -- is reached" (block-granular location tracking, not
                                                     -- per-instruction -- trigger-input-symbolic-
                                                     -- reachability.md Part 2), since 0x9228 itself is
                                                     -- mid-block, not a block boundary Crucible/macaw-
                                                     -- symbolic's own location tracking can ever report
          gateVars =
            [ PH.GateVar "r5[0]"   (deviceStateArray + 0) 1
            , PH.GateVar "r5[1]"   (deviceStateArray + 1) 1
            , PH.GateVar "r5[2]"   (deviceStateArray + 2) 1
            , PH.GateVar "r5[3]"   (deviceStateArray + 3) 1
            , PH.GateVar "state32" state32Addr             4
            , PH.GateVar "state8"  state8Addr              1
            , PH.GateVar "r6[0]"   (trEnableAddr + 0)      1
            ]
          -- The real comparison values each guard's own CMP/CBNZ checks
          -- for (Ghidra disassembly, not a solver assumption -- used only
          -- to build Query B's "must NOT equal" negative checks below).
          expectedGood =
            [ ("r5[0]", 0), ("r5[1]", 0), ("r5[2]", 0), ("r5[3]", 0)
            , ("state32", 0x7b), ("state8", 0x09), ("r6[0]", 0)
            ]
          regOverrides = [(AR.r5, deviceStateArray), (AR.r6, trEnableAddr)]

      entry <- maybe (die "could not resolve 0x9203 entry") pure
                 (resolveEntry mem (macawCortexMEntry entryRaw))
      let addrSymMap = Map.singleton entry (BSC.pack "trigger_gate_crosscheck")
          discState = MD.cfgFromAddrs armCortexMInfo mem addrSymMap [entry] []
          funs = discState ^. MD.funInfo
      Some fn <- maybe (die "0x9203 region was not discovered by Macaw") pure (Map.lookup entry funs)

      putStrLn "=== Query A: positive reachability, entry 0x9202 -> stop 0x9226 (all seven guards free) ==="
      putStrLn ("  regOverrides: r5=0x" ++ showHex deviceStateArray "" ++ " (device-state array), r6=0x"
                ++ showHex trEnableAddr "" ++ " (TR-enable byte address)")
      putStrLn "  symbolic: r5[0..3], state32 (0x20001b38 via the 0x9260 literal), state8 (0x200000d8 via the 0x9264 literal), r6[0]"
      resA <- PH.runGateReachability mem fn regOverrides gateVars stopAddr [] (Just "/tmp/aptrace_crosscheck_A")
      reportGate "Query A (positive)" resA

      putStrLn "\n=== Query B: one negative check per guard (each expected UNSAT) ==="
      mapM_
        (\gv -> do
           let label = PH.gvLabel gv
               good = maybe (error ("no expected-good value for " ++ label)) id (lookup label expectedGood)
           putStrLn ("\n  -- " ++ label ++ " != 0x" ++ showHex good " (all other guards still free)")
           r <- PH.runGateReachability mem fn regOverrides gateVars stopAddr [(label, good)]
                  (Just ("/tmp/aptrace_crosscheck_B_" ++ label))
           reportGate ("Query B (" ++ label ++ " violated)") r)
        gateVars

      putStrLn "\n=== Query C: single-block check at 0x922c (post-digitalRead continuation), R0 symbolic ==="
      case MM.resolveAbsoluteAddr mem (MM.memWord 0x922c) of
        Nothing -> putStrLn "  error: could not resolve 0x922c"
        Just off -> case Map.lookup off (fn ^. MD.parsedBlocks) of
          Nothing -> putStrLn "  error: 0x922c block not found in the re-seeded 0x9203 discovery"
          Just block -> do
            rC <- checkBranchModel mem block
              BranchQuery { bqPointerOverrides = [], bqMemoryBytes = []
                          , bqTargetAddr = 0x8f98, bqObserveReg = AR.r0
                          , bqExcludeObserved = [] }
            putStr "  0x8f98 (config-reload write) reachable from 0x922c: " >> reportResult "R0" rC
            case rC of
              Reachable satVal -> do
                putStrLn ("\n  -- control: R0 != 0x" ++ showHex satVal
                          " (R0 still fully symbolic otherwise) -- is 0x8f98 still reachable?")
                rC2 <- checkBranchModel mem block
                  BranchQuery { bqPointerOverrides = [], bqMemoryBytes = []
                              , bqTargetAddr = 0x8f98, bqObserveReg = AR.r0
                              , bqExcludeObserved = [satVal] }
                reportResult "R0" rC2
              _ -> pure ()

reportGate :: String -> PH.GateResult -> IO ()
reportGate label res = case res of
  PH.GateSat model -> do
    putStrLn ("  " ++ label ++ ": SAT. Model:")
    mapM_ (\(nm, v) -> putStrLn ("    " ++ nm ++ " = 0x" ++ showHex v "")) model
  PH.GateUnsat -> putStrLn ("  " ++ label ++ ": UNSAT.")
  PH.GateError e -> putStrLn ("  " ++ label ++ ": error: " ++ e)

-- | Build one contiguous 'PacketByte' buffer spanning [lo, hi), defaulting
-- every position to @Concrete 0@ (matching this harness's real cold-RAM
-- convention) except the given (address, byte) overrides -- for seeding
-- several known-disjoint addresses in one 'PH.runPacketTransactionTraced'
-- call, which only accepts a single contiguous region. Not a general
-- sparse-memory facility: a purpose-built helper for this one investigation,
-- same spirit as 'APTrace.SymbolicRunner.BranchQuery'\'s 'bqMemoryBytes'
-- but supporting symbolic bytes too, which that record does not need.
sparseBuffer :: Word32 -> Word32 -> [(Word32, PacketByte)] -> (Word32, [PacketByte])
sparseBuffer lo hi overrides =
  (lo, [ maybe (Concrete 0) id (lookup a overrides) | a <- [lo .. hi - 1] ])

reportPacket :: String -> Word32 -> PH.PacketResult -> IO ()
reportPacket label bufLo res = case res of
  PH.ConcreteResult v -> putStrLn ("  " ++ label ++ ": CONCRETE, observed = 0x" ++ showHex v "")
  PH.Reachable models -> do
    putStrLn ("  " ++ label ++ ": SAT -- reachable. Model (buffer offset -> byte value, address = 0x"
              ++ showHex bufLo "" ++ " + offset):")
    mapM_ (\(i, v) -> putStrLn ("    +0x" ++ showHex i "" ++ " (0x" ++ showHex (bufLo + fromIntegral i) ""
                                 ++ ") = 0x" ++ showHex v "")) models
  PH.Unreachable -> putStrLn ("  " ++ label ++ ": UNSAT -- not reachable under any assignment of the symbolic bytes.")
  PH.HarnessError e -> putStrLn ("  " ++ label ++ ": harness error: " ++ e)

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
                      , bqMemoryBytes = [], bqTargetAddr = handlerAddr, bqObserveReg = AR.r3, bqExcludeObserved = [] }
        reportResult "R3" r
        case r of
          Reachable v | v == expected -> putStrLn "  (matches expected ASCII value)"
          Reachable _ -> putStrLn "  (WARNING: does not match expected ASCII value)"
          _ -> pure ()
