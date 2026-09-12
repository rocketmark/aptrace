{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
-- | Builds a Macaw 'MM.Memory' image directly from a raw (headerless)
-- Cortex-M firmware image, with no ELF involved.
--
-- This exists because Macaw's only existing AArch32 loader
-- (@macaw-loader-aarch32@ / @Data.Macaw.BinaryLoader.AArch32@) is ELF-only.
-- The underlying 'Data.Macaw.Memory' construction API it calls into
-- ('Data.Macaw.Memory.memSegment', 'Data.Macaw.Memory.insertMemSegment') is
-- not ELF-specific, so we call it directly instead.
--
-- Also owns APTrace's Cortex-M execution-state policy in full: both halves
-- of it. 'macawCortexMEntry' is Macaw's own *entry-address convention*
-- (which bit of a 'MM.MemSegmentOff' selects Thumb decoding); 'armCortexMInfo'
-- is the *architecture-wide invariant* (PSTATE_T is always true on this
-- target) enforced during discovery itself. They fix two different, real
-- ways Macaw's generic AArch32 backend can end up in A32 mode on a target
-- that has no A32 state at all -- see each one's own Haddock.
module APTrace.FirmwareLoader
  ( buildMemory
  , buildMemoryWithMMIO
  , resolveEntry
  , resolveEntries
  , macawCortexMEntry
  , armCortexMInfo
  ) where

import           Data.Bits ( (.|.) )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.Functor.Identity ( runIdentity )
import qualified Data.Map as Map
import           Data.Maybe ( mapMaybe )
import qualified Data.Set as Set
import           Data.Word ( Word32 )
import           Lens.Micro ( (&), (.~) )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.ARM.ARMReg as ARMReg
import qualified Data.Macaw.ARM.Arch as ARMArch
import qualified Data.Macaw.ARM.Eval as ARMEval
import qualified Data.Macaw.AbsDomain.AbsState as MA
import qualified Data.Macaw.Architecture.Info as MI
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Memory.Permissions as Perm
import qualified Language.ASL.Globals as ASL

import           APTrace.VectorTable ( VectorEntry(..) )

-- | Build a Macaw memory image for a raw Cortex-M firmware image: one
-- executable/readable segment holding the firmware bytes at the given flash
-- load address, and one readable/writable, zero-initialized segment for
-- RAM. Both segments live in absolute address region 0.
--
-- Note: this models RAM as entirely zero at start. Real Cortex-M RAM
-- contents at reset are undefined; this is a deliberately simple starting
-- point (see the project notes on Cortex-M state gaps).
buildMemory :: BS.ByteString  -- ^ Flash contents (the firmware image)
            -> Word32         -- ^ Address that firmware byte 0 is loaded at
            -> Word32         -- ^ RAM base address
            -> Word32         -- ^ RAM size, in bytes
            -> Either String (MM.Memory 32)
buildMemory flashBytes flashBase ramBase ramSize = do
  let flashSeg :: MM.MemSegment 32
      flashSeg = runIdentity $
        MM.memSegment Map.empty 0 0 Nothing (MM.memWord (fromIntegral flashBase))
                       (Perm.read .|. Perm.execute)
                       flashBytes (fromIntegral (BS.length flashBytes))
      ramSeg :: MM.MemSegment 32
      ramSeg = runIdentity $
        MM.memSegment Map.empty 0 0 Nothing (MM.memWord (fromIntegral ramBase))
                       (Perm.read .|. Perm.write)
                       (BS.replicate (fromIntegral ramSize) 0) (fromIntegral ramSize)
  m1 <- overlapErr (MM.insertMemSegment flashSeg (MM.emptyMemory MM.Addr32))
  m2 <- overlapErr (MM.insertMemSegment ramSeg m1)
  pure m2
  where
    overlapErr = either (const (Left "overlapping memory segments")) Right

-- | Like 'buildMemory', but also adds a third, initially-zero, read/write
-- segment covering a memory-mapped peripheral (MMIO) address range. Combined
-- with @Data.Macaw.Symbolic.Memory@'s @SymbolicMutable@ content mode (which
-- makes all /mutable/ (writable) memory fully symbolic rather than concrete),
-- this makes reads from this range come back as fresh symbolic values during
-- Crucible simulation -- exactly modeling an unknown-state peripheral
-- register, without needing a per-read override hook.
buildMemoryWithMMIO :: BS.ByteString
                     -> Word32  -- ^ Flash load address
                     -> Word32  -- ^ RAM base
                     -> Word32  -- ^ RAM size
                     -> Word32  -- ^ MMIO region base
                     -> Word32  -- ^ MMIO region size
                     -> Either String (MM.Memory 32)
buildMemoryWithMMIO flashBytes flashBase ramBase ramSize mmioBase mmioSize = do
  m <- buildMemory flashBytes flashBase ramBase ramSize
  let mmioSeg :: MM.MemSegment 32
      mmioSeg = runIdentity $
        MM.memSegment Map.empty 0 0 Nothing (MM.memWord (fromIntegral mmioBase))
                       (Perm.read .|. Perm.write)
                       (BS.replicate (fromIntegral mmioSize) 0) (fromIntegral mmioSize)
  overlapErr (MM.insertMemSegment mmioSeg m)
  where
    overlapErr = either (const (Left "overlapping memory segments")) Right

-- | Resolve an address to a Macaw segment offset.
--
-- Deliberately does /not/ touch the low (Thumb) bit either way: this is a
-- plain lookup, used both for code entries (which must already have the bit
-- set -- see 'macawCortexMEntry') and for plain data/MMIO addresses (which
-- must not). Callers seeding Macaw code discovery should normalize through
-- 'macawCortexMEntry' first; callers resolving a data address should not.
resolveEntry :: MM.Memory 32 -> Word32 -> Maybe (MM.MemSegmentOff 32)
resolveEntry mem addr = MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral addr))

-- | Convert a canonical Cortex-M code address -- a function's instruction
-- address as it appears in disassembly, a raw vector-table word, or an
-- ARM/Thumb function-pointer value, whether or not it already carries the
-- low "Thumb bit" -- into the address Macaw's AArch32 backend needs to
-- select Thumb (T32) decoding for it.
--
-- Macaw's AArch32 backend (@Data.Macaw.ARM.Eval.mkInitialAbsState@,
-- @lowBitSet@) derives a discovery root's initial @PSTATE_T@ precondition
-- purely from the low bit of the 'MM.MemSegmentOff' handed to
-- 'Data.Macaw.Discovery.cfgFromAddrs' as an entry point: bit set => Thumb,
-- clear => ARM (A32). Cortex-M has no A32 execution state at all, so an
-- even (bit-clear) code address must never be handed to discovery as-is --
-- Macaw has been observed lifting such an address as A32 while the same
-- address with the Thumb bit set decodes correctly. Setting the bit
-- unconditionally is always correct for Cortex-M code and is a no-op for an
-- address that already has it (every real vector-table word and Thumb
-- function pointer already does).
--
-- Only apply this to an address APTrace is intentionally treating as code
-- (a discovery-root entry point). Never apply it to a data/MMIO address.
macawCortexMEntry :: Word32 -> Word32
macawCortexMEntry addr = addr .|. 1

-- | The Cortex-M4F-specific Macaw architecture configuration for all normal
-- APTrace discovery. Built from the pinned 'ARM.arm_linux_info', overriding
-- only the two hooks responsible for the two real, distinct ways Macaw's
-- generic AArch32 backend has been observed losing the Cortex-M Thumb-only
-- invariant during discovery (traced against @firmware_autopilot868.bin@):
--
--  1. 'ARMEval.mkInitialAbsState' derives a freshly-discovered function's
--     initial @PSTATE_T@ purely from the low bit of its own entry address.
--     That's correct for an externally-supplied, Thumb-bit-tagged function
--     pointer (see 'macawCortexMEntry'), but a direct, same-state Thumb
--     @BL@ callee is a plain, /even/ instruction address -- the Thumb-bit
--     tagging convention only applies to interworking function-pointer
--     *data* (register-indirect @BX@\/@BLX@), never to a branch-immediate
--     target. An ordinary internal call can therefore get initialized as
--     A32, and everything decoded from it is not real evidence (confirmed:
--     @0xcd90@ and @0xcdd8@, both called directly from @0xcc24@).
--  2. A post-call continuation block's @PSTATE_T@ can fail to fold to a
--     precise value during Macaw's generic call abstract-state transfer
--     (@Data.Macaw.AbsDomain.AbsState@'s preserved-register handling),
--     leaving 'ARMEval.extractBlockPrecond' unable to resolve it at all
--     (@Left "TopV where PSTATE_T expected"@ -- confirmed at @0xcb94@,
--     the continuation after the call at @0xcb8e@).
--
-- Both are overapproximation artifacts of a generic A/R-profile abstract
-- domain, not real ambiguity: on Cortex-M4F the answer is always Thumb, so
-- both overrides simply assert that fact instead of deriving/propagating
-- it. Neither touches any address -- 'macawCortexMEntry' still owns that,
-- entirely separately (Macaw's entry-address convention vs. this
-- architecture-wide invariant are different problems; this does not
-- replace or subsume that policy). Everything else -- disassembly,
-- classifiers, call identification, rewriting -- is exactly Macaw's own
-- upstream 'ARM.arm_linux_info' behavior, unmodified.
armCortexMInfo :: MI.ArchitectureInfo ARM.ARM
armCortexMInfo = ARM.arm_linux_info
  { MI.mkInitialAbsState = \mem addr ->
      ARMEval.mkInitialAbsState mem addr
        & MA.absRegState . MC.boundValue pstateT .~ MA.FinSet (Set.singleton 1)
  , MI.extractBlockPrecond = \addr absState ->
      case ARMEval.extractBlockPrecond addr absState of
        Right precond -> Right precond
        Left _        -> Right (ARMArch.ARMBlockPrecond { ARMArch.bpPSTATE_T = True })
  }
  where
    pstateT = ARMReg.ARMGlobalBV (ASL.knownGlobalRef @"PSTATE_T")

-- | Resolve a whole vector table's entries into the 'MD.AddrSymMap' and
-- discovery-root list 'Data.Macaw.Discovery.cfgFromAddrs' needs, dropping
-- any entry whose raw address can't be resolved against 'mem' (e.g. an
-- empty/unpopulated vector slot). Each root is normalized through
-- 'macawCortexMEntry' first, matching every other Macaw discovery seed in
-- this project.
resolveEntries :: MM.Memory 32 -> [VectorEntry] -> (MD.AddrSymMap 32, [MM.MemSegmentOff 32])
resolveEntries mem entries =
  let resolved = mapMaybe (\e -> (,) (veName e) <$> resolveEntry mem (macawCortexMEntry (veRawAddr e))) entries
      addrSymMap = Map.fromList [ (addr, BSC.pack name) | (name, addr) <- resolved ]
  in (addrSymMap, map snd resolved)
