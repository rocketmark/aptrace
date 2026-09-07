{-# LANGUAGE DataKinds #-}
-- | Builds a Macaw 'MM.Memory' image directly from a raw (headerless)
-- Cortex-M firmware image, with no ELF involved.
--
-- This exists because Macaw's only existing AArch32 loader
-- (@macaw-loader-aarch32@ / @Data.Macaw.BinaryLoader.AArch32@) is ELF-only.
-- The underlying 'Data.Macaw.Memory' construction API it calls into
-- ('Data.Macaw.Memory.memSegment', 'Data.Macaw.Memory.insertMemSegment') is
-- not ELF-specific, so we call it directly instead.
module APTrace.FirmwareLoader
  ( buildMemory
  , buildMemoryWithMMIO
  , resolveEntry
  ) where

import           Data.Bits ( (.|.) )
import qualified Data.ByteString as BS
import           Data.Functor.Identity ( runIdentity )
import qualified Data.Map as Map
import           Data.Word ( Word32 )

import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Memory.Permissions as Perm

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

-- | Resolve a raw vector-table word to a Macaw segment offset.
--
-- Deliberately does /not/ clear the low (Thumb) bit: Macaw's AArch32 backend
-- (@Data.Macaw.ARM.Eval.mkInitialAbsState@) derives a function's initial
-- decode mode (A32 vs Thumb) from the low bit of its own entry address, so
-- vector-table addresses -- which already have that bit set for every
-- Cortex-M handler, since Cortex-M is Thumb-only -- should be handed to
-- Macaw's code discovery unmodified.
resolveEntry :: MM.Memory 32 -> Word32 -> Maybe (MM.MemSegmentOff 32)
resolveEntry mem addr = MM.resolveAbsoluteAddr mem (MM.memWord (fromIntegral addr))
