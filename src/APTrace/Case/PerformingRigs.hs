-- | Performing Rigs AutoPilot/Remote target configuration: the single
-- authoritative definition of this product's ATSAMD51J19A (Cortex-M4F,
-- 192KB RAM) memory geometry. Every module that previously duplicated
-- these numbers as its own local constants ('APTrace.MacawCensus',
-- 'APTrace.MacawExpand', 'APTrace.DebugHarness', @app/Main.hs@) now takes
-- them as parameters supplied from here instead, so reusable framework
-- code carries no Performing Rigs-specific knowledge of its own -- see
-- @docs/architecture.md@'s framework/case split.
--
-- This is deliberately a handful of plain top-level values, not a record
-- or a configuration framework: there is exactly one target in this
-- project today, and a plugin-style abstraction over a single case would
-- be speculative generality this refactor is not chartered to add.
module APTrace.Case.PerformingRigs
  ( ramBase
  , ramSize
  , numIrq
  , defaultFlashBase
  ) where

import Data.Word ( Word32 )

-- | RAM base address for the AutoPilot/Remote ATSAMD51J19A target.
ramBase :: Word32
ramBase = 0x20000000

-- | RAM size (192KB) for the AutoPilot/Remote ATSAMD51J19A target.
ramSize :: Word32
ramSize = 0x30000

-- | Vector-table entry count (system exceptions + IRQ vectors) this
-- firmware family's Cortex-M4F variant exposes.
numIrq :: Int
numIrq = 40

-- | Performing Rigs firmware images are linked to start at flash 0x4000
-- (past the bootloader) -- the default every CLI subcommand falls back to
-- when the caller doesn't override it.
defaultFlashBase :: Word32
defaultFlashBase = 0x4000
